"""MCP Server Evaluation Harness (OpenAI-compatible).

Runs the `<qa_pair>` tasks from an evaluation XML against a live MCP server by letting an
LLM pick and call the server's own tools, then scores the final `<response>` against the
expected `<answer>`.

The LLM is reached through the OpenAI-compatible chat-completions API, so any gateway that
serves `/v1/chat/completions` with tool calling works (OpenAI, LiteLLM, local proxies, ...).
There is no Anthropic path.

Requires `mcp<2`: connections.py imports `streamablehttp_client`, which was renamed in mcp 2.x.

Example:
  OPENAI_API_KEY=... python evaluation.py -t stdio -c node -a ../dist/main.js \\
      --base-url http://127.0.0.1:20128/v1 \\
      -m oc/space-bunny-free ../evaluations/nist-nvd-mcp-server.xml
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from connections import create_connection

EVALUATION_PROMPT = """You are an AI assistant with access to tools.

When given a task, you MUST:
1. Use the available tools to complete the task
2. Provide summary of each step in your approach, wrapped in <summary> tags
3. Provide feedback on the tools provided, wrapped in <feedback> tags
4. Provide your final response, wrapped in <response> tags

Summary Requirements:
- In your <summary> tags, you must explain:
  - The steps you took to complete the task
  - Which tools you used, in what order, and why
  - The inputs you provided to each tool
  - The outputs you received from each tool
  - A summary for how you arrived at the response

Feedback Requirements:
- In your <feedback> tags, provide constructive feedback on the tools:
  - Comment on tool names: Are they clear and descriptive?
  - Comment on input parameters: Are they well-documented? Are required vs optional parameters clear?
  - Comment on descriptions: Do they accurately describe what the tool does?
  - Comment on any errors encountered during tool usage: Did the tool fail to execute? Did the tool return too many tokens?
  - Identify specific areas for improvement and explain WHY they would help
  - Be specific and actionable in your suggestions

Response Requirements:
- Your response should be concise and directly address what was asked
- Always wrap your final response in <response> tags
- If you cannot solve the task return <response>NOT_FOUND</response>
- For numeric responses, provide just the number
- For IDs, provide just the ID
- For names or text, provide the exact text requested
- Your response should go last"""


def parse_evaluation_file(file_path: Path) -> list[dict[str, Any]]:
    """Parse XML evaluation file with qa_pair elements."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        evaluations = []

        for qa_pair in root.findall(".//qa_pair"):
            question_elem = qa_pair.find("question")
            answer_elem = qa_pair.find("answer")

            if question_elem is not None and answer_elem is not None:
                evaluations.append({
                    "question": (question_elem.text or "").strip(),
                    "answer": (answer_elem.text or "").strip(),
                })

        return evaluations
    except Exception as e:
        print(f"Error parsing evaluation file {file_path}: {e}")
        return []


def extract_xml_content(text: str, tag: str) -> str | None:
    """Extract content from XML tags."""
    pattern = rf"<{tag}>(.*?)</{tag}>"
    matches = re.findall(pattern, text, re.DOTALL)
    return matches[-1].strip() if matches else None


# --- answer grading ---------------------------------------------------------
#
# Grading is strict about content but lenient about presentation. A model that appends
# an explanation to a correct value, wraps it in backticks or quotes, or omits the
# `<response>` wrapper is still reporting the right fact, so scoring it wrong measures
# the wrapper rather than the answer. Every lenient pass carries a label in the report
# so it stays auditable, and `--strict-match` restores exact comparison.

_ANSWER_DECORATION = "\"'`*_ \t\r\n"
# Characters that may not touch a short answer for it to count as a whole token. `.` is
# deliberately absent from the edge set so a sentence-final "9.8." still matches "9.8".
_TOKEN_EDGE = "A-Za-z0-9_-"
_SHORT_TAIL = "A-Za-z0-9_.-"
_SHORT_ANSWER = re.compile(rf"^[{_TOKEN_EDGE}][{_SHORT_TAIL}]*$")


def normalize_answer(text: str) -> str:
    """Strip markdown decoration and surrounding whitespace, then casefold."""
    return text.strip().strip(_ANSWER_DECORATION).strip().casefold()


def answer_is_present(expected: str, text: str) -> bool:
    """True when `expected` occurs in `text` as a whole token (or as a substring).

    A short answer such as `9.8` or `50` must stand alone, so it is not found inside
    `19.8` or `150`. A long answer (a CPE string, a phrase) is matched as a substring.
    """
    if not expected or not text:
        return False
    if _SHORT_ANSWER.match(expected):
        return (
            re.search(
                rf"(?<![{_TOKEN_EDGE}]){re.escape(expected)}(?![{_TOKEN_EDGE}])",
                text,
            )
            is not None
        )
    return expected in text


def grade_answer(
    expected: str,
    response_value: str | None,
    full_reply: str | None,
    strict: bool = False,
) -> tuple[int, str]:
    """Return `(score, method)` for one task.

    Methods: `exact`, `contained`, `prose`, `no_response`, `no_match`.
    """
    expected_norm = normalize_answer(expected)
    response_norm = normalize_answer(response_value) if response_value else ""

    if strict:
        return (1, "exact") if response_norm == expected_norm else (0, "no_match")

    if response_norm:
        if response_norm == expected_norm:
            return 1, "exact"
        if answer_is_present(expected_norm, response_norm):
            return 1, "contained"
        return 0, "no_match"

    # No `<response>` tag: the model answered in prose. The fact is still there, so the
    # whole reply is scanned, but the method stays visible because the tag was requested.
    # Caveat: a model that restates the question can mention the expected value here, so a
    # `prose` pass is labelled for review rather than trusted blindly.
    body = normalize_answer(full_reply) if full_reply else ""
    if body and answer_is_present(expected_norm, body):
        return 1, "prose"
    return 0, "no_response"


def stringify_tool_result(result: Any) -> str:
    """Flatten an MCP tool result into the text the model will read."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        parts = []
        for block in result:
            text = getattr(block, "text", None)
            parts.append(text if isinstance(text, str) else str(block))
        return "\n".join(parts)
    if isinstance(result, (dict, list)):
        return json.dumps(result, default=str)
    return str(result)


def to_openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert MCP tool listings into OpenAI function-tool definitions."""
    converted = []
    for tool in tools:
        parameters = tool.get("input_schema") or tool.get("inputSchema")
        if not isinstance(parameters, dict):
            parameters = {"type": "object", "properties": {}}
        converted.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description") or "",
                "parameters": parameters,
            },
        })
    return converted


def parse_tool_arguments(raw: str | None) -> dict[str, Any]:
    """Parse a tool call's JSON argument payload, tolerating malformed output."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"__raw_arguments": raw}
    return parsed if isinstance(parsed, dict) else {"__value": parsed}


class ProviderError(RuntimeError):
    """Raised when a provider call fails."""


REASONING_EFFORT_VALUES = ("minimal", "low", "medium", "high")


def completion_kwargs(
    model: str,
    messages: list[dict[str, Any]],
    openai_tools: list[dict[str, Any]],
    reasoning_effort: str | None = None,
) -> dict[str, Any]:
    """Build the chat-completion arguments shared by every turn of the agent loop.

    `reasoning_effort` is only sent when a level was requested, so a provider that does not know
    the parameter keeps working. Reasoning models reject an explicit `temperature`, so it is
    dropped in that case; `max_tokens` stays bounded for the models that still accept it.
    """
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "tools": openai_tools,
        "max_tokens": 4096,
    }
    if reasoning_effort is None:
        kwargs["temperature"] = 0
    else:
        kwargs["reasoning_effort"] = reasoning_effort
    return kwargs


async def agent_loop_openai(
    client: Any,
    model: str,
    question: str,
    tools: list[dict[str, Any]],
    connection: Any,
    reasoning_effort: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Run the agent loop against an OpenAI-compatible chat completions endpoint."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": EVALUATION_PROMPT},
        {"role": "user", "content": question},
    ]
    openai_tools = to_openai_tools(tools)

    response = await asyncio.to_thread(
        client.chat.completions.create,
        **completion_kwargs(model, messages, openai_tools, reasoning_effort),
    )
    messages.append(_assistant_message(response))

    tool_metrics: dict[str, dict[str, Any]] = {}

    while response.choices and response.choices[0].message.tool_calls:
        for tool_call in response.choices[0].message.tool_calls or []:
            tool_name = tool_call.function.name
            tool_input = parse_tool_arguments(tool_call.function.arguments)

            tool_start_ts = time.time()
            try:
                tool_result = await connection.call_tool(tool_name, tool_input)
                tool_response = stringify_tool_result(tool_result)
            except Exception as e:
                tool_response = f"Error executing tool {tool_name}: {str(e)}\n"
                tool_response += traceback.format_exc()
            tool_duration = time.time() - tool_start_ts

            if tool_name not in tool_metrics:
                tool_metrics[tool_name] = {"count": 0, "durations": []}
            tool_metrics[tool_name]["count"] += 1
            tool_metrics[tool_name]["durations"].append(tool_duration)

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": tool_response,
            })

        response = await asyncio.to_thread(
            client.chat.completions.create,
            **completion_kwargs(model, messages, openai_tools, reasoning_effort),
        )
        messages.append(_assistant_message(response))

    message = response.choices[0].message if response.choices else None
    return (message.content if message and message.content else ""), tool_metrics


def _assistant_message(response: Any) -> dict[str, Any]:
    """Convert a chat completion into an assistant message that can be replayed."""
    message = response.choices[0].message
    entry: dict[str, Any] = {"role": "assistant", "content": message.content or ""}
    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        entry["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"},
            }
            for tc in tool_calls
        ]
    return entry


async def evaluate_single_task(
    agent_loop: Any,
    client: Any,
    model: str,
    qa_pair: dict[str, Any],
    tools: list[dict[str, Any]],
    connection: Any,
    task_index: int,
    strict_match: bool = False,
) -> dict[str, Any]:
    """Evaluate a single QA pair with the given tools."""
    start_time = time.time()

    print(f"Task {task_index + 1}: Running task with question: {qa_pair['question']}")
    response, tool_metrics = await agent_loop(client, model, qa_pair["question"], tools, connection)

    response_value = extract_xml_content(response, "response")
    summary = extract_xml_content(response, "summary")
    feedback = extract_xml_content(response, "feedback")

    score, match_method = grade_answer(
        qa_pair["answer"], response_value, response, strict=strict_match
    )

    duration_seconds = time.time() - start_time

    return {
        "question": qa_pair["question"],
        "expected": qa_pair["answer"],
        "actual": response_value,
        "score": score,
        "match": match_method,
        "total_duration": duration_seconds,
        "tool_calls": tool_metrics,
        "num_tool_calls": sum(len(metrics["durations"]) for metrics in tool_metrics.values()),
        "summary": summary,
        "feedback": feedback,
    }


REPORT_HEADER = """
# Evaluation Report

## Summary

- **Model**: {model}
- **Reasoning Effort**: {reasoning_effort}
- **Grading**: {grading}
- **Accuracy**: {correct}/{total} ({accuracy:.1f}%)
- **Lenient passes**: {lenient}
- **Average Task Duration**: {average_duration_s:.2f}s
- **Average Tool Calls per Task**: {average_tool_calls:.2f}
- **Total Tool Calls**: {total_tool_calls}

---

Accuracy counts a task correct when the ground truth appears in the answer, so a correct
value with an appended explanation or a missing `<response>` wrapper is not scored wrong.
`Lenient passes` lists those tasks with their method (`contained`, `prose`), so a pass that
did not come from an exact match is always visible. A `prose` pass scans the whole reply and
should be reviewed, since a model restating the question can mention the expected value; use
`--strict-match` to disable every lenient pass.
"""

TASK_TEMPLATE = """
### Task {task_num}

**Question**: {question}
**Ground Truth Answer**: `{expected_answer}`
**Actual Answer**: `{actual_answer}`
**Correct**: {correct_indicator}
**Match**: {match_method}
**Duration**: {total_duration:.2f}s
**Tool Calls**: {tool_calls}

**Summary**
{summary}

**Feedback**
{feedback}

---
"""


async def run_evaluation(
    eval_path: Path,
    connection: Any,
    model: str,
    client: Any,
    agent_loop: Any,
    reasoning_effort: str | None = None,
    strict_match: bool = False,
) -> str:
    """Run every qa_pair in the evaluation file and build a Markdown report."""
    print("🚀 Starting Evaluation")

    tools = await connection.list_tools()
    print(f"📋 Loaded {len(tools)} tools from MCP server")

    qa_pairs = parse_evaluation_file(eval_path)
    print(f"📋 Loaded {len(qa_pairs)} evaluation tasks")

    results = []
    for i, qa_pair in enumerate(qa_pairs):
        print(f"Processing task {i + 1}/{len(qa_pairs)}")
        try:
            result = await evaluate_single_task(
                agent_loop, client, model, qa_pair, tools, connection, i, strict_match
            )
        except Exception as e:
            print(f"  ⚠️  task {i + 1} failed: {e}")
            result = {
                "question": qa_pair["question"],
                "expected": qa_pair["answer"],
                "actual": f"ERROR: {e}",
                "score": 0,
                "match": "error",
                "total_duration": 0.0,
                "tool_calls": {},
                "num_tool_calls": 0,
                "summary": None,
                "feedback": None,
            }
        results.append(result)

    correct = sum(r["score"] for r in results)
    accuracy = (correct / len(results)) * 100 if results else 0
    average_duration_s = sum(r["total_duration"] for r in results) / len(results) if results else 0
    average_tool_calls = sum(r["num_tool_calls"] for r in results) / len(results) if results else 0
    total_tool_calls = sum(r["num_tool_calls"] for r in results)

    lenient = [
        f"task {i + 1} ({r['match']})"
        for i, r in enumerate(results)
        if r["score"] and r["match"] != "exact"
    ]

    report = REPORT_HEADER.format(
        model=model,
        reasoning_effort=reasoning_effort or "default (not sent)",
        grading="exact match only (--strict-match)" if strict_match
        else "content match (exact, contained, or prose without the <response> tag)",
        correct=correct,
        total=len(results),
        accuracy=accuracy,
        lenient=", ".join(lenient) if lenient else "none",
        average_duration_s=average_duration_s,
        average_tool_calls=average_tool_calls,
        total_tool_calls=total_tool_calls,
    )

    report += "".join([
        TASK_TEMPLATE.format(
            task_num=i + 1,
            question=qa_pair["question"],
            expected_answer=qa_pair["answer"],
            actual_answer=result["actual"] or "N/A",
            correct_indicator="✅" if result["score"] else "❌",
            match_method=result["match"],
            total_duration=result["total_duration"],
            tool_calls=json.dumps(result["tool_calls"], indent=2),
            summary=result["summary"] or "N/A",
            feedback=result["feedback"] or "N/A",
        )
        for i, (qa_pair, result) in enumerate(zip(qa_pairs, results))
    ])

    return report


def parse_headers(header_list: list[str]) -> dict[str, str]:
    """Parse header strings in format 'Key: Value' into a dictionary."""
    headers = {}
    if not header_list:
        return headers

    for header in header_list:
        if ":" in header:
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()
        else:
            print(f"Warning: Ignoring malformed header: {header}")
    return headers


def parse_env_vars(env_list: list[str]) -> dict[str, str]:
    """Parse environment variable strings in format 'KEY=VALUE' into a dictionary."""
    env = {}
    if not env_list:
        return env

    for env_var in env_list:
        if "=" in env_var:
            key, value = env_var.split("=", 1)
            env[key.strip()] = value.strip()
        else:
            print(f"Warning: Ignoring malformed environment variable: {env_var}")
    return env


def build_client(base_url: str, api_key_env: str | None) -> Any:
    """Create the OpenAI-compatible client for the configured endpoint."""
    from openai import OpenAI

    env_name = api_key_env or "OPENAI_API_KEY"
    api_key = os.environ.get(env_name)
    if not api_key:
        raise ProviderError(
            f"Environment variable {env_name} is not set (needed for {base_url})."
        )
    print(f"🧠 Provider: OpenAI-compatible endpoint {base_url}")
    return OpenAI(api_key=api_key, base_url=base_url)


async def main():
    parser = argparse.ArgumentParser(
        description="Evaluate MCP servers using test questions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # OpenAI-compatible gateway against a local stdio MCP server
  OPENAI_API_KEY=... python evaluation.py -t stdio -c node -a ../dist/main.js \\
      --base-url http://127.0.0.1:20128/v1 \\
      -m oc/space-bunny-free ../evaluations/nist-nvd-mcp-server.xml

  # SSE MCP server
  python evaluation.py -t sse -u https://example.com/mcp -H "Authorization: Bearer token" eval.xml

  # Reasoning model: pick how much thinking budget the provider may spend
  python evaluation.py -t stdio -c node -a ../dist/main.js \\
      --base-url http://127.0.0.1:20128/v1 \\
      -m openai/gpt-5 --reasoning-effort high ../evaluations/nist-nvd-mcp-server.xml
        """,
    )

    parser.add_argument("eval_file", type=Path, help="Path to evaluation XML file")
    parser.add_argument("-t", "--transport", choices=["stdio", "sse", "http"], default="stdio", help="Transport type (default: stdio)")
    parser.add_argument("-m", "--model", required=True, help="Model id to evaluate with")
    parser.add_argument("--base-url", required=True, help="OpenAI-compatible base URL, e.g. http://127.0.0.1:20128/v1")
    parser.add_argument("--api-key-env", help="Env var holding the API key (default: OPENAI_API_KEY)")

    stdio_group = parser.add_argument_group("stdio options")
    stdio_group.add_argument("-c", "--command", help="Command to run MCP server (stdio only)")
    stdio_group.add_argument("-a", "--args", nargs="+", help="Arguments for the command (stdio only)")
    stdio_group.add_argument("-e", "--env", nargs="+", help="Environment variables in KEY=VALUE format (stdio only)")

    remote_group = parser.add_argument_group("sse/http options")
    remote_group.add_argument("-u", "--url", help="MCP server URL (sse/http only)")
    remote_group.add_argument("-H", "--header", nargs="+", dest="headers", help="HTTP headers in 'Key: Value' format (sse/http only)")

    parser.add_argument(
        "--reasoning-effort",
        choices=REASONING_EFFORT_VALUES,
        help="Send reasoning_effort to the provider (default: omit it, and use temperature=0). "
             "Reasoning models reject an explicit temperature, so it is dropped when this is set.",
    )
    parser.add_argument("-o", "--output", type=Path, help="Output file for evaluation report (default: stdout)")
    parser.add_argument(
        "--strict-match",
        action="store_true",
        help="Score only an exact string match. By default a task is also correct when the "
             "ground truth appears inside a longer answer or in prose without the <response> tag; "
             "those passes are labelled in the report.",
    )

    args = parser.parse_args()

    if not args.eval_file.exists():
        print(f"Error: Evaluation file not found: {args.eval_file}")
        sys.exit(1)

    if not args.model:
        parser.error("-m/--model is required")

    headers = parse_headers(args.headers) if args.headers else None
    env_vars = parse_env_vars(args.env) if args.env else None

    try:
        client = build_client(args.base_url, args.api_key_env)
        connection = create_connection(
            transport=args.transport,
            command=args.command,
            args=args.args,
            env=env_vars,
            url=args.url,
            headers=headers,
        )
    except (ProviderError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"🔗 Connecting to MCP server via {args.transport}...")

    async with connection:
        print("✅ Connected successfully")
        report = await run_evaluation(
            args.eval_file,
            connection,
            args.model,
            client,
            agent_loop_openai,
            reasoning_effort=args.reasoning_effort,
            strict_match=args.strict_match,
        )

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report)
            print(f"\n✅ Report saved to {args.output}")
        else:
            print("\n" + report)


if __name__ == "__main__":
    asyncio.run(main())
