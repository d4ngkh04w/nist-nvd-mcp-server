# LLM evaluations

[README](../README.md)

Run the commands below from the repository root.

## Fixed regression dataset

[`evaluations/nist-nvd-mcp-server.xml`](../evaluations/nist-nvd-mcp-server.xml) contains ten
independent, multi-step questions for a **fixed synthetic dataset**, not real NVD facts.
The fixture wrapper runs the real stdio MCP server against a loopback mock API with
isolated temporary storage. It requires development dependencies and a build; the
contract suite verifies all ten answers through MCP calls.

Install [`scripts/requirements.txt`](../scripts/requirements.txt) in your Python environment
and set `OPENAI_API_KEY` in the environment, never in a report or command argument:

```bash
npm run build
python scripts/evaluation.py evaluations/nist-nvd-mcp-server.xml \
  -t stdio -c node -a node_modules/tsx/dist/cli.mjs scripts/evaluation-fixture.ts \
  --base-url https://api.openai.com/v1 -m YOUR_MODEL --strict-match -o evaluations/report.md
```

LLM evaluation needs an external provider and may incur cost. CI verifies fixture answers,
not model quality.
