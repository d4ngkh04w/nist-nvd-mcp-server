import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { toErrorResult } from './errors.js';
import { buildSuccessResult, extractCacheStatus } from './output.js';
import type { ToolContext } from './tool-context.js';
import { allTools } from './tools/index.js';

export const SERVER_NAME = 'nvd-nist-mcp';
export const SERVER_VERSION = '0.1.0';

/**
 * Creates the MCP server and registers the ten public tools.
 *
 * The MCP layer only validates/serializes: every tool call is delegated to the application layer,
 * domain errors are rendered as `ToolError` payloads and one structured log line is written to
 * stderr per call (stdout stays reserved for JSON-RPC).
 */
export function createMcpServer(ctx: ToolContext): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  for (const tool of allTools) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputShape,
        outputSchema: tool.outputShape,
        annotations: tool.annotations,
      },
      async (args) => {
        const startedAt = Date.now();
        try {
          const payload = await tool.execute(args, ctx);
          ctx.logger.info('tool_call', {
            tool: tool.name,
            outcome: 'ok',
            durationMs: Date.now() - startedAt,
            cacheStatus: extractCacheStatus(payload),
          });
          return buildSuccessResult(payload);
        } catch (error) {
          const result = toErrorResult(error, tool.name, ctx.logger);
          ctx.logger.info('tool_call', {
            tool: tool.name,
            outcome: 'error',
            durationMs: Date.now() - startedAt,
          });
          return result;
        }
      },
    );
  }

  return server;
}
