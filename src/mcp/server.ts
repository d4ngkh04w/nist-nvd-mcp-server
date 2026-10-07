import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { DomainError } from '../domain/errors.js';
import { runWithOperation, throwIfCancelled, waitWithSignal } from '../shared/operation.js';

import { toErrorResult } from './errors.js';
import { buildSuccessResult, extractCacheStatus } from './output.js';
import type { ToolContext } from './tool-context.js';
import { allTools } from './tools/index.js';

export const SERVER_NAME = 'nist-nvd-mcp-server';
export const SERVER_VERSION = '0.1.0';
export const SERVER_INSTRUCTIONS = [
  'Use nvd_get_cve_summary for one CVE, nvd_get_cves for batches, and nvd_get_cve for full details.',
  'Use fields to keep responses compact; verify the CVSS version before comparing scores.',
  'Inspect meta.stale and meta.warnings before drawing conclusions from cached data.',
  'Follow pagination.nextCursor with unchanged filters and pageSize; restart without a cursor if it expires.',
  'cpeNameId identifies a dictionary entry; matchCriteriaId identifies match criteria and is not a dictionary id.',
  'NVD data describes applicability, not proof that a particular deployed system is vulnerable.',
].join(' ');

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
    { capabilities: { tools: {} }, instructions: SERVER_INSTRUCTIONS },
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
      async (args, extra) => {
        const startedAt = Date.now();
        const deadline = new AbortController();
        const signal = AbortSignal.any([extra.signal, deadline.signal]);
        const timer = setTimeout(() => deadline.abort(DomainError.requestTimeout(
          'Tool deadline exceeded; narrow the query or retry with a warm cache',
          { scope: 'tool', timeoutMs: ctx.config.mcp.toolTimeoutMs },
        )), ctx.config.mcp.toolTimeoutMs);
        timer.unref();
        let finished = false;
        let progress = 0;
        const token = extra._meta?.progressToken;
        const onProgress = (message: string) => {
          if (token === undefined || finished || signal.aborted) return;
          void extra.sendNotification({
            method: 'notifications/progress',
            params: { progressToken: token, progress: ++progress, message },
          }).catch(() => { ctx.logger.debug('progress_delivery_failed', { tool: tool.name }); });
        };
        try {
          const payload = await runWithOperation({ signal, onProgress }, async () => {
            throwIfCancelled();
            onProgress('Started tool request');
            const result = await waitWithSignal(tool.execute(args, ctx), signal);
            throwIfCancelled();
            return result;
          });
          const result = buildSuccessResult(payload, ctx.config.mcp.maxOutputBytes);
          ctx.logger.info('tool_call', {
            tool: tool.name,
            outcome: 'ok',
            durationMs: Date.now() - startedAt,
            cacheStatus: extractCacheStatus(payload),
          });
          return result;
        } catch (error) {
          const result = toErrorResult(error, tool.name, ctx.logger);
          ctx.logger.info('tool_call', {
            tool: tool.name,
            outcome: 'error',
            durationMs: Date.now() - startedAt,
          });
          return result;
        } finally {
          finished = true;
          clearTimeout(timer);
        }
      },
    );
  }

  return server;
}
