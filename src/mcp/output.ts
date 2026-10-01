import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

import type { ToolError } from '../domain/errors.js';

/**
 * Builds a successful tool result.
 *
 * `content[0].text` mirrors `structuredContent` so text-only clients see the same payload.
 */
export function buildSuccessResult(payload: Record<string, unknown>): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
  };
}

/**
 * Builds a tool error result.
 *
 * Errors carry the machine-readable `ToolError` contract as JSON text; `structuredContent` is
 * intentionally omitted because the tool output schema describes successful payloads only.
 */
export function buildErrorResult(error: ToolError): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(error) }],
    isError: true,
  };
}

/** Reads `meta.cacheStatus` for the `tool_call` log line. */
export function extractCacheStatus(payload: unknown): string | undefined {
  if (payload === null || typeof payload !== 'object') {
    return undefined;
  }
  const meta = (payload as { meta?: unknown }).meta;
  if (meta === null || typeof meta !== 'object') {
    return undefined;
  }
  const status = (meta as { cacheStatus?: unknown }).cacheStatus;
  return typeof status === 'string' ? status : undefined;
}
