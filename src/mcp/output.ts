import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

import type { ToolError } from '../domain/errors.js';

/** Mirror structured output as text for clients that do not support structuredContent. */
export function buildSuccessResult(payload: Record<string, unknown>): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
  };
}

/** Omit structuredContent on errors: the published output schema describes success only. */
export function buildErrorResult(error: ToolError): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(error) }],
    isError: true,
  };
}

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
