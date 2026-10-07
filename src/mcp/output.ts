import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

import { DEFAULT_MCP_MAX_OUTPUT_BYTES } from '../config/defaults.js';
import { DomainError, type ToolError } from '../domain/errors.js';

/** Mirror structured output as text for clients that do not support structuredContent. */
export function buildSuccessResult(
  payload: Record<string, unknown>,
  maxBytes = DEFAULT_MCP_MAX_OUTPUT_BYTES,
): CallToolResult {
  const text = JSON.stringify(payload);
  const actualBytes = Buffer.byteLength(text, 'utf8');
  if (actualBytes > maxBytes) {
    throw new DomainError({
      code: 'RESPONSE_TOO_LARGE',
      message: 'Response exceeds the output budget; use fewer fields, a smaller pageSize, or set includeRaw, includeConfigurations and includeReferences to false',
      details: { actualBytes, maxBytes },
    });
  }
  return {
    content: [{ type: 'text', text }],
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
