import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

import { toDomainError } from '../domain/errors.js';
import type { Logger } from '../shared/logger.js';
import { buildErrorResult } from './output.js';

/**
 * Converts any thrown value into a tool error result.
 *
 * Domain errors keep their contract; unexpected errors are reported as `INTERNAL_ERROR` with a
 * generic message (the cause is logged to stderr and never leaves the process).
 */
export function toErrorResult(error: unknown, tool: string, logger: Logger): CallToolResult {
  const domainError = toDomainError(error);
  if (domainError.code === 'INTERNAL_ERROR') {
    logger.error('tool_failure', { tool, code: domainError.code, error });
  } else {
    logger.warn('tool_error', {
      tool,
      code: domainError.code,
      message: domainError.message,
      retryable: domainError.retryable,
    });
  }
  return buildErrorResult(domainError.toToolError());
}
