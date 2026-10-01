import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

/**
 * Creates the stdio transport.
 *
 * stdout belongs to the JSON-RPC protocol; all diagnostics go to stderr (see `shared/logger.ts`).
 */
export function createStdioTransport(): StdioServerTransport {
  return new StdioServerTransport();
}
