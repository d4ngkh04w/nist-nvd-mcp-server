import { createApp } from './app.js';
import { loadConfig, loadDotEnvFile } from './config/env.js';
import { createStdioTransport } from './mcp/transport.js';
import { TOOL_COUNT } from './mcp/tools/index.js';
import { createStderrLogger, redirectConsoleToStderr } from './shared/logger.js';

/**
 * stdio entry point.
 *
 * Startup order: environment -> logger (stderr only) -> storage/migrations -> services ->
 * MCP server -> transport. `console.*` is redirected to stderr so no dependency can pollute the
 * JSON-RPC stream on stdout.
 */
async function main(): Promise<void> {
  loadDotEnvFile();
  const config = loadConfig(process.env);
  const logger = createStderrLogger(config.logLevel, { service: 'nist-nvd-mcp-server', pid: process.pid });
  redirectConsoleToStderr(logger);

  const app = await createApp({ config, logger });
  const transport = createStdioTransport();
  let shuttingDown = false;

  const shutdown = async (reason: string, exitCode = 0): Promise<void> => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    logger.info('server_stopping', { reason });
    try {
      await app.server.close();
    } catch (error) {
      logger.warn('server_close_failed', { error });
    }
    try {
      app.close();
    } catch (error) {
      logger.warn('app_close_failed', { error });
    }
    process.exit(exitCode);
  };

  transport.onclose = () => {
    void shutdown('transport_closed');
  };

  // `StdioServerTransport` only listens for `data`/`error`, so a closed stdin pipe (a disconnected
  // or killed host process) would otherwise leave the server running with the database still open.
  const onStdinClosed = (reason: string) => (): void => {
    void shutdown(reason);
  };
  const stdinEnd = onStdinClosed('stdin_closed');
  const stdinError = onStdinClosed('stdin_error');
  process.stdin.on('end', stdinEnd);
  process.stdin.on('close', stdinEnd);
  process.stdin.on('error', (error: unknown) => {
    logger.warn('stdin_error', { error });
    stdinError();
  });

  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });
  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
  process.on('uncaughtException', (error) => {
    logger.error('uncaught_exception', { error });
    void shutdown('uncaught_exception', 1);
  });
  process.on('unhandledRejection', (reason) => {
    logger.error('unhandled_rejection', { error: reason });
  });

  await app.server.connect(transport);

  logger.info('server_started', {
    tools: TOOL_COUNT,
    nodeVersion: process.version,
    nvdBaseUrl: config.nvdBaseUrl,
    nvdCredentialsConfigured: config.nvdApiKey !== undefined,
    logLevel: config.logLevel,
  });
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  process.stderr.write(`${JSON.stringify({ level: 'error', event: 'startup_failed', message })}\n`);
  process.exit(1);
});
