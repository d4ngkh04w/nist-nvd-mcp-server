import { mkdirSync } from 'node:fs';
import path from 'node:path';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { CachedResourceLoader } from './application/cached-resource-loader.js';
import { CpeMatchService } from './application/cpe-match-service.js';
import { CpeService } from './application/cpe-service.js';
import { CveHistoryService } from './application/cve-history-service.js';
import { CveService } from './application/cve-service.js';
import type { AppConfig } from './config/env.js';
import type { Clock } from './domain/ports.js';
import { systemClock } from './domain/ports.js';
import { DiskCache } from './infrastructure/cache/disk-cache.js';
import { createHmacCursorCodec } from './infrastructure/cursor/hmac-cursor-codec.js';
import { NvdCpeMatchClient } from './infrastructure/nvd/cpe-match-client.js';
import { NvdCpeClient } from './infrastructure/nvd/cpe-client.js';
import { NvdCveHistoryClient } from './infrastructure/nvd/cve-history-client.js';
import { NvdCveClient } from './infrastructure/nvd/cve-client.js';
import { NvdHttpClient } from './infrastructure/nvd/http-client.js';
import { SequentialRateLimiter } from './infrastructure/rate-limit/sequential-rate-limiter.js';
import { SqliteCpeMatchRepository } from './infrastructure/sqlite/cpe-match-repository.js';
import { SqliteCpeRepository } from './infrastructure/sqlite/cpe-repository.js';
import { SqliteCveHistoryRepository } from './infrastructure/sqlite/cve-history-repository.js';
import { SqliteCveRepository } from './infrastructure/sqlite/cve-repository.js';
import { openDatabase } from './infrastructure/sqlite/database.js';
import { SqliteAppMetadataRepository } from './infrastructure/sqlite/metadata-repository.js';
import { runMigrations } from './infrastructure/sqlite/migrator.js';
import { SqliteQueryCacheRepository } from './infrastructure/sqlite/query-cache-repository.js';
import { startCacheCleanup, type CacheCleanupHandle } from './maintenance/cache-cleanup.js';
import { createMcpServer } from './mcp/server.js';
import type { ToolContext } from './mcp/tool-context.js';
import { SingleFlight } from './shared/async.js';
import type { Logger } from './shared/logger.js';

export type App = {
  readonly config: AppConfig;
  readonly logger: Logger;
  readonly server: McpServer;
  readonly toolContext: ToolContext;
  /** Runs one cache-cleanup pass (used by tests and by the periodic timer). */
  runMaintenanceOnce(): Promise<void>;
  /** Releases the database handle and stops maintenance timers. */
  close(): void;
};

export type CreateAppOptions = {
  config: AppConfig;
  logger: Logger;
  clock?: Clock;
};

/**
 * Composition root.
 *
 * Wires configuration -> infrastructure (SQLite, disk cache, NVD HTTP client, rate limiter) ->
 * application services -> MCP server. Nothing here writes to stdout.
 */
export async function createApp(options: CreateAppOptions): Promise<App> {
  const { config, logger } = options;
  const clock = options.clock ?? systemClock;
  const storageLogger = logger.child({ component: 'storage' });
  const nvdLogger = logger.child({ component: 'nvd' });

  mkdirSync(path.dirname(config.storage.sqlitePath), { recursive: true });

  const db = openDatabase({
    path: config.storage.sqlitePath,
    busyTimeoutMs: config.storage.sqliteBusyTimeoutMs,
    logger: storageLogger,
  });

  const migrations = await runMigrations(db, {
    migrationsDir: config.storage.migrationsDir,
    logger: storageLogger,
  });
  logger.info('migrations_applied', {
    applied: migrations.applied.length,
    skipped: migrations.skipped.length,
    drift: migrations.drift.length,
  });

  const diskCache = new DiskCache({
    directory: config.cache.directory,
    envelopeVersion: config.cache.envelopeVersion,
    maxEntryBytes: config.cache.maxEntryBytes,
    logger: storageLogger,
    now: () => clock.now(),
  });
  await diskCache.ensureDirectories();

  const cveRepository = new SqliteCveRepository({ db, logger: storageLogger });
  const cveHistoryRepository = new SqliteCveHistoryRepository({ db, logger: storageLogger });
  const cpeRepository = new SqliteCpeRepository({ db, logger: storageLogger });
  const cpeMatchRepository = new SqliteCpeMatchRepository({ db, logger: storageLogger });
  const queryCache = new SqliteQueryCacheRepository({ db, logger: storageLogger });
  const metadataRepository = new SqliteAppMetadataRepository({ db, logger: storageLogger });

  const rateLimiter = new SequentialRateLimiter({
    minIntervalMs: config.nvd.minIntervalMs,
    maxConcurrency: config.nvd.maxConcurrency,
  });
  const httpClient = new NvdHttpClient({
    baseUrl: config.nvdBaseUrl,
    apiKey: config.nvdApiKey,
    requestTimeoutMs: config.nvd.requestTimeoutMs,
    maxRetries: config.nvd.maxRetries,
    retryBaseDelayMs: config.nvd.retryBaseDelayMs,
    rateLimiter,
    logger: nvdLogger,
  });

  const cveClient = new NvdCveClient(httpClient);
  const cveHistoryClient = new NvdCveHistoryClient(httpClient);
  const cpeClient = new NvdCpeClient(httpClient);
  const cpeMatchClient = new NvdCpeMatchClient(httpClient);

  const singleFlight = new SingleFlight();
  const loader = new CachedResourceLoader({
    diskCache,
    singleFlight,
    clock,
    logger: logger.child({ component: 'cache' }),
  });
  const cursorCodec = createHmacCursorCodec({
    secret: config.cursor.secret,
    ttlSeconds: config.cursor.ttlSeconds,
    clock,
    maxStartIndex: config.limits.maxStartIndex,
    maxPageSize: Math.max(
      config.limits.pageSize.cves.max,
      config.limits.pageSize['cve-history'].max,
      config.limits.pageSize.cpes.max,
      config.limits.pageSize['cpe-matches'].max,
    ),
  });

  const services: ToolContext['services'] = {
    cve: new CveService({
      config,
      clock,
      logger: logger.child({ component: 'cve' }),
      cveClient,
      cveRepository,
      queryCache,
      loader,
      cursorCodec,
      singleFlight,
    }),
    cveHistory: new CveHistoryService({
      config,
      clock,
      logger: logger.child({ component: 'cve-history' }),
      historyClient: cveHistoryClient,
      historyRepository: cveHistoryRepository,
      queryCache,
      loader,
      cursorCodec,
    }),
    cpe: new CpeService({
      config,
      clock,
      logger: logger.child({ component: 'cpe' }),
      cpeClient,
      cpeRepository,
      queryCache,
      loader,
      cursorCodec,
    }),
    cpeMatch: new CpeMatchService({
      config,
      clock,
      logger: logger.child({ component: 'cpe-match' }),
      cpeMatchClient,
      cpeMatchRepository,
      queryCache,
      loader,
      cursorCodec,
    }),
  };

  const toolContext: ToolContext = { config, logger, clock, services };
  const server = createMcpServer(toolContext);

  const cleanup: CacheCleanupHandle = startCacheCleanup({
    diskCache,
    queryCache,
    repositories: [
      { name: 'cves', deleteExpired: (now) => cveRepository.deleteExpired(now) },
      { name: 'cve_history', deleteExpired: (now) => cveHistoryRepository.deleteExpired(now) },
      { name: 'cpes', deleteExpired: (now) => cpeRepository.deleteExpired(now) },
      { name: 'cpe_matches', deleteExpired: (now) => cpeMatchRepository.deleteExpired(now) },
    ],
    maxBytes: config.cache.maxSizeBytes,
    maxAgeMs: 0,
    intervalMs: config.cache.cleanupIntervalMs,
    logger: logger.child({ component: 'maintenance' }),
    clock,
  });

  metadataRepository.set('last_started_at', clock.now().toISOString());

  logger.info('app_ready', {
    sqlitePath: config.storage.sqlitePath,
    cacheDirectory: config.cache.directory,
    nvdBaseUrl: config.nvdBaseUrl,
    nvdCredentialsConfigured: config.nvdApiKey !== undefined,
    nvdMinIntervalMs: config.nvd.minIntervalMs,
  });

  return {
    config,
    logger,
    server,
    toolContext,
    runMaintenanceOnce: () => cleanup.runOnce(),
    close: () => {
      cleanup.stop();
      rateLimiter.dispose();
      db.close();
    },
  };
}
