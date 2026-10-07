import type { Clock, QueryCacheRepositoryPort } from '../domain/ports.js';
import type { DiskCache, DiskCacheCleanupStats } from '../infrastructure/cache/disk-cache.js';
import type { Logger } from '../shared/logger.js';

/** A persistent repository that can drop rows whose TTL has passed. */
export type CacheCleanupTarget = {
  name: string;
  deleteExpired(now: Date): number;
};

export type CacheCleanupDependencies = {
  diskCache: DiskCache;
  queryCache: QueryCacheRepositoryPort;
  repositories: CacheCleanupTarget[];
  maxBytes: number;
  maxAgeMs: number;
  intervalMs: number;
  /** Grace period after expiry; zero preserves immediate eviction. */
  staleRetentionMs?: number;
  logger: Logger;
  clock: Clock;
};

export type CacheCleanupHandle = {
  runOnce(): Promise<void>;
  stop(): void;
};

/** `maxAgeMs <= 0` means "no age limit"; the disk cache receives a value that is never reached. */
const NO_AGE_LIMIT_MS = Number.MAX_SAFE_INTEGER;

/**
 * Periodically removes SQLite rows and disk entries after expiry plus their stale grace period.
 *
 * Cleanup is best-effort maintenance: every failure is logged and swallowed so a broken cache
 * can never crash the MCP server. Timer handles are unref'd and therefore never keep the
 * process alive on their own.
 */
export function startCacheCleanup(deps: CacheCleanupDependencies): CacheCleanupHandle {
  const { diskCache, queryCache, repositories, maxBytes, maxAgeMs, intervalMs, logger, clock } = deps;
  const effectiveMaxAgeMs = maxAgeMs > 0 ? maxAgeMs : NO_AGE_LIMIT_MS;

  const runOnce = async (): Promise<void> => {
    const startedAt = Date.now();
    const now = clock.now();
    const evictionCutoff = new Date(now.getTime() - (deps.staleRetentionMs ?? 0));
    const failedTargets: string[] = [];

    let queryCacheDeleted = 0;
    try {
      queryCacheDeleted = queryCache.deleteExpired(evictionCutoff);
    } catch (error) {
      failedTargets.push('query_cache');
      logger.error('cache_cleanup_failed', { target: 'query_cache', error });
    }

    const repositoryDeleted: Record<string, number> = {};
    for (const repository of repositories) {
      try {
        repositoryDeleted[repository.name] = repository.deleteExpired(evictionCutoff);
      } catch (error) {
        failedTargets.push(repository.name);
        logger.error('cache_cleanup_failed', { target: repository.name, error });
      }
    }

    let disk: DiskCacheCleanupStats | null = null;
    try {
      disk = await diskCache.cleanup({
        maxBytes,
        maxAgeMs: effectiveMaxAgeMs,
        ...(deps.staleRetentionMs !== undefined ? { staleRetentionMs: deps.staleRetentionMs } : {}),
      });
    } catch (error) {
      failedTargets.push('disk_cache');
      logger.error('cache_cleanup_failed', { target: 'disk_cache', error });
    }

    logger.info('cache_cleanup', {
      queryCacheDeleted,
      repositories: repositoryDeleted,
      failedTargets,
      disk,
      durationMs: Date.now() - startedAt,
    });
  };

  let timer: NodeJS.Timeout | null = null;
  if (intervalMs > 0) {
    timer = setInterval(() => {
      void runOnce();
    }, intervalMs);
    // Maintenance must never keep the MCP server alive.
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
  }

  const stop = (): void => {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };

  return { runOnce, stop };
}
