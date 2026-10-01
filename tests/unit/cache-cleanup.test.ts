import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { QueryCacheRepositoryPort } from '../../src/domain/ports.js';
import { DiskCache } from '../../src/infrastructure/cache/disk-cache.js';
import {
  startCacheCleanup,
  type CacheCleanupTarget,
} from '../../src/maintenance/cache-cleanup.js';
import { Logger } from '../../src/shared/logger.js';
import { createTempDir } from '../helpers/temp.js';

const NOW_ISO = '2026-01-01T12:00:00.000Z';

type LogRecord = { level: string; event: string } & Record<string, unknown>;

function createQueryCacheStub(): {
  queryCache: QueryCacheRepositoryPort;
  deleteExpired: ReturnType<typeof vi.fn>;
} {
  const deleteExpired = vi.fn((_now: Date) => 0);
  return {
    deleteExpired,
    queryCache: {
      get: () => null,
      put: () => undefined,
      delete: () => undefined,
      deleteExpired,
      count: () => 0,
    },
  };
}

function createHarness() {
  const temp = createTempDir();
  const logs: LogRecord[] = [];
  const logger = new Logger({
    level: 'debug',
    sink: (line) => logs.push(JSON.parse(line) as LogRecord),
  });
  const diskCache = new DiskCache({
    directory: temp.child('cache'),
    envelopeVersion: 1,
    maxEntryBytes: 1_000_000,
    logger,
    now: () => new Date(NOW_ISO),
  });
  const cleanupSpy = vi.spyOn(diskCache, 'cleanup').mockResolvedValue({
    scannedFiles: 0,
    removedFiles: 0,
    freedBytes: 0,
    totalBytes: 0,
  });
  const { queryCache, deleteExpired: queryCacheDeleteExpired } = createQueryCacheStub();
  const repositoryDeleteExpired = vi.fn((_now: Date) => 3);
  const repositories: CacheCleanupTarget[] = [
    { name: 'cves', deleteExpired: repositoryDeleteExpired },
  ];
  const clock = { now: () => new Date(NOW_ISO) };

  return {
    temp,
    logger,
    diskCache,
    cleanupSpy,
    queryCache,
    queryCacheDeleteExpired,
    repositoryDeleteExpired,
    repositories,
    clock,
    events: (): string[] => logs.map((record) => record.event),
    findLogs: (event: string): LogRecord[] => logs.filter((record) => record.event === event),
  };
}

async function flushMicrotasks(rounds = 5): Promise<void> {
  for (let index = 0; index < rounds; index += 1) {
    await Promise.resolve();
  }
}

let harness: ReturnType<typeof createHarness>;

beforeEach(() => {
  harness = createHarness();
});

afterEach(() => {
  vi.useRealTimers();
  harness.temp.cleanup();
});

describe('startCacheCleanup', () => {
  it('deletes expired rows in every repository and runs the disk cleanup once', async () => {
    const handle = startCacheCleanup({
      diskCache: harness.diskCache,
      queryCache: harness.queryCache,
      repositories: harness.repositories,
      maxBytes: 4_096,
      maxAgeMs: 0,
      intervalMs: 0,
      logger: harness.logger,
      clock: harness.clock,
    });

    await handle.runOnce();

    const expectedNow = new Date(NOW_ISO);
    expect(harness.queryCacheDeleteExpired).toHaveBeenCalledTimes(1);
    expect(harness.queryCacheDeleteExpired).toHaveBeenCalledWith(expectedNow);
    expect(harness.repositoryDeleteExpired).toHaveBeenCalledTimes(1);
    expect(harness.repositoryDeleteExpired).toHaveBeenCalledWith(expectedNow);
    expect(harness.cleanupSpy).toHaveBeenCalledTimes(1);
    expect(harness.cleanupSpy).toHaveBeenCalledWith({
      maxBytes: 4_096,
      maxAgeMs: Number.MAX_SAFE_INTEGER,
    });

    const cleanupLogs = harness.findLogs('cache_cleanup');
    expect(cleanupLogs).toHaveLength(1);
    expect(cleanupLogs[0]?.queryCacheDeleted).toBe(0);
    expect(cleanupLogs[0]?.repositories).toEqual({ cves: 3 });
    expect(cleanupLogs[0]?.failedTargets).toEqual([]);
    expect(harness.events()).not.toContain('cache_cleanup_failed');
  });

  it('forwards a positive maxAgeMs to the disk cache', async () => {
    const handle = startCacheCleanup({
      diskCache: harness.diskCache,
      queryCache: harness.queryCache,
      repositories: harness.repositories,
      maxBytes: 1_024,
      maxAgeMs: 60_000,
      intervalMs: 0,
      logger: harness.logger,
      clock: harness.clock,
    });

    await handle.runOnce();

    expect(harness.cleanupSpy).toHaveBeenCalledWith({ maxBytes: 1_024, maxAgeMs: 60_000 });
  });

  it('is resilient when the disk cleanup throws', async () => {
    harness.cleanupSpy.mockRejectedValueOnce(new Error('disk unavailable'));
    const handle = startCacheCleanup({
      diskCache: harness.diskCache,
      queryCache: harness.queryCache,
      repositories: harness.repositories,
      maxBytes: 1_024,
      maxAgeMs: 0,
      intervalMs: 0,
      logger: harness.logger,
      clock: harness.clock,
    });

    await expect(handle.runOnce()).resolves.toBeUndefined();

    const failures = harness.findLogs('cache_cleanup_failed');
    expect(failures).toHaveLength(1);
    expect(failures[0]?.target).toBe('disk_cache');
    expect(harness.findLogs('cache_cleanup')).toHaveLength(1);
  });

  it('is resilient when a repository throws', async () => {
    const failingRepository: CacheCleanupTarget = {
      name: 'cves',
      deleteExpired: () => {
        throw new Error('database is locked');
      },
    };
    const handle = startCacheCleanup({
      diskCache: harness.diskCache,
      queryCache: harness.queryCache,
      repositories: [failingRepository],
      maxBytes: 1_024,
      maxAgeMs: 0,
      intervalMs: 0,
      logger: harness.logger,
      clock: harness.clock,
    });

    await expect(handle.runOnce()).resolves.toBeUndefined();

    const failures = harness.findLogs('cache_cleanup_failed');
    expect(failures).toHaveLength(1);
    expect(failures[0]?.target).toBe('cves');
    expect(harness.cleanupSpy).toHaveBeenCalledTimes(1);
    expect(harness.findLogs('cache_cleanup')).toHaveLength(1);
  });

  it('runs periodically and stop() clears the interval', async () => {
    vi.useFakeTimers();
    const handle = startCacheCleanup({
      diskCache: harness.diskCache,
      queryCache: harness.queryCache,
      repositories: harness.repositories,
      maxBytes: 1_024,
      maxAgeMs: 0,
      intervalMs: 1_000,
      logger: harness.logger,
      clock: harness.clock,
    });

    await vi.advanceTimersByTimeAsync(1_000);
    await flushMicrotasks();
    expect(harness.cleanupSpy).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1_000);
    await flushMicrotasks();
    expect(harness.cleanupSpy).toHaveBeenCalledTimes(2);

    handle.stop();
    await vi.advanceTimersByTimeAsync(5_000);
    await flushMicrotasks();
    expect(harness.cleanupSpy).toHaveBeenCalledTimes(2);

    handle.stop();
    await flushMicrotasks();
    expect(harness.cleanupSpy).toHaveBeenCalledTimes(2);
  });
});
