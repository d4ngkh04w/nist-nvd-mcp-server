import { describe, expect, it, vi } from 'vitest';

import { CachedResourceLoader, type LoadOptions } from '../../src/application/cached-resource-loader.js';
import { CACHE_ENVELOPE_VERSION } from '../../src/config/defaults.js';
import type { CacheResource, StoredValue } from '../../src/domain/cache.js';
import { DomainError } from '../../src/domain/errors.js';
import type { Clock } from '../../src/domain/ports.js';
import type { DiskCache, DiskCacheEnvelope } from '../../src/infrastructure/cache/disk-cache.js';
import { SingleFlight } from '../../src/shared/async.js';
import { Logger } from '../../src/shared/logger.js';

const NOW_ISO = '2026-01-15T12:00:00.000Z';
const CACHE_KEY = `sha256:${'a'.repeat(64)}`;
const RESOURCE: CacheResource = 'cve';

type LogRecord = { level: string; event: string } & Record<string, unknown>;

/** Tiny local clock helper: this file must not depend on `tests/helpers/harness.ts`. */
type LocalClock = Clock & {
  set(iso: string): void;
};

function createLocalClock(startIso: string): LocalClock {
  let current = new Date(startIso);
  return {
    now: () => new Date(current),
    set: (iso: string) => {
      current = new Date(iso);
    },
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function storageKey(resource: CacheResource, key: string): string {
  return `${resource}:${key}`;
}

function staleEntry(): StoredValue<string> {
  return {
    value: 'stale',
    fetchedAt: '2026-01-14T12:00:00.000Z',
    expiresAt: '2026-01-15T11:00:00.000Z',
  };
}

function diskEnvelope<T>(
  resource: CacheResource,
  queryHash: string,
  payload: T,
  overrides: { createdAt?: string; expiresAt?: string } = {},
): DiskCacheEnvelope<T> {
  return {
    version: CACHE_ENVELOPE_VERSION,
    resource,
    queryHash,
    createdAt: overrides.createdAt ?? NOW_ISO,
    expiresAt: overrides.expiresAt ?? '2099-01-01T00:00:00.000Z',
    payload,
  };
}

function expectRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('expected a plain object');
  }
  return value as Record<string, unknown>;
}

async function captureAsyncDomainError(promise: Promise<unknown>): Promise<DomainError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof DomainError) {
      return error;
    }
    throw error;
  }
  throw new Error('Expected the promise to reject with a DomainError');
}

function createContext() {
  const clock = createLocalClock(NOW_ISO);
  const logs: LogRecord[] = [];
  const logger = new Logger({
    level: 'debug',
    sink: (line) => logs.push(JSON.parse(line) as LogRecord),
  });

  // A `DiskCache`-shaped stub: `read` resolves null unless a test seeds it, `write` resolves true.
  const diskEntries = new Map<string, DiskCacheEnvelope<unknown>>();
  const diskRead = vi.fn(async (resource: CacheResource, key: string) =>
    diskEntries.get(storageKey(resource, key)) ?? null,
  );
  const diskWrite = vi.fn(async (envelope: DiskCacheEnvelope<unknown>) => {
    diskEntries.set(storageKey(envelope.resource, envelope.queryHash), envelope);
    return true;
  });
  const diskCache = { read: diskRead, write: diskWrite } as unknown as DiskCache;
  const singleFlight = new SingleFlight();
  const loader = new CachedResourceLoader({ diskCache, singleFlight, clock, logger });

  return {
    loader,
    clock,
    singleFlight,
    diskRead,
    diskWrite,
    diskEntries,
    events: () => logs.map((record) => record.event),
    seedDisk: (resource: CacheResource, key: string, envelope: DiskCacheEnvelope<unknown>): void => {
      diskEntries.set(storageKey(resource, key), envelope);
    },
  };
}

type TestContext = ReturnType<typeof createContext>;

function baseOptions(overrides: Partial<LoadOptions<string>> = {}): LoadOptions<string> {
  const defaults: LoadOptions<string> = {
    resource: RESOURCE,
    cacheKey: CACHE_KEY,
    ttlSeconds: 300,
    readCached: () => null,
    writeCached: () => undefined,
    fetchUpstream: () => Promise.resolve({ found: true as const, value: 'fresh-from-nvd' }),
  };
  return { ...defaults, ...overrides };
}

describe('CachedResourceLoader cache policy', () => {
  it('serves a fresh SQLite entry as a hit without touching NVD or the disk cache', async () => {
    const ctx: TestContext = createContext();
    const fetchUpstream = vi.fn(async () => ({ found: true as const, value: 'from-nvd' }));

    const result = await ctx.loader.load(
      baseOptions({
        readCached: () => ({
          value: 'from-sqlite',
          fetchedAt: '2026-01-15T11:59:00.000Z',
          expiresAt: '2026-01-15T12:05:00.000Z',
        }),
        fetchUpstream,
      }),
    );

    expect(result.value).toBe('from-sqlite');
    expect(result.meta.cacheStatus).toBe('hit');
    expect(result.meta.source).toBe('cache');
    expect(result.meta.stale).toBe(false);
    expect(result.meta.ageSeconds).toBe(60);
    expect(result.meta.warnings).toEqual([]);
    expect(fetchUpstream).not.toHaveBeenCalled();
    expect(ctx.diskRead).not.toHaveBeenCalled();
  });

  it('refreshes an expired entry and writes it to SQLite and the disk cache', async () => {
    const ctx: TestContext = createContext();
    const writeCached = vi.fn();
    const fetchUpstream = vi.fn(async () => ({
      found: true as const,
      value: 'refreshed',
      raw: { id: 'CVE-2024-3094' },
    }));

    const result = await ctx.loader.load(
      baseOptions({
        readCached: () => staleEntry(),
        writeCached,
        fetchUpstream,
      }),
    );

    expect(result.value).toBe('refreshed');
    expect(result.raw).toEqual({ id: 'CVE-2024-3094' });
    expect(result.meta.cacheStatus).toBe('refresh');
    expect(result.meta.source).toBe('nvd');
    expect(result.meta.stale).toBe(false);
    expect(result.meta.ageSeconds).toBe(0);
    expect(fetchUpstream).toHaveBeenCalledTimes(1);

    expect(writeCached).toHaveBeenCalledTimes(1);
    expect(writeCached).toHaveBeenCalledWith({
      value: 'refreshed',
      raw: { id: 'CVE-2024-3094' },
      fetchedAt: NOW_ISO,
      expiresAt: '2026-01-15T12:05:00.000Z',
    });

    expect(ctx.diskWrite).toHaveBeenCalledTimes(1);
    const envelope = ctx.diskWrite.mock.calls[0]?.[0];
    expect(envelope?.version).toBe(CACHE_ENVELOPE_VERSION);
    expect(envelope?.resource).toBe('cve');
    expect(envelope?.queryHash).toBe(CACHE_KEY);
    expect(envelope?.createdAt).toBe(NOW_ISO);
    expect(envelope?.expiresAt).toBe('2026-01-15T12:05:00.000Z');
    expect(expectRecord(envelope?.payload)['value']).toBe('refreshed');
    expect(expectRecord(envelope?.payload)['raw']).toEqual({ id: 'CVE-2024-3094' });
  });

  it('serves stale data with a warning when the refresh fails', async () => {
    const ctx: TestContext = createContext();

    const result = await ctx.loader.load(
      baseOptions({
        readCached: () => staleEntry(),
        fetchUpstream: async () => {
          throw DomainError.upstreamUnavailable('NVD is unavailable');
        },
      }),
    );

    expect(result.value).toBe('stale');
    expect(result.meta.cacheStatus).toBe('stale_fallback');
    expect(result.meta.source).toBe('cache');
    expect(result.meta.stale).toBe(true);
    expect(result.meta.fetchedAt).toBe('2026-01-14T12:00:00.000Z');
    expect(result.meta.ageSeconds).toBe(86_400);
    expect(
      result.meta.warnings.some((warning) => warning.includes('UPSTREAM_UNAVAILABLE')),
    ).toBe(true);
    expect(ctx.events()).toContain('cache_stale_fallback');
  });

  it('propagates the upstream error when there is no cached copy', async () => {
    const ctx: TestContext = createContext();

    const error = await captureAsyncDomainError(
      ctx.loader.load(
        baseOptions({
          readCached: () => null,
          fetchUpstream: async () => {
            throw DomainError.upstreamUnavailable('NVD is unavailable');
          },
        }),
      ),
    );

    expect(error.code).toBe('UPSTREAM_UNAVAILABLE');
  });

  it('throws the not-found error instead of falling back to stale data', async () => {
    const ctx: TestContext = createContext();

    const error = await captureAsyncDomainError(
      ctx.loader.load(
        baseOptions({
          readCached: () => staleEntry(),
          fetchUpstream: async () => ({ found: false as const }),
          notFound: () => DomainError.notFound('CVE_NOT_FOUND', 'No CVE with that identifier'),
        }),
      ),
    );

    expect(error.code).toBe('CVE_NOT_FOUND');
  });

  it('treats a SQLite read failure as a miss and still succeeds', async () => {
    const ctx: TestContext = createContext();

    const result = await ctx.loader.load(
      baseOptions({
        readCached: () => {
          throw new Error('sqlite is locked');
        },
      }),
    );

    expect(result.value).toBe('fresh-from-nvd');
    expect(result.meta.cacheStatus).toBe('miss');
    expect(result.meta.source).toBe('nvd');
    expect(result.meta.warnings.some((warning) => warning.includes('could not be read'))).toBe(true);
    expect(ctx.events()).toContain('cache_read_failed');
  });

  it('does not fail the request when the SQLite write fails', async () => {
    const ctx: TestContext = createContext();

    const result = await ctx.loader.load(
      baseOptions({
        writeCached: () => {
          throw new Error('database is read-only');
        },
      }),
    );

    expect(result.value).toBe('fresh-from-nvd');
    expect(result.meta.cacheStatus).toBe('miss');
    expect(result.meta.warnings.some((warning) => warning.includes('could not be persisted'))).toBe(
      true,
    );
    expect(ctx.events()).toContain('cache_write_failed');
    // The disk write is still attempted so the next process run can serve the value.
    expect(ctx.diskWrite).toHaveBeenCalledTimes(1);
  });

  it('uses a fresh disk entry and backfills SQLite when it has no row', async () => {
    const ctx: TestContext = createContext();
    ctx.seedDisk(
      RESOURCE,
      CACHE_KEY,
      diskEnvelope(
        RESOURCE,
        CACHE_KEY,
        { value: 'from-disk', raw: { fromDisk: true } },
        { createdAt: '2026-01-15T11:30:00.000Z', expiresAt: '2026-01-15T12:30:00.000Z' },
      ),
    );
    const fetchUpstream = vi.fn(async () => ({ found: true as const, value: 'from-nvd' }));
    const writeCached = vi.fn();

    const result = await ctx.loader.load(
      baseOptions({ readCached: () => null, writeCached, fetchUpstream }),
    );

    expect(result.value).toBe('from-disk');
    expect(result.raw).toEqual({ fromDisk: true });
    expect(result.meta.cacheStatus).toBe('hit');
    expect(result.meta.source).toBe('cache');
    expect(result.meta.fetchedAt).toBe('2026-01-15T11:30:00.000Z');
    expect(result.meta.expiresAt).toBe('2026-01-15T12:30:00.000Z');
    expect(fetchUpstream).not.toHaveBeenCalled();

    expect(writeCached).toHaveBeenCalledTimes(1);
    expect(writeCached).toHaveBeenCalledWith({
      value: 'from-disk',
      raw: { fromDisk: true },
      fetchedAt: '2026-01-15T11:30:00.000Z',
      expiresAt: '2026-01-15T12:30:00.000Z',
    });
  });

  it('de-duplicates concurrent loads for the same resource and cache key', async () => {
    const ctx: TestContext = createContext();
    const fetchA = vi.fn(async () => {
      await delay(20);
      return { found: true as const, value: 'shared' };
    });
    const fetchB = vi.fn(async () => {
      await delay(20);
      return { found: true as const, value: 'shared' };
    });

    const [first, second] = await Promise.all([
      ctx.loader.load(baseOptions({ readCached: () => null, fetchUpstream: fetchA })),
      ctx.loader.load(baseOptions({ readCached: () => null, fetchUpstream: fetchB })),
    ]);

    expect(first.value).toBe('shared');
    expect(second.value).toBe('shared');
    expect(first.meta.cacheStatus).toBe('miss');
    expect(second.meta.cacheStatus).toBe('miss');
    expect(fetchA.mock.calls.length + fetchB.mock.calls.length).toBe(1);
  });
});
