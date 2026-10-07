import { createCacheMeta, type CacheMeta, type CacheResource, type StoredValue } from '../domain/cache.js';
import {
  CACHE_ENVELOPE_VERSION,
  CACHE_WRITE_MAX_ATTEMPTS,
  CACHE_WRITE_RETRY_BASE_MS,
} from '../config/defaults.js';
import { DomainError, toDomainError } from '../domain/errors.js';
import type { Clock } from '../domain/ports.js';
import type { DiskCache } from '../infrastructure/cache/disk-cache.js';
import { type SingleFlight, sleep } from '../shared/async.js';
import { safeJsonParse } from '../shared/json.js';
import type { Logger } from '../shared/logger.js';
import { addSeconds, ageSeconds, isExpired, toIso } from '../shared/time.js';

/** Raised when SQLite refused a write because another connection holds the write lock. */
const SQLITE_BUSY_PATTERN = /SQLITE_BUSY|database is locked|database table is locked/i;

/** True for the transient lock contention that is worth retrying instead of dropping the write. */
function isLockContention(error: unknown): boolean {
  const candidates: string[] = [];
  if (error instanceof Error) {
    candidates.push(error.message);
    const cause: unknown = (error as { cause?: unknown }).cause;
    if (cause instanceof Error) {
      candidates.push(cause.message);
    }
  }
  if (error instanceof DomainError && error.cause instanceof Error) {
    candidates.push(error.cause.message);
  }
  return candidates.some((message) => SQLITE_BUSY_PATTERN.test(message));
}

/** A value plus the freshness window and the raw upstream payload it was mapped from. */
export type LoadedRecord<T> = {
  value: T;
  raw?: unknown;
  fetchedAt: string;
  expiresAt: string;
};

export type LoadOptions<T> = {
  resource: CacheResource;
  cacheKey: string;
  ttlSeconds: number;
  /** Reads the SQLite copy (expired rows must still be returned). */
  readCached(): StoredValue<T> | null;
  /** Persists into SQLite; failures must not abort the request. */
  writeCached(record: LoadedRecord<T>): void;
  /** Fetches from NVD through the rate limiter; `found: false` maps to the not-found error. */
  fetchUpstream(): Promise<{ found: true; value: T; raw?: unknown } | { found: false }>;
  /** Error raised when the upstream lookup has no result (defaults to an upstream error). */
  notFound?: () => DomainError;
  /** Extra warnings merged into `meta.warnings`. */
  warnings?: string[];
  /** When true the raw payload is also resolved from SQLite or the disk cache on a hit. */
  needsRaw?: boolean;
  /** Cursor walks must reuse their cached snapshot, never refetch a different result set. */
  cacheOnly?: boolean;
  /**
   * Reads the raw upstream payload persisted next to the cached entity (usually a repository
   * `findRawById`). Used on a fresh SQLite hit before falling back to the disk cache; a missing,
   * corrupt or blank payload is never fatal.
   */
  readRaw?: () => string | null;
};

export type LoadResult<T> = {
  value: T;
  raw?: unknown;
  meta: CacheMeta;
};

const NOT_FOUND_CODES: ReadonlySet<string> = new Set([
  'CVE_NOT_FOUND',
  'CPE_NOT_FOUND',
  'CPE_MATCH_NOT_FOUND',
]);

type DiskPayload<T> = {
  value: T;
  raw?: unknown;
};

/**
 * Cache-first resource loader.
 *
 * 1. fresh SQLite entry -> `hit`, NVD is never contacted;
 * 2. otherwise the disk cache is consulted (and backfilled into SQLite);
 * 3. stale entry -> refresh from NVD, de-duplicated through the single-flight registry;
 * 4. refresh failure with stale data available -> `stale_fallback` + warning;
 * 5. no cached data at all -> the upstream error is propagated.
 */
export class CachedResourceLoader {
  private readonly diskCache: DiskCache;
  private readonly singleFlight: SingleFlight;
  private readonly clock: Clock;
  private readonly logger: Logger;

  constructor(deps: {
    diskCache: DiskCache;
    singleFlight: SingleFlight;
    clock: Clock;
    logger: Logger;
  }) {
    this.diskCache = deps.diskCache;
    this.singleFlight = deps.singleFlight;
    this.clock = deps.clock;
    this.logger = deps.logger;
  }

  async load<T>(options: LoadOptions<T>): Promise<LoadResult<T>> {
    const now = this.clock.now();
    const warnings = [...(options.warnings ?? [])];

    let cached = this.readCachedSafely(options, warnings);
    let raw: unknown;

    if (cached === null) {
      const disk = await this.readFromDisk<T>(options.resource, options.cacheKey);
      if (disk !== null) {
        cached = { value: disk.payload.value, fetchedAt: disk.createdAt, expiresAt: disk.expiresAt };
        raw = disk.payload.raw;
        try {
          const record: LoadedRecord<T> = {
            value: cached.value,
            fetchedAt: cached.fetchedAt,
            expiresAt: cached.expiresAt,
          };
          if (raw !== undefined) {
            record.raw = raw;
          }
          await this.persist(options, () => options.writeCached(record));
        } catch (error) {
          warnings.push('Failed to backfill the local database from the disk cache');
          this.logger.warn('cache_backfill_failed', {
            resource: options.resource,
            error,
          });
        }
      }
    }

    if (cached !== null && (options.cacheOnly === true || !isExpired(cached.expiresAt, now))) {
      if (options.needsRaw === true && raw === undefined) {
        raw = this.readRawFromStore(options);
        if (raw === undefined) {
          const disk = await this.readFromDisk<T>(options.resource, options.cacheKey);
          raw = disk?.payload.raw;
          if (raw === undefined) {
            warnings.push('Raw payload is not available in the local cache; call the tool again to refetch it');
          }
        }
      }
      return {
        value: cached.value,
        raw,
        meta: createCacheMeta({
          status: 'hit',
          fetchedAt: cached.fetchedAt,
          expiresAt: cached.expiresAt,
          ageSeconds: ageSeconds(cached.fetchedAt, now),
          stale: isExpired(cached.expiresAt, now),
          warnings,
        }),
      };
    }

    if (options.cacheOnly === true) {
      throw options.notFound?.() ?? DomainError.cacheCorrupted('Cached snapshot is unavailable');
    }

    const stale = cached;
    const flightKey = `${options.resource}:${options.cacheKey}`;

    try {
      const record = await this.singleFlight.run(flightKey, () =>
        this.refresh(options, now, warnings),
      );
      return {
        value: record.value,
        raw: record.raw,
        meta: createCacheMeta({
          status: stale === null ? 'miss' : 'refresh',
          fetchedAt: record.fetchedAt,
          expiresAt: record.expiresAt,
          ageSeconds: 0,
          warnings,
        }),
      };
    } catch (error) {
      const domainError = toDomainError(error);
      if (stale === null || NOT_FOUND_CODES.has(domainError.code)) {
        throw domainError;
      }
      warnings.push(
        `Served stale cached data because the upstream refresh failed (${domainError.code})`,
      );
      this.logger.warn('cache_stale_fallback', {
        resource: options.resource,
        code: domainError.code,
        retryable: domainError.retryable,
      });
      if (options.needsRaw === true && raw === undefined) {
        raw = this.readRawFromStore(options);
        if (raw === undefined) {
          raw = (await this.readFromDisk<T>(options.resource, options.cacheKey))?.payload.raw;
        }
      }
      return {
        value: stale.value,
        raw,
        meta: createCacheMeta({
          status: 'stale_fallback',
          fetchedAt: stale.fetchedAt,
          expiresAt: stale.expiresAt,
          ageSeconds: ageSeconds(stale.fetchedAt, now),
          stale: true,
          warnings,
        }),
      };
    }
  }

  private readCachedSafely<T>(
    options: LoadOptions<T>,
    warnings: string[],
  ): StoredValue<T> | null {
    try {
      return options.readCached();
    } catch (error) {
      warnings.push('Local cache entry could not be read; the value was refetched from NVD');
      this.logger.warn('cache_read_failed', { resource: options.resource, error });
      return null;
    }
  }

  /**
   * Resolves the raw upstream payload persisted next to the cached entity.
   *
   * `undefined` signals that the disk cache must be consulted instead; a missing row, a read failure
   * and a corrupt payload all produce that signal so a `needsRaw` lookup never fails on its own.
   */
  private readRawFromStore<T>(options: LoadOptions<T>): unknown {
    if (options.readRaw === undefined) {
      return undefined;
    }
    let stored: string | null;
    try {
      stored = options.readRaw();
    } catch (error) {
      this.logger.warn('cache_raw_read_failed', { resource: options.resource, error });
      return undefined;
    }
    if (stored === null) {
      return undefined;
    }
    const parsed = safeJsonParse<unknown>(stored);
    if (!parsed.ok) {
      this.logger.warn('cache_raw_corrupt', { resource: options.resource, error: parsed.error });
      return undefined;
    }
    return parsed.value;
  }

  private async refresh<T>(
    options: LoadOptions<T>,
    now: Date,
    warnings: string[],
  ): Promise<LoadedRecord<T>> {
    const upstream = await options.fetchUpstream();
    if (!upstream.found) {
      throw (
        options.notFound?.() ??
        DomainError.upstreamBadResponse('The upstream lookup returned no result')
      );
    }
    const record: LoadedRecord<T> = {
      value: upstream.value,
      raw: upstream.raw,
      fetchedAt: toIso(now),
      expiresAt: toIso(addSeconds(now, options.ttlSeconds)),
    };
    try {
      await this.persist(options, () => options.writeCached(record));
    } catch (error) {
      warnings.push('The result could not be persisted to the local database');
      this.logger.warn('cache_write_failed', { resource: options.resource, error });
    }
    await this.writeToDisk(options.resource, options.cacheKey, record);
    return record;
  }

  /**
   * Runs a synchronous SQLite write, retrying lock contention.
   *
   * `node:sqlite` blocks the event loop while its busy handler waits, so a contended write is
   * retried here with `await`ed back-off instead of inside SQLite: the request can never stall the
   * whole server, and a write that loses the race for the lock is usually persisted on the next
   * attempt. Any other failure is propagated unchanged.
   */
  private async persist<T>(options: LoadOptions<T>, write: () => void): Promise<void> {
    for (let attempt = 1; attempt <= CACHE_WRITE_MAX_ATTEMPTS; attempt += 1) {
      try {
        write();
        return;
      } catch (error) {
        if (attempt === CACHE_WRITE_MAX_ATTEMPTS || !isLockContention(error)) {
          throw error;
        }
        this.logger.warn('cache_write_retry', {
          resource: options.resource,
          attempt,
          nextAttempt: attempt + 1,
          delayMs: CACHE_WRITE_RETRY_BASE_MS * attempt,
        });
        await sleep(CACHE_WRITE_RETRY_BASE_MS * attempt);
      }
    }
  }

  private async readFromDisk<T>(
    resource: CacheResource,
    cacheKey: string,
  ): Promise<{ payload: DiskPayload<T>; createdAt: string; expiresAt: string } | null> {
    const envelope = await this.diskCache.read<DiskPayload<T>>(resource, cacheKey);
    if (envelope === null) {
      return null;
    }
    const payload = envelope.payload;
    if (
      payload === null ||
      typeof payload !== 'object' ||
      !('value' in (payload as Record<string, unknown>))
    ) {
      this.logger.warn('cache_payload_rejected', { resource });
      return null;
    }
    return { payload, createdAt: envelope.createdAt, expiresAt: envelope.expiresAt };
  }

  private async writeToDisk<T>(
    resource: CacheResource,
    cacheKey: string,
    record: LoadedRecord<T>,
  ): Promise<void> {
    const payload: DiskPayload<T> = { value: record.value };
    if (record.raw !== undefined) {
      payload.raw = record.raw;
    }
    await this.diskCache.write({
      version: CACHE_ENVELOPE_VERSION,
      resource,
      queryHash: cacheKey,
      createdAt: record.fetchedAt,
      expiresAt: record.expiresAt,
      payload,
    });
  }
}
