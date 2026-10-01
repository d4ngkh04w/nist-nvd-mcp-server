import type { CacheResourceDirectory } from '../config/defaults.js';

/** Where a cached payload came from. */
export type CacheSource = 'cache' | 'nvd';

/**
 * How the current result was produced:
 * - `hit`: fresh cache entry, NVD was not contacted.
 * - `miss`: no cached copy existed, NVD returned the data.
 * - `refresh`: a stale copy existed and was successfully refreshed from NVD.
 * - `stale_fallback`: NVD failed, the stale copy was returned instead.
 */
export type CacheStatus = 'hit' | 'miss' | 'refresh' | 'stale_fallback';

export type CacheMeta = {
  source: CacheSource;
  cacheStatus: CacheStatus;
  fetchedAt: string;
  expiresAt: string;
  ageSeconds: number;
  stale: boolean;
  warnings: string[];
};

/** A cached payload together with its freshness window. */
export type StoredValue<T> = {
  value: T;
  fetchedAt: string;
  expiresAt: string;
};

export type CacheResource =
  | 'cve'
  | 'cve-search'
  | 'cve-history'
  | 'cpe'
  | 'cpe-search'
  | 'cpe-match';

/** Mapping from logical resource to disk cache directory. */
export const CACHE_RESOURCE_DIRECTORY: Record<CacheResource, CacheResourceDirectory> = {
  cve: 'cves',
  'cve-search': 'searches',
  'cve-history': 'cve-history',
  cpe: 'cpes',
  'cpe-search': 'cpes',
  'cpe-match': 'cpe-matches',
};

export function cacheSourceFor(status: CacheStatus): CacheSource {
  return status === 'miss' || status === 'refresh' ? 'nvd' : 'cache';
}

export type CreateCacheMetaInput = {
  status: CacheStatus;
  fetchedAt: string;
  expiresAt: string;
  ageSeconds: number;
  stale?: boolean;
  warnings?: string[];
};

export function createCacheMeta(input: CreateCacheMetaInput): CacheMeta {
  return {
    source: cacheSourceFor(input.status),
    cacheStatus: input.status,
    fetchedAt: input.fetchedAt,
    expiresAt: input.expiresAt,
    ageSeconds: input.ageSeconds,
    stale: input.stale ?? input.status === 'stale_fallback',
    warnings: input.warnings ?? [],
  };
}
