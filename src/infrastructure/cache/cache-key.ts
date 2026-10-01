import { buildCacheKey } from '../../shared/json.js';

/**
 * Identity of a cacheable query.
 *
 * `queryHash` and `cacheKey` are intentionally the exact same `sha256:<64 hex>` string and are
 * produced by a single `buildCacheKey` call:
 *
 * - `queryHash` is embedded in opaque cursors, so a cursor can only be replayed against the
 *   identical canonicalized query.
 * - `cacheKey` is the query cache key.
 *
 * Because both come from one call, a cursor's `queryHash` and the cache key can never disagree.
 * `DiskCache` uses the same digest for the file name (with the `sha256:` prefix stripped).
 */
export type QueryIdentity = {
  queryHash: string;
  cacheKey: string;
};

function identityFor(resource: string, payload: Record<string, unknown>): QueryIdentity {
  const hash = buildCacheKey(resource, payload);
  return { queryHash: hash, cacheKey: hash };
}

/** Identity for a list/search query. `pageSize` participates only when provided. */
export function buildQueryIdentity(resource: string, query: unknown, pageSize?: number): QueryIdentity {
  const payload: Record<string, unknown> = { query };
  if (pageSize !== undefined) {
    payload.pageSize = pageSize;
  }
  return identityFor(resource, payload);
}

/** Identity for a single entity lookup (CVE detail, CPE detail, ...). */
export function buildEntityIdentity(resource: string, id: string): QueryIdentity {
  return identityFor(resource, { id });
}
