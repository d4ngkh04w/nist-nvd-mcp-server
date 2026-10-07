import { MAX_QUERY_CACHE_PAYLOAD_BYTES } from '../config/defaults.js';
import type { CacheMeta } from '../domain/cache.js';
import type { CveDetails, CveSummary } from '../domain/cve.js';
import { DomainError } from '../domain/errors.js';
import type { CursorPayload } from '../domain/pagination.js';
import type { NvdCveClientPort, QueryCacheRepositoryPort } from '../domain/ports.js';
import type { CachedPage, CveQuery, NvdPage, NvdPageRequest, WithRaw } from '../domain/queries.js';
import { buildQueryIdentity } from '../infrastructure/cache/cache-key.js';
import { byteLength } from '../shared/json.js';
import { currentOperation, throwIfCancelled } from '../shared/operation.js';
import type { CachedResourceLoader } from './cached-resource-loader.js';

/** NVD sorts by publication even with lastMod filters: load the bounded set before sorting. */
export const MAX_MODIFIED_FEED_RESULTS = 10_000;
const UPSTREAM_PAGE_SIZE = 2_000;

export async function loadModifiedFeedPage(args: {
  query: CveQuery;
  pageSize: number;
  cursor: CursorPayload | null;
  ttlSeconds: number;
  maxStartIndex: number;
  loader: CachedResourceLoader;
  queryCache: QueryCacheRepositoryPort;
  client: NvdCveClientPort;
  mapPage(page: NvdPage<WithRaw<CveDetails>>, request: NvdPageRequest): CachedPage<CveSummary>;
}): Promise<{ page: CachedPage<CveSummary>; meta: CacheMeta }> {
  const identity = buildQueryIdentity('cve-search', { query: args.query, modifiedSnapshot: 1 }, args.pageSize);
  const unavailable = () => DomainError.invalidCursor(
    'Modified feed snapshot is unavailable or replaced; restart pagination without a cursor',
    { reason: 'expired' },
  );
  const result = await args.loader.load<CachedPage<CveSummary>>({
    resource: 'cve-search', cacheKey: identity.cacheKey, ttlSeconds: args.ttlSeconds,
    cacheOnly: args.cursor !== null,
    notFound: unavailable,
    readCached: () => args.queryCache.get<CachedPage<CveSummary>>(identity.cacheKey),
    writeCached: record => args.queryCache.put({
      cacheKey: identity.cacheKey, resource: 'cve-search', queryHash: identity.queryHash,
      value: record.value, createdAt: record.fetchedAt, fetchedAt: record.fetchedAt, expiresAt: record.expiresAt,
    }),
    fetchUpstream: async () => {
      const items: CveSummary[] = [];
      let total: number | undefined;
      let requests = 0;
      const limit = Math.min(MAX_MODIFIED_FEED_RESULTS, args.maxStartIndex + args.pageSize);
      do {
        throwIfCancelled();
        if (++requests > Math.ceil(MAX_MODIFIED_FEED_RESULTS / UPSTREAM_PAGE_SIZE)) {
          throw DomainError.upstreamBadResponse('Modified feed could not be loaded within the request budget; narrow the date window');
        }
        const request = { startIndex: items.length, resultsPerPage: UPSTREAM_PAGE_SIZE };
        const upstream = await args.client.search(args.query, request);
        if (upstream.meta.totalResults > limit) {
          throw DomainError.invalidInput(
            `Modified feed exceeds ${limit} CVEs; narrow the date window or filters, or use nvd_search_cves`,
            { totalResults: upstream.meta.totalResults, maxResults: limit },
          );
        }
        total ??= upstream.meta.totalResults;
        if (upstream.meta.totalResults !== total || upstream.meta.startIndex !== request.startIndex ||
            (upstream.items.length === 0 && items.length < total) ||
            items.length + upstream.items.length > total) {
          throw DomainError.upstreamBadResponse('Modified feed changed or returned an incomplete page; retry');
        }
        items.push(...args.mapPage(upstream, request).items);
        currentOperation()?.onProgress?.(`Loaded ${items.length} of ${total} modified CVEs`);
        if (byteLength(JSON.stringify(items)) > MAX_QUERY_CACHE_PAYLOAD_BYTES - 1_024) {
          throw DomainError.invalidInput('Modified feed exceeds the snapshot byte budget; narrow the date window or filters');
        }
      } while (items.length < total);
      if (new Set(items.map(item => item.id)).size !== items.length) {
        throw DomainError.upstreamBadResponse('Modified feed returned duplicate CVEs; retry');
      }
      items.sort((a, b) => a.lastModified.localeCompare(b.lastModified) || a.id.localeCompare(b.id));
      return { found: true, value: {
        items, totalResults: total, startIndex: 0, resultsPerPage: items.length,
        upstreamCount: items.length, filteredOut: 0, clientSideFilters: [],
      } };
    },
  });
  if (args.cursor !== null && args.cursor.snapshotFetchedAt !== result.meta.fetchedAt) throw unavailable();
  const size = args.cursor?.pageSize ?? args.pageSize;
  const startIndex = args.cursor?.startIndex ?? Math.max(0, result.value.items.length - size);
  const items = result.value.items.slice(startIndex, startIndex + size).reverse();
  return {
    page: { ...result.value, items, startIndex, resultsPerPage: size, upstreamCount: items.length },
    meta: result.meta,
  };
}
