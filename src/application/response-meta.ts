import type { CacheMeta } from '../domain/cache.js';
import type { PaginationMeta } from '../domain/pagination.js';
import type { DateWindow } from '../domain/queries.js';

/**
 * Ordering guarantees the server attaches to a collection.
 *
 * `nvd_default` means the NVD API's own ordering is used as-is; the two `*_desc` values are the
 * server-applied reversal of the ascending date-range results, and `change_created_asc` is the
 * natural creation order of the change history feed.
 */
export const RESPONSE_ORDERINGS = [
  'published_desc',
  'last_modified_desc',
  'change_created_asc',
  'nvd_default',
] as const;

export type ResponseOrdering = (typeof RESPONSE_ORDERINGS)[number];

/**
 * Response metadata attached to every tool result.
 *
 * Extends the cache block with resource-specific context. Warnings are plain strings that never
 * contain credentials, stack traces or raw payloads.
 */
export type ResponseMeta = CacheMeta & {
  /** Ordering guarantee of the returned collection (for example `published_desc`). */
  ordering?: ResponseOrdering;
  /** Resolved date window, when the query was time bounded. */
  window?: DateWindow;
  /** Filters evaluated locally because the NVD API cannot express them. */
  filtersAppliedClientSide?: string[];
  /** Number of upstream rows dropped by local filters. */
  filteredOut?: number;
  /** Item fields kept by the `fields` projection; absent when no projection was requested. */
  fieldsApplied?: string[];
};

/**
 * Echoes the applied projection, which separates a key dropped because the record has no such value
 * from a key that was never requested. The field is absent when every key was returned.
 */
export function withFieldsApplied<T extends ResponseMeta>(
  meta: T,
  fields: readonly string[] | undefined,
): T {
  if (fields === undefined) {
    return meta;
  }
  return { ...meta, fieldsApplied: [...fields] };
}

/**
 * Builds the pagination block every list tool returns.
 *
 * `page` comes from the cursor rather than from the offset: the descending feeds read their first
 * page from the end of the window, so an offset-derived ordinal would report the wrong page.
 * `pageCount` divides the upstream total, which the API recomputes on every call, so it is an
 * estimate for the walk in progress rather than a fixed number of pages.
 *
 * `returned` counts the items the response actually carries, which is 0 when `metaOnly` suppresses
 * them; `totalResults`, `hasMore` and the cursor still describe the page either way.
 */
export function buildPaginationMeta(args: {
  page: number;
  pageSize: number;
  returned: number;
  totalResults: number;
  hasMore: boolean;
  nextCursor: string | null;
}): PaginationMeta {
  return {
    page: args.page,
    pageCount: Math.max(1, Math.ceil(args.totalResults / args.pageSize)),
    pageSize: args.pageSize,
    returned: args.returned,
    totalResults: args.totalResults,
    hasMore: args.hasMore,
    nextCursor: args.nextCursor,
  };
}
