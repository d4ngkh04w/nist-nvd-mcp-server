import type { CacheMeta } from '../domain/cache.js';
import type { DateWindow } from '../domain/queries.js';

/**
 * Response metadata attached to every tool result.
 *
 * Extends the cache block with resource-specific context. Warnings are human-readable strings
 * that never contain credentials, stack traces or raw payloads.
 */
export type ResponseMeta = CacheMeta & {
  /** Ordering guarantee of the returned collection (for example `published_desc`). */
  ordering?: string;
  /** Resolved date window, when the query was time bounded. */
  window?: DateWindow;
  /** Filters that had to be evaluated locally because the NVD API rejects them. */
  filtersAppliedClientSide?: string[];
  /** Number of upstream rows dropped by client-side filters. */
  filteredOut?: number;
};

export function withMeta(meta: CacheMeta, extra: Omit<ResponseMeta, keyof CacheMeta>): ResponseMeta {
  const result: ResponseMeta = { ...meta, warnings: [...meta.warnings] };
  if (extra.ordering !== undefined) {
    result.ordering = extra.ordering;
  }
  if (extra.window !== undefined) {
    result.window = extra.window;
  }
  if (extra.filtersAppliedClientSide !== undefined && extra.filtersAppliedClientSide.length > 0) {
    result.filtersAppliedClientSide = [...extra.filtersAppliedClientSide];
  }
  if (extra.filteredOut !== undefined && extra.filteredOut > 0) {
    result.filteredOut = extra.filteredOut;
  }
  return result;
}
