import type { CpeRecord } from '../domain/cpe.js';
import type { CpeQuery } from '../domain/queries.js';

export type ClientFilterOutcome<T> = {
  items: T[];
  filteredOut: number;
  applied: string[];
};

/**
 * Local filters that remain after every supported NVD parameter is forwarded upstream.
 *
 * CVE filters (`vulnStatuses`, `isVulnerable`, `kevStartDate`/`kevEndDate`) are forwarded to NVD,
 * so no CVE-side local filtering happens any more. The only remaining local policy is the CPE
 * dictionary: the CPE API rejects `includeDeprecated` with HTTP 404 and still returns deprecated
 * entries in its default result set, so the include/exclude decision is applied here and reported
 * through `meta.filtersAppliedClientSide` / `meta.filteredOut`.
 *
 * Because a local filter can drop rows from an upstream page, the top-level `pagination.totalResults`
 * is the *upstream* total (pre-filter) and `pagination.hasMore` tracks the upstream offset walk,
 * not the size of the filtered set.
 */
export function applyCpeQueryFilters(
  items: readonly CpeRecord[],
  query: CpeQuery,
): ClientFilterOutcome<CpeRecord> {
  if (query.includeDeprecated === true) {
    return {
      items: [...items],
      filteredOut: 0,
      applied: ['includeDeprecated'],
    };
  }
  const filtered = items.filter((item) => !item.deprecated);
  return {
    items: filtered,
    filteredOut: items.length - filtered.length,
    applied: [],
  };
}
