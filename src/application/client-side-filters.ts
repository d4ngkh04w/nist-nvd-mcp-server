import type { CpeRecord } from '../domain/cpe.js';
import type { CpeQuery } from '../domain/queries.js';

export type ClientFilterOutcome<T> = {
  items: T[];
  filteredOut: number;
  applied: string[];
};

/**
 * Local filtering that the NVD API cannot express.
 *
 * `/cves/2.0` accepts every supported CVE filter upstream (`vulnStatuses`, `isVulnerable`,
 * `kevStartDate`/`kevEndDate`), so CVE pages are never filtered locally. The CPE dictionary is the
 * exception: `/cpes/2.0` answers HTTP 404 for `includeDeprecated` while still returning deprecated
 * entries in its default result set, so the include/exclude decision is applied here and reported
 * through `meta.filtersAppliedClientSide` / `meta.filteredOut`.
 *
 * A local filter can drop rows from an upstream page, so `pagination.totalResults` is the upstream
 * total counted before the filter, and `pagination.hasMore` follows the upstream offset walk rather
 * than the size of the filtered set.
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
