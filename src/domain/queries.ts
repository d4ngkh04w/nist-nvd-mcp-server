/**
 * Canonical internal query models.
 *
 * A canonical query is a plain, JSON-serializable object with only defined values.
 * Cache keys and cursor hashes are derived from it, so it must never contain credentials,
 * resolved timestamps (when avoidable) or upstream offsets.
 */

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type CvssVersion = '2' | '3' | '3.1' | '4';

export type DateWindow = {
  start: string;
  end: string;
};

export type CvssFilter = {
  version: CvssVersion;
  severity?: Severity;
  metrics?: string;
};

/** Filters accepted by `/cves/2.0`. */
export type CveQuery = {
  cveIds?: string[];
  keyword?: string;
  keywordExactMatch?: boolean;
  cpeName?: string;
  virtualMatchString?: string;
  cweId?: string;
  sourceIdentifier?: string;
  vulnStatuses?: string[];
  cvss?: CvssFilter;
  published?: DateWindow;
  lastModified?: DateWindow;
  kevOnly?: boolean;
  /** Forwarded upstream as `kevStartDate`/`kevEndDate`. */
  kevAddedBetween?: DateWindow;
  noRejected?: boolean;
  hasCertAlerts?: boolean;
  hasCertNotes?: boolean;
  hasOval?: boolean;
  /** Forwarded upstream as the valueless `isVulnerable` flag; NVD only accepts it together with `cpeName`. */
  isVulnerable?: boolean;
};

/** Filters accepted by `/cvehistory/2.0`. */
export type CveHistoryQuery = {
  cveId: string;
  eventName?: string;
  changeBetween?: DateWindow;
};

/** Filters accepted by `/cpes/2.0`. */
export type CpeQuery = {
  keyword?: string;
  keywordExactMatch?: boolean;
  cpeMatchString?: string;
  cpeNameId?: string;
  matchCriteriaId?: string;
  lastModified?: DateWindow;
  /** Applied locally: `/cpes/2.0` answers HTTP 404 for the upstream `includeDeprecated` parameter. */
  includeDeprecated?: boolean;
};

/** Filters accepted by `/cpematch/2.0`. */
export type CpeMatchQuery = {
  cveId?: string;
  matchCriteriaId?: string;
  matchStringSearch?: string;
  lastModified?: DateWindow;
};

export type NvdPageRequest = {
  startIndex: number;
  resultsPerPage: number;
};

export type NvdPageMeta = {
  startIndex: number;
  resultsPerPage: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string | null;
};

export type NvdPage<T> = {
  meta: NvdPageMeta;
  items: T[];
};

/** Domain entity paired with the raw upstream payload it was mapped from. */
export type WithRaw<T> = {
  value: T;
  raw: unknown;
};

/** Payload persisted for a paginated query (shared by SQLite and the disk cache). */
export type CachedPage<T> = {
  items: T[];
  totalResults: number;
  /** NVD offset this page was fetched from. */
  startIndex: number;
  /** Page size requested from NVD (for descending resources this may shrink on the last page). */
  resultsPerPage: number;
  /** Number of upstream rows the page consumed, before local filtering. */
  upstreamCount: number;
  /** Number of upstream rows removed by local filters. */
  filteredOut: number;
  /** Names of the filters that had to be applied locally. */
  clientSideFilters: string[];
};
