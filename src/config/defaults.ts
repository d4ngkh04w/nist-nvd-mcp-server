/**
 * Compile-time defaults and hard limits.
 *
 * Every value here can be overridden through environment variables (see `config/env.ts`),
 * except for protocol-level constants such as the NVD date range limit.
 */

/** NVD REST API base URL (v2.0 endpoints are appended by the clients). */
export const NVD_DEFAULT_BASE_URL = 'https://services.nvd.nist.gov/rest/json';

/** NVD rejects date windows longer than 120 days. */
export const MAX_DATE_RANGE_DAYS = 120;

/** Upstream NVD page size bounds (resultsPerPage). */
export const NVD_MIN_RESULTS_PER_PAGE = 1;
export const NVD_MAX_RESULTS_PER_PAGE = 2000;

/** NVD caps comma separated `cveId` filters at 100 identifiers. */
export const MAX_CVE_IDS_PER_REQUEST = 100;

/** Guard rail for opaque cursors: reject absurd offsets instead of hammering NVD. */
export const MAX_NVD_START_INDEX = 100_000;

/** Public pagination limits per resource. */
export const PAGE_SIZE_LIMITS = {
  cves: { default: 20, max: 50 },
  'cve-history': { default: 20, max: 50 },
  cpes: { default: 20, max: 100 },
  'cpe-matches': { default: 20, max: 100 },
} as const;

export type PaginationResourceName = keyof typeof PAGE_SIZE_LIMITS;

/** Default TTLs (seconds) per cache resource. */
export const DEFAULT_TTL_SECONDS = {
  cve: 86_400,
  cveSearch: 900,
  recent: 300,
  modified: 300,
  history: 3_600,
  cpeDetail: 604_800,
  cpeSearch: 86_400,
  cpeMatch: 86_400,
} as const;

/** Rate limiting, retry and timeout defaults. */
export const DEFAULT_NVD_MIN_INTERVAL_MS = 6_000;
export const DEFAULT_NVD_MAX_CONCURRENCY = 1;
export const DEFAULT_NVD_REQUEST_TIMEOUT_MS = 15_000;
export const DEFAULT_NVD_MAX_RETRIES = 4;
export const DEFAULT_RETRY_BASE_DELAY_MS = 1_000;
export const MAX_RETRY_DELAY_MS = 30_000;

/** HTTP status codes that are worth retrying. */
export const RETRYABLE_STATUS_CODES: readonly number[] = [429, 500, 502, 503, 504];

/** HTTP status codes that must never be retried. */
export const NON_RETRYABLE_STATUS_CODES: readonly number[] = [400, 401, 403, 404, 422];

/** Default cursor TTL. */
export const DEFAULT_CURSOR_TTL_SECONDS = 1_800;
export const CURSOR_VERSION = 1;
export const MAX_CURSOR_LENGTH = 4_096;

/** Disk cache defaults. */
export const CACHE_ENVELOPE_VERSION = 1;
export const DEFAULT_CACHE_MAX_SIZE_MB = 1_024;
export const DEFAULT_CACHE_CLEANUP_INTERVAL_SECONDS = 3_600;

/** Sizes of persisted payloads (hard limit on raw payload size). */
export const MAX_RAW_PAYLOAD_BYTES = 1_000_000;
export const MAX_CACHE_ENTRY_BYTES = 4_000_000;
export const MAX_QUERY_CACHE_PAYLOAD_BYTES = 4_000_000;

/** Summary building limits. */
export const MAX_SUMMARY_AFFECTED_PRODUCTS = 50;
export const MAX_SUMMARY_DESCRIPTION_CHARS = 2_000;

/**
 * Upstream requests a locally filtered collection page may spend to fill `pageSize`
 * (1 initial request + up to N-1 follow-ups). Keeps `/cpes/2.0` calls bounded when the
 * `includeDeprecated` policy drops rows from a page.
 */
export const MAX_LOCAL_FILTER_FILL_REQUESTS = 4;

/** Upstream pages `get_cpe` scans when resolving an exact `cpeName` by pattern search. */
export const MAX_CPE_NAME_SCAN_PAGES = 3;

/**
 * SQLite defaults.
 *
 * The busy handler runs synchronously inside `node:sqlite`, so its timeout is also the worst-case
 * event-loop stall. It is deliberately short: a write that loses the lock race is retried from the
 * application layer (`CACHE_WRITE_MAX_ATTEMPTS`) with an `await`ed back-off, which keeps concurrent
 * tool calls responsive while still tolerating a competing writer.
 */
export const DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 500;

/**
 * Attempts for a cache write that lost the SQLite write lock, and the base delay between them.
 *
 * The busy handler blocks the event loop while it waits, so a contended write is retried from the
 * application layer with an `await`ed back-off; a lower `SQLITE_BUSY_TIMEOUT_MS` keeps each attempt
 * short enough that concurrent tool calls are never stalled for the whole timeout.
 */
export const CACHE_WRITE_MAX_ATTEMPTS = 4;
export const CACHE_WRITE_RETRY_BASE_MS = 25;
export const DATABASE_FILE_NAME = 'nvd.sqlite';

/** Disk cache resource directory names. */
export const CACHE_RESOURCE_DIRECTORIES = [
  'cves',
  'cve-history',
  'cpes',
  'cpe-matches',
  'searches',
] as const;
export type CacheResourceDirectory = (typeof CACHE_RESOURCE_DIRECTORIES)[number];

/** Interval used by maintenance timers that must not keep the process alive. */
export const CACHE_TMP_DIRECTORY = 'tmp';

/** Log levels. */
export const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];
