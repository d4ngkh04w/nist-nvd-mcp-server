export const NVD_DEFAULT_BASE_URL = 'https://services.nvd.nist.gov/rest/json';

/** NVD rejects date windows longer than 120 days. */
export const MAX_DATE_RANGE_DAYS = 120;

/** NVD caps comma separated `cveId` filters at 100 identifiers. */
export const MAX_CVE_IDS_PER_REQUEST = 100;

/** Guard rail for opaque cursors: reject absurd offsets instead of hammering NVD. */
export const MAX_NVD_START_INDEX = 100_000;

export const PAGE_SIZE_LIMITS = {
  cves: { default: 20, max: 50 },
  'cve-history': { default: 20, max: 50 },
  cpes: { default: 20, max: 100 },
  'cpe-matches': { default: 20, max: 100 },
} as const;

export type PaginationResourceName = keyof typeof PAGE_SIZE_LIMITS;

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

export const DEFAULT_NVD_MIN_INTERVAL_MS = 6_000;
export const DEFAULT_NVD_MAX_CONCURRENCY = 1;
export const DEFAULT_NVD_REQUEST_TIMEOUT_MS = 15_000;
export const DEFAULT_MCP_TOOL_TIMEOUT_MS = 120_000;
export const DEFAULT_MCP_MAX_OUTPUT_BYTES = 1_000_000;
export const DEFAULT_NVD_MAX_RETRIES = 4;
export const DEFAULT_RETRY_BASE_DELAY_MS = 1_000;
export const MAX_RETRY_DELAY_MS = 30_000;

export const DEFAULT_CURSOR_TTL_SECONDS = 1_800;
export const CURSOR_VERSION = 1;
export const MAX_CURSOR_LENGTH = 4_096;

export const CACHE_ENVELOPE_VERSION = 1;
export const DEFAULT_CACHE_MAX_SIZE_MB = 1_024;
export const DEFAULT_CACHE_CLEANUP_INTERVAL_SECONDS = 3_600;
/** Keep expired values for outage fallback before maintenance evicts them. */
export const DEFAULT_CACHE_STALE_RETENTION_SECONDS = 604_800;

/** Sizes of persisted payloads (hard limit on raw payload size). */
export const MAX_RAW_PAYLOAD_BYTES = 1_000_000;
export const MAX_CACHE_ENTRY_BYTES = 4_000_000;
export const MAX_QUERY_CACHE_PAYLOAD_BYTES = 4_000_000;

export const MAX_SUMMARY_AFFECTED_PRODUCTS = 50;
export const MAX_SUMMARY_DESCRIPTION_CHARS = 2_000;

/**
 * Upstream requests a locally filtered collection page may spend to fill `pageSize`
 * (1 initial request + up to N-1 follow-ups). Keeps `/cpes/2.0` calls bounded when the
 * `includeDeprecated` policy drops rows from a page.
 */
export const MAX_LOCAL_FILTER_FILL_REQUESTS = 4;

/** Upstream pages `nvd_get_cpe` scans when resolving an exact `cpeName` by pattern search. */
export const MAX_CPE_NAME_SCAN_PAGES = 3;

/**
 * Token count from which an empty `nvd_search_cves` result is annotated with a hint.
 *
 * NVD tokenizes `keyword` and requires every token in the description text, so a long phrase is
 * strictly narrower than a short one. Below this count an empty page is an ordinary "no match".
 */
export const KEYWORD_ZERO_RESULT_HINT_MIN_TOKENS = 4;

/** SQLite busy waits block the event loop; keep them short and retry asynchronously. */
export const DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 500;

export const CACHE_WRITE_MAX_ATTEMPTS = 4;
export const CACHE_WRITE_RETRY_BASE_MS = 25;
export const DATABASE_FILE_NAME = 'nvd.sqlite';

export const CACHE_RESOURCE_DIRECTORIES = [
  'cves',
  'cve-history',
  'cpes',
  'cpe-matches',
  'searches',
] as const;
export type CacheResourceDirectory = (typeof CACHE_RESOURCE_DIRECTORIES)[number];

export const CACHE_TMP_DIRECTORY = 'tmp';

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];
