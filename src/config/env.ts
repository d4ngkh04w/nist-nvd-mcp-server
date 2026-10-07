import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

import {
  CACHE_ENVELOPE_VERSION,
  DATABASE_FILE_NAME,
  DEFAULT_CACHE_CLEANUP_INTERVAL_SECONDS,
  DEFAULT_CACHE_MAX_SIZE_MB,
  DEFAULT_CACHE_STALE_RETENTION_SECONDS,
  DEFAULT_CURSOR_TTL_SECONDS,
  DEFAULT_NVD_MAX_CONCURRENCY,
  DEFAULT_NVD_MAX_RETRIES,
  DEFAULT_NVD_MIN_INTERVAL_MS,
  DEFAULT_NVD_REQUEST_TIMEOUT_MS,
  DEFAULT_RETRY_BASE_DELAY_MS,
  DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
  DEFAULT_TTL_SECONDS,
  LOG_LEVELS,
  MAX_CACHE_ENTRY_BYTES,
  MAX_CVE_IDS_PER_REQUEST,
  MAX_DATE_RANGE_DAYS,
  MAX_NVD_START_INDEX,
  NVD_DEFAULT_BASE_URL,
  PAGE_SIZE_LIMITS,
  type LogLevel,
} from './defaults.js';

export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

export type AppConfig = {
  readonly nvdApiKey: string | undefined;
  readonly nvdBaseUrl: string;
  readonly nvd: {
    readonly minIntervalMs: number;
    readonly maxConcurrency: number;
    readonly requestTimeoutMs: number;
    readonly maxRetries: number;
    readonly retryBaseDelayMs: number;
  };
  readonly storage: {
    readonly sqlitePath: string;
    readonly sqliteBusyTimeoutMs: number;
    readonly migrationsDir: string;
  };
  readonly cache: {
    readonly directory: string;
    readonly maxSizeBytes: number;
    readonly cleanupIntervalMs: number;
    readonly staleRetentionMs: number;
    readonly envelopeVersion: number;
    readonly maxEntryBytes: number;
  };
  readonly ttlSeconds: {
    readonly cve: number;
    readonly cveSearch: number;
    readonly recent: number;
    readonly modified: number;
    readonly history: number;
    readonly cpeDetail: number;
    readonly cpeSearch: number;
    readonly cpeMatch: number;
  };
  readonly cursor: {
    readonly secret: string;
    readonly ttlSeconds: number;
  };
  readonly limits: {
    readonly maxDateRangeDays: number;
    readonly maxCveIdsPerRequest: number;
    readonly maxStartIndex: number;
    readonly pageSize: {
      readonly cves: { readonly default: number; readonly max: number };
      readonly 'cve-history': { readonly default: number; readonly max: number };
      readonly cpes: { readonly default: number; readonly max: number };
      readonly 'cpe-matches': { readonly default: number; readonly max: number };
    };
  };
  readonly logLevel: LogLevel;
  readonly nodeEnv: string;
};

const emptyToUndefined = (value: unknown): unknown => {
  if (typeof value === 'string' && value.trim() === '') {
    return undefined;
  }
  return value;
};

const optionalString = z.preprocess(emptyToUndefined, z.string().min(1).optional());
const nonNegativeInt = (minimum = 0, maximum = Number.MAX_SAFE_INTEGER) =>
  z.coerce.number().int().min(minimum).max(maximum);
const positiveInt = (minimum = 1, maximum = Number.MAX_SAFE_INTEGER) =>
  z.coerce.number().int().min(minimum).max(maximum);

const envSchema = z.object({
  NVD_API_KEY: optionalString,
  NVD_BASE_URL: z
    .preprocess(emptyToUndefined, z.string().url().default(NVD_DEFAULT_BASE_URL))
    .refine((value) => {
      const url = new URL(value);
      const isLoopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase());
      return url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback);
    }, {
      message: 'NVD_BASE_URL must use HTTPS; HTTP is allowed only for localhost loopback testing',
    }),
  NVD_MIN_INTERVAL_MS: nonNegativeInt(0, 3_600_000).default(DEFAULT_NVD_MIN_INTERVAL_MS),
  NVD_MAX_CONCURRENCY: positiveInt(1, 64).default(DEFAULT_NVD_MAX_CONCURRENCY),
  NVD_REQUEST_TIMEOUT_MS: positiveInt(100, 600_000).default(DEFAULT_NVD_REQUEST_TIMEOUT_MS),
  NVD_MAX_RETRIES: nonNegativeInt(0, 20).default(DEFAULT_NVD_MAX_RETRIES),
  NVD_RETRY_BASE_DELAY_MS: nonNegativeInt(0, 600_000).default(DEFAULT_RETRY_BASE_DELAY_MS),

  SQLITE_PATH: z.preprocess(emptyToUndefined, z.string().min(1).optional()),
  SQLITE_BUSY_TIMEOUT_MS: positiveInt(1, 600_000).default(DEFAULT_SQLITE_BUSY_TIMEOUT_MS),
  DATA_DIRECTORY: z.preprocess(emptyToUndefined, z.string().min(1).optional()),
  MIGRATIONS_DIRECTORY: z.preprocess(emptyToUndefined, z.string().min(1).optional()),

  CACHE_DIRECTORY: z.preprocess(emptyToUndefined, z.string().min(1).optional()),
  CACHE_MAX_SIZE_MB: nonNegativeInt(0, 1_048_576).default(DEFAULT_CACHE_MAX_SIZE_MB),
  CACHE_CLEANUP_INTERVAL_SECONDS: nonNegativeInt(0, 604_800).default(
    DEFAULT_CACHE_CLEANUP_INTERVAL_SECONDS,
  ),
  CACHE_MAX_ENTRY_BYTES: positiveInt(1_024, 512 * 1_024 * 1_024).optional(),
  CACHE_STALE_RETENTION_SECONDS: nonNegativeInt(0, 31_536_000).default(
    DEFAULT_CACHE_STALE_RETENTION_SECONDS,
  ),

  CVE_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.cve),
  SEARCH_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.cveSearch),
  RECENT_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.recent),
  MODIFIED_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.modified),
  HISTORY_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.history),
  CPE_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.cpeDetail),
  CPE_SEARCH_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.cpeSearch),
  CPE_MATCH_CACHE_TTL_SECONDS: positiveInt(1, 31_536_000).default(DEFAULT_TTL_SECONDS.cpeMatch),

  CURSOR_SECRET: z.preprocess(emptyToUndefined, z.string().min(16).optional()),
  CURSOR_TTL_SECONDS: positiveInt(1, 604_800).default(DEFAULT_CURSOR_TTL_SECONDS),

  MAX_CVE_PAGE_SIZE: positiveInt(1, PAGE_SIZE_LIMITS.cves.max).default(PAGE_SIZE_LIMITS.cves.max),
  MAX_HISTORY_PAGE_SIZE: positiveInt(1, PAGE_SIZE_LIMITS['cve-history'].max).default(
    PAGE_SIZE_LIMITS['cve-history'].max,
  ),
  MAX_CPE_PAGE_SIZE: positiveInt(1, PAGE_SIZE_LIMITS.cpes.max).default(PAGE_SIZE_LIMITS.cpes.max),
  MAX_CPE_MATCH_PAGE_SIZE: positiveInt(1, PAGE_SIZE_LIMITS['cpe-matches'].max).default(
    PAGE_SIZE_LIMITS['cpe-matches'].max,
  ),
  MAX_DATE_RANGE_DAYS: positiveInt(1, MAX_DATE_RANGE_DAYS).default(MAX_DATE_RANGE_DAYS),
  MAX_CVE_IDS_PER_REQUEST: positiveInt(1, MAX_CVE_IDS_PER_REQUEST).default(MAX_CVE_IDS_PER_REQUEST),
  MAX_NVD_START_INDEX: positiveInt(0, Number.MAX_SAFE_INTEGER).default(MAX_NVD_START_INDEX),

  LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
  NODE_ENV: z.preprocess(emptyToUndefined, z.string().min(1).default('production')),
});

type ParsedEnv = z.infer<typeof envSchema>;

/** Project root, used to resolve default storage locations. */
export function resolveProjectRoot(): string {
  // src/config/env.ts -> ../../ ; dist/config/env.js -> ../../
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function buildConfig(parsed: ParsedEnv, root: string): AppConfig {
  const dataDirectory = parsed.DATA_DIRECTORY
    ? path.resolve(parsed.DATA_DIRECTORY)
    : path.join(root, 'data');

  const sqlitePath = parsed.SQLITE_PATH
    ? path.resolve(parsed.SQLITE_PATH)
    : path.join(dataDirectory, DATABASE_FILE_NAME);

  const cacheDirectory = parsed.CACHE_DIRECTORY
    ? path.resolve(parsed.CACHE_DIRECTORY)
    : path.join(dataDirectory, 'cache');

  const migrationsDir = parsed.MIGRATIONS_DIRECTORY
    ? path.resolve(parsed.MIGRATIONS_DIRECTORY)
    : path.join(root, 'migrations');

  return {
    nvdApiKey: parsed.NVD_API_KEY,
    nvdBaseUrl: parsed.NVD_BASE_URL.replace(/\/+$/, ''),
    nvd: {
      minIntervalMs: parsed.NVD_MIN_INTERVAL_MS,
      maxConcurrency: parsed.NVD_MAX_CONCURRENCY,
      requestTimeoutMs: parsed.NVD_REQUEST_TIMEOUT_MS,
      maxRetries: parsed.NVD_MAX_RETRIES,
      retryBaseDelayMs: parsed.NVD_RETRY_BASE_DELAY_MS,
    },
    storage: {
      sqlitePath,
      sqliteBusyTimeoutMs: parsed.SQLITE_BUSY_TIMEOUT_MS,
      migrationsDir,
    },
    cache: {
      directory: cacheDirectory,
      maxSizeBytes: parsed.CACHE_MAX_SIZE_MB * 1_024 * 1_024,
      cleanupIntervalMs: parsed.CACHE_CLEANUP_INTERVAL_SECONDS * 1_000,
      staleRetentionMs: parsed.CACHE_STALE_RETENTION_SECONDS * 1_000,
      envelopeVersion: CACHE_ENVELOPE_VERSION,
      maxEntryBytes: parsed.CACHE_MAX_ENTRY_BYTES ?? MAX_CACHE_ENTRY_BYTES,
    },
    ttlSeconds: {
      cve: parsed.CVE_CACHE_TTL_SECONDS,
      cveSearch: parsed.SEARCH_CACHE_TTL_SECONDS,
      recent: parsed.RECENT_CACHE_TTL_SECONDS,
      modified: parsed.MODIFIED_CACHE_TTL_SECONDS,
      history: parsed.HISTORY_CACHE_TTL_SECONDS,
      cpeDetail: parsed.CPE_CACHE_TTL_SECONDS,
      cpeSearch: parsed.CPE_SEARCH_CACHE_TTL_SECONDS,
      cpeMatch: parsed.CPE_MATCH_CACHE_TTL_SECONDS,
    },
    cursor: {
      secret: parsed.CURSOR_SECRET ?? randomBytes(32).toString('base64url'),
      ttlSeconds: parsed.CURSOR_TTL_SECONDS,
    },
    limits: {
      maxDateRangeDays: parsed.MAX_DATE_RANGE_DAYS,
      maxCveIdsPerRequest: parsed.MAX_CVE_IDS_PER_REQUEST,
      maxStartIndex: parsed.MAX_NVD_START_INDEX,
      pageSize: {
        cves: { default: PAGE_SIZE_LIMITS.cves.default, max: parsed.MAX_CVE_PAGE_SIZE },
        'cve-history': {
          default: PAGE_SIZE_LIMITS['cve-history'].default,
          max: parsed.MAX_HISTORY_PAGE_SIZE,
        },
        cpes: { default: PAGE_SIZE_LIMITS.cpes.default, max: parsed.MAX_CPE_PAGE_SIZE },
        'cpe-matches': {
          default: PAGE_SIZE_LIMITS['cpe-matches'].default,
          max: parsed.MAX_CPE_MATCH_PAGE_SIZE,
        },
      },
    },
    logLevel: parsed.LOG_LEVEL,
    nodeEnv: parsed.NODE_ENV,
  };
}

/**
 * Loads and validates configuration from the environment.
 * The NVD API key is read here and never logged, echoed or embedded in cache keys.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    throw new ConfigError(`Invalid environment configuration -> ${issues}`);
  }
  return buildConfig(result.data, resolveProjectRoot());
}

/** Loads `.env` when present; Node's built-in loader keeps the dependency list small. */
export function loadDotEnvFile(filePath?: string): void {
  try {
    process.loadEnvFile(filePath);
  } catch {
    // Missing .env is fine: configuration falls back to real environment variables.
  }
}
