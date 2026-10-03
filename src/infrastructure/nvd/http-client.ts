import { DomainError, isDomainError } from '../../domain/errors.js';
import type { Logger } from '../../shared/logger.js';
import { sleep } from '../../shared/async.js';
import { MAX_RETRY_DELAY_MS } from '../../config/defaults.js';
import type { SequentialRateLimiter } from '../rate-limit/sequential-rate-limiter.js';

/** Query parameters: an empty string value is serialized as a valueless flag (`?hasKev`). */
export type NvdQueryParams = Record<string, string>;

export type NvdHttpClientOptions = {
  baseUrl: string;
  /** NVD API key. Sent only through the `apiKey` header, never in the URL or in logs. */
  apiKey: string | undefined;
  requestTimeoutMs: number;
  maxRetries: number;
  retryBaseDelayMs: number;
  rateLimiter: SequentialRateLimiter;
  logger: Logger;
  fetchImpl?: typeof fetch;
  now?: () => number;
  wait?: (ms: number) => Promise<void>;
  random?: () => number;
  maxResponseBytes?: number;
};

const MAX_RESPONSE_BYTES_DEFAULT = 32 * 1_024 * 1_024;

const RETRYABLE_NETWORK_ERROR_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'EPIPE',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'ENOTFOUND',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
]);

type AttemptOutcome =
  | { kind: 'success'; body: unknown }
  | { kind: 'retry'; error: DomainError }
  | { kind: 'fail'; error: DomainError };

/**
 * Transport-level NVD client.
 *
 * Responsibilities: request serialization, `apiKey` header injection, timeout, retry with
 * exponential backoff + jitter, `Retry-After` support and mapping transport failures onto the
 * shared error contract. Response *shape* validation belongs to the typed clients.
 */
export class NvdHttpClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly requestTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly rateLimiter: SequentialRateLimiter;
  private readonly logger: Logger;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly wait: (ms: number) => Promise<void>;
  private readonly random: () => number;
  private readonly maxResponseBytes: number;

  constructor(options: NvdHttpClientOptions) {
    this.baseUrl = options.baseUrl;
    this.apiKey = options.apiKey;
    this.requestTimeoutMs = options.requestTimeoutMs;
    this.maxRetries = options.maxRetries;
    this.retryBaseDelayMs = options.retryBaseDelayMs;
    this.rateLimiter = options.rateLimiter;
    this.logger = options.logger;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.now = options.now ?? (() => Date.now());
    this.wait = options.wait ?? sleep;
    this.random = options.random ?? Math.random;
    this.maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES_DEFAULT;
  }

  /**
   * Executes a GET request against an NVD endpoint and returns the parsed JSON body.
   * Every attempt passes through the shared rate limiter.
   */
  async getJson(path: string, params: NvdQueryParams = {}): Promise<unknown> {
    const endpoint = path.startsWith('/') ? path : `/${path}`;
    const url = `${this.baseUrl}${endpoint}${serializeQuery(params)}`;
    const attempts = this.maxRetries + 1;
    let lastError: DomainError | undefined;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const startedAt = this.now();
      const outcome = await this.attempt(url, endpoint, attempt, Object.keys(params));
      const durationMs = this.now() - startedAt;

      if (outcome.kind === 'success') {
        this.logger.debug('nvd_response', {
          endpoint,
          attempt,
          durationMs,
          paramKeys: Object.keys(params),
        });
        return outcome.body;
      }

      lastError = outcome.error;

      if (outcome.kind === 'fail' || attempt === attempts) {
        this.logger.warn('nvd_request_failed', {
          endpoint,
          attempt,
          durationMs,
          code: outcome.error.code,
          retryable: outcome.error.retryable,
        });
        throw outcome.error;
      }

      const delayMs = this.computeBackoffMs(attempt, outcome.error.retryAfterSeconds);
      this.logger.warn('nvd_retry', {
        endpoint,
        attempt,
        nextAttempt: attempt + 1,
        delayMs,
        code: outcome.error.code,
      });
      await this.wait(delayMs);
    }

    throw lastError ?? DomainError.upstreamUnavailable('NVD request failed');
  }

  private computeBackoffMs(attempt: number, retryAfterSeconds: number | undefined): number {
    if (retryAfterSeconds !== undefined && Number.isFinite(retryAfterSeconds)) {
      return Math.min(MAX_RETRY_DELAY_MS, Math.max(0, Math.round(retryAfterSeconds * 1_000)));
    }
    const exponential = this.retryBaseDelayMs * 2 ** (attempt - 1);
    const jitter = this.random() * this.retryBaseDelayMs;
    return Math.min(MAX_RETRY_DELAY_MS, Math.round(exponential + jitter));
  }

  private async attempt(
    url: string,
    endpoint: string,
    attempt: number,
    paramKeys: string[],
  ): Promise<AttemptOutcome> {
    this.logger.debug('nvd_request', { endpoint, attempt, paramKeys });
    try {
      return await this.rateLimiter.schedule(async () => this.performRequest(url, endpoint, paramKeys));
    } catch (error) {
      if (isDomainError(error)) {
        return { kind: error.retryable ? 'retry' : 'fail', error };
      }
      if (error instanceof Error && error.name === 'AbortError') {
        return { kind: 'retry', error: DomainError.requestTimeout('NVD request timed out') };
      }
      // `redirect: 'error'` surfaces as a TypeError; treat it as an unsupported upstream response.
      if (isRedirectRefusal(error)) {
        return {
          kind: 'fail',
          error: DomainError.upstreamBadResponse('NVD redirected the request; redirects are not followed', {
            endpoint,
          }),
        };
      }
      const code = readErrorCode(error);
      if (code !== undefined && RETRYABLE_NETWORK_ERROR_CODES.has(code)) {
        return {
          kind: 'retry',
          error: DomainError.upstreamUnavailable('NVD request failed due to a network error'),
        };
      }
      return {
        kind: 'fail',
        error: DomainError.upstreamUnavailable('NVD request failed', error),
      };
    }
  }

  private async performRequest(url: string, endpoint: string, paramKeys: string[]): Promise<AttemptOutcome> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    if (typeof timeout.unref === 'function') {
      timeout.unref();
    }
    try {
      const headers: Record<string, string> = { accept: 'application/json' };
      if (this.apiKey !== undefined) {
        headers['apiKey'] = this.apiKey;
      }
      const response = await this.fetchImpl(url, {
        method: 'GET',
        headers,
        signal: controller.signal,
        // NVD never redirects. Following one would attach the `apiKey` header to whatever host the
        // response points at, so redirects are refused instead of silently leaking the credential.
        redirect: 'error',
      });

      if (!response.ok) {
        const retryAfterSeconds = parseRetryAfter(response.headers.get('retry-after'), this.now());
        const snippet = await readBodySnippet(response);
        const error = classifyStatus({
          status: response.status,
          endpoint,
          retryAfterSeconds,
          bodySnippet: snippet,
          apiKeySent: this.apiKey !== undefined,
          paramKeys,
        });
        return { kind: error.retryable ? 'retry' : 'fail', error };
      }

      const text = await response.text();
      if (text.length > this.maxResponseBytes) {
        return {
          kind: 'fail',
          error: DomainError.upstreamBadResponse(
            `NVD response exceeded the ${this.maxResponseBytes} byte limit`,
            { endpoint },
          ),
        };
      }
      try {
        return { kind: 'success', body: JSON.parse(text) as unknown };
      } catch {
        return {
          kind: 'fail',
          error: DomainError.upstreamBadResponse('NVD returned a response that is not valid JSON', {
            endpoint,
          }),
        };
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}

type StatusContext = {
  status: number;
  endpoint: string;
  retryAfterSeconds: number | undefined;
  bodySnippet: string;
  apiKeySent: boolean;
  paramKeys: string[];
};

function classifyStatus(context: StatusContext): DomainError {
  const { status, endpoint, retryAfterSeconds, bodySnippet, apiKeySent, paramKeys } = context;
  if (status === 429) {
    return DomainError.rateLimited(retryAfterSeconds, 'NVD rate limit reached (HTTP 429)');
  }
  if (status === 401 || status === 403) {
    return DomainError.upstreamBadResponse(
      `NVD rejected the request (HTTP ${status}). Verify the configured NVD API key.`,
      { endpoint, status },
    );
  }
  if (status >= 500) {
    return DomainError.upstreamUnavailable(`NVD is unavailable (HTTP ${status})`);
  }
  if (status === 404) {
    // A rejected `apiKey` is answered with 404 on every endpoint, so the credential is the likelier
    // cause than the query whenever one was sent. Echoing the parameter names that were actually
    // sent turns the failure into something the caller can act on instead of guessing which filter
    // was the rejected one.
    const message =
      'NVD returned HTTP 404. The endpoint or one of the query parameters is not supported.' +
      (apiKeySent
        ? ' An invalid or expired NVD_API_KEY also answers 404 on every endpoint, so check the key before changing the query.'
        : '');
    const details: Record<string, unknown> = { endpoint, status, bodySnippet };
    if (paramKeys.length > 0) {
      details['queryParameters'] = paramKeys;
    }
    return DomainError.upstreamBadResponse(message, details);
  }
  return DomainError.upstreamBadResponse(`NVD returned an unexpected status (HTTP ${status})`, {
    endpoint,
    status,
    bodySnippet,
  });
}

/** Detects undici's "redirect not followed" TypeError so it is never mistaken for a network fault. */
function isRedirectRefusal(error: unknown): boolean {
  const messages: string[] = [];
  if (error instanceof Error) {
    messages.push(error.message);
    const cause: unknown = (error as { cause?: unknown }).cause;
    if (cause instanceof Error) {
      messages.push(cause.message);
    }
  }
  return messages.some((message) => /redirect/i.test(message));
}

function readErrorCode(error: unknown): string | undefined {
  if (error instanceof Error) {
    const candidate = (error as { code?: unknown }).code;
    if (typeof candidate === 'string') {
      return candidate;
    }
    const cause = (error as { cause?: unknown }).cause;
    if (cause instanceof Error) {
      const causeCode = (cause as { code?: unknown }).code;
      if (typeof causeCode === 'string') {
        return causeCode;
      }
    }
  }
  return undefined;
}

async function readBodySnippet(response: Response): Promise<string> {
  try {
    const text = await response.text();
    return text.slice(0, 200);
  } catch {
    return '';
  }
}

/** Parses `Retry-After` in either delta-seconds or HTTP-date form. */
export function parseRetryAfter(value: string | null, nowMs: number): number | undefined {
  if (value === null || value.trim() === '') {
    return undefined;
  }
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds) && seconds >= 0) {
    return seconds;
  }
  const date = Date.parse(value);
  if (Number.isNaN(date)) {
    return undefined;
  }
  return Math.max(0, (date - nowMs) / 1_000);
}

/**
 * Serializes NVD query parameters.
 *
 * Empty strings become valueless flags (`?hasKev&noRejected`); the NVD API rejects `?hasKev=true`
 * and `?hasKev=` with HTTP 404.
 */
export function serializeQuery(params: NvdQueryParams): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === '') {
      parts.push(encodeURIComponent(key));
      continue;
    }
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
  }
  return parts.length === 0 ? '' : `?${parts.join('&')}`;
}
