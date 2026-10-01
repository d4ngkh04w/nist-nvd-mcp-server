/**
 * Error contract shared by every layer.
 *
 * Domain code throws `DomainError`; the MCP layer renders it as a `ToolError` payload and never
 * leaks stack traces, SQLite internals, headers or credentials.
 */
export const TOOL_ERROR_CODES = [
  'INVALID_INPUT',
  'CVE_NOT_FOUND',
  'CPE_NOT_FOUND',
  'CPE_MATCH_NOT_FOUND',
  'INVALID_CURSOR',
  'DATE_RANGE_TOO_LARGE',
  'CACHE_CORRUPTED',
  'UPSTREAM_RATE_LIMITED',
  'UPSTREAM_UNAVAILABLE',
  'UPSTREAM_BAD_RESPONSE',
  'REQUEST_TIMEOUT',
  'STORAGE_ERROR',
  'INTERNAL_ERROR',
] as const;

export type ToolErrorCode = (typeof TOOL_ERROR_CODES)[number];

export type ToolError = {
  code: ToolErrorCode;
  message: string;
  retryable: boolean;
  retryAfterSeconds?: number;
  details?: Record<string, unknown>;
};

const RETRYABLE_CODES: ReadonlySet<ToolErrorCode> = new Set<ToolErrorCode>([
  'UPSTREAM_RATE_LIMITED',
  'UPSTREAM_UNAVAILABLE',
  'REQUEST_TIMEOUT',
  'STORAGE_ERROR',
]);

export type DomainErrorOptions = {
  code: ToolErrorCode;
  message: string;
  retryable?: boolean;
  retryAfterSeconds?: number;
  details?: Record<string, unknown>;
  cause?: unknown;
};

export class DomainError extends Error {
  override readonly name = 'DomainError';
  readonly code: ToolErrorCode;
  readonly retryable: boolean;
  readonly retryAfterSeconds: number | undefined;
  readonly details: Record<string, unknown> | undefined;

  constructor(options: DomainErrorOptions) {
    super(options.message, options.cause === undefined ? undefined : { cause: options.cause });
    this.code = options.code;
    this.retryable = options.retryable ?? RETRYABLE_CODES.has(options.code);
    this.retryAfterSeconds = options.retryAfterSeconds;
    this.details = options.details;
  }

  toToolError(): ToolError {
    const toolError: ToolError = {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
    };
    if (this.retryAfterSeconds !== undefined) {
      toolError.retryAfterSeconds = this.retryAfterSeconds;
    }
    if (this.details !== undefined && Object.keys(this.details).length > 0) {
      toolError.details = this.details;
    }
    return toolError;
  }

  static invalidInput(message: string, details?: Record<string, unknown>): DomainError {
    return new DomainError({ code: 'INVALID_INPUT', message, details });
  }

  static notFound(
    code: Extract<ToolErrorCode, 'CVE_NOT_FOUND' | 'CPE_NOT_FOUND' | 'CPE_MATCH_NOT_FOUND'>,
    message: string,
    details?: Record<string, unknown>,
  ): DomainError {
    return new DomainError({ code, message, details });
  }

  static invalidCursor(message: string, details?: Record<string, unknown>): DomainError {
    return new DomainError({ code: 'INVALID_CURSOR', message, details });
  }

  static dateRangeTooLarge(message: string, details?: Record<string, unknown>): DomainError {
    return new DomainError({ code: 'DATE_RANGE_TOO_LARGE', message, details });
  }

  static cacheCorrupted(message: string, details?: Record<string, unknown>): DomainError {
    return new DomainError({ code: 'CACHE_CORRUPTED', message, details });
  }

  static rateLimited(retryAfterSeconds: number | undefined, message?: string): DomainError {
    return new DomainError({
      code: 'UPSTREAM_RATE_LIMITED',
      message: message ?? 'NVD rate limit reached',
      retryAfterSeconds,
    });
  }

  static upstreamUnavailable(message: string, cause?: unknown): DomainError {
    return new DomainError({ code: 'UPSTREAM_UNAVAILABLE', message, cause });
  }

  static upstreamBadResponse(message: string, details?: Record<string, unknown>): DomainError {
    return new DomainError({ code: 'UPSTREAM_BAD_RESPONSE', message, details });
  }

  static requestTimeout(message: string, details?: Record<string, unknown>): DomainError {
    return new DomainError({ code: 'REQUEST_TIMEOUT', message, details });
  }

  static storageError(message: string, cause?: unknown): DomainError {
    return new DomainError({ code: 'STORAGE_ERROR', message, cause });
  }

  static internal(message: string, cause?: unknown): DomainError {
    return new DomainError({ code: 'INTERNAL_ERROR', message, cause, retryable: false });
  }
}

export function isDomainError(value: unknown): value is DomainError {
  return value instanceof DomainError;
}

export function toDomainError(value: unknown): DomainError {
  if (isDomainError(value)) {
    return value;
  }
  if (value instanceof Error) {
    return DomainError.internal('Unexpected server error', value);
  }
  return DomainError.internal('Unexpected server error');
}

export function toToolError(value: unknown): ToolError {
  return toDomainError(value).toToolError();
}

export function isRetryableCode(code: ToolErrorCode): boolean {
  return RETRYABLE_CODES.has(code);
}
