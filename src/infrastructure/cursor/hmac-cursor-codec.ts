import { createHmac, timingSafeEqual } from 'node:crypto';

import { CURSOR_VERSION, MAX_CURSOR_LENGTH, MAX_NVD_START_INDEX } from '../../config/defaults.js';
import { DomainError } from '../../domain/errors.js';
import type { CursorCodec, CursorErrorReason, CursorPayload } from '../../domain/pagination.js';
import type { Clock } from '../../domain/ports.js';
import { safeJsonParse } from '../../shared/json.js';
import { addSeconds, parseIsoDate, toIso } from '../../shared/time.js';

export type HmacCursorCodecOptions = {
  secret: string;
  ttlSeconds: number;
  clock: Clock;
  maxStartIndex?: number;
  maxPageSize?: number;
};

const DEFAULT_MAX_PAGE_SIZE = 1_000;
const SHA256_QUERY_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CURSOR_SEPARATOR = '.';
/** A base64url-encoded SHA-256 digest is always 43 characters, so any other length was altered. */
const SIGNATURE_LENGTH = 43;

function sign(secret: string, encodedPayload: string): string {
  return createHmac('sha256', secret).update(encodedPayload).digest('base64url');
}

function invalid(
  reason: CursorErrorReason,
  message: string,
  details?: Record<string, unknown>,
): DomainError {
  return DomainError.invalidCursor(message, { reason, ...details });
}

function signaturesMatch(provided: string, expected: string): boolean {
  const providedBuffer = Buffer.from(provided, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }
  return timingSafeEqual(providedBuffer, expectedBuffer);
}

function parsePayload(
  value: unknown,
  now: Date,
  maxStartIndex: number,
  maxPageSize: number,
): CursorPayload {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid('payload', 'Cursor payload is malformed');
  }
  const record = value as Record<string, unknown>;

  if (record.version !== CURSOR_VERSION) {
    throw invalid('version', 'Cursor version is not supported');
  }

  const resource = record.resource;
  if (typeof resource !== 'string' || resource.length === 0) {
    throw invalid('resource', 'Cursor resource is invalid');
  }

  const queryHash = record.queryHash;
  if (typeof queryHash !== 'string' || !SHA256_QUERY_HASH_PATTERN.test(queryHash)) {
    throw invalid('query_hash', 'Cursor query hash is invalid');
  }

  const startIndex = record.startIndex;
  if (
    typeof startIndex !== 'number' ||
    !Number.isInteger(startIndex) ||
    startIndex < 0 ||
    startIndex > maxStartIndex
  ) {
    throw invalid('start_index', 'Cursor start index is out of range');
  }

  const pageSize = record.pageSize;
  if (
    typeof pageSize !== 'number' ||
    !Number.isInteger(pageSize) ||
    pageSize < 1 ||
    pageSize > maxPageSize
  ) {
    throw invalid('page_size', 'Cursor page size is out of range');
  }

  const issuedAtRaw = record.issuedAt;
  const expiresAtRaw = record.expiresAt;
  if (typeof issuedAtRaw !== 'string' || typeof expiresAtRaw !== 'string') {
    throw invalid('timestamps', 'Cursor timestamps are invalid');
  }
  const issuedAt = parseIsoDate(issuedAtRaw);
  const expiresAt = parseIsoDate(expiresAtRaw);
  if (issuedAt === null || expiresAt === null) {
    throw invalid('timestamps', 'Cursor timestamps are invalid');
  }
  if (expiresAt.getTime() <= now.getTime()) {
    throw invalid(
      'expired',
      'Cursor has expired; restart pagination from the first page without a cursor',
    );
  }

  const resolvedWindow = parseResolvedWindow(record.resolvedWindow);
  const page = parsePage(record.page);

  return {
    version: CURSOR_VERSION,
    resource: resource as CursorPayload['resource'],
    queryHash,
    startIndex,
    pageSize,
    ...(page !== undefined ? { page } : {}),
    issuedAt: toIso(issuedAt),
    expiresAt: toIso(expiresAt),
    ...(resolvedWindow !== undefined ? { resolvedWindow } : {}),
  };
}

/**
 * Validates the optional 1-based page ordinal. It is only ever written by this server, so an
 * out-of-range value means the payload was tampered with or produced by an older format.
 */
function parsePage(value: unknown): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw invalid('payload', 'Cursor page ordinal is invalid');
  }
  return value;
}

/** Validates the optional `resolvedWindow` carried by relative-window cursors. */
function parseResolvedWindow(
  value: unknown,
): { start: string; end: string } | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid('window', 'Cursor date window is invalid');
  }
  const record = value as Record<string, unknown>;
  const start = record.start;
  const end = record.end;
  if (typeof start !== 'string' || typeof end !== 'string') {
    throw invalid('window', 'Cursor date window is invalid');
  }
  const startDate = parseIsoDate(start);
  const endDate = parseIsoDate(end);
  if (startDate === null || endDate === null || endDate.getTime() < startDate.getTime()) {
    throw invalid('window', 'Cursor date window is invalid');
  }
  return { start: toIso(startDate), end: toIso(endDate) };
}

/**
 * Opaque pagination cursor: `base64url(payload) + '.' + base64url(hmacSha256(secret, payloadPart))`.
 *
 * The token is fully self-describing, so the only server-side state is the HMAC secret. Decode
 * failures (including expiry) are reported as `INVALID_CURSOR` with a `details.reason` code and
 * never echo the token itself.
 */
export function createHmacCursorCodec(options: HmacCursorCodecOptions): CursorCodec {
  const { secret, ttlSeconds, clock } = options;
  const maxStartIndex = options.maxStartIndex ?? MAX_NVD_START_INDEX;
  const maxPageSize = options.maxPageSize ?? DEFAULT_MAX_PAGE_SIZE;

  return {
    encode(payload) {
      const issuedAt = clock.now();
      const full: CursorPayload = {
        version: CURSOR_VERSION,
        resource: payload.resource,
        queryHash: payload.queryHash,
        startIndex: payload.startIndex,
        pageSize: payload.pageSize,
        ...(payload.page !== undefined ? { page: payload.page } : {}),
        issuedAt: toIso(issuedAt),
        expiresAt: toIso(addSeconds(issuedAt, ttlSeconds)),
        ...(payload.resolvedWindow !== undefined
          ? { resolvedWindow: { ...payload.resolvedWindow } }
          : {}),
      };
      const encodedPayload = Buffer.from(JSON.stringify(full), 'utf8').toString('base64url');
      return `${encodedPayload}${CURSOR_SEPARATOR}${sign(secret, encodedPayload)}`;
    },

    decode(token) {
      if (typeof token !== 'string' || token.length === 0) {
        throw invalid('empty', 'Cursor is empty');
      }
      if (token.length > MAX_CURSOR_LENGTH) {
        throw invalid('too_long', 'Cursor is too long');
      }

      const parts = token.split(CURSOR_SEPARATOR);
      const encodedPayload = parts[0];
      const providedSignature = parts[1];
      if (
        parts.length !== 2 ||
        encodedPayload === undefined ||
        encodedPayload.length === 0 ||
        providedSignature === undefined ||
        providedSignature.length === 0
      ) {
        throw invalid('format', 'Cursor format is invalid');
      }

      if (!signaturesMatch(providedSignature, sign(secret, encodedPayload))) {
        // A token this server produced always verifies when echoed byte for byte, so a mismatch
        // means the copy was edited, truncated or re-wrapped on the way here rather than that the
        // query drifted. The length of the signature part separates truncation from substitution.
        throw invalid(
          'signature',
          providedSignature.length === SIGNATURE_LENGTH
            ? 'Cursor signature is invalid: the token was altered in transit. Re-send pagination.nextCursor exactly as returned, keeping pageSize and every filter unchanged.'
            : `Cursor signature is invalid: the token was truncated or re-encoded (signature part is ${providedSignature.length} characters, expected ${SIGNATURE_LENGTH}). Re-send pagination.nextCursor exactly as returned.`,
          { tokenLength: token.length, signatureLength: providedSignature.length },
        );
      }

      const parsed = safeJsonParse<unknown>(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
      if (!parsed.ok) {
        throw invalid('payload', 'Cursor payload is malformed');
      }

      return parsePayload(parsed.value, clock.now(), maxStartIndex, maxPageSize);
    },
  };
}
