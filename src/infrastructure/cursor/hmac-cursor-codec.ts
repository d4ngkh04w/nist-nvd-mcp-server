import { createHmac, timingSafeEqual } from 'node:crypto';

import { CURSOR_VERSION, MAX_CURSOR_LENGTH, MAX_NVD_START_INDEX } from '../../config/defaults.js';
import { DomainError } from '../../domain/errors.js';
import type { CursorCodec, CursorPayload } from '../../domain/pagination.js';
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

function sign(secret: string, encodedPayload: string): string {
  return createHmac('sha256', secret).update(encodedPayload).digest('base64url');
}

function invalid(message: string): DomainError {
  return DomainError.invalidCursor(message);
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
    throw invalid('Cursor payload is malformed');
  }
  const record = value as Record<string, unknown>;

  if (record.version !== CURSOR_VERSION) {
    throw invalid('Cursor version is not supported');
  }

  const resource = record.resource;
  if (typeof resource !== 'string' || resource.length === 0) {
    throw invalid('Cursor resource is invalid');
  }

  const queryHash = record.queryHash;
  if (typeof queryHash !== 'string' || !SHA256_QUERY_HASH_PATTERN.test(queryHash)) {
    throw invalid('Cursor query hash is invalid');
  }

  const startIndex = record.startIndex;
  if (
    typeof startIndex !== 'number' ||
    !Number.isInteger(startIndex) ||
    startIndex < 0 ||
    startIndex > maxStartIndex
  ) {
    throw invalid('Cursor start index is out of range');
  }

  const pageSize = record.pageSize;
  if (
    typeof pageSize !== 'number' ||
    !Number.isInteger(pageSize) ||
    pageSize < 1 ||
    pageSize > maxPageSize
  ) {
    throw invalid('Cursor page size is out of range');
  }

  const issuedAtRaw = record.issuedAt;
  const expiresAtRaw = record.expiresAt;
  if (typeof issuedAtRaw !== 'string' || typeof expiresAtRaw !== 'string') {
    throw invalid('Cursor timestamps are invalid');
  }
  const issuedAt = parseIsoDate(issuedAtRaw);
  const expiresAt = parseIsoDate(expiresAtRaw);
  if (issuedAt === null || expiresAt === null) {
    throw invalid('Cursor timestamps are invalid');
  }
  if (expiresAt.getTime() <= now.getTime()) {
    throw invalid('Cursor has expired');
  }

  const resolvedWindow = parseResolvedWindow(record.resolvedWindow);

  return {
    version: CURSOR_VERSION,
    resource: resource as CursorPayload['resource'],
    queryHash,
    startIndex,
    pageSize,
    issuedAt: toIso(issuedAt),
    expiresAt: toIso(expiresAt),
    ...(resolvedWindow !== undefined ? { resolvedWindow } : {}),
  };
}

/** Validates the optional `resolvedWindow` carried by relative-window cursors. */
function parseResolvedWindow(
  value: unknown,
): { start: string; end: string } | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid('Cursor date window is invalid');
  }
  const record = value as Record<string, unknown>;
  const start = record.start;
  const end = record.end;
  if (typeof start !== 'string' || typeof end !== 'string') {
    throw invalid('Cursor date window is invalid');
  }
  const startDate = parseIsoDate(start);
  const endDate = parseIsoDate(end);
  if (startDate === null || endDate === null || endDate.getTime() < startDate.getTime()) {
    throw invalid('Cursor date window is invalid');
  }
  return { start: toIso(startDate), end: toIso(endDate) };
}

/**
 * Opaque pagination cursor: `base64url(payload) + '.' + base64url(hmacSha256(secret, payloadPart))`.
 *
 * The token is fully self-describing, so the only server-side state is the HMAC secret. Decode
 * failures (including expiry) are reported as `INVALID_CURSOR` and never echo the token itself.
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
        throw invalid('Cursor is empty');
      }
      if (token.length > MAX_CURSOR_LENGTH) {
        throw invalid('Cursor is too long');
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
        throw invalid('Cursor format is invalid');
      }

      if (!signaturesMatch(providedSignature, sign(secret, encodedPayload))) {
        throw invalid('Cursor signature is invalid');
      }

      const parsed = safeJsonParse<unknown>(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
      if (!parsed.ok) {
        throw invalid('Cursor payload is malformed');
      }

      return parsePayload(parsed.value, clock.now(), maxStartIndex, maxPageSize);
    },
  };
}
