import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { CURSOR_VERSION, MAX_CURSOR_LENGTH, MAX_NVD_START_INDEX } from '../../src/config/defaults.js';
import { DomainError } from '../../src/domain/errors.js';
import type { Clock } from '../../src/domain/ports.js';
import { buildQueryIdentity } from '../../src/infrastructure/cache/cache-key.js';
import { createHmacCursorCodec } from '../../src/infrastructure/cursor/hmac-cursor-codec.js';

const SECRET = 'cursor-test-secret-value-long-enough';
const OTHER_SECRET = 'another-cursor-test-secret-value';
const TTL_SECONDS = 1_800;
const QUERY_HASH = buildQueryIdentity('cves', { keyword: 'log4j' }).queryHash;

type FakeClock = Clock & { advance(milliseconds: number): void };

function createFakeClock(startIso: string): FakeClock {
  let currentMs = Date.parse(startIso);
  return {
    now: () => new Date(currentMs),
    advance: (milliseconds: number) => {
      currentMs += milliseconds;
    },
  };
}

function createCodec(
  clock: Clock,
  overrides: {
    secret?: string;
    ttlSeconds?: number;
    maxStartIndex?: number;
    maxPageSize?: number;
  } = {},
) {
  return createHmacCursorCodec({
    secret: overrides.secret ?? SECRET,
    ttlSeconds: overrides.ttlSeconds ?? TTL_SECONDS,
    clock,
    ...(overrides.maxStartIndex === undefined ? {} : { maxStartIndex: overrides.maxStartIndex }),
    ...(overrides.maxPageSize === undefined ? {} : { maxPageSize: overrides.maxPageSize }),
  });
}

function captureInvalidCursor(action: () => unknown): DomainError {
  let caught: unknown;
  try {
    action();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(DomainError);
  const domainError = caught as DomainError;
  expect(domainError.code).toBe('INVALID_CURSOR');
  return domainError;
}

function splitToken(token: string): { payload: string; signature: string } {
  const parts = token.split('.');
  expect(parts).toHaveLength(2);
  return { payload: parts[0] ?? '', signature: parts[1] ?? '' };
}

/** Re-signs an arbitrary payload string with the codec secret (test-only helper). */
function signPayload(secret: string, payloadText: string): string {
  const encoded = Buffer.from(payloadText, 'utf8').toString('base64url');
  const signature = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function cursorPayload(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: CURSOR_VERSION,
    resource: 'cves',
    queryHash: QUERY_HASH,
    startIndex: 0,
    pageSize: 20,
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2027-01-01T00:00:00.000Z',
    ...overrides,
  });
}

describe('createHmacCursorCodec', () => {
  it('round-trips a payload and stamps version and expiry', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);

    const token = codec.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 40,
      pageSize: 20,
    });

    expect(codec.decode(token)).toEqual({
      version: CURSOR_VERSION,
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 40,
      pageSize: 20,
      issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2026-01-01T00:30:00.000Z',
    });
  });

  it('produces different tokens for the same payload when time moves', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);
    const payload = { resource: 'cpes' as const, queryHash: QUERY_HASH, startIndex: 0, pageSize: 20 };

    const first = codec.encode(payload);
    clock.advance(1_000);
    const second = codec.encode(payload);

    expect(second).not.toBe(first);
    expect(codec.decode(first).issuedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(codec.decode(second).issuedAt).toBe('2026-01-01T00:00:01.000Z');
  });

  it('rejects a tampered payload', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);
    const { payload, signature } = splitToken(
      codec.encode({ resource: 'cves', queryHash: QUERY_HASH, startIndex: 0, pageSize: 20 }),
    );

    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    const tampered = Buffer.from(
      JSON.stringify({ ...decodedPayload, startIndex: 60 }),
      'utf8',
    ).toString('base64url');

    const error = captureInvalidCursor(() => codec.decode(`${tampered}.${signature}`));
    expect(error.message).toBe('Cursor signature is invalid');
  });

  it('rejects a tampered signature', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);
    const { payload, signature } = splitToken(
      codec.encode({ resource: 'cves', queryHash: QUERY_HASH, startIndex: 0, pageSize: 20 }),
    );
    const replacement = signature.endsWith('A') ? 'B' : 'A';

    const error = captureInvalidCursor(() =>
      codec.decode(`${payload}.${signature.slice(0, -1)}${replacement}`),
    );
    expect(error.message).toBe('Cursor signature is invalid');
  });

  it('rejects garbage tokens and malformed segments', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);

    for (const token of ['not-a-cursor', 'guess.this', '.signature', 'payload.', 'a.b.c']) {
      const error = captureInvalidCursor(() => codec.decode(token));
      expect(error.message.length).toBeGreaterThan(0);
    }
  });

  it('rejects an expired cursor with the dedicated message', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);
    const token = codec.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 0,
      pageSize: 20,
    });

    clock.advance(TTL_SECONDS * 1_000 + 1);

    const error = captureInvalidCursor(() => codec.decode(token));
    expect(error.message).toBe('Cursor has expired');
  });

  it('rejects a token signed with a different secret', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const encoder = createCodec(clock);
    const decoder = createCodec(clock, { secret: OTHER_SECRET });
    const token = encoder.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 0,
      pageSize: 20,
    });

    const error = captureInvalidCursor(() => decoder.decode(token));
    expect(error.message).toBe('Cursor signature is invalid');
  });

  it('rejects oversized tokens', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);

    const error = captureInvalidCursor(() => codec.decode('a'.repeat(MAX_CURSOR_LENGTH + 1)));
    expect(error.message).toBe('Cursor is too long');
  });

  it('rejects out-of-range startIndex and pageSize values', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock, { maxStartIndex: 100, maxPageSize: 10 });
    const base = { resource: 'cves' as const, queryHash: QUERY_HASH };

    expect(
      captureInvalidCursor(() => codec.decode(codec.encode({ ...base, startIndex: 101, pageSize: 10 })))
        .message,
    ).toBe('Cursor start index is out of range');
    expect(
      captureInvalidCursor(() => codec.decode(codec.encode({ ...base, startIndex: -1, pageSize: 10 })))
        .message,
    ).toBe('Cursor start index is out of range');
    expect(
      captureInvalidCursor(() => codec.decode(codec.encode({ ...base, startIndex: 0, pageSize: 11 })))
        .message,
    ).toBe('Cursor page size is out of range');
    expect(
      captureInvalidCursor(() => codec.decode(codec.encode({ ...base, startIndex: 0, pageSize: 0 })))
        .message,
    ).toBe('Cursor page size is out of range');

    const defaultCodec = createCodec(clock);
    expect(
      captureInvalidCursor(() =>
        defaultCodec.decode(
          defaultCodec.encode({
            ...base,
            startIndex: MAX_NVD_START_INDEX + 1,
            pageSize: 20,
          }),
        ),
      ).message,
    ).toBe('Cursor start index is out of range');
  });

  it('rejects malformed payloads that carry a valid signature', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);

    const cases: Array<{ payload: string; message: string }> = [
      { payload: 'not json', message: 'Cursor payload is malformed' },
      { payload: JSON.stringify([1, 2, 3]), message: 'Cursor payload is malformed' },
      { payload: cursorPayload({ version: 99 }), message: 'Cursor version is not supported' },
      { payload: cursorPayload({ resource: '' }), message: 'Cursor resource is invalid' },
      { payload: cursorPayload({ resource: 42 }), message: 'Cursor resource is invalid' },
      { payload: cursorPayload({ queryHash: 'md5:abc' }), message: 'Cursor query hash is invalid' },
      { payload: cursorPayload({ startIndex: 1.5 }), message: 'Cursor start index is out of range' },
      { payload: cursorPayload({ startIndex: '0' }), message: 'Cursor start index is out of range' },
      { payload: cursorPayload({ pageSize: '20' }), message: 'Cursor page size is out of range' },
      { payload: cursorPayload({ pageSize: 1.5 }), message: 'Cursor page size is out of range' },
      {
        payload: cursorPayload({ pageSize: 1_001 }),
        message: 'Cursor page size is out of range',
      },
      { payload: cursorPayload({ issuedAt: 'nope' }), message: 'Cursor timestamps are invalid' },
      { payload: cursorPayload({ expiresAt: 'nope' }), message: 'Cursor timestamps are invalid' },
      {
        payload: cursorPayload({ expiresAt: '2025-12-31T23:59:59.000Z' }),
        message: 'Cursor has expired',
      },
    ];

    for (const testCase of cases) {
      const error = captureInvalidCursor(() =>
        codec.decode(signPayload(SECRET, testCase.payload)),
      );
      expect(error.message).toBe(testCase.message);
    }
  });

  it('never echoes the token in the error message', () => {
    const clock = createFakeClock('2026-01-01T00:00:00.000Z');
    const codec = createCodec(clock);
    const token = `sensitive-payload.${'z'.repeat(64)}`;

    const error = captureInvalidCursor(() => codec.decode(token));

    expect(error.message).not.toContain('sensitive-payload');
    expect(error.message).not.toContain('zzzz');
  });
});
