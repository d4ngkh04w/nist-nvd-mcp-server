import { describe, expect, it } from 'vitest';

import { DomainError } from '../../src/domain/errors.js';
import type { CursorCodec } from '../../src/domain/pagination.js';
import { createHmacCursorCodec } from '../../src/infrastructure/cursor/hmac-cursor-codec.js';
import { createMutableClock } from '../helpers/harness.js';

const QUERY_HASH = `sha256:${'a'.repeat(64)}`;

function codec(clock: ReturnType<typeof createMutableClock>): CursorCodec {
  return createHmacCursorCodec({
    secret: 'cursor-window-secret-0123456789',
    ttlSeconds: 1_800,
    clock,
  });
}

describe('cursor resolved date window', () => {
  it('round-trips the resolved window', () => {
    const clock = createMutableClock();
    const subject = codec(clock);
    const window = { start: '2026-01-08T12:00:00.000Z', end: '2026-01-15T12:00:00.000Z' };

    const token = subject.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 10,
      pageSize: 20,
      resolvedWindow: window,
    });
    const decoded = subject.decode(token);

    expect(decoded.resolvedWindow).toEqual(window);
    expect(decoded.startIndex).toBe(10);
  });

  it('omits the window when the caller does not provide one', () => {
    const clock = createMutableClock();
    const subject = codec(clock);

    const token = subject.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 0,
      pageSize: 20,
    });

    expect(subject.decode(token).resolvedWindow).toBeUndefined();
  });

  it('rejects a malformed window payload', () => {
    const clock = createMutableClock();
    const subject = codec(clock);
    const token = subject.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 0,
      pageSize: 20,
      resolvedWindow: { start: '2026-01-15T00:00:00.000Z', end: '2026-01-01T00:00:00.000Z' },
    });

    // Encoding accepts what it is given; decoding validates it.
    expect(() => subject.decode(token)).toThrowError(DomainError);
    try {
      subject.decode(token);
    } catch (error) {
      expect((error as DomainError).code).toBe('INVALID_CURSOR');
    }
  });

  it('rejects a tampered window', () => {
    const clock = createMutableClock();
    const subject = codec(clock);
    const token = subject.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 0,
      pageSize: 20,
      resolvedWindow: { start: '2026-01-08T00:00:00.000Z', end: '2026-01-15T00:00:00.000Z' },
    });

    const [payload, signature] = token.split('.');
    const decodedPayload = JSON.parse(Buffer.from(payload ?? '', 'base64url').toString('utf8')) as {
      resolvedWindow: { start: string; end: string };
    };
    decodedPayload.resolvedWindow.start = '2020-01-01T00:00:00.000Z';
    const forgedPayload = Buffer.from(JSON.stringify(decodedPayload), 'utf8').toString('base64url');
    const forged = `${forgedPayload}.${signature ?? ''}`;

    expect(() => subject.decode(forged)).toThrowError(DomainError);
  });

  it('keeps a relative window stable when the clock advances (pagination regression)', () => {
    const clock = createMutableClock('2026-01-15T12:00:00.000Z');
    const subject = codec(clock);

    const page1Window = { start: '2026-01-08T12:00:00.000Z', end: '2026-01-15T12:00:00.000Z' };
    const token = subject.encode({
      resource: 'cves',
      queryHash: QUERY_HASH,
      startIndex: 30,
      pageSize: 20,
      resolvedWindow: page1Window,
    });

    // A minute later the token must still decode with the original window.
    clock.advanceMs(60_000);
    const decoded = subject.decode(token);

    expect(decoded.resolvedWindow).toEqual(page1Window);
    expect(decoded.startIndex).toBe(30);
  });
});
