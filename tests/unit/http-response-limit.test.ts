import { describe, expect, it } from 'vitest';

import { NvdHttpClient } from '../../src/infrastructure/nvd/http-client.js';
import { SequentialRateLimiter } from '../../src/infrastructure/rate-limit/sequential-rate-limiter.js';
import { Logger } from '../../src/shared/logger.js';

function client(response: Response, limit: number) {
  return new NvdHttpClient({
    baseUrl: 'https://example.invalid', apiKey: undefined, requestTimeoutMs: 1_000,
    maxRetries: 0, retryBaseDelayMs: 0, rateLimiter: new SequentialRateLimiter({ minIntervalMs: 0 }),
    logger: new Logger({ level: 'silent' }), maxResponseBytes: limit,
    fetchImpl: async () => response,
  });
}

describe('HTTP response byte limits', () => {
  it('rejects multibyte JSON exceeding the byte limit, not the character limit', async () => {
    const body = JSON.stringify({ text: 'ééé' });
    expect(body.length).toBeLessThan(15);
    await expect(client(new Response(body), 15).getJson('/test')).rejects.toMatchObject({
      code: 'UPSTREAM_BAD_RESPONSE',
    });
  });

  it('accepts JSON exactly at the byte limit across split UTF-8 chunks', async () => {
    const bytes = new TextEncoder().encode(JSON.stringify({ text: 'é' }));
    const stream = new ReadableStream<Uint8Array>({ start(controller) {
      for (const byte of bytes) controller.enqueue(Uint8Array.of(byte));
      controller.close();
    } });
    await expect(client(new Response(stream), bytes.length).getJson('/test')).resolves.toEqual({ text: 'é' });
  });

  it('preserves Response.text UTF-8 BOM decoding behavior', async () => {
    await expect(client(new Response('\uFEFF{"ok":true}'), 32).getJson('/test')).resolves.toEqual({ ok: true });
  });

  it('cancels an oversized stream without draining the whole response', async () => {
    let pulls = 0;
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array(16));
        if (pulls === 100) controller.close();
      },
      cancel() { cancelled = true; },
    });
    await expect(client(new Response(stream), 20).getJson('/test')).rejects.toMatchObject({
      code: 'UPSTREAM_BAD_RESPONSE',
    });
    expect(cancelled).toBe(true);
    expect(pulls).toBeLessThanOrEqual(3);
  });

  it('bounds and cancels error bodies while preserving HTTP status classification', async () => {
    let cancelled = false;
    let pulls = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode('x'.repeat(256)));
        if (++pulls === 100) controller.close();
      },
      cancel() { cancelled = true; },
    });
    await expect(client(new Response(stream, { status: 404 }), 32).getJson('/test')).rejects.toMatchObject({
      code: 'UPSTREAM_BAD_RESPONSE', details: { status: 404, bodySnippet: 'x'.repeat(200) },
    });
    expect(cancelled).toBe(true);
  });
});
