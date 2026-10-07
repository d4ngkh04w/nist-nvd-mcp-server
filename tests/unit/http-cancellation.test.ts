import { describe, expect, it, vi } from 'vitest';

import { NvdHttpClient } from '../../src/infrastructure/nvd/http-client.js';
import { SequentialRateLimiter } from '../../src/infrastructure/rate-limit/sequential-rate-limiter.js';
import { DomainError } from '../../src/domain/errors.js';
import { runWithOperation } from '../../src/shared/operation.js';
import { Logger } from '../../src/shared/logger.js';
import { deferred } from '../helpers/async.js';

describe('HTTP cancellation', () => {
  it('aborts active network I/O without retrying a caller cancellation', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: 0 });
    const entered = deferred<AbortSignal>();
    const fetchImpl = vi.fn<typeof fetch>(async (_url, init) => {
      const signal = init!.signal!;
      entered.resolve(signal);
      return new Promise<Response>((_resolve, reject) => signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true }));
    });
    const http = new NvdHttpClient({ baseUrl: 'https://example.invalid', apiKey: undefined,
      requestTimeoutMs: 10_000, maxRetries: 4, retryBaseDelayMs: 0,
      rateLimiter: limiter, fetchImpl, logger: new Logger({ level: 'silent' }),
    });
    const controller = new AbortController();
    const pending = runWithOperation({ signal: controller.signal }, () => http.getJson('/test'));
    const signal = await entered.promise;
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: 'REQUEST_CANCELLED' });
    expect(signal.aborted).toBe(true);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(limiter.stats().active).toBe(0);
    limiter.dispose();
  });

  it('stops a retry backoff and preserves the overall deadline error', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: 0 });
    const entered = deferred<void>();
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response('{}', { status: 503 }));
    const http = new NvdHttpClient({ baseUrl: 'https://example.invalid', apiKey: undefined,
      requestTimeoutMs: 10_000, maxRetries: 4, retryBaseDelayMs: 100,
      rateLimiter: limiter, fetchImpl, logger: new Logger({ level: 'silent' }),
      wait: () => { entered.resolve(); return new Promise(() => {}); },
    });
    const controller = new AbortController();
    const pending = runWithOperation({ signal: controller.signal }, () => http.getJson('/test'));
    await entered.promise;
    controller.abort(DomainError.requestTimeout('Tool deadline exceeded', { scope: 'tool' }));
    await expect(pending).rejects.toMatchObject({ code: 'REQUEST_TIMEOUT', details: { scope: 'tool' } });
    expect(fetchImpl).toHaveBeenCalledOnce();
    limiter.dispose();
  });
});
