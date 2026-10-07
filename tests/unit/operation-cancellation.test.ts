import { describe, expect, it, vi } from 'vitest';

import { SingleFlight } from '../../src/shared/async.js';
import { currentOperation, runWithOperation, waitWithSignal } from '../../src/shared/operation.js';
import { SequentialRateLimiter } from '../../src/infrastructure/rate-limit/sequential-rate-limiter.js';
import { deferred } from '../helpers/async.js';

describe('operation cancellation', () => {
  it('stops waiting promptly and sanitizes external abort reasons', async () => {
    const controller = new AbortController();
    const pending = waitWithSignal(new Promise(() => {}), controller.signal);
    const error = new Error('deadline');
    controller.abort(error);
    await expect(pending).rejects.toMatchObject({ code: 'REQUEST_CANCELLED' });
  });

  it('removes cancelled queued work without starting it', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: 0 });
    const gate = deferred<void>();
    const first = limiter.schedule(() => gate.promise);
    const controller = new AbortController();
    const task = vi.fn(async () => 'must not run');
    const queued = limiter.schedule(task, controller.signal);
    controller.abort();
    await expect(queued).rejects.toMatchObject({ code: 'REQUEST_CANCELLED' });
    expect(limiter.stats().queued).toBe(0);
    gate.resolve();
    await first;
    expect(task).not.toHaveBeenCalled();
    limiter.dispose();
  });

  it('preserves each queued operation context rather than inheriting the previous task', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: 0 });
    const gate = deferred<void>();
    const firstController = new AbortController();
    const secondController = new AbortController();
    const first = runWithOperation({ signal: firstController.signal }, () => limiter.schedule(() => gate.promise));
    const second = runWithOperation({ signal: secondController.signal }, () => limiter.schedule(async () => currentOperation()?.signal));
    firstController.abort();
    gate.resolve();
    await first;
    await expect(second).resolves.toBe(secondController.signal);
    limiter.dispose();
  });

  it('does not let the first subscriber cancel another subscriber sharing the same fetch', async () => {
    const flights = new SingleFlight();
    const gate = deferred<string>();
    const firstController = new AbortController();
    const secondController = new AbortController();
    let sharedSignal: AbortSignal | undefined;
    const factory = vi.fn(() => {
      sharedSignal = currentOperation()?.signal;
      return gate.promise;
    });
    const first = runWithOperation({ signal: firstController.signal }, () => flights.run('key', factory));
    const second = runWithOperation({ signal: secondController.signal }, () => flights.run('key', factory));
    await Promise.resolve();
    firstController.abort();
    await expect(first).rejects.toMatchObject({ code: 'REQUEST_CANCELLED' });
    expect(sharedSignal?.aborted).toBe(false);
    gate.resolve('ok');
    await expect(second).resolves.toBe('ok');
    expect(factory).toHaveBeenCalledOnce();
    expect(flights.size).toBe(0);
  });

  it('aborts shared work only after the last subscriber leaves and allows an immediate new flight', async () => {
    const flights = new SingleFlight();
    const controller = new AbortController();
    const first = runWithOperation({ signal: controller.signal }, () => flights.run('key', () =>
      waitWithSignal(new Promise(() => {}), currentOperation()?.signal),
    ));
    await Promise.resolve();
    controller.abort();
    await expect(first).rejects.toMatchObject({ code: 'REQUEST_CANCELLED' });
    await expect(flights.run('key', async () => 'fresh')).resolves.toBe('fresh');
    expect(flights.size).toBe(0);
  });

  it('fans out progress to active subscribers only', async () => {
    const flights = new SingleFlight();
    const gate = deferred<void>();
    const firstProgress = vi.fn();
    const secondProgress = vi.fn();
    const controller = new AbortController();
    let report: ((message: string) => void) | undefined;
    const first = runWithOperation({ signal: controller.signal, onProgress: firstProgress }, () =>
      flights.run('key', () => { report = currentOperation()?.onProgress; return gate.promise; }),
    );
    const second = runWithOperation({ onProgress: secondProgress }, () => flights.run('key', () => gate.promise));
    await Promise.resolve();
    report?.('page 1');
    controller.abort();
    await expect(first).rejects.toMatchObject({ code: 'REQUEST_CANCELLED' });
    report?.('page 2');
    gate.resolve();
    await second;
    expect(firstProgress.mock.calls).toEqual([['page 1']]);
    expect(secondProgress.mock.calls).toEqual([['page 1'], ['page 2']]);
  });
});
