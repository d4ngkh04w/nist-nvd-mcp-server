import { describe, expect, it } from 'vitest';

import { SequentialRateLimiter } from '../../src/infrastructure/rate-limit/sequential-rate-limiter.js';
import { DomainError } from '../../src/domain/errors.js';

const MIN_INTERVAL_MS = 40;
/**
 * Node timers never fire early, but `now()` sampling and CI scheduling jitter deserve a small
 * margin. The observed gap must still be far above zero, so the limiter cannot be a no-op.
 */
const TIMING_TOLERANCE_MS = 10;

type Interval = {
  start: number;
  end: number;
};

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function runTask(durationMs: number): Promise<Interval> {
  const start = performance.now();
  await delay(durationMs);
  return { start, end: performance.now() };
}

function requireInterval(value: Interval | undefined, index: number): Interval {
  if (value === undefined) {
    throw new Error(`missing task result at index ${index}`);
  }
  return value;
}

describe('SequentialRateLimiter', () => {
  it('spaces the starts of sequential tasks by at least the minimum interval', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: MIN_INTERVAL_MS });

    const results = await Promise.all([
      limiter.schedule(() => runTask(10)),
      limiter.schedule(() => runTask(10)),
      limiter.schedule(() => runTask(10)),
    ]);

    for (let index = 1; index < results.length; index += 1) {
      const previous = requireInterval(results[index - 1], index - 1);
      const current = requireInterval(results[index], index);

      // Concurrency 1: the next task starts only after the previous one finished.
      expect(current.start).toBeGreaterThanOrEqual(previous.end);
      // Rate limit: consecutive starts are separated by at least the configured interval.
      expect(current.start - previous.start).toBeGreaterThanOrEqual(
        MIN_INTERVAL_MS - TIMING_TOLERANCE_MS,
      );
    }

    const stats = limiter.stats();
    expect(stats.started).toBe(3);
    expect(stats.completed).toBe(3);
    expect(stats.queued).toBe(0);
    expect(stats.active).toBe(0);
  });

  it('overlaps two tasks up to maxConcurrency while still spacing their starts', async () => {
    const limiter = new SequentialRateLimiter({
      minIntervalMs: MIN_INTERVAL_MS,
      maxConcurrency: 2,
    });

    const results = await Promise.all([
      limiter.schedule(() => runTask(60)),
      limiter.schedule(() => runTask(60)),
    ]);
    const first = requireInterval(results[0], 0);
    const second = requireInterval(results[1], 1);

    // Both tasks were running at the same time...
    expect(second.start).toBeLessThan(first.end);
    expect(first.start).toBeLessThan(second.end);
    // ...but the limiter still spaced their starts.
    expect(second.start - first.start).toBeGreaterThanOrEqual(
      MIN_INTERVAL_MS - TIMING_TOLERANCE_MS,
    );
    expect(first.end - first.start).toBeGreaterThanOrEqual(55);
    expect(limiter.stats().maxQueueDepth).toBe(1);
  });

  it('reports queue statistics and drops queued work on dispose', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: MIN_INTERVAL_MS });
    const started: number[] = [];
    let releaseFirst: (() => void) | undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const tasks = [0, 1, 2].map((index) =>
      limiter.schedule(async () => {
        started.push(index);
        if (index === 0) {
          await firstGate;
        }
      }),
    );

    const during = limiter.stats();
    expect(during.started).toBe(1);
    expect(during.completed).toBe(0);
    expect(during.active).toBe(1);
    expect(during.queued).toBe(2);
    expect(during.maxQueueDepth).toBe(2);
    expect(during.lastStartAt).not.toBeNull();

    limiter.dispose();
    expect(limiter.stats().queued).toBe(0);

    // Observe the rejection handlers immediately: dispose() rejects the queued
    // promises synchronously, so settling them only later would let Node/Vitest
    // report an unhandled rejection for the interim tick.
    const settledPromise = Promise.allSettled(tasks);

    if (releaseFirst === undefined) {
      throw new Error('the first task gate was not created');
    }
    releaseFirst();
    await tasks[0];
    await delay(60);
    // Queued work is rejected, never silently dropped, so no promise is left pending.
    const settled = await settledPromise;
    expect(settled.map((outcome) => outcome.status)).toEqual(['fulfilled', 'rejected', 'rejected']);

    expect(started).toEqual([0]);
    expect(limiter.stats()).toMatchObject({
      started: 1,
      completed: 1,
      queued: 0,
      active: 0,
    });
  });

  it('keeps draining the queue after a task rejects and propagates the rejection', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: MIN_INTERVAL_MS });
    const order: string[] = [];

    const failing = limiter.schedule(async () => {
      order.push('failing');
      throw new Error('boom');
    });
    const following = limiter.schedule(async () => {
      order.push('following');
      return 'ok';
    });

    await expect(failing).rejects.toThrow('boom');
    await expect(following).resolves.toBe('ok');
    expect(order).toEqual(['failing', 'following']);
  });

  it('starts tasks back-to-back when the minimum interval is zero', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: 0 });
    const startedAt = performance.now();

    const values = await Promise.all([
      limiter.schedule(async () => 'first'),
      limiter.schedule(async () => 'second'),
    ]);
    const elapsedMs = performance.now() - startedAt;

    expect(values).toEqual(['first', 'second']);
    // A 40 ms limiter would need at least 40 ms for two starts; two immediate tasks are far faster.
    expect(elapsedMs).toBeLessThan(30);
  });

  it('settles every queued promise when the limiter is disposed', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: 5_000 });
    const pending = Array.from({ length: 5 }, (_, index) =>
      limiter.schedule(async () => `task-${index}`),
    );

    // The first task is already running; the other four are still queued.
    expect(limiter.stats().queued).toBe(4);
    limiter.dispose();

    const outcomes = await Promise.allSettled(pending);
    const settled = outcomes.filter((outcome) => outcome.status === 'rejected');
    expect(settled).toHaveLength(4);
    for (const outcome of settled) {
      expect((outcome as PromiseRejectedResult).reason).toBeInstanceOf(DomainError);
      expect((outcome as PromiseRejectedResult).reason.message).toMatch(/shut down|disposed/i);
    }
    expect(limiter.stats().queued).toBe(0);
  });

  it('refuses to queue beyond the depth limit instead of growing without bound', async () => {
    const limiter = new SequentialRateLimiter({ minIntervalMs: 5_000, maxQueueDepth: 3 });

    const accepted = Array.from({ length: 4 }, () => limiter.schedule(async () => 'ok'));
    const overflow = await Promise.allSettled(
      Array.from({ length: 5 }, () => limiter.schedule(async () => 'ok')),
    );

    expect(accepted.every((promise) => promise instanceof Promise)).toBe(true);
    expect(overflow.every((outcome) => outcome.status === 'rejected')).toBe(true);
    const reason = (overflow[0] as PromiseRejectedResult).reason as DomainError;
    expect(reason.code).toBe('UPSTREAM_RATE_LIMITED');
    expect(reason.message).toMatch(/Too many queued NVD requests/);
    // Queue depth never exceeds the configured bound.
    expect(limiter.stats().queued).toBeLessThanOrEqual(3);
    limiter.dispose();
    await Promise.allSettled(accepted);
  });
});
