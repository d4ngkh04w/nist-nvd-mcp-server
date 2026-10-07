import { DomainError } from '../../domain/errors.js';
import { sleep } from '../../shared/async.js';
import { cancellationError, currentOperation, runWithOperation, throwIfCancelled } from '../../shared/operation.js';

export type RateLimiterStats = {
  started: number;
  completed: number;
  queued: number;
  active: number;
  maxQueueDepth: number;
  rejected: number;
  lastStartAt: string | null;
};

export type SequentialRateLimiterOptions = {
  /** Minimum delay between two consecutive task starts (NVD default: 6000 ms). */
  minIntervalMs: number;
  /** Maximum number of tasks running at the same time (NVD default: 1). */
  maxConcurrency?: number;
  /** Maximum number of tasks waiting for a slot; further submissions fail fast. */
  maxQueueDepth?: number;
  now?: () => number;
  wait?: (ms: number) => Promise<void>;
};

type QueueEntry = {
  run: () => void;
  reject: (error: unknown) => void;
  cleanup: () => void;
};

/**
 * Default queue bound.
 *
 * With the anonymous NVD key a queued request waits `minIntervalMs`, so an unbounded queue would
 * turn one burst into minutes of silent waiting and unbounded memory. Rejecting the overflow keeps
 * the wait per submission predictable and the failure visible.
 */
const DEFAULT_MAX_QUEUE_DEPTH = 200;

/**
 * Global, sequential NVD rate limiter.
 *
 * Guarantees:
 * - at most `maxConcurrency` tasks run concurrently;
 * - consecutive task starts are separated by at least `minIntervalMs`;
 * - the queue never exceeds `maxQueueDepth` and a submission beyond that is rejected immediately;
 * - `dispose()` settles every queued task instead of leaving a promise pending forever.
 *
 * Cache hits never reach this limiter, so cached reads stay instant.
 */
export class SequentialRateLimiter {
  private readonly minIntervalMs: number;
  private readonly maxConcurrency: number;
  private readonly queueLimit: number;
  private readonly now: () => number;
  private readonly wait: (ms: number) => Promise<void>;

  private readonly queue: QueueEntry[] = [];
  private active = 0;
  private nextSlotAt = 0;
  private pumpPending = false;
  private disposed = false;

  private startedCount = 0;
  private completedCount = 0;
  private rejectedCount = 0;
  /** Highest number of tasks that were ever waiting at the same time. */
  private observedQueueDepth = 0;
  private lastStartAtMs: number | null = null;

  constructor(options: SequentialRateLimiterOptions) {
    this.minIntervalMs = Math.max(0, options.minIntervalMs);
    this.maxConcurrency = Math.max(1, options.maxConcurrency ?? 1);
    this.queueLimit = Math.max(1, options.maxQueueDepth ?? DEFAULT_MAX_QUEUE_DEPTH);
    this.now = options.now ?? (() => Date.now());
    this.wait = options.wait ?? sleep;
  }

  schedule<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    const operation = currentOperation() ?? {};
    return new Promise<T>((resolve, reject) => {
      if (signal !== undefined) throwIfCancelled(signal);
      if (this.disposed) {
        this.rejectedCount += 1;
        reject(shutdownError());
        return;
      }
      if (this.queue.length >= this.queueLimit) {
        this.rejectedCount += 1;
        reject(
          DomainError.rateLimited(
            undefined,
            `Too many queued NVD requests (limit ${this.queueLimit}); retry shortly`,
          ),
        );
        return;
      }
      const abort = () => {
        const index = this.queue.indexOf(entry);
        if (index < 0) return;
        this.queue.splice(index, 1);
        this.rejectedCount += 1;
        entry.cleanup();
        reject(cancellationError(signal!));
      };
      const entry: QueueEntry = {
        run: () => {
          runWithOperation(operation, () => this.dispatch(task)).then(resolve, reject);
        },
        reject,
        cleanup: () => signal?.removeEventListener('abort', abort),
      };
      signal?.addEventListener('abort', abort, { once: true });
      this.queue.push(entry);
      this.observedQueueDepth = Math.max(this.observedQueueDepth, this.queue.length);
      this.pump();
    });
  }

  stats(): RateLimiterStats {
    return {
      started: this.startedCount,
      completed: this.completedCount,
      queued: this.queue.length,
      active: this.active,
      maxQueueDepth: this.observedQueueDepth,
      rejected: this.rejectedCount,
      lastStartAt: this.lastStartAtMs === null ? null : new Date(this.lastStartAtMs).toISOString(),
    };
  }

  /** Rejects queued work and prevents further scheduling; used on shutdown and in tests. */
  dispose(): void {
    this.disposed = true;
    this.pumpPending = false;
    const error = shutdownError();
    const dropped = this.queue.splice(0, this.queue.length);
    for (const entry of dropped) {
      entry.cleanup();
      this.rejectedCount += 1;
      entry.reject(error);
    }
  }

  private pump(): void {
    while (this.queue.length > 0 && this.active < this.maxConcurrency) {
      const delayMs = this.nextSlotAt - this.now();
      if (delayMs > 0) {
        this.schedulePump(delayMs);
        return;
      }
      const entry = this.queue.shift();
      if (entry === undefined) {
        return;
      }
      this.active += 1;
      entry.cleanup();
      this.startedCount += 1;
      const startedAt = this.now();
      this.lastStartAtMs = startedAt;
      this.nextSlotAt = startedAt + this.minIntervalMs;
      entry.run();
    }
  }

  private schedulePump(delayMs: number): void {
    if (this.pumpPending) {
      return;
    }
    this.pumpPending = true;
    void this.wait(delayMs).then(() => {
      this.pumpPending = false;
      this.pump();
    });
  }

  private async dispatch<T>(task: () => Promise<T>): Promise<T> {
    try {
      return await task();
    } finally {
      this.active -= 1;
      this.completedCount += 1;
      this.pump();
    }
  }
}

function shutdownError(): DomainError {
  return DomainError.upstreamUnavailable('The NVD request queue was shut down before the request ran');
}
