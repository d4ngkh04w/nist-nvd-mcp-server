import { cancellationError, currentOperation, runWithOperation, throwIfCancelled, type OperationContext } from './operation.js';

type Flight = {
  promise: Promise<unknown>;
  controller: AbortController;
  subscribers: Set<OperationContext>;
};

/** Shared work has its own lifetime: one subscriber cannot cancel another's fetch. */
export class SingleFlight {
  private readonly inFlight = new Map<string, Flight>();

  run<T>(key: string, factory: () => Promise<T>): Promise<T> {
    const subscriber = { ...currentOperation() };
    throwIfCancelled(subscriber.signal);
    let flight = this.inFlight.get(key);
    if (flight === undefined) {
      const controller = new AbortController();
      const subscribers = new Set<OperationContext>();
      const context: OperationContext = {
        signal: controller.signal,
        onProgress: message => {
          for (const listener of subscribers) listener.onProgress?.(message);
        },
      };
      const created: Flight = {
        controller, subscribers,
        promise: Promise.resolve().then(() => runWithOperation(context, () => {
          throwIfCancelled();
          return factory();
        })).finally(() => {
          if (this.inFlight.get(key) === created) this.inFlight.delete(key);
        }),
      };
      this.inFlight.set(key, created);
      flight = created;
    }
    const shared = flight;
    shared.subscribers.add(subscriber);
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const detach = () => {
        if (settled) return;
        settled = true;
        subscriber.signal?.removeEventListener('abort', abort);
        shared.subscribers.delete(subscriber);
        if (shared.subscribers.size === 0) {
          if (this.inFlight.get(key) === shared) this.inFlight.delete(key);
          shared.controller.abort();
        }
      };
      const abort = () => {
        reject(cancellationError(subscriber.signal!));
        detach();
      };
      subscriber.signal?.addEventListener('abort', abort, { once: true });
      shared.promise.then(value => {
        resolve(value as T);
        detach();
      }, error => {
        reject(error);
        detach();
      });
    });
  }

  get size(): number {
    return this.inFlight.size;
  }

  has(key: string): boolean {
    return this.inFlight.has(key);
  }
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal !== undefined) throwIfCancelled(signal);
  if (ms <= 0) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(cancellationError(signal!));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', abort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', abort, { once: true });
    // Timers must never keep the process alive on their own.
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
  });
}
