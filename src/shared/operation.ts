import { AsyncLocalStorage } from 'node:async_hooks';

import { DomainError, isDomainError } from '../domain/errors.js';

export type OperationContext = {
  signal?: AbortSignal;
  onProgress?: (message: string) => void;
};

// Request-scoped controls, not business data. AsyncLocalStorage preserves isolation across
// concurrent calls without adding transport parameters to every service/query signature.
const operations = new AsyncLocalStorage<OperationContext>();

export function currentOperation(): OperationContext | undefined {
  return operations.getStore();
}

export function runWithOperation<T>(context: OperationContext, work: () => T): T {
  return operations.run(context, work);
}

export function cancellationError(signal: AbortSignal): DomainError {
  return isDomainError(signal.reason)
    ? signal.reason
    : new DomainError({ code: 'REQUEST_CANCELLED', message: 'The request was cancelled', retryable: false });
}

export function throwIfCancelled(signal = currentOperation()?.signal): void {
  if (signal?.aborted) throw cancellationError(signal);
}

/** Detach a waiter promptly; callers that own the work must also pass the signal to its I/O. */
export function waitWithSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener('abort', abort);
      reject(cancellationError(signal));
    };
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
    // Always observe the underlying promise, even when already aborted.
    promise.then(value => {
      signal.removeEventListener('abort', abort);
      resolve(value);
    }, error => {
      signal.removeEventListener('abort', abort);
      reject(error);
    });
  });
}
