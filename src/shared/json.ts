import { createHash } from 'node:crypto';

/**
 * Deterministic JSON serialization: object keys are sorted, `undefined` values are dropped.
 *
 * Cache keys and cursor query hashes are derived from this representation, so the output must
 * be stable for logically identical inputs.
 */
export function canonicalize(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value ?? null;
  }
  if (typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      const item = source[key];
      if (item === undefined) {
        continue;
      }
      result[key] = canonicalize(item);
    }
    return result;
  }
  return String(value);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Cache key for an upstream query.
 *
 * The payload never contains credentials, so the resulting hash is safe to log and persist.
 */
export function buildCacheKey(resource: string, payload: unknown): string {
  return `sha256:${sha256Hex(`${resource}\n${canonicalJson(payload)}`)}`;
}

export function byteLength(input: string): number {
  return Buffer.byteLength(input, 'utf8');
}

export type JsonParseResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: string };

export function safeJsonParse<T = unknown>(text: string): JsonParseResult<T> {
  try {
    return { ok: true, value: JSON.parse(text) as T };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/** JSON serialization that refuses to exceed a byte budget. */
export function stringifyWithinBudget(
  value: unknown,
  maxBytes: number,
): { json: string; truncated: boolean } {
  const json = JSON.stringify(value);
  if (byteLength(json) <= maxBytes) {
    return { json, truncated: false };
  }
  return { json: JSON.stringify({ truncated: true, reason: 'payload_exceeds_size_budget' }), truncated: true };
}
