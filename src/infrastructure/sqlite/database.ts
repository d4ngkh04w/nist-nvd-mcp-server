import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync, type SQLOutputValue, type StatementSync } from 'node:sqlite';
import { DomainError, isDomainError } from '../../domain/errors.js';
import { safeJsonParse } from '../../shared/json.js';
import type { Logger } from '../../shared/logger.js';

/** One row as returned by `StatementSync.get()` / `StatementSync.all()`. */
export type SqlRow = Record<string, SQLOutputValue>;

/**
 * Minimal synchronous SQLite surface shared by the repositories and the migrator.
 *
 * It exists so every caller uses the same prepared-statement API, the same transaction
 * semantics and the same place where infrastructure failures become `DomainError`s.
 */
export type SqliteDatabase = {
  readonly raw: DatabaseSync;
  exec(sql: string): void;
  prepare(sql: string): StatementSync;
  transaction<T>(fn: () => T): T;
  close(): void;
  isOpen(): boolean;
};

export type OpenDatabaseOptions = {
  path: string;
  busyTimeoutMs: number;
  logger: Logger;
};

const MEMORY_DATABASE_PATH = ':memory:';

/**
 * Opens (and, for file databases, creates) the SQLite database used as the persistent
 * lazy cache.
 *
 * WAL is skipped for in-memory databases because the journal mode has no meaning there.
 */
export function openDatabase(options: OpenDatabaseOptions): SqliteDatabase {
  const inMemory = options.path === MEMORY_DATABASE_PATH;
  if (!inMemory) {
    try {
      mkdirSync(path.dirname(path.resolve(options.path)), { recursive: true });
    } catch (error) {
      throw DomainError.storageError('Failed to create the database directory', error);
    }
  }

  let raw: DatabaseSync;
  try {
    raw = new DatabaseSync(options.path);
  } catch (error) {
    throw DomainError.storageError('Failed to open the SQLite database', error);
  }

  const busyTimeoutMs = normalizeBusyTimeout(options.busyTimeoutMs);
  try {
    applyPragmas(raw, { inMemory, busyTimeoutMs });
  } catch (error) {
    closeQuietly(raw);
    throw DomainError.storageError('Failed to configure the SQLite database', error);
  }

  options.logger.debug('sqlite_opened', { inMemory, busyTimeoutMs });
  return createDatabaseFacade(raw, options.logger);
}

function applyPragmas(
  raw: DatabaseSync,
  options: { inMemory: boolean; busyTimeoutMs: number },
): void {
  if (!options.inMemory) {
    raw.exec('PRAGMA journal_mode = WAL');
  }
  raw.exec('PRAGMA synchronous = NORMAL');
  raw.exec('PRAGMA foreign_keys = ON');
  raw.exec(`PRAGMA busy_timeout = ${options.busyTimeoutMs}`);
}

function normalizeBusyTimeout(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.trunc(value));
}

function createDatabaseFacade(raw: DatabaseSync, logger: Logger): SqliteDatabase {
  let depth = 0;

  return {
    raw,
    exec: (sql: string): void => {
      raw.exec(sql);
    },
    prepare: (sql: string): StatementSync => raw.prepare(sql),
    transaction<T>(fn: () => T): T {
      // Nested calls join the transaction they are already inside of.
      if (depth > 0) {
        depth += 1;
        try {
          return fn();
        } finally {
          depth -= 1;
        }
      }

      try {
        raw.exec('BEGIN IMMEDIATE');
      } catch (error) {
        throw DomainError.storageError('Failed to start a database transaction', error);
      }

      depth = 1;
      let result: T;
      try {
        result = fn();
      } catch (error) {
        depth = 0;
        rollbackQuietly(raw, logger);
        // Never replace the original failure with a rollback failure.
        throw error;
      }

      try {
        raw.exec('COMMIT');
      } catch (error) {
        depth = 0;
        rollbackQuietly(raw, logger);
        throw DomainError.storageError('Failed to commit a database transaction', error);
      }

      depth = 0;
      return result;
    },
    close(): void {
      if (!raw.isOpen) {
        return;
      }
      try {
        raw.close();
      } catch (error) {
        throw DomainError.storageError('Failed to close the SQLite database', error);
      }
      logger.debug('sqlite_closed');
    },
    isOpen: (): boolean => raw.isOpen,
  };
}

function rollbackQuietly(raw: DatabaseSync, logger: Logger): void {
  try {
    raw.exec('ROLLBACK');
  } catch (error) {
    logger.debug('sqlite_rollback_failed', { error });
  }
}

function closeQuietly(raw: DatabaseSync): void {
  try {
    if (raw.isOpen) {
      raw.close();
    }
  } catch {
    // The configuration error is reported by the caller; closing is best effort.
  }
}

/** Re-throws `DomainError`s untouched and translates infrastructure failures into `STORAGE_ERROR`. */
export function wrapStorageError(error: unknown, message: string): DomainError {
  return isDomainError(error) ? error : DomainError.storageError(message, error);
}

/** Reads a TEXT column; returns `null` when the column is missing or not textual. */
export function readRowText(row: SqlRow, column: string): string | null {
  const value = row[column];
  return typeof value === 'string' ? value : null;
}

/**
 * Reads a persisted `raw_json` column.
 *
 * Missing rows, non-textual values and blank strings are treated as absent (`null`) so callers
 * never treat an empty payload as a usable raw response.
 */
export function readStoredRawJson(row: SqlRow | undefined): string | null {
  const value = row?.['raw_json'];
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

/** Reads an INTEGER column; returns `0` when the column is missing or not numeric. */
export function readRowInteger(row: SqlRow | undefined, column: string): number {
  const value = row?.[column];
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'bigint') {
    return Number(value);
  }
  return 0;
}

/** Deserializes a persisted domain entity; malformed payloads and non-objects are treated as corrupt. */
export function parseStoredEntity<T>(json: string): T | null {
  const parsed = safeJsonParse<unknown>(json);
  if (!parsed.ok || parsed.value === null || typeof parsed.value !== 'object') {
    return null;
  }
  return parsed.value as T;
}

/** Serializes a domain value for persistence; `JSON.stringify`'s `undefined` result becomes `null`. */
export function stringifyStoredValue(value: unknown): string {
  return JSON.stringify(value) ?? 'null';
}

/** Resolves the raw upstream payload stored next to an entity; the value is never `null`. */
export function resolveRawJson(
  id: string,
  rawJson: string | null | undefined,
  rawJsonById?: ReadonlyMap<string, string | null>,
): string {
  if (rawJsonById !== undefined && rawJsonById.has(id)) {
    return rawJsonById.get(id) ?? '{}';
  }
  return rawJson ?? '{}';
}
