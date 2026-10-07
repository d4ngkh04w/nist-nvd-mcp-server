import { MAX_QUERY_CACHE_PAYLOAD_BYTES } from '../../config/defaults.js';
import type { StoredValue } from '../../domain/cache.js';
import { DomainError } from '../../domain/errors.js';
import type { QueryCacheRepositoryPort, QueryCacheWrite } from '../../domain/ports.js';
import { byteLength, safeJsonParse } from '../../shared/json.js';
import type { Logger } from '../../shared/logger.js';
import {
  readRowInteger,
  readRowText,
  stringifyStoredValue,
  wrapStorageError,
  type SqliteDatabase,
} from './database.js';

const SELECT_COLUMNS = 'payload_json, fetched_at, expires_at';

const UPSERT_SQL = `
INSERT INTO query_cache (
    cache_key,
    resource,
    query_hash,
    created_at,
    fetched_at,
    expires_at,
    payload_json,
    byte_size
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cache_key) DO UPDATE SET
    resource = excluded.resource,
    query_hash = excluded.query_hash,
    created_at = excluded.created_at,
    fetched_at = excluded.fetched_at,
    expires_at = excluded.expires_at,
    payload_json = excluded.payload_json,
    byte_size = excluded.byte_size`;

export class SqliteQueryCacheRepository implements QueryCacheRepositoryPort {
  constructor(private readonly deps: { db: SqliteDatabase; logger: Logger }) {}

  get<T>(cacheKey: string): StoredValue<T> | null {
    try {
      const row = this.deps.db
        .prepare(`SELECT ${SELECT_COLUMNS} FROM query_cache WHERE cache_key = ?`)
        .get(cacheKey);
      if (row === undefined) {
        return null;
      }

      const payloadJson = readRowText(row, 'payload_json');
      const fetchedAt = readRowText(row, 'fetched_at');
      const expiresAt = readRowText(row, 'expires_at');
      const parsed = payloadJson === null ? null : safeJsonParse<T>(payloadJson);

      if (
        parsed === null ||
        !parsed.ok ||
        fetchedAt === null ||
        expiresAt === null
      ) {
        this.dropCorruptRow(cacheKey);
        return null;
      }
      return { value: parsed.value, fetchedAt, expiresAt };
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the query cache entry');
    }
  }

  put<T>(entry: QueryCacheWrite<T>): void {
    let payloadJson: string;
    try {
      payloadJson = stringifyStoredValue(entry.value);
    } catch (error) {
      throw wrapStorageError(error, 'Failed to serialize the query cache entry');
    }

    if (byteLength(payloadJson) > MAX_QUERY_CACHE_PAYLOAD_BYTES) {
      throw DomainError.storageError('Cache entry exceeds the configured size budget');
    }

    try {
      this.deps.db
        .prepare(UPSERT_SQL)
        .run(
          entry.cacheKey,
          entry.resource,
          entry.queryHash,
          entry.createdAt,
          entry.fetchedAt,
          entry.expiresAt,
          payloadJson,
          byteLength(payloadJson),
        );
    } catch (error) {
      throw wrapStorageError(error, 'Failed to write the query cache entry');
    }
  }

  delete(cacheKey: string): void {
    try {
      this.deps.db.prepare('DELETE FROM query_cache WHERE cache_key = ?').run(cacheKey);
    } catch (error) {
      throw wrapStorageError(error, 'Failed to delete the query cache entry');
    }
  }

  deleteExpired(now: Date): number {
    try {
      const result = this.deps.db
        .prepare('DELETE FROM query_cache WHERE expires_at <= ?')
        .run(now.toISOString());
      const changes = result.changes;
      return typeof changes === 'bigint' ? Number(changes) : changes;
    } catch (error) {
      throw wrapStorageError(error, 'Failed to remove expired query cache entries');
    }
  }

  count(): number {
    try {
      const row = this.deps.db.prepare('SELECT COUNT(*) AS count FROM query_cache').get();
      return readRowInteger(row, 'count');
    } catch (error) {
      throw wrapStorageError(error, 'Failed to count query cache entries');
    }
  }

  private dropCorruptRow(cacheKey: string): void {
    this.deps.logger.warn('cache_row_corrupt', { table: 'query_cache', id: cacheKey });
    try {
      this.deps.db.prepare('DELETE FROM query_cache WHERE cache_key = ?').run(cacheKey);
    } catch (error) {
      this.deps.logger.debug('cache_row_corrupt_delete_failed', {
        table: 'query_cache',
        id: cacheKey,
        error,
      });
    }
  }
}
