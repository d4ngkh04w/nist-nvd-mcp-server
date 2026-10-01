import type { StoredValue } from '../../domain/cache.js';
import type { CpeRecord } from '../../domain/cpe.js';
import type { CpeRepositoryPort, UpsertManyOptions } from '../../domain/ports.js';
import type { Logger } from '../../shared/logger.js';
import {
  parseStoredEntity,
  readRowInteger,
  readRowText,
  readStoredRawJson,
  resolveRawJson,
  stringifyStoredValue,
  wrapStorageError,
  type SqlRow,
  type SqliteDatabase,
} from './database.js';

const SELECT_COLUMNS = 'cpe_name_id, normalized_json, fetched_at, expires_at';

const UPSERT_SQL = `
INSERT INTO cpes (
    cpe_name_id,
    cpe_name,
    deprecated,
    created_at,
    last_modified_at,
    normalized_json,
    raw_json,
    fetched_at,
    expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cpe_name_id) DO UPDATE SET
    cpe_name = excluded.cpe_name,
    deprecated = excluded.deprecated,
    created_at = excluded.created_at,
    last_modified_at = excluded.last_modified_at,
    normalized_json = excluded.normalized_json,
    raw_json = excluded.raw_json,
    fetched_at = excluded.fetched_at,
    expires_at = excluded.expires_at`;

/** SQLite-backed cache for Official CPE Dictionary records. */
export class SqliteCpeRepository implements CpeRepositoryPort {
  constructor(private readonly deps: { db: SqliteDatabase; logger: Logger }) {}

  findById(cpeNameId: string): StoredValue<CpeRecord> | null {
    try {
      const row = this.deps.db
        .prepare(`SELECT ${SELECT_COLUMNS} FROM cpes WHERE cpe_name_id = ?`)
        .get(cpeNameId);
      return this.toStoredValue(row);
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the cached CPE record');
    }
  }

  findRawById(cpeNameId: string): string | null {
    try {
      const row = this.deps.db
        .prepare('SELECT raw_json FROM cpes WHERE cpe_name_id = ?')
        .get(cpeNameId);
      return readStoredRawJson(row);
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the cached CPE raw payload');
    }
  }

  findManyByIds(cpeNameIds: readonly string[]): Map<string, StoredValue<CpeRecord>> {
    const result = new Map<string, StoredValue<CpeRecord>>();
    const uniqueIds = [...new Set(cpeNameIds)];
    if (uniqueIds.length === 0) {
      return result;
    }

    try {
      const placeholders = uniqueIds.map(() => '?').join(', ');
      const rows = this.deps.db
        .prepare(`SELECT ${SELECT_COLUMNS} FROM cpes WHERE cpe_name_id IN (${placeholders})`)
        .all(...uniqueIds);

      for (const row of rows) {
        const cpeNameId = readRowText(row, 'cpe_name_id');
        if (cpeNameId === null) {
          continue;
        }
        const stored = this.toStoredValue(row);
        if (stored !== null) {
          result.set(cpeNameId, stored);
        }
      }
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read cached CPE records');
    }
    return result;
  }

  /**
   * Looks a record up by its CPE name.
   *
   * The exact match uses the `cpe_name` index; when it misses, an ASCII case-insensitive
   * comparison runs as a fallback because models may echo a CPE name in any case.
   */
  findByName(cpeName: string): StoredValue<CpeRecord> | null {
    try {
      const exact = this.deps.db
        .prepare(
          `SELECT ${SELECT_COLUMNS} FROM cpes WHERE cpe_name = ? ORDER BY last_modified_at DESC LIMIT 1`,
        )
        .get(cpeName);
      if (exact !== undefined) {
        return this.toStoredValue(exact);
      }

      const caseInsensitive = this.deps.db
        .prepare(
          `SELECT ${SELECT_COLUMNS} FROM cpes WHERE cpe_name = ? COLLATE NOCASE ORDER BY last_modified_at DESC LIMIT 1`,
        )
        .get(cpeName);
      return this.toStoredValue(caseInsensitive);
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the cached CPE record');
    }
  }

  upsertMany(records: readonly CpeRecord[], options: UpsertManyOptions): void {
    if (records.length === 0) {
      return;
    }
    try {
      this.deps.db.transaction(() => {
        const statement = this.deps.db.prepare(UPSERT_SQL);
        for (const record of records) {
          statement.run(
            record.cpeNameId,
            record.cpeName,
            record.deprecated ? 1 : 0,
            record.created,
            record.lastModified,
            stringifyStoredValue(record),
            resolveRawJson(record.cpeNameId, options.rawJson, options.rawJsonById),
            options.fetchedAt,
            options.expiresAt,
          );
        }
      });
    } catch (error) {
      throw wrapStorageError(error, 'Failed to write cached CPE records');
    }
  }

  deleteExpired(now: Date): number {
    try {
      const result = this.deps.db
        .prepare('DELETE FROM cpes WHERE expires_at <= ?')
        .run(now.toISOString());
      const changes = result.changes;
      return typeof changes === 'bigint' ? Number(changes) : changes;
    } catch (error) {
      throw wrapStorageError(error, 'Failed to remove expired CPE cache entries');
    }
  }

  count(): number {
    try {
      const row = this.deps.db.prepare('SELECT COUNT(*) AS count FROM cpes').get();
      return readRowInteger(row, 'count');
    } catch (error) {
      throw wrapStorageError(error, 'Failed to count CPE cache entries');
    }
  }

  private toStoredValue(row: SqlRow | undefined): StoredValue<CpeRecord> | null {
    if (row === undefined) {
      return null;
    }
    const cpeNameId = readRowText(row, 'cpe_name_id');
    const normalizedJson = readRowText(row, 'normalized_json');
    const fetchedAt = readRowText(row, 'fetched_at');
    const expiresAt = readRowText(row, 'expires_at');
    const value = normalizedJson === null ? null : parseStoredEntity<CpeRecord>(normalizedJson);

    if (cpeNameId === null || value === null || fetchedAt === null || expiresAt === null) {
      if (cpeNameId !== null) {
        this.dropCorruptRow(cpeNameId);
      }
      return null;
    }
    return { value, fetchedAt, expiresAt };
  }

  private dropCorruptRow(cpeNameId: string): void {
    this.deps.logger.warn('cache_row_corrupt', { table: 'cpes', id: cpeNameId });
    try {
      this.deps.db.prepare('DELETE FROM cpes WHERE cpe_name_id = ?').run(cpeNameId);
    } catch (error) {
      this.deps.logger.debug('cache_row_corrupt_delete_failed', {
        table: 'cpes',
        id: cpeNameId,
        error,
      });
    }
  }
}
