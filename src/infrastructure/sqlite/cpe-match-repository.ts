import type { StoredValue } from '../../domain/cache.js';
import type { CpeMatchRecord } from '../../domain/cpe.js';
import type { CpeMatchRepositoryPort, UpsertManyOptions } from '../../domain/ports.js';
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

const SELECT_COLUMNS = 'match_criteria_id, normalized_json, fetched_at, expires_at';

const UPSERT_SQL = `
INSERT INTO cpe_matches (
    match_criteria_id,
    criteria,
    status,
    created_at,
    last_modified_at,
    cpe_last_modified_at,
    normalized_json,
    raw_json,
    fetched_at,
    expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(match_criteria_id) DO UPDATE SET
    criteria = excluded.criteria,
    status = excluded.status,
    created_at = excluded.created_at,
    last_modified_at = excluded.last_modified_at,
    cpe_last_modified_at = excluded.cpe_last_modified_at,
    normalized_json = excluded.normalized_json,
    raw_json = excluded.raw_json,
    fetched_at = excluded.fetched_at,
    expires_at = excluded.expires_at`;

export class SqliteCpeMatchRepository implements CpeMatchRepositoryPort {
  constructor(private readonly deps: { db: SqliteDatabase; logger: Logger }) {}

  findById(matchCriteriaId: string): StoredValue<CpeMatchRecord> | null {
    try {
      const row = this.deps.db
        .prepare(`SELECT ${SELECT_COLUMNS} FROM cpe_matches WHERE match_criteria_id = ?`)
        .get(matchCriteriaId);
      return this.toStoredValue(row);
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the cached CPE match record');
    }
  }

  findRawById(matchCriteriaId: string): string | null {
    try {
      const row = this.deps.db
        .prepare('SELECT raw_json FROM cpe_matches WHERE match_criteria_id = ?')
        .get(matchCriteriaId);
      return readStoredRawJson(row);
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the cached CPE match raw payload');
    }
  }

  upsertMany(records: readonly CpeMatchRecord[], options: UpsertManyOptions): void {
    if (records.length === 0) {
      return;
    }
    try {
      this.deps.db.transaction(() => {
        const statement = this.deps.db.prepare(UPSERT_SQL);
        for (const record of records) {
          statement.run(
            record.matchCriteriaId,
            record.criteria,
            record.status,
            record.created,
            record.lastModified,
            record.cpeLastModified,
            stringifyStoredValue(record),
            resolveRawJson(record.matchCriteriaId, options.rawJson, options.rawJsonById),
            options.fetchedAt,
            options.expiresAt,
          );
        }
      });
    } catch (error) {
      throw wrapStorageError(error, 'Failed to write cached CPE match records');
    }
  }

  deleteExpired(now: Date): number {
    try {
      const result = this.deps.db
        .prepare('DELETE FROM cpe_matches WHERE expires_at <= ?')
        .run(now.toISOString());
      const changes = result.changes;
      return typeof changes === 'bigint' ? Number(changes) : changes;
    } catch (error) {
      throw wrapStorageError(error, 'Failed to remove expired CPE match cache entries');
    }
  }

  count(): number {
    try {
      const row = this.deps.db.prepare('SELECT COUNT(*) AS count FROM cpe_matches').get();
      return readRowInteger(row, 'count');
    } catch (error) {
      throw wrapStorageError(error, 'Failed to count CPE match cache entries');
    }
  }

  private toStoredValue(row: SqlRow | undefined): StoredValue<CpeMatchRecord> | null {
    if (row === undefined) {
      return null;
    }
    const matchCriteriaId = readRowText(row, 'match_criteria_id');
    const normalizedJson = readRowText(row, 'normalized_json');
    const fetchedAt = readRowText(row, 'fetched_at');
    const expiresAt = readRowText(row, 'expires_at');
    const value =
      normalizedJson === null ? null : parseStoredEntity<CpeMatchRecord>(normalizedJson);

    if (matchCriteriaId === null || value === null || fetchedAt === null || expiresAt === null) {
      if (matchCriteriaId !== null) {
        this.dropCorruptRow(matchCriteriaId);
      }
      return null;
    }
    return { value, fetchedAt, expiresAt };
  }

  private dropCorruptRow(matchCriteriaId: string): void {
    this.deps.logger.warn('cache_row_corrupt', { table: 'cpe_matches', id: matchCriteriaId });
    try {
      this.deps.db
        .prepare('DELETE FROM cpe_matches WHERE match_criteria_id = ?')
        .run(matchCriteriaId);
    } catch (error) {
      this.deps.logger.debug('cache_row_corrupt_delete_failed', {
        table: 'cpe_matches',
        id: matchCriteriaId,
        error,
      });
    }
  }
}
