import type { AppMetadataRepositoryPort } from '../../domain/ports.js';
import type { Logger } from '../../shared/logger.js';
import {
  readRowText,
  wrapStorageError,
  type SqliteDatabase,
} from './database.js';

const SELECT_ONE_SQL = 'SELECT "value" FROM app_metadata WHERE "key" = ?';

const SELECT_ALL_SQL = 'SELECT "key", "value" FROM app_metadata';

const UPSERT_SQL = `
INSERT INTO app_metadata ("key", "value", updated_at) VALUES (?, ?, ?)
ON CONFLICT("key") DO UPDATE SET
    "value" = excluded."value",
    updated_at = excluded.updated_at`;

/** Key/value metadata such as the last successful cleanup timestamp. */
export class SqliteAppMetadataRepository implements AppMetadataRepositoryPort {
  constructor(private readonly deps: { db: SqliteDatabase; logger: Logger }) {}

  get(key: string): string | null {
    try {
      const row = this.deps.db.prepare(SELECT_ONE_SQL).get(key);
      return row === undefined ? null : readRowText(row, 'value');
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the application metadata entry');
    }
  }

  set(key: string, value: string): void {
    try {
      this.deps.db.prepare(UPSERT_SQL).run(key, value, new Date().toISOString());
    } catch (error) {
      throw wrapStorageError(error, 'Failed to write the application metadata entry');
    }
  }

  all(): Record<string, string> {
    try {
      const rows = this.deps.db.prepare(SELECT_ALL_SQL).all();
      const result: Record<string, string> = {};
      for (const row of rows) {
        const key = readRowText(row, 'key');
        const value = readRowText(row, 'value');
        if (key !== null && value !== null) {
          result[key] = value;
        }
      }
      return result;
    } catch (error) {
      throw wrapStorageError(error, 'Failed to read the application metadata');
    }
  }
}
