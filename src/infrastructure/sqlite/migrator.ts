import { createHash } from 'node:crypto';
import type { Dirent } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Logger } from '../../shared/logger.js';
import { readRowText, wrapStorageError, type SqliteDatabase } from './database.js';

export type MigrationResult = {
  applied: string[];
  skipped: string[];
  drift: string[];
};

type MigrationFile = {
  version: string;
  name: string;
  sql: string;
  checksum: string;
};

const CREATE_MIGRATIONS_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);`;

const INSERT_MIGRATION_SQL =
  'INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)';

/**
 * Applies every pending `*.sql` migration in filename order.
 *
 * Each migration runs in a single transaction together with its registry row, so a
 * partially applied migration can never be observed. Checksums of already-applied files
 * are verified, but drift is only reported: the database keeps working while an operator
 * investigates the modified file.
 */
export async function runMigrations(
  db: SqliteDatabase,
  options: { migrationsDir: string; logger: Logger },
): Promise<MigrationResult> {
  const files = await readMigrationFiles(options.migrationsDir);
  ensureMigrationsTable(db);
  const appliedChecksums = readAppliedChecksums(db);

  const result: MigrationResult = { applied: [], skipped: [], drift: [] };
  for (const file of files) {
    const recordedChecksum = appliedChecksums.get(file.version);

    if (recordedChecksum === undefined) {
      applyMigration(db, file);
      options.logger.info('migration_applied', { version: file.version });
      result.applied.push(file.version);
      continue;
    }

    if (recordedChecksum === file.checksum) {
      result.skipped.push(file.version);
      continue;
    }

    options.logger.warn('migration_checksum_drift', { version: file.version });
    result.drift.push(file.version);
  }

  return result;
}

async function readMigrationFiles(migrationsDir: string): Promise<MigrationFile[]> {
  let entries: Dirent[];
  try {
    entries = await readdir(migrationsDir, { withFileTypes: true });
  } catch (error) {
    throw wrapStorageError(error, 'Migrations directory is not readable');
  }

  const names = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.sql'))
    .map((entry) => entry.name)
    .sort();

  const files: MigrationFile[] = [];
  for (const name of names) {
    let sql: string;
    try {
      sql = await readFile(path.join(migrationsDir, name), 'utf8');
    } catch (error) {
      throw wrapStorageError(error, `Failed to read migration file ${name}`);
    }
    files.push({
      version: name.replace(/\.sql$/, ''),
      name,
      sql,
      checksum: createHash('sha256').update(sql, 'utf8').digest('hex'),
    });
  }
  return files;
}

function ensureMigrationsTable(db: SqliteDatabase): void {
  try {
    db.exec(CREATE_MIGRATIONS_TABLE_SQL);
  } catch (error) {
    throw wrapStorageError(error, 'Failed to initialise the migration registry');
  }
}

function readAppliedChecksums(db: SqliteDatabase): Map<string, string> {
  try {
    const rows = db.prepare('SELECT version, checksum FROM schema_migrations').all();
    const applied = new Map<string, string>();
    for (const row of rows) {
      const version = readRowText(row, 'version');
      const checksum = readRowText(row, 'checksum');
      if (version !== null && checksum !== null) {
        applied.set(version, checksum);
      }
    }
    return applied;
  } catch (error) {
    throw wrapStorageError(error, 'Failed to read applied migrations');
  }
}

function applyMigration(db: SqliteDatabase, file: MigrationFile): void {
  try {
    db.transaction(() => {
      db.exec(file.sql);
      db.prepare(INSERT_MIGRATION_SQL).run(
        file.version,
        file.name,
        file.checksum,
        new Date().toISOString(),
      );
    });
  } catch (error) {
    throw wrapStorageError(error, `Failed to apply migration ${file.version}`);
  }
}
