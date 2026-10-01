import { existsSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
  MAX_QUERY_CACHE_PAYLOAD_BYTES,
} from '../../src/config/defaults.js';
import type { CveChangeEvent, CveDetails } from '../../src/domain/cve.js';
import type { CpeMatchRecord, CpeRecord } from '../../src/domain/cpe.js';
import { DomainError } from '../../src/domain/errors.js';
import type { QueryCacheWrite } from '../../src/domain/ports.js';
import {
  openDatabase,
  type SqliteDatabase,
} from '../../src/infrastructure/sqlite/database.js';
import { runMigrations } from '../../src/infrastructure/sqlite/migrator.js';
import { SqliteCveRepository } from '../../src/infrastructure/sqlite/cve-repository.js';
import { SqliteCveHistoryRepository } from '../../src/infrastructure/sqlite/cve-history-repository.js';
import { SqliteCpeRepository } from '../../src/infrastructure/sqlite/cpe-repository.js';
import { SqliteCpeMatchRepository } from '../../src/infrastructure/sqlite/cpe-match-repository.js';
import { SqliteQueryCacheRepository } from '../../src/infrastructure/sqlite/query-cache-repository.js';
import { SqliteAppMetadataRepository } from '../../src/infrastructure/sqlite/metadata-repository.js';
import { Logger } from '../../src/shared/logger.js';
import { createTempDir, type TempDir } from '../helpers/temp.js';

const MIGRATIONS_DIR = fileURLToPath(new URL('../../migrations', import.meta.url));
const MIGRATION_VERSIONS = ['001_initial', '002_cve_history', '003_cpes', '004_cpe_matches'];

const FETCHED_AT = '2024-05-01T00:00:00.000Z';
const FUTURE_AT = '2035-01-01T00:00:00.000Z';
const PAST_AT = '2020-01-01T00:00:00.000Z';
const DELETE_CUTOFF = new Date('2025-01-01T00:00:00.000Z');
const OLD_TIMESTAMP = '2000-01-01T00:00:00.000Z';
const DEFAULT_CPE_NAME = 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*';

type Harness = {
  readonly dir: TempDir;
  readonly db: SqliteDatabase;
  readonly logger: Logger;
  readonly logs: string[];
  cleanup(): void;
};

const cleanups: Array<() => void> = [];

function createHarness(busyTimeoutMs = DEFAULT_SQLITE_BUSY_TIMEOUT_MS): Harness {
  const dir = createTempDir('nvd-sqlite-');
  const logs: string[] = [];
  const logger = new Logger({ level: 'warn', sink: (line) => logs.push(line) });
  const db = openDatabase({ path: dir.child('nvd.sqlite'), busyTimeoutMs, logger });

  const harness: Harness = {
    dir,
    db,
    logger,
    logs,
    cleanup: () => {
      db.close();
      dir.cleanup();
    },
  };
  cleanups.push(harness.cleanup);
  return harness;
}

async function createMigratedHarness(busyTimeoutMs?: number): Promise<Harness> {
  const harness = createHarness(busyTimeoutMs);
  await runMigrations(harness.db, { migrationsDir: MIGRATIONS_DIR, logger: harness.logger });
  return harness;
}

function quietLogger(): Logger {
  return new Logger({ level: 'silent', sink: () => undefined });
}

afterEach(() => {
  while (cleanups.length > 0) {
    cleanups.pop()?.();
  }
});

function makeCve(id = 'CVE-2024-3094', overrides: Partial<CveDetails> = {}): CveDetails {
  const base: CveDetails = {
    id,
    sourceIdentifier: 'nvd@nist.gov',
    published: '2024-03-29T00:00:00.000',
    lastModified: '2024-04-02T00:00:00.000',
    vulnStatus: 'Analyzed',
    description: 'XZ Utils backdoor allows remote attackers to execute code.',
    descriptions: [
      { lang: 'en', value: 'XZ Utils backdoor allows remote attackers to execute code.' },
    ],
    metrics: {
      cvssMetricV2: [],
      cvssMetricV30: [],
      cvssMetricV31: [
        {
          source: 'nvd@nist.gov',
          type: 'Primary',
          cvssData: {
            version: '3.1',
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            baseScore: 10,
            baseSeverity: 'CRITICAL',
          },
          baseSeverity: 'CRITICAL',
          exploitabilityScore: 3.9,
          impactScore: 6,
        },
      ],
      cvssMetricV40: [],
      other: {},
    },
    primaryCvss: {
      version: '3.1',
      score: 10,
      severity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      source: 'nvd@nist.gov',
      metricType: 'Primary',
    },
    weaknesses: [{ source: 'nvd@nist.gov', type: 'Primary', cwes: ['CWE-506'] }],
    cwes: ['CWE-506'],
    configurations: [
      {
        nodes: [
          {
            operator: 'OR',
            negate: false,
            children: [],
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*',
                matchCriteriaId: '8D1C2C3F-2F5F-4B53-9F2F-000000000001',
                versionStartIncluding: null,
                versionStartExcluding: null,
                versionEndIncluding: null,
                versionEndExcluding: '5.6.2',
              },
            ],
          },
        ],
      },
    ],
    references: [
      { url: 'https://example.com/advisory', source: 'nvd@nist.gov', tags: ['Vendor Advisory'] },
    ],
    isKnownExploited: true,
    kev: {
      dateAdded: '2024-04-01',
      dueDate: '2024-04-22',
      requiredAction: 'Apply mitigations',
      vulnerabilityName: 'XZ Utils Backdoor',
    },
  };
  return { ...base, ...overrides };
}

function makeHistoryEvent(changeId: string, cveId = 'CVE-2024-3094'): CveChangeEvent {
  return {
    cveId,
    eventName: 'CVE Modified',
    changeId,
    sourceIdentifier: 'nvd@nist.gov',
    created: '2024-04-02T00:00:00.000',
    details: [{ action: 'Changed', type: 'description', newValue: 'updated' }],
  };
}

function makeCpe(
  cpeNameId: string,
  cpeName = DEFAULT_CPE_NAME,
  deprecated = false,
): CpeRecord {
  return {
    cpeNameId,
    cpeName,
    deprecated,
    created: '2024-01-01T00:00:00.000',
    lastModified: '2024-02-01T00:00:00.000',
    titles: [{ title: 'Vendor Product', lang: 'en' }],
    refs: [{ ref: 'https://example.com/product', type: 'Advisory' }],
    deprecatedBy: [],
    deprecates: [],
  };
}

function makeCpeMatch(matchCriteriaId: string): CpeMatchRecord {
  return {
    matchCriteriaId,
    criteria: 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*',
    status: 'Active',
    created: '2024-03-01T00:00:00.000',
    lastModified: '2024-04-01T00:00:00.000',
    cpeLastModified: '2024-04-01T00:00:00.000',
    versionStartIncluding: '5.6.0',
    versionStartExcluding: null,
    versionEndIncluding: null,
    versionEndExcluding: '5.6.2',
    matches: [{ cpeName: DEFAULT_CPE_NAME, cpeNameId: 'cpe-id-1' }],
  };
}

type CachedCvePage = {
  items: CveDetails[];
  totalResults: number;
  startIndex: number;
  resultsPerPage: number;
};

function makeCacheEntry(): QueryCacheWrite<CachedCvePage> {
  return {
    cacheKey: 'sha256:entry-1',
    resource: 'cve-search',
    queryHash: 'sha256:query-1',
    value: { items: [makeCve()], totalResults: 1, startIndex: 0, resultsPerPage: 20 },
    createdAt: FETCHED_AT,
    fetchedAt: FETCHED_AT,
    expiresAt: FUTURE_AT,
  };
}

describe('sqlite migrations', () => {
  it('applies every migration exactly once and is idempotent', async () => {
    const harness = createHarness();

    const first = await runMigrations(harness.db, {
      migrationsDir: MIGRATIONS_DIR,
      logger: harness.logger,
    });
    expect(first.applied).toEqual(MIGRATION_VERSIONS);
    expect(first.skipped).toEqual([]);
    expect(first.drift).toEqual([]);

    const second = await runMigrations(harness.db, {
      migrationsDir: MIGRATIONS_DIR,
      logger: harness.logger,
    });
    expect(second.applied).toEqual([]);
    expect(second.skipped).toEqual(MIGRATION_VERSIONS);
    expect(second.drift).toEqual([]);

    const versions = harness.db
      .prepare('SELECT version FROM schema_migrations ORDER BY version')
      .all()
      .map((row) => row['version']);
    expect(versions).toEqual(MIGRATION_VERSIONS);
  });

  it('reports checksum drift without failing the run', async () => {
    const harness = createHarness();
    await runMigrations(harness.db, { migrationsDir: MIGRATIONS_DIR, logger: harness.logger });
    harness.db
      .prepare('UPDATE schema_migrations SET checksum = ? WHERE version = ?')
      .run('deadbeef', '001_initial');

    const result = await runMigrations(harness.db, {
      migrationsDir: MIGRATIONS_DIR,
      logger: harness.logger,
    });
    expect(result.applied).toEqual([]);
    expect(result.drift).toEqual(['001_initial']);
    expect(result.skipped).toEqual(
      MIGRATION_VERSIONS.filter((version) => version !== '001_initial'),
    );
    expect(harness.logs.some((line) => line.includes('migration_checksum_drift'))).toBe(true);
  });

  it('fails with a storage error when the migrations directory is missing', async () => {
    const harness = createHarness();

    let caught: unknown;
    try {
      await runMigrations(harness.db, {
        migrationsDir: harness.dir.child('missing-migrations'),
        logger: harness.logger,
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(DomainError);
    const domainError = caught as DomainError;
    expect(domainError.code).toBe('STORAGE_ERROR');
    expect(domainError.message).toBe('Migrations directory is not readable');
  });
});

describe('sqlite database', () => {
  it('creates missing parent directories for a file database', () => {
    const dir = createTempDir('nvd-sqlite-nested-');
    const databasePath = dir.child('nested', 'deeper', 'nvd.sqlite');
    const db = openDatabase({ path: databasePath, busyTimeoutMs: 200, logger: quietLogger() });
    cleanups.push(() => {
      db.close();
      dir.cleanup();
    });

    expect(db.isOpen()).toBe(true);
    expect(existsSync(databasePath)).toBe(true);
  });

  it('supports an in-memory database and an idempotent close', () => {
    const db = openDatabase({ path: ':memory:', busyTimeoutMs: 200, logger: quietLogger() });
    cleanups.push(() => db.close());

    db.exec('CREATE TABLE probe (id TEXT PRIMARY KEY)');
    expect(db.isOpen()).toBe(true);

    db.close();
    expect(db.isOpen()).toBe(false);
    expect(() => db.close()).not.toThrow();
  });

  it('joins nested transactions and rolls back only at the outermost level', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const first = makeCve('CVE-2024-1000');
    const second = makeCve('CVE-2024-2000');
    const options = { fetchedAt: FETCHED_AT, expiresAt: FUTURE_AT };

    harness.db.transaction(() => {
      repo.upsert(first, options);
      harness.db.transaction(() => {
        repo.upsert(second, options);
      });
    });
    expect(repo.count()).toBe(2);

    let caught: unknown;
    try {
      harness.db.transaction(() => {
        repo.upsert(makeCve('CVE-2024-3000'), options);
        harness.db.transaction(() => {
          throw new Error('inner failure');
        });
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe('inner failure');
    expect(repo.count()).toBe(2);
  });

  it('raises a storage error when another connection holds the write lock', async () => {
    const harness = await createMigratedHarness(200);
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const other = new DatabaseSync(harness.dir.child('nvd.sqlite'));

    try {
      other.exec('PRAGMA busy_timeout = 200');
      other.exec('BEGIN IMMEDIATE');

      let caught: unknown;
      try {
        repo.upsert(makeCve('CVE-2024-4000'), { fetchedAt: FETCHED_AT, expiresAt: FUTURE_AT });
      } catch (error) {
        caught = error;
      }

      expect(caught).toBeInstanceOf(DomainError);
      const domainError = caught as DomainError;
      expect(domainError.code).toBe('STORAGE_ERROR');
      expect(domainError.message).not.toContain('INSERT');
    } finally {
      try {
        other.exec('ROLLBACK');
      } catch {
        // No active transaction was started.
      }
      other.close();
    }
  });
});

describe('SqliteCveRepository', () => {
  it('round-trips a CVE record including its raw payload', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const cve = makeCve();

    repo.upsert(cve, { fetchedAt: FETCHED_AT, expiresAt: FUTURE_AT, rawJson: '{"raw":true}' });

    const stored = repo.findById(cve.id);
    expect(stored?.value).toEqual(cve);
    expect(stored?.fetchedAt).toBe(FETCHED_AT);
    expect(stored?.expiresAt).toBe(FUTURE_AT);

    const row = harness.db
      .prepare(
        'SELECT raw_json, published_at, primary_cvss_score, is_known_exploited FROM cves WHERE cve_id = ?',
      )
      .get(cve.id);
    expect(row?.['raw_json']).toBe('{"raw":true}');
    expect(row?.['published_at']).toBe(cve.published);
    expect(row?.['primary_cvss_score']).toBe(10);
    expect(row?.['is_known_exploited']).toBe(1);
  });

  it('returns null for unknown ids and an empty map for an empty id list', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });

    expect(repo.findById('CVE-2024-9999')).toBeNull();
    expect(repo.findManyByIds([]).size).toBe(0);
    expect(repo.count()).toBe(0);
  });

  it('reads the stored raw payload by id and treats unknown or blank values as absent', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const cve = makeCve('CVE-2024-0501');

    repo.upsert(cve, { fetchedAt: FETCHED_AT, expiresAt: FUTURE_AT, rawJson: '{"raw":"payload"}' });
    expect(repo.findRawById(cve.id)).toBe('{"raw":"payload"}');

    harness.db.prepare('UPDATE cves SET raw_json = ? WHERE cve_id = ?').run('', cve.id);
    expect(repo.findRawById(cve.id)).toBeNull();

    expect(repo.findRawById('CVE-2024-9998')).toBeNull();
  });

  it('updates existing rows while preserving created_at', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const cve = makeCve();

    repo.upsert(cve, { fetchedAt: FETCHED_AT, expiresAt: FUTURE_AT, rawJson: '{"version":1}' });
    harness.db
      .prepare('UPDATE cves SET created_at = ?, updated_at = ? WHERE cve_id = ?')
      .run(OLD_TIMESTAMP, OLD_TIMESTAMP, cve.id);

    repo.upsert(makeCve(cve.id, { description: 'updated summary' }), {
      fetchedAt: FETCHED_AT,
      expiresAt: FUTURE_AT,
      rawJson: '{"version":2}',
    });

    const row = harness.db
      .prepare(
        'SELECT created_at, updated_at, summary, raw_json FROM cves WHERE cve_id = ?',
      )
      .get(cve.id);
    expect(row?.['created_at']).toBe(OLD_TIMESTAMP);
    expect(row?.['updated_at']).not.toBe(OLD_TIMESTAMP);
    expect(row?.['summary']).toBe('updated summary');
    expect(row?.['raw_json']).toBe('{"version":2}');
    expect(repo.count()).toBe(1);
    expect(repo.findById(cve.id)?.value.description).toBe('updated summary');
  });

  it('batch upserts many CVEs and resolves per-entity raw payloads', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const first = makeCve('CVE-2024-0001');
    const second = makeCve('CVE-2024-0002');
    const third = makeCve('CVE-2024-0003');

    repo.upsertMany([first, second, third], {
      fetchedAt: FETCHED_AT,
      expiresAt: FUTURE_AT,
      rawJson: '{"fallback":true}',
      rawJsonById: new Map([
        [first.id, '{"first":true}'],
        [second.id, null],
      ]),
    });

    expect(repo.count()).toBe(3);
    const many = repo.findManyByIds([first.id, second.id, third.id, 'CVE-2024-0404']);
    expect(many.size).toBe(3);
    expect(many.get(first.id)?.value).toEqual(first);
    expect(many.get(second.id)?.value).toEqual(second);
    expect(many.get(third.id)?.value).toEqual(third);

    const rawRows = harness.db
      .prepare('SELECT cve_id, raw_json FROM cves ORDER BY cve_id')
      .all();
    expect(rawRows.map((row) => row['raw_json'])).toEqual([
      '{"first":true}',
      '{}',
      '{"fallback":true}',
    ]);
  });

  it('returns expired rows from find and removes them with deleteExpired', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const cve = makeCve();

    repo.upsert(cve, { fetchedAt: PAST_AT, expiresAt: PAST_AT });
    expect(repo.findById(cve.id)?.value).toEqual(cve);
    expect(repo.count()).toBe(1);

    expect(repo.deleteExpired(DELETE_CUTOFF)).toBe(1);
    expect(repo.findById(cve.id)).toBeNull();
    expect(repo.count()).toBe(0);
    expect(repo.deleteExpired(DELETE_CUTOFF)).toBe(0);
  });

  it('treats a corrupt normalized_json row as missing and warns', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveRepository({ db: harness.db, logger: harness.logger });
    const good = makeCve('CVE-2024-0001');
    const corruptId = 'CVE-2024-0002';
    repo.upsertMany([good, makeCve(corruptId)], {
      fetchedAt: FETCHED_AT,
      expiresAt: FUTURE_AT,
    });

    harness.db.prepare('UPDATE cves SET normalized_json = ? WHERE cve_id = ?').run('{not-json', corruptId);

    expect(repo.findById(corruptId)).toBeNull();
    expect(repo.count()).toBe(1);
    expect(repo.findManyByIds([good.id, corruptId]).size).toBe(1);
    expect(
      harness.logs.some(
        (line) => line.includes('cache_row_corrupt') && line.includes(corruptId),
      ),
    ).toBe(true);
  });
});

describe('SqliteCveHistoryRepository', () => {
  it('round-trips change events and removes expired rows', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCveHistoryRepository({ db: harness.db, logger: harness.logger });
    const first = makeHistoryEvent('change-1');
    const second = makeHistoryEvent('change-2', 'CVE-2024-0002');

    repo.upsertMany([first, second], {
      fetchedAt: FETCHED_AT,
      expiresAt: FUTURE_AT,
      rawJson: '{"event":true}',
    });

    expect(repo.count()).toBe(2);
    expect(repo.findByChangeId(first.changeId)?.value).toEqual(first);
    expect(repo.findManyByChangeIds(['change-1', 'change-2', 'change-3']).size).toBe(2);
    expect(
      harness.db
        .prepare('SELECT raw_json FROM cve_history WHERE change_id = ?')
        .get('change-1')?.['raw_json'],
    ).toBe('{"event":true}');

    const expired = makeHistoryEvent('change-expired');
    repo.upsertMany([expired], { fetchedAt: PAST_AT, expiresAt: PAST_AT });
    expect(repo.findByChangeId('change-expired')?.value).toEqual(expired);

    expect(repo.deleteExpired(DELETE_CUTOFF)).toBe(1);
    expect(repo.findByChangeId('change-expired')).toBeNull();
    expect(repo.count()).toBe(2);
  });
});

describe('SqliteCpeRepository', () => {
  it('round-trips CPE records by id and by name', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCpeRepository({ db: harness.db, logger: harness.logger });
    const active = makeCpe('cpe-id-1');
    const deprecated = makeCpe(
      'cpe-id-2',
      'cpe:2.3:a:vendor:legacy:1.0:*:*:*:*:*:*:*',
      true,
    );

    repo.upsertMany([active, deprecated], {
      fetchedAt: FETCHED_AT,
      expiresAt: FUTURE_AT,
      rawJson: '{}',
    });

    expect(repo.count()).toBe(2);
    expect(repo.findById('cpe-id-1')?.value).toEqual(active);
    expect(repo.findByName(active.cpeName)?.value).toEqual(active);
    expect(repo.findByName(active.cpeName.toUpperCase())?.value).toEqual(active);
    expect(repo.findByName('cpe:2.3:a:missing:missing:1.0:*:*:*:*:*:*:*')).toBeNull();
    expect(repo.findManyByIds(['cpe-id-1', 'cpe-id-2', 'cpe-id-3']).size).toBe(2);

    const deprecatedRow = harness.db
      .prepare('SELECT deprecated FROM cpes WHERE cpe_name_id = ?')
      .get('cpe-id-2');
    expect(deprecatedRow?.['deprecated']).toBe(1);
  });

  it('removes expired CPE rows', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCpeRepository({ db: harness.db, logger: harness.logger });

    repo.upsertMany([makeCpe('cpe-id-1')], { fetchedAt: PAST_AT, expiresAt: PAST_AT });
    expect(repo.findById('cpe-id-1')).not.toBeNull();

    expect(repo.deleteExpired(DELETE_CUTOFF)).toBe(1);
    expect(repo.count()).toBe(0);
  });
});

describe('SqliteCpeMatchRepository', () => {
  it('round-trips match criteria records and removes expired rows', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteCpeMatchRepository({ db: harness.db, logger: harness.logger });
    const match = makeCpeMatch('match-1');

    repo.upsertMany([match], { fetchedAt: FETCHED_AT, expiresAt: FUTURE_AT, rawJson: '{"m":1}' });
    expect(repo.count()).toBe(1);
    expect(repo.findById('match-1')?.value).toEqual(match);
    expect(repo.findById('match-missing')).toBeNull();

    repo.upsertMany([makeCpeMatch('match-expired')], { fetchedAt: PAST_AT, expiresAt: PAST_AT });
    expect(repo.deleteExpired(DELETE_CUTOFF)).toBe(1);
    expect(repo.count()).toBe(1);
  });
});

describe('SqliteQueryCacheRepository', () => {
  it('stores and reads query cache entries', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteQueryCacheRepository({ db: harness.db, logger: harness.logger });
    const entry = makeCacheEntry();

    repo.put(entry);
    expect(repo.count()).toBe(1);

    const stored = repo.get<CachedCvePage>(entry.cacheKey);
    expect(stored?.value).toEqual(entry.value);
    expect(stored?.fetchedAt).toBe(FETCHED_AT);
    expect(stored?.expiresAt).toBe(FUTURE_AT);
    expect(repo.get('sha256:missing')).toBeNull();

    const row = harness.db
      .prepare('SELECT payload_json, byte_size FROM query_cache WHERE cache_key = ?')
      .get(entry.cacheKey);
    const payloadJson = row?.['payload_json'];
    expect(typeof payloadJson).toBe('string');
    expect(row?.['byte_size']).toBe(Buffer.byteLength(payloadJson as string, 'utf8'));

    repo.delete(entry.cacheKey);
    expect(repo.get(entry.cacheKey)).toBeNull();
    expect(repo.count()).toBe(0);
  });

  it('rejects payloads above the configured size budget', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteQueryCacheRepository({ db: harness.db, logger: harness.logger });
    const entry = makeCacheEntry();

    let caught: unknown;
    try {
      repo.put({
        ...entry,
        cacheKey: 'sha256:huge',
        value: { blob: 'x'.repeat(MAX_QUERY_CACHE_PAYLOAD_BYTES + 16) },
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(DomainError);
    const domainError = caught as DomainError;
    expect(domainError.code).toBe('STORAGE_ERROR');
    expect(domainError.message).toBe('Cache entry exceeds the configured size budget');
    expect(repo.get('sha256:huge')).toBeNull();
  });

  it('returns expired entries while they last and deletes them afterwards', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteQueryCacheRepository({ db: harness.db, logger: harness.logger });
    const expired: QueryCacheWrite<CachedCvePage> = {
      ...makeCacheEntry(),
      cacheKey: 'sha256:expired',
      fetchedAt: PAST_AT,
      expiresAt: PAST_AT,
    };

    repo.put(expired);
    expect(repo.get(expired.cacheKey)).not.toBeNull();

    expect(repo.deleteExpired(DELETE_CUTOFF)).toBe(1);
    expect(repo.get(expired.cacheKey)).toBeNull();
  });

  it('drops corrupt payloads instead of throwing', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteQueryCacheRepository({ db: harness.db, logger: harness.logger });
    const entry = makeCacheEntry();

    repo.put(entry);
    harness.db
      .prepare('UPDATE query_cache SET payload_json = ? WHERE cache_key = ?')
      .run('{not-json', entry.cacheKey);

    expect(repo.get(entry.cacheKey)).toBeNull();
    expect(
      harness.logs.some(
        (line) => line.includes('cache_row_corrupt') && line.includes(entry.cacheKey),
      ),
    ).toBe(true);
  });
});

describe('SqliteAppMetadataRepository', () => {
  it('reads, writes and lists metadata entries', async () => {
    const harness = await createMigratedHarness();
    const repo = new SqliteAppMetadataRepository({ db: harness.db, logger: harness.logger });

    expect(repo.get('schema:state')).toBeNull();

    repo.set('schema:state', 'ready');
    repo.set('schema:version', '1');
    expect(repo.get('schema:state')).toBe('ready');

    repo.set('schema:state', 'updated');
    expect(repo.get('schema:state')).toBe('updated');
    expect(repo.all()).toEqual({ 'schema:state': 'updated', 'schema:version': '1' });

    const row = harness.db
      .prepare('SELECT updated_at FROM app_metadata WHERE "key" = ?')
      .get('schema:state');
    expect(typeof row?.['updated_at']).toBe('string');
  });
});
