import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

import { CachedResourceLoader } from '../../src/application/cached-resource-loader.js';
import { DEFAULT_SQLITE_BUSY_TIMEOUT_MS } from '../../src/config/defaults.js';
import type { CveChangeEvent, CveDetails } from '../../src/domain/cve.js';
import type { CpeMatchRecord, CpeRecord } from '../../src/domain/cpe.js';
import type { Clock } from '../../src/domain/ports.js';
import { SqliteCpeMatchRepository } from '../../src/infrastructure/sqlite/cpe-match-repository.js';
import { SqliteCpeRepository } from '../../src/infrastructure/sqlite/cpe-repository.js';
import { SqliteCveHistoryRepository } from '../../src/infrastructure/sqlite/cve-history-repository.js';
import { SqliteCveRepository } from '../../src/infrastructure/sqlite/cve-repository.js';
import {
  openDatabase,
  type SqliteDatabase,
} from '../../src/infrastructure/sqlite/database.js';
import { runMigrations } from '../../src/infrastructure/sqlite/migrator.js';
import type { DiskCache } from '../../src/infrastructure/cache/disk-cache.js';
import { SingleFlight } from '../../src/shared/async.js';
import { Logger } from '../../src/shared/logger.js';
import { createTempDir, type TempDir } from '../helpers/temp.js';

const MIGRATIONS_DIR = fileURLToPath(new URL('../../migrations', import.meta.url));

const NOW_ISO = '2026-01-15T12:00:00.000Z';
const FUTURE_ISO = '2035-01-01T00:00:00.000Z';
const CACHE_KEY = `sha256:${'a'.repeat(64)}`;
const CVE_ID = 'CVE-2024-3094';

const fixedClock: Clock = { now: () => new Date(NOW_ISO) };

type RawHarness = {
  readonly dir: TempDir;
  readonly db: SqliteDatabase;
  readonly logs: string[];
  readonly logger: Logger;
  readonly cveRepo: SqliteCveRepository;
  readonly cpeRepo: SqliteCpeRepository;
  readonly historyRepo: SqliteCveHistoryRepository;
  readonly matchRepo: SqliteCpeMatchRepository;
  cleanup(): void;
};

const cleanups: Array<() => void> = [];

async function createHarness(): Promise<RawHarness> {
  const dir = createTempDir('nvd-raw-payload-');
  const logs: string[] = [];
  const logger = new Logger({ level: 'warn', sink: (line) => logs.push(line) });
  const db = openDatabase({
    path: dir.child('nvd.sqlite'),
    busyTimeoutMs: DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
    logger,
  });
  await runMigrations(db, { migrationsDir: MIGRATIONS_DIR, logger });

  const harness: RawHarness = {
    dir,
    db,
    logs,
    logger,
    cveRepo: new SqliteCveRepository({ db, logger }),
    cpeRepo: new SqliteCpeRepository({ db, logger }),
    historyRepo: new SqliteCveHistoryRepository({ db, logger }),
    matchRepo: new SqliteCpeMatchRepository({ db, logger }),
    cleanup: () => {
      db.close();
      dir.cleanup();
    },
  };
  cleanups.push(harness.cleanup);
  return harness;
}

afterEach(() => {
  while (cleanups.length > 0) {
    cleanups.pop()?.();
  }
});

/**
 * The loader only needs reading from the disk cache in these tests: everything is fresh in
 * SQLite, so the hit path never writes. A miss keeps the assertion local to SQLite.
 */
function createEmptyDiskCache(): DiskCache {
  return {
    read: async () => null,
    write: async () => false,
  } as unknown as DiskCache;
}

function createLoader(harness: RawHarness): CachedResourceLoader {
  return new CachedResourceLoader({
    diskCache: createEmptyDiskCache(),
    singleFlight: new SingleFlight(),
    clock: fixedClock,
    logger: harness.logger,
  });
}

function makeCve(id: string = CVE_ID, overrides: Partial<CveDetails> = {}): CveDetails {
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
      cvssMetricV31: [],
      cvssMetricV40: [],
      other: {},
    },
    primaryCvss: null,
    weaknesses: [],
    cwes: [],
    configurations: [],
    references: [],
    isKnownExploited: false,
    kev: null,
  };
  return { ...base, ...overrides };
}

function makeCpe(cpeNameId: string): CpeRecord {
  return {
    cpeNameId,
    cpeName: `cpe:2.3:a:vendor:product:${cpeNameId.toLowerCase()}:*:*:*:*:*:*:*`,
    deprecated: false,
    created: '2024-01-01T00:00:00.000',
    lastModified: '2024-02-01T00:00:00.000',
    titles: [{ title: 'Vendor Product', lang: 'en' }],
    refs: [],
    deprecatedBy: [],
    deprecates: [],
  };
}

function makeHistoryEvent(changeId: string): CveChangeEvent {
  return {
    cveId: CVE_ID,
    eventName: 'CVE Modified',
    changeId,
    sourceIdentifier: 'nvd@nist.gov',
    created: '2024-04-02T00:00:00.000',
    details: [{ action: 'Changed', type: 'description', newValue: 'updated' }],
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
    matches: [],
  };
}

describe('raw payload persistence', () => {
  it('Case A: resolves raw from SQLite on a fresh hit when the disk cache is empty', async () => {
    const harness = await createHarness();
    const rawPayload = { vulnerabilities: [{ cve: { id: CVE_ID } }] };
    harness.cveRepo.upsert(makeCve(), {
      fetchedAt: NOW_ISO,
      expiresAt: FUTURE_ISO,
      rawJson: JSON.stringify(rawPayload),
    });

    let upstreamCalls = 0;
    const result = await createLoader(harness).load<CveDetails>({
      resource: 'cve',
      cacheKey: CACHE_KEY,
      ttlSeconds: 86_400,
      readCached: () => harness.cveRepo.findById(CVE_ID),
      writeCached: () => undefined,
      fetchUpstream: async () => {
        upstreamCalls += 1;
        return { found: false as const };
      },
      needsRaw: true,
      readRaw: () => harness.cveRepo.findRawById(CVE_ID),
    });

    expect(result.meta.cacheStatus).toBe('hit');
    expect(result.meta.source).toBe('cache');
    expect(result.raw).toEqual(rawPayload);
    expect(upstreamCalls).toBe(0);
  });

  it('Case B: a corrupt stored raw payload falls back to the disk cache and warns', async () => {
    const harness = await createHarness();
    harness.cveRepo.upsert(makeCve(), {
      fetchedAt: NOW_ISO,
      expiresAt: FUTURE_ISO,
      rawJson: '{"valid":true}',
    });
    harness.db
      .prepare('UPDATE cves SET raw_json = ? WHERE cve_id = ?')
      .run('{not-json', CVE_ID);

    const result = await createLoader(harness).load<CveDetails>({
      resource: 'cve',
      cacheKey: CACHE_KEY,
      ttlSeconds: 86_400,
      readCached: () => harness.cveRepo.findById(CVE_ID),
      writeCached: () => undefined,
      fetchUpstream: async () => ({ found: false as const }),
      needsRaw: true,
      readRaw: () => harness.cveRepo.findRawById(CVE_ID),
    });

    expect(result.meta.cacheStatus).toBe('hit');
    expect(result.raw).toBeUndefined();
    expect(harness.logs.some((line) => line.includes('cache_raw_corrupt'))).toBe(true);
    expect(result.meta.warnings.some((warning) => warning.includes('Raw payload'))).toBe(true);
  });

  it('Case C: batch upserts persist each entity raw payload (CPE, history, match)', async () => {
    const harness = await createHarness();

    const firstCpe = makeCpe('B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C');
    const secondCpe = makeCpe('C1C1C1C1-1111-2222-3333-444444444444');
    harness.cpeRepo.upsertMany([firstCpe, secondCpe], {
      fetchedAt: NOW_ISO,
      expiresAt: FUTURE_ISO,
      rawJsonById: new Map([
        [firstCpe.cpeNameId, '{"cpe":1}'],
        [secondCpe.cpeNameId, '{"cpe":2}'],
      ]),
    });
    expect(harness.cpeRepo.findRawById(firstCpe.cpeNameId)).toBe('{"cpe":1}');
    expect(harness.cpeRepo.findRawById(secondCpe.cpeNameId)).toBe('{"cpe":2}');

    const firstChange = makeHistoryEvent('change-1');
    const secondChange = makeHistoryEvent('change-2');
    harness.historyRepo.upsertMany([firstChange, secondChange], {
      fetchedAt: NOW_ISO,
      expiresAt: FUTURE_ISO,
      rawJsonById: new Map([
        [firstChange.changeId, '{"change":1}'],
        [secondChange.changeId, '{"change":2}'],
      ]),
    });
    expect(harness.historyRepo.findRawByChangeId(firstChange.changeId)).toBe('{"change":1}');
    expect(harness.historyRepo.findRawByChangeId(secondChange.changeId)).toBe('{"change":2}');

    const firstMatch = makeCpeMatch('match-1');
    const secondMatch = makeCpeMatch('match-2');
    harness.matchRepo.upsertMany([firstMatch, secondMatch], {
      fetchedAt: NOW_ISO,
      expiresAt: FUTURE_ISO,
      rawJsonById: new Map([
        [firstMatch.matchCriteriaId, '{"match":1}'],
        [secondMatch.matchCriteriaId, '{"match":2}'],
      ]),
    });
    expect(harness.matchRepo.findRawById(firstMatch.matchCriteriaId)).toBe('{"match":1}');
    expect(harness.matchRepo.findRawById(secondMatch.matchCriteriaId)).toBe('{"match":2}');
  });

  it('Case D: unknown raw payload ids return null without throwing', async () => {
    const harness = await createHarness();

    expect(harness.cveRepo.findRawById('CVE-2024-9999')).toBeNull();
    expect(harness.cpeRepo.findRawById('missing-cpe')).toBeNull();
    expect(harness.historyRepo.findRawByChangeId('missing-change')).toBeNull();
    expect(harness.matchRepo.findRawById('missing-match')).toBeNull();
  });
});
