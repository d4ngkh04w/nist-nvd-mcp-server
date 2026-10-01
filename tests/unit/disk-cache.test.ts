import { createHash } from 'node:crypto';
import { readdir, stat, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { CACHE_RESOURCE_DIRECTORIES } from '../../src/config/defaults.js';
import type { CacheResource } from '../../src/domain/cache.js';
import { DiskCache, type DiskCacheEnvelope } from '../../src/infrastructure/cache/disk-cache.js';
import { Logger } from '../../src/shared/logger.js';
import { createTempDir, type TempDir } from '../helpers/temp.js';

const NOW = new Date('2026-01-01T12:00:00.000Z');
const ENVELOPE_VERSION = 1;
const MAX_ENTRY_BYTES = 100_000;

type LogRecord = { level: string; event: string } & Record<string, unknown>;

type Harness = {
  temp: TempDir;
  cache: DiskCache;
  cacheDir: string;
  logs: LogRecord[];
  events(): string[];
};

function createHarness(): Harness {
  const temp = createTempDir();
  const logs: LogRecord[] = [];
  const logger = new Logger({
    level: 'debug',
    sink: (line) => logs.push(JSON.parse(line) as LogRecord),
  });
  const cacheDir = temp.child('cache');
  const cache = new DiskCache({
    directory: cacheDir,
    envelopeVersion: ENVELOPE_VERSION,
    maxEntryBytes: MAX_ENTRY_BYTES,
    logger,
    now: () => NOW,
  });
  return { temp, cache, cacheDir, logs, events: () => logs.map((record) => record.event) };
}

function diskKey(seed: string): string {
  return createHash('sha256').update(seed).digest('hex');
}

function buildEnvelope<T>(
  resource: CacheResource,
  key: string,
  payload: T,
  overrides: Partial<DiskCacheEnvelope<T>> = {},
): DiskCacheEnvelope<T> {
  return {
    version: ENVELOPE_VERSION,
    resource,
    queryHash: `sha256:${key}`,
    createdAt: '2025-12-31T00:00:00.000Z',
    expiresAt: '2027-01-01T00:00:00.000Z',
    payload,
    ...overrides,
  };
}

function entryPath(cacheDir: string, resourceDir: string, key: string): string {
  return path.join(cacheDir, resourceDir, `${key}.json`);
}

function validEnvelopeFile(key: string): Record<string, unknown> {
  return {
    version: ENVELOPE_VERSION,
    resource: 'cve',
    queryHash: `sha256:${key}`,
    createdAt: '2025-12-31T00:00:00.000Z',
    expiresAt: '2027-01-01T00:00:00.000Z',
    payload: { id: 'CVE-2024-3094' },
  };
}

const mismatchCases: Array<{ name: string; key: string; contents: string }> = [
  {
    name: 'array instead of an envelope',
    key: diskKey('mismatch-array'),
    contents: JSON.stringify([1, 2, 3]),
  },
  {
    name: 'wrong version',
    key: diskKey('mismatch-version'),
    contents: JSON.stringify({ ...validEnvelopeFile(diskKey('mismatch-version')), version: 99 }),
  },
  {
    name: 'mismatching resource',
    key: diskKey('mismatch-resource'),
    contents: JSON.stringify({ ...validEnvelopeFile(diskKey('mismatch-resource')), resource: 'cpe' }),
  },
  {
    name: 'mismatching queryHash',
    key: diskKey('mismatch-query-hash'),
    contents: JSON.stringify({
      ...validEnvelopeFile(diskKey('mismatch-query-hash')),
      queryHash: `sha256:${diskKey('somewhere-else')}`,
    }),
  },
  {
    name: 'payload is a string',
    key: diskKey('mismatch-payload-string'),
    contents: JSON.stringify({
      ...validEnvelopeFile(diskKey('mismatch-payload-string')),
      payload: 'not-an-object',
    }),
  },
  {
    name: 'payload is null',
    key: diskKey('mismatch-payload-null'),
    contents: JSON.stringify({
      ...validEnvelopeFile(diskKey('mismatch-payload-null')),
      payload: null,
    }),
  },
  {
    name: 'payload is an array',
    key: diskKey('mismatch-payload-array'),
    contents: JSON.stringify({
      ...validEnvelopeFile(diskKey('mismatch-payload-array')),
      payload: [1, 2, 3],
    }),
  },
];

let harness: Harness;

beforeEach(() => {
  harness = createHarness();
});

afterEach(() => {
  harness.temp.cleanup();
});

describe('DiskCache.ensureDirectories', () => {
  it('creates the root, tmp and every resource directory', async () => {
    await harness.cache.ensureDirectories();

    const directories = [
      harness.cacheDir,
      path.join(harness.cacheDir, 'tmp'),
      ...CACHE_RESOURCE_DIRECTORIES.map((name) => path.join(harness.cacheDir, name)),
    ];
    for (const directory of directories) {
      const info = await stat(directory);
      expect(info.isDirectory()).toBe(true);
    }
  });
});

describe('DiskCache.read/write', () => {
  it('round-trips an envelope and leaves no temp files behind', async () => {
    await harness.cache.ensureDirectories();
    const key = diskKey('round-trip');
    const payload = { id: 'CVE-2024-3094', summary: 'xz backdoor' };

    const wrote = await harness.cache.write(buildEnvelope('cve', key, payload));
    expect(wrote).toBe(true);

    const stored = await harness.cache.read<typeof payload>('cve', key);
    expect(stored).toEqual(buildEnvelope('cve', key, payload));

    const tmpEntries = await readdir(path.join(harness.cacheDir, 'tmp'));
    expect(tmpEntries.filter((name) => name.endsWith('.tmp'))).toEqual([]);
  });

  it('returns null for a missing entry', async () => {
    const result = await harness.cache.read('cve', diskKey('missing'));

    expect(result).toBeNull();
    expect(harness.events()).not.toContain('cache_corrupted');
  });

  it('deletes a corrupt entry, returns null and logs cache_corrupted', async () => {
    await harness.cache.ensureDirectories();
    const key = diskKey('corrupt');
    const filePath = entryPath(harness.cacheDir, 'cves', key);
    await writeFile(filePath, '{ this is not json', 'utf8');

    expect(await harness.cache.read('cve', key)).toBeNull();
    await expect(stat(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(harness.events()).toContain('cache_corrupted');
  });

  it.each(mismatchCases)('deletes a mismatching envelope: $name', async ({ key, contents }) => {
    await harness.cache.ensureDirectories();
    const filePath = entryPath(harness.cacheDir, 'cves', key);
    await writeFile(filePath, contents, 'utf8');

    expect(await harness.cache.read('cve', key)).toBeNull();
    await expect(stat(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(harness.events()).toContain('cache_corrupted');
  });

  it('skips an entry that exceeds maxEntryBytes and writes nothing', async () => {
    await harness.cache.ensureDirectories();
    const key = diskKey('oversized-write');
    const oversizedPayload = 'x'.repeat(MAX_ENTRY_BYTES + 1_024);

    const wrote = await harness.cache.write(buildEnvelope('cve', key, { blob: oversizedPayload }));

    expect(wrote).toBe(false);
    expect(harness.events()).toContain('cache_entry_skipped');
    await expect(stat(entryPath(harness.cacheDir, 'cves', key))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    expect(await readdir(path.join(harness.cacheDir, 'tmp'))).toEqual([]);
  });

  it('deletes an oversized entry when reading', async () => {
    await harness.cache.ensureDirectories();
    const key = diskKey('oversized-read');
    const filePath = entryPath(harness.cacheDir, 'cves', key);
    await writeFile(filePath, 'x'.repeat(MAX_ENTRY_BYTES + 1), 'utf8');

    expect(await harness.cache.read('cve', key)).toBeNull();
    await expect(stat(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(harness.events()).toContain('cache_entry_oversized');
  });

  it('rejects a key that is not a 64-hex digest without touching the filesystem', async () => {
    expect(await harness.cache.read('cve', '../escape-attempt')).toBeNull();
    await harness.cache.remove('cve', 'not-a-digest');

    expect(
      harness.events().filter((event) => event === 'cache_key_rejected'),
    ).toHaveLength(2);
    // No directory or file was created, proving the key was rejected before any path was built.
    await expect(stat(harness.cacheDir)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('accepts the sha256:-prefixed cache key produced by the identity helpers', async () => {
    await harness.cache.ensureDirectories();
    const key = diskKey('prefixed-key');
    const payload = { id: 'CVE-2024-3094' };
    await harness.cache.write(buildEnvelope('cve', key, payload));

    const stored = await harness.cache.read<typeof payload>('cve', `sha256:${key}`);
    expect(stored?.payload).toEqual(payload);

    await harness.cache.remove('cve', `sha256:${key}`);
    expect(await harness.cache.read('cve', key)).toBeNull();
  });

  it('logs and returns false when the atomic write cannot be performed', async () => {
    const temp = createTempDir();
    try {
      const logs: LogRecord[] = [];
      const logger = new Logger({
        level: 'debug',
        sink: (line) => logs.push(JSON.parse(line) as LogRecord),
      });
      const blockedDirectory = temp.child('blocked');
      await writeFile(blockedDirectory, 'this is a file, not a directory', 'utf8');
      const cache = new DiskCache({
        directory: blockedDirectory,
        envelopeVersion: ENVELOPE_VERSION,
        maxEntryBytes: MAX_ENTRY_BYTES,
        logger,
      });

      const wrote = await cache.write(buildEnvelope('cve', diskKey('blocked'), { id: 'CVE-2024-3094' }));

      expect(wrote).toBe(false);
      expect(logs.map((record) => record.event)).toContain('cache_write_failed');
    } finally {
      temp.cleanup();
    }
  });

  it('removes an entry', async () => {
    await harness.cache.ensureDirectories();
    const key = diskKey('remove-me');
    await harness.cache.write(buildEnvelope('cpe', key, { id: 'cpe:2.3:a:vendor:product' }));
    const filePath = entryPath(harness.cacheDir, 'cpes', key);

    await harness.cache.remove('cpe', key);

    await expect(stat(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await harness.cache.read('cpe', key)).toBeNull();
  });
});

describe('DiskCache.cleanup', () => {
  it('deletes expired entries and trims the budget keeping the newest files', async () => {
    await harness.cache.ensureDirectories();
    const expiredKey = diskKey('cleanup-expired');
    const oldKey = diskKey('cleanup-old');
    const newKey = diskKey('cleanup-new');
    await harness.cache.write(
      buildEnvelope('cve', expiredKey, { name: 'expired' }, { expiresAt: '2025-12-31T00:00:00.000Z' }),
    );
    await harness.cache.write(buildEnvelope('cve', oldKey, { name: 'old' }));
    await harness.cache.write(buildEnvelope('cve', newKey, { name: 'new' }));

    const expiredPath = entryPath(harness.cacheDir, 'cves', expiredKey);
    const oldPath = entryPath(harness.cacheDir, 'cves', oldKey);
    const newPath = entryPath(harness.cacheDir, 'cves', newKey);
    await utimes(oldPath, new Date('2026-01-01T00:00:00.000Z'), new Date('2026-01-01T00:00:00.000Z'));
    await utimes(
      newPath,
      new Date('2026-01-01T11:59:00.000Z'),
      new Date('2026-01-01T11:59:00.000Z'),
    );

    const newSize = (await stat(newPath)).size;
    const stats = await harness.cache.cleanup({ maxBytes: newSize + 16, maxAgeMs: 0 });

    await expect(stat(expiredPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(stat(oldPath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect((await stat(newPath)).isFile()).toBe(true);
    expect(stats.scannedFiles).toBe(3);
    expect(stats.removedFiles).toBe(2);
    expect(stats.totalBytes).toBe(newSize);
    expect(stats.freedBytes).toBeGreaterThan(0);
  });

  it('deletes entries whose mtime is older than maxAgeMs', async () => {
    await harness.cache.ensureDirectories();
    const staleKey = diskKey('age-stale');
    const recentKey = diskKey('age-recent');
    await harness.cache.write(buildEnvelope('cve', staleKey, { name: 'stale' }));
    await harness.cache.write(buildEnvelope('cve', recentKey, { name: 'recent' }));

    const stalePath = entryPath(harness.cacheDir, 'cves', staleKey);
    const recentPath = entryPath(harness.cacheDir, 'cves', recentKey);
    await utimes(
      stalePath,
      new Date('2026-01-01T09:00:00.000Z'),
      new Date('2026-01-01T09:00:00.000Z'),
    );
    await utimes(
      recentPath,
      new Date('2026-01-01T11:59:30.000Z'),
      new Date('2026-01-01T11:59:30.000Z'),
    );

    const stats = await harness.cache.cleanup({
      maxBytes: Number.MAX_SAFE_INTEGER,
      maxAgeMs: 3_600_000,
    });

    await expect(stat(stalePath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect((await stat(recentPath)).isFile()).toBe(true);
    expect(stats.removedFiles).toBe(1);
  });

  it('deletes stale tmp files but keeps recent ones', async () => {
    await harness.cache.ensureDirectories();
    const tmpDirectory = path.join(harness.cacheDir, 'tmp');
    const stalePath = path.join(tmpDirectory, 'stale.tmp');
    const recentPath = path.join(tmpDirectory, 'recent.tmp');
    await writeFile(stalePath, 'partial write', 'utf8');
    await writeFile(recentPath, 'partial write', 'utf8');
    await utimes(
      stalePath,
      new Date('2026-01-01T10:00:00.000Z'),
      new Date('2026-01-01T10:00:00.000Z'),
    );
    await utimes(
      recentPath,
      new Date('2026-01-01T11:59:30.000Z'),
      new Date('2026-01-01T11:59:30.000Z'),
    );

    const stats = await harness.cache.cleanup({
      maxBytes: Number.MAX_SAFE_INTEGER,
      maxAgeMs: 0,
    });

    await expect(stat(stalePath)).rejects.toMatchObject({ code: 'ENOENT' });
    expect((await stat(recentPath)).isFile()).toBe(true);
    expect(stats.removedFiles).toBe(1);
  });

  it('reports stats for the resource directories', async () => {
    await harness.cache.ensureDirectories();
    await harness.cache.write(buildEnvelope('cve', diskKey('stats-1'), { id: 'CVE-2024-3094' }));
    await harness.cache.write(buildEnvelope('cpe', diskKey('stats-2'), { id: 'cpe:2.3:a:x:y' }));

    const stats = await harness.cache.stats();

    expect(stats.files).toBe(2);
    expect(stats.totalBytes).toBeGreaterThan(0);
  });
});
