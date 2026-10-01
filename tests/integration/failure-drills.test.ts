import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { createHarness, type Harness } from '../helpers/harness.js';
import { NvdMockServer, type NvdMockRequest } from '../helpers/nvd-mock-server.js';

const FAST = {
  minIntervalMs: 1,
  maxConcurrency: 1,
  requestTimeoutMs: 150,
  maxRetries: 1,
  retryBaseDelayMs: 1,
};

function cveByIds(harness: Harness): void {
  harness.nvd.on('/cves/2.0', (request: NvdMockRequest) => {
    const ids = (request.params['cveIds'] ?? 'CVE-2024-1000').split(',').filter(Boolean);
    return {
      status: 200,
      body: cveResponse(ids.map((id) => cveItem({ id })), { totalResults: ids.length }),
    };
  });
}

function countRows(sqlitePath: string, table: string): number {
  const probe = new DatabaseSync(sqlitePath, { readOnly: true });
  try {
    const row = probe.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as
      | { count: number }
      | undefined;
    return row?.count ?? -1;
  } finally {
    probe.close();
  }
}

function integrity(sqlitePath: string): string {
  const probe = new DatabaseSync(sqlitePath, { readOnly: true });
  try {
    const row = probe.prepare('PRAGMA integrity_check').get() as
      | { integrity_check: string }
      | undefined;
    return row?.integrity_check ?? 'unknown';
  } finally {
    probe.close();
  }
}

describe('failure drills: shutdown, locking, upstream errors and corruption', () => {
  let harness: Harness | undefined;
  let unhandled: unknown[] = [];

  const onUnhandledRejection = (reason: unknown): void => {
    unhandled.push(reason);
  };

  beforeEach(() => {
    unhandled = [];
    process.on('unhandledRejection', onUnhandledRejection);
  });

  afterEach(async () => {
    process.off('unhandledRejection', onUnhandledRejection);
    await harness?.close();
    harness = undefined;
  });

  it('survives a shutdown that races an in-flight upstream request', async () => {
    harness = await createHarness({ nvdOverrides: { ...FAST, requestTimeoutMs: 5_000 } });
    harness.nvd.on('/cves/2.0', () => ({
      status: 200,
      body: cveResponse([cveItem({ id: 'CVE-2024-1000' })]),
      delayMs: 300,
    }));

    const inFlight = harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });
    // Close the whole app (rate limiter + SQLite handle) while the request is still upstream.
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(() => harness!.app.close()).not.toThrow();

    const outcome = await inFlight;
    // The call must settle deterministically: either served or a structured tool error.
    expect(typeof outcome.isError).toBe('boolean');
    if (outcome.isError) {
      expect(typeof outcome.error?.['code']).toBe('string');
    } else {
      // Graceful degradation: the upstream payload was fetched, only the cache write failed.
      const meta = outcome.structuredContent?.['meta'] as { warnings?: string[] } | undefined;
      expect(meta?.warnings?.join(' ')).toMatch(/local database/);
    }
    expect(outcome.text).not.toMatch(/SQLITE|node:sqlite|at Object\./);

    // A second close (harness teardown) must stay harmless, and the file must be readable.
    expect(() => harness!.app.close()).not.toThrow();
    expect(['ok', 'unknown']).toContain(integrity(harness.config.storage.sqlitePath));

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(unhandled).toEqual([]);
  });

  it('restarts on an existing database and cache and serves the row without upstream', async () => {
    const first = await createHarness({ nvdOverrides: FAST, keepTemp: true });
    cveByIds(first);
    const sqlitePath = first.config.storage.sqlitePath;
    const cacheDirectory = first.config.cache.directory;
    expect((await first.callTool('get_cve', { cveId: 'CVE-2024-1000' })).isError).toBe(false);
    const upstreamCalls = first.nvd.countFor('/cves/2.0');
    expect(upstreamCalls).toBe(1);
    await first.close();

    // A second boot reuses the same SQLite file and disk cache; NVD is now unreachable.
    const mock = await NvdMockServer.start();
    try {
      mock.on('/cves/2.0', () => ({ status: 500, body: { error: 'down' } }));
      harness = await createHarness({
        nvd: mock,
        nvdOverrides: { ...FAST, maxRetries: 0 },
        storage: { sqlitePath },
        cache: { directory: cacheDirectory },
        keepTemp: true,
      });

      const outcome = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });
      expect(outcome.isError).toBe(false);
      const meta = outcome.structuredContent?.['meta'] as { cacheStatus?: string } | undefined;
      expect(meta?.cacheStatus).toBe('hit');
      // No upstream traffic was needed for a row that was already durable.
      expect(mock.countFor('/cves/2.0')).toBe(0);
      expect(integrity(sqlitePath)).toBe('ok');
      expect(countRows(sqlitePath, 'cves')).toBe(1);
    } finally {
      await harness?.close();
      harness = undefined;
      first.temp.cleanup();
    }
  });

  it('retries a contended SQLite write without stalling the event loop', async () => {
    harness = await createHarness({ nvdOverrides: FAST, storage: { sqliteBusyTimeoutMs: 250 } });
    cveByIds(harness);

    const blocker = new DatabaseSync(harness.config.storage.sqlitePath);
    blocker.exec('BEGIN IMMEDIATE');
    blocker.prepare('INSERT INTO app_metadata (key, value, updated_at) VALUES (?, ?, ?)').run(
      'blocker',
      'held',
      new Date().toISOString(),
    );

    // A 20 ms heartbeat proves the event loop is never blocked while writes wait for the lock.
    let ticks = 0;
    let maxGapMs = 0;
    let lastTick = Date.now();
    const heartbeat = setInterval(() => {
      const now = Date.now();
      maxGapMs = Math.max(maxGapMs, now - lastTick);
      lastTick = now;
      ticks += 1;
    }, 20);

    const ids = Array.from({ length: 10 }, (_, index) => `CVE-2024-${3000 + index}`);
    const startedAt = Date.now();
    const inFlight = Promise.all(ids.map((cveId) => harness!.callTool('get_cve', { cveId })));
    // The competing writer releases the lock while the server is persisting its own rows.
    setTimeout(() => {
      blocker.exec('COMMIT');
      blocker.close();
    }, 250);

    const outcomes = await inFlight;
    clearInterval(heartbeat);

    expect(outcomes.filter((outcome) => outcome.isError)).toEqual([]);
    expect(countRows(harness.config.storage.sqlitePath, 'cves')).toBe(ids.length);
    expect(integrity(harness.config.storage.sqlitePath)).toBe('ok');
    expect(harness.logs.some((line) => line.includes('cache_write_retry'))).toBe(true);
    // A synchronous busy handler used to block the loop for the whole timeout (5 s by default).
    expect(maxGapMs).toBeLessThan(500);
    expect(ticks).toBeGreaterThanOrEqual(1);
    expect(Date.now() - startedAt).toBeLessThan(5_000);
  });

  it('degrades gracefully (warning, no data loss) while another writer keeps the lock', async () => {
    harness = await createHarness({ nvdOverrides: FAST, storage: { sqliteBusyTimeoutMs: 20 } });
    cveByIds(harness);

    const blocker = new DatabaseSync(harness.config.storage.sqlitePath);
    blocker.exec('BEGIN IMMEDIATE');
    blocker.prepare('INSERT INTO app_metadata (key, value, updated_at) VALUES (?, ?, ?)').run(
      'blocker-forever',
      'held',
      new Date().toISOString(),
    );

    try {
      const startedAt = Date.now();
      const outcome = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });
      expect(outcome.isError).toBe(false);
      const data = outcome.structuredContent?.['data'] as { id?: string } | undefined;
      expect(data?.id).toBe('CVE-2024-1000');
      const meta = outcome.structuredContent?.['meta'] as { warnings?: string[] } | undefined;
      expect(meta?.warnings?.join(' ')).toMatch(/local database/);
      // Nothing internal leaks into the payload.
      expect(outcome.text).not.toMatch(/SQLITE_BUSY|node:sqlite/i);
      expect(countRows(harness.config.storage.sqlitePath, 'cves')).toBe(0);
      expect(Date.now() - startedAt).toBeLessThan(3_000);
    } finally {
      blocker.exec('ROLLBACK');
      blocker.close();
    }
    expect(integrity(harness.config.storage.sqlitePath)).toBe('ok');
  });

  it('returns REQUEST_TIMEOUT and stays usable after a hanging upstream', async () => {
    harness = await createHarness({ nvdOverrides: { ...FAST, requestTimeoutMs: 60, maxRetries: 2 } });
    harness.nvd.on('/cves/2.0', () => ({ hang: true }));

    const startedAt = Date.now();
    const outcome = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });
    const elapsedMs = Date.now() - startedAt;

    expect(outcome.isError).toBe(true);
    expect(outcome.error?.['code']).toBe('REQUEST_TIMEOUT');
    // 3 attempts (maxRetries=2) * 60 ms timeout, plus scheduling slack.
    expect(harness.nvd.countFor('/cves/2.0')).toBe(3);
    expect(elapsedMs).toBeLessThan(5_000);
    expect(countRows(harness.config.storage.sqlitePath, 'cves')).toBe(0);

    // The process must still serve a healthy request afterwards.
    cveByIds(harness);
    const recovered = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });
    expect(recovered.isError).toBe(false);
    expect(integrity(harness.config.storage.sqlitePath)).toBe('ok');
  });

  it('retries HTTP 429 under concurrent load and never exceeds the retry budget', async () => {
    harness = await createHarness({ nvdOverrides: { ...FAST, maxRetries: 3, retryBaseDelayMs: 5 } });
    let throttled = 0;
    harness.nvd.on('/cves/2.0', (request: NvdMockRequest) => {
      // The first four requests are throttled, everything after that succeeds.
      if (throttled < 4) {
        throttled += 1;
        return { status: 429, headers: { 'retry-after': '0' }, body: { error: 'slow down' } };
      }
      const ids = (request.params['cveIds'] ?? '').split(',').filter(Boolean);
      return {
        status: 200,
        body: cveResponse(ids.map((id) => cveItem({ id })), { totalResults: ids.length }),
      };
    });

    const ids = Array.from({ length: 6 }, (_, index) => `CVE-2024-${2000 + index}`);
    const outcomes = await Promise.all(ids.map((cveId) => harness!.callTool('get_cve', { cveId })));

    const errors = outcomes.filter((outcome) => outcome.isError);
    const successes = outcomes.filter((outcome) => !outcome.isError);
    expect(successes.length).toBeGreaterThan(0);
    // Throttled calls fail with the shared error contract, never with a raw HTTP error.
    for (const error of errors) {
      expect(String(error.error?.['code'])).toBe('RATE_LIMITED');
      expect(String(error.error?.['message'])).not.toMatch(/ECONN|node:internal/);
    }
    // Each logical call issues at most maxRetries+1 requests.
    const maxAttempts = outcomes.length * 4;
    expect(harness.nvd.countFor('/cves/2.0')).toBeLessThanOrEqual(maxAttempts);
    expect(harness.nvd.countFor('/cves/2.0')).toBeGreaterThan(ids.length);
    expect(integrity(harness.config.storage.sqlitePath)).toBe('ok');
  });

  it('maps a persistent HTTP 503 onto UPSTREAM_UNAVAILABLE after the retry budget', async () => {
    harness = await createHarness({ nvdOverrides: { ...FAST, maxRetries: 2 } });
    harness.nvd.on('/cves/2.0', () => ({ status: 503, body: { error: 'maintenance' } }));

    const outcome = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });

    expect(outcome.isError).toBe(true);
    expect(outcome.error?.['code']).toBe('UPSTREAM_UNAVAILABLE');
    expect(harness.nvd.countFor('/cves/2.0')).toBe(3);
    expect(outcome.text).not.toMatch(/maintenance/);
    expect(countRows(harness.config.storage.sqlitePath, 'cves')).toBe(0);
  });

  it('recovers from a corrupted disk-cache file by discarding it and refetching', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    cveByIds(harness);

    expect((await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' })).isError).toBe(false);

    // Drop the SQLite row but keep (and corrupt) the disk cache file.
    const writer = new DatabaseSync(harness.config.storage.sqlitePath);
    writer.prepare('DELETE FROM cves').run();
    writer.close();

    const cveDirectory = path.join(harness.config.cache.directory, 'cves');
    const files = readdirSync(cveDirectory);
    expect(files.length).toBeGreaterThan(0);
    const target = path.join(cveDirectory, files[0] ?? '');
    writeFileSync(target, '{"version":1,"payload":{"trunc', 'utf8');

    const upstreamBefore = harness.nvd.countFor('/cves/2.0');
    const outcome = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });

    expect(outcome.isError).toBe(false);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(upstreamBefore + 1);
    expect(harness.logs.some((line) => line.includes('cache_corrupted'))).toBe(true);
    // The corrupt entry is replaced by a valid one for the same cache key.
    const rewritten = readdirSync(cveDirectory);
    expect(rewritten).toContain(files[0]);
    const reparsed: unknown = JSON.parse(readFileSync(path.join(cveDirectory, files[0] ?? ''), 'utf8'));
    expect(reparsed).toMatchObject({ version: 1, resource: 'cve' });
    expect(integrity(harness.config.storage.sqlitePath)).toBe('ok');
  });

  it('serves a torn SQLite row from the durable copy and repairs it', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    cveByIds(harness);
    expect((await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' })).isError).toBe(false);

    const writer = new DatabaseSync(harness.config.storage.sqlitePath);
    writer.prepare('UPDATE cves SET normalized_json = ? WHERE cve_id = ?').run(
      '{"id":"CVE-2024-1000"',
      'CVE-2024-1000',
    );
    writer.close();

    const before = harness.nvd.countFor('/cves/2.0');
    const outcome = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });

    expect(outcome.isError).toBe(false);
    const data = outcome.structuredContent?.['data'] as { id?: string } | undefined;
    expect(data?.id).toBe('CVE-2024-1000');
    // The disk cache still held a good copy, so no upstream round-trip was needed.
    expect(harness.nvd.countFor('/cves/2.0')).toBe(before);
    expect(harness.logs.some((line) => line.includes('cache_row_corrupt'))).toBe(true);

    const probe = new DatabaseSync(harness.config.storage.sqlitePath, { readOnly: true });
    try {
      const row = probe
        .prepare('SELECT normalized_json FROM cves WHERE cve_id = ?')
        .get('CVE-2024-1000') as { normalized_json: string } | undefined;
      expect(() => JSON.parse(row?.normalized_json ?? 'null')).not.toThrow();
    } finally {
      probe.close();
    }
    expect(integrity(harness.config.storage.sqlitePath)).toBe('ok');
  });

  it('rejects a malformed or schema-invalid upstream payload without corrupting the cache', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    harness.nvd.on('/cves/2.0', () => ({ status: 200, rawBody: '<html>not json</html>' }));

    const notJson = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });
    expect(notJson.isError).toBe(true);
    expect(notJson.error?.['code']).toBe('UPSTREAM_BAD_RESPONSE');

    harness.nvd.on('/cves/2.0', () => ({
      status: 200,
      body: { totalResults: 'many', vulnerabilities: { nope: true } },
    }));
    const invalidShape = await harness.callTool('get_cve', { cveId: 'CVE-2024-1000' });
    expect(invalidShape.isError).toBe(true);
    expect(invalidShape.error?.['code']).toBe('UPSTREAM_BAD_RESPONSE');

    expect(countRows(harness.config.storage.sqlitePath, 'cves')).toBe(0);
    expect(integrity(harness.config.storage.sqlitePath)).toBe('ok');
  });

  it('keeps the tool contract intact after all failure drills', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    const listed = await harness.client?.listTools();
    expect((listed?.tools ?? []).map((tool) => tool.name).sort()).toEqual([
      'get_cpe',
      'get_cve',
      'get_cve_history',
      'get_cve_summary',
      'get_cves',
      'get_modified_cves',
      'get_recent_cves',
      'search_cpe_matches',
      'search_cpes',
      'search_cves',
    ]);
    for (const tool of listed?.tools ?? []) {
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.outputSchema).toBeDefined();
    }
  });
});