import { afterEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { createHarness, readMeta, type Harness } from '../helpers/harness.js';

describe('cache resilience regressions', () => {
  let harness: Harness;
  afterEach(async () => { await harness?.close(); });

  it('retains stale records and raw payloads through maintenance during an outage', async () => {
    harness = await createHarness({ ttlSeconds: { cve: 1 }, nvdOverrides: { maxRetries: 0 } });
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()]) });
    await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094', includeRaw: true });
    harness.clock.advanceMs(2_000);
    harness.nvd.on('/cves/2.0', { status: 503, body: {} });

    const before = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094', includeRaw: true });
    expect(before.isError).toBe(false);
    expect(before.structuredContent?.['data']).toHaveProperty('raw');
    await harness.app.runMaintenanceOnce();
    const after = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094', includeRaw: true });
    expect(after.isError).toBe(false);
    expect(readMeta(after.structuredContent)['cacheStatus']).toBe('stale_fallback');
    expect(after.structuredContent?.['data']).toHaveProperty('raw');
  });

  it('returns successful upstream batch data when SQLite is write-locked', async () => {
    harness = await createHarness({ storage: { sqliteBusyTimeoutMs: 1 } });
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()]) });
    const blocker = new DatabaseSync(harness.config.storage.sqlitePath);
    blocker.exec('BEGIN IMMEDIATE');
    try {
      const result = await harness.callTool('nvd_get_cves', { cveIds: ['CVE-2024-3094'] });
      expect(result.isError).toBe(false);
      expect(result.structuredContent?.['foundIds']).toEqual(['CVE-2024-3094']);
      expect(readMeta(result.structuredContent)['warnings']).toEqual(
        expect.arrayContaining([expect.stringMatching(/persisted/)]),
      );
      expect(readMeta(result.structuredContent)['stale']).toBe(false);
    } finally {
      blocker.exec('ROLLBACK');
      blocker.close();
    }
  });

  it('evicts retained entries once the stale grace period passes', async () => {
    harness = await createHarness({
      ttlSeconds: { cve: 1 }, cache: { staleRetentionMs: 2_000 }, nvdOverrides: { maxRetries: 0 },
    });
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()]) });
    await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094' });
    harness.clock.advanceMs(3_001);
    await harness.app.runMaintenanceOnce();
    harness.nvd.on('/cves/2.0', { status: 503, body: {} });
    const result = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094' });
    expect(result.isError).toBe(true);
    expect(result.error?.['code']).toBe('UPSTREAM_UNAVAILABLE');
  });
});
