import { afterEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { createHarness, readItems, readMeta, readPagination, type Harness } from '../helpers/harness.js';

describe('modified feed global ordering', () => {
  let harness: Harness;
  afterEach(async () => { await harness?.close(); });

  it('orders all pages by modification, not publication, and reuses the cached dataset', async () => {
    harness = await createHarness();
    const dataset = [3, 1, 4, 2, 5].map((day, index) => cveItem({
      id: `CVE-2024-${1000 + index}`, published: `2024-01-0${index + 1}T00:00:00.000`,
      lastModified: `2026-01-1${day}T00:00:00.000`,
    }));
    harness.nvd.on('/cves/2.0', (request) => {
      const startIndex = Number(request.params['startIndex']);
      const size = Number(request.params['resultsPerPage']);
      return { status: 200, body: cveResponse(dataset.slice(startIndex, startIndex + size), {
        startIndex, resultsPerPage: size, totalResults: dataset.length,
      }) };
    });
    const ids: unknown[] = [];
    let cursor: string | undefined;
    do {
      const result = await harness.callTool('nvd_get_modified_cves', { days: 7, pageSize: 2, cursor });
      expect(result.isError).toBe(false);
      expect(readMeta(result.structuredContent)['ordering']).toBe('last_modified_desc');
      ids.push(...readItems(result.structuredContent).map(item => item['id']));
      cursor = readPagination(result.structuredContent)['nextCursor'] as string | undefined;
      harness.clock.advanceMs(6 * 60_000);
    } while (cursor);
    expect(ids).toEqual(['CVE-2024-1004', 'CVE-2024-1002', 'CVE-2024-1000', 'CVE-2024-1003', 'CVE-2024-1001']);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('rejects oversized windows instead of claiming partial results are globally ordered', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()], { totalResults: 10_001 }) });
    const result = await harness.callTool('nvd_get_modified_cves', { days: 7 });
    expect(result.isError).toBe(true);
    expect(result.error?.['code']).toBe('INVALID_INPUT');
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('rejects changing days on a cursor while allowing days to be omitted', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([
      cveItem({ id: 'CVE-2024-1000' }), cveItem({ id: 'CVE-2024-1001' }),
    ], { totalResults: 2 }) });
    const first = await harness.callTool('nvd_get_modified_cves', { days: 2, pageSize: 1 });
    const cursor = readPagination(first.structuredContent)['nextCursor'];
    const changed = await harness.callTool('nvd_get_modified_cves', { days: 3, pageSize: 1, cursor });
    expect(changed.isError).toBe(true);
    expect(changed.error?.['code']).toBe('INVALID_CURSOR');
    const unchanged = await harness.callTool('nvd_get_modified_cves', { pageSize: 1, cursor });
    expect(unchanged.isError).toBe(false);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('rejects cursors after their snapshot was replaced by a fresh first-page query', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([
      cveItem({ id: 'CVE-2024-1000' }), cveItem({ id: 'CVE-2024-1001' }),
    ], { totalResults: 2 }) });
    const input = { start: '2024-04-01', end: '2024-04-03', pageSize: 1 };
    const first = await harness.callTool('nvd_get_modified_cves', input);
    const cursor = readPagination(first.structuredContent)['nextCursor'];
    harness.clock.advanceMs(6 * 60_000);
    expect((await harness.callTool('nvd_get_modified_cves', input)).isError).toBe(false);
    const old = await harness.callTool('nvd_get_modified_cves', { ...input, cursor });
    expect(old.isError).toBe(true);
    expect(old.error?.['code']).toBe('INVALID_CURSOR');
    expect(harness.nvd.countFor('/cves/2.0')).toBe(2);
  });

  it('rejects evicted snapshots without fetching a different dataset for the cursor', async () => {
    harness = await createHarness({ cache: { staleRetentionMs: 0 } });
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([
      cveItem({ id: 'CVE-2024-1000' }), cveItem({ id: 'CVE-2024-1001' }),
    ], { totalResults: 2 }) });
    const first = await harness.callTool('nvd_get_modified_cves', { days: 2, pageSize: 1 });
    harness.clock.advanceMs(6 * 60_000);
    await harness.app.runMaintenanceOnce();
    const result = await harness.callTool('nvd_get_modified_cves', {
      days: 2, pageSize: 1, cursor: readPagination(first.structuredContent)['nextCursor'],
    });
    expect(result.isError).toBe(true);
    expect(result.error?.['code']).toBe('INVALID_CURSOR');
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('recovers a snapshot from disk when its SQLite copy is lost', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([
      cveItem({ id: 'CVE-2024-1000' }), cveItem({ id: 'CVE-2024-1001' }),
    ], { totalResults: 2 }) });
    const first = await harness.callTool('nvd_get_modified_cves', { days: 2, pageSize: 1 });
    const db = new DatabaseSync(harness.config.storage.sqlitePath);
    try { db.exec('DELETE FROM query_cache'); } finally { db.close(); }
    const second = await harness.callTool('nvd_get_modified_cves', {
      pageSize: 1, cursor: readPagination(first.structuredContent)['nextCursor'],
    });
    expect(second.isError).toBe(false);
    expect(readItems(second.structuredContent).map(item => item['id'])).toEqual(['CVE-2024-1000']);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('loads and sorts multiple upstream pages before returning the first client page', async () => {
    harness = await createHarness();
    const dataset = [3, 1, 4, 2, 5].map((day, index) => cveItem({
      id: `CVE-2024-${1000 + index}`, lastModified: `2026-01-1${day}T00:00:00.000`,
    }));
    harness.nvd.on('/cves/2.0', request => {
      const startIndex = Number(request.params['startIndex']);
      return { status: 200, body: cveResponse(dataset.slice(startIndex, startIndex + 2), {
        startIndex, totalResults: 5, resultsPerPage: 2,
      }) };
    });
    const first = await harness.callTool('nvd_get_modified_cves', { days: 7, pageSize: 2 });
    expect(first.isError).toBe(false);
    expect(readItems(first.structuredContent).map(item => item['id'])).toEqual(['CVE-2024-1004', 'CVE-2024-1002']);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(3);
  });

  it('fails rather than sorting an incomplete upstream collection', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', request => ({ status: 200, body: cveResponse(
      Number(request.params['startIndex']) === 0 ? [cveItem()] : [],
      { startIndex: Number(request.params['startIndex']), totalResults: 2 },
    ) }));
    const first = await harness.callTool('nvd_get_modified_cves', { pageSize: 1 });
    expect(first.isError).toBe(true);
    expect(first.error?.['code']).toBe('UPSTREAM_BAD_RESPONSE');
  });
});
