import { afterEach, describe, expect, it } from 'vitest';

import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { createHarness, readItems, readMeta, readPagination, type Harness } from '../helpers/harness.js';
import type { NvdMockRequest } from '../helpers/nvd-mock-server.js';

/** 50 CVEs published one minute apart, oldest first (NVD returns date-range results ascending). */
function ascendingDataset(count = 50): Array<Record<string, unknown>> {
  return Array.from({ length: count }, (_, index) =>
    cveItem({
      id: `CVE-2024-${2000 + index}`,
      published: new Date(Date.UTC(2026, 0, 1, 0, index)).toISOString().slice(0, 23),
      lastModified: new Date(Date.UTC(2026, 0, 2, 0, index)).toISOString().slice(0, 23),
    }),
  );
}

function paginatingResponder(dataset: Array<Record<string, unknown>>) {
  return (request: NvdMockRequest): { status: number; body: unknown } => {
    const startIndex = Number(request.params['startIndex'] ?? '0');
    const resultsPerPage = Number(request.params['resultsPerPage'] ?? '20');
    const slice = dataset.slice(startIndex, startIndex + resultsPerPage);
    return {
      status: 200,
      body: cveResponse(slice, {
        startIndex,
        resultsPerPage,
        totalResults: dataset.length,
      }),
    };
  };
}

describe('nvd_search_cves and the recent/modified feeds (integration)', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('nvd_search_cves maps filters to upstream parameters and caches the page', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()], { totalResults: 1 }) });

    const result = await harness.callTool('nvd_search_cves', {
      keyword: 'xz backdoor',
      keywordExactMatch: true,
      kev: { only: true },
      noRejected: true,
      cweId: 'CWE-506',
      pageSize: 10,
    });
    expect(result.isError).toBe(false);
    expect(readItems(result.structuredContent)).toHaveLength(1);
    expect(readPagination(result.structuredContent)).toMatchObject({
      pageSize: 10,
      returned: 1,
      totalResults: 1,
      hasMore: false,
      nextCursor: null,
    });

    const upstream = harness.nvd.requestsFor('/cves/2.0')[0];
    expect(upstream?.params).toMatchObject({
      keywordSearch: 'xz backdoor',
      keywordExactMatch: '',
      hasKev: '',
      noRejected: '',
      cweId: 'CWE-506',
      startIndex: '0',
      resultsPerPage: '10',
    });

    // Same query again -> cached, no additional upstream call.
    const again = await harness.callTool('nvd_search_cves', {
      keyword: 'xz backdoor',
      keywordExactMatch: true,
      kev: { only: true },
      noRejected: true,
      cweId: 'CWE-506',
      pageSize: 10,
    });
    expect(readMeta(again.structuredContent)).toMatchObject({ cacheStatus: 'hit', source: 'cache' });
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('nvd_search_cves paginates with an opaque cursor and rejects tampering or filter changes', async () => {
    harness = await createHarness();
    const dataset = ascendingDataset(45);
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const page1 = await harness.callTool('nvd_search_cves', { keyword: 'xz', pageSize: 20 });
    expect(page1.isError).toBe(false);
    const pagination = readPagination(page1.structuredContent);
    expect(pagination).toMatchObject({ pageSize: 20, returned: 20, totalResults: 45, hasMore: true });
    const cursor = pagination['nextCursor'];
    expect(typeof cursor).toBe('string');
    // The cursor is an opaque signed token, never a bare offset.
    expect(Number.isInteger(Number(cursor))).toBe(false);
    expect(cursor).not.toContain('startIndex=20');

    const page2 = await harness.callTool('nvd_search_cves', {
      keyword: 'xz',
      pageSize: 20,
      cursor: cursor as string,
    });
    expect(page2.isError).toBe(false);
    expect(readItems(page2.structuredContent)).toHaveLength(20);
    const page2Request = harness.nvd.requestsFor('/cves/2.0')[1];
    expect(page2Request?.params).toMatchObject({ startIndex: '20', resultsPerPage: '20' });

    const tampered = `${(cursor as string).slice(0, -2)}xy`;
    const tamperedResult = await harness.callTool('nvd_search_cves', {
      keyword: 'xz',
      pageSize: 20,
      cursor: tampered,
    });
    expect(tamperedResult.isError).toBe(true);
    expect(tamperedResult.error).toMatchObject({ code: 'INVALID_CURSOR', retryable: false });

    const changedFilters = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      pageSize: 20,
      cursor: cursor as string,
    });
    expect(changedFilters.isError).toBe(true);
    expect(changedFilters.error).toMatchObject({ code: 'INVALID_CURSOR' });
  });

  it('nvd_search_cves validates the documented rules', async () => {
    harness = await createHarness();

    const cases: Array<{ args: Record<string, unknown>; code: string }> = [
      { args: { keywordExactMatch: true }, code: 'INVALID_INPUT' },
      { args: { cpeName: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*', virtualMatchString: 'cpe:2.3:a:x:*' }, code: 'INVALID_INPUT' },
      { args: { virtualMatchString: 'cpe:2.3:a:x:*', isVulnerable: true }, code: 'INVALID_INPUT' },
      { args: { isVulnerable: true }, code: 'INVALID_INPUT' },
      {
        args: { published: { start: '2024-01-01T00:00:00Z', end: '2024-06-01T00:00:00Z' } },
        code: 'DATE_RANGE_TOO_LARGE',
      },
    ];

    for (const testCase of cases) {
      const result = await harness.callTool('nvd_search_cves', testCase.args);
      expect(result.isError, JSON.stringify(testCase.args)).toBe(true);
      expect(result.error?.['code'], JSON.stringify(testCase.args)).toBe(testCase.code);
    }
    expect(harness.nvd.countFor('/cves/2.0')).toBe(0);
  });

  it('forwards vulnStatuses, isVulnerable and the KEV window upstream', async () => {
    harness = await createHarness();
    const dataset = [
      cveItem({
        id: 'CVE-2024-3001',
        vulnStatus: 'Analyzed',
        criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
        criteriaVulnerable: true,
        kev: true,
      }),
      cveItem({
        id: 'CVE-2024-3002',
        vulnStatus: 'Modified',
        criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
        criteriaVulnerable: true,
      }),
    ];
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const statusFiltered = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      vulnStatuses: ['Analyzed', 'Undergoing Analysis'],
    });
    expect(statusFiltered.isError).toBe(false);
    const statusRequest = harness.nvd.requestsFor('/cves/2.0')[0];
    expect(statusRequest?.params['vulnStatuses']).toBe('Analyzed,UndergoingAnalysis');

    const statusMeta = readMeta(statusFiltered.structuredContent);
    // Nothing is filtered locally any more.
    expect(statusMeta['filtersAppliedClientSide']).toBeUndefined();
    expect(statusMeta['filteredOut']).toBeUndefined();
    // Returned items and total come straight from the upstream (filtered) result set.
    expect(readItems(statusFiltered.structuredContent)).toHaveLength(2);
    expect(readPagination(statusFiltered.structuredContent)['totalResults']).toBe(2);

    const vulnerable = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      cpeName: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
      isVulnerable: true,
    });
    expect(vulnerable.isError).toBe(false);
    const vulnerableRequest = harness.nvd.requestsFor('/cves/2.0')[1];
    expect(vulnerableRequest?.params['isVulnerable']).toBe('');
    expect(vulnerableRequest?.params['cpeName']).toBe('cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*');
    expect(readMeta(vulnerable.structuredContent)['filtersAppliedClientSide']).toBeUndefined();

    const kevWindow = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      kev: { addedBetween: { start: '2024-04-01', end: '2024-04-30' } },
    });
    expect(kevWindow.isError).toBe(false);
    const kevRequest = harness.nvd.requestsFor('/cves/2.0')[2];
    expect(kevRequest?.params).toMatchObject({
      kevStartDate: '2024-04-01T00:00:00.000',
      kevEndDate: '2024-04-30T00:00:00.000',
    });
    expect(kevRequest?.params['hasKev']).toBeUndefined();
    expect(readMeta(kevWindow.structuredContent)['filtersAppliedClientSide']).toBeUndefined();
  });

  it('nvd_get_recent_cves uses a 7-day window by default and returns the newest CVEs first', async () => {
    harness = await createHarness();
    const dataset = ascendingDataset(50);
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const page1 = await harness.callTool('nvd_get_recent_cves', { pageSize: 20 });
    expect(page1.isError).toBe(false);

    const upstream = harness.nvd.requestsFor('/cves/2.0');
    expect(upstream).toHaveLength(2); // probe + end-anchored page
    const probe = upstream[0];
    const pageRequest = upstream[1];
    expect(probe?.params).toMatchObject({ startIndex: '0', resultsPerPage: '20' });
    expect(pageRequest?.params).toMatchObject({ startIndex: '30', resultsPerPage: '20' });

    const start = Date.parse(`${probe?.params['pubStartDate'] ?? ''}Z`);
    const end = Date.parse(`${probe?.params['pubEndDate'] ?? ''}Z`);
    expect(Number.isNaN(start)).toBe(false);
    expect(end - start).toBe(7 * 86_400_000);

    const items = readItems(page1.structuredContent);
    expect(items).toHaveLength(20);
    const published = items.map((item) => String(item['published']));
    expect([...published].sort().reverse()).toEqual(published);
    // The newest record of the dataset must be on the first page.
    expect(items[0]?.['id']).toBe('CVE-2024-2049');
    expect(readMeta(page1.structuredContent)['ordering']).toBe('published_desc');
    expect(readMeta(page1.structuredContent)['window']).toBeDefined();

    const pagination = readPagination(page1.structuredContent);
    expect(pagination['hasMore']).toBe(true);
    const page2 = await harness.callTool('nvd_get_recent_cves', {
      pageSize: 20,
      cursor: pagination['nextCursor'] as string,
    });
    expect(page2.isError).toBe(false);
    const page2Request = harness.nvd.requestsFor('/cves/2.0')[2];
    expect(page2Request?.params).toMatchObject({ startIndex: '10', resultsPerPage: '20' });

    const page3 = await harness.callTool('nvd_get_recent_cves', {
      pageSize: 20,
      cursor: readPagination(page2.structuredContent)['nextCursor'] as string,
    });
    expect(readPagination(page3.structuredContent)['hasMore']).toBe(false);
    const page3Request = harness.nvd.requestsFor('/cves/2.0')[3];
    expect(page3Request?.params).toMatchObject({ startIndex: '0', resultsPerPage: '10' });
  });

  it('nvd_get_recent_cves reuses the probe payload when the whole window fits into one page', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', paginatingResponder(ascendingDataset(5)));

    const result = await harness.callTool('nvd_get_recent_cves', { days: 1, pageSize: 20 });
    expect(result.isError).toBe(false);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
    const items = readItems(result.structuredContent);
    expect(items.map((item) => item['id'])).toEqual([
      'CVE-2024-2004',
      'CVE-2024-2003',
      'CVE-2024-2002',
      'CVE-2024-2001',
      'CVE-2024-2000',
    ]);
  });

  it('nvd_get_recent_cves validates the window rules', async () => {
    harness = await createHarness();

    const both = await harness.callTool('nvd_get_recent_cves', { days: 3, start: '2024-01-01' });
    expect(both.isError).toBe(true);
    expect(both.error?.['code']).toBe('INVALID_INPUT');

    const tooWide = await harness.callTool('nvd_get_recent_cves', { days: 121 });
    expect(tooWide.isError).toBe(true);
    // Rejected by the published input schema (the service enforces the same 120-day limit).
    expect(tooWide.text).toContain('Input validation error');
    expect(harness.nvd.countFor('/cves/2.0')).toBe(0);
  });

  it('nvd_get_modified_cves uses last-modified semantics and returns newest first', async () => {
    harness = await createHarness();
    const dataset = ascendingDataset(25).map((item, index) => ({
      ...item,
      lastModified: new Date(Date.UTC(2026, 0, 3, 0, index)).toISOString().slice(0, 23),
    }));
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const result = await harness.callTool('nvd_get_modified_cves', {
      start: '2026-01-01T00:00:00Z',
      end: '2026-01-04T00:00:00Z',
      pageSize: 10,
    });
    expect(result.isError).toBe(false);
    expect(readMeta(result.structuredContent)['ordering']).toBe('last_modified_desc');

    const pageRequest = harness.nvd.requestsFor('/cves/2.0')[1];
    expect(pageRequest?.params).toMatchObject({
      lastModStartDate: '2026-01-01T00:00:00.000',
      lastModEndDate: '2026-01-04T00:00:00.000',
      startIndex: '15',
      resultsPerPage: '10',
    });

    const items = readItems(result.structuredContent);
    const lastModified = items.map((item) => String(item['lastModified']));
    expect([...lastModified].sort().reverse()).toEqual(lastModified);
    expect(items[0]?.['id']).toBe('CVE-2024-2024');
  });

  it('nvd_get_modified_cves forwards vulnStatuses upstream and keeps pagination totals authoritative', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', paginatingResponder([
      cveItem({ id: 'CVE-2024-4001', vulnStatus: 'Analyzed' }),
      cveItem({ id: 'CVE-2024-4002', vulnStatus: 'Rejected' }),
    ]));

    const result = await harness.callTool('nvd_get_modified_cves', {
      days: 2,
      vulnStatuses: ['Analyzed'],
    });
    expect(result.isError).toBe(false);
    expect(readItems(result.structuredContent).map((item) => item['id'])).toEqual([
      // Descending last_modified order.
      'CVE-2024-4002',
      'CVE-2024-4001',
    ]);
    expect(readMeta(result.structuredContent)['filtersAppliedClientSide']).toBeUndefined();
    expect(readPagination(result.structuredContent)['totalResults']).toBe(2);
    // The status filter travels upstream in request form.
    for (const request of harness.nvd.requestsFor('/cves/2.0')) {
      expect(request.params['vulnStatuses']).toBe('Analyzed');
      expect(request.params['vulnStatus']).toBeUndefined();
    }
  });

  it('keeps a relative date window stable across pages although the clock advances', async () => {
    harness = await createHarness();
    const dataset = ascendingDataset(50);
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const page1 = await harness.callTool('nvd_get_recent_cves', { days: 7, pageSize: 20 });
    expect(page1.isError).toBe(false);
    const firstWindow = readMeta(page1.structuredContent)['window'] as
      | { start: string; end: string }
      | undefined;
    expect(firstWindow).toBeDefined();

    // Several minutes pass before the caller asks for the next page.
    harness.clock.advanceMs(5 * 60_000);

    const page2 = await harness.callTool('nvd_get_recent_cves', {
      days: 7,
      pageSize: 20,
      cursor: readPagination(page1.structuredContent)['nextCursor'] as string,
    });

    expect(page2.isError).toBe(false);
    const secondWindow = readMeta(page2.structuredContent)['window'] as
      | { start: string; end: string }
      | undefined;
    expect(secondWindow).toEqual(firstWindow);

    // The second page must reuse the frozen window for the upstream request.
    const page2Request = harness.nvd.requestsFor('/cves/2.0')[2];
    expect(page2Request?.params['pubStartDate']).toBe(
      firstWindow?.start.replace(/Z$/, '').replace(/\.\d{3}Z?$/, '.000'),
    );
    expect(page2Request?.params['pubEndDate']).toBe(
      page2Request?.params['pubEndDate'],
    );
    expect(page2Request?.params['startIndex']).toBe('10');

    // A different explicit window still invalidates the cursor.
    const mismatched = await harness.callTool('nvd_get_recent_cves', {
      start: '2026-01-01T00:00:00Z',
      end: '2026-01-02T00:00:00Z',
      pageSize: 20,
      cursor: readPagination(page1.structuredContent)['nextCursor'] as string,
    });
    expect(mismatched.isError).toBe(true);
    expect(mismatched.error?.['code']).toBe('INVALID_CURSOR');
  });
});
