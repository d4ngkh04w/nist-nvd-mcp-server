import { afterEach, describe, expect, it } from 'vitest';

import { cpeItem, cpeMatchItem, cpeMatchResponse, cpeResponse, cveItem, cveResponse } from '../helpers/fixtures.js';
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
    // The page is served straight from the upstream result set: no local filter ran.
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
    // A date-only `end` is expanded to the end of that day: the NVD KEV timestamps are stored at
    // midnight, so resolving it to 00:00:00 truncates the last day of the window.
    expect(kevRequest?.params).toMatchObject({
      kevStartDate: '2024-04-01T00:00:00.000',
      kevEndDate: '2024-04-30T23:59:59.999',
    });
    expect(kevRequest?.params['hasKev']).toBeUndefined();
    expect(readMeta(kevWindow.structuredContent)['filtersAppliedClientSide']).toBeUndefined();
  });

  it('resolves a single-day KEV query through kev.addedOn and the date-only addedBetween end', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()], { totalResults: 1 }) });

    // `start == end` resolves to 00:00:00, which would cover no instant of that day at all.
    const sameDayRange = await harness.callTool('nvd_search_cves', {
      keyword: 'Remote Desktop Services',
      kev: { addedBetween: { start: '2021-11-03', end: '2021-11-03' } },
    });
    expect(sameDayRange.isError).toBe(false);
    expect(harness.nvd.requestsFor('/cves/2.0')[0]?.params).toMatchObject({
      kevStartDate: '2021-11-03T00:00:00.000',
      kevEndDate: '2021-11-03T23:59:59.999',
    });

    const exactDay = await harness.callTool('nvd_search_cves', {
      keyword: 'Remote Desktop Services exact day',
      kev: { addedOn: '2021-11-03' },
    });
    expect(exactDay.isError).toBe(false);
    expect(harness.nvd.requestsFor('/cves/2.0')[1]?.params).toMatchObject({
      kevStartDate: '2021-11-03T00:00:00.000',
      kevEndDate: '2021-11-03T23:59:59.999',
    });

    // A timestamp bound stays verbatim: only a date-only end is widened.
    const explicitBound = await harness.callTool('nvd_search_cves', {
      keyword: 'Remote Desktop Services explicit bound',
      kev: { addedBetween: { start: '2021-11-03T00:00:00Z', end: '2021-11-04T00:00:00Z' } },
    });
    expect(explicitBound.isError).toBe(false);
    expect(harness.nvd.requestsFor('/cves/2.0')[2]?.params).toMatchObject({
      kevStartDate: '2021-11-03T00:00:00.000',
      kevEndDate: '2021-11-04T00:00:00.000',
    });

    const conflicting = await harness.callTool('nvd_search_cves', {
      keyword: 'Remote Desktop Services conflicting',
      kev: { addedOn: '2021-11-03', addedBetween: { start: '2021-11-01', end: '2021-11-05' } },
    });
    expect(conflicting.isError).toBe(true);
    expect(conflicting.error?.['code']).toBe('INVALID_INPUT');
    expect(String(conflicting.error?.['message'])).toContain('addedOn');
  });

  it('warns that a long keyword matched nothing instead of leaving an empty page unexplained', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([], { totalResults: 0 }) });

    const longPhrase = await harness.callTool('nvd_search_cves', {
      keyword: 'Log4j2 JNDI lookup remote code execution',
    });
    expect(longPhrase.isError).toBe(false);
    expect(readItems(longPhrase.structuredContent)).toHaveLength(0);
    const warnings = readMeta(longPhrase.structuredContent)['warnings'] as string[];
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('6-token phrase');
    expect(warnings[0]).toContain('retry with fewer distinctive terms');
    // The hint is presentational: the upstream query is unchanged.
    expect(harness.nvd.requestsFor('/cves/2.0')[0]?.params).toMatchObject({
      keywordSearch: 'Log4j2 JNDI lookup remote code execution',
    });

    // Three tokens is an ordinary miss, not a suspicious query.
    const shortPhrase = await harness.callTool('nvd_search_cves', {
      keyword: 'Log4j2 JNDI lookup',
    });
    expect(readMeta(shortPhrase.structuredContent)['warnings']).toEqual([]);

    // A phrase that matches keeps the page clean. A distinct keyword is used because the identical
    // query is already cached from the empty response above.
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()], { totalResults: 1 }) });
    const hit = await harness.callTool('nvd_search_cves', {
      keyword: 'Log4Shell JNDI lookup remote code execution in Java',
    });
    expect(readItems(hit.structuredContent)).toHaveLength(1);
    expect(readMeta(hit.structuredContent)['warnings']).toEqual([]);

    // keywordExactMatch asks for the phrase verbatim, so a miss needs no tokenization hint.
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([], { totalResults: 0 }) });
    const exact = await harness.callTool('nvd_search_cves', {
      keyword: 'Log4j2 JNDI lookup remote code execution',
      keywordExactMatch: true,
    });
    expect(readMeta(exact.structuredContent)['warnings']).toEqual([]);
  });

  it('rejects a malformed kev.addedOn and a CPE match string with too many components', async () => {
    harness = await createHarness();
    harness.nvd.on('/cpematch/2.0', {
      status: 200,
      body: cpeMatchResponse([cpeMatchItem()], { totalResults: 1 }),
    });
    harness.nvd.on('/cpes/2.0', { status: 200, body: cpeResponse([cpeItem()], { totalResults: 1 }) });

    const badDay = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      kev: { addedOn: '2021-11-03T00:00:00Z' },
    });
    expect(badDay.isError).toBe(true);
    // Schema violations are reported by the SDK as a plain-text result, not a ToolError payload.
    expect(badDay.text).toContain('kev.addedOn');

    // A CPE name with one trailing `*` too many made /cpematch/2.0 answer HTTP 404; it is now an
    // INVALID_INPUT that names the component limit.
    const tooManyComponents = await harness.callTool('nvd_search_cpe_matches', {
      matchStringSearch: 'cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*:*',
    });
    expect(tooManyComponents.isError).toBe(true);
    expect(tooManyComponents.error?.['code']).toBe('INVALID_INPUT');
    expect(String(tooManyComponents.error?.['message'])).toContain('13');

    // The correct 13-component criteria string still reaches the upstream request.
    const valid = await harness.callTool('nvd_search_cpe_matches', {
      matchStringSearch: 'cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*',
    });
    expect(valid.isError).toBe(false);
    expect(harness.nvd.requestsFor('/cpematch/2.0')[0]?.params['matchStringSearch']).toBe(
      'cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*',
    );

    const shortDictionaryPattern = await harness.callTool('nvd_search_cpes', {
      cpeMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    expect(shortDictionaryPattern.isError).toBe(false);
    expect(harness.nvd.requestsFor('/cpes/2.0')[0]?.params['cpeMatchString']).toBe(
      'cpe:2.3:a:apache:log4j:*',
    );
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

    const pageRequest = harness.nvd.requestsFor('/cves/2.0')[0];
    expect(pageRequest?.params).toMatchObject({
      lastModStartDate: '2026-01-01T00:00:00.000',
      lastModEndDate: '2026-01-04T00:00:00.000',
      startIndex: '0',
      resultsPerPage: '2000',
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

    // Several minutes pass before the next page is requested.
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
      firstWindow?.end.replace(/Z$/, '').replace(/\.\d{3}Z?$/, '.000'),
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

  it('resolves a date-only published end to the last millisecond of that day', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()], { totalResults: 1 }) });

    // Midnight would cover no instant of 31 January and hide every record published that day.
    const result = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      published: { start: '2024-01-01', end: '2024-01-31' },
    });

    expect(result.isError).toBe(false);
    expect(harness.nvd.requestsFor('/cves/2.0')[0]?.params['pubEndDate']).toBe(
      '2024-01-31T23:59:59.999',
    );
    expect(readMeta(result.structuredContent)['window']).toEqual({
      start: '2024-01-01T00:00:00.000Z',
      end: '2024-01-31T23:59:59.999Z',
    });
  });

  it('reports a cursor rejection reason so a mangled token is distinguishable from a stale query', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', paginatingResponder(ascendingDataset(40)));

    const page1 = await harness.callTool('nvd_search_cves', { keyword: 'log4j', pageSize: 10 });
    const cursor = readPagination(page1.structuredContent)['nextCursor'] as string;
    expect(cursor.length).toBeGreaterThan(0);

    // A byte-exact echo is always accepted.
    const page2 = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      pageSize: 10,
      cursor,
    });
    expect(page2.isError).toBe(false);

    // A dropped character while copying is reported as an altered token, not as a query change.
    const truncated = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      pageSize: 10,
      cursor: cursor.slice(0, -1),
    });
    expect(truncated.isError).toBe(true);
    expect(truncated.error?.['code']).toBe('INVALID_CURSOR');
    expect((truncated.error?.['details'] as Record<string, unknown>)['reason']).toBe('signature');

    // Replaying the same token under a different pageSize is a query mismatch.
    const changedPageSize = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      pageSize: 20,
      cursor,
    });
    expect(changedPageSize.isError).toBe(true);
    expect((changedPageSize.error?.['details'] as Record<string, unknown>)['reason']).toBe(
      'filter_mismatch',
    );
  });
});
