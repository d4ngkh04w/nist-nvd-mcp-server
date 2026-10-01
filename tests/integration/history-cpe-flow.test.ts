import { afterEach, describe, expect, it } from 'vitest';

import {
  cpeItem,
  cpeMatchItem,
  cpeMatchResponse,
  cpeResponse,
  cveChange,
  cveHistoryResponse,
} from '../helpers/fixtures.js';
import { createHarness, readItems, readMeta, readPagination, type Harness } from '../helpers/harness.js';
import type { NvdMockRequest } from '../helpers/nvd-mock-server.js';

function paginatingResponder<T>(
  dataset: T[],
  build: (items: T[], options: { startIndex: number; resultsPerPage: number; totalResults: number }) => unknown,
) {
  return (request: NvdMockRequest): { status: number; body: unknown } => {
    const startIndex = Number(request.params['startIndex'] ?? '0');
    const resultsPerPage = Number(request.params['resultsPerPage'] ?? '20');
    return {
      status: 200,
      body: build(dataset.slice(startIndex, startIndex + resultsPerPage), {
        startIndex,
        resultsPerPage,
        totalResults: dataset.length,
      }),
    };
  };
}

describe('CVE history, CPE dictionary and CPE match criteria (integration)', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('get_cve_history maps filters, normalizes the identifier and caches the page for an hour', async () => {
    harness = await createHarness();
    const dataset = [
      cveChange({ cveChangeId: 'A1CEBCCC-B199-4F56-A1B2-95F6725AFDF9', created: '2024-03-29T17:15:21.150' }),
      cveChange({ cveChangeId: '6575122A-CB6E-4772-BE00-0B6D5C1A0615', created: '2024-03-29T19:15:41.947' }),
      cveChange({
        cveChangeId: 'F3F938BC-62F1-4573-B4F6-B48253FE34A2',
        eventName: 'Initial Analysis',
        created: '2024-03-30T11:15:50.713',
      }),
    ];
    harness.nvd.on(
      '/cvehistory/2.0',
      paginatingResponder(dataset, (items, options) => cveHistoryResponse(items, options)),
    );

    const result = await harness.callTool('get_cve_history', {
      cveId: 'cve-2024-3094',
      eventName: 'CVE Modified',
      pageSize: 2,
    });
    expect(result.isError).toBe(false);
    const items = readItems(result.structuredContent);
    expect(items).toHaveLength(2);
    expect(items[0]).toMatchObject({
      cveId: 'CVE-2024-3094',
      eventName: 'CVE Modified',
      changeId: 'A1CEBCCC-B199-4F56-A1B2-95F6725AFDF9',
    });
    expect(items[0]?.['details']).toEqual([
      { action: 'Changed', type: 'CVSS V3.1 Severity', oldValue: 'HIGH', newValue: 'CRITICAL' },
    ]);
    expect(readPagination(result.structuredContent)).toMatchObject({ returned: 2, hasMore: true });

    const request = harness.nvd.requestsFor('/cvehistory/2.0')[0];
    expect(request?.params).toMatchObject({
      cveId: 'CVE-2024-3094',
      eventName: 'CVE Modified',
      startIndex: '0',
      resultsPerPage: '2',
    });

    const repeat = await harness.callTool('get_cve_history', {
      cveId: 'CVE-2024-3094',
      eventName: 'CVE Modified',
      pageSize: 2,
    });
    expect(readMeta(repeat.structuredContent)).toMatchObject({ cacheStatus: 'hit', source: 'cache' });
    expect(harness.nvd.countFor('/cvehistory/2.0')).toBe(1);

    const cursor = readPagination(result.structuredContent)['nextCursor'] as string;
    const page2 = await harness.callTool('get_cve_history', {
      cveId: 'CVE-2024-3094',
      eventName: 'CVE Modified',
      pageSize: 2,
      cursor,
    });
    expect(readItems(page2.structuredContent)).toHaveLength(1);
    expect(harness.nvd.requestsFor('/cvehistory/2.0')[1]?.params).toMatchObject({
      startIndex: '2',
      resultsPerPage: '2',
    });
  });

  it('get_cve_history enforces the change window limit', async () => {
    harness = await createHarness();
    const result = await harness.callTool('get_cve_history', {
      cveId: 'CVE-2024-3094',
      changeBetween: { start: '2024-01-01T00:00:00Z', end: '2024-07-01T00:00:00Z' },
    });
    expect(result.isError).toBe(true);
    expect(result.error?.['code']).toBe('DATE_RANGE_TOO_LARGE');
    expect(harness.nvd.countFor('/cvehistory/2.0')).toBe(0);
  });

  it('search_cpes requires a filter and filters deprecated entries locally', async () => {
    harness = await createHarness();

    const noFilter = await harness.callTool('search_cpes', {});
    expect(noFilter.isError).toBe(true);
    expect(noFilter.error?.['code']).toBe('INVALID_INPUT');

    const dataset = [
      cpeItem({ cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C', cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*' }),
      cpeItem({
        cpeNameId: '11111111-2222-4333-8444-555555555555',
        cpeName: 'cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*',
        deprecated: true,
      }),
    ];
    harness.nvd.on(
      '/cpes/2.0',
      paginatingResponder(dataset, (items, options) => cpeResponse(items, options)),
    );

    const active = await harness.callTool('search_cpes', { keyword: 'xz', keywordExactMatch: true });
    expect(active.isError).toBe(false);
    expect(readItems(active.structuredContent).map((item) => item['cpeNameId'])).toEqual([
      'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
    ]);
    const activeMeta = readMeta(active.structuredContent);
    expect(activeMeta['filteredOut']).toBe(1);

    const upstream = harness.nvd.requestsFor('/cpes/2.0')[0];
    expect(upstream?.params).toMatchObject({ keywordSearch: 'xz', keywordExactMatch: '' });
    expect(upstream?.params['includeDeprecated']).toBeUndefined();

    const withDeprecated = await harness.callTool('search_cpes', {
      keyword: 'xz',
      keywordExactMatch: true,
      includeDeprecated: true,
    });
    expect(readItems(withDeprecated.structuredContent)).toHaveLength(2);
    const meta = readMeta(withDeprecated.structuredContent);
    expect(meta['filtersAppliedClientSide']).toEqual(['includeDeprecated']);
    expect((meta['warnings'] as string[]).join(' ')).toContain('includeDeprecated');
  });

  it('search_cpes paginates and validates the page size', async () => {
    harness = await createHarness();
    const dataset = Array.from({ length: 30 }, (_, index) =>
      cpeItem({
        cpeNameId: `1111111${String(index).padStart(2, '0')}-2222-4333-8444-555555555555`,
        cpeName: `cpe:2.3:a:vendor:product:${index}:*:*:*:*:*:*:*`,
      }),
    );
    harness.nvd.on(
      '/cpes/2.0',
      paginatingResponder(dataset, (items, options) => cpeResponse(items, options)),
    );

    const page1 = await harness.callTool('search_cpes', { keyword: 'product', pageSize: 20 });
    expect(readPagination(page1.structuredContent)).toMatchObject({ returned: 20, totalResults: 30, hasMore: true });
    const cursor = readPagination(page1.structuredContent)['nextCursor'] as string;
    const page2 = await harness.callTool('search_cpes', { keyword: 'product', pageSize: 20, cursor });
    expect(readItems(page2.structuredContent)).toHaveLength(10);
    expect(readPagination(page2.structuredContent)['hasMore']).toBe(false);

    const tooLarge = await harness.callTool('search_cpes', { keyword: 'product', pageSize: 101 });
    expect(tooLarge.isError).toBe(true);
    expect(tooLarge.text).toContain('Input validation error');
  });

  it('get_cpe resolves by cpeNameId and reports CPE_NOT_FOUND', async () => {
    harness = await createHarness();
    harness.nvd.on('/cpes/2.0', (request) => {
      const requested = request.params['cpeNameId'];
      const match = requested === 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C';
      return {
        status: 200,
        body: cpeResponse(match ? [cpeItem()] : [], { totalResults: match ? 1 : 0 }),
      };
    });

    const found = await harness.callTool('get_cpe', {
      cpeNameId: 'b8f16312-24fa-4bec-b1df-a44c0cf6b36c',
    });
    expect(found.isError).toBe(false);
    const data = found.structuredContent?.['data'] as Record<string, unknown>;
    expect(data).toMatchObject({
      cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
      cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
      deprecated: false,
    });
    expect(harness.nvd.requestsFor('/cpes/2.0')[0]?.params).toMatchObject({
      cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
    });

    const missing = await harness.callTool('get_cpe', {
      cpeNameId: '99999999-2222-4333-8444-555555555555',
    });
    expect(missing.isError).toBe(true);
    expect(missing.error).toMatchObject({ code: 'CPE_NOT_FOUND', retryable: false });

    const neither = await harness.callTool('get_cpe', {});
    expect(neither.isError).toBe(true);
    expect(neither.error?.['code']).toBe('INVALID_INPUT');

    const both = await harness.callTool('get_cpe', {
      cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
      cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
    });
    expect(both.isError).toBe(true);
    expect(both.error?.['code']).toBe('INVALID_INPUT');

    const invalidUuid = await harness.callTool('get_cpe', { cpeNameId: 'not-a-uuid' });
    expect(invalidUuid.isError).toBe(true);
    expect(invalidUuid.text).toContain('Input validation error');
  });

  it('get_cpe resolves an exact cpeName from the pattern search and explains truncation', async () => {
    harness = await createHarness();
    const dataset = [
      cpeItem({ cpeName: 'cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*' }),
      cpeItem({
        cpeNameId: '22222222-3333-4444-8555-666666666666',
        cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
      }),
    ];
    harness.nvd.on(
      '/cpes/2.0',
      paginatingResponder(dataset, (items, options) => cpeResponse(items, options)),
    );

    const exact = await harness.callTool('get_cpe', {
      cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
    });
    expect(exact.isError).toBe(false);
    expect((exact.structuredContent?.['data'] as Record<string, unknown>)['cpeNameId']).toBe(
      '22222222-3333-4444-8555-666666666666',
    );
    const meta = readMeta(exact.structuredContent);
    expect((meta['warnings'] as string[]).join(' ')).toContain('pattern search');

    const notInPage = await harness.callTool('get_cpe', {
      cpeName: 'cpe:2.3:a:tukaani:xz:9.9.9:*:*:*:*:*:*:*',
    });
    expect(notInPage.isError).toBe(true);
    expect(notInPage.error?.['code']).toBe('CPE_NOT_FOUND');
  });

  it('search_cpe_matches maps filters, validates the match string and caches the page', async () => {
    harness = await createHarness();
    const dataset = [cpeMatchItem()];
    harness.nvd.on(
      '/cpematch/2.0',
      paginatingResponder(dataset, (items, options) => cpeMatchResponse(items, options)),
    );

    const result = await harness.callTool('search_cpe_matches', {
      cveId: 'cve-2024-3094',
      pageSize: 10,
    });
    expect(result.isError).toBe(false);
    const items = readItems(result.structuredContent);
    expect(items[0]).toMatchObject({
      matchCriteriaId: '55782A0B-B9C5-4536-A885-84CAB7029C09',
      criteria: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
      status: 'Active',
      versionStartIncluding: null,
    });
    expect(items[0]?.['matches']).toEqual([
      {
        cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
        cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
      },
    ]);
    expect(harness.nvd.requestsFor('/cpematch/2.0')[0]?.params).toMatchObject({
      cveId: 'CVE-2024-3094',
      resultsPerPage: '10',
    });

    const byCriteria = await harness.callTool('search_cpe_matches', {
      matchCriteriaId: '55782a0b-b9c5-4536-a885-84cab7029c09',
    });
    expect(byCriteria.isError).toBe(false);

    const searchString = await harness.callTool('search_cpe_matches', {
      matchStringSearch: 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*',
    });
    expect(searchString.isError).toBe(false);
    expect(
      harness.nvd.requestsFor('/cpematch/2.0').at(-1)?.params['matchStringSearch'],
    ).toBe('cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*');

    const noFilter = await harness.callTool('search_cpe_matches', {});
    expect(noFilter.error?.['code']).toBe('INVALID_INPUT');

    const partialKeyword = await harness.callTool('search_cpe_matches', {
      matchStringSearch: 'log4j',
    });
    expect(partialKeyword.isError).toBe(true);
    expect(partialKeyword.error?.['code']).toBe('INVALID_INPUT');
    expect((partialKeyword.error?.['message'] as string).length).toBeGreaterThan(20);

    const badUuid = await harness.callTool('search_cpe_matches', { matchCriteriaId: 'nope' });
    expect(badUuid.isError).toBe(true);
    expect(badUuid.text).toContain('Input validation error');

    const badCve = await harness.callTool('search_cpe_matches', { cveId: 'CVE-24-1' });
    expect(badCve.isError).toBe(true);
    expect(badCve.text).toContain('Input validation error');
  });
});
