import { afterEach, describe, expect, it } from 'vitest';

import { CVE_SUMMARY_FIELDS } from '../../src/domain/field-projection.js';
import {
  cpeItem,
  cpeMatchItem,
  cpeMatchResponse,
  cpeResponse,
  cveChange,
  cveHistoryResponse,
  cveItem,
  cveResponse,
} from '../helpers/fixtures.js';
import { createHarness, readItems, readMeta, readPagination, type Harness } from '../helpers/harness.js';
import type { NvdMockRequest } from '../helpers/nvd-mock-server.js';

const CVE_ID = 'CVE-2021-44228';

/** A second identifier, so the batch test can distinguish "found" from "missing". */
const OTHER_CVE_ID = 'CVE-2016-5195';

/** Every top-level key of the published CVE summary output schema. */
const CVE_SUMMARY_KEYS = [
  'id',
  'published',
  'lastModified',
  'vulnStatus',
  'summary',
  'primaryCvss',
  'cwes',
  'affectedProducts',
  'isKnownExploited',
  'kevDateAdded',
  'referenceCount',
];

function paginatingResponder(dataset: Array<Record<string, unknown>>) {
  return (request: NvdMockRequest): { status: number; body: unknown } => {
    const startIndex = Number(request.params['startIndex'] ?? '0');
    const resultsPerPage = Number(request.params['resultsPerPage'] ?? '20');
    return {
      status: 200,
      body: cveResponse(dataset.slice(startIndex, startIndex + resultsPerPage), {
        startIndex,
        resultsPerPage,
        totalResults: dataset.length,
      }),
    };
  };
}

describe('response shaping with `fields` (integration)', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('nvd_get_cve_summary returns every field by default and only the selection with fields', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', {
      status: 200,
      body: cveResponse([cveItem({ id: CVE_ID, kev: true })], { totalResults: 1 }),
    });

    // A KEV record, so every published field (including the optional kevDateAdded) is present.
    const full = await harness.callTool('nvd_get_cve_summary', { cveId: CVE_ID });
    expect(full.isError).toBe(false);
    const fullData = full.structuredContent?.['data'] as Record<string, unknown>;
    // An omitted `fields` list carries every published key.
    expect(Object.keys(fullData).sort()).toEqual([...CVE_SUMMARY_KEYS].sort());
    expect(fullData['kevDateAdded']).toBeDefined();
    expect(readMeta(full.structuredContent)['fieldsApplied']).toBeUndefined();

    const compact = await harness.callTool('nvd_get_cve_summary', {
      cveId: CVE_ID,
      fields: ['id', 'primaryCvss', 'isKnownExploited', 'kevDateAdded'],
    });
    expect(compact.isError).toBe(false);
    expect(Object.keys(compact.structuredContent?.['data'] as object).sort()).toEqual([
      'id',
      'isKnownExploited',
      'kevDateAdded',
      'primaryCvss',
    ]);
    expect(readMeta(compact.structuredContent)['fieldsApplied']).toEqual([
      'id',
      'primaryCvss',
      'isKnownExploited',
      'kevDateAdded',
    ]);

    // Presentational only: the same upstream record served both responses (cache hit, one request).
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('nvd_get_cve drops the configuration tree and references on request', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem({ id: CVE_ID })], { totalResults: 1 }) });

    const full = await harness.callTool('nvd_get_cve', { cveId: CVE_ID });
    expect(full.isError).toBe(false);
    const fullData = full.structuredContent?.['data'] as Record<string, unknown>;
    expect(fullData['configurations']).toBeDefined();
    expect(fullData['references']).toBeDefined();

    const compact = await harness.callTool('nvd_get_cve', {
      cveId: CVE_ID,
      includeConfigurations: false,
      includeReferences: false,
      fields: ['id', 'cwes', 'kev'],
    });
    expect(compact.isError).toBe(false);
    expect(compact.structuredContent?.['data']).toEqual({
      id: CVE_ID,
      cwes: (fullData['cwes'] as unknown[]) ?? [],
      kev: fullData['kev'],
    });
    expect(readMeta(compact.structuredContent)['fieldsApplied']).toEqual(['id', 'cwes', 'kev']);
  });

  it('rejects an unknown field instead of silently dropping it', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem({ id: CVE_ID })], { totalResults: 1 }) });

    const result = await harness.callTool('nvd_get_cve_summary', { cveId: CVE_ID, fields: ['title'] });
    expect(result.isError).toBe(true);
    expect(result.error?.['code']).toBe('INVALID_INPUT');
    expect(String(result.error?.['message'])).toContain('title');
    expect(harness.nvd.countFor('/cves/2.0')).toBe(0);
  });

  it('projects batch items and keeps foundIds/missingIds untouched', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', {
      status: 200,
      body: cveResponse([cveItem({ id: CVE_ID }), cveItem({ id: OTHER_CVE_ID })], { totalResults: 2 }),
    });

    const result = await harness.callTool('nvd_get_cves', {
      cveIds: [CVE_ID, OTHER_CVE_ID],
      fields: ['id', 'primaryCvss'],
    });
    expect(result.isError).toBe(false);
    const items = readItems(result.structuredContent);
    expect(items).toHaveLength(2);
    for (const item of items) {
      expect(Object.keys(item).sort()).toEqual(['id', 'primaryCvss']);
    }
    expect(result.structuredContent?.['foundIds']).toEqual([CVE_ID, OTHER_CVE_ID]);
    expect(result.structuredContent?.['missingIds']).toEqual([]);
    expect(readMeta(result.structuredContent)['found']).toBe(2);
  });

  it('projects search results without changing pagination or the cursor', async () => {
    harness = await createHarness();
    const dataset = Array.from({ length: 50 }, (_, index) =>
      cveItem({ id: `CVE-2024-${3000 + index}` }),
    );
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const full = await harness.callTool('nvd_search_cves', { keyword: 'vendor', pageSize: 20 });
    expect(full.isError).toBe(false);
    const fullPagination = readPagination(full.structuredContent);

    const compact = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      pageSize: 20,
      fields: ['id', 'published'],
    });
    expect(compact.isError).toBe(false);
    expect(readPagination(compact.structuredContent)).toEqual(fullPagination);
    for (const item of readItems(compact.structuredContent)) {
      expect(Object.keys(item).sort()).toEqual(['id', 'published']);
    }

    // The cursor is not bound to the projection: page two can be walked with either shape.
    const cursor = readPagination(full.structuredContent)['nextCursor'] as string;
    const page2 = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      pageSize: 20,
      cursor,
      fields: ['id'],
    });
    expect(page2.isError).toBe(false);
    expect(readItems(page2.structuredContent).length).toBe(20);
    expect(Object.keys(readItems(page2.structuredContent)[0] ?? {})).toEqual(['id']);
  });

  it('numbers pages from the cursor walk and estimates the page count', async () => {
    harness = await createHarness();
    const dataset = Array.from({ length: 50 }, (_, index) =>
      cveItem({ id: `CVE-2024-${3000 + index}` }),
    );
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const first = await harness.callTool('nvd_search_cves', { keyword: 'vendor', pageSize: 20 });
    const p1 = readPagination(first.structuredContent);
    expect(p1['page']).toBe(1);
    expect(p1['pageCount']).toBe(3);
    expect(p1['returned']).toBe(20);
    expect(p1['totalResults']).toBe(50);
    expect(p1['hasMore']).toBe(true);

    const second = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      pageSize: 20,
      cursor: p1['nextCursor'] as string,
    });
    const p2 = readPagination(second.structuredContent);
    expect(p2['page']).toBe(2);
    expect(p2['pageCount']).toBe(3);
    expect(p2['returned']).toBe(20);

    const third = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      pageSize: 20,
      cursor: p2['nextCursor'] as string,
    });
    const p3 = readPagination(third.structuredContent);
    expect(p3['page']).toBe(3);
    expect(p3['returned']).toBe(10);
    expect(p3['hasMore']).toBe(false);
    expect(p3['nextCursor']).toBeNull();
  });

  it('omits items on request while keeping the pagination block complete', async () => {
    harness = await createHarness();
    const dataset = Array.from({ length: 50 }, (_, index) =>
      cveItem({ id: `CVE-2024-${3000 + index}` }),
    );
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const full = await harness.callTool('nvd_search_cves', { keyword: 'vendor', pageSize: 20 });
    const metaOnly = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      pageSize: 20,
      metaOnly: true,
    });
    expect(metaOnly.isError).toBe(false);
    expect(readItems(metaOnly.structuredContent)).toEqual([]);

    const thinPagination = readPagination(metaOnly.structuredContent);
    expect(thinPagination['page']).toBe(1);
    expect(thinPagination['pageCount']).toBe(3);
    expect(thinPagination['returned']).toBe(0);
    expect(thinPagination['totalResults']).toBe(50);
    expect(thinPagination['hasMore']).toBe(true);
    expect(thinPagination['nextCursor']).toBe(
      readPagination(full.structuredContent)['nextCursor'],
    );

    // The walk still advances, so a metadata-only client can page without reading items.
    const next = await harness.callTool('nvd_search_cves', {
      keyword: 'vendor',
      pageSize: 20,
      cursor: thinPagination['nextCursor'] as string,
      metaOnly: true,
    });
    expect(readPagination(next.structuredContent)['page']).toBe(2);

    // `metaOnly` is presentational: page one stays a single upstream request for both shapes, and
    // only the page-two call is a second one.
    expect(harness.nvd.requestsFor('/cves/2.0')).toHaveLength(2);
  });

  it('keeps the ordering marker in a metadata-only feed response', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', {
      status: 200,
      body: cveResponse([cveItem({ id: CVE_ID })], { totalResults: 1 }),
    });

    const result = await harness.callTool('nvd_get_recent_cves', { days: 7, metaOnly: true });
    expect(result.isError).toBe(false);
    expect(readItems(result.structuredContent)).toEqual([]);
    expect(readMeta(result.structuredContent)['ordering']).toBe('published_desc');
    expect(readPagination(result.structuredContent)['totalResults']).toBe(1);
    expect(readPagination(result.structuredContent)['returned']).toBe(0);
  });

  it('projects both feeds and still reports the ordering marker', async () => {
    harness = await createHarness();
    const dataset = Array.from({ length: 50 }, (_, index) =>
      cveItem({ id: `CVE-2024-${4000 + index}` }),
    );
    harness.nvd.on('/cves/2.0', paginatingResponder(dataset));

    const recent = await harness.callTool('nvd_get_recent_cves', {
      pageSize: 5,
      fields: ['id', 'published'],
    });
    expect(recent.isError).toBe(false);
    expect(readMeta(recent.structuredContent)['ordering']).toBe('published_desc');
    expect(Object.keys(readItems(recent.structuredContent)[0] ?? {}).sort()).toEqual([
      'id',
      'published',
    ]);

    const modified = await harness.callTool('nvd_get_modified_cves', {
      pageSize: 5,
      fields: ['id', 'lastModified'],
    });
    expect(modified.isError).toBe(false);
    expect(readMeta(modified.structuredContent)['ordering']).toBe('last_modified_desc');
    expect(Object.keys(readItems(modified.structuredContent)[0] ?? {}).sort()).toEqual([
      'id',
      'lastModified',
    ]);
  });

  it('strips the bulky details payload from the change history on request', async () => {
    harness = await createHarness();
    const longCpeTree = 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'.repeat(400);
    harness.nvd.on('/cvehistory/2.0', {
      status: 200,
      body: cveHistoryResponse(
        [
          cveChange({
            eventName: 'CVE Modified',
            details: [
              { action: 'Changed', type: 'CVE configurations', newValue: longCpeTree },
              { action: 'Changed', type: 'CVE description', newValue: 'updated summary' },
            ],
          }),
          cveChange({ eventName: 'CPE Deprecation Remap' }),
        ],
        { totalResults: 2 },
      ),
    });

    const full = await harness.callTool('nvd_get_cve_history', { cveId: CVE_ID, pageSize: 10 });
    expect(full.isError).toBe(false);
    const fullItems = readItems(full.structuredContent);
    expect((fullItems[0]?.['details'] as unknown[])?.length).toBe(2);
    const fullSize = JSON.stringify(full.structuredContent).length;

    const compact = await harness.callTool('nvd_get_cve_history', {
      cveId: CVE_ID,
      pageSize: 10,
      fields: ['eventName', 'changeId', 'created'],
    });
    expect(compact.isError).toBe(false);
    const compactItems = readItems(compact.structuredContent);
    for (const item of compactItems) {
      expect(Object.keys(item).sort()).toEqual(['changeId', 'created', 'eventName']);
    }
    expect(compactItems.map((item) => item['eventName'])).toEqual([
      'CVE Modified',
      'CPE Deprecation Remap',
    ]);
    const compactSize = JSON.stringify(compact.structuredContent).length;
    expect(compactSize).toBeLessThan(fullSize / 10);
    expect(readMeta(compact.structuredContent)['ordering']).toBe('change_created_asc');
  });

  it('omits the expanded matches array from nvd_search_cpe_matches on request', async () => {
    harness = await createHarness();
    harness.nvd.on('/cpematch/2.0', {
      status: 200,
      body: cpeMatchResponse([cpeMatchItem()], { totalResults: 1 }),
    });

    const full = await harness.callTool('nvd_search_cpe_matches', { cveId: CVE_ID });
    expect(full.isError).toBe(false);
    const fullItem = readItems(full.structuredContent)[0] ?? {};
    expect(fullItem['matches']).toBeDefined();

    const compact = await harness.callTool('nvd_search_cpe_matches', {
      cveId: CVE_ID,
      fields: ['matchCriteriaId', 'criteria', 'status'],
    });
    expect(compact.isError).toBe(false);
    expect(Object.keys(readItems(compact.structuredContent)[0] ?? {}).sort()).toEqual([
      'criteria',
      'matchCriteriaId',
      'status',
    ]);
    expect(readPagination(compact.structuredContent)['returned']).toBe(1);
    expect(readMeta(compact.structuredContent)['fieldsApplied']).toEqual([
      'matchCriteriaId',
      'criteria',
      'status',
    ]);
  });

  it('narrows nvd_search_cpes items and leaves the default page complete', async () => {
    harness = await createHarness();
    harness.nvd.on('/cpes/2.0', {
      status: 200,
      body: cpeResponse([cpeItem(), cpeItem({ cpeName: 'cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*' })]),
    });

    const full = await harness.callTool('nvd_search_cpes', { keyword: 'log4j' });
    expect(full.isError).toBe(false);
    expect(Object.keys(readItems(full.structuredContent)[0] ?? {}).sort()).toEqual([
      'cpeName',
      'cpeNameId',
      'created',
      'deprecated',
      'deprecatedBy',
      'deprecates',
      'lastModified',
      'refs',
      'titles',
    ]);
    expect(readMeta(full.structuredContent)['fieldsApplied']).toBeUndefined();

    const compact = await harness.callTool('nvd_search_cpes', {
      keyword: 'log4j',
      fields: ['cpeName', 'cpeNameId', 'deprecated'],
    });
    expect(compact.isError).toBe(false);
    for (const item of readItems(compact.structuredContent)) {
      expect(Object.keys(item).sort()).toEqual(['cpeName', 'cpeNameId', 'deprecated']);
    }
    expect(readMeta(compact.structuredContent)['fieldsApplied']).toEqual([
      'cpeName',
      'cpeNameId',
      'deprecated',
    ]);
    // The projection is presentational: pagination still describes the upstream page.
    expect(readPagination(compact.structuredContent)['returned']).toBe(2);
  });

  it('rejects an unsupported nvd_search_cpes field before contacting NVD', async () => {
    harness = await createHarness();
    harness.nvd.on('/cpes/2.0', {
      status: 200,
      body: cpeResponse([cpeItem()]),
    });

    const result = await harness.callTool('nvd_search_cpes', {
      keyword: 'log4j',
      fields: ['cpeName', 'cpeMatch'],
    });
    expect(result.isError).toBe(true);
    expect(result.error?.['code']).toBe('INVALID_INPUT');
    expect(String(result.error?.['message'])).toContain('cpeMatch');
    expect(harness.nvd.requests.filter((r) => r.path === '/cpes/2.0')).toHaveLength(0);
  });

  it('accepts the full documented allowlist of nvd_get_cve_summary', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem({ id: CVE_ID })], { totalResults: 1 }) });

    const result = await harness.callTool('nvd_get_cve_summary', {
      cveId: CVE_ID,
      fields: [...CVE_SUMMARY_FIELDS],
    });
    expect(result.isError).toBe(false);
    expect(readMeta(result.structuredContent)['fieldsApplied']).toEqual([...CVE_SUMMARY_FIELDS]);
  });

  it('reports the affectedProducts cap only while the field is part of the projection', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', {
      status: 200,
      body: cveResponse([cveItem({ id: CVE_ID, affectedProductCount: 60 })], { totalResults: 1 }),
    });

    const full = await harness.callTool('nvd_get_cve_summary', { cveId: CVE_ID });
    const fullWarnings = readMeta(full.structuredContent)['warnings'] as string[];
    expect(fullWarnings.join(' ')).toContain('affectedProducts was truncated');

    const compact = await harness.callTool('nvd_get_cve_summary', {
      cveId: CVE_ID,
      fields: ['id', 'primaryCvss'],
    });
    const compactWarnings = readMeta(compact.structuredContent)['warnings'] as string[];
    expect(compactWarnings.join(' ')).not.toContain('affectedProducts');
    expect(Object.keys(compact.structuredContent?.['data'] as object).sort()).toEqual([
      'id',
      'primaryCvss',
    ]);
  });

  it('echoes the resolved date window of a single-window nvd_search_cves query', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()], { totalResults: 1 }) });

    const published = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      published: { start: '2024-01-01', end: '2024-01-31' },
    });
    expect(readMeta(published.structuredContent)['window']).toEqual({
      start: '2024-01-01T00:00:00.000Z',
      end: '2024-01-31T23:59:59.999Z',
    });

    const both = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      published: { start: '2024-01-01', end: '2024-01-31' },
      lastModified: { start: '2024-02-01', end: '2024-02-10' },
    });
    // Two windows would not fit the single `{ start, end }` echo, so none is reported.
    expect(readMeta(both.structuredContent)['window']).toBeUndefined();
  });

  it('rejects cveId combined with matchStringSearch before any upstream request', async () => {
    harness = await createHarness();
    harness.nvd.on('/cpematch/2.0', { status: 200, body: cpeMatchResponse([cpeMatchItem()]) });

    const result = await harness.callTool('nvd_search_cpe_matches', {
      cveId: CVE_ID,
      matchStringSearch: 'cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*',
    });
    expect(result.isError).toBe(true);
    expect(result.error?.code).toBe('INVALID_INPUT');
    expect(result.error?.message).toContain('cveId and matchStringSearch cannot be combined');
    expect(harness.nvd.requests.filter((r) => r.path === '/cpematch/2.0')).toHaveLength(0);

    const alone = await harness.callTool('nvd_search_cpe_matches', {
      matchStringSearch: 'cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*',
    });
    expect(alone.isError).toBe(false);
    expect(harness.nvd.requests.filter((r) => r.path === '/cpematch/2.0')).toHaveLength(1);
  });
});
