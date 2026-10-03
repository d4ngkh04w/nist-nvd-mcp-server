import { afterEach, describe, expect, it } from 'vitest';

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

const CPE_ID = 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C';
const MATCH_ID = '55782A0B-B9C5-4536-A885-84CAB7029C09';

describe('MCP contract: tools/call for all ten tools', () => {
  let harness: Harness | undefined;

  async function buildHarness(): Promise<Harness> {
    const created = await createHarness();
    created.nvd.on('/cves/2.0', (request) => {
      const ids = request.params['cveIds'];
      if (ids !== undefined) {
        const requested = ids.split(',').map((value) => value.trim());
        return {
          status: 200,
          body: cveResponse(
            requested.map((id) => cveItem({ id, kev: true })),
            { totalResults: requested.length },
          ),
        };
      }
      const cveOnly = request.params['keywordSearch'] === 'log4j';
      return {
        status: 200,
        body: cveResponse([cveItem({ id: cveOnly ? 'CVE-2021-44228' : 'CVE-2024-3094', kev: true })], {
          totalResults: 1,
        }),
      };
    });
    created.nvd.on('/cvehistory/2.0', {
      status: 200,
      body: cveHistoryResponse([cveChange()]),
    });
    created.nvd.on('/cpes/2.0', (request) => {
      const byId = request.params['cpeNameId'] !== undefined;
      return {
        status: 200,
        body: cpeResponse([cpeItem()], { totalResults: byId ? 1 : 1 }),
      };
    });
    created.nvd.on('/cpematch/2.0', {
      status: 200,
      body: cpeMatchResponse([cpeMatchItem()]),
    });
    return created;
  }

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('serves every tool with structuredContent that mirrors the text payload', async () => {
    harness = await buildHarness();

    const calls: Array<{ tool: string; args: Record<string, unknown>; assert: (payload: Record<string, unknown>) => void }> = [
      {
        tool: 'nvd_get_cve',
        args: { cveId: 'CVE-2024-3094' },
        assert: (payload) => {
          const data = payload['data'] as Record<string, unknown>;
          expect(data['id']).toBe('CVE-2024-3094');
          expect(data['isKnownExploited']).toBe(true);
          expect(data['kev']).toMatchObject({ dateAdded: '2024-04-01' });
        },
      },
      {
        tool: 'nvd_get_cve_summary',
        args: { cveId: 'CVE-2024-3094' },
        assert: (payload) => {
          const data = payload['data'] as Record<string, unknown>;
          expect(data).toMatchObject({ id: 'CVE-2024-3094', isKnownExploited: true, kevDateAdded: '2024-04-01' });
          expect(data).not.toHaveProperty('configurations');
        },
      },
      {
        tool: 'nvd_get_cves',
        args: { cveIds: ['CVE-2024-3094', 'CVE-2024-3095'] },
        assert: (payload) => {
          expect(readItems(payload)).toHaveLength(2);
          expect(payload['missingIds']).toEqual([]);
          expect(payload['meta']).toMatchObject({ requested: 2, found: 2, missing: 0 });
        },
      },
      {
        tool: 'nvd_search_cves',
        args: { keyword: 'log4j', pageSize: 5 },
        assert: (payload) => {
          expect(readItems(payload)[0]?.['id']).toBe('CVE-2021-44228');
          expect(readPagination(payload)).toMatchObject({ pageSize: 5, returned: 1, hasMore: false });
        },
      },
      {
        tool: 'nvd_get_cve_history',
        args: { cveId: 'CVE-2024-3094' },
        assert: (payload) => {
          expect(readItems(payload)[0]).toMatchObject({ eventName: 'CVE Modified' });
          expect(readPagination(payload)['totalResults']).toBe(1);
        },
      },
      {
        tool: 'nvd_get_recent_cves',
        args: { days: 7 },
        assert: (payload) => {
          expect(readItems(payload)).toHaveLength(1);
          expect(readMeta(payload)['ordering']).toBe('published_desc');
        },
      },
      {
        tool: 'nvd_get_modified_cves',
        args: { days: 7, vulnStatuses: ['Analyzed'] },
        assert: (payload) => {
          expect(readItems(payload)).toHaveLength(1);
          expect(readMeta(payload)['ordering']).toBe('last_modified_desc');
          // vulnStatuses reaches NVD, so no local filter ran.
          expect(readMeta(payload)['filtersAppliedClientSide']).toBeUndefined();
          expect(readPagination(payload)['totalResults']).toBe(1);
        },
      },
      {
        tool: 'nvd_search_cpes',
        args: { keyword: 'xz' },
        assert: (payload) => {
          expect(readItems(payload)[0]?.['cpeNameId']).toBe(CPE_ID);
        },
      },
      {
        tool: 'nvd_get_cpe',
        args: { cpeNameId: CPE_ID },
        assert: (payload) => {
          const data = payload['data'] as Record<string, unknown>;
          expect(data).toMatchObject({ cpeNameId: CPE_ID, deprecated: false });
        },
      },
      {
        tool: 'nvd_search_cpe_matches',
        args: { cveId: 'CVE-2024-3094' },
        assert: (payload) => {
          expect(readItems(payload)[0]?.['matchCriteriaId']).toBe(MATCH_ID);
          expect(readItems(payload)[0]?.['matches']).toHaveLength(1);
        },
      },
    ];

    expect(calls.map((call) => call.tool).sort()).toEqual(
      [
        'nvd_get_cpe',
        'nvd_get_cve',
        'nvd_get_cve_history',
        'nvd_get_cve_summary',
        'nvd_get_cves',
        'nvd_get_modified_cves',
        'nvd_get_recent_cves',
        'nvd_search_cpe_matches',
        'nvd_search_cpes',
        'nvd_search_cves',
      ].sort(),
    );

    for (const call of calls) {
      const result = await harness.callTool(call.tool, call.args);
      expect(result.isError, `${call.tool} failed: ${result.text}`).toBe(false);
      expect(result.structuredContent, `${call.tool} structuredContent`).toBeDefined();
      const payload = result.structuredContent as Record<string, unknown>;
      // The text content mirrors structuredContent exactly.
      expect(JSON.parse(result.text), call.tool).toEqual(payload);
      // Every tool reports cache metadata.
      expect(readMeta(payload)['cacheStatus'], call.tool).toBeDefined();
      call.assert(payload);
    }
  });

  it('returns the ToolError contract as JSON text for domain errors', async () => {
    harness = await buildHarness();

    const notFound = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094' });
    expect(notFound.isError).toBe(false);

    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([]) });
    const missing = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-7777' });
    expect(missing.isError).toBe(true);
    expect(missing.structuredContent).toBeUndefined();
    expect(missing.error).toMatchObject({
      code: 'CVE_NOT_FOUND',
      retryable: false,
    });
    expect(typeof missing.error?.['message']).toBe('string');
    expect(missing.error).not.toHaveProperty('stack');
  });

  it('reports invalid cursors and invalid input without leaking internals', async () => {
    harness = await buildHarness();

    const badCursor = await harness.callTool('nvd_search_cves', {
      keyword: 'log4j',
      cursor: 'not.a-real-cursor-value',
    });
    expect(badCursor.isError).toBe(true);
    expect(badCursor.error).toMatchObject({ code: 'INVALID_CURSOR', retryable: false });
    expect(badCursor.text).not.toContain('HMAC');

    const invalidInput = await harness.callTool('nvd_search_cves', {
      cpeName: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      virtualMatchString: 'cpe:2.3:a:x:*',
    });
    expect(invalidInput.isError).toBe(true);
    expect(invalidInput.error?.['code']).toBe('INVALID_INPUT');

    const upstreamError = (await harness.callTool('nvd_get_cpe', {
      cpeNameId: '99999999-2222-4333-8444-555555555555',
    })) as { isError: boolean; error?: Record<string, unknown> };
    // The mock always returns the fixture, so this call succeeds; a schema violation is next.
    expect(upstreamError.isError).toBe(false);

    const schemaViolation = await harness.callTool('nvd_get_cves', { cveIds: [] });
    expect(schemaViolation.isError).toBe(true);
    expect(schemaViolation.text).toContain('Input validation error');
  });

  it('never exposes an apiKey or raw stack traces in tool payloads', async () => {
    harness = await createHarness({ apiKey: '[REDACTED:auth_header]' });
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()]) });

    const result = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094' });
    expect(result.isError).toBe(false);
    expect(result.text).not.toContain('super-secret-api-key');
    expect(result.text).not.toContain('stack');
    expect(harness.logs.join('\n')).not.toContain('super-secret-api-key');
  });
});
