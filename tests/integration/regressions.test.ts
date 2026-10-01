import { afterEach, describe, expect, it } from 'vitest';
import { rmSync } from 'node:fs';
import path from 'node:path';

import { cpeItem, cpeResponse, cveItem, cveResponse } from '../helpers/fixtures.js';
import { createHarness, readItems, readMeta, readPagination, type Harness } from '../helpers/harness.js';
import type { NvdMockRequest } from '../helpers/nvd-mock-server.js';

/**
 * Regression suite for cross-cutting behaviours that are easy to break:
 *
 * - a relative date window stays frozen inside the cursor for the whole pagination session
 * - pagination/totalResults semantics when a filter is still applied locally (CPE deprecation
 *   policy) - pages must stay full, offsets must not overlap, totals stay upstream
 * - recursive CVE configuration `children` survive schema + mapper + MCP output
 * - the raw payload stays available from SQLite after the disk cache entry disappears
 * - `get_cpe` by cpeName scans more than the first upstream page
 */

const CPE_NAME_TARGET = 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*';
const CPE_ID_TARGET = 'AAAAAAAA-3333-4444-8555-666666666666';

function cpeDataset(count: number, deprecatedIndexes: readonly number[]): Array<Record<string, unknown>> {
  return Array.from({ length: count }, (_, index) =>
    cpeItem({
      cpeNameId: `AAAAAAAA-3333-4444-8555-${String(index).padStart(12, '0')}`,
      cpeName: `cpe:2.3:a:vendor:product:${index}:*:*:*:*:*:*:*`,
      deprecated: deprecatedIndexes.includes(index),
    }),
  );
}

describe('cross-cutting regressions', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  describe('CPE pages stay full when deprecated entries are filtered locally', () => {
    it('keeps fetching upstream pages and reports the upstream total', async () => {
      harness = await createHarness();
      const dataset = cpeDataset(10, [0, 1, 2, 3]);
      harness.nvd.on('/cpes/2.0', (request: NvdMockRequest) => {
        const startIndex = Number(request.params['startIndex'] ?? '0');
        const resultsPerPage = Number(request.params['resultsPerPage'] ?? '20');
        return {
          status: 200,
          body: cpeResponse(dataset.slice(startIndex, startIndex + resultsPerPage), {
            startIndex,
            resultsPerPage,
            totalResults: dataset.length,
          }),
        };
      });

      const page1 = await harness.callTool('search_cpes', { keyword: 'product', pageSize: 5 });
      expect(page1.isError).toBe(false);

      // The first upstream page contains four deprecated rows, so a second request is needed.
      const requests = harness.nvd.requestsFor('/cpes/2.0');
      expect(requests).toHaveLength(2);
      expect(requests[0]?.params).toMatchObject({ startIndex: '0', resultsPerPage: '5' });
      expect(requests[1]?.params).toMatchObject({ startIndex: '5', resultsPerPage: '4' });

      const items = readItems(page1.structuredContent);
      expect(items).toHaveLength(5);
      expect(items.every((item) => item['deprecated'] === false)).toBe(true);

      const meta = readMeta(page1.structuredContent);
      expect(meta['filteredOut']).toBe(4);
      const pagination = readPagination(page1.structuredContent);
      // Upstream total (pre-filter) is preserved and documented as such.
      expect(pagination['totalResults']).toBe(10);
      expect(pagination['returned']).toBe(5);
      // Nine upstream rows were consumed, so one more page exists.
      expect(pagination['hasMore']).toBe(true);

      const page2 = await harness.callTool('search_cpes', {
        keyword: 'product',
        pageSize: 5,
        cursor: pagination['nextCursor'] as string,
      });
      expect(page2.isError).toBe(false);
      const page2Request = harness.nvd.requestsFor('/cpes/2.0')[2];
      // The next cursor continues after the consumed offset - no gap, no duplicate.
      expect(page2Request?.params).toMatchObject({ startIndex: '9', resultsPerPage: '5' });
      expect(readItems(page2.structuredContent)).toHaveLength(1);
      expect(readPagination(page2.structuredContent)['hasMore']).toBe(false);
    });

    it('keeps a single upstream request when includeDeprecated is requested', async () => {
      harness = await createHarness();
      const dataset = cpeDataset(10, [0, 1, 2, 3]);
      harness.nvd.on('/cpes/2.0', (request: NvdMockRequest) => {
        const startIndex = Number(request.params['startIndex'] ?? '0');
        const resultsPerPage = Number(request.params['resultsPerPage'] ?? '20');
        return {
          status: 200,
          body: cpeResponse(dataset.slice(startIndex, startIndex + resultsPerPage), {
            startIndex,
            resultsPerPage,
            totalResults: dataset.length,
          }),
        };
      });

      const result = await harness.callTool('search_cpes', {
        keyword: 'product',
        pageSize: 5,
        includeDeprecated: true,
      });
      expect(result.isError).toBe(false);
      expect(harness.nvd.countFor('/cpes/2.0')).toBe(1);
      expect(readItems(result.structuredContent)).toHaveLength(5);
      expect(readMeta(result.structuredContent)['filteredOut']).toBeUndefined();
    });
  });

  describe('get_cpe resolves an exact cpeName beyond the first page', () => {
    it('scans subsequent upstream pages before reporting not found', async () => {
      harness = await createHarness();
      const target = cpeItem({ cpeNameId: CPE_ID_TARGET, cpeName: CPE_NAME_TARGET });
      const decoys = cpeDataset(2, []);
      // The exact match only appears on the page after the first one.
      const firstScanPage = [...decoys, target, ...decoys];
      harness.nvd.on('/cpes/2.0', (request: NvdMockRequest) => {
        const startIndex = Number(request.params['startIndex'] ?? '0');
        const resultsPerPage = Number(request.params['resultsPerPage'] ?? '20');
        const all = startIndex === 0 ? firstScanPage : decoys;
        return {
          status: 200,
          body: cpeResponse(
            all.slice(startIndex, startIndex + resultsPerPage),
            { startIndex, resultsPerPage, totalResults: 4 },
          ),
        };
      });

      const found = await harness.callTool('get_cpe', { cpeName: CPE_NAME_TARGET });
      expect(found.isError).toBe(false);
      expect((found.structuredContent?.['data'] as Record<string, unknown>)['cpeNameId']).toBe(
        CPE_ID_TARGET,
      );
      expect(harness.nvd.countFor('/cpes/2.0')).toBeGreaterThanOrEqual(1);

      harness.nvd.reset();
      // A large result set: the scan must stop at the configured page budget (not unbounded).
      const big = cpeDataset(1_000, []);
      harness.nvd.on('/cpes/2.0', (request: NvdMockRequest) => {
        const startIndex = Number(request.params['startIndex'] ?? '0');
        const resultsPerPage = Number(request.params['resultsPerPage'] ?? '20');
        return {
          status: 200,
          body: cpeResponse(big.slice(startIndex, startIndex + resultsPerPage), {
            startIndex,
            resultsPerPage,
            totalResults: big.length,
          }),
        };
      });

      const missing = await harness.callTool('get_cpe', {
        cpeName: 'cpe:2.3:a:vendor:product:does-not-exist:*:*:*:*:*:*:*',
      });
      expect(missing.isError).toBe(true);
      expect(missing.error?.['code']).toBe('CPE_NOT_FOUND');
      const message = missing.error?.['message'] as string;
      expect(message).toContain('search_cpes');
      expect(message).toContain('300 of 1000');
      // The scan is bounded, never unbounded.
      expect(harness.nvd.countFor('/cpes/2.0')).toBe(3);
    });
  });

  describe('nested configuration children reach the MCP payload', () => {
    it('returns the applicability tree with children through get_cve', async () => {
      harness = await createHarness();
      harness.nvd.on('/cves/2.0', {
        status: 200,
        body: cveResponse([cveItem({ withNestedConfiguration: true })]),
      });

      const result = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
      expect(result.isError).toBe(false);

      const data = result.structuredContent?.['data'] as {
        configurations?: Array<{
          nodes: Array<{
            operator: string | null;
            children: Array<{
              cpeMatch: Array<{ criteria: string; vulnerable: boolean }>;
              children: Array<{ cpeMatch: Array<{ criteria: string }> }>;
            }>;
          }>;
        }>;
      };
      const root = data.configurations?.[0]?.nodes[0];
      expect(root?.operator).toBe('AND');
      expect(root?.children).toHaveLength(1);
      expect(root?.children[0]?.cpeMatch[0]?.vulnerable).toBe(true);
      expect(root?.children[0]?.children[0]?.cpeMatch[0]?.criteria).toContain('vendor:client');

      const summary = await harness.callTool('get_cve_summary', { cveId: 'CVE-2024-3094' });
      const affected = (summary.structuredContent?.['data'] as Record<string, unknown>)[
        'affectedProducts'
      ] as Array<{ criteria: string }>;
      // Nested CPEs are part of the summary projection.
      expect(affected.map((entry) => entry.criteria)).toEqual(
        expect.arrayContaining([
          'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*',
          'cpe:2.3:a:vendor:client:1.0:*:*:*:*:*:*:*',
        ]),
      );
    });
  });

  describe('raw payload survives a disk-cache cleanup', () => {
    it('serves includeRaw from SQLite when the disk entry is gone', async () => {
      harness = await createHarness();
      harness.nvd.on('/cves/2.0', {
        status: 200,
        body: cveResponse([cveItem({ id: 'CVE-2024-3094' })]),
      });

      const first = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094', includeRaw: true });
      expect(first.isError).toBe(false);
      expect((first.structuredContent?.['data'] as Record<string, unknown>)['raw']).toBeDefined();
      expect(harness.nvd.countFor('/cves/2.0')).toBe(1);

      // Simulate a disk-cache cleanup while SQLite keeps its fresh row.
      rmSync(path.join(harness.config.cache.directory), { recursive: true, force: true });

      const second = await harness.callTool('get_cve', {
        cveId: 'CVE-2024-3094',
        includeRaw: true,
      });
      expect(second.isError).toBe(false);
      expect(readMeta(second.structuredContent)['cacheStatus']).toBe('hit');
      expect(harness.nvd.countFor('/cves/2.0')).toBe(1);

      const raw = (second.structuredContent?.['data'] as Record<string, unknown>)['raw'] as
        | Record<string, unknown>
        | undefined;
      expect(raw?.['id']).toBe('CVE-2024-3094');
      expect((second.structuredContent?.['meta'] as Record<string, unknown>)['warnings']).toEqual([]);
    });
  });

  describe('a CVSS filter without criteria is rejected', () => {
    it('rejects cvss: {version} without severity or metrics', async () => {
      harness = await createHarness();
      harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()]) });

      const invalid = await harness.callTool('search_cves', {
        keyword: 'xz',
        cvss: { version: '3.1' },
      });
      expect(invalid.isError).toBe(true);
      expect(invalid.text).toContain('Input validation error');
      expect(harness.nvd.countFor('/cves/2.0')).toBe(0);

      const valid = await harness.callTool('search_cves', {
        keyword: 'xz',
        cvss: { version: '3.1', severity: 'HIGH' },
      });
      expect(valid.isError).toBe(false);
      expect(harness.nvd.requestsFor('/cves/2.0')[0]?.params['cvssV3Severity']).toBe('HIGH');
    });
  });
});
