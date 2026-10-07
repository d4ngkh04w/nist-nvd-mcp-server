import { afterEach, describe, expect, it, vi } from 'vitest';

import { createHarness, type Harness } from '../helpers/harness.js';
import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { deferred } from '../helpers/async.js';

describe('MCP request controls', () => {
  let harness: Harness | undefined;
  afterEach(async () => { await harness?.close(); harness = undefined; });

  it('enforces an overall deadline even when the request is still queued', async () => {
    harness = await createHarness({ mcp: { toolTimeoutMs: 100 }, nvdOverrides: { minIntervalMs: 10_000 } });
    harness.nvd.on('/cves/2.0', request => ({ body: cveResponse([cveItem({ id: request.params['cveIds'] })]) }));
    // Occupy the first rate-limit slot outside the deliberately tiny MCP deadline.
    await harness.app.toolContext.services.cve.getCve({ cveId: 'CVE-2024-1001' });
    const queued = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-1002' });
    expect(queued.error).toMatchObject({ code: 'REQUEST_TIMEOUT', details: { scope: 'tool' } });
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('handles a real client cancellation and releases the upstream slot without retrying', async () => {
    harness = await createHarness({ nvdOverrides: { requestTimeoutMs: 15_000, maxRetries: 4 } });
    const entered = deferred<void>();
    harness.nvd.on('/cves/2.0', () => { entered.resolve(); return { hang: true }; });
    const controller = new AbortController();
    const pending = harness.client!.callTool({ name: 'nvd_get_cve', arguments: { cveId: 'CVE-2024-3094' } }, undefined, { signal: controller.signal });
    const rejection = expect(pending).rejects.toBeDefined();
    await entered.promise;
    controller.abort();
    await rejection;
    await vi.waitFor(() => expect(harness!.logs.some(line => line.includes('REQUEST_CANCELLED'))).toBe(true));
    harness.nvd.on('/cves/2.0', { body: cveResponse([cveItem({ id: 'CVE-2024-1002' })]) });
    const next = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-1002' });
    expect(next.isError).toBe(false);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(2);
  });

  it('reports monotonic progress for a multi-page snapshot only with a requested token', async () => {
    harness = await createHarness();
    harness.nvd.on('/cves/2.0', request => {
      const start = Number(request.params['startIndex']);
      return { body: cveResponse([cveItem({ id: `CVE-2024-${1001 + start}` })], { totalResults: 2, startIndex: start }) };
    });
    const updates: Array<{ progress: number; message?: string }> = [];
    const result = await harness.client!.callTool({
      name: 'nvd_get_modified_cves', arguments: { days: 7 }, _meta: { progressToken: 'snapshot' },
    }, undefined, { onprogress: update => { updates.push(update); } });
    expect(result.isError).not.toBe(true);
    expect(updates.some(update => update.message?.includes('Loaded 2 of 2'))).toBe(true);
    expect(updates.every((update, index) => index === 0 || update.progress > updates[index - 1]!.progress)).toBe(true);
    const count = updates.length;
    await harness.callTool('nvd_get_cve_summary', { cveId: 'CVE-2024-1001' });
    expect(updates).toHaveLength(count);
  });

  it('does not fall back to stale data when a tool deadline is exceeded', async () => {
    harness = await createHarness({ mcp: { toolTimeoutMs: 100 }, ttlSeconds: { cve: 1 } });
    harness.nvd.on('/cves/2.0', { body: cveResponse([cveItem()]) });
    await harness.app.toolContext.services.cve.getCve({ cveId: 'CVE-2024-3094' });
    harness.clock.advanceMs(2_000);
    harness.nvd.on('/cves/2.0', { hang: true });
    const result = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094' });
    expect(result.error).toMatchObject({ code: 'REQUEST_TIMEOUT', details: { scope: 'tool' } });
    expect(harness.logs.some(line => line.includes('cache_stale_fallback'))).toBe(false);
  });

  it('returns an actionable tool error for oversized output and allows field projection to recover', async () => {
    harness = await createHarness({ mcp: { maxOutputBytes: 1_024 } });
    harness.nvd.on('/cves/2.0', { body: cveResponse([cveItem({ referenceCount: 50 })]) });
    const tooLarge = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094' });
    expect(tooLarge.error).toMatchObject({ code: 'RESPONSE_TOO_LARGE' });
    expect(tooLarge.structuredContent).toBeUndefined();
    const compact = await harness.callTool('nvd_get_cve', { cveId: 'CVE-2024-3094', fields: ['id'] });
    expect(compact.isError).toBe(false);
    expect(compact.structuredContent?.['data']).toEqual({ id: 'CVE-2024-3094' });
  });
});
