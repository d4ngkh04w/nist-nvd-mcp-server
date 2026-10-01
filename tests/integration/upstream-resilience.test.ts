import { afterEach, describe, expect, it } from 'vitest';

import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { createHarness, readMeta, type Harness } from '../helpers/harness.js';

describe('NVD resilience: retry, timeout, error mapping and rate limiting (integration)', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('retries HTTP 429 and honours Retry-After', async () => {
    harness = await createHarness({ nvdOverrides: { maxRetries: 2 } });
    harness.nvd.on('/cves/2.0', (_request, index) =>
      index === 0
        ? { status: 429, headers: { 'retry-after': '1' }, body: { message: 'rate limited' } }
        : { status: 200, body: cveResponse([cveItem()]) },
    );

    const startedAt = Date.now();
    const result = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    const elapsedMs = Date.now() - startedAt;

    expect(result.isError).toBe(false);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(2);
    expect(elapsedMs).toBeGreaterThanOrEqual(900);
    expect(harness.logs.join('\n')).toContain('nvd_retry');
  });

  it('retries 503 responses up to NVD_MAX_RETRIES and then reports UPSTREAM_UNAVAILABLE', async () => {
    harness = await createHarness({ nvdOverrides: { maxRetries: 1 } });
    harness.nvd.on('/cves/2.0', { status: 503, body: { message: 'unavailable' } });

    const result = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    expect(result.isError).toBe(true);
    expect(result.error).toMatchObject({ code: 'UPSTREAM_UNAVAILABLE', retryable: true });
    // 1 initial attempt + 1 retry.
    expect(harness.nvd.countFor('/cves/2.0')).toBe(2);
  });

  it('recovers when a retry succeeds', async () => {
    harness = await createHarness({ nvdOverrides: { maxRetries: 3 } });
    harness.nvd.on('/cves/2.0', (_request, index) =>
      index < 2
        ? { status: 500, body: {} }
        : { status: 200, body: cveResponse([cveItem({ id: 'CVE-2024-3094' })]) },
    );

    const result = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    expect(result.isError).toBe(false);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(3);
    expect(readMeta(result.structuredContent)).toMatchObject({ cacheStatus: 'miss', source: 'nvd' });
  });

  it('never retries a non-retryable status such as 404', async () => {
    harness = await createHarness({ nvdOverrides: { maxRetries: 4 } });
    harness.nvd.on('/cves/2.0', { status: 404, body: {} });

    const result = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    expect(result.isError).toBe(true);
    expect(result.error).toMatchObject({ code: 'UPSTREAM_BAD_RESPONSE', retryable: false });
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('maps an aborted request to REQUEST_TIMEOUT and retries it', async () => {
    harness = await createHarness({
      nvdOverrides: { requestTimeoutMs: 120, maxRetries: 1 },
    });
    harness.nvd.on('/cves/2.0', { hang: true });

    const result = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    expect(result.isError).toBe(true);
    expect(result.error).toMatchObject({ code: 'REQUEST_TIMEOUT', retryable: true });
    expect(harness.nvd.countFor('/cves/2.0')).toBeGreaterThanOrEqual(2);
  }, 20_000);

  it('reports invalid JSON and unexpected response shapes as UPSTREAM_BAD_RESPONSE', async () => {
    harness = await createHarness({ nvdOverrides: { maxRetries: 0 } });
    harness.nvd.on('/cves/2.0', { status: 200, rawBody: 'not-json' });

    const malformed = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    expect(malformed.isError).toBe(true);
    expect(malformed.error?.['code']).toBe('UPSTREAM_BAD_RESPONSE');
    expect(malformed.error?.['message']).toContain('not valid JSON');

    harness.nvd.reset();
    harness.nvd.on('/cves/2.0', { status: 200, body: { resultsPerPage: 1 } });
    const wrongShape = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    expect(wrongShape.isError).toBe(true);
    expect(wrongShape.error?.['code']).toBe('UPSTREAM_BAD_RESPONSE');
    const details = wrongShape.error?.['details'] as Record<string, unknown>;
    expect(details['endpoint']).toBe('/cves/2.0');
    expect(Array.isArray(details['issues'])).toBe(true);
  });

  it('enforces the minimum interval between consecutive NVD request starts', async () => {
    harness = await createHarness({ nvdOverrides: { minIntervalMs: 120 } });
    harness.nvd.on('/cves/2.0', () => ({
      status: 200,
      body: cveResponse(
        Array.from({ length: 25 }, (_, index) => cveItem({ id: `CVE-2024-${3000 + index}` })),
        { totalResults: 25 },
      ),
    }));

    // A descending feed issues a probe request and then the end-anchored page.
    const result = await harness.callTool('get_recent_cves', { days: 3, pageSize: 10 });
    expect(result.isError).toBe(false);

    const requests = harness.nvd.requestsFor('/cves/2.0');
    expect(requests.length).toBeGreaterThanOrEqual(2);
    for (let index = 1; index < requests.length; index += 1) {
      const previous = requests[index - 1];
      const current = requests[index];
      const gap = (current?.receivedAtMs ?? 0) - (previous?.receivedAtMs ?? 0);
      expect(gap, `request ${index} started ${gap}ms after the previous one`).toBeGreaterThanOrEqual(90);
    }
  });

  it('does not throttle cached reads', async () => {
    harness = await createHarness({ nvdOverrides: { minIntervalMs: 120 } });
    harness.nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()]) });

    await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    const startedAt = Date.now();
    const cached = await harness.callTool('get_cve', { cveId: 'CVE-2024-3094' });
    const elapsedMs = Date.now() - startedAt;

    expect(readMeta(cached.structuredContent)).toMatchObject({ cacheStatus: 'hit' });
    expect(elapsedMs).toBeLessThan(100);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });
});
