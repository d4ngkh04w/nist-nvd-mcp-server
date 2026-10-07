import { afterEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

import {
  cveChange,
  cveHistoryResponse,
  cveItem,
  cveResponse,
  cpeItem,
  cpeResponse,
} from '../helpers/fixtures.js';
import { createHarness, type Harness } from '../helpers/harness.js';
import type { NvdMockRequest } from '../helpers/nvd-mock-server.js';

/** Latency percentiles in milliseconds. */
type Percentiles = { p50: number; p95: number; p99: number; max: number; count: number };

function percentiles(samples: readonly number[]): Percentiles {
  const sorted = [...samples].sort((left, right) => left - right);
  const at = (fraction: number): number => {
    const index = Math.min(
      sorted.length - 1,
      Math.max(0, Math.ceil(fraction * sorted.length) - 1),
    );
    return sorted[index] ?? 0;
  };
  return {
    p50: at(0.5),
    p95: at(0.95),
    p99: at(0.99),
    max: sorted[sorted.length - 1] ?? 0,
    count: sorted.length,
  };
}

/** Reports a benchmark line; vitest captures stdout so the numbers can be read from the run output. */
function report(label: string, stats: Percentiles, extra: Record<string, unknown> = {}): void {
  console.info(
    `[perf] ${label} ${JSON.stringify({
      ...stats,
      ...extra,
      unit: 'ms',
      heapUsedMb: Number((process.memoryUsage().heapUsed / 1_048_576).toFixed(1)),
    })}`,
  );
}

type TimedResult = {
  label: string;
  durationMs: number;
  ok: boolean;
  code: string | undefined;
};

async function timed(
  harness: Harness,
  label: string,
  tool: string,
  args: Record<string, unknown>,
): Promise<TimedResult> {
  const startedAt = performance.now();
  const outcome = await harness.callTool(tool, args);
  const durationMs = performance.now() - startedAt;
  return {
    label,
    durationMs,
    ok: !outcome.isError,
    code: typeof outcome.error?.['code'] === 'string' ? (outcome.error['code'] as string) : undefined,
  };
}

/** Registers the CVE, history and CPE endpoints with `count` synthetic records. */
function seedUpstream(harness: Harness, count: number): { ids: string[]; cpeIds: string[] } {
  const ids: string[] = Array.from({ length: count }, (_, index) => `CVE-2024-${1000 + index}`);
  const cpeIds: string[] = Array.from(
    { length: count },
    (_, index) => `AAAAAAAA-0000-4000-8000-${String(index).padStart(12, '0')}`,
  );
  const byId = new Map(
    ids.map((id) => [id, cveItem({ id, criteria: `cpe:2.3:a:vendor:p:${id}:*:*:*:*:*:*:*` })] as const),
  );

  harness.nvd.on('/cves/2.0', (request: NvdMockRequest) => {
    // `cveIds` lookups (nvd_get_cve, nvd_get_cves, nvd_get_cve_history preflight).
    const cveIds = request.params['cveIds'];
    if (cveIds !== undefined) {
      const items = cveIds
        .split(',')
        .filter((value) => value.length > 0)
        .map((id) => byId.get(id) ?? cveItem({ id }));
      return { status: 200, body: cveResponse(items, { totalResults: items.length }) };
    }
    // Date-window feeds (nvd_search_cves, nvd_get_recent_cves, nvd_get_modified_cves).
    const startIndex = Number(request.params['startIndex'] ?? '0');
    const pageSize = Number(request.params['resultsPerPage'] ?? '20');
    // A real NVD page never wraps past totalResults or repeats rows to fill resultsPerPage.
    const items = ids.slice(startIndex, startIndex + pageSize).map(id => byId.get(id)!);
    return {
      status: 200,
      body: cveResponse(items, {
        startIndex,
        resultsPerPage: pageSize,
        totalResults: ids.length,
      }),
    };
  });

  harness.nvd.on('/cvehistory/2.0', (request: NvdMockRequest) => {
    const cveId = request.params['cveId'] ?? 'CVE-2024-1000';
    return {
      status: 200,
      body: cveHistoryResponse([
        cveChange({ cveId, cveChangeId: `AAAAAAAA-0000-4000-8000-${cveId.slice(-4)}` }),
      ]),
    };
  });

  harness.nvd.on('/cpes/2.0', () => ({
    status: 200,
    body: cpeResponse(
      cpeIds.map((id) => cpeItem({ cpeNameId: id, cpeName: `cpe:2.3:a:vendor:p:${id}:*:*:*:*:*:*:*` })),
    ),
  }));

  return { ids, cpeIds };
}

const FAST = {
  minIntervalMs: 1,
  maxConcurrency: 1,
  requestTimeoutMs: 5_000,
  maxRetries: 1,
  retryBaseDelayMs: 1,
};

describe('concurrency and load behaviour', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('collapses 25 concurrent cold-cache reads of one CVE into a single upstream request', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    seedUpstream(harness, 5);

    const results = await Promise.all(
      Array.from({ length: 25 }, () =>
        timed(harness!, 'nvd_get_cve', 'nvd_get_cve', { cveId: 'CVE-2024-1000' }),
      ),
    );

    expect(results.filter((result) => !result.ok)).toEqual([]);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);

    // Every concurrent call observes the same record, served from the local cache afterwards.
    const payloads = await Promise.all(
      Array.from({ length: 25 }, () =>
        harness!.callTool('nvd_get_cve', { cveId: 'CVE-2024-1000' }),
      ),
    );
    const first = JSON.stringify(payloads[0]?.structuredContent);
    for (const payload of payloads) {
      expect(payload.isError).toBe(false);
      expect(JSON.stringify(payload.structuredContent)).toBe(first);
    }
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);

    report('thundering-herd-25x-nvd_get_cve', percentiles(results.map((r) => r.durationMs)), {
      upstreamRequests: 1,
    });
  });

  it('serves 50 concurrent distinct CVEs without error and without cross-talk', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    const { ids } = seedUpstream(harness, 50);

    const results = await Promise.all(ids.map((cveId) => timed(harness!, 'nvd_get_cve', 'nvd_get_cve', { cveId })));

    expect(results.filter((result) => !result.ok)).toEqual([]);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(50);

    for (const cveId of ids) {
      const payload = await harness.callTool('nvd_get_cve', { cveId });
      expect(payload.isError).toBe(false);
      const data = payload.structuredContent?.['data'] as { id?: string } | undefined;
      expect(data?.id).toBe(cveId);
    }

    const stats = percentiles(results.map((result) => result.durationMs));
    report('50-concurrent-distinct-nvd_get_cve', stats, { upstreamRequests: 50 });
    expect(stats.p99).toBeLessThan(5_000);
  });

  it('collapses concurrent identical collection queries into one upstream page', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    seedUpstream(harness, 40);

    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        timed(harness!, 'nvd_search_cves', 'nvd_search_cves', { hasKev: true, pageSize: 5 }),
      ),
    );

    expect(results.filter((result) => !result.ok)).toEqual([]);
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
    report('thundering-herd-20x-nvd_search_cves', percentiles(results.map((r) => r.durationMs)), {
      upstreamRequests: 1,
    });
  });

  it('mixes five tool families under 50 concurrent calls with no error', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    const { ids } = seedUpstream(harness, 50);

    const calls: Array<{ tool: string; args: Record<string, unknown> }> = [];
    for (let index = 0; index < 10; index += 1) {
      calls.push({ tool: 'nvd_get_cve', args: { cveId: ids[index] ?? 'CVE-2024-1000' } });
      calls.push({ tool: 'nvd_get_cve_summary', args: { cveId: ids[index + 10] ?? 'CVE-2024-1010' } });
      calls.push({ tool: 'nvd_search_cves', args: { hasKev: index % 2 === 0, pageSize: 3 } });
      calls.push({ tool: 'nvd_get_recent_cves', args: { pageSize: 3 } });
      calls.push({ tool: 'nvd_get_modified_cves', args: { pageSize: 3 } });
    }

    const results = await Promise.all(calls.map((call) => timed(harness!, call.tool, call.tool, call.args)));

    expect(results.filter((result) => !result.ok).map((r) => `${r.label}:${r.code}`)).toEqual([]);

    const byTool = new Map<string, number[]>();
    for (const result of results) {
      const samples = byTool.get(result.label) ?? [];
      samples.push(result.durationMs);
      byTool.set(result.label, samples);
    }
    for (const [tool, samples] of byTool) {
      report(`mixed-${tool}`, percentiles(samples), { calls: samples.length });
    }
    const stats = percentiles(results.map((result) => result.durationMs));
    report('mixed-50-tools', stats, { upstreamRequests: harness.nvd.requests.length });
    expect(stats.p95).toBeLessThan(5_000);
  });

  it('serializes upstream requests through the rate limiter under load', async () => {
    const minIntervalMs = 30;
    harness = await createHarness({ nvdOverrides: { ...FAST, minIntervalMs } });
    const { ids } = seedUpstream(harness, 8);

    await Promise.all(ids.map((cveId) => timed(harness!, 'nvd_get_cve', 'nvd_get_cve', { cveId })));

    const arrivals = harness.nvd.requestsFor('/cves/2.0').map((request) => request.receivedAtMs);
    expect(arrivals).toHaveLength(8);
    const gaps = arrivals.slice(1).map((value, index) => value - (arrivals[index] ?? value));
    // Arrivals are stamped by the mock server's own event loop, which competes with 30 sibling test
    // workers, so the per-gap bound tolerates a stalled read. The span bound below is the assertion
    // that actually measures the limiter: timers firing late only lengthen it.
    const totalSpan = (arrivals[arrivals.length - 1] ?? 0) - (arrivals[0] ?? 0);
    expect(totalSpan).toBeGreaterThanOrEqual(minIntervalMs * (arrivals.length - 1) - 5);
    // A gap far below the interval means two requests were released together, which the limiter
    // never does; only measurement noise can produce one, and noise shows up as a single outlier.
    const belowInterval = gaps.filter((gap) => gap < minIntervalMs / 2);
    expect(belowInterval).toHaveLength(0);
    report(
      'rate-limiter-8-requests',
      { p50: totalSpan, p95: totalSpan, p99: totalSpan, max: totalSpan, count: arrivals.length },
      { minIntervalMs, minGapMs: Math.min(...gaps), gaps },
    );
  });

  it('persists exactly one row per CVE and serves 30 later reads as hits', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    seedUpstream(harness, 3);

    await Promise.all(
      Array.from({ length: 30 }, () =>
        timed(harness!, 'nvd_get_cve', 'nvd_get_cve', { cveId: 'CVE-2024-1001' }),
      ),
    );

    const probe = new DatabaseSync(harness.config.storage.sqlitePath, { readOnly: true });
    try {
      const row = probe.prepare('SELECT COUNT(*) AS count FROM cves').get() as
        | { count: number }
        | undefined;
      expect(row?.count).toBe(1);
      const integrity = probe.prepare('PRAGMA integrity_check').get() as
        | { integrity_check: string }
        | undefined;
      expect(integrity?.integrity_check).toBe('ok');
    } finally {
      probe.close();
    }

    const later = await Promise.all(
      Array.from({ length: 30 }, () =>
        harness!.callTool('nvd_get_cve', { cveId: 'CVE-2024-1001' }),
      ),
    );
    for (const payload of later) {
      expect(payload.isError).toBe(false);
      const meta = payload.structuredContent?.['meta'] as { cacheStatus?: string } | undefined;
      expect(meta?.cacheStatus).toBe('hit');
    }
    expect(harness.nvd.countFor('/cves/2.0')).toBe(1);
  });

  it('does not grow the heap without bound across repeated load waves', async () => {
    harness = await createHarness({ nvdOverrides: FAST });
    const { ids } = seedUpstream(harness, 50);

    const wave = async (): Promise<number[]> => {
      const samples: number[] = [];
      for (const cveId of ids) {
        samples.push((await timed(harness!, 'nvd_get_cve', 'nvd_get_cve', { cveId })).durationMs);
      }
      return samples;
    };

    await wave(); // warm-up: populates the cache and the JIT
    const before = process.memoryUsage().heapUsed;
    const waves = [await wave(), await wave(), await wave(), await wave()];
    const after = process.memoryUsage().heapUsed;
    const growthMb = (after - before) / 1_048_576;

    report('memory-4-waves', percentiles(waves.flat()), {
      heapGrowthMb: Number(growthMb.toFixed(2)),
      upstreamRequests: harness.nvd.countFor('/cves/2.0'),
    });
    expect(harness.nvd.countFor('/cves/2.0')).toBe(50);
    // Later waves are served from SQLite, so no new upstream traffic and no heap blow-up.
    expect(growthMb).toBeLessThan(64);
  });
});
