import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { seedEvaluationFixture } from '../../evaluations/fixture.js';
import { createHarness, readItems, readPagination, type Harness } from '../helpers/harness.js';

const xml = readFileSync(new URL('../../evaluations/nist-nvd-mcp-server.xml', import.meta.url), 'utf8');
const answers = [...xml.matchAll(/<answer>(.*?)<\/answer>/g)].map(match => match[1]);
const window = { start: '2024-03-01', end: '2024-03-10' };

describe('fixed evaluation answers through MCP tools (synthetic data, not live NVD)', () => {
  let harness: Harness | undefined;
  afterEach(async () => { await harness?.close(); harness = undefined; });
  async function call(tool: string, args: Record<string, unknown>) {
    const result = await harness!.callTool(tool, args);
    expect(result.isError, result.text).toBe(false);
    return result.structuredContent!;
  }
  async function setup() {
    harness = await createHarness();
    seedEvaluationFixture(harness.nvd);
  }

  it('has ten fixed, independent questions', () => {
    expect(answers).toHaveLength(10);
    expect(xml).not.toMatch(/last seven days|last-modified date, restricted to the last/);
  });
  it('1: finds and confirms the exploited Aurora parser CVE', async () => {
    await setup();
    const search = await call('nvd_search_cves', { keyword: 'Aurora parser', published: window });
    const id = readItems(search)[0]!['id'];
    const summary = await call('nvd_get_cve_summary', { cveId: id });
    expect(summary['data']).toMatchObject({ isKnownExploited: true });
    expect(id).toBe(answers[0]);
  });
  it('2: compares the exploited CVEs in a fixed KEV batch', async () => {
    await setup();
    const search = await call('nvd_search_cves', { kev: { addedOn: '2024-04-01' } });
    const batch = await call('nvd_get_cves', { cveIds: readItems(search).map(item => item['id']) });
    const sorted = readItems(batch).sort((a, b) => Number((b['primaryCvss'] as { score: number }).score) - Number((a['primaryCvss'] as { score: number }).score));
    expect(sorted[0]!['id']).toBe(answers[1]);
  });
  it('3: finds the least severe record after search and batch lookup', async () => {
    await setup();
    const search = await call('nvd_search_cves', { published: window });
    const batch = await call('nvd_get_cves', { cveIds: readItems(search).map(item => item['id']) });
    const scores = readItems(batch).map(item => ({ id: item['id'], score: (item['primaryCvss'] as { score: number }).score }));
    expect(scores.sort((a, b) => a.score - b.score)[0]!.id).toBe(answers[2]);
  });
  it('4: resolves the upper bound of an applicability range', async () => {
    await setup();
    const search = await call('nvd_search_cves', { keyword: 'Aurora parser' });
    const details = await call('nvd_get_cve', { cveId: readItems(search)[0]!['id'] });
    const configurations = (details['data'] as { configurations: Array<{ nodes: Array<{ cpeMatch: Array<{ versionEndExcluding: string }> }> }> }).configurations;
    expect(configurations[0]!.nodes[0]!.cpeMatch[0]!.versionEndExcluding).toBe(answers[3]);
    const matches = await call('nvd_search_cpe_matches', { cveId: readItems(search)[0]!['id'] });
    expect(readItems(matches)[0]!['versionEndExcluding']).toBe(answers[3]);
  });
  it('5: pages through a fixed history and reads the final event', async () => {
    await setup();
    let result = await call('nvd_get_cve_history', { cveId: 'CVE-2024-1001', pageSize: 1 });
    while (readPagination(result)['nextCursor']) result = await call('nvd_get_cve_history', { cveId: 'CVE-2024-1001', pageSize: 1, cursor: readPagination(result)['nextCursor'] });
    expect(readItems(result)[0]!['eventName']).toBe(answers[4]);
  });
  it('6: pages through criteria and resolves a dictionary id', async () => {
    await setup();
    const matches = await call('nvd_search_cpe_matches', { cveId: 'CVE-2024-1001', pageSize: 1 });
    const next = await call('nvd_search_cpe_matches', { cveId: 'CVE-2024-1001', pageSize: 1, cursor: readPagination(matches)['nextCursor'] });
    const refs = readItems(next)[0]!['matches'] as Array<{ cpeNameId: string }>;
    const cpe = await call('nvd_get_cpe', { cpeNameId: refs[0]!.cpeNameId });
    expect((cpe['data'] as { cpeName: string }).cpeName).toBe(answers[5]);
  });
  it('7: follows a deprecated entry to its replacement', async () => {
    await setup();
    const search = await call('nvd_search_cpes', { keyword: 'Aurora', includeDeprecated: true });
    const old = readItems(search).find(item => item['deprecated'])!;
    const replacement = (old['deprecatedBy'] as Array<{ cpeNameId: string }>)[0]!;
    const cpe = await call('nvd_get_cpe', { cpeNameId: replacement.cpeNameId });
    expect((cpe['data'] as { cpeName: string }).cpeName).toBe(answers[6]);
  });
  it('8: finds the newest modification across two snapshot pages', async () => {
    await setup();
    const first = await call('nvd_get_modified_cves', { ...window, pageSize: 2 });
    const second = await call('nvd_get_modified_cves', { ...window, pageSize: 2, cursor: readPagination(first)['nextCursor'] });
    const rows = [...readItems(first), ...readItems(second)];
    expect(new Set(rows.map(row => row['id'])).size).toBe(4);
    expect(rows[0]!['id']).toBe(answers[7]);
  });
  it('9: finds the oldest publication across two descending pages', async () => {
    await setup();
    const first = await call('nvd_get_recent_cves', { ...window, pageSize: 2 });
    const second = await call('nvd_get_recent_cves', { ...window, pageSize: 2, cursor: readPagination(first)['nextCursor'] });
    expect(readItems(second).at(-1)!['id']).toBe(answers[8]);
  });
  it('10: looks up a build and reads its English title', async () => {
    await setup();
    const search = await call('nvd_search_cpes', { keyword: 'Aurora' });
    const cpe = await call('nvd_get_cpe', { cpeNameId: readItems(search)[0]!['cpeNameId'] });
    expect((cpe['data'] as { titles: Array<{ title: string }> }).titles[0]!.title).toBe(answers[9]);
  });
});
