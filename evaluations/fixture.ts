import {
  cveItem, cveResponse, cveChange, cveHistoryResponse,
  cpeItem, cpeResponse, cpeMatchItem, cpeMatchResponse,
} from '../tests/helpers/fixtures.js';
import type { NvdMockRequest, NvdMockServer } from '../tests/helpers/nvd-mock-server.js';

// Deliberately synthetic: these facts belong only to this regression dataset, not to NVD.
// Reuse the test API envelopes/mocks so evaluation exercises the real MCP application stack.
const OLD_CPE = 'cpe:2.3:a:fixture:aurora:1.0:*:*:*:*:*:*:*';
const NEW_CPE = 'cpe:2.3:a:fixture:aurora:2.0:*:*:*:*:*:*:*';
const RANGE_CPE = 'cpe:2.3:a:fixture:aurora:*:*:*:*:*:*:*:*';
const OLD_ID = 'AAAAAAAA-1111-4111-8111-AAAAAAAAAAAA';
const NEW_ID = 'BBBBBBBB-2222-4222-8222-BBBBBBBBBBBB';
const cves = [
  {
    ...cveItem({ id: 'CVE-2024-1001', description: 'Aurora parser remote code execution.', baseScore: 9.8, baseSeverity: 'CRITICAL', kev: true, published: '2024-03-01T12:00:00.000', lastModified: '2024-03-04T12:00:00.000' }),
    configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: RANGE_CPE,
      matchCriteriaId: '55782A0B-B9C5-4536-A885-84CAB7029C09', versionStartIncluding: '1.0', versionEndExcluding: '2.0' }] }] }],
  },
  cveItem({ id: 'CVE-2024-1002', description: 'Borealis renderer memory corruption.', baseScore: 7.5, kev: true, published: '2024-03-02T12:00:00.000', lastModified: '2024-03-08T12:00:00.000' }),
  cveItem({ id: 'CVE-2024-1003', description: 'Aurora network information disclosure.', baseScore: 5.3, baseSeverity: 'MEDIUM', published: '2024-03-03T12:00:00.000', lastModified: '2024-03-06T12:00:00.000' }),
  cveItem({ id: 'CVE-2024-1004', description: 'Borealis storage privilege escalation.', published: '2024-03-04T12:00:00.000', lastModified: '2024-03-05T12:00:00.000' }),
];
const cpes = [
  cpeItem({ cpeName: OLD_CPE, cpeNameId: OLD_ID, deprecated: true, titles: [{ lang: 'en', title: 'Fixture Aurora 1.0' }], deprecatedBy: [{ cpeName: NEW_CPE, cpeNameId: NEW_ID }] }),
  cpeItem({ cpeName: NEW_CPE, cpeNameId: NEW_ID, titles: [{ lang: 'en', title: 'Fixture Aurora 2.0' }], deprecates: [{ cpeName: OLD_CPE, cpeNameId: OLD_ID }] }),
];
const matches = [
  cpeMatchItem({ criteria: RANGE_CPE, versionStartIncluding: '1.0', versionEndExcluding: '2.0', matches: [{ cpeName: OLD_CPE, cpeNameId: OLD_ID }] }),
  cpeMatchItem({ criteria: NEW_CPE, matchCriteriaId: 'CCCCCCCC-3333-4333-8333-CCCCCCCCCCCC', matches: [{ cpeName: NEW_CPE, cpeNameId: NEW_ID }] }),
];
const history = ['Initial Analysis', 'CVE Modified', 'CPE Deprecation Remap'].map((eventName, index) =>
  cveChange({ cveId: 'CVE-2024-1001', eventName, cveChangeId: `DDDDDDDD-4444-4444-8444-${String(index).padStart(12, '0')}`, created: `2024-03-0${index + 1}T15:00:00.000` }),
);

function inWindow(value: unknown, start?: string, end?: string): boolean {
  const time = Date.parse(`${String(value).replace(/Z$/, '')}Z`);
  return (start === undefined || time >= Date.parse(start)) && (end === undefined || time <= Date.parse(end));
}
function keywordMatches(text: string, keyword?: string): boolean {
  return keyword === undefined || keyword.toLowerCase().split(/\s+/).every(token => text.toLowerCase().includes(token));
}
function page(rows: Record<string, unknown>[], request: NvdMockRequest, envelope: typeof cveResponse) {
  const startIndex = Number(request.params['startIndex'] ?? 0);
  const resultsPerPage = Number(request.params['resultsPerPage'] ?? 20);
  return { body: envelope(rows.slice(startIndex, startIndex + resultsPerPage), { startIndex, resultsPerPage, totalResults: rows.length }) };
}

export function seedEvaluationFixture(mock: NvdMockServer): void {
  mock.on('/cves/2.0', request => {
    const p = request.params;
    const ids = p['cveIds']?.split(',');
    const rows = cves.filter(row =>
      (ids === undefined || ids.includes(String(row['id']))) &&
      keywordMatches(JSON.stringify(row['descriptions']), p['keywordSearch']) &&
      (!('hasKev' in p) || row['cisaExploitAdd'] !== undefined) &&
      (p['kevStartDate'] === undefined || (row['cisaExploitAdd'] !== undefined && inWindow(row['cisaExploitAdd'], p['kevStartDate'], p['kevEndDate']))) &&
      inWindow(row['published'], p['pubStartDate'], p['pubEndDate']) &&
      inWindow(row['lastModified'], p['lastModStartDate'], p['lastModEndDate']),
    );
    return page(rows, request, cveResponse);
  });
  mock.on('/cvehistory/2.0', request => page(history.filter(row => row['cveId'] === request.params['cveId']), request, cveHistoryResponse));
  mock.on('/cpes/2.0', request => {
    const p = request.params;
    return page(cpes.filter(row =>
      (p['cpeNameId'] === undefined || row['cpeNameId'] === p['cpeNameId']) &&
      (p['cpeMatchString'] === undefined || String(row['cpeName']).startsWith(p['cpeMatchString'].split('*')[0]!)) &&
      keywordMatches(JSON.stringify(row['titles']), p['keywordSearch']),
    ), request, cpeResponse);
  });
  mock.on('/cpematch/2.0', request => page(
    request.params['cveId'] !== undefined && request.params['cveId'] !== 'CVE-2024-1001' ? [] : matches.filter(row =>
      (request.params['matchCriteriaId'] === undefined || row['matchCriteriaId'] === request.params['matchCriteriaId']) &&
      (request.params['matchStringSearch'] === undefined || String(row['criteria']).startsWith(request.params['matchStringSearch'].split('*')[0]!)),
    ), request, cpeMatchResponse,
  ));
}
