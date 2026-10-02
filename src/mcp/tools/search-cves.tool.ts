import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS, PAGE_SIZE_LIMITS } from '../../config/defaults.js';
import {
  cveIdInput,
  cacheMetaOutput,
  cpeMatchStringInput,
  cursorInput,
  cveSummaryOutput,
  cvssFilterInput,
  dateWindowInput,
  pageSizeInput,
  paginationOutput,
  readOnlyAnnotations,
  vulnStatusesInput,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `nvd_search_cves` - general CVE search.
 *
 * Every filter accepted by the NVD API is forwarded upstream (`vulnStatuses`, `isVulnerable`,
 * `kevStartDate`/`kevEndDate` included), so results and totals reflect the real server-side
 * result set.
 */
export const searchCvesTool = defineTool({
  name: 'nvd_search_cves',
  title: 'Search CVEs',
  description: [
    'Search CVE records with the NVD 2.0 filters: keyword, CVE IDs, CPE name or match string, CWE,',
    'source identifier, vuln statuses, published/last-modified windows, KEV window, CVSS metrics and',
    'CERT flags.',
    'Rules: keywordExactMatch requires keyword; isVulnerable requires cpeName; cpeName and',
    `virtualMatchString are mutually exclusive; date windows are limited to ${MAX_DATE_RANGE_DAYS} days.`,
    'NVD evaluates every filter, so totalResults is the exact upstream total.',
    'Cached for 15 minutes; paginate by passing pagination.nextCursor back as `cursor` with the same',
    'filters and pageSize.',
  ].join(' '),
  inputShape: {
    keyword: z.string().min(1).optional().describe('Keyword matched against CVE descriptions'),
    keywordExactMatch: z
      .boolean()
      .optional()
      .describe('Require the exact keyword phrase (requires keyword)'),
    cveIds: z
      .array(cveIdInput)
      .min(1)
      .max(100)
      .optional()
      .describe('Restrict the search to these CVE identifiers'),
    cpeName: cpeMatchStringInput.optional().describe(
      'CPE name filter; translates to the upstream cpeName parameter',
    ),
    virtualMatchString: cpeMatchStringInput.optional().describe(
      'CPE match string (supports wildcards and version ranges); mutually exclusive with cpeName',
    ),
    cweId: z.string().optional().describe('CWE identifier such as CWE-79'),
    sourceIdentifier: z
      .string()
      .min(1)
      .optional()
      .describe('CNA or NVD source identifier, for example secalert@redhat.com'),
    vulnStatuses: vulnStatusesInput,
    cvss: cvssFilterInput.optional(),
    published: dateWindowInput.optional().describe('Filter on the published date (max 120 days)'),
    lastModified: dateWindowInput
      .optional()
      .describe('Filter on the last-modified date (max 120 days)'),
    kev: z
      .object({
        only: z.boolean().optional().describe('Restrict to CISA KEV entries (upstream hasKev)'),
        addedBetween: dateWindowInput
          .optional()
          .describe('KEV date-added window, sent upstream as kevStartDate/kevEndDate (max 120 days)'),
      })
      .optional(),
    noRejected: z.boolean().optional().describe('Exclude rejected CVEs (upstream noRejected)'),
    hasCertAlerts: z.boolean().optional().describe('Only CVEs with CERT alerts'),
    hasCertNotes: z.boolean().optional().describe('Only CVEs with CERT notes'),
    hasOval: z.boolean().optional().describe('Only CVEs with OVAL definitions'),
    isVulnerable: z
      .boolean()
      .optional()
      .describe(
        'Only CVEs where cpeName is marked vulnerable; requires cpeName, incompatible with virtualMatchString',
      ),
    pageSize: pageSizeInput(PAGE_SIZE_LIMITS.cves.max, PAGE_SIZE_LIMITS.cves.default),
    cursor: cursorInput,
  },
  outputShape: {
    items: z.array(cveSummaryOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.searchCves(input),
});
