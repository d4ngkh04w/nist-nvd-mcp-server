import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS, MAX_SUMMARY_AFFECTED_PRODUCTS, PAGE_SIZE_LIMITS } from '../../config/defaults.js';
import { CVE_SUMMARY_FIELDS } from '../../domain/field-projection.js';
import {
  cveIdInput,
  cacheMetaOutput,
  cpeMatchStringInput,
  cursorInput,
  cveSummaryOutput,
  cvssFilterInput,
  dateWindowInput,
  fieldsInput,
  metaOnlyInput,
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
    'The published and lastModified windows are independent: supply either one or both, each is optional.',
    'keyword is matched against the description with NVD tokenization: every whitespace-separated token',
    'must be present in the description text. Two or three distinctive terms work; a whole sentence',
    'usually matches nothing ("copy-on-write" matches, "copy-on-write page race condition Linux kernel"',
    'does not). A zero-result keyword search asking for more than three tokens reports why in',
    'meta.warnings.',
    'Filters are combined with AND, so keyword plus kev.addedOn narrows one KEV batch to a single product',
    'without paging through it.',
    'NVD evaluates every filter, so pagination.totalResults is the exact upstream total.',
    'pagination.page is the 1-based page ordinal and pagination.pageCount estimates the total pages.',
    'Cached for 15 minutes. Pass metaOnly:true for pagination and meta without items, for example',
    'to confirm a marker or count pages cheaply.',
    `Items are CVE summaries capped at ${MAX_SUMMARY_AFFECTED_PRODUCTS} affectedProducts; use fields (for example`,
    '["id","published","summary","primaryCvss","isKnownExploited","kevDateAdded"]) to keep a wide page small.',
  ].join(' '),
  inputShape: {
    keyword: z
      .string()
      .min(1)
      .optional()
      .describe(
        'Keyword matched against the CVE description text; it does not match product or CPE names. Most product names have no CPE entry of their own (a search for "remote desktop services" in the CPE dictionary returns nothing, while the affected builds are cpe:2.3:o:microsoft:windows_7 and friends), so cpeName and virtualMatchString target CPE dictionary names rather than human-readable products',
      ),
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
        addedOn: z
          .string()
          .regex(/^\d{4}-\d{2}-\d{2}$/, { message: 'kev.addedOn must be a YYYY-MM-DD date' })
          .optional()
          .describe(
            'Exact day CISA added the entries to KEV, for example 2021-11-03. Sent as kevStartDate 00:00:00 plus kevEndDate 23:59:59 of that day, so a single-day batch is never truncated; mutually exclusive with addedBetween',
          ),
        addedBetween: dateWindowInput.optional().describe(
          `KEV date-added window sent upstream as kevStartDate/kevEndDate (max ${MAX_DATE_RANGE_DAYS} days). A date-only end (2024-04-30) is expanded to 23:59:59.999 so the whole day counts; a timestamp end is used verbatim, so prefer addedOn for one exact day`,
        ),
      })
      .strict()
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
    fields: fieldsInput(CVE_SUMMARY_FIELDS),
    metaOnly: metaOnlyInput,
  },
  outputShape: {
    items: z.array(cveSummaryOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.searchCves(input),
});
