import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS, PAGE_SIZE_LIMITS } from '../../config/defaults.js';
import {
  cacheMetaOutput,
  cpeMatchStringInput,
  cursorInput,
  cveSummaryOutput,
  cvssFilterInput,
  pageSizeInput,
  paginationOutput,
  readOnlyAnnotations,
  vulnStatusesInput,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `get_modified_cves` - recently updated CVEs, newest first.
 *
 * Uses `lastModStartDate`/`lastModEndDate` semantics; `vulnStatuses` is forwarded to NVD.
 */
export const getModifiedCvesTool = defineTool({
  name: 'get_modified_cves',
  title: 'Get recently modified CVEs',
  description: [
    'Return CVEs ordered by last-modified date, newest first (ordering "last_modified_desc").',
    'Defaults to the last 7 days: use `days` or an explicit `start`+`end` window (mutually exclusive,',
    `maximum ${MAX_DATE_RANGE_DAYS} days).`,
    'All filters are sent to NVD, so totalResults is the exact upstream total.',
    'Cached for 5 minutes; paginate by passing pagination.nextCursor back as `cursor` with the same',
    'filters and pageSize - the resolved window travels inside the cursor, so a relative `days` window',
    'stays stable across pages.',
  ].join(' '),
  inputShape: {
    start: z.string().min(1).optional().describe('ISO-8601 window start (use with `end`)'),
    end: z.string().min(1).optional().describe('ISO-8601 window end (use with `start`)'),
    days: z
      .number()
      .int()
      .min(1)
      .max(MAX_DATE_RANGE_DAYS)
      .optional()
      .describe('Relative window in days counted back from now (default 7)'),
    keyword: z.string().min(1).optional().describe('Optional keyword filter'),
    cpeName: cpeMatchStringInput.optional().describe('Optional CPE name filter'),
    cvss: cvssFilterInput.optional(),
    vulnStatuses: vulnStatusesInput,
    kevOnly: z.boolean().optional().describe('Only CISA KEV entries'),
    noRejected: z.boolean().optional().describe('Exclude rejected CVEs'),
    pageSize: pageSizeInput(PAGE_SIZE_LIMITS.cves.max, PAGE_SIZE_LIMITS.cves.default),
    cursor: cursorInput,
  },
  outputShape: {
    items: z.array(cveSummaryOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.getModifiedCves(input),
});
