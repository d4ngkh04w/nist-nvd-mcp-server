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
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

const sharedFeedFields = {
  keyword: z.string().min(1).optional().describe('Optional keyword filter'),
  cpeName: cpeMatchStringInput.optional().describe('Optional CPE name filter'),
  cvss: cvssFilterInput.optional(),
  pageSize: pageSizeInput(PAGE_SIZE_LIMITS.cves.max, PAGE_SIZE_LIMITS.cves.default),
  cursor: cursorInput,
};

/**
 * `get_recent_cves` - newly published CVEs, newest first.
 *
 * The NVD API returns date-range results in ascending order, so the first page costs one extra
 * probing request and pages are fetched end-anchored to guarantee `published_desc` ordering.
 */
export const getRecentCvesTool = defineTool({
  name: 'get_recent_cves',
  title: 'Get recently published CVEs',
  description: [
    'Return CVEs ordered by publication date, newest first (ordering "published_desc").',
    'Defaults to the last 7 days: use `days` or an explicit `start`+`end` window (mutually exclusive,',
    `maximum ${MAX_DATE_RANGE_DAYS} days).`,
    'Cached for 5 minutes; paginate by passing pagination.nextCursor back as `cursor` with the same',
    'filters and pageSize - the resolved window travels inside the cursor, so a relative `days` window',
    'stays stable across pages.',
  ].join(' '),
  inputShape: {
    ...sharedFeedFields,
    start: z.string().min(1).optional().describe('ISO-8601 window start (use with `end`)'),
    end: z.string().min(1).optional().describe('ISO-8601 window end (use with `start`)'),
    days: z
      .number()
      .int()
      .min(1)
      .max(MAX_DATE_RANGE_DAYS)
      .optional()
      .describe('Relative window in days counted back from now (default 7)'),
    kevOnly: z.boolean().optional().describe('Only CISA KEV entries'),
    noRejected: z.boolean().optional().describe('Exclude rejected CVEs'),
  },
  outputShape: {
    items: z.array(cveSummaryOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.getRecentCves(input),
});
