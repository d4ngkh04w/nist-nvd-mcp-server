import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS, PAGE_SIZE_LIMITS } from '../../config/defaults.js';
import {
  cveIdInput,
  cacheMetaOutput,
  cpeMatchRecordOutput,
  cursorInput,
  dateWindowInput,
  pageSizeInput,
  paginationOutput,
  readOnlyAnnotations,
  uuidInput,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `nvd_search_cpe_matches` - CPE Match Criteria (`/cpematch/2.0`).
 */
export const searchCpeMatchesTool = defineTool({
  name: 'nvd_search_cpe_matches',
  title: 'Search CPE Match Criteria',
  description: [
    'Search CPE Match Criteria, which link CVEs to CPE names and version ranges.',
    'At least one filter is required: cveId, matchCriteriaId, matchStringSearch or',
    `lastModified (maximum ${MAX_DATE_RANGE_DAYS} days).`,
    'matchStringSearch must be a complete CPE match string such as cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*;',
    'upstream rejects partial keywords and version ranges.',
    'Cached for 24 hours; paginate with the opaque cursor.',
  ].join(' '),
  inputShape: {
    cveId: cveIdInput.optional().describe('Return the match criteria referenced by this CVE'),
    matchCriteriaId: uuidInput.optional().describe('Match criteria UUID'),
    matchStringSearch: z
      .string()
      .trim()
      .min(3)
      .optional()
      .describe('Complete CPE match string (wildcards allowed, no version ranges)'),
    lastModified: dateWindowInput
      .optional()
      .describe('Filter on the match criteria last-modified date (max 120 days)'),
    pageSize: pageSizeInput(
      PAGE_SIZE_LIMITS['cpe-matches'].max,
      PAGE_SIZE_LIMITS['cpe-matches'].default,
    ),
    cursor: cursorInput,
  },
  outputShape: {
    items: z.array(cpeMatchRecordOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cpeMatch.searchCpeMatches(input),
});
