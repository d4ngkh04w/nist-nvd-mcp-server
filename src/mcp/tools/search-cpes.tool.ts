import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS, PAGE_SIZE_LIMITS } from '../../config/defaults.js';
import {
  cacheMetaOutput,
  cpeMatchStringInput,
  cpeRecordOutput,
  cursorInput,
  dateWindowInput,
  pageSizeInput,
  paginationOutput,
  readOnlyAnnotations,
  uuidInput,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `search_cpes` - search the Official CPE Dictionary (`/cpes/2.0`).
 */
export const searchCpesTool = defineTool({
  name: 'search_cpes',
  title: 'Search CPE names',
  description: [
    'Search the NVD Official CPE Dictionary by keyword, match string, criteria UUID, or last-modified window.',
    `At least one filter is required; date windows are limited to ${MAX_DATE_RANGE_DAYS} days.`,
    'Deprecated CPEs are filtered locally unless includeDeprecated is true.',
    'totalResults is the upstream NVD count before local filtering, so it may be greater than returned items or even > 0 with an empty items array when matching entries are filtered out.',
    'Results are cached for 24 hours and use opaque cursor pagination; reuse nextCursor with the same filters and pageSize.',
  ].join(' '),
  inputShape: {
    keyword: z.string().min(1).optional().describe('Keyword matched against CPE titles'),
    keywordExactMatch: z
      .boolean()
      .optional()
      .describe('Require the exact keyword phrase (requires keyword)'),
    cpeMatchString: cpeMatchStringInput.optional().describe('CPE match string to look up'),
    matchCriteriaId: uuidInput
      .optional()
      .describe('CPE Match Criteria UUID whose CPE names should be returned'),
    lastModified: dateWindowInput
      .optional()
      .describe('Filter on the CPE last-modified date (max 120 days)'),
    includeDeprecated: z
      .boolean()
      .optional()
      .describe(
        'Include deprecated CPE names (default false). This filter runs locally; see meta.filteredOut.',
      ),
    pageSize: pageSizeInput(PAGE_SIZE_LIMITS.cpes.max, PAGE_SIZE_LIMITS.cpes.default),
    cursor: cursorInput,
  },
  outputShape: {
    items: z.array(cpeRecordOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cpe.searchCpes(input),
});
