import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS, PAGE_SIZE_LIMITS } from '../../config/defaults.js';
import { CPE_RECORD_FIELDS } from '../../domain/field-projection.js';
import {
  cacheMetaOutput,
  cpeMatchStringInput,
  cpeRecordItemOutput,
  cursorInput,
  dateWindowInput,
  fieldsInput,
  metaOnlyInput,
  pageSizeInput,
  paginationOutput,
  readOnlyAnnotations,
  uuidInput,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `nvd_search_cpes` - search the Official CPE Dictionary (`/cpes/2.0`).
 */
export const searchCpesTool = defineTool({
  name: 'nvd_search_cpes',
  title: 'Search CPE names',
  description: [
    'Search the NVD Official CPE Dictionary by keyword, match string, criteria UUID, or last-modified window.',
    `At least one filter is required; date windows are limited to ${MAX_DATE_RANGE_DAYS} days.`,
    'matchCriteriaId is a CPE Match Criteria UUID as returned by nvd_search_cpe_matches, not a CPE',
    'dictionary id - use cpeNameId, or nvd_get_cpe, to look up a dictionary entry directly.',
    'cpeMatchString matches dictionary names by pattern, and adding a version narrows it:',
    'cpe:2.3:a:apache:log4j:* matches the product, cpe:2.3:a:apache:log4j:2.0:rc1:* a single build.',
    'Prefixes are allowed and the string is at most 13 CPE 2.3 components.',
    'Deprecated CPEs are filtered locally unless includeDeprecated is true: the NVD CPE API rejects the',
    'includeDeprecated parameter, so upstream totals already include deprecated entries.',
    'pagination.totalResults is the upstream NVD count before local filtering, so it may be greater than',
    'returned items or even > 0 with an empty items array when matching entries are filtered out;',
    'meta.filteredOut reports how many entries the local filter removed from this page.',
    'Results are cached for 24 hours and use opaque cursor pagination; reuse nextCursor with the same filters and pageSize.',
    'To walk many entries pass fields:["cpeName","cpeNameId","deprecated"] - titles and refs dominate the payload of a wide page.',
    'Nearby builds carry look-alike titles (2.0 rc1 versus 2.15.0 rc1), so when the target build is named',
    'by a match criterion, copy that criteria string as the pattern and compare the returned cpeName',
    'verbatim instead of trusting the title.',
    'Pass metaOnly:true for pagination and meta without items.',
  ].join(' '),
  inputShape: {
    keyword: z
      .string()
      .min(1)
      .optional()
      .describe(
        'Keyword matched against CPE titles. It is a loose text match, so a version token such as "rc1" matches tens of thousands of entries; use cpeMatchString to target one build',
      ),
    keywordExactMatch: z
      .boolean()
      .optional()
      .describe('Require the exact keyword phrase (requires keyword)'),
    cpeMatchString: cpeMatchStringInput.optional().describe('CPE match string to look up'),
    matchCriteriaId: uuidInput
      .optional()
      .describe(
        'CPE Match Criteria UUID whose CPE names should be returned (from nvd_search_cpe_matches, not a cpeNameId)',
      ),
    lastModified: dateWindowInput
      .optional()
      .describe('Filter on the CPE last-modified date (max 120 days)'),
    includeDeprecated: z
      .boolean()
      .optional()
      .describe(
        'Include deprecated CPE names (default false). The NVD CPE API rejects the upstream includeDeprecated parameter, so this filter runs locally: see meta.filtersAppliedClientSide and meta.filteredOut, and expect totalResults to count deprecated entries too.',
      ),
    pageSize: pageSizeInput(PAGE_SIZE_LIMITS.cpes.max, PAGE_SIZE_LIMITS.cpes.default),
    cursor: cursorInput,
    fields: fieldsInput(CPE_RECORD_FIELDS),
    metaOnly: metaOnlyInput,
  },
  outputShape: {
    items: z.array(cpeRecordItemOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cpe.searchCpes(input),
});
