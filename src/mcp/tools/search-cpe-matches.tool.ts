import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS, PAGE_SIZE_LIMITS } from '../../config/defaults.js';
import { CPE_MATCH_FIELDS } from '../../domain/field-projection.js';
import { CPE_23_MAX_COMPONENTS } from '../../domain/validation.js';
import {
  cveIdInput,
  cacheMetaOutput,
  cpeMatchRecordOutput,
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
 * `nvd_search_cpe_matches` - CPE Match Criteria (`/cpematch/2.0`).
 */
export const searchCpeMatchesTool = defineTool({
  name: 'nvd_search_cpe_matches',
  title: 'Search CPE Match Criteria',
  description: [
    'Search CPE Match Criteria: the rules that link a CVE to CPE names and version ranges. Each item',
    'carries matchCriteriaId, criteria, status, timestamps, the version bounds and the expanded',
    '`matches` list of CPE dictionary names. Filters (at least one is required):',
    '- cveId: every criteria referenced by that CVE, of which it can have hundreds.',
    '- matchCriteriaId: a criteria UUID returned by this tool, never a CPE dictionary id.',
    `- matchStringSearch: the criteria's own match string, at most ${CPE_23_MAX_COMPONENTS} colon separated`,
    'components, e.g. cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*. It is neither a dictionary CPE name nor a',
    'version range, and an over-long string is rejected before the request rather than answering 404.',
    '- lastModified: change window of the criteria themselves (max 120 days).',
    'cveId and matchStringSearch cannot be combined (the NVD CPE match API answers HTTP 500 for that',
    'pairing). matchStringSearch alone searches every CVE, so it doubles as a uniqueness check: one',
    'item means the string belongs to exactly one match criterion. To find which criteria a CVE uses',
    'for that string, page the cveId result and compare the criteria strings, or read the tree with',
    'nvd_get_cve.',
    'matchStringSearch is not an exact lookup: upstream matches loosely, and a version token it cannot',
    'parse degrades the query to the vendor and product prefix, returning every criteria row for that',
    'product with a wildcard version. A partial version therefore enumerates criteria:',
    'cpe:2.3:a:apache:log4j:* returns every log4j row and cpe:2.3:a:apache:log4j:2.0:* only the 2.0',
    'ones, which is how to inspect one product without reading a whole configuration tree. So more than',
    'one result means the string was not found verbatim, not that it is ambiguous, and a row whose',
    'criteria equals the query is the exact match. A criteria string ending in a concrete version with',
    'null version bounds matches that one build exactly; null bounds do not mean every version.',
    'Dictionary lookups belong to nvd_search_cpes (cpeMatchString accepts a short pattern such as',
    'cpe:2.3:a:apache:log4j:*) and nvd_get_cpe (cpeNameId).',
    'To scan many criteria, pass fields:["matchCriteriaId","criteria","status"] - dropping `matches`',
    'removes the expanded CPE name list, which dominates the payload. Pass metaOnly:true for pagination',
    'and meta without items.',
    `pageSize accepts up to ${PAGE_SIZE_LIMITS['cpe-matches'].max} rows. Cached for 24 hours.`,
  ].join(' '),
  inputShape: {
    cveId: cveIdInput
      .optional()
      .describe(
        'Return the match criteria referenced by this CVE. Cannot be combined with matchStringSearch.',
      ),
    matchCriteriaId: uuidInput
      .optional()
      .describe('CPE Match Criteria UUID (as returned by this tool, not a cpeNameId)'),
    matchStringSearch: z
      .string()
      .trim()
      .min(3)
      .optional()
      .describe(
        `Criteria match string, at most ${CPE_23_MAX_COMPONENTS} colon separated CPE 2.3 components; upstream rejects bare keywords, version ranges and longer strings. Matching is loose, so compare the returned criteria field with this string to confirm an exact hit`,
      ),
    lastModified: dateWindowInput
      .optional()
      .describe(`Filter on the match criteria last-modified date (max ${MAX_DATE_RANGE_DAYS} days)`),
    pageSize: pageSizeInput(
      PAGE_SIZE_LIMITS['cpe-matches'].max,
      PAGE_SIZE_LIMITS['cpe-matches'].default,
    ),
    cursor: cursorInput,
    fields: fieldsInput(CPE_MATCH_FIELDS),
    metaOnly: metaOnlyInput,
  },
  outputShape: {
    items: z.array(cpeMatchRecordOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cpeMatch.searchCpeMatches(input),
});
