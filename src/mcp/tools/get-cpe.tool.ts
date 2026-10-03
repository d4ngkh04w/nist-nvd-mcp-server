import { MAX_CPE_NAME_SCAN_PAGES } from '../../config/defaults.js';
import {
  cacheMetaOutput,
  cpeMatchStringInput,
  cpeRecordOutput,
  readOnlyAnnotations,
  uuidInput,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `nvd_get_cpe` - single CPE dictionary entry, by UUID (preferred) or by exact CPE name.
 */
export const getCpeTool = defineTool({
  name: 'nvd_get_cpe',
  title: 'Get a CPE name',
  description: [
    'Return one entry of the NVD Official CPE Dictionary: cpeName, cpeNameId, deprecated, titles, refs,',
    'created/lastModified and the deprecatedBy/deprecates relations.',
    'Provide exactly one of cpeNameId (preferred, exact CPE dictionary UUID) or cpeName.',
    `cpeName is resolved by upstream pattern search over at most ${MAX_CPE_NAME_SCAN_PAGES} pages; if the`,
    'exact name is not in that window the tool returns CPE_NOT_FOUND with the scanned/total counts and',
    'suggests nvd_search_cpes. That search ignores the deprecation filter, so deprecated entries resolve too.',
    'No deprecation filter is applied here: a deprecated entry comes back with deprecated true rather',
    'than being hidden, so deprecated false is an active statement by NVD - never the result of',
    'filtering - and it is consistent with empty deprecatedBy and deprecates, which stay empty for an',
    'entry that neither replaces nor is replaced.',
    'Near-identical builds coexist as separate entries (cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*',
    'and cpe:2.3:a:apache:log4j:2.0:rc1-rc1:*:*:*:*:*:*), so confirm the intended one from its titles.',
    'A CPE Match Criteria UUID is not a valid cpeNameId: use nvd_search_cpe_matches for criteria and',
    'their expanded CPE names.',
    'Entries are cached for 7 days.',
  ].join(' '),
  inputShape: {
    cpeNameId: uuidInput
      .optional()
      .describe(
        'CPE name UUID (preferred lookup key). A CPE Match Criteria UUID is not a dictionary id here: use nvd_search_cpe_matches for criteria.',
      ),
    cpeName: cpeMatchStringInput.optional().describe('Exact CPE name to resolve'),
  },
  outputShape: {
    data: cpeRecordOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cpe.getCpe(input),
});
