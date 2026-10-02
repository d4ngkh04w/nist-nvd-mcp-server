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
    'Return one entry of the NVD Official CPE Dictionary. Provide exactly one of cpeNameId (preferred,',
    'exact) or cpeName.',
    `cpeName is resolved by upstream pattern search over at most ${MAX_CPE_NAME_SCAN_PAGES} pages; if the`,
    'exact name is not in that window the tool returns CPE_NOT_FOUND with the scanned/total counts and',
    'suggests nvd_search_cpes. That search ignores the deprecation filter, so deprecated entries resolve too.',
    'Entries are cached for 7 days.',
  ].join(' '),
  inputShape: {
    cpeNameId: uuidInput.optional().describe('CPE name UUID (preferred lookup key)'),
    cpeName: cpeMatchStringInput.optional().describe('Exact CPE name to resolve'),
  },
  outputShape: {
    data: cpeRecordOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cpe.getCpe(input),
});
