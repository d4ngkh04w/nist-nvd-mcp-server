import { z } from 'zod';

import { MAX_DATE_RANGE_DAYS } from '../../config/defaults.js';
import {
  cacheMetaOutput,
  cveFeedPageInput,
  cveSummaryOutput,
  feedFiltersInput,
  feedWindowInput,
  paginationOutput,
  readOnlyAnnotations,
  vulnStatusesInput,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `nvd_get_modified_cves` - recently updated CVEs, newest first.
 *
 * Uses `lastModStartDate`/`lastModEndDate` semantics; `vulnStatuses` is forwarded to NVD.
 */
export const getModifiedCvesTool = defineTool({
  name: 'nvd_get_modified_cves',
  title: 'Get recently modified CVEs',
  description: [
    'Return CVEs ordered by last-modified date, newest first. This feed always reports meta.ordering as',
    '"last_modified_desc" on every page. Across the suite meta.ordering is one of published_desc,',
    'last_modified_desc, change_created_asc or nvd_default, the last meaning no server-side reordering',
    'and being what the search and CPE tools report.',
    'Defaults to the last 7 days: use `days` or an explicit `start`+`end` window (mutually exclusive,',
    `maximum ${MAX_DATE_RANGE_DAYS} days).`,
    'All filters are sent to NVD, so pagination.totalResults is the exact upstream total.',
    'The cursor already carries the resolved window, so a relative window stays stable across pages and',
    'repeating `days` is optional; with a cursor, omitting `days`/`start`/`end` reuses the frozen window',
    'while a different explicit window is rejected with INVALID_CURSOR rather than silently re-anchored.',
    'Cached for 5 minutes. For multi-page traversal pass fields:["id","lastModified"] to walk the feed',
    'cheaply, and keep the same `fields` on every page so the pages stay comparable.',
    'Pass metaOnly:true for pagination and meta without items; pagination.page and pagination.pageCount',
    'still report the position and the estimated page total.',
  ].join(' '),
  inputShape: {
    ...feedWindowInput,
    ...feedFiltersInput,
    vulnStatuses: vulnStatusesInput,
    ...cveFeedPageInput,
  },
  outputShape: {
    items: z.array(cveSummaryOutput),
    pagination: paginationOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.getModifiedCves(input),
});
