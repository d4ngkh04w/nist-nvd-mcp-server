import { z } from 'zod';

import { cveIdListInput, cacheMetaOutput, cveSummaryOutput, readOnlyAnnotations } from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `get_cves` - batch CVE lookup.
 *
 * Only identifiers that are missing or stale locally are grouped into one NVD request.
 */
export const getCvesTool = defineTool({
  name: 'get_cves',
  title: 'Get multiple CVE summaries',
  description: [
    'Return summaries for up to 100 CVE identifiers in one call.',
    'Identifiers are uppercased and de-duplicated; only missing or stale ones are fetched, in one batch.',
    'Reports foundIds, missingIds and meta.requested/found/missing; use get_cve for a full record.',
  ].join(' '),
  inputShape: {
    cveIds: cveIdListInput,
  },
  outputShape: {
    items: z.array(cveSummaryOutput),
    foundIds: z.array(z.string()),
    missingIds: z.array(z.string()),
    meta: cacheMetaOutput.extend({
      requested: z.number(),
      found: z.number(),
      missing: z.number(),
    }),
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.getCves(input),
});
