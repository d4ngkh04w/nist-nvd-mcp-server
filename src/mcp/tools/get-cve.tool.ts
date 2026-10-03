import { z } from 'zod';

import { CVE_DETAILS_FIELDS } from '../../domain/field-projection.js';
import {
  cveIdInput,
  cacheMetaOutput,
  cveDetailsOutput,
  fieldsInput,
  readOnlyAnnotations,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `nvd_get_cve` - full CVE record.
 *
 * Served from the SQLite/disk cache when fresh (24 h TTL); a cache hit never contacts NVD.
 */
export const getCveTool = defineTool({
  name: 'nvd_get_cve',
  title: 'Get CVE details',
  description: [
    'Return the full NVD record for one CVE: description, all CVSS metrics, CWEs, configurations,',
    'references and CISA KEV status. Use nvd_get_cve_summary for the essentials, nvd_get_cves for a batch.',
    'Cached for 24 hours; on an NVD outage the stale copy is returned with a warning in meta.warnings.',
    'configurations and references are both included by default, so includeConfigurations and',
    'includeReferences only matter when set to false, which drops that part of the record.',
    '`fields` works on top-level keys only and cannot prune inside the configurations tree: to look at',
    'one product, drop configurations here and enumerate its criteria instead, with',
    'nvd_search_cpe_matches matchStringSearch cpe:2.3:a:apache:log4j:* for every row of that product.',
  ].join(' '),
  inputShape: {
    cveId: cveIdInput,
    includeConfigurations: z
      .boolean()
      .optional()
      .describe('Include the CPE configuration tree (default true; pass false to drop it)'),
    includeReferences: z
      .boolean()
      .optional()
      .describe('Include the reference list (default true; pass false to drop it)'),
    includeRaw: z
      .boolean()
      .optional()
      .describe(
        'Include the raw NVD payload when it is available in the local cache (default false)',
      ),
    fields: fieldsInput(CVE_DETAILS_FIELDS),
  },
  outputShape: {
    data: cveDetailsOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.getCve(input),
});
