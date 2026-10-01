import { z } from 'zod';

import { cveIdInput, cacheMetaOutput, cveDetailsOutput, readOnlyAnnotations } from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `get_cve` - full CVE record.
 *
 * Served from the SQLite/disk cache when fresh (24 h TTL); a cache hit never contacts NVD.
 */
export const getCveTool = defineTool({
  name: 'get_cve',
  title: 'Get CVE details',
  description: [
    'Return the full NVD record for one CVE: description, all CVSS metrics, CWEs, configurations,',
    'references and CISA KEV status. Use get_cve_summary for the essentials, get_cves for a batch.',
    'Cached for 24 hours; on an NVD outage the stale copy is returned with a warning in meta.warnings.',
  ].join(' '),
  inputShape: {
    cveId: cveIdInput,
    includeConfigurations: z
      .boolean()
      .optional()
      .describe('Include the CPE configuration tree (default true)'),
    includeReferences: z
      .boolean()
      .optional()
      .describe('Include the reference list (default true)'),
    includeRaw: z
      .boolean()
      .optional()
      .describe(
        'Include the raw NVD payload when it is available in the local cache (default false)',
      ),
  },
  outputShape: {
    data: cveDetailsOutput,
    meta: cacheMetaOutput,
  },
  annotations: readOnlyAnnotations,
  execute: (input, ctx) => ctx.services.cve.getCve(input),
});
