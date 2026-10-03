import { z } from 'zod';

import { MAX_SUMMARY_AFFECTED_PRODUCTS } from '../../config/defaults.js';
import { CVE_SUMMARY_FIELDS } from '../../domain/field-projection.js';
import {
  cveIdListInput,
  cacheMetaOutput,
  cveSummaryOutput,
  fieldsInput,
  metaOnlyInput,
  readOnlyAnnotations,
} from '../tool-schemas.js';
import { defineTool } from '../tool.js';

/**
 * `nvd_get_cves` - batch CVE lookup.
 *
 * Only identifiers that are missing or stale locally are grouped into one NVD request.
 */
export const getCvesTool = defineTool({
  name: 'nvd_get_cves',
  title: 'Get multiple CVE summaries',
  description: [
    'Return summaries for up to 100 CVE identifiers in one call.',
    'Identifiers are uppercased and de-duplicated; only missing or stale ones are fetched, in one batch.',
    'Reports foundIds, missingIds and meta.requested/found/missing; use nvd_get_cve for a full record.',
    'Pass metaOnly:true for the counts without items.',
    `Each item is capped at ${MAX_SUMMARY_AFFECTED_PRODUCTS} affectedProducts; for score comparison pass`,
    'fields:["id","primaryCvss"] to keep the response small.',
    'Compare primaryCvss.version before comparing scores: primaryCvss is the single metric NVD marks as',
    'primary, not always the version asked for, and a record with no metric of that version reports the',
    'one it does have.',
    'The tool answers with whatever the identifiers resolve to and never guesses which record a description',
    'means, so identify a CVE with nvd_search_cves rather than a guessed id; when checking records against',
    'prose, keep summary in fields, because a wrong identifier still returns a complete but unrelated',
    'record and projecting the summary away is what hides the mismatch.',
  ].join(' '),
  inputShape: {
    cveIds: cveIdListInput,
    fields: fieldsInput(CVE_SUMMARY_FIELDS),
    metaOnly: metaOnlyInput,
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
