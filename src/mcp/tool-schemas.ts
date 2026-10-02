import { z } from 'zod';

import { MAX_CURSOR_LENGTH } from '../config/defaults.js';
import { CVE_ID_PATTERN_CASE_INSENSITIVE, UUID_PATTERN } from '../domain/validation.js';

/**
 * Reusable zod fragments shared by the tool input/output schemas.
 *
 * Inputs are validated here first (MCP schema validation) and again inside the use cases, which
 * also enforce cross-field rules (mutually exclusive filters, date windows, ...).
 */

export const cveIdInput = z
  .string()
  .trim()
  .regex(CVE_ID_PATTERN_CASE_INSENSITIVE, {
    message: 'cveId must match CVE-YYYY-NNNN (for example CVE-2024-3094)',
  })
  .describe('CVE identifier such as CVE-2024-3094 (case insensitive)');

export const cveIdListInput = z
  .array(cveIdInput)
  .min(1)
  .max(100)
  .describe('1-100 CVE identifiers; duplicates are removed and identifiers normalized to uppercase');

export const uuidInput = z
  .string()
  .trim()
  .regex(UUID_PATTERN, { message: 'value must be a UUID' });

export const cpeMatchStringInput = z
  .string()
  .trim()
  .min(3)
  .describe(
    'CPE 2.3 string, for example cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:* (CPE 2.2 URIs are also accepted)',
  );

export const dateWindowInput = z
  .object({
    start: z.string().min(1).describe('ISO-8601 inclusive start (UTC, for example 2024-01-01 or 2024-01-01T00:00:00Z)'),
    end: z.string().min(1).describe('ISO-8601 inclusive end (UTC)'),
  })
  .describe('Closed date window; NVD rejects windows longer than 120 days');

export const pageSizeInput = (max: number, defaultValue: number) =>
  z
    .number()
    .int()
    .min(1)
    .max(max)
    .optional()
    .describe(`Page size (default ${defaultValue}, maximum ${max})`);

export const cursorInput = z
  .string()
  .min(8)
  .max(MAX_CURSOR_LENGTH)
  .optional()
  .describe(
    'Opaque signed cursor from the previous page: pass the response\'s pagination.nextCursor. Never build it by hand; it expires after 30 minutes and is bound to the filters, pageSize and date window.',
  );

export const severityInput = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

export const cvssVersionInput = z.enum(['2', '3', '3.1', '4']);

export const cvssFilterInput = z
  .object({
    version: cvssVersionInput.describe('CVSS version whose metrics should be filtered'),
    severity: severityInput.optional().describe('Base severity to match'),
    metrics: z
      .string()
      .optional()
      .describe('Full CVSS vector string, for example CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
  })
  .refine((value) => value.severity !== undefined || value.metrics !== undefined, {
    message: 'cvss requires at least one of severity or metrics',
  })
  .describe('CVSS metric filter; requires at least one of severity or metrics');

export const vulnStatusesInput = z
  .array(z.string().min(1))
  .min(1)
  .max(10)
  .optional()
  .describe(
    'Vulnerability statuses (Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified, Deferred, Rejected). Spaced and camel-case spellings are both canonicalized, and the filter is applied by NVD.',
  );

// ----------------------------------------------------------------- output shapes

export const cacheMetaOutput = z
  .object({
    source: z.enum(['cache', 'nvd']).describe('Where the served payload came from'),
    cacheStatus: z.enum(['hit', 'miss', 'refresh', 'stale_fallback']),
    fetchedAt: z.string(),
    expiresAt: z.string(),
    ageSeconds: z.number(),
    stale: z.boolean(),
    warnings: z.array(z.string()),
    ordering: z.string().optional(),
    window: z.object({ start: z.string(), end: z.string() }).optional(),
    filtersAppliedClientSide: z.array(z.string()).optional(),
    filteredOut: z.number().optional(),
  })
  .describe('Cache/freshness metadata; warnings carries stale-fallback and truncation notices');

export const paginationOutput = z
  .object({
    pageSize: z.number(),
    returned: z.number(),
    totalResults: z
      .number()
      .describe(
        'Upstream (NVD) total for the filter set, before local filtering, so it can exceed the returned items.',
      ),
    hasMore: z
      .boolean()
      .describe(
        'True while the upstream offset walk still has rows; follows the upstream set, not a locally filtered page.',
      ),
    nextCursor: z.string().nullable(),
  })
  .describe('Pagination block; nextCursor is null on the last page');

/** A CPE name/id pair as returned by NVD. */
export const cpeNameRefOutput = z
  .object({
    cpeName: z.string(),
    cpeNameId: z.string(),
  })
  .loose();

export const primaryCvssOutput = z
  .object({
    version: z.string(),
    score: z.number(),
    severity: z.string(),
    vector: z.string(),
  })
  .loose();

export const cvssMetricOutput = z
  .object({
    source: z.string(),
    type: z.string().nullable(),
    cvssData: z
      .object({
        version: z.string(),
        vectorString: z.string(),
        baseScore: z.number(),
        baseSeverity: z.string().nullable(),
      })
      .loose(),
    baseSeverity: z.string().nullable(),
    exploitabilityScore: z.number().nullable(),
    impactScore: z.number().nullable(),
  })
  .loose();

export const cveSummaryOutput = z
  .object({
    id: z.string(),
    published: z.string(),
    lastModified: z.string(),
    vulnStatus: z.string().nullable(),
    summary: z.string().nullable(),
    primaryCvss: primaryCvssOutput.nullable(),
    cwes: z.array(z.string()),
    affectedProducts: z.array(z.object({ criteria: z.string(), vulnerable: z.boolean() }).loose()),
    isKnownExploited: z.boolean(),
    kevDateAdded: z.string().optional(),
    referenceCount: z.number(),
  })
  .loose();

export const cveCpeMatchOutput = z
  .object({
    vulnerable: z.boolean(),
    criteria: z.string(),
    matchCriteriaId: z.string().nullable(),
    versionStartIncluding: z.string().nullable(),
    versionStartExcluding: z.string().nullable(),
    versionEndIncluding: z.string().nullable(),
    versionEndExcluding: z.string().nullable(),
  })
  .loose();

export type CveConfigurationNodeOutput = {
  operator: string | null;
  negate: boolean;
  cpeMatch: Array<z.infer<typeof cveCpeMatchOutput>>;
  children: CveConfigurationNodeOutput[];
};

/**
 * CPE applicability node.
 *
 * NVD nests nodes through `children`, so the schema is recursive (`z.lazy`) - a flattened schema
 * would silently drop the deeper levels of the configuration tree.
 */
export const cveConfigurationNodeOutput: z.ZodType<CveConfigurationNodeOutput> = z.lazy(() =>
  z.object({
    operator: z.string().nullable(),
    negate: z.boolean(),
    cpeMatch: z.array(cveCpeMatchOutput),
    children: z.array(cveConfigurationNodeOutput),
  }),
);

export const cveDetailsOutput = z
  .object({
    id: z.string(),
    sourceIdentifier: z.string(),
    published: z.string(),
    lastModified: z.string(),
    vulnStatus: z.string().nullable(),
    description: z.string().nullable(),
    descriptions: z.array(z.object({ lang: z.string(), value: z.string() }).loose()),
    metrics: z
      .object({
        cvssMetricV2: z.array(cvssMetricOutput),
        cvssMetricV30: z.array(cvssMetricOutput),
        cvssMetricV31: z.array(cvssMetricOutput),
        cvssMetricV40: z.array(cvssMetricOutput),
        other: z.record(z.string(), z.unknown()),
      })
      .loose(),
    primaryCvss: z
      .object({
        version: z.string(),
        score: z.number(),
        severity: z.string(),
        vector: z.string(),
        source: z.string().nullable(),
        metricType: z.string().nullable(),
      })
      .loose()
      .nullable(),
    weaknesses: z.array(
      z.object({ source: z.string(), type: z.string().nullable(), cwes: z.array(z.string()) }).loose(),
    ),
    cwes: z.array(z.string()),
    configurations: z.array(z.object({ nodes: z.array(cveConfigurationNodeOutput) }).loose()).optional(),
    references: z
      .array(
        z.object({ url: z.string(), source: z.string().nullable(), tags: z.array(z.string()) }).loose(),
      )
      .optional(),
    isKnownExploited: z.boolean(),
    kev: z
      .object({
        dateAdded: z.string(),
        dueDate: z.string().nullable(),
        requiredAction: z.string().nullable(),
        vulnerabilityName: z.string().nullable(),
      })
      .loose()
      .nullable(),
    raw: z.unknown().optional(),
  })
  .loose();

export const cveChangeEventOutput = z
  .object({
    cveId: z.string(),
    eventName: z.string(),
    changeId: z.string(),
    sourceIdentifier: z.string(),
    created: z.string(),
    details: z.array(
      z
        .object({
          action: z.enum(['Added', 'Changed', 'Removed']),
          type: z.string(),
          oldValue: z.string().optional(),
          newValue: z.string().optional(),
        })
        .loose(),
    ),
  })
  .loose();

export const cpeRecordOutput = z
  .object({
    cpeNameId: z.string(),
    cpeName: z.string(),
    deprecated: z.boolean(),
    created: z.string(),
    lastModified: z.string(),
    titles: z.array(z.object({ title: z.string(), lang: z.string() }).loose()),
    refs: z.array(z.object({ ref: z.string(), type: z.string().nullable() }).loose()),
    deprecatedBy: z.array(cpeNameRefOutput),
    /** CPE names this entry deprecates (the inverse relation of `deprecatedBy`). */
    deprecates: z.array(cpeNameRefOutput),
  })
  .loose();

export const cpeMatchRecordOutput = z
  .object({
    matchCriteriaId: z.string(),
    criteria: z.string(),
    status: z.string(),
    created: z.string(),
    lastModified: z.string(),
    cpeLastModified: z.string().nullable(),
    versionStartIncluding: z.string().nullable(),
    versionStartExcluding: z.string().nullable(),
    versionEndIncluding: z.string().nullable(),
    versionEndExcluding: z.string().nullable(),
    matches: z.array(z.object({ cpeName: z.string(), cpeNameId: z.string() }).loose()),
  })
  .loose();

/**
 * Annotations applied to every tool: the server never mutates remote state.
 *
 * `destructiveHint` is stated explicitly even though the specification only considers it when
 * `readOnlyHint` is false: its default is `true`, and some clients read it without checking
 * `readOnlyHint` first.
 */
export const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;
