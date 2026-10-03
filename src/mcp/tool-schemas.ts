import { z } from 'zod';

import { MAX_CURSOR_LENGTH, MAX_DATE_RANGE_DAYS, PAGE_SIZE_LIMITS } from '../config/defaults.js';
import { CVE_SUMMARY_FIELDS } from '../domain/field-projection.js';
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
    end: z
      .string()
      .min(1)
      .describe(
        'ISO-8601 inclusive end (UTC). A date-only end covers the whole day and is sent as 23:59:59.999, so 2024-01-31 still includes records published during that day; a timestamp end is used verbatim',
      ),
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
    'Pass the previous page\'s pagination.nextCursor back byte for byte, with every filter and pageSize unchanged; never build or edit it. It is bound to those values, expires after 30 minutes, and a rejected cursor reports details.reason so an altered copy is distinguishable from a stale query.',
  );

export const severityInput = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

export const cvssVersionInput = z.enum(['2', '3', '3.1', '4']);

export const cvssFilterInput = z
  .object({
    version: cvssVersionInput.describe(
      'CVSS version whose metrics are inspected (required, and the reason a severity-only filter still needs it: a record can carry a 2.0 and a 3.1 score at once)',
    ),
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

/**
 * Input fragments shared by `nvd_get_recent_cves` and `nvd_get_modified_cves`.
 *
 * Both feeds resolve a relative `days` window or an explicit `start`+`end` pair and accept the same
 * CVE filters, so the schema is declared once here. Keeping it in one place is also what stops the
 * two published input schemas from drifting apart.
 */
export const feedWindowInput = {
  start: z.string().min(1).optional().describe('ISO-8601 window start (use with `end`)'),
  end: z
    .string()
    .min(1)
    .optional()
    .describe(
      'ISO-8601 window end (use with `start`); a date-only end covers the whole day and is sent as 23:59:59.999',
    ),
  days: z
    .number()
    .int()
    .min(1)
    .max(MAX_DATE_RANGE_DAYS)
    .optional()
    .describe('Relative window in days counted back from now; omitting it resolves to exactly 7'),
};

export const feedFiltersInput = {
  keyword: z.string().min(1).optional().describe('Optional keyword filter'),
  cpeName: cpeMatchStringInput.optional().describe('Optional CPE name filter'),
  cvss: cvssFilterInput.optional(),
  kevOnly: z.boolean().optional().describe('Only CISA KEV entries'),
  noRejected: z.boolean().optional().describe('Exclude rejected CVEs'),
};

/**
 * Response shaping for the payload-heavy tools.
 *
 * An omitted `fields` returns every field. The list is an allowlist: an unknown name is rejected with
 * the supported set in the message instead of being silently dropped.
 */
export const fieldsInput = (allowed: readonly string[]) =>
  z
    .array(z.string().min(1))
    .min(1)
    .max(allowed.length)
    .optional()
    .describe(
      [
        'Return only these top-level item fields; omit for all of them.',
        `Supported: ${allowed.join(', ')}.`,
        'Presentational only: the query, cache and cursor are unaffected, absent fields are omitted, and the',
        'applied list is echoed in meta.fieldsApplied.',
      ].join(' '),
    );

/**
 * Metadata-only response mode for the list tools.
 *
 * The upstream request and the cache read still happen, so this only removes the item array from the
 * response; `pagination.totalResults`, `hasMore` and the cursor still describe the page.
 */
export const metaOnlyInput = z
  .boolean()
  .optional()
  .describe(
    'Return only pagination and meta, with items as an empty array and pagination.returned as 0. The upstream request still happens, so use it to verify ordering or count pages, not to avoid the call. The pagination block still describes the suppressed page, so hasMore and nextCursor are returned as usual: ignore them for a pure metadata check, or follow nextCursor to continue the walk without the skipped page items.',
  );

/** Paging and projection shared by the two CVE feeds, which return the same item shape. */
export const cveFeedPageInput = {
  pageSize: pageSizeInput(PAGE_SIZE_LIMITS.cves.max, PAGE_SIZE_LIMITS.cves.default),
  cursor: cursorInput,
  fields: fieldsInput(CVE_SUMMARY_FIELDS),
  metaOnly: metaOnlyInput,
};

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
    ordering: z
      .enum(['published_desc', 'last_modified_desc', 'change_created_asc', 'nvd_default'])
      .optional()
      .describe(
        'Server-applied ordering: published_desc (newest publication first), last_modified_desc (newest modification first), change_created_asc (change history in creation order) or nvd_default (NVD ordering kept as-is).',
      ),
    window: z
      .object({ start: z.string(), end: z.string() })
      .optional()
      .describe(
        'The window actually queried: the resolved absolute bounds, echoed so a client can verify the exact range it asked for. A date-only end is echoed as that day 23:59:59.999. Absent when the query was not time bounded, or when two independent windows (published plus lastModified) were combined, since this field holds a single range.',
      ),
    filtersAppliedClientSide: z.array(z.string()).optional(),
    filteredOut: z.number().optional(),
    fieldsApplied: z
      .array(z.string())
      .optional()
      .describe('Item fields kept by the `fields` projection; absent when every field was returned'),
  })
  .describe('Cache/freshness metadata; warnings carries stale-fallback and truncation notices');

export const paginationOutput = z
  .object({
    page: z
      .number()
      .describe(
        'Ordinal of this page within the cursor walk, starting at 1. It comes from the cursor rather than from the upstream offset, so the descending feeds report 1 for their first page.',
      ),
    pageCount: z
      .number()
      .describe(
        'Pages the current upstream total divides into. The upstream set is live, so this is an estimate for the walk in progress and can change between two calls of the same walk.',
      ),
    pageSize: z.number(),
    returned: z
      .number()
      .describe('Items this response carries, so 0 when metaOnly suppressed them.'),
    totalResults: z
      .number()
      .describe(
        'Upstream (NVD) total for the filter set, before local filtering, so it can exceed the returned items. Reordering the window server side does not change it.',
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
    version: z.string().describe("NVD's preferred metric for the record; check it before comparing scores"),
    score: z.number(),
    severity: z.string(),
    vector: z.string(),
  })
  .loose()
  .describe(
    "The metric NVD marks as primary, which is not always CVSS 3.1: version can be 2, 3.0, 3.1 or 4",
  );

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

/**
 * Compact CVE projection (`nvd_get_cve_summary`, `nvd_get_cves`, `nvd_search_cves`, feeds).
 *
 * Every field is optional because the `fields` projection may omit it; without `fields` the response
 * always carries the full set.
 */
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
  .loose()
  .partial();

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

/** Full CVE record (`nvd_get_cve`); keys are optional so the `fields` projection can drop them. */
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
  .loose()
  .partial();

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
  .loose()
  .partial();

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

/**
 * A CPE dictionary entry inside a list response.
 *
 * `nvd_get_cpe` returns one entry with every key, so its schema stays complete; a list item can be
 * narrowed with `fields`, which is why the `required` list is dropped here.
 */
export const cpeRecordItemOutput = cpeRecordOutput.partial().loose();

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
  .loose()
  .partial();

/**
 * Annotations applied to every tool: the server never mutates remote state.
 *
 * `destructiveHint` defaults to `true` in the protocol and is only meaningful when `readOnlyHint` is
 * false, so it is stated explicitly instead of being left to that default.
 */
export const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;
