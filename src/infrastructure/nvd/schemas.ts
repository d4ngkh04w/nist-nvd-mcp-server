import { z } from 'zod';

import { DomainError } from '../../domain/errors.js';

/**
 * Response schemas for the NVD 2.0 endpoints.
 *
 * The envelope (pagination metadata) is validated strictly; entity payloads validate only the
 * fields this server depends on and keep unknown members, so new NVD fields never break the server.
 * A validation failure is reported as `UPSTREAM_BAD_RESPONSE`.
 */

const descriptionSchema = z
  .object({
    lang: z.string(),
    value: z.string(),
  })
  .loose();

const cvssDataSchema = z
  .object({
    version: z.string(),
    vectorString: z.string(),
    baseScore: z.number(),
    baseSeverity: z.string().nullish(),
  })
  .loose();

export const cvssMetricSchema = z
  .object({
    source: z.string(),
    type: z.string().nullish(),
    cvssData: cvssDataSchema,
    baseSeverity: z.string().nullish(),
    exploitabilityScore: z.number().nullish(),
    impactScore: z.number().nullish(),
  })
  .loose();

/** Recursive CPE applicability node: either `cpeMatch` entries, `children`, or both. */
export type NvdConfigurationNode = {
  operator?: string | null;
  negate?: boolean | null;
  cpeMatch?: NvdCpeMatchEntry[] | null;
  children?: NvdConfigurationNode[] | null;
};

export type NvdCpeMatchEntry = {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId?: string | null;
  versionStartIncluding?: string | null;
  versionStartExcluding?: string | null;
  versionEndIncluding?: string | null;
  versionEndExcluding?: string | null;
};

const cveCpeMatchSchema = z
  .object({
    vulnerable: z.boolean(),
    criteria: z.string(),
    matchCriteriaId: z.string().nullish(),
    versionStartIncluding: z.string().nullish(),
    versionStartExcluding: z.string().nullish(),
    versionEndIncluding: z.string().nullish(),
    versionEndExcluding: z.string().nullish(),
  })
  .loose();

const cveConfigurationNodeSchema: z.ZodType<NvdConfigurationNode> = z.lazy(() =>
  z
    .object({
      operator: z.string().nullish(),
      negate: z.boolean().nullish(),
      cpeMatch: z.array(cveCpeMatchSchema).nullish(),
      children: z.array(cveConfigurationNodeSchema).nullish(),
    })
    .loose(),
);

export const nvdCveItemSchema = z
  .object({
    id: z.string().min(1),
    sourceIdentifier: z.string().nullish(),
    published: z.string(),
    lastModified: z.string(),
    vulnStatus: z.string().nullish(),
    descriptions: z.array(descriptionSchema).nullish(),
    metrics: z.record(z.string(), z.unknown()).nullish(),
    weaknesses: z
      .array(
        z
          .object({
            source: z.string().nullish(),
            type: z.string().nullish(),
            description: z.array(descriptionSchema).nullish(),
          })
          .loose(),
      )
      .nullish(),
    configurations: z
      .array(z.object({ nodes: z.array(cveConfigurationNodeSchema).nullish() }).loose())
      .nullish(),
    references: z
      .array(
        z
          .object({
            url: z.string(),
            source: z.string().nullish(),
            tags: z.array(z.string()).nullish(),
          })
          .loose(),
      )
      .nullish(),
    cisaExploitAdd: z.string().nullish(),
    cisaActionDue: z.string().nullish(),
    cisaRequiredAction: z.string().nullish(),
    cisaVulnerabilityName: z.string().nullish(),
    cveTags: z.array(z.unknown()).nullish(),
    affected: z.unknown().optional(),
  })
  .loose();

const envelopeShape = {
  resultsPerPage: z.number(),
  startIndex: z.number(),
  totalResults: z.number(),
  format: z.string(),
  version: z.string(),
  timestamp: z.string().nullish(),
};

export const nvdCveResponseSchema = z
  .object({
    ...envelopeShape,
    vulnerabilities: z.array(z.object({ cve: nvdCveItemSchema }).loose()),
  })
  .loose();

export const nvdCveHistoryItemSchema = z
  .object({
    cveId: z.string().min(1),
    eventName: z.string(),
    cveChangeId: z.string().min(1),
    sourceIdentifier: z.string().nullish(),
    created: z.string(),
    details: z
      .array(
        z
          .object({
            action: z.string(),
            type: z.string().nullish(),
            oldValue: z.string().nullish(),
            newValue: z.string().nullish(),
          })
          .loose(),
      )
      .nullish(),
  })
  .loose();

export const nvdCveHistoryResponseSchema = z
  .object({
    ...envelopeShape,
    cveChanges: z.array(z.object({ change: nvdCveHistoryItemSchema }).loose()),
  })
  .loose();

export const nvdCpeItemSchema = z
  .object({
    cpeName: z.string().min(1),
    cpeNameId: z.string().min(1),
    deprecated: z.boolean().nullish(),
    created: z.string().nullish(),
    lastModified: z.string().nullish(),
    titles: z.array(z.object({ title: z.string(), lang: z.string() }).loose()).nullish(),
    refs: z.array(z.object({ ref: z.string(), type: z.string().nullish() }).loose()).nullish(),
    deprecatedBy: z
      .array(z.object({ cpeName: z.string(), cpeNameId: z.string() }).loose())
      .nullish(),
    deprecates: z
      .array(z.object({ cpeName: z.string(), cpeNameId: z.string() }).loose())
      .nullish(),
  })
  .loose();

export const nvdCpeResponseSchema = z
  .object({
    ...envelopeShape,
    products: z.array(z.object({ cpe: nvdCpeItemSchema }).loose()),
  })
  .loose();

export const nvdCpeMatchItemSchema = z
  .object({
    matchCriteriaId: z.string().min(1),
    criteria: z.string().min(1),
    status: z.string().nullish(),
    created: z.string().nullish(),
    lastModified: z.string().nullish(),
    cpeLastModified: z.string().nullish(),
    versionStartIncluding: z.string().nullish(),
    versionStartExcluding: z.string().nullish(),
    versionEndIncluding: z.string().nullish(),
    versionEndExcluding: z.string().nullish(),
    matches: z.array(z.object({ cpeName: z.string(), cpeNameId: z.string() }).loose()).nullish(),
  })
  .loose();

export const nvdCpeMatchResponseSchema = z
  .object({
    ...envelopeShape,
    matchStrings: z.array(z.object({ matchString: nvdCpeMatchItemSchema }).loose()),
  })
  .loose();

export type NvdCveItem = z.infer<typeof nvdCveItemSchema>;
export type NvdCveResponse = z.infer<typeof nvdCveResponseSchema>;
export type NvdCveHistoryItem = z.infer<typeof nvdCveHistoryItemSchema>;
export type NvdCveHistoryResponse = z.infer<typeof nvdCveHistoryResponseSchema>;
export type NvdCpeItem = z.infer<typeof nvdCpeItemSchema>;
export type NvdCpeResponse = z.infer<typeof nvdCpeResponseSchema>;
export type NvdCpeMatchItem = z.infer<typeof nvdCpeMatchItemSchema>;
export type NvdCpeMatchResponse = z.infer<typeof nvdCpeMatchResponseSchema>;

/** Validates a decoded NVD payload, converting schema failures into a structured tool error. */
export function parseNvdResponse<T>(schema: z.ZodType<T>, payload: unknown, endpoint: string): T {
  const result = schema.safeParse(payload);
  if (result.success) {
    return result.data;
  }
  const issues = result.error.issues.slice(0, 5).map((issue) => ({
    path: issue.path.map((segment) => String(segment)).join('.'),
    message: issue.message,
  }));
  throw DomainError.upstreamBadResponse(
    `NVD returned an unexpected response shape for ${endpoint}`,
    { endpoint, issues },
  );
}
