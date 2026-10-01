/**
 * Inference domain model for CVE records.
 */

export type CvssSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type CvssData = {
  version: string;
  vectorString: string;
  baseScore: number;
  baseSeverity: string | null;
  [key: string]: unknown;
};

export type CvssMetric = {
  source: string;
  type: string | null;
  cvssData: CvssData;
  /** Some NVD records (CVSS v2) carry the severity at metric level instead of inside `cvssData`. */
  baseSeverity: string | null;
  exploitabilityScore: number | null;
  impactScore: number | null;
};

/** CVSS metrics grouped by the NVD metric key. Unknown metric families are preserved verbatim. */
export type CveMetrics = {
  cvssMetricV2: CvssMetric[];
  cvssMetricV30: CvssMetric[];
  cvssMetricV31: CvssMetric[];
  cvssMetricV40: CvssMetric[];
  other: Record<string, unknown>;
};

export type PrimaryCvss = {
  version: string;
  score: number;
  severity: string;
  vector: string;
  source: string | null;
  metricType: string | null;
};

export type CveWeakness = {
  source: string;
  type: string | null;
  cwes: string[];
};

export type CveReference = {
  url: string;
  source: string | null;
  tags: string[];
};

export type CveCpeMatch = {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId: string | null;
  versionStartIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndIncluding: string | null;
  versionEndExcluding: string | null;
};

export type CveConfigurationNode = {
  operator: string | null;
  negate: boolean;
  cpeMatch: CveCpeMatch[];
  /** Nested nodes: NVD expresses AND/OR/NEGATE trees through `children`. */
  children: CveConfigurationNode[];
};

export type CveConfiguration = {
  nodes: CveConfigurationNode[];
};

export type KevInfo = {
  dateAdded: string;
  dueDate: string | null;
  requiredAction: string | null;
  vulnerabilityName: string | null;
};

export type CveDescription = {
  lang: string;
  value: string;
};

/** Full CVE detail as returned by `get_cve`. */
export type CveDetails = {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string | null;
  description: string | null;
  descriptions: CveDescription[];
  metrics: CveMetrics;
  primaryCvss: PrimaryCvss | null;
  weaknesses: CveWeakness[];
  cwes: string[];
  configurations?: CveConfiguration[];
  references?: CveReference[];
  isKnownExploited: boolean;
  kev: KevInfo | null;
  raw?: unknown;
};

/** Compact projection used by `get_cve_summary`, `get_cves` and search results. */
export type CveSummary = {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus: string | null;
  summary: string | null;
  primaryCvss: {
    version: string;
    score: number;
    severity: string;
    vector: string;
  } | null;
  cwes: string[];
  affectedProducts: Array<{
    criteria: string;
    vulnerable: boolean;
  }>;
  isKnownExploited: boolean;
  kevDateAdded?: string;
  referenceCount: number;
};

export type CveChangeDetail = {
  action: 'Added' | 'Changed' | 'Removed';
  type: string;
  oldValue?: string;
  newValue?: string;
};

export type CveChangeEvent = {
  cveId: string;
  eventName: string;
  changeId: string;
  sourceIdentifier: string;
  created: string;
  details: CveChangeDetail[];
};
