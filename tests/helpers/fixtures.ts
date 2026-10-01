/**
 * Realistic NVD payload fixtures.
 *
 * Shapes mirror the live API responses (verified against services.nvd.nist.gov) so the mappers and
 * schemas are exercised with production-like data.
 */

export type CveFixtureOverrides = {
  id?: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string | null;
  description?: string | null;
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
  cwes?: string[];
  criteria?: string;
  criteriaVulnerable?: boolean;
  kev?: boolean;
  referenceCount?: number;
  withConfiguration?: boolean;
  /** Build a multi-level configuration tree (root without cpeMatch, nested `children`). */
  withNestedConfiguration?: boolean;
  withV2Metric?: boolean;
  withV40Metric?: boolean;
};

/** Criteria used by `withNestedConfiguration`, exported so tests can assert on them. */
export const NESTED_CONFIGURATION_CRITERIA = {
  childVulnerable: 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*',
  grandchildApplication: 'cpe:2.3:a:vendor:client:1.0:*:*:*:*:*:*:*',
  rootOnly: 'cpe:2.3:a:vendor:suite:2.0:*:*:*:*:*:*:*',
} as const;

/**
 * Three-level applicability tree:
 * root (no cpeMatch, `rootOnly` ignored) -> child (vulnerable kernel match)
 * -> grandchild (non-vulnerable application match).
 */
function nestedConfiguration(): Array<Record<string, unknown>> {
  return [
    {
      nodes: [
        {
          operator: 'AND',
          negate: false,
          children: [
            {
              operator: 'OR',
              negate: false,
              cpeMatch: [
                {
                  vulnerable: true,
                  criteria: NESTED_CONFIGURATION_CRITERIA.childVulnerable,
                  matchCriteriaId: 'AAAAAAAA-1111-4111-8111-AAAAAAAAAAAA',
                },
              ],
              children: [
                {
                  operator: 'OR',
                  negate: false,
                  cpeMatch: [
                    {
                      vulnerable: false,
                      criteria: NESTED_CONFIGURATION_CRITERIA.grandchildApplication,
                      matchCriteriaId: 'BBBBBBBB-2222-4222-8222-BBBBBBBBBBBB',
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
  ];
}

export function cveItem(overrides: CveFixtureOverrides = {}): Record<string, unknown> {
  const id = overrides.id ?? 'CVE-2024-3094';
  const description =
    overrides.description ??
    'Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0.';
  const criteria = overrides.criteria ?? 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*';
  const criteriaVulnerable = overrides.criteriaVulnerable ?? true;

  const metrics: Record<string, unknown> = {
    cvssMetricV31: [
      {
        source: 'nvd@nist.gov',
        type: 'Primary',
        cvssData: {
          version: '3.1',
          vectorString: overrides.vectorString ?? 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: overrides.baseScore ?? 8.1,
          baseSeverity: overrides.baseSeverity ?? 'HIGH',
          attackVector: 'NETWORK',
        },
        exploitabilityScore: 2.2,
        impactScore: 5.9,
      },
    ],
  };

  if (overrides.withV2Metric === true) {
    metrics['cvssMetricV2'] = [
      {
        source: 'nvd@nist.gov',
        type: 'Primary',
        cvssData: {
          version: '2.0',
          vectorString: 'AV:N/AC:M/Au:N/C:C/I:C/A:C',
          baseScore: 9.3,
        },
        baseSeverity: 'HIGH',
        exploitabilityScore: 8.6,
        impactScore: 10,
      },
    ];
  }

  if (overrides.withV40Metric === true) {
    metrics['cvssMetricV40'] = [
      {
        source: 'nvd@nist.gov',
        type: 'Primary',
        cvssData: {
          version: '4.0',
          vectorString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
          baseScore: 9.8,
          baseSeverity: 'CRITICAL',
        },
      },
    ];
  }

  const item: Record<string, unknown> = {
    id,
    sourceIdentifier: 'secalert@redhat.com',
    published: overrides.published ?? '2024-03-29T17:15:21.150',
    lastModified: overrides.lastModified ?? '2024-04-02T18:15:05.760',
    vulnStatus: overrides.vulnStatus === undefined ? 'Analyzed' : overrides.vulnStatus,
    descriptions: [{ lang: 'en', value: description }],
    metrics,
    weaknesses: [
      {
        source: 'nvd@nist.gov',
        type: 'Primary',
        description: (overrides.cwes ?? ['CWE-506']).map((cwe) => ({ lang: 'en', value: cwe })),
      },
    ],
    references: Array.from({ length: overrides.referenceCount ?? 2 }, (_, index) => ({
      url: `https://example.invalid/advisory/${index + 1}`,
      source: 'secalert@redhat.com',
      tags: ['Vendor Advisory'],
    })),
    cveTags: [],
  };

  if (overrides.withNestedConfiguration === true) {
    item['configurations'] = nestedConfiguration();
  } else if (overrides.withConfiguration !== false) {
    item['configurations'] = [
      {
        nodes: [
          {
            operator: 'OR',
            negate: false,
            cpeMatch: [
              {
                vulnerable: criteriaVulnerable,
                criteria,
                matchCriteriaId: '73F1DAD7-F362-4C5B-B980-2E5313C369DA',
              },
            ],
          },
        ],
      },
    ];
  }

  if (overrides.kev === true) {
    item['cisaExploitAdd'] = '2024-04-01';
    item['cisaActionDue'] = '2024-04-22';
    item['cisaRequiredAction'] = 'Apply mitigations per vendor instructions.';
    item['cisaVulnerabilityName'] = 'XZ Utils Backdoor';
  }

  return item;
}

export type CveResponseOptions = {
  startIndex?: number;
  resultsPerPage?: number;
  totalResults?: number;
};

export function cveResponse(
  items: Array<Record<string, unknown>>,
  options: CveResponseOptions = {},
): Record<string, unknown> {
  return {
    resultsPerPage: options.resultsPerPage ?? items.length,
    startIndex: options.startIndex ?? 0,
    totalResults: options.totalResults ?? items.length,
    format: 'NVD_CVE',
    version: '2.0',
    timestamp: '2026-01-15T12:00:00.000',
    vulnerabilities: items.map((cve) => ({ cve })),
  };
}

export function cveIds(count: number, startYear = 2024): string[] {
  return Array.from({ length: count }, (_, index) => `CVE-${startYear}-${1000 + index}`);
}

export function cveChange(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    cveId: 'CVE-2024-3094',
    eventName: 'CVE Modified',
    cveChangeId: '6575122A-CB6E-4772-BE00-0B6D5C1A0615',
    sourceIdentifier: 'nvd@nist.gov',
    created: '2024-03-29T19:15:41.947',
    details: [
      {
        action: 'Changed',
        type: 'CVSS V3.1 Severity',
        oldValue: 'HIGH',
        newValue: 'CRITICAL',
      },
    ],
    ...overrides,
  };
}

export function cveHistoryResponse(
  changes: Array<Record<string, unknown>>,
  options: CveResponseOptions = {},
): Record<string, unknown> {
  return {
    resultsPerPage: options.resultsPerPage ?? changes.length,
    startIndex: options.startIndex ?? 0,
    totalResults: options.totalResults ?? changes.length,
    format: 'NVD_CVEHistory',
    version: '2.0',
    timestamp: '2026-01-15T12:00:00.000',
    cveChanges: changes.map((change) => ({ change })),
  };
}

export function cpeItem(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    deprecated: false,
    cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
    cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
    lastModified: '2024-04-02T13:15:43.973',
    created: '2024-04-01T16:31:29.560',
    titles: [{ title: 'Tukaani XZ Utils 5.6.1', lang: 'en' }],
    refs: [{ ref: 'https://tukaani.org/xz/', type: 'Product' }],
    ...overrides,
  };
}

export function cpeResponse(
  items: Array<Record<string, unknown>>,
  options: CveResponseOptions = {},
): Record<string, unknown> {
  return {
    resultsPerPage: options.resultsPerPage ?? items.length,
    startIndex: options.startIndex ?? 0,
    totalResults: options.totalResults ?? items.length,
    format: 'NVD_CPE',
    version: '2.0',
    timestamp: '2026-01-15T12:00:00.000',
    products: items.map((cpe) => ({ cpe })),
  };
}

export function cpeMatchItem(
  overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    matchCriteriaId: '55782A0B-B9C5-4536-A885-84CAB7029C09',
    criteria: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
    lastModified: '2024-04-02T13:15:43.973',
    cpeLastModified: '2024-04-02T13:15:43.973',
    created: '2024-04-01T16:31:29.560',
    status: 'Active',
    matches: [
      {
        cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
        cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
      },
    ],
    ...overrides,
  };
}

export function cpeMatchResponse(
  items: Array<Record<string, unknown>>,
  options: CveResponseOptions = {},
): Record<string, unknown> {
  return {
    resultsPerPage: options.resultsPerPage ?? items.length,
    startIndex: options.startIndex ?? 0,
    totalResults: options.totalResults ?? items.length,
    format: 'NVD_CPEMatchString',
    version: '2.0',
    timestamp: '2026-01-15T12:00:00.000',
    matchStrings: items.map((matchString) => ({ matchString })),
  };
}
