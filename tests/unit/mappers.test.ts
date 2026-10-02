import { describe, expect, it } from 'vitest';

import { buildCveSummary, projectCveDetails } from '../../src/application/mapping/cve-summary.js';
import { MAX_SUMMARY_AFFECTED_PRODUCTS, MAX_SUMMARY_DESCRIPTION_CHARS } from '../../src/config/defaults.js';
import type { CveCpeMatch, CveConfiguration, CveDetails } from '../../src/domain/cve.js';
import { DomainError } from '../../src/domain/errors.js';
import {
  collectAffectedProducts,
  mapCveItem,
  severityFromScore,
} from '../../src/infrastructure/nvd/mappers/cve-mapper.js';
import { mapCveChange } from '../../src/infrastructure/nvd/mappers/cve-history-mapper.js';
import { mapCpeItem } from '../../src/infrastructure/nvd/mappers/cpe-mapper.js';
import { mapCpeMatch } from '../../src/infrastructure/nvd/mappers/cpe-match-mapper.js';
import {
  nvdCveHistoryItemSchema,
  nvdCveHistoryResponseSchema,
  nvdCveItemSchema,
  nvdCveResponseSchema,
  nvdCpeItemSchema,
  nvdCpeMatchItemSchema,
  nvdCpeMatchResponseSchema,
  nvdCpeResponseSchema,
  parseNvdResponse,
} from '../../src/infrastructure/nvd/schemas.js';
import {
  cpeItem,
  cpeMatchItem,
  cpeMatchResponse,
  cpeResponse,
  cveChange,
  cveHistoryResponse,
  cveItem,
  cveResponse,
  SSVC_CHANGE_DETAIL,
  type CveFixtureOverrides,
} from '../helpers/fixtures.js';

/** Runs `fn` and returns the `DomainError` it must throw. */
function captureDomainError(fn: () => unknown): DomainError {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  if (!(caught instanceof DomainError)) {
    throw new Error('Expected the call to throw a DomainError');
  }
  return caught;
}

/** Maps the first CVE of a realistic `/cves/2.0` response through the real schema. */
function mapFirstCve(overrides: CveFixtureOverrides = {}): CveDetails {
  const response = nvdCveResponseSchema.parse(cveResponse([cveItem(overrides)]));
  const first = response.vulnerabilities[0];
  if (first === undefined) {
    throw new Error('fixture produced no vulnerability');
  }
  return mapCveItem(first.cve);
}

function metricsOf(raw: Record<string, unknown>): Record<string, unknown> {
  const metrics = raw['metrics'];
  if (metrics === null || typeof metrics !== 'object' || Array.isArray(metrics)) {
    throw new Error('fixture is missing a metrics record');
  }
  return metrics as Record<string, unknown>;
}

function firstV31Metric(raw: Record<string, unknown>): Record<string, unknown> {
  const family = metricsOf(raw)['cvssMetricV31'];
  if (!Array.isArray(family) || family.length === 0) {
    throw new Error('fixture is missing cvssMetricV31');
  }
  const first: unknown = family[0];
  if (first === null || typeof first !== 'object') {
    throw new Error('cvssMetricV31 entry is not an object');
  }
  return first as Record<string, unknown>;
}

function cpeMatch(criteria: string, vulnerable: boolean): CveCpeMatch {
  return {
    criteria,
    vulnerable,
    matchCriteriaId: null,
    versionStartIncluding: null,
    versionStartExcluding: null,
    versionEndIncluding: null,
    versionEndExcluding: null,
  };
}

describe('NVD fixtures', () => {
  it('stay schema-valid for every real response schema', () => {
    const cve = nvdCveResponseSchema.parse(cveResponse([cveItem()]));
    expect(cve.vulnerabilities).toHaveLength(1);
    expect(cve.vulnerabilities[0]?.cve.id).toBe('CVE-2024-3094');

    const history = nvdCveHistoryResponseSchema.parse(cveHistoryResponse([cveChange()]));
    expect(history.cveChanges[0]?.change.cveId).toBe('CVE-2024-3094');

    const cpes = nvdCpeResponseSchema.parse(cpeResponse([cpeItem()]));
    expect(cpes.products[0]?.cpe.cpeNameId).toBe('B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C');

    const matches = nvdCpeMatchResponseSchema.parse(cpeMatchResponse([cpeMatchItem()]));
    expect(matches.matchStrings[0]?.matchString.matchCriteriaId).toBe(
      '55782A0B-B9C5-4536-A885-84CAB7029C09',
    );
  });
});

describe('mapCveItem', () => {
  it('uppercases the id and prefers the English description', () => {
    const raw = cveItem({ id: 'cve-2024-3094' });
    raw['descriptions'] = [
      { lang: 'es', value: 'descripción en español' },
      { lang: 'en-US', value: 'English description' },
    ];

    const details = mapCveItem(nvdCveItemSchema.parse(raw));

    expect(details.id).toBe('CVE-2024-3094');
    expect(details.description).toBe('English description');
    expect(details.descriptions).toHaveLength(2);
  });

  it('falls back to the first description when no English one exists', () => {
    const raw = cveItem();
    raw['descriptions'] = [{ lang: 'de', value: 'deutsche Beschreibung' }];

    const details = mapCveItem(nvdCveItemSchema.parse(raw));

    expect(details.description).toBe('deutsche Beschreibung');
  });

  it('maps the CISA KEV fields and flags isKnownExploited', () => {
    const details = mapFirstCve({ kev: true });

    expect(details.isKnownExploited).toBe(true);
    expect(details.kev).toEqual({
      dateAdded: '2024-04-01',
      dueDate: '2024-04-22',
      requiredAction: 'Apply mitigations per vendor instructions.',
      vulnerabilityName: 'XZ Utils Backdoor',
    });
  });

  it('reports no KEV data when the CISA fields are absent', () => {
    const details = mapFirstCve();

    expect(details.isKnownExploited).toBe(false);
    expect(details.kev).toBeNull();
  });

  it('splits known CVSS families and preserves unknown ones in metrics.other', () => {
    const raw = cveItem({ withV2Metric: true, withV40Metric: true });
    metricsOf(raw)['ssvcV203'] = {
      id: 'CVE-2024-3094',
      role: 'CISA Coordinator',
      version: '2.0.3',
    };

    const details = mapCveItem(nvdCveItemSchema.parse(raw));

    expect(details.metrics.cvssMetricV2).toHaveLength(1);
    expect(details.metrics.cvssMetricV30).toHaveLength(0);
    expect(details.metrics.cvssMetricV31).toHaveLength(1);
    expect(details.metrics.cvssMetricV40).toHaveLength(1);
    expect(details.metrics.other).toHaveProperty('ssvcV203');
    expect(details.metrics.cvssMetricV2[0]?.baseSeverity).toBe('HIGH');
  });

  it('maps configurations, weaknesses and references', () => {
    const details = mapFirstCve({
      cwes: ['CWE-506', 'cwe-506', 'NVD-CWE-noinfo', 'CWE-79'],
      referenceCount: 3,
    });

    expect(details.weaknesses).toHaveLength(1);
    expect(details.cwes).toEqual(['CWE-506', 'CWE-79']);
    expect(details.configurations).toHaveLength(1);

    const match = details.configurations?.[0]?.nodes[0]?.cpeMatch[0];
    expect(match?.vulnerable).toBe(true);
    expect(match?.criteria).toBe('cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*');
    expect(match?.matchCriteriaId).toBe('73F1DAD7-F362-4C5B-B980-2E5313C369DA');

    expect(details.references).toHaveLength(3);
    expect(details.references?.[0]).toEqual({
      url: 'https://example.invalid/advisory/1',
      source: 'secalert@redhat.com',
      tags: ['Vendor Advisory'],
    });
  });
});

describe('primary CVSS selection', () => {
  it('prefers a Primary v3.1 metric over a Secondary one', () => {
    const raw = cveItem();
    metricsOf(raw)['cvssMetricV31'] = [
      {
        source: 'third-party@example.invalid',
        type: 'Secondary',
        cvssData: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          baseScore: 5.0,
          baseSeverity: 'MEDIUM',
        },
      },
      {
        source: 'nvd@nist.gov',
        type: 'Primary',
        cvssData: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 9.8,
          baseSeverity: 'CRITICAL',
        },
      },
    ];

    const details = mapCveItem(nvdCveItemSchema.parse(raw));

    expect(details.primaryCvss?.score).toBe(9.8);
    expect(details.primaryCvss?.severity).toBe('CRITICAL');
    expect(details.primaryCvss?.metricType).toBe('Primary');
    expect(details.primaryCvss?.source).toBe('nvd@nist.gov');
  });

  it('falls back to the first metric when none is marked Primary', () => {
    const raw = cveItem();
    metricsOf(raw)['cvssMetricV31'] = [
      {
        source: 'third-party@example.invalid',
        type: 'Secondary',
        cvssData: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          baseScore: 7.0,
          baseSeverity: 'HIGH',
        },
      },
    ];

    const details = mapCveItem(nvdCveItemSchema.parse(raw));

    expect(details.primaryCvss?.score).toBe(7.0);
    expect(details.primaryCvss?.metricType).toBe('Secondary');
  });

  it('prefers CVSS v4.0 over v3.1 when both are present', () => {
    const details = mapFirstCve({ withV40Metric: true });

    expect(details.primaryCvss?.version).toBe('4.0');
    expect(details.primaryCvss?.score).toBe(9.8);
    expect(details.primaryCvss?.severity).toBe('CRITICAL');
  });

  it('yields a primary from a v2-only record using the metric-level severity', () => {
    const raw = cveItem({ withV2Metric: true });
    delete metricsOf(raw)['cvssMetricV31'];

    const details = mapCveItem(nvdCveItemSchema.parse(raw));

    expect(details.primaryCvss?.version).toBe('2.0');
    expect(details.primaryCvss?.score).toBe(9.3);
    expect(details.primaryCvss?.severity).toBe('HIGH');
  });

  it('derives the severity from the score when baseSeverity is missing', () => {
    const cases: Array<{ score: number; severity: string }> = [
      { score: 9.8, severity: 'CRITICAL' },
      { score: 7.5, severity: 'HIGH' },
      { score: 5.0, severity: 'MEDIUM' },
      { score: 1.0, severity: 'LOW' },
      { score: 0, severity: 'NONE' },
    ];

    for (const entry of cases) {
      const raw = cveItem({ baseScore: entry.score });
      const metric = firstV31Metric(raw);
      const cvssData = metric['cvssData'];
      if (cvssData === null || typeof cvssData !== 'object') {
        throw new Error('fixture is missing cvssData');
      }
      delete (cvssData as Record<string, unknown>)['baseSeverity'];

      const details = mapCveItem(nvdCveItemSchema.parse(raw));
      expect(details.primaryCvss?.score).toBe(entry.score);
      expect(details.primaryCvss?.severity).toBe(entry.severity);
    }
  });

  it('maps scores to severities at the documented boundaries', () => {
    expect(severityFromScore(9.8)).toBe('CRITICAL');
    expect(severityFromScore(7.5)).toBe('HIGH');
    expect(severityFromScore(5.0)).toBe('MEDIUM');
    expect(severityFromScore(1.0)).toBe('LOW');
    expect(severityFromScore(0)).toBe('NONE');
  });
});

describe('buildCveSummary', () => {
  it('truncates descriptions that exceed the summary budget', () => {
    const description = 'x'.repeat(MAX_SUMMARY_DESCRIPTION_CHARS + 500);
    const { summary, warnings } = buildCveSummary(mapFirstCve({ description }));

    const summaryText = summary.summary;
    expect(summaryText).not.toBeNull();
    if (summaryText === null) {
      throw new Error('summary should not be null');
    }
    expect(summaryText.endsWith('... (truncated)')).toBe(true);
    expect(summaryText.length).toBe(MAX_SUMMARY_DESCRIPTION_CHARS + '... (truncated)'.length);
    expect(warnings).toEqual([]);
  });

  it('caps affectedProducts and adds a warning when configurations contain more', () => {
    const raw = cveItem({ withConfiguration: false });
    const criteriaCount = MAX_SUMMARY_AFFECTED_PRODUCTS + 7;
    raw['configurations'] = [
      {
        nodes: [
          {
            operator: 'OR',
            negate: false,
            cpeMatch: Array.from({ length: criteriaCount }, (_, index) => ({
              vulnerable: true,
              criteria: `cpe:2.3:a:vendor:product:${index + 1}.0:*:*:*:*:*:*:*`,
              matchCriteriaId: `00000000-0000-0000-0000-${String(index).padStart(12, '0')}`,
            })),
          },
        ],
      },
    ];

    const { summary, warnings } = buildCveSummary(mapCveItem(nvdCveItemSchema.parse(raw)));

    expect(summary.affectedProducts).toHaveLength(MAX_SUMMARY_AFFECTED_PRODUCTS);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`truncated to ${MAX_SUMMARY_AFFECTED_PRODUCTS}`);
  });

  it('deduplicates identical criteria in affectedProducts', () => {
    const raw = cveItem({ withConfiguration: false });
    const duplicate = {
      vulnerable: true,
      criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
    };
    raw['configurations'] = [
      {
        nodes: [
          {
            operator: 'OR',
            negate: false,
            cpeMatch: [duplicate, duplicate, { ...duplicate, vulnerable: false }],
          },
        ],
      },
    ];

    const { summary } = buildCveSummary(mapCveItem(nvdCveItemSchema.parse(raw)));

    expect(summary.affectedProducts).toEqual([
      { criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', vulnerable: true },
      { criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', vulnerable: false },
    ]);
  });

  it('sets kevDateAdded only for KEV records', () => {
    const kevSummary = buildCveSummary(mapFirstCve({ kev: true })).summary;
    expect(kevSummary.isKnownExploited).toBe(true);
    expect(kevSummary.kevDateAdded).toBe('2024-04-01');

    const plainSummary = buildCveSummary(mapFirstCve()).summary;
    expect(plainSummary.isKnownExploited).toBe(false);
    expect(plainSummary).not.toHaveProperty('kevDateAdded');
  });

  it('projects the primary CVSS values and counts the references', () => {
    const { summary } = buildCveSummary(mapFirstCve({ referenceCount: 5 }));

    expect(summary.primaryCvss).toEqual({
      version: '3.1',
      score: 8.1,
      severity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    });
    expect(summary.referenceCount).toBe(5);
  });
});

describe('projectCveDetails', () => {
  it('removes configurations, references and raw when they are not requested', () => {
    const details = mapFirstCve({ referenceCount: 2 });
    details.raw = { huge: 'payload' };

    const projected = projectCveDetails(details, {
      includeConfigurations: false,
      includeReferences: false,
    });

    expect('configurations' in projected).toBe(false);
    expect('references' in projected).toBe(false);
    expect('raw' in projected).toBe(false);

    // Deleting on the projection is not aliased to the source object.
    expect(details.configurations).toBeDefined();
    expect(details.references).toBeDefined();
    expect(details.raw).toBeDefined();

    // Mutating the source afterwards cannot resurrect the removed keys.
    details.raw = 'mutated';
    details.configurations = [];
    expect('raw' in projected).toBe(false);
    expect('configurations' in projected).toBe(false);
  });

  it('keeps configurations and references when they are requested but always drops raw', () => {
    const details = mapFirstCve({ referenceCount: 2 });
    details.raw = { huge: 'payload' };

    const projected = projectCveDetails(details, {
      includeConfigurations: true,
      includeReferences: true,
    });

    expect(projected.configurations).toEqual(details.configurations);
    expect(projected.references).toEqual(details.references);
    expect('raw' in projected).toBe(false);
  });
});

describe('mapCveChange', () => {
  it('maps a realistic change event through the response schema', () => {
    const response = nvdCveHistoryResponseSchema.parse(
      cveHistoryResponse([cveChange({ cveChangeId: '6575122a-cb6e-4772-be00-0b6d5c1a0615' })]),
    );
    const change = response.cveChanges[0]?.change;
    if (change === undefined) {
      throw new Error('fixture produced no change');
    }

    const mapped = mapCveChange(change);

    expect(mapped.cveId).toBe('CVE-2024-3094');
    expect(mapped.eventName).toBe('CVE Modified');
    expect(mapped.changeId).toBe('6575122A-CB6E-4772-BE00-0B6D5C1A0615');
    expect(mapped.sourceIdentifier).toBe('nvd@nist.gov');
    expect(mapped.details).toEqual([
      { action: 'Changed', type: 'CVSS V3.1 Severity', oldValue: 'HIGH', newValue: 'CRITICAL' },
    ]);
  });

  it('normalizes actions and only carries oldValue/newValue when supplied', () => {
    const item = nvdCveHistoryItemSchema.parse(
      cveChange({
        details: [
          { action: 'added', type: 'Reference', newValue: 'https://example.invalid/new' },
          { action: 'removed', type: 'Reference', oldValue: 'https://example.invalid/old' },
          { action: 'changed', type: 'CVSS' },
          { action: 'something-else', type: 'Other' },
        ],
      }),
    );

    const mapped = mapCveChange(item);

    expect(mapped.details.map((detail) => detail.action)).toEqual([
      'Added',
      'Removed',
      'Changed',
      'Changed',
    ]);

    const added = mapped.details[0];
    const removed = mapped.details[1];
    const changed = mapped.details[2];
    if (added === undefined || removed === undefined || changed === undefined) {
      throw new Error('expected four mapped details');
    }
    expect('oldValue' in added).toBe(false);
    expect(added.newValue).toBe('https://example.invalid/new');
    expect(removed.oldValue).toBe('https://example.invalid/old');
    expect('newValue' in removed).toBe(false);
    expect('oldValue' in changed).toBe(false);
    expect('newValue' in changed).toBe(false);
    expect(changed.type).toBe('CVSS');
  });

  it('accepts an SSVC detail whose newValue is a JSON object and flattens it to text', () => {
    // Regression: the live /cvehistory/2.0 returns `newValue` as an object for structured payloads,
    // which used to fail response validation with UPSTREAM_BAD_RESPONSE and break page 2.
    const item = nvdCveHistoryItemSchema.parse(
      cveChange({ cveId: 'CVE-2021-44228', details: [SSVC_CHANGE_DETAIL] }),
    );

    const mapped = mapCveChange(item);

    const detail = mapped.details[0];
    if (detail === undefined) {
      throw new Error('expected one mapped detail');
    }
    expect(detail.type).toBe('SSVC');
    expect(typeof detail.newValue).toBe('string');
    expect(JSON.parse(detail.newValue ?? '{}')).toEqual(SSVC_CHANGE_DETAIL.newValue);
  });

  it('keeps a page of changes valid when only some details carry structured values', () => {
    const response = nvdCveHistoryResponseSchema.parse(
      cveHistoryResponse([
        cveChange({ details: [SSVC_CHANGE_DETAIL] }),
        cveChange({ cveChangeId: 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE' }),
        cveChange({
          cveChangeId: '11111111-2222-3333-4444-555555555555',
          details: [{ action: 'Removed', type: 'Reference', oldValue: '' }],
        }),
      ]),
    );

    const mapped = response.cveChanges.map((wrapper) => mapCveChange(wrapper.change));

    expect(mapped).toHaveLength(3);
    expect(typeof mapped[0]?.details[0]?.newValue).toBe('string');
    expect(mapped[1]?.details[0]?.newValue).toBe('CRITICAL');
    expect(mapped[2]?.details[0]?.oldValue).toBe('');
  });
});

describe('mapCpeItem', () => {
  it('uppercases the id, defaults deprecated and maps titles, refs and deprecatedBy', () => {
    const item = nvdCpeItemSchema.parse(
      cpeItem({
        cpeNameId: 'b8f16312-24fa-4bec-b1df-a44c0cf6b36c',
        deprecated: undefined,
        deprecatedBy: [
          {
            cpeName: 'cpe:2.3:a:tukaani:xz:5.6.2:*:*:*:*:*:*:*',
            cpeNameId: 'c1c1c1c1-1111-2222-3333-444444444444',
          },
        ],
      }),
    );

    const mapped = mapCpeItem(item);

    expect(mapped.cpeNameId).toBe('B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C');
    expect(mapped.deprecated).toBe(false);
    expect(mapped.titles).toEqual([{ title: 'Tukaani XZ Utils 5.6.1', lang: 'en' }]);
    expect(mapped.refs).toEqual([{ ref: 'https://tukaani.org/xz/', type: 'Product' }]);
    expect(mapped.deprecatedBy).toEqual([
      {
        cpeName: 'cpe:2.3:a:tukaani:xz:5.6.2:*:*:*:*:*:*:*',
        cpeNameId: 'C1C1C1C1-1111-2222-3333-444444444444',
      },
    ]);
  });

  it('preserves deprecation and defaults the missing timestamps to empty strings', () => {
    const item = nvdCpeItemSchema.parse(
      cpeItem({ deprecated: true, created: undefined, lastModified: undefined }),
    );

    const mapped = mapCpeItem(item);

    expect(mapped.deprecated).toBe(true);
    expect(mapped.created).toBe('');
    expect(mapped.lastModified).toBe('');
  });
});

describe('mapCpeMatch', () => {
  it('defaults the version range to null, status to Unknown and uppercases match ids', () => {
    const item = nvdCpeMatchItemSchema.parse(
      cpeMatchItem({
        matchCriteriaId: '55782a0b-b9c5-4536-a885-84cab7029c09',
        status: undefined,
        matches: [
          {
            cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
            cpeNameId: 'b8f16312-24fa-4bec-b1df-a44c0cf6b36c',
          },
        ],
      }),
    );

    const mapped = mapCpeMatch(item);

    expect(mapped.matchCriteriaId).toBe('55782A0B-B9C5-4536-A885-84CAB7029C09');
    expect(mapped.status).toBe('Unknown');
    expect(mapped.versionStartIncluding).toBeNull();
    expect(mapped.versionStartExcluding).toBeNull();
    expect(mapped.versionEndIncluding).toBeNull();
    expect(mapped.versionEndExcluding).toBeNull();
    expect(mapped.cpeLastModified).toBe('2024-04-02T13:15:43.973');
    expect(mapped.matches).toEqual([
      {
        cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
        cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
      },
    ]);
  });

  it('keeps status and version range values when they are present', () => {
    const item = nvdCpeMatchItemSchema.parse(
      cpeMatchItem({
        status: 'Active',
        versionStartIncluding: '5.6.0',
        versionEndExcluding: '5.6.2',
      }),
    );

    const mapped = mapCpeMatch(item);

    expect(mapped.status).toBe('Active');
    expect(mapped.versionStartIncluding).toBe('5.6.0');
    expect(mapped.versionEndExcluding).toBe('5.6.2');
  });
});

describe('collectAffectedProducts', () => {
  it('deduplicates identical {criteria, vulnerable} pairs but keeps distinct pairs', () => {
    const configuration: CveConfiguration = {
      nodes: [
        {
          operator: 'OR',
          negate: false,
          children: [],
          cpeMatch: [
            cpeMatch('cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', true),
            cpeMatch('cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', true),
            cpeMatch('cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', false),
            cpeMatch('cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*', true),
          ],
        },
      ],
    };

    expect(collectAffectedProducts([configuration])).toEqual([
      { criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', vulnerable: true },
      { criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', vulnerable: false },
      { criteria: 'cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*', vulnerable: true },
    ]);
  });

  it('returns an empty list when there are no configurations', () => {
    expect(collectAffectedProducts(undefined)).toEqual([]);
    expect(collectAffectedProducts([])).toEqual([]);
  });
});

describe('parseNvdResponse', () => {
  it('throws UPSTREAM_BAD_RESPONSE with the endpoint for an invalid payload', () => {
    const error = captureDomainError(() => parseNvdResponse(nvdCveResponseSchema, {}, '/cves/2.0'));

    expect(error.code).toBe('UPSTREAM_BAD_RESPONSE');
    expect(error.details).toMatchObject({ endpoint: '/cves/2.0' });
    expect(Array.isArray(error.details?.['issues'])).toBe(true);
  });
});
