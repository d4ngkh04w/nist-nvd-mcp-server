import { describe, expect, it } from 'vitest';

import { DomainError } from '../../src/domain/errors.js';
import type {
  CveHistoryQuery,
  CveQuery,
  CpeMatchQuery,
  CpeQuery,
  CvssVersion,
} from '../../src/domain/queries.js';
import { NvdHttpClient, serializeQuery } from '../../src/infrastructure/nvd/http-client.js';
import {
  buildCpeMatchParams,
  buildCpeParams,
  buildCveHistoryParams,
  buildCveIdLookupParams,
  buildCveSearchParams,
  cvssParamKeys,
  toNvdDateParam,
  withPagination,
} from '../../src/infrastructure/nvd/query-params.js';
import { SequentialRateLimiter } from '../../src/infrastructure/rate-limit/sequential-rate-limiter.js';
import { Logger } from '../../src/shared/logger.js';
import { cveItem, cveResponse } from '../helpers/fixtures.js';

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

describe('buildCveSearchParams', () => {
  it('maps the full filter set onto the documented upstream parameter names', () => {
    const query: CveQuery = {
      cveIds: ['cve-2024-3094', 'CVE-2021-44228'],
      keyword: 'xz backdoor',
      keywordExactMatch: true,
      cpeName: 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*',
      virtualMatchString: 'cpe:2.3:a:tukaani:xz',
      cweId: 'CWE-506',
      sourceIdentifier: 'secalert@redhat.com',
      vulnStatuses: ['Analyzed'],
      cvss: {
        version: '3.1',
        severity: 'HIGH',
        metrics: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      },
      published: { start: '2024-01-01T00:00:00Z', end: '2024-03-01T00:00:00Z' },
      lastModified: { start: '2024-02-01T00:00:00Z', end: '2024-03-15T00:00:00Z' },
      kevOnly: true,
      kevAddedBetween: { start: '2024-04-01T00:00:00Z', end: '2024-04-10T00:00:00Z' },
      noRejected: true,
      hasCertAlerts: true,
      hasCertNotes: true,
      hasOval: true,
      isVulnerable: true,
    };

    const params = buildCveSearchParams(query);

    expect(params).toEqual({
      cveIds: 'CVE-2024-3094,CVE-2021-44228',
      keywordSearch: 'xz backdoor',
      keywordExactMatch: '',
      cpeName: 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*',
      virtualMatchString: 'cpe:2.3:a:tukaani:xz',
      cweId: 'CWE-506',
      sourceIdentifier: 'secalert@redhat.com',
      vulnStatuses: 'Analyzed',
      cvssV3Severity: 'HIGH',
      cvssV3Metrics: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      pubStartDate: '2024-01-01T00:00:00.000',
      pubEndDate: '2024-03-01T00:00:00.000',
      lastModStartDate: '2024-02-01T00:00:00.000',
      lastModEndDate: '2024-03-15T00:00:00.000',
      kevStartDate: '2024-04-01T00:00:00.000',
      kevEndDate: '2024-04-10T00:00:00.000',
      hasKev: '',
      isVulnerable: '',
      noRejected: '',
      hasCertAlerts: '',
      hasCertNotes: '',
      hasOval: '',
    });
  });

  it('emits the valueless flags as empty strings', () => {
    const params = buildCveSearchParams({
      kevOnly: true,
      noRejected: true,
      hasCertAlerts: true,
      hasCertNotes: true,
      hasOval: true,
    });

    for (const key of ['hasKev', 'noRejected', 'hasCertAlerts', 'hasCertNotes', 'hasOval']) {
      expect(params[key]).toBe('');
    }
  });

  it('forwards every filter the live API accepts', () => {
    const params = buildCveSearchParams({
      vulnStatuses: ['Analyzed', 'Modified'],
      isVulnerable: true,
      kevAddedBetween: { start: '2024-04-01T00:00:00Z', end: '2024-04-10T00:00:00Z' },
    });

    expect(params).toEqual({
      vulnStatuses: 'Analyzed,Modified',
      isVulnerable: '',
      kevStartDate: '2024-04-01T00:00:00.000',
      kevEndDate: '2024-04-10T00:00:00.000',
    });
    expect(params).not.toHaveProperty('vulnStatus');
    expect(params).not.toHaveProperty('kevAddedBetween');
  });

  it('canonicalizes status spellings to the request form', () => {
    const params = buildCveSearchParams({
      vulnStatuses: ['Undergoing Analysis', 'AwaitingAnalysis', 'undergoinganalysis'],
    });

    // Spaced and camel spellings collapse onto one comma separated camel-case value.
    expect(params['vulnStatuses']).toBe('UndergoingAnalysis,AwaitingAnalysis');
  });

  it('uses the plural cveIds parameter for lookups', () => {
    expect(buildCveIdLookupParams(['cve-2024-3094'])).toEqual({ cveIds: 'CVE-2024-3094' });
    expect(buildCveSearchParams({ cveIds: ['CVE-2024-3094'] })).toEqual({
      cveIds: 'CVE-2024-3094',
    });
  });

  it('renders the published date window in NVD format', () => {
    const params = buildCveSearchParams({
      published: { start: '2024-01-01', end: '2024-01-08' },
    });

    expect(params).toEqual({
      pubStartDate: '2024-01-01T00:00:00.000',
      pubEndDate: '2024-01-08T00:00:00.000',
    });
  });
});

describe('toNvdDateParam', () => {
  it('renders UTC datetimes as YYYY-MM-DDTHH:mm:ss.SSS without a timezone suffix', () => {
    const value = toNvdDateParam('2024-01-01T10:20:30Z');

    expect(value).toBe('2024-01-01T10:20:30.000');
    expect(value).not.toContain('Z');
    expect(value).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}$/);
  });

  it('converts offset timestamps to UTC', () => {
    expect(toNvdDateParam('2024-01-01T12:20:30+02:00')).toBe('2024-01-01T10:20:30.000');
    expect(toNvdDateParam('2024-01-01T05:20:30-05:00')).toBe('2024-01-01T10:20:30.000');
  });

  it('treats date-only values as midnight UTC', () => {
    expect(toNvdDateParam('2024-01-01')).toBe('2024-01-01T00:00:00.000');
  });

  it('rejects unparseable timestamps with INVALID_INPUT', () => {
    const error = captureDomainError(() => toNvdDateParam('yesterday'));
    expect(error.code).toBe('INVALID_INPUT');
  });
});

describe('cvssParamKeys', () => {
  const cases: Array<{
    version: CvssVersion;
    severityKey: string;
    metricsKey: string;
    otherFamilies: string[];
  }> = [
    {
      version: '2',
      severityKey: 'cvssV2Severity',
      metricsKey: 'cvssV2Metrics',
      otherFamilies: ['cvssV3Severity', 'cvssV3Metrics', 'cvssV4Severity', 'cvssV4Metrics'],
    },
    {
      version: '3',
      severityKey: 'cvssV3Severity',
      metricsKey: 'cvssV3Metrics',
      otherFamilies: ['cvssV2Severity', 'cvssV2Metrics', 'cvssV4Severity', 'cvssV4Metrics'],
    },
    {
      version: '3.1',
      severityKey: 'cvssV3Severity',
      metricsKey: 'cvssV3Metrics',
      otherFamilies: ['cvssV2Severity', 'cvssV2Metrics', 'cvssV4Severity', 'cvssV4Metrics'],
    },
    {
      version: '4',
      severityKey: 'cvssV4Severity',
      metricsKey: 'cvssV4Metrics',
      otherFamilies: ['cvssV2Severity', 'cvssV2Metrics', 'cvssV3Severity', 'cvssV3Metrics'],
    },
  ];

  it('maps each CVSS version to its upstream parameter names', () => {
    for (const entry of cases) {
      expect(cvssParamKeys(entry.version)).toEqual({
        severityKey: entry.severityKey,
        metricsKey: entry.metricsKey,
      });
    }
  });

  it('emits only the selected CVSS family in the built search params', () => {
    for (const entry of cases) {
      const params = buildCveSearchParams({
        cvss: { version: entry.version, severity: 'HIGH', metrics: 'CVSS:3.1/AV:N' },
      });

      expect(params[entry.severityKey]).toBe('HIGH');
      expect(params[entry.metricsKey]).toBe('CVSS:3.1/AV:N');
      for (const key of entry.otherFamilies) {
        expect(params).not.toHaveProperty(key);
      }
    }
  });
});

describe('buildCveIdLookupParams', () => {
  it('joins the normalized identifiers with commas', () => {
    expect(buildCveIdLookupParams([' cve-2024-3094', 'CVE-2021-44228'])).toEqual({
      cveIds: 'CVE-2024-3094,CVE-2021-44228',
    });
  });
});

describe('buildCveHistoryParams', () => {
  it('maps the id, event name and change window', () => {
    const query: CveHistoryQuery = {
      cveId: ' cve-2024-3094 ',
      eventName: 'CVE Modified',
      changeBetween: { start: '2024-03-01T00:00:00Z', end: '2024-03-02T00:00:00Z' },
    };

    expect(buildCveHistoryParams(query)).toEqual({
      cveId: 'CVE-2024-3094',
      eventName: 'CVE Modified',
      changeStartDate: '2024-03-01T00:00:00.000',
      changeEndDate: '2024-03-02T00:00:00.000',
    });
  });

  it('omits the optional filters when they are not provided', () => {
    expect(buildCveHistoryParams({ cveId: 'CVE-2024-3094' })).toEqual({ cveId: 'CVE-2024-3094' });
  });
});

describe('buildCpeParams', () => {
  it('maps keyword, CPE identifiers and the modified window', () => {
    const query: CpeQuery = {
      keyword: 'xz utils',
      keywordExactMatch: true,
      cpeMatchString: 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*',
      cpeNameId: 'b8f16312-24fa-4bec-b1df-a44c0cf6b36c',
      matchCriteriaId: '55782a0b-b9c5-4536-a885-84cab7029c09',
      lastModified: { start: '2024-04-01', end: '2024-04-02' },
      includeDeprecated: true,
    };

    const params = buildCpeParams(query);

    expect(params).toEqual({
      keywordSearch: 'xz utils',
      keywordExactMatch: '',
      cpeMatchString: 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*',
      cpeNameId: 'b8f16312-24fa-4bec-b1df-a44c0cf6b36c',
      matchCriteriaId: '55782a0b-b9c5-4536-a885-84cab7029c09',
      lastModStartDate: '2024-04-01T00:00:00.000',
      lastModEndDate: '2024-04-02T00:00:00.000',
    });
    expect(params).not.toHaveProperty('includeDeprecated');
  });

  it('omits keywordExactMatch when it is false', () => {
    expect(buildCpeParams({ keyword: 'xz', keywordExactMatch: false })).toEqual({
      keywordSearch: 'xz',
    });
  });
});

describe('buildCpeMatchParams', () => {
  it('maps the CVE, match identifiers, search term and modified window', () => {
    const query: CpeMatchQuery = {
      cveId: 'cve-2024-3094',
      matchCriteriaId: '55782a0b-b9c5-4536-a885-84cab7029c09',
      matchStringSearch: 'tukaani',
      lastModified: { start: '2024-04-01T00:00:00Z', end: '2024-04-02T00:00:00Z' },
    };

    expect(buildCpeMatchParams(query)).toEqual({
      cveId: 'CVE-2024-3094',
      matchCriteriaId: '55782a0b-b9c5-4536-a885-84cab7029c09',
      matchStringSearch: 'tukaani',
      lastModStartDate: '2024-04-01T00:00:00.000',
      lastModEndDate: '2024-04-02T00:00:00.000',
    });
  });

  it('returns an empty record when no filter is provided', () => {
    expect(buildCpeMatchParams({})).toEqual({});
  });
});

describe('withPagination', () => {
  it('adds the NVD offset and page size as strings without mutating the input', () => {
    const params = { cveId: 'CVE-2024-3094' };

    const paged = withPagination(params, { startIndex: 40, resultsPerPage: 50 });

    expect(paged).toEqual({ cveId: 'CVE-2024-3094', startIndex: '40', resultsPerPage: '50' });
    expect(typeof paged['startIndex']).toBe('string');
    expect(typeof paged['resultsPerPage']).toBe('string');
    expect(params).toEqual({ cveId: 'CVE-2024-3094' });
  });
});

describe('serializeQuery', () => {
  it('returns an empty string when there are no parameters', () => {
    expect(serializeQuery({})).toBe('');
  });

  it('serializes empty-string values as valueless flags without `=`', () => {
    expect(serializeQuery({ hasKev: '', noRejected: '' })).toBe('?hasKev&noRejected');
  });

  it('percent-encodes non-empty values', () => {
    expect(
      serializeQuery({ cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*' }),
    ).toBe(`?cpeName=cpe%3A2.3%3Aa%3Atukaani%3Axz%3A5.6.1${'%3A*'.repeat(7)}`);
    expect(serializeQuery({ keywordSearch: 'xz backdoor' })).toBe(
      '?keywordSearch=xz%20backdoor',
    );
  });

  it('never carries the API key into the query string', async () => {
    const apiKey = 'super-secret-api-key';
    let capturedUrl = '';
    let capturedHeaders: Record<string, string> = {};
    const fetchImpl: typeof fetch = async (input, init) => {
      capturedUrl = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      capturedHeaders = (init?.headers ?? {}) as Record<string, string>;
      return new Response(JSON.stringify(cveResponse([cveItem()])), { status: 200 });
    };
    const client = new NvdHttpClient({
      baseUrl: 'https://example.invalid/rest/json',
      apiKey,
      requestTimeoutMs: 1_000,
      maxRetries: 0,
      retryBaseDelayMs: 1,
      rateLimiter: new SequentialRateLimiter({ minIntervalMs: 0 }),
      logger: new Logger({ level: 'silent' }),
      fetchImpl,
    });

    await client.getJson('/cves/2.0', { cveId: 'CVE-2024-3094' });

    expect(capturedUrl).toBe('https://example.invalid/rest/json/cves/2.0?cveId=CVE-2024-3094');
    expect(capturedUrl).not.toContain(apiKey);
    expect(capturedHeaders['apiKey']).toBe(apiKey);
  });
});
