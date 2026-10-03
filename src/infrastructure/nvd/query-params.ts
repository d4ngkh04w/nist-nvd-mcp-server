import { DomainError } from '../../domain/errors.js';
import type {
  CveHistoryQuery,
  CveQuery,
  CpeMatchQuery,
  CpeQuery,
  CvssVersion,
  NvdPageRequest,
} from '../../domain/queries.js';
import { normalizeCveId, normalizeVulnStatuses } from '../../domain/validation.js';
import { parseIsoDate, toNvdDate } from '../../shared/time.js';
import type { NvdQueryParams } from './http-client.js';

/**
 * URL query builders for the four NVD 2.0 endpoints.
 *
 * Notes on upstream behaviour (verified against the live API):
 * - valueless flags must be emitted without `=` (`?hasKev`); `?hasKev=true` and `?hasKev=` return 404.
 * - `vulnStatuses` takes comma separated camel-case values (`UndergoingAnalysis`), while responses
 *   use spaced values (`Undergoing Analysis`).
 * - KEV date filtering uses `kevStartDate`/`kevEndDate`.
 * - `isVulnerable` is only accepted together with `cpeName` (HTTP 404 otherwise); the application
 *   layer enforces that pairing.
 * - the CPE `includeDeprecated` parameter is rejected by the live API (HTTP 404), so that policy is
 *   the only policy still applied locally.
 */

export function cvssParamKeys(version: CvssVersion): {
  severityKey: string;
  metricsKey: string;
} {
  switch (version) {
    case '2':
      return { severityKey: 'cvssV2Severity', metricsKey: 'cvssV2Metrics' };
    case '4':
      return { severityKey: 'cvssV4Severity', metricsKey: 'cvssV4Metrics' };
    case '3':
    case '3.1':
      return { severityKey: 'cvssV3Severity', metricsKey: 'cvssV3Metrics' };
    default:
      return { severityKey: 'cvssV3Severity', metricsKey: 'cvssV3Metrics' };
  }
}

export function toNvdDateParam(value: string): string {
  const parsed = parseIsoDate(value);
  if (parsed === null) {
    throw DomainError.invalidInput('Invalid ISO-8601 timestamp', { value });
  }
  return toNvdDate(parsed);
}

export function buildCveSearchParams(query: CveQuery): NvdQueryParams {
  const params: NvdQueryParams = {};

  if (query.cveIds !== undefined && query.cveIds.length > 0) {
    params['cveIds'] = query.cveIds.map(normalizeCveId).join(',');
  }
  if (query.keyword !== undefined) {
    params['keywordSearch'] = query.keyword;
  }
  if (query.keywordExactMatch === true) {
    params['keywordExactMatch'] = '';
  }
  if (query.cpeName !== undefined) {
    params['cpeName'] = query.cpeName;
  }
  if (query.isVulnerable === true) {
    // Upstream requires the valueless flag to be combined with `cpeName` (404 otherwise).
    params['isVulnerable'] = '';
  }
  if (query.virtualMatchString !== undefined) {
    params['virtualMatchString'] = query.virtualMatchString;
  }
  if (query.cweId !== undefined) {
    params['cweId'] = query.cweId;
  }
  if (query.sourceIdentifier !== undefined) {
    params['sourceIdentifier'] = query.sourceIdentifier;
  }
  if (query.cvss !== undefined) {
    const { severityKey, metricsKey } = cvssParamKeys(query.cvss.version);
    if (query.cvss.severity !== undefined) {
      params[severityKey] = query.cvss.severity;
    }
    if (query.cvss.metrics !== undefined) {
      params[metricsKey] = query.cvss.metrics;
    }
  }
  if (query.vulnStatuses !== undefined && query.vulnStatuses.length > 0) {
    params['vulnStatuses'] = normalizeVulnStatuses(query.vulnStatuses).join(',');
  }
  if (query.published !== undefined) {
    params['pubStartDate'] = toNvdDateParam(query.published.start);
    params['pubEndDate'] = toNvdDateParam(query.published.end);
  }
  if (query.lastModified !== undefined) {
    params['lastModStartDate'] = toNvdDateParam(query.lastModified.start);
    params['lastModEndDate'] = toNvdDateParam(query.lastModified.end);
  }
  if (query.kevAddedBetween !== undefined) {
    params['kevStartDate'] = toNvdDateParam(query.kevAddedBetween.start);
    params['kevEndDate'] = toNvdDateParam(query.kevAddedBetween.end);
  }
  if (query.kevOnly === true) {
    params['hasKev'] = '';
  }
  if (query.noRejected === true) {
    params['noRejected'] = '';
  }
  if (query.hasCertAlerts === true) {
    params['hasCertAlerts'] = '';
  }
  if (query.hasCertNotes === true) {
    params['hasCertNotes'] = '';
  }
  if (query.hasOval === true) {
    params['hasOval'] = '';
  }

  return params;
}

export function buildCveIdLookupParams(cveIds: readonly string[]): NvdQueryParams {
  return { cveIds: cveIds.map(normalizeCveId).join(',') };
}

export function buildCveHistoryParams(query: CveHistoryQuery): NvdQueryParams {
  const params: NvdQueryParams = { cveId: normalizeCveId(query.cveId) };
  if (query.eventName !== undefined) {
    params['eventName'] = query.eventName;
  }
  if (query.changeBetween !== undefined) {
    params['changeStartDate'] = toNvdDateParam(query.changeBetween.start);
    params['changeEndDate'] = toNvdDateParam(query.changeBetween.end);
  }
  return params;
}

export function buildCpeParams(query: CpeQuery): NvdQueryParams {
  const params: NvdQueryParams = {};
  if (query.keyword !== undefined) {
    params['keywordSearch'] = query.keyword;
  }
  if (query.keywordExactMatch === true) {
    params['keywordExactMatch'] = '';
  }
  if (query.cpeMatchString !== undefined) {
    params['cpeMatchString'] = query.cpeMatchString;
  }
  if (query.cpeNameId !== undefined) {
    params['cpeNameId'] = query.cpeNameId;
  }
  if (query.matchCriteriaId !== undefined) {
    params['matchCriteriaId'] = query.matchCriteriaId;
  }
  if (query.lastModified !== undefined) {
    params['lastModStartDate'] = toNvdDateParam(query.lastModified.start);
    params['lastModEndDate'] = toNvdDateParam(query.lastModified.end);
  }
  return params;
}

export function buildCpeMatchParams(query: CpeMatchQuery): NvdQueryParams {
  const params: NvdQueryParams = {};
  if (query.cveId !== undefined) {
    params['cveId'] = normalizeCveId(query.cveId);
  }
  if (query.matchCriteriaId !== undefined) {
    params['matchCriteriaId'] = query.matchCriteriaId;
  }
  if (query.matchStringSearch !== undefined) {
    params['matchStringSearch'] = query.matchStringSearch;
  }
  if (query.lastModified !== undefined) {
    params['lastModStartDate'] = toNvdDateParam(query.lastModified.start);
    params['lastModEndDate'] = toNvdDateParam(query.lastModified.end);
  }
  return params;
}

export function withPagination(params: NvdQueryParams, page: NvdPageRequest): NvdQueryParams {
  return {
    ...params,
    startIndex: String(page.startIndex),
    resultsPerPage: String(page.resultsPerPage),
  };
}
