import { describe, expect, it } from 'vitest';

import { DomainError } from '../../src/domain/errors.js';
import {
  canonicalStatusKey,
  cpeComponentsMatch,
  isCpe23Name,
  isValidCpeMatchString,
  isValidCveId,
  isValidUuid,
  isVulnerableCpeMatch,
  normalizeCveId,
  normalizeCveIds,
  normalizeUuid,
  normalizeVulnStatuses,
  requireAtLeastOneFilter,
  resolveDateWindow,
  resolvePageSize,
  toNvdStatusParam,
  validateDateWindow,
} from '../../src/domain/validation.js';

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

const WINDOW_OPTIONS = { maxDays: 120, field: 'published' };

describe('normalizeCveId / isValidCveId', () => {
  it('trims and uppercases the identifier', () => {
    expect(normalizeCveId('  cve-2024-3094  ')).toBe('CVE-2024-3094');
  });

  it('accepts lowercase and padded identifiers', () => {
    expect(isValidCveId('cve-2024-3094')).toBe(true);
    expect(isValidCveId(' CVE-2021-44228 ')).toBe(true);
  });

  it('rejects malformed identifiers', () => {
    for (const value of ['CVE-24-3094', 'CVE-2024-123', 'GHSA-xxxx-yyyy-zzzz', 'CVE-2024-3094x', '', '   ']) {
      expect(isValidCveId(value)).toBe(false);
    }
  });
});

describe('normalizeUuid / isValidUuid', () => {
  it('accepts the 36-character form in any case', () => {
    const lowercase = 'b8f16312-24fa-4bec-b1df-a44c0cf6b36c';
    const uppercase = 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C';

    expect(isValidUuid(lowercase)).toBe(true);
    expect(isValidUuid(uppercase)).toBe(true);
    expect(isValidUuid(`  ${lowercase}  `)).toBe(true);
    expect(normalizeUuid(lowercase)).toBe(uppercase);
  });

  it('rejects truncated and non-hex values', () => {
    for (const value of [
      'b8f16312-24fa-4bec-b1df-a44c0cf6b36',
      'b8f16312-24fa-4bec-b1df-a44c0cf6b36cc',
      'zzzzzzzz-24fa-4bec-b1df-a44c0cf6b36c',
      'b8f16312_24fa_4bec_b1df_a44c0cf6b36c',
      '',
    ]) {
      expect(isValidUuid(value)).toBe(false);
    }
  });
});

describe('CPE match-string validation', () => {
  it('accepts formatted CPE 2.3 names', () => {
    expect(isValidCpeMatchString('cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*')).toBe(true);
    expect(isCpe23Name('cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*')).toBe(true);
    expect(isCpe23Name('  CPE:2.3:a:vendor:product  ')).toBe(true);
  });

  it('accepts URI-binding names for search but not as CPE 2.3 names', () => {
    expect(isValidCpeMatchString('cpe:/a:tukaani:xz:5.6.1')).toBe(true);
    expect(isCpe23Name('cpe:/a:tukaani:xz:5.6.1')).toBe(false);
  });

  it('accepts the legacy CPE 2.2 formatted prefix', () => {
    expect(isValidCpeMatchString('cpe:2.2:a:tukaani:xz:5.6.1')).toBe(true);
    expect(isCpe23Name('cpe:2.2:a:tukaani:xz:5.6.1')).toBe(false);
  });

  it('rejects plain words and unsupported prefixes', () => {
    for (const value of ['tukaani:xz', 'cpe', 'cpe:2.4:a:vendor:product', '', '   ']) {
      expect(isValidCpeMatchString(value)).toBe(false);
      expect(isCpe23Name(value)).toBe(false);
    }
  });
});

describe('normalizeCveIds', () => {
  it('uppercases, reports duplicates and invalid entries and preserves first-seen order', () => {
    const result = normalizeCveIds([
      ' cve-2024-3094 ',
      'CVE-2021-44228',
      'cve-2024-3094',
      'GHSA-xxxx-yyyy-zzzz',
      'CVE-24-3094',
      '   ',
    ]);

    expect(result.ids).toEqual(['CVE-2024-3094', 'CVE-2021-44228']);
    expect(result.duplicates).toEqual(['CVE-2024-3094']);
    expect(result.invalid).toEqual(['GHSA-xxxx-yyyy-zzzz', 'CVE-24-3094', '']);
  });

  it('returns empty buckets for an empty list', () => {
    expect(normalizeCveIds([])).toEqual({ ids: [], duplicates: [], invalid: [] });
  });
});

describe('validateDateWindow', () => {
  it('accepts a window of exactly 120 days', () => {
    const result = validateDateWindow(
      { start: '2024-01-01T00:00:00Z', end: '2024-04-30T00:00:00Z' },
      WINDOW_OPTIONS,
    );

    expect(result.days).toBe(120);
    expect(result.startIso).toBe('2024-01-01T00:00:00.000Z');
    expect(result.endIso).toBe('2024-04-30T00:00:00.000Z');
  });

  it('rejects a window that exceeds 120 days by one millisecond', () => {
    const error = captureDomainError(() =>
      validateDateWindow(
        { start: '2024-01-01T00:00:00.000Z', end: '2024-04-30T00:00:00.001Z' },
        WINDOW_OPTIONS,
      ),
    );

    expect(error.code).toBe('DATE_RANGE_TOO_LARGE');
    expect(error.details).toMatchObject({ field: 'published', maxDays: 120, requestedDays: 121 });
  });

  it('widens a date-only end to the last millisecond of that day', () => {
    // NVD timestamps carry a clock time, so resolving `2024-01-31` to midnight would drop every
    // record published during the day and empty a single-day range.
    expect(
      validateDateWindow({ start: '2024-01-01', end: '2024-01-31' }, WINDOW_OPTIONS),
    ).toMatchObject({ startIso: '2024-01-01T00:00:00.000Z', endIso: '2024-01-31T23:59:59.999Z' });

    expect(
      validateDateWindow({ start: '2024-01-31', end: '2024-01-31' }, WINDOW_OPTIONS).endIso,
    ).toBe('2024-01-31T23:59:59.999Z');
  });

  it('leaves an explicit timestamp end untouched', () => {
    expect(
      validateDateWindow(
        { start: '2024-01-01T00:00:00Z', end: '2024-01-31T12:30:00Z' },
        WINDOW_OPTIONS,
      ).endIso,
    ).toBe('2024-01-31T12:30:00.000Z');
  });

  it('does not let the end-of-day widening push an accepted window past the limit', () => {
    const result = validateDateWindow(
      { start: '2024-01-01', end: '2024-04-30' },
      WINDOW_OPTIONS,
    );

    expect(result.days).toBe(120);
    expect(result.endIso).toBe('2024-04-30T23:59:59.999Z');
  });

  it('rejects an inverted window with INVALID_INPUT', () => {
    const error = captureDomainError(() =>
      validateDateWindow(
        { start: '2024-02-01T00:00:00Z', end: '2024-01-01T00:00:00Z' },
        WINDOW_OPTIONS,
      ),
    );

    expect(error.code).toBe('INVALID_INPUT');
    expect(error.message).toContain('must not be earlier');
  });

  it('rejects unparseable timestamps with INVALID_INPUT', () => {
    for (const value of ['not-a-date', '2024-13-45T00:00:00Z', '']) {
      const badStart = captureDomainError(() =>
        validateDateWindow({ start: value, end: '2024-01-01T00:00:00Z' }, WINDOW_OPTIONS),
      );
      expect(badStart.code).toBe('INVALID_INPUT');

      const badEnd = captureDomainError(() =>
        validateDateWindow({ start: '2024-01-01T00:00:00Z', end: value }, WINDOW_OPTIONS),
      );
      expect(badEnd.code).toBe('INVALID_INPUT');
    }
  });

  it('interprets naive datetimes as UTC regardless of the process timezone', () => {
    const originalTimezone = process.env['TZ'];
    try {
      for (const timezone of ['UTC', 'America/New_York', 'Asia/Tokyo']) {
        process.env['TZ'] = timezone;
        const naive = validateDateWindow(
          { start: '2024-01-01T00:00:00', end: '2024-01-02T00:00:00' },
          WINDOW_OPTIONS,
        );
        const explicit = validateDateWindow(
          { start: '2024-01-01T00:00:00Z', end: '2024-01-02T00:00:00Z' },
          WINDOW_OPTIONS,
        );

        expect(naive.startIso).toBe('2024-01-01T00:00:00.000Z');
        expect(naive.endIso).toBe('2024-01-02T00:00:00.000Z');
        expect(naive).toEqual(explicit);
      }
    } finally {
      if (originalTimezone === undefined) {
        delete process.env['TZ'];
      } else {
        process.env['TZ'] = originalTimezone;
      }
    }
  });
});

describe('resolveDateWindow', () => {
  const NOW = new Date('2026-01-15T12:00:00.000Z');
  const OPTIONS = { now: NOW, maxDays: 120, defaultDays: 7, field: 'published' };

  it('rejects days combined with an explicit range', () => {
    const error = captureDomainError(() =>
      resolveDateWindow(
        { days: 7, start: '2024-01-01T00:00:00Z', end: '2024-01-08T00:00:00Z' },
        OPTIONS,
      ),
    );

    expect(error.code).toBe('INVALID_INPUT');
    expect(error.message).toContain('cannot be combined');
  });

  it('rejects a start or end that is not paired with its counterpart', () => {
    for (const input of [
      { start: '2024-01-01T00:00:00Z' },
      { end: '2024-01-08T00:00:00Z' },
    ]) {
      const error = captureDomainError(() => resolveDateWindow(input, OPTIONS));
      expect(error.code).toBe('INVALID_INPUT');
    }
  });

  it('defaults to the trailing 7-day window ending at now', () => {
    const result = resolveDateWindow({}, OPTIONS);

    expect(result).toEqual({
      startIso: '2026-01-08T12:00:00.000Z',
      endIso: '2026-01-15T12:00:00.000Z',
      days: 7,
    });
  });

  it('accepts an explicit positive days value', () => {
    const result = resolveDateWindow({ days: 30 }, OPTIONS);

    expect(result.days).toBe(30);
    expect(result.startIso).toBe('2025-12-16T12:00:00.000Z');
    expect(result.endIso).toBe('2026-01-15T12:00:00.000Z');
  });

  it('rejects zero and negative day counts with INVALID_INPUT', () => {
    for (const days of [0, -1]) {
      const error = captureDomainError(() => resolveDateWindow({ days }, OPTIONS));
      expect(error.code).toBe('INVALID_INPUT');
    }
  });

  it('rejects a days value above the maximum with DATE_RANGE_TOO_LARGE', () => {
    const error = captureDomainError(() => resolveDateWindow({ days: 121 }, OPTIONS));

    expect(error.code).toBe('DATE_RANGE_TOO_LARGE');
    expect(error.details).toMatchObject({ maxDays: 120, requestedDays: 121 });
  });
});

describe('resolvePageSize', () => {
  const LIMITS = { default: 20, max: 50 };

  it('returns the default when no value is requested', () => {
    expect(resolvePageSize(undefined, LIMITS, 'pageSize')).toBe(20);
  });

  it('accepts a value within bounds', () => {
    expect(resolvePageSize(1, LIMITS, 'pageSize')).toBe(1);
    expect(resolvePageSize(50, LIMITS, 'pageSize')).toBe(50);
  });

  it('rejects zero, negative, fractional and above-max values with INVALID_INPUT', () => {
    for (const value of [0, -1, 1.5, 51, Number.NaN]) {
      const error = captureDomainError(() => resolvePageSize(value, LIMITS, 'pageSize'));
      expect(error.code).toBe('INVALID_INPUT');
    }
  });
});

describe('requireAtLeastOneFilter', () => {
  it('throws when every filter is undefined or false', () => {
    const error = captureDomainError(() =>
      requireAtLeastOneFilter(
        { keyword: undefined, cveIds: undefined, kevOnly: false },
        'At least one filter is required',
      ),
    );

    expect(error.code).toBe('INVALID_INPUT');
    expect(error.message).toBe('At least one filter is required');
  });

  it('throws for an empty filter record', () => {
    const error = captureDomainError(() => requireAtLeastOneFilter({}, 'At least one filter is required'));
    expect(error.code).toBe('INVALID_INPUT');
  });

  it('passes when at least one filter is set', () => {
    expect(() => requireAtLeastOneFilter({ keyword: 'log4j', kevOnly: false }, 'msg')).not.toThrow();
    expect(() => requireAtLeastOneFilter({ keyword: undefined, kevOnly: true }, 'msg')).not.toThrow();
  });
});

describe('cpeComponentsMatch', () => {
  const concrete = 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*';
  const wildcard = 'cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*';

  it('treats a * component as a wildcard on either side', () => {
    expect(cpeComponentsMatch(concrete, wildcard)).toBe(true);
    expect(cpeComponentsMatch(wildcard, concrete)).toBe(true);
    expect(cpeComponentsMatch(wildcard, wildcard)).toBe(true);
  });

  it('matches a - component only against another -', () => {
    const productWithDash = 'cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*';

    expect(cpeComponentsMatch(productWithDash, productWithDash)).toBe(true);
    expect(cpeComponentsMatch(productWithDash, 'cpe:2.3:a:vendor:product:na:*:*:*:*:*:*:*')).toBe(false);
    expect(cpeComponentsMatch(concrete, productWithDash)).toBe(false);
  });

  it('honours escaped colons when comparing components', () => {
    const escaped = 'cpe:2.3:a:vendor:prod\\:name:1.0:*:*:*:*:*:*:*';

    expect(cpeComponentsMatch(escaped, escaped)).toBe(true);
    expect(cpeComponentsMatch(escaped, 'cpe:2.3:a:vendor:prodname:1.0:*:*:*:*:*:*:*')).toBe(false);
    // Unescaped colons split the value into a different number of components.
    expect(
      cpeComponentsMatch('cpe:2.3:a:vendor:prod:name:1.0:*:*:*:*:*:*:*', escaped),
    ).toBe(false);
  });

  it('never matches values with different component counts', () => {
    expect(cpeComponentsMatch('cpe:2.3:a:tukaani', wildcard)).toBe(false);
  });

  it('compares components case-insensitively', () => {
    expect(cpeComponentsMatch('CPE:2.3:A:Tukaani:XZ:5.6.1:*:*:*:*:*:*:*', wildcard)).toBe(true);
  });

  it('is exposed through isVulnerableCpeMatch', () => {
    expect(isVulnerableCpeMatch(concrete, wildcard)).toBe(true);
    expect(isVulnerableCpeMatch('cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*', wildcard)).toBe(false);
  });
});

describe('vulnerability status canonicalization', () => {
  it('maps both request and response spellings onto the camel-case request form', () => {
    expect(toNvdStatusParam('Undergoing Analysis')).toBe('UndergoingAnalysis');
    expect(toNvdStatusParam('UndergoingAnalysis')).toBe('UndergoingAnalysis');
    expect(toNvdStatusParam('undergoing_analysis')).toBe('UndergoingAnalysis');
    expect(toNvdStatusParam('Awaiting Analysis')).toBe('AwaitingAnalysis');
    expect(toNvdStatusParam(' analyzed ')).toBe('Analyzed');
    expect(toNvdStatusParam('Modified')).toBe('Modified');
    expect(toNvdStatusParam('Deferred')).toBe('Deferred');
    expect(toNvdStatusParam('Rejected')).toBe('Rejected');
    expect(toNvdStatusParam('Received')).toBe('Received');
  });

  it('forwards unknown statuses with whitespace removed', () => {
    expect(toNvdStatusParam('Brand New Status')).toBe('BrandNewStatus');
  });

  it('exposes a canonical comparison key', () => {
    expect(canonicalStatusKey('Undergoing Analysis')).toBe('undergoinganalysis');
    expect(canonicalStatusKey('UndergoingAnalysis')).toBe('undergoinganalysis');
    expect(canonicalStatusKey('Undergoing Analysis')).toBe(canonicalStatusKey('undergoinganalysis'));
  });

  it('normalizes, de-duplicates and keeps the caller order', () => {
    expect(
      normalizeVulnStatuses([
        'Undergoing Analysis',
        'undergoinganalysis',
        'Analyzed',
        '  ',
        'Modified',
        'Analyzed',
      ]),
    ).toEqual(['UndergoingAnalysis', 'Analyzed', 'Modified']);
  });

  it('returns an empty list when no usable status is supplied', () => {
    expect(normalizeVulnStatuses(['', '   '])).toEqual([]);
  });
});
