import { describe, expect, it } from 'vitest';

import { DomainError } from '../../src/domain/errors.js';
import {
  CPE_23_MAX_COMPONENTS,
  assertCpeComponentCount,
  countCpe23Components,
  endOfDayIso,
  isDateOnly,
  splitCpeComponents,
} from '../../src/domain/validation.js';

describe('date-only helpers', () => {
  it('recognises a YYYY-MM-DD bound and rejects anything with a time component', () => {
    expect(isDateOnly('2021-11-03')).toBe(true);
    expect(isDateOnly('  2021-11-03  ')).toBe(true);
    expect(isDateOnly('2021-11-03T00:00:00Z')).toBe(false);
    expect(isDateOnly('2021-11-03T00:00:00.000')).toBe(false);
    expect(isDateOnly('2021-11')).toBe(false);
    expect(isDateOnly('not-a-date')).toBe(false);
  });

  it('builds the end-of-day timestamp used to widen a date-only window end', () => {
    expect(endOfDayIso('2021-11-03')).toBe('2021-11-03T23:59:59.999Z');
    expect(Date.parse(endOfDayIso('2021-11-03')) - Date.parse('2021-11-03T00:00:00.000Z')).toBe(
      86_399_999,
    );
  });
});

describe('CPE component counting', () => {
  it('counts the components of a CPE 2.3 string', () => {
    expect(countCpe23Components('cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*')).toBe(
      CPE_23_MAX_COMPONENTS,
    );
    expect(countCpe23Components('cpe:2.3:a:apache:log4j:*')).toBe(6);
  });

  it('honours escaped colons inside a component', () => {
    // `acme\:corp` is a single component, so this is a 6 component string, not 7.
    expect(countCpe23Components('cpe:2.3:a:acme\\:corp:widget:*')).toBe(6);
    expect(splitCpeComponents('cpe:2.3:a:acme\\:corp:widget:*')).toEqual([
      'cpe',
      '2.3',
      'a',
      'acme:corp',
      'widget',
      '*',
    ]);
  });

  it('returns null for the CPE 2.2 URI binding, which has its own grammar', () => {
    expect(countCpe23Components('cpe:/a:apache:log4j:2.0:rc1')).toBeNull();
  });
});

describe('assertCpeComponentCount', () => {
  it('accepts a full CPE 2.3 criteria string and short patterns', () => {
    expect(() =>
      assertCpeComponentCount('cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*', 'matchStringSearch'),
    ).not.toThrow();
    expect(() =>
      assertCpeComponentCount('cpe:2.3:a:apache:log4j:*', 'cpeMatchString'),
    ).not.toThrow();
    expect(() =>
      assertCpeComponentCount('cpe:/a:apache:log4j:2.0:rc1', 'cpeMatchString'),
    ).not.toThrow();
  });

  it('rejects a string with one component too many, which upstream answers with HTTP 404', () => {
    // A CPE name with a trailing `*` appended to the 13 component form.
    try {
      assertCpeComponentCount('cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*:*', 'matchStringSearch');
      expect.unreachable('a 14 component string must be rejected');
    } catch (error) {
      expect(error).toBeInstanceOf(DomainError);
      const domainError = error as DomainError;
      expect(domainError.code).toBe('INVALID_INPUT');
      expect(domainError.message).toContain('matchStringSearch');
      expect(domainError.message).toContain('14');
      expect(domainError.details).toMatchObject({ components: 14, maxComponents: 13 });
    }
  });
});
