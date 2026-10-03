import { describe, expect, it } from 'vitest';

import {
  CPE_MATCH_FIELDS,
  CPE_RECORD_FIELDS,
  CVE_CHANGE_EVENT_FIELDS,
  CVE_DETAILS_FIELDS,
  CVE_SUMMARY_FIELDS,
  projectFieldList,
  projectFields,
  resolveFields,
} from '../../src/domain/field-projection.js';
import { DomainError } from '../../src/domain/errors.js';

describe('field projection', () => {
  it('returns undefined (no projection) when the caller omits `fields`', () => {
    expect(resolveFields(undefined, CVE_SUMMARY_FIELDS, 'nvd_get_cve_summary')).toBeUndefined();
  });

  it('keeps the requested order and removes duplicates and surrounding blanks', () => {
    const resolved = resolveFields(
      [' primaryCvss ', 'id', 'primaryCvss', 'isKnownExploited'],
      CVE_SUMMARY_FIELDS,
      'nvd_get_cve_summary',
    );
    expect(resolved).toEqual(['primaryCvss', 'id', 'isKnownExploited']);
  });

  it('rejects an empty list with a message that points at the default', () => {
    try {
      resolveFields([], CVE_SUMMARY_FIELDS, 'nvd_get_cve_summary');
      expect.unreachable('an empty fields list must be rejected');
    } catch (error) {
      expect(error).toBeInstanceOf(DomainError);
      expect((error as DomainError).code).toBe('INVALID_INPUT');
      expect((error as DomainError).message).toContain('omit the parameter');
    }
  });

  it('rejects an unknown field and lists the supported ones', () => {
    try {
      resolveFields(['id', 'title'], CVE_SUMMARY_FIELDS, 'nvd_get_cve_summary');
      expect.unreachable('an unknown field must be rejected');
    } catch (error) {
      expect((error as DomainError).code).toBe('INVALID_INPUT');
      expect((error as DomainError).message).toContain('title');
      expect((error as DomainError).message).toContain('kevDateAdded');
      expect((error as DomainError).details).toMatchObject({ unsupported: ['title'] });
    }
  });

  it('rejects a field that belongs to a different tool', () => {
    // `matchCriteriaId` is a CPE match field, so a CVE allowlist must not accept it.
    expect(() =>
      resolveFields(['id', 'matchCriteriaId'], CVE_SUMMARY_FIELDS, 'nvd_get_cves'),
    ).toThrow(/unsupported field/);
  });

  it('separates a filter parameter from a returnable field in the rejection message', () => {
    // `cveId` filters nvd_search_cpe_matches but is not a field of the returned criteria.
    expect(() =>
      resolveFields(['cveId'], CPE_MATCH_FIELDS, 'nvd_search_cpe_matches'),
    ).toThrow(/not filter parameters/);
  });

  it('projectFields returns the value untouched when no projection is requested', () => {
    const record = { id: 'CVE-2021-44228', summary: 'log4shell' };
    expect(projectFields(record, undefined)).toBe(record);
  });

  it('projectFields keeps only the requested keys that the record carries', () => {
    const record = {
      id: 'CVE-2021-44228',
      primaryCvss: { version: '3.1', score: 10 },
      isKnownExploited: true,
    };
    expect(projectFields(record, ['id', 'primaryCvss'])).toEqual({
      id: 'CVE-2021-44228',
      primaryCvss: { version: '3.1', score: 10 },
    });
  });

  it('projectFields omits a requested key the record does not carry instead of inventing null', () => {
    const record = { id: 'CVE-2024-0001' };
    const projected = projectFields(record, ['id', 'kevDateAdded']);
    expect(projected).toEqual({ id: 'CVE-2024-0001' });
    expect(Object.prototype.hasOwnProperty.call(projected, 'kevDateAdded')).toBe(false);
    expect(JSON.stringify(projected)).not.toContain('null');
  });

  it('projectFieldList projects every element and copies the array without a projection', () => {
    const items = [
      { id: 'CVE-2024-0001', summary: 'a' },
      { id: 'CVE-2024-0002', summary: 'b' },
    ];
    expect(projectFieldList(items, ['id'])).toEqual([
      { id: 'CVE-2024-0001' },
      { id: 'CVE-2024-0002' },
    ]);
    const untouched = projectFieldList(items, undefined);
    expect(untouched).toEqual(items);
    expect(untouched).not.toBe(items);
  });

  it('exposes an allowlist that covers every published output key of its item schema', () => {
    expect(CVE_SUMMARY_FIELDS).toContain('kevDateAdded');
    expect(CVE_SUMMARY_FIELDS).toContain('affectedProducts');
    expect(CVE_DETAILS_FIELDS).toContain('configurations');
    expect(CVE_DETAILS_FIELDS).toContain('references');
    expect(CVE_DETAILS_FIELDS).toContain('raw');
    expect(CVE_DETAILS_FIELDS).toContain('kev');
    expect(CVE_CHANGE_EVENT_FIELDS).toContain('eventName');
    expect(CVE_CHANGE_EVENT_FIELDS).toContain('details');
    expect(CPE_MATCH_FIELDS).toContain('matches');
    expect(CPE_MATCH_FIELDS).toContain('matchCriteriaId');
    expect(CPE_RECORD_FIELDS).toContain('cpeNameId');
    expect(CPE_RECORD_FIELDS).toContain('titles');
    expect(CPE_RECORD_FIELDS).toContain('deprecates');

    // A CPE dictionary key must not be accepted where a match criterion is expected, and the reverse
    // holds too, since both UUIDs have the same shape.
    expect(CPE_RECORD_FIELDS).not.toContain('matchCriteriaId');
    expect(CPE_MATCH_FIELDS).not.toContain('cpeNameId');

    // No duplicates inside an allowlist (they would make the parameter description misleading).
    for (const list of [
      CVE_SUMMARY_FIELDS,
      CVE_DETAILS_FIELDS,
      CVE_CHANGE_EVENT_FIELDS,
      CPE_MATCH_FIELDS,
      CPE_RECORD_FIELDS,
    ]) {
      expect(new Set(list).size).toBe(list.length);
    }
  });
});
