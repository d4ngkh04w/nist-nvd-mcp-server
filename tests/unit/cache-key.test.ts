import { describe, expect, it } from 'vitest';

import {
  buildEntityIdentity,
  buildQueryIdentity,
} from '../../src/infrastructure/cache/cache-key.js';

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;

describe('buildQueryIdentity', () => {
  it('produces the same hash for a logically identical query regardless of key order', () => {
    const first = buildQueryIdentity('cves', {
      keyword: 'log4j',
      severity: 'HIGH',
      nested: { b: 2, a: 1 },
    });
    const second = buildQueryIdentity('cves', {
      nested: { a: 1, b: 2 },
      severity: 'HIGH',
      keyword: 'log4j',
    });

    expect(first.queryHash).toBe(second.queryHash);
    expect(first.queryHash).toMatch(SHA256_PATTERN);
    expect(first.cacheKey).toBe(first.queryHash);
    expect(second.cacheKey).toBe(second.queryHash);
  });

  it('changes the hash when pageSize is added or changed', () => {
    const query = { keyword: 'log4j' };
    const withoutPageSize = buildQueryIdentity('cves', query);
    const withTwenty = buildQueryIdentity('cves', query, 20);
    const withFifty = buildQueryIdentity('cves', query, 50);

    expect(withTwenty.queryHash).not.toBe(withoutPageSize.queryHash);
    expect(withFifty.queryHash).not.toBe(withTwenty.queryHash);
  });

  it('changes the hash when the resource changes', () => {
    const query = { keyword: 'apache' };

    expect(buildQueryIdentity('cves', query).queryHash).not.toBe(
      buildQueryIdentity('cpes', query).queryHash,
    );
  });

  it('is stable across calls with the same input', () => {
    const query = { keyword: 'log4j', vulnStatuses: ['Analyzed', 'Modified'] };

    expect(buildQueryIdentity('cves', query).queryHash).toBe(
      buildQueryIdentity('cves', query).queryHash,
    );
  });
});

describe('buildEntityIdentity', () => {
  it('differs from the equivalent query identity', () => {
    const entity = buildEntityIdentity('cve', 'CVE-2024-3094');
    const query = buildQueryIdentity('cve', { cveId: 'CVE-2024-3094' });

    expect(entity.queryHash).not.toBe(query.queryHash);
    expect(entity.queryHash).toMatch(SHA256_PATTERN);
    expect(entity.cacheKey).toBe(entity.queryHash);
  });

  it('differs per identifier', () => {
    expect(buildEntityIdentity('cve', 'CVE-2024-3094').queryHash).not.toBe(
      buildEntityIdentity('cve', 'CVE-2021-44228').queryHash,
    );
  });
});
