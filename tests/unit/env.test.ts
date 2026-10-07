import { describe, expect, it } from 'vitest';

import { ConfigError, loadConfig } from '../../src/config/env.js';

describe('loadConfig NVD transport security', () => {
  it('rejects a plaintext HTTP upstream URL outside loopback', () => {
    expect(() => loadConfig({ NVD_BASE_URL: 'http://nvd.example.test/rest/json' })).toThrow(ConfigError);
    expect(() => loadConfig({ NVD_BASE_URL: 'http://nvd.example.test/rest/json' })).toThrow(/must use HTTPS/);
  });

  it('accepts the default HTTPS NVD endpoint, HTTPS overrides and local HTTP test servers', () => {
    expect(loadConfig({}).nvdBaseUrl).toBe('https://services.nvd.nist.gov/rest/json');
    expect(
      loadConfig({ NVD_BASE_URL: 'https://nvd.example.test/rest/json' }).nvdBaseUrl,
    ).toBe('https://nvd.example.test/rest/json');
    expect(loadConfig({ NVD_BASE_URL: 'http://127.0.0.1:8080/rest/json' }).nvdBaseUrl).toBe(
      'http://127.0.0.1:8080/rest/json',
    );
  });
});

describe('stale cache retention configuration', () => {
  it('defaults to seven days and allows explicit zero retention', () => {
    expect(loadConfig({}).cache.staleRetentionMs).toBe(7 * 86_400_000);
    expect(loadConfig({ CACHE_STALE_RETENTION_SECONDS: '0' }).cache.staleRetentionMs).toBe(0);
    expect(loadConfig({ CACHE_STALE_RETENTION_SECONDS: '60' }).cache.staleRetentionMs).toBe(60_000);
  });

  it('rejects negative and non-integer retention', () => {
    expect(() => loadConfig({ CACHE_STALE_RETENTION_SECONDS: '-1' })).toThrow(ConfigError);
    expect(() => loadConfig({ CACHE_STALE_RETENTION_SECONDS: '0.5' })).toThrow(ConfigError);
  });
});
