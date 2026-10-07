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

describe('MCP request and output budgets', () => {
  it('provides bounded defaults and accepts explicit overrides', () => {
    expect(loadConfig({}).mcp).toEqual({ toolTimeoutMs: 120_000, maxOutputBytes: 1_000_000 });
    expect(loadConfig({ MCP_TOOL_TIMEOUT_MS: '500', MCP_MAX_OUTPUT_BYTES: '2048' }).mcp)
      .toEqual({ toolTimeoutMs: 500, maxOutputBytes: 2_048 });
  });
  it.each([
    { MCP_TOOL_TIMEOUT_MS: '0' }, { MCP_TOOL_TIMEOUT_MS: '3600001' },
    { MCP_MAX_OUTPUT_BYTES: '1023' }, { MCP_MAX_OUTPUT_BYTES: '16000001' },
    { MCP_MAX_OUTPUT_BYTES: '1024.5' },
  ])('rejects invalid budgets: %j', env => {
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });
});
