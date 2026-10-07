import { describe, expect, it } from 'vitest';

import { buildSuccessResult } from '../../src/mcp/output.js';

describe('MCP output budget', () => {
  it('preserves complete output at the exact UTF-8 byte limit', () => {
    const payload = { data: '🙂' };
    const text = JSON.stringify(payload);
    const result = buildSuccessResult(payload, Buffer.byteLength(text));
    expect(result.structuredContent).toEqual(payload);
    expect(result.content).toEqual([{ type: 'text', text }]);
  });

  it('rejects oversized output without returning truncated success or echoing data', () => {
    const payload = { data: '🙂'.repeat(100) };
    try {
      buildSuccessResult(payload, 100);
      expect.fail('oversized output was accepted');
    } catch (error) {
      expect(error).toMatchObject({ code: 'RESPONSE_TOO_LARGE', retryable: false });
      expect(String(error)).toMatch(/fields|pageSize/);
      expect(String(error)).not.toContain('🙂');
    }
  });
});
