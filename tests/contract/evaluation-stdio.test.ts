import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { describe, expect, it } from 'vitest';

describe('evaluation fixture stdio wrapper', () => {
  it('runs the real server against isolated synthetic data and exits when the client closes', async () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    const client = new Client({ name: 'fixture-smoke', version: '1.0.0' });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL('../../node_modules/tsx/dist/cli.mjs', import.meta.url)),
        fileURLToPath(new URL('../../scripts/evaluation-fixture.ts', import.meta.url))],
      cwd: root, env: { LOG_LEVEL: 'silent' }, stderr: 'pipe',
    });
    try {
      await client.connect(transport);
      expect((await client.listTools()).tools).toHaveLength(10);
      const result = await client.callTool({ name: 'nvd_get_cve_summary', arguments: { cveId: 'CVE-2024-1001' } });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ data: { id: 'CVE-2024-1001', isKnownExploited: true } });
    } finally {
      await client.close();
    }
  });
});
