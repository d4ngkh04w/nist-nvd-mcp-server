import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { NvdMockServer } from '../helpers/nvd-mock-server.js';
import { createTempDir, type TempDir } from '../helpers/temp.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const serverEntry = path.join(projectRoot, 'dist', 'main.js');
const API_KEY = '[REDACTED:auth_header]';

type JsonRpcMessage = {
  jsonrpc?: string;
  id?: number;
  result?: unknown;
  error?: unknown;
  method?: string;
};

type StdioSessionResult = {
  stdout: string[];
  stderr: string;
  exitCode: number | null;
  messages: JsonRpcMessage[];
};

/** Runs a real stdio session against `dist/main.js` and captures the raw streams. */
async function runStdioSession(
  env: NodeJS.ProcessEnv,
  options: { callTool: boolean },
): Promise<StdioSessionResult> {
  const child = spawn(process.execPath, [serverEntry], {
    cwd: projectRoot,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const stdoutLines: string[] = [];
  const messages: JsonRpcMessage[] = [];
  let stderr = '';
  let buffered = '';

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk: string) => {
    buffered += chunk;
    let newlineIndex = buffered.indexOf('\n');
    while (newlineIndex >= 0) {
      const line = buffered.slice(0, newlineIndex);
      buffered = buffered.slice(newlineIndex + 1);
      if (line.trim().length > 0) {
        stdoutLines.push(line);
        try {
          messages.push(JSON.parse(line) as JsonRpcMessage);
        } catch {
          // Left in `stdoutLines` so the purity assertion can report it.
        }
      }
      newlineIndex = buffered.indexOf('\n');
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });

  const exited = new Promise<number | null>((resolve) => {
    child.on('exit', (code) => resolve(code));
  });

  const waitForId = async (id: number, timeoutMs = 15_000): Promise<JsonRpcMessage> => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const found = messages.find((message) => message.id === id);
      if (found !== undefined) {
        return found;
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error(`Timed out waiting for JSON-RPC response ${id}. stderr: ${stderr}`);
  };

  const send = (payload: unknown): void => {
    child.stdin.write(`${JSON.stringify(payload)}\n`);
  };

  send({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'stdout-purity-test', version: '0.0.1' },
    },
  });
  await waitForId(1);

  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  await waitForId(2);

  if (options.callTool) {
    send({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'nvd_get_cve', arguments: { cveId: 'CVE-2024-3094' } },
    });
    await waitForId(3);
  }

  child.stdin.end();
  const exitCode = await exited;

  return { stdout: stdoutLines, stderr, exitCode, messages };
}

describe('MCP contract: stdio framing and stdout purity', () => {
  let nvd: NvdMockServer;
  let temp: TempDir;

  beforeAll(async () => {
    if (!existsSync(serverEntry)) {
      throw new Error(`Missing ${serverEntry}. Run "npm run build" before the contract tests.`);
    }
    nvd = await NvdMockServer.start();
    temp = createTempDir('nvd-mcp-stdio-');
  });

  afterAll(async () => {
    await nvd.stop();
    temp.cleanup();
  });

  it('writes only JSON-RPC frames to stdout and logs to stderr', async () => {
    nvd.reset();
    nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()], { totalResults: 1 }) });

    const session = await runStdioSession(
      {
        ...process.env,
        NODE_ENV: 'test',
        LOG_LEVEL: 'debug',
        NVD_API_KEY: API_KEY,
        NVD_BASE_URL: nvd.baseUrl,
        NVD_MIN_INTERVAL_MS: '5',
        NVD_MAX_RETRIES: '0',
        NVD_REQUEST_TIMEOUT_MS: '2_000'.replace('_', ''),
        SQLITE_PATH: temp.child('nvd.sqlite'),
        CACHE_DIRECTORY: temp.child('cache'),
        CURSOR_SECRET: 'test-cursor-secret-0123456789abcdef',
      },
      { callTool: true },
    );

    // 1. Every stdout line is a JSON-RPC 2.0 frame.
    expect(session.stdout.length).toBeGreaterThanOrEqual(3);
    for (const line of session.stdout) {
      const parsed = JSON.parse(line) as JsonRpcMessage;
      expect(parsed.jsonrpc).toBe('2.0');
      expect(parsed.method).toBeUndefined();
    }
    expect(session.stdout.join('\n')).not.toContain('"level"');
    expect(session.stdout.join('\n')).not.toContain('server_started');

    // 2. The handshake, tools/list and tools/call all answered.
    const initialize = session.messages.find((message) => message.id === 1);
    const listResult = session.messages.find((message) => message.id === 2)?.result as
      | { tools?: Array<{ name: string }> }
      | undefined;
    const callResult = session.messages.find((message) => message.id === 3)?.result as
      | { isError?: boolean; structuredContent?: Record<string, unknown> }
      | undefined;

    expect(initialize?.result).toBeDefined();
    expect(listResult?.tools).toHaveLength(10);
    expect(listResult?.tools?.map((tool) => tool.name)).toContain('nvd_get_cve');
    expect(callResult?.isError ?? false).toBe(false);
    expect((callResult?.structuredContent?.['data'] as { id?: string } | undefined)?.id).toBe(
      'CVE-2024-3094',
    );

    // 3. Diagnostics land on stderr only, and the API key never appears anywhere.
    expect(session.stderr).toContain('server_started');
    expect(session.stderr).toContain('tool_call');
    expect(session.stderr).not.toContain(API_KEY);
    expect(session.stdout.join('\n')).not.toContain(API_KEY);

    // 4. Closing stdin shuts the server down cleanly.
    expect(session.exitCode).toBe(0);
  }, 40_000);

  it('keeps stdout clean when the client sends an unknown method', async () => {
    nvd.reset();
    nvd.on('/cves/2.0', { status: 200, body: cveResponse([cveItem()]) });

    const session = await runStdioSession(
      {
        ...process.env,
        NODE_ENV: 'test',
        LOG_LEVEL: 'info',
        NVD_BASE_URL: nvd.baseUrl,
        NVD_MIN_INTERVAL_MS: '5',
        SQLITE_PATH: temp.child('nvd-2.sqlite'),
        CACHE_DIRECTORY: temp.child('cache-2'),
        CURSOR_SECRET: 'test-cursor-secret-0123456789abcdef',
      },
      { callTool: false },
    );

    for (const line of session.stdout) {
      const parsed = JSON.parse(line) as JsonRpcMessage;
      expect(parsed.jsonrpc).toBe('2.0');
    }
    expect(session.exitCode).toBe(0);
  }, 40_000);
});
