import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

import { cveItem, cveResponse } from '../helpers/fixtures.js';
import { NvdMockServer } from '../helpers/nvd-mock-server.js';
import { createTempDir, type TempDir } from '../helpers/temp.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const serverEntry = path.join(projectRoot, 'dist', 'main.js');

type JsonRpcMessage = { id?: number; result?: unknown; error?: unknown; method?: string };

type Session = {
  child: ChildProcessWithoutNullStreams;
  stdoutLines: string[];
  stderr(): string;
  exited: Promise<number | null>;
  send(payload: unknown): void;
  waitForId(id: number, timeoutMs?: number): Promise<JsonRpcMessage>;
  initialize(): Promise<void>;
};

function startSession(env: NodeJS.ProcessEnv): Session {
  const child = spawn(process.execPath, [serverEntry], {
    cwd: projectRoot,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  }) as ChildProcessWithoutNullStreams;

  const stdoutLines: string[] = [];
  let stderrText = '';
  let buffered = '';
  const messages: JsonRpcMessage[] = [];

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
          // Left in `stdoutLines` so the assertion can report a polluted stdout.
        }
      }
      newlineIndex = buffered.indexOf('\n');
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderrText += chunk;
  });

  const exited = new Promise<number | null>((resolve) => {
    child.on('exit', (code) => resolve(code));
  });

  const send = (payload: unknown): void => {
    child.stdin.write(`${JSON.stringify(payload)}\n`);
  };

  const waitForId = async (id: number, timeoutMs = 15_000): Promise<JsonRpcMessage> => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const found = messages.find((message) => message.id === id);
      if (found !== undefined) {
        return found;
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error(`Timed out waiting for JSON-RPC response ${id}. stderr: ${stderrText}`);
  };

  return {
    child,
    stdoutLines,
    stderr: () => stderrText,
    exited,
    send,
    waitForId,
    initialize: async () => {
      send({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'shutdown-test', version: '0.0.1' },
        },
      });
      await waitForId(1);
      send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    },
  };
}

function baseEnv(nvd: NvdMockServer, sqlitePath: string, cacheDirectory: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NODE_ENV: 'test',
    LOG_LEVEL: 'debug',
    NVD_BASE_URL: nvd.baseUrl,
    NVD_MIN_INTERVAL_MS: '5',
    NVD_MAX_RETRIES: '0',
    NVD_REQUEST_TIMEOUT_MS: '20000',
    SQLITE_PATH: sqlitePath,
    CACHE_DIRECTORY: cacheDirectory,
    CURSOR_SECRET: 'test-cursor-secret-0123456789abcdef',
  };
}

function integrity(sqlitePath: string): string {
  const probe = new DatabaseSync(sqlitePath, { readOnly: true });
  try {
    const row = probe.prepare('PRAGMA integrity_check').get() as
      | { integrity_check: string }
      | undefined;
    return row?.integrity_check ?? 'unknown';
  } finally {
    probe.close();
  }
}

describe('MCP contract: graceful shutdown and restart', () => {
  let nvd: NvdMockServer;
  let temp: TempDir;

  beforeAll(async () => {
    if (!existsSync(serverEntry)) {
      throw new Error(`Missing ${serverEntry}. Run "npm run build" before the contract tests.`);
    }
    nvd = await NvdMockServer.start();
    temp = createTempDir('nvd-mcp-shutdown-');
  });

  afterAll(async () => {
    await nvd.stop();
    temp.cleanup();
  });

  it('exits promptly on SIGTERM while an upstream request is in flight', async () => {
    // The upstream never answers within the test, so the request is still running when the signal lands.
    nvd.reset();
    nvd.on('/cves/2.0', () => ({ status: 200, body: cveResponse([cveItem()]), delayMs: 8_000 }));

    const sqlitePath = temp.child('sigterm.sqlite');
    const cacheDirectory = temp.child('sigterm-cache');
    const session = startSession(baseEnv(nvd, sqlitePath, cacheDirectory));
    await session.initialize();
    session.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'get_cve', arguments: { cveId: 'CVE-2024-3094' } },
    });
    await new Promise((resolve) => setTimeout(resolve, 400));

    const signalAt = Date.now();
    session.child.kill('SIGTERM');
    const exitCode = await session.exited;
    const shutdownMs = Date.now() - signalAt;

    expect(shutdownMs).toBeLessThan(5_000);
    expect(exitCode).toBe(0);
    expect(session.stderr()).toContain('server_stopping');
    expect(session.stderr()).toMatch(/"reason":"SIGTERM"/);
    // stdout stayed a pure JSON-RPC stream even while shutting down.
    for (const line of session.stdoutLines) {
      expect(() => JSON.parse(line) as unknown).not.toThrow();
    }
    expect(integrity(sqlitePath)).toBe('ok');
  });

  it('exits promptly on SIGINT and a broken pipe, then restarts cleanly on the same files', async () => {
    nvd.reset();
    nvd.on('/cves/2.0', () => ({ status: 200, body: cveResponse([cveItem({ id: 'CVE-2024-3094' })]), delayMs: 8_000 }));

    const sqlitePath = temp.child('sigint.sqlite');
    const cacheDirectory = temp.child('sigint-cache');

    // 1. SIGINT during a request.
    const first = startSession(baseEnv(nvd, sqlitePath, cacheDirectory));
    await first.initialize();
    first.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'get_cve', arguments: { cveId: 'CVE-2024-3094' } },
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const signalAt = Date.now();
    first.child.kill('SIGINT');
    expect(await first.exited).toBe(0);
    expect(Date.now() - signalAt).toBeLessThan(5_000);
    expect(first.stderr()).toMatch(/"reason":"SIGINT"/);

    // 2. Client disconnects (stdout closed) while a request is running.
    const second = startSession(baseEnv(nvd, sqlitePath, cacheDirectory));
    await second.initialize();
    second.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'get_cve', arguments: { cveId: 'CVE-2024-3094' } },
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const pipeAt = Date.now();
    second.child.stdin.end();
    expect(await second.exited).toBe(0);
    expect(Date.now() - pipeAt).toBeLessThan(5_000);
    expect(second.stderr()).toMatch(/"reason":"stdin_closed"/);

    // 3. Restart on the same database and cache: the server answers normally.
    nvd.reset();
    nvd.on('/cves/2.0', () => ({
      status: 200,
      body: cveResponse([cveItem({ id: 'CVE-2024-3094' })]),
    }));
    const third = startSession(baseEnv(nvd, sqlitePath, cacheDirectory));
    await third.initialize();
    third.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'get_cve', arguments: { cveId: 'CVE-2024-3094' } },
    });
    const response = await third.waitForId(2, 20_000);
    expect(response.error).toBeUndefined();
    expect(JSON.stringify(response.result)).toContain('CVE-2024-3094');
    third.child.kill('SIGTERM');
    expect(await third.exited).toBe(0);
    expect(integrity(sqlitePath)).toBe('ok');
  });

  it('recovers a database that was killed with SIGKILL mid-write', async () => {
    nvd.reset();
    nvd.on('/cves/2.0', () => ({
      status: 200,
      body: cveResponse([cveItem({ id: 'CVE-2024-3094' })]),
      delayMs: 5_000,
    }));

    const sqlitePath = temp.child('sigkill.sqlite');
    const cacheDirectory = temp.child('sigkill-cache');
    const session = startSession(baseEnv(nvd, sqlitePath, cacheDirectory));
    await session.initialize();
    session.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'get_cve', arguments: { cveId: 'CVE-2024-3094' } },
    });
    await new Promise((resolve) => setTimeout(resolve, 400));
    session.child.kill('SIGKILL');
    await session.exited;

    // WAL recovery must leave a usable, consistent database.
    expect(integrity(sqlitePath)).toBe('ok');

    nvd.reset();
    nvd.on('/cves/2.0', () => ({
      status: 200,
      body: cveResponse([cveItem({ id: 'CVE-2024-3094' })]),
    }));
    const restarted = startSession(baseEnv(nvd, sqlitePath, cacheDirectory));
    await restarted.initialize();
    restarted.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'get_cve', arguments: { cveId: 'CVE-2024-3094' } },
    });
    const response = await restarted.waitForId(2, 20_000);
    expect(JSON.stringify(response.result)).toContain('CVE-2024-3094');
    restarted.child.kill('SIGTERM');
    expect(await restarted.exited).toBe(0);
  });
});