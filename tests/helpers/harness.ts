import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { createApp, type App } from '../../src/app.js';
import { loadConfig, type AppConfig } from '../../src/config/env.js';
import type { Clock } from '../../src/domain/ports.js';
import { Logger } from '../../src/shared/logger.js';
import { NvdMockServer } from './nvd-mock-server.js';
import { createTempDir, type TempDir } from './temp.js';

export type MutableClock = Clock & {
  set(iso: string): void;
  advanceMs(ms: number): void;
};

export function createMutableClock(startIso = '2026-01-15T12:00:00.000Z'): MutableClock {
  let current = new Date(startIso);
  return {
    now: () => new Date(current),
    set: (iso: string) => {
      current = new Date(iso);
    },
    advanceMs: (ms: number) => {
      current = new Date(current.getTime() + ms);
    },
  };
}

export type ToolCallOutcome = {
  isError: boolean;
  structuredContent: Record<string, unknown> | undefined;
  /** Parsed `ToolError` payload when the call failed. */
  error: Record<string, unknown> | undefined;
  text: string;
};

export type HarnessOptions = {
  nvd?: NvdMockServer;
  clock?: MutableClock;
  /** When set, requests must carry it in the `apiKey` header (and never in the URL). */
  apiKey?: string;
  nvdOverrides?: Partial<AppConfig['nvd']>;
  ttlSeconds?: Partial<AppConfig['ttlSeconds']>;
  limits?: Partial<AppConfig['limits']>;
  cache?: Partial<AppConfig['cache']>;
  /** Overrides for the temporary SQLite database (lock/latency drills). */
  storage?: Partial<Pick<AppConfig['storage'], 'sqliteBusyTimeoutMs' | 'sqlitePath'>>;
  /** Keeps the temporary directory on `close()` so a restart test can reuse the files. */
  keepTemp?: boolean;
  /** Set to false to build the app without an MCP client (raw service tests). */
  withClient?: boolean;
};

export type Harness = {
  app: App;
  config: AppConfig;
  clock: MutableClock;
  nvd: NvdMockServer;
  temp: TempDir;
  client: Client | null;
  /** All log lines written by the server (JSON strings), useful for log assertions. */
  logs: string[];
  callTool(name: string, args?: Record<string, unknown>): Promise<ToolCallOutcome>;
  close(): Promise<void>;
};

const FAST_NVD_SETTINGS: AppConfig['nvd'] = {
  minIntervalMs: 5,
  maxConcurrency: 1,
  requestTimeoutMs: 300,
  maxRetries: 2,
  retryBaseDelayMs: 1,
};

/**
 * Boots a full application instance (SQLite + disk cache + mock NVD) inside a temporary directory
 * and connects an in-memory MCP client so contract-level behaviour can be exercised in-process.
 */
export async function createHarness(options: HarnessOptions = {}): Promise<Harness> {
  const temp = createTempDir();
  const ownsMockServer = options.nvd === undefined;
  const nvd = options.nvd ?? (await NvdMockServer.start());
  const clock = options.clock ?? createMutableClock();
  const defaults = loadConfig({} as NodeJS.ProcessEnv);

  const config: AppConfig = {
    ...defaults,
    nvdApiKey: options.apiKey,
    nvdBaseUrl: nvd.baseUrl,
    nvd: { ...FAST_NVD_SETTINGS, ...options.nvdOverrides },
    storage: {
      sqlitePath: temp.child('nvd.sqlite'),
      sqliteBusyTimeoutMs: 1_000,
      migrationsDir: defaults.storage.migrationsDir,
      ...options.storage,
    },
    cache: {
      directory: temp.child('cache'),
      maxSizeBytes: 1_000_000,
      cleanupIntervalMs: 0,
      staleRetentionMs: defaults.cache.staleRetentionMs,
      envelopeVersion: defaults.cache.envelopeVersion,
      maxEntryBytes: defaults.cache.maxEntryBytes,
      ...options.cache,
    },
    cursor: { secret: 'test-cursor-secret-0123456789abcdef', ttlSeconds: 1_800 },
    ttlSeconds: { ...defaults.ttlSeconds, ...options.ttlSeconds },
    limits: {
      ...defaults.limits,
      pageSize: {
        ...defaults.limits.pageSize,
        ...options.limits?.pageSize,
      },
    },
    logLevel: 'debug',
    nodeEnv: 'test',
  };

  const logs: string[] = [];
  const logger = new Logger({ level: 'debug', sink: (line) => logs.push(line) });

  const app = await createApp({ config, logger, clock });

  let client: Client | null = null;
  if (options.withClient !== false) {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client(
      { name: 'nvd-mcp-test-client', version: '0.0.1' },
      { capabilities: {} },
    );
    await Promise.all([client.connect(clientTransport), app.server.connect(serverTransport)]);
  }

  const connectedClient = client;

  const callTool = async (
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<ToolCallOutcome> => {
    if (connectedClient === null) {
      throw new Error('Harness was created without an MCP client');
    }
    const result = await connectedClient.callTool({ name, arguments: args });
    const content = Array.isArray(result.content) ? result.content : [];
    const first = content[0] as { type?: string; text?: string } | undefined;
    const text = typeof first?.text === 'string' ? first.text : '';
    const structured =
      result.structuredContent !== undefined && typeof result.structuredContent === 'object'
        ? (result.structuredContent as Record<string, unknown>)
        : undefined;
    const isError = result.isError === true;

    let error: Record<string, unknown> | undefined;
    if (isError && text.length > 0) {
      try {
        const parsed: unknown = JSON.parse(text);
        if (parsed !== null && typeof parsed === 'object') {
          error = parsed as Record<string, unknown>;
        }
      } catch {
        error = undefined;
      }
    }

    return { isError, structuredContent: structured, error, text };
  };

  return {
    app,
    config,
    clock,
    nvd,
    temp,
    client,
    logs,
    callTool,
    close: async () => {
      if (client !== null) {
        await client.close();
      }
      app.close();
      if (ownsMockServer) {
        await nvd.stop();
      }
      if (options.keepTemp !== true) {
        temp.cleanup();
      }
    },
  };
}

/** Extracts `meta` from a successful tool payload. */
export function readMeta(payload: Record<string, unknown> | undefined): Record<string, unknown> {
  const meta = payload?.['meta'];
  return meta !== null && typeof meta === 'object' ? (meta as Record<string, unknown>) : {};
}

/** Extracts `pagination` from a successful collection payload. */
export function readPagination(
  payload: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const pagination = payload?.['pagination'];
  return pagination !== null && typeof pagination === 'object'
    ? (pagination as Record<string, unknown>)
    : {};
}

export function readItems(payload: Record<string, unknown> | undefined): Array<Record<string, unknown>> {
  const items = payload?.['items'];
  return Array.isArray(items) ? (items as Array<Record<string, unknown>>) : [];
}
