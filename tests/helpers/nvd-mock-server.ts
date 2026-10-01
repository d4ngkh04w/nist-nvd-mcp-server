import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export type NvdMockRequest = {
  /** Endpoint path as the server addresses it, e.g. `/cves/2.0` (the `/rest/json` prefix is stripped). */
  path: string;
  /** Full request path, including the `/rest/json` prefix. */
  fullPath: string;
  query: string;
  /** Milliseconds since epoch when the request arrived (used for rate-limit assertions). */
  receivedAtMs: number;
  /** First value for every query parameter (valueless flags map to `''`). */
  params: Record<string, string>;
  /** Raw parameter pairs, so repeated keys and valueless flags stay observable. */
  paramPairs: Array<[string, string]>;
  headers: Record<string, string | string[] | undefined>;
  method: string;
};

export type NvdMockResponse = {
  status?: number;
  body?: unknown;
  /** Sent verbatim instead of `body` (used to simulate malformed payloads). */
  rawBody?: string;
  headers?: Record<string, string>;
  /** Delay before writing the response. */
  delayMs?: number;
  /** Never answer: the client must hit its request timeout. */
  hang?: boolean;
};

/**
 * Scripted response for one call: either a static response or a function of the request index.
 * The index counts previous requests to the same path starting at 0.
 */
export type NvdMockResponder = (
  request: NvdMockRequest,
  indexForPath: number,
) => NvdMockResponse | undefined;

/** Normalizes `/rest/json/cves/2.0` to `/cves/2.0` so handlers read like the NVD endpoints. */
function normalizePath(rawPath: string): string {
  const prefix = '/rest/json';
  if (rawPath === prefix) {
    return '/';
  }
  if (rawPath.startsWith(`${prefix}/`)) {
    return rawPath.slice(prefix.length);
  }
  return rawPath;
}

/** Minimal stand-in for the NVD REST API used by the integration and contract tests. */
export class NvdMockServer {
  private readonly server: Server;
  private readonly handlers = new Map<string, NvdMockResponder>();
  private fallback: NvdMockResponse = { status: 404, body: {} };
  private readonly log: NvdMockRequest[] = [];
  private readonly pathCounters = new Map<string, number>();

  private constructor(server: Server, private readonly port: number) {
    this.server = server;
  }

  static async start(): Promise<NvdMockServer> {
    const server = createServer();
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = server.address() as AddressInfo;
    const instance = new NvdMockServer(server, address.port);
    server.on('request', (request, response) => {
      instance.handle(request, response);
    });
    return instance;
  }

  get baseUrl(): string {
    return `http://127.0.0.1:${this.port}/rest/json`;
  }

  /** Registers a responder for a path such as `/cves/2.0`. */
  on(path: string, responder: NvdMockResponder | NvdMockResponse): this {
    this.handlers.set(path, typeof responder === 'function' ? responder : () => responder);
    return this;
  }

  setFallback(response: NvdMockResponse): this {
    this.fallback = response;
    return this;
  }

  get requests(): readonly NvdMockRequest[] {
    return this.log;
  }

  requestsFor(path: string): NvdMockRequest[] {
    return this.log.filter((request) => request.path === path);
  }

  countFor(path: string): number {
    return this.requestsFor(path).length;
  }

  reset(): void {
    this.log.length = 0;
    this.pathCounters.clear();
    this.handlers.clear();
    this.fallback = { status: 404, body: {} };
  }

  async stop(): Promise<void> {
    this.server.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  private handle(request: IncomingMessage, response: ServerResponse): void {
    const rawUrl = request.url ?? '/';
    const [rawPath = '/', query = ''] = rawUrl.split('?');
    const path = normalizePath(rawPath);
    const search = new URLSearchParams(query);
    const params: Record<string, string> = {};
    const paramPairs: Array<[string, string]> = [];
    for (const [key, value] of search.entries()) {
      paramPairs.push([key, value]);
      if (!(key in params)) {
        params[key] = value;
      }
    }
    const logged: NvdMockRequest = {
      path,
      fullPath: rawPath,
      query,
      receivedAtMs: Date.now(),
      params,
      paramPairs,
      headers: request.headers,
      method: request.method ?? 'GET',
    };
    this.log.push(logged);

    const indexForPath = this.pathCounters.get(path) ?? 0;
    this.pathCounters.set(path, indexForPath + 1);

    const responder = this.handlers.get(path);
    const scripted = responder?.(logged, indexForPath) ?? this.fallback;

    if (scripted.hang === true) {
      // Deliberately leave the request unanswered so the client times out.
      return;
    }

    const send = (): void => {
      const status = scripted.status ?? 200;
      const body =
        scripted.rawBody ?? (scripted.body === undefined ? '' : JSON.stringify(scripted.body));
      response.writeHead(status, {
        'content-type': 'application/json',
        ...scripted.headers,
      });
      response.end(body);
    };

    if (scripted.delayMs !== undefined && scripted.delayMs > 0) {
      const timer = setTimeout(send, scripted.delayMs);
      timer.unref?.();
      return;
    }
    send();
  }
}
