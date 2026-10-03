import type { LogLevel } from '../config/defaults.js';

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

/** Field names that must never be written to logs. */
const SENSITIVE_KEY_PATTERN =
  /(api[-_]?key|apikey|authorization|auth[-_]?header|x-api-key|secret|token|password|cookie|credential)/i;

const MAX_STRING_LENGTH = 600;
const MAX_ARRAY_ITEMS = 50;
const MAX_LINE_LENGTH = 8_000;

export type LogFields = Record<string, unknown>;

export type LoggerOptions = {
  readonly level: LogLevel;
  readonly sink?: (line: string) => void;
  readonly bindings?: LogFields;
  readonly includeStack?: boolean;
};

function sanitizeValue(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    return value.length > MAX_STRING_LENGTH
      ? `${value.slice(0, MAX_STRING_LENGTH)}... (${value.length} chars)`
      : value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (value instanceof Error) {
    return { name: value.name, message: value.message, code: readErrorCode(value) };
  }
  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => sanitizeValue(item, seen));
  }
  if (typeof value === 'object') {
    if (seen.has(value)) {
      return '[circular]';
    }
    seen.add(value);
    const result: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        result[key] = '[redacted]';
        continue;
      }
      const sanitized = sanitizeValue(nested, seen);
      if (sanitized !== undefined) {
        result[key] = sanitized;
      }
    }
    return result;
  }
  return String(value);
}

function readErrorCode(error: Error): string | undefined {
  const candidate = (error as { code?: unknown }).code;
  return typeof candidate === 'string' || typeof candidate === 'number'
    ? String(candidate)
    : undefined;
}

/**
 * Minimal structured logger.
 *
 * All output goes to stderr so that stdout stays reserved for MCP JSON-RPC frames.
 */
export class Logger {
  private readonly level: LogLevel;
  private readonly sink: (line: string) => void;
  private readonly bindings: LogFields;
  private readonly includeStack: boolean;

  constructor(options: LoggerOptions) {
    this.level = options.level;
    this.sink = options.sink ?? defaultSink;
    this.bindings = options.bindings ?? {};
    this.includeStack = options.includeStack ?? false;
  }

  isEnabled(level: LogLevel): boolean {
    return LEVEL_WEIGHT[level] >= LEVEL_WEIGHT[this.level];
  }

  child(bindings: LogFields): Logger {
    return new Logger({
      level: this.level,
      sink: this.sink,
      bindings: { ...this.bindings, ...bindings },
      includeStack: this.includeStack,
    });
  }

  log(level: Exclude<LogLevel, 'silent'>, event: string, fields: LogFields = {}): void {
    if (!this.isEnabled(level)) {
      return;
    }
    const record: Record<string, unknown> = {
      time: new Date().toISOString(),
      level,
      event,
      ...sanitizeValue({ ...this.bindings, ...fields }, new WeakSet()) as LogFields,
    };
    if (this.includeStack && fields.error instanceof Error && fields.error.stack) {
      record.stack = fields.error.stack;
    }
    let line: string;
    try {
      line = JSON.stringify(record);
    } catch {
      line = JSON.stringify({ time: record.time, level, event, logError: 'serialization_failed' });
    }
    this.sink(line.length > MAX_LINE_LENGTH ? `${line.slice(0, MAX_LINE_LENGTH)}...` : line);
  }

  debug(event: string, fields?: LogFields): void {
    this.log('debug', event, fields);
  }

  info(event: string, fields?: LogFields): void {
    this.log('info', event, fields);
  }

  warn(event: string, fields?: LogFields): void {
    this.log('warn', event, fields);
  }

  error(event: string, fields?: LogFields): void {
    this.log('error', event, fields);
  }
}

function defaultSink(line: string): void {
  process.stderr.write(`${line}\n`);
}

export function createStderrLogger(level: LogLevel, bindings: LogFields = {}): Logger {
  return new Logger({ level, bindings, includeStack: level === 'debug' });
}

/**
 * Routes stray console output to stderr.
 *
 * The MCP stdio transport owns stdout; a single `console.log` from any dependency would
 * corrupt the JSON-RPC stream, so the process entry point installs this guard.
 */
export function redirectConsoleToStderr(logger: Logger): void {
  const write = (level: 'info' | 'warn' | 'error', args: unknown[]): void => {
    const [first, ...rest] = args;
    const message =
      typeof first === 'string'
        ? [first, ...rest.map((item) => (typeof item === 'string' ? item : safeStringify(item)))].join(' ')
        : safeStringify(first);
    logger.log(level, 'console_output', { message });
  };

  /* eslint-disable no-console -- stdout is reserved for MCP JSON-RPC: every console channel is redirected to stderr here */
  console.log = (...args: unknown[]): void => write('info', args);
  console.info = (...args: unknown[]): void => write('info', args);
  console.debug = (...args: unknown[]): void => write('info', args);
  console.warn = (...args: unknown[]): void => write('warn', args);
  console.error = (...args: unknown[]): void => write('error', args);
  /* eslint-enable no-console */
}

function safeStringify(value: unknown): string {
  if (value instanceof Error) {
    return `${value.name}: ${value.message}`;
  }
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}
