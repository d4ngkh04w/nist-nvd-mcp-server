import { DomainError } from './errors.js';
import { differenceInDays, parseIsoDate, toIso } from '../shared/time.js';

/** `CVE-YYYY-NNNN(N)` per the CVE ID syntax. */
export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;

/** Case-insensitive variant used for input validation (values are uppercased later). */
export const CVE_ID_PATTERN_CASE_INSENSITIVE = /^CVE-\d{4}-\d{4,}$/i;

export const UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** `cpe:2.3:...` (formatted string) or `cpe:/...` (URI binding). */
export const CPE_MATCH_STRING_PATTERN = /^cpe:(?:2\.[23]:|\/)/i;

/**
 * Component count of a complete CPE 2.3 formatted string:
 * `cpe`, `2.3`, part, vendor, product, version, update, edition, language, sw_edition, target_sw,
 * target_hw, other.
 *
 * The NVD `/cpematch/2.0` endpoint answers HTTP 404 for a longer string (for example a CPE name with
 * one extra trailing `*`), which is indistinguishable from "no such criteria" unless the count is
 * checked before the request.
 */
export const CPE_23_MAX_COMPONENTS = 13;

/** `YYYY-MM-DD` with no time component. */
export const DATE_ONLY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

export function isDateOnly(value: string): boolean {
  return DATE_ONLY_PATTERN.test(value.trim());
}

/**
 * End of the day for a `YYYY-MM-DD` string.
 *
 * Used for KEV date windows: NVD compares the window against the KEV `dateAdded` midnight
 * timestamp, so a date-only `end` bound resolved to `00:00:00` yields an empty range.
 */
export function endOfDayIso(dateOnly: string): string {
  return `${dateOnly.trim()}T23:59:59.999Z`;
}

/** Number of colon separated components of a CPE 2.3 string, or `null` for the `cpe:/` URI form. */
export function countCpe23Components(value: string): number | null {
  if (!/^cpe:2\.3:/i.test(value.trim())) {
    return null;
  }
  return splitCpeComponents(value.trim()).length;
}

/**
 * Rejects a CPE string that the NVD endpoints would answer with HTTP 404.
 *
 * Applied to `matchStringSearch` (`/cpematch/2.0`) and to the dictionary-side `cpeMatchString`
 * (`/cpes/2.0`) so the failure is a precise `INVALID_INPUT` instead of an opaque
 * `UPSTREAM_BAD_RESPONSE`.
 */
export function assertCpeComponentCount(value: string, field: string): void {
  const components = countCpe23Components(value);
  if (components === null || components <= CPE_23_MAX_COMPONENTS) {
    return;
  }
  throw DomainError.invalidInput(
    `${field} has ${components} colon separated components; a CPE 2.3 string has at most ${CPE_23_MAX_COMPONENTS} (cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other) and the NVD API answers HTTP 404 for longer strings`,
    { field, components, maxComponents: CPE_23_MAX_COMPONENTS },
  );
}

export function normalizeCveId(value: string): string {
  return value.trim().toUpperCase();
}

export function isValidCveId(value: string): boolean {
  return CVE_ID_PATTERN.test(normalizeCveId(value));
}

export function normalizeUuid(value: string): string {
  return value.trim().toUpperCase();
}

export function isValidUuid(value: string): boolean {
  return UUID_PATTERN.test(value.trim());
}

export function isCpe23Name(value: string): boolean {
  return /^cpe:2\.3:/i.test(value.trim());
}

export function isValidCpeMatchString(value: string): boolean {
  return CPE_MATCH_STRING_PATTERN.test(value.trim());
}

export type NormalizedCveIds = {
  ids: string[];
  duplicates: string[];
  invalid: string[];
};

/** Uppercases, de-duplicates and validates a list of CVE IDs. */
export function normalizeCveIds(values: readonly string[]): NormalizedCveIds {
  const seen = new Set<string>();
  const ids: string[] = [];
  const duplicates: string[] = [];
  const invalid: string[] = [];
  for (const raw of values) {
    const normalized = normalizeCveId(raw);
    if (!CVE_ID_PATTERN.test(normalized)) {
      invalid.push(raw.trim());
      continue;
    }
    if (seen.has(normalized)) {
      duplicates.push(normalized);
      continue;
    }
    seen.add(normalized);
    ids.push(normalized);
  }
  return { ids, duplicates, invalid };
}

export type DateWindowResolution = {
  startIso: string;
  endIso: string;
  days: number;
};

/**
 * Validates a resolved date window against the NVD hard limit (120 days).
 *
 * A date-only end (`2021-12-31`) is widened to `23:59:59.999`: NVD timestamps carry a real clock
 * time, so resolving a bare date to midnight silently drops every record published during that day
 * and turns a single-day range into an empty interval. The span check runs on the values as given,
 * so widening never pushes an accepted window past `maxDays`.
 */
export function validateDateWindow(
  window: { start: string; end: string },
  options: { maxDays: number; field: string },
): DateWindowResolution {
  const start = parseIsoDate(window.start);
  const end = parseIsoDate(window.end);
  if (!start || !end) {
    throw DomainError.invalidInput(
      `${options.field} must contain ISO-8601 timestamps ('YYYY-MM-DD' or 'YYYY-MM-DDTHH:mm:ssZ')`,
      { field: options.field },
    );
  }
  if (end.getTime() < start.getTime()) {
    throw DomainError.invalidInput(`${options.field}.end must not be earlier than ${options.field}.start`, {
      field: options.field,
    });
  }
  const days = differenceInDays(start, end);
  if (days > options.maxDays) {
    throw DomainError.dateRangeTooLarge(
      `${options.field} must not span more than ${options.maxDays} days (received ${Math.ceil(days)} days)`,
      { field: options.field, maxDays: options.maxDays, requestedDays: Math.ceil(days) },
    );
  }
  const endIso = isDateOnly(window.end) ? endOfDayIso(window.end) : toIso(end);
  return { startIso: toIso(start), endIso, days };
}

/**
 * Resolves the `days` / `start`+`end` / default-window input pattern used by
 * `nvd_get_recent_cves` and `nvd_get_modified_cves`.
 */
export function resolveDateWindow(
  input: { days?: number; start?: string; end?: string | undefined },
  options: { now: Date; maxDays: number; defaultDays: number; field: string },
): DateWindowResolution {
  const hasRange = input.start !== undefined || input.end !== undefined;
  if (input.days !== undefined && hasRange) {
    throw DomainError.invalidInput(
      `${options.field}.days cannot be combined with ${options.field}.start/end`,
      { field: options.field },
    );
  }
  if (hasRange) {
    if (input.start === undefined || input.end === undefined) {
      throw DomainError.invalidInput(
        `${options.field}.start and ${options.field}.end must be provided together`,
        { field: options.field },
      );
    }
    return validateDateWindow({ start: input.start, end: input.end }, options);
  }
  const days = input.days ?? options.defaultDays;
  if (!Number.isFinite(days) || days <= 0) {
    throw DomainError.invalidInput(`${options.field}.days must be a positive number`, {
      field: options.field,
    });
  }
  if (days > options.maxDays) {
    throw DomainError.dateRangeTooLarge(
      `${options.field}.days must not exceed ${options.maxDays} days (received ${days})`,
      { field: options.field, maxDays: options.maxDays, requestedDays: days },
    );
  }
  const end = options.now;
  const start = new Date(end.getTime() - days * 86_400_000);
  return { startIso: toIso(start), endIso: toIso(end), days };
}

export function resolvePageSize(
  requested: number | undefined,
  limits: { default: number; max: number },
  field: string,
): number {
  if (requested === undefined) {
    return limits.default;
  }
  if (!Number.isInteger(requested) || requested < 1) {
    throw DomainError.invalidInput(`${field} must be a positive integer`, { field });
  }
  if (requested > limits.max) {
    throw DomainError.invalidInput(
      `${field} must not exceed ${limits.max} for this resource (received ${requested})`,
      { field, max: limits.max },
    );
  }
  return requested;
}

export function requireAtLeastOneFilter(
  filters: Record<string, unknown>,
  message: string,
): void {
  const hasFilter = Object.values(filters).some((value) => value !== undefined && value !== false);
  if (!hasFilter) {
    throw DomainError.invalidInput(message);
  }
}

/** Splits a CPE 2.3 formatted string into components, honouring `\:` escapes. */
export function splitCpeComponents(value: string): string[] {
  const components: string[] = [];
  let current = '';
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char === '\\' && index + 1 < value.length) {
      current += value[index + 1];
      index += 1;
      continue;
    }
    if (char === ':') {
      components.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  components.push(current);
  return components;
}

/**
 * Component-wise comparison of a concrete CPE name against a CPE match string.
 *
 * `isVulnerable` is evaluated by NVD upstream, so this helper backs the recursive
 * `hasVulnerableCpeMatch` diagnostic in `cve-tree.ts`, which walks the applicability tree.
 */
export function cpeComponentsMatch(left: string, right: string): boolean {
  const leftParts = splitCpeComponents(left.trim().toLowerCase());
  const rightParts = splitCpeComponents(right.trim().toLowerCase());
  if (leftParts.length !== rightParts.length) {
    return false;
  }
  for (let index = 0; index < leftParts.length; index += 1) {
    const a = leftParts[index] ?? '';
    const b = rightParts[index] ?? '';
    if (a === '*' || b === '*') {
      continue;
    }
    if (a === '-' || b === '-') {
      if (a !== b) {
        return false;
      }
      continue;
    }
    if (a !== b) {
      return false;
    }
  }
  return true;
}

export function isVulnerableCpeMatch(cpeName: string, criteria: string): boolean {
  return cpeComponentsMatch(cpeName, criteria);
}

/**
 * NVD transmits vulnerability statuses without spaces (`UndergoingAnalysis`) but returns them with
 * spaces (`Undergoing Analysis`), so both spellings must map onto one canonical value.
 */
export function canonicalStatusKey(value: string): string {
  return value.trim().toLowerCase().replace(/[\s_-]+/g, '');
}

const NVD_STATUS_PARAM_BY_KEY: Readonly<Record<string, string>> = {
  received: 'Received',
  awaitinganalysis: 'AwaitingAnalysis',
  undergoinganalysis: 'UndergoingAnalysis',
  analyzed: 'Analyzed',
  modified: 'Modified',
  deferred: 'Deferred',
  rejected: 'Rejected',
};

/** Converts a status into the spelling the NVD API expects in `vulnStatuses`. */
export function toNvdStatusParam(value: string): string {
  const trimmed = value.trim();
  const known = NVD_STATUS_PARAM_BY_KEY[canonicalStatusKey(trimmed)];
  if (known !== undefined) {
    return known;
  }
  // Unknown/custom statuses are forwarded with whitespace removed, matching the request style.
  return trimmed.replace(/\s+/g, '');
}

/** Canonicalizes, validates and de-duplicates a status list. */
export function normalizeVulnStatuses(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const key = canonicalStatusKey(trimmed);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(toNvdStatusParam(trimmed));
  }
  return result;
}
