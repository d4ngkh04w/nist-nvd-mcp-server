import { fileURLToPath } from 'node:url';

export const ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

/**
 * Parses an ISO-8601 timestamp.
 *
 * Datetimes without an explicit offset are interpreted as UTC (the NVD API always operates in UTC),
 * which keeps behaviour identical regardless of the host timezone.
 */
export function parseIsoDate(value: string): Date | null {
  const trimmed = value.trim();
  if (!ISO_DATE_PATTERN.test(trimmed)) {
    return null;
  }
  const normalized = trimmed.includes('T') || trimmed.includes(' ')
    ? normalizeDateTime(trimmed)
    : `${trimmed}T00:00:00.000Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function normalizeDateTime(value: string): string {
  const withT = value.replace(' ', 'T');
  if (/[Zz]$/.test(withT) || /[+-]\d{2}:?\d{2}$/.test(withT)) {
    return withT;
  }
  return `${withT}Z`;
}

export function toIso(date: Date): string {
  return date.toISOString();
}

/** NVD expects `yyyy-MM-ddTHH:mm:ss.SSS` in UTC and rejects a trailing `Z`. */
export function toNvdDate(date: Date): string {
  return date.toISOString().slice(0, 23);
}

export function addSeconds(date: Date, seconds: number): Date {
  return new Date(date.getTime() + seconds * 1_000);
}

export function isExpired(expiresAt: string, now: Date): boolean {
  const parsed = Date.parse(expiresAt);
  if (Number.isNaN(parsed)) {
    return true;
  }
  return parsed <= now.getTime();
}

export function ageSeconds(isoTimestamp: string, now: Date): number {
  const parsed = Date.parse(isoTimestamp);
  if (Number.isNaN(parsed)) {
    return 0;
  }
  return Math.max(0, Math.round((now.getTime() - parsed) / 1_000));
}

export function differenceInDays(start: Date, end: Date): number {
  return (end.getTime() - start.getTime()) / 86_400_000;
}

export function fileUrlToPath(importMetaUrl: string): string {
  return fileURLToPath(importMetaUrl);
}
