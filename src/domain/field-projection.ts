import { DomainError } from './errors.js';

/** Field projection affects output only, never fetched records, cache keys or cursors. */
export const CVE_SUMMARY_FIELDS = [
  'id',
  'published',
  'lastModified',
  'vulnStatus',
  'summary',
  'primaryCvss',
  'cwes',
  'affectedProducts',
  'isKnownExploited',
  'kevDateAdded',
  'referenceCount',
] as const;

export const CVE_DETAILS_FIELDS = [
  'id',
  'sourceIdentifier',
  'published',
  'lastModified',
  'vulnStatus',
  'description',
  'descriptions',
  'metrics',
  'primaryCvss',
  'weaknesses',
  'cwes',
  'configurations',
  'references',
  'isKnownExploited',
  'kev',
  'raw',
] as const;

export const CVE_CHANGE_EVENT_FIELDS = [
  'cveId',
  'eventName',
  'changeId',
  'sourceIdentifier',
  'created',
  'details',
] as const;

export const CPE_MATCH_FIELDS = [
  'matchCriteriaId',
  'criteria',
  'status',
  'created',
  'lastModified',
  'cpeLastModified',
  'versionStartIncluding',
  'versionStartExcluding',
  'versionEndIncluding',
  'versionEndExcluding',
  'matches',
] as const;

export const CPE_RECORD_FIELDS = [
  'cpeNameId',
  'cpeName',
  'deprecated',
  'created',
  'lastModified',
  'titles',
  'refs',
  'deprecatedBy',
  'deprecates',
] as const;

export type FieldName<T extends readonly string[]> = T[number];

/**
 * Validates a `fields` list against the allowlist of one tool.
 *
 * Returns `undefined` when the list is omitted, which keeps the projection inactive. Unknown names
 * are rejected instead of ignored, so an unsupported key surfaces as `INVALID_INPUT` carrying the
 * supported set rather than as a key that silently disappears from the payload.
 */
export function resolveFields<TTool extends readonly string[]>(
  requested: readonly string[] | undefined,
  allowed: TTool,
  toolName: string,
): FieldName<TTool>[] | undefined {
  if (requested === undefined) {
    return undefined;
  }
  if (requested.length === 0) {
    throw DomainError.invalidInput(
      `${toolName}.fields must list at least one field; omit the parameter to receive every field`,
      { allowedFields: [...allowed] },
    );
  }

  const allowedSet = new Set<string>(allowed);
  const selected: FieldName<TTool>[] = [];
  const seen = new Set<string>();
  const unknown: string[] = [];

  for (const raw of requested) {
    const field = raw.trim();
    if (!allowedSet.has(field)) {
      if (!unknown.includes(field)) {
        unknown.push(field);
      }
      continue;
    }
    if (seen.has(field)) {
      continue;
    }
    seen.add(field);
    selected.push(field as FieldName<TTool>);
  }

  if (unknown.length > 0) {
    throw DomainError.invalidInput(
      `${toolName}.fields contains unsupported field(s): ${unknown.join(', ')}. fields lists returnable item fields, not filter parameters. Supported fields: ${allowed.join(', ')}`,
      { unsupported: unknown, allowedFields: [...allowed] },
    );
  }

  return selected;
}

/**
 * Keeps only the requested top-level keys.
 *
 * Keys the record does not carry are omitted rather than emitted as `null`, so a projection never
 * invents data. Without `fields` the value is returned untouched.
 */
export function projectFields<T extends object>(value: T, fields: readonly string[] | undefined): T {
  if (fields === undefined) {
    return value;
  }
  const projected: Record<string, unknown> = {};
  const source = value as Record<string, unknown>;
  for (const field of fields) {
    if (Object.prototype.hasOwnProperty.call(source, field)) {
      projected[field] = source[field];
    }
  }
  return projected as T;
}

export function projectFieldList<T extends object>(
  items: readonly T[],
  fields: readonly string[] | undefined,
): T[] {
  if (fields === undefined) {
    return [...items];
  }
  return items.map((item) => projectFields(item, fields));
}
