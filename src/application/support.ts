import { MAX_RAW_PAYLOAD_BYTES } from '../config/defaults.js';
import { stringifyWithinBudget } from '../shared/json.js';

/** Serializes a raw upstream payload for persistence, honouring the size budget. */
export function serializeRawPayload(raw: unknown): string | null {
  if (raw === undefined || raw === null) {
    return null;
  }
  const { json, truncated } = stringifyWithinBudget(raw, MAX_RAW_PAYLOAD_BYTES);
  return truncated ? null : json;
}

/** De-duplicating merge of warning lists. */
export function mergeWarnings(...groups: Array<readonly string[] | undefined>): string[] {
  const merged: string[] = [];
  const seen = new Set<string>();
  for (const group of groups) {
    for (const warning of group ?? []) {
      if (seen.has(warning)) {
        continue;
      }
      seen.add(warning);
      merged.push(warning);
    }
  }
  return merged;
}
