import type { CpeRecord } from '../../../domain/cpe.js';
import type { NvdCpeItem } from '../schemas.js';

/** Maps a validated NVD CPE dictionary entry onto the inference domain model. */
export function mapCpeItem(item: NvdCpeItem): CpeRecord {
  return {
    cpeNameId: item.cpeNameId.trim().toUpperCase(),
    cpeName: item.cpeName,
    deprecated: item.deprecated ?? false,
    created: item.created ?? '',
    lastModified: item.lastModified ?? '',
    titles: (item.titles ?? []).map((title) => ({ title: title.title, lang: title.lang })),
    refs: (item.refs ?? []).map((reference) => ({
      ref: reference.ref,
      type: reference.type ?? null,
    })),
    deprecatedBy: (item.deprecatedBy ?? []).map((entry) => ({
      cpeName: entry.cpeName,
      cpeNameId: entry.cpeNameId.trim().toUpperCase(),
    })),
    deprecates: (item.deprecates ?? []).map((entry) => ({
      cpeName: entry.cpeName,
      cpeNameId: entry.cpeNameId.trim().toUpperCase(),
    })),
  };
}
