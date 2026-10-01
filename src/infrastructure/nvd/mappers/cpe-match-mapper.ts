import type { CpeMatchRecord } from '../../../domain/cpe.js';
import type { NvdCpeMatchItem } from '../schemas.js';

/** Maps a validated NVD CPE Match Criteria entry onto the inference domain model. */
export function mapCpeMatch(item: NvdCpeMatchItem): CpeMatchRecord {
  return {
    matchCriteriaId: item.matchCriteriaId.trim().toUpperCase(),
    criteria: item.criteria,
    status: item.status ?? 'Unknown',
    created: item.created ?? '',
    lastModified: item.lastModified ?? '',
    cpeLastModified: item.cpeLastModified ?? null,
    versionStartIncluding: item.versionStartIncluding ?? null,
    versionStartExcluding: item.versionStartExcluding ?? null,
    versionEndIncluding: item.versionEndIncluding ?? null,
    versionEndExcluding: item.versionEndExcluding ?? null,
    matches: (item.matches ?? []).map((match) => ({
      cpeName: match.cpeName,
      cpeNameId: match.cpeNameId.trim().toUpperCase(),
    })),
  };
}
