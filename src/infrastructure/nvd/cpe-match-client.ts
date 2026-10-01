import type { CpeMatchRecord } from '../../domain/cpe.js';
import type { NvdCpeMatchClientPort } from '../../domain/ports.js';
import type { CpeMatchQuery, NvdPage, NvdPageRequest, WithRaw } from '../../domain/queries.js';
import type { NvdHttpClient } from './http-client.js';
import { mapCpeMatch } from './mappers/cpe-match-mapper.js';
import { toPageMeta } from './page-meta.js';
import { buildCpeMatchParams, withPagination } from './query-params.js';
import { nvdCpeMatchResponseSchema, parseNvdResponse } from './schemas.js';

export const CPE_MATCH_ENDPOINT = '/cpematch/2.0';

/** Typed client for `/cpematch/2.0` (CPE Match Criteria). */
export class NvdCpeMatchClient implements NvdCpeMatchClientPort {
  constructor(private readonly http: NvdHttpClient) {}

  async search(
    query: CpeMatchQuery,
    page: NvdPageRequest,
  ): Promise<NvdPage<WithRaw<CpeMatchRecord>>> {
    const payload = await this.http.getJson(
      CPE_MATCH_ENDPOINT,
      withPagination(buildCpeMatchParams(query), page),
    );
    const parsed = parseNvdResponse(nvdCpeMatchResponseSchema, payload, CPE_MATCH_ENDPOINT);
    return {
      meta: toPageMeta(parsed),
      items: parsed.matchStrings.map((entry) => ({
        value: mapCpeMatch(entry.matchString),
        raw: entry.matchString,
      })),
    };
  }
}
