import type { CpeRecord } from '../../domain/cpe.js';
import type { NvdCpeClientPort } from '../../domain/ports.js';
import type { CpeQuery, NvdPage, NvdPageRequest, WithRaw } from '../../domain/queries.js';
import type { NvdHttpClient, NvdQueryParams } from './http-client.js';
import { mapCpeItem } from './mappers/cpe-mapper.js';
import { toPageMeta } from './page-meta.js';
import { buildCpeParams, withPagination } from './query-params.js';
import { nvdCpeResponseSchema, parseNvdResponse } from './schemas.js';

export const CPE_ENDPOINT = '/cpes/2.0';

/** Typed client for `/cpes/2.0` (Official CPE Dictionary). */
export class NvdCpeClient implements NvdCpeClientPort {
  constructor(private readonly http: NvdHttpClient) {}

  async fetchById(cpeNameId: string): Promise<WithRaw<CpeRecord> | null> {
    const page = await this.request(
      { cpeNameId },
      { startIndex: 0, resultsPerPage: 1 },
    );
    return (
      page.items.find((item) => item.value.cpeNameId === cpeNameId.toUpperCase()) ??
      page.items[0] ??
      null
    );
  }

  async search(query: CpeQuery, page: NvdPageRequest): Promise<NvdPage<WithRaw<CpeRecord>>> {
    return this.request(buildCpeParams(query), page);
  }

  private async request(
    params: NvdQueryParams,
    page: NvdPageRequest,
  ): Promise<NvdPage<WithRaw<CpeRecord>>> {
    const payload = await this.http.getJson(CPE_ENDPOINT, withPagination(params, page));
    const parsed = parseNvdResponse(nvdCpeResponseSchema, payload, CPE_ENDPOINT);
    return {
      meta: toPageMeta(parsed),
      items: parsed.products.map((entry) => ({ value: mapCpeItem(entry.cpe), raw: entry.cpe })),
    };
  }
}
