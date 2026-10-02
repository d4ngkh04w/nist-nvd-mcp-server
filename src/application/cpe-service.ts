import type { AppConfig } from '../config/env.js';
import { MAX_CPE_NAME_SCAN_PAGES, MAX_LOCAL_FILTER_FILL_REQUESTS } from '../config/defaults.js';
import type { CacheMeta, CacheResource } from '../domain/cache.js';
import type { CpeRecord } from '../domain/cpe.js';
import { DomainError } from '../domain/errors.js';
import type { CursorCodec, CursorPayload, PaginationMeta, PaginationResource } from '../domain/pagination.js';
import type { Clock, CpeRepositoryPort, NvdCpeClientPort, QueryCacheRepositoryPort } from '../domain/ports.js';
import type { CachedPage, CpeQuery, DateWindow, NvdPageRequest } from '../domain/queries.js';
import {
  isValidCpeMatchString,
  isValidUuid,
  normalizeUuid,
  resolvePageSize,
  validateDateWindow,
} from '../domain/validation.js';
import { buildEntityIdentity, buildQueryIdentity } from '../infrastructure/cache/cache-key.js';
import type { Logger } from '../shared/logger.js';
import { addSeconds, toIso } from '../shared/time.js';
import type { CachedResourceLoader } from './cached-resource-loader.js';
import { applyCpeQueryFilters } from './client-side-filters.js';
import type { ResponseMeta } from './response-meta.js';
import { mergeWarnings, serializeRawPayload } from './support.js';

export type SearchCpesInput = {
  keyword?: string;
  keywordExactMatch?: boolean;
  cpeMatchString?: string;
  matchCriteriaId?: string;
  lastModified?: DateWindow;
  includeDeprecated?: boolean;
  pageSize?: number;
  cursor?: string;
};

export type CpeCollectionOutput = {
  items: CpeRecord[];
  pagination: PaginationMeta;
  meta: ResponseMeta;
};

export type GetCpeInput = {
  cpeNameId?: string;
  cpeName?: string;
};

export type GetCpeOutput = {
  data: CpeRecord;
  meta: ResponseMeta;
};

export type CpeServiceDeps = {
  config: AppConfig;
  clock: Clock;
  logger: Logger;
  cpeClient: NvdCpeClientPort;
  cpeRepository: CpeRepositoryPort;
  queryCache: QueryCacheRepositoryPort;
  loader: CachedResourceLoader;
  cursorCodec: CursorCodec;
};

/** Use cases for `nvd_search_cpes` and `nvd_get_cpe` (`/cpes/2.0`). */
export class CpeService {
  constructor(private readonly deps: CpeServiceDeps) {}

  async searchCpes(input: SearchCpesInput): Promise<CpeCollectionOutput> {
    const query = this.buildSearchQuery(input);
    const pageSize = resolvePageSize(
      input.pageSize,
      this.deps.config.limits.pageSize.cpes,
      'pageSize',
    );
    const identity = buildQueryIdentity('cpe-search', query, pageSize);
    const cursor = this.decodeCursor(input.cursor, 'cpes', identity.queryHash, pageSize);
    const pageRequest: NvdPageRequest = {
      startIndex: cursor?.startIndex ?? 0,
      resultsPerPage: pageSize,
    };
    const pageIdentity = buildQueryIdentity(
      'cpe-search',
      { query, startIndex: pageRequest.startIndex, resultsPerPage: pageRequest.resultsPerPage },
      pageSize,
    );

    const { page, meta } = await this.loadPage({
      resource: 'cpe-search',
      cacheKey: pageIdentity.cacheKey,
      queryHash: pageIdentity.queryHash,
      query,
      pageRequest,
      ttlSeconds: this.deps.config.ttlSeconds.cpeSearch,
    });

    const nextStartIndex = page.startIndex + page.upstreamCount;
    const hasMore = page.upstreamCount > 0 && nextStartIndex < page.totalResults;

    const result: ResponseMeta = {
      ...meta,
      warnings: mergeWarnings(meta.warnings),
      ordering: 'nvd_default',
    };
    if (page.clientSideFilters.length > 0) {
      result.filtersAppliedClientSide = [...page.clientSideFilters];
      result.warnings = mergeWarnings(result.warnings, [
        'The NVD CPE API rejects the includeDeprecated parameter; deprecated handling is applied locally',
      ]);
    }
    if (page.filteredOut > 0) {
      result.filteredOut = page.filteredOut;
    }

    return {
      items: page.items,
      pagination: {
        pageSize,
        returned: page.items.length,
        totalResults: page.totalResults,
        hasMore,
        nextCursor: hasMore
          ? this.deps.cursorCodec.encode({
              resource: 'cpes',
              queryHash: identity.queryHash,
              startIndex: nextStartIndex,
              pageSize,
            })
          : null,
      },
      meta: result,
    };
  }

  async getCpe(input: GetCpeInput): Promise<GetCpeOutput> {
    const hasId = input.cpeNameId !== undefined;
    const hasName = input.cpeName !== undefined;
    if (hasId === hasName) {
      throw DomainError.invalidInput('Provide exactly one of cpeNameId or cpeName');
    }

    if (hasId) {
      return this.getCpeById(normalizeUuid(input.cpeNameId as string));
    }
    return this.getCpeByName((input.cpeName as string).trim());
  }

  private async getCpeById(cpeNameId: string): Promise<GetCpeOutput> {
    if (!isValidUuid(cpeNameId)) {
      throw DomainError.invalidInput(`cpeNameId must be a UUID: ${cpeNameId}`, { cpeNameId });
    }
    const identity = buildEntityIdentity('cpe', cpeNameId);
    const result = await this.deps.loader.load<CpeRecord>({
      resource: 'cpe',
      cacheKey: identity.cacheKey,
      ttlSeconds: this.deps.config.ttlSeconds.cpeDetail,
      readCached: () => this.deps.cpeRepository.findById(cpeNameId),
      writeCached: (record) => {
        this.deps.cpeRepository.upsertMany([record.value], {
          fetchedAt: record.fetchedAt,
          expiresAt: record.expiresAt,
          rawJsonById: new Map([[record.value.cpeNameId, serializeRawPayload(record.raw)]]),
        });
      },
      fetchUpstream: async () => {
        const match = await this.deps.cpeClient.fetchById(cpeNameId);
        if (match === null) {
          return { found: false as const };
        }
        return { found: true as const, value: match.value, raw: match.raw };
      },
      notFound: () =>
        DomainError.notFound('CPE_NOT_FOUND', `No CPE name found for cpeNameId ${cpeNameId}`, {
          cpeNameId,
        }),
    });
    return { data: result.value, meta: { ...result.meta, warnings: mergeWarnings(result.meta.warnings) } };
  }

  private async getCpeByName(cpeName: string): Promise<GetCpeOutput> {
    if (!isValidCpeMatchString(cpeName)) {
      throw DomainError.invalidInput(
        `cpeName must be a CPE 2.3 formatted string or a CPE 2.2 URI (received: ${cpeName})`,
        { cpeName },
      );
    }
    const identity = buildEntityIdentity('cpe', `name:${cpeName.toLowerCase()}`);
    const pageSize = this.deps.config.limits.pageSize.cpes.max;
    const scan = { pages: 0, scanned: 0, totalResults: 0 };
    const warnings: string[] = [
      `cpeName lookups use an upstream pattern search; the server scans up to ${MAX_CPE_NAME_SCAN_PAGES} pages for the exact name`,
    ];
    const result = await this.deps.loader.load<CpeRecord>({
      resource: 'cpe',
      cacheKey: identity.cacheKey,
      ttlSeconds: this.deps.config.ttlSeconds.cpeDetail,
      warnings,
      readCached: () => this.deps.cpeRepository.findByName(cpeName),
      writeCached: (record) => {
        this.deps.cpeRepository.upsertMany([record.value], {
          fetchedAt: record.fetchedAt,
          expiresAt: record.expiresAt,
          rawJsonById: new Map([[record.value.cpeNameId, serializeRawPayload(record.raw)]]),
        });
      },
      fetchUpstream: async () => {
        const target = cpeName.toLowerCase();
        for (let page = 0; page < MAX_CPE_NAME_SCAN_PAGES; page += 1) {
          const response = await this.deps.cpeClient.search(
            { cpeMatchString: cpeName, includeDeprecated: true },
            { startIndex: page * pageSize, resultsPerPage: pageSize },
          );
          scan.pages += 1;
          scan.scanned += response.items.length;
          scan.totalResults = response.meta.totalResults;
          if (response.items.length > 0) {
            try {
              this.deps.cpeRepository.upsertMany(
                response.items.map((item) => item.value),
                {
                  fetchedAt: toIso(this.deps.clock.now()),
                  expiresAt: toIso(
                    addSeconds(this.deps.clock.now(), this.deps.config.ttlSeconds.cpeDetail),
                  ),
                  rawJsonById: new Map(
                    response.items.map((item) => [
                      item.value.cpeNameId,
                      serializeRawPayload(item.raw),
                    ]),
                  ),
                },
              );
            } catch (error) {
              this.deps.logger.warn('cpe_persist_failed', { error });
            }
          }
          const exact = response.items.find((item) => item.value.cpeName.toLowerCase() === target);
          if (exact !== undefined) {
            return { found: true as const, value: exact.value, raw: exact.raw };
          }
          const exhausted =
            response.items.length === 0 ||
            response.items.length < pageSize ||
            (page + 1) * pageSize >= response.meta.totalResults;
          if (exhausted) {
            break;
          }
        }
        return { found: false as const };
      },
      notFound: () =>
        DomainError.notFound(
          'CPE_NOT_FOUND',
          scan.totalResults > scan.scanned
            ? `No CPE name exactly matching ${cpeName} was found within the first ${scan.scanned} of ${scan.totalResults} upstream results; use nvd_search_cpes to locate it`
            : `CPE ${cpeName} was not found in the NVD CPE dictionary`,
          { cpeName, scanned: scan.scanned, totalResults: scan.totalResults },
        ),
    });
    return { data: result.value, meta: { ...result.meta, warnings: mergeWarnings(result.meta.warnings) } };
  }

  private buildSearchQuery(input: SearchCpesInput): CpeQuery {
    if (input.keywordExactMatch === true && input.keyword === undefined) {
      throw DomainError.invalidInput('keywordExactMatch requires keyword');
    }
    if (input.matchCriteriaId !== undefined && !isValidUuid(input.matchCriteriaId)) {
      throw DomainError.invalidInput('matchCriteriaId must be a UUID', {
        matchCriteriaId: input.matchCriteriaId,
      });
    }
    if (input.cpeMatchString !== undefined && !isValidCpeMatchString(input.cpeMatchString)) {
      throw DomainError.invalidInput(
        'cpeMatchString must be a CPE 2.3 formatted string or a CPE 2.2 URI',
        { cpeMatchString: input.cpeMatchString },
      );
    }

    const query: CpeQuery = {};
    if (input.keyword !== undefined) {
      query.keyword = input.keyword;
    }
    if (input.keywordExactMatch === true) {
      query.keywordExactMatch = true;
    }
    if (input.cpeMatchString !== undefined) {
      query.cpeMatchString = input.cpeMatchString;
    }
    if (input.matchCriteriaId !== undefined) {
      query.matchCriteriaId = normalizeUuid(input.matchCriteriaId);
    }
    if (input.includeDeprecated === true) {
      query.includeDeprecated = true;
    }
    if (input.lastModified !== undefined) {
      const validated = validateDateWindow(input.lastModified, {
        maxDays: this.deps.config.limits.maxDateRangeDays,
        field: 'lastModified',
      });
      query.lastModified = { start: validated.startIso, end: validated.endIso };
    }

    if (
      query.keyword === undefined &&
      query.cpeMatchString === undefined &&
      query.matchCriteriaId === undefined &&
      query.lastModified === undefined
    ) {
      throw DomainError.invalidInput(
        'nvd_search_cpes requires at least one filter: keyword, cpeMatchString, matchCriteriaId or lastModified',
      );
    }

    return query;
  }

  private async loadPage(args: {
    resource: CacheResource;
    cacheKey: string;
    queryHash: string;
    query: CpeQuery;
    pageRequest: NvdPageRequest;
    ttlSeconds: number;
  }): Promise<{ page: CachedPage<CpeRecord>; meta: CacheMeta }> {
    const result = await this.deps.loader.load<CachedPage<CpeRecord>>({
      resource: args.resource,
      cacheKey: args.cacheKey,
      ttlSeconds: args.ttlSeconds,
      readCached: () => this.deps.queryCache.get<CachedPage<CpeRecord>>(args.cacheKey),
      writeCached: (record) => {
        this.deps.queryCache.put({
          cacheKey: args.cacheKey,
          resource: args.resource,
          queryHash: args.queryHash,
          value: record.value,
          createdAt: record.fetchedAt,
          fetchedAt: record.fetchedAt,
          expiresAt: record.expiresAt,
        });
      },
      fetchUpstream: async () => ({
        found: true as const,
        value: await this.fetchPage(args.query, args.pageRequest),
      }),
    });
    return { page: result.value, meta: result.meta };
  }

  /**
   * Fetches one public page.
   *
   * The CPE dictionary applies its `includeDeprecated` policy locally (the upstream parameter is
   * rejected with HTTP 404), so a single upstream page can contain fewer usable rows than the
   * caller asked for. To keep pagination semantics intact the loader keeps requesting only the
   * still-missing number of rows (never more), which guarantees that `items.length <= pageSize`
   * and that `startIndex + upstreamCount` is exactly the offset of the next page - no gaps, no
   * duplicates, and `totalResults` keeps its upstream meaning.
   */
  private async fetchPage(
    query: CpeQuery,
    pageRequest: NvdPageRequest,
  ): Promise<CachedPage<CpeRecord>> {
    const collected: CpeRecord[] = [];
    const appliedFilters = new Set<string>();
    let offset = pageRequest.startIndex;
    let upstreamCount = 0;
    let filteredOut = 0;
    let totalResults = 0;

    const needsLocalFiltering = query.includeDeprecated !== true;
    const maxRequests = needsLocalFiltering ? MAX_LOCAL_FILTER_FILL_REQUESTS : 1;

    for (let request = 0; request < maxRequests; request += 1) {
      const remaining = pageRequest.resultsPerPage - collected.length;
      if (remaining <= 0) {
        break;
      }
      const upstream = await this.deps.cpeClient.search(query, {
        startIndex: offset,
        resultsPerPage: remaining,
      });
      totalResults = upstream.meta.totalResults;
      upstreamCount += upstream.items.length;

      const now = this.deps.clock.now();
      const fetchedAt = toIso(now);
      const expiresAt = toIso(addSeconds(now, this.deps.config.ttlSeconds.cpeDetail));
      const rawJsonById = new Map<string, string | null>();
      for (const item of upstream.items) {
        rawJsonById.set(item.value.cpeNameId, serializeRawPayload(item.raw));
      }
      if (upstream.items.length > 0) {
        try {
          this.deps.cpeRepository.upsertMany(
            upstream.items.map((item) => item.value),
            { fetchedAt, expiresAt, rawJsonById },
          );
        } catch (error) {
          this.deps.logger.warn('cpe_persist_failed', { error });
        }
      }

      const filtered = applyCpeQueryFilters(
        upstream.items.map((item) => item.value),
        query,
      );
      collected.push(...filtered.items);
      filteredOut += filtered.filteredOut;
      for (const name of filtered.applied) {
        appliedFilters.add(name);
      }

      offset += upstream.items.length;
      const exhausted = upstream.items.length === 0 || offset >= totalResults;
      if (exhausted) {
        break;
      }
    }

    return {
      items: collected,
      totalResults,
      startIndex: pageRequest.startIndex,
      resultsPerPage: pageRequest.resultsPerPage,
      upstreamCount,
      filteredOut,
      clientSideFilters: [...appliedFilters],
    };
  }

  private decodeCursor(
    token: string | undefined,
    resource: PaginationResource,
    queryHash: string,
    maxPageSize: number,
  ): CursorPayload | null {
    if (token === undefined) {
      return null;
    }
    const payload = this.deps.cursorCodec.decode(token);
    if (payload.resource !== resource) {
      throw DomainError.invalidCursor(
        `Cursor was issued for "${payload.resource}" but this tool paginates "${resource}"`,
        { expected: resource, received: payload.resource },
      );
    }
    if (payload.queryHash !== queryHash) {
      throw DomainError.invalidCursor(
        'Cursor does not match the supplied filters; restart pagination without a cursor',
      );
    }
    if (payload.pageSize > maxPageSize) {
      throw DomainError.invalidCursor('Cursor page size exceeds the supported maximum', {
        max: maxPageSize,
      });
    }
    return payload;
  }
}
