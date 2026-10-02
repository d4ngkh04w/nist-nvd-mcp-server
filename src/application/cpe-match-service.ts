import type { AppConfig } from '../config/env.js';
import type { CacheMeta } from '../domain/cache.js';
import type { CpeMatchRecord } from '../domain/cpe.js';
import { DomainError } from '../domain/errors.js';
import type { CursorCodec, CursorPayload, PaginationMeta, PaginationResource } from '../domain/pagination.js';
import type {
  Clock,
  CpeMatchRepositoryPort,
  NvdCpeMatchClientPort,
  QueryCacheRepositoryPort,
} from '../domain/ports.js';
import type { CachedPage, CpeMatchQuery, DateWindow, NvdPageRequest } from '../domain/queries.js';
import {
  isValidCpeMatchString,
  isValidCveId,
  isValidUuid,
  normalizeCveId,
  normalizeUuid,
  resolvePageSize,
  validateDateWindow,
} from '../domain/validation.js';
import { buildQueryIdentity } from '../infrastructure/cache/cache-key.js';
import type { Logger } from '../shared/logger.js';
import { addSeconds, toIso } from '../shared/time.js';
import type { CachedResourceLoader } from './cached-resource-loader.js';
import type { ResponseMeta } from './response-meta.js';
import { mergeWarnings, serializeRawPayload } from './support.js';

export type SearchCpeMatchesInput = {
  cveId?: string;
  matchCriteriaId?: string;
  matchStringSearch?: string;
  lastModified?: DateWindow;
  pageSize?: number;
  cursor?: string;
};

export type CpeMatchCollectionOutput = {
  items: CpeMatchRecord[];
  pagination: PaginationMeta;
  meta: ResponseMeta;
};

export type CpeMatchServiceDeps = {
  config: AppConfig;
  clock: Clock;
  logger: Logger;
  cpeMatchClient: NvdCpeMatchClientPort;
  cpeMatchRepository: CpeMatchRepositoryPort;
  queryCache: QueryCacheRepositoryPort;
  loader: CachedResourceLoader;
  cursorCodec: CursorCodec;
};

/** Use case for `nvd_search_cpe_matches` (`/cpematch/2.0`). */
export class CpeMatchService {
  constructor(private readonly deps: CpeMatchServiceDeps) {}

  async searchCpeMatches(input: SearchCpeMatchesInput): Promise<CpeMatchCollectionOutput> {
    const query = this.buildQuery(input);
    const pageSize = resolvePageSize(
      input.pageSize,
      this.deps.config.limits.pageSize['cpe-matches'],
      'pageSize',
    );
    const identity = buildQueryIdentity('cpe-match', query, pageSize);
    const cursor = this.decodeCursor(input.cursor, 'cpe-matches', identity.queryHash, pageSize);
    const pageRequest: NvdPageRequest = {
      startIndex: cursor?.startIndex ?? 0,
      resultsPerPage: pageSize,
    };
    const pageIdentity = buildQueryIdentity(
      'cpe-match',
      { query, startIndex: pageRequest.startIndex, resultsPerPage: pageRequest.resultsPerPage },
      pageSize,
    );

    const { page, meta } = await this.loadPage({
      cacheKey: pageIdentity.cacheKey,
      queryHash: pageIdentity.queryHash,
      query,
      pageRequest,
    });

    const nextStartIndex = page.startIndex + page.upstreamCount;
    const hasMore = page.upstreamCount > 0 && nextStartIndex < page.totalResults;

    return {
      items: page.items,
      pagination: {
        pageSize,
        returned: page.items.length,
        totalResults: page.totalResults,
        hasMore,
        nextCursor: hasMore
          ? this.deps.cursorCodec.encode({
              resource: 'cpe-matches',
              queryHash: identity.queryHash,
              startIndex: nextStartIndex,
              pageSize,
            })
          : null,
      },
      meta: {
        ...meta,
        warnings: mergeWarnings(meta.warnings),
        ordering: 'nvd_default',
      },
    };
  }

  private buildQuery(input: SearchCpeMatchesInput): CpeMatchQuery {
    const query: CpeMatchQuery = {};

    if (input.cveId !== undefined) {
      const cveId = normalizeCveId(input.cveId);
      if (!isValidCveId(cveId)) {
        throw DomainError.invalidInput(`cveId must match CVE-YYYY-NNNN: ${input.cveId}`, {
          cveId: input.cveId,
        });
      }
      query.cveId = cveId;
    }

    if (input.matchCriteriaId !== undefined) {
      if (!isValidUuid(input.matchCriteriaId)) {
        throw DomainError.invalidInput('matchCriteriaId must be a UUID', {
          matchCriteriaId: input.matchCriteriaId,
        });
      }
      query.matchCriteriaId = normalizeUuid(input.matchCriteriaId);
    }

    if (input.matchStringSearch !== undefined) {
      const matchString = input.matchStringSearch.trim();
      if (!isValidCpeMatchString(matchString)) {
        throw DomainError.invalidInput(
          'matchStringSearch must be a complete CPE match string (for example "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); the NVD API rejects partial keywords and version ranges',
          { matchStringSearch: input.matchStringSearch },
        );
      }
      query.matchStringSearch = matchString;
    }

    if (input.lastModified !== undefined) {
      const validated = validateDateWindow(input.lastModified, {
        maxDays: this.deps.config.limits.maxDateRangeDays,
        field: 'lastModified',
      });
      query.lastModified = { start: validated.startIso, end: validated.endIso };
    }

    if (
      query.cveId === undefined &&
      query.matchCriteriaId === undefined &&
      query.matchStringSearch === undefined &&
      query.lastModified === undefined
    ) {
      throw DomainError.invalidInput(
        'nvd_search_cpe_matches requires at least one filter: cveId, matchCriteriaId, matchStringSearch or lastModified',
      );
    }

    return query;
  }

  private async loadPage(args: {
    cacheKey: string;
    queryHash: string;
    query: CpeMatchQuery;
    pageRequest: NvdPageRequest;
  }): Promise<{ page: CachedPage<CpeMatchRecord>; meta: CacheMeta }> {
    const resource = 'cpe-match' as const;
    const result = await this.deps.loader.load<CachedPage<CpeMatchRecord>>({
      resource,
      cacheKey: args.cacheKey,
      ttlSeconds: this.deps.config.ttlSeconds.cpeMatch,
      readCached: () => this.deps.queryCache.get<CachedPage<CpeMatchRecord>>(args.cacheKey),
      writeCached: (record) => {
        this.deps.queryCache.put({
          cacheKey: args.cacheKey,
          resource,
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

  private async fetchPage(
    query: CpeMatchQuery,
    pageRequest: NvdPageRequest,
  ): Promise<CachedPage<CpeMatchRecord>> {
    const upstream = await this.deps.cpeMatchClient.search(query, pageRequest);
    const now = this.deps.clock.now();
    const fetchedAt = toIso(now);
    const expiresAt = toIso(addSeconds(now, this.deps.config.ttlSeconds.cpeMatch));
    const rawJsonById = new Map<string, string | null>();
    for (const item of upstream.items) {
      rawJsonById.set(item.value.matchCriteriaId, serializeRawPayload(item.raw));
    }
    if (upstream.items.length > 0) {
      try {
        this.deps.cpeMatchRepository.upsertMany(
          upstream.items.map((item) => item.value),
          { fetchedAt, expiresAt, rawJsonById },
        );
      } catch (error) {
        this.deps.logger.warn('cpe_match_persist_failed', { error });
      }
    }

    return {
      items: upstream.items.map((item) => item.value),
      totalResults: upstream.meta.totalResults,
      startIndex: pageRequest.startIndex,
      resultsPerPage: pageRequest.resultsPerPage,
      upstreamCount: upstream.items.length,
      filteredOut: 0,
      clientSideFilters: [],
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
