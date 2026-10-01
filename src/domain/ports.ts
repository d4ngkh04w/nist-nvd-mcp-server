import type { CacheResource, StoredValue } from './cache.js';
import type { CveChangeEvent, CveDetails } from './cve.js';
import type { CpeMatchRecord, CpeRecord } from './cpe.js';
import type {
  CveHistoryQuery,
  CveQuery,
  CpeMatchQuery,
  CpeQuery,
  NvdPage,
  NvdPageRequest,
  WithRaw,
} from './queries.js';

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export type UpsertOptions = {
  fetchedAt: string;
  expiresAt: string;
  rawJson?: string | null;
};

export type UpsertManyOptions = UpsertOptions & {
  /** Raw payload per entity, keyed by entity identifier. */
  rawJsonById?: Map<string, string | null>;
};

export interface CveRepositoryPort {
  findById(cveId: string): StoredValue<CveDetails> | null;
  /**
   * Reads the stored raw upstream payload for a row.
   *
   * Returns `null` when the row is absent, the payload is missing or it cannot be read as text;
   * it never returns an empty string.
   */
  findRawById(cveId: string): string | null;
  findManyByIds(cveIds: readonly string[]): Map<string, StoredValue<CveDetails>>;
  upsert(cve: CveDetails, options: UpsertOptions): void;
  upsertMany(cves: readonly CveDetails[], options: UpsertManyOptions): void;
  deleteExpired(now: Date): number;
  count(): number;
}

export interface CveHistoryRepositoryPort {
  findByChangeId(changeId: string): StoredValue<CveChangeEvent> | null;
  /** Reads the stored raw upstream payload for a change event; see `CveRepositoryPort.findRawById`. */
  findRawByChangeId(changeId: string): string | null;
  findManyByChangeIds(changeIds: readonly string[]): Map<string, StoredValue<CveChangeEvent>>;
  upsertMany(events: readonly CveChangeEvent[], options: UpsertManyOptions): void;
  deleteExpired(now: Date): number;
  count(): number;
}

export interface CpeRepositoryPort {
  findById(cpeNameId: string): StoredValue<CpeRecord> | null;
  /** Reads the stored raw upstream payload for a row; see `CveRepositoryPort.findRawById`. */
  findRawById(cpeNameId: string): string | null;
  findManyByIds(cpeNameIds: readonly string[]): Map<string, StoredValue<CpeRecord>>;
  findByName(cpeName: string): StoredValue<CpeRecord> | null;
  upsertMany(records: readonly CpeRecord[], options: UpsertManyOptions): void;
  deleteExpired(now: Date): number;
  count(): number;
}

export interface CpeMatchRepositoryPort {
  findById(matchCriteriaId: string): StoredValue<CpeMatchRecord> | null;
  /** Reads the stored raw upstream payload for a row; see `CveRepositoryPort.findRawById`. */
  findRawById(matchCriteriaId: string): string | null;
  upsertMany(records: readonly CpeMatchRecord[], options: UpsertManyOptions): void;
  deleteExpired(now: Date): number;
  count(): number;
}

export type QueryCacheWrite<T> = {
  cacheKey: string;
  resource: CacheResource;
  queryHash: string;
  value: T;
  createdAt: string;
  fetchedAt: string;
  expiresAt: string;
};

export interface QueryCacheRepositoryPort {
  get<T>(cacheKey: string): StoredValue<T> | null;
  put<T>(entry: QueryCacheWrite<T>): void;
  delete(cacheKey: string): void;
  deleteExpired(now: Date): number;
  count(): number;
}

export interface AppMetadataRepositoryPort {
  get(key: string): string | null;
  set(key: string, value: string): void;
  all(): Record<string, string>;
}

export interface NvdCveClientPort {
  fetchByIds(
    cveIds: readonly string[],
    page: NvdPageRequest,
  ): Promise<NvdPage<WithRaw<CveDetails>>>;
  search(query: CveQuery, page: NvdPageRequest): Promise<NvdPage<WithRaw<CveDetails>>>;
}

export interface NvdCveHistoryClientPort {
  search(
    query: CveHistoryQuery,
    page: NvdPageRequest,
  ): Promise<NvdPage<WithRaw<CveChangeEvent>>>;
}

export interface NvdCpeClientPort {
  fetchById(cpeNameId: string): Promise<WithRaw<CpeRecord> | null>;
  search(query: CpeQuery, page: NvdPageRequest): Promise<NvdPage<WithRaw<CpeRecord>>>;
}

export interface NvdCpeMatchClientPort {
  search(
    query: CpeMatchQuery,
    page: NvdPageRequest,
  ): Promise<NvdPage<WithRaw<CpeMatchRecord>>>;
}
