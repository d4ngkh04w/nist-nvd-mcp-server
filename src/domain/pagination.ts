import type { PaginationResourceName } from '../config/defaults.js';

/** Resources that support NVD offset pagination. */
export type PaginationResource = PaginationResourceName;

/** Signed cursor payload. */
export type CursorPayload = {
  version: number;
  resource: PaginationResource;
  queryHash: string;
  startIndex: number;
  pageSize: number;
  /**
   * 1-based ordinal of this page within the cursor walk.
   *
   * Derived from the offset alone it would be wrong for the descending feeds, whose first page is
   * read from the end of the window, so the ordinal travels with the signed cursor instead.
   */
  page?: number;
  issuedAt: string;
  expiresAt: string;
  /** Modification-sorted snapshot generation; reject a cursor if the cache was replaced. */
  snapshotFetchedAt?: string;
  /**
   * Date window that was resolved when the cursor was issued.
   *
   * Relative inputs (`days: 7`) resolve against the wall clock, so the window must travel with the
   * cursor; otherwise a later page would resolve a different window and fail the query-hash check.
   */
  resolvedWindow?: {
    start: string;
    end: string;
  };
};

/**
 * Machine-readable cause carried in `INVALID_CURSOR` `details.reason`.
 *
 * A single error code covers every rejection, so the reason is what lets a caller tell a token it
 * mangled in transit apart from one that expired or was issued for a different query.
 */
export type CursorErrorReason =
  | 'empty'
  | 'too_long'
  | 'format'
  | 'signature'
  | 'payload'
  | 'version'
  | 'resource'
  | 'query_hash'
  | 'start_index'
  | 'page_size'
  | 'timestamps'
  | 'expired'
  | 'window'
  | 'filter_mismatch'
  | 'out_of_range';

/** Cursor data before signing; the codec adds `version`, `issuedAt` and `expiresAt`. */
export type CursorInput = {
  resource: PaginationResource;
  queryHash: string;
  startIndex: number;
  pageSize: number;
  /** 1-based ordinal of the page this cursor points at. */
  page?: number;
  snapshotFetchedAt?: string;
  resolvedWindow?: {
    start: string;
    end: string;
  };
};

export type CursorCodec = {
  /** Serializes and signs a cursor payload. */
  encode(input: CursorInput): string;
  /** Verifies the signature/expiry and returns the payload, or throws `INVALID_CURSOR`. */
  decode(token: string): CursorPayload;
};

/** Public pagination block attached to list responses. Never exposes `startIndex`. */
export type PaginationMeta = {
  /** 1-based ordinal of this page within the cursor walk; 1 on the first page. */
  page: number;
  /**
   * Pages the current upstream total divides into. The upstream set is live, so it can change
   * between two calls of the same walk and this is an estimate rather than a fixed plan.
   */
  pageCount: number;
  pageSize: number;
  returned: number;
  totalResults: number;
  hasMore: boolean;
  nextCursor: string | null;
};
