import { CURSOR_VERSION, type PaginationResourceName } from '../config/defaults.js';

/** Resources that support NVD offset pagination. */
export type PaginationResource = PaginationResourceName;

/** Signed cursor payload. */
export type CursorPayload = {
  version: number;
  resource: PaginationResource;
  queryHash: string;
  startIndex: number;
  pageSize: number;
  issuedAt: string;
  expiresAt: string;
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

export const CURRENT_CURSOR_VERSION = CURSOR_VERSION;

/** Caller-supplied cursor data; the codec adds `version`, `issuedAt` and `expiresAt`. */
export type CursorInput = {
  resource: PaginationResource;
  queryHash: string;
  startIndex: number;
  pageSize: number;
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

export type PageRequest = {
  startIndex: number;
  pageSize: number;
};

/** Public pagination block attached to list responses. Never exposes `startIndex`. */
export type PaginationMeta = {
  pageSize: number;
  returned: number;
  totalResults: number;
  hasMore: boolean;
  nextCursor: string | null;
};
