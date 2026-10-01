import type { NvdPageMeta } from '../../domain/queries.js';

export type NvdEnvelopeInput = {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp?: string | null | undefined;
};

export function toPageMeta(envelope: NvdEnvelopeInput): NvdPageMeta {
  return {
    startIndex: envelope.startIndex,
    resultsPerPage: envelope.resultsPerPage,
    totalResults: envelope.totalResults,
    format: envelope.format,
    version: envelope.version,
    timestamp: envelope.timestamp ?? null,
  };
}
