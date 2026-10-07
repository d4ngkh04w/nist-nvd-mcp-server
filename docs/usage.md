# Usage

[README](../README.md) · [Operations](./operations.md)

These examples are `tools/call` arguments. All tools are read-only. Unknown input fields
are rejected with `INVALID_INPUT`, so copy parameter names verbatim. Every tool accepts
`fields`; list tools also accept `metaOnly`, `pageSize` and `cursor`.

## CVE summary

Call `nvd_get_cve_summary`:

```json
{ "cveId": "CVE-2021-44228" }
```

Returns `data` with `id`, `summary`, `primaryCvss`, `cwes`, `affectedProducts`,
`isKnownExploited` and `kevDateAdded` without the full configuration tree.

## Batch comparison

Call `nvd_get_cves`:

```json
{
  "cveIds": ["CVE-2014-0160", "CVE-2016-5195", "CVE-2021-44228"],
  "fields": ["id", "primaryCvss", "isKnownExploited"]
}
```

Identifiers are uppercased and de-duplicated. The response reports `foundIds`, `missingIds`
and `meta.requested/found/missing`. Use `nvd_get_cve` for a full record rather than a summary.
Check the CVSS version before comparing scores.

## KEV search

Call `nvd_search_cves`:

```json
{
  "kev": { "addedOn": "2021-11-03" },
  "keyword": "Remote Desktop Services",
  "fields": ["id", "published", "summary", "primaryCvss", "isKnownExploited", "kevDateAdded"]
}
```

`addedOn` covers that exact `YYYY-MM-DD` day, from 00:00:00 to 23:59:59. Filters combine
with AND. Use two or three distinctive keyword terms; longer phrases often match nothing.

## Pagination

Call `nvd_get_recent_cves`:

```json
{ "days": 7, "pageSize": 25 }
```

Pass `pagination.nextCursor` back with identical filters and `pageSize`:

```json
{ "days": 7, "pageSize": 25, "cursor": "<pagination.nextCursor>" }
```

Feeds report `meta.ordering`: `published_desc` or `last_modified_desc`. `metaOnly: true`
suppresses items but still reads the cache or upstream; it does not make the query free.

### Modified-feed limits

NVD sorts by publication date even with last-modified filters. The modified feed loads
the complete filtered set before sorting, bounded to 10,000 CVEs, five upstream pages and
a roughly 4 MB summary snapshot. Larger sets return `INVALID_INPUT`: narrow the window or
filters, or use `nvd_search_cves` without a global last-modified ordering guarantee.

A cold request may take several request intervals. Cursors reuse the original snapshot
after its freshness TTL passes, but return `INVALID_CURSOR` if that snapshot is evicted or
replaced by a fresh first-page query. Restart without a cursor in that case.

## CVE to CPE builds

Call `nvd_search_cpe_matches`:

```json
{ "cveId": "CVE-2021-44228", "pageSize": 20 }
```

Find the criterion `cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*`, then call `nvd_get_cpe`:

```json
{ "cpeName": "cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*" }
```

Prefer `cpeNameId` when available; a `matchCriteriaId` is not a dictionary id. To retrieve
change history, call `nvd_get_cve_history` with `{ "cveId": "CVE-2021-44228", "pageSize": 20 }`
and follow `nextCursor`.

## Response format

Single-record tools return `data`; collection tools return `items`. Both include `meta`,
and paginated tools add `pagination`:

```jsonc
{
  "items": [ /* tool-specific records */ ],
  "meta": { /* cacheStatus, warnings, window, fieldsApplied, ... */ },
  "pagination": { /* page, pageCount, totalResults, hasMore, nextCursor */ }
}
```

- `pagination.totalResults` is the upstream count before local filtering.
- Cursor rejection carries `details.reason`.
- `fields` exposes an enum allowlist in the input schema; unsupported fields are rejected.
- Oversized results return `RESPONSE_TOO_LARGE`, never a silently truncated success. Reduce
  `pageSize`/`fields`, or set `includeRaw`, `includeConfigurations` and `includeReferences` to false.
- `MCP_MAX_OUTPUT_BYTES` limits one serialized success payload. The wire response also
  carries its text mirror and JSON-RPC framing, so its total size is larger.
