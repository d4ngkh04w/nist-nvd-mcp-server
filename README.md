# NIST NVD MCP server

MCP server exposing the NVD APIs (CVE search, history, CPE dictionary, CPE match criteria) over **stdio**, with a local SQLite + JSON disk cache so repeated lookups do not hit the upstream API.

## Requirements

- **Node.js >= 22.5** (uses the built-in `node:sqlite` module)
- A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) is recommended

## Register with an MCP client

```bash
npm install && npm run build
```

```json
{
  "mcpServers": {
    "nist-nvd": {
      "command": "node",
      "args": ["/absolute/path/to/dist/main.js"],
      "env": { "NVD_API_KEY": "your-key" }
    }
  }
}
```

The server speaks JSON-RPC on **stdin/stdout**; every log line goes to stderr.

## Tools

| Tool | Purpose |
| --- | --- |
| `nvd_get_cve` | Full record for one CVE |
| `nvd_get_cve_summary` | Compact summary of one CVE |
| `nvd_get_cves` | Batch summaries (up to 100 IDs) |
| `nvd_search_cves` | Search CVEs by keyword, IDs, CPE, CWE, CVSS, KEV, dates |
| `nvd_get_recent_cves` | Newest CVEs by publication date |
| `nvd_get_modified_cves` | Newest CVEs by last-modified date |
| `nvd_get_cve_history` | Change history of one CVE |
| `nvd_search_cpes` | Search the CPE Dictionary |
| `nvd_get_cpe` | One CPE Dictionary entry |
| `nvd_search_cpe_matches` | Search CPE Match Criteria |

Every tool accepts `fields` to narrow payloads; every list tool accepts `metaOnly: true` and `pageSize`/`cursor` for pagination.
Unknown input fields are rejected with `INVALID_INPUT` (typo guard), so copy parameter names verbatim.

## Examples

These are `tools/call` arguments (MCP JSON-RPC). All of them are read-only.

**1. Compact summary of one CVE** (`nvd_get_cve_summary`):

```json
{ "cveId": "CVE-2021-44228" }
```

Returns `data` with `id`, `summary`, `primaryCvss`, `cwes`, `affectedProducts`,
`isKnownExploited` and `kevDateAdded` — without the full configuration tree.

**2. Compare CVSS scores of several CVEs in one call** (`nvd_get_cves`):

```json
{
  "cveIds": ["CVE-2014-0160", "CVE-2016-5195", "CVE-2021-44228"],
  "fields": ["id", "primaryCvss", "isKnownExploited"]
}
```

Identifiers are uppercased and de-duplicated; the response reports `foundIds`,
`missingIds` and `meta.requested/found/missing`. Use `nvd_get_cve` when you need
the full record instead of a summary.

**3. Narrow one KEV batch to a single product** (`nvd_search_cves`):

```json
{
  "kev": { "addedOn": "2021-11-03" },
  "keyword": "Remote Desktop Services",
  "fields": ["id", "published", "summary", "primaryCvss", "isKnownExploited", "kevDateAdded"]
}
```

`addedOn` is an exact `YYYY-MM-DD` day (sent as that day 00:00:00–23:59:59, so the
batch is never truncated). Filters combine with AND. A keyword with more than
three tokens usually matches nothing — use two or three distinctive terms.

**4. Walk a paginated feed** (`nvd_get_recent_cves` + cursor):

```json
{ "days": 7, "pageSize": 25 }
```

Take `pagination.nextCursor` from the response and call again with **identical**
filters plus the cursor:

```json
{ "days": 7, "pageSize": 25, "cursor": "<pagination.nextCursor>" }
```

Feeds report `meta.ordering` (`published_desc` / `last_modified_desc`) so you can
assert the newest-first reversal happened. Pass `metaOnly: true` to check counts
and paging without the `items` array.

**5. From a CVE to its CPE builds** (`nvd_search_cpe_matches` → `nvd_get_cpe`):

```json
{ "cveId": "CVE-2021-44228", "pageSize": 20 }
```

Find the row whose `criteria` is `cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*`,
then resolve the dictionary entry directly:

```json
{ "cpeName": "cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*" }
```

Prefer `cpeNameId` (UUID) when you already have it — a CPE Match Criteria UUID
is not a dictionary id. For change history, `nvd_get_cve_history` works the same
way: `{ "cveId": "CVE-2021-44228", "pageSize": 20 }` and follow `nextCursor`.

## Response shape

```jsonc
{
  "data": { /* tool-specific */ },
  "meta": { /* cacheStatus, warnings, window, fieldsApplied, ... */ },
  "pagination": { /* page, pageCount, totalResults, hasMore, nextCursor */ }
}
```

- Pass `pagination.nextCursor` back as `cursor` with identical filters and `pageSize`.
- `pagination.totalResults` is the upstream count before local filtering.
- Feeds always report one ordering marker in `meta.ordering`.
- Cursor rejection carries `details.reason`.

## Caching and rate limiting

- A cache hit never calls NVD. Expired entries fall back to the stale copy with a warning.
- Concurrent identical requests are collapsed.
- Upstream calls are serialized (`NVD_MIN_INTERVAL_MS`, default 6000) and retried with backoff.
- Default files live under `./data`; migrations are applied at startup.

## Configuration

Copy `.env.example` to `.env`. Key variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | - | API key, sent as the `apiKey` header only |
| `NVD_BASE_URL` | NVD public API | Upstream base URL |
| `NVD_MIN_INTERVAL_MS` | `6000` | Minimum gap between upstream requests |
| `SQLITE_PATH` | `./data/nvd.sqlite` | Database file |
| `CACHE_DIRECTORY` | `./data/cache` | JSON disk cache directory |
| `CURSOR_SECRET` | random | HMAC key for cursors |
| `CURSOR_TTL_SECONDS` | `1800` | Cursor lifetime |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` / `silent` |

## Docker

```bash
docker build -t nist-nvd-mcp-server .
docker run -i --rm -e NVD_API_KEY=your-key -v nvd-data:/data nist-nvd-mcp-server
```

Use `-i` (not `-t`) so stdin stays open. The container runs as a non-root user and shuts down cleanly on `docker stop`.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm test            # vitest (unit + integration + contract); runs build first
npm run build       # emit dist/
npm run dev         # tsx src/main.ts, no build step
```

Tests never touch the real NVD API - they use a mock server, a temp SQLite DB, and a temp cache dir.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `startup_failed: Failed to configure the SQLite database` | Give each instance its own `SQLITE_PATH` and `CACHE_DIRECTORY` |
| `startup_failed: Invalid environment configuration` | Fix the value named in the stderr JSON |
| `UPSTREAM_RATE_LIMITED` / `UPSTREAM_UNAVAILABLE` | Set `NVD_API_KEY`; cached entries are still served |
| `UPSTREAM_BAD_RESPONSE` with `details.status: 404` on every tool | `NVD_API_KEY` is likely invalid/expired; drop it or issue a new key |
| No output when running by hand | It is a stdio server waiting for JSON-RPC on stdin |

## License

[MIT](./LICENSE) - this project is not affiliated with or endorsed by NIST/NVD.
