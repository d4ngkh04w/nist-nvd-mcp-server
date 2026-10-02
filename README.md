# NIST NVD MCP server

MCP server exposing the [NVD](https://nvd.nist.gov/developers) APIs - CVE search, CVE history,
the Official CPE Dictionary and CPE Match Criteria - over **stdio**, with a local SQLite + JSON disk
cache so repeated lookups do not hit the (heavily rate-limited) upstream API.

## Requirements

- **Node.js >= 22.5** (uses the built-in `node:sqlite` module - no native compilation)
- Optional but recommended: a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)

## Installation

```bash
npm install
npm run build
```

The server speaks JSON-RPC on **stdin/stdout**: stdout carries protocol frames only, every log line
goes to stderr. It is not an HTTP server and opens no ports.

## Register with an MCP client

```json
{
  "mcpServers": {
    "nist-nvd": {
      "command": "node",
      "args": ["/absolute/path/to/nist-nvd-mcp-server/dist/main.js"],
      "env": { "NVD_API_KEY": "your-key" }
    }
  }
}
```

The API key is sent only in the `apiKey` request header - never in a URL, never logged, never
written to SQLite or the disk cache. Without it the public API allows roughly 5 requests / 30 s, so
one full sweep of the 10 tools takes 60-90 s.

## Tools

| Tool | Purpose |
| --- | --- |
| `nvd_get_cve` | Full record for one CVE: description, all CVSS metrics, CWEs, configurations, references, CISA KEV status |
| `nvd_get_cve_summary` | Compact view of one CVE: timestamps, status, English summary, primary CVSS, CWEs, affected products, KEV |
| `nvd_get_cves` | Summaries for up to 100 CVE IDs in one batch (only missing/stale IDs are fetched) |
| `nvd_search_cves` | Filter CVEs by keyword, IDs, CPE, CWE, CVSS, `vulnStatuses`, KEV date window, published/modified window |
| `nvd_get_recent_cves` | CVEs ordered by publication date, newest first |
| `nvd_get_modified_cves` | CVEs ordered by last-modified date, newest first |
| `nvd_get_cve_history` | Change history of one CVE (paged; `eventName` values include `CVE Modified`, `Initial Analysis`, `Modified Analysis`, `Reanalysis`, `CPE Deprecation Remap`) |
| `nvd_search_cpes` | Search the CPE Dictionary by keyword, CPE match string, criteria UUID, or last-modified window |
| `nvd_get_cpe` | One CPE Dictionary entry, by `cpeNameId` or by exact `cpeName` |
| `nvd_search_cpe_matches` | Search CPE Match Criteria (the CVE ↔ CPE version-range links) |

## Response shape

```jsonc
{
  "data": { /* tool-specific */ },
  "meta": {
    "source": "cache",           // "cache" | "nvd"
    "cacheStatus": "hit",        // "hit" | "miss" | "refresh" | "stale_fallback"
    "fetchedAt": "...", "expiresAt": "...", "ageSeconds": 3, "stale": false,
    "warnings": []               // stale fallback, local filtering, truncation, ...
  },
  "pagination": {                // list tools only
    "pageSize": 20, "returned": 20, "totalResults": 312, "hasMore": true,
    "nextCursor": "eyJ2ZXJzaW9uIjoxLC..."
  }
}
```

### Pagination

Read `pagination.nextCursor` (top level, **not** inside `meta`) and pass it back as `cursor` with
**identical filters and pageSize** until `hasMore` is `false`.

The cursor is an opaque HMAC-signed token that stands in for NVD's internal `startIndex`. It cannot
be forged or edited - a tampered token, a cursor reused with different filters, or one older than
`CURSOR_TTL_SECONDS` (default 30 min) returns `INVALID_CURSOR`. Relative date windows (`days: 7`)
are frozen into the cursor so every page sees the same range.

`totalResults` is the **upstream** NVD count before local filtering (see below), so it can exceed
the number of returned items.

## Caching and rate limiting

- Two tiers: a JSON disk cache with per-resource TTLs, backed by SQLite for entity lookups
  (`nvd_get_cve`, `nvd_get_cve_summary`, `nvd_get_cve_history`, `nvd_get_cpe`).
- **A cache hit never calls NVD.** Expired entries are refreshed; if NVD is unreachable the stale
  copy is served with `cacheStatus: "stale_fallback"` and a `meta.warnings` entry.
- Concurrent identical requests are collapsed (single-flight), so a burst of 25 identical calls
  produces exactly one upstream request.
- Upstream calls are serialized with a minimum interval (`NVD_MIN_INTERVAL_MS`, default 6000) and
  retried with exponential backoff on 429/5xx/timeouts.
- Default files live under `./data` (`nvd.sqlite` + `cache/`). Schema migrations are applied at
  startup from `migrations/`.

## Configuration

Every variable is optional - copy `.env.example` to `.env` and set what you need. Real environment
variables take precedence over `.env`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | - | API key, sent as the `apiKey` header only |
| `NVD_BASE_URL` | `https://services.nvd.nist.gov/rest/json` | Upstream base URL (HTTPS, or HTTP for localhost) |
| `NVD_MIN_INTERVAL_MS` | `6000` | Minimum gap between upstream requests |
| `NVD_REQUEST_TIMEOUT_MS` | `15000` | Per-request timeout |
| `NVD_MAX_RETRIES` | `4` | Retries on 429/5xx/network errors |
| `SQLITE_PATH` | `./data/nvd.sqlite` | Database file |
| `CACHE_DIRECTORY` | `./data/cache` | JSON disk cache directory |
| `*_CACHE_TTL_SECONDS` | 300-604800 | Freshness window per resource |
| `CURSOR_SECRET` | random per process | HMAC key for cursors; set it (>= 16 chars) to keep cursors valid across restarts |
| `CURSOR_TTL_SECONDS` | `1800` | Cursor lifetime |
| `MAX_*_PAGE_SIZE` | 50 / 50 / 100 / 100 | Page size caps per tool |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` \| `silent` |

See `.env.example` for the full list with defaults and explanations.

## NVD API quirks worth knowing

Verified empirically against the live API:

- **Boolean filters must be valueless** (`?isVulnerable`), and `isVulnerable` is only accepted
  together with `cpeName`.
- **Date windows are capped at 120 days** by NVD; wider requests return 404, so they are rejected
  locally first.
- `vulnStatuses` is sent in unspaced form (`UndergoingAnalysis`) while NVD responds with the spaced
  form (`Undergoing Analysis`); the server canonicalizes both ways.
- CPE deprecation filtering (`includeDeprecated`) and some CPE search keys are **not supported
  upstream** (they return 404), so they are applied locally: `totalResults` stays the upstream
  count and up to 4 extra upstream pages may be fetched to fill a page after filtering.
- `nvd_get_cpe` by exact `cpeName` scans at most 300 upstream rows before reporting `CPE_NOT_FOUND`.

## Docker

```bash
docker build -t nist-nvd-mcp-server .
docker run -i --rm -e NVD_API_KEY=your-key -v nvd-data:/data nist-nvd-mcp-server
```

Use `-i` (not `-t`) so stdin stays open. The container runs as a non-root user with `/data`
writable; `docker stop` shuts it down cleanly in a few milliseconds.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run lint        # eslint (no-console is an error: stdout must stay protocol-only)
npm test            # vitest run (unit + integration + MCP contract); runs build first
npm run test:watch  # vitest in watch mode
npm run build       # emit dist/
npm start           # node dist/main.js
npm run dev         # tsx src/main.ts, no build step
npm run clean       # remove dist/
```

Tests never touch the real NVD API - they run against an in-process mock server, a temp SQLite
database and a temp cache directory.

## Evaluation

`scripts/evaluation.py` scores the ten tools the way a real client uses them: it hands each question
from `evaluations/nist-nvd-mcp-server.xml` to an LLM together with this server's tool list, lets the
model pick the tools itself, then compares the final answer with the expected value.

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r scripts/requirements.txt

OPENAI_API_KEY=... python scripts/evaluation.py \
  -t stdio -c node -a "$PWD/dist/main.js" \
  -e PATH="$PATH" NVD_MIN_INTERVAL_MS=6500 \
  --base-url http://127.0.0.1:20128/v1 -m <model-id> \
  -o evaluations/report-<model>.md evaluations/nist-nvd-mcp-server.xml
```

The LLM is reached through the OpenAI-compatible chat-completions API, so any gateway serving
`/v1/chat/completions` with tool calling works. Set `NVD_MIN_INTERVAL_MS` above 6000 to stay inside
the anonymous rate limit, and point `SQLITE_PATH`/`CACHE_DIRECTORY` at a scratch directory if
another instance already has the defaults open.

The question set asks for capabilities, never tool names, and every expected answer is a stable fact
(KEV dates, CVSS scores, immutable `cpeNameId` / `matchCriteriaId`, counts over wide windows) verified
against the live API. Reports are git-ignored; the question set is committed.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `startup_failed: Failed to configure the SQLite database` | Another process holds the database file (two instances sharing `./data`, or the same file opened from Windows and WSL) | Give each instance its own `SQLITE_PATH` and `CACHE_DIRECTORY` |
| `startup_failed: Invalid environment configuration` | A variable failed validation (e.g. `CURSOR_SECRET` shorter than 16 characters) | Fix the value named in the stderr JSON, or unset it - every variable is optional |
| `UPSTREAM_RATE_LIMITED` / `UPSTREAM_UNAVAILABLE` | NVD throttled or unreachable | Set `NVD_API_KEY`; cached entries are still served, with `stale_fallback` and a warning |
| `UPSTREAM_BAD_RESPONSE` | NVD returned a payload that failed schema validation | Raise `LOG_LEVEL=debug` and read the stderr log; the failing path is logged, not the body |
| No output when running by hand | The server is waiting for JSON-RPC on stdin | It is a stdio server; drive it from an MCP client, or pipe a `initialize` request |

## License

[MIT](./LICENSE) - this project is not affiliated with or endorsed by NIST/NVD. It is a client for
the public [NVD API](https://nvd.nist.gov/developers), whose data is provided by NIST in the
public domain.