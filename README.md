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

All tools are read-only. Use `fields` to narrow payloads, and `pageSize`/`cursor` to paginate lists.

## Example

Call `nvd_get_cve_summary` with:

```json
{ "cveId": "CVE-2021-44228" }
```

Returns a compact CVE summary and cache metadata. See [usage](./docs/usage.md) for batch,
search, pagination and CPE examples.

## Defaults and limits

- Fresh cache hits avoid NVD; outage fallback is marked by `meta.stale` and `meta.warnings`.
- Upstream requests are serialized, 6 seconds apart by default. Tool deadline: 120 seconds.
- Modified feeds are bounded to 10,000 CVEs and a roughly 4 MB snapshot; narrow large queries.
- Unknown inputs and oversized output return errors; use smaller pages or fewer `fields`.

Configuration is optional: copy [`.env.example`](./.env.example) to `.env` or set environment
variables in your MCP client. See [operations](./docs/operations.md) for details and troubleshooting.

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
GitHub Actions runs the same checks on Node.js 22 and 24.

## Documentation

- [Usage and response format](./docs/usage.md)
- [Configuration, caching and troubleshooting](./docs/operations.md)
- [LLM evaluations](./docs/evaluations.md)

## License

[MIT](./LICENSE) - this project is not affiliated with or endorsed by NIST/NVD.
