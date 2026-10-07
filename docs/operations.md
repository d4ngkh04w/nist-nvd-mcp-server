# Operations

[README](../README.md) · [Usage](./usage.md)

## Configuration

Copy [`.env.example`](../.env.example) to `.env`, or set environment variables in your MCP
client. All variables are optional. Real environment variables take precedence over `.env`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | - | API key, sent as the `apiKey` header only |
| `NVD_BASE_URL` | NVD public API | Upstream base URL |
| `NVD_MIN_INTERVAL_MS` | `6000` | Minimum gap between upstream requests |
| `MCP_TOOL_TIMEOUT_MS` | `120000` | Overall tool deadline in milliseconds (100–3600000) |
| `MCP_MAX_OUTPUT_BYTES` | `1000000` | Serialized success payload byte limit (1024–16000000) |
| `SQLITE_PATH` | `./data/nvd.sqlite` | Database file |
| `CACHE_DIRECTORY` | `./data/cache` | JSON disk cache directory |
| `CACHE_STALE_RETENTION_SECONDS` | `604800` | Retain expired entries for outage fallback; `0` evicts at expiry |
| `CURSOR_SECRET` | random | HMAC key for cursors |
| `CURSOR_TTL_SECONDS` | `1800` | Cursor lifetime |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` / `silent` |

Keep API keys and cursor secrets out of source control and logs. When `CURSOR_SECRET` is
unset, a new secret is generated at startup, so previous cursors stop working after restart.

## Caching and rate limiting

- Fresh cache hits never call NVD. Expired entries are refreshed; upstream failures fall
  back to the stale copy with `meta.stale` and a warning in `meta.warnings`.
- Maintenance retains expired entries for seven extra days by default. Disk size limits
  may evict entries sooner.
- Concurrent identical requests are collapsed.
- Upstream calls are serialized, six seconds apart by default, and retried with backoff.
- Default files live under `./data`; migrations are applied at startup.

## Deadlines, cancellation and progress

Tool calls have an overall 120-second deadline, including queue waits, retry backoff and
multi-page fetches. Deadline errors use `REQUEST_TIMEOUT` with `details.scope: "tool"`.
Caller cancellation never triggers stale fallback.

Cancelling a call removes its queued work and aborts active HTTP I/O when no other caller
shares that fetch. Callers retain independent deadlines even when sharing upstream work.

Clients providing `_meta.progressToken` receive monotonic progress updates for upstream
attempts, retries and modified-feed pages. Notifications stop at completion or cancellation;
clients without a token receive none. A client may have its own shorter timeout: configure
that client to allow the desired tool deadline.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `startup_failed: Failed to configure the SQLite database` | Give each instance its own `SQLITE_PATH` and `CACHE_DIRECTORY` |
| `startup_failed: Invalid environment configuration` | Fix the value named in the stderr JSON |
| `UPSTREAM_RATE_LIMITED` / `UPSTREAM_UNAVAILABLE` | Set `NVD_API_KEY`; cached entries are still served |
| `UPSTREAM_BAD_RESPONSE` with `details.status: 404` on every tool | `NVD_API_KEY` is likely invalid/expired; drop it or issue a new key |
| `REQUEST_TIMEOUT` with `details.scope: "tool"` | Narrow the query or adjust server and client deadlines |
| `RESPONSE_TOO_LARGE` | Reduce `pageSize` or `fields`; omit raw payloads, configurations or references |
| No output when running by hand | It is a stdio server waiting for JSON-RPC on stdin |
