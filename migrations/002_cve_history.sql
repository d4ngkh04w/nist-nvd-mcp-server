-- 002_cve_history.sql — CVE change history cache.

CREATE TABLE IF NOT EXISTS cve_history (
    change_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    event_name TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    created_at TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_history_cve_id ON cve_history (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_history_created_at ON cve_history (created_at);
