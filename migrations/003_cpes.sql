-- 003_cpes.sql — Official CPE Dictionary cache.

CREATE TABLE IF NOT EXISTS cpes (
    cpe_name_id TEXT PRIMARY KEY,
    cpe_name TEXT NOT NULL,
    deprecated INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_modified_at TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cpes_cpe_name ON cpes (cpe_name);
CREATE INDEX IF NOT EXISTS idx_cpes_last_modified_at ON cpes (last_modified_at);
CREATE INDEX IF NOT EXISTS idx_cpes_deprecated ON cpes (deprecated);
