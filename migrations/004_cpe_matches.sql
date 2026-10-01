-- 004_cpe_matches.sql — CPE Match Criteria cache.

CREATE TABLE IF NOT EXISTS cpe_matches (
    match_criteria_id TEXT PRIMARY KEY,
    criteria TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_modified_at TEXT NOT NULL,
    cpe_last_modified_at TEXT,
    normalized_json TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cpe_matches_criteria ON cpe_matches (criteria);
CREATE INDEX IF NOT EXISTS idx_cpe_matches_last_modified_at ON cpe_matches (last_modified_at);
CREATE INDEX IF NOT EXISTS idx_cpe_matches_status ON cpe_matches (status);
