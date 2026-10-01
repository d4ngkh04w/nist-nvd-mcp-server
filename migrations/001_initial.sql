-- 001_initial.sql — migration registry, metadata and the core CVE/query cache tables.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    source_identifier TEXT NOT NULL,
    published_at TEXT NOT NULL,
    last_modified_at TEXT NOT NULL,
    vuln_status TEXT,
    summary TEXT,
    primary_cvss_version TEXT,
    primary_cvss_score REAL,
    primary_cvss_severity TEXT,
    primary_cvss_vector TEXT,
    is_known_exploited INTEGER NOT NULL DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    raw_json TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS query_cache (
    cache_key TEXT PRIMARY KEY,
    resource TEXT NOT NULL,
    query_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    byte_size INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cves_published_at ON cves (published_at);
CREATE INDEX IF NOT EXISTS idx_cves_last_modified_at ON cves (last_modified_at);
CREATE INDEX IF NOT EXISTS idx_cves_primary_cvss_severity ON cves (primary_cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cves_is_known_exploited ON cves (is_known_exploited);
CREATE INDEX IF NOT EXISTS idx_cves_vuln_status ON cves (vuln_status);

CREATE INDEX IF NOT EXISTS idx_query_cache_expires_at ON query_cache (expires_at);
CREATE INDEX IF NOT EXISTS idx_query_cache_resource ON query_cache (resource);
