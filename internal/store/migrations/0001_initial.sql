CREATE TABLE IF NOT EXISTS providers (
    name TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    base_url TEXT NOT NULL,
    api_key_enc TEXT NOT NULL DEFAULT '',
    passthrough INTEGER NOT NULL DEFAULT 0,
    models_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_routes (
    alias TEXT PRIMARY KEY,
    provider_name TEXT NOT NULL REFERENCES providers(name) ON DELETE CASCADE,
    upstream_model TEXT NOT NULL,
    fallbacks_json TEXT NOT NULL DEFAULT '[]',
    input_cost_per_million REAL,
    output_cost_per_million REAL,
    cache_read_cost_per_million REAL,
    cache_write_cost_per_million REAL,
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_model_routes_provider ON model_routes(provider_name);

CREATE TABLE IF NOT EXISTS usage_logs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    node_name TEXT NOT NULL DEFAULT '',
    node_ip TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    auth_source TEXT NOT NULL DEFAULT '',
    provider_name TEXT NOT NULL,
    provider_type TEXT NOT NULL DEFAULT '',
    requested_model TEXT NOT NULL,
    upstream_model TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    endpoint TEXT NOT NULL DEFAULT '',
    stream INTEGER NOT NULL DEFAULT 0,
    translated INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    ttft_ms INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_usage_logs_created_at ON usage_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_subject_created_at ON usage_logs(subject, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_provider_created_at ON usage_logs(provider_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_model_created_at ON usage_logs(requested_model, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_payloads (
    id TEXT PRIMARY KEY,
    usage_log_id TEXT NOT NULL UNIQUE REFERENCES usage_logs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    request_headers_json TEXT NOT NULL DEFAULT '{}',
    request_body TEXT NOT NULL DEFAULT '',
    response_headers_json TEXT NOT NULL DEFAULT '{}',
    response_body TEXT NOT NULL DEFAULT '',
    redacted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_payloads_created_at ON audit_payloads(created_at);
