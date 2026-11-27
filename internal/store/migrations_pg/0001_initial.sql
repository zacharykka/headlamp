CREATE TABLE IF NOT EXISTS providers (
    name TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    base_url TEXT NOT NULL,
    api_key_enc TEXT NOT NULL DEFAULT '',
    passthrough BOOLEAN NOT NULL DEFAULT FALSE,
    models_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS model_routes (
    alias TEXT PRIMARY KEY,
    provider_name TEXT NOT NULL REFERENCES providers(name) ON DELETE CASCADE,
    upstream_model TEXT NOT NULL,
    fallbacks_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    input_cost_per_million DOUBLE PRECISION,
    output_cost_per_million DOUBLE PRECISION,
    cache_read_cost_per_million DOUBLE PRECISION,
    cache_write_cost_per_million DOUBLE PRECISION,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_model_routes_provider ON model_routes(provider_name);

CREATE TABLE IF NOT EXISTS usage_logs (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    node_name TEXT NOT NULL DEFAULT '',
    node_ip TEXT NOT NULL DEFAULT '',
    tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    auth_source TEXT NOT NULL DEFAULT '',
    provider_name TEXT NOT NULL,
    provider_type TEXT NOT NULL DEFAULT '',
    requested_model TEXT NOT NULL,
    upstream_model TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    endpoint TEXT NOT NULL DEFAULT '',
    stream BOOLEAN NOT NULL DEFAULT FALSE,
    translated BOOLEAN NOT NULL DEFAULT FALSE,
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    cache_read_tokens BIGINT NOT NULL DEFAULT 0,
    cache_write_tokens BIGINT NOT NULL DEFAULT 0,
    reasoning_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    latency_ms BIGINT NOT NULL DEFAULT 0,
    ttft_ms BIGINT NOT NULL DEFAULT 0,
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
    created_at TIMESTAMPTZ NOT NULL,
    request_headers_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_body TEXT NOT NULL DEFAULT '',
    response_headers_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_body TEXT NOT NULL DEFAULT '',
    redacted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_audit_payloads_created_at ON audit_payloads(created_at);
