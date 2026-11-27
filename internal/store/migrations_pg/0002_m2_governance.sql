ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS guardrail_action TEXT NOT NULL DEFAULT '';
ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS guardrail_hits_json JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_usage_logs_guardrail_action ON usage_logs(guardrail_action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_status_created_at ON usage_logs(status_code, created_at DESC);

CREATE TABLE IF NOT EXISTS budgets (
    scope TEXT PRIMARY KEY,
    rpm INTEGER NOT NULL DEFAULT 0,
    tpm BIGINT NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 0,
    daily_usd DOUBLE PRECISION,
    monthly_usd DOUBLE PRECISION,
    soft_alert_pct INTEGER NOT NULL DEFAULT 80,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS guardrail_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'custom',
    pattern TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'redact',
    builtin BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    type TEXT NOT NULL,
    secret_enc TEXT NOT NULL DEFAULT '',
    events_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    timeout_ms INTEGER NOT NULL DEFAULT 2000,
    fail_open BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_settings (
    key TEXT PRIMARY KEY,
    value_json JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
