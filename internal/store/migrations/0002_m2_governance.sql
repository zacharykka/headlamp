ALTER TABLE usage_logs ADD COLUMN guardrail_action TEXT NOT NULL DEFAULT '';
ALTER TABLE usage_logs ADD COLUMN guardrail_hits_json TEXT NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_usage_logs_guardrail_action ON usage_logs(guardrail_action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_status_created_at ON usage_logs(status_code, created_at DESC);

CREATE TABLE IF NOT EXISTS budgets (
    scope TEXT PRIMARY KEY,
    rpm INTEGER NOT NULL DEFAULT 0,
    tpm INTEGER NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 0,
    daily_usd REAL,
    monthly_usd REAL,
    soft_alert_pct INTEGER NOT NULL DEFAULT 80,
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS guardrail_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'custom',
    pattern TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'redact',
    builtin INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    type TEXT NOT NULL,
    secret_enc TEXT NOT NULL DEFAULT '',
    events_json TEXT NOT NULL DEFAULT '[]',
    timeout_ms INTEGER NOT NULL DEFAULT 2000,
    fail_open INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
