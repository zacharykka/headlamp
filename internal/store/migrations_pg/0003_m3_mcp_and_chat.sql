CREATE TABLE IF NOT EXISTS mcp_servers (
    name TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    transport TEXT NOT NULL DEFAULT 'streamable_http',
    auth_type TEXT NOT NULL DEFAULT 'none',
    auth_header TEXT NOT NULL DEFAULT '',
    auth_token_enc TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_audit_logs (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    node_name TEXT NOT NULL DEFAULT '',
    node_ip TEXT NOT NULL DEFAULT '',
    tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    auth_source TEXT NOT NULL DEFAULT '',
    server_name TEXT NOT NULL,
    method TEXT NOT NULL,
    tool_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    latency_ms BIGINT NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    arguments_preview TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_created_at ON mcp_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_server_created_at ON mcp_audit_logs(server_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_subject_created_at ON mcp_audit_logs(subject, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_status_created_at ON mcp_audit_logs(status, created_at DESC);

CREATE TABLE IF NOT EXISTS chat_sessions (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    mcp_servers_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    system_prompt TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_subject_updated_at ON chat_sessions(subject, updated_at DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    tool_events_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    model TEXT NOT NULL DEFAULT '',
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_created_at ON chat_messages(session_id, created_at ASC);
