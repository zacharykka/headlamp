-- Normalize legacy variable-width RFC3339 / RFC3339Nano UTC timestamps (< 30 chars)
-- to fixed-width 9-digit nanosecond UTC format (2006-01-02T15:04:05.000000000Z) so
-- SQLite lexical >= / <= / ORDER BY comparisons remain exact across midnight and sub-second boundaries.

UPDATE usage_logs
SET created_at = CASE
    WHEN length(created_at) = 20 AND substr(created_at, 20, 1) = 'Z'
        THEN substr(created_at, 1, 19) || '.000000000Z'
    WHEN length(created_at) > 20 AND length(created_at) < 30 AND substr(created_at, 20, 1) = '.'
        THEN substr(created_at, 1, 20) || substr(rtrim(substr(created_at, 21), 'Z') || '000000000', 1, 9) || 'Z'
    ELSE created_at
END
WHERE length(created_at) < 30 AND created_at LIKE '%Z';

UPDATE audit_payloads
SET created_at = CASE
    WHEN length(created_at) = 20 AND substr(created_at, 20, 1) = 'Z'
        THEN substr(created_at, 1, 19) || '.000000000Z'
    WHEN length(created_at) > 20 AND length(created_at) < 30 AND substr(created_at, 20, 1) = '.'
        THEN substr(created_at, 1, 20) || substr(rtrim(substr(created_at, 21), 'Z') || '000000000', 1, 9) || 'Z'
    ELSE created_at
END
WHERE length(created_at) < 30 AND created_at LIKE '%Z';

UPDATE mcp_audit_logs
SET created_at = CASE
    WHEN length(created_at) = 20 AND substr(created_at, 20, 1) = 'Z'
        THEN substr(created_at, 1, 19) || '.000000000Z'
    WHEN length(created_at) > 20 AND length(created_at) < 30 AND substr(created_at, 20, 1) = '.'
        THEN substr(created_at, 1, 20) || substr(rtrim(substr(created_at, 21), 'Z') || '000000000', 1, 9) || 'Z'
    ELSE created_at
END
WHERE length(created_at) < 30 AND created_at LIKE '%Z';

UPDATE chat_sessions
SET created_at = CASE
    WHEN length(created_at) = 20 AND substr(created_at, 20, 1) = 'Z'
        THEN substr(created_at, 1, 19) || '.000000000Z'
    WHEN length(created_at) > 20 AND length(created_at) < 30 AND substr(created_at, 20, 1) = '.'
        THEN substr(created_at, 1, 20) || substr(rtrim(substr(created_at, 21), 'Z') || '000000000', 1, 9) || 'Z'
    ELSE created_at
END
WHERE length(created_at) < 30 AND created_at LIKE '%Z';

UPDATE chat_sessions
SET updated_at = CASE
    WHEN length(updated_at) = 20 AND substr(updated_at, 20, 1) = 'Z'
        THEN substr(updated_at, 1, 19) || '.000000000Z'
    WHEN length(updated_at) > 20 AND length(updated_at) < 30 AND substr(updated_at, 20, 1) = '.'
        THEN substr(updated_at, 1, 20) || substr(rtrim(substr(updated_at, 21), 'Z') || '000000000', 1, 9) || 'Z'
    ELSE updated_at
END
WHERE length(updated_at) < 30 AND updated_at LIKE '%Z';

UPDATE chat_messages
SET created_at = CASE
    WHEN length(created_at) = 20 AND substr(created_at, 20, 1) = 'Z'
        THEN substr(created_at, 1, 19) || '.000000000Z'
    WHEN length(created_at) > 20 AND length(created_at) < 30 AND substr(created_at, 20, 1) = '.'
        THEN substr(created_at, 1, 20) || substr(rtrim(substr(created_at, 21), 'Z') || '000000000', 1, 9) || 'Z'
    ELSE created_at
END
WHERE length(created_at) < 30 AND created_at LIKE '%Z';
