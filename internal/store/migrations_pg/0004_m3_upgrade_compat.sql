ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS seq BIGSERIAL NOT NULL;

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_seq ON chat_messages(session_id, created_at ASC, seq ASC);
