package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/config"
)

// --- MCP Servers ---

func (s *SQLiteStore) UpsertMCPServer(ctx context.Context, srv MCPServer) error {
	name := strings.TrimSpace(srv.Name)
	if name == "" {
		return errors.New("store: mcp server name is required")
	}
	if strings.Contains(name, "/") {
		return errors.New("store: mcp server name must not contain '/'")
	}
	transport := strings.ToLower(strings.TrimSpace(srv.Transport))
	if transport == "" {
		transport = config.MCPTransportStreamableHTTP
	}
	authType := strings.ToLower(strings.TrimSpace(srv.AuthType))
	if authType == "" {
		authType = config.MCPAuthNone
	}

	tokenEnc := ""
	if authType != config.MCPAuthNone && srv.AuthToken != "" {
		var err error
		tokenEnc, err = s.cipher.EncryptString(srv.AuthToken)
		if err != nil {
			return fmt.Errorf("store: encrypt auth token for mcp server %q: %w", name, err)
		}
	}

	now := time.Now().UTC()
	source := defaultSource(srv.Source)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO mcp_servers (name, url, transport, auth_type, auth_header, auth_token_enc, enabled, source, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
	url = excluded.url,
	transport = excluded.transport,
	auth_type = excluded.auth_type,
	auth_header = excluded.auth_header,
	auth_token_enc = excluded.auth_token_enc,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		name, strings.TrimSpace(srv.URL), transport, authType, strings.TrimSpace(srv.AuthHeader),
		tokenEnc, boolToInt(srv.Enabled), source, formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert mcp server %q: %w", name, err)
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) GetMCPServer(ctx context.Context, name string) (*MCPServer, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	m, ok := snap.mcpServersByName[name]
	if !ok {
		return nil, ErrNotFound
	}
	cp := cloneMCPServer(m)
	return &cp, nil
}

func (s *SQLiteStore) ListMCPServers(ctx context.Context) ([]MCPServer, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.mcpServers) == 0 {
		return nil, nil
	}
	out := make([]MCPServer, len(snap.mcpServers))
	for i, m := range snap.mcpServers {
		out[i] = cloneMCPServer(m)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteMCPServer(ctx context.Context, name string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM mcp_servers WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete mcp server %q: %w", name, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) scanMCPServer(sc scanner) (MCPServer, error) {
	var (
		m            MCPServer
		tokenEnc     string
		enabled      int
		createdAtStr string
		updatedAtStr string
	)
	if err := sc.Scan(
		&m.Name, &m.URL, &m.Transport, &m.AuthType, &m.AuthHeader,
		&tokenEnc, &enabled, &m.Source, &createdAtStr, &updatedAtStr,
	); err != nil {
		return MCPServer{}, err
	}
	if tokenEnc != "" {
		dec, err := s.cipher.DecryptString(tokenEnc)
		if err != nil {
			return MCPServer{}, fmt.Errorf("store: decrypt auth token for mcp server %q: %w", m.Name, err)
		}
		m.AuthToken = dec
	}
	m.Enabled = enabled != 0
	m.CreatedAt = parseTime(createdAtStr)
	m.UpdatedAt = parseTime(updatedAtStr)
	return m, nil
}

// --- MCP Audit Logs ---

func (s *SQLiteStore) InsertMCPAuditLog(ctx context.Context, log MCPAuditLog) error {
	if strings.TrimSpace(log.ID) == "" {
		log.ID = uuid.NewString()
	}
	createdAt := log.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	tagsJSON, err := marshalStringSlice(log.Tags)
	if err != nil {
		return fmt.Errorf("store: encode mcp audit tags: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_audit_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, server_name, method, tool_name, status,
	latency_ms, error_message, arguments_preview
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID, formatTime(createdAt), log.RequestID, log.Subject, log.DisplayName,
		log.NodeName, log.NodeIP, tagsJSON, log.AuthSource, log.ServerName,
		log.Method, log.ToolName, log.Status, log.LatencyMS, log.ErrorMessage,
		log.ArgumentsPreview,
	)
	if err != nil {
		return fmt.Errorf("store: insert mcp audit log %q: %w", log.ID, err)
	}
	return nil
}

func (s *SQLiteStore) QueryMCPAuditLogs(ctx context.Context, filter MCPAuditFilter) ([]MCPAuditLog, error) {
	where, args := buildMCPAuditWhere(filter)
	query := `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json, auth_source, server_name, method, tool_name, status,
       latency_ms, error_message, arguments_preview
FROM mcp_audit_logs` + where + ` ORDER BY created_at DESC, id DESC`

	if filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += ` OFFSET ?`
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query mcp audit logs: %w", err)
	}
	defer rows.Close()

	var out []MCPAuditLog
	for rows.Next() {
		log, err := scanMCPAuditLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func buildMCPAuditWhere(filter MCPAuditFilter) (string, []any) {
	var clauses []string
	var args []any

	if filter.ServerName != "" {
		clauses = append(clauses, "server_name = ?")
		args = append(args, filter.ServerName)
	}
	if filter.Subject != "" {
		clauses = append(clauses, "subject = ?")
		args = append(args, filter.Subject)
	}
	if filter.ToolName != "" {
		clauses = append(clauses, "tool_name = ?")
		args = append(args, filter.ToolName)
	}
	if filter.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, filter.Status)
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, "created_at >= ?")
		args = append(args, formatTime(filter.Since.UTC()))
	}
	if !filter.Until.IsZero() {
		clauses = append(clauses, "created_at <= ?")
		args = append(args, formatTime(filter.Until.UTC()))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func scanMCPAuditLog(sc scanner) (MCPAuditLog, error) {
	var (
		log          MCPAuditLog
		createdAtStr string
		tagsJSON     string
	)
	if err := sc.Scan(
		&log.ID, &createdAtStr, &log.RequestID, &log.Subject, &log.DisplayName,
		&log.NodeName, &log.NodeIP, &tagsJSON, &log.AuthSource, &log.ServerName,
		&log.Method, &log.ToolName, &log.Status, &log.LatencyMS, &log.ErrorMessage,
		&log.ArgumentsPreview,
	); err != nil {
		return MCPAuditLog{}, err
	}
	tags, err := unmarshalStringSlice(tagsJSON)
	if err != nil {
		return MCPAuditLog{}, err
	}
	log.Tags = tags
	log.CreatedAt = parseTime(createdAtStr)
	return log, nil
}

// --- Chat Sessions & Messages ---

func (s *SQLiteStore) CreateChatSession(ctx context.Context, session ChatSession) (*ChatSession, error) {
	subject := strings.TrimSpace(session.Subject)
	if subject == "" {
		return nil, errors.New("store: chat session subject is required")
	}
	if strings.TrimSpace(session.ID) == "" {
		session.ID = uuid.NewString()
	}
	session.Subject = subject
	if session.MCPServers == nil {
		session.MCPServers = []string{}
	}
	now := time.Now().UTC()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	} else {
		session.CreatedAt = session.CreatedAt.UTC()
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = session.CreatedAt
	} else {
		session.UpdatedAt = session.UpdatedAt.UTC()
	}

	mcpJSON, err := marshalStringSlice(session.MCPServers)
	if err != nil {
		return nil, fmt.Errorf("store: encode chat session mcp_servers: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO chat_sessions (id, subject, title, model, mcp_servers_json, system_prompt, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.Subject, session.Title, session.Model,
		mcpJSON, session.SystemPrompt, formatTime(session.CreatedAt), formatTime(session.UpdatedAt),
	)
	if err != nil {
		return nil, fmt.Errorf("store: create chat session %q: %w", session.ID, err)
	}
	return s.GetChatSession(ctx, subject, session.ID)
}

func (s *SQLiteStore) GetChatSession(ctx context.Context, subject, id string) (*ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(id) == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, subject, title, model, mcp_servers_json, system_prompt, created_at, updated_at
FROM chat_sessions WHERE id = ? AND subject = ?`, id, subject)
	sess, err := scanChatSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get chat session %q: %w", id, err)
	}
	return &sess, nil
}

func (s *SQLiteStore) ListChatSessions(ctx context.Context, subject string, limit, offset int) ([]ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, nil
	}
	query := `
SELECT id, subject, title, model, mcp_servers_json, system_prompt, created_at, updated_at
FROM chat_sessions WHERE subject = ? ORDER BY updated_at DESC, created_at DESC, id DESC`
	args := []any{subject}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
		if offset > 0 {
			query += ` OFFSET ?`
			args = append(args, offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list chat sessions: %w", err)
	}
	defer rows.Close()

	var out []ChatSession
	for rows.Next() {
		sess, err := scanChatSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateChatSession(ctx context.Context, subject string, session ChatSession) (*ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(session.ID) == "" {
		return nil, ErrNotFound
	}
	mcpJSON, err := marshalStringSlice(session.MCPServers)
	if err != nil {
		return nil, fmt.Errorf("store: encode chat session mcp_servers: %w", err)
	}
	nowStr := formatTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE chat_sessions
SET title = ?, model = ?, mcp_servers_json = ?, system_prompt = ?, updated_at = ?
WHERE id = ? AND subject = ?`,
		session.Title, session.Model, mcpJSON, session.SystemPrompt, nowStr, session.ID, subject,
	)
	if err != nil {
		return nil, fmt.Errorf("store: update chat session %q: %w", session.ID, err)
	}
	if err := checkAffected(res); err != nil {
		return nil, err
	}
	return s.GetChatSession(ctx, subject, session.ID)
}

func (s *SQLiteStore) DeleteChatSession(ctx context.Context, subject, id string) error {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(id) == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM chat_sessions WHERE id = ? AND subject = ?`, id, subject)
	if err != nil {
		return fmt.Errorf("store: delete chat session %q: %w", id, err)
	}
	return checkAffected(res)
}

func (s *SQLiteStore) InsertChatMessage(ctx context.Context, subject string, msg ChatMessage) (*ChatMessage, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(msg.SessionID) == "" {
		return nil, ErrNotFound
	}
	if strings.TrimSpace(msg.ID) == "" {
		msg.ID = uuid.NewString()
	}
	if msg.ToolEvents == nil {
		msg.ToolEvents = []ChatToolEvent{}
	}
	createdAt := msg.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	msg.CreatedAt = createdAt

	eventsJSON, err := marshalChatToolEvents(msg.ToolEvents)
	if err != nil {
		return nil, fmt.Errorf("store: encode chat tool_events: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin insert chat message: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Enforce strict per-subject ownership before inserting.
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM chat_sessions WHERE id = ? AND subject = ?`, msg.SessionID, subject).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: verify chat session ownership: %w", err)
	}

	createdStr := formatTime(createdAt)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO chat_messages (id, session_id, role, content, tool_events_json, model, input_tokens, output_tokens, cost_usd, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.ID, msg.SessionID, msg.Role, msg.Content, eventsJSON,
		msg.Model, msg.InputTokens, msg.OutputTokens, msg.CostUSD, createdStr,
	); err != nil {
		return nil, fmt.Errorf("store: insert chat message %q: %w", msg.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE chat_sessions SET updated_at = ? WHERE id = ? AND subject = ?`,
		formatTime(time.Now().UTC()), msg.SessionID, subject,
	); err != nil {
		return nil, fmt.Errorf("store: touch chat session %q: %w", msg.SessionID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit insert chat message: %w", err)
	}
	cp := msg
	cp.ToolEvents = slices.Clone(msg.ToolEvents)
	return &cp, nil
}

func (s *SQLiteStore) ListChatMessages(ctx context.Context, subject, sessionID string) ([]ChatMessage, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(sessionID) == "" {
		return nil, ErrNotFound
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM chat_sessions WHERE id = ? AND subject = ?`, sessionID, subject).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: verify chat session ownership: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, role, content, tool_events_json, model, input_tokens, output_tokens, cost_usd, created_at
FROM chat_messages WHERE session_id = ? ORDER BY created_at ASC, rowid ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store: list chat messages: %w", err)
	}
	defer rows.Close()

	var out []ChatMessage
	for rows.Next() {
		m, err := scanChatMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteChatMessage(ctx context.Context, subject, sessionID, messageID string) error {
	subject = strings.TrimSpace(subject)
	sessionID = strings.TrimSpace(sessionID)
	messageID = strings.TrimSpace(messageID)
	if subject == "" || sessionID == "" || messageID == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `
DELETE FROM chat_messages
WHERE id = ? AND session_id = ?
  AND EXISTS (SELECT 1 FROM chat_sessions WHERE id = ? AND subject = ?)`,
		messageID, sessionID, sessionID, subject,
	)
	if err != nil {
		return fmt.Errorf("store: delete chat message %q: %w", messageID, err)
	}
	return checkAffected(res)
}

func scanChatSession(sc scanner) (ChatSession, error) {
	var (
		sess         ChatSession
		mcpJSON      string
		createdAtStr string
		updatedAtStr string
	)
	if err := sc.Scan(
		&sess.ID, &sess.Subject, &sess.Title, &sess.Model,
		&mcpJSON, &sess.SystemPrompt, &createdAtStr, &updatedAtStr,
	); err != nil {
		return ChatSession{}, err
	}
	servers, err := unmarshalStringSlice(mcpJSON)
	if err != nil {
		return ChatSession{}, fmt.Errorf("store: decode chat session mcp_servers: %w", err)
	}
	if servers == nil {
		servers = []string{}
	}
	sess.MCPServers = servers
	sess.CreatedAt = parseTime(createdAtStr)
	sess.UpdatedAt = parseTime(updatedAtStr)
	return sess, nil
}

func scanChatMessage(sc scanner) (ChatMessage, error) {
	var (
		msg          ChatMessage
		eventsJSON   string
		createdAtStr string
	)
	if err := sc.Scan(
		&msg.ID, &msg.SessionID, &msg.Role, &msg.Content, &eventsJSON,
		&msg.Model, &msg.InputTokens, &msg.OutputTokens, &msg.CostUSD, &createdAtStr,
	); err != nil {
		return ChatMessage{}, err
	}
	events, err := unmarshalChatToolEvents(eventsJSON)
	if err != nil {
		return ChatMessage{}, fmt.Errorf("store: decode chat tool_events: %w", err)
	}
	msg.ToolEvents = events
	msg.CreatedAt = parseTime(createdAtStr)
	return msg, nil
}
