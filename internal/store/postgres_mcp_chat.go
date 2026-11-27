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

func (s *PostgresStore) UpsertMCPServer(ctx context.Context, srv MCPServer) error {
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
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
		tokenEnc, srv.Enabled, source, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: upsert mcp server %q: %w", name, err)
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) GetMCPServer(ctx context.Context, name string) (*MCPServer, error) {
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

func (s *PostgresStore) ListMCPServers(ctx context.Context) ([]MCPServer, error) {
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

func (s *PostgresStore) DeleteMCPServer(ctx context.Context, name string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM mcp_servers WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("store: delete mcp server %q: %w", name, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) scanMCPServer(sc scanner) (MCPServer, error) {
	var (
		m        MCPServer
		tokenEnc string
	)
	if err := sc.Scan(
		&m.Name, &m.URL, &m.Transport, &m.AuthType, &m.AuthHeader,
		&tokenEnc, &m.Enabled, &m.Source, &m.CreatedAt, &m.UpdatedAt,
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
	m.CreatedAt = m.CreatedAt.UTC()
	m.UpdatedAt = m.UpdatedAt.UTC()
	return m, nil
}

// --- MCP Audit Logs ---

func (s *PostgresStore) InsertMCPAuditLog(ctx context.Context, log MCPAuditLog) error {
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
	tagsJSON = string(stripPostgresJSONNUL([]byte(tagsJSON)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_audit_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, server_name, method, tool_name, status,
	latency_ms, error_message, arguments_preview
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14, $15, $16)`,
		stripPostgresNUL(log.ID), createdAt, stripPostgresNUL(log.RequestID), stripPostgresNUL(log.Subject),
		stripPostgresNUL(log.DisplayName), stripPostgresNUL(log.NodeName), stripPostgresNUL(log.NodeIP),
		tagsJSON, stripPostgresNUL(log.AuthSource), stripPostgresNUL(log.ServerName),
		stripPostgresNUL(log.Method), stripPostgresNUL(log.ToolName), stripPostgresNUL(log.Status),
		log.LatencyMS, stripPostgresNUL(log.ErrorMessage), stripPostgresNUL(log.ArgumentsPreview),
	)
	if err != nil {
		return fmt.Errorf("store: insert mcp audit log %q: %w", log.ID, err)
	}
	return nil
}

func (s *PostgresStore) QueryMCPAuditLogs(ctx context.Context, filter MCPAuditFilter) ([]MCPAuditLog, error) {
	where, args := pgBuildMCPAuditWhere(filter)
	query := `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json::text, auth_source, server_name, method, tool_name, status,
       latency_ms, error_message, arguments_preview
FROM mcp_audit_logs` + where + ` ORDER BY created_at DESC, id DESC`

	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf(` LIMIT $%d`, len(args))
		if filter.Offset > 0 {
			args = append(args, filter.Offset)
			query += fmt.Sprintf(` OFFSET $%d`, len(args))
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres mcp audit logs: %w", err)
	}
	defer rows.Close()

	var out []MCPAuditLog
	for rows.Next() {
		log, err := pgScanMCPAuditLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func pgBuildMCPAuditWhere(filter MCPAuditFilter) (string, []any) {
	var clauses []string
	var args []any
	add := func(condFmt string, val any) {
		args = append(args, val)
		clauses = append(clauses, fmt.Sprintf(condFmt, len(args)))
	}

	if filter.ServerName != "" {
		add("server_name = $%d", filter.ServerName)
	}
	if filter.Subject != "" {
		add("subject = $%d", filter.Subject)
	}
	if filter.ToolName != "" {
		add("tool_name = $%d", filter.ToolName)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if !filter.Since.IsZero() {
		add("created_at >= $%d", filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		add("created_at <= $%d", filter.Until.UTC())
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func pgScanMCPAuditLog(sc scanner) (MCPAuditLog, error) {
	var (
		log      MCPAuditLog
		tagsJSON string
	)
	if err := sc.Scan(
		&log.ID, &log.CreatedAt, &log.RequestID, &log.Subject, &log.DisplayName,
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
	log.CreatedAt = log.CreatedAt.UTC()
	return log, nil
}

// --- Chat Sessions & Messages ---

func (s *PostgresStore) CreateChatSession(ctx context.Context, session ChatSession) (*ChatSession, error) {
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
	mcpJSON = string(stripPostgresJSONNUL([]byte(mcpJSON)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO chat_sessions (id, subject, title, model, mcp_servers_json, system_prompt, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)`,
		stripPostgresNUL(session.ID), stripPostgresNUL(session.Subject), stripPostgresNUL(session.Title),
		stripPostgresNUL(session.Model), mcpJSON, stripPostgresNUL(session.SystemPrompt),
		session.CreatedAt, session.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("store: create chat session %q: %w", session.ID, err)
	}
	return s.GetChatSession(ctx, subject, session.ID)
}

func (s *PostgresStore) GetChatSession(ctx context.Context, subject, id string) (*ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(id) == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, subject, title, model, mcp_servers_json::text, system_prompt, created_at, updated_at
FROM chat_sessions WHERE id = $1 AND subject = $2`, id, subject)
	sess, err := pgScanChatSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get chat session %q: %w", id, err)
	}
	return &sess, nil
}

func (s *PostgresStore) ListChatSessions(ctx context.Context, subject string, limit, offset int) ([]ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, nil
	}
	query := `
SELECT id, subject, title, model, mcp_servers_json::text, system_prompt, created_at, updated_at
FROM chat_sessions WHERE subject = $1 ORDER BY updated_at DESC, created_at DESC, id DESC`
	args := []any{subject}
	if limit > 0 {
		args = append(args, limit)
		query += fmt.Sprintf(` LIMIT $%d`, len(args))
		if offset > 0 {
			args = append(args, offset)
			query += fmt.Sprintf(` OFFSET $%d`, len(args))
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list postgres chat sessions: %w", err)
	}
	defer rows.Close()

	var out []ChatSession
	for rows.Next() {
		sess, err := pgScanChatSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateChatSession(ctx context.Context, subject string, session ChatSession) (*ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(session.ID) == "" {
		return nil, ErrNotFound
	}
	mcpJSON, err := marshalStringSlice(session.MCPServers)
	if err != nil {
		return nil, fmt.Errorf("store: encode chat session mcp_servers: %w", err)
	}
	mcpJSON = string(stripPostgresJSONNUL([]byte(mcpJSON)))
	res, err := s.db.ExecContext(ctx, `
UPDATE chat_sessions
SET title = $1, model = $2, mcp_servers_json = $3::jsonb, system_prompt = $4, updated_at = $5
WHERE id = $6 AND subject = $7`,
		stripPostgresNUL(session.Title), stripPostgresNUL(session.Model), mcpJSON,
		stripPostgresNUL(session.SystemPrompt), time.Now().UTC(), session.ID, subject,
	)
	if err != nil {
		return nil, fmt.Errorf("store: update chat session %q: %w", session.ID, err)
	}
	if err := checkAffected(res); err != nil {
		return nil, err
	}
	return s.GetChatSession(ctx, subject, session.ID)
}

func (s *PostgresStore) DeleteChatSession(ctx context.Context, subject, id string) error {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(id) == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM chat_sessions WHERE id = $1 AND subject = $2`, id, subject)
	if err != nil {
		return fmt.Errorf("store: delete chat session %q: %w", id, err)
	}
	return checkAffected(res)
}

func (s *PostgresStore) InsertChatMessage(ctx context.Context, subject string, msg ChatMessage) (*ChatMessage, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(msg.SessionID) == "" {
		return nil, ErrNotFound
	}
	if strings.TrimSpace(msg.ID) == "" {
		msg.ID = uuid.NewString()
	}
	msg.Role = stripPostgresNUL(msg.Role)
	msg.Content = stripPostgresNUL(msg.Content)
	msg.Model = stripPostgresNUL(msg.Model)
	if msg.ToolEvents == nil {
		msg.ToolEvents = []ChatToolEvent{}
	} else {
		cleaned := make([]ChatToolEvent, len(msg.ToolEvents))
		for i, ev := range msg.ToolEvents {
			ev.ID = stripPostgresNUL(ev.ID)
			ev.Server = stripPostgresNUL(ev.Server)
			ev.Tool = stripPostgresNUL(ev.Tool)
			ev.Result = stripPostgresNUL(ev.Result)
			if len(ev.Arguments) > 0 {
				ev.Arguments = stripPostgresJSONNUL(ev.Arguments)
			}
			cleaned[i] = ev
		}
		msg.ToolEvents = cleaned
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
	eventsJSON = string(stripPostgresJSONNUL([]byte(eventsJSON)))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin insert chat message: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM chat_sessions WHERE id = $1 AND subject = $2`, msg.SessionID, subject).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: verify chat session ownership: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO chat_messages (id, session_id, role, content, tool_events_json, model, input_tokens, output_tokens, cost_usd, created_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)`,
		stripPostgresNUL(msg.ID), stripPostgresNUL(msg.SessionID), msg.Role, msg.Content, eventsJSON,
		msg.Model, msg.InputTokens, msg.OutputTokens, msg.CostUSD, createdAt,
	); err != nil {
		return nil, fmt.Errorf("store: insert chat message %q: %w", msg.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE chat_sessions SET updated_at = $1 WHERE id = $2 AND subject = $3`,
		time.Now().UTC(), msg.SessionID, subject,
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

func (s *PostgresStore) ListChatMessages(ctx context.Context, subject, sessionID string) ([]ChatMessage, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(sessionID) == "" {
		return nil, ErrNotFound
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM chat_sessions WHERE id = $1 AND subject = $2`, sessionID, subject).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: verify chat session ownership: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, role, content, tool_events_json::text, model, input_tokens, output_tokens, cost_usd, created_at
FROM chat_messages WHERE session_id = $1 ORDER BY created_at ASC, seq ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store: list postgres chat messages: %w", err)
	}
	defer rows.Close()

	var out []ChatMessage
	for rows.Next() {
		m, err := pgScanChatMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) DeleteChatMessage(ctx context.Context, subject, sessionID, messageID string) error {
	subject = strings.TrimSpace(subject)
	sessionID = strings.TrimSpace(sessionID)
	messageID = strings.TrimSpace(messageID)
	if subject == "" || sessionID == "" || messageID == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `
DELETE FROM chat_messages
WHERE id = $1 AND session_id = $2
  AND EXISTS (SELECT 1 FROM chat_sessions WHERE id = $2 AND subject = $3)`,
		messageID, sessionID, subject,
	)
	if err != nil {
		return fmt.Errorf("store: delete postgres chat message %q: %w", messageID, err)
	}
	return checkAffected(res)
}

func pgScanChatSession(sc scanner) (ChatSession, error) {
	var (
		sess    ChatSession
		mcpJSON string
	)
	if err := sc.Scan(
		&sess.ID, &sess.Subject, &sess.Title, &sess.Model,
		&mcpJSON, &sess.SystemPrompt, &sess.CreatedAt, &sess.UpdatedAt,
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
	sess.CreatedAt = sess.CreatedAt.UTC()
	sess.UpdatedAt = sess.UpdatedAt.UTC()
	return sess, nil
}

func pgScanChatMessage(sc scanner) (ChatMessage, error) {
	var (
		msg        ChatMessage
		eventsJSON string
	)
	if err := sc.Scan(
		&msg.ID, &msg.SessionID, &msg.Role, &msg.Content, &eventsJSON,
		&msg.Model, &msg.InputTokens, &msg.OutputTokens, &msg.CostUSD, &msg.CreatedAt,
	); err != nil {
		return ChatMessage{}, err
	}
	events, err := unmarshalChatToolEvents(eventsJSON)
	if err != nil {
		return ChatMessage{}, fmt.Errorf("store: decode chat tool_events: %w", err)
	}
	msg.ToolEvents = events
	msg.CreatedAt = msg.CreatedAt.UTC()
	return msg, nil
}
