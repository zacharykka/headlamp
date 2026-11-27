package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

// --- Runtime Settings ---

func (s *SQLiteStore) GetAuditSettings(ctx context.Context) (*AuditSettings, error) {
	var (
		valueJSON    string
		updatedAtStr string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT value_json, updated_at FROM runtime_settings WHERE key = ?`, runtimeSettingAuditKey).
		Scan(&valueJSON, &updatedAtStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get audit settings: %w", err)
	}

	var out AuditSettings
	if err := json.Unmarshal([]byte(valueJSON), &out); err != nil {
		return nil, fmt.Errorf("store: decode audit settings: %w", err)
	}
	out.UpdatedAt = parseTime(updatedAtStr)
	return &out, nil
}

func (s *SQLiteStore) SetAuditSettings(ctx context.Context, settings AuditSettings) error {
	if settings.RetentionDays < 0 {
		return fmt.Errorf("store: retention_days must be >= 0, got %d", settings.RetentionDays)
	}
	payload, err := json.Marshal(struct {
		StorePayloads bool `json:"store_payloads"`
		RetentionDays int  `json:"retention_days"`
	}{
		StorePayloads: settings.StorePayloads,
		RetentionDays: settings.RetentionDays,
	})
	if err != nil {
		return fmt.Errorf("store: encode audit settings: %w", err)
	}

	nowStr := formatTime(time.Now().UTC())
	_, err = s.db.ExecContext(ctx, `
INSERT INTO runtime_settings (key, value_json, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
	value_json = excluded.value_json,
	updated_at = excluded.updated_at`,
		runtimeSettingAuditKey, string(payload), nowStr,
	)
	if err != nil {
		return fmt.Errorf("store: set audit settings: %w", err)
	}
	return nil
}

// --- Usage Logs & Dashboard Analytics ---

func (s *SQLiteStore) InsertUsageLog(ctx context.Context, log UsageLog) error {
	if strings.TrimSpace(log.ID) == "" {
		log.ID = uuid.NewString()
	}
	createdAt := log.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	tagsJSON, err := marshalStringSlice(log.Tags)
	if err != nil {
		return fmt.Errorf("store: encode usage tags: %w", err)
	}
	hitsJSON, err := marshalStringSlice(log.GuardrailHits)
	if err != nil {
		return fmt.Errorf("store: encode guardrail hits: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO usage_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, provider_name, provider_type, requested_model,
	upstream_model, protocol, endpoint, stream, translated,
	input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
	reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
	status_code, error_message, guardrail_action, guardrail_hits_json
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID, formatTime(createdAt), log.RequestID, log.Subject, log.DisplayName,
		log.NodeName, log.NodeIP, tagsJSON, log.AuthSource, log.ProviderName,
		log.ProviderType, log.RequestedModel, log.UpstreamModel, log.Protocol,
		log.Endpoint, boolToInt(log.Stream), boolToInt(log.Translated),
		log.InputTokens, log.OutputTokens, log.CacheReadTokens, log.CacheWriteTokens,
		log.ReasoningTokens, log.TotalTokens, log.CostUSD, log.LatencyMS, log.TTFTMS,
		log.StatusCode, log.ErrorMessage, log.GuardrailAction, hitsJSON,
	)
	if err != nil {
		return fmt.Errorf("store: insert usage log %q: %w", log.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetUsageLog(ctx context.Context, id string) (*UsageLog, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json
FROM usage_logs WHERE id = ?`, id)

	log, err := scanUsageLog(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &log, nil
}

func (s *SQLiteStore) QueryUsageLogs(ctx context.Context, filter UsageFilter) ([]UsageLog, error) {
	where, args := buildUsageWhere(filter)
	query := `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json
FROM usage_logs` + where + ` ORDER BY created_at DESC, id DESC`

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
		return nil, fmt.Errorf("store: query usage logs: %w", err)
	}
	defer rows.Close()

	var out []UsageLog
	for rows.Next() {
		log, err := scanUsageLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SummarizeUsage(ctx context.Context, filter UsageFilter) (UsageSummary, error) {
	where, args := buildUsageWhere(filter)
	query := `
SELECT COUNT(*),
       COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cache_read_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0),
       COALESCE(SUM(reasoning_tokens), 0),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0)
FROM usage_logs` + where

	var sum UsageSummary
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&sum.RequestCount, &sum.InputTokens, &sum.OutputTokens,
		&sum.CacheReadTokens, &sum.CacheWriteTokens, &sum.ReasoningTokens,
		&sum.TotalTokens, &sum.CostUSD,
	); err != nil {
		return UsageSummary{}, fmt.Errorf("store: summarize usage: %w", err)
	}
	return sum, nil
}

func (s *SQLiteStore) SummarizeUsageExtended(ctx context.Context, filter UsageFilter) (UsageExtendedSummary, error) {
	where, args := buildUsageWhere(filter)
	query := `
SELECT COUNT(*),
       COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cache_read_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0),
       COALESCE(SUM(reasoning_tokens), 0),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0),
       COALESCE(SUM(CASE WHEN status_code >= 400 OR status_code = 0 OR error_message != '' THEN 1 ELSE 0 END), 0)
FROM usage_logs` + where

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return UsageExtendedSummary{}, fmt.Errorf("store: begin summarize usage extended tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var ext UsageExtendedSummary
	if err := tx.QueryRowContext(ctx, query, args...).Scan(
		&ext.RequestCount, &ext.InputTokens, &ext.OutputTokens,
		&ext.CacheReadTokens, &ext.CacheWriteTokens, &ext.ReasoningTokens,
		&ext.TotalTokens, &ext.CostUSD, &ext.ErrorCount,
	); err != nil {
		return UsageExtendedSummary{}, fmt.Errorf("store: summarize usage extended: %w", err)
	}

	if ext.RequestCount > 0 {
		offset := int64(math.Ceil(0.95*float64(ext.RequestCount))) - 1
		if offset < 0 {
			offset = 0
		}
		if offset >= ext.RequestCount {
			offset = ext.RequestCount - 1
		}
		p95Args := make([]any, 0, len(args)+1)
		p95Args = append(p95Args, args...)
		p95Args = append(p95Args, offset)
		p95Query := `SELECT latency_ms FROM usage_logs` + where + ` ORDER BY latency_ms ASC LIMIT 1 OFFSET ?`
		if err := tx.QueryRowContext(ctx, p95Query, p95Args...).Scan(&ext.P95LatencyMS); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return UsageExtendedSummary{}, fmt.Errorf("store: compute p95 latency: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return UsageExtendedSummary{}, fmt.Errorf("store: commit summarize usage extended tx: %w", err)
	}

	return ext, nil
}

func (s *SQLiteStore) QueryUsageSeries(ctx context.Context, filter UsageFilter, bucket string) ([]UsageTimeBucket, error) {
	var bucketExpr string
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "hour":
		bucketExpr = "substr(created_at, 1, 13) || ':00:00Z'"
	case "", "day":
		bucketExpr = "substr(created_at, 1, 10)"
	default:
		return nil, fmt.Errorf("store: invalid usage series bucket %q (must be hour or day)", bucket)
	}

	where, args := buildUsageWhere(filter)
	query := fmt.Sprintf(`
SELECT %s AS bucket,
       COUNT(*),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0),
       COALESCE(SUM(CASE WHEN status_code >= 400 OR status_code = 0 OR error_message != '' THEN 1 ELSE 0 END), 0)
FROM usage_logs%s
GROUP BY bucket
ORDER BY bucket ASC`, bucketExpr, where)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query usage series: %w", err)
	}
	defer rows.Close()

	var out []UsageTimeBucket
	for rows.Next() {
		var b UsageTimeBucket
		if err := rows.Scan(&b.Bucket, &b.Requests, &b.Tokens, &b.CostUSD, &b.Errors); err != nil {
			return nil, fmt.Errorf("store: scan usage series bucket: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) QueryTopSubjects(ctx context.Context, filter UsageFilter, limit int) ([]SubjectUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := buildUsageWhere(filter)
	args = append(args, limit)
	query := `
SELECT subject,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs` + where + `
GROUP BY subject
ORDER BY total_cost DESC, req_count DESC, subject ASC
LIMIT ?`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query top subjects: %w", err)
	}
	defer rows.Close()

	var out []SubjectUsageStat
	for rows.Next() {
		var st SubjectUsageStat
		if err := rows.Scan(&st.Subject, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan top subject: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) QueryTopModels(ctx context.Context, filter UsageFilter, limit int) ([]ModelUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := buildUsageWhere(filter)
	args = append(args, limit)
	query := `
SELECT requested_model,
       provider_name,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs` + where + `
GROUP BY requested_model, provider_name
ORDER BY total_cost DESC, req_count DESC, requested_model ASC
LIMIT ?`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query top models: %w", err)
	}
	defer rows.Close()

	var out []ModelUsageStat
	for rows.Next() {
		var st ModelUsageStat
		if err := rows.Scan(&st.Model, &st.Provider, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan top model: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func buildUsageWhere(filter UsageFilter) (string, []any) {
	var clauses []string
	var args []any

	if filter.Subject != "" {
		clauses = append(clauses, "subject = ?")
		args = append(args, filter.Subject)
	}
	if filter.Tag != "" {
		clauses = append(clauses, "(subject = ? OR EXISTS (SELECT 1 FROM json_each(usage_logs.tags_json) WHERE value = ?))")
		args = append(args, filter.Tag, filter.Tag)
	}
	if filter.ProviderName != "" {
		clauses = append(clauses, "provider_name = ?")
		args = append(args, filter.ProviderName)
	}
	if filter.Model != "" {
		clauses = append(clauses, "(requested_model = ? OR upstream_model = ?)")
		args = append(args, filter.Model, filter.Model)
	}
	if filter.StatusCode > 0 {
		clauses = append(clauses, "status_code = ?")
		args = append(args, filter.StatusCode)
	}
	if filter.ErrorsOnly {
		clauses = append(clauses, "(status_code >= 400 OR status_code = 0 OR error_message != '')")
	}
	if filter.GuardrailOnly {
		clauses = append(clauses, "guardrail_action != ''")
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

func scanUsageLog(sc scanner) (UsageLog, error) {
	var (
		log          UsageLog
		createdAtStr string
		tagsJSON     string
		hitsJSON     string
		stream       int
		translated   int
	)
	if err := sc.Scan(
		&log.ID, &createdAtStr, &log.RequestID, &log.Subject, &log.DisplayName,
		&log.NodeName, &log.NodeIP, &tagsJSON, &log.AuthSource, &log.ProviderName,
		&log.ProviderType, &log.RequestedModel, &log.UpstreamModel, &log.Protocol,
		&log.Endpoint, &stream, &translated,
		&log.InputTokens, &log.OutputTokens, &log.CacheReadTokens, &log.CacheWriteTokens,
		&log.ReasoningTokens, &log.TotalTokens, &log.CostUSD, &log.LatencyMS, &log.TTFTMS,
		&log.StatusCode, &log.ErrorMessage, &log.GuardrailAction, &hitsJSON,
	); err != nil {
		return UsageLog{}, err
	}
	tags, err := unmarshalStringSlice(tagsJSON)
	if err != nil {
		return UsageLog{}, err
	}
	hits, err := unmarshalStringSlice(hitsJSON)
	if err != nil {
		return UsageLog{}, err
	}
	log.Tags = tags
	log.GuardrailHits = hits
	log.CreatedAt = parseTime(createdAtStr)
	log.Stream = stream != 0
	log.Translated = translated != 0
	return log, nil
}

// --- Audit Payloads & Retention ---

func (s *SQLiteStore) InsertAuditPayload(ctx context.Context, payload AuditPayload) error {
	if strings.TrimSpace(payload.UsageLogID) == "" {
		return errors.New("store: audit payload usage_log_id is required")
	}
	if strings.TrimSpace(payload.ID) == "" {
		payload.ID = uuid.NewString()
	}
	createdAt := payload.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	reqHeaders, err := marshalStringMap(payload.RequestHeaders)
	if err != nil {
		return fmt.Errorf("store: encode request headers: %w", err)
	}
	respHeaders, err := marshalStringMap(payload.ResponseHeaders)
	if err != nil {
		return fmt.Errorf("store: encode response headers: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_payloads (
	id, usage_log_id, created_at, request_headers_json, request_body,
	response_headers_json, response_body, redacted
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		payload.ID, payload.UsageLogID, formatTime(createdAt), reqHeaders,
		payload.RequestBody, respHeaders, payload.ResponseBody, boolToInt(payload.Redacted),
	)
	if err != nil {
		return fmt.Errorf("store: insert audit payload: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetAuditPayloadByUsageLogID(ctx context.Context, usageLogID string) (*AuditPayload, error) {
	var (
		p            AuditPayload
		createdAtStr string
		reqHeaders   string
		respHeaders  string
		redacted     int
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, usage_log_id, created_at, request_headers_json, request_body,
       response_headers_json, response_body, redacted
FROM audit_payloads WHERE usage_log_id = ?`, usageLogID).
		Scan(&p.ID, &p.UsageLogID, &createdAtStr, &reqHeaders, &p.RequestBody,
			&respHeaders, &p.ResponseBody, &redacted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get audit payload for %q: %w", usageLogID, err)
	}
	if p.RequestHeaders, err = unmarshalStringMap(reqHeaders); err != nil {
		return nil, err
	}
	if p.ResponseHeaders, err = unmarshalStringMap(respHeaders); err != nil {
		return nil, err
	}
	p.CreatedAt = parseTime(createdAtStr)
	p.Redacted = redacted != 0
	return &p, nil
}

func (s *SQLiteStore) PurgeAuditPayloads(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_payloads WHERE created_at < ?`, formatTime(olderThan.UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: purge audit payloads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: purge audit payloads rows affected: %w", err)
	}
	return n, nil
}
