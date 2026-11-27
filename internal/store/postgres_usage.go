package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// --- Runtime Settings ---

func (s *PostgresStore) GetAuditSettings(ctx context.Context) (*AuditSettings, error) {
	var (
		valueJSON string
		updatedAt time.Time
	)
	err := s.db.QueryRowContext(ctx, `
SELECT value_json::text, updated_at FROM runtime_settings WHERE key = $1`, runtimeSettingAuditKey).
		Scan(&valueJSON, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get postgres audit settings: %w", err)
	}
	var out AuditSettings
	if err := json.Unmarshal([]byte(valueJSON), &out); err != nil {
		return nil, fmt.Errorf("store: decode audit settings: %w", err)
	}
	out.UpdatedAt = updatedAt.UTC()
	return &out, nil
}

func (s *PostgresStore) SetAuditSettings(ctx context.Context, settings AuditSettings) error {
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

	_, err = s.db.ExecContext(ctx, `
INSERT INTO runtime_settings (key, value_json, updated_at)
VALUES ($1, $2::jsonb, $3)
ON CONFLICT(key) DO UPDATE SET
	value_json = excluded.value_json,
	updated_at = excluded.updated_at`,
		runtimeSettingAuditKey, string(payload), time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("store: set postgres audit settings: %w", err)
	}
	return nil
}

// --- Usage Logs & Dashboard Analytics ---

func (s *PostgresStore) InsertUsageLog(ctx context.Context, log UsageLog) error {
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
	tagsJSON = string(stripPostgresJSONNUL([]byte(tagsJSON)))
	hitsJSON, err := marshalStringSlice(log.GuardrailHits)
	if err != nil {
		return fmt.Errorf("store: encode guardrail hits: %w", err)
	}
	hitsJSON = string(stripPostgresJSONNUL([]byte(hitsJSON)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO usage_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, provider_name, provider_type, requested_model,
	upstream_model, protocol, endpoint, stream, translated,
	input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
	reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
	status_code, error_message, guardrail_action, guardrail_hits_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30::jsonb)`,
		stripPostgresNUL(log.ID), createdAt, stripPostgresNUL(log.RequestID), stripPostgresNUL(log.Subject),
		stripPostgresNUL(log.DisplayName), stripPostgresNUL(log.NodeName), stripPostgresNUL(log.NodeIP),
		tagsJSON, stripPostgresNUL(log.AuthSource), stripPostgresNUL(log.ProviderName),
		stripPostgresNUL(log.ProviderType), stripPostgresNUL(log.RequestedModel), stripPostgresNUL(log.UpstreamModel),
		stripPostgresNUL(log.Protocol), stripPostgresNUL(log.Endpoint), log.Stream, log.Translated,
		log.InputTokens, log.OutputTokens, log.CacheReadTokens, log.CacheWriteTokens,
		log.ReasoningTokens, log.TotalTokens, log.CostUSD, log.LatencyMS, log.TTFTMS,
		log.StatusCode, stripPostgresNUL(log.ErrorMessage), stripPostgresNUL(log.GuardrailAction), hitsJSON,
	)
	if err != nil {
		return fmt.Errorf("store: insert postgres usage log %q: %w", log.ID, err)
	}
	return nil
}

func (s *PostgresStore) GetUsageLog(ctx context.Context, id string) (*UsageLog, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json::text, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json::text
FROM usage_logs WHERE id = $1`, id)

	log, err := pgScanUsageLog(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &log, nil
}

func (s *PostgresStore) QueryUsageLogs(ctx context.Context, filter UsageFilter) ([]UsageLog, error) {
	where, args := pgBuildUsageWhere(filter)
	query := `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json::text, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json::text
FROM usage_logs` + where + ` ORDER BY created_at DESC, id DESC`

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
		return nil, fmt.Errorf("store: query postgres usage logs: %w", err)
	}
	defer rows.Close()

	var out []UsageLog
	for rows.Next() {
		log, err := pgScanUsageLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SummarizeUsage(ctx context.Context, filter UsageFilter) (UsageSummary, error) {
	where, args := pgBuildUsageWhere(filter)
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
		return UsageSummary{}, fmt.Errorf("store: summarize postgres usage: %w", err)
	}
	return sum, nil
}

func (s *PostgresStore) SummarizeUsageExtended(ctx context.Context, filter UsageFilter) (UsageExtendedSummary, error) {
	where, args := pgBuildUsageWhere(filter)
	query := `
SELECT COUNT(*),
       COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cache_read_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0),
       COALESCE(SUM(reasoning_tokens), 0),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0),
       COALESCE(SUM(CASE WHEN status_code >= 400 OR status_code = 0 OR error_message != '' THEN 1 ELSE 0 END), 0),
       COALESCE((percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms))::bigint, 0)
FROM usage_logs` + where

	var ext UsageExtendedSummary
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&ext.RequestCount, &ext.InputTokens, &ext.OutputTokens,
		&ext.CacheReadTokens, &ext.CacheWriteTokens, &ext.ReasoningTokens,
		&ext.TotalTokens, &ext.CostUSD, &ext.ErrorCount, &ext.P95LatencyMS,
	); err != nil {
		return UsageExtendedSummary{}, fmt.Errorf("store: summarize postgres usage extended: %w", err)
	}
	return ext, nil
}

func (s *PostgresStore) QueryUsageSeries(ctx context.Context, filter UsageFilter, bucket string) ([]UsageTimeBucket, error) {
	var bucketExpr string
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "hour":
		bucketExpr = `to_char(date_trunc('hour', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:00:00"Z"')`
	case "", "day":
		bucketExpr = `to_char(date_trunc('day', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD')`
	default:
		return nil, fmt.Errorf("store: invalid usage series bucket %q (must be hour or day)", bucket)
	}

	where, args := pgBuildUsageWhere(filter)
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
		return nil, fmt.Errorf("store: query postgres usage series: %w", err)
	}
	defer rows.Close()

	var out []UsageTimeBucket
	for rows.Next() {
		var b UsageTimeBucket
		if err := rows.Scan(&b.Bucket, &b.Requests, &b.Tokens, &b.CostUSD, &b.Errors); err != nil {
			return nil, fmt.Errorf("store: scan postgres usage series bucket: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *PostgresStore) QueryTopSubjects(ctx context.Context, filter UsageFilter, limit int) ([]SubjectUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := pgBuildUsageWhere(filter)
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT subject,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs%s
GROUP BY subject
ORDER BY total_cost DESC, req_count DESC, subject ASC
LIMIT $%d`, where, len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres top subjects: %w", err)
	}
	defer rows.Close()

	var out []SubjectUsageStat
	for rows.Next() {
		var st SubjectUsageStat
		if err := rows.Scan(&st.Subject, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan postgres top subject: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *PostgresStore) QueryTopModels(ctx context.Context, filter UsageFilter, limit int) ([]ModelUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := pgBuildUsageWhere(filter)
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT requested_model,
       provider_name,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs%s
GROUP BY requested_model, provider_name
ORDER BY total_cost DESC, req_count DESC, requested_model ASC
LIMIT $%d`, where, len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres top models: %w", err)
	}
	defer rows.Close()

	var out []ModelUsageStat
	for rows.Next() {
		var st ModelUsageStat
		if err := rows.Scan(&st.Model, &st.Provider, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan postgres top model: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func pgBuildUsageWhere(filter UsageFilter) (string, []any) {
	var clauses []string
	var args []any

	if filter.Subject != "" {
		args = append(args, filter.Subject)
		clauses = append(clauses, fmt.Sprintf("subject = $%d", len(args)))
	}
	if filter.Tag != "" {
		args = append(args, filter.Tag)
		p1 := len(args)
		args = append(args, filter.Tag)
		p2 := len(args)
		clauses = append(clauses, fmt.Sprintf("(subject = $%d OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(usage_logs.tags_json) AS elem WHERE elem = $%d))", p1, p2))
	}
	if filter.ProviderName != "" {
		args = append(args, filter.ProviderName)
		clauses = append(clauses, fmt.Sprintf("provider_name = $%d", len(args)))
	}
	if filter.Model != "" {
		args = append(args, filter.Model)
		p1 := len(args)
		args = append(args, filter.Model)
		p2 := len(args)
		clauses = append(clauses, fmt.Sprintf("(requested_model = $%d OR upstream_model = $%d)", p1, p2))
	}
	if filter.StatusCode > 0 {
		args = append(args, filter.StatusCode)
		clauses = append(clauses, fmt.Sprintf("status_code = $%d", len(args)))
	}
	if filter.ErrorsOnly {
		clauses = append(clauses, "(status_code >= 400 OR status_code = 0 OR error_message != '')")
	}
	if filter.GuardrailOnly {
		clauses = append(clauses, "guardrail_action != ''")
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since.UTC())
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !filter.Until.IsZero() {
		args = append(args, filter.Until.UTC())
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func pgScanUsageLog(sc scanner) (UsageLog, error) {
	var (
		log      UsageLog
		tagsJSON string
		hitsJSON string
	)
	if err := sc.Scan(
		&log.ID, &log.CreatedAt, &log.RequestID, &log.Subject, &log.DisplayName,
		&log.NodeName, &log.NodeIP, &tagsJSON, &log.AuthSource, &log.ProviderName,
		&log.ProviderType, &log.RequestedModel, &log.UpstreamModel, &log.Protocol,
		&log.Endpoint, &log.Stream, &log.Translated,
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
	log.CreatedAt = log.CreatedAt.UTC()
	return log, nil
}

// --- Audit Payloads & Retention ---

func (s *PostgresStore) InsertAuditPayload(ctx context.Context, payload AuditPayload) error {
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
	reqHeaders = string(stripPostgresJSONNUL([]byte(reqHeaders)))
	respHeaders, err := marshalStringMap(payload.ResponseHeaders)
	if err != nil {
		return fmt.Errorf("store: encode response headers: %w", err)
	}
	respHeaders = string(stripPostgresJSONNUL([]byte(respHeaders)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_payloads (
	id, usage_log_id, created_at, request_headers_json, request_body,
	response_headers_json, response_body, redacted
)
VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7, $8)`,
		stripPostgresNUL(payload.ID), stripPostgresNUL(payload.UsageLogID), createdAt, reqHeaders,
		stripPostgresNUL(payload.RequestBody), respHeaders, stripPostgresNUL(payload.ResponseBody), payload.Redacted,
	)
	if err != nil {
		return fmt.Errorf("store: insert postgres audit payload: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetAuditPayloadByUsageLogID(ctx context.Context, usageLogID string) (*AuditPayload, error) {
	var (
		p           AuditPayload
		reqHeaders  string
		respHeaders string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, usage_log_id, created_at, request_headers_json::text, request_body,
       response_headers_json::text, response_body, redacted
FROM audit_payloads WHERE usage_log_id = $1`, usageLogID).
		Scan(&p.ID, &p.UsageLogID, &p.CreatedAt, &reqHeaders, &p.RequestBody,
			&respHeaders, &p.ResponseBody, &p.Redacted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get postgres audit payload for %q: %w", usageLogID, err)
	}
	if p.RequestHeaders, err = unmarshalStringMap(reqHeaders); err != nil {
		return nil, err
	}
	if p.ResponseHeaders, err = unmarshalStringMap(respHeaders); err != nil {
		return nil, err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return &p, nil
}

func (s *PostgresStore) PurgeAuditPayloads(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_payloads WHERE created_at < $1`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("store: purge postgres audit payloads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: purge postgres audit payloads rows affected: %w", err)
	}
	return n, nil
}
