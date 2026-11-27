package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/store"
)

// clientUpstreamErrorMessage returns a sanitized diagnostic error for admins while
// hiding internal upstream URLs/IPs from non-admin callers (matching /api/v1/chat/mcp-servers).
func (g *Gateway) clientUpstreamErrorMessage(ctx context.Context, p *auth.Principal, prefix, safeErr string) string {
	if g.isAdminPrincipal(ctx, p) {
		return prefix + ": " + safeErr
	}
	return "upstream MCP server unavailable"
}

func (g *Gateway) processJSONRPCResponseBytes(
	ctx context.Context,
	raw []byte,
	p *auth.Principal,
	serverName string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string][]*trackedToolCall,
	localErrors []json.RawMessage,
	isBatchRequest bool,
) ([]byte, error) {
	mustFilterTools := g.authorizer != nil && len(toolsListIDs) > 0
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if mustFilterTools {
			return nil, errors.New("empty upstream response for tools/list")
		}
		if len(localErrors) > 0 && isBatchRequest {
			return marshalRawArray(localErrors), nil
		}
		return raw, nil
	}

	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			if mustFilterTools {
				return nil, fmt.Errorf("malformed batch JSON response for tools/list: %w", err)
			}
			return raw, nil
		}
		modified := false
		for i, item := range items {
			updated, changed, err := g.processSingleRPCResponse(ctx, item, p, serverName, toolsListIDs, trackedCalls)
			if err != nil {
				return nil, err
			}
			if changed {
				items[i] = updated
				modified = true
			}
		}
		if len(localErrors) > 0 {
			items = append(items, localErrors...)
			modified = true
		}
		if !modified {
			return raw, nil
		}
		return marshalRawArray(items), nil
	}

	if trimmed[0] == '{' {
		updated, changed, err := g.processSingleRPCResponse(ctx, trimmed, p, serverName, toolsListIDs, trackedCalls)
		if err != nil {
			return nil, err
		}
		if len(localErrors) > 0 && isBatchRequest {
			merged := append([]json.RawMessage{updated}, localErrors...)
			return marshalRawArray(merged), nil
		}
		if !changed {
			return raw, nil
		}
		return updated, nil
	}

	if mustFilterTools {
		return nil, errors.New("non-JSON upstream response for tools/list")
	}
	return raw, nil
}

func (g *Gateway) processSingleRPCResponse(
	ctx context.Context,
	rawItem json.RawMessage,
	p *auth.Principal,
	serverName string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string][]*trackedToolCall,
) (json.RawMessage, bool, error) {
	var msg jsonRPCMessage
	if err := json.Unmarshal(rawItem, &msg); err != nil {
		if g.authorizer != nil && len(toolsListIDs) > 0 {
			return nil, false, fmt.Errorf("invalid JSON-RPC response for tools/list: %w", err)
		}
		return rawItem, false, nil
	}

	cid := canonicalRPCID(msg.ID)

	// P2-3: Pop FIFO tracked tools/call per id so duplicate IDs in a batch never clobber audit logs.
	if trackedCalls != nil && cid != "" {
		if queue := trackedCalls[cid]; len(queue) > 0 {
			tc := queue[0]
			trackedCalls[cid] = queue[1:]
			if !tc.recorded {
				tc.recorded = true
				status, errMsg := classifyToolCallResponse(msg)
				g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
			}
		}
	}

	// Filter tools/list responses so unauthorized tools are completely invisible (Fail-Closed).
	if g.authorizer == nil || len(bytes.TrimSpace(msg.Result)) == 0 {
		return rawItem, false, nil
	}
	_, matchedToolsListID := toolsListIDs[cid]
	hasToolsArr := resultHasToolsArray(msg.Result)
	if !matchedToolsListID && !hasToolsArr {
		return rawItem, false, nil
	}

	filteredItem, changed, err := g.filterToolsListResponse(ctx, rawItem, p, serverName, matchedToolsListID)
	if err != nil {
		return nil, false, err
	}
	return filteredItem, changed, nil
}

func (g *Gateway) filterToolsListResponse(
	ctx context.Context,
	rawItem json.RawMessage,
	p *auth.Principal,
	serverName string,
	strict bool,
) (json.RawMessage, bool, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rawItem, &env); err != nil {
		if strict {
			return nil, false, fmt.Errorf("failed to parse tools/list envelope: %w", err)
		}
		return rawItem, false, nil
	}
	rawResult, ok := env["result"]
	if !ok {
		return rawItem, false, nil
	}
	var resultObj map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &resultObj); err != nil {
		if strict {
			return nil, false, fmt.Errorf("failed to parse tools/list result object: %w", err)
		}
		return rawItem, false, nil
	}
	rawTools, hasTools := resultObj["tools"]
	if !hasTools {
		return rawItem, false, nil
	}

	var toolEntries []json.RawMessage
	if err := json.Unmarshal(rawTools, &toolEntries); err != nil {
		if strict {
			return nil, false, fmt.Errorf("failed to parse tools/list tools array: %w", err)
		}
		return rawItem, false, nil
	}

	allowed := make([]json.RawMessage, 0, len(toolEntries))
	removed := false
	for _, entry := range toolEntries {
		var meta struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(entry, &meta); err != nil || meta.Name == "" {
			removed = true
			continue
		}
		ok, _, err := g.authorizer.AuthorizeMCPTool(ctx, p, serverName+"/"+meta.Name)
		if err != nil || !ok {
			removed = true
			continue
		}
		allowed = append(allowed, entry)
	}
	if !removed {
		return rawItem, false, nil
	}

	resultObj["tools"] = marshalRawArray(allowed)
	encodedResult, err := json.Marshal(resultObj)
	if err != nil {
		return nil, false, err
	}
	env["result"] = encodedResult
	encodedEnv, err := json.Marshal(env)
	if err != nil {
		return nil, false, err
	}
	return encodedEnv, true, nil
}

func resultHasToolsArray(rawResult json.RawMessage) bool {
	trimmed := bytes.TrimSpace(rawResult)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	var probe struct {
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return false
	}
	t := bytes.TrimSpace(probe.Tools)
	return len(t) > 0 && t[0] == '['
}

func classifyToolCallResponse(msg jsonRPCMessage) (status, errMsg string) {
	if msg.Error != nil {
		return AuditStatusError, fmt.Sprintf("JSON-RPC error %d: %s", msg.Error.Code, msg.Error.Message)
	}
	if len(bytes.TrimSpace(msg.Result)) > 0 {
		var res struct {
			IsError bool `json:"isError"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(msg.Result, &res); err == nil && res.IsError {
			var parts []string
			for _, c := range res.Content {
				if strings.TrimSpace(c.Text) != "" {
					parts = append(parts, c.Text)
				}
			}
			msgText := strings.Join(parts, "; ")
			if msgText == "" {
				msgText = "tool returned isError=true"
			}
			return AuditStatusError, truncateString(msgText, 512)
		}
	}
	return AuditStatusOK, ""
}

// inspectToolArguments wraps arguments inside {"arguments": <rawArgs>} before
// invoking GuardrailInspector so Headlamp's path-aware guardrail evaluator scans
// 100% of nested string keys (including "id", "name", "detail", "model", "role").
func (g *Gateway) inspectToolArguments(
	ctx context.Context,
	requestID string,
	p *auth.Principal,
	serverName, toolName string,
	rawArgs json.RawMessage,
) (action string, modifiedArgs json.RawMessage, reason string, err error) {
	trimmed := bytes.TrimSpace(rawArgs)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		trimmed = json.RawMessage(`{}`)
	}
	wrapped, err := json.Marshal(struct {
		Arguments json.RawMessage `json:"arguments"`
	}{Arguments: trimmed})
	if err != nil {
		return "", nil, "", err
	}

	dec, err := g.guardrails.Inspect(ctx, GuardrailRequest{
		RequestID: requestID,
		Principal: p,
		Protocol:  "mcp",
		Model:     serverName + "/" + toolName,
		Body:      wrapped,
	})
	if err != nil || dec == nil {
		return "allow", trimmed, "", err
	}

	if dec.Action == "block" {
		return "block", nil, dec.Reason, nil
	}
	if (dec.Action == "redact" || dec.Action == "modify") && len(bytes.TrimSpace(dec.ModifiedBody)) > 0 {
		var unwrapped map[string]json.RawMessage
		if err := json.Unmarshal(dec.ModifiedBody, &unwrapped); err == nil {
			if modArgs, ok := unwrapped["arguments"]; ok && len(unwrapped) == 1 && json.Valid(modArgs) {
				return dec.Action, bytes.Clone(modArgs), "", nil
			}
		}
		if json.Valid(dec.ModifiedBody) {
			return dec.Action, bytes.Clone(dec.ModifiedBody), "", nil
		}
	}
	return dec.Action, trimmed, dec.Reason, nil
}

func (g *Gateway) finalizePendingCalls(
	p *auth.Principal,
	serverName string,
	tracked map[string][]*trackedToolCall,
	unkeyed []*trackedToolCall,
	status, errMsg string,
) {
	for _, queue := range tracked {
		for _, tc := range queue {
			if tc.recorded {
				continue
			}
			tc.recorded = true
			g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
		}
	}
	for _, tc := range unkeyed {
		if tc.recorded {
			continue
		}
		tc.recorded = true
		g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
	}
}

func (g *Gateway) recordAudit(
	p *auth.Principal,
	serverName, method, toolName, requestID, status string,
	latencyMS int64,
	errMsg, argsPreview string,
) {
	if g.store == nil {
		return
	}
	entry := store.MCPAuditLog{
		ID:               uuid.NewString(),
		CreatedAt:        time.Now().UTC(),
		RequestID:        requestID,
		ServerName:       serverName,
		Method:           method,
		ToolName:         toolName,
		Status:           status,
		LatencyMS:        latencyMS,
		ErrorMessage:     errMsg,
		ArgumentsPreview: argsPreview,
	}
	if p != nil {
		entry.Subject = p.Subject
		entry.DisplayName = p.DisplayName
		entry.NodeName = p.NodeName
		entry.NodeIP = p.NodeIP
		entry.Tags = slices.Clone(p.Tags)
		entry.AuthSource = p.AuthSource
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.store.InsertMCPAuditLog(ctx, entry); err != nil {
		g.logf("headlamp mcp: persist audit log failed: %v", err)
	}
}

func truncatePreview(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, trimmed); err == nil {
		return truncateString(compact.String(), maxAuditArgsPreviewBytes)
	}
	return truncateString(string(trimmed), maxAuditArgsPreviewBytes)
}

func truncateString(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	const suffix = "...[truncated]"
	limit := maxBytes - len(suffix)
	if limit <= 0 {
		return s[:maxBytes]
	}
	// Back up to a valid UTF-8 rune boundary.
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + suffix
}
