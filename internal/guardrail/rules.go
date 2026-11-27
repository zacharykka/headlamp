package guardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

const (
	ActionAllow   = "allow"
	ActionLogOnly = config.GuardrailActionLogOnly
	ActionRedact  = config.GuardrailActionRedact
	ActionModify  = "modify"
	ActionBlock   = config.GuardrailActionBlock
)

// RuleMatch records a single guardrail rule hit. JSON tags match the Admin API test contract.
type RuleMatch struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Category string `json:"category"`
	Action   string `json:"action"`
}

// TestResult is returned by TestText for live Admin UI testing of regex rules.
type TestResult struct {
	Action       string      `json:"action"`
	RedactedText string      `json:"redacted_text"`
	Matches      []RuleMatch `json:"matches"`
}

// InspectResult holds the local regex evaluation outcome for an LLM JSON request body.
type InspectResult struct {
	Action       string
	ModifiedBody []byte
	Matches      []RuleMatch
	Reason       string
}

type compiledRule struct {
	rule store.GuardrailRule
	re   *regexp.Regexp
}

// Evaluator evaluates enabled regex guardrail rules from store.Store, caching
// compiled *regexp.Regexp objects until the enabled rule set changes.
type Evaluator struct {
	store store.Store
	logf  func(format string, args ...any)

	mu          sync.RWMutex
	fingerprint string
	compiled    []compiledRule
}

// NewEvaluator creates a local regex guardrail Evaluator backed by st.
func NewEvaluator(st store.Store, logf func(format string, args ...any)) *Evaluator {
	return &Evaluator{
		store: st,
		logf:  logf,
	}
}

// TestText runs all enabled regex rules against plain text and returns the
// highest-precedence action (block > redact > log_only > allow), redacted text,
// and deduplicated matches.
func (e *Evaluator) TestText(ctx context.Context, text string) (*TestResult, error) {
	rules, err := e.loadCompiledRules(ctx)
	if err != nil {
		return nil, err
	}

	action, redacted, matches := evaluateString(rules, text)
	if matches == nil {
		matches = []RuleMatch{}
	}
	return &TestResult{
		Action:       action,
		RedactedText: redacted,
		Matches:      matches,
	}, nil
}

// skippedJSONKeys are structural/protocol metadata keys whose string values are
// never scanned or rewritten by guardrails so valid LLM payloads remain intact.
var skippedJSONKeys = map[string]struct{}{
	"model":             {},
	"role":              {},
	"type":              {},
	"id":                {},
	"tool_use_id":       {},
	"tool_call_id":      {},
	"object":            {},
	"name":              {},
	"media_type":        {},
	"mime_type":         {},
	"mimeType":          {},
	"finish_reason":     {},
	"stop_reason":       {},
	"encoding_format":   {},
	"detail":            {},
	"anthropic_version": {},
}

// InspectJSONPayload scans prompt and content string values inside a JSON LLM
// request body while preserving valid JSON structure and protocol metadata keys.
//
// Precedence across all matches is: block > redact > log_only > allow.
// ModifiedBody is rewritten valid JSON only when Action == "redact"; otherwise
// the original body bytes are returned unchanged.
func (e *Evaluator) InspectJSONPayload(ctx context.Context, body []byte) (*InspectResult, error) {
	rules, err := e.loadCompiledRules(ctx)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 || len(bytes.TrimSpace(body)) == 0 {
		return &InspectResult{
			Action:       ActionAllow,
			ModifiedBody: body,
			Matches:      []RuleMatch{},
		}, nil
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		// Non-JSON payload fallback: evaluate as raw text without mutating structure.
		action, redacted, matches := evaluateString(rules, string(body))
		res := &InspectResult{
			Action:       action,
			ModifiedBody: body,
			Matches:      matches,
		}
		if action == ActionRedact {
			res.ModifiedBody = []byte(redacted)
		} else if action == ActionBlock {
			res.Reason = formatBlockReason(matches)
		}
		return res, nil
	}

	acc := &scanAccumulator{
		action:  ActionAllow,
		seenIDs: make(map[string]struct{}),
		matches: []RuleMatch{},
	}
	mutatedRoot, mutated := scanJSONValue(rules, root, "", acc)

	res := &InspectResult{
		Action:       acc.action,
		ModifiedBody: body,
		Matches:      acc.matches,
	}
	if acc.action == ActionBlock {
		res.Reason = formatBlockReason(acc.matches)
		return res, nil
	}
	if acc.action == ActionRedact && mutated {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(mutatedRoot); err != nil {
			return nil, fmt.Errorf("guardrail: encode redacted payload: %w", err)
		}
		res.ModifiedBody = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	return res, nil
}

type scanAccumulator struct {
	action  string
	seenIDs map[string]struct{}
	matches []RuleMatch
}

func (a *scanAccumulator) record(action string, matches []RuleMatch) {
	if actionRank(action) > actionRank(a.action) {
		a.action = action
	}
	for _, m := range matches {
		if _, exists := a.seenIDs[m.RuleID]; exists {
			continue
		}
		a.seenIDs[m.RuleID] = struct{}{}
		a.matches = append(a.matches, m)
	}
}

func scanJSONValue(rules []compiledRule, v any, parentKey string, acc *scanAccumulator) (any, bool) {
	switch val := v.(type) {
	case string:
		if _, skip := skippedJSONKeys[parentKey]; skip {
			return val, false
		}
		action, redacted, matches := evaluateString(rules, val)
		if len(matches) > 0 {
			acc.record(action, matches)
		}
		if action == ActionRedact && redacted != val {
			return redacted, true
		}
		return val, false

	case map[string]any:
		// Skip inline base64 media payloads (Anthropic {"type":"base64","media_type":...,"data":"..."}
		// and Gemini inlineData/inline_data {"mimeType"|"mime_type":...,"data":"..."})
		// so random base64 runs don't false-positive as API keys.
		isBase64Source := val["type"] == "base64" || hasNonEmptyString(val, "mimeType") || hasNonEmptyString(val, "mime_type")
		mutated := false
		for k, elem := range val {
			if _, skip := skippedJSONKeys[k]; skip {
				continue
			}
			if isBase64Source && k == "data" {
				continue
			}
			newElem, changed := scanJSONValue(rules, elem, k, acc)
			if changed {
				val[k] = newElem
				mutated = true
			}
		}
		return val, mutated

	case []any:
		mutated := false
		for i, elem := range val {
			newElem, changed := scanJSONValue(rules, elem, parentKey, acc)
			if changed {
				val[i] = newElem
				mutated = true
			}
		}
		return val, mutated

	default:
		return v, false
	}
}

// evaluateString applies compiled rules against a single string value.
// Block and log_only rules are evaluated against the original text so redactions
// never hide a higher-severity block rule; redact rules are applied sequentially
// so more-specific patterns (e.g. builtin-anthropic-key) cleanly claim their span
// before broader patterns (e.g. builtin-openai-key).
func evaluateString(rules []compiledRule, text string) (action string, redacted string, matches []RuleMatch) {
	if text == "" || len(rules) == 0 {
		return ActionAllow, text, nil
	}

	action = ActionAllow
	redacted = text
	seen := make(map[string]struct{})
	addMatch := func(r store.GuardrailRule) {
		if actionRank(r.Action) > actionRank(action) {
			action = r.Action
		}
		if _, dup := seen[r.ID]; dup {
			return
		}
		seen[r.ID] = struct{}{}
		matches = append(matches, RuleMatch{
			RuleID:   r.ID,
			RuleName: r.Name,
			Category: r.Category,
			Action:   r.Action,
		})
	}

	// Pass 1: block rules against original text.
	for _, cr := range rules {
		if cr.rule.Action != ActionBlock {
			continue
		}
		if cr.re.MatchString(text) {
			addMatch(cr.rule)
		}
	}

	// Pass 2: redact rules sequentially against redacted buffer.
	for _, cr := range rules {
		if cr.rule.Action != ActionRedact {
			continue
		}
		if cr.re.MatchString(redacted) {
			placeholder := fmt.Sprintf("[REDACTED:%s]", cr.rule.ID)
			redacted = cr.re.ReplaceAllLiteralString(redacted, placeholder)
			addMatch(cr.rule)
		}
	}

	// Pass 3: log_only rules against original text.
	for _, cr := range rules {
		if cr.rule.Action != ActionLogOnly {
			continue
		}
		if cr.re.MatchString(text) {
			addMatch(cr.rule)
		}
	}

	return action, redacted, matches
}

func (e *Evaluator) loadCompiledRules(ctx context.Context) ([]compiledRule, error) {
	if e.store == nil {
		return nil, nil
	}
	all, err := e.store.ListGuardrailRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("guardrail: list rules: %w", err)
	}

	var (
		enabled []store.GuardrailRule
		fp      strings.Builder
	)
	for _, r := range all {
		if !r.Enabled || strings.TrimSpace(r.Pattern) == "" {
			continue
		}
		enabled = append(enabled, r)
		fp.WriteString(r.ID)
		fp.WriteByte(0)
		fp.WriteString(r.Name)
		fp.WriteByte(0)
		fp.WriteString(r.Category)
		fp.WriteByte(0)
		fp.WriteString(r.Action)
		fp.WriteByte(0)
		fp.WriteString(r.Pattern)
		fp.WriteByte('\n')
	}
	fingerprint := fp.String()

	e.mu.RLock()
	if fingerprint == e.fingerprint && (len(enabled) == 0 || len(e.compiled) > 0) {
		cached := e.compiled
		e.mu.RUnlock()
		return cached, nil
	}
	e.mu.RUnlock()

	compiled := make([]compiledRule, 0, len(enabled))
	for _, r := range enabled {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			if e.logf != nil {
				e.logf("headlamp guardrail: skipping invalid regex for rule %q: %v", r.ID, err)
			}
			continue
		}
		compiled = append(compiled, compiledRule{rule: r, re: re})
	}

	e.mu.Lock()
	e.fingerprint = fingerprint
	e.compiled = compiled
	e.mu.Unlock()
	return compiled, nil
}

func actionRank(action string) int {
	switch action {
	case ActionBlock:
		return 3
	case ActionRedact, ActionModify:
		return 2
	case ActionLogOnly:
		return 1
	default:
		return 0
	}
}

func formatBlockReason(matches []RuleMatch) string {
	var names []string
	for _, m := range matches {
		if m.Action == ActionBlock {
			if m.RuleName != "" {
				names = append(names, fmt.Sprintf("%s (%s)", m.RuleName, m.RuleID))
			} else {
				names = append(names, m.RuleID)
			}
		}
	}
	if len(names) == 0 {
		return "request blocked by guardrail policy"
	}
	return "request blocked by guardrail rule: " + strings.Join(names, ", ")
}

func hasNonEmptyString(m map[string]any, key string) bool {
	s, ok := m[key].(string)
	return ok && strings.TrimSpace(s) != ""
}
