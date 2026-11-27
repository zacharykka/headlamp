package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode"
)

func parseGatewayErrorBody(status int, body []byte) (errType, message string) {
	var envelope struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &envelope); err == nil && envelope.Error.Message != "" {
		errType = envelope.Error.Type
		if errType == "" {
			errType = envelope.Error.Code
		}
		if errType == "" {
			errType = envelope.Error.Status
		}
		if errType == "" {
			errType = defaultErrorTypeForStatus(status)
		}
		return errType, envelope.Error.Message
	}

	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = http.StatusText(status)
	}
	return defaultErrorTypeForStatus(status), msg
}

func defaultErrorTypeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusNotFound:
		return "not_found_error"
	default:
		return "upstream_error"
	}
}

func classifyStreamError(err error) (string, string) {
	var gwErr *gatewayHTTPError
	if errors.As(err, &gwErr) {
		return gwErr.Type, gwErr.Message
	}
	return "stream_error", err.Error()
}

func deriveSessionTitle(prompt string) string {
	collapsed := strings.Join(strings.Fields(prompt), " ")
	runes := []rune(collapsed)
	if len(runes) <= maxAutoTitleRunes {
		return collapsed
	}
	return strings.TrimSpace(string(runes[:maxAutoTitleRunes-3])) + "..."
}

func cleanStringSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if trimmed := strings.TrimSpace(s); trimmed != "" && !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	return out
}

func encodeToolName(server, tool string, existing map[string]toolBinding) string {
	base := "mcp__" + sanitizeToolSegment(server) + "__" + sanitizeToolSegment(tool)
	if len(base) > 60 {
		base = base[:60]
	}
	candidate := base
	for suffix := 2; ; suffix++ {
		if _, taken := existing[candidate]; !taken {
			return candidate
		}
		tail := fmt.Sprintf("_%d", suffix)
		prefix := base
		if len(prefix)+len(tail) > 64 {
			prefix = prefix[:64-len(tail)]
		}
		candidate = prefix + tail
	}
}

func sanitizeToolSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else if !unicode.IsSpace(r) {
			b.WriteByte('_')
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "tool"
	}
	return out
}

func normalizeToolSchema(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return trimmed
}

// sanitizeGeminiSchema resolves local JSON Schema $ref pointers (against $defs/definitions)
// and strips JSON Schema keywords rejected by Google's Gemini functionDeclarations validator
// without stripping user-defined parameter names inside "properties" maps.
func sanitizeGeminiSchema(raw json.RawMessage) any {
	var obj map[string]any
	if err := json.Unmarshal(normalizeToolSchema(raw), &obj); err != nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return cleanGeminiSchemaNode(obj, obj, false, make(map[string]bool))
}

func cleanGeminiSchemaNode(node any, root map[string]any, inPropertiesMap bool, visiting map[string]bool) any {
	switch v := node.(type) {
	case map[string]any:
		if inPropertiesMap {
			// Inside a "properties" object, keys are user-defined parameter names (such as
			// "default" or "definitions") and MUST NOT be stripped; recurse into each
			// parameter's child schema at schema-object level.
			out := make(map[string]any, len(v))
			for propName, propSchema := range v {
				out[propName] = cleanGeminiSchemaNode(propSchema, root, false, visiting)
			}
			return out
		}

		// Inline local $ref nodes before stripping $defs / definitions.
		if refRaw, hasRef := v["$ref"]; hasRef {
			refStr, _ := refRaw.(string)
			refStr = strings.TrimSpace(refStr)
			var resolved map[string]any
			if refStr != "" && !visiting[refStr] {
				if target, ok := resolveGeminiSchemaRef(root, refStr); ok {
					visiting[refStr] = true
					cleaned := cleanGeminiSchemaNode(target, root, false, visiting)
					delete(visiting, refStr)
					if m, ok := cleaned.(map[string]any); ok {
						resolved = m
					}
				}
			}
			if resolved == nil {
				// Cyclic or unresolvable $ref: fall back cleanly so Gemini never sees a dangling $ref.
				resolved = map[string]any{"type": "string"}
			}
			// Preserve allowed sibling schema fields (such as "description") alongside $ref.
			for k, val := range v {
				switch k {
				case "$ref", "$schema", "additionalProperties", "$defs", "definitions", "default":
					continue
				case "properties":
					resolved[k] = cleanGeminiSchemaNode(val, root, true, visiting)
				default:
					resolved[k] = cleanGeminiSchemaNode(val, root, false, visiting)
				}
			}
			return resolved
		}

		out := make(map[string]any, len(v))
		for k, val := range v {
			switch k {
			case "$schema", "additionalProperties", "$defs", "definitions", "default":
				continue
			case "properties":
				out[k] = cleanGeminiSchemaNode(val, root, true, visiting)
			default:
				out[k] = cleanGeminiSchemaNode(val, root, false, visiting)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cleanGeminiSchemaNode(item, root, false, visiting)
		}
		return out
	default:
		return v
	}
}

// resolveGeminiSchemaRef resolves a local JSON Pointer (such as "#/$defs/Repo" or
// "#/definitions/Filter") within root, applying RFC 6901 unescaping.
func resolveGeminiSchemaRef(root map[string]any, ref string) (map[string]any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	segments := strings.Split(ref[2:], "/")
	var cur any = root
	for _, seg := range segments {
		seg = strings.ReplaceAll(seg, "~1", "/")
		seg = strings.ReplaceAll(seg, "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := m[seg]
		if !exists {
			return nil, false
		}
		cur = next
	}
	target, ok := cur.(map[string]any)
	return target, ok
}
