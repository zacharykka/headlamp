package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const maxStrictJSONDepth = 128

// validateStrictJSONValue recursively walks every nested JSON object and array
// in raw (bounded by maxStrictJSONDepth), rejecting duplicate keys, case-folded
// colliding keys (e.g. "key"+"Key"), and trailing tokens at any nesting depth.
func validateStrictJSONValue(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := validateStrictJSONNextToken(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing tokens after JSON value")
	}
	return nil
}

func validateStrictJSONNextToken(dec *json.Decoder, depth int) error {
	if depth > maxStrictJSONDepth {
		return fmt.Errorf("JSON nesting depth exceeds maximum %d", maxStrictJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON token: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seenLower := make(map[string]string)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyTok.(string)
			if !ok {
				return errors.New("JSON object key must be a string")
			}
			lower := strings.ToLower(key)
			if prev, exists := seenLower[lower]; exists {
				return fmt.Errorf("duplicate or case-colliding JSON key %q (conflicts with %q)", key, prev)
			}
			seenLower[lower] = key
			if err := validateStrictJSONNextToken(dec, depth+1); err != nil {
				return err
			}
		}
		endTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("unterminated JSON object: %w", err)
		}
		if d, ok := endTok.(json.Delim); !ok || d != '}' {
			return errors.New("expected closing brace for JSON object")
		}
		return nil

	case '[':
		for dec.More() {
			if err := validateStrictJSONNextToken(dec, depth+1); err != nil {
				return err
			}
		}
		endTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("unterminated JSON array: %w", err)
		}
		if d, ok := endTok.(json.Delim); !ok || d != ']' {
			return errors.New("expected closing bracket for JSON array")
		}
		return nil

	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

// parseStrictJSONObject decodes raw as a single JSON object with exact case-sensitive
// keys while rejecting duplicate keys, case-folded colliding keys (e.g. "method"+"Method",
// "name"+"Name", "arguments"+"Arguments"), and trailing tokens.
func parseStrictJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON object: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("JSON value must be an object")
	}

	fields := make(map[string]json.RawMessage)
	seenLower := make(map[string]string)

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON object key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("JSON object key must be a string")
		}
		lower := strings.ToLower(key)
		if prev, exists := seenLower[lower]; exists {
			return nil, fmt.Errorf("duplicate or case-colliding JSON key %q (conflicts with %q)", key, prev)
		}
		seenLower[lower] = key

		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, fmt.Errorf("invalid JSON value for key %q: %w", key, err)
		}
		fields[key] = bytes.Clone(val)
	}

	endTok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("unterminated JSON object: %w", err)
	}
	if endDelim, ok := endTok.(json.Delim); !ok || endDelim != '}' {
		return nil, errors.New("expected closing brace for JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing tokens after JSON object")
	}

	return fields, nil
}

type strictRPCEnvelope struct {
	ID         json.RawMessage
	Method     string
	Params     json.RawMessage
	HasParams  bool
	Result     json.RawMessage
	HasResult  bool
	Error      json.RawMessage
	HasError   bool
	IsResponse bool
}

var reservedRPCKeys = map[string]struct{}{
	"jsonrpc": {},
	"id":      {},
	"method":  {},
	"params":  {},
	"result":  {},
	"error":   {},
}

// parseStrictRPCRequest parses a JSON-RPC 2.0 message strictly:
//   - rejects duplicate or case-colliding keys,
//   - rejects non-lowercase variants of JSON-RPC envelope keys (e.g. "Method", "Params"),
//   - requires "jsonrpc": "2.0" and either a non-empty string "method" or a valid client response ("id" + "result"/"error").
func parseStrictRPCRequest(raw []byte) (*strictRPCEnvelope, error) {
	fields, err := parseStrictJSONObject(raw)
	if err != nil {
		return nil, err
	}

	for k := range fields {
		lower := strings.ToLower(k)
		if _, reserved := reservedRPCKeys[lower]; reserved && k != lower {
			return nil, fmt.Errorf("non-canonical JSON-RPC key %q (must be lowercase %q)", k, lower)
		}
	}

	rawVer, hasVer := fields["jsonrpc"]
	if !hasVer {
		return nil, errors.New("missing required \"jsonrpc\" field")
	}
	var ver string
	if err := json.Unmarshal(rawVer, &ver); err != nil || ver != "2.0" {
		return nil, errors.New("\"jsonrpc\" must be \"2.0\"")
	}

	env := &strictRPCEnvelope{}
	if rawID, hasID := fields["id"]; hasID {
		if !isValidRPCID(rawID) {
			return nil, errors.New("\"id\" must be a string, number, or null")
		}
		env.ID = rawID
	}

	if rawMethod, hasMethod := fields["method"]; hasMethod {
		var method string
		if err := json.Unmarshal(rawMethod, &method); err != nil || strings.TrimSpace(method) == "" {
			return nil, errors.New("\"method\" must be a non-empty string")
		}
		env.Method = method
		if rawParams, hasParams := fields["params"]; hasParams {
			trimmed := bytes.TrimSpace(rawParams)
			if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
				if trimmed[0] != '{' && trimmed[0] != '[' {
					return nil, errors.New("\"params\" must be a JSON object or array")
				}
				if method != "tools/call" {
					if err := validateStrictJSONValue(trimmed); err != nil {
						return nil, fmt.Errorf("invalid \"params\": %w", err)
					}
				}
				env.Params = trimmed
				env.HasParams = true
			}
		}
		return env, nil
	}

	// Client-to-server JSON-RPC response (e.g. response to server-initiated request).
	rawRes, hasRes := fields["result"]
	rawErr, hasErr := fields["error"]
	if (hasRes || hasErr) && !(hasRes && hasErr) && env.hasID() {
		env.IsResponse = true
		env.Result = rawRes
		env.HasResult = hasRes
		env.Error = rawErr
		env.HasError = hasErr
		return env, nil
	}

	return nil, errors.New("JSON-RPC message must include a \"method\" string")
}

func (e *strictRPCEnvelope) hasID() bool {
	trimmed := bytes.TrimSpace(e.ID)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// marshalCanonical re-serializes the strictly validated JSON-RPC envelope using ONLY
// canonical lowercase keys so raw smuggling bytes are never forwarded upstream.
func (e *strictRPCEnvelope) marshalCanonical(overrideParams json.RawMessage) ([]byte, error) {
	out := make(map[string]any, 4)
	out["jsonrpc"] = "2.0"
	if len(bytes.TrimSpace(e.ID)) > 0 {
		out["id"] = e.ID
	}
	if e.IsResponse {
		if e.HasResult {
			out["result"] = e.Result
		}
		if e.HasError {
			out["error"] = e.Error
		}
	} else {
		out["method"] = e.Method
		if len(overrideParams) > 0 {
			out["params"] = overrideParams
		} else if e.HasParams {
			out["params"] = e.Params
		}
	}
	return json.Marshal(out)
}

func isValidRPCID(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	if trimmed[0] == '"' {
		var s string
		return json.Unmarshal(trimmed, &s) == nil
	}
	var num json.Number
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&num); err != nil {
		return false
	}
	// Reject booleans/objects/arrays; json.Number only accepts numbers/strings and we handled strings above.
	if trimmed[0] == '{' || trimmed[0] == '[' || trimmed[0] == 't' || trimmed[0] == 'f' {
		return false
	}
	return true
}

type strictToolCallParams struct {
	Name      string
	Arguments json.RawMessage
	Meta      json.RawMessage
	HasMeta   bool
}

var reservedToolCallParamKeys = map[string]struct{}{
	"name":      {},
	"arguments": {},
	"_meta":     {},
}

// parseStrictToolCallParams strictly validates MCP tools/call params:
//   - rejects duplicate or case-colliding keys (e.g. "name"+"Name", "arguments"+"Arguments"),
//   - rejects non-lowercase variants of "name", "arguments", "_meta",
//   - requires exact lowercase non-empty string "name",
//   - normalizes omitted/null "arguments" to "{}", and requires non-null "arguments" to be a valid JSON object.
func parseStrictToolCallParams(raw json.RawMessage) (*strictToolCallParams, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("tools/call requires a \"params\" object")
	}
	if err := validateStrictJSONValue(trimmed); err != nil {
		return nil, fmt.Errorf("invalid tools/call params: %w", err)
	}
	fields, err := parseStrictJSONObject(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid tools/call params: %w", err)
	}
	for k := range fields {
		lower := strings.ToLower(k)
		if _, reserved := reservedToolCallParamKeys[lower]; reserved && k != lower {
			return nil, fmt.Errorf("non-canonical tools/call param key %q (must be lowercase %q)", k, lower)
		}
	}

	rawName, hasName := fields["name"]
	if !hasName {
		return nil, errors.New("tools/call params missing required \"name\" field")
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil || strings.TrimSpace(name) == "" {
		return nil, errors.New("tools/call params \"name\" must be a non-empty string")
	}

	args := json.RawMessage(`{}`)
	if rawArgs, hasArgs := fields["arguments"]; hasArgs {
		trimmedArgs := bytes.TrimSpace(rawArgs)
		if len(trimmedArgs) > 0 && !bytes.Equal(trimmedArgs, []byte("null")) {
			if trimmedArgs[0] != '{' {
				return nil, errors.New("tools/call params \"arguments\" must be a JSON object")
			}
			args = trimmedArgs
		}
	}

	out := &strictToolCallParams{
		Name:      strings.TrimSpace(name),
		Arguments: args,
	}
	if rawMeta, hasMeta := fields["_meta"]; hasMeta {
		out.Meta = rawMeta
		out.HasMeta = true
	}
	return out, nil
}

func (p *strictToolCallParams) marshalCanonical(effectiveArgs json.RawMessage) (json.RawMessage, error) {
	out := make(map[string]any, 3)
	out["name"] = p.Name
	if len(bytes.TrimSpace(effectiveArgs)) > 0 {
		out["arguments"] = effectiveArgs
	} else {
		out["arguments"] = json.RawMessage(`{}`)
	}
	if p.HasMeta {
		out["_meta"] = p.Meta
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return b, nil
}
