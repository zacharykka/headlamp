package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zacharykka/headlamp/internal/auth"
)

const (
	// CapHeadlampGateway is Headlamp's native Headscale v0.29+ / Tailscale peer capability name.
	CapHeadlampGateway = auth.CapHeadlampGateway
	// CapApertureCompat is Tailscale Aperture's peer capability name supported on official Tailscale SaaS
	// (Headscale v0.29.7 rejects tailscale.com/* capability names and uses headlamp.dev/cap/gateway).
	CapApertureCompat = "tailscale.com/cap/aperture"
)

// StringOrSlice unmarshals either a single JSON string (Aperture style, e.g. "anthropic/**")
// or an array of strings (Headlamp style, e.g. ["anthropic/*", "openai/gpt-5*"]).
type StringOrSlice []string

// UnmarshalJSON decodes a JSON string, array of strings, or null into StringOrSlice.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*s = nil
		return nil
	}

	if trimmed[0] == '"' {
		var single string
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return err
		}
		if v := strings.TrimSpace(single); v != "" {
			*s = []string{v}
		} else {
			*s = nil
		}
		return nil
	}

	var list []string
	if err := json.Unmarshal(trimmed, &list); err != nil {
		return err
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if v := strings.TrimSpace(item); v != "" {
			out = append(out, v)
		}
	}
	*s = out
	return nil
}

// GrantCapability represents one capability object from headlamp.dev/cap/gateway
// or tailscale.com/cap/aperture in a Headscale/Tailscale grant rule.
type GrantCapability struct {
	Role         string        `json:"role"`
	Models       StringOrSlice `json:"models"`
	DenyModels   StringOrSlice `json:"deny_models"`
	MCPTools     StringOrSlice `json:"mcp_tools"`
	DenyMCPTools StringOrSlice `json:"deny_mcp_tools"`
	Connectors   StringOrSlice `json:"connectors"` // Aperture alias for MCP tools
}

// ParsedGrants holds the merged permissions extracted from a Principal's RawCaps.
type ParsedGrants struct {
	HasGrants     bool
	Roles         []string
	AllowModels   []string
	DenyModels    []string
	AllowMCPTools []string
	DenyMCPTools  []string
}

// ParseGrants decodes and merges Headscale/Tailscale grant capabilities from Principal.RawCaps.
// Both headlamp.dev/cap/gateway and tailscale.com/cap/aperture are recognized; each capability
// value may be a JSON array of objects (matching []tailcfg.RawMessage) or a single JSON object.
func ParseGrants(rawCaps map[string][]byte) (*ParsedGrants, error) {
	out := &ParsedGrants{}
	if len(rawCaps) == 0 {
		return out, nil
	}

	for _, capKey := range []string{CapHeadlampGateway, CapApertureCompat} {
		raw, ok := rawCaps[capKey]
		if !ok {
			continue
		}
		caps, err := decodeGrantCapabilities(raw)
		if err != nil {
			return nil, fmt.Errorf("policy: parse grant capability %q: %w", capKey, err)
		}
		if len(caps) > 0 {
			out.HasGrants = true
		}
		for _, gc := range caps {
			if role := normalizeRole(gc.Role); role != "" {
				out.Roles = appendUnique(out.Roles, role)
			}
			for _, m := range gc.Models {
				out.AllowModels = appendUnique(out.AllowModels, m)
			}
			for _, m := range gc.DenyModels {
				out.DenyModels = appendUnique(out.DenyModels, m)
			}
			for _, t := range gc.MCPTools {
				out.AllowMCPTools = appendUnique(out.AllowMCPTools, t)
			}
			for _, t := range gc.Connectors {
				out.AllowMCPTools = appendUnique(out.AllowMCPTools, t)
			}
			for _, t := range gc.DenyMCPTools {
				out.DenyMCPTools = appendUnique(out.DenyMCPTools, t)
			}
		}
	}

	return out, nil
}

func decodeGrantCapabilities(raw []byte) ([]GrantCapability, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}

	if trimmed[0] == '[' {
		var list []GrantCapability
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, err
		}
		return list, nil
	}

	var single GrantCapability
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, err
	}
	return []GrantCapability{single}, nil
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case auth.RoleAdmin:
		return auth.RoleAdmin
	case auth.RoleUser:
		return auth.RoleUser
	default:
		return ""
	}
}
