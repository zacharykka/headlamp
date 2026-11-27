package policy

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/zacharykka/headlamp/internal/auth"
)

// EffectivePolicy is the resolved grants-only authorization view for a Principal.
type EffectivePolicy struct {
	Subject       string   `json:"subject"`
	Roles         []string `json:"roles"`
	AllowModels   []string `json:"allow_models"`
	DenyModels    []string `json:"deny_models"`
	AllowMCPTools []string `json:"allow_mcp_tools"`
	DenyMCPTools  []string `json:"deny_mcp_tools"`
	GrantsApplied bool     `json:"grants_applied"`
}

// HasRole reports whether the effective policy grants the specified role.
// The "admin" role is a superset of "user".
func (ep *EffectivePolicy) HasRole(role string) bool {
	if ep == nil {
		return false
	}
	if slices.Contains(ep.Roles, role) {
		return true
	}
	return role == auth.RoleUser && slices.Contains(ep.Roles, auth.RoleAdmin)
}

// IsAdmin reports whether the effective policy grants administrative privileges.
func (ep *EffectivePolicy) IsAdmin() bool {
	return ep.HasRole(auth.RoleAdmin)
}

// IsModelDenied reports whether model matches any explicit DenyModels rule.
func (ep *EffectivePolicy) IsModelDenied(model string) (denied bool, reason string) {
	if ep == nil {
		return false, ""
	}
	return matchDenyRule(model, "model", ep.DenyModels, matchPattern)
}

// AllowsModel evaluates model access with Explicit Deny Wins semantics.
func (ep *EffectivePolicy) AllowsModel(model string) (allowed bool, reason string) {
	if ep == nil {
		return false, "no effective policy"
	}
	return evaluateResource(model, "model", ep.AllowModels, ep.DenyModels, ep.GrantsApplied, matchPattern)
}

// IsMCPToolDenied reports whether tool matches any explicit DenyMCPTools rule.
func (ep *EffectivePolicy) IsMCPToolDenied(tool string) (denied bool, reason string) {
	if ep == nil {
		return false, ""
	}
	return matchDenyRule(tool, "mcp tool", ep.DenyMCPTools, matchMCPPattern)
}

// AllowsMCPTool evaluates MCP tool access with Explicit Deny Wins semantics.
func (ep *EffectivePolicy) AllowsMCPTool(tool string) (allowed bool, reason string) {
	if ep == nil {
		return false, "no effective policy"
	}
	return evaluateResource(tool, "mcp tool", ep.AllowMCPTools, ep.DenyMCPTools, ep.GrantsApplied, matchMCPPattern)
}

// AllowsMCPServer reports whether at least one MCP tool under serverName could be permitted
// by the effective policy (respecting blanket DenyMCPTools rules and MCP server prefix matching).
func (ep *EffectivePolicy) AllowsMCPServer(serverName string) (allowed bool, reason string) {
	if ep == nil {
		return false, "no effective policy"
	}
	srv := strings.TrimSpace(serverName)
	if srv == "" {
		return false, "mcp server name is empty"
	}

	// Explicit Deny Wins: if any deny rule blanket-denies every tool on serverName, deny server access.
	for _, pat := range ep.DenyMCPTools {
		if isBlanketDenyForServer(pat, srv) {
			return false, fmt.Sprintf("mcp server %q explicitly denied by rule %q", srv, pat)
		}
	}

	for _, pat := range ep.AllowMCPTools {
		if patternMatchesMCPServer(pat, srv) && !isAllowPatternShadowedByDeny(pat, ep.DenyMCPTools) {
			return true, fmt.Sprintf("mcp server %q allowed by rule %q", srv, pat)
		}
	}

	if !ep.GrantsApplied {
		return false, fmt.Sprintf("mcp server %q denied: no matching grants", srv)
	}
	return false, fmt.Sprintf("mcp server %q not permitted by any grant rule", srv)
}

func matchDenyRule(target, kind string, denies []string, matcher func(pattern, target string) bool) (bool, string) {
	name := strings.TrimSpace(target)
	if name == "" {
		return false, ""
	}
	for _, pat := range denies {
		if matcher(pat, name) {
			return true, fmt.Sprintf("%s %q explicitly denied by rule %q", kind, name, pat)
		}
	}
	return false, ""
}

func evaluateResource(target, kind string, allows, denies []string, grantsApplied bool, matcher func(pattern, target string) bool) (bool, string) {
	name := strings.TrimSpace(target)
	if name == "" {
		return false, fmt.Sprintf("%s name is empty", kind)
	}

	// Explicit Deny Wins: evaluate all deny patterns before any allow pattern.
	if denied, reason := matchDenyRule(name, kind, denies, matcher); denied {
		return false, reason
	}

	for _, pat := range allows {
		if matcher(pat, name) {
			return true, fmt.Sprintf("%s %q allowed by rule %q", kind, name, pat)
		}
	}

	if !grantsApplied {
		return false, fmt.Sprintf("%s %q denied: no matching grants", kind, name)
	}
	return false, fmt.Sprintf("%s %q not permitted by any grant rule", kind, name)
}

// Evaluator is Headlamp's stateless grants-only authorization engine.
// It derives permissions solely from Principal.RawCaps (Headscale v0.29+ / Tailscale SaaS
// peer capabilities, or synthesized grants from DevAuthenticator / TokenAuthenticator).
type Evaluator struct{}

// NewEvaluator creates a stateless grants-only Evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// Evaluate computes the EffectivePolicy for p strictly from Principal.RawCaps.
// When no grants are present, Evaluate returns an empty EffectivePolicy (default deny).
func (e *Evaluator) Evaluate(ctx context.Context, p *auth.Principal) (*EffectivePolicy, error) {
	if p == nil {
		return nil, auth.ErrUnauthenticated
	}

	parsed, err := ParseGrants(p.RawCaps)
	if err != nil {
		return nil, err
	}

	ep := &EffectivePolicy{
		Subject: strings.TrimSpace(p.Subject),
	}
	if !parsed.HasGrants {
		return ep, nil
	}

	ep.GrantsApplied = true
	ep.Roles = slices.Clone(parsed.Roles)
	ep.AllowModels = slices.Clone(parsed.AllowModels)
	ep.DenyModels = slices.Clone(parsed.DenyModels)
	ep.AllowMCPTools = slices.Clone(parsed.AllowMCPTools)
	ep.DenyMCPTools = slices.Clone(parsed.DenyMCPTools)

	if slices.Contains(ep.Roles, auth.RoleAdmin) {
		ep.Roles = appendUnique(ep.Roles, auth.RoleUser)
	}
	sort.Strings(ep.Roles)
	return ep, nil
}

// AuthorizeModel checks whether p is allowed to invoke model, returning a human-readable reason.
func (e *Evaluator) AuthorizeModel(ctx context.Context, p *auth.Principal, model string) (allowed bool, reason string, err error) {
	ep, err := e.Evaluate(ctx, p)
	if err != nil {
		return false, "", err
	}
	allowed, reason = ep.AllowsModel(model)
	return allowed, reason, nil
}

// IsModelDenied checks whether model matches any explicit DenyModels rule for p.
// Used by proxy route execution to enforce DenyModels on concrete upstream targets
// behind allowed virtual route aliases.
func (e *Evaluator) IsModelDenied(ctx context.Context, p *auth.Principal, model string) (denied bool, reason string, err error) {
	ep, err := e.Evaluate(ctx, p)
	if err != nil {
		return false, "", err
	}
	denied, reason = ep.IsModelDenied(model)
	return denied, reason, nil
}

// FilterModels returns the subset of models that p is authorized to use, preserving input order.
func (e *Evaluator) FilterModels(ctx context.Context, p *auth.Principal, models []string) ([]string, error) {
	ep, err := e.Evaluate(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(models))
	for _, m := range models {
		if ok, _ := ep.AllowsModel(m); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// IsAdmin reports whether p holds the admin role according to its grants.
func (e *Evaluator) IsAdmin(ctx context.Context, p *auth.Principal) (bool, error) {
	ep, err := e.Evaluate(ctx, p)
	if err != nil {
		return false, err
	}
	return ep.IsAdmin(), nil
}

// AuthorizeMCPTool checks whether p is allowed to see or call the given MCP tool.
func (e *Evaluator) AuthorizeMCPTool(ctx context.Context, p *auth.Principal, tool string) (allowed bool, reason string, err error) {
	ep, err := e.Evaluate(ctx, p)
	if err != nil {
		return false, "", err
	}
	allowed, reason = ep.AllowsMCPTool(tool)
	return allowed, reason, nil
}

// AuthorizeMCPServer checks whether p is allowed to access at least one tool on serverName.
func (e *Evaluator) AuthorizeMCPServer(ctx context.Context, p *auth.Principal, serverName string) (allowed bool, reason string, err error) {
	ep, err := e.Evaluate(ctx, p)
	if err != nil {
		return false, "", err
	}
	allowed, reason = ep.AllowsMCPServer(serverName)
	return allowed, reason, nil
}

// matchPattern matches an LLM model identifier against a doublestar glob pattern.
//
// Rules:
//   - "*" and "**" match any non-empty target (so grant wildcards like "*" match both
//     bare model names and "provider/model" identifiers).
//   - Patterns containing "/" (e.g. "anthropic/*", "anthropic/**", "openai/gpt-5*") match
//     against the full target string via doublestar.Match.
//   - Bare patterns without "/" (e.g. "gpt-4.1*", "claude-sonnet-*") match against both the
//     full target and the bare model portion after the first "/" in "provider/model".
func matchPattern(pattern, target string) bool {
	pat := strings.TrimSpace(pattern)
	if pat == "" || target == "" {
		return false
	}
	if pat == "*" || pat == "**" {
		return true
	}

	if ok, err := doublestar.Match(pat, target); err == nil && ok {
		return true
	}

	if !strings.Contains(pat, "/") {
		if _, bare, hasSlash := strings.Cut(target, "/"); hasSlash && bare != "" {
			if ok, err := doublestar.Match(pat, bare); err == nil && ok {
				return true
			}
		}
	}
	return false
}

// normalizeMCPPattern normalizes MCP tool glob patterns so that a trailing "/*"
// matches arbitrary slash depths under that prefix (equivalent to "/**"), preventing
// multi-segment tool names such as "github/repos/delete" from bypassing "github/*".
func normalizeMCPPattern(pattern string) string {
	pat := strings.TrimSpace(pattern)
	if strings.HasSuffix(pat, "/*") {
		return strings.TrimSuffix(pat, "/*") + "/**"
	}
	return pat
}

// matchMCPPattern matches an MCP tool identifier ("<server>/<tool>") against a glob pattern.
//
// Rules:
//   - "*" and "**" match any non-empty target.
//   - A trailing "/*" (e.g. "github/*") is treated identically to "/**" so tools with
//     embedded slashes (e.g. "github/repos/delete") are matched consistently.
//   - Bare patterns without "/" NEVER perform cross-server suffix matching against
//     "<server>/<tool>" targets (e.g. "github" will NOT match "other/github").
func matchMCPPattern(pattern, target string) bool {
	pat := normalizeMCPPattern(pattern)
	if pat == "" || target == "" {
		return false
	}
	if pat == "*" || pat == "**" {
		return true
	}
	ok, err := doublestar.Match(pat, target)
	return err == nil && ok
}

// isBlanketDenyForServer reports whether pattern denies every possible tool on serverName.
func isBlanketDenyForServer(pattern, serverName string) bool {
	pat := normalizeMCPPattern(pattern)
	if pat == "" || serverName == "" {
		return false
	}
	if pat == "*" || pat == "**" {
		return true
	}
	serverPat, toolPat, hasSlash := strings.Cut(pat, "/")
	if !hasSlash {
		return false
	}
	if toolPat != "*" && toolPat != "**" {
		return false
	}
	if serverPat == "*" || serverPat == "**" {
		return true
	}
	ok, err := doublestar.Match(serverPat, serverName)
	return err == nil && ok
}

// patternMatchesMCPServer reports whether an AllowMCPTools pattern can match at least one
// "<serverName>/<tool>" identifier.
func patternMatchesMCPServer(pattern, serverName string) bool {
	pat := normalizeMCPPattern(pattern)
	if pat == "" || serverName == "" {
		return false
	}
	if pat == "*" || pat == "**" {
		return true
	}
	serverPat, toolPat, hasSlash := strings.Cut(pat, "/")
	if !hasSlash || toolPat == "" {
		return false
	}
	if serverPat == "*" || serverPat == "**" {
		return true
	}
	ok, err := doublestar.Match(serverPat, serverName)
	return err == nil && ok
}

// isAllowPatternShadowedByDeny reports whether an AllowMCPTools pattern is completely negated
// by an explicit DenyMCPTools rule (either exact normalized pattern equality, or a literal
// non-glob allow pattern matched by a deny rule).
func isAllowPatternShadowedByDeny(allowPat string, denies []string) bool {
	normAllow := normalizeMCPPattern(allowPat)
	if normAllow == "" {
		return true
	}
	hasGlobMeta := strings.ContainsAny(normAllow, "*?[{\\")
	for _, deny := range denies {
		normDeny := normalizeMCPPattern(deny)
		if normDeny == "" {
			continue
		}
		if normDeny == normAllow {
			return true
		}
		if !hasGlobMeta && matchMCPPattern(deny, strings.TrimSpace(allowPat)) {
			return true
		}
	}
	return false
}

func appendUnique(list []string, item string) []string {
	if item == "" || slices.Contains(list, item) {
		return list
	}
	return append(list, item)
}
