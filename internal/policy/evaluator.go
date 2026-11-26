package policy

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

// EffectivePolicy is the merged authorization view resolved for a Principal.
type EffectivePolicy struct {
	Mode            string   `json:"mode"`
	Subject         string   `json:"subject"`
	Groups          []string `json:"groups"`
	Roles           []string `json:"roles"`
	AllowModels     []string `json:"allow_models"`
	DenyModels      []string `json:"deny_models"`
	AllowMCPTools   []string `json:"allow_mcp_tools"`
	DenyMCPTools    []string `json:"deny_mcp_tools"`
	MatchedPolicies []string `json:"matched_policies"`
	GrantsApplied   bool     `json:"grants_applied"`
	BootstrapAdmin  bool     `json:"bootstrap_admin"`
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

// AllowsModel evaluates model access with Explicit Deny Wins semantics.
func (ep *EffectivePolicy) AllowsModel(model string) (allowed bool, reason string) {
	if ep == nil {
		return false, "no effective policy"
	}
	return evaluateResource(model, "model", ep.AllowModels, ep.DenyModels, ep.Mode, ep.GrantsApplied)
}

// AllowsMCPTool evaluates MCP tool access with Explicit Deny Wins semantics.
func (ep *EffectivePolicy) AllowsMCPTool(tool string) (allowed bool, reason string) {
	if ep == nil {
		return false, "no effective policy"
	}
	return evaluateResource(tool, "mcp tool", ep.AllowMCPTools, ep.DenyMCPTools, ep.Mode, ep.GrantsApplied)
}

func evaluateResource(target, kind string, allows, denies []string, mode string, grantsApplied bool) (bool, string) {
	name := strings.TrimSpace(target)
	if name == "" {
		return false, fmt.Sprintf("%s name is empty", kind)
	}

	// Explicit Deny Wins: evaluate all deny patterns before any allow pattern.
	for _, pat := range denies {
		if matchPattern(pat, name) {
			return false, fmt.Sprintf("%s %q explicitly denied by rule %q", kind, name, pat)
		}
	}

	for _, pat := range allows {
		if matchPattern(pat, name) {
			return true, fmt.Sprintf("%s %q allowed by rule %q", kind, name, pat)
		}
	}

	if mode == config.PolicyModeGrantsOnly && !grantsApplied {
		return false, fmt.Sprintf("%s %q denied: no matching Headscale grants", kind, name)
	}
	return false, fmt.Sprintf("%s %q not permitted by any policy rule", kind, name)
}

// Evaluator implements Headlamp's dual-track authorization engine (local policies + Headscale grants).
type Evaluator struct {
	mode            string
	bootstrapAdmins map[string]struct{}
	store           store.Store
}

// NewEvaluator creates an Evaluator for the given PolicyConfig and backing Store.
// Store may be nil in grants_only mode or tests that do not rely on local policies.
func NewEvaluator(cfg config.PolicyConfig, st store.Store) *Evaluator {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = config.PolicyModeHybrid
	}

	admins := make(map[string]struct{}, len(cfg.BootstrapAdmins))
	for _, subj := range cfg.BootstrapAdmins {
		if trimmed := strings.TrimSpace(subj); trimmed != "" {
			admins[trimmed] = struct{}{}
		}
	}

	return &Evaluator{
		mode:            mode,
		bootstrapAdmins: admins,
		store:           st,
	}
}

// Evaluate computes the EffectivePolicy for p according to the configured policy mode
// (hybrid, local_only, or grants_only).
func (e *Evaluator) Evaluate(ctx context.Context, p *auth.Principal) (*EffectivePolicy, error) {
	if p == nil {
		return nil, auth.ErrUnauthenticated
	}

	ep := &EffectivePolicy{
		Mode:    e.mode,
		Subject: strings.TrimSpace(p.Subject),
	}

	_, isBootstrap := e.bootstrapAdmins[ep.Subject]
	if isBootstrap && ep.Subject != "" {
		ep.BootstrapAdmin = true
		ep.Roles = appendUnique(ep.Roles, auth.RoleAdmin)
		ep.Roles = appendUnique(ep.Roles, auth.RoleUser)
	}

	switch e.mode {
	case config.PolicyModeLocalOnly:
		if err := e.applyLocal(ctx, p, ep); err != nil {
			return nil, err
		}
	case config.PolicyModeGrantsOnly:
		if err := e.applyGrants(p, ep); err != nil {
			return nil, err
		}
	case config.PolicyModeHybrid:
		if err := e.applyLocal(ctx, p, ep); err != nil {
			return nil, err
		}
		if err := e.applyGrants(p, ep); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("policy: unsupported policy mode %q", e.mode)
	}

	if slices.Contains(ep.Roles, auth.RoleAdmin) {
		ep.Roles = appendUnique(ep.Roles, auth.RoleUser)
	}

	sort.Strings(ep.Groups)
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

// IsAdmin reports whether p holds the admin role under the configured policy mode.
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

func (e *Evaluator) applyLocal(ctx context.Context, p *auth.Principal, ep *EffectivePolicy) error {
	for _, r := range p.Roles {
		if nr := normalizeRole(r); nr != "" {
			ep.Roles = appendUnique(ep.Roles, nr)
		}
	}

	// Bootstrap admins have full model/MCP allow defaults in hybrid & local_only modes
	// (still subject to Explicit Deny Wins rules).
	if ep.BootstrapAdmin {
		ep.AllowModels = appendUnique(ep.AllowModels, "*")
		ep.AllowMCPTools = appendUnique(ep.AllowMCPTools, "*")
	}

	groups := make([]string, 0, len(p.Groups))
	for _, g := range p.Groups {
		if trimmed := strings.TrimSpace(g); trimmed != "" {
			groups = appendUnique(groups, trimmed)
		}
	}

	if e.store != nil {
		memberKeys := make([]string, 0, 1+len(p.Tags))
		if ep.Subject != "" {
			memberKeys = append(memberKeys, ep.Subject)
		}
		for _, tag := range p.Tags {
			if trimmed := strings.TrimSpace(tag); trimmed != "" {
				memberKeys = appendUnique(memberKeys, trimmed)
			}
		}

		if len(memberKeys) > 0 {
			storeGroups, err := e.store.ListGroupsForMember(ctx, memberKeys...)
			if err != nil {
				return fmt.Errorf("policy: list groups for %q: %w", ep.Subject, err)
			}
			for _, g := range storeGroups {
				if trimmed := strings.TrimSpace(g); trimmed != "" {
					groups = appendUnique(groups, trimmed)
				}
			}
		}

		policies, err := e.store.ListPolicies(ctx)
		if err != nil {
			return fmt.Errorf("policy: list policies: %w", err)
		}

		matchedSubjects := buildMatchedSubjects(ep.Subject, p.Tags, groups)
		for _, pol := range policies {
			if !pol.Enabled {
				continue
			}
			if _, ok := matchedSubjects[strings.TrimSpace(pol.Subject)]; !ok {
				continue
			}

			label := strings.TrimSpace(pol.Name)
			if label == "" {
				label = pol.ID
			}
			ep.MatchedPolicies = appendUnique(ep.MatchedPolicies, label)

			if nr := normalizeRole(pol.Role); nr != "" {
				ep.Roles = appendUnique(ep.Roles, nr)
			}
			for _, m := range pol.AllowModels {
				if trimmed := strings.TrimSpace(m); trimmed != "" {
					ep.AllowModels = appendUnique(ep.AllowModels, trimmed)
				}
			}
			for _, m := range pol.DenyModels {
				if trimmed := strings.TrimSpace(m); trimmed != "" {
					ep.DenyModels = appendUnique(ep.DenyModels, trimmed)
				}
			}
			for _, t := range pol.AllowMCPTools {
				if trimmed := strings.TrimSpace(t); trimmed != "" {
					ep.AllowMCPTools = appendUnique(ep.AllowMCPTools, trimmed)
				}
			}
			for _, t := range pol.DenyMCPTools {
				if trimmed := strings.TrimSpace(t); trimmed != "" {
					ep.DenyMCPTools = appendUnique(ep.DenyMCPTools, trimmed)
				}
			}
		}
	}

	ep.Groups = groups
	return nil
}

func (e *Evaluator) applyGrants(p *auth.Principal, ep *EffectivePolicy) error {
	parsed, err := ParseGrants(p.RawCaps)
	if err != nil {
		return err
	}
	if !parsed.HasGrants {
		return nil
	}

	ep.GrantsApplied = true
	for _, r := range parsed.Roles {
		ep.Roles = appendUnique(ep.Roles, r)
	}
	for _, m := range parsed.AllowModels {
		ep.AllowModels = appendUnique(ep.AllowModels, m)
	}
	for _, m := range parsed.DenyModels {
		ep.DenyModels = appendUnique(ep.DenyModels, m)
	}
	for _, t := range parsed.AllowMCPTools {
		ep.AllowMCPTools = appendUnique(ep.AllowMCPTools, t)
	}
	for _, t := range parsed.DenyMCPTools {
		ep.DenyMCPTools = appendUnique(ep.DenyMCPTools, t)
	}
	return nil
}

func buildMatchedSubjects(subject string, tags, groups []string) map[string]struct{} {
	set := map[string]struct{}{
		"*": {},
	}
	if subject != "" {
		set[subject] = struct{}{}
	}
	for _, tag := range tags {
		if trimmed := strings.TrimSpace(tag); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	for _, g := range groups {
		trimmed := strings.TrimSpace(g)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
		bare := strings.TrimPrefix(trimmed, "group:")
		if bare != "" {
			set["group:"+bare] = struct{}{}
		}
	}
	return set
}

// matchPattern matches a model or MCP tool identifier against a doublestar glob pattern.
//
// Rules:
//   - "*" and "**" match any non-empty target (so config/grant wildcards like "*" match both
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

func appendUnique(list []string, item string) []string {
	if item == "" || slices.Contains(list, item) {
		return list
	}
	return append(list, item)
}
