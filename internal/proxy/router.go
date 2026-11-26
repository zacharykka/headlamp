package proxy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

var errModelNotFound = errors.New("proxy: model not found")

type routeCandidate struct {
	provider      store.Provider
	upstreamModel string
}

type resolvedRoute struct {
	// canonicalModel is passed to Authorizer.AuthorizeModel:
	//   - "<route.Alias>" for virtual model routes (e.g. "team/coding")
	//   - "<provider.Name>/<upstreamModel>" for direct provider models
	canonicalModel string
	isAlias        bool
	costOverride   *CostOverride
	candidates     []routeCandidate
}

type catalogModel struct {
	ID           string
	ProviderName string
	ProviderType string
	IsAlias      bool
	Candidates   []routeCandidate
}

// resolveRoute resolves requestedModel against enabled store routes and providers.
//
// Resolution order:
//  1. Enabled virtual route alias (with primary + fallback chain).
//  2. Explicit "<provider>/<model>" prefix targeting an enabled provider by Name (or Type).
//  3. Bare model matching an enabled provider's Models list (preferring native protocol first,
//     then cross-protocol providers).
//  4. Wildcard enabled provider matching ingressProtocol with an empty Models list.
func resolveRoute(ctx context.Context, st store.Store, ingressProtocol, requestedModel string) (*resolvedRoute, error) {
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return nil, errModelNotFound
	}

	providers, err := st.ListProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxy: list providers: %w", err)
	}
	enabledProviders := make([]store.Provider, 0, len(providers))
	byName := make(map[string]store.Provider, len(providers))
	for _, p := range providers {
		if !p.Enabled {
			continue
		}
		enabledProviders = append(enabledProviders, p)
		byName[p.Name] = p
	}

	routes, err := st.ListModelRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxy: list model routes: %w", err)
	}

	// 1. Virtual route alias match.
	for _, r := range routes {
		if !r.Enabled || r.Alias != requestedModel {
			continue
		}
		var cands []routeCandidate
		if p, ok := byName[r.ProviderName]; ok {
			cands = append(cands, routeCandidate{provider: p, upstreamModel: r.UpstreamModel})
		}
		for _, fb := range r.Fallbacks {
			if p, ok := byName[fb.Provider]; ok {
				cands = append(cands, routeCandidate{provider: p, upstreamModel: fb.Model})
			}
		}
		if len(cands) == 0 {
			return nil, fmt.Errorf("%w: route %q has no enabled providers", errModelNotFound, requestedModel)
		}
		return &resolvedRoute{
			canonicalModel: r.Alias,
			isAlias:        true,
			costOverride:   routeCostOverride(r),
			candidates:     cands,
		}, nil
	}

	// 2. Explicit "<provider>/<model>" prefix match.
	if prefix, modelID, hasSlash := strings.Cut(requestedModel, "/"); hasSlash && prefix != "" && modelID != "" {
		if p, ok := byName[prefix]; ok {
			return &resolvedRoute{
				canonicalModel: p.Name + "/" + modelID,
				candidates:     []routeCandidate{{provider: p, upstreamModel: modelID}},
			}, nil
		}
		// Fallback: match by provider type if no provider is named exactly after prefix.
		var fallbackByType *store.Provider
		for i := range enabledProviders {
			p := &enabledProviders[i]
			if p.Type != prefix {
				continue
			}
			if slices.Contains(p.Models, modelID) {
				return &resolvedRoute{
					canonicalModel: p.Name + "/" + modelID,
					candidates:     []routeCandidate{{provider: *p, upstreamModel: modelID}},
				}, nil
			}
			if fallbackByType == nil {
				fallbackByType = p
			}
		}
		if fallbackByType != nil {
			return &resolvedRoute{
				canonicalModel: fallbackByType.Name + "/" + modelID,
				candidates:     []routeCandidate{{provider: *fallbackByType, upstreamModel: modelID}},
			}, nil
		}
	}

	// 3a. Bare model in an enabled provider's Models list with native protocol match first.
	for _, p := range enabledProviders {
		if isNativeProtocolMatch(ingressProtocol, p.Type) && slices.Contains(p.Models, requestedModel) {
			return &resolvedRoute{
				canonicalModel: p.Name + "/" + requestedModel,
				candidates:     []routeCandidate{{provider: p, upstreamModel: requestedModel}},
			}, nil
		}
	}

	// 3b. Bare model in any enabled provider's Models list (enables cross-protocol routing).
	for _, p := range enabledProviders {
		if slices.Contains(p.Models, requestedModel) {
			return &resolvedRoute{
				canonicalModel: p.Name + "/" + requestedModel,
				candidates:     []routeCandidate{{provider: p, upstreamModel: requestedModel}},
			}, nil
		}
	}

	// 4. Wildcard native provider (enabled provider with empty Models list).
	for _, p := range enabledProviders {
		if isNativeProtocolMatch(ingressProtocol, p.Type) && len(p.Models) == 0 {
			return &resolvedRoute{
				canonicalModel: p.Name + "/" + requestedModel,
				candidates:     []routeCandidate{{provider: p, upstreamModel: requestedModel}},
			}, nil
		}
	}

	return nil, fmt.Errorf("%w: %q", errModelNotFound, requestedModel)
}

func routeCostOverride(r store.ModelRoute) *CostOverride {
	if r.InputCostPerMillion == nil && r.OutputCostPerMillion == nil &&
		r.CacheReadCostPerMillion == nil && r.CacheWriteCostPerMillion == nil {
		return nil
	}
	return &CostOverride{
		Input:      r.InputCostPerMillion,
		Output:     r.OutputCostPerMillion,
		CacheRead:  r.CacheReadCostPerMillion,
		CacheWrite: r.CacheWriteCostPerMillion,
	}
}

func isNativeProtocolMatch(ingressProtocol, providerType string) bool {
	switch ingressProtocol {
	case ProtocolOpenAIChat, ProtocolOpenAIResponses, ProtocolOpenAIEmbeddings:
		return providerType == config.ProviderTypeOpenAI || providerType == config.ProviderTypeOllama
	case ProtocolAnthropicMessages:
		return providerType == config.ProviderTypeAnthropic
	case ProtocolGemini:
		return providerType == config.ProviderTypeGemini
	default:
		return false
	}
}

func canTranslateProtocol(ingressProtocol, providerType string) bool {
	switch ingressProtocol {
	case ProtocolOpenAIChat:
		return providerType == config.ProviderTypeAnthropic
	case ProtocolAnthropicMessages:
		return providerType == config.ProviderTypeOpenAI || providerType == config.ProviderTypeOllama
	default:
		return false
	}
}

func upstreamWireProtocol(ingressProtocol, providerType string) string {
	if isNativeProtocolMatch(ingressProtocol, providerType) {
		return ingressProtocol
	}
	switch providerType {
	case config.ProviderTypeAnthropic:
		return ProtocolAnthropicMessages
	case config.ProviderTypeOpenAI, config.ProviderTypeOllama:
		return ProtocolOpenAIChat
	case config.ProviderTypeGemini:
		return ProtocolGemini
	default:
		return ingressProtocol
	}
}

func listCatalogModels(ctx context.Context, st store.Store) ([]catalogModel, error) {
	providers, err := st.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]store.Provider, len(providers))
	for _, p := range providers {
		if p.Enabled {
			byName[p.Name] = p
		}
	}

	routes, err := st.ListModelRoutes(ctx)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var catalog []catalogModel

	for _, r := range routes {
		if !r.Enabled || r.Alias == "" {
			continue
		}
		var cands []routeCandidate
		if primary, exists := byName[r.ProviderName]; exists {
			cands = append(cands, routeCandidate{provider: primary, upstreamModel: r.UpstreamModel})
		}
		for _, fb := range r.Fallbacks {
			if fp, exists := byName[fb.Provider]; exists {
				cands = append(cands, routeCandidate{provider: fp, upstreamModel: fb.Model})
			}
		}
		if len(cands) == 0 {
			continue
		}
		if _, dup := seen[r.Alias]; dup {
			continue
		}
		seen[r.Alias] = struct{}{}
		catalog = append(catalog, catalogModel{
			ID:           r.Alias,
			ProviderName: cands[0].provider.Name,
			ProviderType: cands[0].provider.Type,
			IsAlias:      true,
			Candidates:   cands,
		})
	}

	for _, p := range providers {
		if !p.Enabled {
			continue
		}
		for _, m := range p.Models {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			id := p.Name + "/" + m
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			catalog = append(catalog, catalogModel{
				ID:           id,
				ProviderName: p.Name,
				ProviderType: p.Type,
				Candidates:   []routeCandidate{{provider: p, upstreamModel: m}},
			})
		}
	}

	sort.Slice(catalog, func(i, j int) bool {
		return catalog[i].ID < catalog[j].ID
	})
	return catalog, nil
}
