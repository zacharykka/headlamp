package metering

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/zacharykka/headlamp/internal/store"
)

//go:embed default_pricing.json
var defaultPricingJSON []byte

// ModelPrice holds USD prices per 1,000,000 tokens.
type ModelPrice struct {
	Input        float64 `json:"input"`
	Output       float64 `json:"output"`
	CacheRead    float64 `json:"cache_read"`
	CacheWrite   float64 `json:"cache_write"`
	CacheWrite1h float64 `json:"cache_write_1h,omitempty"`
}

// PatternPrice binds a glob pattern to a ModelPrice.
type PatternPrice struct {
	Pattern string `json:"pattern"`
	ModelPrice
}

// PriceOverride overrides any non-nil per-1M-token USD prices for a specific route/model.
type PriceOverride struct {
	Input        *float64
	Output       *float64
	CacheRead    *float64
	CacheWrite   *float64
	CacheWrite1h *float64
}

// PriceOverrideFromRoute converts a store.ModelRoute's nullable cost columns into a PriceOverride.
// Returns nil if r is nil or has no cost overrides configured.
func PriceOverrideFromRoute(r *store.ModelRoute) *PriceOverride {
	if r == nil {
		return nil
	}
	if r.InputCostPerMillion == nil &&
		r.OutputCostPerMillion == nil &&
		r.CacheReadCostPerMillion == nil &&
		r.CacheWriteCostPerMillion == nil {
		return nil
	}
	return &PriceOverride{
		Input:      r.InputCostPerMillion,
		Output:     r.OutputCostPerMillion,
		CacheRead:  r.CacheReadCostPerMillion,
		CacheWrite: r.CacheWriteCostPerMillion,
	}
}

type pricingFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Currency      string                `json:"currency"`
	Unit          string                `json:"unit"`
	Models        map[string]ModelPrice `json:"models"`
	Patterns      []PatternPrice        `json:"patterns"`
}

// PricingTable resolves model pricing via exact match followed by ordered doublestar glob patterns.
type PricingTable struct {
	models   map[string]ModelPrice
	patterns []PatternPrice
}

// LoadDefault parses the embedded default_pricing.json table.
func LoadDefault() (*PricingTable, error) {
	return LoadFromBytes(defaultPricingJSON)
}

// LoadFromBytes parses a pricing JSON document into a PricingTable.
func LoadFromBytes(data []byte) (*PricingTable, error) {
	var pf pricingFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("metering: parse pricing table: %w", err)
	}

	models := make(map[string]ModelPrice, len(pf.Models))
	for k, v := range pf.Models {
		models[strings.ToLower(strings.TrimSpace(k))] = v
	}

	patterns := make([]PatternPrice, 0, len(pf.Patterns))
	for _, p := range pf.Patterns {
		pat := strings.ToLower(strings.TrimSpace(p.Pattern))
		if pat == "" {
			continue
		}
		if !doublestar.ValidatePattern(pat) {
			return nil, fmt.Errorf("metering: invalid pricing glob pattern %q", p.Pattern)
		}
		patterns = append(patterns, PatternPrice{
			Pattern:    pat,
			ModelPrice: p.ModelPrice,
		})
	}

	return &PricingTable{
		models:   models,
		patterns: patterns,
	}, nil
}

// Lookup finds pricing for (providerType, model) using exact match first,
// then ordered glob match via doublestar.
func (t *PricingTable) Lookup(providerType, model string) (ModelPrice, bool) {
	if t == nil {
		return ModelPrice{}, false
	}

	key := normalizePricingKey(providerType, model)
	if key == "" {
		return ModelPrice{}, false
	}

	if price, ok := t.models[key]; ok {
		return price, true
	}

	for _, entry := range t.patterns {
		if matchPricingPattern(entry.Pattern, key) {
			return entry.ModelPrice, true
		}
	}
	return ModelPrice{}, false
}

// CalculateCost computes total USD cost for u using exact provider token inclusivity rules:
//   - OpenAI & Gemini: InputTokens INCLUDES CacheReadTokens (uncached = max(0, InputTokens - CacheReadTokens)).
//   - Anthropic: InputTokens EXCLUDES CacheReadTokens, CacheWriteTokens, and CacheWrite1hTokens.
//   - Gemini: ReasoningTokens (thoughtsTokenCount) is EXCLUDED from OutputTokens yet billed at output rate.
//   - OpenAI: ReasoningTokens is ALREADY included in OutputTokens (not double-counted).
//   - Anthropic cache writes: CacheWriteTokens billed at cache_write (5m), CacheWrite1hTokens at cache_write_1h (1h).
func (t *PricingTable) CalculateCost(providerType, model string, u Usage, override *PriceOverride) float64 {
	price, _ := t.Lookup(providerType, model)
	if override != nil {
		if override.Input != nil {
			price.Input = *override.Input
		}
		if override.Output != nil {
			price.Output = *override.Output
		}
		if override.CacheRead != nil {
			price.CacheRead = *override.CacheRead
		}
		if override.CacheWrite != nil {
			price.CacheWrite = *override.CacheWrite
			if override.CacheWrite1h == nil {
				price.CacheWrite1h = *override.CacheWrite
			}
		}
		if override.CacheWrite1h != nil {
			price.CacheWrite1h = *override.CacheWrite1h
		}
	}

	cacheWrite1hRate := price.CacheWrite1h
	if cacheWrite1hRate == 0 && price.CacheWrite > 0 {
		cacheWrite1hRate = price.CacheWrite
	}

	billable := normalizeBillableTokens(providerType, u)

	cost := (float64(billable.uncachedInput)*price.Input +
		float64(billable.cacheRead)*price.CacheRead +
		float64(billable.cacheWrite5m)*price.CacheWrite +
		float64(billable.cacheWrite1h)*cacheWrite1hRate +
		float64(billable.output)*price.Output) / 1_000_000.0

	if cost < 0 {
		return 0
	}
	return cost
}

type billableTokens struct {
	uncachedInput int64
	cacheRead     int64
	cacheWrite5m  int64
	cacheWrite1h  int64
	output        int64
}

func normalizeBillableTokens(providerType string, u Usage) billableTokens {
	provider := canonicalProvider(providerType)
	in := maxInt64(0, u.InputTokens)
	out := maxInt64(0, u.OutputTokens)
	cacheRead := maxInt64(0, u.CacheReadTokens)
	cacheWrite5m := maxInt64(0, u.CacheWriteTokens)
	cacheWrite1h := maxInt64(0, u.CacheWrite1hTokens)
	reasoning := maxInt64(0, u.ReasoningTokens)

	switch provider {
	case "anthropic":
		// Anthropic input_tokens excludes cache_read and cache_creation tokens;
		// output_tokens already includes thinking tokens.
		return billableTokens{
			uncachedInput: in,
			cacheRead:     cacheRead,
			cacheWrite5m:  cacheWrite5m,
			cacheWrite1h:  cacheWrite1h,
			output:        out,
		}
	case "gemini":
		// Gemini promptTokenCount includes cachedContentTokenCount;
		// candidatesTokenCount EXCLUDES thoughtsTokenCount, which is billed at output rate.
		return billableTokens{
			uncachedInput: maxInt64(0, in-cacheRead),
			cacheRead:     cacheRead,
			cacheWrite5m:  cacheWrite5m,
			cacheWrite1h:  cacheWrite1h,
			output:        out + reasoning,
		}
	case "ollama":
		return billableTokens{
			uncachedInput: in,
			cacheRead:     cacheRead,
			cacheWrite5m:  cacheWrite5m,
			cacheWrite1h:  cacheWrite1h,
			output:        out,
		}
	default:
		// OpenAI (chat & responses) and OpenAI-compatible:
		// input/prompt_tokens includes cached_tokens; output/completion_tokens includes reasoning_tokens.
		return billableTokens{
			uncachedInput: maxInt64(0, in-cacheRead),
			cacheRead:     cacheRead,
			cacheWrite5m:  cacheWrite5m,
			cacheWrite1h:  cacheWrite1h,
			output:        out,
		}
	}
}

func canonicalProvider(providerOrProtocol string) string {
	switch strings.ToLower(strings.TrimSpace(providerOrProtocol)) {
	case "anthropic", ProtocolAnthropicMessages:
		return "anthropic"
	case "openai", ProtocolOpenAIChat, ProtocolOpenAIResponses:
		return "openai"
	case "gemini", "google":
		return "gemini"
	case "ollama":
		return "ollama"
	default:
		return strings.ToLower(strings.TrimSpace(providerOrProtocol))
	}
}

func normalizePricingKey(providerType, model string) string {
	p := canonicalProvider(providerType)
	m := strings.ToLower(strings.TrimSpace(model))
	m = strings.TrimPrefix(m, "models/")
	if m == "" {
		return ""
	}
	if p == "" {
		return m
	}
	if strings.HasPrefix(m, p+"/") {
		return m
	}
	// If model already includes a different provider namespace (e.g. "local/llama3"), keep it intact.
	if strings.Contains(m, "/") && (strings.HasPrefix(m, "openai/") ||
		strings.HasPrefix(m, "anthropic/") ||
		strings.HasPrefix(m, "gemini/") ||
		strings.HasPrefix(m, "ollama/") ||
		strings.HasPrefix(m, "local/")) {
		return m
	}
	return p + "/" + m
}

func matchPricingPattern(pattern, key string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	if matched, err := doublestar.Match(pattern, key); err == nil && matched {
		return true
	}
	// Allow prefix wildcards like "ollama/*" or "local/*" to also match slash-delimited
	// model identifiers (e.g. "ollama/hf.co/org/model").
	if strings.HasSuffix(pattern, "/*") {
		deep := strings.TrimSuffix(pattern, "/*") + "/**"
		if matched, err := doublestar.Match(deep, key); err == nil && matched {
			return true
		}
	}
	return false
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
