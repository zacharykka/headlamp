package metering

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
)

const (
	ProtocolOpenAIChat        = "openai_chat"
	ProtocolOpenAIResponses   = "openai_responses"
	ProtocolOpenAIEmbeddings  = "openai_embeddings"
	ProtocolAnthropicMessages = "anthropic_messages"
	ProtocolGemini            = "gemini"
	ProtocolOllama            = "ollama"
)

// Usage holds raw provider token metrics extracted from JSON or SSE responses.
type Usage struct {
	InputTokens        int64
	OutputTokens       int64
	CacheReadTokens    int64
	CacheWriteTokens   int64 // Anthropic 5m ephemeral cache writes (or unclassified cache_creation_input_tokens)
	CacheWrite1hTokens int64 // Anthropic 1h ephemeral cache writes
	ReasoningTokens    int64 // OpenAI reasoning_tokens or Gemini thoughtsTokenCount
	TotalTokens        int64 // Provider-reported total when available
}

// NormalizedTotal returns the total token count respecting each provider's inclusivity rules.
func (u Usage) NormalizedTotal(protocol string) int64 {
	if u.TotalTokens > 0 {
		return u.TotalTokens
	}
	switch canonicalProvider(protocol) {
	case "anthropic":
		return maxInt64(0, u.InputTokens) +
			maxInt64(0, u.CacheReadTokens) +
			maxInt64(0, u.CacheWriteTokens) +
			maxInt64(0, u.CacheWrite1hTokens) +
			maxInt64(0, u.OutputTokens)
	case "gemini":
		return maxInt64(0, u.InputTokens) +
			maxInt64(0, u.OutputTokens) +
			maxInt64(0, u.ReasoningTokens)
	default:
		return maxInt64(0, u.InputTokens) + maxInt64(0, u.OutputTokens)
	}
}

// ParseJSONUsage extracts Usage from a non-streaming response body for the given protocol.
// Supported protocols: openai_chat (or openai), openai_responses, anthropic_messages (or anthropic), gemini, ollama.
func ParseJSONUsage(protocol string, body []byte) Usage {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return Usage{}
	}

	switch normalizeProtocol(protocol) {
	case ProtocolOpenAIChat, ProtocolOpenAIEmbeddings:
		return parseOpenAIChatUsage(trimmed)
	case ProtocolOpenAIResponses:
		return parseOpenAIResponsesUsage(trimmed)
	case ProtocolAnthropicMessages:
		return parseAnthropicJSONUsage(trimmed)
	case ProtocolGemini:
		return parseGeminiJSONUsage(trimmed)
	case ProtocolOllama:
		return parseOllamaJSONUsage(trimmed)
	default:
		// Best-effort fallback for generic OpenAI-compatible payloads.
		if u := parseOpenAIChatUsage(trimmed); u != (Usage{}) {
			return u
		}
		return parseOpenAIResponsesUsage(trimmed)
	}
}

// SSEUsageParser incrementally extracts token usage across streaming SSE frames.
// It is safe for concurrent use.
type SSEUsageParser struct {
	mu       sync.Mutex
	protocol string
	usage    Usage
}

// NewSSEUsageParser creates a stateful streaming usage parser for the given protocol.
func NewSSEUsageParser(protocol string) *SSEUsageParser {
	return &SSEUsageParser{
		protocol: normalizeProtocol(protocol),
	}
}

// Feed processes a single SSE event payload (or NDJSON line for Ollama).
func (p *SSEUsageParser) Feed(eventName string, data []byte) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("[DONE]")) {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	switch p.protocol {
	case ProtocolOpenAIChat:
		if u := parseOpenAIChatUsage(trimmed); u != (Usage{}) {
			p.usage = u
		}
	case ProtocolOpenAIResponses:
		if u, ok := parseOpenAIResponsesSSE(eventName, trimmed); ok {
			p.usage = u
		}
	case ProtocolAnthropicMessages:
		applyAnthropicSSE(&p.usage, eventName, trimmed)
	case ProtocolGemini:
		if u, ok := parseGeminiChunkUsage(trimmed); ok {
			p.usage = u
		}
	case ProtocolOllama:
		if u := parseOllamaLineUsage(trimmed); u != (Usage{}) {
			p.usage = u
		}
	default:
		if u := parseOpenAIChatUsage(trimmed); u != (Usage{}) {
			p.usage = u
		}
	}
}

// Usage returns the accumulated/latest Usage snapshot.
func (p *SSEUsageParser) Usage() Usage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.usage
}

func normalizeProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case ProtocolOpenAIChat, "openai":
		return ProtocolOpenAIChat
	case ProtocolOpenAIResponses, "responses":
		return ProtocolOpenAIResponses
	case ProtocolOpenAIEmbeddings, "embeddings":
		return ProtocolOpenAIEmbeddings
	case ProtocolAnthropicMessages, "anthropic":
		return ProtocolAnthropicMessages
	case ProtocolGemini, "google":
		return ProtocolGemini
	case ProtocolOllama:
		return ProtocolOllama
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

// --- OpenAI Chat Completions ---

type openAIChatPayload struct {
	Usage *openAIChatUsage `json:"usage"`
}

type openAIChatUsage struct {
	PromptTokens        int64 `json:"prompt_tokens"`
	CompletionTokens    int64 `json:"completion_tokens"`
	TotalTokens         int64 `json:"total_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
	// Also tolerate Responses-style fields if a caller passed protocol="openai" on /v1/responses.
	InputTokens        int64 `json:"input_tokens"`
	OutputTokens       int64 `json:"output_tokens"`
	InputTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	OutputTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

func parseOpenAIChatUsage(data []byte) Usage {
	var env openAIChatPayload
	if err := json.Unmarshal(data, &env); err != nil || env.Usage == nil {
		return Usage{}
	}
	u := env.Usage
	in := u.PromptTokens
	out := u.CompletionTokens
	if in == 0 && u.InputTokens > 0 {
		in = u.InputTokens
	}
	if out == 0 && u.OutputTokens > 0 {
		out = u.OutputTokens
	}
	var cached, reasoning int64
	if u.PromptTokensDetails != nil {
		cached = u.PromptTokensDetails.CachedTokens
	} else if u.InputTokensDetails != nil {
		cached = u.InputTokensDetails.CachedTokens
	}
	if u.CompletionTokensDetails != nil {
		reasoning = u.CompletionTokensDetails.ReasoningTokens
	} else if u.OutputTokensDetails != nil {
		reasoning = u.OutputTokensDetails.ReasoningTokens
	}
	return Usage{
		InputTokens:     in,
		OutputTokens:    out,
		CacheReadTokens: cached,
		ReasoningTokens: reasoning,
		TotalTokens:     u.TotalTokens,
	}
}

// --- OpenAI Responses API ---

type openAIResponsesUsage struct {
	InputTokens        int64 `json:"input_tokens"`
	OutputTokens       int64 `json:"output_tokens"`
	TotalTokens        int64 `json:"total_tokens"`
	InputTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	OutputTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

func (u *openAIResponsesUsage) toUsage() Usage {
	if u == nil {
		return Usage{}
	}
	var cached, reasoning int64
	if u.InputTokensDetails != nil {
		cached = u.InputTokensDetails.CachedTokens
	}
	if u.OutputTokensDetails != nil {
		reasoning = u.OutputTokensDetails.ReasoningTokens
	}
	return Usage{
		InputTokens:     u.InputTokens,
		OutputTokens:    u.OutputTokens,
		CacheReadTokens: cached,
		ReasoningTokens: reasoning,
		TotalTokens:     u.TotalTokens,
	}
}

func parseOpenAIResponsesUsage(data []byte) Usage {
	var env struct {
		Usage *openAIResponsesUsage `json:"usage"`
	}
	if err := json.Unmarshal(data, &env); err != nil || env.Usage == nil {
		return Usage{}
	}
	return env.Usage.toUsage()
}

func parseOpenAIResponsesSSE(eventName string, data []byte) (Usage, bool) {
	var env struct {
		Type     string `json:"type"`
		Response *struct {
			Usage *openAIResponsesUsage `json:"usage"`
		} `json:"response"`
		Usage *openAIResponsesUsage `json:"usage"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return Usage{}, false
	}
	evType := env.Type
	if evType == "" {
		evType = strings.TrimSpace(eventName)
	}
	if env.Response != nil && env.Response.Usage != nil {
		// Accept response.completed, response.incomplete, or any response envelope carrying usage.
		if evType == "" || evType == "response.completed" || evType == "response.incomplete" || evType == "response.done" {
			return env.Response.Usage.toUsage(), true
		}
	}
	if env.Usage != nil {
		return env.Usage.toUsage(), true
	}
	return Usage{}, false
}

// --- Anthropic Messages API ---

type anthropicCacheCreation struct {
	Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
	Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
}

type anthropicUsagePayload struct {
	InputTokens              int64                   `json:"input_tokens"`
	OutputTokens             int64                   `json:"output_tokens"`
	CacheCreationInputTokens int64                   `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64                   `json:"cache_read_input_tokens"`
	CacheCreation            *anthropicCacheCreation `json:"cache_creation"`
}

// mergeAnthropicUsage applies cumulative Anthropic usage updates without summing.
// Only non-zero fields overwrite existing values so message_delta (which often omits
// input/cache fields) preserves values recorded from message_start.
func mergeAnthropicUsage(dst *Usage, src *anthropicUsagePayload) {
	if src == nil {
		return
	}
	if src.InputTokens > 0 {
		dst.InputTokens = src.InputTokens
	}
	if src.OutputTokens > 0 {
		dst.OutputTokens = src.OutputTokens
	}
	if src.CacheReadInputTokens > 0 {
		dst.CacheReadTokens = src.CacheReadInputTokens
	}

	if src.CacheCreation != nil && (src.CacheCreation.Ephemeral5mInputTokens > 0 || src.CacheCreation.Ephemeral1hInputTokens > 0) {
		w5m := src.CacheCreation.Ephemeral5mInputTokens
		w1h := src.CacheCreation.Ephemeral1hInputTokens
		// Preserve any uncategorized remainder if aggregate exceeds the split breakdown.
		if rem := src.CacheCreationInputTokens - (w5m + w1h); rem > 0 {
			w5m += rem
		}
		dst.CacheWriteTokens = w5m
		dst.CacheWrite1hTokens = w1h
	} else if src.CacheCreationInputTokens > 0 {
		if dst.CacheWrite1hTokens > 0 {
			// Preserve an existing 5m/1h split from message_start when a cumulative
			// message_delta repeats cache_creation_input_tokens without cache_creation.
			existingTotal := dst.CacheWriteTokens + dst.CacheWrite1hTokens
			if src.CacheCreationInputTokens > existingTotal {
				dst.CacheWriteTokens += src.CacheCreationInputTokens - existingTotal
			}
		} else {
			dst.CacheWriteTokens = src.CacheCreationInputTokens
		}
	}
}

func parseAnthropicJSONUsage(data []byte) Usage {
	var env struct {
		Usage *anthropicUsagePayload `json:"usage"`
	}
	if err := json.Unmarshal(data, &env); err != nil || env.Usage == nil {
		return Usage{}
	}
	var out Usage
	mergeAnthropicUsage(&out, env.Usage)
	return out
}

func applyAnthropicSSE(dst *Usage, eventName string, data []byte) {
	var env struct {
		Type    string `json:"type"`
		Message *struct {
			Usage *anthropicUsagePayload `json:"usage"`
		} `json:"message"`
		Usage *anthropicUsagePayload `json:"usage"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}

	evType := env.Type
	if evType == "" {
		evType = strings.TrimSpace(eventName)
	}
	switch evType {
	case "message_start":
		if env.Message != nil {
			mergeAnthropicUsage(dst, env.Message.Usage)
		}
	case "message_delta":
		mergeAnthropicUsage(dst, env.Usage)
	default:
		if env.Message != nil && env.Message.Usage != nil {
			mergeAnthropicUsage(dst, env.Message.Usage)
		}
		if env.Usage != nil {
			mergeAnthropicUsage(dst, env.Usage)
		}
	}
}

// --- Google Gemini API ---

type geminiUsageMetadata struct {
	PromptTokenCount        int64 `json:"promptTokenCount"`
	CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
	CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
	ThoughtsTokenCount      int64 `json:"thoughtsTokenCount"`
	ToolUsePromptTokenCount int64 `json:"toolUsePromptTokenCount"`
	TotalTokenCount         int64 `json:"totalTokenCount"`
}

func (m *geminiUsageMetadata) toUsage() Usage {
	if m == nil {
		return Usage{}
	}
	return Usage{
		InputTokens:     m.PromptTokenCount + m.ToolUsePromptTokenCount,
		OutputTokens:    m.CandidatesTokenCount,
		CacheReadTokens: m.CachedContentTokenCount,
		ReasoningTokens: m.ThoughtsTokenCount,
		TotalTokens:     m.TotalTokenCount,
	}
}

func parseGeminiChunkUsage(data []byte) (Usage, bool) {
	var env struct {
		UsageMetadata *geminiUsageMetadata `json:"usageMetadata"`
	}
	if err := json.Unmarshal(data, &env); err != nil || env.UsageMetadata == nil {
		return Usage{}, false
	}
	return env.UsageMetadata.toUsage(), true
}

func parseGeminiJSONUsage(data []byte) Usage {
	// Non-SSE Gemini streamGenerateContent returns a JSON array of chunks.
	if data[0] == '[' {
		var chunks []struct {
			UsageMetadata *geminiUsageMetadata `json:"usageMetadata"`
		}
		if err := json.Unmarshal(data, &chunks); err != nil {
			return Usage{}
		}
		var latest Usage
		for _, ch := range chunks {
			if ch.UsageMetadata != nil {
				latest = ch.UsageMetadata.toUsage()
			}
		}
		return latest
	}
	u, _ := parseGeminiChunkUsage(data)
	return u
}

// --- Ollama (OpenAI-compatible & native /api/chat, /api/generate) ---

type ollamaNativePayload struct {
	PromptEvalCount int64 `json:"prompt_eval_count"`
	EvalCount       int64 `json:"eval_count"`
}

func parseOllamaLineUsage(data []byte) Usage {
	if u := parseOpenAIChatUsage(data); u != (Usage{}) {
		return u
	}
	var native ollamaNativePayload
	if err := json.Unmarshal(data, &native); err != nil {
		return Usage{}
	}
	if native.PromptEvalCount == 0 && native.EvalCount == 0 {
		return Usage{}
	}
	return Usage{
		InputTokens:  native.PromptEvalCount,
		OutputTokens: native.EvalCount,
		TotalTokens:  native.PromptEvalCount + native.EvalCount,
	}
}

func parseOllamaJSONUsage(data []byte) Usage {
	// Support single JSON object as well as NDJSON lines.
	if !bytes.ContainsRune(data, '\n') {
		return parseOllamaLineUsage(data)
	}
	var latest Usage
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if u := parseOllamaLineUsage(trimmed); u != (Usage{}) {
			latest = u
		}
	}
	return latest
}
