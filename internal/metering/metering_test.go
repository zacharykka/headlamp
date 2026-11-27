package metering

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/store"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func floatPtr(v float64) *float64 { return &v }

func TestPricingLookupAndCalculateCost(t *testing.T) {
	pt, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	// Exact match
	p, ok := pt.Lookup("openai", "gpt-5")
	if !ok || !almostEqual(p.Input, 1.25) || !almostEqual(p.Output, 10.00) || !almostEqual(p.CacheRead, 0.125) {
		t.Fatalf("Lookup(openai, gpt-5) = (%+v, %v)", p, ok)
	}

	// Ordered glob match for dated Anthropic snapshot
	p, ok = pt.Lookup("anthropic", "claude-sonnet-4-20250514")
	if !ok || !almostEqual(p.Input, 3.00) || !almostEqual(p.CacheWrite, 3.75) || !almostEqual(p.CacheWrite1h, 6.00) {
		t.Fatalf("Lookup(anthropic, claude-sonnet-4-20250514) = (%+v, %v)", p, ok)
	}

	// Gemini models/ prefix normalization + glob
	p, ok = pt.Lookup("gemini", "models/gemini-2.5-flash-preview-05-20")
	if !ok || !almostEqual(p.Input, 0.30) || !almostEqual(p.Output, 2.50) {
		t.Fatalf("Lookup(gemini, models/gemini-2.5-flash-preview-05-20) = (%+v, %v)", p, ok)
	}

	// Ollama zero-cost (including slash-delimited HF model name)
	p, ok = pt.Lookup("ollama", "hf.co/qwen/qwen2.5-coder:32b")
	if !ok || p.Input != 0 || p.Output != 0 {
		t.Fatalf("Lookup(ollama, slash model) = (%+v, %v)", p, ok)
	}

	// Unknown model falls back to "*" zero-cost rule
	p, ok = pt.Lookup("custom", "totally-unknown-model")
	if !ok || p.Input != 0 || p.Output != 0 {
		t.Fatalf("Lookup(custom, unknown) = (%+v, %v)", p, ok)
	}

	// 1) OpenAI inclusivity: InputTokens INCLUDES CacheReadTokens; OutputTokens INCLUDES ReasoningTokens
	openaiCost := pt.CalculateCost("openai", "gpt-5", Usage{
		InputTokens:     2_500_000,
		CacheReadTokens: 2_000_000,
		OutputTokens:    3_300_000,
		ReasoningTokens: 3_000_000,
	}, nil)
	// uncached_in = 500k * 1.25 = 0.625; cache_read = 2M * 0.125 = 0.25; out = 3.3M * 10.0 = 33.00
	if !almostEqual(openaiCost, 33.875) {
		t.Fatalf("openaiCost = %.9f, want 33.875", openaiCost)
	}

	// Guard against malformed cached > input (must clamp uncached input to 0, never negative)
	clampedCost := pt.CalculateCost("openai", "gpt-5", Usage{
		InputTokens:     100,
		CacheReadTokens: 500,
	}, nil)
	if clampedCost < 0 {
		t.Fatalf("clampedCost = %f, must be non-negative", clampedCost)
	}

	// 2) Anthropic exclusivity + 5m vs 1h cache write tiers
	anthropicCost := pt.CalculateCost("anthropic", "claude-sonnet-4-6", Usage{
		InputTokens:        1_000_000,
		CacheReadTokens:    1_000_000,
		CacheWriteTokens:   1_000_000,
		CacheWrite1hTokens: 1_000_000,
		OutputTokens:       1_000_000,
	}, nil)
	// 3.00 + 0.30 + 3.75 + 6.00 + 15.00 = 28.05
	if !almostEqual(anthropicCost, 28.05) {
		t.Fatalf("anthropicCost = %.9f, want 28.05", anthropicCost)
	}

	// 3) Gemini: promptTokenCount INCLUDES cached; thoughtsTokenCount EXCLUDED from candidatesTokenCount yet billed at output rate
	geminiCost := pt.CalculateCost("gemini", "gemini-2.5-flash", Usage{
		InputTokens:     260_000,
		CacheReadTokens: 120_000,
		OutputTokens:    45_000,
		ReasoningTokens: 22_000,
	}, nil)
	// uncached_in = 140k * 0.30 / 1M = 0.042
	// cache_read  = 120k * 0.03 / 1M = 0.0036
	// billableOut = (45k + 22k) * 2.50 / 1M = 0.1675
	// total = 0.2131
	if !almostEqual(geminiCost, 0.2131) {
		t.Fatalf("geminiCost = %.9f, want 0.2131", geminiCost)
	}

	// 4) Ollama default zero-cost vs custom route price override
	ollamaFree := pt.CalculateCost("ollama", "qwen2.5-coder:32b", Usage{
		InputTokens:  500_000,
		OutputTokens: 250_000,
	}, nil)
	if ollamaFree != 0 {
		t.Fatalf("ollamaFree = %f, want 0", ollamaFree)
	}
	ollamaOverride := pt.CalculateCost("ollama", "qwen2.5-coder:32b", Usage{
		InputTokens:  500_000,
		OutputTokens: 250_000,
	}, &PriceOverride{
		Input:  floatPtr(0.20),
		Output: floatPtr(0.80),
	})
	// 0.5 * 0.20 + 0.25 * 0.80 = 0.10 + 0.20 = 0.30
	if !almostEqual(ollamaOverride, 0.30) {
		t.Fatalf("ollamaOverride = %.9f, want 0.30", ollamaOverride)
	}

	// 5) Anthropic route overriding CacheWrite (e.g. $0.0) without explicit CacheWrite1h must also override 1h tier
	zeroAnthropicOverride := pt.CalculateCost("anthropic", "claude-sonnet-4-6", Usage{
		InputTokens:        1_000_000,
		CacheReadTokens:    1_000_000,
		CacheWriteTokens:   500_000,
		CacheWrite1hTokens: 500_000,
		OutputTokens:       1_000_000,
	}, &PriceOverride{
		Input:      floatPtr(0.0),
		Output:     floatPtr(0.0),
		CacheRead:  floatPtr(0.0),
		CacheWrite: floatPtr(0.0),
	})
	if zeroAnthropicOverride != 0 {
		t.Fatalf("zeroAnthropicOverride = %.9f, want 0", zeroAnthropicOverride)
	}

	customCacheWriteOverride := pt.CalculateCost("anthropic", "claude-sonnet-4-6", Usage{
		CacheWriteTokens:   500_000,
		CacheWrite1hTokens: 500_000,
	}, &PriceOverride{
		CacheWrite: floatPtr(2.0),
	})
	// Both 5m and 1h use overridden $2.0/1M -> 1M * $2.0 = $2.0
	if !almostEqual(customCacheWriteOverride, 2.0) {
		t.Fatalf("customCacheWriteOverride = %.9f, want 2.0", customCacheWriteOverride)
	}
}

func TestParseJSONUsageAllProtocols(t *testing.T) {
	// OpenAI Chat
	u := ParseJSONUsage(ProtocolOpenAIChat, []byte(`{
		"id": "chatcmpl-1",
		"usage": {
			"prompt_tokens": 2500,
			"completion_tokens": 300,
			"total_tokens": 2800,
			"prompt_tokens_details": {"cached_tokens": 2000},
			"completion_tokens_details": {"reasoning_tokens": 50}
		}
	}`))
	if u.InputTokens != 2500 || u.OutputTokens != 300 || u.CacheReadTokens != 2000 || u.ReasoningTokens != 50 || u.TotalTokens != 2800 {
		t.Fatalf("openai_chat usage = %+v", u)
	}

	// OpenAI Embeddings
	uEmb := ParseJSONUsage(ProtocolOpenAIEmbeddings, []byte(`{
		"object": "list",
		"usage": {"prompt_tokens": 42, "total_tokens": 42}
	}`))
	if uEmb.InputTokens != 42 || uEmb.TotalTokens != 42 || uEmb.OutputTokens != 0 {
		t.Fatalf("openai_embeddings usage = %+v", uEmb)
	}

	// OpenAI Responses
	u = ParseJSONUsage(ProtocolOpenAIResponses, []byte(`{
		"id": "resp_1",
		"usage": {
			"input_tokens": 2500,
			"input_tokens_details": {"cached_tokens": 2000},
			"output_tokens": 3300,
			"output_tokens_details": {"reasoning_tokens": 3000},
			"total_tokens": 5800
		}
	}`))
	if u.InputTokens != 2500 || u.CacheReadTokens != 2000 || u.OutputTokens != 3300 || u.ReasoningTokens != 3000 || u.TotalTokens != 5800 {
		t.Fatalf("openai_responses usage = %+v", u)
	}

	// Anthropic Messages with 5m + 1h cache_creation split
	u = ParseJSONUsage(ProtocolAnthropicMessages, []byte(`{
		"id": "msg_1",
		"usage": {
			"input_tokens": 342,
			"cache_creation_input_tokens": 500,
			"cache_read_input_tokens": 1800,
			"cache_creation": {
				"ephemeral_5m_input_tokens": 400,
				"ephemeral_1h_input_tokens": 100
			},
			"output_tokens": 145
		}
	}`))
	if u.InputTokens != 342 || u.CacheReadTokens != 1800 || u.CacheWriteTokens != 400 || u.CacheWrite1hTokens != 100 || u.OutputTokens != 145 {
		t.Fatalf("anthropic usage = %+v", u)
	}
	if got := u.NormalizedTotal(ProtocolAnthropicMessages); got != 2787 {
		t.Fatalf("anthropic normalized total = %d, want 2787", got)
	}

	// Gemini single object + array response
	u = ParseJSONUsage(ProtocolGemini, []byte(`{
		"usageMetadata": {
			"promptTokenCount": 260,
			"cachedContentTokenCount": 120,
			"candidatesTokenCount": 45,
			"thoughtsTokenCount": 22,
			"totalTokenCount": 327
		}
	}`))
	if u.InputTokens != 260 || u.CacheReadTokens != 120 || u.OutputTokens != 45 || u.ReasoningTokens != 22 || u.TotalTokens != 327 {
		t.Fatalf("gemini usage = %+v", u)
	}

	uArr := ParseJSONUsage(ProtocolGemini, []byte(`[
		{"usageMetadata": {"promptTokenCount": 260, "candidatesTokenCount": 10}},
		{"usageMetadata": {"promptTokenCount": 260, "cachedContentTokenCount": 120, "candidatesTokenCount": 45, "thoughtsTokenCount": 22, "totalTokenCount": 327}}
	]`))
	if uArr != u {
		t.Fatalf("gemini array usage = %+v, want %+v", uArr, u)
	}

	// Ollama native NDJSON
	u = ParseJSONUsage(ProtocolOllama, []byte(
		"{\"model\":\"qwen2.5\",\"done\":false}\n"+
			"{\"model\":\"qwen2.5\",\"done\":true,\"prompt_eval_count\":120,\"eval_count\":80}\n",
	))
	if u.InputTokens != 120 || u.OutputTokens != 80 || u.TotalTokens != 200 {
		t.Fatalf("ollama native usage = %+v", u)
	}
}

func TestSSEUsageParserAllProtocolsAndLargePayload(t *testing.T) {
	// 1) OpenAI Chat with empty choices usage chunk + [DONE]
	chatParser := NewSSEUsageParser(ProtocolOpenAIChat)
	chatParser.Feed("", []byte(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"hi"}}],"usage":null}`))
	chatParser.Feed("", []byte(`{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200,"prompt_tokens_details":{"cached_tokens":400}}}`))
	chatParser.Feed("", []byte(`[DONE]`))
	gotChat := chatParser.Usage()
	if gotChat.InputTokens != 1000 || gotChat.OutputTokens != 200 || gotChat.CacheReadTokens != 400 {
		t.Fatalf("chat SSE usage = %+v", gotChat)
	}

	// 2) OpenAI Responses with >64 KiB response.completed payload
	respParser := NewSSEUsageParser(ProtocolOpenAIResponses)
	largeText := strings.Repeat("A", 128*1024) // 128 KiB (> 64 KiB scanner limit)
	largeEvent := fmt.Sprintf(
		`{"type":"response.completed","sequence_number":42,"response":{"id":"resp_big","output":[{"text":%q}],"usage":{"input_tokens":5000,"input_tokens_details":{"cached_tokens":3000},"output_tokens":900,"output_tokens_details":{"reasoning_tokens":600},"total_tokens":5900}}}`,
		largeText,
	)
	respParser.Feed("response.completed", []byte(largeEvent))
	gotResp := respParser.Usage()
	if gotResp.InputTokens != 5000 || gotResp.CacheReadTokens != 3000 || gotResp.OutputTokens != 900 || gotResp.ReasoningTokens != 600 {
		t.Fatalf("responses large SSE usage = %+v", gotResp)
	}

	// 3) Anthropic cumulative overwrite (NOT additive!) + 5m/1h cache split
	anthParser := NewSSEUsageParser(ProtocolAnthropicMessages)
	anthParser.Feed("message_start", []byte(`{
		"type":"message_start",
		"message":{
			"id":"msg_1",
			"usage":{
				"input_tokens":342,
				"cache_creation_input_tokens":500,
				"cache_read_input_tokens":1800,
				"cache_creation":{"ephemeral_5m_input_tokens":400,"ephemeral_1h_input_tokens":100},
				"output_tokens":1
			}
		}
	}`))
	anthParser.Feed("content_block_delta", []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`))
	// Intermediate/final message_delta has cumulative output_tokens=145 (must overwrite 1, NOT sum to 146)
	// and omits input/cache fields (must preserve message_start values).
	anthParser.Feed("message_delta", []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":145}}`))
	anthParser.Feed("message_stop", []byte(`{"type":"message_stop"}`))
	gotAnth := anthParser.Usage()
	if gotAnth.InputTokens != 342 || gotAnth.CacheReadTokens != 1800 || gotAnth.CacheWriteTokens != 400 || gotAnth.CacheWrite1hTokens != 100 || gotAnth.OutputTokens != 145 {
		t.Fatalf("anthropic SSE usage = %+v", gotAnth)
	}

	// 3b) Anthropic cumulative message_delta repeating cache_creation_input_tokens WITHOUT nested cache_creation
	// must preserve the 5m/1h split from message_start (and add only any positive delta to 5m).
	anthSplitParser := NewSSEUsageParser(ProtocolAnthropicMessages)
	anthSplitParser.Feed("message_start", []byte(`{
		"type":"message_start",
		"message":{
			"id":"msg_split",
			"usage":{
				"input_tokens":100,
				"cache_creation_input_tokens":500,
				"cache_creation":{"ephemeral_5m_input_tokens":100,"ephemeral_1h_input_tokens":400},
				"output_tokens":1
			}
		}
	}`))
	anthSplitParser.Feed("message_delta", []byte(`{
		"type":"message_delta",
		"usage":{"input_tokens":100,"cache_creation_input_tokens":500,"output_tokens":50}
	}`))
	gotSplit := anthSplitParser.Usage()
	if gotSplit.CacheWriteTokens != 100 || gotSplit.CacheWrite1hTokens != 400 || gotSplit.OutputTokens != 50 {
		t.Fatalf("anthropic cumulative message_delta wiped 1h split: %+v", gotSplit)
	}
	// If a later cumulative delta increases cache_creation_input_tokens to 550 without cache_creation,
	// keep 1h=400 and add the +50 delta to 5m -> 150.
	anthSplitParser.Feed("message_delta", []byte(`{
		"type":"message_delta",
		"usage":{"cache_creation_input_tokens":550,"output_tokens":80}
	}`))
	gotSplit2 := anthSplitParser.Usage()
	if gotSplit2.CacheWriteTokens != 150 || gotSplit2.CacheWrite1hTokens != 400 || gotSplit2.OutputTokens != 80 {
		t.Fatalf("anthropic cumulative delta increase mismatch: %+v", gotSplit2)
	}

	// 4) Gemini SSE cumulative usageMetadata
	gemParser := NewSSEUsageParser(ProtocolGemini)
	gemParser.Feed("", []byte(`{"candidates":[{"content":{"parts":[{"text":"part1"}]}}],"usageMetadata":{"promptTokenCount":260,"candidatesTokenCount":10}}`))
	gemParser.Feed("", []byte(`{"candidates":[{"content":{"parts":[{"text":"part2"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":260,"cachedContentTokenCount":120,"candidatesTokenCount":45,"thoughtsTokenCount":22,"totalTokenCount":327}}`))
	gotGem := gemParser.Usage()
	if gotGem.InputTokens != 260 || gotGem.CacheReadTokens != 120 || gotGem.OutputTokens != 45 || gotGem.ReasoningTokens != 22 {
		t.Fatalf("gemini SSE usage = %+v", gotGem)
	}

	// 5) Ollama OpenAI-compat SSE
	ollamaParser := NewSSEUsageParser(ProtocolOllama)
	ollamaParser.Feed("", []byte(`{"choices":[],"usage":{"prompt_tokens":310,"completion_tokens":95,"total_tokens":405}}`))
	gotOllama := ollamaParser.Usage()
	if gotOllama.InputTokens != 310 || gotOllama.OutputTokens != 95 {
		t.Fatalf("ollama SSE usage = %+v", gotOllama)
	}
}

func newTestSQLiteStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	st, err := store.NewSQLiteStore(context.Background(), ":memory:", c)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRecorderAsyncFlushWithoutAndWithAuditPayloads(t *testing.T) {
	ctx := context.Background()
	pt, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	// Case A: StorePayloads = false (default privacy-minimal mode)
	t.Run("store_payloads_disabled", func(t *testing.T) {
		st := newTestSQLiteStore(t)
		rec := NewRecorder(st, config.AuditConfig{StorePayloads: false, RetentionDays: 7}, pt, RecorderOptions{
			DisableAutoPurge: true,
		})

		obs := rec.Start(ctx, RequestInfo{
			RequestID:      "req-anth-1",
			Principal:      &auth.Principal{Subject: "alice@example.com", NodeName: "alice-mac", NodeIP: "100.64.0.2", Tags: []string{"tag:dev"}, AuthSource: auth.AuthSourceTSNet},
			Protocol:       ProtocolAnthropicMessages,
			Endpoint:       "/anthropic/v1/messages",
			Provider:       "anthropic",
			ProviderType:   config.ProviderTypeAnthropic,
			RequestedModel: "team/coding",
			UpstreamModel:  "claude-sonnet-4-6",
			Stream:         true,
			RequestBody:    []byte(`{"model":"team/coding","messages":[{"role":"user","content":"hi"}]}`),
		})
		obs.OnSSEEvent("message_start", []byte(`{"type":"message_start","message":{"usage":{"input_tokens":1000,"cache_read_input_tokens":500,"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":100},"output_tokens":1}}}`))
		obs.OnSSEEvent("message_delta", []byte(`{"type":"message_delta","usage":{"output_tokens":300}}`))
		obs.Finish(200, 1250, 210, "")
		// Calling Finish a second time must be a no-op.
		obs.Finish(200, 1250, 210, "")

		if err := rec.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}

		logs, err := st.QueryUsageLogs(ctx, store.UsageFilter{Subject: "alice@example.com"})
		if err != nil {
			t.Fatalf("QueryUsageLogs: %v", err)
		}
		if len(logs) != 1 {
			t.Fatalf("len(logs) = %d, want 1", len(logs))
		}
		got := logs[0]
		if got.InputTokens != 1000 || got.OutputTokens != 300 || got.CacheReadTokens != 500 || got.CacheWriteTokens != 300 || got.TotalTokens != 2100 {
			t.Fatalf("unexpected usage log tokens: %+v", got)
		}
		// Cost: (1000*3.0 + 500*0.30 + 200*3.75 + 100*6.00 + 300*15.0) / 1M
		// = (3000 + 150 + 750 + 600 + 4500) / 1M = 9000 / 1M = 0.009
		if !almostEqual(got.CostUSD, 0.009) {
			t.Fatalf("CostUSD = %.9f, want 0.009", got.CostUSD)
		}

		// No audit payload should be stored when StorePayloads == false.
		if _, err := st.GetAuditPayloadByUsageLogID(ctx, got.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for audit payload, got %v", err)
		}
	})

	// Case B: StorePayloads = true with body capping, header redaction, and retention purge
	t.Run("store_payloads_enabled_and_capped", func(t *testing.T) {
		st := newTestSQLiteStore(t)
		rec := NewRecorder(st, config.AuditConfig{StorePayloads: true, RetentionDays: 7}, pt, RecorderOptions{
			MaxAuditBodyBytes: 64,
			DisableAutoPurge:  true,
		})

		bigReq := []byte(strings.Repeat("x", 200))
		obs := rec.Start(ctx, RequestInfo{
			RequestID:      "req-json-1",
			Timestamp:      time.Now().UTC().Add(-10 * 24 * time.Hour), // 10 days old (eligible for purge)
			Principal:      &auth.Principal{Subject: "bob@example.com", AuthSource: auth.AuthSourceAPIKey},
			Protocol:       ProtocolOpenAIChat,
			Endpoint:       "/v1/chat/completions",
			Provider:       "openai",
			ProviderType:   config.ProviderTypeOpenAI,
			RequestedModel: "gpt-4.1",
			UpstreamModel:  "gpt-4.1",
			RequestHeaders: map[string]string{
				"Authorization": "Bearer sk-personal-secret",
				"Content-Type":  "application/json",
			},
			RequestBody: bigReq,
		})
		obs.SetResponseHeaders(map[string]string{"Content-Type": "application/json"})
		obs.OnJSONResponse([]byte(`{"id":"chatcmpl-1","choices":[{"message":{"content":"` + strings.Repeat("y", 200) + `"}}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`))
		obs.Finish(200, 400, 0, "")

		if err := rec.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}

		logs, err := st.QueryUsageLogs(ctx, store.UsageFilter{Subject: "bob@example.com"})
		if err != nil || len(logs) != 1 {
			t.Fatalf("QueryUsageLogs = (%d, %v)", len(logs), err)
		}

		payload, err := st.GetAuditPayloadByUsageLogID(ctx, logs[0].ID)
		if err != nil {
			t.Fatalf("GetAuditPayloadByUsageLogID: %v", err)
		}
		if payload.RequestHeaders["Authorization"] != "[REDACTED]" {
			t.Fatalf("Authorization header not redacted: %+v", payload.RequestHeaders)
		}
		if !payload.Redacted {
			t.Fatal("expected AuditPayload.Redacted=true when Authorization header was redacted")
		}
		if !strings.HasSuffix(payload.RequestBody, truncationMarker) {
			t.Fatalf("expected truncated request body, got len=%d %q", len(payload.RequestBody), payload.RequestBody)
		}
		if !strings.HasSuffix(payload.ResponseBody, truncationMarker) {
			t.Fatalf("expected truncated response body, got len=%d %q", len(payload.ResponseBody), payload.ResponseBody)
		}

		// PurgeNow should remove the 10-day-old audit payload.
		purged, err := rec.PurgeNow(ctx)
		if err != nil {
			t.Fatalf("PurgeNow: %v", err)
		}
		if purged != 1 {
			t.Fatalf("purged = %d, want 1", purged)
		}
		if _, err := st.GetAuditPayloadByUsageLogID(ctx, logs[0].ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expected purged audit payload to return ErrNotFound, got %v", err)
		}
	})

	// Case C: Recorder.Record clones Principal.Tags so caller mutations after Record cannot race.
	t.Run("record_clones_principal_tags", func(t *testing.T) {
		st := newTestSQLiteStore(t)
		rec := NewRecorder(st, config.AuditConfig{StorePayloads: false}, pt, RecorderOptions{
			DisableAutoPurge: true,
		})
		tags := []string{"tag:original"}
		p := &auth.Principal{Subject: "carol@example.com", Tags: tags, AuthSource: auth.AuthSourceTSNet}
		rec.Record(RequestInfo{
			RequestID:      "req-direct-1",
			Principal:      p,
			Protocol:       ProtocolOllama,
			Provider:       "ollama",
			ProviderType:   config.ProviderTypeOllama,
			RequestedModel: "qwen2.5",
			UpstreamModel:  "qwen2.5",
		}, Usage{InputTokens: 10, OutputTokens: 5}, 200, 100, 20, "", nil)
		// Mutate caller's slice immediately while background worker may be marshaling Tags.
		tags[0] = "tag:mutated"

		if err := rec.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}
		logs, err := st.QueryUsageLogs(ctx, store.UsageFilter{Subject: "carol@example.com"})
		if err != nil || len(logs) != 1 {
			t.Fatalf("QueryUsageLogs = (%d, %v)", len(logs), err)
		}
		if len(logs[0].Tags) != 1 || logs[0].Tags[0] != "tag:original" {
			t.Fatalf("expected cloned tag [tag:original], got %#v", logs[0].Tags)
		}
	})

	// Case D: AuditPayload.Redacted is false when no sensitive headers were present,
	// and true when a response header (e.g. Set-Cookie) was redacted.
	t.Run("audit_redacted_flag_tracking", func(t *testing.T) {
		st := newTestSQLiteStore(t)
		rec := NewRecorder(st, config.AuditConfig{StorePayloads: true, RetentionDays: 7}, pt, RecorderOptions{
			DisableAutoPurge: true,
		})

		obsClean := rec.Start(ctx, RequestInfo{
			RequestID:      "req-clean",
			Principal:      &auth.Principal{Subject: "alice@example.com"},
			Protocol:       ProtocolOpenAIChat,
			Provider:       "openai",
			ProviderType:   config.ProviderTypeOpenAI,
			RequestedModel: "gpt-4.1",
			UpstreamModel:  "gpt-4.1",
			RequestHeaders: map[string]string{"Content-Type": "application/json"},
		})
		obsClean.SetResponseHeaders(map[string]string{"Content-Type": "application/json"})
		obsClean.OnJSONResponse([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
		obsClean.Finish(200, 50, 0, "")

		obsRespRedacted := rec.Start(ctx, RequestInfo{
			RequestID:      "req-resp-redacted",
			Principal:      &auth.Principal{Subject: "bob@example.com"},
			Protocol:       ProtocolOpenAIChat,
			Provider:       "openai",
			ProviderType:   config.ProviderTypeOpenAI,
			RequestedModel: "gpt-4.1",
			UpstreamModel:  "gpt-4.1",
			RequestHeaders: map[string]string{"Content-Type": "application/json"},
		})
		obsRespRedacted.SetResponseHeaders(map[string]string{
			"Content-Type": "application/json",
			"Set-Cookie":   "session=secret",
		})
		obsRespRedacted.OnJSONResponse([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
		obsRespRedacted.Finish(200, 50, 0, "")

		if err := rec.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}

		aliceLogs, _ := st.QueryUsageLogs(ctx, store.UsageFilter{Subject: "alice@example.com"})
		pClean, err := st.GetAuditPayloadByUsageLogID(ctx, aliceLogs[0].ID)
		if err != nil {
			t.Fatalf("GetAuditPayloadByUsageLogID(clean): %v", err)
		}
		if pClean.Redacted {
			t.Fatal("expected Redacted=false when no sensitive headers were present")
		}

		bobLogs, _ := st.QueryUsageLogs(ctx, store.UsageFilter{Subject: "bob@example.com"})
		pResp, err := st.GetAuditPayloadByUsageLogID(ctx, bobLogs[0].ID)
		if err != nil {
			t.Fatalf("GetAuditPayloadByUsageLogID(resp): %v", err)
		}
		if !pResp.Redacted || pResp.ResponseHeaders["Set-Cookie"] != "[REDACTED]" {
			t.Fatalf("expected Redacted=true and redacted Set-Cookie, got %+v", pResp)
		}
	})

	// Case E: GuardrailAction/GuardrailHits persisted, UpdateAuditConfig takes effect live,
	// and WithOnRecorded fires on each persisted UsageLog.
	t.Run("guardrail_fields_live_audit_config_and_on_recorded_callback", func(t *testing.T) {
		st := newTestSQLiteStore(t)
		var recordedLogs []store.UsageLog
		rec := NewRecorder(st, config.AuditConfig{StorePayloads: false, RetentionDays: 7}, pt, RecorderOptions{
			DisableAutoPurge: true,
		}).WithOnRecorded(func(log store.UsageLog) {
			recordedLogs = append(recordedLogs, log)
		})

		// Initially StorePayloads=false
		if rec.AuditConfig().StorePayloads {
			t.Fatal("expected StorePayloads=false initially")
		}
		// Toggle live via UpdateAuditConfig
		rec.UpdateAuditConfig(config.AuditConfig{StorePayloads: true, RetentionDays: 14})
		if got := rec.AuditConfig(); !got.StorePayloads || got.RetentionDays != 14 {
			t.Fatalf("AuditConfig after update = %+v", got)
		}

		obs := rec.Start(ctx, RequestInfo{
			RequestID:       "req-guard-1",
			Principal:       &auth.Principal{Subject: "alice@example.com", AuthSource: auth.AuthSourceTSNet},
			Protocol:        ProtocolOpenAIChat,
			Provider:        "openai",
			ProviderType:    config.ProviderTypeOpenAI,
			RequestedModel:  "gpt-5",
			UpstreamModel:   "gpt-5",
			RequestBody:     []byte(`{"messages":[{"role":"user","content":"[REDACTED:AWS_KEY]"}]}`),
			GuardrailAction: config.GuardrailActionRedact,
			GuardrailHits:   []string{"builtin-aws-access-key"},
		})
		obs.OnJSONResponse([]byte(`{"usage":{"prompt_tokens":1000,"completion_tokens":100,"total_tokens":1100}}`))
		obs.Finish(200, 120, 0, "")

		if err := rec.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}

		if len(recordedLogs) != 1 || recordedLogs[0].GuardrailAction != config.GuardrailActionRedact ||
			len(recordedLogs[0].GuardrailHits) != 1 || recordedLogs[0].GuardrailHits[0] != "builtin-aws-access-key" {
			t.Fatalf("WithOnRecorded callback received unexpected logs: %+v", recordedLogs)
		}

		// Audit payload must exist because UpdateAuditConfig enabled StorePayloads before Start.
		payload, err := st.GetAuditPayloadByUsageLogID(ctx, recordedLogs[0].ID)
		if err != nil || !strings.Contains(payload.RequestBody, "REDACTED:AWS_KEY") {
			t.Fatalf("expected audit payload persisted after runtime UpdateAuditConfig, got (%+v, %v)", payload, err)
		}
	})
}

func TestDefaultPricingSyncedWithSpec(t *testing.T) {
	specPath := filepath.Join("..", "..", "docs", "specs", "default_pricing.json")
	specBytes, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec pricing %q: %v", specPath, err)
	}
	if !bytes.Equal(defaultPricingJSON, specBytes) {
		t.Fatalf("internal/metering/default_pricing.json has drifted from %s", specPath)
	}
}
