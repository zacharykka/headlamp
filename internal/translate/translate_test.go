package translate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadSSEEventLargePayload(t *testing.T) {
	// >200 KiB single SSE data line (exceeds bufio.Scanner's 64 KiB cap by >3x).
	largeText := strings.Repeat("a", 210*1024)
	wire := ": keepalive comment\r\n" +
		"event: content_block_delta\r\n" +
		"data: {\"text\":\"" + largeText + "\"}\r\n" +
		"\r\n" +
		"data: line1\n" +
		"data: line2\n" +
		"\n"

	r := bufio.NewReaderSize(strings.NewReader(wire), 4096)

	ev1, err := ReadSSEEvent(r)
	if err != nil {
		t.Fatalf("ReadSSEEvent 1: %v", err)
	}
	if ev1.Event != "content_block_delta" {
		t.Fatalf("expected event content_block_delta, got %q", ev1.Event)
	}
	if !strings.Contains(string(ev1.Data), largeText) {
		t.Fatalf("large payload truncated: got len %d", len(ev1.Data))
	}

	ev2, err := ReadSSEEvent(r)
	if err != nil {
		t.Fatalf("ReadSSEEvent 2: %v", err)
	}
	if ev2.Event != "" || string(ev2.Data) != "line1\nline2" {
		t.Fatalf("unexpected multi-line event: %+v", ev2)
	}

	if _, err := ReadSSEEvent(r); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestOpenAIRequestToAnthropic(t *testing.T) {
	input := `{
		"model": "anthropic/claude-sonnet-4-6",
		"stream": true,
		"stream_options": {"include_usage": true},
		"stop": "END",
		"temperature": 0.2,
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "developer", "content": "Follow JSON rules."},
			{"role": "user", "content": [
				{"type": "text", "text": "Inspect this"},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,aGVsbG8="}},
				{"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
			]},
			{"role": "assistant", "content": "Checking...", "tool_calls": [
				{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}},
				{"id": "call_2", "type": "function", "function": {"name": "get_time", "arguments": ""}}
			]},
			{"role": "tool", "tool_call_id": "call_1", "content": "65F"},
			{"role": "tool", "tool_call_id": "call_2", "content": "10:00"},
			{"role": "user", "content": "Summarize both"}
		],
		"tools": [{
			"type": "function",
			"function": {
				"name": "get_weather",
				"description": "Weather lookup",
				"parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
			}
		}],
		"tool_choice": "required"
	}`

	outBytes, err := OpenAIRequestToAnthropic([]byte(input), "claude-sonnet-4-6")
	if err != nil {
		t.Fatalf("OpenAIRequestToAnthropic failed: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(outBytes, &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	if out["model"] != "claude-sonnet-4-6" {
		t.Fatalf("unexpected model: %v", out["model"])
	}
	if int(out["max_tokens"].(float64)) != DefaultAnthropicMaxTokens {
		t.Fatalf("expected default max_tokens %d, got %v", DefaultAnthropicMaxTokens, out["max_tokens"])
	}
	if _, hasStreamOpts := out["stream_options"]; hasStreamOpts {
		t.Fatalf("stream_options must be stripped for Anthropic")
	}
	if out["system"] != "You are helpful.\n\nFollow JSON rules." {
		t.Fatalf("unexpected system: %q", out["system"])
	}
	stops := out["stop_sequences"].([]any)
	if len(stops) != 1 || stops[0] != "END" {
		t.Fatalf("unexpected stop_sequences: %v", stops)
	}
	tc := out["tool_choice"].(map[string]any)
	if tc["type"] != "any" {
		t.Fatalf("expected tool_choice type 'any', got %v", tc)
	}

	msgs := out["messages"].([]any)
	// Turns must strictly alternate: user -> assistant -> user (merged 2 tool_results + trailing user text).
	if len(msgs) != 3 {
		t.Fatalf("expected 3 alternating messages, got %d: %s", len(msgs), string(outBytes))
	}

	// Verify user image conversion.
	u0 := msgs[0].(map[string]any)
	u0Blocks := u0["content"].([]any)
	if len(u0Blocks) != 3 {
		t.Fatalf("expected 3 blocks in user[0], got %d", len(u0Blocks))
	}
	img1 := u0Blocks[1].(map[string]any)["source"].(map[string]any)
	if img1["type"] != "base64" || img1["media_type"] != "image/png" || img1["data"] != "aGVsbG8=" {
		t.Fatalf("unexpected base64 image block: %v", img1)
	}
	img2 := u0Blocks[2].(map[string]any)["source"].(map[string]any)
	if img2["type"] != "url" || img2["url"] != "https://example.com/a.png" {
		t.Fatalf("unexpected url image block: %v", img2)
	}

	// Verify assistant tool_use blocks have parsed object inputs.
	a1 := msgs[1].(map[string]any)
	a1Blocks := a1["content"].([]any)
	if len(a1Blocks) != 3 {
		t.Fatalf("expected 3 blocks in assistant turn, got %d", len(a1Blocks))
	}
	tu1 := a1Blocks[1].(map[string]any)
	if tu1["type"] != "tool_use" || tu1["id"] != "call_1" || tu1["input"].(map[string]any)["city"] != "SF" {
		t.Fatalf("unexpected tool_use 1: %v", tu1)
	}
	tu2 := a1Blocks[2].(map[string]any)
	if len(tu2["input"].(map[string]any)) != 0 {
		t.Fatalf("expected empty object input for empty arguments, got %v", tu2["input"])
	}

	// Verify consecutive tool messages + trailing user message merged into one user turn.
	u2 := msgs[2].(map[string]any)
	if u2["role"] != "user" {
		t.Fatalf("expected role user for merged tool results, got %v", u2["role"])
	}
	u2Blocks := u2["content"].([]any)
	if len(u2Blocks) != 3 {
		t.Fatalf("expected 3 merged blocks (2 tool_result + 1 text), got %d: %v", len(u2Blocks), u2Blocks)
	}
	if u2Blocks[0].(map[string]any)["type"] != "tool_result" || u2Blocks[1].(map[string]any)["type"] != "tool_result" || u2Blocks[2].(map[string]any)["type"] != "text" {
		t.Fatalf("unexpected merged block types: %v", u2Blocks)
	}
}

func TestOpenAIRequestMaxCompletionTokensPriority(t *testing.T) {
	input := `{"model":"x","max_tokens":100,"max_completion_tokens":2048,"messages":[{"role":"user","content":"hi"}]}`
	out, err := OpenAIRequestToAnthropic([]byte(input), "claude-haiku-4-5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed anthropicRequest
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.MaxTokens != 2048 {
		t.Fatalf("expected max_tokens 2048, got %d", parsed.MaxTokens)
	}
}

func TestAnthropicRequestToOpenAI(t *testing.T) {
	input := `{
		"model": "openai/gpt-4.1",
		"max_tokens": 1024,
		"stream": true,
		"system": [{"type": "text", "text": "Be concise."}],
		"stop_sequences": ["DONE"],
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "Look at image"},
				{"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "QUJD"}}
			]},
			{"role": "assistant", "content": [
				{"type": "thinking", "thinking": "internal thought", "signature": "sig123"},
				{"type": "text", "text": "Calling tool"},
				{"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"q": "go"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "result text"}]},
				{"type": "text", "text": "Thanks"}
			]}
		],
		"tools": [{
			"name": "lookup",
			"description": "Search docs",
			"input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}
		}],
		"tool_choice": {"type": "tool", "name": "lookup"}
	}`

	outBytes, err := AnthropicRequestToOpenAI([]byte(input), "gpt-4.1", "openai")
	if err != nil {
		t.Fatalf("AnthropicRequestToOpenAI failed: %v", err)
	}

	var out openAIChatRequest
	if err := json.Unmarshal(outBytes, &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	if out.Model != "gpt-4.1" {
		t.Fatalf("expected gpt-4.1, got %q", out.Model)
	}
	if out.MaxCompletionTokens == nil || *out.MaxCompletionTokens != 1024 || out.MaxTokens != nil {
		t.Fatalf("expected max_completion_tokens=1024 and nil max_tokens for openai, got max_completion_tokens=%v max_tokens=%v", out.MaxCompletionTokens, out.MaxTokens)
	}
	if out.StreamOptions == nil || !out.StreamOptions.IncludeUsage {
		t.Fatalf("expected stream_options.include_usage=true for streaming request")
	}
	// system + user + assistant + tool + user = 5 messages
	if len(out.Messages) != 5 {
		t.Fatalf("expected 5 messages, got %d: %s", len(out.Messages), string(outBytes))
	}
	if out.Messages[0].Role != "system" || extractOpenAIText(out.Messages[0].Content) != "Be concise." {
		t.Fatalf("unexpected system message: %+v", out.Messages[0])
	}
	if out.Messages[2].Role != "assistant" || len(out.Messages[2].ToolCalls) != 1 {
		t.Fatalf("unexpected assistant message: %+v", out.Messages[2])
	}
	if out.Messages[2].ToolCalls[0].Function.Arguments != `{"q":"go"}` {
		t.Fatalf("unexpected tool arguments: %q", out.Messages[2].ToolCalls[0].Function.Arguments)
	}
	if out.Messages[3].Role != "tool" || out.Messages[3].ToolCallID != "toolu_1" || extractOpenAIText(out.Messages[3].Content) != "result text" {
		t.Fatalf("unexpected tool result message: %+v", out.Messages[3])
	}
	if out.Messages[4].Role != "user" || extractOpenAIText(out.Messages[4].Content) != "Thanks" {
		t.Fatalf("unexpected trailing user message: %+v", out.Messages[4])
	}
	if !strings.Contains(string(out.ToolChoice), `"lookup"`) {
		t.Fatalf("unexpected tool_choice: %s", string(out.ToolChoice))
	}
}

func TestNonStreamingResponseTranslation(t *testing.T) {
	// 1. Anthropic -> OpenAI (exclusive -> inclusive usage + tool_use + thinking omitted)
	anthropicResp := `{
		"id": "msg_01abc",
		"type": "message",
		"role": "assistant",
		"model": "claude-sonnet-4-6",
		"content": [
			{"type": "thinking", "thinking": "hmm", "signature": "sig"},
			{"type": "tool_use", "id": "toolu_1", "name": "calc", "input": {"x": 2}}
		],
		"stop_reason": "tool_use",
		"usage": {
			"input_tokens": 100,
			"cache_read_input_tokens": 400,
			"cache_creation_input_tokens": 50,
			"output_tokens": 30
		}
	}`

	openAIBytes, err := AnthropicResponseToOpenAI([]byte(anthropicResp), "team/coding")
	if err != nil {
		t.Fatalf("AnthropicResponseToOpenAI: %v", err)
	}
	var oResp openAIChatResponse
	if err := json.Unmarshal(openAIBytes, &oResp); err != nil {
		t.Fatal(err)
	}
	if oResp.Model != "team/coding" {
		t.Fatalf("expected model team/coding, got %q", oResp.Model)
	}
	if oResp.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("expected finish_reason tool_calls, got %q", oResp.Choices[0].FinishReason)
	}
	if oResp.Choices[0].Message.Content != nil {
		t.Fatalf("expected null content when only tool_use present, got %v", *oResp.Choices[0].Message.Content)
	}
	if len(oResp.Choices[0].Message.ToolCalls) != 1 || oResp.Choices[0].Message.ToolCalls[0].Function.Arguments != `{"x":2}` {
		t.Fatalf("unexpected tool calls: %+v", oResp.Choices[0].Message.ToolCalls)
	}
	if oResp.Usage.PromptTokens != 550 || oResp.Usage.PromptTokensDetails.CachedTokens != 400 || oResp.Usage.CompletionTokens != 30 {
		t.Fatalf("unexpected OpenAI usage mapping: %+v", oResp.Usage)
	}

	// 2. OpenAI -> Anthropic (inclusive -> exclusive usage + tool_calls)
	openAIResp := `{
		"id": "chatcmpl-xyz",
		"object": "chat.completion",
		"created": 1700000000,
		"model": "gpt-4.1",
		"choices": [{
			"index": 0,
			"message": {
				"role": "assistant",
				"content": "Let me run that.",
				"tool_calls": [{
					"id": "call_99",
					"type": "function",
					"function": {"name": "search", "arguments": "{\"q\":\"headscale\"}"}
				}]
			},
			"finish_reason": "tool_calls"
		}],
		"usage": {
			"prompt_tokens": 1000,
			"completion_tokens": 60,
			"total_tokens": 1060,
			"prompt_tokens_details": {"cached_tokens": 750}
		}
	}`

	anthBytes, err := OpenAIResponseToAnthropic([]byte(openAIResp), "gpt-4.1")
	if err != nil {
		t.Fatalf("OpenAIResponseToAnthropic: %v", err)
	}
	var aResp anthropicResponse
	if err := json.Unmarshal(anthBytes, &aResp); err != nil {
		t.Fatal(err)
	}
	if aResp.StopReason == nil || *aResp.StopReason != "tool_use" {
		t.Fatalf("expected stop_reason tool_use, got %v", aResp.StopReason)
	}
	if len(aResp.Content) != 2 || aResp.Content[0].Type != "text" || aResp.Content[1].Type != "tool_use" {
		t.Fatalf("unexpected anthropic content blocks: %+v", aResp.Content)
	}
	if aResp.Usage.InputTokens != 250 || aResp.Usage.CacheReadInputTokens != 750 || aResp.Usage.OutputTokens != 60 {
		t.Fatalf("unexpected exclusive anthropic usage: %+v", aResp.Usage)
	}
}

func TestStreamAnthropicToOpenAIWithThinkingAndMultipleTools(t *testing.T) {
	// Block 0 = thinking, Block 1 = text, Block 2 = tool_use #1, Block 3 = tool_use #2.
	// OpenAI tool_call indices MUST be 0 and 1 (NOT Anthropic's block indices 2 and 3!).
	upstreamSSE := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"usage":{"input_tokens":100,"cache_read_input_tokens":500,"cache_creation_input_tokens":50,"output_tokens":1}}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"reasoning..."}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig_abc"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Working..."}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":1}`,
		``,
		`event: ping`,
		`data: {"type":"ping"}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_a","name":"fn_a","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"a\":1}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":2}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":3,"content_block":{"type":"tool_use","id":"toolu_b","name":"fn_b","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\"b\":2}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":3}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":42}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	rec := httptest.NewRecorder()
	var upstreamEvents int
	var firstTokenCalls int
	err := StreamAnthropicToOpenAI(strings.NewReader(upstreamSSE), rec, rec, StreamOptions{
		RequestedModel: "team/coding",
		IncludeUsage:   true,
		OnUpstreamEvent: func(string, []byte) {
			upstreamEvents++
		},
		OnFirstToken: func() {
			firstTokenCalls++
		},
	})
	if err != nil {
		t.Fatalf("StreamAnthropicToOpenAI failed: %v", err)
	}
	if upstreamEvents != 17 {
		t.Fatalf("expected 17 upstream events observed, got %d", upstreamEvents)
	}
	if firstTokenCalls != 1 {
		t.Fatalf("expected OnFirstToken called once, got %d", firstTokenCalls)
	}

	// Parse emitted OpenAI SSE chunks.
	reader := bufio.NewReader(bytes.NewReader(rec.Body.Bytes()))
	var (
		gotText       strings.Builder
		toolIdxByID   = make(map[string]int)
		toolArgsByIdx = make(map[int]string)
		finishReason  string
		finalUsage    *openAIUsage
		gotDone       bool
	)
	for {
		ev, err := ReadSSEEvent(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read translated sse: %v", err)
		}
		if string(ev.Data) == "[DONE]" {
			gotDone = true
			continue
		}
		var chunk openAIChatChunk
		if err := json.Unmarshal(ev.Data, &chunk); err != nil {
			t.Fatalf("unmarshal chunk %q: %v", string(ev.Data), err)
		}
		if chunk.Usage != nil && len(chunk.Choices) == 0 {
			finalUsage = chunk.Usage
			continue
		}
		c := chunk.Choices[0]
		if c.Delta.Content != nil {
			gotText.WriteString(*c.Delta.Content)
		}
		for _, tc := range c.Delta.ToolCalls {
			if tc.ID != "" {
				toolIdxByID[tc.ID] = tc.Index
			}
			toolArgsByIdx[tc.Index] += tc.Function.Arguments
		}
		if c.FinishReason != nil {
			finishReason = *c.FinishReason
		}
	}

	if !gotDone {
		t.Fatalf("missing [DONE] sentinel")
	}
	if gotText.String() != "Working..." {
		t.Fatalf("unexpected text: %q", gotText.String())
	}
	if toolIdxByID["toolu_a"] != 0 || toolIdxByID["toolu_b"] != 1 {
		t.Fatalf("expected tool indices 0 and 1, got %v", toolIdxByID)
	}
	if toolArgsByIdx[0] != `{"a":1}` || toolArgsByIdx[1] != `{"b":2}` {
		t.Fatalf("unexpected tool args: %v", toolArgsByIdx)
	}
	if finishReason != "tool_calls" {
		t.Fatalf("expected finish_reason tool_calls, got %q", finishReason)
	}
	if finalUsage == nil || finalUsage.PromptTokens != 650 || finalUsage.CompletionTokens != 42 || finalUsage.PromptTokensDetails.CachedTokens != 500 {
		t.Fatalf("unexpected final usage: %+v", finalUsage)
	}
}

func TestStreamOpenAIToAnthropicWithTextAndToolCalls(t *testing.T) {
	upstreamSSE := strings.Join([]string{
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`,
		``,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"content":"Hi "},"finish_reason":null}]}`,
		``,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"content":"there"},"finish_reason":null}]}`,
		``,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":""}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":\"a.go\"}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"stat","arguments":"{\"p\":\"b\"}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		``,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[],"usage":{"prompt_tokens":300,"completion_tokens":50,"total_tokens":350,"prompt_tokens_details":{"cached_tokens":120}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	rec := httptest.NewRecorder()
	var upstreamEvents int
	var firstTokenCalls int
	err := StreamOpenAIToAnthropic(strings.NewReader(upstreamSSE), rec, rec, StreamOptions{
		RequestedModel: "openai/gpt-4.1",
		OnUpstreamEvent: func(string, []byte) {
			upstreamEvents++
		},
		OnFirstToken: func() {
			firstTokenCalls++
		},
	})
	if err != nil {
		t.Fatalf("StreamOpenAIToAnthropic failed: %v", err)
	}
	if upstreamEvents != 8 {
		t.Fatalf("expected 8 upstream JSON chunks (excluding [DONE]), got %d", upstreamEvents)
	}
	if firstTokenCalls != 1 {
		t.Fatalf("expected OnFirstToken once, got %d", firstTokenCalls)
	}

	reader := bufio.NewReader(bytes.NewReader(rec.Body.Bytes()))
	var (
		eventOrder []string
		blocks     = make(map[int]string)
		textOut    strings.Builder
		jsonByIdx  = make(map[int]string)
		finalDelta *anthropicMessageDeltaEvent
	)
	for {
		ev, err := ReadSSEEvent(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read translated anthropic sse: %v", err)
		}
		eventOrder = append(eventOrder, ev.Event)
		switch ev.Event {
		case "content_block_start":
			var rawBlock map[string]any
			if err := json.Unmarshal(ev.Data, &rawBlock); err != nil {
				t.Fatal(err)
			}
			cb := rawBlock["content_block"].(map[string]any)
			if cb["type"] == "text" {
				textVal, hasTextKey := cb["text"]
				if !hasTextKey || textVal != "" {
					t.Fatalf("content_block_start for text MUST serialize explicit \"text\":\"\", got: %s", string(ev.Data))
				}
			}
			var s anthropicContentBlockStartEvent
			if err := json.Unmarshal(ev.Data, &s); err != nil {
				t.Fatal(err)
			}
			blocks[s.Index] = s.ContentBlock.Type
		case "content_block_delta":
			var d anthropicContentBlockDeltaEvent
			if err := json.Unmarshal(ev.Data, &d); err != nil {
				t.Fatal(err)
			}
			if d.Delta.Type == "text_delta" {
				textOut.WriteString(d.Delta.Text)
			} else if d.Delta.Type == "input_json_delta" {
				jsonByIdx[d.Index] += d.Delta.PartialJSON
			}
		case "message_delta":
			var md anthropicMessageDeltaEvent
			if err := json.Unmarshal(ev.Data, &md); err != nil {
				t.Fatal(err)
			}
			finalDelta = &md
		}
	}

	if eventOrder[0] != "message_start" || eventOrder[len(eventOrder)-1] != "message_stop" {
		t.Fatalf("unexpected lifecycle bookends: %v", eventOrder)
	}
	if blocks[0] != "text" || blocks[1] != "tool_use" || blocks[2] != "tool_use" {
		t.Fatalf("unexpected block types by index: %v", blocks)
	}
	if textOut.String() != "Hi there" {
		t.Fatalf("unexpected text output: %q", textOut.String())
	}
	if jsonByIdx[1] != `{"path":"a.go"}` || jsonByIdx[2] != `{"p":"b"}` {
		t.Fatalf("unexpected tool JSON deltas: %v", jsonByIdx)
	}
	if finalDelta == nil || finalDelta.Delta.StopReason == nil || *finalDelta.Delta.StopReason != "tool_use" {
		t.Fatalf("unexpected final message_delta: %+v", finalDelta)
	}
	if finalDelta.Usage.InputTokens != 180 || finalDelta.Usage.CacheReadInputTokens != 120 || finalDelta.Usage.OutputTokens != 50 {
		t.Fatalf("unexpected translated exclusive usage: %+v", finalDelta.Usage)
	}
}

// Compile-time check that httptest.ResponseRecorder satisfies http.Flusher.
var _ http.Flusher = (*httptest.ResponseRecorder)(nil)

func TestOpenAIRequestEmptyUserContentSerializesTextKey(t *testing.T) {
	outBytes, err := OpenAIRequestToAnthropic([]byte(`{"model":"x","messages":[{"role":"user","content":""}]}`), "claude-sonnet-4-6")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(outBytes), `"type":"text","text":""`) {
		t.Fatalf("expected explicit empty text field in request block, got: %s", string(outBytes))
	}
}

func TestStreamOpenAIToAnthropicMidStreamError(t *testing.T) {
	upstreamSSE := strings.Join([]string{
		`data: {"id":"chatcmpl-e1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"role":"assistant","content":"partial"},"finish_reason":null}]}`,
		``,
		`data: {"error":{"message":"upstream backend failed","type":"server_error","code":"server_error"}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	rec := httptest.NewRecorder()
	err := StreamOpenAIToAnthropic(strings.NewReader(upstreamSSE), rec, rec, StreamOptions{
		RequestedModel: "openai/gpt-4.1",
	})
	if err == nil {
		t.Fatalf("expected non-nil error on mid-stream OpenAI error frame")
	}
	if !strings.Contains(err.Error(), "upstream backend failed") {
		t.Fatalf("expected upstream error message in returned error, got: %v", err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: error\n") || !strings.Contains(body, `"upstream backend failed"`) {
		t.Fatalf("expected Anthropic error SSE frame, got:\n%s", body)
	}
	if strings.Contains(body, "event: message_stop") {
		t.Fatalf("must not emit message_stop after mid-stream error, got:\n%s", body)
	}
}

func TestAnthropicRequestToOpenAI_MaxTokensByProviderType(t *testing.T) {
	in := []byte(`{"model":"m","max_tokens":512,"messages":[{"role":"user","content":"hi"}]}`)

	// OpenAI (and empty default) must emit max_completion_tokens, never max_tokens.
	for _, prov := range []string{"openai", ""} {
		out, err := AnthropicRequestToOpenAI(in, "o3", prov)
		if err != nil {
			t.Fatalf("provider %q failed: %v", prov, err)
		}
		var raw map[string]any
		if err := json.Unmarshal(out, &raw); err != nil {
			t.Fatal(err)
		}
		if int(raw["max_completion_tokens"].(float64)) != 512 {
			t.Fatalf("provider %q expected max_completion_tokens=512, got %s", prov, string(out))
		}
		if _, hasOld := raw["max_tokens"]; hasOld {
			t.Fatalf("provider %q must not emit deprecated max_tokens: %s", prov, string(out))
		}
	}

	// Ollama keeps max_tokens.
	outOllama, err := AnthropicRequestToOpenAI(in, "qwen2.5-coder:32b", "ollama")
	if err != nil {
		t.Fatalf("ollama failed: %v", err)
	}
	var rawOllama map[string]any
	if err := json.Unmarshal(outOllama, &rawOllama); err != nil {
		t.Fatal(err)
	}
	if int(rawOllama["max_tokens"].(float64)) != 512 {
		t.Fatalf("ollama expected max_tokens=512, got %s", string(outOllama))
	}
	if _, hasNew := rawOllama["max_completion_tokens"]; hasNew {
		t.Fatalf("ollama should not emit max_completion_tokens: %s", string(outOllama))
	}
}

func TestAnthropicRequestToOpenAI_ToolResultIsErrorAndEmbeddedImages(t *testing.T) {
	input := `{
		"model": "gpt-5",
		"max_tokens": 256,
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_err", "name": "run_cmd", "input": {"cmd": "false"}},
				{"type": "tool_use", "id": "toolu_img", "name": "screenshot", "input": {}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_err", "is_error": true, "content": "exit status 1"},
				{"type": "tool_result", "tool_use_id": "toolu_img", "content": [
					{"type": "text", "text": "captured screen"},
					{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw=="}},
					{"type": "image", "source": {"type": "url", "url": "https://example.com/shot.png"}}
				]}
			]}
		]
	}`

	outBytes, err := AnthropicRequestToOpenAI([]byte(input), "gpt-5", "openai")
	if err != nil {
		t.Fatalf("AnthropicRequestToOpenAI failed: %v", err)
	}
	var out openAIChatRequest
	if err := json.Unmarshal(outBytes, &out); err != nil {
		t.Fatal(err)
	}
	// assistant + tool(err) + tool(img) + user(attached images) = 4 messages.
	if len(out.Messages) != 4 {
		t.Fatalf("expected 4 messages, got %d: %s", len(out.Messages), string(outBytes))
	}
	if got := extractOpenAIText(out.Messages[1].Content); got != "[Tool Error]\nexit status 1" {
		t.Fatalf("expected [Tool Error] prefix on error tool_result, got %q", got)
	}
	if got := extractOpenAIText(out.Messages[2].Content); got != "captured screen" {
		t.Fatalf("unexpected image tool_result text: %q", got)
	}
	if out.Messages[3].Role != "user" {
		t.Fatalf("expected trailing user message for embedded tool images, got role=%q", out.Messages[3].Role)
	}
	var imgParts []openAIContentPart
	if err := json.Unmarshal(out.Messages[3].Content, &imgParts); err != nil {
		t.Fatalf("unmarshal trailing user image parts: %v", err)
	}
	if len(imgParts) != 2 ||
		imgParts[0].ImageURL.URL != "data:image/png;base64,iVBORw==" ||
		imgParts[1].ImageURL.URL != "https://example.com/shot.png" {
		t.Fatalf("embedded tool_result images not preserved: %+v", imgParts)
	}
}

func TestOpenAIRequestToAnthropic_LeadingUserAndEmptyGuard(t *testing.T) {
	// Zero messages -> clean error.
	if _, err := OpenAIRequestToAnthropic([]byte(`{"model":"x","messages":[]}`), "claude-sonnet-4-6"); err == nil {
		t.Fatalf("expected error for zero messages")
	}

	// System-only message -> non-empty messages starting with user.
	sysOnly, err := OpenAIRequestToAnthropic([]byte(`{"model":"x","messages":[{"role":"system","content":"be brief"}]}`), "claude-sonnet-4-6")
	if err != nil {
		t.Fatalf("system-only failed: %v", err)
	}
	var parsedSys anthropicRequest
	if err := json.Unmarshal(sysOnly, &parsedSys); err != nil {
		t.Fatal(err)
	}
	if len(parsedSys.Messages) != 1 || parsedSys.Messages[0].Role != "user" {
		t.Fatalf("expected synthetic leading user turn for system-only request, got %s", string(sysOnly))
	}

	// Assistant-first message -> prepends user turn before assistant.
	asstFirst, err := OpenAIRequestToAnthropic([]byte(`{"model":"x","messages":[{"role":"assistant","content":"prefill"}]}`), "claude-sonnet-4-6")
	if err != nil {
		t.Fatalf("assistant-first failed: %v", err)
	}
	var parsedAsst anthropicRequest
	if err := json.Unmarshal(asstFirst, &parsedAsst); err != nil {
		t.Fatal(err)
	}
	if len(parsedAsst.Messages) != 2 || parsedAsst.Messages[0].Role != "user" || parsedAsst.Messages[1].Role != "assistant" {
		t.Fatalf("expected [user, assistant] turns, got %s", string(asstFirst))
	}
}

func TestStreamingPrematureEOFDetection(t *testing.T) {
	// 1. Anthropic -> OpenAI truncated before message_stop.
	truncatedAnth := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":1}}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}`,
		``,
	}, "\n")
	rec1 := httptest.NewRecorder()
	err1 := StreamAnthropicToOpenAI(strings.NewReader(truncatedAnth), rec1, rec1, StreamOptions{RequestedModel: "m"})
	if !errors.Is(err1, io.ErrUnexpectedEOF) {
		t.Fatalf("StreamAnthropicToOpenAI expected io.ErrUnexpectedEOF, got %v", err1)
	}
	if strings.Contains(rec1.Body.String(), "data: [DONE]") {
		t.Fatalf("must not emit [DONE] on premature EOF: %s", rec1.Body.String())
	}
	if !strings.Contains(rec1.Body.String(), `"unexpected upstream stream EOF"`) {
		t.Fatalf("expected OpenAI SSE error frame on premature EOF: %s", rec1.Body.String())
	}

	// 2. OpenAI -> Anthropic truncated before [DONE].
	truncatedOAI := strings.Join([]string{
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"role":"assistant","content":"half"},"finish_reason":null}]}`,
		``,
	}, "\n")
	rec2 := httptest.NewRecorder()
	err2 := StreamOpenAIToAnthropic(strings.NewReader(truncatedOAI), rec2, rec2, StreamOptions{RequestedModel: "m"})
	if !errors.Is(err2, io.ErrUnexpectedEOF) {
		t.Fatalf("StreamOpenAIToAnthropic expected io.ErrUnexpectedEOF, got %v", err2)
	}
	if strings.Contains(rec2.Body.String(), "event: message_stop") {
		t.Fatalf("must not emit message_stop on premature EOF: %s", rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "event: error\n") || !strings.Contains(rec2.Body.String(), `"unexpected upstream stream EOF"`) {
		t.Fatalf("expected Anthropic SSE error frame on premature EOF: %s", rec2.Body.String())
	}
}

func TestStreamingIDPrefixDeduplication(t *testing.T) {
	anthSSE := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"chatcmpl-already","model":"claude-sonnet-4-6","usage":{"input_tokens":1,"output_tokens":1}}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")
	rec1 := httptest.NewRecorder()
	if err := StreamAnthropicToOpenAI(strings.NewReader(anthSSE), rec1, rec1, StreamOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec1.Body.String(), "chatcmpl-chatcmpl-") || !strings.Contains(rec1.Body.String(), `"id":"chatcmpl-already"`) {
		t.Fatalf("chatcmpl- prefix duplicated: %s", rec1.Body.String())
	}

	oaiSSE := strings.Join([]string{
		`data: {"id":"msg_already","object":"chat.completion.chunk","created":1,"model":"gpt-4.1","choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")
	rec2 := httptest.NewRecorder()
	if err := StreamOpenAIToAnthropic(strings.NewReader(oaiSSE), rec2, rec2, StreamOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec2.Body.String(), "msg_msg_") || !strings.Contains(rec2.Body.String(), `"id":"msg_already"`) {
		t.Fatalf("msg_ prefix duplicated: %s", rec2.Body.String())
	}
}
