package translate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnthropicRequestToOpenAI converts an Anthropic Messages API request body
// into an OpenAI Chat Completions request body.
func AnthropicRequestToOpenAI(body []byte, upstreamModel string) ([]byte, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("translate: decode anthropic request: %w", err)
	}

	model := upstreamModel
	if model == "" {
		model = req.Model
	}

	out := openAIChatRequest{
		Model:       model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      req.Stream,
	}
	if req.MaxTokens > 0 {
		maxTok := req.MaxTokens
		out.MaxTokens = &maxTok
	}
	if req.Stream {
		out.StreamOptions = &openAIStreamOptions{IncludeUsage: true}
	}
	if len(req.StopSequences) > 0 {
		stopJSON, err := json.Marshal(req.StopSequences)
		if err != nil {
			return nil, fmt.Errorf("translate: encode openai stop: %w", err)
		}
		out.Stop = stopJSON
	}

	if sysText := extractAnthropicSystem(req.System); sysText != "" {
		contentJSON, _ := json.Marshal(sysText)
		out.Messages = append(out.Messages, openAIMessage{
			Role:    "system",
			Content: contentJSON,
		})
	}

	for _, msg := range req.Messages {
		blocks := parseAnthropicContentBlocks(msg.Content)
		switch msg.Role {
		case "user":
			var userParts []openAIContentPart
			for _, b := range blocks {
				switch b.Type {
				case "tool_result":
					// Explode each Anthropic tool_result into its own OpenAI role="tool" turn.
					toolText := extractAnthropicToolResultText(b.Content)
					contentJSON, _ := json.Marshal(toolText)
					out.Messages = append(out.Messages, openAIMessage{
						Role:       "tool",
						ToolCallID: b.ToolUseID,
						Content:    contentJSON,
					})
				case "text":
					userParts = append(userParts, openAIContentPart{Type: "text", Text: b.Text})
				case "image":
					if b.Source == nil {
						continue
					}
					if b.Source.Type == "base64" {
						uri := fmt.Sprintf("data:%s;base64,%s", b.Source.MediaType, b.Source.Data)
						userParts = append(userParts, openAIContentPart{
							Type:     "image_url",
							ImageURL: &openAIImageURL{URL: uri},
						})
					} else if b.Source.Type == "url" && b.Source.URL != "" {
						userParts = append(userParts, openAIContentPart{
							Type:     "image_url",
							ImageURL: &openAIImageURL{URL: b.Source.URL},
						})
					}
				}
			}
			if len(userParts) > 0 {
				contentJSON, err := encodeOpenAIUserParts(userParts)
				if err != nil {
					return nil, err
				}
				out.Messages = append(out.Messages, openAIMessage{
					Role:    "user",
					Content: contentJSON,
				})
			}

		case "assistant":
			var (
				textParts []string
				toolCalls []openAIToolCall
			)
			for _, b := range blocks {
				switch b.Type {
				case "text":
					if b.Text != "" {
						textParts = append(textParts, b.Text)
					}
				case "tool_use":
					toolCalls = append(toolCalls, openAIToolCall{
						ID:   b.ID,
						Type: "function",
						Function: openAIToolCallFunction{
							Name:      b.Name,
							Arguments: marshalObjectOrEmptyString(b.Input),
						},
					})
				case "thinking", "redacted_thinking":
					// Skip Anthropic-specific thinking blocks when calling OpenAI Chat Completions.
				}
			}
			assistantMsg := openAIMessage{
				Role:      "assistant",
				ToolCalls: toolCalls,
			}
			joined := strings.Join(textParts, "")
			if joined != "" || len(toolCalls) == 0 {
				contentJSON, _ := json.Marshal(joined)
				assistantMsg.Content = contentJSON
			}
			out.Messages = append(out.Messages, assistantMsg)
		}
	}

	if len(req.Tools) > 0 {
		out.Tools = make([]openAITool, 0, len(req.Tools))
		for _, t := range req.Tools {
			params := bytes.TrimSpace(t.InputSchema)
			if len(params) == 0 || bytes.Equal(params, []byte("null")) {
				params = []byte(`{"type":"object","properties":{}}`)
			}
			out.Tools = append(out.Tools, openAITool{
				Type: "function",
				Function: openAIToolFunction{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  json.RawMessage(params),
				},
			})
		}
		if req.ToolChoice != nil {
			out.ToolChoice = anthropicToolChoiceToOpenAI(req.ToolChoice)
		}
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("translate: encode openai request: %w", err)
	}
	return encoded, nil
}

// OpenAIResponseToAnthropic converts a non-streaming OpenAI Chat Completions
// response into an Anthropic Messages response.
func OpenAIResponseToAnthropic(body []byte, requestedModel string) ([]byte, error) {
	var resp openAIChatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("translate: decode openai response: %w", err)
	}

	var (
		blocks     []anthropicContentBlock
		stopReason = "end_turn"
	)
	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		stopReason = mapOpenAIFinishReason(choice.FinishReason)
		if choice.Message.Content != nil && *choice.Message.Content != "" {
			blocks = append(blocks, anthropicContentBlock{
				Type: "text",
				Text: *choice.Message.Content,
			})
		}
		for _, tc := range choice.Message.ToolCalls {
			blocks = append(blocks, anthropicContentBlock{
				Type:  "tool_use",
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: parseJSONObjectOrEmpty(tc.Function.Arguments),
			})
		}
	}
	if blocks == nil {
		blocks = []anthropicContentBlock{}
	}

	var usage anthropicUsage
	if resp.Usage != nil {
		var cached int64
		if resp.Usage.PromptTokensDetails != nil {
			cached = resp.Usage.PromptTokensDetails.CachedTokens
		}
		uncached := resp.Usage.PromptTokens - cached
		if uncached < 0 {
			uncached = 0
		}
		usage = anthropicUsage{
			InputTokens:          uncached,
			OutputTokens:         resp.Usage.CompletionTokens,
			CacheReadInputTokens: cached,
		}
	}

	model := requestedModel
	if model == "" {
		model = resp.Model
	}
	id := resp.ID
	if id == "" {
		id = fmt.Sprintf("msg_%d", time.Now().UnixNano())
	} else if !strings.HasPrefix(id, "msg_") {
		id = "msg_" + id
	}

	out := anthropicResponse{
		ID:         id,
		Type:       "message",
		Role:       "assistant",
		Model:      model,
		Content:    blocks,
		StopReason: &stopReason,
		Usage:      usage,
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("translate: encode anthropic response: %w", err)
	}
	return encoded, nil
}

// StreamOpenAIToAnthropic translates an OpenAI Chat Completions SSE stream into
// an Anthropic Messages SSE stream, flushing after each emitted event.
func StreamOpenAIToAnthropic(upstream io.Reader, downstream io.Writer, flusher http.Flusher, opts StreamOptions) error {
	reader := bufio.NewReaderSize(upstream, 64*1024)

	var (
		msgID            = fmt.Sprintf("msg_%d", time.Now().UnixNano())
		model            = opts.RequestedModel
		started          bool
		blockIdx         = -1
		openBlockType    string // "" | "text" | "tool_use"
		activeToolIdx    = -1
		stopReason       = "end_turn"
		promptTokens     int64
		cachedTokens     int64
		completionTokens int64
		firstTokenSent   bool
	)

	markFirstToken := func() {
		if !firstTokenSent {
			firstTokenSent = true
			if opts.OnFirstToken != nil {
				opts.OnFirstToken()
			}
		}
	}

	emitEvent := func(eventName string, v any) error {
		payload, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if err := WriteSSEEvent(downstream, eventName, payload); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}

	ensureStarted := func() error {
		if started {
			return nil
		}
		started = true
		return emitEvent("message_start", anthropicMessageStartEvent{
			Type: "message_start",
			Message: anthropicResponse{
				ID:      msgID,
				Type:    "message",
				Role:    "assistant",
				Model:   model,
				Content: []anthropicContentBlock{},
				Usage:   anthropicUsage{},
			},
		})
	}

	closeOpenBlock := func() error {
		if openBlockType == "" {
			return nil
		}
		openBlockType = ""
		activeToolIdx = -1
		return emitEvent("content_block_stop", anthropicContentBlockStopEvent{
			Type:  "content_block_stop",
			Index: blockIdx,
		})
	}

	finishStream := func() error {
		if err := ensureStarted(); err != nil {
			return err
		}
		if err := closeOpenBlock(); err != nil {
			return err
		}
		uncached := promptTokens - cachedTokens
		if uncached < 0 {
			uncached = 0
		}
		sr := stopReason
		if err := emitEvent("message_delta", anthropicMessageDeltaEvent{
			Type: "message_delta",
			Delta: anthropicMessageDeltaBody{
				StopReason: &sr,
			},
			Usage: &anthropicUsage{
				InputTokens:          uncached,
				CacheReadInputTokens: cachedTokens,
				OutputTokens:         completionTokens,
			},
		}); err != nil {
			return err
		}
		return emitEvent("message_stop", map[string]string{"type": "message_stop"})
	}

	for {
		ev, err := ReadSSEEvent(reader)
		if errors.Is(err, io.EOF) {
			return finishStream()
		}
		if err != nil {
			return fmt.Errorf("translate: read openai sse: %w", err)
		}

		data := bytes.TrimSpace(ev.Data)
		if len(data) == 0 {
			continue
		}
		if bytes.Equal(data, []byte("[DONE]")) {
			return finishStream()
		}

		if opts.OnUpstreamEvent != nil {
			opts.OnUpstreamEvent(ev.Event, data)
		}

		var chunk openAIChatChunk
		if err := json.Unmarshal(data, &chunk); err != nil {
			continue
		}

		if chunk.Error != nil {
			errType := mapOpenAIErrorTypeToAnthropic(chunk.Error.Type)
			msg := chunk.Error.Message
			if msg == "" {
				msg = "upstream openai stream error"
			}
			_ = emitEvent("error", map[string]any{
				"type": "error",
				"error": map[string]string{
					"type":    errType,
					"message": msg,
				},
			})
			return fmt.Errorf("translate: upstream openai error (%s): %s", errType, msg)
		}

		if !started {
			if chunk.ID != "" {
				msgID = "msg_" + chunk.ID
			}
			if model == "" {
				model = chunk.Model
			}
			if err := ensureStarted(); err != nil {
				return err
			}
		}

		if chunk.Usage != nil {
			promptTokens = chunk.Usage.PromptTokens
			completionTokens = chunk.Usage.CompletionTokens
			if chunk.Usage.PromptTokensDetails != nil {
				cachedTokens = chunk.Usage.PromptTokensDetails.CachedTokens
			}
		}

		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]

		if choice.Delta.Content != nil && *choice.Delta.Content != "" {
			if openBlockType != "text" {
				if err := closeOpenBlock(); err != nil {
					return err
				}
				blockIdx++
				openBlockType = "text"
				if err := emitEvent("content_block_start", anthropicContentBlockStartEvent{
					Type:  "content_block_start",
					Index: blockIdx,
					ContentBlock: anthropicContentBlock{
						Type: "text",
						Text: "",
					},
				}); err != nil {
					return err
				}
			}
			markFirstToken()
			if err := emitEvent("content_block_delta", anthropicContentBlockDeltaEvent{
				Type:  "content_block_delta",
				Index: blockIdx,
				Delta: anthropicStreamDelta{
					Type: "text_delta",
					Text: *choice.Delta.Content,
				},
			}); err != nil {
				return err
			}
		}

		for _, tc := range choice.Delta.ToolCalls {
			if openBlockType != "tool_use" || tc.Index != activeToolIdx {
				if err := closeOpenBlock(); err != nil {
					return err
				}
				blockIdx++
				openBlockType = "tool_use"
				activeToolIdx = tc.Index
				callID := tc.ID
				if callID == "" {
					callID = fmt.Sprintf("toolu_%d_%d", time.Now().UnixNano(), tc.Index)
				}
				markFirstToken()
				if err := emitEvent("content_block_start", anthropicContentBlockStartEvent{
					Type:  "content_block_start",
					Index: blockIdx,
					ContentBlock: anthropicContentBlock{
						Type:  "tool_use",
						ID:    callID,
						Name:  tc.Function.Name,
						Input: json.RawMessage(`{}`),
					},
				}); err != nil {
					return err
				}
			}
			if tc.Function.Arguments != "" {
				markFirstToken()
				if err := emitEvent("content_block_delta", anthropicContentBlockDeltaEvent{
					Type:  "content_block_delta",
					Index: blockIdx,
					Delta: anthropicStreamDelta{
						Type:        "input_json_delta",
						PartialJSON: tc.Function.Arguments,
					},
				}); err != nil {
					return err
				}
			}
		}

		if choice.FinishReason != nil && *choice.FinishReason != "" {
			stopReason = mapOpenAIFinishReason(*choice.FinishReason)
		}
	}
}

func extractAnthropicSystem(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return s
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(trimmed, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n\n")
	}
	return ""
}

func parseAnthropicContentBlocks(raw json.RawMessage) []anthropicContentBlock {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return []anthropicContentBlock{{Type: "text", Text: s}}
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(trimmed, &blocks); err == nil {
		return blocks
	}
	return nil
}

func extractAnthropicToolResultText(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return s
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(trimmed, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return string(trimmed)
}

func encodeOpenAIUserParts(parts []openAIContentPart) (json.RawMessage, error) {
	// If there is only plain text, emit a compact string for maximum upstream compatibility.
	allText := true
	for _, p := range parts {
		if p.Type != "text" {
			allText = false
			break
		}
	}
	if allText {
		var texts []string
		for _, p := range parts {
			texts = append(texts, p.Text)
		}
		return json.Marshal(strings.Join(texts, "\n"))
	}
	return json.Marshal(parts)
}

func anthropicToolChoiceToOpenAI(choice *anthropicChoice) json.RawMessage {
	if choice == nil {
		return nil
	}
	switch choice.Type {
	case "auto":
		return json.RawMessage(`"auto"`)
	case "any":
		return json.RawMessage(`"required"`)
	case "none":
		return json.RawMessage(`"none"`)
	case "tool":
		if choice.Name == "" {
			return nil
		}
		b, _ := json.Marshal(map[string]any{
			"type":     "function",
			"function": map[string]string{"name": choice.Name},
		})
		return b
	default:
		return nil
	}
}
