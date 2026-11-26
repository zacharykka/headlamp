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

// OpenAIRequestToAnthropic converts an OpenAI Chat Completions request body
// into an Anthropic Messages API request body.
func OpenAIRequestToAnthropic(body []byte, upstreamModel string) ([]byte, error) {
	var req openAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("translate: decode openai chat request: %w", err)
	}

	model := upstreamModel
	if model == "" {
		model = req.Model
	}

	maxTokens := DefaultAnthropicMaxTokens
	if req.MaxCompletionTokens != nil && *req.MaxCompletionTokens > 0 {
		maxTokens = *req.MaxCompletionTokens
	} else if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTokens = *req.MaxTokens
	}

	out := anthropicRequest{
		Model:       model,
		MaxTokens:   maxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      req.Stream,
	}

	if len(req.Stop) > 0 && !bytes.Equal(bytes.TrimSpace(req.Stop), []byte("null")) {
		var single string
		if err := json.Unmarshal(req.Stop, &single); err == nil {
			if single != "" {
				out.StopSequences = []string{single}
			}
		} else {
			var multi []string
			if err := json.Unmarshal(req.Stop, &multi); err == nil && len(multi) > 0 {
				out.StopSequences = multi
			}
		}
	}

	var systemParts []string
	type pendingMsg struct {
		role   string
		blocks []anthropicContentBlock
	}
	var merged []pendingMsg
	appendTurn := func(role string, blocks []anthropicContentBlock) {
		if len(blocks) == 0 {
			return
		}
		// Anthropic enforces strict alternating user/assistant turns, so consecutive
		// tool results (mapped to role="user") and adjacent user messages merge.
		if len(merged) > 0 && merged[len(merged)-1].role == role {
			merged[len(merged)-1].blocks = append(merged[len(merged)-1].blocks, blocks...)
			return
		}
		merged = append(merged, pendingMsg{role: role, blocks: blocks})
	}

	for _, msg := range req.Messages {
		switch msg.Role {
		case "system", "developer":
			if text := extractOpenAIText(msg.Content); text != "" {
				systemParts = append(systemParts, text)
			}

		case "user":
			blocks := openAIContentToAnthropicBlocks(msg.Content)
			if len(blocks) == 0 {
				blocks = []anthropicContentBlock{{Type: "text", Text: ""}}
			}
			appendTurn("user", blocks)

		case "assistant":
			blocks := openAIContentToAnthropicBlocks(msg.Content)
			for _, tc := range msg.ToolCalls {
				blocks = append(blocks, anthropicContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Function.Name,
					Input: parseJSONObjectOrEmpty(tc.Function.Arguments),
				})
			}
			appendTurn("assistant", blocks)

		case "tool":
			contentRaw := msg.Content
			if len(bytes.TrimSpace(contentRaw)) == 0 || bytes.Equal(bytes.TrimSpace(contentRaw), []byte("null")) {
				contentRaw = json.RawMessage(`""`)
			}
			appendTurn("user", []anthropicContentBlock{{
				Type:      "tool_result",
				ToolUseID: msg.ToolCallID,
				Content:   contentRaw,
			}})
		}
	}

	if len(systemParts) > 0 {
		sysJSON, err := json.Marshal(strings.Join(systemParts, "\n\n"))
		if err != nil {
			return nil, fmt.Errorf("translate: encode anthropic system: %w", err)
		}
		out.System = sysJSON
	}

	out.Messages = make([]anthropicMessage, 0, len(merged))
	for _, m := range merged {
		contentJSON, err := json.Marshal(m.blocks)
		if err != nil {
			return nil, fmt.Errorf("translate: encode anthropic message blocks: %w", err)
		}
		out.Messages = append(out.Messages, anthropicMessage{
			Role:    m.role,
			Content: contentJSON,
		})
	}

	if len(req.Tools) > 0 {
		out.Tools = make([]anthropicTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			schema := bytes.TrimSpace(t.Function.Parameters)
			if len(schema) == 0 || bytes.Equal(schema, []byte("null")) {
				schema = []byte(`{"type":"object","properties":{}}`)
			}
			out.Tools = append(out.Tools, anthropicTool{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				InputSchema: json.RawMessage(schema),
			})
		}
		if len(req.ToolChoice) > 0 {
			out.ToolChoice = openAIToolChoiceToAnthropic(req.ToolChoice)
		}
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("translate: encode anthropic request: %w", err)
	}
	return encoded, nil
}

// AnthropicResponseToOpenAI converts a non-streaming Anthropic Messages response
// into an OpenAI Chat Completions response.
func AnthropicResponseToOpenAI(body []byte, requestedModel string) ([]byte, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("translate: decode anthropic response: %w", err)
	}

	var (
		textParts []string
		toolCalls []openAIToolCall
	)
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			textParts = append(textParts, block.Text)
		case "tool_use":
			idx := len(toolCalls)
			toolCalls = append(toolCalls, openAIToolCall{
				Index: &idx,
				ID:    block.ID,
				Type:  "function",
				Function: openAIToolCallFunction{
					Name:      block.Name,
					Arguments: marshalObjectOrEmptyString(block.Input),
				},
			})
		}
	}

	var contentPtr *string
	joined := strings.Join(textParts, "")
	if joined != "" || len(toolCalls) == 0 {
		contentPtr = &joined
	}

	stopReason := ""
	if resp.StopReason != nil {
		stopReason = *resp.StopReason
	}

	model := requestedModel
	if model == "" {
		model = resp.Model
	}

	// Anthropic input_tokens excludes cache_read and cache_creation; OpenAI prompt_tokens includes them.
	promptTokens := resp.Usage.InputTokens + resp.Usage.CacheReadInputTokens + resp.Usage.CacheCreationInputTokens
	completionTokens := resp.Usage.OutputTokens
	usage := &openAIUsage{
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      promptTokens + completionTokens,
	}
	if resp.Usage.CacheReadInputTokens > 0 {
		usage.PromptTokensDetails = &openAIPromptTokensDetails{
			CachedTokens: resp.Usage.CacheReadInputTokens,
		}
	}

	id := resp.ID
	if id == "" {
		id = fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	} else if !strings.HasPrefix(id, "chatcmpl-") {
		id = "chatcmpl-" + id
	}

	out := openAIChatResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []openAIChoice{{
			Index: 0,
			Message: openAIResponseMsg{
				Role:      "assistant",
				Content:   contentPtr,
				ToolCalls: toolCalls,
			},
			FinishReason: mapAnthropicStopReason(stopReason),
		}},
		Usage: usage,
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("translate: encode openai response: %w", err)
	}
	return encoded, nil
}

// StreamAnthropicToOpenAI translates an Anthropic Messages SSE stream into
// an OpenAI Chat Completions SSE stream, flushing after each emitted chunk.
func StreamAnthropicToOpenAI(upstream io.Reader, downstream io.Writer, flusher http.Flusher, opts StreamOptions) error {
	reader := bufio.NewReaderSize(upstream, 64*1024)

	var (
		chatID         = fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
		model          = opts.RequestedModel
		created        = time.Now().Unix()
		inputTokens    int64
		cacheRead      int64
		cacheCreate    int64
		outputTokens   int64
		nextToolIdx    int
		blockToToolIdx = make(map[int]int)
		finishReason   = "stop"
		sentFinish     bool
		firstTokenSent bool
	)

	markFirstToken := func() {
		if !firstTokenSent {
			firstTokenSent = true
			if opts.OnFirstToken != nil {
				opts.OnFirstToken()
			}
		}
	}

	emitChunk := func(chunk openAIChatChunk) error {
		payload, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		if err := WriteSSEEvent(downstream, "", payload); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}

	for {
		ev, err := ReadSSEEvent(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("translate: read anthropic sse: %w", err)
		}

		if opts.OnUpstreamEvent != nil {
			opts.OnUpstreamEvent(ev.Event, ev.Data)
		}

		eventType := ev.Event
		if eventType == "" {
			var probe struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(ev.Data, &probe)
			eventType = probe.Type
		}

		switch eventType {
		case "message_start":
			var msgStart anthropicMessageStartEvent
			if err := json.Unmarshal(ev.Data, &msgStart); err != nil {
				continue
			}
			if msgStart.Message.ID != "" {
				chatID = "chatcmpl-" + msgStart.Message.ID
			}
			if model == "" {
				model = msgStart.Message.Model
			}
			inputTokens = msgStart.Message.Usage.InputTokens
			cacheRead = msgStart.Message.Usage.CacheReadInputTokens
			cacheCreate = msgStart.Message.Usage.CacheCreationInputTokens
			if msgStart.Message.Usage.OutputTokens > outputTokens {
				outputTokens = msgStart.Message.Usage.OutputTokens
			}

			empty := ""
			if err := emitChunk(openAIChatChunk{
				ID:      chatID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []openAIChunkChoice{{
					Index: 0,
					Delta: openAIChunkDelta{Role: "assistant", Content: &empty},
				}},
			}); err != nil {
				return err
			}

		case "content_block_start":
			var blockStart anthropicContentBlockStartEvent
			if err := json.Unmarshal(ev.Data, &blockStart); err != nil {
				continue
			}
			if blockStart.ContentBlock.Type == "tool_use" {
				toolIdx := nextToolIdx
				nextToolIdx++
				blockToToolIdx[blockStart.Index] = toolIdx
				markFirstToken()
				if err := emitChunk(openAIChatChunk{
					ID:      chatID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []openAIChunkChoice{{
						Index: 0,
						Delta: openAIChunkDelta{
							ToolCalls: []openAIChunkToolCall{{
								Index: toolIdx,
								ID:    blockStart.ContentBlock.ID,
								Type:  "function",
								Function: openAIToolCallFunction{
									Name:      blockStart.ContentBlock.Name,
									Arguments: "",
								},
							}},
						},
					}},
				}); err != nil {
					return err
				}
			}

		case "content_block_delta":
			var blockDelta anthropicContentBlockDeltaEvent
			if err := json.Unmarshal(ev.Data, &blockDelta); err != nil {
				continue
			}
			switch blockDelta.Delta.Type {
			case "text_delta":
				if blockDelta.Delta.Text != "" {
					markFirstToken()
					text := blockDelta.Delta.Text
					if err := emitChunk(openAIChatChunk{
						ID:      chatID,
						Object:  "chat.completion.chunk",
						Created: created,
						Model:   model,
						Choices: []openAIChunkChoice{{
							Index: 0,
							Delta: openAIChunkDelta{Content: &text},
						}},
					}); err != nil {
						return err
					}
				}
			case "input_json_delta":
				toolIdx, ok := blockToToolIdx[blockDelta.Index]
				if !ok {
					toolIdx = nextToolIdx
					nextToolIdx++
					blockToToolIdx[blockDelta.Index] = toolIdx
				}
				if blockDelta.Delta.PartialJSON != "" {
					markFirstToken()
					if err := emitChunk(openAIChatChunk{
						ID:      chatID,
						Object:  "chat.completion.chunk",
						Created: created,
						Model:   model,
						Choices: []openAIChunkChoice{{
							Index: 0,
							Delta: openAIChunkDelta{
								ToolCalls: []openAIChunkToolCall{{
									Index: toolIdx,
									Function: openAIToolCallFunction{
										Arguments: blockDelta.Delta.PartialJSON,
									},
								}},
							},
						}},
					}); err != nil {
						return err
					}
				}
			case "thinking_delta", "signature_delta":
				// Extended thinking blocks are skipped in OpenAI Chat Completions deltas.
			}

		case "message_delta":
			var msgDelta anthropicMessageDeltaEvent
			if err := json.Unmarshal(ev.Data, &msgDelta); err != nil {
				continue
			}
			if msgDelta.Usage != nil {
				// Anthropic message_delta usage is cumulative; overwrite non-zero totals.
				if msgDelta.Usage.OutputTokens > 0 {
					outputTokens = msgDelta.Usage.OutputTokens
				}
				if msgDelta.Usage.InputTokens > 0 {
					inputTokens = msgDelta.Usage.InputTokens
				}
				if msgDelta.Usage.CacheReadInputTokens > 0 {
					cacheRead = msgDelta.Usage.CacheReadInputTokens
				}
				if msgDelta.Usage.CacheCreationInputTokens > 0 {
					cacheCreate = msgDelta.Usage.CacheCreationInputTokens
				}
			}
			if msgDelta.Delta.StopReason != nil {
				finishReason = mapAnthropicStopReason(*msgDelta.Delta.StopReason)
			}
			fr := finishReason
			sentFinish = true
			if err := emitChunk(openAIChatChunk{
				ID:      chatID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []openAIChunkChoice{{
					Index:        0,
					Delta:        openAIChunkDelta{},
					FinishReason: &fr,
				}},
			}); err != nil {
				return err
			}

		case "message_stop":
			if !sentFinish {
				fr := finishReason
				sentFinish = true
				if err := emitChunk(openAIChatChunk{
					ID:      chatID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []openAIChunkChoice{{
						Index:        0,
						Delta:        openAIChunkDelta{},
						FinishReason: &fr,
					}},
				}); err != nil {
					return err
				}
			}
			if opts.IncludeUsage {
				promptTotal := inputTokens + cacheRead + cacheCreate
				usage := &openAIUsage{
					PromptTokens:     promptTotal,
					CompletionTokens: outputTokens,
					TotalTokens:      promptTotal + outputTokens,
				}
				if cacheRead > 0 {
					usage.PromptTokensDetails = &openAIPromptTokensDetails{CachedTokens: cacheRead}
				}
				if err := emitChunk(openAIChatChunk{
					ID:      chatID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []openAIChunkChoice{},
					Usage:   usage,
				}); err != nil {
					return err
				}
			}
			if err := WriteSSEEvent(downstream, "", []byte("[DONE]")); err != nil {
				return err
			}
			if flusher != nil {
				flusher.Flush()
			}
			return nil

		case "error":
			var aErr anthropicErrorEvent
			_ = json.Unmarshal(ev.Data, &aErr)
			msg := aErr.Error.Message
			if msg == "" {
				msg = "upstream anthropic stream error"
			}
			errPayload, _ := json.Marshal(map[string]any{
				"error": map[string]any{
					"message": msg,
					"type":    aErr.Error.Type,
					"param":   nil,
					"code":    aErr.Error.Type,
				},
			})
			_ = WriteSSEEvent(downstream, "", errPayload)
			if flusher != nil {
				flusher.Flush()
			}
			return fmt.Errorf("translate: upstream anthropic error (%s): %s", aErr.Error.Type, msg)
		}
	}

	// Stream ended via EOF without message_stop; still terminate cleanly.
	if err := WriteSSEEvent(downstream, "", []byte("[DONE]")); err != nil {
		return err
	}
	if flusher != nil {
		flusher.Flush()
	}
	return nil
}

func extractOpenAIText(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return s
	}
	var parts []openAIContentPart
	if err := json.Unmarshal(trimmed, &parts); err == nil {
		var sb strings.Builder
		for _, p := range parts {
			if p.Type == "text" && p.Text != "" {
				if sb.Len() > 0 {
					sb.WriteByte('\n')
				}
				sb.WriteString(p.Text)
			}
		}
		return sb.String()
	}
	return ""
}

func openAIContentToAnthropicBlocks(raw json.RawMessage) []anthropicContentBlock {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		if s == "" {
			return nil
		}
		return []anthropicContentBlock{{Type: "text", Text: s}}
	}
	var parts []openAIContentPart
	if err := json.Unmarshal(trimmed, &parts); err != nil {
		return nil
	}
	blocks := make([]anthropicContentBlock, 0, len(parts))
	for _, p := range parts {
		switch p.Type {
		case "text":
			blocks = append(blocks, anthropicContentBlock{Type: "text", Text: p.Text})
		case "image_url":
			if p.ImageURL == nil || p.ImageURL.URL == "" {
				continue
			}
			if mediaType, data, ok := parseDataURI(p.ImageURL.URL); ok {
				blocks = append(blocks, anthropicContentBlock{
					Type: "image",
					Source: &anthropicImageSource{
						Type:      "base64",
						MediaType: mediaType,
						Data:      data,
					},
				})
			} else {
				blocks = append(blocks, anthropicContentBlock{
					Type: "image",
					Source: &anthropicImageSource{
						Type: "url",
						URL:  p.ImageURL.URL,
					},
				})
			}
		}
	}
	return blocks
}

func openAIToolChoiceToAnthropic(raw json.RawMessage) *anthropicChoice {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var str string
	if err := json.Unmarshal(trimmed, &str); err == nil {
		switch str {
		case "auto":
			return &anthropicChoice{Type: "auto"}
		case "required":
			return &anthropicChoice{Type: "any"}
		case "none":
			return &anthropicChoice{Type: "none"}
		default:
			return nil
		}
	}
	var obj struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(trimmed, &obj); err == nil && obj.Function.Name != "" {
		return &anthropicChoice{Type: "tool", Name: obj.Function.Name}
	}
	return nil
}
