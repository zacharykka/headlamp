package chat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

// --- OpenAI Chat Completions Streaming Path (OpenAI, Anthropic via translate, Ollama, aliases) ---

type openAIChatMessage struct {
	Role       string           `json:"role"`
	Content    any              `json:"content,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
}

type openAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openAIFunctionCall `json:"function"`
}

type openAIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openAIToolDef struct {
	Type     string               `json:"type"`
	Function openAIFunctionSchema `json:"function"`
}

type openAIFunctionSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

type openAIStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens        int64 `json:"prompt_tokens"`
		CompletionTokens    int64 `json:"completion_tokens"`
		TotalTokens         int64 `json:"total_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
		CompletionTokensDetails *struct {
			ReasoningTokens int64 `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type pendingToolCall struct {
	Index int
	ID    string
	Name  string
	Args  strings.Builder
}

func (s *Service) runOpenAIChatLoop(
	ctx context.Context,
	p *auth.Principal,
	model string,
	systemPrompt string,
	history []store.ChatMessage,
	userPrompt string,
	round0UserPrompt string,
	tools []toolBinding,
	toolLookup map[string]toolBinding,
	emitter *sseEmitter,
) (*turnOutcome, error) {
	messages := buildOpenAIMessages(systemPrompt, history, userPrompt)
	openAITools := buildOpenAIToolDefs(tools)

	outcome := &turnOutcome{}
	var contentBuf strings.Builder

	// Allow up to s.maxToolRounds tool rounds plus 1 final synthesis turn without tools.
	for round := 0; round <= s.maxToolRounds; round++ {
		if ctx.Err() != nil {
			outcome.content = contentBuf.String()
			return outcome, ctx.Err()
		}

		// Round 0 dispatches round0UserPrompt (raw user input when pre-redacted) so proxy.Gateway
		// runs guardrail.Engine once for webhook alerts and usage_logs; Round 1+ uses the
		// already-redacted messages history so subsequent tool rounds do not re-trigger webhooks.
		roundMessages := messages
		if round == 0 && round0UserPrompt != "" && round0UserPrompt != userPrompt {
			roundMessages = buildOpenAIMessages(systemPrompt, history, round0UserPrompt)
		}

		reqPayload := map[string]any{
			"model":    model,
			"messages": roundMessages,
			"stream":   true,
			"stream_options": map[string]any{
				"include_usage": true,
			},
		}
		if len(openAITools) > 0 && round < s.maxToolRounds {
			reqPayload["tools"] = openAITools
		}

		reqBytes, err := json.Marshal(reqPayload)
		if err != nil {
			outcome.content = contentBuf.String()
			return outcome, fmt.Errorf("chat: marshal openai request: %w", err)
		}

		streamReader, respHeaders, closeStream, err := s.invokeGatewayStream(ctx, p, "/v1/chat/completions", reqBytes)
		if err != nil {
			outcome.content = contentBuf.String()
			return outcome, err
		}

		var (
			roundText  strings.Builder
			pendingMap = make(map[int]*pendingToolCall)
			roundUsage metering.Usage
			streamErr  error
		)

		br := bufio.NewReaderSize(streamReader, 64*1024)
		for {
			if ctx.Err() != nil {
				streamErr = ctx.Err()
				break
			}
			ev, readErr := translate.ReadSSEEvent(br)
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				streamErr = readErr
				break
			}
			data := bytes.TrimSpace(ev.Data)
			if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
				if bytes.Equal(data, []byte("[DONE]")) {
					break
				}
				continue
			}

			var chunk openAIStreamChunk
			if err := json.Unmarshal(data, &chunk); err != nil {
				continue
			}
			if chunk.Error != nil && chunk.Error.Message != "" {
				errType := chunk.Error.Type
				if errType == "" {
					errType = chunk.Error.Code
				}
				if errType == "" {
					errType = "upstream_error"
				}
				streamErr = &gatewayHTTPError{
					StatusCode: 502,
					Type:       errType,
					Message:    chunk.Error.Message,
				}
				break
			}

			if chunk.Usage != nil {
				roundUsage.InputTokens = chunk.Usage.PromptTokens
				roundUsage.OutputTokens = chunk.Usage.CompletionTokens
				roundUsage.TotalTokens = chunk.Usage.TotalTokens
				if chunk.Usage.PromptTokensDetails != nil {
					roundUsage.CacheReadTokens = chunk.Usage.PromptTokensDetails.CachedTokens
				}
				if chunk.Usage.CompletionTokensDetails != nil {
					roundUsage.ReasoningTokens = chunk.Usage.CompletionTokensDetails.ReasoningTokens
				}
			}

			if len(chunk.Choices) > 0 {
				delta := chunk.Choices[0].Delta
				if delta.Content != "" {
					roundText.WriteString(delta.Content)
					contentBuf.WriteString(delta.Content)
					_ = emitter.Emit("delta", map[string]string{"text": delta.Content})
				}
				for _, tc := range delta.ToolCalls {
					entry, ok := pendingMap[tc.Index]
					if !ok {
						entry = &pendingToolCall{Index: tc.Index}
						pendingMap[tc.Index] = entry
					}
					if tc.ID != "" {
						entry.ID = tc.ID
					}
					if tc.Function.Name != "" {
						entry.Name = tc.Function.Name
					}
					if tc.Function.Arguments != "" {
						entry.Args.WriteString(tc.Function.Arguments)
					}
				}
			}
		}

		closeStream()
		addUsage(&outcome.usage, roundUsage)
		outcome.rounds = append(outcome.rounds, roundMetrics{
			providerType:  respHeaders.Get(headerProviderType),
			upstreamModel: respHeaders.Get(headerUpstreamModel),
			usage:         roundUsage,
		})

		if streamErr != nil {
			outcome.content = contentBuf.String()
			return outcome, streamErr
		}

		if len(pendingMap) == 0 || round >= s.maxToolRounds {
			break
		}

		// Execute accumulated tool calls in index order and append results for next turn.
		ordered := make([]*pendingToolCall, 0, len(pendingMap))
		for _, entry := range pendingMap {
			ordered = append(ordered, entry)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].Index < ordered[j].Index })

		assistantToolCalls := make([]openAIToolCall, 0, len(ordered))
		for _, tc := range ordered {
			if tc.ID == "" {
				tc.ID = "call_" + uuid.NewString()[:12]
			}
			argsStr := strings.TrimSpace(tc.Args.String())
			if argsStr == "" {
				argsStr = "{}"
			}
			assistantToolCalls = append(assistantToolCalls, openAIToolCall{
				ID:   tc.ID,
				Type: "function",
				Function: openAIFunctionCall{
					Name:      tc.Name,
					Arguments: argsStr,
				},
			})
		}

		assistantTurn := openAIChatMessage{
			Role:      "assistant",
			ToolCalls: assistantToolCalls,
		}
		if roundText.Len() > 0 {
			assistantTurn.Content = roundText.String()
		}
		messages = append(messages, assistantTurn)

		for _, tc := range assistantToolCalls {
			if ctx.Err() != nil {
				outcome.content = contentBuf.String()
				return outcome, ctx.Err()
			}
			toolEv := s.executeMCPToolCall(ctx, p, tc.ID, tc.Function.Name, tc.Function.Arguments, toolLookup, emitter)
			outcome.toolEvents = append(outcome.toolEvents, toolEv)
			messages = append(messages, openAIChatMessage{
				Role:       "tool",
				ToolCallID: tc.ID,
				Content:    toolEv.Result,
			})
		}
	}

	outcome.content = contentBuf.String()
	return outcome, nil
}

func buildOpenAIMessages(systemPrompt string, history []store.ChatMessage, userPrompt string) []openAIChatMessage {
	msgs := make([]openAIChatMessage, 0, len(history)+2)
	if sp := strings.TrimSpace(systemPrompt); sp != "" {
		msgs = append(msgs, openAIChatMessage{Role: "system", Content: sp})
	}
	for _, m := range history {
		if m.Role != "user" && m.Role != "assistant" {
			continue
		}
		if m.Content == "" {
			continue
		}
		msgs = append(msgs, openAIChatMessage{Role: m.Role, Content: m.Content})
	}
	msgs = append(msgs, openAIChatMessage{Role: "user", Content: userPrompt})
	return msgs
}

func buildOpenAIToolDefs(tools []toolBinding) []openAIToolDef {
	if len(tools) == 0 {
		return nil
	}
	out := make([]openAIToolDef, 0, len(tools))
	for _, t := range tools {
		out = append(out, openAIToolDef{
			Type: "function",
			Function: openAIFunctionSchema{
				Name:        t.EncodedName,
				Description: t.Description,
				Parameters:  t.InputSchema,
			},
		})
	}
	return out
}

// --- Pure Gemini Streaming Path (/gemini/v1beta/models/<model>:streamGenerateContent?alt=sse) ---

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string                  `json:"text,omitempty"`
	Thought          bool                    `json:"thought,omitempty"`
	ThoughtSignature string                  `json:"thoughtSignature,omitempty"`
	FunctionCall     *geminiFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResponse `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type geminiFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type geminiStreamChunk struct {
	Candidates []struct {
		Content struct {
			Role  string       `json:"role"`
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata *struct {
		PromptTokenCount        int64 `json:"promptTokenCount"`
		CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
		CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
		ThoughtsTokenCount      int64 `json:"thoughtsTokenCount"`
		TotalTokenCount         int64 `json:"totalTokenCount"`
	} `json:"usageMetadata"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

func (s *Service) runGeminiChatLoop(
	ctx context.Context,
	p *auth.Principal,
	model string,
	systemPrompt string,
	history []store.ChatMessage,
	userPrompt string,
	round0UserPrompt string,
	tools []toolBinding,
	toolLookup map[string]toolBinding,
	emitter *sseEmitter,
) (*turnOutcome, error) {
	contents := buildGeminiContents(history, userPrompt)
	geminiPath := "/gemini/v1beta/models/" + strings.TrimPrefix(model, "/") + ":streamGenerateContent?alt=sse"

	var funcDecls []map[string]any
	for _, t := range tools {
		decl := map[string]any{
			"name":       t.EncodedName,
			"parameters": sanitizeGeminiSchema(t.InputSchema),
		}
		if t.Description != "" {
			decl["description"] = t.Description
		}
		funcDecls = append(funcDecls, decl)
	}

	outcome := &turnOutcome{}
	var contentBuf strings.Builder

	for round := 0; round <= s.maxToolRounds; round++ {
		if ctx.Err() != nil {
			outcome.content = contentBuf.String()
			return outcome, ctx.Err()
		}

		// Round 0 dispatches round0UserPrompt (raw user input when pre-redacted) so proxy.Gateway
		// runs guardrail.Engine once for webhook alerts and usage_logs; Round 1+ uses the
		// already-redacted contents history so subsequent tool rounds do not re-trigger webhooks.
		roundContents := contents
		if round == 0 && round0UserPrompt != "" && round0UserPrompt != userPrompt {
			roundContents = buildGeminiContents(history, round0UserPrompt)
		}

		reqPayload := map[string]any{
			"contents": roundContents,
		}
		if sp := strings.TrimSpace(systemPrompt); sp != "" {
			reqPayload["systemInstruction"] = map[string]any{
				"parts": []map[string]string{{"text": sp}},
			}
		}
		if len(funcDecls) > 0 && round < s.maxToolRounds {
			reqPayload["tools"] = []map[string]any{
				{"functionDeclarations": funcDecls},
			}
		}

		reqBytes, err := json.Marshal(reqPayload)
		if err != nil {
			outcome.content = contentBuf.String()
			return outcome, fmt.Errorf("chat: marshal gemini request: %w", err)
		}

		streamReader, respHeaders, closeStream, err := s.invokeGatewayStream(ctx, p, geminiPath, reqBytes)
		if err != nil {
			outcome.content = contentBuf.String()
			return outcome, err
		}

		var (
			modelParts []geminiPart
			funcCalls  []geminiFunctionCall
			roundUsage metering.Usage
			streamErr  error
		)

		br := bufio.NewReaderSize(streamReader, 64*1024)
		for {
			if ctx.Err() != nil {
				streamErr = ctx.Err()
				break
			}
			ev, readErr := translate.ReadSSEEvent(br)
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				streamErr = readErr
				break
			}
			data := bytes.TrimSpace(ev.Data)
			if len(data) == 0 {
				continue
			}

			var chunk geminiStreamChunk
			if err := json.Unmarshal(data, &chunk); err != nil {
				continue
			}
			if chunk.Error != nil && chunk.Error.Message != "" {
				errType := chunk.Error.Status
				if errType == "" {
					errType = "upstream_error"
				}
				streamErr = &gatewayHTTPError{
					StatusCode: chunk.Error.Code,
					Type:       errType,
					Message:    chunk.Error.Message,
				}
				break
			}

			if chunk.UsageMetadata != nil {
				roundUsage.InputTokens = chunk.UsageMetadata.PromptTokenCount
				roundUsage.OutputTokens = chunk.UsageMetadata.CandidatesTokenCount
				roundUsage.CacheReadTokens = chunk.UsageMetadata.CachedContentTokenCount
				roundUsage.ReasoningTokens = chunk.UsageMetadata.ThoughtsTokenCount
				roundUsage.TotalTokens = chunk.UsageMetadata.TotalTokenCount
			}

			if len(chunk.Candidates) > 0 {
				for _, part := range chunk.Candidates[0].Content.Parts {
					if part.Text != "" && !part.Thought {
						contentBuf.WriteString(part.Text)
						_ = emitter.Emit("delta", map[string]string{"text": part.Text})
					}
					if part.FunctionCall != nil {
						funcCalls = append(funcCalls, *part.FunctionCall)
					}
					// Preserve all non-empty parts verbatim in modelParts (including Thought and
					// ThoughtSignature) so Gemini 2.5/3 thinking models succeed across tool rounds.
					if part.Text != "" || part.Thought || part.ThoughtSignature != "" || part.FunctionCall != nil {
						modelParts = append(modelParts, part)
					}
				}
			}
		}

		closeStream()
		addUsage(&outcome.usage, roundUsage)
		outcome.rounds = append(outcome.rounds, roundMetrics{
			providerType:  respHeaders.Get(headerProviderType),
			upstreamModel: respHeaders.Get(headerUpstreamModel),
			usage:         roundUsage,
		})

		if streamErr != nil {
			outcome.content = contentBuf.String()
			return outcome, streamErr
		}

		if len(funcCalls) == 0 || round >= s.maxToolRounds {
			break
		}

		contents = appendGeminiContent(contents, "model", modelParts...)

		respParts := make([]geminiPart, 0, len(funcCalls))
		for _, fc := range funcCalls {
			if ctx.Err() != nil {
				outcome.content = contentBuf.String()
				return outcome, ctx.Err()
			}
			callID := "gcall_" + uuid.NewString()[:12]
			argsStr := strings.TrimSpace(string(fc.Args))
			if argsStr == "" {
				argsStr = "{}"
			}
			toolEv := s.executeMCPToolCall(ctx, p, callID, fc.Name, argsStr, toolLookup, emitter)
			outcome.toolEvents = append(outcome.toolEvents, toolEv)

			respParts = append(respParts, geminiPart{
				FunctionResponse: &geminiFunctionResponse{
					Name: fc.Name,
					Response: map[string]any{
						"content":  toolEv.Result,
						"is_error": toolEv.IsError,
					},
				},
			})
		}

		contents = appendGeminiContent(contents, "user", respParts...)
	}

	outcome.content = contentBuf.String()
	return outcome, nil
}

func buildGeminiContents(history []store.ChatMessage, userPrompt string) []geminiContent {
	contents := make([]geminiContent, 0, len(history)+1)
	for _, m := range history {
		if m.Content == "" {
			continue
		}
		var role string
		switch m.Role {
		case "user":
			role = "user"
		case "assistant":
			role = "model"
		default:
			continue
		}
		contents = appendGeminiContent(contents, role, geminiPart{Text: m.Content})
	}
	contents = appendGeminiContent(contents, "user", geminiPart{Text: userPrompt})
	return contents
}

// appendGeminiContent appends parts to contents while merging adjacent turns that share
// the same Gemini role ("user" or "model") so Gemini never rejects consecutive same-role turns.
func appendGeminiContent(contents []geminiContent, role string, parts ...geminiPart) []geminiContent {
	if len(parts) == 0 {
		return contents
	}
	if n := len(contents); n > 0 && contents[n-1].Role == role {
		contents[n-1].Parts = append(contents[n-1].Parts, parts...)
		return contents
	}
	return append(contents, geminiContent{
		Role:  role,
		Parts: parts,
	})
}

// --- Shared MCP Tool Execution & Usage Helpers ---

func (s *Service) executeMCPToolCall(
	ctx context.Context,
	p *auth.Principal,
	callID string,
	encodedName string,
	rawArgs string,
	toolLookup map[string]toolBinding,
	emitter *sseEmitter,
) store.ChatToolEvent {
	binding, known := toolLookup[encodedName]
	serverName := binding.Server
	toolName := binding.Tool
	if !known {
		toolName = encodedName
	}

	argsJSON := normalizeToolArgsJSON(rawArgs)

	_ = emitter.Emit("tool_start", map[string]any{
		"id":        callID,
		"server":    serverName,
		"tool":      toolName,
		"arguments": argsJSON,
	})

	start := time.Now()
	var res *ToolResult
	if !known || s.mcp == nil {
		res = &ToolResult{
			Result:     fmt.Sprintf("tool %q is not available or not authorized", encodedName),
			IsError:    true,
			DurationMS: time.Since(start).Milliseconds(),
		}
	} else {
		var err error
		res, err = s.mcp.CallTool(ctx, p, serverName, toolName, argsJSON)
		if err != nil {
			res = &ToolResult{
				Result:     err.Error(),
				IsError:    true,
				DurationMS: time.Since(start).Milliseconds(),
			}
		} else if res == nil {
			res = &ToolResult{
				Result:     "",
				IsError:    false,
				DurationMS: time.Since(start).Milliseconds(),
			}
		}
	}

	_ = emitter.Emit("tool_result", map[string]any{
		"id":          callID,
		"server":      serverName,
		"tool":        toolName,
		"result":      res.Result,
		"is_error":    res.IsError,
		"duration_ms": res.DurationMS,
	})

	return store.ChatToolEvent{
		ID:         callID,
		Server:     serverName,
		Tool:       toolName,
		Arguments:  argsJSON,
		Result:     res.Result,
		IsError:    res.IsError,
		DurationMS: res.DurationMS,
	}
}

func normalizeToolArgsJSON(raw string) json.RawMessage {
	trimmed := bytes.TrimSpace([]byte(raw))
	if len(trimmed) == 0 {
		return json.RawMessage(`{}`)
	}
	if json.Valid(trimmed) {
		return json.RawMessage(trimmed)
	}
	wrapped, _ := json.Marshal(map[string]string{"raw": raw})
	return json.RawMessage(wrapped)
}

func addUsage(dst *metering.Usage, src metering.Usage) {
	dst.InputTokens += src.InputTokens
	dst.OutputTokens += src.OutputTokens
	dst.CacheReadTokens += src.CacheReadTokens
	dst.CacheWriteTokens += src.CacheWriteTokens
	dst.CacheWrite1hTokens += src.CacheWrite1hTokens
	dst.ReasoningTokens += src.ReasoningTokens
	dst.TotalTokens += src.TotalTokens
}
