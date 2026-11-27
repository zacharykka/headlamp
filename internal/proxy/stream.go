package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zacharykka/headlamp/internal/translate"
)

// fallbackTokenObserver wraps a StreamObserver that does not implement TokenReporter
// so QuotaTicket.Release still receives accurate total token counts.
type fallbackTokenObserver struct {
	inner     StreamObserver
	input     int64
	output    int64
	cacheRead int64
	cacheWr   int64
	thoughts  int64
	total     int64
}

func (f *fallbackTokenObserver) SetResponseHeaders(h map[string]string) {
	f.inner.SetResponseHeaders(h)
}
func (f *fallbackTokenObserver) Finish(fin TelemetryFinish) { f.inner.Finish(fin) }

func (f *fallbackTokenObserver) OnSSEEvent(eventName string, data []byte) {
	f.inner.OnSSEEvent(eventName, data)
	f.extractTokens(data)
}

func (f *fallbackTokenObserver) OnJSONResponse(body []byte) {
	f.inner.OnJSONResponse(body)
	f.extractTokens(body)
}

func (f *fallbackTokenObserver) TotalTokens() int64 {
	if f.total > 0 {
		return f.total
	}
	return f.input + f.output + f.cacheRead + f.cacheWr + f.thoughts
}

func (f *fallbackTokenObserver) extractTokens(data []byte) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return
	}
	var probe struct {
		Usage *struct {
			PromptTokens             int64 `json:"prompt_tokens"`
			CompletionTokens         int64 `json:"completion_tokens"`
			TotalTokens              int64 `json:"total_tokens"`
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
		Message *struct {
			Usage *struct {
				InputTokens              int64 `json:"input_tokens"`
				OutputTokens             int64 `json:"output_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			} `json:"usage"`
		} `json:"message"`
		Response *struct {
			Usage *struct {
				TotalTokens  int64 `json:"total_tokens"`
				InputTokens  int64 `json:"input_tokens"`
				OutputTokens int64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"response"`
		UsageMetadata *struct {
			TotalTokenCount      int64 `json:"totalTokenCount"`
			PromptTokenCount     int64 `json:"promptTokenCount"`
			CandidatesTokenCount int64 `json:"candidatesTokenCount"`
			ThoughtsTokenCount   int64 `json:"thoughtsTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return
	}
	if probe.Usage != nil {
		if probe.Usage.TotalTokens > 0 {
			f.total = probe.Usage.TotalTokens
		}
		if probe.Usage.PromptTokens > 0 {
			f.input = probe.Usage.PromptTokens
		}
		if probe.Usage.CompletionTokens > 0 {
			f.output = probe.Usage.CompletionTokens
		}
		if probe.Usage.InputTokens > 0 {
			f.input = probe.Usage.InputTokens
		}
		if probe.Usage.OutputTokens > 0 {
			f.output = probe.Usage.OutputTokens
		}
		if probe.Usage.CacheReadInputTokens > 0 {
			f.cacheRead = probe.Usage.CacheReadInputTokens
		}
		if probe.Usage.CacheCreationInputTokens > 0 {
			f.cacheWr = probe.Usage.CacheCreationInputTokens
		}
	}
	if probe.Message != nil && probe.Message.Usage != nil {
		u := probe.Message.Usage
		if u.InputTokens > 0 {
			f.input = u.InputTokens
		}
		if u.OutputTokens > 0 {
			f.output = u.OutputTokens
		}
		if u.CacheReadInputTokens > 0 {
			f.cacheRead = u.CacheReadInputTokens
		}
		if u.CacheCreationInputTokens > 0 {
			f.cacheWr = u.CacheCreationInputTokens
		}
	}
	if probe.Response != nil && probe.Response.Usage != nil {
		u := probe.Response.Usage
		if u.TotalTokens > 0 {
			f.total = u.TotalTokens
		} else if u.InputTokens+u.OutputTokens > 0 {
			f.total = u.InputTokens + u.OutputTokens
		}
	}
	if probe.UsageMetadata != nil {
		u := probe.UsageMetadata
		if u.TotalTokenCount > 0 {
			f.total = u.TotalTokenCount
		} else if u.PromptTokenCount+u.CandidatesTokenCount+u.ThoughtsTokenCount > 0 {
			f.total = u.PromptTokenCount + u.CandidatesTokenCount + u.ThoughtsTokenCount
		}
	}
}

func (g *Gateway) startTelemetry(
	ctx context.Context,
	requestID string,
	ts time.Time,
	inv llmInvocation,
	cand routeCandidate,
	costOverride *CostOverride,
	translated bool,
) StreamObserver {
	if g.telemetry == nil {
		return noopObserver{}
	}
	obs := g.telemetry.Start(ctx, TelemetryStart{
		RequestID:       requestID,
		Timestamp:       ts,
		Principal:       inv.principal,
		Protocol:        upstreamWireProtocol(inv.ingressProtocol, cand.provider.Type),
		IngressProtocol: inv.ingressProtocol,
		Endpoint:        inv.endpointPath(),
		Provider:        cand.provider.Name,
		ProviderType:    cand.provider.Type,
		RequestedModel:  inv.requestedModel,
		UpstreamModel:   cand.upstreamModel,
		Stream:          inv.stream,
		Translated:      translated,
		RequestHeaders:  inv.reqHeaders,
		RequestBody:     inv.reqBody,
		CostOverride:    costOverride,
		GuardrailAction: inv.guardrailAction,
		GuardrailHits:   inv.guardrailHits,
	})
	if obs == nil {
		return noopObserver{}
	}
	return obs
}

func (g *Gateway) handleJSONResponse(
	w http.ResponseWriter,
	resp *http.Response,
	observer StreamObserver,
	startTime time.Time,
	attemptStart time.Time,
	inv llmInvocation,
	cand routeCandidate,
	translated bool,
) {
	upBody, err := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
	ttft := time.Since(attemptStart).Milliseconds()
	if err != nil {
		observer.Finish(TelemetryFinish{
			StatusCode:   http.StatusBadGateway,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttft,
			ErrorMessage: err.Error(),
		})
		WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "failed to read upstream response")
		return
	}

	// Feed raw upstream JSON to metering so provider-native usage fields are parsed losslessly.
	observer.OnJSONResponse(upBody)

	if !translated {
		copyResponseHeaders(w.Header(), resp.Header)
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("X-Headlamp-Provider-Type", cand.provider.Type)
		w.Header().Set("X-Headlamp-Upstream-Model", cand.upstreamModel)
		w.WriteHeader(resp.StatusCode)
		_, writeErr := w.Write(upBody)
		errMsg := ""
		if writeErr != nil {
			errMsg = writeErr.Error()
		}
		observer.Finish(TelemetryFinish{
			StatusCode:   resp.StatusCode,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttft,
			ErrorMessage: errMsg,
		})
		return
	}

	var outBody []byte
	switch inv.ingressProtocol {
	case ProtocolOpenAIChat:
		outBody, err = translate.AnthropicResponseToOpenAI(upBody, inv.requestedModel)
	case ProtocolAnthropicMessages:
		outBody, err = translate.OpenAIResponseToAnthropic(upBody, inv.requestedModel)
	default:
		err = fmt.Errorf("unsupported response translation for %s", inv.ingressProtocol)
	}
	if err != nil {
		observer.Finish(TelemetryFinish{
			StatusCode:   http.StatusBadGateway,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttft,
			ErrorMessage: err.Error(),
		})
		WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "failed to translate upstream response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Headlamp-Provider-Type", cand.provider.Type)
	w.Header().Set("X-Headlamp-Upstream-Model", cand.upstreamModel)
	w.WriteHeader(resp.StatusCode)
	_, writeErr := w.Write(outBody)
	errMsg := ""
	if writeErr != nil {
		errMsg = writeErr.Error()
	}
	observer.Finish(TelemetryFinish{
		StatusCode:   resp.StatusCode,
		LatencyMS:    time.Since(startTime).Milliseconds(),
		TTFTMS:       ttft,
		ErrorMessage: errMsg,
	})
}

func (g *Gateway) handleStreamingResponse(
	w http.ResponseWriter,
	resp *http.Response,
	observer StreamObserver,
	startTime time.Time,
	attemptStart time.Time,
	inv llmInvocation,
	cand routeCandidate,
	translated bool,
	isEventStream bool,
	suppressSyntheticUsage bool,
) {
	flusher, _ := w.(http.Flusher)

	copyResponseHeaders(w.Header(), resp.Header)
	if translated || isEventStream {
		w.Header().Set("Content-Type", "text/event-stream")
	} else if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Headlamp-Provider-Type", cand.provider.Type)
	w.Header().Set("X-Headlamp-Upstream-Model", cand.upstreamModel)
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	if flusher != nil {
		flusher.Flush()
	}

	var (
		ttftMS    int64
		gotFirst  bool
		streamErr error
	)
	recordFirstToken := func() {
		if !gotFirst {
			gotFirst = true
			ttftMS = time.Since(attemptStart).Milliseconds()
		}
	}

	defer func() {
		errMsg := ""
		if streamErr != nil {
			errMsg = streamErr.Error()
		}
		observer.Finish(TelemetryFinish{
			StatusCode:   resp.StatusCode,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttftMS,
			ErrorMessage: errMsg,
		})
	}()

	if !translated {
		if isEventStream || (inv.ingressProtocol != ProtocolGemini && inv.stream) {
			streamErr = streamNativeSSE(resp.Body, w, flusher, observer, suppressSyntheticUsage, recordFirstToken)
			return
		}
		// Fallback for non-SSE streaming (e.g. Gemini :streamGenerateContent without ?alt=sse).
		streamErr = streamNativeJSONChunks(resp.Body, w, flusher, observer, g.maxResponseBodyBytes, recordFirstToken)
		return
	}

	opts := translate.StreamOptions{
		RequestedModel: inv.requestedModel,
		IncludeUsage:   inv.clientIncludeUsage,
		OnUpstreamEvent: func(eventName string, data []byte) {
			observer.OnSSEEvent(eventName, data)
		},
		OnFirstToken: recordFirstToken,
	}

	switch inv.ingressProtocol {
	case ProtocolOpenAIChat:
		streamErr = translate.StreamAnthropicToOpenAI(resp.Body, w, flusher, opts)
	case ProtocolAnthropicMessages:
		streamErr = translate.StreamOpenAIToAnthropic(resp.Body, w, flusher, opts)
	default:
		streamErr = fmt.Errorf("unsupported streaming translation for %s", inv.ingressProtocol)
	}
}

// streamNativeSSE relays upstream SSE bytes using bufio.Reader (no 64 KiB Scanner
// limit), flushing at every event boundary and delivering decoded (eventName, data)
// frames to observer.OnSSEEvent.
//
// When suppressSyntheticUsage is true (meaning Headlamp injected stream_options.include_usage
// on behalf of a client that did not ask for it), the pure usage-only chunk
// (choices: [] && usage != nil && error == nil) is still delivered to observer.OnSSEEvent
// for metering but withheld from the downstream client.
func streamNativeSSE(
	upstream io.Reader,
	downstream io.Writer,
	flusher http.Flusher,
	observer StreamObserver,
	suppressSyntheticUsage bool,
	onFirstFrame func(),
) error {
	reader := bufio.NewReaderSize(upstream, 64*1024)

	var (
		eventName string
		dataBuf   bytes.Buffer
		frameBuf  bytes.Buffer
		hasData   bool
		hasEvent  bool
	)

	flushAndDispatch := func() error {
		var (
			data   []byte
			evName string
			hasEv  = hasData || hasEvent
		)
		if hasEv {
			data = bytes.Clone(dataBuf.Bytes())
			evName = eventName
			eventName = ""
			dataBuf.Reset()
			hasData = false
			hasEvent = false

			trimmed := bytes.TrimSpace(data)
			if !bytes.Equal(trimmed, []byte("[DONE]")) {
				observer.OnSSEEvent(evName, data)
			}
		}

		if suppressSyntheticUsage {
			if frameBuf.Len() > 0 {
				skipDownstream := hasEv && isSyntheticUsageOnlyChunk(data)
				if !skipDownstream {
					if onFirstFrame != nil {
						onFirstFrame()
					}
					if _, writeErr := downstream.Write(frameBuf.Bytes()); writeErr != nil {
						frameBuf.Reset()
						return writeErr
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				frameBuf.Reset()
			}
			return nil
		}

		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}

	for {
		line, readErr := translate.ReadLineLimited(reader, translate.MaxSSELineBytes)
		if len(line) > 0 {
			if suppressSyntheticUsage {
				if frameBuf.Len()+len(line) > translate.MaxSSELineBytes {
					frameBuf.Reset()
					dataBuf.Reset()
					return fmt.Errorf("%w (%d bytes)", translate.ErrSSELineTooLong, translate.MaxSSELineBytes)
				}
				frameBuf.Write(line)
			} else {
				if onFirstFrame != nil {
					onFirstFrame()
				}
				if _, writeErr := downstream.Write(line); writeErr != nil {
					if hasData || hasEvent {
						data := bytes.Clone(dataBuf.Bytes())
						if !bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
							observer.OnSSEEvent(eventName, data)
						}
					}
					return writeErr
				}
			}

			trimmed := bytes.TrimRight(line, "\r\n")
			if len(trimmed) == 0 {
				if writeErr := flushAndDispatch(); writeErr != nil {
					return writeErr
				}
			} else if trimmed[0] != ':' {
				colon := bytes.IndexByte(trimmed, ':')
				var field, value string
				if colon < 0 {
					field = string(trimmed)
				} else {
					field = string(trimmed[:colon])
					val := trimmed[colon+1:]
					if len(val) > 0 && val[0] == ' ' {
						val = val[1:]
					}
					value = string(val)
				}
				switch field {
				case "event":
					eventName = value
					hasEvent = true
				case "data":
					extra := len(value)
					if hasData {
						extra++
					}
					if dataBuf.Len()+extra > translate.MaxSSELineBytes {
						dataBuf.Reset()
						frameBuf.Reset()
						return fmt.Errorf("%w (%d bytes)", translate.ErrSSELineTooLong, translate.MaxSSELineBytes)
					}
					if hasData {
						dataBuf.WriteByte('\n')
					}
					dataBuf.WriteString(value)
					hasData = true
				}
			}
		}

		if readErr != nil {
			writeErr := flushAndDispatch()
			if writeErr != nil {
				return writeErr
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func isSyntheticUsageOnlyChunk(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	var probe struct {
		Choices json.RawMessage `json:"choices"`
		Usage   json.RawMessage `json:"usage"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return false
	}
	if isJSONEmptyOrNull(probe.Usage) || !isJSONEmptyOrNull(probe.Error) {
		return false
	}
	choicesRaw := bytes.TrimSpace(probe.Choices)
	if len(choicesRaw) == 0 || bytes.Equal(choicesRaw, []byte("null")) {
		return true
	}
	var choices []json.RawMessage
	return json.Unmarshal(choicesRaw, &choices) == nil && len(choices) == 0
}

func isJSONEmptyOrNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// streamNativeJSONChunks relays non-SSE streaming responses (such as Gemini
// :streamGenerateContent without ?alt=sse) chunk-by-chunk while extracting
// usageMetadata from the accumulated JSON payload when complete.
func streamNativeJSONChunks(
	upstream io.Reader,
	downstream io.Writer,
	flusher http.Flusher,
	observer StreamObserver,
	maxCaptureBytes int64,
	onFirstByte func(),
) error {
	if maxCaptureBytes <= 0 {
		maxCaptureBytes = defaultMaxResponseBodyBytes
	}
	var captured bytes.Buffer
	buf := make([]byte, 16*1024)
	for {
		n, readErr := upstream.Read(buf)
		if n > 0 {
			if onFirstByte != nil {
				onFirstByte()
			}
			chunk := buf[:n]
			if _, writeErr := downstream.Write(chunk); writeErr != nil {
				return writeErr
			}
			if flusher != nil {
				flusher.Flush()
			}
			if int64(captured.Len()) < maxCaptureBytes {
				captured.Write(chunk)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				feedJSONArrayOrObject(captured.Bytes(), observer)
				return nil
			}
			return readErr
		}
	}
}

func feedJSONArrayOrObject(raw []byte, observer StreamObserver) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return
	}
	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err == nil {
			for _, item := range items {
				observer.OnSSEEvent("", item)
			}
			return
		}
	}
	observer.OnJSONResponse(trimmed)
}
