package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
)

func (g *Gateway) makeJSONLLMHandler(ingressProtocol, upstreamPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := g.requirePrincipal(w, r, ingressProtocol)
		if !ok {
			return
		}

		reqBody, err := g.readLimitedBody(r)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				WriteError(w, ingressProtocol, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds gateway limit")
				return
			}
			WriteError(w, ingressProtocol, http.StatusBadRequest, "invalid_request", "failed to read request body")
			return
		}

		var meta struct {
			Model         string `json:"model"`
			Stream        bool   `json:"stream"`
			StreamOptions *struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
		}
		if err := json.Unmarshal(reqBody, &meta); err != nil {
			WriteError(w, ingressProtocol, http.StatusBadRequest, "invalid_request", "invalid JSON request body")
			return
		}
		if strings.TrimSpace(meta.Model) == "" {
			WriteError(w, ingressProtocol, http.StatusBadRequest, "invalid_request", "field 'model' is required")
			return
		}

		clientIncludeUsage := meta.StreamOptions != nil && meta.StreamOptions.IncludeUsage
		g.executeLLMRequest(w, r, llmInvocation{
			principal:          principal,
			ingressProtocol:    ingressProtocol,
			upstreamPath:       upstreamPath,
			requestedModel:     meta.Model,
			stream:             meta.Stream,
			clientIncludeUsage: clientIncludeUsage,
			reqHeaders:         r.Header.Clone(),
			reqBody:            reqBody,
		})
	}
}

func (g *Gateway) handleAnthropicCountTokens(w http.ResponseWriter, r *http.Request) {
	principal, ok := g.requirePrincipal(w, r, ProtocolAnthropicMessages)
	if !ok {
		return
	}

	reqBody, err := g.readLimitedBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			WriteError(w, ProtocolAnthropicMessages, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds gateway limit")
			return
		}
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request", "failed to read request body")
		return
	}

	var meta struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(reqBody, &meta); err != nil || strings.TrimSpace(meta.Model) == "" {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request", "valid JSON body with 'model' is required")
		return
	}

	resolved, err := resolveRoute(r.Context(), g.store, ProtocolAnthropicMessages, meta.Model)
	if err != nil {
		if errors.Is(err, errModelNotFound) {
			WriteError(w, ProtocolAnthropicMessages, http.StatusNotFound, "not_found_error", fmt.Sprintf("model %q not found", meta.Model))
			return
		}
		WriteError(w, ProtocolAnthropicMessages, http.StatusInternalServerError, "api_error", "route resolution failed")
		return
	}

	if !g.authorizeModel(w, r, principal, ProtocolAnthropicMessages, resolved.canonicalModel) {
		return
	}

	var anthropicCands []routeCandidate
	for _, cand := range resolved.candidates {
		if cand.provider.Type == config.ProviderTypeAnthropic {
			anthropicCands = append(anthropicCands, cand)
		}
	}
	if len(anthropicCands) == 0 {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request_error", "count_tokens is only supported for Anthropic upstreams")
		return
	}

	if resolved.isAlias && g.authorizer != nil {
		filtered := make([]routeCandidate, 0, len(anthropicCands))
		var lastDenyReason string
		for _, cand := range anthropicCands {
			candModel := cand.provider.Name + "/" + cand.upstreamModel
			denied, reason, denyErr := g.authorizer.IsModelDenied(r.Context(), principal, candModel)
			if denyErr != nil {
				WriteError(w, ProtocolAnthropicMessages, http.StatusInternalServerError, "api_error", "authorization check failed")
				return
			}
			if denied {
				if reason == "" {
					reason = fmt.Sprintf("underlying model %q denied by policy", candModel)
				}
				lastDenyReason = reason
				continue
			}
			filtered = append(filtered, cand)
		}
		if len(filtered) == 0 {
			WriteError(w, ProtocolAnthropicMessages, http.StatusForbidden, "permission_error", lastDenyReason)
			return
		}
		anthropicCands = filtered
	}

	// Run guardrails before forwarding prompt messages to Anthropic's count_tokens endpoint.
	guardrailModified := false
	if g.guardrails != nil {
		requestID := uuid.NewString()
		decision, gErr := g.guardrails.Inspect(r.Context(), GuardrailRequest{
			RequestID: requestID,
			Principal: principal,
			Protocol:  ProtocolAnthropicMessages,
			Model:     resolved.canonicalModel,
			Body:      reqBody,
		})
		if gErr != nil {
			g.logf("headlamp proxy: count_tokens request_id=%s guardrail error: %v", requestID, gErr)
			WriteError(w, ProtocolAnthropicMessages, http.StatusInternalServerError, "api_error", "guardrail inspection failed")
			return
		}
		if decision != nil {
			if decision.Action == "block" {
				statusCode := decision.StatusCode
				if statusCode < 400 {
					statusCode = http.StatusBadRequest
				}
				reason := decision.Reason
				if reason == "" {
					reason = "request blocked by guardrail policy"
				}
				WriteError(w, ProtocolAnthropicMessages, statusCode, "guardrail_blocked", reason)
				return
			}
			if (decision.Action == "redact" || decision.Action == "modify") && len(decision.ModifiedBody) > 0 {
				reqBody = decision.ModifiedBody
				guardrailModified = true
			}
		}
	}

	var lastResp *http.Response
	for i, cand := range anthropicCands {
		bodyToSend := reqBody
		if cand.upstreamModel != meta.Model || guardrailModified {
			bodyToSend, _, err = patchJSONRequest(reqBody, cand.upstreamModel, false)
			if err != nil {
				if i+1 < len(anthropicCands) {
					continue
				}
				WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request_error", "failed to rewrite model field")
				return
			}
		}

		targetURL := buildUpstreamURL(cand.provider, "/v1/messages/count_tokens", "")
		upReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(bodyToSend))
		if reqErr != nil {
			if i+1 < len(anthropicCands) {
				continue
			}
			WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "failed to construct upstream request")
			return
		}
		applyUpstreamHeaders(upReq, r, cand.provider, true)

		resp, doErr := g.httpClient.Do(upReq)
		if doErr != nil {
			safeErr := sanitizeUpstreamError(doErr)
			if i+1 < len(anthropicCands) {
				next := anthropicCands[i+1]
				g.logf("headlamp proxy: count_tokens model=%s candidate %s/%s failed (%s), falling back to %s/%s",
					meta.Model, cand.provider.Name, cand.upstreamModel, safeErr, next.provider.Name, next.upstreamModel)
				continue
			}
			WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "upstream request failed: "+safeErr)
			return
		}

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && i+1 < len(anthropicCands) {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()
			next := anthropicCands[i+1]
			g.logf("headlamp proxy: count_tokens model=%s candidate %s/%s returned HTTP %d, falling back to %s/%s",
				meta.Model, cand.provider.Name, cand.upstreamModel, resp.StatusCode, next.provider.Name, next.upstreamModel)
			continue
		}

		lastResp = resp
		break
	}
	if lastResp == nil {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "no Anthropic upstream succeeded for count_tokens")
		return
	}
	defer lastResp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(lastResp.Body, g.maxResponseBodyBytes))
	if err != nil {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "failed to read upstream response")
		return
	}
	copyResponseHeaders(w.Header(), lastResp.Header)
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(lastResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (g *Gateway) handleGeminiGenerate(w http.ResponseWriter, r *http.Request) {
	principal, ok := g.requirePrincipal(w, r, ProtocolGemini)
	if !ok {
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/gemini/v1beta/models/")
	modelID, action, hasColon := strings.Cut(rest, ":")
	if !hasColon || modelID == "" || (action != "generateContent" && action != "streamGenerateContent") {
		WriteError(w, ProtocolGemini, http.StatusNotFound, "NOT_FOUND", "unsupported Gemini endpoint; expected :generateContent or :streamGenerateContent")
		return
	}
	if decoded, err := url.PathUnescape(modelID); err == nil {
		modelID = decoded
	}

	reqBody, err := g.readLimitedBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			WriteError(w, ProtocolGemini, http.StatusRequestEntityTooLarge, "INVALID_ARGUMENT", "request body exceeds gateway limit")
			return
		}
		WriteError(w, ProtocolGemini, http.StatusBadRequest, "INVALID_ARGUMENT", "failed to read request body")
		return
	}

	trimmedBody := bytes.TrimSpace(reqBody)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' || !json.Valid(trimmedBody) {
		WriteError(w, ProtocolGemini, http.StatusBadRequest, "INVALID_ARGUMENT", "invalid JSON request body")
		return
	}

	g.executeLLMRequest(w, r, llmInvocation{
		principal:       principal,
		ingressProtocol: ProtocolGemini,
		requestedModel:  modelID,
		stream:          action == "streamGenerateContent",
		geminiAction:    action,
		rawQuery:        r.URL.RawQuery,
		reqHeaders:      r.Header.Clone(),
		reqBody:         reqBody,
	})
}

type llmInvocation struct {
	principal          *auth.Principal
	ingressProtocol    string
	upstreamPath       string
	requestedModel     string
	stream             bool
	clientIncludeUsage bool
	geminiAction       string
	rawQuery           string
	reqHeaders         http.Header
	reqBody            []byte
	guardrailAction    string
	guardrailHits      []string
	guardrailModified  bool
}

func (inv llmInvocation) endpointPath() string {
	if inv.ingressProtocol == ProtocolGemini {
		return "/gemini/v1beta/models/" + inv.requestedModel + ":" + inv.geminiAction
	}
	return inv.upstreamPath
}

func (g *Gateway) executeLLMRequest(w http.ResponseWriter, r *http.Request, inv llmInvocation) {
	resolved, err := resolveRoute(r.Context(), g.store, inv.ingressProtocol, inv.requestedModel)
	if err != nil {
		if errors.Is(err, errModelNotFound) {
			WriteError(w, inv.ingressProtocol, http.StatusNotFound, "model_not_found", fmt.Sprintf("model %q not found", inv.requestedModel))
			return
		}
		WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "route resolution failed")
		return
	}

	if !g.authorizeModel(w, r, inv.principal, inv.ingressProtocol, resolved.canonicalModel) {
		return
	}

	startTime := time.Now()
	requestID := uuid.NewString()

	type compatibleCandidate struct {
		cand         routeCandidate
		isNative     bool
		isTranslated bool
	}

	compatible := make([]compatibleCandidate, 0, len(resolved.candidates))
	var incompatErr error
	for _, cand := range resolved.candidates {
		isNative := isNativeProtocolMatch(inv.ingressProtocol, cand.provider.Type)
		isTranslated := !isNative && canTranslateProtocol(inv.ingressProtocol, cand.provider.Type)
		if !isNative && !isTranslated {
			if incompatErr == nil {
				incompatErr = fmt.Errorf("unsupported cross-protocol route from %s to %s", inv.ingressProtocol, cand.provider.Type)
			}
			continue
		}
		compatible = append(compatible, compatibleCandidate{
			cand:         cand,
			isNative:     isNative,
			isTranslated: isTranslated,
		})
	}
	if len(compatible) == 0 {
		msg := "no compatible upstream provider available"
		if incompatErr != nil {
			msg = incompatErr.Error()
		}
		WriteError(w, inv.ingressProtocol, http.StatusBadRequest, "invalid_request", msg)
		return
	}

	// Enforce explicit DenyModels on concrete underlying candidates of a virtual route alias.
	if resolved.isAlias && g.authorizer != nil {
		allowedCands := make([]compatibleCandidate, 0, len(compatible))
		var lastDenyReason string
		for _, item := range compatible {
			candModel := item.cand.provider.Name + "/" + item.cand.upstreamModel
			denied, reason, denyErr := g.authorizer.IsModelDenied(r.Context(), inv.principal, candModel)
			if denyErr != nil {
				WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "authorization check failed")
				return
			}
			if denied {
				if reason == "" {
					reason = fmt.Sprintf("underlying model %q denied by policy", candModel)
				}
				lastDenyReason = reason
				continue
			}
			allowedCands = append(allowedCands, item)
		}
		if len(allowedCands) == 0 {
			WriteError(w, inv.ingressProtocol, http.StatusForbidden, "model_not_allowed", lastDenyReason)
			return
		}
		compatible = allowedCands
	}

	// Pre-request Guardrail inspection (local regex + sync_review webhooks).
	if g.guardrails != nil {
		decision, gErr := g.guardrails.Inspect(r.Context(), GuardrailRequest{
			RequestID: requestID,
			Principal: inv.principal,
			Protocol:  inv.ingressProtocol,
			Model:     resolved.canonicalModel,
			Body:      inv.reqBody,
		})
		if gErr != nil {
			g.logf("headlamp proxy: request_id=%s guardrail error: %v", requestID, gErr)
			WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "guardrail inspection failed")
			return
		}
		if decision != nil {
			if decision.Action != "" && decision.Action != "allow" {
				inv.guardrailAction = decision.Action
				inv.guardrailHits = decision.Hits
			}
			if decision.Action == "block" {
				statusCode := decision.StatusCode
				if statusCode < 400 {
					statusCode = http.StatusBadRequest
				}
				reason := decision.Reason
				if reason == "" {
					reason = "request blocked by guardrail policy"
				}
				// Never persist blocked raw secrets (e.g. PEM private keys) into audit_payloads.
				inv.reqBody = []byte("[BLOCKED BY GUARDRAIL]")
				obs := g.startTelemetry(r.Context(), requestID, startTime, inv, compatible[0].cand, resolved.costOverride, compatible[0].isTranslated)
				obs.Finish(TelemetryFinish{
					StatusCode:   statusCode,
					LatencyMS:    time.Since(startTime).Milliseconds(),
					ErrorMessage: reason,
				})
				WriteError(w, inv.ingressProtocol, statusCode, "guardrail_blocked", reason)
				return
			}
			if (decision.Action == "redact" || decision.Action == "modify") && len(decision.ModifiedBody) > 0 {
				inv.reqBody = decision.ModifiedBody
				inv.guardrailModified = true
			}
		}
	}

	// Quota & rate-limit acquisition (RPM / TPM / MaxConcurrent / Daily & Monthly USD).
	var (
		quotaTicket QuotaTicket
		usedTokens  int64
	)
	if g.quota != nil {
		ticket, rej, qErr := g.quota.Acquire(r.Context(), inv.principal)
		if qErr != nil {
			g.logf("headlamp proxy: request_id=%s quota error: %v", requestID, qErr)
			WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "quota check failed")
			return
		}
		if rej != nil {
			if rej.RetryAfterSec > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(rej.RetryAfterSec))
			}
			reason := rej.Reason
			if reason == "" {
				reason = "quota or rate limit exceeded"
			}
			code := "rate_limit_exceeded"
			if rej.Metric == "daily_usd" || rej.Metric == "monthly_usd" {
				code = "insufficient_quota"
			}
			obs := g.startTelemetry(r.Context(), requestID, startTime, inv, compatible[0].cand, resolved.costOverride, compatible[0].isTranslated)
			obs.Finish(TelemetryFinish{
				StatusCode:   http.StatusTooManyRequests,
				LatencyMS:    time.Since(startTime).Milliseconds(),
				ErrorMessage: reason,
			})
			WriteError(w, inv.ingressProtocol, http.StatusTooManyRequests, code, reason)
			return
		}
		quotaTicket = ticket
	}
	if quotaTicket != nil {
		defer func() {
			quotaTicket.Release(usedTokens)
		}()
	}

	var (
		lastResp          *http.Response
		lastCand          routeCandidate
		lastTranslated    bool
		lastInjectedUsage bool
		lastAttemptStart  time.Time
		lastErr           error
	)

	for i, item := range compatible {
		cand := item.cand
		isNative := item.isNative
		isTranslated := item.isTranslated

		upBody, upURL, injectedIncludeUsage, err := g.prepareUpstreamRequestPayload(inv, cand, isNative)
		if err != nil {
			lastErr = err
			if i+1 < len(compatible) {
				next := compatible[i+1].cand
				g.logf("headlamp proxy: request_id=%s model=%s candidate %s/%s payload error (%v), falling back to %s/%s",
					requestID, inv.requestedModel, cand.provider.Name, cand.upstreamModel, err, next.provider.Name, next.upstreamModel)
				g.emitFallbackEvent(requestID, inv, cand, next, 0, err.Error())
				continue
			}
			WriteError(w, inv.ingressProtocol, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upURL, bytes.NewReader(upBody))
		if err != nil {
			lastErr = err
			if i+1 < len(compatible) {
				continue
			}
			WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "failed to build upstream request")
			return
		}
		applyUpstreamHeaders(upReq, r, cand.provider, isNative)

		attemptStart := time.Now()
		resp, err := g.httpClient.Do(upReq)
		if err != nil {
			safeErr := sanitizeUpstreamError(err)
			lastErr = errors.New(safeErr)
			lastCand = cand
			lastTranslated = isTranslated
			if i+1 < len(compatible) {
				next := compatible[i+1].cand
				g.logf("headlamp proxy: request_id=%s model=%s candidate %s/%s network error (%s), falling back to %s/%s",
					requestID, inv.requestedModel, cand.provider.Name, cand.upstreamModel, safeErr, next.provider.Name, next.upstreamModel)
				g.emitFallbackEvent(requestID, inv, cand, next, 0, safeErr)
				continue
			}
			// Network failure on last compatible candidate.
			g.emitUpstreamErrorEvent(requestID, inv, cand, http.StatusBadGateway, safeErr)
			obs := g.startTelemetry(r.Context(), requestID, startTime, inv, cand, resolved.costOverride, isTranslated)
			obs.Finish(TelemetryFinish{
				StatusCode:   http.StatusBadGateway,
				LatencyMS:    time.Since(startTime).Milliseconds(),
				TTFTMS:       time.Since(attemptStart).Milliseconds(),
				ErrorMessage: safeErr,
			})
			WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "upstream request failed: "+safeErr)
			return
		}

		// Retry fallback candidates on 429 or 5xx BEFORE writing any response headers to the client.
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && i+1 < len(compatible) {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()
			next := compatible[i+1].cand
			reason := fmt.Sprintf("HTTP %d", resp.StatusCode)
			g.logf("headlamp proxy: request_id=%s model=%s candidate %s/%s returned %s, falling back to %s/%s",
				requestID, inv.requestedModel, cand.provider.Name, cand.upstreamModel, reason, next.provider.Name, next.upstreamModel)
			g.emitFallbackEvent(requestID, inv, cand, next, resp.StatusCode, reason)
			lastErr = fmt.Errorf("upstream %s returned HTTP %d", cand.provider.Name, resp.StatusCode)
			continue
		}

		lastResp = resp
		lastCand = cand
		lastTranslated = isTranslated
		lastInjectedUsage = injectedIncludeUsage
		lastAttemptStart = attemptStart
		break
	}

	if lastResp == nil {
		msg := "no compatible upstream provider available"
		if lastErr != nil {
			msg = lastErr.Error()
		}
		WriteError(w, inv.ingressProtocol, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	defer lastResp.Body.Close()

	observer := g.startTelemetry(r.Context(), requestID, startTime, inv, lastCand, resolved.costOverride, lastTranslated)
	// Ensure token usage is tracked for quotaTicket.Release even when no TokenReporter is wired.
	var tokenTracker *fallbackTokenObserver
	if quotaTicket != nil {
		if _, hasReporter := observer.(TokenReporter); !hasReporter {
			tokenTracker = &fallbackTokenObserver{inner: observer}
			observer = tokenTracker
		}
		defer func() {
			if tr, ok := observer.(TokenReporter); ok {
				usedTokens = tr.TotalTokens()
			} else if tokenTracker != nil {
				usedTokens = tokenTracker.TotalTokens()
			}
		}()
	}
	observer.SetResponseHeaders(flattenHeaders(lastResp.Header))

	// Handle non-2xx upstream response (status + error envelope).
	if lastResp.StatusCode < 200 || lastResp.StatusCode >= 300 {
		errBody, readErr := io.ReadAll(io.LimitReader(lastResp.Body, g.maxResponseBodyBytes))
		if len(errBody) > 0 {
			observer.OnJSONResponse(errBody)
		}
		latency := time.Since(startTime).Milliseconds()
		ttft := time.Since(lastAttemptStart).Milliseconds()
		errMsg := extractUpstreamErrorMessage(errBody, fmt.Sprintf("upstream returned HTTP %d", lastResp.StatusCode))
		if readErr != nil {
			errMsg = readErr.Error()
		}
		if lastResp.StatusCode >= 500 {
			g.emitUpstreamErrorEvent(requestID, inv, lastCand, lastResp.StatusCode, errMsg)
		}
		observer.Finish(TelemetryFinish{
			StatusCode:   lastResp.StatusCode,
			LatencyMS:    latency,
			TTFTMS:       ttft,
			ErrorMessage: errMsg,
		})
		if lastTranslated {
			WriteError(w, inv.ingressProtocol, lastResp.StatusCode, "", errMsg)
			return
		}
		copyResponseHeaders(w.Header(), lastResp.Header)
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(lastResp.StatusCode)
		_, _ = w.Write(errBody)
		return
	}

	contentType := strings.ToLower(lastResp.Header.Get("Content-Type"))
	isEventStream := strings.Contains(contentType, "text/event-stream")
	isStreamingResp := isEventStream || inv.stream

	if isStreamingResp {
		g.handleStreamingResponse(w, lastResp, observer, startTime, lastAttemptStart, inv, lastCand, lastTranslated, isEventStream, lastInjectedUsage)
		return
	}

	g.handleJSONResponse(w, lastResp, observer, startTime, lastAttemptStart, inv, lastCand, lastTranslated)
}

func (g *Gateway) emitFallbackEvent(requestID string, inv llmInvocation, failed, next routeCandidate, statusCode int, reason string) {
	if g.events == nil {
		return
	}
	subject := ""
	if inv.principal != nil {
		subject = inv.principal.Subject
	}
	g.events.Emit(config.WebhookEventUpstreamFallback, map[string]any{
		"request_id":      requestID,
		"subject":         subject,
		"model":           inv.requestedModel,
		"failed_provider": failed.provider.Name,
		"failed_model":    failed.upstreamModel,
		"next_provider":   next.provider.Name,
		"next_model":      next.upstreamModel,
		"status_code":     statusCode,
		"reason":          reason,
	})
}

func (g *Gateway) emitUpstreamErrorEvent(requestID string, inv llmInvocation, cand routeCandidate, statusCode int, errMsg string) {
	if g.events == nil {
		return
	}
	subject := ""
	if inv.principal != nil {
		subject = inv.principal.Subject
	}
	g.events.Emit(config.WebhookEventUpstreamError, map[string]any{
		"request_id":     requestID,
		"subject":        subject,
		"model":          inv.requestedModel,
		"provider":       cand.provider.Name,
		"upstream_model": cand.upstreamModel,
		"status_code":    statusCode,
		"error":          errMsg,
	})
}
