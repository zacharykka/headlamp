package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

func (g *Gateway) prepareUpstreamRequestPayload(inv llmInvocation, cand routeCandidate, isNative bool) (body []byte, targetURL string, injectedIncludeUsage bool, err error) {
	if isNative {
		switch inv.ingressProtocol {
		case ProtocolGemini:
			rawQuery := inv.rawQuery
			if !cand.provider.Passthrough {
				rawQuery = stripQueryParam(rawQuery, "key")
			}
			path := "/v1beta/models/" + url.PathEscape(cand.upstreamModel) + ":" + inv.geminiAction
			return inv.reqBody, buildUpstreamURL(cand.provider, path, rawQuery), false, nil

		case ProtocolOpenAIChat:
			needModelRewrite := cand.upstreamModel != inv.requestedModel || inv.guardrailModified
			needStreamOpts := inv.stream
			body = inv.reqBody
			if needModelRewrite || needStreamOpts {
				newModel := ""
				if needModelRewrite {
					newModel = cand.upstreamModel
				}
				var pinStream *bool
				if inv.guardrailModified {
					streamVal := inv.stream
					pinStream = &streamVal
				}
				body, injectedIncludeUsage, err = patchJSONRequestWithStream(inv.reqBody, newModel, needStreamOpts, pinStream)
				if err != nil {
					return nil, "", false, err
				}
			}
			return body, buildUpstreamURL(cand.provider, inv.upstreamPath, ""), injectedIncludeUsage, nil

		default:
			// OpenAI Responses, OpenAI Embeddings, Anthropic Messages:
			// zero JSON restructuring when model name matches and body was not rewritten by guardrails.
			body = inv.reqBody
			if cand.upstreamModel != inv.requestedModel || inv.guardrailModified {
				var pinStream *bool
				if inv.guardrailModified && inv.ingressProtocol != ProtocolOpenAIEmbeddings {
					streamVal := inv.stream
					pinStream = &streamVal
				}
				body, _, err = patchJSONRequestWithStream(inv.reqBody, cand.upstreamModel, false, pinStream)
				if err != nil {
					return nil, "", false, err
				}
			}
			return body, buildUpstreamURL(cand.provider, inv.upstreamPath, ""), false, nil
		}
	}

	// Cross-protocol translation: if guardrails modified the body, re-pin "stream"
	// before translating so a sync_review webhook cannot flip streaming mode.
	reqBody := inv.reqBody
	if inv.guardrailModified {
		streamVal := inv.stream
		reqBody, _, err = patchJSONRequestWithStream(reqBody, "", false, &streamVal)
		if err != nil {
			return nil, "", false, err
		}
	}

	switch inv.ingressProtocol {
	case ProtocolOpenAIChat:
		// OpenAI Chat -> Anthropic Messages.
		translatedBody, err := translate.OpenAIRequestToAnthropic(reqBody, cand.upstreamModel)
		if err != nil {
			return nil, "", false, err
		}
		return translatedBody, buildUpstreamURL(cand.provider, "/v1/messages", ""), false, nil

	case ProtocolAnthropicMessages:
		// Anthropic Messages -> OpenAI Chat (OpenAI or Ollama).
		translatedBody, err := translate.AnthropicRequestToOpenAI(reqBody, cand.upstreamModel, cand.provider.Type)
		if err != nil {
			return nil, "", false, err
		}
		return translatedBody, buildUpstreamURL(cand.provider, "/v1/chat/completions", ""), false, nil

	default:
		return nil, "", false, fmt.Errorf("unsupported cross-protocol translation from %s to %s", inv.ingressProtocol, cand.provider.Type)
	}
}

// patchJSONRequest rewrites only top-level "model" and/or force-merges
// "stream_options":{"include_usage":true}, preserving all other JSON fields
// (including sibling keys inside "stream_options") untouched.
//
// injectedIncludeUsage is true whenever injectStreamOptions was requested and
// the client did not already supply "stream_options": {"include_usage": true}.
func patchJSONRequest(body []byte, newModel string, injectStreamOptions bool) ([]byte, bool, error) {
	return patchJSONRequestWithStream(body, newModel, injectStreamOptions, nil)
}

func patchJSONRequestWithStream(body []byte, newModel string, injectStreamOptions bool, pinStream *bool) ([]byte, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, false, fmt.Errorf("invalid JSON object: %w", err)
	}
	if fields == nil {
		return nil, false, errors.New("JSON body must be an object")
	}

	modified := false
	injectedIncludeUsage := false
	if newModel != "" {
		encodedModel, err := json.Marshal(newModel)
		if err != nil {
			return nil, false, err
		}
		fields["model"] = encodedModel
		modified = true
	}

	if pinStream != nil {
		if *pinStream {
			fields["stream"] = json.RawMessage("true")
			modified = true
		} else {
			if _, hasStream := fields["stream"]; hasStream {
				fields["stream"] = json.RawMessage("false")
				modified = true
			}
			if _, hasOpts := fields["stream_options"]; hasOpts {
				delete(fields, "stream_options")
				modified = true
			}
		}
	}

	if injectStreamOptions {
		raw, exists := fields["stream_options"]
		trimmed := bytes.TrimSpace(raw)
		if !exists || len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			fields["stream_options"] = json.RawMessage(`{"include_usage":true}`)
			modified = true
			injectedIncludeUsage = true
		} else {
			var opts map[string]json.RawMessage
			if err := json.Unmarshal(trimmed, &opts); err != nil || opts == nil {
				fields["stream_options"] = json.RawMessage(`{"include_usage":true}`)
				modified = true
				injectedIncludeUsage = true
			} else {
				var alreadyTrue bool
				if incRaw, hasInc := opts["include_usage"]; hasInc {
					_ = json.Unmarshal(incRaw, &alreadyTrue)
				}
				if !alreadyTrue {
					opts["include_usage"] = json.RawMessage("true")
					encodedOpts, err := json.Marshal(opts)
					if err != nil {
						return nil, false, err
					}
					fields["stream_options"] = encodedOpts
					modified = true
					injectedIncludeUsage = true
				}
			}
		}
	}

	if !modified {
		return body, false, nil
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, false, err
	}
	return encoded, injectedIncludeUsage, nil
}

func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

// sanitizeUpstreamError strips query strings and userinfo from *url.Error URLs
// so passthrough credentials (such as Gemini ?key=...) never leak into
// usage_logs.error_message or HTTP 502 error envelopes.
func sanitizeUpstreamError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		cleanURL := urlErr.URL
		if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
			parsed.RawQuery = ""
			parsed.User = nil
			cleanURL = parsed.String()
		}
		return fmt.Sprintf("%s %q: %v", urlErr.Op, cleanURL, urlErr.Err)
	}
	return err.Error()
}

func buildUpstreamURL(provider store.Provider, endpointPath, rawQuery string) string {
	base := strings.TrimRight(strings.TrimSpace(provider.BaseURL), "/")
	if base == "" {
		base = strings.TrimRight(config.DefaultBaseURL(provider.Type), "/")
	}

	// Avoid duplicating version prefixes when BaseURL already includes /v1 or /v1beta.
	if strings.HasPrefix(endpointPath, "/v1/") && strings.HasSuffix(base, "/v1") {
		base = strings.TrimSuffix(base, "/v1")
	} else if strings.HasPrefix(endpointPath, "/v1beta/") && strings.HasSuffix(base, "/v1beta") {
		base = strings.TrimSuffix(base, "/v1beta")
	}

	target := base + endpointPath
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	return target
}

func stripQueryParam(rawQuery, name string) string {
	if rawQuery == "" {
		return ""
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	vals.Del(name)
	return vals.Encode()
}

func applyUpstreamHeaders(upReq, inReq *http.Request, provider store.Provider, isNative bool) {
	upReq.Header.Set("Content-Type", "application/json")
	if accept := inReq.Header.Get("Accept"); accept != "" {
		upReq.Header.Set("Accept", accept)
	}
	if ua := inReq.Header.Get("User-Agent"); ua != "" {
		upReq.Header.Set("User-Agent", ua)
	}

	// Forward provider-specific non-auth headers on native passthrough.
	if isNative {
		switch provider.Type {
		case config.ProviderTypeAnthropic:
			for _, h := range []string{"Anthropic-Version", "Anthropic-Beta"} {
				for _, v := range inReq.Header.Values(h) {
					upReq.Header.Add(h, v)
				}
			}
		case config.ProviderTypeOpenAI:
			for _, h := range []string{"OpenAI-Organization", "OpenAI-Project", "OpenAI-Beta"} {
				if v := inReq.Header.Get(h); v != "" {
					upReq.Header.Set(h, v)
				}
			}
		}
	}

	// Ensure Anthropic always receives anthropic-version even when translated or omitted.
	if provider.Type == config.ProviderTypeAnthropic && upReq.Header.Get("Anthropic-Version") == "" {
		upReq.Header.Set("Anthropic-Version", defaultAnthropicVersion)
	}

	// Auth headers: passthrough forwards client credentials; managed injects encrypted-at-rest key.
	if provider.Passthrough {
		for _, h := range []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key"} {
			if v := inReq.Header.Get(h); v != "" {
				upReq.Header.Set(h, v)
			}
		}
		return
	}

	if provider.APIKey == "" {
		return
	}
	switch provider.Type {
	case config.ProviderTypeOpenAI, config.ProviderTypeOllama:
		upReq.Header.Set("Authorization", "Bearer "+provider.APIKey)
	case config.ProviderTypeAnthropic:
		upReq.Header.Set("x-api-key", provider.APIKey)
	case config.ProviderTypeGemini:
		upReq.Header.Set("x-goog-api-key", provider.APIKey)
	}
}

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-encoding":    {},
	"content-length":      {},
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		if _, skip := hopByHopHeaders[strings.ToLower(k)]; skip {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}
