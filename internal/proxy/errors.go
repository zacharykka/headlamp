package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// ProtocolForPath infers the client-facing LLM protocol from an HTTP request path.
// Useful both inside Gateway and as an error-formatting helper for auth.Middleware.
func ProtocolForPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/anthropic/"):
		return ProtocolAnthropicMessages
	case strings.HasPrefix(path, "/gemini/"):
		return ProtocolGemini
	case path == "/v1/responses" || path == "/openai/v1/responses":
		return ProtocolOpenAIResponses
	default:
		return ProtocolOpenAIChat
	}
}

// AuthErrorHandler is an auth.Middleware onError callback that writes a 401
// Unauthorized JSON error formatted for the request path's native LLM protocol.
func AuthErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	msg := "authentication required"
	if err != nil {
		msg = err.Error()
	}
	WriteError(w, ProtocolForPath(r.URL.Path), http.StatusUnauthorized, "authentication_error", msg)
}

// WriteError writes a protocol-accurate JSON error envelope matching OpenAI,
// Anthropic, or Google Gemini conventions.
func WriteError(w http.ResponseWriter, protocol string, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	switch protocol {
	case ProtocolAnthropicMessages:
		errType := anthropicErrorType(statusCode, code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    errType,
				"message": message,
			},
			"request_id": "req_headlamp_" + uuid.NewString(),
		})

	case ProtocolGemini:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    statusCode,
				"message": message,
				"status":  geminiErrorStatus(statusCode, code),
			},
		})

	default:
		errType, errCode := openAIErrorTypeAndCode(statusCode, code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": message,
				"type":    errType,
				"param":   nil,
				"code":    errCode,
			},
		})
	}
}

func openAIErrorTypeAndCode(statusCode int, code string) (errType, errCode string) {
	errCode = code
	switch statusCode {
	case http.StatusBadRequest:
		errType = "invalid_request_error"
		if errCode == "" {
			errCode = "invalid_request"
		}
	case http.StatusUnauthorized:
		errType = "authentication_error"
		if errCode == "" || errCode == "authentication_error" {
			errCode = "invalid_api_key"
		}
	case http.StatusForbidden:
		errType = "permission_error"
		if errCode == "" {
			errCode = "model_not_allowed"
		}
	case http.StatusNotFound:
		errType = "invalid_request_error"
		if errCode == "" {
			errCode = "model_not_found"
		}
	case http.StatusTooManyRequests:
		if code == "insufficient_quota" {
			errType = "insufficient_quota"
		} else {
			errType = "requests"
			if errCode == "" {
				errCode = "rate_limit_exceeded"
			}
		}
	default:
		errType = "server_error"
		if errCode == "" {
			errCode = "upstream_error"
		}
	}
	return errType, errCode
}

func anthropicErrorType(statusCode int, code string) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case 529:
		return "overloaded_error"
	default:
		if code == "overloaded_error" {
			return "overloaded_error"
		}
		return "api_error"
	}
}

func geminiErrorStatus(statusCode int, code string) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "INVALID_ARGUMENT"
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusTooManyRequests:
		return "RESOURCE_EXHAUSTED"
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return "UNAVAILABLE"
	default:
		if code != "" {
			return strings.ToUpper(code)
		}
		return "INTERNAL"
	}
}

// extractUpstreamErrorMessage pulls a human-readable message from an upstream
// JSON error payload when translating an error across protocols.
func extractUpstreamErrorMessage(body []byte, fallback string) string {
	var parsed struct {
		Error any `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Error != nil {
		switch v := parsed.Error.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return v
			}
		case map[string]any:
			if msg, ok := v["message"].(string); ok && strings.TrimSpace(msg) != "" {
				return msg
			}
		}
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "" && len(trimmed) <= 512 {
		return trimmed
	}
	return fallback
}
