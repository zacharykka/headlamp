package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

// --- Team Web Chat Endpoints (/api/v1/chat/*) ---

func (h *Handler) handleChatModels(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if h.chatHandler == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "chat service is not configured")
		return
	}
	models, err := h.chatHandler.ListModels(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if models == nil {
		models = []ChatModelItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

func (h *Handler) handleChatMCPServers(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if h.chatHandler == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "chat service is not configured")
		return
	}
	servers, err := h.chatHandler.ListMCPServers(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if servers == nil {
		servers = []ChatMCPServerItem{}
	}
	for i := range servers {
		if servers[i].Tools == nil {
			servers[i].Tools = []MCPToolInfo{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers})
}

func (h *Handler) handleChatListSessions(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	limit := parseIntQuery(r, "limit", 50, 1, 200)
	offset := parseIntQuery(r, "offset", 0, 0, 100000)

	sessions, err := h.store.ListChatSessions(r.Context(), p.Subject, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if sessions == nil {
		sessions = []store.ChatSession{}
	}
	for i := range sessions {
		if sessions[i].MCPServers == nil {
			sessions[i].MCPServers = []string{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (h *Handler) handleChatCreateSession(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	var req struct {
		Title        string   `json:"title"`
		Model        string   `json:"model"`
		MCPServers   []string `json:"mcp_servers"`
		SystemPrompt string   `json:"system_prompt"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "model is required")
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "New Chat"
	}

	created, err := h.store.CreateChatSession(r.Context(), store.ChatSession{
		Subject:      p.Subject,
		Title:        title,
		Model:        model,
		MCPServers:   cleanStringList(req.MCPServers),
		SystemPrompt: req.SystemPrompt,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if created.MCPServers == nil {
		created.MCPServers = []string{}
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) handleChatGetSession(w http.ResponseWriter, r *http.Request, p *auth.Principal, id string) {
	sess, err := h.store.GetChatSession(r.Context(), p.Subject, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("chat session %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	msgs, err := h.store.ListChatMessages(r.Context(), p.Subject, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("chat session %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if sess.MCPServers == nil {
		sess.MCPServers = []string{}
	}
	if msgs == nil {
		msgs = []store.ChatMessage{}
	}
	for i := range msgs {
		if msgs[i].ToolEvents == nil {
			msgs[i].ToolEvents = []store.ChatToolEvent{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session":  sess,
		"messages": msgs,
	})
}

func (h *Handler) handleChatUpdateSession(w http.ResponseWriter, r *http.Request, p *auth.Principal, id string) {
	existing, err := h.store.GetChatSession(r.Context(), p.Subject, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("chat session %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var req struct {
		Title        *string   `json:"title"`
		Model        *string   `json:"model"`
		MCPServers   *[]string `json:"mcp_servers"`
		SystemPrompt *string   `json:"system_prompt"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Title != nil {
		existing.Title = strings.TrimSpace(*req.Title)
	}
	if req.Model != nil {
		m := strings.TrimSpace(*req.Model)
		if m == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "model must not be empty")
			return
		}
		existing.Model = m
	}
	if req.MCPServers != nil {
		existing.MCPServers = cleanStringList(*req.MCPServers)
	}
	if req.SystemPrompt != nil {
		existing.SystemPrompt = *req.SystemPrompt
	}

	updated, err := h.store.UpdateChatSession(r.Context(), p.Subject, *existing)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("chat session %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if updated.MCPServers == nil {
		updated.MCPServers = []string{}
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) handleChatDeleteSession(w http.ResponseWriter, r *http.Request, p *auth.Principal, id string) {
	if err := h.store.DeleteChatSession(r.Context(), p.Subject, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("chat session %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (h *Handler) handleChatSendMessage(w http.ResponseWriter, r *http.Request, p *auth.Principal, id string) {
	if h.chatHandler == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "chat service is not configured")
		return
	}
	var req ChatSendMessageRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "content is required")
		return
	}
	if _, err := h.store.GetChatSession(r.Context(), p.Subject, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("chat session %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	tw := &responseCommittedWriter{ResponseWriter: w}
	if err := h.chatHandler.StreamMessage(r.Context(), tw, p, id, req); err != nil && !tw.committed {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("chat session %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
	}
}

// responseCommittedWriter tracks whether status/body has been written while preserving http.Flusher
// and http.ResponseController Unwrap() for SSE streaming.
type responseCommittedWriter struct {
	http.ResponseWriter
	committed bool
}

func (w *responseCommittedWriter) WriteHeader(code int) {
	w.committed = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseCommittedWriter) Write(p []byte) (int, error) {
	w.committed = true
	return w.ResponseWriter.Write(p)
}

func (w *responseCommittedWriter) Flush() {
	if fl, ok := w.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (w *responseCommittedWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// --- Admin MCP Gateway Endpoints (/api/v1/admin/mcp/*) ---

type mcpServerResponse struct {
	Name             string    `json:"name"`
	URL              string    `json:"url"`
	Transport        string    `json:"transport"`
	AuthType         string    `json:"auth_type"`
	AuthHeader       string    `json:"auth_header"`
	HasAuthToken     bool      `json:"has_auth_token"`
	AuthTokenPreview string    `json:"auth_token_preview"`
	Enabled          bool      `json:"enabled"`
	Source           string    `json:"source"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func toMCPServerResponse(m store.MCPServer) mcpServerResponse {
	return mcpServerResponse{
		Name:             m.Name,
		URL:              m.URL,
		Transport:        m.Transport,
		AuthType:         m.AuthType,
		AuthHeader:       m.AuthHeader,
		HasAuthToken:     m.AuthToken != "",
		AuthTokenPreview: maskSecret(m.AuthToken),
		Enabled:          m.Enabled,
		Source:           m.Source,
		UpdatedAt:        m.UpdatedAt,
	}
}

type mcpServerRequest struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	Transport      string `json:"transport"`
	AuthType       string `json:"auth_type"`
	AuthHeader     string `json:"auth_header"`
	AuthToken      string `json:"auth_token"`
	ClearAuthToken bool   `json:"clear_auth_token"`
	Enabled        *bool  `json:"enabled"`
}

func (h *Handler) handleAdminListMCPServers(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListMCPServers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	out := make([]mcpServerResponse, 0, len(list))
	for _, m := range list {
		out = append(out, toMCPServerResponse(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

func (h *Handler) handleAdminCreateMCPServer(w http.ResponseWriter, r *http.Request) {
	var req mcpServerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	srv, err := validateMCPServerPayload(req.Name, req, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if existing, err := h.store.GetMCPServer(r.Context(), srv.Name); err == nil {
		if existing.Source == store.SourceConfig {
			writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("mcp server", srv.Name))
			return
		}
		writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("mcp server %q already exists", srv.Name))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := h.store.UpsertMCPServer(r.Context(), srv); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetMCPServer(r.Context(), srv.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toMCPServerResponse(*saved))
}

func (h *Handler) handleAdminUpdateMCPServer(w http.ResponseWriter, r *http.Request, name string) {
	existing, err := h.store.GetMCPServer(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("mcp server %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("mcp server", name))
		return
	}
	var req mcpServerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	srv, err := validateMCPServerPayload(name, req, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.store.UpsertMCPServer(r.Context(), srv); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetMCPServer(r.Context(), srv.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toMCPServerResponse(*saved))
}

func (h *Handler) handleAdminDeleteMCPServer(w http.ResponseWriter, r *http.Request, name string) {
	existing, err := h.store.GetMCPServer(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("mcp server %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("mcp server", name))
		return
	}
	if err := h.store.DeleteMCPServer(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("mcp server %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

func (h *Handler) handleAdminTestMCPServer(w http.ResponseWriter, r *http.Request, name string) {
	if h.mcpTester == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "mcp tester is not configured")
		return
	}
	srv, err := h.store.GetMCPServer(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("mcp server %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	tools, latencyMS, err := h.mcpTester.DiscoverTools(r.Context(), *srv)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": latencyMS,
			"message":    sanitizeNetError(err),
			"tools":      []MCPToolInfo{},
		})
		return
	}
	if tools == nil {
		tools = []MCPToolInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"latency_ms": latencyMS,
		"message":    fmt.Sprintf("Discovered %d tool(s)", len(tools)),
		"tools":      tools,
	})
}

func (h *Handler) handleAdminMCPAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.MCPAuditFilter{
		ServerName: strings.TrimSpace(q.Get("server")),
		Subject:    strings.TrimSpace(q.Get("subject")),
		ToolName:   strings.TrimSpace(q.Get("tool")),
		Status:     strings.TrimSpace(q.Get("status")),
		Limit:      parseIntQuery(r, "limit", 50, 1, 500),
		Offset:     parseIntQuery(r, "offset", 0, 0, 100000),
	}
	if sinceStr := strings.TrimSpace(q.Get("since")); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "since must be RFC3339 timestamp")
			return
		}
		filter.Since = t
	}
	if untilStr := strings.TrimSpace(q.Get("until")); untilStr != "" {
		t, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "until must be RFC3339 timestamp")
			return
		}
		filter.Until = t
	}

	logs, err := h.store.QueryMCPAuditLogs(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if logs == nil {
		logs = []store.MCPAuditLog{}
	}
	for i := range logs {
		if logs[i].Tags == nil {
			logs[i].Tags = []string{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

func validateMCPServerPayload(name string, req mcpServerRequest, existing *store.MCPServer) (store.MCPServer, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return store.MCPServer{}, errors.New("mcp server name is required")
	}
	if strings.Contains(name, "/") {
		return store.MCPServer{}, errors.New("mcp server name must not contain '/'")
	}

	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" && existing != nil {
		rawURL = existing.URL
	}
	if err := validateHTTPURL(rawURL); err != nil {
		return store.MCPServer{}, fmt.Errorf("url: %w", err)
	}

	transport := strings.ToLower(strings.TrimSpace(req.Transport))
	if transport == "" {
		if existing != nil && existing.Transport != "" {
			transport = existing.Transport
		} else {
			transport = config.MCPTransportStreamableHTTP
		}
	}
	switch transport {
	case config.MCPTransportStreamableHTTP, config.MCPTransportSSE:
	default:
		return store.MCPServer{}, fmt.Errorf("transport %q must be streamable_http or sse", transport)
	}

	authType := strings.ToLower(strings.TrimSpace(req.AuthType))
	if authType == "" {
		if existing != nil && existing.AuthType != "" {
			authType = existing.AuthType
		} else {
			authType = config.MCPAuthNone
		}
	}
	authHeader := strings.TrimSpace(req.AuthHeader)
	if authHeader == "" && existing != nil && authType == existing.AuthType {
		authHeader = existing.AuthHeader
	}
	switch authType {
	case config.MCPAuthNone, config.MCPAuthBearer, config.MCPAuthBasic:
		if authType != config.MCPAuthHeader {
			authHeader = ""
		}
	case config.MCPAuthHeader:
		if authHeader == "" {
			return store.MCPServer{}, errors.New("auth_header is required when auth_type is header")
		}
	default:
		return store.MCPServer{}, fmt.Errorf("auth_type %q must be none, bearer, header, or basic", authType)
	}

	authToken := req.AuthToken
	if existing != nil {
		if req.ClearAuthToken {
			authToken = ""
		} else if authToken == "" {
			authToken = existing.AuthToken
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}

	return store.MCPServer{
		Name:       name,
		URL:        rawURL,
		Transport:  transport,
		AuthType:   authType,
		AuthHeader: authHeader,
		AuthToken:  authToken,
		Enabled:    enabled,
		Source:     store.SourceLocal,
	}, nil
}

func cleanStringList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
