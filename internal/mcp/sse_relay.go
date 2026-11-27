package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

func (g *Gateway) relayStreamableHTTPSSE(
	w http.ResponseWriter,
	ctx context.Context,
	resp *http.Response,
	p *auth.Principal,
	srv store.MCPServer,
	incomingClientSID string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string][]*trackedToolCall,
	unkeyedCalls []*trackedToolCall,
	localErrors []json.RawMessage,
) {
	flusher, _ := w.(http.Flusher)
	copyResponseHeaders(w.Header(), resp.Header)
	if upRespSID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); upRespSID != "" {
		clientSID := g.sessions.bindUpstreamID(incomingClientSID, p.Subject, srv.Name, upRespSID)
		w.Header().Set("Mcp-Session-Id", clientSID)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	if flusher != nil {
		flusher.Flush()
	}

	for _, localErr := range localErrors {
		_ = writeSSEFrame(w, sseFrame{Event: "message", Data: localErr})
		if flusher != nil {
			flusher.Flush()
		}
	}

	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	var streamErr error
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				streamErr = err
			}
			break
		}
		if len(bytes.TrimSpace(frame.Data)) > 0 {
			filtered, fErr := g.processJSONRPCResponseBytes(ctx, frame.Data, p, srv.Name, toolsListIDs, trackedCalls, nil, false)
			if fErr != nil {
				streamErr = fErr
				break
			}
			frame.Data = filtered
		}
		if writeErr := writeSSEFrame(w, frame); writeErr != nil {
			streamErr = writeErr
			break
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	if streamErr != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, streamErr.Error())
	} else {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusOK, "")
	}
}

func (g *Gateway) handleSSEGet(w http.ResponseWriter, r *http.Request, p *auth.Principal, srv store.MCPServer, subpath string) {
	// P1-1: GET never accepts arbitrary subpaths (neither streamable_http nor sse).
	if subpath != "" {
		writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "subpaths are not allowed on MCP GET endpoints")
		return
	}

	var (
		incomingClientSID string
		upstreamSID       string
		allowLastEventID  bool
	)
	if clientSID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); clientSID != "" {
		sess, err := g.sessions.lookup(clientSID, p.Subject, srv.Name)
		if err != nil {
			if errors.Is(err, errSessionForbidden) {
				writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, "MCP session does not belong to caller")
				return
			}
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "unknown or expired MCP session")
			return
		}
		incomingClientSID = clientSID
		upstreamSID = sess.upstreamID
		allowLastEventID = true
	}

	targetURL, err := buildUpstreamBaseURL(srv, r.URL.RawQuery)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, err.Error())
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to construct upstream SSE request")
		return
	}
	copyMCPRequestHeaders(upReq.Header, r.Header)
	if upReq.Header.Get("Accept") == "" {
		upReq.Header.Set("Accept", "text/event-stream")
	}
	if upstreamSID != "" {
		upReq.Header.Set("Mcp-Session-Id", upstreamSID)
	}
	if allowLastEventID {
		if lastEv := strings.TrimSpace(r.Header.Get("Last-Event-ID")); lastEv != "" {
			upReq.Header.Set("Last-Event-ID", lastEv)
		}
	}
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.logf("headlamp mcp: upstream SSE %s failed: %s", srv.Name, safeErr)
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, g.clientUpstreamErrorMessage(r.Context(), p, "upstream MCP SSE failed", safeErr))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	flusher, _ := w.(http.Flusher)
	copyResponseHeaders(w.Header(), resp.Header)
	if upRespSID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); upRespSID != "" {
		clientSID := g.sessions.bindUpstreamID(incomingClientSID, p.Subject, srv.Name, upRespSID)
		w.Header().Set("Mcp-Session-Id", clientSID)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	if flusher != nil {
		flusher.Flush()
	}

	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			return
		}
		if frame.Event == "endpoint" {
			resolved, resErr := resolveSameOriginEndpoint(srv, string(frame.Data))
			if resErr != nil {
				g.logf("headlamp mcp: rejected unsafe SSE endpoint from %q: %v", srv.Name, resErr)
				return
			}
			cbPath := formatRecordedCallbackPath(resolved)
			clientID := g.sessions.createSSECallback(p.Subject, srv.Name, cbPath)
			rewritten := "/mcp/" + url.PathEscape(srv.Name) + sseCallbackPathPrefix + clientID
			frame.Data = []byte(rewritten)
		} else if len(bytes.TrimSpace(frame.Data)) > 0 {
			// Also filter tools/list responses delivered asynchronously over legacy SSE streams.
			filtered, fErr := g.processJSONRPCResponseBytes(r.Context(), frame.Data, p, srv.Name, nil, nil, nil, false)
			if fErr != nil {
				g.logf("headlamp mcp: aborting SSE stream on filter error for %q: %v", srv.Name, fErr)
				return
			}
			frame.Data = filtered
		}
		if err := writeSSEFrame(w, frame); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (g *Gateway) handleSessionDelete(w http.ResponseWriter, r *http.Request, p *auth.Principal, srv store.MCPServer, subpath string) {
	isSSE := strings.EqualFold(strings.TrimSpace(srv.Transport), config.MCPTransportSSE)

	if subpath != "" {
		if !isSSE {
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "subpaths are not allowed on streamable_http MCP servers")
			return
		}
		cbClientID, ok := parseSSECallbackClientID(subpath)
		if !ok {
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "invalid MCP SSE session path")
			return
		}
		if _, err := g.sessions.delete(cbClientID, p.Subject, srv.Name); err != nil {
			if errors.Is(err, errSessionForbidden) {
				writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, "MCP SSE session does not belong to caller")
				return
			}
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "unknown or expired MCP SSE session")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	clientSID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if clientSID == "" {
		writeJSONRPCStatus(w, http.StatusBadRequest, nil, CodeInvalidRequest, "Mcp-Session-Id header is required")
		return
	}
	sess, err := g.sessions.delete(clientSID, p.Subject, srv.Name)
	if err != nil {
		if errors.Is(err, errSessionForbidden) {
			writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, "MCP session does not belong to caller")
			return
		}
		writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "unknown or expired MCP session")
		return
	}

	targetURL, err := buildUpstreamBaseURL(srv, r.URL.RawQuery)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, err.Error())
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, targetURL, nil)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to construct upstream DELETE request")
		return
	}
	copyMCPRequestHeaders(upReq.Header, r.Header)
	if sess.upstreamID != "" {
		upReq.Header.Set("Mcp-Session-Id", sess.upstreamID)
	}
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.logf("headlamp mcp: upstream DELETE %s failed: %s", srv.Name, safeErr)
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, g.clientUpstreamErrorMessage(r.Context(), p, "upstream MCP DELETE failed", safeErr))
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if len(respBody) > 0 {
		_, _ = w.Write(respBody)
	}
}

// sseFrame preserves SSE event metadata (id, event, retry, data) using a
// 16 MiB-capable bufio.Reader (never 64 KiB bufio.Scanner).
type sseFrame struct {
	ID    string
	Event string
	Retry string
	Data  []byte
}

func readSSEFrame(r *bufio.Reader) (sseFrame, error) {
	var (
		frame   sseFrame
		dataBuf bytes.Buffer
		hasAny  bool
		hasData bool
	)

	for {
		line, err := translate.ReadLineLimited(r, translate.MaxSSELineBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			return sseFrame{}, err
		}

		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			if hasAny {
				if hasData {
					frame.Data = bytes.Clone(dataBuf.Bytes())
				}
				return frame, nil
			}
			if errors.Is(err, io.EOF) {
				return sseFrame{}, io.EOF
			}
			continue
		}

		if trimmed[0] != ':' {
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
				frame.Event = value
				hasAny = true
			case "id":
				frame.ID = value
				hasAny = true
			case "retry":
				frame.Retry = value
				hasAny = true
			case "data":
				// P1-2: Bound total multi-line data accumulation to MaxSSELineBytes to prevent OOM.
				extra := len(value)
				if hasData {
					extra++
				}
				if dataBuf.Len()+extra > translate.MaxSSELineBytes {
					return sseFrame{}, fmt.Errorf("%w (%d bytes)", translate.ErrSSELineTooLong, translate.MaxSSELineBytes)
				}
				if hasData {
					dataBuf.WriteByte('\n')
				}
				dataBuf.WriteString(value)
				hasData = true
				hasAny = true
			}
		}

		if errors.Is(err, io.EOF) {
			if hasAny {
				if hasData {
					frame.Data = bytes.Clone(dataBuf.Bytes())
				}
				return frame, nil
			}
			return sseFrame{}, io.EOF
		}
	}
}

func writeSSEFrame(w io.Writer, frame sseFrame) error {
	var buf bytes.Buffer
	if frame.ID != "" {
		buf.WriteString("id: ")
		buf.WriteString(frame.ID)
		buf.WriteByte('\n')
	}
	if frame.Event != "" {
		buf.WriteString("event: ")
		buf.WriteString(frame.Event)
		buf.WriteByte('\n')
	}
	if frame.Retry != "" {
		buf.WriteString("retry: ")
		buf.WriteString(frame.Retry)
		buf.WriteByte('\n')
	}
	if len(frame.Data) > 0 {
		lines := bytes.Split(frame.Data, []byte("\n"))
		for _, line := range lines {
			buf.WriteString("data: ")
			buf.Write(line)
			buf.WriteByte('\n')
		}
	} else {
		buf.WriteString("data: \n")
	}
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}
