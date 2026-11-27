package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zacharykka/headlamp/internal/api"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/chat"
	"github.com/zacharykka/headlamp/internal/guardrail"
	"github.com/zacharykka/headlamp/internal/mcp"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/proxy"
	"github.com/zacharykka/headlamp/internal/quota"
	"github.com/zacharykka/headlamp/internal/store"
)

var (
	_ proxy.TelemetryFactory   = (*telemetryAdapter)(nil)
	_ proxy.StreamObserver     = (*observerAdapter)(nil)
	_ proxy.TokenReporter      = (*observerAdapter)(nil)
	_ proxy.QuotaLimiter       = (*quotaLimiterAdapter)(nil)
	_ proxy.GuardrailInspector = (*guardrailInspectorAdapter)(nil)
	_ proxy.EventDispatcher    = (*guardrail.Engine)(nil)
	_ mcp.GuardrailInspector   = (*mcpGuardrailAdapter)(nil)
	_ chat.MCPBridge           = (*chatMCPAdapter)(nil)
	_ api.AuditController      = (*metering.Recorder)(nil)
	_ api.BudgetReporter       = (*budgetReporterAdapter)(nil)
	_ api.GuardrailTester      = (*guardrailTesterAdapter)(nil)
	_ api.WebhookTester        = (*webhookTesterAdapter)(nil)
	_ api.MCPTester            = (*mcpTesterAdapter)(nil)
	_ api.ChatHandler          = (*chatHandlerAdapter)(nil)
)

// telemetryAdapter bridges *metering.Recorder to proxy.TelemetryFactory.
type telemetryAdapter struct {
	recorder *metering.Recorder
}

func (a *telemetryAdapter) Start(ctx context.Context, info proxy.TelemetryStart) proxy.StreamObserver {
	if a == nil || a.recorder == nil {
		return nil
	}
	var override *metering.PriceOverride
	if info.CostOverride != nil {
		override = &metering.PriceOverride{
			Input:      info.CostOverride.Input,
			Output:     info.CostOverride.Output,
			CacheRead:  info.CostOverride.CacheRead,
			CacheWrite: info.CostOverride.CacheWrite,
		}
	}
	obs := a.recorder.Start(ctx, metering.RequestInfo{
		RequestID:       info.RequestID,
		Timestamp:       info.Timestamp,
		Principal:       info.Principal,
		Protocol:        info.Protocol,
		Endpoint:        info.Endpoint,
		Provider:        info.Provider,
		ProviderType:    info.ProviderType,
		RequestedModel:  info.RequestedModel,
		UpstreamModel:   info.UpstreamModel,
		Stream:          info.Stream,
		Translated:      info.Translated,
		RequestHeaders:  flattenHeaders(info.RequestHeaders),
		RequestBody:     info.RequestBody,
		PriceOverride:   override,
		GuardrailAction: info.GuardrailAction,
		GuardrailHits:   info.GuardrailHits,
	})
	return &observerAdapter{obs: obs, protocol: info.Protocol}
}

type observerAdapter struct {
	obs      *metering.RequestObserver
	protocol string
}

func (o *observerAdapter) OnSSEEvent(eventName string, data []byte) {
	o.obs.OnSSEEvent(eventName, data)
}

func (o *observerAdapter) OnJSONResponse(body []byte) {
	o.obs.OnJSONResponse(body)
}

func (o *observerAdapter) SetResponseHeaders(headers map[string]string) {
	o.obs.SetResponseHeaders(headers)
}

func (o *observerAdapter) TotalTokens() int64 {
	return o.obs.Usage().NormalizedTotal(o.protocol)
}

func (o *observerAdapter) Finish(fin proxy.TelemetryFinish) {
	o.obs.Finish(fin.StatusCode, fin.LatencyMS, fin.TTFTMS, fin.ErrorMessage)
}

// quotaLimiterAdapter bridges *quota.Manager to proxy.QuotaLimiter.
type quotaLimiterAdapter struct {
	mgr *quota.Manager
}

func (a *quotaLimiterAdapter) Acquire(ctx context.Context, p *auth.Principal) (proxy.QuotaTicket, *proxy.QuotaRejection, error) {
	ticket, rej, err := a.mgr.Acquire(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	if rej != nil {
		return nil, &proxy.QuotaRejection{
			Scope:         rej.Scope,
			Metric:        rej.Metric,
			Reason:        rej.Reason,
			RetryAfterSec: rej.RetryAfterSec,
		}, nil
	}
	if ticket == nil {
		return nil, nil, nil
	}
	return ticket, nil, nil
}

// guardrailInspectorAdapter bridges *guardrail.Engine to proxy.GuardrailInspector.
type guardrailInspectorAdapter struct {
	engine *guardrail.Engine
}

func (a *guardrailInspectorAdapter) Inspect(ctx context.Context, req proxy.GuardrailRequest) (*proxy.GuardrailDecision, error) {
	in := guardrail.InspectInput{
		RequestID: req.RequestID,
		Protocol:  req.Protocol,
		Model:     req.Model,
		Body:      req.Body,
	}
	if req.Principal != nil {
		in.Subject = req.Principal.Subject
		in.NodeName = req.Principal.NodeName
	}
	dec, err := a.engine.InspectRequest(ctx, in)
	if err != nil || dec == nil {
		return nil, err
	}
	return &proxy.GuardrailDecision{
		Action:       dec.Action,
		ModifiedBody: dec.ModifiedBody,
		Hits:         dec.Hits,
		Reason:       dec.Reason,
		StatusCode:   dec.StatusCode,
	}, nil
}

// budgetReporterAdapter bridges *quota.Manager to api.BudgetReporter.
type budgetReporterAdapter struct {
	mgr *quota.Manager
}

func (a *budgetReporterAdapter) StatusForPrincipal(ctx context.Context, p *auth.Principal) ([]api.BudgetStatusItem, error) {
	statuses, err := a.mgr.StatusForPrincipal(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]api.BudgetStatusItem, len(statuses))
	for i, s := range statuses {
		out[i] = api.BudgetStatusItem{
			Scope:           s.Scope,
			DailyUSD:        s.DailyUSD,
			DailySpentUSD:   s.DailySpentUSD,
			MonthlyUSD:      s.MonthlyUSD,
			MonthlySpentUSD: s.MonthlySpentUSD,
			RPM:             s.RPM,
			TPM:             s.TPM,
			MaxConcurrent:   s.MaxConcurrent,
			SoftAlertPct:    s.SoftAlertPct,
		}
	}
	return out, nil
}

func (a *budgetReporterAdapter) ListAllStatuses(ctx context.Context) ([]api.BudgetAdminItem, error) {
	statuses, err := a.mgr.ListAllStatuses(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]api.BudgetAdminItem, len(statuses))
	for i, s := range statuses {
		out[i] = api.BudgetAdminItem{
			Scope:           s.Scope,
			RPM:             s.RPM,
			TPM:             s.TPM,
			MaxConcurrent:   s.MaxConcurrent,
			DailyUSD:        s.DailyUSD,
			MonthlyUSD:      s.MonthlyUSD,
			DailySpentUSD:   s.DailySpentUSD,
			MonthlySpentUSD: s.MonthlySpentUSD,
			SoftAlertPct:    s.SoftAlertPct,
			Enabled:         s.Enabled,
			Source:          s.Source,
			UpdatedAt:       s.UpdatedAt,
		}
	}
	return out, nil
}

// guardrailTesterAdapter bridges *guardrail.Engine to api.GuardrailTester.
type guardrailTesterAdapter struct {
	engine *guardrail.Engine
}

func (a *guardrailTesterAdapter) TestText(ctx context.Context, text string) (*api.GuardrailTestResult, error) {
	res, err := a.engine.TestText(ctx, text)
	if err != nil || res == nil {
		return nil, err
	}
	matches := make([]api.GuardrailMatch, len(res.Matches))
	for i, m := range res.Matches {
		matches[i] = api.GuardrailMatch{
			RuleID:   m.RuleID,
			RuleName: m.RuleName,
			Category: m.Category,
			Action:   m.Action,
		}
	}
	return &api.GuardrailTestResult{
		Action:       res.Action,
		RedactedText: res.RedactedText,
		Matches:      matches,
	}, nil
}

// webhookTesterAdapter bridges *guardrail.Engine to api.WebhookTester.
type webhookTesterAdapter struct {
	engine *guardrail.Engine
}

func (a *webhookTesterAdapter) PingWebhook(ctx context.Context, wh store.Webhook) (*api.WebhookTestResult, error) {
	res, err := a.engine.PingWebhook(ctx, wh)
	if err != nil || res == nil {
		return nil, err
	}
	return &api.WebhookTestResult{
		OK:         res.OK,
		StatusCode: res.StatusCode,
		LatencyMS:  res.LatencyMS,
		Message:    res.Message,
	}, nil
}

// mcpGuardrailAdapter bridges *guardrail.Engine to mcp.GuardrailInspector.
type mcpGuardrailAdapter struct {
	engine *guardrail.Engine
}

func (a *mcpGuardrailAdapter) Inspect(ctx context.Context, req mcp.GuardrailRequest) (*mcp.GuardrailDecision, error) {
	in := guardrail.InspectInput{
		RequestID: req.RequestID,
		Protocol:  req.Protocol,
		Model:     req.Model,
		Body:      req.Body,
	}
	if req.Principal != nil {
		in.Subject = req.Principal.Subject
		in.NodeName = req.Principal.NodeName
	}
	dec, err := a.engine.InspectRequest(ctx, in)
	if err != nil || dec == nil {
		return nil, err
	}
	return &mcp.GuardrailDecision{
		Action:       dec.Action,
		ModifiedBody: dec.ModifiedBody,
		Hits:         dec.Hits,
		Reason:       dec.Reason,
		StatusCode:   dec.StatusCode,
	}, nil
}

// chatGuardrailAdapter bridges *guardrail.Engine to chat.GuardrailInspector.
type chatGuardrailAdapter struct {
	engine *guardrail.Engine
}

func (a *chatGuardrailAdapter) InspectText(ctx context.Context, text string) (action, redacted, reason string, err error) {
	res, err := a.engine.TestText(ctx, text)
	if err != nil || res == nil {
		return "", text, "", err
	}
	if res.Action == guardrail.ActionBlock {
		var blocked []string
		for _, m := range res.Matches {
			if m.Action != guardrail.ActionBlock {
				continue
			}
			label := strings.TrimSpace(m.RuleName)
			if label == "" {
				label = strings.TrimSpace(m.RuleID)
			}
			if label != "" {
				blocked = append(blocked, label)
			}
		}
		if len(blocked) > 0 {
			reason = "blocked by guardrail rule: " + strings.Join(blocked, ", ")
		} else {
			reason = "blocked by guardrail policy"
		}
	}
	return res.Action, res.RedactedText, reason, nil
}

// chatMCPAdapter bridges *mcp.Gateway to chat.MCPBridge.
type chatMCPAdapter struct {
	gw *mcp.Gateway
}

func (a *chatMCPAdapter) ListAuthorizedTools(ctx context.Context, p *auth.Principal, serverNames []string) ([]chat.ServerTools, error) {
	servers, err := a.gw.ListAuthorizedToolsForPrincipal(ctx, p, serverNames)
	if err != nil {
		return nil, err
	}
	out := make([]chat.ServerTools, len(servers))
	for i, srv := range servers {
		tools := make([]chat.ToolSpec, len(srv.Tools))
		for j, tool := range srv.Tools {
			tools[j] = chat.ToolSpec{
				Server:      srv.Name,
				Name:        tool.Name,
				Description: tool.Description,
				InputSchema: tool.InputSchema,
			}
		}
		out[i] = chat.ServerTools{
			Name:      srv.Name,
			Transport: srv.Transport,
			Enabled:   srv.Enabled,
			Tools:     tools,
			Error:     srv.Error,
		}
	}
	return out, nil
}

func (a *chatMCPAdapter) CallTool(ctx context.Context, p *auth.Principal, serverName, toolName string, args json.RawMessage) (*chat.ToolResult, error) {
	res, err := a.gw.CallAuthorizedTool(ctx, p, serverName, toolName, args)
	if err != nil || res == nil {
		return nil, err
	}
	return &chat.ToolResult{
		Result:     res.Result,
		IsError:    res.IsError,
		DurationMS: res.DurationMS,
	}, nil
}

// mcpTesterAdapter bridges *mcp.Gateway to api.MCPTester.
type mcpTesterAdapter struct {
	gw *mcp.Gateway
}

func (a *mcpTesterAdapter) DiscoverTools(ctx context.Context, srv store.MCPServer) ([]api.MCPToolInfo, int64, error) {
	tools, latencyMS, err := a.gw.DiscoverTools(ctx, srv)
	if err != nil {
		return nil, latencyMS, err
	}
	out := make([]api.MCPToolInfo, len(tools))
	for i, t := range tools {
		out[i] = api.MCPToolInfo{
			Name:        t.Name,
			Description: t.Description,
		}
	}
	return out, latencyMS, nil
}

// chatHandlerAdapter bridges *chat.Service to api.ChatHandler.
type chatHandlerAdapter struct {
	svc *chat.Service
}

func (a *chatHandlerAdapter) ListModels(ctx context.Context, p *auth.Principal) ([]api.ChatModelItem, error) {
	models, err := a.svc.ListModels(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]api.ChatModelItem, len(models))
	for i, m := range models {
		out[i] = api.ChatModelItem{
			ID:           m.ID,
			Provider:     m.Provider,
			ProviderType: m.ProviderType,
			IsAlias:      m.IsAlias,
		}
	}
	return out, nil
}

func (a *chatHandlerAdapter) ListMCPServers(ctx context.Context, p *auth.Principal) ([]api.ChatMCPServerItem, error) {
	servers, err := a.svc.ListMCPServers(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]api.ChatMCPServerItem, len(servers))
	for i, srv := range servers {
		tools := make([]api.MCPToolInfo, len(srv.Tools))
		for j, t := range srv.Tools {
			tools[j] = api.MCPToolInfo{
				Name:        t.Name,
				Description: t.Description,
			}
		}
		out[i] = api.ChatMCPServerItem{
			Name:      srv.Name,
			Transport: srv.Transport,
			Enabled:   srv.Enabled,
			Tools:     tools,
			Error:     srv.Error,
		}
	}
	return out, nil
}

func (a *chatHandlerAdapter) StreamMessage(ctx context.Context, w http.ResponseWriter, p *auth.Principal, sessionID string, req api.ChatSendMessageRequest) error {
	return a.svc.StreamMessage(ctx, w, p, sessionID, chat.SendMessageRequest{
		Content:    req.Content,
		Model:      req.Model,
		MCPServers: req.MCPServers,
	})
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
