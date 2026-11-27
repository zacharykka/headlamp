import type {
  AdminLogsFilter,
  AdminLogsResponse,
  AdminOverviewResponse,
  AuditPayload,
  AuditSettings,
  BudgetItem,
  BudgetUpsertPayload,
  ChatMCPServerOption,
  ChatMessage,
  ChatModelOption,
  ChatSendMessagePayload,
  ChatSession,
  ChatSessionCreatePayload,
  ChatSessionDetailResponse,
  ChatSessionUpdatePayload,
  GrantsGuideResponse,
  GuardrailRule,
  GuardrailTestResponse,
  GuardrailUpsertPayload,
  MCPAuditFilter,
  MCPAuditLog,
  MCPServerItem,
  MCPServerTestResult,
  MCPServerUpsertPayload,
  MeResponse,
  MeUsageResponse,
  ModelRouteItem,
  ModelRouteUpsertPayload,
  PricingResponse,
  ProviderItem,
  ProviderTestResult,
  ProviderUpsertPayload,
  TimeWindow,
  WebhookItem,
  WebhookTestResult,
  WebhookUpsertPayload,
} from '../types/api';
import { consumeSSEStream } from '../lib/sse';

export interface ChatStreamCallbacks {
  onMessageStart?: (data: { user_message: ChatMessage; session: ChatSession }) => void;
  onDelta?: (data: { text: string }) => void;
  onToolStart?: (data: {
    id: string;
    server: string;
    tool: string;
    arguments?: unknown;
  }) => void;
  onToolResult?: (data: {
    id: string;
    server: string;
    tool: string;
    result: string;
    is_error: boolean;
    duration_ms: number;
  }) => void;
  onMessageDone?: (data: { assistant_message: ChatMessage }) => void;
  onError?: (data: { type?: string; message: string }) => void;
}

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export interface RequestOptions {
  signal?: AbortSignal;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  headers.set('Accept', 'application/json');

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: 'same-origin',
  });

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (typeof data?.error === 'string' && data.error) {
        message = data.error;
      } else if (typeof data?.error?.message === 'string' && data.error.message) {
        message = data.error.message;
      } else if (typeof data?.message === 'string' && data.message) {
        message = data.message;
      }
    } catch {
      // Fall back to HTTP status string when error body is not JSON.
    }
    throw new ApiError(response.status, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export const api = {
  getMe(opts?: RequestOptions): Promise<MeResponse> {
    return requestJson<MeResponse>('/api/v1/me', { signal: opts?.signal });
  },

  getMeUsage(
    window: TimeWindow,
    limit = 50,
    offset = 0,
    opts?: RequestOptions,
  ): Promise<MeUsageResponse> {
    const params = new URLSearchParams({
      window,
      limit: String(limit),
      offset: String(offset),
    });
    return requestJson<MeUsageResponse>(`/api/v1/me/usage?${params.toString()}`, {
      signal: opts?.signal,
    });
  },

  getAdminOverview(
    window: TimeWindow,
    opts?: RequestOptions,
  ): Promise<AdminOverviewResponse> {
    const params = new URLSearchParams({ window });
    return requestJson<AdminOverviewResponse>(
      `/api/v1/admin/overview?${params.toString()}`,
      { signal: opts?.signal },
    );
  },

  async listProviders(opts?: RequestOptions): Promise<ProviderItem[]> {
    const res = await requestJson<{ providers?: ProviderItem[] | null }>(
      '/api/v1/admin/providers',
      { signal: opts?.signal },
    );
    return res.providers ?? [];
  },

  createProvider(payload: ProviderUpsertPayload): Promise<ProviderItem> {
    return requestJson<ProviderItem>('/api/v1/admin/providers', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateProvider(name: string, payload: ProviderUpsertPayload): Promise<ProviderItem> {
    return requestJson<ProviderItem>(
      `/api/v1/admin/providers/${encodeURIComponent(name)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
    );
  },

  deleteProvider(name: string): Promise<void> {
    return requestJson<void>(`/api/v1/admin/providers/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
  },

  testProvider(name: string): Promise<ProviderTestResult> {
    return requestJson<ProviderTestResult>(
      `/api/v1/admin/providers/${encodeURIComponent(name)}/test`,
      { method: 'POST' },
    );
  },

  async listRoutes(opts?: RequestOptions): Promise<ModelRouteItem[]> {
    const res = await requestJson<{ routes?: ModelRouteItem[] | null }>(
      '/api/v1/admin/routes',
      { signal: opts?.signal },
    );
    return res.routes ?? [];
  },

  createRoute(payload: ModelRouteUpsertPayload): Promise<ModelRouteItem> {
    return requestJson<ModelRouteItem>('/api/v1/admin/routes', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateRoute(alias: string, payload: ModelRouteUpsertPayload): Promise<ModelRouteItem> {
    const params = new URLSearchParams({ alias });
    return requestJson<ModelRouteItem>(`/api/v1/admin/routes?${params.toString()}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  deleteRoute(alias: string): Promise<void> {
    const params = new URLSearchParams({ alias });
    return requestJson<void>(`/api/v1/admin/routes?${params.toString()}`, {
      method: 'DELETE',
    });
  },

  getPricing(opts?: RequestOptions): Promise<PricingResponse> {
    return requestJson<PricingResponse>('/api/v1/admin/pricing', {
      signal: opts?.signal,
    });
  },

  async listBudgets(opts?: RequestOptions): Promise<BudgetItem[]> {
    const res = await requestJson<{ budgets?: BudgetItem[] | null }>(
      '/api/v1/admin/budgets',
      { signal: opts?.signal },
    );
    return res.budgets ?? [];
  },

  createBudget(payload: BudgetUpsertPayload): Promise<BudgetItem> {
    return requestJson<BudgetItem>('/api/v1/admin/budgets', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateBudget(scope: string, payload: BudgetUpsertPayload): Promise<BudgetItem> {
    const params = new URLSearchParams({ scope });
    return requestJson<BudgetItem>(`/api/v1/admin/budgets?${params.toString()}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  deleteBudget(scope: string): Promise<void> {
    const params = new URLSearchParams({ scope });
    return requestJson<void>(`/api/v1/admin/budgets?${params.toString()}`, {
      method: 'DELETE',
    });
  },

  getGrantsGuide(opts?: RequestOptions): Promise<GrantsGuideResponse> {
    return requestJson<GrantsGuideResponse>('/api/v1/admin/grants-guide', {
      signal: opts?.signal,
    });
  },

  listAdminLogs(
    filter: AdminLogsFilter,
    opts?: RequestOptions,
  ): Promise<AdminLogsResponse> {
    const params = new URLSearchParams();
    if (filter.subject) params.set('subject', filter.subject);
    if (filter.provider) params.set('provider', filter.provider);
    if (filter.model) params.set('model', filter.model);
    if (filter.status) params.set('status', filter.status);
    if (filter.errors_only) params.set('errors_only', 'true');
    if (filter.guardrail_only) params.set('guardrail_only', 'true');
    if (filter.since) params.set('since', filter.since);
    if (filter.until) params.set('until', filter.until);
    params.set('limit', String(filter.limit ?? 50));
    params.set('offset', String(filter.offset ?? 0));
    return requestJson<AdminLogsResponse>(`/api/v1/admin/logs?${params.toString()}`, {
      signal: opts?.signal,
    });
  },

  getLogPayload(id: string, opts?: RequestOptions): Promise<AuditPayload> {
    return requestJson<AuditPayload>(
      `/api/v1/admin/logs/${encodeURIComponent(id)}/payload`,
      { signal: opts?.signal },
    );
  },

  getAuditSettings(opts?: RequestOptions): Promise<AuditSettings> {
    return requestJson<AuditSettings>('/api/v1/admin/settings/audit', {
      signal: opts?.signal,
    });
  },

  updateAuditSettings(settings: AuditSettings): Promise<AuditSettings> {
    return requestJson<AuditSettings>('/api/v1/admin/settings/audit', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  },

  purgeAuditPayloads(retentionDays: number): Promise<{ purged: number }> {
    return requestJson<{ purged: number }>('/api/v1/admin/settings/audit/purge', {
      method: 'POST',
      body: JSON.stringify({ retention_days: retentionDays }),
    });
  },

  async listGuardrails(opts?: RequestOptions): Promise<GuardrailRule[]> {
    const res = await requestJson<{ rules?: GuardrailRule[] | null }>(
      '/api/v1/admin/guardrails',
      { signal: opts?.signal },
    );
    return res.rules ?? [];
  },

  createGuardrail(payload: GuardrailUpsertPayload): Promise<GuardrailRule> {
    return requestJson<GuardrailRule>('/api/v1/admin/guardrails', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateGuardrail(id: string, payload: GuardrailUpsertPayload): Promise<GuardrailRule> {
    return requestJson<GuardrailRule>(
      `/api/v1/admin/guardrails/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
    );
  },

  deleteGuardrail(id: string): Promise<void> {
    return requestJson<void>(`/api/v1/admin/guardrails/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  testGuardrails(text: string): Promise<GuardrailTestResponse> {
    return requestJson<GuardrailTestResponse>('/api/v1/admin/guardrails/test', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
  },

  async listWebhooks(opts?: RequestOptions): Promise<WebhookItem[]> {
    const res = await requestJson<{ webhooks?: WebhookItem[] | null }>(
      '/api/v1/admin/webhooks',
      { signal: opts?.signal },
    );
    return res.webhooks ?? [];
  },

  createWebhook(payload: WebhookUpsertPayload): Promise<WebhookItem> {
    return requestJson<WebhookItem>('/api/v1/admin/webhooks', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateWebhook(id: string, payload: WebhookUpsertPayload): Promise<WebhookItem> {
    return requestJson<WebhookItem>(
      `/api/v1/admin/webhooks/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
    );
  },

  deleteWebhook(id: string): Promise<void> {
    return requestJson<void>(`/api/v1/admin/webhooks/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  testWebhook(id: string): Promise<WebhookTestResult> {
    return requestJson<WebhookTestResult>(
      `/api/v1/admin/webhooks/${encodeURIComponent(id)}/test`,
      { method: 'POST' },
    );
  },

  /* ==================== M3: TEAM CHAT ==================== */

  async listChatModels(opts?: RequestOptions): Promise<ChatModelOption[]> {
    const res = await requestJson<{ models?: ChatModelOption[] | null }>(
      '/api/v1/chat/models',
      { signal: opts?.signal },
    );
    return res.models ?? [];
  },

  async listChatMCPServers(opts?: RequestOptions): Promise<ChatMCPServerOption[]> {
    const res = await requestJson<{ servers?: ChatMCPServerOption[] | null }>(
      '/api/v1/chat/mcp-servers',
      { signal: opts?.signal },
    );
    return res.servers ?? [];
  },

  async listChatSessions(
    limit = 50,
    opts?: RequestOptions,
  ): Promise<ChatSession[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    const res = await requestJson<{ sessions?: ChatSession[] | null }>(
      `/api/v1/chat/sessions?${params.toString()}`,
      { signal: opts?.signal },
    );
    return res.sessions ?? [];
  },

  createChatSession(payload: ChatSessionCreatePayload): Promise<ChatSession> {
    return requestJson<ChatSession>('/api/v1/chat/sessions', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getChatSession(
    id: string,
    opts?: RequestOptions,
  ): Promise<ChatSessionDetailResponse> {
    return requestJson<ChatSessionDetailResponse>(
      `/api/v1/chat/sessions/${encodeURIComponent(id)}`,
      { signal: opts?.signal },
    );
  },

  updateChatSession(
    id: string,
    payload: ChatSessionUpdatePayload,
  ): Promise<ChatSession> {
    return requestJson<ChatSession>(
      `/api/v1/chat/sessions/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(payload),
      },
    );
  },

  deleteChatSession(id: string): Promise<void> {
    return requestJson<void>(`/api/v1/chat/sessions/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  async streamChatMessage(
    sessionId: string,
    payload: ChatSendMessagePayload,
    callbacks: ChatStreamCallbacks,
    opts?: RequestOptions,
  ): Promise<void> {
    const response = await fetch(
      `/api/v1/chat/sessions/${encodeURIComponent(sessionId)}/messages`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream',
        },
        body: JSON.stringify(payload),
        credentials: 'same-origin',
        signal: opts?.signal,
      },
    );

    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const data = await response.json();
        if (typeof data?.error === 'string' && data.error) {
          message = data.error;
        } else if (
          typeof data?.error?.message === 'string' &&
          data.error.message
        ) {
          message = data.error.message;
        } else if (typeof data?.message === 'string' && data.message) {
          message = data.message;
        }
      } catch {
        // Fall back to HTTP status string when error body is not JSON.
      }
      throw new ApiError(response.status, message);
    }

    if (!response.body) {
      throw new Error('Streaming response body unavailable');
    }

    await consumeSSEStream(response.body, (frame) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(frame.data);
      } catch {
        return;
      }

      switch (frame.event) {
        case 'message_start':
          callbacks.onMessageStart?.(
            parsed as { user_message: ChatMessage; session: ChatSession },
          );
          break;
        case 'delta':
          callbacks.onDelta?.(parsed as { text: string });
          break;
        case 'tool_start':
          callbacks.onToolStart?.(
            parsed as {
              id: string;
              server: string;
              tool: string;
              arguments?: unknown;
            },
          );
          break;
        case 'tool_result':
          callbacks.onToolResult?.(
            parsed as {
              id: string;
              server: string;
              tool: string;
              result: string;
              is_error: boolean;
              duration_ms: number;
            },
          );
          break;
        case 'message_done':
          callbacks.onMessageDone?.(
            parsed as { assistant_message: ChatMessage },
          );
          break;
        case 'error':
          callbacks.onError?.(parsed as { type?: string; message: string });
          break;
      }
    });
  },

  /* ==================== M3: ADMIN MCP GATEWAY ==================== */

  async listAdminMCPServers(opts?: RequestOptions): Promise<MCPServerItem[]> {
    const res = await requestJson<{ servers?: MCPServerItem[] | null }>(
      '/api/v1/admin/mcp/servers',
      { signal: opts?.signal },
    );
    return res.servers ?? [];
  },

  createAdminMCPServer(payload: MCPServerUpsertPayload): Promise<MCPServerItem> {
    return requestJson<MCPServerItem>('/api/v1/admin/mcp/servers', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateAdminMCPServer(
    name: string,
    payload: MCPServerUpsertPayload,
  ): Promise<MCPServerItem> {
    return requestJson<MCPServerItem>(
      `/api/v1/admin/mcp/servers/${encodeURIComponent(name)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
    );
  },

  deleteAdminMCPServer(name: string): Promise<void> {
    return requestJson<void>(
      `/api/v1/admin/mcp/servers/${encodeURIComponent(name)}`,
      { method: 'DELETE' },
    );
  },

  testAdminMCPServer(name: string): Promise<MCPServerTestResult> {
    return requestJson<MCPServerTestResult>(
      `/api/v1/admin/mcp/servers/${encodeURIComponent(name)}/test`,
      { method: 'POST' },
    );
  },

  async listAdminMCPLogs(
    filter: MCPAuditFilter,
    opts?: RequestOptions,
  ): Promise<MCPAuditLog[]> {
    const params = new URLSearchParams();
    if (filter.server) params.set('server', filter.server);
    if (filter.subject) params.set('subject', filter.subject);
    if (filter.tool) params.set('tool', filter.tool);
    if (filter.status) params.set('status', filter.status);
    params.set('limit', String(filter.limit ?? 50));
    params.set('offset', String(filter.offset ?? 0));
    const res = await requestJson<{ logs?: MCPAuditLog[] | null }>(
      `/api/v1/admin/mcp/logs?${params.toString()}`,
      { signal: opts?.signal },
    );
    return res.logs ?? [];
  },
};
