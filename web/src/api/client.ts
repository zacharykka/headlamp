import type {
  AdminLogsFilter,
  AdminLogsResponse,
  AdminOverviewResponse,
  AuditPayload,
  AuditSettings,
  BudgetItem,
  BudgetUpsertPayload,
  GrantsGuideResponse,
  GuardrailRule,
  GuardrailTestResponse,
  GuardrailUpsertPayload,
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

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
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
  getMe(): Promise<MeResponse> {
    return requestJson<MeResponse>('/api/v1/me');
  },

  getMeUsage(window: TimeWindow, limit = 50, offset = 0): Promise<MeUsageResponse> {
    const params = new URLSearchParams({
      window,
      limit: String(limit),
      offset: String(offset),
    });
    return requestJson<MeUsageResponse>(`/api/v1/me/usage?${params.toString()}`);
  },

  getAdminOverview(window: TimeWindow): Promise<AdminOverviewResponse> {
    const params = new URLSearchParams({ window });
    return requestJson<AdminOverviewResponse>(`/api/v1/admin/overview?${params.toString()}`);
  },

  async listProviders(): Promise<ProviderItem[]> {
    const res = await requestJson<{ providers?: ProviderItem[] | null }>('/api/v1/admin/providers');
    return res.providers ?? [];
  },

  createProvider(payload: ProviderUpsertPayload): Promise<ProviderItem> {
    return requestJson<ProviderItem>('/api/v1/admin/providers', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateProvider(name: string, payload: ProviderUpsertPayload): Promise<ProviderItem> {
    return requestJson<ProviderItem>(`/api/v1/admin/providers/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
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

  async listRoutes(): Promise<ModelRouteItem[]> {
    const res = await requestJson<{ routes?: ModelRouteItem[] | null }>('/api/v1/admin/routes');
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

  getPricing(): Promise<PricingResponse> {
    return requestJson<PricingResponse>('/api/v1/admin/pricing');
  },

  async listBudgets(): Promise<BudgetItem[]> {
    const res = await requestJson<{ budgets?: BudgetItem[] | null }>('/api/v1/admin/budgets');
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

  getGrantsGuide(): Promise<GrantsGuideResponse> {
    return requestJson<GrantsGuideResponse>('/api/v1/admin/grants-guide');
  },

  listAdminLogs(filter: AdminLogsFilter): Promise<AdminLogsResponse> {
    const params = new URLSearchParams();
    if (filter.subject) params.set('subject', filter.subject);
    if (filter.provider) params.set('provider', filter.provider);
    if (filter.model) params.set('model', filter.model);
    if (filter.status) params.set('status', filter.status);
    if (filter.guardrail_only) params.set('guardrail_only', 'true');
    if (filter.since) params.set('since', filter.since);
    if (filter.until) params.set('until', filter.until);
    params.set('limit', String(filter.limit ?? 50));
    params.set('offset', String(filter.offset ?? 0));
    return requestJson<AdminLogsResponse>(`/api/v1/admin/logs?${params.toString()}`);
  },

  getLogPayload(id: string): Promise<AuditPayload> {
    return requestJson<AuditPayload>(`/api/v1/admin/logs/${encodeURIComponent(id)}/payload`);
  },

  getAuditSettings(): Promise<AuditSettings> {
    return requestJson<AuditSettings>('/api/v1/admin/settings/audit');
  },

  updateAuditSettings(settings: AuditSettings): Promise<AuditSettings> {
    return requestJson<AuditSettings>('/api/v1/admin/settings/audit', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  },

  purgeAuditPayloads(): Promise<{ purged: number }> {
    return requestJson<{ purged: number }>('/api/v1/admin/settings/audit/purge', {
      method: 'POST',
    });
  },

  async listGuardrails(): Promise<GuardrailRule[]> {
    const res = await requestJson<{ rules?: GuardrailRule[] | null }>('/api/v1/admin/guardrails');
    return res.rules ?? [];
  },

  createGuardrail(payload: GuardrailUpsertPayload): Promise<GuardrailRule> {
    return requestJson<GuardrailRule>('/api/v1/admin/guardrails', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateGuardrail(id: string, payload: GuardrailUpsertPayload): Promise<GuardrailRule> {
    return requestJson<GuardrailRule>(`/api/v1/admin/guardrails/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
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

  async listWebhooks(): Promise<WebhookItem[]> {
    const res = await requestJson<{ webhooks?: WebhookItem[] | null }>('/api/v1/admin/webhooks');
    return res.webhooks ?? [];
  },

  createWebhook(payload: WebhookUpsertPayload): Promise<WebhookItem> {
    return requestJson<WebhookItem>('/api/v1/admin/webhooks', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateWebhook(id: string, payload: WebhookUpsertPayload): Promise<WebhookItem> {
    return requestJson<WebhookItem>(`/api/v1/admin/webhooks/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
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
};
