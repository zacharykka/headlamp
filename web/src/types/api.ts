export type TimeWindow = '24h' | '7d' | '30d';

export interface Principal {
  subject: string;
  display_name: string;
  node_name: string;
  node_ip: string;
  tags?: string[] | null;
  roles?: string[] | null;
  auth_source: string;
}

export interface EffectivePolicy {
  subject: string;
  roles?: string[] | null;
  allow_models?: string[] | null;
  deny_models?: string[] | null;
  allow_mcp_tools?: string[] | null;
  deny_mcp_tools?: string[] | null;
  grants_applied: boolean;
}

export interface BudgetStatus {
  scope: string;
  daily_usd?: number | null;
  daily_spent_usd: number;
  monthly_usd?: number | null;
  monthly_spent_usd: number;
  rpm: number;
  tpm: number;
  max_concurrent: number;
  soft_alert_pct: number;
}

export interface MeResponse {
  principal: Principal;
  is_admin: boolean;
  policy: EffectivePolicy;
  budget_status?: BudgetStatus[] | null;
}

export interface UsageSummary {
  request_count: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
  total_tokens: number;
  cost_usd: number;
  error_count?: number;
  p95_latency_ms?: number;
}

export interface UsageSeriesPoint {
  bucket: string;
  requests: number;
  tokens: number;
  cost_usd: number;
  errors: number;
}

export interface UsageLog {
  id: string;
  created_at: string;
  request_id: string;
  subject: string;
  display_name: string;
  node_name: string;
  node_ip: string;
  tags?: string[] | null;
  auth_source: string;
  provider_name: string;
  provider_type: string;
  requested_model: string;
  upstream_model: string;
  protocol: string;
  endpoint: string;
  stream: boolean;
  translated: boolean;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
  total_tokens: number;
  cost_usd: number;
  latency_ms: number;
  ttft_ms: number;
  status_code: number;
  error_message: string;
  guardrail_action?: string;
  guardrail_hits?: string[] | null;
}

export interface MeUsageResponse {
  summary: UsageSummary;
  series?: UsageSeriesPoint[] | null;
  logs?: UsageLog[] | null;
}

export interface SubjectUsageStat {
  subject: string;
  requests: number;
  tokens: number;
  cost_usd: number;
}

export interface ModelUsageStat {
  model: string;
  provider: string;
  requests: number;
  tokens: number;
  cost_usd: number;
}

export interface AdminOverviewResponse {
  window: TimeWindow;
  today_cost_usd: number;
  month_cost_usd: number;
  summary: UsageSummary;
  series?: UsageSeriesPoint[] | null;
  top_subjects?: SubjectUsageStat[] | null;
  top_models?: ModelUsageStat[] | null;
}

export type ProviderType = 'openai' | 'anthropic' | 'gemini' | 'ollama';

export interface ProviderItem {
  name: string;
  type: ProviderType | string;
  base_url: string;
  has_api_key: boolean;
  api_key_preview?: string;
  passthrough: boolean;
  models?: string[] | null;
  enabled: boolean;
  source: string;
  updated_at: string;
}

export interface ProviderUpsertPayload {
  name: string;
  type: ProviderType | string;
  base_url: string;
  api_key?: string;
  clear_api_key?: boolean;
  passthrough: boolean;
  models: string[];
  enabled: boolean;
}

export interface ProviderTestResult {
  ok: boolean;
  latency_ms: number;
  message: string;
}

export interface RouteFallback {
  provider: string;
  model: string;
}

export interface ModelRouteItem {
  alias: string;
  provider_name: string;
  upstream_model: string;
  fallbacks?: RouteFallback[] | null;
  input_cost_per_million?: number | null;
  output_cost_per_million?: number | null;
  cache_read_cost_per_million?: number | null;
  cache_write_cost_per_million?: number | null;
  enabled: boolean;
  source: string;
  updated_at: string;
}

export interface ModelRouteUpsertPayload {
  alias: string;
  provider_name: string;
  upstream_model: string;
  fallbacks: RouteFallback[];
  input_cost_per_million?: number | null;
  output_cost_per_million?: number | null;
  cache_read_cost_per_million?: number | null;
  cache_write_cost_per_million?: number | null;
  enabled: boolean;
}

export interface ModelPrice {
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
  cache_write_1h?: number;
}

export interface PatternPrice extends ModelPrice {
  pattern: string;
}

export interface PricingResponse {
  exact?: Record<string, ModelPrice> | null;
  patterns?: PatternPrice[] | null;
}

export interface BudgetItem {
  scope: string;
  rpm: number;
  tpm: number;
  max_concurrent: number;
  daily_usd?: number | null;
  monthly_usd?: number | null;
  daily_spent_usd: number;
  monthly_spent_usd: number;
  soft_alert_pct: number;
  enabled: boolean;
  source: string;
  updated_at: string;
}

export interface BudgetUpsertPayload {
  scope: string;
  rpm: number;
  tpm: number;
  max_concurrent: number;
  daily_usd?: number | null;
  monthly_usd?: number | null;
  soft_alert_pct: number;
  enabled: boolean;
}

export interface GrantsGuideResponse {
  policy: EffectivePolicy;
  headscale_example: string;
}

export interface AdminLogsFilter {
  subject?: string;
  provider?: string;
  model?: string;
  status?: string;
  errors_only?: boolean;
  guardrail_only?: boolean;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export interface AdminLogsResponse {
  logs?: UsageLog[] | null;
  summary: UsageSummary;
}

export interface AuditPayload {
  id: string;
  usage_log_id: string;
  created_at: string;
  request_headers?: Record<string, string> | null;
  request_body: string;
  response_headers?: Record<string, string> | null;
  response_body: string;
  redacted: boolean;
}

export interface AuditSettings {
  store_payloads: boolean;
  retention_days: number;
}

export type GuardrailCategory = 'secret' | 'pii' | 'custom';
export type GuardrailAction = 'log_only' | 'redact' | 'block';

export interface GuardrailRule {
  id: string;
  name: string;
  category: GuardrailCategory | string;
  pattern: string;
  action: GuardrailAction | string;
  builtin: boolean;
  enabled: boolean;
  source: string;
  updated_at: string;
}

export interface GuardrailUpsertPayload {
  id: string;
  name: string;
  category: GuardrailCategory | string;
  pattern: string;
  action: GuardrailAction | string;
  enabled: boolean;
}

export interface GuardrailMatch {
  rule_id: string;
  rule_name: string;
  category: string;
  action: string;
}

export interface GuardrailTestResponse {
  action: string;
  redacted_text: string;
  matches?: GuardrailMatch[] | null;
}

export type WebhookType = 'sync_review' | 'async_event';

export interface WebhookItem {
  id: string;
  name: string;
  url: string;
  type: WebhookType | string;
  has_secret: boolean;
  events?: string[] | null;
  timeout_ms: number;
  fail_open: boolean;
  enabled: boolean;
  source: string;
  updated_at: string;
}

export interface WebhookUpsertPayload {
  id: string;
  name: string;
  url: string;
  type: WebhookType | string;
  secret?: string;
  clear_secret?: boolean;
  events: string[];
  timeout_ms: number;
  fail_open: boolean;
  enabled: boolean;
}

export interface WebhookTestResult {
  ok: boolean;
  status_code: number;
  latency_ms: number;
  message: string;
}
