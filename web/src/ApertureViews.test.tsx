import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { ApiError, api } from './api/client';
import { ConfirmDeleteButton } from './components/Primitives';
import { AuditLogsView } from './views/AuditLogsView';
import { PersonalView } from './views/PersonalView';
import { RoutingView } from './views/RoutingView';
import { SecurityView } from './views/SecurityView';

describe('Aperture views, collapsed sidebar accordion, confirmations, and API alignment', () => {
  beforeEach(() => {
    window.scrollTo = vi.fn();
  });
  afterEach(() => {
    cleanup();
    document.body.style.overflow = '';
    vi.restoreAllMocks();
  });

  it('serializes errors_only=true in api.listAdminLogs', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          logs: [],
          summary: {
            request_count: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            total_tokens: 0,
            cost_usd: 0,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    await api.listAdminLogs({ errors_only: true, limit: 25, offset: 0 });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const calledUrl = String(fetchSpy.mock.calls[0][0]);
    expect(calledUrl).toContain('errors_only=true');
    expect(calledUrl).toContain('limit=25');
  });

  it('locks YAML-managed providers, locks modal body scroll, and renders inline validation errors', async () => {
    vi.spyOn(api, 'listProviders').mockResolvedValue([
      {
        name: 'anthropic-yaml',
        type: 'anthropic',
        base_url: 'https://api.anthropic.com',
        has_api_key: true,
        api_key_preview: 'sk-ant...****',
        passthrough: false,
        models: ['claude-sonnet-4-20250514'],
        enabled: true,
        source: 'config',
        updated_at: '2026-11-27T00:00:00Z',
      },
      {
        name: 'openai-local',
        type: 'openai',
        base_url: 'https://api.openai.com',
        has_api_key: false,
        passthrough: true,
        models: [],
        enabled: true,
        source: 'local',
        updated_at: '2026-11-27T00:00:00Z',
      },
    ]);

    vi.spyOn(api, 'listRoutes').mockResolvedValue([
      {
        alias: 'team/cache-tuned',
        provider_name: 'anthropic-yaml',
        upstream_model: 'claude-sonnet-4-20250514',
        fallbacks: [],
        input_cost_per_million: 0.45,
        output_cost_per_million: null,
        cache_read_cost_per_million: null,
        cache_write_cost_per_million: null,
        enabled: true,
        source: 'local',
        updated_at: '2026-11-27T00:00:00Z',
      },
    ]);

    render(<RoutingView />);

    await waitFor(() => {
      expect(screen.getByText('anthropic-yaml')).toBeTruthy();
    });

    expect(screen.getByText('Managed by YAML')).toBeTruthy();
    const editYamlBtn = screen.getByRole('button', { name: 'Edit anthropic-yaml' });
    expect((editYamlBtn as HTMLButtonElement).disabled).toBe(true);

    // Partial cost override shows Default across remaining null tiers
    expect(screen.getByText('team/cache-tuned')).toBeTruthy();
    expect(screen.getByText(/\$0\.45/)).toBeTruthy();
    expect(screen.getByText(/Default \/ Default/)).toBeTruthy();

    // Open Add Route modal -> locks body scroll and shows inline error on bad fallback
    fireEvent.click(screen.getByRole('button', { name: /Add Route/i }));
    expect(document.body.style.overflow).toBe('hidden');
    const dialog = screen.getByRole('dialog', { name: /Add Model Route/i });

    fireEvent.change(within(dialog).getByLabelText(/Virtual Alias/i), {
      target: { value: 'team/fast' },
    });
    fireEvent.change(within(dialog).getByLabelText(/Primary Upstream Model ID/i), {
      target: { value: 'gpt-4.1-mini' },
    });
    fireEvent.change(within(dialog).getByLabelText(/Fallback Targets/i), {
      target: { value: 'gpt-4o-without-provider' },
    });

    fireEvent.click(within(dialog).getByRole('button', { name: /Save Route/i }));

    const alert = await within(dialog).findByRole('alert');
    expect(alert.textContent).toContain('must use "provider/model" format');

    fireEvent.click(within(dialog).getByRole('button', { name: /Cancel/i }));
    expect(document.body.style.overflow).toBe('');
  });

  it('requires two-step inline confirmation on ConfirmDeleteButton', async () => {
    const onConfirm = vi.fn();
    render(<ConfirmDeleteButton itemName="openai-local" onConfirm={onConfirm} />);

    const btn = screen.getByRole('button', { name: 'Delete openai-local' });
    fireEvent.click(btn);
    expect(onConfirm).not.toHaveBeenCalled();

    const confirmBtn = screen.getByRole('button', {
      name: 'Confirm delete openai-local',
    });
    expect(confirmBtn.textContent).toContain('Confirm?');
    fireEvent.click(confirmBtn);
    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledTimes(1);
    });
  });

  it('enforces built-in vs YAML guardrail locks and highlights playground redactions', async () => {
    vi.spyOn(api, 'listGuardrails').mockResolvedValue([
      {
        id: 'openai_api_key',
        name: 'OpenAI API Key',
        category: 'secret',
        pattern: 'sk-[A-Za-z0-9]{20,}',
        action: 'redact',
        builtin: true,
        enabled: true,
        source: 'builtin',
        updated_at: '2026-11-27T00:00:00Z',
      },
      {
        id: 'yaml_ssn',
        name: 'YAML Pinned SSN',
        category: 'pii',
        pattern: '\\d{3}-\\d{2}-\\d{4}',
        action: 'block',
        builtin: false,
        enabled: true,
        source: 'config',
        updated_at: '2026-11-27T00:00:00Z',
      },
    ]);
    vi.spyOn(api, 'listWebhooks').mockResolvedValue([]);
    vi.spyOn(api, 'testGuardrails').mockResolvedValue({
      action: 'redact',
      redacted_text: 'Authorization: Bearer [REDACTED:openai_api_key]',
      matches: [
        {
          rule_id: 'openai_api_key',
          rule_name: 'OpenAI API Key',
          category: 'secret',
          action: 'redact',
        },
      ],
    });

    render(<SecurityView />);

    await waitFor(() => {
      expect(screen.getByText('OpenAI API Key')).toBeTruthy();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Edit OpenAI API Key' }));
    const dialog = screen.getByRole('dialog', { name: /Edit Guardrail/i });
    expect(
      (within(dialog).getByLabelText(/Display Name/i) as HTMLInputElement).disabled,
    ).toBe(true);
    expect(
      (within(dialog).getByLabelText(/Go Regular Expression/i) as HTMLInputElement)
        .disabled,
    ).toBe(true);
    expect(
      (within(dialog).getByLabelText(/Action on Match/i) as HTMLSelectElement).disabled,
    ).toBe(false);
    fireEvent.click(within(dialog).getByRole('button', { name: /Cancel/i }));

    fireEvent.click(screen.getByRole('button', { name: /Evaluate Sample/i }));
    await waitFor(() => {
      expect(screen.getByText(/Verdict: REDACT/i)).toBeTruthy();
      expect(screen.getByText('[REDACTED:openai_api_key]')).toBeTruthy();
    });
  });

  it('distinguishes 404 vs 500 payloads, displays accurate SQLite storage copy, and resets timePreset on focus', async () => {
    vi.spyOn(api, 'getAuditSettings').mockResolvedValue({
      store_payloads: false,
      retention_days: 14,
    });
    const purgeSpy = vi
      .spyOn(api, 'purgeAuditPayloads')
      .mockResolvedValue({ purged: 3 });

    const listSpy = vi.spyOn(api, 'listAdminLogs').mockResolvedValue({
      summary: {
        request_count: 2,
        input_tokens: 100,
        output_tokens: 50,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 150,
        cost_usd: 0.002,
        error_count: 1,
        p95_latency_ms: 180,
      },
      logs: [
        {
          id: 'log-404',
          created_at: '2026-11-27T01:00:00Z',
          request_id: 'req-404',
          subject: 'alice@tailnet',
          display_name: 'Alice',
          node_name: 'macbook',
          node_ip: '100.64.0.2',
          auth_source: 'tailnet',
          provider_name: 'anthropic',
          provider_type: 'anthropic',
          requested_model: 'claude-sonnet-4-20250514',
          upstream_model: 'claude-sonnet-4-20250514',
          protocol: 'anthropic_messages',
          endpoint: '/anthropic/v1/messages',
          stream: false,
          translated: false,
          input_tokens: 50,
          output_tokens: 25,
          cache_read_tokens: 0,
          cache_write_tokens: 0,
          reasoning_tokens: 0,
          total_tokens: 75,
          cost_usd: 0.001,
          latency_ms: 150,
          ttft_ms: 90,
          status_code: 200,
          error_message: '',
        },
        {
          id: 'log-500',
          created_at: '2026-11-27T01:01:00Z',
          request_id: 'req-500',
          subject: 'bob@tailnet',
          display_name: 'Bob',
          node_name: 'linux-ws',
          node_ip: '100.64.0.3',
          auth_source: 'tailnet',
          provider_name: 'openai',
          provider_type: 'openai',
          requested_model: 'gpt-4.1',
          upstream_model: 'gpt-4.1',
          protocol: 'openai_chat',
          endpoint: '/v1/chat/completions',
          stream: false,
          translated: false,
          input_tokens: 50,
          output_tokens: 25,
          cache_read_tokens: 0,
          cache_write_tokens: 0,
          reasoning_tokens: 0,
          total_tokens: 75,
          cost_usd: 0.001,
          latency_ms: 210,
          ttft_ms: 110,
          status_code: 502,
          error_message: 'bad gateway',
        },
      ],
    });

    vi.spyOn(api, 'getLogPayload').mockImplementation(async (id: string) => {
      if (id === 'log-404') {
        throw new ApiError(404, 'audit payload not found');
      }
      throw new ApiError(500, 'sqlite disk I/O failure');
    });

    const { rerender } = render(
      <AuditLogsView focus={{ errorsOnly: true, timePreset: '7d', nonce: 1 }} />,
    );

    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(
        expect.objectContaining({ errors_only: true }),
        expect.anything(),
      );
    });

    // External focus without timePreset resets timePreset to 'all' and clears errorsOnly
    rerender(<AuditLogsView focus={{ subject: 'alice@tailnet', nonce: 2 }} />);
    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          subject: 'alice@tailnet',
          errors_only: undefined,
          since: undefined,
        }),
        expect.anything(),
      );
    });

    await waitFor(() => {
      expect(screen.getByText('alice@tailnet')).toBeTruthy();
    });

    fireEvent.click(screen.getByText('alice@tailnet'));
    await waitFor(() => {
      expect(
        screen.getByText(/Payload logging was off for this request/i),
      ).toBeTruthy();
    });

    fireEvent.click(screen.getByText('bob@tailnet'));
    await waitFor(() => {
      expect(screen.getByText(/Failed to fetch audit payload/i)).toBeTruthy();
      expect(screen.getByText(/sqlite disk I\/O failure/i)).toBeTruthy();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    fireEvent.click(screen.getByRole('button', { name: /Audit Storage/i }));
    const settingsDialog = await screen.findByRole('dialog', {
      name: /Audit Storage & Payload Retention/i,
    });
    expect(
      within(settingsDialog).getByText(
        /Stores sanitized headers and guardrail-redacted bodies \(capped at 256 KB\) in local SQLite\./i,
      ),
    ).toBeTruthy();

    fireEvent.change(within(settingsDialog).getByLabelText(/Retention Window/i), {
      target: { value: '7' },
    });
    fireEvent.click(within(settingsDialog).getByRole('button', { name: /Purge Now/i }));

    await waitFor(() => {
      expect(purgeSpy).toHaveBeenCalledWith(7);
      expect(within(settingsDialog).getByText(/Purged 3 payloads older than 7d/i)).toBeTruthy();
    });
  });

  it('prevents in-flight getAuditSettings from overwriting retention_days=0 and requires two-step confirm on 0-day purge', async () => {
    let savedRetention = 14;
    let resolveModalFetch!: (val: {
      store_payloads: boolean;
      retention_days: number;
    }) => void;
    let callCount = 0;

    vi.spyOn(api, 'getAuditSettings').mockImplementation(() => {
      callCount += 1;
      if (callCount === 2) {
        return new Promise((resolve) => {
          resolveModalFetch = resolve;
        });
      }
      return Promise.resolve({ store_payloads: false, retention_days: savedRetention });
    });

    const updateSpy = vi
      .spyOn(api, 'updateAuditSettings')
      .mockImplementation(async (next) => {
        savedRetention = next.retention_days;
        return next;
      });
    const purgeSpy = vi
      .spyOn(api, 'purgeAuditPayloads')
      .mockResolvedValue({ purged: 5 });

    vi.spyOn(api, 'listAdminLogs').mockResolvedValue({
      summary: {
        request_count: 0,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
        cost_usd: 0,
      },
      logs: [],
    });

    render(<AuditLogsView />);

    fireEvent.click(screen.getByRole('button', { name: /Audit Storage/i }));
    const dialog = await screen.findByRole('dialog', {
      name: /Audit Storage & Payload Retention/i,
    });
    const retentionInput = within(dialog).getByLabelText(/Retention Window/i) as HTMLInputElement;
    fireEvent.change(retentionInput, { target: { value: '0' } });

    resolveModalFetch({ store_payloads: false, retention_days: 14 });
    await new Promise((r) => setTimeout(r, 20));
    expect(retentionInput.value).toBe('0');

    fireEvent.click(within(dialog).getByRole('button', { name: /Save Settings/i }));
    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledWith({
        store_payloads: false,
        retention_days: 0,
      });
    });

    fireEvent.click(screen.getByRole('button', { name: /Audit Storage/i }));
    const reopenedDialog = await screen.findByRole('dialog', {
      name: /Audit Storage & Payload Retention/i,
    });

    // First click on 0-day Purge Now arms confirmation without purging
    fireEvent.click(within(reopenedDialog).getByRole('button', { name: /Purge Now/i }));
    expect(purgeSpy).not.toHaveBeenCalled();
    const confirmBtn = within(reopenedDialog).getByRole('button', {
      name: /Confirm Purge All\?/i,
    });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(purgeSpy).toHaveBeenCalledWith(0);
      expect(within(reopenedDialog).getByText(/Purged all 5 stored payloads/i)).toBeTruthy();
    });
  });

  it('starts sidebar groups collapsed, syncs section toggles two-way, opens global Model Pricing, and expands group on Error Rate click', async () => {
    vi.spyOn(api, 'getMe').mockResolvedValue({
      principal: {
        subject: 'shan@tailnet',
        display_name: 'Shan',
        node_name: 'macbook-pro',
        node_ip: '100.64.0.12',
        auth_source: 'tailnet',
      },
      is_admin: true,
      policy: {
        subject: 'shan@tailnet',
        roles: ['admin'],
        allow_models: ['*'],
        grants_applied: true,
      },
    });
    vi.spyOn(api, 'getAdminOverview').mockResolvedValue({
      window: '7d',
      today_cost_usd: 1.2,
      month_cost_usd: 15.4,
      summary: {
        request_count: 10,
        input_tokens: 500,
        output_tokens: 200,
        cache_read_tokens: 100,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 800,
        cost_usd: 1.2,
        error_count: 2,
        p95_latency_ms: 140,
      },
      series: [],
      top_subjects: [],
      top_models: [],
    });
    vi.spyOn(api, 'listProviders').mockResolvedValue([]);
    vi.spyOn(api, 'listRoutes').mockResolvedValue([]);
    vi.spyOn(api, 'listBudgets').mockResolvedValue([]);
    vi.spyOn(api, 'listGuardrails').mockResolvedValue([]);
    vi.spyOn(api, 'listWebhooks').mockResolvedValue([]);
    vi.spyOn(api, 'getPricing').mockResolvedValue({ exact: {}, patterns: [] });
    vi.spyOn(api, 'getAuditSettings').mockResolvedValue({
      store_payloads: false,
      retention_days: 7,
    });
    const logsSpy = vi.spyOn(api, 'listAdminLogs').mockResolvedValue({
      logs: [],
      summary: {
        request_count: 2,
        input_tokens: 100,
        output_tokens: 50,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 150,
        cost_usd: 0.2,
        error_count: 2,
      },
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Usage Overview' })).toBeTruthy();
    });

    // All 4 sidebar groups start collapsed by default; Usage & Adoption shows active parent indicator
    const usageGroupBtn = screen.getByRole('button', { name: /Usage & Adoption/i });
    const securityGroupBtn = screen.getByRole('button', { name: /Security/i });
    const adminGroupBtn = screen.getByRole('button', { name: /Administration/i });
    const refGroupBtn = screen.getByRole('button', { name: /Reference/i });

    expect(usageGroupBtn.getAttribute('aria-expanded')).toBe('false');
    expect(usageGroupBtn.getAttribute('data-has-active')).toBe('true');
    expect(securityGroupBtn.getAttribute('aria-expanded')).toBe('false');
    expect(adminGroupBtn.getAttribute('aria-expanded')).toBe('false');
    expect(refGroupBtn.getAttribute('aria-expanded')).toBe('false');

    // Global Model Pricing drawer opens from Reference without switching activeNav away from Usage Overview
    fireEvent.click(refGroupBtn);
    expect(refGroupBtn.getAttribute('aria-expanded')).toBe('true');
    fireEvent.click(screen.getByRole('button', { name: 'Model Pricing' }));
    expect(
      await screen.findByRole('dialog', { name: /Built-in Model Pricing Reference/i }),
    ).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(screen.getByRole('heading', { name: 'Usage Overview' })).toBeTruthy();

    // Clicking Error Rate KPI card jumps to Activity Logs with errors_only=true and auto-expands Security group
    fireEvent.click(
      screen.getByRole('button', { name: /Inspect error requests in Activity Logs/i }),
    );
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Activity & Audit Logs' })).toBeTruthy();
      expect(securityGroupBtn.getAttribute('aria-expanded')).toBe('true');
      expect(logsSpy).toHaveBeenCalledWith(
        expect.objectContaining({ errors_only: true }),
        expect.anything(),
      );
    });

    // Two-way sync between Administration -> Providers / Model Routing and in-page segmented toggle
    fireEvent.click(adminGroupBtn);
    const providersNavBtn = screen.getByRole('button', { name: /^Providers/i });
    const routesNavBtn = screen.getByRole('button', { name: /^Model Routing/i });
    fireEvent.click(providersNavBtn);
    expect(providersNavBtn.getAttribute('data-active')).toBe('true');

    fireEvent.click(screen.getByRole('tab', { name: /^Routes/i }));
    expect(routesNavBtn.getAttribute('data-active')).toBe('true');
    expect(providersNavBtn.getAttribute('data-active')).toBe('false');

    // Clicking Activity Logs in sidebar resets stale logsFocus (clears errors_only & since)
    logsSpy.mockClear();
    fireEvent.click(screen.getByRole('button', { name: 'Activity Logs' }));
    await waitFor(() => {
      expect(logsSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          errors_only: undefined,
          since: undefined,
        }),
        expect.anything(),
      );
    });
  });

  it('uses <YOUR_HEADLAMP_API_TOKEN> placeholder in Quickstart snippets when auth_source is api_key', () => {
    vi.spyOn(api, 'getMeUsage').mockResolvedValue({
      summary: {
        request_count: 0,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
        cost_usd: 0,
      },
      series: [],
      logs: [],
    });

    render(
      <PersonalView
        me={{
          principal: {
            subject: 'tag:ci-runner',
            display_name: 'CI Runner',
            node_name: '',
            node_ip: '',
            auth_source: 'api_key',
          },
          is_admin: false,
          policy: {
            subject: 'tag:ci-runner',
            roles: ['user'],
            allow_models: ['openai/gpt-4.1'],
            grants_applied: true,
          },
          budget_status: [],
        }}
      />,
    );

    expect(screen.getByText(/<YOUR_HEADLAMP_API_TOKEN>/)).toBeTruthy();
  });
});
