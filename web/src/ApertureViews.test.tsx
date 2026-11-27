import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from './api/client';
import { AuditLogsView } from './views/AuditLogsView';
import { RoutingView } from './views/RoutingView';
import { SecurityView } from './views/SecurityView';

describe('Aperture views: GitOps locks, inline modal errors, and audit inspector', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('locks YAML-managed providers and renders inline validation errors inside Route modal', async () => {
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

    vi.spyOn(api, 'getPricing').mockResolvedValue({ exact: {}, patterns: [] });

    render(<RoutingView />);

    await waitFor(() => {
      expect(screen.getByText('anthropic-yaml')).toBeTruthy();
    });

    // YAML-managed badge is visible and Edit/Delete are disabled on anthropic-yaml row
    expect(screen.getByText('Managed by YAML')).toBeTruthy();
    const editYamlBtn = screen.getByRole('button', { name: 'Edit anthropic-yaml' });
    expect((editYamlBtn as HTMLButtonElement).disabled).toBe(true);

    // Input-only override displays Default across all 3 remaining null tiers (output + both cache tiers)
    expect(screen.getByText('team/cache-tuned')).toBeTruthy();
    expect(screen.getByText(/\$0\.45/)).toBeTruthy();
    expect(screen.getByText(/Default \/ Default/)).toBeTruthy();

    // Open Add Route modal and enter malformed fallback line missing "/"
    fireEvent.click(screen.getByRole('button', { name: /Add Route/i }));
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

    // Built-in rule allows opening Edit modal with Name/Category/Pattern disabled
    const editButtons = screen.getAllByRole('button', { name: /Edit/i });
    fireEvent.click(editButtons[0]);
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

    // Live playground renders verdict and highlighted [REDACTED:...] span
    fireEvent.click(screen.getByRole('button', { name: /Evaluate Sample/i }));
    await waitFor(() => {
      expect(screen.getByText(/Verdict: REDACT/i)).toBeTruthy();
      expect(screen.getByText('[REDACTED:openai_api_key]')).toBeTruthy();
    });
  });

  it('distinguishes 404 unstored payloads from 500 errors and sends retention_days on purge', async () => {
    vi.spyOn(api, 'getAuditSettings').mockResolvedValue({
      store_payloads: false,
      retention_days: 14,
    });
    const purgeSpy = vi
      .spyOn(api, 'purgeAuditPayloads')
      .mockResolvedValue({ purged: 3 });

    vi.spyOn(api, 'listAdminLogs').mockResolvedValue({
      summary: {
        request_count: 2,
        input_tokens: 100,
        output_tokens: 50,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 150,
        cost_usd: 0.002,
        error_count: 0,
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
          status_code: 200,
          error_message: '',
        },
      ],
    });

    vi.spyOn(api, 'getLogPayload').mockImplementation(async (id: string) => {
      if (id === 'log-404') {
        throw new ApiError(404, 'audit payload not found');
      }
      throw new ApiError(500, 'sqlite disk I/O failure');
    });

    render(<AuditLogsView />);

    await waitFor(() => {
      expect(screen.getByText('alice@tailnet')).toBeTruthy();
    });

    // Click log-404 -> calm "Payload logging was off for this request" message
    fireEvent.click(screen.getByText('alice@tailnet'));
    await waitFor(() => {
      expect(
        screen.getByText(/Payload logging was off for this request/i),
      ).toBeTruthy();
    });

    // Click log-500 -> real error banner with actual server error text
    fireEvent.click(screen.getByText('bob@tailnet'));
    await waitFor(() => {
      expect(screen.getByText(/Failed to fetch audit payload/i)).toBeTruthy();
      expect(screen.getByText(/sqlite disk I\/O failure/i)).toBeTruthy();
    });

    // Close drawer and verify Audit Storage Purge sends retention_days
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    fireEvent.click(screen.getByRole('button', { name: /Audit Storage/i }));
    const settingsDialog = await screen.findByRole('dialog', {
      name: /Audit Storage & Payload Retention/i,
    });
    fireEvent.change(within(settingsDialog).getByLabelText(/Retention Window/i), {
      target: { value: '7' },
    });
    fireEvent.click(within(settingsDialog).getByRole('button', { name: /Purge Now/i }));

    await waitFor(() => {
      expect(purgeSpy).toHaveBeenCalledWith(7);
      expect(within(settingsDialog).getByText(/Purged 3 payloads older than 7d/i)).toBeTruthy();
    });
  });

  it('prevents in-flight getAuditSettings from overwriting retention_days=0 edits and purges with 0', async () => {
    let savedRetention = 14;
    let resolveModalFetch!: (val: {
      store_payloads: boolean;
      retention_days: number;
    }) => void;
    let callCount = 0;

    vi.spyOn(api, 'getAuditSettings').mockImplementation(() => {
      callCount += 1;
      // First call on mount resolves immediately; second call when opening modal resolves late
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

    // Open Audit Storage and edit Retention Window to 0 BEFORE getAuditSettings resolves
    fireEvent.click(screen.getByRole('button', { name: /Audit Storage/i }));
    const dialog = await screen.findByRole('dialog', {
      name: /Audit Storage & Payload Retention/i,
    });
    const retentionInput = within(dialog).getByLabelText(/Retention Window/i) as HTMLInputElement;
    fireEvent.change(retentionInput, { target: { value: '0' } });

    // Now resolve the slow in-flight getAuditSettings() with stale 14 — must NOT clobber 0!
    resolveModalFetch({ store_payloads: false, retention_days: 14 });
    await new Promise((r) => setTimeout(r, 20));
    expect(retentionInput.value).toBe('0');

    // Save Settings -> sends retention_days: 0 and closes modal
    fireEvent.click(within(dialog).getByRole('button', { name: /Save Settings/i }));
    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledWith({
        store_payloads: false,
        retention_days: 0,
      });
    });

    // Reopen Audit Storage -> retention is 0 -> Purge Now sends {"retention_days": 0}
    fireEvent.click(screen.getByRole('button', { name: /Audit Storage/i }));
    const reopenedDialog = await screen.findByRole('dialog', {
      name: /Audit Storage & Payload Retention/i,
    });
    fireEvent.click(within(reopenedDialog).getByRole('button', { name: /Purge Now/i }));
    await waitFor(() => {
      expect(purgeSpy).toHaveBeenCalledWith(0);
      expect(within(reopenedDialog).getByText(/Purged all 5 stored payloads/i)).toBeTruthy();
    });
  });
});
