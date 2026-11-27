import { useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  TailnetMeshGlyph,
  TerminalIcon,
} from '../components/ApertureIcons';
import {
  CodeBlock,
  ProgressBar,
  SegmentedControl,
} from '../components/Primitives';
import { UsageChart, type ChartMetric } from '../components/UsageChart';
import {
  formatCompactTokens,
  formatLatency,
  formatNumber,
  formatTimestamp,
  formatUSD,
} from '../lib/format';
import type { MeResponse, MeUsageResponse, TimeWindow } from '../types/api';

type ToolTab = 'claude' | 'openai' | 'gemini' | 'cursor';

interface PersonalViewProps {
  me: MeResponse;
}

function pickExampleModel(allowModels: string[], family: 'anthropic' | 'openai' | 'gemini'): string {
  const defaults = {
    anthropic: 'claude-sonnet-4-20250514',
    openai: 'gpt-4.1',
    gemini: 'gemini-2.5-pro',
  };
  for (const pat of allowModels) {
    const clean = pat.trim();
    if (!clean || clean === '*' || clean === '**') continue;
    if (clean.startsWith(`${family}/`) && !clean.includes('*')) {
      return clean.slice(family.length + 1);
    }
    if (!clean.includes('*') && !clean.includes('/')) {
      return clean;
    }
  }
  return defaults[family];
}

export function PersonalView({ me }: PersonalViewProps) {
  const [toolTab, setToolTab] = useState<ToolTab>('claude');
  const [windowRange, setWindowRange] = useState<TimeWindow>('7d');
  const [metric, setMetric] = useState<ChartMetric>('cost_usd');
  const [usage, setUsage] = useState<MeUsageResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    api
      .getMeUsage(windowRange, 50, 0, { signal: controller.signal })
      .then((res) => {
        if (!controller.signal.aborted) setUsage(res);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setError(err instanceof Error ? err.message : 'Failed to load personal usage');
      });
    return () => controller.abort();
  }, [windowRange]);

  const origin =
    typeof window !== 'undefined' && window.location.origin
      ? window.location.origin
      : 'http://headlamp';

  const allowModels = me.policy.allow_models ?? [];
  const denyModels = me.policy.deny_models ?? [];
  const budgets = me.budget_status ?? [];

  const snippets = useMemo(() => {
    const claudeModel = pickExampleModel(allowModels, 'anthropic');
    const openaiModel = pickExampleModel(allowModels, 'openai');
    const geminiModel = pickExampleModel(allowModels, 'gemini');

    return {
      claude: {
        label: 'Claude Code · ~/.zshrc or shell env',
        code: [
          `# Connect Claude Code over your Tailnet — no upstream API key needed`,
          `export ANTHROPIC_BASE_URL="${origin}/anthropic"`,
          `export ANTHROPIC_API_KEY="tailnet"`,
          ``,
          `claude --model ${claudeModel}`,
        ].join('\n'),
      },
      openai: {
        label: 'Codex CLI & OpenAI SDK · ~/.zshrc or shell env',
        code: [
          `# Connect Codex CLI, Aider, or any OpenAI-compatible SDK`,
          `export OPENAI_BASE_URL="${origin}/v1"`,
          `export OPENAI_API_KEY="tailnet"`,
          ``,
          `curl -sS "${origin}/v1/chat/completions" \\`,
          `  -H "Content-Type: application/json" \\`,
          `  -d '{"model":"${openaiModel}","messages":[{"role":"user","content":"ping"}]}'`,
        ].join('\n'),
      },
      gemini: {
        label: 'Gemini CLI & Google GenAI SDK · ~/.zshrc or shell env',
        code: [
          `# Connect Gemini CLI & Google GenAI clients via Headlamp`,
          `export GEMINI_API_BASE="${origin}/gemini"`,
          `export GOOGLE_GEMINI_BASE_URL="${origin}/gemini"`,
          `export GEMINI_API_KEY="tailnet"`,
          ``,
          `gemini -m ${geminiModel} -p "Hello from Tailnet"`,
        ].join('\n'),
      },
      cursor: {
        label: 'Cursor / IDE Override · Settings → Models',
        code: [
          `# Override OpenAI Base URL in Cursor / Continue / Zed:`,
          `Base URL:  ${origin}/v1`,
          `API Key:   tailnet`,
          `Model ID:  ${openaiModel}`,
          ``,
          `# ~/.continue/config.json snippet:`,
          `{`,
          `  "models": [`,
          `    {`,
          `      "title": "Headlamp (${openaiModel})",`,
          `      "provider": "openai",`,
          `      "model": "${openaiModel}",`,
          `      "apiBase": "${origin}/v1",`,
          `      "apiKey": "tailnet"`,
          `    }`,
          `  ]`,
          `}`,
        ].join('\n'),
      },
    };
  }, [origin, allowModels]);

  const summary = usage?.summary;
  const logs = usage?.logs ?? [];
  const cachedTokens =
    (summary?.cache_read_tokens ?? 0) + (summary?.cache_write_tokens ?? 0);

  return (
    <div className="ap-page">
      <header className="ap-page-header">
        <div className="ap-page-title-row">
          <div>
            <h1 className="ap-page-title">Quickstart & My Usage</h1>
            <p className="ap-page-subtitle">
              Point your local coding agents at Headlamp over Tailnet — authenticated automatically by node identity.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="ap-badge ap-badge--blue ap-mono">
              <TailnetMeshGlyph size={12} />
              <span>
                {me.principal.node_name || me.principal.subject} ·{' '}
                {me.principal.node_ip || me.principal.auth_source}
              </span>
            </span>
          </div>
        </div>
      </header>

      {error && (
        <div className="ap-alert ap-alert--danger" role="alert">
          <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{error}</span>
        </div>
      )}

      {/* Developer Connection Hub inside Double-Bezel Tray */}
      <section className="ap-bezel-tray" aria-label="Connect local coding tools">
        <div className="ap-card">
          <div className="ap-card-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
              <TerminalIcon size={17} />
              <div>
                <h2 className="ap-card-title">Connect Your Tools</h2>
                <p className="ap-card-subtitle">
                  Gateway origin: <span className="ap-mono">{origin}</span>
                </p>
              </div>
            </div>
            <SegmentedControl
              ariaLabel="Developer tool configuration"
              value={toolTab}
              onChange={setToolTab}
              options={[
                { value: 'claude', label: 'Claude Code' },
                { value: 'openai', label: 'Codex / OpenAI SDK' },
                { value: 'gemini', label: 'Gemini CLI' },
                { value: 'cursor', label: 'Cursor / IDE' },
              ]}
            />
          </div>

          <div className="ap-card-body ap-quickstart-grid">
            <CodeBlock
              label={snippets[toolTab].label}
              code={snippets[toolTab].code}
            />

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div
                className="ap-kpi-card ap-kpi-card--sub"
                style={{ justifyContent: 'flex-start', gap: 10 }}
              >
                <div className="ap-kpi-label">
                  <span>Your Allowed Models (Tailnet Grants)</span>
                  <span
                    className={`ap-badge ${
                      me.policy.grants_applied ? 'ap-badge--green' : 'ap-badge--amber'
                    }`}
                  >
                    {me.policy.grants_applied ? 'Grants Active' : 'No Grants'}
                  </span>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {allowModels.length > 0 ? (
                    allowModels.map((m) => (
                      <span key={m} className="ap-badge ap-mono" style={{ background: '#FFFFFF' }}>
                        {m}
                      </span>
                    ))
                  ) : (
                    <span style={{ color: 'var(--ap-text-muted)', fontSize: 12.5 }}>
                      No model globs granted to this principal.
                    </span>
                  )}
                </div>

                {denyModels.length > 0 && (
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                    <span style={{ fontSize: 11.5, color: 'var(--ap-text-muted)' }}>
                      Denied:
                    </span>
                    {denyModels.map((m) => (
                      <span key={m} className="ap-badge ap-badge--red ap-mono">
                        {m}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div
                className="ap-kpi-card ap-kpi-card--sub"
                style={{ justifyContent: 'flex-start', gap: 10 }}
              >
                <div className="ap-kpi-label">
                  <span>Active Quotas & Remaining Balance</span>
                </div>
                {budgets.length === 0 ? (
                  <span style={{ color: 'var(--ap-text-secondary)', fontSize: 12.5 }}>
                    No spend caps applied to your Tailnet identity.
                  </span>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {budgets.map((b) => {
                      const dailyRem =
                        b.daily_usd != null
                          ? Math.max(0, b.daily_usd - b.daily_spent_usd)
                          : null;
                      const monthlyRem =
                        b.monthly_usd != null
                          ? Math.max(0, b.monthly_usd - b.monthly_spent_usd)
                          : null;
                      return (
                        <div
                          key={b.scope}
                          style={{
                            padding: '10px 12px',
                            borderRadius: 'var(--ap-radius-sm)',
                            background: '#FFFFFF',
                            border: '1px solid var(--ap-border)',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 7,
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 12 }}>
                            <span className="ap-mono" style={{ fontWeight: 600 }}>
                              {b.scope === '*' ? '* (Global)' : b.scope}
                            </span>
                            <span className="ap-tabular" style={{ color: 'var(--ap-text-secondary)' }}>
                              {[
                                b.rpm > 0 ? `${formatNumber(b.rpm)} RPM` : null,
                                b.tpm > 0 ? `${formatCompactTokens(b.tpm)} TPM` : null,
                              ]
                                .filter(Boolean)
                                .join(' · ') || 'No rate cap'}
                            </span>
                          </div>

                          {b.daily_usd != null && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                              <div className="ap-tabular" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                                <span style={{ color: 'var(--ap-text-secondary)' }}>
                                  Daily remaining: <strong>{formatUSD(dailyRem)}</strong>
                                </span>
                                <span style={{ color: 'var(--ap-text-muted)' }}>
                                  {formatUSD(b.daily_spent_usd)} / {formatUSD(b.daily_usd)}
                                </span>
                              </div>
                              <ProgressBar
                                spent={b.daily_spent_usd}
                                limit={b.daily_usd}
                                softAlertPct={b.soft_alert_pct}
                              />
                            </div>
                          )}

                          {b.monthly_usd != null && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                              <div className="ap-tabular" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                                <span style={{ color: 'var(--ap-text-secondary)' }}>
                                  Monthly remaining: <strong>{formatUSD(monthlyRem)}</strong>
                                </span>
                                <span style={{ color: 'var(--ap-text-muted)' }}>
                                  {formatUSD(b.monthly_spent_usd)} / {formatUSD(b.monthly_usd)}
                                </span>
                              </div>
                              <ProgressBar
                                spent={b.monthly_spent_usd}
                                limit={b.monthly_usd}
                                softAlertPct={b.soft_alert_pct}
                              />
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Personal Telemetry */}
      <section className="ap-card" aria-label="Personal usage telemetry">
        <div className="ap-card-header">
          <div>
            <h2 className="ap-card-title">My Telemetry ({windowRange})</h2>
            <p className="ap-card-subtitle">
              Metered spend and token usage attributed to {me.principal.subject}.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <SegmentedControl
              ariaLabel="Personal chart metric"
              value={metric}
              onChange={setMetric}
              options={[
                { value: 'cost_usd', label: 'Spend' },
                { value: 'requests', label: 'Requests' },
                { value: 'tokens', label: 'Tokens' },
              ]}
            />
            <SegmentedControl
              ariaLabel="Personal time window"
              value={windowRange}
              onChange={setWindowRange}
              options={[
                { value: '24h', label: '24h' },
                { value: '7d', label: '7d' },
                { value: '30d', label: '30d' },
              ]}
            />
          </div>
        </div>

        <div className="ap-card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="ap-kpi-primary-grid">
            <div className="ap-kpi-card ap-kpi-card--sub">
              <span className="ap-kpi-label">Spend ({windowRange})</span>
              <span className="ap-kpi-value ap-kpi-value--sub">
                {formatUSD(summary?.cost_usd)}
              </span>
            </div>
            <div className="ap-kpi-card ap-kpi-card--sub">
              <span className="ap-kpi-label">Requests</span>
              <span className="ap-kpi-value ap-kpi-value--sub">
                {formatNumber(summary?.request_count)}
              </span>
            </div>
            <div className="ap-kpi-card ap-kpi-card--sub">
              <span className="ap-kpi-label">Total / Cached Tokens</span>
              <span className="ap-kpi-value ap-kpi-value--sub">
                {formatCompactTokens(summary?.total_tokens)}{' '}
                <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--ap-text-secondary)' }}>
                  ({formatCompactTokens(cachedTokens)} cached)
                </span>
              </span>
            </div>
            <div className="ap-kpi-card ap-kpi-card--sub">
              <span className="ap-kpi-label">P95 Latency</span>
              <span className="ap-kpi-value ap-kpi-value--sub">
                {formatLatency(summary?.p95_latency_ms)}
              </span>
            </div>
          </div>

          <UsageChart series={usage?.series ?? []} metric={metric} flush />
        </div>
      </section>

      <section className="ap-card" aria-label="Recent personal requests">
        <div className="ap-card-header">
          <h2 className="ap-card-title">Recent Requests</h2>
        </div>
        <div className="ap-table-wrap">
          <table className="ap-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Model</th>
                <th>Protocol</th>
                <th className="ap-num">Tokens</th>
                <th className="ap-num">Cost</th>
                <th className="ap-num">Latency</th>
                <th className="ap-num">Status</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ color: 'var(--ap-text-muted)', padding: '24px 14px', textAlign: 'center' }}>
                    No recent requests for your Tailnet identity.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="ap-row">
                    <td className="ap-tabular" style={{ color: 'var(--ap-text-secondary)', fontSize: 12 }}>
                      {formatTimestamp(log.created_at)}
                    </td>
                    <td className="ap-mono" style={{ fontWeight: 550 }}>
                      {log.requested_model}
                    </td>
                    <td style={{ color: 'var(--ap-text-secondary)' }}>{log.protocol}</td>
                    <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                      {formatCompactTokens(log.total_tokens)}
                    </td>
                    <td className="ap-num" style={{ fontWeight: 560 }}>
                      {formatUSD(log.cost_usd)}
                    </td>
                    <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                      {formatLatency(log.latency_ms)}
                    </td>
                    <td className="ap-num">
                      <span
                        className={`ap-badge ap-tabular ${
                          log.status_code >= 400 ? 'ap-badge--red' : 'ap-badge--green'
                        }`}
                      >
                        {log.status_code}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
