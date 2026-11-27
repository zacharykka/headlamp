import { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  CodeBlock,
  ProgressBar,
  SegmentedControl,
} from '../components/Primitives';
import { UsageChart } from '../components/UsageChart';
import {
  formatCompactTokens,
  formatLatency,
  formatNumber,
  formatTimestamp,
  formatUSD,
} from '../lib/format';
import type { MeResponse, MeUsageResponse, TimeWindow } from '../types/api';

interface PersonalViewProps {
  me: MeResponse;
}

export function PersonalView({ me }: PersonalViewProps) {
  const [windowRange, setWindowRange] = useState<TimeWindow>('7d');
  const [metric, setMetric] = useState<'cost_usd' | 'requests'>('cost_usd');
  const [usage, setUsage] = useState<MeUsageResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    api
      .getMeUsage(windowRange, 50, 0)
      .then((res) => {
        if (!cancelled) setUsage(res);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load usage');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [windowRange]);

  const origin =
    typeof window !== 'undefined' && window.location.origin
      ? window.location.origin
      : 'http://headlamp';

  const setupSnippet = [
    `# Claude Code`,
    `export ANTHROPIC_BASE_URL="${origin}/anthropic"`,
    `export ANTHROPIC_API_KEY="tailnet"`,
    ``,
    `# Codex / OpenAI SDK`,
    `export OPENAI_BASE_URL="${origin}/v1"`,
    `export OPENAI_API_KEY="tailnet"`,
    ``,
    `# Gemini CLI`,
    `export GEMINI_API_BASE="${origin}/gemini"`,
    `export GEMINI_API_KEY="tailnet"`,
  ].join('\n');

  const budgets = me.budget_status ?? [];
  const allowModels = me.policy.allow_models ?? [];
  const denyModels = me.policy.deny_models ?? [];
  const summary = usage?.summary;
  const logs = usage?.logs ?? [];

  return (
    <>
      <section className="hl-section">
        <div className="hl-section-bar">
          <h1>My Usage</h1>
          <div className="hl-toolbar">
            <SegmentedControl
              ariaLabel="Chart metric"
              value={metric}
              onChange={setMetric}
              options={[
                { value: 'cost_usd', label: 'Spend' },
                { value: 'requests', label: 'Requests' },
              ]}
            />
            <SegmentedControl
              ariaLabel="Time window"
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

        {error && <p className="hl-status-text hl-status-danger">{error}</p>}

        <div className="hl-kpi-grid">
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">Spend ({windowRange})</span>
            <span className="hl-kpi-value hl-kpi-value-accent">
              {formatUSD(summary?.cost_usd)}
            </span>
          </div>
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">Requests</span>
            <span className="hl-kpi-value">{formatNumber(summary?.request_count)}</span>
          </div>
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">Total Tokens</span>
            <span className="hl-kpi-value">
              {formatCompactTokens(summary?.total_tokens)}
            </span>
          </div>
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">P95 Latency</span>
            <span className="hl-kpi-value">
              {formatLatency(summary?.p95_latency_ms)}
            </span>
          </div>
        </div>

        <UsageChart series={usage?.series ?? []} metric={metric} />
      </section>

      <div className="hl-split-2">
        <section className="hl-section">
          <h2>Active Quotas & Allowed Models</h2>
          <div className="hl-table-wrap">
            <table className="hl-table">
              <thead>
                <tr>
                  <th>Scope</th>
                  <th>Daily</th>
                  <th>Monthly</th>
                  <th>Limits</th>
                </tr>
              </thead>
              <tbody>
                {budgets.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="hl-secondary">
                      No active budget limits
                    </td>
                  </tr>
                ) : (
                  budgets.map((b) => {
                    const dailyRem =
                      b.daily_usd != null
                        ? Math.max(0, b.daily_usd - b.daily_spent_usd)
                        : null;
                    const monthlyRem =
                      b.monthly_usd != null
                        ? Math.max(0, b.monthly_usd - b.monthly_spent_usd)
                        : null;
                    return (
                      <tr key={b.scope} className="hl-row">
                        <td
                          className="hl-mono"
                          style={{
                            fontWeight: 500,
                            maxWidth: 176,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {b.scope === '*' ? '* (Global)' : b.scope}
                        </td>
                        <td style={{ minWidth: 96 }}>
                          {dailyRem != null ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                              <span>{formatUSD(dailyRem)}</span>
                              <ProgressBar spent={b.daily_spent_usd} limit={b.daily_usd} />
                            </div>
                          ) : (
                            <span className="hl-secondary">Unlimited</span>
                          )}
                        </td>
                        <td style={{ minWidth: 96 }}>
                          {monthlyRem != null ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                              <span>{formatUSD(monthlyRem)}</span>
                              <ProgressBar
                                spent={b.monthly_spent_usd}
                                limit={b.monthly_usd}
                              />
                            </div>
                          ) : (
                            <span className="hl-secondary">Unlimited</span>
                          )}
                        </td>
                        <td className="hl-secondary hl-nowrap">
                          {[
                            b.rpm > 0 ? `${formatNumber(b.rpm)} RPM` : null,
                            b.tpm > 0 ? `${formatCompactTokens(b.tpm)} TPM` : null,
                          ]
                            .filter(Boolean)
                            .join(' · ') || '—'}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="hl-table-wrap">
            <table className="hl-table">
              <tbody>
                <tr className="hl-row">
                  <td className="hl-secondary">Node Identity</td>
                  <td className="hl-mono">
                    {me.principal.node_name || '—'} ({me.principal.node_ip || me.principal.auth_source})
                  </td>
                </tr>
                <tr className="hl-row">
                  <td className="hl-secondary">Allowed Models</td>
                  <td className="hl-mono">
                    {allowModels.length > 0 ? allowModels.join(', ') : 'None'}
                  </td>
                </tr>
                {denyModels.length > 0 && (
                  <tr className="hl-row">
                    <td className="hl-secondary">Denied Models</td>
                    <td className="hl-mono hl-status-danger">
                      {denyModels.join(', ')}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="hl-section">
          <h2>Client Setup</h2>
          <CodeBlock code={setupSnippet} />
        </section>
      </div>

      <section className="hl-section">
        <h2>Recent Requests</h2>
        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Model</th>
                <th>Protocol</th>
                <th className="hl-num">Tokens</th>
                <th className="hl-num">Cost</th>
                <th className="hl-num">Latency</th>
                <th className="hl-num">Status</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="hl-secondary">
                    No recent requests
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hl-row">
                    <td className="hl-secondary">{formatTimestamp(log.created_at)}</td>
                    <td className="hl-mono">{log.requested_model}</td>
                    <td className="hl-secondary">{log.protocol}</td>
                    <td className="hl-num hl-secondary">
                      {formatCompactTokens(log.total_tokens)}
                    </td>
                    <td className="hl-num">{formatUSD(log.cost_usd)}</td>
                    <td className="hl-num hl-secondary">
                      {formatLatency(log.latency_ms)}
                    </td>
                    <td
                      className={`hl-num ${
                        log.status_code >= 400 ? 'hl-status-danger' : ''
                      }`}
                    >
                      {log.status_code}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
