import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { SegmentedControl } from '../components/Primitives';
import { UsageChart } from '../components/UsageChart';
import {
  formatCompactTokens,
  formatLatency,
  formatNumber,
  formatUSD,
} from '../lib/format';
import type { AdminOverviewResponse, TimeWindow } from '../types/api';

interface OverviewViewProps {
  windowRange: TimeWindow;
  onWindowChange: (next: TimeWindow) => void;
  onJumpToLogs: (filter: { subject?: string; model?: string }) => void;
}

export function OverviewView({
  windowRange,
  onWindowChange,
  onJumpToLogs,
}: OverviewViewProps) {
  const [data, setData] = useState<AdminOverviewResponse | null>(null);
  const [metric, setMetric] = useState<'cost_usd' | 'requests'>('cost_usd');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getAdminOverview(windowRange)
      .then((res) => {
        if (!cancelled) {
          setData(res);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load overview');
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [windowRange]);

  const summary = data?.summary;
  const series = data?.series ?? [];
  const topSubjects = data?.top_subjects ?? [];
  const topModels = data?.top_models ?? [];

  return (
    <>
      <section className="hl-section">
        <div className="hl-section-bar">
          <h1>Overview</h1>
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
              onChange={onWindowChange}
              options={[
                { value: '24h', label: '24h' },
                { value: '7d', label: '7d' },
                { value: '30d', label: '30d' },
              ]}
            />
          </div>
        </div>

        {error && <p className="hl-status-text hl-status-danger">{error}</p>}

        <div
          className="hl-kpi-grid"
          style={{ gridTemplateColumns: 'repeat(5, minmax(0, 1fr))' }}
        >
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">Today Spend</span>
            <span className="hl-kpi-value hl-kpi-value-accent">
              {loading && !data ? '—' : formatUSD(data?.today_cost_usd)}
            </span>
          </div>
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">Month Spend</span>
            <span className="hl-kpi-value">
              {loading && !data ? '—' : formatUSD(data?.month_cost_usd)}
            </span>
          </div>
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">Requests ({windowRange})</span>
            <span className="hl-kpi-value">
              {loading && !data ? '—' : formatNumber(summary?.request_count)}
            </span>
          </div>
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">Tokens ({windowRange})</span>
            <span className="hl-kpi-value">
              {loading && !data ? '—' : formatCompactTokens(summary?.total_tokens)}
            </span>
          </div>
          <div className="hl-kpi-item">
            <span className="hl-kpi-label">P95 Latency</span>
            <span
              className={`hl-kpi-value ${
                (summary?.error_count ?? 0) > 0 ? '' : ''
              }`}
            >
              {loading && !data ? '—' : formatLatency(summary?.p95_latency_ms)}
            </span>
          </div>
        </div>

        <UsageChart series={series} metric={metric} />
      </section>

      <div className="hl-split-2">
        <section className="hl-section">
          <div className="hl-section-bar">
            <h2>Top Subjects</h2>
          </div>
          <div className="hl-table-wrap">
            <table className="hl-table">
              <thead>
                <tr>
                  <th>Subject</th>
                  <th className="hl-num">Requests</th>
                  <th className="hl-num">Tokens</th>
                  <th className="hl-num">Spend</th>
                </tr>
              </thead>
              <tbody>
                {topSubjects.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="hl-secondary">
                      No subject activity
                    </td>
                  </tr>
                ) : (
                  topSubjects.map((item) => (
                    <tr
                      key={item.subject}
                      className="hl-row hl-row-clickable"
                      tabIndex={0}
                      onClick={() => onJumpToLogs({ subject: item.subject })}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') onJumpToLogs({ subject: item.subject });
                      }}
                    >
                      <td className="hl-nowrap" style={{ fontWeight: 500 }}>
                        {item.subject}
                      </td>
                      <td className="hl-num hl-nowrap">{formatNumber(item.requests)}</td>
                      <td className="hl-num hl-secondary hl-nowrap">
                        {formatCompactTokens(item.tokens)}
                      </td>
                      <td className="hl-num hl-nowrap" style={{ fontWeight: 500 }}>
                        {formatUSD(item.cost_usd)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="hl-section">
          <div className="hl-section-bar">
            <h2>Top Models</h2>
          </div>
          <div className="hl-table-wrap">
            <table className="hl-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Provider</th>
                  <th className="hl-num">Requests</th>
                  <th className="hl-num">Tokens</th>
                  <th className="hl-num">Spend</th>
                </tr>
              </thead>
              <tbody>
                {topModels.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="hl-secondary">
                      No model activity
                    </td>
                  </tr>
                ) : (
                  topModels.map((item) => (
                    <tr
                      key={`${item.provider}/${item.model}`}
                      className="hl-row hl-row-clickable"
                      tabIndex={0}
                      onClick={() => onJumpToLogs({ model: item.model })}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') onJumpToLogs({ model: item.model });
                      }}
                    >
                      <td className="hl-mono hl-nowrap" style={{ fontWeight: 500 }}>
                        {item.model}
                      </td>
                      <td className="hl-secondary hl-nowrap">{item.provider}</td>
                      <td className="hl-num hl-nowrap">{formatNumber(item.requests)}</td>
                      <td className="hl-num hl-secondary hl-nowrap">
                        {formatCompactTokens(item.tokens)}
                      </td>
                      <td className="hl-num hl-nowrap" style={{ fontWeight: 500 }}>
                        {formatUSD(item.cost_usd)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}
