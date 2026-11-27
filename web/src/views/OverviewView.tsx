import { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  DownloadIcon,
  ProviderGlyph,
  RefreshIcon,
} from '../components/ApertureIcons';
import { SegmentedControl } from '../components/Primitives';
import { UsageChart, type ChartMetric } from '../components/UsageChart';
import {
  formatCompactTokens,
  formatLatency,
  formatNumber,
  formatPercent,
  formatUSD,
} from '../lib/format';
import type { AdminOverviewResponse, TimeWindow } from '../types/api';

interface OverviewViewProps {
  windowRange: TimeWindow;
  onWindowChange: (next: TimeWindow) => void;
  onJumpToLogs: (filter: {
    subject?: string;
    model?: string;
    status?: string;
  }) => void;
}

export function OverviewView({
  windowRange,
  onWindowChange,
  onJumpToLogs,
}: OverviewViewProps) {
  const [data, setData] = useState<AdminOverviewResponse | null>(null);
  const [metric, setMetric] = useState<ChartMetric>('cost_usd');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadSeq, setReloadSeq] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);

    api
      .getAdminOverview(windowRange, { signal: controller.signal })
      .then((res) => {
        if (!controller.signal.aborted) {
          setData(res);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setError(err instanceof Error ? err.message : 'Failed to load usage overview');
        setLoading(false);
      });

    return () => controller.abort();
  }, [windowRange, reloadSeq]);

  const summary = data?.summary;
  const series = data?.series ?? [];
  const topSubjects = data?.top_subjects ?? [];
  const topModels = data?.top_models ?? [];

  const cachedTokens =
    (summary?.cache_read_tokens ?? 0) + (summary?.cache_write_tokens ?? 0);
  const errorCount = summary?.error_count ?? 0;
  const requestCount = summary?.request_count ?? 0;

  const handleExportCsv = () => {
    const header = ['bucket,requests,tokens,cost_usd,errors'];
    const rows = series.map(
      (pt) =>
        `"${pt.bucket.replace(/"/g, '""')}",${pt.requests},${pt.tokens},${pt.cost_usd.toFixed(6)},${pt.errors}`,
    );
    const blob = new Blob([[...header, ...rows].join('\n')], {
      type: 'text/csv;charset=utf-8;',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `headlamp-usage-${windowRange}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const windowLabel =
    windowRange === '24h'
      ? 'Last 24h'
      : windowRange === '7d'
        ? 'Last 7d'
        : 'Last 30d';

  return (
    <div className="ap-page">
      <header className="ap-page-header">
        <div className="ap-page-title-row">
          <div>
            <h1 className="ap-page-title">Usage Overview</h1>
            <p className="ap-page-subtitle">
              Top-level spend, token throughput, cache efficiency, and tailnet caller activity.
            </p>
          </div>
        </div>

        <div className="ap-filter-bar">
          <div className="ap-filter-group">
            <span className="ap-filter-pill">
              <span style={{ color: 'var(--ap-text-secondary)' }}>Date:</span>
              <strong>{windowLabel}</strong>
            </span>
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
            <SegmentedControl
              ariaLabel="Chart metric"
              value={metric}
              onChange={setMetric}
              options={[
                { value: 'cost_usd', label: 'Spend' },
                { value: 'requests', label: 'Requests' },
                { value: 'tokens', label: 'Tokens' },
                { value: 'errors', label: 'Errors' },
              ]}
            />
          </div>

          <div className="ap-filter-group">
            <button
              type="button"
              className="ap-btn"
              onClick={() => setReloadSeq((n) => n + 1)}
              title="Refresh telemetry"
            >
              <RefreshIcon />
              <span>Refresh</span>
            </button>
            <button
              type="button"
              className="ap-btn ap-btn-primary"
              onClick={handleExportCsv}
            >
              <DownloadIcon />
              <span>CSV</span>
            </button>
          </div>
        </div>
      </header>

      {error && (
        <div className="ap-alert ap-alert--danger" role="alert">
          <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{error}</span>
        </div>
      )}

      <section className="ap-bezel-tray" aria-label="Gateway telemetry summary">
        <div className="ap-card">
          <UsageChart series={series} metric={metric} />
        </div>

        <div className="ap-kpi-primary-grid">
          <div className="ap-kpi-card">
            <span className="ap-kpi-label">Spend Today</span>
            <span className="ap-kpi-value">
              {loading && !data ? '—' : formatUSD(data?.today_cost_usd)}
            </span>
            <span className="ap-kpi-foot">UTC day-to-date metered cost</span>
          </div>

          <div className="ap-kpi-card">
            <span className="ap-kpi-label">Month Spend</span>
            <span className="ap-kpi-value">
              {loading && !data ? '—' : formatUSD(data?.month_cost_usd)}
            </span>
            <span className="ap-kpi-foot">
              {windowLabel} window: {formatUSD(summary?.cost_usd)}
            </span>
          </div>

          <div className="ap-kpi-card">
            <span className="ap-kpi-label">Requests ({windowRange})</span>
            <span className="ap-kpi-value">
              {loading && !data ? '—' : formatNumber(requestCount)}
            </span>
            <span className="ap-kpi-foot">
              {topSubjects.length} active {topSubjects.length === 1 ? 'subject' : 'subjects'}
            </span>
          </div>

          <div className="ap-kpi-card">
            <span className="ap-kpi-label">Total Tokens ({windowRange})</span>
            <span className="ap-kpi-value">
              {loading && !data ? '—' : formatCompactTokens(summary?.total_tokens)}
            </span>
            <span className="ap-kpi-foot">
              {formatNumber(summary?.total_tokens)} metered tokens
            </span>
          </div>
        </div>

        <div className="ap-kpi-secondary-grid">
          <div className="ap-kpi-card ap-kpi-card--sub">
            <span className="ap-kpi-label">Input / Output</span>
            <span className="ap-kpi-value ap-kpi-value--sub">
              {formatCompactTokens(summary?.input_tokens)} /{' '}
              {formatCompactTokens(summary?.output_tokens)}
            </span>
            <span className="ap-kpi-foot">
              Reasoning: {formatCompactTokens(summary?.reasoning_tokens)}
            </span>
          </div>

          <div className="ap-kpi-card ap-kpi-card--sub">
            <span className="ap-kpi-label">
              <span>Cached Tokens</span>
              <span className="ap-badge ap-badge--blue">
                {formatPercent(cachedTokens, summary?.total_tokens)}
              </span>
            </span>
            <span className="ap-kpi-value ap-kpi-value--sub">
              {formatCompactTokens(cachedTokens)}
            </span>
            <span className="ap-kpi-foot">
              Read {formatCompactTokens(summary?.cache_read_tokens)} · Write{' '}
              {formatCompactTokens(summary?.cache_write_tokens)}
            </span>
          </div>

          <div
            className="ap-kpi-card ap-kpi-card--sub"
            style={{ cursor: errorCount > 0 ? 'pointer' : undefined }}
            onClick={() => {
              if (errorCount > 0) onJumpToLogs({});
            }}
          >
            <span className="ap-kpi-label">
              <span>Error Rate</span>
              <span
                className={`ap-badge ${
                  errorCount > 0 ? 'ap-badge--red' : 'ap-badge--green'
                }`}
              >
                {formatPercent(errorCount, requestCount)}
              </span>
            </span>
            <span
              className="ap-kpi-value ap-kpi-value--sub"
              style={{ color: errorCount > 0 ? 'var(--ap-red)' : undefined }}
            >
              {formatNumber(errorCount)} {errorCount === 1 ? 'error' : 'errors'}
            </span>
            <span className="ap-kpi-foot">HTTP 4xx / 5xx gateway responses</span>
          </div>

          <div className="ap-kpi-card ap-kpi-card--sub">
            <span className="ap-kpi-label">P95 Latency</span>
            <span className="ap-kpi-value ap-kpi-value--sub">
              {loading && !data ? '—' : formatLatency(summary?.p95_latency_ms)}
            </span>
            <span className="ap-kpi-foot">End-to-end upstream completion</span>
          </div>
        </div>
      </section>

      <div className="ap-split-2">
        <section className="ap-card">
          <div className="ap-card-header">
            <div>
              <h2 className="ap-card-title">Top Users & Nodes</h2>
              <p className="ap-card-subtitle">
                Click a caller to filter Activity Logs by tailnet subject.
              </p>
            </div>
          </div>
          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Subject</th>
                  <th className="ap-num">Requests</th>
                  <th className="ap-num">Tokens</th>
                  <th className="ap-num">Spend</th>
                </tr>
              </thead>
              <tbody>
                {topSubjects.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ color: 'var(--ap-text-muted)', padding: '24px 14px', textAlign: 'center' }}>
                      No caller activity in this window.
                    </td>
                  </tr>
                ) : (
                  topSubjects.map((item) => (
                    <tr
                      key={item.subject}
                      className="ap-row ap-row-clickable"
                      tabIndex={0}
                      onClick={() => onJumpToLogs({ subject: item.subject })}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') onJumpToLogs({ subject: item.subject });
                      }}
                    >
                      <td
                        className="ap-mono ap-truncate"
                        style={{ maxWidth: 210, fontWeight: 550 }}
                        title={item.subject}
                      >
                        {item.subject}
                      </td>
                      <td className="ap-num">{formatNumber(item.requests)}</td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatCompactTokens(item.tokens)}
                      </td>
                      <td className="ap-num" style={{ fontWeight: 600 }}>
                        {formatUSD(item.cost_usd)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="ap-card">
          <div className="ap-card-header">
            <div>
              <h2 className="ap-card-title">Top Models</h2>
              <p className="ap-card-subtitle">
                Click a model to inspect matching upstream requests.
              </p>
            </div>
          </div>
          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Provider</th>
                  <th className="ap-num">Requests</th>
                  <th className="ap-num">Tokens</th>
                  <th className="ap-num">Spend</th>
                </tr>
              </thead>
              <tbody>
                {topModels.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ color: 'var(--ap-text-muted)', padding: '24px 14px', textAlign: 'center' }}>
                      No model activity in this window.
                    </td>
                  </tr>
                ) : (
                  topModels.map((item) => (
                    <tr
                      key={`${item.provider}/${item.model}`}
                      className="ap-row ap-row-clickable"
                      tabIndex={0}
                      onClick={() => onJumpToLogs({ model: item.model })}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') onJumpToLogs({ model: item.model });
                      }}
                    >
                      <td
                        className="ap-mono ap-truncate"
                        style={{ maxWidth: 190, fontWeight: 550 }}
                        title={item.model}
                      >
                        {item.model}
                      </td>
                      <td>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 6,
                            color: 'var(--ap-text-secondary)',
                          }}
                        >
                          <ProviderGlyph type={item.provider} />
                          <span>{item.provider}</span>
                        </span>
                      </td>
                      <td className="ap-num">{formatNumber(item.requests)}</td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatCompactTokens(item.tokens)}
                      </td>
                      <td className="ap-num" style={{ fontWeight: 600 }}>
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
    </div>
  );
}
