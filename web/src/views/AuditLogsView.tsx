import { useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../api/client';
import {
  AlertIcon,
  EyeIcon,
  GearIcon,
  ProviderGlyph,
  RefreshIcon,
} from '../components/ApertureIcons';
import { Toggle } from '../components/Primitives';
import {
  formatCompactTokens,
  formatLatency,
  formatNumber,
  formatTimestamp,
  formatUSD,
} from '../lib/format';
import type {
  AdminLogsResponse,
  AuditPayload,
  AuditSettings,
  UsageLog,
} from '../types/api';
import {
  AuditPayloadDrawer,
  type PayloadLoadState,
} from './audit/AuditPayloadDrawer';
import { AuditSettingsModal } from './audit/AuditSettingsModal';

type LogTimePreset = 'all' | '1h' | '24h' | '7d' | '30d';

export interface LogsFocusState {
  subject?: string;
  provider?: string;
  model?: string;
  status?: string;
  errorsOnly?: boolean;
  guardrail_only?: boolean;
  timePreset?: LogTimePreset;
  openSettings?: boolean;
  nonce?: number;
}

interface AuditLogsViewProps {
  focus?: LogsFocusState;
}

const PAGE_LIMIT = 50;

function sinceFromPreset(preset: LogTimePreset): string | undefined {
  const now = Date.now();
  if (preset === '1h') return new Date(now - 3600 * 1000).toISOString();
  if (preset === '24h') return new Date(now - 24 * 3600 * 1000).toISOString();
  if (preset === '7d') return new Date(now - 7 * 24 * 3600 * 1000).toISOString();
  if (preset === '30d') return new Date(now - 30 * 24 * 3600 * 1000).toISOString();
  return undefined;
}

export function AuditLogsView({ focus }: AuditLogsViewProps) {
  const [subject, setSubject] = useState('');
  const [provider, setProvider] = useState('');
  const [model, setModel] = useState('');
  const [status, setStatus] = useState('');
  const [timePreset, setTimePreset] = useState<LogTimePreset>('all');
  const [guardrailOnly, setGuardrailOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [refreshTick, setRefreshTick] = useState(0);

  const [data, setData] = useState<AdminLogsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [pageError, setPageError] = useState<string | null>(null);

  // Race-safe request tracking for log stream
  const logAbortRef = useRef<AbortController | null>(null);
  const logSeqRef = useRef(0);

  // Payload Inspector Drawer State
  const [selectedLog, setSelectedLog] = useState<UsageLog | null>(null);
  const [payload, setPayload] = useState<AuditPayload | null>(null);
  const [payloadState, setPayloadState] = useState<PayloadLoadState>('idle');
  const [payloadError, setPayloadError] = useState<string | null>(null);
  const payloadAbortRef = useRef<AbortController | null>(null);
  const payloadSeqRef = useRef(0);

  // Audit Storage Settings Modal
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<AuditSettings>({
    store_payloads: false,
    retention_days: 7,
  });
  const settingsDirtyRef = useRef(false);

  useEffect(() => {
    void api
      .getAuditSettings()
      .then((res) => {
        if (!settingsDirtyRef.current) {
          setSettings(res);
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!focus) return;
    setSubject(focus.subject ?? '');
    setProvider(focus.provider ?? '');
    setModel(focus.model ?? '');
    setStatus(focus.errorsOnly ? 'errors_only' : (focus.status ?? ''));
    setGuardrailOnly(Boolean(focus.guardrail_only));
    setTimePreset(focus.timePreset ?? 'all');
    setOffset(0);
    if (focus.openSettings) {
      setSettingsOpen(true);
    }
  }, [focus?.nonce]);

  useEffect(() => {
    const seq = ++logSeqRef.current;
    const timer = window.setTimeout(() => {
      logAbortRef.current?.abort();
      const controller = new AbortController();
      logAbortRef.current = controller;

      setLoading(true);
      setPageError(null);

      api
        .listAdminLogs(
          {
            subject: subject.trim() || undefined,
            provider: provider.trim() || undefined,
            model: model.trim() || undefined,
            status: status && status !== 'errors_only' ? status : undefined,
            errors_only: status === 'errors_only' ? true : undefined,
            guardrail_only: guardrailOnly || undefined,
            since: sinceFromPreset(timePreset),
            limit: PAGE_LIMIT,
            offset,
          },
          { signal: controller.signal },
        )
        .then((res) => {
          if (seq !== logSeqRef.current || controller.signal.aborted) return;
          setData(res);
          setLoading(false);
        })
        .catch((err: unknown) => {
          if (seq !== logSeqRef.current || controller.signal.aborted) return;
          setPageError(
            err instanceof Error ? err.message : 'Failed to load activity logs',
          );
          setLoading(false);
        });
    }, 100);

    return () => {
      window.clearTimeout(timer);
    };
  }, [subject, provider, model, status, guardrailOnly, timePreset, offset, refreshTick]);

  useEffect(() => {
    return () => {
      logAbortRef.current?.abort();
      payloadAbortRef.current?.abort();
    };
  }, []);

  const inspectLog = async (log: UsageLog) => {
    payloadAbortRef.current?.abort();
    const controller = new AbortController();
    payloadAbortRef.current = controller;
    const seq = ++payloadSeqRef.current;

    setSelectedLog(log);
    setPayload(null);
    setPayloadError(null);
    setPayloadState('loading');

    try {
      const res = await api.getLogPayload(log.id, { signal: controller.signal });
      if (seq !== payloadSeqRef.current || controller.signal.aborted) return;
      setPayload(res);
      setPayloadState('ready');
    } catch (err: unknown) {
      if (seq !== payloadSeqRef.current || controller.signal.aborted) return;
      if (err instanceof ApiError && err.status === 404) {
        setPayloadState('not_stored');
      } else {
        setPayloadState('error');
        setPayloadError(
          err instanceof Error
            ? err.message
            : 'Network or server error while loading audit payload.',
        );
      }
    }
  };

  const closeDrawer = () => {
    payloadAbortRef.current?.abort();
    setSelectedLog(null);
  };

  const hasFilters = Boolean(
    subject || provider || model || status || guardrailOnly || timePreset !== 'all',
  );
  const logs = data?.logs ?? [];
  const summary = data?.summary;

  return (
    <div className="ap-page">
      <header className="ap-page-header">
        <div className="ap-page-title-row">
          <div>
            <h1 className="ap-page-title">Activity & Audit Logs</h1>
            <p className="ap-page-subtitle">
              Real-time gateway request stream across Tailnet callers, model routes, guardrail decisions, and stored payloads.
            </p>
          </div>
          <div className="ap-filter-group">
            <span
              className={`ap-badge ${
                settings.store_payloads ? 'ap-badge--green' : ''
              }`}
            >
              {settings.store_payloads
                ? `Payloads ON (${settings.retention_days}d)`
                : 'Payloads OFF'}
            </span>
            <button
              type="button"
              className="ap-btn"
              onClick={() => setSettingsOpen(true)}
            >
              <GearIcon size={15} />
              <span>Audit Storage</span>
            </button>
            <button
              type="button"
              className="ap-btn ap-btn-primary"
              onClick={() => setRefreshTick((n) => n + 1)}
            >
              <RefreshIcon />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        <div className="ap-filter-bar">
          <div className="ap-filter-group">
            <input
              className="ap-input ap-input--sm"
              style={{ width: 155 }}
              placeholder="Caller / Subject"
              aria-label="Filter by subject"
              value={subject}
              onChange={(e) => {
                setSubject(e.target.value);
                setOffset(0);
              }}
            />
            <input
              className="ap-input ap-input--sm"
              style={{ width: 130 }}
              placeholder="Provider"
              aria-label="Filter by provider"
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value);
                setOffset(0);
              }}
            />
            <input
              className="ap-input ap-input--sm ap-mono"
              style={{ width: 170 }}
              placeholder="Model ID or alias"
              aria-label="Filter by model"
              value={model}
              onChange={(e) => {
                setModel(e.target.value);
                setOffset(0);
              }}
            />
            <select
              className="ap-select ap-select--sm"
              style={{ width: 146 }}
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setOffset(0);
              }}
              aria-label="HTTP status filter"
            >
              <option value="">All Statuses</option>
              <option value="errors_only">Errors (4xx/5xx)</option>
              <option value="200">200 OK</option>
              <option value="400">400 Bad Request</option>
              <option value="403">403 Forbidden</option>
              <option value="429">429 Quota / Rate</option>
              <option value="500">500 Upstream Err</option>
              <option value="502">502 Bad Gateway</option>
            </select>
            <select
              className="ap-select ap-select--sm"
              style={{ width: 126 }}
              value={timePreset}
              onChange={(e) => {
                setTimePreset(e.target.value as LogTimePreset);
                setOffset(0);
              }}
              aria-label="Time window filter"
            >
              <option value="all">All Time</option>
              <option value="1h">Last 1h</option>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
              <option value="30d">Last 30d</option>
            </select>

            <label
              className="ap-filter-pill"
              style={{ cursor: 'pointer', gap: 8 }}
            >
              <Toggle
                checked={guardrailOnly}
                onChange={(next) => {
                  setGuardrailOnly(next);
                  setOffset(0);
                }}
                label="Guardrail hits only"
              />
              <span>Guardrail Hits</span>
            </label>

            {hasFilters && (
              <button
                type="button"
                className="ap-btn ap-btn-ghost"
                onClick={() => {
                  setSubject('');
                  setProvider('');
                  setModel('');
                  setStatus('');
                  setTimePreset('all');
                  setGuardrailOnly(false);
                  setOffset(0);
                }}
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </header>

      {pageError && (
        <div className="ap-alert ap-alert--danger" role="alert">
          <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{pageError}</span>
        </div>
      )}

      <section className="ap-card" aria-label="Gateway request stream">
        {summary && (
          <div
            className="ap-card-header ap-tabular"
            style={{ background: '#FAF9F6', fontSize: 12.5 }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
              <span>
                <span style={{ color: 'var(--ap-text-secondary)' }}>Matched Requests: </span>
                <strong>{formatNumber(summary.request_count)}</strong>
              </span>
              <span>
                <span style={{ color: 'var(--ap-text-secondary)' }}>Tokens: </span>
                <strong>{formatCompactTokens(summary.total_tokens)}</strong>
              </span>
              <span>
                <span style={{ color: 'var(--ap-text-secondary)' }}>Spend: </span>
                <strong>{formatUSD(summary.cost_usd)}</strong>
              </span>
              <span>
                <span style={{ color: 'var(--ap-text-secondary)' }}>Errors: </span>
                <strong
                  style={{
                    color: (summary.error_count ?? 0) > 0 ? 'var(--ap-red)' : undefined,
                  }}
                >
                  {formatNumber(summary.error_count)}
                </strong>
              </span>
              <span>
                <span style={{ color: 'var(--ap-text-secondary)' }}>P95: </span>
                <strong>{formatLatency(summary.p95_latency_ms)}</strong>
              </span>
            </div>
            <span style={{ color: 'var(--ap-text-muted)', fontSize: 11.5 }}>
              Click any row to inspect metadata & captured payload
            </span>
          </div>
        )}

        <div className="ap-table-wrap">
          <table className="ap-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Caller</th>
                <th>Model & Provider</th>
                <th className="ap-num">Tokens</th>
                <th className="ap-num">Cost</th>
                <th className="ap-num">Latency</th>
                <th>Guardrail</th>
                <th className="ap-num">Status</th>
                <th style={{ textAlign: 'right' }} />
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ color: 'var(--ap-text-muted)', padding: '30px 14px', textAlign: 'center' }}>
                    {loading ? 'Loading request stream...' : 'No requests match the active filters.'}
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const isError =
                    log.status_code >= 400 ||
                    log.status_code === 0 ||
                    Boolean(log.error_message);
                  const grAction = log.guardrail_action || '';
                  return (
                    <tr
                      key={log.id}
                      className="ap-row ap-row-clickable"
                      data-selected={selectedLog?.id === log.id}
                      tabIndex={0}
                      onClick={() => void inspectLog(log)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void inspectLog(log);
                      }}
                    >
                      <td
                        className="ap-tabular"
                        style={{ whiteSpace: 'nowrap', color: 'var(--ap-text-secondary)', fontSize: 12 }}
                      >
                        {formatTimestamp(log.created_at)}
                      </td>
                      <td style={{ maxWidth: 160 }}>
                        <div
                          className="ap-truncate"
                          style={{ fontWeight: 560 }}
                          title={log.subject}
                        >
                          {log.subject}
                        </div>
                        <div
                          className="ap-mono ap-truncate"
                          style={{ fontSize: 11, color: 'var(--ap-text-muted)' }}
                        >
                          {log.node_name || log.auth_source}
                        </div>
                      </td>
                      <td style={{ maxWidth: 210 }}>
                        <div
                          className="ap-mono ap-truncate"
                          style={{ fontSize: 12.5, fontWeight: 550 }}
                          title={
                            log.upstream_model && log.upstream_model !== log.requested_model
                              ? `${log.requested_model} → ${log.upstream_model}`
                              : log.requested_model
                          }
                        >
                          {log.requested_model}
                        </div>
                        <div
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 5,
                            fontSize: 11.5,
                            color: 'var(--ap-text-secondary)',
                            marginTop: 1,
                          }}
                        >
                          <ProviderGlyph type={log.provider_type || log.provider_name} />
                          <span>{log.provider_name || 'gateway'}</span>
                        </div>
                      </td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatCompactTokens(log.total_tokens)}
                      </td>
                      <td className="ap-num" style={{ fontWeight: 560 }}>
                        {formatUSD(log.cost_usd)}
                      </td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatLatency(log.latency_ms)}
                      </td>
                      <td>
                        {grAction ? (
                          <span
                            className={`ap-badge ${
                              grAction === 'block'
                                ? 'ap-badge--red'
                                : grAction === 'redact'
                                  ? 'ap-badge--amber'
                                  : 'ap-badge--purple'
                            }`}
                          >
                            {grAction}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--ap-text-muted)' }}>—</span>
                        )}
                      </td>
                      <td className="ap-num">
                        <span
                          className={`ap-badge ap-tabular ${
                            isError ? 'ap-badge--red' : 'ap-badge--green'
                          }`}
                        >
                          {log.status_code}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button
                          type="button"
                          className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                          aria-label="Inspect request"
                          onClick={(e) => {
                            e.stopPropagation();
                            void inspectLog(log);
                          }}
                        >
                          <EyeIcon />
                          <span className="ap-action-label">Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {(offset > 0 || logs.length >= PAGE_LIMIT) && (
          <div
            className="ap-card-header"
            style={{ borderTop: '1px solid var(--ap-border)', borderBottom: 'none', justifyContent: 'space-between' }}
          >
            <span className="ap-tabular" style={{ color: 'var(--ap-text-muted)', fontSize: 12 }}>
              Showing rows {offset + 1}–{offset + logs.length}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="ap-btn ap-btn-sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_LIMIT))}
              >
                Previous
              </button>
              <button
                type="button"
                className="ap-btn ap-btn-sm"
                disabled={logs.length < PAGE_LIMIT}
                onClick={() => setOffset(offset + PAGE_LIMIT)}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </section>

      <AuditPayloadDrawer
        selectedLog={selectedLog}
        payload={payload}
        payloadState={payloadState}
        payloadError={payloadError}
        onClose={closeDrawer}
        onRetry={(log) => void inspectLog(log)}
      />

      <AuditSettingsModal
        open={settingsOpen}
        settings={settings}
        settingsDirtyRef={settingsDirtyRef}
        onSettingsChange={setSettings}
        onClose={() => setSettingsOpen(false)}
      />
    </div>
  );
}
