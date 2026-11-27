import { useEffect, useState, type FormEvent } from 'react';
import { Eye, Refresh, Setting2, Trash } from 'reicon-react';
import { api, ApiError } from '../api/client';
import { Icon } from '../components/Icon';
import { CodeBlock, Drawer, Modal, Toggle } from '../components/Primitives';
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

export interface LogsFocusState {
  subject?: string;
  provider?: string;
  model?: string;
  status?: string;
  guardrail_only?: boolean;
  openSettings?: boolean;
  nonce?: number;
}

interface AuditLogsViewProps {
  focus?: LogsFocusState;
}

const PAGE_LIMIT = 50;

function formatPrettyBody(raw: string): string {
  if (!raw) return '';
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

export function AuditLogsView({ focus }: AuditLogsViewProps) {
  const [subject, setSubject] = useState('');
  const [provider, setProvider] = useState('');
  const [model, setModel] = useState('');
  const [status, setStatus] = useState('');
  const [guardrailOnly, setGuardrailOnly] = useState(false);
  const [offset, setOffset] = useState(0);

  const [data, setData] = useState<AdminLogsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Payload Drawer
  const [selectedLog, setSelectedLog] = useState<UsageLog | null>(null);
  const [payload, setPayload] = useState<AuditPayload | null>(null);
  const [payloadStatus, setPayloadStatus] = useState<'idle' | 'loading' | 'missing' | 'ready'>('idle');

  // Audit Settings Modal
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<AuditSettings>({
    store_payloads: false,
    retention_days: 7,
  });
  const [retentionDaysInput, setRetentionDaysInput] = useState('7');
  const [savingSettings, setSavingSettings] = useState(false);
  const [purgeNotice, setPurgeNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!focus) return;
    setSubject(focus.subject ?? '');
    setProvider(focus.provider ?? '');
    setModel(focus.model ?? '');
    setStatus(focus.status ?? '');
    setGuardrailOnly(Boolean(focus.guardrail_only));
    setOffset(0);
    if (focus.openSettings) {
      void openAuditSettings();
    }
  }, [focus?.nonce]);

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listAdminLogs({
        subject: subject.trim() || undefined,
        provider: provider.trim() || undefined,
        model: model.trim() || undefined,
        status: status || undefined,
        guardrail_only: guardrailOnly || undefined,
        limit: PAGE_LIMIT,
        offset,
      });
      setData(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fetchLogs();
    }, 120);
    return () => window.clearTimeout(timer);
  }, [subject, provider, model, status, guardrailOnly, offset]);

  const inspectLog = async (log: UsageLog) => {
    setSelectedLog(log);
    setPayload(null);
    setPayloadStatus('loading');
    try {
      const res = await api.getLogPayload(log.id);
      setPayload(res);
      setPayloadStatus('ready');
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 404) {
        setPayloadStatus('missing');
      } else {
        setPayloadStatus('missing');
      }
    }
  };

  const openAuditSettings = async () => {
    setPurgeNotice(null);
    setRetentionDaysInput(String(settings.retention_days));
    setSettingsOpen(true);
    try {
      const current = await api.getAuditSettings();
      setSettings(current);
      setRetentionDaysInput(String(current.retention_days));
    } catch {
      // Keep default state if unavailable.
    }
  };

  const handleSaveSettings = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = retentionDaysInput.trim();
    const parsedDays = trimmed === '' ? 0 : Number(trimmed);
    if (!Number.isFinite(parsedDays) || parsedDays < 0) {
      setError('Retention days must be 0 or greater');
      return;
    }
    setSavingSettings(true);
    try {
      const updated = await api.updateAuditSettings({
        store_payloads: settings.store_payloads,
        retention_days: Math.floor(parsedDays),
      });
      setSettings(updated);
      setRetentionDaysInput(String(updated.retention_days));
      setSettingsOpen(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save audit settings');
    } finally {
      setSavingSettings(false);
    }
  };

  const handlePurge = async () => {
    try {
      const res = await api.purgeAuditPayloads();
      setPurgeNotice(`Purged ${formatNumber(res.purged)} payloads`);
    } catch (err: unknown) {
      setPurgeNotice(err instanceof Error ? err.message : 'Purge failed');
    }
  };

  const hasFilters = Boolean(subject || provider || model || status || guardrailOnly);
  const logs = data?.logs ?? [];
  const summary = data?.summary;

  return (
    <>
      <section className="hl-section">
        <div className="hl-section-bar">
          <h1>Audit Logs</h1>
          <div className="hl-toolbar">
            <button type="button" className="hl-btn" onClick={openAuditSettings}>
              <Icon icon={Setting2} />
              <span>Audit Settings</span>
            </button>
            <button type="button" className="hl-btn" onClick={fetchLogs}>
              <Icon icon={Refresh} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        <div className="hl-toolbar">
          <input
            className="hl-input"
            style={{ width: 200 }}
            placeholder="Subject"
            value={subject}
            onChange={(e) => {
              setSubject(e.target.value);
              setOffset(0);
            }}
          />
          <input
            className="hl-input"
            style={{ width: 160 }}
            placeholder="Provider"
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value);
              setOffset(0);
            }}
          />
          <input
            className="hl-input hl-mono"
            style={{ width: 220 }}
            placeholder="Model"
            value={model}
            onChange={(e) => {
              setModel(e.target.value);
              setOffset(0);
            }}
          />
          <select
            className="hl-select"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setOffset(0);
            }}
            aria-label="HTTP status filter"
          >
            <option value="">All Statuses</option>
            <option value="200">200 OK</option>
            <option value="400">400 Bad Request</option>
            <option value="403">403 Forbidden</option>
            <option value="429">429 Rate Limited</option>
            <option value="500">500 Error</option>
          </select>

          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, paddingLeft: 8 }}>
            <Toggle
              checked={guardrailOnly}
              onChange={(next) => {
                setGuardrailOnly(next);
                setOffset(0);
              }}
              label="Guardrail hits only"
            />
            <span className="hl-secondary" style={{ fontSize: 14 }}>
              Guardrail Hits
            </span>
          </div>

          {hasFilters && (
            <button
              type="button"
              className="hl-btn hl-btn-ghost"
              onClick={() => {
                setSubject('');
                setProvider('');
                setModel('');
                setStatus('');
                setGuardrailOnly(false);
                setOffset(0);
              }}
            >
              Clear
            </button>
          )}
        </div>

        {error && <p className="hl-status-text hl-status-danger">{error}</p>}

        {summary && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 32, fontSize: 14 }}>
            <span>
              <span className="hl-secondary">Requests </span>
              <strong>{formatNumber(summary.request_count)}</strong>
            </span>
            <span>
              <span className="hl-secondary">Tokens </span>
              <strong>{formatCompactTokens(summary.total_tokens)}</strong>
            </span>
            <span>
              <span className="hl-secondary">Spend </span>
              <strong>{formatUSD(summary.cost_usd)}</strong>
            </span>
          </div>
        )}

        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Subject</th>
                <th>Model</th>
                <th>Provider</th>
                <th className="hl-num">Tokens</th>
                <th className="hl-num">Cost</th>
                <th className="hl-num">Latency</th>
                <th>Guardrail</th>
                <th className="hl-num">Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={10} className="hl-secondary">
                    {loading ? 'Loading logs...' : 'No matching requests'}
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const isError = log.status_code >= 400;
                  const grAction = log.guardrail_action || '';
                  return (
                    <tr
                      key={log.id}
                      className="hl-row hl-row-clickable"
                      data-selected={selectedLog?.id === log.id}
                      tabIndex={0}
                      onClick={() => inspectLog(log)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void inspectLog(log);
                      }}
                    >
                      <td className="hl-secondary" style={{ whiteSpace: 'nowrap' }}>
                        {formatTimestamp(log.created_at)}
                      </td>
                      <td style={{ fontWeight: 500 }}>{log.subject}</td>
                      <td className="hl-mono">{log.requested_model}</td>
                      <td className="hl-secondary">{log.provider_name}</td>
                      <td className="hl-num hl-secondary">
                        {formatCompactTokens(log.total_tokens)}
                      </td>
                      <td className="hl-num">{formatUSD(log.cost_usd)}</td>
                      <td className="hl-num hl-secondary">
                        {formatLatency(log.latency_ms)}
                      </td>
                      <td
                        className={
                          grAction === 'block'
                            ? 'hl-status-danger'
                            : grAction === 'redact'
                              ? 'hl-status-accent'
                              : 'hl-secondary'
                        }
                      >
                        {grAction || '—'}
                      </td>
                      <td
                        className={`hl-num ${isError ? 'hl-status-danger' : ''}`}
                        style={{ fontWeight: 500 }}
                      >
                        {log.status_code}
                      </td>
                      <td>
                        <div className="hl-row-actions">
                          <button
                            type="button"
                            className="hl-btn hl-btn-ghost"
                            onClick={(e) => {
                              e.stopPropagation();
                              void inspectLog(log);
                            }}
                          >
                            <Icon icon={Eye} />
                            <span>Inspect</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {(offset > 0 || logs.length >= PAGE_LIMIT) && (
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
            <button
              type="button"
              className="hl-btn"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_LIMIT))}
            >
              Previous
            </button>
            <button
              type="button"
              className="hl-btn"
              disabled={logs.length < PAGE_LIMIT}
              onClick={() => setOffset(offset + PAGE_LIMIT)}
            >
              Next
            </button>
          </div>
        )}
      </section>

      <Drawer
        open={Boolean(selectedLog)}
        title={selectedLog ? `Request ${selectedLog.request_id || selectedLog.id}` : 'Request'}
        onClose={() => setSelectedLog(null)}
      >
        {selectedLog && (
          <>
            <div className="hl-table-wrap">
              <table className="hl-table">
                <tbody>
                  <tr className="hl-row">
                    <td className="hl-secondary">Timestamp</td>
                    <td>{formatTimestamp(selectedLog.created_at)}</td>
                  </tr>
                  <tr className="hl-row">
                    <td className="hl-secondary">Caller</td>
                    <td>
                      {selectedLog.subject}{' '}
                      <span className="hl-secondary">
                        ({selectedLog.node_name || selectedLog.auth_source})
                      </span>
                    </td>
                  </tr>
                  <tr className="hl-row">
                    <td className="hl-secondary">Endpoint</td>
                    <td className="hl-mono">
                      {selectedLog.endpoint} ({selectedLog.protocol})
                    </td>
                  </tr>
                  <tr className="hl-row">
                    <td className="hl-secondary">Model Route</td>
                    <td className="hl-mono">
                      {selectedLog.requested_model} → {selectedLog.provider_name}/
                      {selectedLog.upstream_model}
                    </td>
                  </tr>
                  <tr className="hl-row">
                    <td className="hl-secondary">Token Breakdown</td>
                    <td>
                      In {formatNumber(selectedLog.input_tokens)} · Out{' '}
                      {formatNumber(selectedLog.output_tokens)} · Cache Read{' '}
                      {formatNumber(selectedLog.cache_read_tokens)} · Cache Write{' '}
                      {formatNumber(selectedLog.cache_write_tokens)}
                    </td>
                  </tr>
                  <tr className="hl-row">
                    <td className="hl-secondary">Cost & Timing</td>
                    <td>
                      {formatUSD(selectedLog.cost_usd)} · Total{' '}
                      {formatLatency(selectedLog.latency_ms)} · TTFT{' '}
                      {formatLatency(selectedLog.ttft_ms)}
                    </td>
                  </tr>
                  {(selectedLog.guardrail_action ||
                    (selectedLog.guardrail_hits?.length ?? 0) > 0) && (
                    <tr className="hl-row">
                      <td className="hl-secondary">Guardrail</td>
                      <td className="hl-mono">
                        {selectedLog.guardrail_action || 'matched'}{' '}
                        {(selectedLog.guardrail_hits ?? []).join(', ')}
                      </td>
                    </tr>
                  )}
                  {selectedLog.error_message && (
                    <tr className="hl-row">
                      <td className="hl-secondary">Error</td>
                      <td className="hl-status-danger">{selectedLog.error_message}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {payloadStatus === 'loading' && (
              <p className="hl-secondary">Loading captured payload...</p>
            )}
            {payloadStatus === 'missing' && (
              <p className="hl-secondary">No stored payload for this request</p>
            )}
            {payloadStatus === 'ready' && payload && (
              <>
                <div className="hl-section" style={{ gap: 12 }}>
                  <div className="hl-section-bar">
                    <h3>Request Body</h3>
                    {payload.redacted && (
                      <span className="hl-status-text hl-status-accent">Redacted</span>
                    )}
                  </div>
                  <CodeBlock code={formatPrettyBody(payload.request_body)} />
                </div>

                <div className="hl-section" style={{ gap: 12 }}>
                  <h3>Response Body</h3>
                  <CodeBlock code={formatPrettyBody(payload.response_body)} />
                </div>
              </>
            )}
          </>
        )}
      </Drawer>

      <Modal
        open={settingsOpen}
        title="Audit Settings"
        onClose={() => setSettingsOpen(false)}
      >
        <form onSubmit={handleSaveSettings} style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Store Request & Response Payloads</span>
            <Toggle
              checked={settings.store_payloads}
              onChange={(next) =>
                setSettings((prev) => ({ ...prev, store_payloads: next }))
              }
              label="Store Request & Response Payloads"
            />
          </div>

          <label className="hl-field">
            <span className="hl-label">Retention Days</span>
            <input
              type="number"
              min={0}
              step={1}
              className="hl-input"
              value={retentionDaysInput}
              onChange={(e) => setRetentionDaysInput(e.target.value)}
            />
          </label>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <button
              type="button"
              className="hl-btn hl-btn-danger"
              onClick={handlePurge}
            >
              <Icon icon={Trash} />
              <span>Purge Expired Payloads</span>
            </button>
            {purgeNotice && <span className="hl-secondary">{purgeNotice}</span>}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
            <button
              type="button"
              className="hl-btn"
              onClick={() => setSettingsOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="hl-btn hl-btn-primary"
              disabled={savingSettings}
            >
              {savingSettings ? 'Saving' : 'Save'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
