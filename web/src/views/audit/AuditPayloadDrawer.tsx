import { AlertIcon } from '../../components/ApertureIcons';
import { CodeBlock, Drawer } from '../../components/Primitives';
import {
  formatLatency,
  formatNumber,
  formatTimestamp,
  formatUSD,
} from '../../lib/format';
import type { AuditPayload, UsageLog } from '../../types/api';

export function formatPrettyBody(raw: string): string {
  if (!raw) return '';
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

export type PayloadLoadState = 'idle' | 'loading' | 'not_stored' | 'error' | 'ready';

interface AuditPayloadDrawerProps {
  selectedLog: UsageLog | null;
  payload: AuditPayload | null;
  payloadState: PayloadLoadState;
  payloadError: string | null;
  onClose: () => void;
  onRetry: (log: UsageLog) => void;
}

export function AuditPayloadDrawer({
  selectedLog,
  payload,
  payloadState,
  payloadError,
  onClose,
  onRetry,
}: AuditPayloadDrawerProps) {
  return (
    <Drawer
      open={Boolean(selectedLog)}
      title={
        selectedLog
          ? `Inspect Request · HTTP ${selectedLog.status_code}`
          : 'Inspect Request'
      }
      subtitle={selectedLog ? selectedLog.request_id || selectedLog.id : undefined}
      onClose={onClose}
    >
      {selectedLog && (
        <>
          {selectedLog.error_message && (
            <div className="ap-alert ap-alert--danger">
              <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
              <div>
                <strong style={{ display: 'block', marginBottom: 2 }}>
                  Gateway / Upstream Error
                </strong>
                <span>{selectedLog.error_message}</span>
              </div>
            </div>
          )}

          <section className="ap-card">
            <div className="ap-card-header">
              <h3 className="ap-card-title">Request Telemetry & Identity</h3>
              <span className="ap-badge ap-mono">
                {selectedLog.protocol}
                {selectedLog.stream ? ' · stream' : ''}
                {selectedLog.translated ? ' · translated' : ''}
              </span>
            </div>
            <div className="ap-table-wrap">
              <table className="ap-table">
                <tbody>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)', width: 135 }}>Timestamp</td>
                    <td className="ap-tabular">{formatTimestamp(selectedLog.created_at)}</td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Caller</td>
                    <td>
                      <strong>{selectedLog.subject}</strong>{' '}
                      <span className="ap-mono" style={{ color: 'var(--ap-text-secondary)', fontSize: 12 }}>
                        ({selectedLog.node_name || 'local'} · {selectedLog.node_ip || selectedLog.auth_source})
                      </span>
                    </td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Endpoint</td>
                    <td className="ap-mono">{selectedLog.endpoint}</td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Model Route</td>
                    <td className="ap-mono">
                      {selectedLog.requested_model} → {selectedLog.provider_name}/
                      {selectedLog.upstream_model}
                    </td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Tokens</td>
                    <td className="ap-tabular">
                      In {formatNumber(selectedLog.input_tokens)} · Out{' '}
                      {formatNumber(selectedLog.output_tokens)} · Cache R{' '}
                      {formatNumber(selectedLog.cache_read_tokens)} · Cache W{' '}
                      {formatNumber(selectedLog.cache_write_tokens)}
                      {selectedLog.reasoning_tokens > 0
                        ? ` · Reasoning ${formatNumber(selectedLog.reasoning_tokens)}`
                        : ''}
                    </td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Cost & Timing</td>
                    <td className="ap-tabular">
                      <strong>{formatUSD(selectedLog.cost_usd)}</strong> · Total{' '}
                      {formatLatency(selectedLog.latency_ms)} · TTFT{' '}
                      {formatLatency(selectedLog.ttft_ms)}
                    </td>
                  </tr>
                  {(selectedLog.guardrail_action ||
                    (selectedLog.guardrail_hits?.length ?? 0) > 0) && (
                    <tr className="ap-row">
                      <td style={{ color: 'var(--ap-text-secondary)' }}>Guardrails</td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                          {selectedLog.guardrail_action && (
                            <span
                              className={`ap-badge ${
                                selectedLog.guardrail_action === 'block'
                                  ? 'ap-badge--red'
                                  : 'ap-badge--amber'
                              }`}
                            >
                              {selectedLog.guardrail_action}
                            </span>
                          )}
                          {(selectedLog.guardrail_hits ?? []).map((hit) => (
                            <span key={hit} className="ap-badge ap-mono">
                              {hit}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          {payloadState === 'loading' && (
            <div className="ap-card ap-card-body" style={{ color: 'var(--ap-text-secondary)' }}>
              Loading captured request & response payload...
            </div>
          )}

          {payloadState === 'not_stored' && (
            <div className="ap-alert ap-alert--info">
              <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
              <div>
                <strong style={{ display: 'block', marginBottom: 2 }}>
                  Payload logging was off for this request
                </strong>
                <span>
                  No request/response body is stored for this log entry (payload capture was disabled at request time or already purged by retention policy). Enable{' '}
                  <strong>Store Payloads</strong> in Audit Storage Settings to capture future requests.
                </span>
              </div>
            </div>
          )}

          {payloadState === 'error' && (
            <div className="ap-alert ap-alert--danger">
              <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
              <div style={{ flex: 1 }}>
                <strong style={{ display: 'block', marginBottom: 2 }}>
                  Failed to fetch audit payload
                </strong>
                <span>{payloadError}</span>
              </div>
              <button
                type="button"
                className="ap-btn ap-btn-sm"
                onClick={() => onRetry(selectedLog)}
              >
                Retry
              </button>
            </div>
          )}

          {payloadState === 'ready' && payload && (() => {
            const hasRedaction =
              payload.redacted ||
              selectedLog.guardrail_action === 'redact' ||
              payload.request_body.includes('[REDACTED') ||
              payload.response_body.includes('[REDACTED');
            return (
              <>
                {hasRedaction && (
                  <div
                    className="ap-alert"
                    style={{
                      background: 'var(--ap-amber-soft)',
                      borderColor: 'var(--ap-amber-border)',
                      color: 'var(--ap-amber)',
                    }}
                  >
                    <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
                    <span>
                      Sensitive credentials or PII in headers and body were redacted before storage and upstream dispatch.
                    </span>
                  </div>
                )}

                {Object.keys(payload.request_headers ?? {}).length > 0 && (
                  <CodeBlock
                    label="Request Headers (sanitized)"
                    code={JSON.stringify(payload.request_headers, null, 2)}
                    highlightRedactions
                  />
                )}

                <CodeBlock
                  label={
                    hasRedaction ? 'Request Body (Redacted)' : 'Request Body'
                  }
                  code={formatPrettyBody(payload.request_body) || '(empty request body)'}
                  highlightRedactions
                />

                {Object.keys(payload.response_headers ?? {}).length > 0 && (
                  <CodeBlock
                    label="Response Headers"
                    code={JSON.stringify(payload.response_headers, null, 2)}
                    highlightRedactions
                  />
                )}

                <CodeBlock
                  label="Response Body"
                  code={formatPrettyBody(payload.response_body) || '(empty response body)'}
                  highlightRedactions
                />
              </>
            );
          })()}
        </>
      )}
    </Drawer>
  );
}
