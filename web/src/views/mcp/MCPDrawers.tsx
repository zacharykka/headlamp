import { AlertIcon, WrenchIcon } from '../../components/ApertureIcons';
import { CodeBlock, Drawer } from '../../components/Primitives';
import { formatLatency, formatTimestamp } from '../../lib/format';
import type { MCPAuditLog, MCPServerTestResult } from '../../types/api';

export function formatPrettyJson(raw: string): string {
  if (!raw) return '';
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

interface MCPDiscoveryDrawerProps {
  serverName: string | null;
  discovery: MCPServerTestResult | null;
  onClose: () => void;
}

export function MCPDiscoveryDrawer({
  serverName,
  discovery,
  onClose,
}: MCPDiscoveryDrawerProps) {
  return (
    <Drawer
      open={Boolean(serverName && discovery)}
      title={serverName ? `MCP Discovery · ${serverName}` : 'MCP Discovery'}
      subtitle={discovery?.message}
      onClose={onClose}
    >
      {discovery && (
        <>
          {!discovery.ok && discovery.message && (
            <div className="ap-alert ap-alert--danger" role="alert">
              <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
              <span>{discovery.message}</span>
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span
              className={`ap-badge ${
                discovery.ok ? 'ap-badge--green' : 'ap-badge--red'
              }`}
            >
              {discovery.ok ? 'Connected' : 'Failed'}
            </span>
            <span className="ap-badge ap-tabular">
              {formatLatency(discovery.latency_ms)}
            </span>
            <span className="ap-badge ap-tabular">
              {(discovery.tools ?? []).length} discovered tools
            </span>
          </div>

          <section className="ap-card">
            <div className="ap-card-header">
              <h3 className="ap-card-title">Discovered Tools</h3>
            </div>
            <div className="ap-table-wrap">
              <table className="ap-table">
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {(discovery.tools ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={2} style={{ color: 'var(--ap-text-muted)', padding: 18, textAlign: 'center' }}>
                        No tools reported by this MCP server.
                      </td>
                    </tr>
                  ) : (
                    (discovery.tools ?? []).map((t) => (
                      <tr key={t.name} className="ap-row">
                        <td className="ap-mono" style={{ fontWeight: 600, whiteSpace: 'nowrap' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                            <WrenchIcon size={13} />
                            <span>{t.name}</span>
                          </span>
                        </td>
                        <td style={{ color: 'var(--ap-text-secondary)', fontSize: 12.5 }}>
                          {t.description || '—'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </Drawer>
  );
}

interface MCPAuditDetailDrawerProps {
  log: MCPAuditLog | null;
  onClose: () => void;
}

export function MCPAuditDetailDrawer({
  log,
  onClose,
}: MCPAuditDetailDrawerProps) {
  return (
    <Drawer
      open={Boolean(log)}
      title={
        log
          ? `MCP Call · ${log.server_name}/${log.tool_name || log.method}`
          : 'MCP Call'
      }
      subtitle={log ? log.request_id || log.id : undefined}
      onClose={onClose}
    >
      {log && (
        <>
          {log.error_message && (
            <div className="ap-alert ap-alert--danger">
              <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
              <span>{log.error_message}</span>
            </div>
          )}

          <section className="ap-card">
            <div className="ap-card-header">
              <h3 className="ap-card-title">Call Metadata</h3>
              <span
                className={`ap-badge ${
                  log.status === 'ok'
                    ? 'ap-badge--green'
                    : log.status === 'denied'
                      ? 'ap-badge--amber'
                      : 'ap-badge--red'
                }`}
              >
                {log.status}
              </span>
            </div>
            <div className="ap-table-wrap">
              <table className="ap-table">
                <tbody>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)', width: 130 }}>Timestamp</td>
                    <td className="ap-tabular">{formatTimestamp(log.created_at)}</td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Caller</td>
                    <td>
                      <strong>{log.subject}</strong>{' '}
                      <span className="ap-mono" style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}>
                        ({log.node_name || 'tailnet'} · {log.node_ip || '—'})
                      </span>
                    </td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>MCP Server</td>
                    <td className="ap-mono">{log.server_name}</td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Method & Tool</td>
                    <td className="ap-mono">
                      {log.method}
                      {log.tool_name ? ` → ${log.tool_name}` : ''}
                    </td>
                  </tr>
                  <tr className="ap-row">
                    <td style={{ color: 'var(--ap-text-secondary)' }}>Latency</td>
                    <td className="ap-tabular">{formatLatency(log.latency_ms)}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <CodeBlock
            label="Arguments Preview (redacted)"
            code={formatPrettyJson(log.arguments_preview) || '(no arguments)'}
            highlightRedactions
          />
        </>
      )}
    </Drawer>
  );
}
