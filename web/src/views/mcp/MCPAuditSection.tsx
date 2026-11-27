import { EyeIcon } from '../../components/ApertureIcons';
import { formatLatency, formatTimestamp } from '../../lib/format';
import type { MCPAuditLog } from '../../types/api';

interface MCPAuditSectionProps {
  auditServer: string;
  auditSubject: string;
  auditTool: string;
  auditStatus: string;
  auditOffset: number;
  auditLimit: number;
  auditLogs: MCPAuditLog[];
  loadingAudit: boolean;
  onServerChange: (value: string) => void;
  onSubjectChange: (value: string) => void;
  onToolChange: (value: string) => void;
  onStatusChange: (value: string) => void;
  onClearFilters: () => void;
  onOffsetChange: (nextOffset: number) => void;
  onSelectLog: (log: MCPAuditLog) => void;
}

export function MCPAuditSection({
  auditServer,
  auditSubject,
  auditTool,
  auditStatus,
  auditOffset,
  auditLimit,
  auditLogs,
  loadingAudit,
  onServerChange,
  onSubjectChange,
  onToolChange,
  onStatusChange,
  onClearFilters,
  onOffsetChange,
  onSelectLog,
}: MCPAuditSectionProps) {
  const hasAuditFilters = Boolean(
    auditServer || auditSubject || auditTool || auditStatus,
  );

  return (
    <section className="ap-card" aria-label="MCP tool call audit logs">
      <div className="ap-card-header">
        <div>
          <h2 className="ap-card-title">MCP Tool Call Audit Stream</h2>
          <p className="ap-card-subtitle">
            Inspect MCP JSON-RPC calls, capability grant denials, guardrail blocks, and upstream tool execution latency.
          </p>
        </div>

        <div className="ap-filter-group">
          <input
            className="ap-input ap-input--sm ap-mono"
            style={{ width: 120 }}
            placeholder="Server"
            aria-label="Filter MCP logs by server"
            value={auditServer}
            onChange={(e) => onServerChange(e.target.value)}
          />
          <input
            className="ap-input ap-input--sm"
            style={{ width: 132 }}
            placeholder="Caller / Subject"
            aria-label="Filter MCP logs by caller"
            value={auditSubject}
            onChange={(e) => onSubjectChange(e.target.value)}
          />
          <input
            className="ap-input ap-input--sm ap-mono"
            style={{ width: 126 }}
            placeholder="Tool name"
            aria-label="Filter MCP logs by tool"
            value={auditTool}
            onChange={(e) => onToolChange(e.target.value)}
          />
          <select
            className="ap-select ap-select--sm"
            style={{ width: 126 }}
            value={auditStatus}
            onChange={(e) => onStatusChange(e.target.value)}
            aria-label="Filter MCP logs by status"
          >
            <option value="">All Statuses</option>
            <option value="ok">ok</option>
            <option value="denied">denied</option>
            <option value="blocked">blocked</option>
            <option value="error">error</option>
          </select>
          {hasAuditFilters && (
            <button
              type="button"
              className="ap-btn ap-btn-ghost ap-btn-sm"
              onClick={onClearFilters}
            >
              Clear
            </button>
          )}
        </div>
      </div>

      <div className="ap-table-wrap">
        <table className="ap-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Caller</th>
              <th>Server / Tool</th>
              <th>Status</th>
              <th className="ap-num">Latency</th>
              <th>Preview</th>
              <th style={{ textAlign: 'right' }} />
            </tr>
          </thead>
          <tbody>
            {auditLogs.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ color: 'var(--ap-text-muted)', padding: '26px 14px', textAlign: 'center' }}>
                  {loadingAudit ? 'Loading MCP audit logs...' : 'No MCP calls match the active filters.'}
                </td>
              </tr>
            ) : (
              auditLogs.map((row) => (
                <tr
                  key={row.id}
                  className="ap-row ap-row-clickable"
                  tabIndex={0}
                  onClick={() => onSelectLog(row)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') onSelectLog(row);
                  }}
                >
                  <td
                    className="ap-tabular"
                    style={{ whiteSpace: 'nowrap', fontSize: 12, color: 'var(--ap-text-secondary)' }}
                  >
                    {formatTimestamp(row.created_at)}
                  </td>
                  <td style={{ maxWidth: 145 }}>
                    <div className="ap-truncate" style={{ fontWeight: 560 }} title={row.subject}>
                      {row.subject}
                    </div>
                    <div className="ap-mono ap-truncate" style={{ fontSize: 11, color: 'var(--ap-text-muted)' }}>
                      {row.node_name || row.node_ip || 'tailnet'}
                    </div>
                  </td>
                  <td style={{ maxWidth: 165 }}>
                    <div className="ap-mono ap-truncate" style={{ fontWeight: 560 }}>
                      {row.server_name}/{row.tool_name || row.method}
                    </div>
                    <div className="ap-mono" style={{ fontSize: 11, color: 'var(--ap-text-muted)' }}>
                      {row.method}
                    </div>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <span
                      className={`ap-badge ${
                        row.status === 'ok'
                          ? 'ap-badge--green'
                          : row.status === 'denied'
                            ? 'ap-badge--amber'
                            : 'ap-badge--red'
                      }`}
                    >
                      {row.status}
                    </span>
                  </td>
                  <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                    {formatLatency(row.latency_ms)}
                  </td>
                  <td style={{ maxWidth: 170 }}>
                    <span
                      className="ap-mono ap-truncate"
                      style={{
                        display: 'block',
                        fontSize: 11.5,
                        color: row.error_message ? 'var(--ap-red)' : 'var(--ap-text-secondary)',
                      }}
                      title={row.error_message || row.arguments_preview}
                    >
                      {row.error_message || row.arguments_preview || '—'}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <button
                      type="button"
                      className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                      aria-label="Inspect MCP call"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectLog(row);
                      }}
                    >
                      <EyeIcon />
                      <span className="ap-action-label">Inspect</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {(auditOffset > 0 || auditLogs.length >= auditLimit) && (
        <div
          className="ap-card-header"
          style={{ borderTop: '1px solid var(--ap-border)', borderBottom: 'none', justifyContent: 'space-between' }}
        >
          <span className="ap-tabular" style={{ fontSize: 12, color: 'var(--ap-text-muted)' }}>
            Showing rows {auditOffset + 1}–{auditOffset + auditLogs.length}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              className="ap-btn ap-btn-sm"
              disabled={auditOffset === 0}
              onClick={() => onOffsetChange(Math.max(0, auditOffset - auditLimit))}
            >
              Previous
            </button>
            <button
              type="button"
              className="ap-btn ap-btn-sm"
              disabled={auditLogs.length < auditLimit}
              onClick={() => onOffsetChange(auditOffset + auditLimit)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
