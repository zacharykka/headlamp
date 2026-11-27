import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  CheckIcon,
  CopyIcon,
  EditIcon,
  EyeIcon,
  PlayIcon,
  PlusIcon,
  RefreshIcon,
  WrenchIcon,
} from '../components/ApertureIcons';
import {
  CodeBlock,
  ConfirmDeleteButton,
  Drawer,
  Modal,
  SegmentedControl,
  SourceBadge,
  Toggle,
  YAML_LOCK_TOOLTIP,
} from '../components/Primitives';
import { formatLatency, formatTimestamp } from '../lib/format';
import type {
  MCPAuditLog,
  MCPServerItem,
  MCPServerTestResult,
  MCPServerUpsertPayload,
} from '../types/api';

export interface MCPFocusState {
  section?: 'all' | 'servers' | 'audit';
  modal?: 'server' | null;
  nonce?: number;
}

interface MCPViewProps {
  focus?: MCPFocusState;
  onSectionChange?: (section: 'all' | 'servers' | 'audit') => void;
  onCountChange?: (serverCount: number) => void;
}

const AUDIT_LIMIT = 50;

function formatPrettyJson(raw: string): string {
  if (!raw) return '';
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

export function MCPView({
  focus,
  onSectionChange,
  onCountChange,
}: MCPViewProps) {
  const [servers, setServers] = useState<MCPServerItem[]>([]);
  const [pageError, setPageError] = useState<string | null>(null);
  const [sectionMode, setSectionMode] = useState<'all' | 'servers' | 'audit'>(
    focus?.section ?? 'all',
  );

  // Server probe / test & discover state
  const [testingMap, setTestingMap] = useState<Record<string, boolean>>({});
  const [testResults, setTestResults] = useState<
    Record<string, MCPServerTestResult>
  >({});
  const [inspectToolsServer, setInspectToolsServer] = useState<string | null>(
    null,
  );
  const [togglingServers, setTogglingServers] = useState<
    Record<string, boolean>
  >({});
  const [copiedServerUrl, setCopiedServerUrl] = useState<string | null>(null);

  // Server Add/Edit Modal
  const [modalOpen, setModalOpen] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [editingServer, setEditingServer] = useState<MCPServerItem | null>(null);
  const [srvName, setSrvName] = useState('');
  const [srvUrl, setSrvUrl] = useState('');
  const [srvTransport, setSrvTransport] = useState('streamable_http');
  const [srvAuthType, setSrvAuthType] = useState('none');
  const [srvAuthHeader, setSrvAuthHeader] = useState('X-API-Key');
  const [srvAuthToken, setSrvAuthToken] = useState('');
  const [srvClearToken, setSrvClearToken] = useState(false);
  const [srvEnabled, setSrvEnabled] = useState(true);
  const [savingServer, setSavingServer] = useState(false);

  // MCP Audit Logs state
  const [auditServer, setAuditServer] = useState('');
  const [auditSubject, setAuditSubject] = useState('');
  const [auditTool, setAuditTool] = useState('');
  const [auditStatus, setAuditStatus] = useState('');
  const [auditOffset, setAuditOffset] = useState(0);
  const [auditTick, setAuditTick] = useState(0);
  const [auditLogs, setAuditLogs] = useState<MCPAuditLog[]>([]);
  const [loadingAudit, setLoadingAudit] = useState(true);
  const [selectedLog, setSelectedLog] = useState<MCPAuditLog | null>(null);

  const auditAbortRef = useRef<AbortController | null>(null);
  const auditSeqRef = useRef(0);

  const origin =
    typeof window !== 'undefined' && window.location.origin
      ? window.location.origin
      : 'http://headlamp';

  const loadServers = async () => {
    setPageError(null);
    try {
      const list = await api.listAdminMCPServers();
      setServers(list);
      onCountChange?.(list.length);
    } catch (err: unknown) {
      setPageError(
        err instanceof Error ? err.message : 'Failed to load MCP servers',
      );
    }
  };

  useEffect(() => {
    void loadServers();
    return () => {
      auditAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!focus) return;
    if (focus.section) setSectionMode(focus.section);
    if (focus.modal === 'server') openCreateServer();
  }, [focus?.nonce]);

  useEffect(() => {
    const seq = ++auditSeqRef.current;
    const timer = window.setTimeout(() => {
      auditAbortRef.current?.abort();
      const controller = new AbortController();
      auditAbortRef.current = controller;

      setLoadingAudit(true);
      api
        .listAdminMCPLogs(
          {
            server: auditServer.trim() || undefined,
            subject: auditSubject.trim() || undefined,
            tool: auditTool.trim() || undefined,
            status: auditStatus || undefined,
            limit: AUDIT_LIMIT,
            offset: auditOffset,
          },
          { signal: controller.signal },
        )
        .then((rows) => {
          if (seq !== auditSeqRef.current || controller.signal.aborted) return;
          setAuditLogs(rows);
          setPageError(null);
          setLoadingAudit(false);
        })
        .catch((err: unknown) => {
          if (seq !== auditSeqRef.current || controller.signal.aborted) return;
          setPageError(
            err instanceof Error ? err.message : 'Failed to load MCP audit logs',
          );
          setLoadingAudit(false);
        });
    }, 100);

    return () => window.clearTimeout(timer);
  }, [auditServer, auditSubject, auditTool, auditStatus, auditOffset, auditTick]);

  const handleSectionSelect = (next: 'all' | 'servers' | 'audit') => {
    setSectionMode(next);
    onSectionChange?.(next);
  };

  const openCreateServer = () => {
    setEditingServer(null);
    setModalError(null);
    setSrvName('');
    setSrvUrl('');
    setSrvTransport('streamable_http');
    setSrvAuthType('none');
    setSrvAuthHeader('X-API-Key');
    setSrvAuthToken('');
    setSrvClearToken(false);
    setSrvEnabled(true);
    setModalOpen(true);
  };

  const openEditServer = (item: MCPServerItem) => {
    if (item.source === 'config') return;
    setEditingServer(item);
    setModalError(null);
    setSrvName(item.name);
    setSrvUrl(item.url);
    setSrvTransport(item.transport || 'streamable_http');
    setSrvAuthType(item.auth_type || 'none');
    setSrvAuthHeader(item.auth_header || 'X-API-Key');
    setSrvAuthToken('');
    setSrvClearToken(false);
    setSrvEnabled(item.enabled);
    setModalOpen(true);
  };

  const handleSaveServer = async (e: FormEvent) => {
    e.preventDefault();
    setModalError(null);

    const name = srvName.trim();
    if (!name) {
      setModalError('MCP server name is required.');
      return;
    }
    if (name.includes('/')) {
      setModalError('MCP server name must not contain "/".');
      return;
    }
    if (!srvUrl.trim()) {
      setModalError('Upstream HTTP/HTTPS URL is required.');
      return;
    }
    if (srvAuthType === 'header' && !srvAuthHeader.trim()) {
      setModalError('Header name is required when auth_type is "header".');
      return;
    }

    setSavingServer(true);
    const payload: MCPServerUpsertPayload = {
      name,
      url: srvUrl.trim(),
      transport: srvTransport,
      auth_type: srvAuthType,
      auth_header: srvAuthType === 'header' ? srvAuthHeader.trim() : '',
      enabled: srvEnabled,
    };
    if (srvAuthToken.trim()) {
      payload.auth_token = srvAuthToken.trim();
    }
    if (editingServer && srvClearToken) {
      payload.clear_auth_token = true;
    }

    try {
      if (editingServer) {
        await api.updateAdminMCPServer(editingServer.name, payload);
      } else {
        await api.createAdminMCPServer(payload);
      }
      setModalOpen(false);
      await loadServers();
    } catch (err: unknown) {
      setModalError(
        err instanceof Error ? err.message : 'Failed to save MCP server',
      );
    } finally {
      setSavingServer(false);
    }
  };

  const handleToggleServer = async (item: MCPServerItem, next: boolean) => {
    if (item.source === 'config' || togglingServers[item.name]) return;
    setPageError(null);
    setTogglingServers((prev) => ({ ...prev, [item.name]: true }));
    try {
      await api.updateAdminMCPServer(item.name, {
        name: item.name,
        url: item.url,
        transport: item.transport,
        auth_type: item.auth_type,
        auth_header: item.auth_header,
        enabled: next,
      });
      setServers((prev) =>
        prev.map((s) => (s.name === item.name ? { ...s, enabled: next } : s)),
      );
    } catch (err: unknown) {
      setPageError(
        err instanceof Error ? err.message : 'Failed to update MCP server',
      );
    } finally {
      setTogglingServers((prev) => ({ ...prev, [item.name]: false }));
    }
  };

  const handleDeleteServer = async (item: MCPServerItem) => {
    if (item.source === 'config') return;
    setPageError(null);
    try {
      await api.deleteAdminMCPServer(item.name);
      await loadServers();
    } catch (err: unknown) {
      setPageError(
        err instanceof Error ? err.message : 'Failed to delete MCP server',
      );
    }
  };

  const handleTestServer = async (name: string) => {
    if (testingMap[name]) return;
    setTestingMap((prev) => ({ ...prev, [name]: true }));
    try {
      const res = await api.testAdminMCPServer(name);
      setTestResults((prev) => ({ ...prev, [name]: res }));
      setInspectToolsServer(name);
    } catch (err: unknown) {
      setTestResults((prev) => ({
        ...prev,
        [name]: {
          ok: false,
          latency_ms: 0,
          message: err instanceof Error ? err.message : 'Discovery failed',
          tools: [],
        },
      }));
      setInspectToolsServer(name);
    } finally {
      setTestingMap((prev) => ({ ...prev, [name]: false }));
    }
  };

  const copyGatewayUrl = async (name: string) => {
    const clientUrl = `${origin}/mcp/${name}`;
    try {
      await navigator.clipboard.writeText(clientUrl);
      setCopiedServerUrl(name);
      window.setTimeout(() => {
        setCopiedServerUrl((prev) => (prev === name ? null : prev));
      }, 1500);
    } catch {
      // ignore
    }
  };

  const showServers = sectionMode === 'all' || sectionMode === 'servers';
  const showAudit = sectionMode === 'all' || sectionMode === 'audit';
  const hasAuditFilters = Boolean(
    auditServer || auditSubject || auditTool || auditStatus,
  );

  const inspectedDiscovery = inspectToolsServer
    ? testResults[inspectToolsServer] ?? null
    : null;

  return (
    <div className="ap-page">
      <header className="ap-page-header">
        <div className="ap-page-title-row">
          <div>
            <h1 className="ap-page-title">
              {sectionMode === 'servers'
                ? 'MCP Servers'
                : sectionMode === 'audit'
                  ? 'MCP Audit Logs'
                  : 'MCP Gateway'}
            </h1>
            <p className="ap-page-subtitle">
              Proxy remote Model Context Protocol servers over Tailnet with centralized credentials, capability grants, and per-tool audit logs.
            </p>
          </div>
        </div>

        <div className="ap-filter-bar">
          <div className="ap-filter-group">
            <SegmentedControl
              ariaLabel="MCP Gateway section"
              value={sectionMode}
              onChange={handleSectionSelect}
              options={[
                { value: 'all', label: 'All' },
                { value: 'servers', label: `MCP Servers (${servers.length})` },
                { value: 'audit', label: 'MCP Audit' },
              ]}
            />
          </div>

          <div className="ap-filter-group">
            <button
              type="button"
              className="ap-btn"
              onClick={() => {
                void loadServers();
                setAuditTick((n) => n + 1);
              }}
            >
              <RefreshIcon />
              <span>Refresh</span>
            </button>
            <button
              type="button"
              className="ap-btn ap-btn-primary"
              onClick={openCreateServer}
            >
              <PlusIcon />
              <span>Add MCP Server</span>
            </button>
          </div>
        </div>
      </header>

      {pageError && (
        <div className="ap-alert ap-alert--danger" role="alert">
          <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{pageError}</span>
        </div>
      )}

      {showServers && (
        <section className="ap-card" aria-label="Upstream MCP servers">
          <div className="ap-card-header">
            <div>
              <h2 className="ap-card-title">Upstream MCP Servers ({servers.length})</h2>
              <p className="ap-card-subtitle">
                Callers connect to <span className="ap-mono">{origin}/mcp/&lt;name&gt;</span>; Headlamp enforces <span className="ap-mono">mcp_tools</span> grants and injects upstream auth.
              </p>
            </div>
          </div>

          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Server & Client Endpoint</th>
                  <th>Origin</th>
                  <th>Upstream & Transport</th>
                  <th>Auth</th>
                  <th>Enabled</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {servers.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ color: 'var(--ap-text-muted)', padding: '26px 14px', textAlign: 'center' }}>
                      No MCP servers configured.
                    </td>
                  </tr>
                ) : (
                  servers.map((srv) => {
                    const isYaml = srv.source === 'config';
                    const isTesting = Boolean(testingMap[srv.name]);
                    const probe = testResults[srv.name];
                    const clientUrl = `${origin}/mcp/${srv.name}`;

                    return (
                      <tr key={srv.name} className="ap-row">
                        <td style={{ maxWidth: 165 }}>
                          <div
                            className="ap-mono ap-truncate"
                            style={{ fontWeight: 600 }}
                            title={srv.name}
                          >
                            {srv.name}
                          </div>
                          <button
                            type="button"
                            className="ap-btn ap-btn-ghost ap-btn-sm"
                            style={{
                              height: 20,
                              padding: '0 4px',
                              marginLeft: -4,
                              fontSize: 11,
                              maxWidth: '100%',
                            }}
                            title={`Copy client endpoint ${clientUrl}`}
                            onClick={() => void copyGatewayUrl(srv.name)}
                          >
                            {copiedServerUrl === srv.name ? (
                              <CheckIcon size={11} />
                            ) : (
                              <CopyIcon size={11} />
                            )}
                            <span className="ap-mono ap-truncate">
                              /mcp/{srv.name}
                            </span>
                          </button>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <SourceBadge source={srv.source} />
                        </td>
                        <td style={{ maxWidth: 185 }}>
                          <div
                            className="ap-mono ap-truncate"
                            style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}
                            title={srv.url}
                          >
                            {srv.url}
                          </div>
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 5,
                              marginTop: 2,
                              minWidth: 0,
                            }}
                          >
                            <span className="ap-badge ap-badge--blue">
                              {srv.transport === 'sse' ? 'SSE' : 'Streamable HTTP'}
                            </span>
                            {probe && (
                              <button
                                type="button"
                                className={`ap-badge ap-tabular ${
                                  probe.ok ? 'ap-badge--green' : 'ap-badge--red'
                                }`}
                                style={{ cursor: 'pointer', flexShrink: 0 }}
                                title={probe.message}
                                onClick={() => setInspectToolsServer(srv.name)}
                              >
                                {probe.ok
                                  ? `${formatLatency(probe.latency_ms)} · ${
                                      probe.tools?.length ?? 0
                                    }t`
                                  : 'Err'}
                              </button>
                            )}
                          </div>
                        </td>
                        <td style={{ maxWidth: 145 }}>
                          <div
                            style={{
                              display: 'flex',
                              flexDirection: 'column',
                              alignItems: 'flex-start',
                              gap: 3,
                              minWidth: 0,
                            }}
                          >
                            <span
                              className="ap-badge ap-truncate"
                              style={{ maxWidth: '100%', display: 'inline-block' }}
                              title={
                                srv.auth_type === 'header' && srv.auth_header
                                  ? `header:${srv.auth_header}`
                                  : srv.auth_type || 'none'
                              }
                            >
                              {srv.auth_type === 'header' && srv.auth_header
                                ? `header:${srv.auth_header}`
                                : srv.auth_type || 'none'}
                            </span>
                            {srv.auth_type &&
                              srv.auth_type !== 'none' &&
                              srv.has_auth_token && (
                                <span
                                  className="ap-mono ap-truncate"
                                  style={{
                                    fontSize: 11,
                                    color: 'var(--ap-text-muted)',
                                    maxWidth: '100%',
                                  }}
                                  title={srv.auth_token_preview || 'Stored'}
                                >
                                  {srv.auth_token_preview || '****'}
                                </span>
                              )}
                          </div>
                        </td>
                        <td>
                          <Toggle
                            checked={srv.enabled}
                            disabled={isYaml || Boolean(togglingServers[srv.name])}
                            title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                            onChange={(next) => void handleToggleServer(srv, next)}
                            label={`Enable MCP server ${srv.name}`}
                          />
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="ap-row-actions">
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm"
                              disabled={isTesting}
                              onClick={() => void handleTestServer(srv.name)}
                              title={`Test connectivity & discover tools on ${srv.name}`}
                            >
                              <PlayIcon />
                              <span>{isTesting ? 'Probing' : 'Test'}</span>
                            </button>
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                              disabled={isYaml}
                              aria-label={`Edit ${srv.name}`}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${srv.name}`}
                              onClick={() => openEditServer(srv)}
                            >
                              <EditIcon />
                              <span className="ap-action-label">Edit</span>
                            </button>
                            <ConfirmDeleteButton
                              itemName={srv.name}
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${srv.name}`}
                              onConfirm={() => handleDeleteServer(srv)}
                            />
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {showAudit && (
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
                onChange={(e) => {
                  setAuditServer(e.target.value);
                  setAuditOffset(0);
                }}
              />
              <input
                className="ap-input ap-input--sm"
                style={{ width: 132 }}
                placeholder="Caller / Subject"
                aria-label="Filter MCP logs by caller"
                value={auditSubject}
                onChange={(e) => {
                  setAuditSubject(e.target.value);
                  setAuditOffset(0);
                }}
              />
              <input
                className="ap-input ap-input--sm ap-mono"
                style={{ width: 126 }}
                placeholder="Tool name"
                aria-label="Filter MCP logs by tool"
                value={auditTool}
                onChange={(e) => {
                  setAuditTool(e.target.value);
                  setAuditOffset(0);
                }}
              />
              <select
                className="ap-select ap-select--sm"
                style={{ width: 126 }}
                value={auditStatus}
                onChange={(e) => {
                  setAuditStatus(e.target.value);
                  setAuditOffset(0);
                }}
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
                  onClick={() => {
                    setAuditServer('');
                    setAuditSubject('');
                    setAuditTool('');
                    setAuditStatus('');
                    setAuditOffset(0);
                  }}
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
                      onClick={() => setSelectedLog(row)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') setSelectedLog(row);
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
                            setSelectedLog(row);
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

          {(auditOffset > 0 || auditLogs.length >= AUDIT_LIMIT) && (
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
                  onClick={() => setAuditOffset(Math.max(0, auditOffset - AUDIT_LIMIT))}
                >
                  Previous
                </button>
                <button
                  type="button"
                  className="ap-btn ap-btn-sm"
                  disabled={auditLogs.length < AUDIT_LIMIT}
                  onClick={() => setAuditOffset(auditOffset + AUDIT_LIMIT)}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </section>
      )}

      {/* Add / Edit MCP Server Modal */}
      <Modal
        open={modalOpen}
        title={
          editingServer
            ? `Edit MCP Server (${editingServer.name})`
            : 'Add MCP Server'
        }
        onClose={() => setModalOpen(false)}
        error={modalError}
      >
        <form
          noValidate
          onSubmit={handleSaveServer}
          style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
        >
          <div className="ap-form-grid">
            <label className="ap-field">
              <span className="ap-label">Server Name</span>
              <input
                className="ap-input ap-mono"
                required
                disabled={Boolean(editingServer)}
                value={srvName}
                onChange={(e) => setSrvName(e.target.value)}
                placeholder="github-internal"
              />
            </label>

            <label className="ap-field">
              <span className="ap-label">Transport</span>
              <select
                className="ap-select"
                value={srvTransport}
                onChange={(e) => setSrvTransport(e.target.value)}
              >
                <option value="streamable_http">streamable_http (MCP HTTP)</option>
                <option value="sse">sse (Legacy HTTP+SSE)</option>
              </select>
            </label>
          </div>

          <label className="ap-field">
            <span className="ap-label">Upstream MCP Endpoint URL</span>
            <input
              className="ap-input ap-mono"
              required
              value={srvUrl}
              onChange={(e) => setSrvUrl(e.target.value)}
              placeholder="https://mcp.internal.example.com/mcp"
            />
          </label>

          <div className="ap-form-grid">
            <label className="ap-field">
              <span className="ap-label">Upstream Auth Type</span>
              <select
                className="ap-select"
                value={srvAuthType}
                onChange={(e) => setSrvAuthType(e.target.value)}
              >
                <option value="none">none</option>
                <option value="bearer">bearer (Authorization: Bearer)</option>
                <option value="header">header (Custom Header)</option>
                <option value="basic">basic (Authorization: Basic)</option>
              </select>
            </label>

            {srvAuthType === 'header' && (
              <label className="ap-field">
                <span className="ap-label">Custom Header Name</span>
                <input
                  className="ap-input ap-mono"
                  required
                  value={srvAuthHeader}
                  onChange={(e) => setSrvAuthHeader(e.target.value)}
                  placeholder="X-API-Key"
                />
              </label>
            )}
          </div>

          {srvAuthType !== 'none' && (
            <label className="ap-field">
              <span className="ap-label">Auth Token / Credential (AES-GCM encrypted)</span>
              <input
                type="password"
                className="ap-input ap-mono"
                value={srvAuthToken}
                onChange={(e) => {
                  setSrvAuthToken(e.target.value);
                  if (e.target.value) setSrvClearToken(false);
                }}
                placeholder={
                  editingServer?.has_auth_token
                    ? `${editingServer.auth_token_preview || 'Stored'} — leave blank to keep`
                    : 'Secret token...'
                }
              />
            </label>
          )}

          {editingServer?.has_auth_token && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span className="ap-label">Clear stored auth token</span>
              <Toggle
                checked={srvClearToken}
                onChange={setSrvClearToken}
                label="Clear stored auth token"
              />
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="ap-label">Enabled</span>
            <Toggle
              checked={srvEnabled}
              onChange={setSrvEnabled}
              label="MCP Server Enabled"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, paddingTop: 6 }}>
            <button
              type="button"
              className="ap-btn"
              onClick={() => setModalOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="ap-btn ap-btn-primary"
              disabled={savingServer}
            >
              {savingServer ? 'Saving...' : 'Save MCP Server'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Discovered Tools Drawer */}
      <Drawer
        open={Boolean(inspectToolsServer && inspectedDiscovery)}
        title={
          inspectToolsServer
            ? `MCP Discovery · ${inspectToolsServer}`
            : 'MCP Discovery'
        }
        subtitle={inspectedDiscovery?.message}
        onClose={() => setInspectToolsServer(null)}
      >
        {inspectedDiscovery && (
          <>
            {!inspectedDiscovery.ok && inspectedDiscovery.message && (
              <div className="ap-alert ap-alert--danger" role="alert">
                <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
                <span>{inspectedDiscovery.message}</span>
              </div>
            )}

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span
                className={`ap-badge ${
                  inspectedDiscovery.ok ? 'ap-badge--green' : 'ap-badge--red'
                }`}
              >
                {inspectedDiscovery.ok ? 'Connected' : 'Failed'}
              </span>
              <span className="ap-badge ap-tabular">
                {formatLatency(inspectedDiscovery.latency_ms)}
              </span>
              <span className="ap-badge ap-tabular">
                {(inspectedDiscovery.tools ?? []).length} discovered tools
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
                    {(inspectedDiscovery.tools ?? []).length === 0 ? (
                      <tr>
                        <td colSpan={2} style={{ color: 'var(--ap-text-muted)', padding: 18, textAlign: 'center' }}>
                          No tools reported by this MCP server.
                        </td>
                      </tr>
                    ) : (
                      (inspectedDiscovery.tools ?? []).map((t) => (
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

      {/* MCP Audit Log Inspector Drawer */}
      <Drawer
        open={Boolean(selectedLog)}
        title={
          selectedLog
            ? `MCP Call · ${selectedLog.server_name}/${selectedLog.tool_name || selectedLog.method}`
            : 'MCP Call'
        }
        subtitle={selectedLog ? selectedLog.request_id || selectedLog.id : undefined}
        onClose={() => setSelectedLog(null)}
      >
        {selectedLog && (
          <>
            {selectedLog.error_message && (
              <div className="ap-alert ap-alert--danger">
                <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
                <span>{selectedLog.error_message}</span>
              </div>
            )}

            <section className="ap-card">
              <div className="ap-card-header">
                <h3 className="ap-card-title">Call Metadata</h3>
                <span
                  className={`ap-badge ${
                    selectedLog.status === 'ok'
                      ? 'ap-badge--green'
                      : selectedLog.status === 'denied'
                        ? 'ap-badge--amber'
                        : 'ap-badge--red'
                  }`}
                >
                  {selectedLog.status}
                </span>
              </div>
              <div className="ap-table-wrap">
                <table className="ap-table">
                  <tbody>
                    <tr className="ap-row">
                      <td style={{ color: 'var(--ap-text-secondary)', width: 130 }}>Timestamp</td>
                      <td className="ap-tabular">{formatTimestamp(selectedLog.created_at)}</td>
                    </tr>
                    <tr className="ap-row">
                      <td style={{ color: 'var(--ap-text-secondary)' }}>Caller</td>
                      <td>
                        <strong>{selectedLog.subject}</strong>{' '}
                        <span className="ap-mono" style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}>
                          ({selectedLog.node_name || 'tailnet'} · {selectedLog.node_ip || '—'})
                        </span>
                      </td>
                    </tr>
                    <tr className="ap-row">
                      <td style={{ color: 'var(--ap-text-secondary)' }}>MCP Server</td>
                      <td className="ap-mono">{selectedLog.server_name}</td>
                    </tr>
                    <tr className="ap-row">
                      <td style={{ color: 'var(--ap-text-secondary)' }}>Method & Tool</td>
                      <td className="ap-mono">
                        {selectedLog.method}
                        {selectedLog.tool_name ? ` → ${selectedLog.tool_name}` : ''}
                      </td>
                    </tr>
                    <tr className="ap-row">
                      <td style={{ color: 'var(--ap-text-secondary)' }}>Latency</td>
                      <td className="ap-tabular">{formatLatency(selectedLog.latency_ms)}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            <CodeBlock
              label="Arguments Preview (redacted)"
              code={formatPrettyJson(selectedLog.arguments_preview) || '(no arguments)'}
              highlightRedactions
            />
          </>
        )}
      </Drawer>
    </div>
  );
}
