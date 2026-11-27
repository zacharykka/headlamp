import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  CheckIcon,
  CopyIcon,
  EditIcon,
  PlayIcon,
  PlusIcon,
  RefreshIcon,
} from '../components/ApertureIcons';
import {
  ConfirmDeleteButton,
  SegmentedControl,
  SourceBadge,
  Toggle,
  YAML_LOCK_TOOLTIP,
} from '../components/Primitives';
import { formatLatency } from '../lib/format';
import type {
  MCPAuditLog,
  MCPServerItem,
  MCPServerTestResult,
} from '../types/api';
import { MCPAuditSection } from './mcp/MCPAuditSection';
import {
  MCPAuditDetailDrawer,
  MCPDiscoveryDrawer,
} from './mcp/MCPDrawers';
import { MCPServerModal } from './mcp/MCPServerModal';

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
  const [editingServer, setEditingServer] = useState<MCPServerItem | null>(null);

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
    setModalOpen(true);
  };

  const openEditServer = (item: MCPServerItem) => {
    if (item.source === 'config') return;
    setEditingServer(item);
    setModalOpen(true);
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
        <MCPAuditSection
          auditServer={auditServer}
          auditSubject={auditSubject}
          auditTool={auditTool}
          auditStatus={auditStatus}
          auditOffset={auditOffset}
          auditLimit={AUDIT_LIMIT}
          auditLogs={auditLogs}
          loadingAudit={loadingAudit}
          onServerChange={(val) => {
            setAuditServer(val);
            setAuditOffset(0);
          }}
          onSubjectChange={(val) => {
            setAuditSubject(val);
            setAuditOffset(0);
          }}
          onToolChange={(val) => {
            setAuditTool(val);
            setAuditOffset(0);
          }}
          onStatusChange={(val) => {
            setAuditStatus(val);
            setAuditOffset(0);
          }}
          onClearFilters={() => {
            setAuditServer('');
            setAuditSubject('');
            setAuditTool('');
            setAuditStatus('');
            setAuditOffset(0);
          }}
          onOffsetChange={setAuditOffset}
          onSelectLog={setSelectedLog}
        />
      )}

      {modalOpen && (
        <MCPServerModal
          editingServer={editingServer}
          onClose={() => setModalOpen(false)}
          onSaved={loadServers}
        />
      )}

      <MCPDiscoveryDrawer
        serverName={inspectToolsServer}
        discovery={inspectedDiscovery}
        onClose={() => setInspectToolsServer(null)}
      />

      <MCPAuditDetailDrawer
        log={selectedLog}
        onClose={() => setSelectedLog(null)}
      />
    </div>
  );
}
