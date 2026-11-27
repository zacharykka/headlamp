import { useState, type FormEvent } from 'react';
import { api } from '../../api/client';
import { Modal, Toggle } from '../../components/Primitives';
import type { MCPServerItem, MCPServerUpsertPayload } from '../../types/api';

interface MCPServerModalProps {
  editingServer: MCPServerItem | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

export function MCPServerModal({
  editingServer,
  onClose,
  onSaved,
}: MCPServerModalProps) {
  const [modalError, setModalError] = useState<string | null>(null);
  const [srvName, setSrvName] = useState(editingServer?.name ?? '');
  const [srvUrl, setSrvUrl] = useState(editingServer?.url ?? '');
  const [srvTransport, setSrvTransport] = useState(
    editingServer?.transport || 'streamable_http',
  );
  const [srvAuthType, setSrvAuthType] = useState(editingServer?.auth_type || 'none');
  const [srvAuthHeader, setSrvAuthHeader] = useState(
    editingServer?.auth_header || 'X-API-Key',
  );
  const [srvAuthToken, setSrvAuthToken] = useState('');
  const [srvClearToken, setSrvClearToken] = useState(false);
  const [srvEnabled, setSrvEnabled] = useState(editingServer?.enabled ?? true);
  const [savingServer, setSavingServer] = useState(false);

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
      onClose();
      await onSaved();
    } catch (err: unknown) {
      setModalError(
        err instanceof Error ? err.message : 'Failed to save MCP server',
      );
    } finally {
      setSavingServer(false);
    }
  };

  return (
    <Modal
      open
      title={
        editingServer
          ? `Edit MCP Server (${editingServer.name})`
          : 'Add MCP Server'
      }
      onClose={onClose}
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
            onClick={onClose}
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
  );
}
