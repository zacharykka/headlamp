import { useState, type FormEvent } from 'react';
import { api } from '../../api/client';
import { Modal, Toggle } from '../../components/Primitives';
import type { ProviderItem, ProviderUpsertPayload } from '../../types/api';

export const DEFAULT_BASE_URLS: Record<string, string> = {
  openai: 'https://api.openai.com',
  anthropic: 'https://api.anthropic.com',
  gemini: 'https://generativelanguage.googleapis.com',
  ollama: 'http://127.0.0.1:11434',
};

interface ProviderModalProps {
  editingProvider: ProviderItem | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

export function ProviderModal({
  editingProvider,
  onClose,
  onSaved,
}: ProviderModalProps) {
  const [modalError, setModalError] = useState<string | null>(null);
  const [provName, setProvName] = useState(editingProvider?.name ?? '');
  const [provType, setProvType] = useState(editingProvider?.type ?? 'openai');
  const [provBaseURL, setProvBaseURL] = useState(
    editingProvider?.base_url ?? DEFAULT_BASE_URLS.openai,
  );
  const [provAPIKey, setProvAPIKey] = useState('');
  const [provClearKey, setProvClearKey] = useState(false);
  const [provModels, setProvModels] = useState(
    editingProvider ? (editingProvider.models ?? []).join(', ') : '',
  );
  const [provPassthrough, setProvPassthrough] = useState(editingProvider?.passthrough ?? false);
  const [provEnabled, setProvEnabled] = useState(editingProvider?.enabled ?? true);
  const [savingProvider, setSavingProvider] = useState(false);

  const handleSaveProvider = async (event: FormEvent) => {
    event.preventDefault();
    setModalError(null);

    const trimmedName = provName.trim();
    if (!trimmedName) {
      setModalError('Provider name is required.');
      return;
    }
    if (trimmedName.includes('/')) {
      setModalError('Provider name must not contain "/".');
      return;
    }

    setSavingProvider(true);
    const payload: ProviderUpsertPayload = {
      name: trimmedName,
      type: provType,
      base_url: provBaseURL.trim(),
      passthrough: provPassthrough,
      models: provModels
        .split(/[,\n]/)
        .map((m) => m.trim())
        .filter(Boolean),
      enabled: provEnabled,
    };
    if (provAPIKey.trim()) {
      payload.api_key = provAPIKey.trim();
    }
    if (editingProvider && provClearKey) {
      payload.clear_api_key = true;
    }

    try {
      if (editingProvider) {
        await api.updateProvider(editingProvider.name, payload);
      } else {
        await api.createProvider(payload);
      }
      onClose();
      await onSaved();
    } catch (err: unknown) {
      setModalError(
        err instanceof Error ? err.message : 'Failed to save provider',
      );
    } finally {
      setSavingProvider(false);
    }
  };

  return (
    <Modal
      open
      title={editingProvider ? `Edit Provider (${editingProvider.name})` : 'Add Provider'}
      onClose={onClose}
      error={modalError}
    >
      <form
        onSubmit={handleSaveProvider}
        style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
      >
        <div className="ap-form-grid">
          <label className="ap-field">
            <span className="ap-label">Provider Name</span>
            <input
              className="ap-input ap-mono"
              required
              disabled={Boolean(editingProvider)}
              value={provName}
              onChange={(e) => setProvName(e.target.value)}
              placeholder="anthropic-prod"
            />
          </label>

          <label className="ap-field">
            <span className="ap-label">Protocol</span>
            <select
              className="ap-select"
              value={provType}
              onChange={(e) => {
                const next = e.target.value;
                setProvType(next);
                if (!editingProvider && DEFAULT_BASE_URLS[next]) {
                  setProvBaseURL(DEFAULT_BASE_URLS[next]);
                }
              }}
            >
              <option value="openai">OpenAI (/v1)</option>
              <option value="anthropic">Anthropic (/v1/messages)</option>
              <option value="gemini">Gemini (/v1beta)</option>
              <option value="ollama">Ollama (Local / HTTP)</option>
            </select>
          </label>
        </div>

        <label className="ap-field">
          <span className="ap-label">Upstream Base URL</span>
          <input
            className="ap-input ap-mono"
            required
            value={provBaseURL}
            onChange={(e) => setProvBaseURL(e.target.value)}
            placeholder="https://api.anthropic.com"
          />
        </label>

        <label className="ap-field">
          <span className="ap-label">Upstream API Key (encrypted at rest)</span>
          <input
            type="password"
            className="ap-input ap-mono"
            value={provAPIKey}
            onChange={(e) => {
              setProvAPIKey(e.target.value);
              if (e.target.value) setProvClearKey(false);
            }}
            placeholder={
              editingProvider?.has_api_key
                ? `${editingProvider.api_key_preview || 'Stored'} — leave blank to keep`
                : 'sk-...'
            }
          />
        </label>

        {editingProvider?.has_api_key && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="ap-label">Clear stored API key</span>
            <Toggle
              checked={provClearKey}
              onChange={setProvClearKey}
              label="Clear stored API key"
            />
          </div>
        )}

        <label className="ap-field">
          <span className="ap-label">Advertised Models (optional, comma-separated)</span>
          <input
            className="ap-input ap-mono"
            value={provModels}
            onChange={(e) => setProvModels(e.target.value)}
            placeholder="claude-sonnet-4-20250514, claude-opus-4-20250514"
          />
        </label>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div className="ap-label">Client Key Passthrough</div>
            <div className="ap-hint">Forward caller Authorization / x-api-key header when gateway has no stored key.</div>
          </div>
          <Toggle
            checked={provPassthrough}
            onChange={setProvPassthrough}
            label="Allow Client Key Passthrough"
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="ap-label">Enabled</span>
          <Toggle
            checked={provEnabled}
            onChange={setProvEnabled}
            label="Provider Enabled"
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
            disabled={savingProvider}
          >
            {savingProvider ? 'Saving...' : 'Save Provider'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
