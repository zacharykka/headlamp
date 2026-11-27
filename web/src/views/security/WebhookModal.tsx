import { useEffect, useState, type FormEvent } from 'react';
import { api } from '../../api/client';
import { Modal, Toggle } from '../../components/Primitives';
import type { WebhookItem, WebhookUpsertPayload } from '../../types/api';

export const WEBHOOK_EVENTS = [
  '*',
  'budget.threshold',
  'budget.exceeded',
  'guardrail.triggered',
  'upstream.fallback',
  'upstream.error',
];

interface WebhookModalProps {
  open: boolean;
  editingWebhook: WebhookItem | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

export function WebhookModal({
  open,
  editingWebhook,
  onClose,
  onSaved,
}: WebhookModalProps) {
  const [modalError, setModalError] = useState<string | null>(null);
  const [whId, setWhId] = useState('');
  const [whName, setWhName] = useState('');
  const [whUrl, setWhUrl] = useState('');
  const [whType, setWhType] = useState('async_event');
  const [whSecret, setWhSecret] = useState('');
  const [whClearSecret, setWhClearSecret] = useState(false);
  const [whEvents, setWhEvents] = useState<string[]>(['guardrail.triggered', 'budget.exceeded']);
  const [whTimeout, setWhTimeout] = useState('2000');
  const [whFailOpen, setWhFailOpen] = useState(true);
  const [whEnabled, setWhEnabled] = useState(true);
  const [savingWebhook, setSavingWebhook] = useState(false);

  useEffect(() => {
    if (!open) return;
    setModalError(null);
    if (editingWebhook) {
      setWhId(editingWebhook.id);
      setWhName(editingWebhook.name);
      setWhUrl(editingWebhook.url);
      setWhType(editingWebhook.type);
      setWhSecret('');
      setWhClearSecret(false);
      setWhEvents(editingWebhook.events ?? []);
      setWhTimeout(String(editingWebhook.timeout_ms || 2000));
      setWhFailOpen(editingWebhook.fail_open);
      setWhEnabled(editingWebhook.enabled);
    } else {
      setWhId('');
      setWhName('');
      setWhUrl('');
      setWhType('async_event');
      setWhSecret('');
      setWhClearSecret(false);
      setWhEvents(['guardrail.triggered', 'budget.exceeded']);
      setWhTimeout('2000');
      setWhFailOpen(true);
      setWhEnabled(true);
    }
  }, [open, editingWebhook]);

  const toggleWebhookEvent = (evt: string) => {
    setWhEvents((prev) =>
      prev.includes(evt) ? prev.filter((item) => item !== evt) : [...prev, evt],
    );
  };

  const handleSaveWebhook = async (event: FormEvent) => {
    event.preventDefault();
    setModalError(null);

    if (whId.trim().includes('/')) {
      setModalError('Webhook ID must not contain "/".');
      return;
    }
    if (!whName.trim()) {
      setModalError('Webhook name is required.');
      return;
    }
    if (!whUrl.trim()) {
      setModalError('Target HTTP/HTTPS URL is required.');
      return;
    }
    const parsedTimeout = Number(whTimeout);
    if (!Number.isFinite(parsedTimeout) || parsedTimeout <= 0) {
      setModalError('Timeout (ms) must be a positive number.');
      return;
    }

    setSavingWebhook(true);
    const payload: WebhookUpsertPayload = {
      id: whId.trim(),
      name: whName.trim(),
      url: whUrl.trim(),
      type: whType,
      events: whType === 'async_event' ? whEvents : [],
      timeout_ms: Math.floor(parsedTimeout),
      fail_open: whFailOpen,
      enabled: whEnabled,
    };
    if (whSecret.trim()) {
      payload.secret = whSecret.trim();
    }
    if (editingWebhook && whClearSecret) {
      payload.clear_secret = true;
    }

    try {
      if (editingWebhook) {
        await api.updateWebhook(editingWebhook.id, payload);
      } else {
        await api.createWebhook(payload);
      }
      onClose();
      await onSaved();
    } catch (err: unknown) {
      setModalError(err instanceof Error ? err.message : 'Failed to save webhook');
    } finally {
      setSavingWebhook(false);
    }
  };

  return (
    <Modal
      open={open}
      title={editingWebhook ? `Edit Webhook (${editingWebhook.name})` : 'Add Webhook'}
      onClose={onClose}
      maxWidth={600}
      error={modalError}
    >
      <form
        onSubmit={handleSaveWebhook}
        style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
      >
        <div className="ap-form-grid">
          <label className="ap-field">
            <span className="ap-label">Webhook ID</span>
            <input
              className="ap-input ap-mono"
              disabled={Boolean(editingWebhook)}
              value={whId}
              onChange={(e) => setWhId(e.target.value)}
              placeholder="Auto-generated if blank"
            />
          </label>
          <label className="ap-field">
            <span className="ap-label">Display Name</span>
            <input
              className="ap-input"
              required
              value={whName}
              onChange={(e) => setWhName(e.target.value)}
              placeholder="SecOps Alerts"
            />
          </label>
        </div>

        <div className="ap-form-grid">
          <label className="ap-field">
            <span className="ap-label">Mode</span>
            <select
              className="ap-select"
              value={whType}
              onChange={(e) => setWhType(e.target.value)}
            >
              <option value="async_event">async_event (non-blocking notifications)</option>
              <option value="sync_review">sync_review (pre-request allow/block)</option>
            </select>
          </label>
          <label className="ap-field">
            <span className="ap-label">Timeout (ms)</span>
            <input
              type="number"
              min={100}
              className="ap-input ap-tabular"
              value={whTimeout}
              onChange={(e) => setWhTimeout(e.target.value)}
            />
          </label>
        </div>

        <label className="ap-field">
          <span className="ap-label">Target Endpoint URL</span>
          <input
            className="ap-input ap-mono"
            required
            value={whUrl}
            onChange={(e) => setWhUrl(e.target.value)}
            placeholder="https://secops.internal/hooks/headlamp"
          />
        </label>

        <label className="ap-field">
          <span className="ap-label">HMAC-SHA256 Signing Secret (optional)</span>
          <input
            type="password"
            className="ap-input ap-mono"
            value={whSecret}
            onChange={(e) => {
              setWhSecret(e.target.value);
              if (e.target.value) setWhClearSecret(false);
            }}
            placeholder={
              editingWebhook?.has_secret
                ? 'Signed — leave blank to keep current secret'
                : 'whsec_...'
            }
          />
        </label>

        {editingWebhook?.has_secret && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="ap-label">Clear stored HMAC secret</span>
            <Toggle
              checked={whClearSecret}
              onChange={setWhClearSecret}
              label="Clear stored HMAC secret"
            />
          </div>
        )}

        {whType === 'async_event' ? (
          <div className="ap-field">
            <span className="ap-label">Subscribed Events</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {WEBHOOK_EVENTS.map((evt) => {
                const selected = whEvents.includes(evt);
                return (
                  <button
                    key={evt}
                    type="button"
                    className={`ap-btn ap-btn-sm ap-mono ${
                      selected ? 'ap-btn-primary' : ''
                    }`}
                    onClick={() => toggleWebhookEvent(evt)}
                  >
                    {evt}
                  </button>
                );
              })}
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div className="ap-label">Fail Open on Webhook Timeout / Error</div>
              <div className="ap-hint">Allow requests through when the review service is unreachable.</div>
            </div>
            <Toggle
              checked={whFailOpen}
              onChange={setWhFailOpen}
              label="Fail Open"
            />
          </div>
        )}

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="ap-label">Enabled</span>
          <Toggle
            checked={whEnabled}
            onChange={setWhEnabled}
            label="Webhook Enabled"
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
            disabled={savingWebhook}
          >
            {savingWebhook ? 'Saving...' : 'Save Webhook'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
