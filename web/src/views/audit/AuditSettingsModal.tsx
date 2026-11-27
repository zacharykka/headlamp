import {
  useEffect,
  useRef,
  useState,
  type Dispatch,
  type FormEvent,
  type SetStateAction,
} from 'react';
import { api } from '../../api/client';
import { CheckIcon, TrashIcon } from '../../components/ApertureIcons';
import { Modal, Toggle } from '../../components/Primitives';
import { formatNumber } from '../../lib/format';
import type { AuditSettings } from '../../types/api';

interface AuditSettingsModalProps {
  settings: AuditSettings;
  settingsDirtyRef: { current: boolean };
  onSettingsChange: Dispatch<SetStateAction<AuditSettings>>;
  onClose: () => void;
}

export function AuditSettingsModal({
  settings,
  settingsDirtyRef,
  onSettingsChange,
  onClose,
}: AuditSettingsModalProps) {
  const [modalError, setModalError] = useState<string | null>(null);
  const [retentionDaysInput, setRetentionDaysInput] = useState(
    String(settings.retention_days),
  );
  const [savingSettings, setSavingSettings] = useState(false);
  const [purging, setPurging] = useState(false);
  const [confirmZeroPurge, setConfirmZeroPurge] = useState(false);
  const [purgeNotice, setPurgeNotice] = useState<string | null>(null);

  const settingsLoadSeqRef = useRef(0);
  const zeroPurgeTimerRef = useRef<number | null>(null);

  const clearZeroPurgeTimer = () => {
    if (zeroPurgeTimerRef.current !== null) {
      window.clearTimeout(zeroPurgeTimerRef.current);
      zeroPurgeTimerRef.current = null;
    }
  };

  useEffect(() => {
    let active = true;
    settingsDirtyRef.current = false;
    clearZeroPurgeTimer();
    const seq = ++settingsLoadSeqRef.current;

    void api
      .getAuditSettings()
      .then((current) => {
        if (active && seq === settingsLoadSeqRef.current && !settingsDirtyRef.current) {
          onSettingsChange(current);
          setRetentionDaysInput(String(current.retention_days));
        }
      })
      .catch((err: unknown) => {
        if (active && seq === settingsLoadSeqRef.current) {
          setModalError(
            err instanceof Error ? err.message : 'Failed to load current audit settings',
          );
        }
      });

    return () => {
      active = false;
      clearZeroPurgeTimer();
    };
  }, []);

  const parseRetentionInput = (): { days: number; error: string | null } => {
    const trimmed = retentionDaysInput.trim();
    const parsed = trimmed === '' ? 0 : Number(trimmed);
    if (!Number.isFinite(parsed) || parsed < 0) {
      return { days: 0, error: 'Retention days must be an integer >= 0.' };
    }
    return { days: Math.floor(parsed), error: null };
  };

  const handleSaveSettings = async (event: FormEvent) => {
    event.preventDefault();
    setModalError(null);
    const { days, error } = parseRetentionInput();
    if (error) {
      setModalError(error);
      return;
    }

    setSavingSettings(true);
    try {
      const updated = await api.updateAuditSettings({
        store_payloads: settings.store_payloads,
        retention_days: days,
      });
      onSettingsChange(updated);
      setRetentionDaysInput(String(updated.retention_days));
      onClose();
    } catch (err: unknown) {
      setModalError(
        err instanceof Error ? err.message : 'Failed to save audit storage settings',
      );
    } finally {
      setSavingSettings(false);
    }
  };

  const handlePurge = async () => {
    setModalError(null);
    setPurgeNotice(null);
    const { days, error } = parseRetentionInput();
    if (error) {
      setModalError(error);
      return;
    }
    if (days === 0 && !confirmZeroPurge) {
      setConfirmZeroPurge(true);
      clearZeroPurgeTimer();
      zeroPurgeTimerRef.current = window.setTimeout(() => {
        zeroPurgeTimerRef.current = null;
        setConfirmZeroPurge(false);
      }, 4000);
      return;
    }
    clearZeroPurgeTimer();
    setConfirmZeroPurge(false);
    setPurging(true);
    try {
      const res = await api.purgeAuditPayloads(days);
      setPurgeNotice(
        days === 0
          ? `Purged all ${formatNumber(res.purged)} stored payloads`
          : `Purged ${formatNumber(res.purged)} payloads older than ${days}d`,
      );
    } catch (err: unknown) {
      setModalError(
        err instanceof Error ? err.message : 'Failed to purge audit payloads',
      );
    } finally {
      setPurging(false);
    }
  };

  return (
    <Modal
      open
      title="Audit Storage & Payload Retention"
      onClose={onClose}
      error={modalError}
    >
      <form
        onSubmit={handleSaveSettings}
        style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div>
            <div className="ap-label">Store Request & Response Payloads</div>
            <div className="ap-hint">
              Stores sanitized headers and guardrail-redacted bodies (capped at 256 KB) in local SQLite.
            </div>
          </div>
          <Toggle
            checked={settings.store_payloads}
            onChange={(next) => {
              settingsDirtyRef.current = true;
              onSettingsChange((prev) => ({ ...prev, store_payloads: next }));
            }}
            label="Store Request & Response Payloads"
          />
        </div>

        <label className="ap-field">
          <span className="ap-label">Retention Window (Days)</span>
          <input
            type="number"
            min={0}
            step={1}
            className="ap-input ap-tabular"
            value={retentionDaysInput}
            onChange={(e) => {
              settingsDirtyRef.current = true;
              clearZeroPurgeTimer();
              setConfirmZeroPurge(false);
              setRetentionDaysInput(e.target.value);
            }}
          />
          <span className="ap-hint">
            Set to 0 to disable automatic background purge, or enter N days to retain payloads.
          </span>
        </label>

        <div
          className="ap-card"
          style={{
            padding: 12,
            background: 'var(--ap-subcard-bg)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            flexWrap: 'wrap',
          }}
        >
          <div>
            <div style={{ fontWeight: 560, fontSize: 12.5 }}>Instant Payload Purge</div>
            <div className="ap-hint">
              Purges stored bodies older than the retention days entered above (0 purges all).
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {confirmZeroPurge && (
              <button
                type="button"
                className="ap-btn ap-btn-ghost ap-btn-sm"
                onClick={() => {
                  clearZeroPurgeTimer();
                  setConfirmZeroPurge(false);
                }}
              >
                Cancel
              </button>
            )}
            <button
              type="button"
              className="ap-btn ap-btn-danger ap-btn-sm"
              disabled={purging}
              onClick={() => void handlePurge()}
            >
              <TrashIcon />
              <span>
                {purging
                  ? 'Purging...'
                  : confirmZeroPurge
                    ? 'Confirm Purge All?'
                    : 'Purge Now'}
              </span>
            </button>
          </div>
        </div>

        {purgeNotice && (
          <div className="ap-alert ap-alert--success">
            <CheckIcon style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{purgeNotice}</span>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, paddingTop: 4 }}>
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
            disabled={savingSettings}
          >
            {savingSettings ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
