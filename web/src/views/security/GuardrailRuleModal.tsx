import { useEffect, useState, type FormEvent } from 'react';
import { api } from '../../api/client';
import { AlertIcon } from '../../components/ApertureIcons';
import { Modal, Toggle } from '../../components/Primitives';
import type { GuardrailRule, GuardrailUpsertPayload } from '../../types/api';

interface GuardrailRuleModalProps {
  open: boolean;
  editingRule: GuardrailRule | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

export function GuardrailRuleModal({
  open,
  editingRule,
  onClose,
  onSaved,
}: GuardrailRuleModalProps) {
  const [modalError, setModalError] = useState<string | null>(null);
  const [ruleId, setRuleId] = useState('');
  const [ruleName, setRuleName] = useState('');
  const [ruleCategory, setRuleCategory] = useState('custom');
  const [rulePattern, setRulePattern] = useState('');
  const [ruleAction, setRuleAction] = useState('redact');
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [savingRule, setSavingRule] = useState(false);

  useEffect(() => {
    if (!open) return;
    setModalError(null);
    if (editingRule) {
      setRuleId(editingRule.id);
      setRuleName(editingRule.name);
      setRuleCategory(editingRule.category);
      setRulePattern(editingRule.pattern);
      setRuleAction(editingRule.action);
      setRuleEnabled(editingRule.enabled);
    } else {
      setRuleId('');
      setRuleName('');
      setRuleCategory('custom');
      setRulePattern('');
      setRuleAction('redact');
      setRuleEnabled(true);
    }
  }, [open, editingRule]);

  const handleSaveRule = async (event: FormEvent) => {
    event.preventDefault();
    setModalError(null);

    const trimmedId = ruleId.trim();
    if (trimmedId.includes('/')) {
      setModalError('Rule ID must not contain "/".');
      return;
    }
    if (trimmedId.toLowerCase() === 'test') {
      setModalError('Rule ID "test" is reserved by the playground endpoint.');
      return;
    }

    const isBuiltinPreset = Boolean(editingRule?.builtin);
    if (!isBuiltinPreset) {
      if (!ruleName.trim()) {
        setModalError('Display name is required.');
        return;
      }
      if (!rulePattern.trim()) {
        setModalError('Regular expression pattern is required.');
        return;
      }
    }

    setSavingRule(true);
    const payload: GuardrailUpsertPayload =
      isBuiltinPreset && editingRule
        ? {
            id: editingRule.id,
            name: editingRule.name,
            category: editingRule.category,
            pattern: editingRule.pattern,
            action: ruleAction,
            enabled: ruleEnabled,
          }
        : {
            id: trimmedId,
            name: ruleName.trim(),
            category: ruleCategory,
            pattern: rulePattern,
            action: ruleAction,
            enabled: ruleEnabled,
          };

    try {
      if (editingRule) {
        await api.updateGuardrail(editingRule.id, payload);
      } else {
        await api.createGuardrail(payload);
      }
      onClose();
      await onSaved();
    } catch (err: unknown) {
      setModalError(
        err instanceof Error ? err.message : 'Failed to save guardrail rule',
      );
    } finally {
      setSavingRule(false);
    }
  };

  return (
    <Modal
      open={open}
      title={editingRule ? `Edit Guardrail (${editingRule.name})` : 'Add Guardrail Rule'}
      onClose={onClose}
      error={modalError}
    >
      <form
        onSubmit={handleSaveRule}
        style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
      >
        {editingRule?.builtin && (
          <div className="ap-alert ap-alert--info">
            <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
            <span>
              Built-in detector presets keep Name, Category, and Regex read-only. You can customize Action and Enabled state below.
            </span>
          </div>
        )}

        <div className="ap-form-grid">
          <label className="ap-field">
            <span className="ap-label">Rule ID</span>
            <input
              className="ap-input ap-mono"
              disabled={Boolean(editingRule)}
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              placeholder="Auto-generated if blank"
            />
          </label>
          <label className="ap-field">
            <span className="ap-label">Display Name</span>
            <input
              className="ap-input"
              required={!editingRule?.builtin}
              disabled={Boolean(editingRule?.builtin)}
              value={ruleName}
              onChange={(e) => setRuleName(e.target.value)}
              placeholder="Internal Deploy Token"
            />
          </label>
        </div>

        <div className="ap-form-grid">
          <label className="ap-field">
            <span className="ap-label">Category</span>
            <select
              className="ap-select"
              disabled={Boolean(editingRule?.builtin)}
              value={ruleCategory}
              onChange={(e) => setRuleCategory(e.target.value)}
            >
              <option value="secret">secret</option>
              <option value="pii">pii</option>
              <option value="custom">custom</option>
            </select>
          </label>
          <label className="ap-field">
            <span className="ap-label">Action on Match</span>
            <select
              className="ap-select"
              value={ruleAction}
              onChange={(e) => setRuleAction(e.target.value)}
            >
              <option value="redact">redact (mask matched value)</option>
              <option value="block">block (HTTP 400 reject)</option>
              <option value="log_only">log_only (audit without modifying)</option>
            </select>
          </label>
        </div>

        <label className="ap-field">
          <span className="ap-label">Go Regular Expression (RE2)</span>
          <input
            className="ap-input ap-mono"
            required={!editingRule?.builtin}
            disabled={Boolean(editingRule?.builtin)}
            value={rulePattern}
            onChange={(e) => setRulePattern(e.target.value)}
            placeholder="hlp_[a-zA-Z0-9]{24,}"
          />
        </label>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="ap-label">Enabled</span>
          <Toggle
            checked={ruleEnabled}
            onChange={setRuleEnabled}
            label="Rule Enabled"
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
            disabled={savingRule}
          >
            {savingRule ? 'Saving...' : 'Save Rule'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
