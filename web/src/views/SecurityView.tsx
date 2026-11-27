import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Add, Edit, Play, ShieldCheck, Trash } from 'reicon-react';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import {
  CodeBlock,
  Modal,
  SegmentedControl,
  Toggle,
} from '../components/Primitives';
import { formatLatency } from '../lib/format';
import type {
  GuardrailRule,
  GuardrailTestResponse,
  GuardrailUpsertPayload,
  WebhookItem,
  WebhookTestResult,
  WebhookUpsertPayload,
} from '../types/api';

const WEBHOOK_EVENTS = [
  '*',
  'budget.threshold',
  'budget.exceeded',
  'guardrail.triggered',
  'upstream.fallback',
  'upstream.error',
];

export interface SecurityFocusState {
  category?: string;
  webhookType?: string;
  modal?: 'guardrail' | 'webhook' | null;
  nonce?: number;
}

interface SecurityViewProps {
  focus?: SecurityFocusState;
}

export function SecurityView({ focus }: SecurityViewProps) {
  const [rules, setRules] = useState<GuardrailRule[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookItem[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [categoryFilter, setCategoryFilter] = useState<'all' | 'secret' | 'pii' | 'custom'>('all');
  const [webhookFilter, setWebhookFilter] = useState<'all' | 'sync_review' | 'async_event'>('all');

  // Guardrail Live Tester
  const [sampleText, setSampleText] = useState(
    'Authorization: Bearer sk-proj-9f8e7d6c5b4a32109876543210abcdef',
  );
  const [testResult, setTestResult] = useState<GuardrailTestResponse | null>(null);
  const [testingGuardrail, setTestingGuardrail] = useState(false);

  // Guardrail Modal
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<GuardrailRule | null>(null);
  const [ruleId, setRuleId] = useState('');
  const [ruleName, setRuleName] = useState('');
  const [ruleCategory, setRuleCategory] = useState('secret');
  const [rulePattern, setRulePattern] = useState('');
  const [ruleAction, setRuleAction] = useState('redact');
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [savingRule, setSavingRule] = useState(false);

  // Webhook Modal
  const [whModalOpen, setWhModalOpen] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<WebhookItem | null>(null);
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

  const [webhookTests, setWebhookTests] = useState<Record<string, WebhookTestResult>>({});
  const [testingWebhookId, setTestingWebhookId] = useState<string | null>(null);

  const loadAll = async () => {
    setError(null);
    try {
      const [ruleList, webhookList] = await Promise.all([
        api.listGuardrails(),
        api.listWebhooks(),
      ]);
      setRules(ruleList);
      setWebhooks(webhookList);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load security configuration');
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    if (!focus) return;
    if (
      focus.category === 'all' ||
      focus.category === 'secret' ||
      focus.category === 'pii' ||
      focus.category === 'custom'
    ) {
      setCategoryFilter(focus.category);
    }
    if (
      focus.webhookType === 'all' ||
      focus.webhookType === 'sync_review' ||
      focus.webhookType === 'async_event'
    ) {
      setWebhookFilter(focus.webhookType);
    }
    if (focus.modal === 'guardrail') openCreateRule();
    if (focus.modal === 'webhook') openCreateWebhook();
  }, [focus?.nonce]);

  const openCreateRule = () => {
    setEditingRule(null);
    setRuleId('');
    setRuleName('');
    setRuleCategory('custom');
    setRulePattern('');
    setRuleAction('redact');
    setRuleEnabled(true);
    setRuleModalOpen(true);
  };

  const openEditRule = (item: GuardrailRule) => {
    setEditingRule(item);
    setRuleId(item.id);
    setRuleName(item.name);
    setRuleCategory(item.category);
    setRulePattern(item.pattern);
    setRuleAction(item.action);
    setRuleEnabled(item.enabled);
    setRuleModalOpen(true);
  };

  const handleSaveRule = async (event: FormEvent) => {
    event.preventDefault();
    setSavingRule(true);
    setError(null);

    const payload: GuardrailUpsertPayload = {
      id: ruleId.trim(),
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
      setRuleModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save guardrail rule');
    } finally {
      setSavingRule(false);
    }
  };

  const handleToggleRule = async (item: GuardrailRule, next: boolean) => {
    try {
      await api.updateGuardrail(item.id, {
        id: item.id,
        name: item.name,
        category: item.category,
        pattern: item.pattern,
        action: item.action,
        enabled: next,
      });
      setRules((prev) =>
        prev.map((r) => (r.id === item.id ? { ...r, enabled: next } : r)),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update rule');
    }
  };

  const handleDeleteRule = async (id: string) => {
    try {
      await api.deleteGuardrail(id);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule');
    }
  };

  const handleRunTest = async (event: FormEvent) => {
    event.preventDefault();
    setTestingGuardrail(true);
    setError(null);
    try {
      const res = await api.testGuardrails(sampleText);
      setTestResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Guardrail evaluation failed');
    } finally {
      setTestingGuardrail(false);
    }
  };

  const openCreateWebhook = () => {
    setEditingWebhook(null);
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
    setWhModalOpen(true);
  };

  const openEditWebhook = (item: WebhookItem) => {
    setEditingWebhook(item);
    setWhId(item.id);
    setWhName(item.name);
    setWhUrl(item.url);
    setWhType(item.type);
    setWhSecret('');
    setWhClearSecret(false);
    setWhEvents(item.events ?? []);
    setWhTimeout(String(item.timeout_ms || 2000));
    setWhFailOpen(item.fail_open);
    setWhEnabled(item.enabled);
    setWhModalOpen(true);
  };

  const handleSaveWebhook = async (event: FormEvent) => {
    event.preventDefault();
    setSavingWebhook(true);
    setError(null);

    const payload: WebhookUpsertPayload = {
      id: whId.trim(),
      name: whName.trim(),
      url: whUrl.trim(),
      type: whType,
      events: whType === 'async_event' ? whEvents : [],
      timeout_ms: Math.max(100, Number(whTimeout) || 2000),
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
      setWhModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save webhook');
    } finally {
      setSavingWebhook(false);
    }
  };

  const handleToggleWebhook = async (item: WebhookItem, next: boolean) => {
    try {
      await api.updateWebhook(item.id, {
        id: item.id,
        name: item.name,
        url: item.url,
        type: item.type,
        events: item.events ?? [],
        timeout_ms: item.timeout_ms,
        fail_open: item.fail_open,
        enabled: next,
      });
      setWebhooks((prev) =>
        prev.map((w) => (w.id === item.id ? { ...w, enabled: next } : w)),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update webhook');
    }
  };

  const handleDeleteWebhook = async (id: string) => {
    try {
      await api.deleteWebhook(id);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete webhook');
    }
  };

  const handleTestWebhook = async (id: string) => {
    setTestingWebhookId(id);
    try {
      const res = await api.testWebhook(id);
      setWebhookTests((prev) => ({ ...prev, [id]: res }));
    } catch (err: unknown) {
      setWebhookTests((prev) => ({
        ...prev,
        [id]: {
          ok: false,
          status_code: 0,
          latency_ms: 0,
          message: err instanceof Error ? err.message : 'Ping failed',
        },
      }));
    } finally {
      setTestingWebhookId(null);
    }
  };

  const toggleWebhookEvent = (evt: string) => {
    setWhEvents((prev) =>
      prev.includes(evt) ? prev.filter((item) => item !== evt) : [...prev, evt],
    );
  };

  const filteredRules = useMemo(() => {
    if (categoryFilter === 'all') return rules;
    return rules.filter((r) => r.category === categoryFilter);
  }, [rules, categoryFilter]);

  const filteredWebhooks = useMemo(() => {
    if (webhookFilter === 'all') return webhooks;
    return webhooks.filter((w) => w.type === webhookFilter);
  }, [webhooks, webhookFilter]);

  return (
    <>
      <section className="hl-section">
        <div className="hl-section-bar">
          <h1>Guardrails</h1>
          <div className="hl-toolbar">
            <SegmentedControl
              ariaLabel="Guardrail category"
              value={categoryFilter}
              onChange={setCategoryFilter}
              options={[
                { value: 'all', label: 'All' },
                { value: 'secret', label: 'Secrets' },
                { value: 'pii', label: 'PII' },
                { value: 'custom', label: 'Custom' },
              ]}
            />
            <button
              type="button"
              className="hl-btn hl-btn-primary"
              onClick={openCreateRule}
            >
              <Icon icon={Add} />
              <span>Add Rule</span>
            </button>
          </div>
        </div>

        {error && <p className="hl-status-text hl-status-danger">{error}</p>}

        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Category</th>
                <th>Pattern</th>
                <th>Action</th>
                <th>Origin</th>
                <th>Enabled</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="hl-secondary">
                    No guardrail rules
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr key={rule.id} className="hl-row">
                    <td style={{ fontWeight: 500 }}>{rule.name}</td>
                    <td className="hl-secondary">{rule.category}</td>
                    <td
                      className="hl-mono hl-secondary"
                      style={{
                        maxWidth: 320,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {rule.pattern}
                    </td>
                    <td
                      className={
                        rule.action === 'block'
                          ? 'hl-status-danger'
                          : rule.action === 'redact'
                            ? 'hl-status-accent'
                            : 'hl-secondary'
                      }
                      style={{ fontWeight: 500 }}
                    >
                      {rule.action}
                    </td>
                    <td className="hl-secondary">
                      {rule.builtin ? 'Built-in' : 'Custom'}
                    </td>
                    <td>
                      <Toggle
                        checked={rule.enabled}
                        onChange={(next) => handleToggleRule(rule, next)}
                        label={`Enable ${rule.name}`}
                      />
                    </td>
                    <td>
                      <div className="hl-row-actions">
                        <button
                          type="button"
                          className="hl-btn hl-btn-ghost"
                          onClick={() => openEditRule(rule)}
                        >
                          <Icon icon={Edit} />
                          <span>Edit</span>
                        </button>
                        {!rule.builtin && (
                          <button
                            type="button"
                            className="hl-btn hl-btn-ghost hl-btn-danger"
                            onClick={() => handleDeleteRule(rule.id)}
                          >
                            <Icon icon={Trash} />
                            <span>Delete</span>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="hl-section">
        <div className="hl-section-bar">
          <h2>Guardrail Tester</h2>
        </div>

        <form onSubmit={handleRunTest} className="hl-split-2">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <textarea
              className="hl-textarea hl-mono"
              value={sampleText}
              onChange={(e) => setSampleText(e.target.value)}
              placeholder="Paste sample prompt to inspect redaction or blocking..."
            />
            <div>
              <button
                type="submit"
                className="hl-btn hl-btn-primary"
                disabled={testingGuardrail || !sampleText.trim()}
              >
                <Icon icon={ShieldCheck} />
                <span>{testingGuardrail ? 'Checking' : 'Test Sample'}</span>
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {testResult ? (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 24, fontSize: 14 }}>
                  <span>
                    <span className="hl-secondary">Action </span>
                    <strong
                      className={
                        testResult.action === 'block'
                          ? 'hl-status-danger'
                          : testResult.action === 'redact'
                            ? 'hl-status-accent'
                            : ''
                      }
                    >
                      {testResult.action || 'allow'}
                    </strong>
                  </span>
                  <span className="hl-secondary">
                    {(testResult.matches ?? []).length > 0
                      ? `Matched: ${(testResult.matches ?? [])
                          .map((m) => m.rule_name)
                          .join(', ')}`
                      : 'No rules triggered'}
                  </span>
                </div>
                <CodeBlock code={testResult.redacted_text} />
              </>
            ) : (
              <div
                className="hl-surface"
                style={{
                  minHeight: 96,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <span className="hl-secondary">Run a sample to view output</span>
              </div>
            )}
          </div>
        </form>
      </section>

      <section className="hl-section">
        <div className="hl-section-bar">
          <h2>Webhooks</h2>
          <div className="hl-toolbar">
            <SegmentedControl
              ariaLabel="Webhook mode"
              value={webhookFilter}
              onChange={setWebhookFilter}
              options={[
                { value: 'all', label: 'All' },
                { value: 'sync_review', label: 'Sync Review' },
                { value: 'async_event', label: 'Async Event' },
              ]}
            />
            <button
              type="button"
              className="hl-btn hl-btn-primary"
              onClick={openCreateWebhook}
            >
              <Icon icon={Add} />
              <span>Add Webhook</span>
            </button>
          </div>
        </div>

        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Mode</th>
                <th>Endpoint</th>
                <th>Events / Policy</th>
                <th>HMAC</th>
                <th>Enabled</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filteredWebhooks.length === 0 ? (
                <tr>
                  <td colSpan={7} className="hl-secondary">
                    No webhooks configured
                  </td>
                </tr>
              ) : (
                filteredWebhooks.map((wh) => {
                  const ping = webhookTests[wh.id];
                  const isPinging = testingWebhookId === wh.id;
                  return (
                    <tr key={wh.id} className="hl-row">
                      <td style={{ fontWeight: 500 }}>{wh.name}</td>
                      <td className="hl-secondary">{wh.type}</td>
                      <td className="hl-mono hl-secondary">{wh.url}</td>
                      <td className="hl-secondary">
                        {wh.type === 'sync_review'
                          ? `${wh.timeout_ms} ms · ${
                              wh.fail_open ? 'fail_open' : 'fail_closed'
                            }`
                          : (wh.events ?? []).includes('*')
                            ? 'All events'
                            : (wh.events ?? []).length > 0
                              ? (wh.events ?? []).join(', ')
                              : 'None'}
                      </td>
                      <td className="hl-secondary">
                        {wh.has_secret ? 'Signed' : 'Unsigned'}
                      </td>
                      <td>
                        <Toggle
                          checked={wh.enabled}
                          onChange={(next) => handleToggleWebhook(wh, next)}
                          label={`Enable ${wh.name}`}
                        />
                      </td>
                      <td>
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'flex-end',
                            gap: 12,
                          }}
                        >
                          {ping && (
                            <span
                              className={
                                ping.ok
                                  ? 'hl-status-text hl-status-accent'
                                  : 'hl-status-text hl-status-danger'
                              }
                            >
                              {ping.ok
                                ? `${ping.status_code} · ${formatLatency(ping.latency_ms)}`
                                : ping.message}
                            </span>
                          )}
                          <div className="hl-row-actions" data-visible={isPinging}>
                            <button
                              type="button"
                              className="hl-btn hl-btn-ghost"
                              disabled={isPinging}
                              onClick={() => handleTestWebhook(wh.id)}
                            >
                              <Icon icon={Play} />
                              <span>{isPinging ? 'Testing' : 'Test'}</span>
                            </button>
                            <button
                              type="button"
                              className="hl-btn hl-btn-ghost"
                              onClick={() => openEditWebhook(wh)}
                            >
                              <Icon icon={Edit} />
                              <span>Edit</span>
                            </button>
                            <button
                              type="button"
                              className="hl-btn hl-btn-ghost hl-btn-danger"
                              onClick={() => handleDeleteWebhook(wh.id)}
                            >
                              <Icon icon={Trash} />
                              <span>Delete</span>
                            </button>
                          </div>
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

      <Modal
        open={ruleModalOpen}
        title={editingRule ? `Edit ${editingRule.name}` : 'Add Guardrail Rule'}
        onClose={() => setRuleModalOpen(false)}
      >
        <form onSubmit={handleSaveRule} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Rule ID</span>
              <input
                className="hl-input hl-mono"
                disabled={Boolean(editingRule)}
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value)}
                placeholder="Auto-generated if blank"
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Display Name</span>
              <input
                className="hl-input"
                required
                disabled={Boolean(editingRule?.builtin)}
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                placeholder="Internal Token"
              />
            </label>
          </div>

          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Category</span>
              <select
                className="hl-select"
                disabled={Boolean(editingRule?.builtin)}
                value={ruleCategory}
                onChange={(e) => setRuleCategory(e.target.value)}
              >
                <option value="secret">secret</option>
                <option value="pii">pii</option>
                <option value="custom">custom</option>
              </select>
            </label>
            <label className="hl-field">
              <span className="hl-label">Action</span>
              <select
                className="hl-select"
                value={ruleAction}
                onChange={(e) => setRuleAction(e.target.value)}
              >
                <option value="redact">redact</option>
                <option value="block">block</option>
                <option value="log_only">log_only</option>
              </select>
            </label>
          </div>

          <label className="hl-field">
            <span className="hl-label">Regular Expression</span>
            <input
              className="hl-input hl-mono"
              required
              disabled={Boolean(editingRule?.builtin)}
              value={rulePattern}
              onChange={(e) => setRulePattern(e.target.value)}
              placeholder="hlp_[a-zA-Z0-9]{24,}"
            />
          </label>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Enabled</span>
            <Toggle
              checked={ruleEnabled}
              onChange={setRuleEnabled}
              label="Rule Enabled"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, paddingTop: 8 }}>
            <button
              type="button"
              className="hl-btn"
              onClick={() => setRuleModalOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="hl-btn hl-btn-primary"
              disabled={savingRule}
            >
              {savingRule ? 'Saving' : 'Save Rule'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        open={whModalOpen}
        title={editingWebhook ? `Edit ${editingWebhook.name}` : 'Add Webhook'}
        onClose={() => setWhModalOpen(false)}
      >
        <form onSubmit={handleSaveWebhook} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Webhook ID</span>
              <input
                className="hl-input hl-mono"
                disabled={Boolean(editingWebhook)}
                value={whId}
                onChange={(e) => setWhId(e.target.value)}
                placeholder="Auto-generated if blank"
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Name</span>
              <input
                className="hl-input"
                required
                value={whName}
                onChange={(e) => setWhName(e.target.value)}
                placeholder="SecOps Alerts"
              />
            </label>
          </div>

          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Mode</span>
              <select
                className="hl-select"
                value={whType}
                onChange={(e) => setWhType(e.target.value)}
              >
                <option value="async_event">async_event</option>
                <option value="sync_review">sync_review</option>
              </select>
            </label>
            <label className="hl-field">
              <span className="hl-label">Timeout (ms)</span>
              <input
                type="number"
                min={100}
                className="hl-input"
                value={whTimeout}
                onChange={(e) => setWhTimeout(e.target.value)}
              />
            </label>
          </div>

          <label className="hl-field">
            <span className="hl-label">Target URL</span>
            <input
              type="url"
              className="hl-input hl-mono"
              required
              value={whUrl}
              onChange={(e) => setWhUrl(e.target.value)}
              placeholder="https://hooks.internal/headlamp"
            />
          </label>

          <label className="hl-field">
            <span className="hl-label">HMAC Secret</span>
            <input
              type="password"
              className="hl-input hl-mono"
              value={whSecret}
              onChange={(e) => {
                setWhSecret(e.target.value);
                if (e.target.value) setWhClearSecret(false);
              }}
              placeholder={
                editingWebhook?.has_secret
                  ? 'Leave blank to keep stored secret'
                  : 'Optional signing key'
              }
            />
          </label>

          {editingWebhook?.has_secret && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span className="hl-label">Clear stored HMAC secret</span>
              <Toggle
                checked={whClearSecret}
                onChange={setWhClearSecret}
                label="Clear stored HMAC secret"
              />
            </div>
          )}

          {whType === 'async_event' && (
            <div className="hl-field">
              <span className="hl-label">Events</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {WEBHOOK_EVENTS.map((evt) => {
                  const active = whEvents.includes(evt);
                  return (
                    <button
                      key={evt}
                      type="button"
                      className={active ? 'hl-btn hl-btn-primary' : 'hl-btn'}
                      style={{ height: 32, padding: '0 12px' }}
                      onClick={() => toggleWebhookEvent(evt)}
                    >
                      {evt}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Fail Open on Upstream Timeout</span>
            <Toggle
              checked={whFailOpen}
              onChange={setWhFailOpen}
              label="Fail Open"
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Enabled</span>
            <Toggle
              checked={whEnabled}
              onChange={setWhEnabled}
              label="Webhook Enabled"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, paddingTop: 8 }}>
            <button
              type="button"
              className="hl-btn"
              onClick={() => setWhModalOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="hl-btn hl-btn-primary"
              disabled={savingWebhook}
            >
              {savingWebhook ? 'Saving' : 'Save Webhook'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
