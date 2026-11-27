import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  EditIcon,
  PlayIcon,
  PlusIcon,
  ShieldIcon,
  TrashIcon,
} from '../components/ApertureIcons';
import {
  CodeBlock,
  Modal,
  SegmentedControl,
  SourceBadge,
  Toggle,
  YAML_LOCK_TOOLTIP,
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

const PLAYGROUND_PRESETS = [
  {
    label: 'Secret + Email PII',
    text: 'Deploy with OPENAI_API_KEY=sk-proj-9f8e7d6c5b4a32109876543210abcdef and notify ops-lead@acme.internal.',
  },
  {
    label: 'AWS Access Key',
    text: 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\nssn = 123-45-6789',
  },
  {
    label: 'Clean Prompt',
    text: 'Summarize Kubernetes pod restart causes in three concise bullet points.',
  },
];

export interface SecurityFocusState {
  section?: 'all' | 'guardrails' | 'webhooks';
  category?: string;
  webhookType?: string;
  modal?: 'guardrail' | 'webhook' | null;
  nonce?: number;
}

interface SecurityViewProps {
  focus?: SecurityFocusState;
  onCountsChange?: (counts: { rules: number; webhooks: number }) => void;
}

export function SecurityView({ focus, onCountsChange }: SecurityViewProps) {
  const [rules, setRules] = useState<GuardrailRule[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookItem[]>([]);
  const [pageError, setPageError] = useState<string | null>(null);

  const [sectionMode, setSectionMode] = useState<'all' | 'guardrails' | 'webhooks'>('all');
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'secret' | 'pii' | 'custom'>('all');
  const [webhookFilter, setWebhookFilter] = useState<'all' | 'sync_review' | 'async_event'>('all');

  // Interactive Live Guardrail Playground
  const [sampleText, setSampleText] = useState(PLAYGROUND_PRESETS[0].text);
  const [testResult, setTestResult] = useState<GuardrailTestResponse | null>(null);
  const [testingGuardrail, setTestingGuardrail] = useState(false);
  const [playgroundError, setPlaygroundError] = useState<string | null>(null);

  // Guardrail Rule Modal
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [ruleModalError, setRuleModalError] = useState<string | null>(null);
  const [editingRule, setEditingRule] = useState<GuardrailRule | null>(null);
  const [ruleId, setRuleId] = useState('');
  const [ruleName, setRuleName] = useState('');
  const [ruleCategory, setRuleCategory] = useState('custom');
  const [rulePattern, setRulePattern] = useState('');
  const [ruleAction, setRuleAction] = useState('redact');
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [savingRule, setSavingRule] = useState(false);

  // Webhook Modal
  const [whModalOpen, setWhModalOpen] = useState(false);
  const [whModalError, setWhModalError] = useState<string | null>(null);
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
    setPageError(null);
    try {
      const [ruleList, webhookList] = await Promise.all([
        api.listGuardrails(),
        api.listWebhooks(),
      ]);
      setRules(ruleList);
      setWebhooks(webhookList);
      onCountsChange?.({ rules: ruleList.length, webhooks: webhookList.length });
    } catch (err: unknown) {
      setPageError(
        err instanceof Error ? err.message : 'Failed to load guardrails and webhooks',
      );
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    if (!focus) return;
    if (focus.section) setSectionMode(focus.section);
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
    setRuleModalError(null);
    setRuleId('');
    setRuleName('');
    setRuleCategory('custom');
    setRulePattern('');
    setRuleAction('redact');
    setRuleEnabled(true);
    setRuleModalOpen(true);
  };

  const openEditRule = (item: GuardrailRule) => {
    if (item.source === 'config') return;
    setEditingRule(item);
    setRuleModalError(null);
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
    setRuleModalError(null);

    const trimmedId = ruleId.trim();
    if (trimmedId.includes('/')) {
      setRuleModalError('Rule ID must not contain "/".');
      return;
    }
    if (trimmedId.toLowerCase() === 'test') {
      setRuleModalError('Rule ID "test" is reserved by the playground endpoint.');
      return;
    }

    const isBuiltinPreset = Boolean(editingRule?.builtin);
    if (!isBuiltinPreset) {
      if (!ruleName.trim()) {
        setRuleModalError('Display name is required.');
        return;
      }
      if (!rulePattern.trim()) {
        setRuleModalError('Regular expression pattern is required.');
        return;
      }
    }

    setSavingRule(true);
    const payload: GuardrailUpsertPayload = isBuiltinPreset && editingRule
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
      setRuleModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setRuleModalError(
        err instanceof Error ? err.message : 'Failed to save guardrail rule',
      );
    } finally {
      setSavingRule(false);
    }
  };

  const handleToggleRule = async (item: GuardrailRule, next: boolean) => {
    if (item.source === 'config') return;
    setPageError(null);
    try {
      const updated = await api.updateGuardrail(item.id, {
        id: item.id,
        name: item.name,
        category: item.category,
        pattern: item.pattern,
        action: item.action,
        enabled: next,
      });
      setRules((prev) => prev.map((r) => (r.id === item.id ? updated : r)));
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to toggle guardrail rule');
    }
  };

  const handleDeleteRule = async (item: GuardrailRule) => {
    if (item.source === 'config' || item.builtin) return;
    setPageError(null);
    try {
      await api.deleteGuardrail(item.id);
      await loadAll();
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to delete guardrail rule');
    }
  };

  const runPlayground = async (textToTest: string) => {
    setTestingGuardrail(true);
    setPlaygroundError(null);
    try {
      const res = await api.testGuardrails(textToTest);
      setTestResult(res);
    } catch (err: unknown) {
      setPlaygroundError(
        err instanceof Error ? err.message : 'Guardrail evaluation failed',
      );
    } finally {
      setTestingGuardrail(false);
    }
  };

  const handleRunTest = (event: FormEvent) => {
    event.preventDefault();
    void runPlayground(sampleText);
  };

  const openCreateWebhook = () => {
    setEditingWebhook(null);
    setWhModalError(null);
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
    if (item.source === 'config') return;
    setEditingWebhook(item);
    setWhModalError(null);
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
    setWhModalError(null);

    if (whId.trim().includes('/')) {
      setWhModalError('Webhook ID must not contain "/".');
      return;
    }
    if (!whName.trim()) {
      setWhModalError('Webhook name is required.');
      return;
    }
    if (!whUrl.trim()) {
      setWhModalError('Target HTTP/HTTPS URL is required.');
      return;
    }
    const parsedTimeout = Number(whTimeout);
    if (!Number.isFinite(parsedTimeout) || parsedTimeout <= 0) {
      setWhModalError('Timeout (ms) must be a positive number.');
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
      setWhModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setWhModalError(err instanceof Error ? err.message : 'Failed to save webhook');
    } finally {
      setSavingWebhook(false);
    }
  };

  const handleToggleWebhook = async (item: WebhookItem, next: boolean) => {
    if (item.source === 'config') return;
    setPageError(null);
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
      setPageError(err instanceof Error ? err.message : 'Failed to update webhook');
    }
  };

  const handleDeleteWebhook = async (item: WebhookItem) => {
    if (item.source === 'config') return;
    setPageError(null);
    try {
      await api.deleteWebhook(item.id);
      await loadAll();
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to delete webhook');
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

  const showGuardrails = sectionMode === 'all' || sectionMode === 'guardrails';
  const showWebhooks = sectionMode === 'all' || sectionMode === 'webhooks';

  const verdictAction = (testResult?.action || 'allow').toLowerCase();

  return (
    <div className="ap-page">
      <header className="ap-page-header">
        <div className="ap-page-title-row">
          <div>
            <h1 className="ap-page-title">
              {sectionMode === 'guardrails'
                ? 'Guardrails & DLP'
                : sectionMode === 'webhooks'
                  ? 'Webhooks & Event Hooks'
                  : 'Guardrails & Webhooks'}
            </h1>
            <p className="ap-page-subtitle">
              Inspect prompts for secrets and PII before upstream dispatch, test live redactions, and wire HMAC-signed review or event webhooks.
            </p>
          </div>
        </div>

        <div className="ap-filter-bar">
          <div className="ap-filter-group">
            <SegmentedControl
              ariaLabel="Security section"
              value={sectionMode}
              onChange={setSectionMode}
              options={[
                { value: 'all', label: 'All' },
                { value: 'guardrails', label: `Guardrails (${rules.length})` },
                { value: 'webhooks', label: `Webhooks (${webhooks.length})` },
              ]}
            />
          </div>

          <div className="ap-filter-group">
            <button type="button" className="ap-btn" onClick={openCreateWebhook}>
              <PlusIcon />
              <span>Add Webhook</span>
            </button>
            <button
              type="button"
              className="ap-btn ap-btn-primary"
              onClick={openCreateRule}
            >
              <PlusIcon />
              <span>Add Guardrail Rule</span>
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

      {showGuardrails && (
        <>
          {/* Live Guardrail Playground inside Aperture Double-Bezel Tray */}
          <section className="ap-bezel-tray" aria-label="Live Guardrail Playground">
            <div className="ap-card">
              <div className="ap-card-header">
                <div>
                  <h2 className="ap-card-title">Live Guardrail Playground</h2>
                  <p className="ap-card-subtitle">
                    Paste a sample prompt or JSON body to simulate active detectors and preview `[REDACTED:...]` output.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {PLAYGROUND_PRESETS.map((preset) => (
                    <button
                      key={preset.label}
                      type="button"
                      className="ap-btn ap-btn-sm"
                      onClick={() => {
                        setSampleText(preset.text);
                        void runPlayground(preset.text);
                      }}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              <form onSubmit={handleRunTest} className="ap-card-body ap-split-2">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <textarea
                    className="ap-textarea ap-mono"
                    style={{ minHeight: 118 }}
                    value={sampleText}
                    onChange={(e) => setSampleText(e.target.value)}
                    placeholder="Paste sample prompt or JSON request..."
                    aria-label="Sample prompt to evaluate against guardrails"
                  />
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                    <span className="ap-hint">
                      Evaluates against all currently enabled rules in SQLite & YAML.
                    </span>
                    <button
                      type="submit"
                      className="ap-btn ap-btn-primary"
                      disabled={testingGuardrail || !sampleText.trim()}
                    >
                      <ShieldIcon size={15} />
                      <span>{testingGuardrail ? 'Evaluating...' : 'Evaluate Sample'}</span>
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }}>
                  {playgroundError && (
                    <div className="ap-alert ap-alert--danger">
                      <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
                      <span>{playgroundError}</span>
                    </div>
                  )}

                  {testResult ? (
                    <>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          flexWrap: 'wrap',
                        }}
                      >
                        <span
                          className={`ap-badge ${
                            verdictAction === 'block'
                              ? 'ap-badge--red'
                              : verdictAction === 'redact'
                                ? 'ap-badge--amber'
                                : 'ap-badge--green'
                          }`}
                        >
                          Verdict: {verdictAction.toUpperCase()}
                        </span>
                        {(testResult.matches ?? []).length > 0 ? (
                          (testResult.matches ?? []).map((m) => (
                            <span key={m.rule_id} className="ap-badge ap-mono">
                              {m.rule_name} ({m.action})
                            </span>
                          ))
                        ) : (
                          <span style={{ color: 'var(--ap-text-secondary)', fontSize: 12 }}>
                            No rules matched — request allowed unchanged.
                          </span>
                        )}
                      </div>
                      <CodeBlock
                        label="Evaluated / Redacted Output"
                        code={testResult.redacted_text}
                        highlightRedactions
                      />
                    </>
                  ) : (
                    <div
                      style={{
                        flex: 1,
                        minHeight: 118,
                        borderRadius: 'var(--ap-radius-md)',
                        border: '1px dashed var(--ap-border-strong)',
                        background: 'var(--ap-subcard-bg)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        padding: 16,
                        color: 'var(--ap-text-secondary)',
                        fontSize: 12.5,
                        textAlign: 'center',
                      }}
                    >
                      Click &ldquo;Evaluate Sample&rdquo; or pick a preset above to inspect rule hits and redactions.
                    </div>
                  )}
                </div>
              </form>
            </div>
          </section>

          {/* Guardrail Rules Inventory */}
          <section className="ap-card" aria-label="Guardrail rules">
            <div className="ap-card-header">
              <div>
                <h2 className="ap-card-title">Detector Rules ({filteredRules.length})</h2>
                <p className="ap-card-subtitle">
                  Built-in presets allow toggling Enabled and Action; YAML-defined rules remain locked to headlamp.yaml.
                </p>
              </div>
              <SegmentedControl
                ariaLabel="Guardrail category filter"
                value={categoryFilter}
                onChange={setCategoryFilter}
                options={[
                  { value: 'all', label: 'All' },
                  { value: 'secret', label: 'Secrets' },
                  { value: 'pii', label: 'PII' },
                  { value: 'custom', label: 'Custom' },
                ]}
              />
            </div>

            <div className="ap-table-wrap">
              <table className="ap-table">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Origin</th>
                    <th>Category</th>
                    <th>Regex Pattern</th>
                    <th>Action</th>
                    <th>Enabled</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ color: 'var(--ap-text-muted)', padding: '26px 14px', textAlign: 'center' }}>
                        No guardrail rules in this category.
                      </td>
                    </tr>
                  ) : (
                    filteredRules.map((rule) => {
                      const isYaml = rule.source === 'config';
                      const canDelete = !isYaml && !rule.builtin;

                      return (
                        <tr key={rule.id} className="ap-row">
                          <td>
                            <div style={{ fontWeight: 560 }}>{rule.name}</div>
                            <div className="ap-mono" style={{ fontSize: 11, color: 'var(--ap-text-muted)' }}>
                              {rule.id}
                            </div>
                          </td>
                          <td>
                            <SourceBadge source={rule.source} builtin={rule.builtin} />
                          </td>
                          <td style={{ textTransform: 'uppercase', fontSize: 11.5, color: 'var(--ap-text-secondary)', fontWeight: 550 }}>
                            {rule.category}
                          </td>
                          <td style={{ maxWidth: 230 }}>
                            <span
                              className="ap-mono ap-truncate"
                              style={{ display: 'block', fontSize: 12, color: 'var(--ap-text-secondary)' }}
                              title={rule.pattern}
                            >
                              {rule.pattern}
                            </span>
                          </td>
                          <td>
                            <span
                              className={`ap-badge ${
                                rule.action === 'block'
                                  ? 'ap-badge--red'
                                  : rule.action === 'redact'
                                    ? 'ap-badge--amber'
                                    : ''
                              }`}
                            >
                              {rule.action}
                            </span>
                          </td>
                          <td>
                            <Toggle
                              checked={rule.enabled}
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                              onChange={(next) => handleToggleRule(rule, next)}
                              label={`Enable ${rule.name}`}
                            />
                          </td>
                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <div className="ap-row-actions">
                              <button
                                type="button"
                                className="ap-btn ap-btn-ghost ap-btn-sm"
                                disabled={isYaml}
                                title={
                                  isYaml
                                    ? YAML_LOCK_TOOLTIP
                                    : rule.builtin
                                      ? 'Edit action or enabled state'
                                      : `Edit ${rule.name}`
                                }
                                onClick={() => openEditRule(rule)}
                              >
                                <EditIcon />
                                <span>Edit</span>
                              </button>
                              {canDelete && (
                                <button
                                  type="button"
                                  className="ap-btn ap-btn-ghost ap-btn-danger ap-btn-sm"
                                  onClick={() => handleDeleteRule(rule)}
                                >
                                  <TrashIcon />
                                  <span>Delete</span>
                                </button>
                              )}
                              {isYaml && !rule.builtin && (
                                <button
                                  type="button"
                                  className="ap-btn ap-btn-ghost ap-btn-danger ap-btn-sm"
                                  disabled
                                  title={YAML_LOCK_TOOLTIP}
                                >
                                  <TrashIcon />
                                  <span>Delete</span>
                                </button>
                              )}
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
        </>
      )}

      {showWebhooks && (
        <section className="ap-card" aria-label="Sync review and async event webhooks">
          <div className="ap-card-header">
            <div>
              <h2 className="ap-card-title">Webhooks ({filteredWebhooks.length})</h2>
              <p className="ap-card-subtitle">
                Sync Review webhooks gate requests inline before upstream execution; Async Event webhooks stream telemetry & alerts.
              </p>
            </div>
            <SegmentedControl
              ariaLabel="Webhook mode filter"
              value={webhookFilter}
              onChange={setWebhookFilter}
              options={[
                { value: 'all', label: 'All' },
                { value: 'sync_review', label: 'Sync Review' },
                { value: 'async_event', label: 'Async Event' },
              ]}
            />
          </div>

          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Webhook</th>
                  <th>Origin</th>
                  <th>Mode</th>
                  <th>Endpoint & Policy</th>
                  <th>HMAC</th>
                  <th>Enabled</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredWebhooks.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ color: 'var(--ap-text-muted)', padding: '26px 14px', textAlign: 'center' }}>
                      No webhooks configured.
                    </td>
                  </tr>
                ) : (
                  filteredWebhooks.map((wh) => {
                    const isYaml = wh.source === 'config';
                    const ping = webhookTests[wh.id];
                    const isPinging = testingWebhookId === wh.id;

                    return (
                      <tr key={wh.id} className="ap-row">
                        <td>
                          <div style={{ fontWeight: 560 }}>{wh.name}</div>
                          <div className="ap-mono" style={{ fontSize: 11, color: 'var(--ap-text-muted)' }}>
                            {wh.id}
                          </div>
                        </td>
                        <td>
                          <SourceBadge source={wh.source} />
                        </td>
                        <td>
                          <span
                            className={`ap-badge ${
                              wh.type === 'sync_review' ? 'ap-badge--purple' : 'ap-badge--blue'
                            }`}
                          >
                            {wh.type === 'sync_review' ? 'Sync Review' : 'Async Event'}
                          </span>
                        </td>
                        <td style={{ maxWidth: 230 }}>
                          <div
                            className="ap-mono ap-truncate"
                            style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}
                            title={wh.url}
                          >
                            {wh.url}
                          </div>
                          <div
                            className="ap-truncate"
                            style={{ fontSize: 11.5, color: 'var(--ap-text-muted)', marginTop: 2 }}
                          >
                            {wh.type === 'sync_review'
                              ? `${wh.timeout_ms} ms timeout · ${
                                  wh.fail_open ? 'fail_open' : 'fail_closed'
                                }`
                              : (wh.events ?? []).includes('*')
                                ? 'All events (*)'
                                : (wh.events ?? []).join(', ') || 'No events'}
                          </div>
                        </td>
                        <td>
                          <span
                            className={`ap-badge ${
                              wh.has_secret ? 'ap-badge--green' : ''
                            }`}
                          >
                            {wh.has_secret ? 'HMAC Signed' : 'Unsigned'}
                          </span>
                        </td>
                        <td>
                          <Toggle
                            checked={wh.enabled}
                            disabled={isYaml}
                            title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                            onChange={(next) => handleToggleWebhook(wh, next)}
                            label={`Enable ${wh.name}`}
                          />
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="ap-row-actions">
                            {ping && (
                              <span
                                className={`ap-badge ap-tabular ${
                                  ping.ok ? 'ap-badge--green' : 'ap-badge--red'
                                }`}
                                title={ping.message}
                              >
                                {ping.ok
                                  ? `${ping.status_code} · ${formatLatency(ping.latency_ms)}`
                                  : ping.message.slice(0, 26)}
                              </span>
                            )}
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm"
                              disabled={isPinging}
                              onClick={() => handleTestWebhook(wh.id)}
                            >
                              <PlayIcon />
                              <span>{isPinging ? 'Pinging' : 'Test Ping'}</span>
                            </button>
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm"
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${wh.name}`}
                              onClick={() => openEditWebhook(wh)}
                            >
                              <EditIcon />
                              <span>Edit</span>
                            </button>
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-danger ap-btn-sm"
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${wh.name}`}
                              onClick={() => handleDeleteWebhook(wh)}
                            >
                              <TrashIcon />
                              <span>Delete</span>
                            </button>
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

      {/* Guardrail Rule Modal */}
      <Modal
        open={ruleModalOpen}
        title={editingRule ? `Edit Guardrail (${editingRule.name})` : 'Add Guardrail Rule'}
        onClose={() => setRuleModalOpen(false)}
        error={ruleModalError}
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
              onClick={() => setRuleModalOpen(false)}
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

      {/* Webhook Modal */}
      <Modal
        open={whModalOpen}
        title={editingWebhook ? `Edit Webhook (${editingWebhook.name})` : 'Add Webhook'}
        onClose={() => setWhModalOpen(false)}
        maxWidth={600}
        error={whModalError}
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
              onClick={() => setWhModalOpen(false)}
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
    </div>
  );
}
