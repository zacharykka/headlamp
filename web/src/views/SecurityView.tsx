import { useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  EditIcon,
  PlayIcon,
  PlusIcon,
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
  GuardrailRule,
  WebhookItem,
  WebhookTestResult,
} from '../types/api';
import { GuardrailPlayground } from './security/GuardrailPlayground';
import { GuardrailRuleModal } from './security/GuardrailRuleModal';
import { WebhookModal } from './security/WebhookModal';

export interface SecurityFocusState {
  section?: 'all' | 'guardrails' | 'webhooks';
  category?: string;
  webhookType?: string;
  modal?: 'guardrail' | 'webhook' | null;
  nonce?: number;
}

interface SecurityViewProps {
  focus?: SecurityFocusState;
  onSectionChange?: (section: 'all' | 'guardrails' | 'webhooks') => void;
  onCountsChange?: (counts: { rules: number; webhooks: number }) => void;
}

export function SecurityView({
  focus,
  onSectionChange,
  onCountsChange,
}: SecurityViewProps) {
  const [rules, setRules] = useState<GuardrailRule[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookItem[]>([]);
  const [pageError, setPageError] = useState<string | null>(null);

  const [sectionMode, setSectionMode] = useState<'all' | 'guardrails' | 'webhooks'>(
    focus?.section ?? 'all',
  );
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'secret' | 'pii' | 'custom'>('all');
  const [webhookFilter, setWebhookFilter] = useState<'all' | 'sync_review' | 'async_event'>('all');
  const [togglingRules, setTogglingRules] = useState<Record<string, boolean>>({});
  const [togglingWebhooks, setTogglingWebhooks] = useState<Record<string, boolean>>({});

  // Guardrail Rule Modal
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<GuardrailRule | null>(null);

  // Webhook Modal
  const [whModalOpen, setWhModalOpen] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<WebhookItem | null>(null);

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
    setRuleModalOpen(true);
  };

  const openEditRule = (item: GuardrailRule) => {
    if (item.source === 'config') return;
    setEditingRule(item);
    setRuleModalOpen(true);
  };

  const handleToggleRule = async (item: GuardrailRule, next: boolean) => {
    if (item.source === 'config' || togglingRules[item.id]) return;
    setPageError(null);
    setTogglingRules((prev) => ({ ...prev, [item.id]: true }));
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
    } finally {
      setTogglingRules((prev) => ({ ...prev, [item.id]: false }));
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

  const openCreateWebhook = () => {
    setEditingWebhook(null);
    setWhModalOpen(true);
  };

  const openEditWebhook = (item: WebhookItem) => {
    if (item.source === 'config') return;
    setEditingWebhook(item);
    setWhModalOpen(true);
  };

  const handleToggleWebhook = async (item: WebhookItem, next: boolean) => {
    if (item.source === 'config' || togglingWebhooks[item.id]) return;
    setPageError(null);
    setTogglingWebhooks((prev) => ({ ...prev, [item.id]: true }));
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
    } finally {
      setTogglingWebhooks((prev) => ({ ...prev, [item.id]: false }));
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

  const handleSectionSelect = (next: 'all' | 'guardrails' | 'webhooks') => {
    setSectionMode(next);
    onSectionChange?.(next);
  };

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
              onChange={handleSectionSelect}
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
          <GuardrailPlayground />

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
                          <td style={{ maxWidth: 140 }}>
                            <div className="ap-truncate" style={{ fontWeight: 560 }} title={rule.name}>
                              {rule.name}
                            </div>
                            <div
                              className="ap-mono ap-truncate"
                              style={{ fontSize: 11, color: 'var(--ap-text-muted)' }}
                              title={rule.id}
                            >
                              {rule.id}
                            </div>
                          </td>
                          <td style={{ whiteSpace: 'nowrap' }}>
                            <SourceBadge source={rule.source} builtin={rule.builtin} />
                          </td>
                          <td style={{ textTransform: 'uppercase', fontSize: 11.5, color: 'var(--ap-text-secondary)', fontWeight: 550, whiteSpace: 'nowrap' }}>
                            {rule.category}
                          </td>
                          <td style={{ maxWidth: 145 }}>
                            <span
                              className="ap-mono ap-truncate"
                              style={{ display: 'block', fontSize: 12, color: 'var(--ap-text-secondary)' }}
                              title={rule.pattern}
                            >
                              {rule.pattern}
                            </span>
                          </td>
                          <td style={{ whiteSpace: 'nowrap' }}>
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
                              disabled={isYaml || Boolean(togglingRules[rule.id])}
                              title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                              onChange={(next) => handleToggleRule(rule, next)}
                              label={`Enable ${rule.name}`}
                            />
                          </td>
                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <div className="ap-row-actions">
                              <button
                                type="button"
                                className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                                disabled={isYaml}
                                aria-label={`Edit ${rule.name}`}
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
                                <span className="ap-action-label">Edit</span>
                              </button>
                              {canDelete && (
                                <ConfirmDeleteButton
                                  itemName={rule.name}
                                  onConfirm={() => handleDeleteRule(rule)}
                                />
                              )}
                              {isYaml && !rule.builtin && (
                                <ConfirmDeleteButton
                                  itemName={rule.name}
                                  disabled
                                  title={YAML_LOCK_TOOLTIP}
                                  onConfirm={() => handleDeleteRule(rule)}
                                />
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
                        <td style={{ maxWidth: 122 }}>
                          <div className="ap-truncate" style={{ fontWeight: 560 }} title={wh.name}>
                            {wh.name}
                          </div>
                          <div
                            className="ap-mono ap-truncate"
                            style={{ fontSize: 11, color: 'var(--ap-text-muted)' }}
                            title={wh.id}
                          >
                            {wh.id}
                          </div>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <SourceBadge source={wh.source} />
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <span
                            className={`ap-badge ${
                              wh.type === 'sync_review' ? 'ap-badge--purple' : 'ap-badge--blue'
                            }`}
                          >
                            {wh.type === 'sync_review' ? 'Sync Review' : 'Async Event'}
                          </span>
                        </td>
                        <td style={{ maxWidth: 162 }}>
                          <div
                            className="ap-mono ap-truncate"
                            style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}
                            title={wh.url}
                          >
                            {wh.url}
                          </div>
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 6,
                              marginTop: 2,
                              minWidth: 0,
                            }}
                          >
                            <span
                              className="ap-truncate"
                              style={{ fontSize: 11.5, color: 'var(--ap-text-muted)' }}
                            >
                              {wh.type === 'sync_review'
                                ? `${wh.timeout_ms} ms · ${
                                    wh.fail_open ? 'fail_open' : 'fail_closed'
                                  }`
                                : (wh.events ?? []).includes('*')
                                  ? 'All events (*)'
                                  : (wh.events ?? []).join(', ') || 'No events'}
                            </span>
                            {ping && (
                              <span
                                className={`ap-badge ap-tabular ${
                                  ping.ok ? 'ap-badge--green' : 'ap-badge--red'
                                }`}
                                style={{ flexShrink: 0 }}
                                title={ping.message}
                              >
                                {ping.ok
                                  ? `${ping.status_code} · ${formatLatency(ping.latency_ms)}`
                                  : ping.message.slice(0, 18)}
                              </span>
                            )}
                          </div>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
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
                            disabled={isYaml || Boolean(togglingWebhooks[wh.id])}
                            title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                            onChange={(next) => handleToggleWebhook(wh, next)}
                            label={`Enable ${wh.name}`}
                          />
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="ap-row-actions">
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
                              className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                              disabled={isYaml}
                              aria-label={`Edit ${wh.name}`}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${wh.name}`}
                              onClick={() => openEditWebhook(wh)}
                            >
                              <EditIcon />
                              <span className="ap-action-label">Edit</span>
                            </button>
                            <ConfirmDeleteButton
                              itemName={wh.name}
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${wh.name}`}
                              onConfirm={() => handleDeleteWebhook(wh)}
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

      <GuardrailRuleModal
        open={ruleModalOpen}
        editingRule={editingRule}
        onClose={() => setRuleModalOpen(false)}
        onSaved={loadAll}
      />

      <WebhookModal
        open={whModalOpen}
        editingWebhook={editingWebhook}
        onClose={() => setWhModalOpen(false)}
        onSaved={loadAll}
      />
    </div>
  );
}
