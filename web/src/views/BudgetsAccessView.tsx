import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  EditIcon,
  PlusIcon,
  TailnetMeshGlyph,
  TrashIcon,
} from '../components/ApertureIcons';
import {
  CodeBlock,
  Modal,
  ProgressBar,
  SegmentedControl,
  SourceBadge,
  Toggle,
  YAML_LOCK_TOOLTIP,
} from '../components/Primitives';
import { formatCompactTokens, formatNumber, formatUSD } from '../lib/format';
import type {
  BudgetItem,
  BudgetUpsertPayload,
  GrantsGuideResponse,
} from '../types/api';

type ScopeFilter = 'all' | 'global' | 'tag' | 'user';

export interface BudgetsFocusState {
  scopeFilter?: ScopeFilter;
  openCreate?: boolean;
  nonce?: number;
}

interface BudgetsAccessViewProps {
  focus?: BudgetsFocusState;
  onCountChange?: (count: number) => void;
}

function parseOptionalCap(
  raw: string,
  label: string,
): { value: number | null; error: string | null } {
  const trimmed = raw.trim();
  if (!trimmed) return { value: null, error: null };
  const val = Number(trimmed);
  if (!Number.isFinite(val) || val < 0) {
    return { value: null, error: `${label} must be 0 or greater.` };
  }
  return { value: val, error: null };
}

export function BudgetsAccessView({
  focus,
  onCountChange,
}: BudgetsAccessViewProps) {
  const [budgets, setBudgets] = useState<BudgetItem[]>([]);
  const [grantsGuide, setGrantsGuide] = useState<GrantsGuideResponse | null>(null);
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>('all');
  const [pageError, setPageError] = useState<string | null>(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [editingBudget, setEditingBudget] = useState<BudgetItem | null>(null);
  const [scope, setScope] = useState('*');
  const [dailyUSD, setDailyUSD] = useState('');
  const [monthlyUSD, setMonthlyUSD] = useState('');
  const [rpm, setRpm] = useState('60');
  const [tpm, setTpm] = useState('200000');
  const [maxConcurrent, setMaxConcurrent] = useState('8');
  const [softAlertPct, setSoftAlertPct] = useState('80');
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  const loadAll = async () => {
    setPageError(null);
    try {
      const [budgetList, guide] = await Promise.all([
        api.listBudgets(),
        api.getGrantsGuide().catch(() => null),
      ]);
      setBudgets(budgetList);
      onCountChange?.(budgetList.length);
      if (guide) setGrantsGuide(guide);
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to load quotas and grants');
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    if (!focus) return;
    if (focus.scopeFilter) setScopeFilter(focus.scopeFilter);
    if (focus.openCreate) openCreateModal();
  }, [focus?.nonce]);

  const openCreateModal = () => {
    setEditingBudget(null);
    setModalError(null);
    setScope('*');
    setDailyUSD('25');
    setMonthlyUSD('250');
    setRpm('60');
    setTpm('200000');
    setMaxConcurrent('8');
    setSoftAlertPct('80');
    setEnabled(true);
    setModalOpen(true);
  };

  const openEditModal = (item: BudgetItem) => {
    if (item.source === 'config') return;
    setEditingBudget(item);
    setModalError(null);
    setScope(item.scope);
    setDailyUSD(item.daily_usd != null ? String(item.daily_usd) : '');
    setMonthlyUSD(item.monthly_usd != null ? String(item.monthly_usd) : '');
    setRpm(String(item.rpm ?? 0));
    setTpm(String(item.tpm ?? 0));
    setMaxConcurrent(String(item.max_concurrent ?? 0));
    setSoftAlertPct(String(item.soft_alert_pct || 80));
    setEnabled(item.enabled);
    setModalOpen(true);
  };

  const handleSave = async (event: FormEvent) => {
    event.preventDefault();
    setModalError(null);

    const trimmedScope = scope.trim();
    if (!trimmedScope) {
      setModalError('Budget scope is required (*, tag:<name>, or user@domain).');
      return;
    }

    const parsedDaily = parseOptionalCap(dailyUSD, 'Daily cap');
    if (parsedDaily.error) {
      setModalError(parsedDaily.error);
      return;
    }
    const parsedMonthly = parseOptionalCap(monthlyUSD, 'Monthly cap');
    if (parsedMonthly.error) {
      setModalError(parsedMonthly.error);
      return;
    }

    const parsedSoft = Number(softAlertPct);
    if (!Number.isFinite(parsedSoft) || parsedSoft < 1 || parsedSoft > 100) {
      setModalError('Soft alert threshold must be between 1% and 100%.');
      return;
    }

    setSaving(true);
    const payload: BudgetUpsertPayload = {
      scope: trimmedScope,
      daily_usd: parsedDaily.value,
      monthly_usd: parsedMonthly.value,
      rpm: Math.max(0, Math.floor(Number(rpm) || 0)),
      tpm: Math.max(0, Math.floor(Number(tpm) || 0)),
      max_concurrent: Math.max(0, Math.floor(Number(maxConcurrent) || 0)),
      soft_alert_pct: Math.floor(parsedSoft),
      enabled,
    };

    try {
      if (editingBudget) {
        await api.updateBudget(editingBudget.scope, payload);
      } else {
        await api.createBudget(payload);
      }
      setModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setModalError(err instanceof Error ? err.message : 'Failed to save quota');
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (item: BudgetItem, next: boolean) => {
    if (item.source === 'config') return;
    setPageError(null);
    try {
      await api.updateBudget(item.scope, {
        scope: item.scope,
        daily_usd: item.daily_usd ?? null,
        monthly_usd: item.monthly_usd ?? null,
        rpm: item.rpm,
        tpm: item.tpm,
        max_concurrent: item.max_concurrent,
        soft_alert_pct: item.soft_alert_pct,
        enabled: next,
      });
      setBudgets((prev) =>
        prev.map((b) => (b.scope === item.scope ? { ...b, enabled: next } : b)),
      );
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to update quota');
    }
  };

  const handleDelete = async (item: BudgetItem) => {
    if (item.source === 'config') return;
    setPageError(null);
    try {
      await api.deleteBudget(item.scope);
      await loadAll();
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to delete quota');
    }
  };

  const filteredBudgets = useMemo(() => {
    return budgets.filter((b) => {
      if (scopeFilter === 'global') return b.scope === '*';
      if (scopeFilter === 'tag') return b.scope.startsWith('tag:');
      if (scopeFilter === 'user') return b.scope !== '*' && !b.scope.startsWith('tag:');
      return true;
    });
  }, [budgets, scopeFilter]);

  const policy = grantsGuide?.policy;

  return (
    <div className="ap-page">
      <header className="ap-page-header">
        <div className="ap-page-title-row">
          <div>
            <h1 className="ap-page-title">Quotas & Tailnet Grants</h1>
            <p className="ap-page-subtitle">
              Enforce USD spend caps and rate limits per scope while delegating model access to Headscale & Tailscale grants.
            </p>
          </div>
        </div>

        <div className="ap-filter-bar">
          <div className="ap-filter-group">
            <SegmentedControl
              ariaLabel="Budget scope filter"
              value={scopeFilter}
              onChange={setScopeFilter}
              options={[
                { value: 'all', label: 'All Scopes' },
                { value: 'global', label: 'Global (*)' },
                { value: 'tag', label: 'Node Tags' },
                { value: 'user', label: 'Users' },
              ]}
            />
          </div>

          <button
            type="button"
            className="ap-btn ap-btn-primary"
            onClick={openCreateModal}
          >
            <PlusIcon />
            <span>Add Quota</span>
          </button>
        </div>
      </header>

      {pageError && (
        <div className="ap-alert ap-alert--danger" role="alert">
          <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{pageError}</span>
        </div>
      )}

      <section className="ap-card" aria-label="Spend and rate limit budgets">
        <div className="ap-card-header">
          <div>
            <h2 className="ap-card-title">Quota Policies ({filteredBudgets.length})</h2>
            <p className="ap-card-subtitle">
              Scopes match Global (*), Tailnet node tags (tag:*), or individual Tailnet user subjects.
            </p>
          </div>
        </div>

        <div className="ap-table-wrap">
          <table className="ap-table">
            <thead>
              <tr>
                <th>Scope</th>
                <th>Origin</th>
                <th style={{ minWidth: 122 }}>Daily Consumption</th>
                <th style={{ minWidth: 122 }}>Monthly Consumption</th>
                <th>Rate & Concurrency</th>
                <th>Enabled</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredBudgets.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ color: 'var(--ap-text-muted)', padding: '26px 14px', textAlign: 'center' }}>
                    No quota policies configured for this scope filter.
                  </td>
                </tr>
              ) : (
                filteredBudgets.map((item) => {
                  const isYaml = item.source === 'config';
                  return (
                    <tr key={item.scope} className="ap-row">
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                          <span className="ap-mono" style={{ fontWeight: 600 }}>
                            {item.scope === '*' ? '* (Global)' : item.scope}
                          </span>
                          <span style={{ fontSize: 11.5, color: 'var(--ap-text-muted)' }}>
                            Alert at {item.soft_alert_pct}%
                          </span>
                        </div>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <SourceBadge source={item.source} />
                      </td>
                      <td style={{ maxWidth: 155 }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          <div
                            className="ap-tabular"
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              gap: 6,
                              fontSize: 12,
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <span style={{ fontWeight: 600 }}>
                              {formatUSD(item.daily_spent_usd)}
                            </span>
                            <span style={{ color: 'var(--ap-text-muted)' }}>
                              {item.daily_usd != null
                                ? `/ ${formatUSD(item.daily_usd)}`
                                : 'No cap'}
                            </span>
                          </div>
                          {item.daily_usd != null && (
                            <ProgressBar
                              spent={item.daily_spent_usd}
                              limit={item.daily_usd}
                              softAlertPct={item.soft_alert_pct}
                            />
                          )}
                        </div>
                      </td>
                      <td style={{ maxWidth: 155 }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          <div
                            className="ap-tabular"
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              gap: 6,
                              fontSize: 12,
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <span style={{ fontWeight: 600 }}>
                              {formatUSD(item.monthly_spent_usd)}
                            </span>
                            <span style={{ color: 'var(--ap-text-muted)' }}>
                              {item.monthly_usd != null
                                ? `/ ${formatUSD(item.monthly_usd)}`
                                : 'No cap'}
                            </span>
                          </div>
                          {item.monthly_usd != null && (
                            <ProgressBar
                              spent={item.monthly_spent_usd}
                              limit={item.monthly_usd}
                              softAlertPct={item.soft_alert_pct}
                            />
                          )}
                        </div>
                      </td>
                      <td
                        className="ap-tabular"
                        style={{
                          color: 'var(--ap-text-secondary)',
                          fontSize: 11.5,
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {[
                          item.rpm > 0 ? `${formatNumber(item.rpm)} RPM` : null,
                          item.tpm > 0 ? `${formatCompactTokens(item.tpm)} TPM` : null,
                          item.max_concurrent > 0 ? `${item.max_concurrent} conc` : null,
                        ]
                          .filter(Boolean)
                          .join(' · ') || 'Unlimited'}
                      </td>
                      <td>
                        <Toggle
                          checked={item.enabled}
                          disabled={isYaml}
                          title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                          onChange={(next) => handleToggle(item, next)}
                          label={`Enable budget ${item.scope}`}
                        />
                      </td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <div className="ap-row-actions">
                          <button
                            type="button"
                            className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                            disabled={isYaml}
                            aria-label={`Edit ${item.scope}`}
                            title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${item.scope}`}
                            onClick={() => openEditModal(item)}
                          >
                            <EditIcon />
                            <span className="ap-action-label">Edit</span>
                          </button>
                          <button
                            type="button"
                            className="ap-btn ap-btn-ghost ap-btn-danger ap-btn-sm ap-btn-icon-compact"
                            disabled={isYaml}
                            aria-label={`Delete ${item.scope}`}
                            title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${item.scope}`}
                            onClick={() => handleDelete(item)}
                          >
                            <TrashIcon />
                            <span className="ap-action-label">Delete</span>
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

      <div className="ap-split-2">
        <section className="ap-card" aria-label="Live Headscale grants inspector">
          <div
            className="ap-card-header"
            style={{ flexWrap: 'nowrap', alignItems: 'flex-start' }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 8,
                flex: 1,
                minWidth: 0,
              }}
            >
              <span style={{ marginTop: 2, display: 'inline-flex', flexShrink: 0 }}>
                <TailnetMeshGlyph size={16} />
              </span>
              <div style={{ minWidth: 0 }}>
                <h2 className="ap-card-title">Live Policy Inspector</h2>
                <p className="ap-card-subtitle">
                  Evaluated headlamp.dev/cap/gateway capabilities for your session.
                </p>
              </div>
            </div>
            <span
              className={`ap-badge ${
                policy?.grants_applied ? 'ap-badge--green' : 'ap-badge--amber'
              }`}
              style={{ flexShrink: 0 }}
            >
              {policy?.grants_applied ? 'Grants Active' : 'No Matching Grants'}
            </span>
          </div>

          <div className="ap-table-wrap">
            <table className="ap-table">
              <tbody>
                <tr className="ap-row">
                  <td style={{ color: 'var(--ap-text-secondary)', width: 140 }}>Subject</td>
                  <td className="ap-mono" style={{ fontWeight: 560 }}>
                    {policy?.subject || '—'}
                  </td>
                </tr>
                <tr className="ap-row">
                  <td style={{ color: 'var(--ap-text-secondary)' }}>Roles</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {(policy?.roles ?? []).length > 0 ? (
                        (policy?.roles ?? []).map((r) => (
                          <span key={r} className="ap-badge ap-badge--blue ap-mono">
                            {r}
                          </span>
                        ))
                      ) : (
                        <span style={{ color: 'var(--ap-text-muted)' }}>—</span>
                      )}
                    </div>
                  </td>
                </tr>
                <tr className="ap-row">
                  <td style={{ color: 'var(--ap-text-secondary)' }}>Allowed Models</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {(policy?.allow_models ?? []).length > 0 ? (
                        (policy?.allow_models ?? []).map((m) => (
                          <span key={m} className="ap-badge ap-mono">
                            {m}
                          </span>
                        ))
                      ) : (
                        <span style={{ color: 'var(--ap-text-muted)' }}>None</span>
                      )}
                    </div>
                  </td>
                </tr>
                <tr className="ap-row">
                  <td style={{ color: 'var(--ap-text-secondary)' }}>Denied Models</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {(policy?.deny_models ?? []).length > 0 ? (
                        (policy?.deny_models ?? []).map((m) => (
                          <span key={m} className="ap-badge ap-badge--red ap-mono">
                            {m}
                          </span>
                        ))
                      ) : (
                        <span style={{ color: 'var(--ap-text-muted)' }}>None</span>
                      )}
                    </div>
                  </td>
                </tr>
                <tr className="ap-row">
                  <td style={{ color: 'var(--ap-text-secondary)' }}>Allowed MCP Tools</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {(policy?.allow_mcp_tools ?? []).length > 0 ? (
                        (policy?.allow_mcp_tools ?? []).map((t) => (
                          <span key={t} className="ap-badge ap-mono">
                            {t}
                          </span>
                        ))
                      ) : (
                        <span style={{ color: 'var(--ap-text-muted)' }}>—</span>
                      )}
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section className="ap-card" aria-label="Headscale policy template">
          <div className="ap-card-header">
            <div>
              <h2 className="ap-card-title">Headscale policy.hujson Template</h2>
              <p className="ap-card-subtitle">
                Paste into Headscale v0.29+ or Tailscale ACL grants to govern roles and model globs.
              </p>
            </div>
          </div>
          <div className="ap-card-body">
            {grantsGuide?.headscale_example ? (
              <CodeBlock
                label="policy.hujson · headlamp.dev/cap/gateway"
                code={grantsGuide.headscale_example}
              />
            ) : (
              <p style={{ color: 'var(--ap-text-muted)' }}>
                Loading policy template...
              </p>
            )}
          </div>
        </section>
      </div>

      <Modal
        open={modalOpen}
        title={editingBudget ? `Edit Quota (${editingBudget.scope})` : 'Add Quota Policy'}
        onClose={() => setModalOpen(false)}
        error={modalError}
      >
        <form
          onSubmit={handleSave}
          style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
        >
          <label className="ap-field">
            <span className="ap-label">Scope (*, tag:name, or user@domain)</span>
            <input
              className="ap-input ap-mono"
              required
              disabled={Boolean(editingBudget)}
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder="tag:engineering"
            />
          </label>

          <div className="ap-form-grid">
            <label className="ap-field">
              <span className="ap-label">Daily Cap (USD)</span>
              <input
                type="number"
                min={0}
                step="any"
                className="ap-input ap-tabular"
                value={dailyUSD}
                onChange={(e) => setDailyUSD(e.target.value)}
                placeholder="No cap"
              />
            </label>
            <label className="ap-field">
              <span className="ap-label">Monthly Cap (USD)</span>
              <input
                type="number"
                min={0}
                step="any"
                className="ap-input ap-tabular"
                value={monthlyUSD}
                onChange={(e) => setMonthlyUSD(e.target.value)}
                placeholder="No cap"
              />
            </label>
            <label className="ap-field">
              <span className="ap-label">RPM Limit (0 = unlimited)</span>
              <input
                type="number"
                min={0}
                className="ap-input ap-tabular"
                value={rpm}
                onChange={(e) => setRpm(e.target.value)}
              />
            </label>
            <label className="ap-field">
              <span className="ap-label">TPM Limit (0 = unlimited)</span>
              <input
                type="number"
                min={0}
                className="ap-input ap-tabular"
                value={tpm}
                onChange={(e) => setTpm(e.target.value)}
              />
            </label>
            <label className="ap-field">
              <span className="ap-label">Max Concurrent Requests</span>
              <input
                type="number"
                min={0}
                className="ap-input ap-tabular"
                value={maxConcurrent}
                onChange={(e) => setMaxConcurrent(e.target.value)}
              />
            </label>
            <label className="ap-field">
              <span className="ap-label">Soft Alert Threshold (%)</span>
              <input
                type="number"
                min={1}
                max={100}
                className="ap-input ap-tabular"
                value={softAlertPct}
                onChange={(e) => setSoftAlertPct(e.target.value)}
              />
            </label>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="ap-label">Enabled</span>
            <Toggle checked={enabled} onChange={setEnabled} label="Quota Enabled" />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, paddingTop: 6 }}>
            <button
              type="button"
              className="ap-btn"
              onClick={() => setModalOpen(false)}
            >
              Cancel
            </button>
            <button type="submit" className="ap-btn ap-btn-primary" disabled={saving}>
              {saving ? 'Saving...' : 'Save Quota'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
