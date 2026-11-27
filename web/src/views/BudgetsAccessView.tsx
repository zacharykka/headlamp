import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Add, Edit, Trash } from 'reicon-react';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import {
  CodeBlock,
  Modal,
  ProgressBar,
  SegmentedControl,
  Toggle,
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
}

function parseNullableFloat(raw: string): number | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const val = Number(trimmed);
  return Number.isFinite(val) && val >= 0 ? val : null;
}

export function BudgetsAccessView({ focus }: BudgetsAccessViewProps) {
  const [budgets, setBudgets] = useState<BudgetItem[]>([]);
  const [grantsGuide, setGrantsGuide] = useState<GrantsGuideResponse | null>(null);
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>('all');
  const [error, setError] = useState<string | null>(null);

  const [modalOpen, setModalOpen] = useState(false);
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
    setError(null);
    try {
      const [budgetList, guide] = await Promise.all([
        api.listBudgets(),
        api.getGrantsGuide().catch(() => null),
      ]);
      setBudgets(budgetList);
      if (guide) setGrantsGuide(guide);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load budgets');
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
    setScope('*');
    setDailyUSD('');
    setMonthlyUSD('100');
    setRpm('60');
    setTpm('200000');
    setMaxConcurrent('8');
    setSoftAlertPct('80');
    setEnabled(true);
    setModalOpen(true);
  };

  const openEditModal = (item: BudgetItem) => {
    setEditingBudget(item);
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
    setSaving(true);
    setError(null);

    const payload: BudgetUpsertPayload = {
      scope: scope.trim(),
      daily_usd: parseNullableFloat(dailyUSD),
      monthly_usd: parseNullableFloat(monthlyUSD),
      rpm: Math.max(0, Number(rpm) || 0),
      tpm: Math.max(0, Number(tpm) || 0),
      max_concurrent: Math.max(0, Number(maxConcurrent) || 0),
      soft_alert_pct: Math.min(100, Math.max(1, Number(softAlertPct) || 80)),
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
      setError(err instanceof Error ? err.message : 'Failed to save budget');
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (item: BudgetItem, next: boolean) => {
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
      setError(err instanceof Error ? err.message : 'Failed to update budget');
    }
  };

  const handleDelete = async (targetScope: string) => {
    try {
      await api.deleteBudget(targetScope);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete budget');
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
    <>
      <section className="hl-section">
        <div className="hl-section-bar">
          <h1>Budgets</h1>
          <div className="hl-toolbar">
            <SegmentedControl
              ariaLabel="Budget scope filter"
              value={scopeFilter}
              onChange={setScopeFilter}
              options={[
                { value: 'all', label: 'All' },
                { value: 'global', label: 'Global' },
                { value: 'tag', label: 'Tags' },
                { value: 'user', label: 'Users' },
              ]}
            />
            <button
              type="button"
              className="hl-btn hl-btn-primary"
              onClick={openCreateModal}
            >
              <Icon icon={Add} />
              <span>Add Budget</span>
            </button>
          </div>
        </div>

        {error && <p className="hl-status-text hl-status-danger">{error}</p>}

        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Scope</th>
                <th style={{ minWidth: 168 }}>Daily Spend</th>
                <th style={{ minWidth: 168 }}>Monthly Spend</th>
                <th>Rate Limits</th>
                <th>Soft Alert</th>
                <th>Enabled</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filteredBudgets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="hl-secondary">
                    No budgets configured
                  </td>
                </tr>
              ) : (
                filteredBudgets.map((item) => (
                  <tr key={item.scope} className="hl-row">
                    <td className="hl-mono hl-nowrap" style={{ fontWeight: 500 }}>
                      {item.scope === '*' ? '* (Global)' : item.scope}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span>{formatUSD(item.daily_spent_usd)}</span>
                          <span className="hl-secondary">
                            {item.daily_usd != null ? formatUSD(item.daily_usd) : 'No cap'}
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
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span>{formatUSD(item.monthly_spent_usd)}</span>
                          <span className="hl-secondary">
                            {item.monthly_usd != null
                              ? formatUSD(item.monthly_usd)
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
                    <td className="hl-secondary hl-nowrap">
                      {[
                        item.rpm > 0 ? `${formatNumber(item.rpm)} RPM` : null,
                        item.tpm > 0 ? `${formatCompactTokens(item.tpm)} TPM` : null,
                        item.max_concurrent > 0 ? `${item.max_concurrent} conc` : null,
                      ]
                        .filter(Boolean)
                        .join(' · ') || '—'}
                    </td>
                    <td className="hl-secondary hl-nowrap">{item.soft_alert_pct}%</td>
                    <td>
                      <Toggle
                        checked={item.enabled}
                        onChange={(next) => handleToggle(item, next)}
                        label={`Enable budget ${item.scope}`}
                      />
                    </td>
                    <td>
                      <div className="hl-row-actions">
                        <button
                          type="button"
                          className="hl-btn hl-btn-ghost"
                          onClick={() => openEditModal(item)}
                        >
                          <Icon icon={Edit} />
                          <span>Edit</span>
                        </button>
                        <button
                          type="button"
                          className="hl-btn hl-btn-ghost hl-btn-danger"
                          onClick={() => handleDelete(item.scope)}
                        >
                          <Icon icon={Trash} />
                          <span>Delete</span>
                        </button>
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
          <h2>Headscale Grants</h2>
        </div>

        <div className="hl-split-2">
          <div className="hl-table-wrap">
            <table className="hl-table">
              <tbody>
                <tr className="hl-row">
                  <td className="hl-secondary">Subject</td>
                  <td className="hl-mono">{policy?.subject || '—'}</td>
                </tr>
                <tr className="hl-row">
                  <td className="hl-secondary">Grants Status</td>
                  <td
                    className={
                      policy?.grants_applied ? 'hl-status-accent' : 'hl-secondary'
                    }
                    style={{ fontWeight: 500 }}
                  >
                    {policy?.grants_applied ? 'Active' : 'No matching grants'}
                  </td>
                </tr>
                <tr className="hl-row">
                  <td className="hl-secondary">Roles</td>
                  <td className="hl-mono">
                    {(policy?.roles ?? []).join(', ') || '—'}
                  </td>
                </tr>
                <tr className="hl-row">
                  <td className="hl-secondary">Allow Models</td>
                  <td className="hl-mono">
                    {(policy?.allow_models ?? []).join(', ') || '—'}
                  </td>
                </tr>
                <tr className="hl-row">
                  <td className="hl-secondary">Deny Models</td>
                  <td className="hl-mono">
                    {(policy?.deny_models ?? []).join(', ') || '—'}
                  </td>
                </tr>
                <tr className="hl-row">
                  <td className="hl-secondary">Allow MCP Tools</td>
                  <td className="hl-mono">
                    {(policy?.allow_mcp_tools ?? []).join(', ') || '—'}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          {grantsGuide?.headscale_example && (
            <CodeBlock code={grantsGuide.headscale_example} />
          )}
        </div>
      </section>

      <Modal
        open={modalOpen}
        title={editingBudget ? `Edit Budget (${editingBudget.scope})` : 'Add Budget'}
        onClose={() => setModalOpen(false)}
      >
        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <label className="hl-field">
            <span className="hl-label">Scope (*, tag:name, or user@domain)</span>
            <input
              className="hl-input hl-mono"
              required
              disabled={Boolean(editingBudget)}
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder="tag:engineering"
            />
          </label>

          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Daily Cap (USD)</span>
              <input
                type="number"
                min={0}
                step="any"
                className="hl-input"
                value={dailyUSD}
                onChange={(e) => setDailyUSD(e.target.value)}
                placeholder="No cap"
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Monthly Cap (USD)</span>
              <input
                type="number"
                min={0}
                step="any"
                className="hl-input"
                value={monthlyUSD}
                onChange={(e) => setMonthlyUSD(e.target.value)}
                placeholder="100.00"
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">RPM Limit</span>
              <input
                type="number"
                className="hl-input"
                value={rpm}
                onChange={(e) => setRpm(e.target.value)}
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">TPM Limit</span>
              <input
                type="number"
                className="hl-input"
                value={tpm}
                onChange={(e) => setTpm(e.target.value)}
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Max Concurrent</span>
              <input
                type="number"
                className="hl-input"
                value={maxConcurrent}
                onChange={(e) => setMaxConcurrent(e.target.value)}
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Soft Alert (%)</span>
              <input
                type="number"
                min={1}
                max={100}
                className="hl-input"
                value={softAlertPct}
                onChange={(e) => setSoftAlertPct(e.target.value)}
              />
            </label>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Enabled</span>
            <Toggle checked={enabled} onChange={setEnabled} label="Budget Enabled" />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, paddingTop: 8 }}>
            <button
              type="button"
              className="hl-btn"
              onClick={() => setModalOpen(false)}
            >
              Cancel
            </button>
            <button type="submit" className="hl-btn hl-btn-primary" disabled={saving}>
              {saving ? 'Saving' : 'Save Budget'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
