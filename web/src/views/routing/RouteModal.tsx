import { useEffect, useState, type FormEvent } from 'react';
import { api } from '../../api/client';
import { Modal, Toggle } from '../../components/Primitives';
import { parseRouteFallbacks } from '../../lib/format';
import type {
  ModelRouteItem,
  ModelRouteUpsertPayload,
  ProviderItem,
} from '../../types/api';

export function parseOptionalNonNegativeNumber(
  raw: string,
  fieldLabel: string,
): { value: number | null; error: string | null } {
  const trimmed = raw.trim();
  if (!trimmed) return { value: null, error: null };
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return { value: null, error: `${fieldLabel} must be a non-negative number.` };
  }
  return { value: parsed, error: null };
}

interface RouteModalProps {
  open: boolean;
  editingRoute: ModelRouteItem | null;
  providers: ProviderItem[];
  onClose: () => void;
  onSaved: () => Promise<void>;
}

export function RouteModal({
  open,
  editingRoute,
  providers,
  onClose,
  onSaved,
}: RouteModalProps) {
  const [modalError, setModalError] = useState<string | null>(null);
  const [routeAlias, setRouteAlias] = useState('');
  const [routeProvider, setRouteProvider] = useState('');
  const [routeUpstreamModel, setRouteUpstreamModel] = useState('');
  const [routeFallbacksText, setRouteFallbacksText] = useState('');
  const [routeInputCost, setRouteInputCost] = useState('');
  const [routeOutputCost, setRouteOutputCost] = useState('');
  const [routeCacheReadCost, setRouteCacheReadCost] = useState('');
  const [routeCacheWriteCost, setRouteCacheWriteCost] = useState('');
  const [routeEnabled, setRouteEnabled] = useState(true);
  const [savingRoute, setSavingRoute] = useState(false);

  useEffect(() => {
    if (!open) return;
    setModalError(null);
    if (editingRoute) {
      setRouteAlias(editingRoute.alias);
      setRouteProvider(editingRoute.provider_name);
      setRouteUpstreamModel(editingRoute.upstream_model);
      setRouteFallbacksText(
        (editingRoute.fallbacks ?? []).map((fb) => `${fb.provider}/${fb.model}`).join('\n'),
      );
      setRouteInputCost(
        editingRoute.input_cost_per_million != null
          ? String(editingRoute.input_cost_per_million)
          : '',
      );
      setRouteOutputCost(
        editingRoute.output_cost_per_million != null
          ? String(editingRoute.output_cost_per_million)
          : '',
      );
      setRouteCacheReadCost(
        editingRoute.cache_read_cost_per_million != null
          ? String(editingRoute.cache_read_cost_per_million)
          : '',
      );
      setRouteCacheWriteCost(
        editingRoute.cache_write_cost_per_million != null
          ? String(editingRoute.cache_write_cost_per_million)
          : '',
      );
      setRouteEnabled(editingRoute.enabled);
    } else {
      setRouteAlias('');
      setRouteProvider(providers[0]?.name ?? '');
      setRouteUpstreamModel('');
      setRouteFallbacksText('');
      setRouteInputCost('');
      setRouteOutputCost('');
      setRouteCacheReadCost('');
      setRouteCacheWriteCost('');
      setRouteEnabled(true);
    }
  }, [open, editingRoute]);

  useEffect(() => {
    if (!editingRoute) {
      setRouteProvider((prev) => prev || providers[0]?.name || '');
    }
  }, [providers, editingRoute]);

  const handleSaveRoute = async (event: FormEvent) => {
    event.preventDefault();
    setModalError(null);

    const alias = routeAlias.trim();
    if (!alias) {
      setModalError('Route alias is required.');
      return;
    }

    const effectiveProvider =
      routeProvider.trim() || (!editingRoute ? providers[0]?.name ?? '' : '');
    if (!effectiveProvider) {
      setModalError('Add an upstream provider first before creating a route.');
      return;
    }

    const upstreamModel = routeUpstreamModel.trim();
    if (!upstreamModel) {
      setModalError('Primary upstream model ID is required.');
      return;
    }

    const knownProviderNames = providers.map((p) => p.name);
    const parsedFallbacks = parseRouteFallbacks(routeFallbacksText, knownProviderNames);
    if (parsedFallbacks.error) {
      setModalError(parsedFallbacks.error);
      return;
    }

    const inTier = parseOptionalNonNegativeNumber(routeInputCost, 'Input cost');
    if (inTier.error) {
      setModalError(inTier.error);
      return;
    }
    const outTier = parseOptionalNonNegativeNumber(routeOutputCost, 'Output cost');
    if (outTier.error) {
      setModalError(outTier.error);
      return;
    }
    const crTier = parseOptionalNonNegativeNumber(routeCacheReadCost, 'Cache read cost');
    if (crTier.error) {
      setModalError(crTier.error);
      return;
    }
    const cwTier = parseOptionalNonNegativeNumber(routeCacheWriteCost, 'Cache write cost');
    if (cwTier.error) {
      setModalError(cwTier.error);
      return;
    }

    setSavingRoute(true);
    const payload: ModelRouteUpsertPayload = {
      alias,
      provider_name: effectiveProvider,
      upstream_model: upstreamModel,
      fallbacks: parsedFallbacks.fallbacks,
      input_cost_per_million: inTier.value,
      output_cost_per_million: outTier.value,
      cache_read_cost_per_million: crTier.value,
      cache_write_cost_per_million: cwTier.value,
      enabled: routeEnabled,
    };

    try {
      if (editingRoute) {
        await api.updateRoute(editingRoute.alias, payload);
      } else {
        await api.createRoute(payload);
      }
      onClose();
      await onSaved();
    } catch (err: unknown) {
      setModalError(
        err instanceof Error ? err.message : 'Failed to save model route',
      );
    } finally {
      setSavingRoute(false);
    }
  };

  return (
    <Modal
      open={open}
      title={editingRoute ? `Edit Route (${editingRoute.alias})` : 'Add Model Route'}
      onClose={onClose}
      maxWidth={620}
      error={modalError}
    >
      <form
        onSubmit={handleSaveRoute}
        style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
      >
        <div className="ap-form-grid">
          <label className="ap-field">
            <span className="ap-label">Virtual Alias</span>
            <input
              className="ap-input ap-mono"
              required
              disabled={Boolean(editingRoute)}
              value={routeAlias}
              onChange={(e) => setRouteAlias(e.target.value)}
              placeholder="team/coding"
            />
          </label>

          <label className="ap-field">
            <span className="ap-label">Primary Provider</span>
            <select
              className="ap-select"
              value={routeProvider}
              onChange={(e) => setRouteProvider(e.target.value)}
            >
              {providers.length === 0 && (
                <option value="">No providers configured</option>
              )}
              {providers.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name} ({p.type})
                </option>
              ))}
            </select>
          </label>
        </div>

        <label className="ap-field">
          <span className="ap-label">Primary Upstream Model ID</span>
          <input
            className="ap-input ap-mono"
            required
            value={routeUpstreamModel}
            onChange={(e) => setRouteUpstreamModel(e.target.value)}
            placeholder="claude-sonnet-4-20250514"
          />
        </label>

        <label className="ap-field">
          <span className="ap-label">Fallback Targets (one provider/model per line)</span>
          <textarea
            className="ap-textarea ap-mono"
            value={routeFallbacksText}
            onChange={(e) => setRouteFallbacksText(e.target.value)}
            placeholder={'openai/gpt-4.1\ngemini/gemini-2.5-pro'}
          />
          <span className="ap-hint">
            Each line must include both provider name and model ID separated by "/".
          </span>
        </label>

        <div className="ap-field">
          <span className="ap-label">
            Cost Overrides (USD per 1M tokens — leave blank for built-in default)
          </span>
          <div className="ap-form-grid-4">
            <label className="ap-field">
              <span className="ap-hint">Input</span>
              <input
                type="number"
                min={0}
                step="any"
                className="ap-input ap-input--sm ap-tabular"
                value={routeInputCost}
                onChange={(e) => setRouteInputCost(e.target.value)}
                placeholder="Default"
              />
            </label>
            <label className="ap-field">
              <span className="ap-hint">Output</span>
              <input
                type="number"
                min={0}
                step="any"
                className="ap-input ap-input--sm ap-tabular"
                value={routeOutputCost}
                onChange={(e) => setRouteOutputCost(e.target.value)}
                placeholder="Default"
              />
            </label>
            <label className="ap-field">
              <span className="ap-hint">Cache Read</span>
              <input
                type="number"
                min={0}
                step="any"
                className="ap-input ap-input--sm ap-tabular"
                value={routeCacheReadCost}
                onChange={(e) => setRouteCacheReadCost(e.target.value)}
                placeholder="Default"
              />
            </label>
            <label className="ap-field">
              <span className="ap-hint">Cache Write</span>
              <input
                type="number"
                min={0}
                step="any"
                className="ap-input ap-input--sm ap-tabular"
                value={routeCacheWriteCost}
                onChange={(e) => setRouteCacheWriteCost(e.target.value)}
                placeholder="Default"
              />
            </label>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="ap-label">Enabled</span>
          <Toggle
            checked={routeEnabled}
            onChange={setRouteEnabled}
            label="Route Enabled"
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
            disabled={savingRoute}
          >
            {savingRoute ? 'Saving...' : 'Save Route'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
