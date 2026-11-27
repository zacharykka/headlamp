import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Add, Edit, Play, Trash } from 'reicon-react';
import { api } from '../api/client';
import { CascadeMenu } from '../components/CascadeMenu';
import { Icon } from '../components/Icon';
import { Modal, Toggle } from '../components/Primitives';
import { formatLatency, formatUSD } from '../lib/format';
import type {
  ModelRouteItem,
  ModelRouteUpsertPayload,
  PricingResponse,
  ProviderItem,
  ProviderTestResult,
  ProviderUpsertPayload,
  RouteFallback,
} from '../types/api';

const DEFAULT_BASE_URLS: Record<string, string> = {
  openai: 'https://api.openai.com',
  anthropic: 'https://api.anthropic.com',
  gemini: 'https://generativelanguage.googleapis.com',
  ollama: 'http://127.0.0.1:11434',
};

export interface RoutingFocusState {
  providerType?: string;
  routeFilter?: 'all' | 'fallbacks' | 'custom_pricing';
  modal?: 'provider' | 'route' | 'pricing' | null;
  nonce?: number;
}

interface RoutingViewProps {
  focus?: RoutingFocusState;
}

function parseOptionalNumber(raw: string): number | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseFallbacks(raw: string): RouteFallback[] {
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const slashIdx = line.indexOf('/');
      if (slashIdx <= 0) {
        return { provider: '', model: line };
      }
      return {
        provider: line.slice(0, slashIdx).trim(),
        model: line.slice(slashIdx + 1).trim(),
      };
    })
    .filter((fb) => fb.provider && fb.model);
}

export function RoutingView({ focus }: RoutingViewProps) {
  const [providers, setProviders] = useState<ProviderItem[]>([]);
  const [routes, setRoutes] = useState<ModelRouteItem[]>([]);
  const [pricing, setPricing] = useState<PricingResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [providerTypeFilter, setProviderTypeFilter] = useState<string>('all');
  const [routeFilter, setRouteFilter] = useState<'all' | 'fallbacks' | 'custom_pricing'>(
    'all',
  );

  const [testResults, setTestResults] = useState<Record<string, ProviderTestResult>>({});
  const [testingName, setTestingName] = useState<string | null>(null);

  // Provider Modal State
  const [providerModalOpen, setProviderModalOpen] = useState(false);
  const [editingProvider, setEditingProvider] = useState<ProviderItem | null>(null);
  const [provName, setProvName] = useState('');
  const [provType, setProvType] = useState('openai');
  const [provBaseURL, setProvBaseURL] = useState(DEFAULT_BASE_URLS.openai);
  const [provAPIKey, setProvAPIKey] = useState('');
  const [provClearKey, setProvClearKey] = useState(false);
  const [provModels, setProvModels] = useState('');
  const [provPassthrough, setProvPassthrough] = useState(false);
  const [provEnabled, setProvEnabled] = useState(true);
  const [savingProvider, setSavingProvider] = useState(false);

  // Route Modal State
  const [routeModalOpen, setRouteModalOpen] = useState(false);
  const [editingRoute, setEditingRoute] = useState<ModelRouteItem | null>(null);
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

  // Pricing Modal State
  const [pricingModalOpen, setPricingModalOpen] = useState(false);

  const loadAll = async () => {
    setError(null);
    try {
      const [provList, routeList, pricingRes] = await Promise.all([
        api.listProviders(),
        api.listRoutes(),
        api.getPricing().catch(() => null),
      ]);
      setProviders(provList);
      setRoutes(routeList);
      if (pricingRes) setPricing(pricingRes);
      setRouteProvider((prev) => prev || provList[0]?.name || '');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load routing');
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    if (!focus) return;
    if (focus.providerType) setProviderTypeFilter(focus.providerType);
    if (focus.routeFilter) setRouteFilter(focus.routeFilter);
    if (focus.modal === 'provider') {
      openCreateProvider();
    } else if (focus.modal === 'route') {
      openCreateRoute();
    } else if (focus.modal === 'pricing') {
      setPricingModalOpen(true);
    }
  }, [focus?.nonce]);

  const openCreateProvider = () => {
    setEditingProvider(null);
    setProvName('');
    setProvType('openai');
    setProvBaseURL(DEFAULT_BASE_URLS.openai);
    setProvAPIKey('');
    setProvClearKey(false);
    setProvModels('');
    setProvPassthrough(false);
    setProvEnabled(true);
    setProviderModalOpen(true);
  };

  const openEditProvider = (item: ProviderItem) => {
    setEditingProvider(item);
    setProvName(item.name);
    setProvType(item.type);
    setProvBaseURL(item.base_url);
    setProvAPIKey('');
    setProvClearKey(false);
    setProvModels((item.models ?? []).join(', '));
    setProvPassthrough(item.passthrough);
    setProvEnabled(item.enabled);
    setProviderModalOpen(true);
  };

  const handleSaveProvider = async (event: FormEvent) => {
    event.preventDefault();
    setSavingProvider(true);
    setError(null);
    const payload: ProviderUpsertPayload = {
      name: provName.trim(),
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
      setProviderModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save provider');
    } finally {
      setSavingProvider(false);
    }
  };

  const handleToggleProvider = async (item: ProviderItem, enabled: boolean) => {
    try {
      await api.updateProvider(item.name, {
        name: item.name,
        type: item.type,
        base_url: item.base_url,
        passthrough: item.passthrough,
        models: item.models ?? [],
        enabled,
      });
      setProviders((prev) =>
        prev.map((p) => (p.name === item.name ? { ...p, enabled } : p)),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update provider');
    }
  };

  const handleDeleteProvider = async (name: string) => {
    try {
      await api.deleteProvider(name);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete provider');
    }
  };

  const handleTestProvider = async (name: string) => {
    setTestingName(name);
    try {
      const res = await api.testProvider(name);
      setTestResults((prev) => ({ ...prev, [name]: res }));
    } catch (err: unknown) {
      setTestResults((prev) => ({
        ...prev,
        [name]: {
          ok: false,
          latency_ms: 0,
          message: err instanceof Error ? err.message : 'Connection failed',
        },
      }));
    } finally {
      setTestingName(null);
    }
  };

  const openCreateRoute = () => {
    setEditingRoute(null);
    setRouteAlias('');
    setRouteProvider(providers[0]?.name ?? '');
    setRouteUpstreamModel('');
    setRouteFallbacksText('');
    setRouteInputCost('');
    setRouteOutputCost('');
    setRouteCacheReadCost('');
    setRouteCacheWriteCost('');
    setRouteEnabled(true);
    setRouteModalOpen(true);
  };

  const openEditRoute = (item: ModelRouteItem) => {
    setEditingRoute(item);
    setRouteAlias(item.alias);
    setRouteProvider(item.provider_name);
    setRouteUpstreamModel(item.upstream_model);
    setRouteFallbacksText(
      (item.fallbacks ?? []).map((fb) => `${fb.provider}/${fb.model}`).join('\n'),
    );
    setRouteInputCost(
      item.input_cost_per_million !== null && item.input_cost_per_million !== undefined
        ? String(item.input_cost_per_million)
        : '',
    );
    setRouteOutputCost(
      item.output_cost_per_million !== null && item.output_cost_per_million !== undefined
        ? String(item.output_cost_per_million)
        : '',
    );
    setRouteCacheReadCost(
      item.cache_read_cost_per_million !== null &&
        item.cache_read_cost_per_million !== undefined
        ? String(item.cache_read_cost_per_million)
        : '',
    );
    setRouteCacheWriteCost(
      item.cache_write_cost_per_million !== null &&
        item.cache_write_cost_per_million !== undefined
        ? String(item.cache_write_cost_per_million)
        : '',
    );
    setRouteEnabled(item.enabled);
    setRouteModalOpen(true);
  };

  const handleSaveRoute = async (event: FormEvent) => {
    event.preventDefault();
    setSavingRoute(true);
    setError(null);

    const effectiveProvider =
      routeProvider.trim() || (!editingRoute ? providers[0]?.name ?? '' : '');

    const payload: ModelRouteUpsertPayload = {
      alias: routeAlias.trim(),
      provider_name: effectiveProvider,
      upstream_model: routeUpstreamModel.trim(),
      fallbacks: parseFallbacks(routeFallbacksText),
      input_cost_per_million: parseOptionalNumber(routeInputCost),
      output_cost_per_million: parseOptionalNumber(routeOutputCost),
      cache_read_cost_per_million: parseOptionalNumber(routeCacheReadCost),
      cache_write_cost_per_million: parseOptionalNumber(routeCacheWriteCost),
      enabled: routeEnabled,
    };

    try {
      if (editingRoute) {
        await api.updateRoute(editingRoute.alias, payload);
      } else {
        await api.createRoute(payload);
      }
      setRouteModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save route');
    } finally {
      setSavingRoute(false);
    }
  };

  const handleToggleRoute = async (item: ModelRouteItem, enabled: boolean) => {
    try {
      await api.updateRoute(item.alias, {
        alias: item.alias,
        provider_name: item.provider_name,
        upstream_model: item.upstream_model,
        fallbacks: item.fallbacks ?? [],
        input_cost_per_million: item.input_cost_per_million ?? null,
        output_cost_per_million: item.output_cost_per_million ?? null,
        cache_read_cost_per_million: item.cache_read_cost_per_million ?? null,
        cache_write_cost_per_million: item.cache_write_cost_per_million ?? null,
        enabled,
      });
      setRoutes((prev) =>
        prev.map((r) => (r.alias === item.alias ? { ...r, enabled } : r)),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update route');
    }
  };

  const handleDeleteRoute = async (alias: string) => {
    try {
      await api.deleteRoute(alias);
      await loadAll();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete route');
    }
  };

  const filteredProviders = useMemo(() => {
    if (providerTypeFilter === 'all') return providers;
    return providers.filter((p) => p.type === providerTypeFilter);
  }, [providers, providerTypeFilter]);

  const filteredRoutes = useMemo(() => {
    if (routeFilter === 'fallbacks') {
      return routes.filter((r) => (r.fallbacks?.length ?? 0) > 0);
    }
    if (routeFilter === 'custom_pricing') {
      return routes.filter(
        (r) =>
          r.input_cost_per_million != null ||
          r.output_cost_per_million != null ||
          r.cache_read_cost_per_million != null ||
          r.cache_write_cost_per_million != null,
      );
    }
    return routes;
  }, [routes, routeFilter]);

  const exactPricingEntries = Object.entries(pricing?.exact ?? {});
  const patternPricingEntries = pricing?.patterns ?? [];

  return (
    <>
      <section className="hl-section">
        <div className="hl-section-bar">
          <h1>Providers</h1>
          <div className="hl-toolbar">
            <CascadeMenu
              label={
                providerTypeFilter === 'all' && routeFilter === 'all'
                  ? 'Filter'
                  : `Filter: ${
                      providerTypeFilter !== 'all' ? providerTypeFilter : routeFilter
                    }`
              }
              items={[
                {
                  id: 'prov-filter',
                  label: 'Provider Protocol',
                  children: [
                    {
                      id: 'all',
                      label: 'All Protocols',
                      selected: providerTypeFilter === 'all',
                      onSelect: () => setProviderTypeFilter('all'),
                    },
                    {
                      id: 'openai',
                      label: 'OpenAI',
                      selected: providerTypeFilter === 'openai',
                      onSelect: () => setProviderTypeFilter('openai'),
                    },
                    {
                      id: 'anthropic',
                      label: 'Anthropic',
                      selected: providerTypeFilter === 'anthropic',
                      onSelect: () => setProviderTypeFilter('anthropic'),
                    },
                    {
                      id: 'gemini',
                      label: 'Gemini',
                      selected: providerTypeFilter === 'gemini',
                      onSelect: () => setProviderTypeFilter('gemini'),
                    },
                    {
                      id: 'ollama',
                      label: 'Ollama',
                      selected: providerTypeFilter === 'ollama',
                      onSelect: () => setProviderTypeFilter('ollama'),
                    },
                  ],
                },
                {
                  id: 'route-filter',
                  label: 'Route Traits',
                  children: [
                    {
                      id: 'r-all',
                      label: 'All Routes',
                      selected: routeFilter === 'all',
                      onSelect: () => setRouteFilter('all'),
                    },
                    {
                      id: 'r-fb',
                      label: 'With Fallbacks',
                      selected: routeFilter === 'fallbacks',
                      onSelect: () => setRouteFilter('fallbacks'),
                    },
                    {
                      id: 'r-price',
                      label: 'Custom Pricing',
                      selected: routeFilter === 'custom_pricing',
                      onSelect: () => setRouteFilter('custom_pricing'),
                    },
                  ],
                },
              ]}
            />
            <button
              type="button"
              className="hl-btn hl-btn-primary"
              onClick={openCreateProvider}
            >
              <Icon icon={Add} />
              <span>Add Provider</span>
            </button>
          </div>
        </div>

        {error && <p className="hl-status-text hl-status-danger">{error}</p>}

        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Protocol</th>
                <th>Base URL</th>
                <th>Credentials</th>
                <th>Models</th>
                <th>Enabled</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filteredProviders.length === 0 ? (
                <tr>
                  <td colSpan={7} className="hl-secondary">
                    No providers configured
                  </td>
                </tr>
              ) : (
                filteredProviders.map((prov) => {
                  const testStatus = testResults[prov.name];
                  const isTesting = testingName === prov.name;
                  return (
                    <tr key={prov.name} className="hl-row">
                      <td className="hl-nowrap" style={{ fontWeight: 500 }}>
                        {prov.name}
                      </td>
                      <td className="hl-secondary hl-nowrap">{prov.type}</td>
                      <td
                        className="hl-mono hl-secondary"
                        style={{
                          maxWidth: 224,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {prov.base_url}
                      </td>
                      <td className="hl-nowrap">
                        {prov.has_api_key ? (
                          <span className="hl-mono">
                            {prov.api_key_preview || 'Stored'}
                          </span>
                        ) : prov.passthrough ? (
                          <span className="hl-secondary">Passthrough</span>
                        ) : (
                          <span className="hl-secondary">None</span>
                        )}
                      </td>
                      <td
                        className="hl-secondary"
                        style={{
                          maxWidth: 192,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {(prov.models ?? []).length > 0
                          ? (prov.models ?? []).join(', ')
                          : '—'}
                      </td>
                      <td>
                        <Toggle
                          checked={prov.enabled}
                          onChange={(next) => handleToggleProvider(prov, next)}
                          label={`Enable ${prov.name}`}
                        />
                      </td>
                      <td className="hl-nowrap">
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 12 }}>
                          {testStatus && (
                            <span
                              className={
                                testStatus.ok
                                  ? 'hl-status-text hl-status-accent hl-nowrap'
                                  : 'hl-status-text hl-status-danger hl-nowrap'
                              }
                            >
                              {testStatus.ok
                                ? formatLatency(testStatus.latency_ms)
                                : testStatus.message}
                            </span>
                          )}
                          <div
                            className="hl-row-actions"
                            data-visible={isTesting}
                          >
                            <button
                              type="button"
                              className="hl-btn hl-btn-ghost"
                              disabled={isTesting}
                              onClick={() => handleTestProvider(prov.name)}
                            >
                              <Icon icon={Play} />
                              <span>{isTesting ? 'Testing' : 'Test'}</span>
                            </button>
                            <button
                              type="button"
                              className="hl-btn hl-btn-ghost"
                              onClick={() => openEditProvider(prov)}
                            >
                              <Icon icon={Edit} />
                              <span>Edit</span>
                            </button>
                            <button
                              type="button"
                              className="hl-btn hl-btn-ghost hl-btn-danger"
                              onClick={() => handleDeleteProvider(prov.name)}
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

      <section className="hl-section">
        <div className="hl-section-bar">
          <h2>Model Routes</h2>
          <div className="hl-toolbar">
            <button
              type="button"
              className="hl-btn"
              onClick={() => setPricingModalOpen(true)}
            >
              <span>Pricing Table</span>
            </button>
            <button
              type="button"
              className="hl-btn hl-btn-primary"
              onClick={openCreateRoute}
            >
              <Icon icon={Add} />
              <span>Add Route</span>
            </button>
          </div>
        </div>

        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Alias</th>
                <th>Primary Target</th>
                <th>Fallbacks</th>
                <th>Pricing (/1M)</th>
                <th>Enabled</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filteredRoutes.length === 0 ? (
                <tr>
                  <td colSpan={6} className="hl-secondary">
                    No virtual model routes configured
                  </td>
                </tr>
              ) : (
                filteredRoutes.map((route) => {
                  const hasOverride =
                    route.input_cost_per_million != null ||
                    route.output_cost_per_million != null;
                  return (
                    <tr key={route.alias} className="hl-row">
                      <td className="hl-mono" style={{ fontWeight: 500 }}>
                        {route.alias}
                      </td>
                      <td className="hl-mono">
                        {route.provider_name}/{route.upstream_model}
                      </td>
                      <td className="hl-mono hl-secondary">
                        {(route.fallbacks ?? []).length > 0
                          ? (route.fallbacks ?? [])
                              .map((fb) => `${fb.provider}/${fb.model}`)
                              .join(', ')
                          : '—'}
                      </td>
                      <td className="hl-secondary">
                        {hasOverride
                          ? `${formatUSD(route.input_cost_per_million ?? 0)} / ${formatUSD(
                              route.output_cost_per_million ?? 0,
                            )}`
                          : 'Default'}
                      </td>
                      <td>
                        <Toggle
                          checked={route.enabled}
                          onChange={(next) => handleToggleRoute(route, next)}
                          label={`Enable ${route.alias}`}
                        />
                      </td>
                      <td>
                        <div className="hl-row-actions">
                          <button
                            type="button"
                            className="hl-btn hl-btn-ghost"
                            onClick={() => openEditRoute(route)}
                          >
                            <Icon icon={Edit} />
                            <span>Edit</span>
                          </button>
                          <button
                            type="button"
                            className="hl-btn hl-btn-ghost hl-btn-danger"
                            onClick={() => handleDeleteRoute(route.alias)}
                          >
                            <Icon icon={Trash} />
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

      <Modal
        open={providerModalOpen}
        title={editingProvider ? `Edit ${editingProvider.name}` : 'Add Provider'}
        onClose={() => setProviderModalOpen(false)}
      >
        <form onSubmit={handleSaveProvider} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Name</span>
              <input
                className="hl-input"
                required
                disabled={Boolean(editingProvider)}
                value={provName}
                onChange={(e) => setProvName(e.target.value)}
                placeholder="anthropic-prod"
              />
            </label>

            <label className="hl-field">
              <span className="hl-label">Protocol</span>
              <select
                className="hl-select"
                value={provType}
                onChange={(e) => {
                  const next = e.target.value;
                  setProvType(next);
                  if (!editingProvider && DEFAULT_BASE_URLS[next]) {
                    setProvBaseURL(DEFAULT_BASE_URLS[next]);
                  }
                }}
              >
                <option value="openai">openai</option>
                <option value="anthropic">anthropic</option>
                <option value="gemini">gemini</option>
                <option value="ollama">ollama</option>
              </select>
            </label>
          </div>

          <label className="hl-field">
            <span className="hl-label">Base URL</span>
            <input
              className="hl-input hl-mono"
              required
              value={provBaseURL}
              onChange={(e) => setProvBaseURL(e.target.value)}
            />
          </label>

          <label className="hl-field">
            <span className="hl-label">API Key</span>
            <input
              type="password"
              className="hl-input hl-mono"
              value={provAPIKey}
              onChange={(e) => {
                setProvAPIKey(e.target.value);
                if (e.target.value) setProvClearKey(false);
              }}
              placeholder={
                editingProvider?.has_api_key
                  ? editingProvider.api_key_preview || 'Leave blank to keep stored key'
                  : 'sk-...'
              }
            />
          </label>

          {editingProvider?.has_api_key && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span className="hl-label">Clear stored API key</span>
              <Toggle
                checked={provClearKey}
                onChange={setProvClearKey}
                label="Clear stored API key"
              />
            </div>
          )}

          <label className="hl-field">
            <span className="hl-label">Models</span>
            <input
              className="hl-input hl-mono"
              value={provModels}
              onChange={(e) => setProvModels(e.target.value)}
              placeholder="claude-sonnet-4-20250514, claude-opus-4-20250514"
            />
          </label>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Allow Client Key Passthrough</span>
            <Toggle
              checked={provPassthrough}
              onChange={setProvPassthrough}
              label="Allow Client Key Passthrough"
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Enabled</span>
            <Toggle
              checked={provEnabled}
              onChange={setProvEnabled}
              label="Provider Enabled"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, paddingTop: 8 }}>
            <button
              type="button"
              className="hl-btn"
              onClick={() => setProviderModalOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="hl-btn hl-btn-primary"
              disabled={savingProvider}
            >
              {savingProvider ? 'Saving' : 'Save Provider'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        open={routeModalOpen}
        title={editingRoute ? `Edit ${editingRoute.alias}` : 'Add Route'}
        onClose={() => setRouteModalOpen(false)}
      >
        <form onSubmit={handleSaveRoute} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <label className="hl-field">
            <span className="hl-label">Alias</span>
            <input
              className="hl-input hl-mono"
              required
              disabled={Boolean(editingRoute)}
              value={routeAlias}
              onChange={(e) => setRouteAlias(e.target.value)}
              placeholder="team/coding"
            />
          </label>

          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Primary Provider</span>
              {providers.length > 0 ? (
                <select
                  className="hl-select"
                  value={routeProvider}
                  onChange={(e) => setRouteProvider(e.target.value)}
                >
                  {providers.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  className="hl-input"
                  required
                  value={routeProvider}
                  onChange={(e) => setRouteProvider(e.target.value)}
                  placeholder="anthropic"
                />
              )}
            </label>

            <label className="hl-field">
              <span className="hl-label">Upstream Model</span>
              <input
                className="hl-input hl-mono"
                required
                value={routeUpstreamModel}
                onChange={(e) => setRouteUpstreamModel(e.target.value)}
                placeholder="claude-sonnet-4-20250514"
              />
            </label>
          </div>

          <label className="hl-field">
            <span className="hl-label">Fallbacks (provider/model per line)</span>
            <textarea
              className="hl-textarea hl-mono"
              style={{ minHeight: 80 }}
              value={routeFallbacksText}
              onChange={(e) => setRouteFallbacksText(e.target.value)}
              placeholder={'openai/gpt-4.1\ngemini/gemini-2.5-pro'}
            />
          </label>

          <div className="hl-form-grid">
            <label className="hl-field">
              <span className="hl-label">Input ($ / 1M)</span>
              <input
                type="number"
                step="any"
                className="hl-input"
                value={routeInputCost}
                onChange={(e) => setRouteInputCost(e.target.value)}
                placeholder="Default"
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Output ($ / 1M)</span>
              <input
                type="number"
                step="any"
                className="hl-input"
                value={routeOutputCost}
                onChange={(e) => setRouteOutputCost(e.target.value)}
                placeholder="Default"
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Cache Read ($ / 1M)</span>
              <input
                type="number"
                step="any"
                className="hl-input"
                value={routeCacheReadCost}
                onChange={(e) => setRouteCacheReadCost(e.target.value)}
                placeholder="Default"
              />
            </label>
            <label className="hl-field">
              <span className="hl-label">Cache Write ($ / 1M)</span>
              <input
                type="number"
                step="any"
                className="hl-input"
                value={routeCacheWriteCost}
                onChange={(e) => setRouteCacheWriteCost(e.target.value)}
                placeholder="Default"
              />
            </label>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="hl-label">Enabled</span>
            <Toggle
              checked={routeEnabled}
              onChange={setRouteEnabled}
              label="Route Enabled"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, paddingTop: 8 }}>
            <button
              type="button"
              className="hl-btn"
              onClick={() => setRouteModalOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="hl-btn hl-btn-primary"
              disabled={savingRoute}
            >
              {savingRoute ? 'Saving' : 'Save Route'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        open={pricingModalOpen}
        title="Built-in Pricing ($ / 1M Tokens)"
        onClose={() => setPricingModalOpen(false)}
        maxWidth={720}
      >
        <div className="hl-table-wrap">
          <table className="hl-table">
            <thead>
              <tr>
                <th>Model / Pattern</th>
                <th className="hl-num">Input</th>
                <th className="hl-num">Output</th>
                <th className="hl-num">Cache Read</th>
                <th className="hl-num">Cache Write</th>
              </tr>
            </thead>
            <tbody>
              {exactPricingEntries.map(([model, price]) => (
                <tr key={model} className="hl-row">
                  <td className="hl-mono">{model}</td>
                  <td className="hl-num">{formatUSD(price.input)}</td>
                  <td className="hl-num">{formatUSD(price.output)}</td>
                  <td className="hl-num hl-secondary">{formatUSD(price.cache_read)}</td>
                  <td className="hl-num hl-secondary">{formatUSD(price.cache_write)}</td>
                </tr>
              ))}
              {patternPricingEntries.map((entry) => (
                <tr key={entry.pattern} className="hl-row">
                  <td className="hl-mono hl-secondary">{entry.pattern}</td>
                  <td className="hl-num">{formatUSD(entry.input)}</td>
                  <td className="hl-num">{formatUSD(entry.output)}</td>
                  <td className="hl-num hl-secondary">{formatUSD(entry.cache_read)}</td>
                  <td className="hl-num hl-secondary">{formatUSD(entry.cache_write)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Modal>
    </>
  );
}
