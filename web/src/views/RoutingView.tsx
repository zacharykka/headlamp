import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  BookIcon,
  EditIcon,
  PlayIcon,
  PlusIcon,
  SearchIcon,
  TrashIcon,
} from '../components/ApertureIcons';
import {
  Drawer,
  Modal,
  ProviderTypeBadge,
  SegmentedControl,
  SourceBadge,
  Toggle,
  YAML_LOCK_TOOLTIP,
} from '../components/Primitives';
import {
  formatCostTier,
  formatLatency,
  formatUSD,
  hasRouteCostOverride,
  parseRouteFallbacks,
} from '../lib/format';
import type {
  ModelRouteItem,
  ModelRouteUpsertPayload,
  PricingResponse,
  ProviderItem,
  ProviderTestResult,
  ProviderUpsertPayload,
} from '../types/api';

const DEFAULT_BASE_URLS: Record<string, string> = {
  openai: 'https://api.openai.com',
  anthropic: 'https://api.anthropic.com',
  gemini: 'https://generativelanguage.googleapis.com',
  ollama: 'http://127.0.0.1:11434',
};

export interface RoutingFocusState {
  section?: 'all' | 'providers' | 'routes';
  providerType?: string;
  routeFilter?: 'all' | 'fallbacks' | 'custom_pricing';
  modal?: 'provider' | 'route' | 'pricing' | null;
  nonce?: number;
}

interface RoutingViewProps {
  focus?: RoutingFocusState;
  onCountsChange?: (counts: { providers: number; routes: number }) => void;
}

function parseOptionalNonNegativeNumber(
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

export function RoutingView({ focus, onCountsChange }: RoutingViewProps) {
  const [providers, setProviders] = useState<ProviderItem[]>([]);
  const [routes, setRoutes] = useState<ModelRouteItem[]>([]);
  const [pricing, setPricing] = useState<PricingResponse | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);

  const [sectionMode, setSectionMode] = useState<'all' | 'providers' | 'routes'>('all');
  const [providerTypeFilter, setProviderTypeFilter] = useState<string>('all');
  const [routeFilter, setRouteFilter] = useState<'all' | 'fallbacks' | 'custom_pricing'>(
    'all',
  );

  const [testResults, setTestResults] = useState<Record<string, ProviderTestResult>>({});
  const [testingName, setTestingName] = useState<string | null>(null);

  // Provider Modal State
  const [providerModalOpen, setProviderModalOpen] = useState(false);
  const [providerModalError, setProviderModalError] = useState<string | null>(null);
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
  const [routeModalError, setRouteModalError] = useState<string | null>(null);
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

  // Searchable Pricing Drawer State
  const [pricingOpen, setPricingOpen] = useState(false);
  const [pricingQuery, setPricingQuery] = useState('');

  const loadAll = async () => {
    setPageError(null);
    try {
      const [provList, routeList, pricingRes] = await Promise.all([
        api.listProviders(),
        api.listRoutes(),
        api.getPricing().catch(() => null),
      ]);
      setProviders(provList);
      setRoutes(routeList);
      if (pricingRes) setPricing(pricingRes);
      onCountsChange?.({ providers: provList.length, routes: routeList.length });
      setRouteProvider((prev) => prev || provList[0]?.name || '');
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to load providers and routes');
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    if (!focus) return;
    if (focus.section) setSectionMode(focus.section);
    if (focus.providerType) setProviderTypeFilter(focus.providerType);
    if (focus.routeFilter) setRouteFilter(focus.routeFilter);
    if (focus.modal === 'provider') {
      openCreateProvider();
    } else if (focus.modal === 'route') {
      openCreateRoute();
    } else if (focus.modal === 'pricing') {
      setPricingOpen(true);
    }
  }, [focus?.nonce]);

  const openCreateProvider = () => {
    setEditingProvider(null);
    setProviderModalError(null);
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
    if (item.source === 'config') return;
    setEditingProvider(item);
    setProviderModalError(null);
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
    setProviderModalError(null);

    const trimmedName = provName.trim();
    if (!trimmedName) {
      setProviderModalError('Provider name is required.');
      return;
    }
    if (trimmedName.includes('/')) {
      setProviderModalError('Provider name must not contain "/".');
      return;
    }

    setSavingProvider(true);
    const payload: ProviderUpsertPayload = {
      name: trimmedName,
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
      setProviderModalError(
        err instanceof Error ? err.message : 'Failed to save provider',
      );
    } finally {
      setSavingProvider(false);
    }
  };

  const handleToggleProvider = async (item: ProviderItem, enabled: boolean) => {
    if (item.source === 'config') return;
    setPageError(null);
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
      setPageError(err instanceof Error ? err.message : 'Failed to update provider');
    }
  };

  const handleDeleteProvider = async (item: ProviderItem) => {
    if (item.source === 'config') return;
    setPageError(null);
    try {
      await api.deleteProvider(item.name);
      await loadAll();
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to delete provider');
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
          message: err instanceof Error ? err.message : 'Probe failed',
        },
      }));
    } finally {
      setTestingName(null);
    }
  };

  const openCreateRoute = () => {
    setEditingRoute(null);
    setRouteModalError(null);
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
    if (item.source === 'config') return;
    setEditingRoute(item);
    setRouteModalError(null);
    setRouteAlias(item.alias);
    setRouteProvider(item.provider_name);
    setRouteUpstreamModel(item.upstream_model);
    setRouteFallbacksText(
      (item.fallbacks ?? []).map((fb) => `${fb.provider}/${fb.model}`).join('\n'),
    );
    setRouteInputCost(
      item.input_cost_per_million != null ? String(item.input_cost_per_million) : '',
    );
    setRouteOutputCost(
      item.output_cost_per_million != null ? String(item.output_cost_per_million) : '',
    );
    setRouteCacheReadCost(
      item.cache_read_cost_per_million != null
        ? String(item.cache_read_cost_per_million)
        : '',
    );
    setRouteCacheWriteCost(
      item.cache_write_cost_per_million != null
        ? String(item.cache_write_cost_per_million)
        : '',
    );
    setRouteEnabled(item.enabled);
    setRouteModalOpen(true);
  };

  const handleSaveRoute = async (event: FormEvent) => {
    event.preventDefault();
    setRouteModalError(null);

    const alias = routeAlias.trim();
    if (!alias) {
      setRouteModalError('Route alias is required.');
      return;
    }

    const effectiveProvider =
      routeProvider.trim() || (!editingRoute ? providers[0]?.name ?? '' : '');
    if (!effectiveProvider) {
      setRouteModalError('Add an upstream provider first before creating a route.');
      return;
    }

    const upstreamModel = routeUpstreamModel.trim();
    if (!upstreamModel) {
      setRouteModalError('Primary upstream model ID is required.');
      return;
    }

    const knownProviderNames = providers.map((p) => p.name);
    const parsedFallbacks = parseRouteFallbacks(routeFallbacksText, knownProviderNames);
    if (parsedFallbacks.error) {
      setRouteModalError(parsedFallbacks.error);
      return;
    }

    const inTier = parseOptionalNonNegativeNumber(routeInputCost, 'Input cost');
    if (inTier.error) {
      setRouteModalError(inTier.error);
      return;
    }
    const outTier = parseOptionalNonNegativeNumber(routeOutputCost, 'Output cost');
    if (outTier.error) {
      setRouteModalError(outTier.error);
      return;
    }
    const crTier = parseOptionalNonNegativeNumber(routeCacheReadCost, 'Cache read cost');
    if (crTier.error) {
      setRouteModalError(crTier.error);
      return;
    }
    const cwTier = parseOptionalNonNegativeNumber(routeCacheWriteCost, 'Cache write cost');
    if (cwTier.error) {
      setRouteModalError(cwTier.error);
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
      setRouteModalOpen(false);
      await loadAll();
    } catch (err: unknown) {
      setRouteModalError(
        err instanceof Error ? err.message : 'Failed to save model route',
      );
    } finally {
      setSavingRoute(false);
    }
  };

  const handleToggleRoute = async (item: ModelRouteItem, enabled: boolean) => {
    if (item.source === 'config') return;
    setPageError(null);
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
      setPageError(err instanceof Error ? err.message : 'Failed to update route');
    }
  };

  const handleDeleteRoute = async (item: ModelRouteItem) => {
    if (item.source === 'config') return;
    setPageError(null);
    try {
      await api.deleteRoute(item.alias);
      await loadAll();
    } catch (err: unknown) {
      setPageError(err instanceof Error ? err.message : 'Failed to delete route');
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
      return routes.filter(hasRouteCostOverride);
    }
    return routes;
  }, [routes, routeFilter]);

  const exactPricingEntries = useMemo(() => {
    const q = pricingQuery.trim().toLowerCase();
    const entries = Object.entries(pricing?.exact ?? {}).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    if (!q) return entries;
    return entries.filter(([model]) => model.toLowerCase().includes(q));
  }, [pricing, pricingQuery]);

  const patternPricingEntries = useMemo(() => {
    const q = pricingQuery.trim().toLowerCase();
    const entries = pricing?.patterns ?? [];
    if (!q) return entries;
    return entries.filter((p) => p.pattern.toLowerCase().includes(q));
  }, [pricing, pricingQuery]);

  const showProviders = sectionMode === 'all' || sectionMode === 'providers';
  const showRoutes = sectionMode === 'all' || sectionMode === 'routes';

  return (
    <div className="ap-page">
      <header className="ap-page-header">
        <div className="ap-page-title-row">
          <div>
            <h1 className="ap-page-title">
              {sectionMode === 'providers'
                ? 'Providers'
                : sectionMode === 'routes'
                  ? 'Model Routing'
                  : 'Providers & Model Routing'}
            </h1>
            <p className="ap-page-subtitle">
              Upstream LLM credentials, live health probes, virtual model aliases, fallback chains, and per-tier cost overrides.
            </p>
          </div>
        </div>

        <div className="ap-filter-bar">
          <div className="ap-filter-group">
            <SegmentedControl
              ariaLabel="Routing view section"
              value={sectionMode}
              onChange={setSectionMode}
              options={[
                { value: 'all', label: 'All' },
                { value: 'providers', label: `Providers (${providers.length})` },
                { value: 'routes', label: `Routes (${routes.length})` },
              ]}
            />
          </div>

          <div className="ap-filter-group">
            <button
              type="button"
              className="ap-btn"
              onClick={() => setPricingOpen(true)}
            >
              <BookIcon size={15} />
              <span>Model Pricing</span>
            </button>
            <button
              type="button"
              className="ap-btn"
              onClick={openCreateRoute}
            >
              <PlusIcon />
              <span>Add Route</span>
            </button>
            <button
              type="button"
              className="ap-btn ap-btn-primary"
              onClick={openCreateProvider}
            >
              <PlusIcon />
              <span>Add Provider</span>
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

      {showProviders && (
        <section className="ap-card" aria-label="Upstream providers">
          <div className="ap-card-header">
            <div>
              <h2 className="ap-card-title">Upstream Providers</h2>
              <p className="ap-card-subtitle">
                Configure OpenAI, Anthropic, Gemini, and Ollama endpoints. YAML-defined providers remain locked to GitOps config.
              </p>
            </div>
            <SegmentedControl
              ariaLabel="Filter providers by protocol"
              value={providerTypeFilter}
              onChange={setProviderTypeFilter}
              options={[
                { value: 'all', label: 'All' },
                { value: 'openai', label: 'OpenAI' },
                { value: 'anthropic', label: 'Anthropic' },
                { value: 'gemini', label: 'Gemini' },
                { value: 'ollama', label: 'Ollama' },
              ]}
            />
          </div>

          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Origin</th>
                  <th>Endpoint & Models</th>
                  <th>Credentials</th>
                  <th>Enabled</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredProviders.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ color: 'var(--ap-text-muted)', padding: '26px 14px', textAlign: 'center' }}>
                      No upstream providers match the selected filter.
                    </td>
                  </tr>
                ) : (
                  filteredProviders.map((prov) => {
                    const isYaml = prov.source === 'config';
                    const testStatus = testResults[prov.name];
                    const isTesting = testingName === prov.name;
                    const modelList = prov.models ?? [];

                    return (
                      <tr key={prov.name} className="ap-row">
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            <span style={{ fontWeight: 600 }}>{prov.name}</span>
                            <span style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}>
                              <ProviderTypeBadge type={prov.type} />
                            </span>
                          </div>
                        </td>
                        <td>
                          <SourceBadge source={prov.source} />
                        </td>
                        <td style={{ maxWidth: 230 }}>
                          <div
                            className="ap-mono ap-truncate"
                            style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}
                            title={prov.base_url}
                          >
                            {prov.base_url}
                          </div>
                          <div
                            className="ap-truncate"
                            style={{ fontSize: 11.5, color: 'var(--ap-text-muted)', marginTop: 2 }}
                            title={modelList.join(', ')}
                          >
                            {modelList.length > 0
                              ? `${modelList.length} ${modelList.length === 1 ? 'model' : 'models'}: ${modelList.join(', ')}`
                              : 'All upstream models'}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                            {prov.has_api_key ? (
                              <span className="ap-badge ap-mono">
                                {prov.api_key_preview || 'Stored key'}
                              </span>
                            ) : (
                              <span style={{ color: 'var(--ap-text-muted)', fontSize: 12 }}>
                                No stored key
                              </span>
                            )}
                            {prov.passthrough && (
                              <span
                                className="ap-badge ap-badge--blue"
                                title="Forwards caller API key when present"
                              >
                                Passthrough
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <Toggle
                            checked={prov.enabled}
                            disabled={isYaml}
                            title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                            onChange={(next) => handleToggleProvider(prov, next)}
                            label={`Enable ${prov.name}`}
                          />
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="ap-row-actions">
                            {testStatus && (
                              <span
                                className={`ap-badge ap-tabular ${
                                  testStatus.ok ? 'ap-badge--green' : 'ap-badge--red'
                                }`}
                                title={testStatus.message}
                              >
                                {testStatus.ok
                                  ? `${formatLatency(testStatus.latency_ms)}`
                                  : testStatus.message.slice(0, 28)}
                              </span>
                            )}
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm"
                              disabled={isTesting}
                              onClick={() => handleTestProvider(prov.name)}
                              title={`Probe ${prov.name} upstream endpoint`}
                            >
                              <PlayIcon />
                              <span>{isTesting ? 'Probing' : 'Test'}</span>
                            </button>
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm"
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${prov.name}`}
                              onClick={() => openEditProvider(prov)}
                            >
                              <EditIcon />
                              <span>Edit</span>
                            </button>
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-danger ap-btn-sm"
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${prov.name}`}
                              onClick={() => handleDeleteProvider(prov)}
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

      {showRoutes && (
        <section className="ap-card" aria-label="Virtual model routes">
          <div className="ap-card-header">
            <div>
              <h2 className="ap-card-title">Virtual Model Routes</h2>
              <p className="ap-card-subtitle">
                Map stable model aliases to primary targets, ordered fallback chains, and custom per-million token pricing.
              </p>
            </div>
            <SegmentedControl
              ariaLabel="Filter model routes"
              value={routeFilter}
              onChange={setRouteFilter}
              options={[
                { value: 'all', label: 'All Routes' },
                { value: 'fallbacks', label: 'With Fallbacks' },
                { value: 'custom_pricing', label: 'Cost Overrides' },
              ]}
            />
          </div>

          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Alias</th>
                  <th>Origin</th>
                  <th>Primary Target</th>
                  <th>Fallback Chain</th>
                  <th>Cost Overrides (/1M)</th>
                  <th>Enabled</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRoutes.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ color: 'var(--ap-text-muted)', padding: '26px 14px', textAlign: 'center' }}>
                      No virtual model routes match the selected filter.
                    </td>
                  </tr>
                ) : (
                  filteredRoutes.map((route) => {
                    const isYaml = route.source === 'config';
                    const hasOverride = hasRouteCostOverride(route);
                    const fallbacks = route.fallbacks ?? [];

                    return (
                      <tr key={route.alias} className="ap-row">
                        <td>
                          <span className="ap-mono" style={{ fontWeight: 600 }}>
                            {route.alias}
                          </span>
                        </td>
                        <td>
                          <SourceBadge source={route.source} />
                        </td>
                        <td style={{ maxWidth: 200 }}>
                          <span
                            className="ap-mono ap-truncate"
                            style={{ display: 'block', fontSize: 12.5 }}
                            title={`${route.provider_name}/${route.upstream_model}`}
                          >
                            {route.provider_name}/{route.upstream_model}
                          </span>
                        </td>
                        <td style={{ maxWidth: 200 }}>
                          {fallbacks.length > 0 ? (
                            <span
                              className="ap-mono ap-truncate"
                              style={{
                                display: 'block',
                                fontSize: 12,
                                color: 'var(--ap-text-secondary)',
                              }}
                              title={fallbacks
                                .map((fb) => `${fb.provider}/${fb.model}`)
                                .join(' → ')}
                            >
                              {fallbacks
                                .map((fb) => `${fb.provider}/${fb.model}`)
                                .join(' → ')}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--ap-text-muted)' }}>—</span>
                          )}
                        </td>
                        <td>
                          {hasOverride ? (
                            <div
                              className="ap-tabular"
                              style={{ fontSize: 11.5, lineHeight: 1.45 }}
                            >
                              <div>
                                <span style={{ color: 'var(--ap-text-muted)' }}>In/Out: </span>
                                <strong>{formatCostTier(route.input_cost_per_million)}</strong>
                                {' / '}
                                <strong>{formatCostTier(route.output_cost_per_million)}</strong>
                              </div>
                              {(route.cache_read_cost_per_million != null ||
                                route.cache_write_cost_per_million != null) && (
                                <div style={{ color: 'var(--ap-text-secondary)' }}>
                                  <span style={{ color: 'var(--ap-text-muted)' }}>
                                    Cache R/W:{' '}
                                  </span>
                                  {formatCostTier(route.cache_read_cost_per_million)} /{' '}
                                  {formatCostTier(route.cache_write_cost_per_million)}
                                </div>
                              )}
                            </div>
                          ) : (
                            <span className="ap-badge">Default</span>
                          )}
                        </td>
                        <td>
                          <Toggle
                            checked={route.enabled}
                            disabled={isYaml}
                            title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                            onChange={(next) => handleToggleRoute(route, next)}
                            label={`Enable route ${route.alias}`}
                          />
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="ap-row-actions">
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm"
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${route.alias}`}
                              onClick={() => openEditRoute(route)}
                            >
                              <EditIcon />
                              <span>Edit</span>
                            </button>
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-danger ap-btn-sm"
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${route.alias}`}
                              onClick={() => handleDeleteRoute(route)}
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

      {/* Provider Modal */}
      <Modal
        open={providerModalOpen}
        title={editingProvider ? `Edit Provider (${editingProvider.name})` : 'Add Provider'}
        onClose={() => setProviderModalOpen(false)}
        error={providerModalError}
      >
        <form
          onSubmit={handleSaveProvider}
          style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
        >
          <div className="ap-form-grid">
            <label className="ap-field">
              <span className="ap-label">Provider Name</span>
              <input
                className="ap-input ap-mono"
                required
                disabled={Boolean(editingProvider)}
                value={provName}
                onChange={(e) => setProvName(e.target.value)}
                placeholder="anthropic-prod"
              />
            </label>

            <label className="ap-field">
              <span className="ap-label">Protocol</span>
              <select
                className="ap-select"
                value={provType}
                onChange={(e) => {
                  const next = e.target.value;
                  setProvType(next);
                  if (!editingProvider && DEFAULT_BASE_URLS[next]) {
                    setProvBaseURL(DEFAULT_BASE_URLS[next]);
                  }
                }}
              >
                <option value="openai">OpenAI (/v1)</option>
                <option value="anthropic">Anthropic (/v1/messages)</option>
                <option value="gemini">Gemini (/v1beta)</option>
                <option value="ollama">Ollama (Local / HTTP)</option>
              </select>
            </label>
          </div>

          <label className="ap-field">
            <span className="ap-label">Upstream Base URL</span>
            <input
              className="ap-input ap-mono"
              required
              value={provBaseURL}
              onChange={(e) => setProvBaseURL(e.target.value)}
              placeholder="https://api.anthropic.com"
            />
          </label>

          <label className="ap-field">
            <span className="ap-label">Upstream API Key (encrypted at rest)</span>
            <input
              type="password"
              className="ap-input ap-mono"
              value={provAPIKey}
              onChange={(e) => {
                setProvAPIKey(e.target.value);
                if (e.target.value) setProvClearKey(false);
              }}
              placeholder={
                editingProvider?.has_api_key
                  ? `${editingProvider.api_key_preview || 'Stored'} — leave blank to keep`
                  : 'sk-...'
              }
            />
          </label>

          {editingProvider?.has_api_key && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span className="ap-label">Clear stored API key</span>
              <Toggle
                checked={provClearKey}
                onChange={setProvClearKey}
                label="Clear stored API key"
              />
            </div>
          )}

          <label className="ap-field">
            <span className="ap-label">Advertised Models (optional, comma-separated)</span>
            <input
              className="ap-input ap-mono"
              value={provModels}
              onChange={(e) => setProvModels(e.target.value)}
              placeholder="claude-sonnet-4-20250514, claude-opus-4-20250514"
            />
          </label>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div className="ap-label">Client Key Passthrough</div>
              <div className="ap-hint">Forward caller Authorization / x-api-key header when gateway has no stored key.</div>
            </div>
            <Toggle
              checked={provPassthrough}
              onChange={setProvPassthrough}
              label="Allow Client Key Passthrough"
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="ap-label">Enabled</span>
            <Toggle
              checked={provEnabled}
              onChange={setProvEnabled}
              label="Provider Enabled"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, paddingTop: 6 }}>
            <button
              type="button"
              className="ap-btn"
              onClick={() => setProviderModalOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="ap-btn ap-btn-primary"
              disabled={savingProvider}
            >
              {savingProvider ? 'Saving...' : 'Save Provider'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Route Modal */}
      <Modal
        open={routeModalOpen}
        title={editingRoute ? `Edit Route (${editingRoute.alias})` : 'Add Model Route'}
        onClose={() => setRouteModalOpen(false)}
        maxWidth={620}
        error={routeModalError}
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
              onClick={() => setRouteModalOpen(false)}
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

      {/* Searchable Built-in Model Pricing Reference Drawer */}
      <Drawer
        open={pricingOpen}
        title="Built-in Model Pricing Reference"
        subtitle="USD per 1,000,000 tokens used when route cost tiers are set to Default"
        onClose={() => setPricingOpen(false)}
      >
        <div style={{ position: 'relative' }}>
          <SearchIcon
            style={{
              position: 'absolute',
              left: 11,
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--ap-text-muted)',
              pointerEvents: 'none',
            }}
          />
          <input
            className="ap-input"
            style={{ paddingLeft: 34 }}
            placeholder="Filter models or wildcard patterns (e.g. claude, gpt-4.1, gemini)..."
            value={pricingQuery}
            onChange={(e) => setPricingQuery(e.target.value)}
            aria-label="Filter built-in model pricing"
          />
        </div>

        <section className="ap-card">
          <div className="ap-card-header">
            <h3 className="ap-card-title">
              Exact Models ({exactPricingEntries.length})
            </h3>
          </div>
          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Model ID</th>
                  <th className="ap-num">Input</th>
                  <th className="ap-num">Output</th>
                  <th className="ap-num">Cache Read</th>
                  <th className="ap-num">Cache Write</th>
                </tr>
              </thead>
              <tbody>
                {exactPricingEntries.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ color: 'var(--ap-text-muted)', textAlign: 'center', padding: 18 }}>
                      No matching exact models.
                    </td>
                  </tr>
                ) : (
                  exactPricingEntries.map(([model, price]) => (
                    <tr key={model} className="ap-row">
                      <td className="ap-mono" style={{ fontSize: 12 }}>
                        {model}
                      </td>
                      <td className="ap-num">{formatUSD(price.input)}</td>
                      <td className="ap-num">{formatUSD(price.output)}</td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatUSD(price.cache_read)}
                      </td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatUSD(price.cache_write)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="ap-card">
          <div className="ap-card-header">
            <h3 className="ap-card-title">
              Wildcard Family Fallbacks ({patternPricingEntries.length})
            </h3>
          </div>
          <div className="ap-table-wrap">
            <table className="ap-table">
              <thead>
                <tr>
                  <th>Pattern</th>
                  <th className="ap-num">Input</th>
                  <th className="ap-num">Output</th>
                  <th className="ap-num">Cache Read</th>
                  <th className="ap-num">Cache Write</th>
                </tr>
              </thead>
              <tbody>
                {patternPricingEntries.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ color: 'var(--ap-text-muted)', textAlign: 'center', padding: 18 }}>
                      No matching wildcard patterns.
                    </td>
                  </tr>
                ) : (
                  patternPricingEntries.map((item) => (
                    <tr key={item.pattern} className="ap-row">
                      <td className="ap-mono" style={{ fontSize: 12 }}>
                        {item.pattern}
                      </td>
                      <td className="ap-num">{formatUSD(item.input)}</td>
                      <td className="ap-num">{formatUSD(item.output)}</td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatUSD(item.cache_read)}
                      </td>
                      <td className="ap-num" style={{ color: 'var(--ap-text-secondary)' }}>
                        {formatUSD(item.cache_write)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </Drawer>
    </div>
  );
}
