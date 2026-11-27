import { useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  BookIcon,
  EditIcon,
  PlayIcon,
  PlusIcon,
} from '../components/ApertureIcons';
import { PricingDrawer } from '../components/PricingDrawer';
import {
  ConfirmDeleteButton,
  ProviderTypeBadge,
  SegmentedControl,
  SourceBadge,
  Toggle,
  YAML_LOCK_TOOLTIP,
} from '../components/Primitives';
import {
  formatCostTier,
  formatLatency,
  hasRouteCostOverride,
} from '../lib/format';
import type {
  ModelRouteItem,
  ProviderItem,
  ProviderTestResult,
} from '../types/api';
import { ProviderModal } from './routing/ProviderModal';
import { RouteModal } from './routing/RouteModal';

export interface RoutingFocusState {
  section?: 'all' | 'providers' | 'routes';
  providerType?: string;
  routeFilter?: 'all' | 'fallbacks' | 'custom_pricing';
  modal?: 'provider' | 'route' | 'pricing' | null;
  nonce?: number;
}

interface RoutingViewProps {
  focus?: RoutingFocusState;
  onSectionChange?: (section: 'all' | 'providers' | 'routes') => void;
  onOpenPricing?: () => void;
  onCountsChange?: (counts: { providers: number; routes: number }) => void;
}

export function RoutingView({
  focus,
  onSectionChange,
  onOpenPricing,
  onCountsChange,
}: RoutingViewProps) {
  const [providers, setProviders] = useState<ProviderItem[]>([]);
  const [routes, setRoutes] = useState<ModelRouteItem[]>([]);
  const [pageError, setPageError] = useState<string | null>(null);

  const [sectionMode, setSectionMode] = useState<'all' | 'providers' | 'routes'>(
    focus?.section ?? 'all',
  );
  const [providerTypeFilter, setProviderTypeFilter] = useState<string>('all');
  const [routeFilter, setRouteFilter] = useState<'all' | 'fallbacks' | 'custom_pricing'>(
    'all',
  );

  const [testResults, setTestResults] = useState<Record<string, ProviderTestResult>>({});
  const [testingName, setTestingName] = useState<string | null>(null);
  const [togglingProviders, setTogglingProviders] = useState<Record<string, boolean>>({});
  const [togglingRoutes, setTogglingRoutes] = useState<Record<string, boolean>>({});

  // Provider Modal State
  const [providerModalOpen, setProviderModalOpen] = useState(false);
  const [editingProvider, setEditingProvider] = useState<ProviderItem | null>(null);

  // Route Modal State
  const [routeModalOpen, setRouteModalOpen] = useState(false);
  const [editingRoute, setEditingRoute] = useState<ModelRouteItem | null>(null);

  // Fallback local Pricing Drawer when RoutingView is rendered standalone
  const [pricingOpen, setPricingOpen] = useState(false);

  const loadAll = async () => {
    setPageError(null);
    try {
      const [provList, routeList] = await Promise.all([
        api.listProviders(),
        api.listRoutes(),
      ]);
      setProviders(provList);
      setRoutes(routeList);
      onCountsChange?.({ providers: provList.length, routes: routeList.length });
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
      if (onOpenPricing) {
        onOpenPricing();
      } else {
        setPricingOpen(true);
      }
    }
  }, [focus?.nonce]);

  const openCreateProvider = () => {
    setEditingProvider(null);
    setProviderModalOpen(true);
  };

  const openEditProvider = (item: ProviderItem) => {
    if (item.source === 'config') return;
    setEditingProvider(item);
    setProviderModalOpen(true);
  };

  const handleToggleProvider = async (item: ProviderItem, enabled: boolean) => {
    if (item.source === 'config' || togglingProviders[item.name]) return;
    setPageError(null);
    setTogglingProviders((prev) => ({ ...prev, [item.name]: true }));
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
    } finally {
      setTogglingProviders((prev) => ({ ...prev, [item.name]: false }));
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
    setRouteModalOpen(true);
  };

  const openEditRoute = (item: ModelRouteItem) => {
    if (item.source === 'config') return;
    setEditingRoute(item);
    setRouteModalOpen(true);
  };

  const handleToggleRoute = async (item: ModelRouteItem, enabled: boolean) => {
    if (item.source === 'config' || togglingRoutes[item.alias]) return;
    setPageError(null);
    setTogglingRoutes((prev) => ({ ...prev, [item.alias]: true }));
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
    } finally {
      setTogglingRoutes((prev) => ({ ...prev, [item.alias]: false }));
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

  const showProviders = sectionMode === 'all' || sectionMode === 'providers';
  const showRoutes = sectionMode === 'all' || sectionMode === 'routes';

  const handleSectionSelect = (next: 'all' | 'providers' | 'routes') => {
    setSectionMode(next);
    onSectionChange?.(next);
  };

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
              onChange={handleSectionSelect}
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
              onClick={() => {
                if (onOpenPricing) {
                  onOpenPricing();
                } else {
                  setPricingOpen(true);
                }
              }}
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
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            <span style={{ fontWeight: 600 }}>{prov.name}</span>
                            <span style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}>
                              <ProviderTypeBadge type={prov.type} />
                            </span>
                          </div>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <SourceBadge source={prov.source} />
                        </td>
                        <td style={{ maxWidth: 185 }}>
                          <div
                            className="ap-mono ap-truncate"
                            style={{ fontSize: 12, color: 'var(--ap-text-secondary)' }}
                            title={prov.base_url}
                          >
                            {prov.base_url}
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
                              title={modelList.join(', ')}
                            >
                              {modelList.length > 0
                                ? `${modelList.length} ${modelList.length === 1 ? 'model' : 'models'}: ${modelList.join(', ')}`
                                : 'All upstream models'}
                            </span>
                            {testStatus && (
                              <span
                                className={`ap-badge ap-tabular ${
                                  testStatus.ok ? 'ap-badge--green' : 'ap-badge--red'
                                }`}
                                style={{ flexShrink: 0 }}
                                title={testStatus.message}
                              >
                                {testStatus.ok
                                  ? formatLatency(testStatus.latency_ms)
                                  : testStatus.message.slice(0, 18)}
                              </span>
                            )}
                          </div>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                            {prov.has_api_key ? (
                              <span className="ap-badge ap-mono">
                                {prov.api_key_preview || 'Stored key'}
                              </span>
                            ) : (
                              <span style={{ color: 'var(--ap-text-muted)', fontSize: 12 }}>
                                No key
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
                            disabled={isYaml || Boolean(togglingProviders[prov.name])}
                            title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                            onChange={(next) => handleToggleProvider(prov, next)}
                            label={`Enable ${prov.name}`}
                          />
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="ap-row-actions">
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
                              className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                              disabled={isYaml}
                              aria-label={`Edit ${prov.name}`}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${prov.name}`}
                              onClick={() => openEditProvider(prov)}
                            >
                              <EditIcon />
                              <span className="ap-action-label">Edit</span>
                            </button>
                            <ConfirmDeleteButton
                              itemName={prov.name}
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${prov.name}`}
                              onConfirm={() => handleDeleteProvider(prov)}
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
                        <td style={{ maxWidth: 118 }}>
                          <span
                            className="ap-mono ap-truncate"
                            style={{ display: 'block', fontWeight: 600 }}
                            title={route.alias}
                          >
                            {route.alias}
                          </span>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <SourceBadge source={route.source} />
                        </td>
                        <td style={{ maxWidth: 138 }}>
                          <span
                            className="ap-mono ap-truncate"
                            style={{ display: 'block', fontSize: 12 }}
                            title={`${route.provider_name}/${route.upstream_model}`}
                          >
                            {route.provider_name}/{route.upstream_model}
                          </span>
                        </td>
                        <td style={{ maxWidth: 125 }}>
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
                        <td style={{ whiteSpace: 'nowrap' }}>
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
                              <div style={{ color: 'var(--ap-text-secondary)' }}>
                                <span style={{ color: 'var(--ap-text-muted)' }}>
                                  Cache R/W:{' '}
                                </span>
                                {formatCostTier(route.cache_read_cost_per_million)} /{' '}
                                {formatCostTier(route.cache_write_cost_per_million)}
                              </div>
                            </div>
                          ) : (
                            <span className="ap-badge">Default</span>
                          )}
                        </td>
                        <td>
                          <Toggle
                            checked={route.enabled}
                            disabled={isYaml || Boolean(togglingRoutes[route.alias])}
                            title={isYaml ? YAML_LOCK_TOOLTIP : undefined}
                            onChange={(next) => handleToggleRoute(route, next)}
                            label={`Enable route ${route.alias}`}
                          />
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="ap-row-actions">
                            <button
                              type="button"
                              className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                              disabled={isYaml}
                              aria-label={`Edit ${route.alias}`}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Edit ${route.alias}`}
                              onClick={() => openEditRoute(route)}
                            >
                              <EditIcon />
                              <span className="ap-action-label">Edit</span>
                            </button>
                            <ConfirmDeleteButton
                              itemName={route.alias}
                              disabled={isYaml}
                              title={isYaml ? YAML_LOCK_TOOLTIP : `Delete ${route.alias}`}
                              onConfirm={() => handleDeleteRoute(route)}
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

      <ProviderModal
        open={providerModalOpen}
        editingProvider={editingProvider}
        onClose={() => setProviderModalOpen(false)}
        onSaved={loadAll}
      />

      <RouteModal
        open={routeModalOpen}
        editingRoute={editingRoute}
        providers={providers}
        onClose={() => setRouteModalOpen(false)}
        onSaved={loadAll}
      />

      {!onOpenPricing && (
        <PricingDrawer
          open={pricingOpen}
          onClose={() => setPricingOpen(false)}
        />
      )}
    </div>
  );
}
