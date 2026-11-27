import { useEffect, useState } from 'react';
import { api } from './api/client';
import {
  AlertIcon,
  BookIcon,
  ChartBarIcon,
  ChatBubbleIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CloseIcon,
  GearIcon,
  HeadlampMark,
  ShieldIcon,
  SidebarToggleIcon,
  SparkleIcon,
  TailnetMeshGlyph,
  TerminalIcon,
} from './components/ApertureIcons';
import { PricingDrawer } from './components/PricingDrawer';
import type { MeResponse, TimeWindow } from './types/api';
import { AuditLogsView, type LogsFocusState } from './views/AuditLogsView';
import {
  BudgetsAccessView,
  type BudgetsFocusState,
} from './views/BudgetsAccessView';
import { ChatView } from './views/ChatView';
import { MCPView, type MCPFocusState } from './views/MCPView';
import { OverviewView } from './views/OverviewView';
import { PersonalView } from './views/PersonalView';
import { RoutingView, type RoutingFocusState } from './views/RoutingView';
import { SecurityView, type SecurityFocusState } from './views/SecurityView';

export type NavKey =
  | 'overview'
  | 'logs'
  | 'providers'
  | 'routes'
  | 'budgets'
  | 'mcp_servers'
  | 'mcp_audit'
  | 'guardrails'
  | 'webhooks'
  | 'chat'
  | 'quickstart';

type GroupKey = 'telemetry' | 'security' | 'admin' | 'developer';

interface SidebarCounts {
  providers: number;
  routes: number;
  budgets: number;
  mcpServers: number;
  rules: number;
  webhooks: number;
}

function groupForNav(nav: NavKey): GroupKey | null {
  if (nav === 'overview') return 'telemetry';
  if (nav === 'logs' || nav === 'guardrails' || nav === 'webhooks') return 'security';
  if (
    nav === 'providers' ||
    nav === 'routes' ||
    nav === 'budgets' ||
    nav === 'mcp_servers' ||
    nav === 'mcp_audit'
  ) {
    return 'admin';
  }
  return null;
}

function initialsFromPrincipal(name: string): string {
  const cleaned = name.replace(/^tag:/, '').trim();
  if (!cleaned) return 'HL';
  const parts = cleaned.split(/[@.\s_-]+/).filter(Boolean);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return cleaned.slice(0, 2).toUpperCase();
}

export function App() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loadingMe, setLoadingMe] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const [activeNav, setActiveNav] = useState<NavKey>('overview');
  const [overviewWindow, setOverviewWindow] = useState<TimeWindow>('7d');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [bannerDismissed, setBannerDismissed] = useState(false);
  const [pricingOpen, setPricingOpen] = useState(false);

  // All sidebar groups start collapsed by default
  const [openGroups, setOpenGroups] = useState<Record<GroupKey, boolean>>({
    telemetry: false,
    security: false,
    admin: false,
    developer: false,
  });

  const [counts, setCounts] = useState<SidebarCounts>({
    providers: 0,
    routes: 0,
    budgets: 0,
    mcpServers: 0,
    rules: 0,
    webhooks: 0,
  });

  const [routingFocus, setRoutingFocus] = useState<RoutingFocusState>({
    section: 'providers',
  });
  const [budgetsFocus, setBudgetsFocus] = useState<BudgetsFocusState>({});
  const [mcpFocus, setMcpFocus] = useState<MCPFocusState>({
    section: 'servers',
  });
  const [logsFocus, setLogsFocus] = useState<LogsFocusState>({});
  const [securityFocus, setSecurityFocus] = useState<SecurityFocusState>({
    section: 'guardrails',
  });

  useEffect(() => {
    api
      .getMe()
      .then((res) => {
        setMe(res);
        if (!res.is_admin) {
          setActiveNav('chat');
        } else {
          void Promise.all([
            api.listProviders().catch(() => []),
            api.listRoutes().catch(() => []),
            api.listBudgets().catch(() => []),
            api.listAdminMCPServers().catch(() => []),
            api.listGuardrails().catch(() => []),
            api.listWebhooks().catch(() => []),
          ]).then(([p, r, b, m, g, w]) => {
            setCounts({
              providers: p.length,
              routes: r.length,
              budgets: b.length,
              mcpServers: m.length,
              rules: g.length,
              webhooks: w.length,
            });
          });
        }
        setLoadingMe(false);
      })
      .catch((err: unknown) => {
        setAuthError(
          err instanceof Error ? err.message : 'Unable to authenticate with Headlamp',
        );
        setLoadingMe(false);
      });
  }, []);

  if (loadingMe) {
    return (
      <main
        style={{
          width: '100%',
          minHeight: '100dvh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 10,
          color: 'var(--ap-text-secondary)',
        }}
      >
        <HeadlampMark size={20} />
        <span>Loading Headlamp...</span>
      </main>
    );
  }

  if (authError || !me) {
    return (
      <main
        style={{
          width: '100%',
          minHeight: '100dvh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 24,
        }}
      >
        <section className="ap-card ap-card-body" style={{ maxWidth: 460, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <HeadlampMark size={22} />
            <h1 style={{ fontSize: 18, fontWeight: 650 }}>Headlamp</h1>
          </div>
          <div className="ap-alert ap-alert--danger">
            <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{authError || 'Tailnet authentication required.'}</span>
          </div>
        </section>
      </main>
    );
  }

  const toggleGroup = (key: GroupKey) => {
    setOpenGroups((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const navigate = (next: NavKey, opts?: { expandGroup?: boolean }) => {
    setActiveNav(next);
    setMobileSidebarOpen(false);
    if (opts?.expandGroup) {
      const targetGroup = groupForNav(next);
      if (targetGroup) {
        setOpenGroups((prev) => ({ ...prev, [targetGroup]: true }));
      }
    }
    if (typeof window !== 'undefined') {
      window.scrollTo(0, 0);
    }
    if (next === 'logs') {
      setLogsFocus({ nonce: Date.now() });
    } else if (next === 'providers') {
      setRoutingFocus({ section: 'providers', nonce: Date.now() });
    } else if (next === 'routes') {
      setRoutingFocus({ section: 'routes', nonce: Date.now() });
    } else if (next === 'mcp_servers') {
      setMcpFocus({ section: 'servers', nonce: Date.now() });
    } else if (next === 'mcp_audit') {
      setMcpFocus({ section: 'audit', nonce: Date.now() });
    } else if (next === 'guardrails') {
      setSecurityFocus({ section: 'guardrails', nonce: Date.now() });
    } else if (next === 'webhooks') {
      setSecurityFocus({ section: 'webhooks', nonce: Date.now() });
    }
  };

  const jumpToLogs = (filter: Omit<LogsFocusState, 'nonce'>) => {
    setActiveNav('logs');
    setOpenGroups((prev) => ({ ...prev, security: true }));
    if (typeof window !== 'undefined') {
      window.scrollTo(0, 0);
    }
    setLogsFocus({ ...filter, nonce: Date.now() });
  };

  const displayName = me.principal.display_name || me.principal.subject;
  const nodeSubtitle = me.principal.node_name
    ? `${me.principal.node_name}${me.principal.node_ip ? ` · ${me.principal.node_ip}` : ''}`
    : me.principal.node_ip || me.principal.auth_source;

  const isChatView = activeNav === 'chat';
  const isQuickstartView =
    activeNav === 'quickstart' || (!me.is_admin && activeNav !== 'chat');
  const isAdminConsoleView = me.is_admin && !isChatView && !isQuickstartView;
  const activeGroup = groupForNav(activeNav);

  return (
    <div className="ap-shell">
      {mobileSidebarOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 65,
            background: 'rgba(18, 18, 16, 0.28)',
          }}
          onClick={() => setMobileSidebarOpen(false)}
        />
      )}

      <aside
        className="ap-sidebar"
        data-mobile-open={mobileSidebarOpen}
        aria-label="Primary navigation"
      >
        <div className="ap-sidebar-brand">
          <button
            type="button"
            className="ap-brand-btn"
            onClick={() => navigate(me.is_admin ? 'overview' : 'chat')}
          >
            <HeadlampMark size={22} />
            <span className="ap-brand-wordmark">headlamp</span>
          </button>
          <span className="ap-brand-tag">{me.is_admin ? 'admin' : 'tailnet'}</span>
        </div>

        <nav className="ap-sidebar-scroll">
          {me.is_admin ? (
            <>
              {/* Usage & Adoption */}
              <div className="ap-nav-group">
                <button
                  type="button"
                  className="ap-nav-group-btn"
                  data-has-active={!openGroups.telemetry && activeGroup === 'telemetry'}
                  onClick={() => toggleGroup('telemetry')}
                  aria-expanded={openGroups.telemetry}
                >
                  <span className="ap-nav-group-label">
                    <ChartBarIcon size={16} />
                    <span>Usage & Adoption</span>
                  </span>
                  <span
                    className="ap-nav-group-chevron"
                    data-open={openGroups.telemetry}
                  >
                    <ChevronDownIcon />
                  </span>
                </button>
                <div
                  className={`ap-nav-collapse ${openGroups.telemetry ? 'is-open' : ''}`}
                  aria-hidden={!openGroups.telemetry}
                >
                  <div className="ap-nav-collapse-inner">
                    <div className="ap-nav-items">
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.telemetry ? 0 : -1}
                        data-active={activeNav === 'overview'}
                        onClick={() => navigate('overview')}
                      >
                        <span>Usage Overview</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Security */}
              <div className="ap-nav-group">
                <button
                  type="button"
                  className="ap-nav-group-btn"
                  data-has-active={!openGroups.security && activeGroup === 'security'}
                  onClick={() => toggleGroup('security')}
                  aria-expanded={openGroups.security}
                >
                  <span className="ap-nav-group-label">
                    <ShieldIcon size={16} />
                    <span>Security</span>
                  </span>
                  <span
                    className="ap-nav-group-chevron"
                    data-open={openGroups.security}
                  >
                    <ChevronDownIcon />
                  </span>
                </button>
                <div
                  className={`ap-nav-collapse ${openGroups.security ? 'is-open' : ''}`}
                  aria-hidden={!openGroups.security}
                >
                  <div className="ap-nav-collapse-inner">
                    <div className="ap-nav-items">
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.security ? 0 : -1}
                        data-active={activeNav === 'logs'}
                        onClick={() => navigate('logs')}
                      >
                        <span>Activity Logs</span>
                      </button>
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.security ? 0 : -1}
                        data-active={activeNav === 'guardrails'}
                        onClick={() => navigate('guardrails')}
                      >
                        <span>Guardrails</span>
                        {counts.rules > 0 && (
                          <span className="ap-nav-count">{counts.rules}</span>
                        )}
                      </button>
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.security ? 0 : -1}
                        data-active={activeNav === 'webhooks'}
                        onClick={() => navigate('webhooks')}
                      >
                        <span>Webhooks</span>
                        {counts.webhooks > 0 && (
                          <span className="ap-nav-count">{counts.webhooks}</span>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Administration */}
              <div className="ap-nav-group">
                <button
                  type="button"
                  className="ap-nav-group-btn"
                  data-has-active={!openGroups.admin && activeGroup === 'admin'}
                  onClick={() => toggleGroup('admin')}
                  aria-expanded={openGroups.admin}
                >
                  <span className="ap-nav-group-label">
                    <GearIcon size={16} />
                    <span>Administration</span>
                  </span>
                  <span
                    className="ap-nav-group-chevron"
                    data-open={openGroups.admin}
                  >
                    <ChevronDownIcon />
                  </span>
                </button>
                <div
                  className={`ap-nav-collapse ${openGroups.admin ? 'is-open' : ''}`}
                  aria-hidden={!openGroups.admin}
                >
                  <div className="ap-nav-collapse-inner">
                    <div className="ap-nav-items">
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.admin ? 0 : -1}
                        data-active={activeNav === 'providers'}
                        onClick={() => navigate('providers')}
                      >
                        <span>Providers</span>
                        {counts.providers > 0 && (
                          <span className="ap-nav-count">{counts.providers}</span>
                        )}
                      </button>
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.admin ? 0 : -1}
                        data-active={activeNav === 'routes'}
                        onClick={() => navigate('routes')}
                      >
                        <span>Model Routing</span>
                        {counts.routes > 0 && (
                          <span className="ap-nav-count">{counts.routes}</span>
                        )}
                      </button>
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.admin ? 0 : -1}
                        data-active={activeNav === 'budgets'}
                        onClick={() => navigate('budgets')}
                      >
                        <span>Quotas & Grants</span>
                        {counts.budgets > 0 && (
                          <span className="ap-nav-count">{counts.budgets}</span>
                        )}
                      </button>
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.admin ? 0 : -1}
                        data-active={activeNav === 'mcp_servers'}
                        onClick={() => navigate('mcp_servers')}
                      >
                        <span>MCP Servers</span>
                        {counts.mcpServers > 0 && (
                          <span className="ap-nav-count">{counts.mcpServers}</span>
                        )}
                      </button>
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.admin ? 0 : -1}
                        data-active={activeNav === 'mcp_audit'}
                        onClick={() => navigate('mcp_audit')}
                      >
                        <span>MCP Audit</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Reference */}
              <div className="ap-nav-group">
                <button
                  type="button"
                  className="ap-nav-group-btn"
                  data-has-active={!openGroups.developer && pricingOpen}
                  onClick={() => toggleGroup('developer')}
                  aria-expanded={openGroups.developer}
                >
                  <span className="ap-nav-group-label">
                    <BookIcon size={16} />
                    <span>Reference</span>
                  </span>
                  <span
                    className="ap-nav-group-chevron"
                    data-open={openGroups.developer}
                  >
                    <ChevronDownIcon />
                  </span>
                </button>
                <div
                  className={`ap-nav-collapse ${openGroups.developer ? 'is-open' : ''}`}
                  aria-hidden={!openGroups.developer}
                >
                  <div className="ap-nav-collapse-inner">
                    <div className="ap-nav-items">
                      <button
                        type="button"
                        className="ap-nav-item"
                        tabIndex={openGroups.developer ? 0 : -1}
                        data-active={pricingOpen}
                        onClick={() => {
                          setMobileSidebarOpen(false);
                          setPricingOpen(true);
                        }}
                      >
                        <span>Model Pricing</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="ap-nav-group" style={{ gap: 3 }}>
              <button
                type="button"
                className="ap-nav-item ap-nav-item--top"
                data-active={activeNav === 'chat'}
                onClick={() => navigate('chat')}
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 9 }}>
                  <ChatBubbleIcon size={16} />
                  <span>Team Chat</span>
                </span>
              </button>
              <button
                type="button"
                className="ap-nav-item ap-nav-item--top"
                data-active={activeNav === 'quickstart'}
                onClick={() => navigate('quickstart')}
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 9 }}>
                  <TerminalIcon size={16} />
                  <span>My Usage & SDKs</span>
                </span>
              </button>
            </div>
          )}
        </nav>

        <div className="ap-sidebar-footer">
          {me.is_admin && (
            <div className="ap-mode-switch-wrap" style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {!isChatView && (
                <button
                  type="button"
                  className="ap-mode-switch-btn"
                  onClick={() => navigate('chat')}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 9 }}>
                    <ChatBubbleIcon size={16} />
                    <span>Team Chat</span>
                  </span>
                  <ChevronRightIcon size={13} />
                </button>
              )}

              {!isQuickstartView && (
                <button
                  type="button"
                  className="ap-mode-switch-btn"
                  onClick={() => navigate('quickstart')}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 9 }}>
                    <TerminalIcon size={16} />
                    <span>Quickstart & SDKs</span>
                  </span>
                  <ChevronRightIcon size={13} />
                </button>
              )}

              {!isAdminConsoleView && (
                <button
                  type="button"
                  className="ap-mode-switch-btn"
                  onClick={() => navigate('overview')}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 9 }}>
                    <GearIcon size={16} />
                    <span>Admin console</span>
                  </span>
                  <ChevronRightIcon size={13} />
                </button>
              )}
            </div>
          )}

          <div className="ap-identity-bar">
            <div className="ap-identity-user">
              <span className="ap-avatar">
                {initialsFromPrincipal(displayName)}
              </span>
              <div className="ap-identity-meta">
                <span className="ap-identity-name" title={displayName}>
                  {displayName}
                </span>
                <span className="ap-identity-node" title={nodeSubtitle}>
                  {nodeSubtitle}
                </span>
              </div>
            </div>
            <span
              className="ap-identity-chip"
              title={`Tailnet identity (${me.principal.auth_source}) · Role: ${
                me.is_admin ? 'admin' : 'user'
              }`}
            >
              <TailnetMeshGlyph size={14} />
            </span>
          </div>
        </div>
      </aside>

      <div className="ap-main-col">
        <div className="ap-mobile-bar">
          <button
            type="button"
            className="ap-btn ap-btn-ghost"
            onClick={() => setMobileSidebarOpen(true)}
            aria-label="Open navigation"
          >
            <SidebarToggleIcon />
            <span style={{ fontWeight: 650 }}>headlamp</span>
          </button>
          <span className="ap-badge ap-mono">{displayName}</span>
        </div>

        {me.is_admin && !bannerDismissed && !isChatView && (
          <div className="ap-info-banner">
            <div className="ap-info-banner-body">
              <SparkleIcon
                size={15}
                style={{ flexShrink: 0, marginTop: 2 }}
              />
              <span style={{ minWidth: 0 }}>
                <strong>Keyless Tailnet AI Gateway is active.</strong> Connect Claude Code, Codex, Gemini CLI, and Cursor using your node identity in{' '}
                <button
                  type="button"
                  className="ap-info-banner-link"
                  onClick={() => navigate('quickstart')}
                >
                  Quickstart & SDKs
                </button>
                , or inspect capability rules in{' '}
                <button
                  type="button"
                  className="ap-info-banner-link"
                  onClick={() => {
                    navigate('budgets', { expandGroup: true });
                    setBudgetsFocus({ scopeFilter: 'all', nonce: Date.now() });
                  }}
                >
                  Quotas & Grants
                </button>
                .
              </span>
            </div>
            <button
              type="button"
              className="ap-btn ap-btn-ghost ap-btn-sm"
              style={{ flexShrink: 0, height: 22, padding: '0 4px' }}
              onClick={() => setBannerDismissed(true)}
              aria-label="Dismiss banner"
            >
              <CloseIcon size={14} />
            </button>
          </div>
        )}

        <main style={{ flex: 1, minWidth: 0 }}>
          {isChatView ? (
            <ChatView />
          ) : isQuickstartView ? (
            <PersonalView me={me} />
          ) : activeNav === 'overview' ? (
            <OverviewView
              windowRange={overviewWindow}
              onWindowChange={setOverviewWindow}
              onJumpToLogs={jumpToLogs}
            />
          ) : activeNav === 'providers' || activeNav === 'routes' ? (
            <RoutingView
              focus={routingFocus}
              onSectionChange={(sec) =>
                setActiveNav(sec === 'routes' ? 'routes' : 'providers')
              }
              onOpenPricing={() => setPricingOpen(true)}
              onCountsChange={({ providers, routes }) =>
                setCounts((prev) => ({ ...prev, providers, routes }))
              }
            />
          ) : activeNav === 'budgets' ? (
            <BudgetsAccessView
              focus={budgetsFocus}
              onCountChange={(budgets) =>
                setCounts((prev) => ({ ...prev, budgets }))
              }
            />
          ) : activeNav === 'mcp_servers' || activeNav === 'mcp_audit' ? (
            <MCPView
              focus={mcpFocus}
              onSectionChange={(sec) =>
                setActiveNav(sec === 'audit' ? 'mcp_audit' : 'mcp_servers')
              }
              onCountChange={(mcpServers) =>
                setCounts((prev) => ({ ...prev, mcpServers }))
              }
            />
          ) : activeNav === 'logs' ? (
            <AuditLogsView focus={logsFocus} />
          ) : (
            <SecurityView
              focus={securityFocus}
              onSectionChange={(sec) =>
                setActiveNav(sec === 'webhooks' ? 'webhooks' : 'guardrails')
              }
              onCountsChange={({ rules, webhooks }) =>
                setCounts((prev) => ({ ...prev, rules, webhooks }))
              }
            />
          )}
        </main>
      </div>

      <PricingDrawer
        open={pricingOpen}
        onClose={() => setPricingOpen(false)}
      />
    </div>
  );
}
