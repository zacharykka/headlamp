import { useEffect, useState } from 'react';
import { Sparkles, User } from 'reicon-react';
import { api } from './api/client';
import { CascadeMenu } from './components/CascadeMenu';
import { Icon } from './components/Icon';
import type { MeResponse, TimeWindow } from './types/api';
import { AuditLogsView, type LogsFocusState } from './views/AuditLogsView';
import {
  BudgetsAccessView,
  type BudgetsFocusState,
} from './views/BudgetsAccessView';
import { OverviewView } from './views/OverviewView';
import { PersonalView } from './views/PersonalView';
import { RoutingView, type RoutingFocusState } from './views/RoutingView';
import { SecurityView, type SecurityFocusState } from './views/SecurityView';

type AdminTab = 'overview' | 'routing' | 'budgets' | 'logs' | 'security' | 'personal';

export function App() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loadingMe, setLoadingMe] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<AdminTab>('overview');
  const [overviewWindow, setOverviewWindow] = useState<TimeWindow>('7d');

  const [routingFocus, setRoutingFocus] = useState<RoutingFocusState>({});
  const [budgetsFocus, setBudgetsFocus] = useState<BudgetsFocusState>({});
  const [logsFocus, setLogsFocus] = useState<LogsFocusState>({});
  const [securityFocus, setSecurityFocus] = useState<SecurityFocusState>({});

  useEffect(() => {
    api
      .getMe()
      .then((res) => {
        setMe(res);
        if (!res.is_admin) {
          setActiveTab('personal');
        }
        setLoadingMe(false);
      })
      .catch((err: unknown) => {
        setAuthError(err instanceof Error ? err.message : 'Unable to authenticate');
        setLoadingMe(false);
      });
  }, []);

  if (loadingMe) {
    return (
      <main className="hl-main">
        <p className="hl-secondary">Loading Headlamp...</p>
      </main>
    );
  }

  if (authError || !me) {
    return (
      <main className="hl-main">
        <section className="hl-section">
          <h1>Headlamp</h1>
          <p className="hl-status-text hl-status-danger">
            {authError || 'Authentication required'}
          </p>
        </section>
      </main>
    );
  }

  const goRouting = (next: Omit<RoutingFocusState, 'nonce'>) => {
    setActiveTab('routing');
    setRoutingFocus({ ...next, nonce: Date.now() });
  };

  const goBudgets = (next: Omit<BudgetsFocusState, 'nonce'>) => {
    setActiveTab('budgets');
    setBudgetsFocus({ ...next, nonce: Date.now() });
  };

  const goLogs = (next: Omit<LogsFocusState, 'nonce'>) => {
    setActiveTab('logs');
    setLogsFocus({ ...next, nonce: Date.now() });
  };

  const goSecurity = (next: Omit<SecurityFocusState, 'nonce'>) => {
    setActiveTab('security');
    setSecurityFocus({ ...next, nonce: Date.now() });
  };

  return (
    <>
      <header className="hl-header">
        <div className="hl-header-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
            <button
              type="button"
              className="hl-brand"
              onClick={() => setActiveTab(me.is_admin ? 'overview' : 'personal')}
            >
              <Icon icon={Sparkles} color="#0071E3" />
              <span>Headlamp</span>
            </button>

            {me.is_admin && (
              <nav className="hl-nav" aria-label="Primary navigation">
                <CascadeMenu
                  label="Overview"
                  current={activeTab === 'overview'}
                  onPrimaryClick={() => setActiveTab('overview')}
                  items={[
                    {
                      id: 'ov-window',
                      label: 'Time Window',
                      children: [
                        {
                          id: 'w-24h',
                          label: 'Last 24 Hours',
                          selected: overviewWindow === '24h',
                          onSelect: () => {
                            setActiveTab('overview');
                            setOverviewWindow('24h');
                          },
                        },
                        {
                          id: 'w-7d',
                          label: 'Last 7 Days',
                          selected: overviewWindow === '7d',
                          onSelect: () => {
                            setActiveTab('overview');
                            setOverviewWindow('7d');
                          },
                        },
                        {
                          id: 'w-30d',
                          label: 'Last 30 Days',
                          selected: overviewWindow === '30d',
                          onSelect: () => {
                            setActiveTab('overview');
                            setOverviewWindow('30d');
                          },
                        },
                      ],
                    },
                  ]}
                />

                <CascadeMenu
                  label="Routing"
                  current={activeTab === 'routing'}
                  onPrimaryClick={() => goRouting({ providerType: 'all', routeFilter: 'all' })}
                  items={[
                    {
                      id: 'nav-providers',
                      label: 'Providers',
                      children: [
                        {
                          id: 'p-all',
                          label: 'All Providers',
                          onSelect: () => goRouting({ providerType: 'all' }),
                        },
                        {
                          id: 'p-openai',
                          label: 'OpenAI',
                          onSelect: () => goRouting({ providerType: 'openai' }),
                        },
                        {
                          id: 'p-anthropic',
                          label: 'Anthropic',
                          onSelect: () => goRouting({ providerType: 'anthropic' }),
                        },
                        {
                          id: 'p-gemini',
                          label: 'Gemini',
                          onSelect: () => goRouting({ providerType: 'gemini' }),
                        },
                        {
                          id: 'p-ollama',
                          label: 'Ollama',
                          onSelect: () => goRouting({ providerType: 'ollama' }),
                        },
                        {
                          id: 'p-new',
                          label: 'Add Provider',
                          onSelect: () => goRouting({ modal: 'provider' }),
                        },
                      ],
                    },
                    {
                      id: 'nav-routes',
                      label: 'Model Routes',
                      children: [
                        {
                          id: 'r-all',
                          label: 'All Routes',
                          onSelect: () => goRouting({ routeFilter: 'all' }),
                        },
                        {
                          id: 'r-fb',
                          label: 'With Fallbacks',
                          onSelect: () => goRouting({ routeFilter: 'fallbacks' }),
                        },
                        {
                          id: 'r-custom',
                          label: 'Custom Pricing',
                          onSelect: () => goRouting({ routeFilter: 'custom_pricing' }),
                        },
                        {
                          id: 'r-new',
                          label: 'Add Route',
                          onSelect: () => goRouting({ modal: 'route' }),
                        },
                      ],
                    },
                    {
                      id: 'nav-pricing',
                      label: 'Pricing Table',
                      onSelect: () => goRouting({ modal: 'pricing' }),
                    },
                  ]}
                />

                <CascadeMenu
                  label="Budgets"
                  current={activeTab === 'budgets'}
                  onPrimaryClick={() => goBudgets({ scopeFilter: 'all' })}
                  items={[
                    {
                      id: 'b-scopes',
                      label: 'Scopes',
                      children: [
                        {
                          id: 'b-all',
                          label: 'All Scopes',
                          onSelect: () => goBudgets({ scopeFilter: 'all' }),
                        },
                        {
                          id: 'b-global',
                          label: 'Global (*)',
                          onSelect: () => goBudgets({ scopeFilter: 'global' }),
                        },
                        {
                          id: 'b-tag',
                          label: 'Node Tags',
                          onSelect: () => goBudgets({ scopeFilter: 'tag' }),
                        },
                        {
                          id: 'b-user',
                          label: 'Users',
                          onSelect: () => goBudgets({ scopeFilter: 'user' }),
                        },
                      ],
                    },
                    {
                      id: 'b-new',
                      label: 'Add Budget',
                      onSelect: () => goBudgets({ openCreate: true }),
                    },
                  ]}
                />

                <CascadeMenu
                  label="Audit Logs"
                  current={activeTab === 'logs'}
                  onPrimaryClick={() => goLogs({})}
                  items={[
                    {
                      id: 'l-status',
                      label: 'Filter by Status',
                      children: [
                        {
                          id: 'l-all',
                          label: 'All Requests',
                          onSelect: () => goLogs({}),
                        },
                        {
                          id: 'l-200',
                          label: '200 OK',
                          onSelect: () => goLogs({ status: '200' }),
                        },
                        {
                          id: 'l-429',
                          label: '429 Rate Limited',
                          onSelect: () => goLogs({ status: '429' }),
                        },
                        {
                          id: 'l-500',
                          label: '500 Error',
                          onSelect: () => goLogs({ status: '500' }),
                        },
                      ],
                    },
                    {
                      id: 'l-guardrail',
                      label: 'Guardrail Hits',
                      onSelect: () => goLogs({ guardrail_only: true }),
                    },
                    {
                      id: 'l-settings',
                      label: 'Audit Settings',
                      onSelect: () => goLogs({ openSettings: true }),
                    },
                  ]}
                />

                <CascadeMenu
                  label="Security"
                  current={activeTab === 'security'}
                  onPrimaryClick={() => goSecurity({ category: 'all', webhookType: 'all' })}
                  items={[
                    {
                      id: 's-guardrails',
                      label: 'Guardrails',
                      children: [
                        {
                          id: 'sg-all',
                          label: 'All Rules',
                          onSelect: () => goSecurity({ category: 'all' }),
                        },
                        {
                          id: 'sg-secret',
                          label: 'Secret Detectors',
                          onSelect: () => goSecurity({ category: 'secret' }),
                        },
                        {
                          id: 'sg-pii',
                          label: 'PII Detectors',
                          onSelect: () => goSecurity({ category: 'pii' }),
                        },
                        {
                          id: 'sg-new',
                          label: 'Add Rule',
                          onSelect: () => goSecurity({ modal: 'guardrail' }),
                        },
                      ],
                    },
                    {
                      id: 's-webhooks',
                      label: 'Webhooks',
                      children: [
                        {
                          id: 'sw-all',
                          label: 'All Webhooks',
                          onSelect: () => goSecurity({ webhookType: 'all' }),
                        },
                        {
                          id: 'sw-sync',
                          label: 'Sync Review',
                          onSelect: () => goSecurity({ webhookType: 'sync_review' }),
                        },
                        {
                          id: 'sw-async',
                          label: 'Async Event',
                          onSelect: () => goSecurity({ webhookType: 'async_event' }),
                        },
                        {
                          id: 'sw-new',
                          label: 'Add Webhook',
                          onSelect: () => goSecurity({ modal: 'webhook' }),
                        },
                      ],
                    },
                  ]}
                />
              </nav>
            )}
          </div>

          <div className="hl-principal-bar">
            <span>{me.principal.display_name || me.principal.subject}</span>
            {me.is_admin && (
              <button
                type="button"
                className="hl-btn hl-btn-ghost"
                data-active={activeTab === 'personal'}
                onClick={() =>
                  setActiveTab((prev) => (prev === 'personal' ? 'overview' : 'personal'))
                }
              >
                <Icon icon={User} />
                <span>{activeTab === 'personal' ? 'Admin' : 'My Usage'}</span>
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="hl-main">
        {!me.is_admin || activeTab === 'personal' ? (
          <PersonalView me={me} />
        ) : activeTab === 'overview' ? (
          <OverviewView
            windowRange={overviewWindow}
            onWindowChange={setOverviewWindow}
            onJumpToLogs={(filter) => goLogs(filter)}
          />
        ) : activeTab === 'routing' ? (
          <RoutingView focus={routingFocus} />
        ) : activeTab === 'budgets' ? (
          <BudgetsAccessView focus={budgetsFocus} />
        ) : activeTab === 'logs' ? (
          <AuditLogsView focus={logsFocus} />
        ) : (
          <SecurityView focus={securityFocus} />
        )}
      </main>
    </>
  );
}
