import { useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import { AlertIcon, SearchIcon } from './ApertureIcons';
import { Drawer } from './Primitives';
import { formatUSD } from '../lib/format';
import type { PricingResponse } from '../types/api';

interface PricingDrawerProps {
  open: boolean;
  onClose: () => void;
}

export function PricingDrawer({ open, onClose }: PricingDrawerProps) {
  const [pricing, setPricing] = useState<PricingResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (!open || pricing) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api
      .getPricing({ signal: controller.signal })
      .then((res) => {
        if (!controller.signal.aborted) {
          setPricing(res);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setError(err instanceof Error ? err.message : 'Failed to load model pricing');
        setLoading(false);
      });
    return () => controller.abort();
  }, [open, pricing]);

  const exactPricingEntries = useMemo(() => {
    const q = query.trim().toLowerCase();
    const entries = Object.entries(pricing?.exact ?? {}).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    if (!q) return entries;
    return entries.filter(([model]) => model.toLowerCase().includes(q));
  }, [pricing, query]);

  const patternPricingEntries = useMemo(() => {
    const q = query.trim().toLowerCase();
    const entries = pricing?.patterns ?? [];
    if (!q) return entries;
    return entries.filter((p) => p.pattern.toLowerCase().includes(q));
  }, [pricing, query]);

  return (
    <Drawer
      open={open}
      title="Built-in Model Pricing Reference"
      subtitle="USD per 1,000,000 tokens used when route cost tiers are set to Default"
      onClose={onClose}
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
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter built-in model pricing"
        />
      </div>

      {error && (
        <div className="ap-alert ap-alert--danger" role="alert">
          <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{error}</span>
        </div>
      )}

      {loading && !pricing ? (
        <div className="ap-card ap-card-body" style={{ color: 'var(--ap-text-secondary)' }}>
          Loading built-in pricing catalog...
        </div>
      ) : (
        <>
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
        </>
      )}
    </Drawer>
  );
}
