import type { ModelRouteItem, RouteFallback } from '../types/api';

export function formatUSD(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '$0.00';
  }
  if (value > 0 && value < 0.01) {
    return `$${value.toFixed(4)}`;
  }
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: value < 1 ? 4 : 2,
  }).format(value);
}

/**
 * Renders a route cost tier (/1M tokens).
 * Explicitly returns "Default" when null or undefined — never "$0.00" — while
 * preserving "$0.00" when a route explicitly sets a zero-cost override.
 */
export function formatCostTier(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'Default';
  }
  return formatUSD(value);
}

/**
 * Detects whether a virtual model route overrides pricing on ANY of the 4 tiers.
 */
export function hasRouteCostOverride(
  route: Pick<
    ModelRouteItem,
    | 'input_cost_per_million'
    | 'output_cost_per_million'
    | 'cache_read_cost_per_million'
    | 'cache_write_cost_per_million'
  >,
): boolean {
  return (
    route.input_cost_per_million != null ||
    route.output_cost_per_million != null ||
    route.cache_read_cost_per_million != null ||
    route.cache_write_cost_per_million != null
  );
}

/**
 * Validates and parses fallback lines in strict "provider/model" format.
 * Never silently drops malformed lines missing "/".
 */
export function parseRouteFallbacks(
  raw: string,
  knownProviders?: string[],
): { fallbacks: RouteFallback[]; error: string | null } {
  const lines = raw.split('\n');
  const fallbacks: RouteFallback[] = [];
  const providerSet =
    knownProviders && knownProviders.length > 0 ? new Set(knownProviders) : null;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line) continue;

    const slashIdx = line.indexOf('/');
    if (slashIdx <= 0 || slashIdx === line.length - 1) {
      return {
        fallbacks: [],
        error: `Fallback line ${i + 1} ("${line}") must use "provider/model" format (for example: openai/gpt-4.1-mini).`,
      };
    }

    const provider = line.slice(0, slashIdx).trim();
    const model = line.slice(slashIdx + 1).trim();
    if (!provider || !model) {
      return {
        fallbacks: [],
        error: `Fallback line ${i + 1} ("${line}") requires both a provider name and model ID.`,
      };
    }

    if (providerSet && !providerSet.has(provider)) {
      return {
        fallbacks: [],
        error: `Fallback line ${i + 1} references unknown provider "${provider}". Available providers: ${knownProviders!.join(', ')}.`,
      };
    }

    fallbacks.push({ provider, model });
  }

  return { fallbacks, error: null };
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '0';
  }
  return new Intl.NumberFormat('en-US').format(value);
}

export function formatCompactTokens(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '0';
  }
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(2)}M`;
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(1)}K`;
  }
  return String(value);
}

export function formatLatency(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || Number.isNaN(ms) || ms <= 0) {
    return '0 ms';
  }
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(2)} s`;
  }
  return `${Math.round(ms)} ms`;
}

export function formatPercent(
  numerator: number | null | undefined,
  denominator: number | null | undefined,
): string {
  const num = numerator ?? 0;
  const den = denominator ?? 0;
  if (den <= 0 || num <= 0) return '0.0%';
  const pct = (num / den) * 100;
  if (pct < 0.1) return '<0.1%';
  return `${pct.toFixed(1)}%`;
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) {
    return '—';
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

export function formatBucketLabel(bucket: string): string {
  if (!bucket) return '';
  const date = new Date(bucket);
  if (!Number.isNaN(date.getTime())) {
    if (bucket.includes('T') && (bucket.includes(':') || bucket.endsWith('Z'))) {
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        hour12: false,
      }).format(date);
    }
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
    }).format(date);
  }
  return bucket.length > 10 ? bucket.slice(5, 16) : bucket;
}
