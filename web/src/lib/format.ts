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
