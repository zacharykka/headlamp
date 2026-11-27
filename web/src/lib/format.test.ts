import { describe, expect, it } from 'vitest';
import {
  formatCostTier,
  formatPercent,
  hasRouteCostOverride,
  parseRouteFallbacks,
} from './format';

describe('Aperture routing & telemetry helpers', () => {
  it('renders Default for null/undefined cost tiers and preserves explicit $0.00', () => {
    expect(formatCostTier(null)).toBe('Default');
    expect(formatCostTier(undefined)).toBe('Default');
    expect(formatCostTier(0)).toBe('$0.00');
    expect(formatCostTier(3)).toBe('$3.00');
    expect(formatCostTier(0.15)).toBe('$0.15');
  });

  it('detects route cost overrides across all 4 pricing tiers', () => {
    expect(
      hasRouteCostOverride({
        input_cost_per_million: null,
        output_cost_per_million: null,
        cache_read_cost_per_million: null,
        cache_write_cost_per_million: null,
      }),
    ).toBe(false);

    expect(
      hasRouteCostOverride({
        input_cost_per_million: null,
        output_cost_per_million: null,
        cache_read_cost_per_million: 0.3,
        cache_write_cost_per_million: null,
      }),
    ).toBe(true);

    expect(
      hasRouteCostOverride({
        input_cost_per_million: null,
        output_cost_per_million: null,
        cache_read_cost_per_million: null,
        cache_write_cost_per_million: 3.75,
      }),
    ).toBe(true);
  });

  it('rejects fallback lines missing provider/model slash instead of silently dropping', () => {
    const missingSlash = parseRouteFallbacks('gpt-4.1-mini', ['openai', 'anthropic']);
    expect(missingSlash.error).toContain('must use "provider/model" format');
    expect(missingSlash.fallbacks).toEqual([]);

    const unknownProvider = parseRouteFallbacks('bedrock/claude-3-7-sonnet', [
      'openai',
      'anthropic',
    ]);
    expect(unknownProvider.error).toContain('unknown provider "bedrock"');

    const valid = parseRouteFallbacks(
      'openai/gpt-4.1\n  anthropic/claude-sonnet-4-20250514  \n',
      ['openai', 'anthropic'],
    );
    expect(valid.error).toBeNull();
    expect(valid.fallbacks).toEqual([
      { provider: 'openai', model: 'gpt-4.1' },
      { provider: 'anthropic', model: 'claude-sonnet-4-20250514' },
    ]);
  });

  it('formats error and cache percentages cleanly', () => {
    expect(formatPercent(0, 0)).toBe('0.0%');
    expect(formatPercent(2, 50)).toBe('4.0%');
    expect(formatPercent(1, 5000)).toBe('<0.1%');
  });
});
