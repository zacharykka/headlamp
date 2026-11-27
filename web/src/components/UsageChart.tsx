import { useId, useState } from 'react';
import {
  formatBucketLabel,
  formatCompactTokens,
  formatNumber,
  formatUSD,
} from '../lib/format';
import type { UsageSeriesPoint } from '../types/api';

export type ChartMetric = 'cost_usd' | 'requests' | 'tokens' | 'errors';

interface UsageChartProps {
  series: UsageSeriesPoint[];
  metric: ChartMetric;
  flush?: boolean;
}

export function UsageChart({ series, metric, flush = false }: UsageChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const gradId = useId();

  const totalAcrossWindow = series.reduce(
    (acc, pt) => acc + pt.requests + pt.tokens + pt.cost_usd + pt.errors,
    0,
  );

  if (series.length === 0 || totalAcrossWindow === 0) {
    return (
      <div className="ap-empty-state">
        <span>No usage in the selected time range. Try adjusting the range.</span>
      </div>
    );
  }

  const width = 980;
  const height = 220;
  const padLeft = 64;
  const padRight = 22;
  const padTop = 18;
  const padBottom = 32;
  const plotW = width - padLeft - padRight;
  const plotH = height - padTop - padBottom;

  const valueOf = (pt: UsageSeriesPoint): number => {
    if (metric === 'cost_usd') return pt.cost_usd;
    if (metric === 'tokens') return pt.tokens;
    if (metric === 'errors') return pt.errors;
    return pt.requests;
  };

  const values = series.map(valueOf);
  const rawMax = Math.max(...values, 0);
  const maxVal = rawMax > 0 ? rawMax * 1.15 : 1;

  const xFor = (idx: number) => {
    if (series.length === 1) return padLeft + plotW / 2;
    return padLeft + (idx / (series.length - 1)) * plotW;
  };

  const yFor = (val: number) => padTop + plotH - (val / maxVal) * plotH;

  const points = values.map((val, idx) => ({
    x: xFor(idx),
    y: yFor(val),
    value: val,
    raw: series[idx],
  }));

  const linePath = points
    .map((pt, idx) => `${idx === 0 ? 'M' : 'L'} ${pt.x.toFixed(2)} ${pt.y.toFixed(2)}`)
    .join(' ');

  const areaPath =
    points.length > 1
      ? `${linePath} L ${points[points.length - 1].x.toFixed(2)} ${(
          padTop + plotH
        ).toFixed(2)} L ${points[0].x.toFixed(2)} ${(padTop + plotH).toFixed(2)} Z`
      : '';

  const strokeColor = metric === 'errors' ? '#DC2626' : '#2563EB';
  const activePoint = hoveredIndex !== null ? points[hoveredIndex] : null;

  const firstLabel = formatBucketLabel(series[0].bucket);
  const midLabel =
    series.length > 2
      ? formatBucketLabel(series[Math.floor(series.length / 2)].bucket)
      : '';
  const lastLabel =
    series.length > 1 ? formatBucketLabel(series[series.length - 1].bucket) : '';

  const formatAxisVal = (val: number) => {
    if (metric === 'cost_usd') return formatUSD(val);
    if (metric === 'tokens') return formatCompactTokens(Math.round(val));
    return formatNumber(Math.round(val));
  };

  const metricLabel =
    metric === 'cost_usd'
      ? 'Spend (USD)'
      : metric === 'tokens'
        ? 'Tokens'
        : metric === 'errors'
          ? 'Errors'
          : 'Requests';

  return (
    <div style={{ padding: flush ? '4px 0 0' : '14px 18px 16px' }}>
      <div
        style={{
          minHeight: 24,
          marginBottom: 8,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          flexWrap: 'wrap',
          fontSize: 12.5,
        }}
      >
        {activePoint ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 600 }}>
              {formatBucketLabel(activePoint.raw.bucket)}
            </span>
            <span className="ap-tabular" style={{ color: '#1D4ED8', fontWeight: 600 }}>
              {formatUSD(activePoint.raw.cost_usd)}
            </span>
            <span className="ap-tabular" style={{ color: 'var(--ap-text-secondary)' }}>
              {formatNumber(activePoint.raw.requests)} req
            </span>
            <span className="ap-tabular" style={{ color: 'var(--ap-text-secondary)' }}>
              {formatCompactTokens(activePoint.raw.tokens)} tok
            </span>
            {activePoint.raw.errors > 0 && (
              <span className="ap-badge ap-badge--red ap-tabular">
                {formatNumber(activePoint.raw.errors)} err
              </span>
            )}
          </div>
        ) : (
          <span style={{ color: 'var(--ap-text-secondary)', fontWeight: 500 }}>
            {metricLabel} over time
          </span>
        )}
        <span style={{ color: 'var(--ap-text-muted)', fontSize: 11.5 }}>
          Hover buckets to inspect spend, requests, tokens & errors
        </span>
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: '100%', height: 210, display: 'block' }}
        role="img"
        aria-label={`${metricLabel} trend chart`}
        onMouseLeave={() => setHoveredIndex(null)}
      >
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={strokeColor} stopOpacity="0.16" />
            <stop offset="100%" stopColor={strokeColor} stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {[0, 0.5, 1].map((tick) => {
          const val = maxVal * tick;
          const y = yFor(val);
          return (
            <g key={tick}>
              <line
                x1={padLeft}
                x2={width - padRight}
                y1={y}
                y2={y}
                stroke="rgba(24, 24, 21, 0.08)"
                strokeDasharray={tick === 0 ? undefined : '3 3'}
                strokeWidth="1"
              />
              <text
                x={padLeft - 10}
                y={y + 4}
                textAnchor="end"
                fill="#84827C"
                fontSize="11.5"
                style={{ fontVariantNumeric: 'tabular-nums' }}
              >
                {formatAxisVal(val)}
              </text>
            </g>
          );
        })}

        {areaPath && <path d={areaPath} fill={`url(#${gradId})`} />}

        {points.length === 1 ? (
          <g>
            <rect
              x={points[0].x - 22}
              y={points[0].y}
              width={44}
              height={Math.max(2, padTop + plotH - points[0].y)}
              rx={5}
              fill={strokeColor}
              fillOpacity="0.14"
            />
            <line
              x1={points[0].x}
              x2={points[0].x}
              y1={points[0].y}
              y2={padTop + plotH}
              stroke={strokeColor}
              strokeWidth="2"
              strokeLinecap="round"
            />
          </g>
        ) : (
          <path
            d={linePath}
            fill="none"
            stroke={strokeColor}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}

        {activePoint && (
          <line
            x1={activePoint.x}
            x2={activePoint.x}
            y1={padTop}
            y2={padTop + plotH}
            stroke="#151514"
            strokeOpacity="0.18"
            strokeWidth="1"
          />
        )}

        {points.map((pt, idx) => {
          const hasError = pt.raw.errors > 0 && metric !== 'errors';
          return (
            <g key={pt.raw.bucket + String(idx)}>
              <circle
                cx={pt.x}
                cy={pt.y}
                r={hoveredIndex === idx ? 4.8 : points.length === 1 ? 4 : 3}
                fill={hoveredIndex === idx ? strokeColor : '#FFFFFF'}
                stroke={strokeColor}
                strokeWidth="2"
              />
              {hasError && (
                <circle
                  cx={pt.x}
                  cy={padTop + 4}
                  r={2.6}
                  fill="#DC2626"
                />
              )}
            </g>
          );
        })}

        <text
          x={points.length === 1 ? points[0].x : padLeft}
          y={height - 7}
          textAnchor={points.length === 1 ? 'middle' : 'start'}
          fill="#84827C"
          fontSize="11.5"
        >
          {firstLabel}
        </text>
        {midLabel && (
          <text
            x={padLeft + plotW / 2}
            y={height - 7}
            textAnchor="middle"
            fill="#84827C"
            fontSize="11.5"
          >
            {midLabel}
          </text>
        )}
        {lastLabel && (
          <text
            x={width - padRight}
            y={height - 7}
            textAnchor="end"
            fill="#84827C"
            fontSize="11.5"
          >
            {lastLabel}
          </text>
        )}

        {points.map((pt, idx) => {
          const step = series.length > 1 ? plotW / (series.length - 1) : plotW;
          return (
            <rect
              key={`hit-${idx}`}
              x={pt.x - step / 2}
              y={padTop}
              width={step}
              height={plotH}
              fill="transparent"
              onMouseEnter={() => setHoveredIndex(idx)}
            />
          );
        })}
      </svg>
    </div>
  );
}
