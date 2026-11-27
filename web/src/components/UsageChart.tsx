import { useState } from 'react';
import type { UsageSeriesPoint } from '../types/api';
import { formatBucketLabel, formatNumber, formatUSD } from '../lib/format';

interface UsageChartProps {
  series: UsageSeriesPoint[];
  metric: 'cost_usd' | 'requests';
}

export function UsageChart({ series, metric }: UsageChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  if (series.length === 0) {
    return (
      <div
        className="hl-surface"
        style={{
          height: 240,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <span className="hl-secondary">No traffic in selected window</span>
      </div>
    );
  }

  const width = 1040;
  const height = 240;
  const padLeft = 64;
  const padRight = 24;
  const padTop = 24;
  const padBottom = 36;
  const plotW = width - padLeft - padRight;
  const plotH = height - padTop - padBottom;

  const values = series.map((pt) =>
    metric === 'cost_usd' ? pt.cost_usd : pt.requests,
  );
  const rawMax = Math.max(...values, 0);
  const maxVal = rawMax > 0 ? rawMax * 1.12 : 1;

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

  const pathD = points
    .map((pt, idx) => `${idx === 0 ? 'M' : 'L'} ${pt.x.toFixed(2)} ${pt.y.toFixed(2)}`)
    .join(' ');

  const activePoint = hoveredIndex !== null ? points[hoveredIndex] : null;
  const firstLabel = formatBucketLabel(series[0].bucket);
  const midLabel =
    series.length > 2
      ? formatBucketLabel(series[Math.floor(series.length / 2)].bucket)
      : '';
  const lastLabel =
    series.length > 1 ? formatBucketLabel(series[series.length - 1].bucket) : '';

  const formatAxisVal = (val: number) =>
    metric === 'cost_usd' ? formatUSD(val) : formatNumber(Math.round(val));

  return (
    <div className="hl-surface" style={{ padding: 28 }}>
      <div
        style={{
          height: 24,
          marginBottom: 12,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: 14,
        }}
      >
        {activePoint ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ fontWeight: 500 }}>
              {formatBucketLabel(activePoint.raw.bucket)}
            </span>
            <span className="hl-status-accent" style={{ fontWeight: 600 }}>
              {formatUSD(activePoint.raw.cost_usd)}
            </span>
            <span className="hl-secondary">
              {formatNumber(activePoint.raw.requests)} req
            </span>
          </div>
        ) : (
          <span className="hl-secondary">
            {metric === 'cost_usd' ? 'Spend (USD)' : 'Requests'}
          </span>
        )}
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: '100%', height: 224, display: 'block', overflow: 'visible' }}
        role="img"
        aria-label={metric === 'cost_usd' ? 'Spend trend chart' : 'Request trend chart'}
        onMouseLeave={() => setHoveredIndex(null)}
      >
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
                stroke="#E5E5EA"
                strokeWidth="1"
              />
              <text
                x={padLeft - 12}
                y={y + 4}
                textAnchor="end"
                fill="#6A6A6A"
                fontSize="14"
              >
                {formatAxisVal(val)}
              </text>
            </g>
          );
        })}

        <path
          d={pathD}
          fill="none"
          stroke="#0071E3"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {points.map((pt, idx) => (
          <circle
            key={pt.raw.bucket + String(idx)}
            cx={pt.x}
            cy={pt.y}
            r={hoveredIndex === idx ? 5 : 3}
            fill={hoveredIndex === idx ? '#0071E3' : '#FFFFFF'}
            stroke="#0071E3"
            strokeWidth="2"
          />
        ))}

        {activePoint && (
          <line
            x1={activePoint.x}
            x2={activePoint.x}
            y1={padTop}
            y2={padTop + plotH}
            stroke="#181818"
            strokeOpacity="0.16"
            strokeWidth="1"
          />
        )}

        <text x={padLeft} y={height - 8} textAnchor="start" fill="#6A6A6A" fontSize="14">
          {firstLabel}
        </text>
        {midLabel && (
          <text
            x={padLeft + plotW / 2}
            y={height - 8}
            textAnchor="middle"
            fill="#6A6A6A"
            fontSize="14"
          >
            {midLabel}
          </text>
        )}
        {lastLabel && (
          <text
            x={width - padRight}
            y={height - 8}
            textAnchor="end"
            fill="#6A6A6A"
            fontSize="14"
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
