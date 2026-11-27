import type { SVGProps } from 'react';

export interface SvgIconProps extends SVGProps<SVGSVGElement> {
  size?: number;
}

function baseProps(size: number, props?: SvgIconProps): SVGProps<SVGSVGElement> {
  return {
    width: size,
    height: size,
    viewBox: '0 0 20 20',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.45,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    'aria-hidden': true,
    ...props,
  };
}

/**
 * Geometric lens/beacon mark inspired by Tailscale Aperture's multi-dot orbital glyph.
 */
export function HeadlampMark({ size = 22 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      style={{ flexShrink: 0 }}
    >
      <path
        d="M5.4 8.2C6.8 5.4 9.7 3.7 13 4c2.1.2 4 1.1 5.4 2.6"
        stroke="#181817"
        strokeWidth="2.3"
        strokeLinecap="round"
      />
      <path
        d="M18.6 15.8c-1.4 2.8-4.3 4.5-7.6 4.2-2.1-.2-4-1.1-5.4-2.6"
        stroke="#4B4A46"
        strokeWidth="2.3"
        strokeLinecap="round"
      />
      <circle cx="12" cy="12" r="2.6" fill="#181817" />
      <circle cx="18.8" cy="9.5" r="1.65" fill="#2563EB" />
      <circle cx="5.2" cy="14.5" r="1.65" fill="#181817" />
    </svg>
  );
}

/**
 * Tailscale-style 3x3 mesh dot glyph for tailnet identity & grants indicators.
 */
export function TailnetMeshGlyph({ size = 14 }: { size?: number }) {
  const dots = [4, 10, 16];
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      aria-hidden="true"
      style={{ flexShrink: 0 }}
    >
      {dots.map((cy, rIdx) =>
        dots.map((cx, cIdx) => {
          const active = (rIdx === 1 && cIdx >= 0) || (rIdx === 2 && cIdx === 1) || (rIdx === 0 && cIdx === 1);
          return (
            <circle
              key={`${rIdx}-${cIdx}`}
              cx={cx}
              cy={cy}
              r={1.7}
              fill="currentColor"
              fillOpacity={active ? 0.95 : 0.28}
            />
          );
        }),
      )}
    </svg>
  );
}

export function ChartBarIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <rect x="3" y="10.5" width="3.2" height="6" rx="0.8" />
      <rect x="8.4" y="5.5" width="3.2" height="11" rx="0.8" />
      <rect x="13.8" y="8" width="3.2" height="8.5" rx="0.8" />
    </svg>
  );
}

export function ActivityIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M2.5 10h3.2l2.1-4.8 3.6 9.6 2.3-4.8h3.8" />
    </svg>
  );
}

export function ShieldIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M10 2.6 4 5.1v4.6c0 4.1 2.5 6.8 6 7.9 3.5-1.1 6-3.8 6-7.9V5.1L10 2.6Z" />
      <path d="m7.7 10.1 1.6 1.6 3.2-3.3" />
    </svg>
  );
}

export function GearIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <circle cx="10" cy="10" r="2.5" />
      <path d="M10 3.1v1.5M10 15.4v1.5M3.1 10h1.5M15.4 10h1.5M5.1 5.1l1.1 1.1M13.8 13.8l1.1 1.1M14.9 5.1l-1.1 1.1M6.2 13.8l-1.1 1.1" />
    </svg>
  );
}

export function RouteIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <circle cx="4.5" cy="5.5" r="2" />
      <circle cx="4.5" cy="14.5" r="2" />
      <circle cx="15.5" cy="10" r="2" />
      <path d="M6.5 5.8c3.5 0 3.5 4.2 7 4.2M6.5 14.2c3.5 0 3.5-4.2 7-4.2" />
    </svg>
  );
}

export function ServerIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <rect x="3" y="3.5" width="14" height="5.2" rx="1.4" />
      <rect x="3" y="11.3" width="14" height="5.2" rx="1.4" />
      <circle cx="6" cy="6.1" r="0.8" fill="currentColor" stroke="none" />
      <circle cx="6" cy="13.9" r="0.8" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function QuotaIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <rect x="2.8" y="4.5" width="14.4" height="11" rx="2" />
      <path d="M2.8 8.2h14.4M6.5 12.2h3" />
    </svg>
  );
}

export function WebhookIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <circle cx="10" cy="5.2" r="2.1" />
      <circle cx="5.2" cy="13.8" r="2.1" />
      <circle cx="14.8" cy="13.8" r="2.1" />
      <path d="M8.9 7 6.3 11.9M11.1 7l2.6 4.9M7.3 13.8h5.4" />
    </svg>
  );
}

export function TerminalIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <rect x="2.6" y="3.6" width="14.8" height="12.8" rx="2" />
      <path d="m6.2 8 2.4 2.2-2.4 2.2M10.4 12.4h3.4" />
    </svg>
  );
}

export function BookIcon({ size = 17, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M3.2 4.5c1.8-.6 4-.6 6.8.6 2.8-1.2 5-1.2 6.8-.6v10.8c-1.8-.6-4-.6-6.8.6-2.8-1.2-5-1.2-6.8-.6V4.5Z" />
      <path d="M10 5.1v10.8" />
    </svg>
  );
}

export function SparkleIcon({ size = 16, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M10 2.8 11.6 8l5.2 1.6-5.2 1.6L10 16.4 8.4 11.2 3.2 9.6 8.4 8 10 2.8Z" />
      <path d="M15.8 3.2v2.4M14.6 4.4h2.4" />
    </svg>
  );
}

export function PlusIcon({ size = 15, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M10 4.2v11.6M4.2 10h11.6" />
    </svg>
  );
}

export function DownloadIcon({ size = 15, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M10 3.5v9.2M6.6 9.6 10 13l3.4-3.4M4 15.8h12" />
    </svg>
  );
}

export function RefreshIcon({ size = 15, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M16.2 6.2A6.5 6.5 0 0 0 4.3 7.6M3.8 3.8v4h4M3.8 13.8a6.5 6.5 0 0 0 11.9-1.4M16.2 16.2v-4h-4" />
    </svg>
  );
}

export function SearchIcon({ size = 15, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <circle cx="9" cy="9" r="5.3" />
      <path d="m13 13 3.6 3.6" />
    </svg>
  );
}

export function CopyIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <rect x="6.8" y="6.8" width="9.4" height="9.4" rx="1.6" />
      <path d="M4.6 13.2H4a1.4 1.4 0 0 1-1.4-1.4V4.2A1.4 1.4 0 0 1 4 2.8h7.6A1.4 1.4 0 0 1 13 4.2v.6" />
    </svg>
  );
}

export function CheckIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="m4.2 10.4 3.6 3.6 8-8.2" />
    </svg>
  );
}

export function CloseIcon({ size = 16, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="m5.2 5.2 9.6 9.6M14.8 5.2l-9.6 9.6" />
    </svg>
  );
}

export function ChevronDownIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="m5.5 7.8 4.5 4.5 4.5-4.5" />
    </svg>
  );
}

export function ChevronRightIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="m7.8 5.5 4.5 4.5-4.5 4.5" />
    </svg>
  );
}

export function LockIcon({ size = 13, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <rect x="4.5" y="9" width="11" height="7.8" rx="1.6" />
      <path d="M6.8 9V6.6a3.2 3.2 0 0 1 6.4 0V9" />
    </svg>
  );
}

export function PlayIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="m6.5 4.6 8.6 5.4-8.6 5.4V4.6Z" />
    </svg>
  );
}

export function EditIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M12.9 4.1a1.6 1.6 0 0 1 2.3 2.3L7.1 14.5l-3.2.8.8-3.2 8.2-8Z" />
    </svg>
  );
}

export function TrashIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M4.2 5.8h11.6M7.6 5.8V4.2a1 1 0 0 1 1-1h2.8a1 1 0 0 1 1 1v1.6M6 5.8l.7 10a1.4 1.4 0 0 0 1.4 1.3h3.8a1.4 1.4 0 0 0 1.4-1.3l.7-10" />
    </svg>
  );
}

export function EyeIcon({ size = 14, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <path d="M2.4 10S5.2 4.8 10 4.8 17.6 10 17.6 10 14.8 15.2 10 15.2 2.4 10 2.4 10Z" />
      <circle cx="10" cy="10" r="2.2" />
    </svg>
  );
}

export function AlertIcon({ size = 15, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <circle cx="10" cy="10" r="7.2" />
      <path d="M10 6.5v4.1M10 13.5h.01" />
    </svg>
  );
}

export function SidebarToggleIcon({ size = 16, ...props }: SvgIconProps) {
  return (
    <svg {...baseProps(size, props)}>
      <rect x="2.8" y="3.8" width="14.4" height="12.4" rx="2" />
      <path d="M7.6 3.8v12.4" />
    </svg>
  );
}

export function resolveProviderFamily(
  typeOrName: string,
): 'anthropic' | 'openai' | 'gemini' | 'ollama' | 'other' {
  const norm = (typeOrName || '').toLowerCase();
  if (norm === 'anthropic' || norm.includes('anthropic') || norm.includes('claude')) {
    return 'anthropic';
  }
  if (norm === 'openai' || norm.includes('openai') || norm.includes('gpt')) {
    return 'openai';
  }
  if (
    norm === 'gemini' ||
    norm.includes('gemini') ||
    norm.includes('vertex') ||
    norm.includes('google')
  ) {
    return 'gemini';
  }
  if (norm === 'ollama' || norm.includes('ollama')) {
    return 'ollama';
  }
  return 'other';
}

export function ProviderGlyph({ type }: { type: string }) {
  const family = resolveProviderFamily(type);
  if (family === 'anthropic') {
    return (
      <span className="ap-prov-dot" data-provider="anthropic" aria-hidden="true">
        A
      </span>
    );
  }
  if (family === 'openai') {
    return (
      <span className="ap-prov-dot" data-provider="openai" aria-hidden="true">
        O
      </span>
    );
  }
  if (family === 'gemini') {
    return (
      <span className="ap-prov-dot" data-provider="gemini" aria-hidden="true">
        G
      </span>
    );
  }
  if (family === 'ollama') {
    return (
      <span className="ap-prov-dot" data-provider="ollama" aria-hidden="true">
        L
      </span>
    );
  }
  return (
    <span className="ap-prov-dot" data-provider="other" aria-hidden="true">
      •
    </span>
  );
}
