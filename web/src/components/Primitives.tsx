import { useEffect, useState, type ReactNode } from 'react';
import { Check, CloseCircle, Copy } from 'reicon-react';
import { Icon } from './Icon';

interface ModalProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  maxWidth?: number;
}

export function Modal({ open, title, onClose, children, maxWidth = 600 }: ModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="hl-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="hl-modal" style={{ maxWidth }}>
        <div className="hl-section-bar">
          <h2>{title}</h2>
          <button
            type="button"
            className="hl-btn hl-btn-ghost"
            onClick={onClose}
            aria-label="Close"
          >
            <Icon icon={CloseCircle} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

interface DrawerProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}

export function Drawer({ open, title, onClose, children }: DrawerProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="hl-drawer-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="hl-drawer">
        <div className="hl-section-bar">
          <h2>{title}</h2>
          <button
            type="button"
            className="hl-btn hl-btn-ghost"
            onClick={onClose}
            aria-label="Close"
          >
            <Icon icon={CloseCircle} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

interface ToggleProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  disabled?: boolean;
}

export function Toggle({ checked, onChange, label, disabled = false }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className="hl-toggle"
      onClick={() => onChange(!checked)}
    >
      <span className="hl-toggle-thumb" />
    </button>
  );
}

interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

interface SegmentedControlProps<T extends string> {
  value: T;
  options: SegmentedOption<T>[];
  onChange: (next: T) => void;
  ariaLabel: string;
}

export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
}: SegmentedControlProps<T>) {
  return (
    <div className="hl-segmented" role="tablist" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={value === option.value}
          data-active={value === option.value}
          className="hl-segment-btn"
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

interface ProgressBarProps {
  spent: number;
  limit: number | null | undefined;
  softAlertPct?: number;
}

export function ProgressBar({ spent, limit }: ProgressBarProps) {
  if (limit === null || limit === undefined || limit < 0) {
    return <span className="hl-secondary">—</span>;
  }
  const ratio =
    limit === 0 ? 100 : Math.min(100, Math.max(0, (spent / limit) * 100));
  const exceeded = limit === 0 || spent >= limit;
  return (
    <div className="hl-progress-track">
      <div
        className="hl-progress-fill"
        data-exceeded={exceeded}
        style={{ width: `${ratio}%` }}
      />
    </div>
  );
}

interface CodeBlockProps {
  code: string;
}

export function CodeBlock({ code }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard API may be unavailable in restricted contexts.
    }
  };

  return (
    <div className="hl-code-block hl-surface-hover-zone">
      <div
        className="hl-row-actions"
        data-visible={copied}
        style={{ position: 'absolute', top: 16, right: 16 }}
      >
        <button type="button" className="hl-btn hl-btn-ghost" onClick={handleCopy}>
          <Icon icon={copied ? Check : Copy} />
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre>{code}</pre>
    </div>
  );
}
