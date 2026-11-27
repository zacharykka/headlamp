import { useEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import {
  AlertIcon,
  CheckIcon,
  CloseIcon,
  CopyIcon,
  LockIcon,
  ProviderGlyph,
  TrashIcon,
} from './ApertureIcons';

let activeOverlayCount = 0;
let savedBodyOverflow = '';

function acquireBodyScrollLock(): () => void {
  if (typeof document === 'undefined') return () => {};
  if (activeOverlayCount === 0) {
    savedBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
  }
  activeOverlayCount += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeOverlayCount = Math.max(0, activeOverlayCount - 1);
    if (activeOverlayCount === 0 && typeof document !== 'undefined') {
      document.body.style.overflow = savedBodyOverflow;
    }
  };
}

interface ModalProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  maxWidth?: number;
  error?: string | null;
}

export function Modal({
  open,
  title,
  onClose,
  children,
  maxWidth = 580,
  error,
}: ModalProps) {
  useEffect(() => {
    if (!open) return;
    const releaseScroll = acquireBodyScrollLock();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      releaseScroll();
    };
  }, [open, onClose]);

  if (!open) return null;

  const node = (
    <div
      className="ap-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="ap-modal" style={{ maxWidth }}>
        <div className="ap-modal-head">
          <h2 className="ap-modal-title">{title}</h2>
          <button
            type="button"
            className="ap-btn ap-btn-ghost"
            onClick={onClose}
            aria-label="Close"
          >
            <CloseIcon />
          </button>
        </div>
        <div className="ap-modal-body">
          {error && (
            <div className="ap-alert ap-alert--danger" role="alert">
              <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
              <span>{error}</span>
            </div>
          )}
          {children}
        </div>
      </div>
    </div>
  );

  return typeof document !== 'undefined' ? createPortal(node, document.body) : node;
}

interface DrawerProps {
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
}

export function Drawer({ open, title, subtitle, onClose, children }: DrawerProps) {
  useEffect(() => {
    if (!open) return;
    const releaseScroll = acquireBodyScrollLock();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      releaseScroll();
    };
  }, [open, onClose]);

  if (!open) return null;

  const node = (
    <div
      className="ap-drawer-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="ap-drawer">
        <div className="ap-modal-head">
          <div style={{ minWidth: 0 }}>
            <h2 className="ap-modal-title ap-truncate">{title}</h2>
            {subtitle && (
              <p className="ap-card-subtitle ap-mono ap-truncate">{subtitle}</p>
            )}
          </div>
          <button
            type="button"
            className="ap-btn ap-btn-ghost"
            onClick={onClose}
            aria-label="Close"
          >
            <CloseIcon />
          </button>
        </div>
        <div className="ap-drawer-body">{children}</div>
      </div>
    </div>
  );

  return typeof document !== 'undefined' ? createPortal(node, document.body) : node;
}

interface ToggleProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  disabled?: boolean;
  title?: string;
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
  title,
}: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      title={title}
      className="ap-toggle"
      onClick={() => {
        if (!disabled) onChange(!checked);
      }}
    >
      <span className="ap-toggle-thumb" />
    </button>
  );
}

interface ConfirmDeleteButtonProps {
  itemName: string;
  onConfirm: () => void | Promise<void>;
  disabled?: boolean;
  title?: string;
}

/**
 * Lightweight two-step inline confirmation button for destructive row deletions.
 * First click arms "Confirm?" (auto-resets after 4s or Escape/blur); second click executes.
 */
export function ConfirmDeleteButton({
  itemName,
  onConfirm,
  disabled = false,
  title,
}: ConfirmDeleteButtonProps) {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const timerRef = useRef<number | null>(null);

  const clearArmTimer = () => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  useEffect(() => clearArmTimer, []);

  useEffect(() => {
    if (disabled && armed) {
      clearArmTimer();
      setArmed(false);
    }
  }, [disabled, armed]);

  const handleClick = async () => {
    if (disabled || busy) return;
    if (!armed) {
      setArmed(true);
      clearArmTimer();
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null;
        setArmed(false);
      }, 4000);
      return;
    }

    clearArmTimer();
    setArmed(false);
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      type="button"
      className={
        armed
          ? 'ap-btn ap-btn-danger ap-btn-sm'
          : 'ap-btn ap-btn-ghost ap-btn-danger ap-btn-sm ap-btn-icon-compact'
      }
      disabled={disabled || busy}
      aria-label={armed ? `Confirm delete ${itemName}` : `Delete ${itemName}`}
      title={
        disabled
          ? title
          : armed
            ? `Click again to permanently delete ${itemName} (Esc to cancel)`
            : title || `Delete ${itemName}`
      }
      onClick={() => void handleClick()}
      onBlur={() => {
        if (armed) {
          clearArmTimer();
          setArmed(false);
        }
      }}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && armed) {
          e.stopPropagation();
          clearArmTimer();
          setArmed(false);
        }
      }}
    >
      <TrashIcon />
      {armed ? (
        <span>Confirm?</span>
      ) : (
        <span className="ap-action-label">{busy ? 'Deleting' : 'Delete'}</span>
      )}
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
    <div className="ap-segmented" role="tablist" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={value === option.value}
          data-active={value === option.value}
          className="ap-segment-btn"
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

export function ProgressBar({ spent, limit, softAlertPct = 80 }: ProgressBarProps) {
  if (limit === null || limit === undefined || limit < 0) {
    return null;
  }
  const ratio =
    limit === 0 ? 100 : Math.min(100, Math.max(0, (spent / limit) * 100));
  const tone =
    limit === 0 || spent >= limit
      ? 'danger'
      : ratio >= softAlertPct
        ? 'warn'
        : 'normal';

  return (
    <div className="ap-progress-track" aria-hidden="true">
      <div
        className="ap-progress-fill"
        data-tone={tone}
        style={{ width: `${ratio}%` }}
      />
    </div>
  );
}

interface CodeBlockProps {
  code: string;
  label?: string;
  highlightRedactions?: boolean;
}

export function CodeBlock({
  code,
  label,
  highlightRedactions = false,
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        copyTimerRef.current = null;
        setCopied(false);
      }, 1600);
    } catch {
      // Clipboard API may be unavailable in restricted contexts.
    }
  };

  return (
    <div className="ap-code-wrap">
      <div className="ap-code-head">
        <span>{label || 'Snippet'}</span>
        <button
          type="button"
          className="ap-btn ap-btn-ghost ap-btn-sm"
          onClick={handleCopy}
        >
          {copied ? <CheckIcon /> : <CopyIcon />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre
        className={`ap-code-pre ${
          highlightRedactions ? 'ap-code-pre--wrap' : ''
        }`}
      >
        {highlightRedactions ? renderRedactedParts(code) : code}
      </pre>
    </div>
  );
}

export function renderRedactedParts(text: string): ReactNode {
  if (!text) return '';
  const parts = text.split(/(\[REDACTED(?::[^\]]+)?\])/g);
  if (parts.length === 1) return text;
  return parts.map((part, idx) => {
    if (part.startsWith('[REDACTED') && part.endsWith(']')) {
      return (
        <span key={idx} className="ap-redacted-token">
          {part}
        </span>
      );
    }
    return part;
  });
}

export function SourceBadge({
  source,
  builtin = false,
}: {
  source?: string;
  builtin?: boolean;
}) {
  if (source === 'config') {
    return (
      <span
        className="ap-badge ap-badge--amber"
        title="Managed by headlamp.yaml (read-only via API; edit YAML config to modify)"
      >
        <LockIcon size={11} />
        <span>Managed by YAML</span>
      </span>
    );
  }
  if (builtin || source === 'builtin') {
    return (
      <span
        className="ap-badge ap-badge--purple"
        title="Built-in Headlamp detector preset (action and enabled state can be customized)"
      >
        Built-in
      </span>
    );
  }
  return (
    <span className="ap-badge" title="Created dynamically in SQLite store">
      Custom
    </span>
  );
}

const PROVIDER_LABELS: Record<string, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  gemini: 'Gemini',
  ollama: 'Ollama',
};

export function ProviderTypeBadge({ type }: { type: string }) {
  const norm = type.toLowerCase();
  const label = PROVIDER_LABELS[norm] || type;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        fontWeight: 500,
      }}
    >
      <ProviderGlyph type={type} />
      <span>{label}</span>
    </span>
  );
}

export const YAML_LOCK_TOOLTIP =
  'Managed by headlamp.yaml (source=config) — edit headlamp.yaml and restart to modify';
