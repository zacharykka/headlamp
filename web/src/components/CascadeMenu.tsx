import { useEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronRight } from 'reicon-react';
import { Icon } from './Icon';
import {
  isInsideSubmenuSafeTriangle,
  MENU_CLOSE_DELAY_MS,
  MENU_OPEN_DELAY_MS,
  SAFE_TRIANGLE_SETTLE_MS,
  type Point,
  type Rect,
} from '../lib/safeTriangle';

export interface CascadeMenuLeaf {
  id: string;
  label: string;
  selected?: boolean;
  onSelect: () => void;
}

export interface CascadeMenuItem {
  id: string;
  label: string;
  selected?: boolean;
  onSelect?: () => void;
  children?: CascadeMenuLeaf[];
}

interface CascadeMenuProps {
  label: string;
  current?: boolean;
  onPrimaryClick?: () => void;
  items: CascadeMenuItem[];
}

export function CascadeMenu({
  label,
  current = false,
  onPrimaryClick,
  items,
}: CascadeMenuProps) {
  const [open, setOpen] = useState(false);
  const [activeParentId, setActiveParentId] = useState<string | null>(null);

  const rootRef = useRef<HTMLDivElement | null>(null);
  const submenuRef = useRef<HTMLDivElement | null>(null);

  const openTimerRef = useRef<number | null>(null);
  const closeTimerRef = useRef<number | null>(null);
  const submenuTimerRef = useRef<number | null>(null);
  const cursorHistoryRef = useRef<Point[]>([]);

  const clearTimer = (ref: { current: number | null }) => {
    if (ref.current !== null) {
      window.clearTimeout(ref.current);
      ref.current = null;
    }
  };

  const clearAllTimers = () => {
    clearTimer(openTimerRef);
    clearTimer(closeTimerRef);
    clearTimer(submenuTimerRef);
  };

  useEffect(() => clearAllTimers, []);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        clearAllTimers();
        setOpen(false);
        setActiveParentId(null);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        clearAllTimers();
        setOpen(false);
        setActiveParentId(null);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  const recordCursor = (point: Point) => {
    const hist = cursorHistoryRef.current;
    hist.push(point);
    if (hist.length > 4) {
      hist.shift();
    }
  };

  const getSubmenuRect = (): Rect | null => {
    const el = submenuRef.current;
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
  };

  const handleRootEnter = () => {
    clearTimer(closeTimerRef);
    if (!open && openTimerRef.current === null) {
      openTimerRef.current = window.setTimeout(() => {
        openTimerRef.current = null;
        setOpen(true);
      }, MENU_OPEN_DELAY_MS);
    }
  };

  const handleRootLeave = () => {
    clearTimer(openTimerRef);
    clearTimer(submenuTimerRef);
    closeTimerRef.current = window.setTimeout(() => {
      closeTimerRef.current = null;
      setOpen(false);
      setActiveParentId(null);
      cursorHistoryRef.current = [];
    }, MENU_CLOSE_DELAY_MS);
  };

  const scheduleSubmenuSwitch = (targetId: string | null, delayMs: number) => {
    clearTimer(submenuTimerRef);
    submenuTimerRef.current = window.setTimeout(() => {
      submenuTimerRef.current = null;
      setActiveParentId(targetId);
    }, delayMs);
  };

  const handleItemPointerMove = (item: CascadeMenuItem, clientX: number, clientY: number) => {
    const currentPos: Point = { x: clientX, y: clientY };
    const anchorPos =
      cursorHistoryRef.current.length > 0 ? cursorHistoryRef.current[0] : null;
    recordCursor(currentPos);

    const nextId = item.children && item.children.length > 0 ? item.id : null;
    if (activeParentId === nextId) {
      clearTimer(submenuTimerRef);
      return;
    }

    if (activeParentId !== null) {
      const rect = getSubmenuRect();
      if (isInsideSubmenuSafeTriangle(currentPos, anchorPos, rect)) {
        // Inside the safe triangle moving toward open submenu B:
        // keep submenu B open, only switching if the cursor stops moving on this sibling.
        scheduleSubmenuSwitch(nextId, SAFE_TRIANGLE_SETTLE_MS);
        return;
      }
    }

    scheduleSubmenuSwitch(nextId, MENU_OPEN_DELAY_MS);
  };

  const closeImmediately = () => {
    clearAllTimers();
    setOpen(false);
    setActiveParentId(null);
  };

  return (
    <div
      ref={rootRef}
      className="hl-cascade-root"
      onMouseEnter={handleRootEnter}
      onMouseLeave={handleRootLeave}
    >
      <button
        type="button"
        className="hl-cascade-trigger"
        data-open={open}
        data-current={current}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => {
          if (onPrimaryClick) {
            onPrimaryClick();
            closeImmediately();
          } else {
            clearAllTimers();
            setOpen((prev) => !prev);
          }
        }}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown') {
            event.preventDefault();
            clearAllTimers();
            setOpen(true);
          }
        }}
      >
        <span>{label}</span>
        <Icon icon={ChevronDown} />
      </button>

      {open && (
        <div className="hl-cascade-panel" role="menu" aria-label={label}>
          {items.map((item) => {
            const hasSubmenu = Boolean(item.children && item.children.length > 0);
            const isSubmenuOpen = hasSubmenu && activeParentId === item.id;

            return (
              <div
                key={item.id}
                className="hl-cascade-item-wrap"
                onMouseEnter={(e) => handleItemPointerMove(item, e.clientX, e.clientY)}
                onMouseMove={(e) => handleItemPointerMove(item, e.clientX, e.clientY)}
              >
                <button
                  type="button"
                  role="menuitem"
                  aria-haspopup={hasSubmenu ? 'menu' : undefined}
                  aria-expanded={hasSubmenu ? isSubmenuOpen : undefined}
                  data-highlighted={isSubmenuOpen}
                  data-selected={Boolean(item.selected)}
                  className="hl-cascade-item"
                  onFocus={() => {
                    if (hasSubmenu) {
                      setActiveParentId(item.id);
                    }
                  }}
                  onClick={() => {
                    if (item.onSelect) {
                      item.onSelect();
                      closeImmediately();
                    } else if (hasSubmenu) {
                      setActiveParentId(item.id);
                    }
                  }}
                >
                  <span>{item.label}</span>
                  {hasSubmenu && <Icon icon={ChevronRight} />}
                </button>

                {isSubmenuOpen && item.children && (
                  <div
                    ref={submenuRef}
                    className="hl-cascade-submenu"
                    role="menu"
                    aria-label={item.label}
                    onMouseEnter={() => clearTimer(submenuTimerRef)}
                  >
                    {item.children.map((leaf) => (
                      <button
                        key={leaf.id}
                        type="button"
                        role="menuitem"
                        data-selected={Boolean(leaf.selected)}
                        className="hl-cascade-item"
                        onClick={() => {
                          leaf.onSelect();
                          closeImmediately();
                        }}
                      >
                        <span>{leaf.label}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
