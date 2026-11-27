import { describe, expect, it } from 'vitest';
import {
  getSubmenuFacingEdge,
  isInsideSubmenuSafeTriangle,
  isPointInTriangle,
  MENU_CLOSE_DELAY_MS,
  MENU_OPEN_DELAY_MS,
  type Rect,
} from './safeTriangle';

describe('safeTriangle geometry', () => {
  const submenuRect: Rect = {
    left: 260,
    top: 80,
    right: 460,
    bottom: 280,
  };

  it('exposes exact DESIGN.md menu delay constants', () => {
    expect(MENU_OPEN_DELAY_MS).toBe(120);
    expect(MENU_CLOSE_DELAY_MS).toBe(180);
  });

  it('detects points inside and outside a triangle', () => {
    const a = { x: 100, y: 120 };
    const b = { x: 260, y: 72 };
    const c = { x: 260, y: 288 };

    expect(isPointInTriangle({ x: 180, y: 160 }, a, b, c)).toBe(true);
    expect(isPointInTriangle({ x: 100, y: 220 }, a, b, c)).toBe(false);
    expect(isPointInTriangle({ x: 300, y: 160 }, a, b, c)).toBe(false);
  });

  it('selects left edge when submenu opens to the right of parent menu', () => {
    const edge = getSubmenuFacingEdge({ x: 120, y: 100 }, submenuRect, 8);
    expect(edge.direction).toBe('right');
    expect(edge.topEdge).toEqual({ x: 260, y: 72 });
    expect(edge.bottomEdge).toEqual({ x: 260, y: 288 });
  });

  it('protects diagonal movement from parent item A toward right-hand submenu B', () => {
    const prev = { x: 120, y: 104 };
    const diagonalCursorOverSibling = { x: 196, y: 172 };

    expect(
      isInsideSubmenuSafeTriangle(diagonalCursorOverSibling, prev, submenuRect),
    ).toBe(true);
  });

  it('does not block purely vertical movement to sibling menu item C', () => {
    const prev = { x: 120, y: 104 };
    const straightDownSibling = { x: 120, y: 164 };

    expect(
      isInsideSubmenuSafeTriangle(straightDownSibling, prev, submenuRect),
    ).toBe(false);
  });

  it('does not block movement away from submenu B', () => {
    const prev = { x: 210, y: 150 };
    const retreatingCursor = { x: 150, y: 150 };

    expect(
      isInsideSubmenuSafeTriangle(retreatingCursor, prev, submenuRect),
    ).toBe(false);
  });

  it('supports left-opening submenus near the viewport right edge', () => {
    const leftSubmenu: Rect = { left: 40, top: 80, right: 220, bottom: 260 };
    const prev = { x: 320, y: 110 };
    const movingLeftIntoCone = { x: 260, y: 165 };

    expect(
      isInsideSubmenuSafeTriangle(movingLeftIntoCone, prev, leftSubmenu),
    ).toBe(true);
  });
});
