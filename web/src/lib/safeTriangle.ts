export interface Point {
  x: number;
  y: number;
}

export interface Rect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export const MENU_OPEN_DELAY_MS = 120;
export const MENU_CLOSE_DELAY_MS = 180;
export const SAFE_TRIANGLE_SETTLE_MS = 240;

function crossProductSign(p1: Point, p2: Point, p3: Point): number {
  return (p1.x - p3.x) * (p2.y - p3.y) - (p2.x - p3.x) * (p1.y - p3.y);
}

/**
 * Returns true if `point` lies inside or on the boundary of triangle `(a, b, c)`.
 */
export function isPointInTriangle(point: Point, a: Point, b: Point, c: Point): boolean {
  const d1 = crossProductSign(point, a, b);
  const d2 = crossProductSign(point, b, c);
  const d3 = crossProductSign(point, c, a);

  const hasNeg = d1 < 0 || d2 < 0 || d3 < 0;
  const hasPos = d1 > 0 || d2 > 0 || d3 > 0;

  return !(hasNeg && hasPos);
}

/**
 * Computes the two target edge endpoints `(topEdge, bottomEdge)` of submenu B
 * facing the origin cursor position `anchor`, with an optional tolerance pad (default 8px).
 */
export function getSubmenuFacingEdge(
  anchor: Point,
  submenuRect: Rect,
  verticalPad = 8,
): { topEdge: Point; bottomEdge: Point; direction: 'right' | 'left' } {
  const submenuCenterX = (submenuRect.left + submenuRect.right) / 2;
  const opensRight = submenuCenterX >= anchor.x;
  const edgeX = opensRight ? submenuRect.left : submenuRect.right;

  return {
    topEdge: { x: edgeX, y: submenuRect.top - verticalPad },
    bottomEdge: { x: edgeX, y: submenuRect.bottom + verticalPad },
    direction: opensRight ? 'right' : 'left',
  };
}

/**
 * Determines whether the cursor moving from `prevCursor` to `currentCursor`
 * is protected by the geometric safe-triangle toward `submenuRect`.
 *
 * Per DESIGN.md §4:
 * While cursor moves from parent item A toward open submenu B, form a triangle
 * from `(prevCursor, submenuTopEdge, submenuBottomEdge)` and keep submenu B open
 * while `currentCursor` stays inside that triangle and advances toward submenu B.
 */
export function isInsideSubmenuSafeTriangle(
  currentCursor: Point,
  prevCursor: Point | null,
  submenuRect: Rect | null,
  verticalPad = 8,
): boolean {
  if (!prevCursor || !submenuRect) {
    return false;
  }

  const { topEdge, bottomEdge, direction } = getSubmenuFacingEdge(
    prevCursor,
    submenuRect,
    verticalPad,
  );

  const movingTowardSubmenu =
    direction === 'right'
      ? currentCursor.x > prevCursor.x
      : currentCursor.x < prevCursor.x;

  if (!movingTowardSubmenu) {
    return false;
  }

  return isPointInTriangle(currentCursor, prevCursor, topEdge, bottomEdge);
}
