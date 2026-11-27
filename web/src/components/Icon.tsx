import type { ComponentType } from 'react';

export interface ReiconProps {
  size?: number | string;
  color?: string;
  weight?: 'Outline' | 'Filled';
  strokeWidth?: number | string;
  className?: string;
}

interface IconProps {
  icon: ComponentType<ReiconProps>;
  color?: string;
}

/**
 * Enforces DESIGN.md §3 icon geometry:
 * 18px icon body, 1.5px stroke width, centered inside a 24px × 24px transparent box.
 */
export function Icon({ icon: IconGlyph, color = 'currentColor' }: IconProps) {
  return (
    <span className="hl-icon" aria-hidden="true">
      <IconGlyph size={18} strokeWidth={1.5} weight="Outline" color={color} />
    </span>
  );
}
