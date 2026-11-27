import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CascadeMenu } from './CascadeMenu';
import {
  MENU_CLOSE_DELAY_MS,
  MENU_OPEN_DELAY_MS,
  SAFE_TRIANGLE_SETTLE_MS,
} from '../lib/safeTriangle';

describe('CascadeMenu interaction timing and safe triangle', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('enforces open delay, safe-triangle submenu retention, and close delay', () => {
    const onSelectOpenAI = vi.fn();
    const onSelectRoutes = vi.fn();

    render(
      <CascadeMenu
        label="Routing"
        items={[
          {
            id: 'providers',
            label: 'Providers',
            children: [
              { id: 'openai', label: 'OpenAI', onSelect: onSelectOpenAI },
            ],
          },
          {
            id: 'routes',
            label: 'Model Routes',
            children: [
              { id: 'all-routes', label: 'All Routes', onSelect: onSelectRoutes },
            ],
          },
        ]}
      />,
    );

    const trigger = screen.getByRole('button', { name: /Routing/i });
    const root = trigger.parentElement!;

    // 1. Hovering trigger respects 120ms open delay
    fireEvent.mouseEnter(root);
    act(() => {
      vi.advanceTimersByTime(MENU_OPEN_DELAY_MS - 20);
    });
    expect(screen.queryByRole('menu', { name: 'Routing' })).toBeNull();

    act(() => {
      vi.advanceTimersByTime(25);
    });
    expect(screen.getByRole('menu', { name: 'Routing' })).toBeTruthy();

    // 2. Hovering parent item A ("Providers") opens submenu B after 120ms
    const providersItem = screen.getByRole('menuitem', { name: 'Providers' });
    fireEvent.mouseEnter(providersItem.parentElement!, { clientX: 100, clientY: 90 });
    act(() => {
      vi.advanceTimersByTime(MENU_OPEN_DELAY_MS);
    });

    const submenuB = screen.getByRole('menu', { name: 'Providers' });
    vi.spyOn(submenuB, 'getBoundingClientRect').mockReturnValue({
      left: 260,
      top: 72,
      right: 460,
      bottom: 260,
      width: 200,
      height: 188,
      x: 260,
      y: 72,
      toJSON: () => ({}),
    });

    // 3. Diagonal cursor sweep across sibling "Model Routes" toward submenu B (x: 100->190, y: 90->150)
    const routesItem = screen.getByRole('menuitem', { name: 'Model Routes' });
    fireEvent.mouseMove(routesItem.parentElement!, { clientX: 190, clientY: 150 });

    // Even after normal 120ms open delay, safe triangle keeps "Providers" submenu B open!
    act(() => {
      vi.advanceTimersByTime(MENU_OPEN_DELAY_MS + 40);
    });
    expect(screen.getByRole('menu', { name: 'Providers' })).toBeTruthy();
    expect(screen.queryByRole('menu', { name: 'Model Routes' })).toBeNull();

    // If user instead pauses stationary on "Model Routes" past settle threshold, it switches cleanly
    act(() => {
      vi.advanceTimersByTime(SAFE_TRIANGLE_SETTLE_MS);
    });
    expect(screen.getByRole('menu', { name: 'Model Routes' })).toBeTruthy();

    // 4. Leaving root respects 180ms close delay
    fireEvent.mouseLeave(root);
    act(() => {
      vi.advanceTimersByTime(MENU_CLOSE_DELAY_MS - 30);
    });
    expect(screen.getByRole('menu', { name: 'Routing' })).toBeTruthy();

    act(() => {
      vi.advanceTimersByTime(40);
    });
    expect(screen.queryByRole('menu', { name: 'Routing' })).toBeNull();
  });
});
