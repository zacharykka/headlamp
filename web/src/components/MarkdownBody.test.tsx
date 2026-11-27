import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { MarkdownBody } from './MarkdownBody';

describe('MarkdownBody XSS-safe renderer', () => {
  afterEach(() => {
    cleanup();
  });

  it('renders headings, inline formatting, lists, blockquotes, and fenced code blocks with copy button', () => {
    const md = [
      '## Gateway Status',
      '',
      'Traffic is **healthy** with *low* latency and ***zero*** drops via `tailscaled`.',
      '',
      '- Primary route: `anthropic/claude-sonnet-4-6`',
      '- Fallback route: `openai/gpt-4.1`',
      '',
      '1. Verify grant',
      '2. Send request',
      '',
      '> Audited over Tailnet mesh',
      '',
      '```bash',
      'curl -sS http://headlamp/v1/models',
      '```',
    ].join('\n');

    render(<MarkdownBody content={md} />);

    expect(screen.getByRole('heading', { level: 2, name: 'Gateway Status' })).toBeTruthy();
    expect(screen.getByText('healthy').tagName).toBe('STRONG');
    expect(screen.getByText('low').tagName).toBe('EM');
    expect(screen.getByText('tailscaled').tagName).toBe('CODE');
    expect(screen.getByText('Audited over Tailnet mesh')).toBeTruthy();

    expect(screen.getByText('bash')).toBeTruthy();
    expect(screen.getByText('curl -sS http://headlamp/v1/models')).toBeTruthy();
    expect(screen.getByRole('button', { name: /Copy/i })).toBeTruthy();
  });

  it('supports special language tags (c#, c++), info attributes, and 4-backtick fences wrapping 3-backtick blocks (P2-7)', () => {
    const md = [
      '```c#',
      'Console.WriteLine("hello");',
      '```',
      '',
      '```ts title="src/gateway.ts"',
      'export const ready = true;',
      '```',
      '',
      '````markdown',
      'Nested example:',
      '```go',
      'fmt.Println("inside")',
      '```',
      'Still inside outer block',
      '````',
      '',
      'Outside paragraph.',
    ].join('\n');

    render(<MarkdownBody content={md} />);

    expect(screen.getByText('c#')).toBeTruthy();
    expect(screen.getByText('Console.WriteLine("hello");')).toBeTruthy();
    expect(screen.getByText('ts')).toBeTruthy();
    expect(screen.getByText('export const ready = true;')).toBeTruthy();
    expect(screen.getByText('markdown')).toBeTruthy();
    expect(screen.getByText(/Still inside outer block/)).toBeTruthy();
    expect(screen.getByText('Outside paragraph.').tagName).toBe('P');
  });

  it('allows http/https links and neutralizes javascript/data URLs', () => {
    const md = [
      'Read [Tailscale Docs](https://tailscale.com/kb) or [Evil JS](javascript:alert(1)) or [Evil Data](data:text/html,<script>alert(1)</script>).',
    ].join('\n');

    const { container } = render(<MarkdownBody content={md} />);

    const links = container.querySelectorAll('a');
    expect(links.length).toBe(1);
    expect(links[0].getAttribute('href')).toBe('https://tailscale.com/kb');
    expect(links[0].getAttribute('rel')).toBe('noopener noreferrer');
    expect(container.textContent).toContain('Evil JS');
    expect(container.textContent).toContain('Evil Data');
  });

  it('never injects raw HTML elements (zero dangerouslySetInnerHTML)', () => {
    const malicious = [
      '# Heading <script>window.__xss = 1</script>',
      '',
      'Hello <img src="x" onerror="alert(1)" /> and <iframe src="https://evil.example"></iframe>',
      '',
      '- Item with <svg onload="alert(2)"></svg>',
    ].join('\n');

    const { container } = render(<MarkdownBody content={malicious} />);

    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('iframe')).toBeNull();
    expect(container.querySelector('svg')).toBeNull();

    expect(container.textContent).toContain('<script>window.__xss = 1</script>');
    expect(container.textContent).toContain('<img src="x" onerror="alert(1)" />');
  });
});
