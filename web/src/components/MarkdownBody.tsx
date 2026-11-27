import type { ReactNode } from 'react';
import { CodeBlock } from './Primitives';

interface MarkdownBodyProps {
  content: string;
}

type BlockNode =
  | { kind: 'code'; lang: string; code: string }
  | { kind: 'heading'; level: 1 | 2 | 3 | 4; text: string }
  | { kind: 'ul'; items: string[] }
  | { kind: 'ol'; items: string[] }
  | { kind: 'blockquote'; lines: string[] }
  | { kind: 'hr' }
  | { kind: 'paragraph'; text: string };

/**
 * Lightweight, 100% XSS-safe Markdown renderer built on React elements.
 * Never uses dangerouslySetInnerHTML; raw HTML tags render strictly as escaped text.
 */
export function MarkdownBody({ content }: MarkdownBodyProps) {
  if (!content) return null;
  const blocks = parseBlocks(content);

  return (
    <div className="ap-md">
      {blocks.map((block, idx) => {
        switch (block.kind) {
          case 'code':
            return (
              <CodeBlock
                key={idx}
                label={block.lang || 'Code'}
                code={block.code}
              />
            );
          case 'heading': {
            const Tag =
              block.level === 1
                ? 'h1'
                : block.level === 2
                  ? 'h2'
                  : block.level === 3
                    ? 'h3'
                    : 'h4';
            return (
              <Tag key={idx} className={`ap-md-h ap-md-h${block.level}`}>
                {renderInline(block.text)}
              </Tag>
            );
          }
          case 'ul':
            return (
              <ul key={idx} className="ap-md-list">
                {block.items.map((item, i) => (
                  <li key={i}>{renderInline(item)}</li>
                ))}
              </ul>
            );
          case 'ol':
            return (
              <ol key={idx} className="ap-md-list ap-md-list--ol">
                {block.items.map((item, i) => (
                  <li key={i}>{renderInline(item)}</li>
                ))}
              </ol>
            );
          case 'blockquote':
            return (
              <blockquote key={idx} className="ap-md-quote">
                {block.lines.map((line, i) => (
                  <p key={i}>{renderInline(line)}</p>
                ))}
              </blockquote>
            );
          case 'hr':
            return <hr key={idx} className="ap-md-hr" />;
          case 'paragraph':
            return (
              <p key={idx} className="ap-md-p">
                {renderInlineWithBreaks(block.text)}
              </p>
            );
        }
      })}
    </div>
  );
}

function parseBlocks(src: string): BlockNode[] {
  const lines = src.replace(/\r\n/g, '\n').split('\n');
  const blocks: BlockNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (!line.trim()) {
      i += 1;
      continue;
    }

    // Fenced code block: 3+ backticks with arbitrary info string (e.g. ```c#, ```c++, ```ts title="x", ````md)
    const fenceMatch = /^\s*(`{3,})(.*)$/.exec(line);
    if (fenceMatch && !fenceMatch[2].includes('`')) {
      const fenceTicks = fenceMatch[1];
      const infoString = fenceMatch[2].trim();
      const lang = infoString.split(/\s+/)[0] || '';
      const closeFenceRe = new RegExp(`^\\s*\`{${fenceTicks.length},}\\s*$`);
      const codeLines: string[] = [];
      i += 1;
      while (i < lines.length && !closeFenceRe.test(lines[i])) {
        codeLines.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) {
        i += 1; // skip closing fence
      }
      blocks.push({ kind: 'code', lang, code: codeLines.join('\n') });
      continue;
    }

    // Horizontal rule
    if (/^(?:---|\*\*\*|___)\s*$/.test(line.trim())) {
      blocks.push({ kind: 'hr' });
      i += 1;
      continue;
    }

    // Heading
    const headingMatch = /^(#{1,4})\s+(.+)$/.exec(line);
    if (headingMatch) {
      blocks.push({
        kind: 'heading',
        level: headingMatch[1].length as 1 | 2 | 3 | 4,
        text: headingMatch[2].trim(),
      });
      i += 1;
      continue;
    }

    // Blockquote
    if (/^>\s?/.test(line)) {
      const quoteLines: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        quoteLines.push(lines[i].replace(/^>\s?/, ''));
        i += 1;
      }
      blocks.push({ kind: 'blockquote', lines: quoteLines });
      continue;
    }

    // Unordered list
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ''));
        i += 1;
      }
      blocks.push({ kind: 'ul', items });
      continue;
    }

    // Ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''));
        i += 1;
      }
      blocks.push({ kind: 'ol', items });
      continue;
    }

    // Paragraph until blank line or block starter
    const paraLines: string[] = [line];
    i += 1;
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !/^\s*`{3,}(?!.*`)/.test(lines[i]) &&
      !/^(#{1,4})\s+/.test(lines[i]) &&
      !/^>\s?/.test(lines[i]) &&
      !/^\s*[-*]\s+/.test(lines[i]) &&
      !/^\s*\d+\.\s+/.test(lines[i]) &&
      !/^(?:---|\*\*\*|___)\s*$/.test(lines[i].trim())
    ) {
      paraLines.push(lines[i]);
      i += 1;
    }
    blocks.push({ kind: 'paragraph', text: paraLines.join('\n') });
  }

  return blocks;
}

function renderInlineWithBreaks(text: string): ReactNode[] {
  const lines = text.split('\n');
  const out: ReactNode[] = [];
  lines.forEach((line, idx) => {
    if (idx > 0) out.push(<br key={`br-${idx}`} />);
    out.push(...renderInline(line, `l${idx}`));
  });
  return out;
}

const INLINE_TOKEN_RE =
  /(`[^`]+`|\*\*\*[^*]+\*\*\*|\*\*[^*]+\*\*|\*[^*\n]+\*|\[[^\]]+\]\([^)\s]+\))/g;

function isSafeHttpUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function renderInline(text: string, keyPrefix = 'in'): ReactNode[] {
  if (!text) return [];
  const parts = text.split(INLINE_TOKEN_RE);
  const nodes: ReactNode[] = [];

  parts.forEach((part, idx) => {
    if (!part) return;
    const key = `${keyPrefix}-${idx}`;

    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      nodes.push(
        <code key={key} className="ap-md-inline-code">
          {part.slice(1, -1)}
        </code>,
      );
      return;
    }

    if (part.startsWith('***') && part.endsWith('***') && part.length > 6) {
      nodes.push(
        <strong key={key}>
          <em>{part.slice(3, -3)}</em>
        </strong>,
      );
      return;
    }

    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      nodes.push(<strong key={key}>{part.slice(2, -2)}</strong>);
      return;
    }

    if (part.startsWith('*') && part.endsWith('*') && part.length > 2) {
      nodes.push(<em key={key}>{part.slice(1, -1)}</em>);
      return;
    }

    const linkMatch = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(part);
    if (linkMatch) {
      const [, label, href] = linkMatch;
      if (isSafeHttpUrl(href)) {
        nodes.push(
          <a
            key={key}
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="ap-md-link"
          >
            {label}
          </a>,
        );
      } else {
        nodes.push(label);
      }
      return;
    }

    nodes.push(part);
  });

  return nodes;
}
