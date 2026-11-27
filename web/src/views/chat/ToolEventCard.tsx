import { useState } from 'react';
import {
  ChevronDownIcon,
  ChevronRightIcon,
  WrenchIcon,
} from '../../components/ApertureIcons';
import { CodeBlock } from '../../components/Primitives';
import { formatLatency } from '../../lib/format';
import type { ChatMessage, ChatToolEvent } from '../../types/api';

export interface ActiveStreamMeta {
  tempUserId: string;
  persistedUserId: string | null;
  tempAssistantId: string;
  assistantProgressed: boolean;
  originalDraft: string;
}

export function formatToolArgs(args: unknown): string {
  if (args === undefined || args === null) return '{}';
  if (typeof args === 'string') {
    try {
      return JSON.stringify(JSON.parse(args), null, 2);
    } catch {
      return args;
    }
  }
  try {
    return JSON.stringify(args, null, 2);
  } catch {
    return String(args);
  }
}

export function finalizeIncompleteAssistantMessage(
  messages: ChatMessage[],
  assistantId: string,
  reason: 'aborted' | 'error',
): ChatMessage[] {
  const out: ChatMessage[] = [];
  for (const msg of messages) {
    if (msg.id !== assistantId) {
      out.push(msg);
      continue;
    }

    const updatedTools = (msg.tool_events ?? []).map((ev) =>
      ev.result === undefined && !ev.is_error
        ? {
            ...ev,
            is_error: true,
            result:
              reason === 'aborted'
                ? 'Cancelled by user'
                : 'Interrupted by stream error',
          }
        : ev,
    );

    const hasText = Boolean(msg.content && msg.content.length > 0);
    const hasTools = updatedTools.length > 0;
    if (!hasText && !hasTools) {
      // Remove empty placeholder bubble on early stop or error before output arrives
      continue;
    }

    out.push({
      ...msg,
      tool_events: updatedTools,
    });
  }
  return out;
}

export function ToolEventCard({ event }: { event: ChatToolEvent }) {
  const [expanded, setExpanded] = useState(false);
  const isRunning = event.result === undefined && !event.is_error;

  return (
    <div className="ap-tool-card">
      <button
        type="button"
        className="ap-tool-card-head"
        onClick={() => setExpanded((prev) => !prev)}
        aria-expanded={expanded}
      >
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            minWidth: 0,
          }}
        >
          {isRunning ? (
            <span className="ap-spinner" aria-label="Running tool" />
          ) : (
            <WrenchIcon size={14} style={{ color: 'var(--ap-text-secondary)', flexShrink: 0 }} />
          )}
          <span className="ap-mono ap-truncate" style={{ fontWeight: 560 }}>
            {event.server}/{event.tool}
          </span>
        </span>

        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          {isRunning ? (
            <span className="ap-badge ap-badge--blue">Running...</span>
          ) : event.is_error ? (
            <span className="ap-badge ap-badge--red ap-tabular">
              Error{event.duration_ms ? ` · ${formatLatency(event.duration_ms)}` : ''}
            </span>
          ) : (
            <span className="ap-badge ap-badge--green ap-tabular">
              OK{event.duration_ms ? ` · ${formatLatency(event.duration_ms)}` : ''}
            </span>
          )}
          {expanded ? <ChevronDownIcon size={13} /> : <ChevronRightIcon size={13} />}
        </span>
      </button>

      {expanded && (
        <div
          style={{
            padding: '8px 12px 12px',
            borderTop: '1px solid var(--ap-border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
          }}
        >
          <CodeBlock
            label="Tool Arguments"
            code={formatToolArgs(event.arguments)}
          />
          {event.result !== undefined && (
            <CodeBlock
              label={event.is_error ? 'Tool Error' : 'Tool Result'}
              code={formatToolArgs(event.result)}
              highlightRedactions
            />
          )}
        </div>
      )}
    </div>
  );
}
