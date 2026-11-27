import type { RefObject } from 'react';
import { HeadlampMark, ProviderGlyph } from '../../components/ApertureIcons';
import { MarkdownBody } from '../../components/MarkdownBody';
import { formatCompactTokens, formatUSD } from '../../lib/format';
import type { ChatMessage } from '../../types/api';
import { ToolEventCard } from './ToolEventCard';

interface ChatThreadProps {
  threadScrollRef: RefObject<HTMLDivElement | null>;
  onScroll: () => void;
  loadingThread: boolean;
  messages: ChatMessage[];
  streaming: boolean;
  activeAssistantId: string | null;
  resolveProviderType: (modelId?: string) => string;
}

export function ChatThread({
  threadScrollRef,
  onScroll,
  loadingThread,
  messages,
  streaming,
  activeAssistantId,
  resolveProviderType,
}: ChatThreadProps) {
  return (
    <div
      ref={threadScrollRef}
      className="ap-chat-thread"
      onScroll={onScroll}
    >
      {loadingThread ? (
        <div className="ap-chat-hero">
          <span style={{ color: 'var(--ap-text-secondary)' }}>
            Loading conversation...
          </span>
        </div>
      ) : messages.length === 0 ? (
        <div className="ap-chat-hero">
          <div className="ap-chat-hero-glow" />
          <div
            style={{
              position: 'relative',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 12 }}>
              <HeadlampMark size={36} />
              <span
                style={{
                  fontSize: 30,
                  fontWeight: 700,
                  letterSpacing: '-0.035em',
                }}
              >
                headlamp
              </span>
            </div>
            <span style={{ fontSize: 12.5, color: 'var(--ap-text-secondary)' }}>
              Private Tailnet chat · metered & policy-governed
            </span>
          </div>
        </div>
      ) : (
        <div className="ap-chat-thread-inner">
          {messages.map((msg) => {
            if (msg.role === 'user') {
              return (
                <div key={msg.id} className="ap-chat-msg-user">
                  {msg.content}
                </div>
              );
            }

            const toolEvents = msg.tool_events ?? [];
            const hasMetrics =
              (msg.input_tokens ?? 0) > 0 ||
              (msg.output_tokens ?? 0) > 0 ||
              (msg.cost_usd ?? 0) > 0;

            return (
              <div key={msg.id} className="ap-chat-msg-assistant">
                <div style={{ marginTop: 2 }}>
                  <ProviderGlyph type={resolveProviderType(msg.model)} />
                </div>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {toolEvents.length > 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {toolEvents.map((ev) => (
                        <ToolEventCard key={ev.id} event={ev} />
                      ))}
                    </div>
                  )}

                  {msg.content ? (
                    <MarkdownBody content={msg.content} />
                  ) : streaming && msg.id === activeAssistantId ? (
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 8,
                        color: 'var(--ap-text-muted)',
                        fontSize: 12.5,
                      }}
                    >
                      <span className="ap-spinner" />
                      <span>Thinking...</span>
                    </span>
                  ) : null}

                  {hasMetrics && (
                    <div
                      className="ap-tabular ap-mono"
                      style={{
                        fontSize: 11,
                        color: 'var(--ap-text-muted)',
                        display: 'flex',
                        gap: 10,
                        flexWrap: 'wrap',
                      }}
                    >
                      {msg.model && <span>{msg.model}</span>}
                      <span>
                        in {formatCompactTokens(msg.input_tokens)} · out{' '}
                        {formatCompactTokens(msg.output_tokens)} tok
                      </span>
                      <span>{formatUSD(msg.cost_usd)}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
