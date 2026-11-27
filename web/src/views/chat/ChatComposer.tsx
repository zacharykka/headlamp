import {
  useEffect,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type RefObject,
} from 'react';
import {
  ArrowUpIcon,
  SlidersIcon,
  StopSquareIcon,
  WrenchIcon,
} from '../../components/ApertureIcons';
import { Modal } from '../../components/Primitives';

interface ChatComposerProps {
  draft: string;
  onDraftChange: (value: string) => void;
  onKeyDown: (e: KeyboardEvent<HTMLTextAreaElement>) => void;
  streaming: boolean;
  onSend: () => void;
  onStopStreaming: () => void;
  modelsCount: number;
  selectedModel: string;
  selectedMcpNames: string[];
  missingSelectedMcpNames: string[];
  onToggleMcpServer: (name: string, enabled: boolean) => void;
  onToggleToolsPopover: () => void;
  bottomToolsBtnRef: RefObject<HTMLButtonElement | null>;
  systemPrompt: string;
  onOpenSystemPrompt: () => void;
  sysModalOpen: boolean;
  onCloseSysModal: () => void;
  onSaveSystemPrompt: (nextPrompt: string) => Promise<void>;
}

export function ChatComposer({
  draft,
  onDraftChange,
  onKeyDown,
  streaming,
  onSend,
  onStopStreaming,
  modelsCount,
  selectedModel,
  selectedMcpNames,
  missingSelectedMcpNames,
  onToggleMcpServer,
  onToggleToolsPopover,
  bottomToolsBtnRef,
  systemPrompt,
  onOpenSystemPrompt,
  sysModalOpen,
  onCloseSysModal,
  onSaveSystemPrompt,
}: ChatComposerProps) {
  const [sysDraft, setSysDraft] = useState(systemPrompt);
  const [sysModalError, setSysModalError] = useState<string | null>(null);
  const [savingSys, setSavingSys] = useState(false);

  useEffect(() => {
    if (sysModalOpen) {
      setSysDraft(systemPrompt);
      setSysModalError(null);
    }
  }, [sysModalOpen, systemPrompt]);

  const handleSaveSystemPrompt = async (e: FormEvent) => {
    e.preventDefault();
    setSysModalError(null);
    setSavingSys(true);
    try {
      await onSaveSystemPrompt(sysDraft);
      onCloseSysModal();
    } catch (err: unknown) {
      setSysModalError(
        err instanceof Error ? err.message : 'Failed to save system prompt',
      );
    } finally {
      setSavingSys(false);
    }
  };

  return (
    <>
      <div className="ap-chat-composer-dock">
        <div className="ap-chat-composer">
          <textarea
            className="ap-chat-textarea"
            placeholder="Ask anything..."
            value={draft}
            onChange={(e) => onDraftChange(e.target.value)}
            onKeyDown={onKeyDown}
            aria-label="Message input"
          />

          <div className="ap-chat-composer-bar">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <button
                ref={bottomToolsBtnRef}
                type="button"
                className="ap-btn ap-btn-ghost ap-btn-sm"
                onClick={onToggleToolsPopover}
              >
                <WrenchIcon size={13} />
                <span>
                  {selectedMcpNames.length > 0
                    ? `${selectedMcpNames.length} MCP attached`
                    : 'Attach MCP'}
                </span>
              </button>
              {missingSelectedMcpNames.map((missingName) => (
                <button
                  key={missingName}
                  type="button"
                  className="ap-badge ap-badge--amber ap-mono"
                  style={{ cursor: 'pointer' }}
                  title={`Remove unavailable MCP server ${missingName}`}
                  onClick={() => onToggleMcpServer(missingName, false)}
                >
                  <span>{missingName} (unavailable) ×</span>
                </button>
              ))}
              <button
                type="button"
                className="ap-btn ap-btn-ghost ap-btn-sm"
                onClick={onOpenSystemPrompt}
              >
                <SlidersIcon size={13} />
                <span>
                  {systemPrompt.trim() ? 'System prompt set' : 'System prompt'}
                </span>
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {selectedModel && (
                <span
                  className="ap-mono ap-truncate ap-chat-composer-model"
                  style={{
                    fontSize: 11.5,
                    color: 'var(--ap-text-secondary)',
                    maxWidth: 190,
                  }}
                  title={selectedModel}
                >
                  {selectedModel}
                </span>
              )}

              {streaming ? (
                <button
                  type="button"
                  className="ap-chat-send-btn ap-chat-send-btn--stop"
                  onClick={onStopStreaming}
                  aria-label="Stop generation"
                >
                  <StopSquareIcon size={11} />
                  <span>Stop</span>
                </button>
              ) : (
                <button
                  type="button"
                  className="ap-chat-send-btn"
                  disabled={!draft.trim() || (modelsCount === 0 && !selectedModel)}
                  onClick={onSend}
                  aria-label="Send message"
                >
                  <ArrowUpIcon size={15} />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      <Modal
        open={sysModalOpen}
        title="System Prompt"
        onClose={onCloseSysModal}
        error={sysModalError}
      >
        <form
          onSubmit={handleSaveSystemPrompt}
          style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
        >
          <label className="ap-field">
            <span className="ap-label">Session Instructions (optional)</span>
            <textarea
              className="ap-textarea"
              style={{ minHeight: 120 }}
              value={sysDraft}
              onChange={(e) => setSysDraft(e.target.value)}
              placeholder="You are an infrastructure assistant for our Tailnet engineering team..."
            />
          </label>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button
              type="button"
              className="ap-btn"
              onClick={onCloseSysModal}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="ap-btn ap-btn-primary"
              disabled={savingSys}
            >
              {savingSys ? 'Saving...' : 'Save System Prompt'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
