import { useEffect, useRef, useState } from 'react';
import {
  CheckIcon,
  CloseIcon,
  EditIcon,
  PlusIcon,
} from '../../components/ApertureIcons';
import { ConfirmDeleteButton } from '../../components/Primitives';
import type { ChatSession } from '../../types/api';

interface ChatSidebarProps {
  sessions: ChatSession[];
  activeSessionId: string | null;
  onNewChat: () => void;
  onSelectSession: (session: ChatSession) => void;
  onRenameSession: (sessionId: string, title: string) => Promise<void>;
  onDeleteSession: (sessionId: string) => Promise<void>;
  onClose: () => void;
  onRenamingChange: (renaming: boolean) => void;
}

export function ChatSidebar({
  sessions,
  activeSessionId,
  onNewChat,
  onSelectSession,
  onRenameSession,
  onDeleteSession,
  onClose,
  onRenamingChange,
}: ChatSidebarProps) {
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameText, setRenameText] = useState('');
  const renameSubmittingRef = useRef(false);

  useEffect(() => {
    onRenamingChange(renamingId !== null);
    return () => {
      onRenamingChange(false);
    };
  }, [renamingId, onRenamingChange]);

  const commitRename = async (sessionId: string) => {
    if (renameSubmittingRef.current) return;
    renameSubmittingRef.current = true;
    const trimmed = renameText.trim();
    setRenamingId(null);
    if (!trimmed) {
      renameSubmittingRef.current = false;
      return;
    }
    try {
      await onRenameSession(sessionId, trimmed);
    } finally {
      renameSubmittingRef.current = false;
    }
  };

  return (
    <>
      <div
        className="ap-chat-rail-backdrop"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside className="ap-chat-rail" aria-label="Chat history">
        <div className="ap-chat-rail-head">
          <button
            type="button"
            className="ap-btn ap-btn-sm"
            style={{ flex: 1, justifyContent: 'flex-start', minWidth: 0 }}
            onClick={onNewChat}
          >
            <PlusIcon size={14} />
            <span>New chat</span>
          </button>
          <button
            type="button"
            className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact ap-chat-rail-close"
            onClick={onClose}
            aria-label="Close chat history"
            title="Close chat history"
          >
            <CloseIcon size={14} />
          </button>
        </div>

        <div className="ap-chat-rail-list">
          <div
            style={{
              padding: '4px 8px 6px',
              fontSize: 11,
              fontWeight: 600,
              color: 'var(--ap-text-muted)',
              letterSpacing: '0.02em',
            }}
          >
            Chats
          </div>

          {sessions.length === 0 ? (
            <div
              style={{
                padding: '8px 8px',
                fontSize: 12.5,
                color: 'var(--ap-text-muted)',
              }}
            >
              No conversations yet
            </div>
          ) : (
            sessions.map((sess) => {
              const isActive = sess.id === activeSessionId;
              const isRenaming = renamingId === sess.id;

              return (
                <div
                  key={sess.id}
                  className="ap-chat-session-row"
                  data-active={isActive}
                  onClick={() => {
                    if (!isRenaming) onSelectSession(sess);
                  }}
                >
                  {isRenaming ? (
                    <form
                      style={{ flex: 1, display: 'flex', gap: 4, minWidth: 0 }}
                      onSubmit={(e) => {
                        e.preventDefault();
                        void commitRename(sess.id);
                      }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <input
                        className="ap-input ap-input--sm"
                        style={{ height: 26, padding: '2px 6px', fontSize: 12 }}
                        autoFocus
                        value={renameText}
                        onChange={(e) => setRenameText(e.target.value)}
                        onBlur={() => void commitRename(sess.id)}
                        onKeyDown={(e) => {
                          if (e.key === 'Escape') {
                            e.stopPropagation();
                            renameSubmittingRef.current = true;
                            setRenamingId(null);
                            window.setTimeout(() => {
                              renameSubmittingRef.current = false;
                            }, 0);
                          }
                        }}
                        aria-label="Session title"
                      />
                      <button
                        type="submit"
                        className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                        aria-label="Save title"
                      >
                        <CheckIcon size={13} />
                      </button>
                    </form>
                  ) : (
                    <>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div
                          className="ap-truncate"
                          style={{
                            fontSize: 12.5,
                            fontWeight: isActive ? 600 : 480,
                          }}
                          title={sess.title || 'Untitled chat'}
                        >
                          {sess.title || 'Untitled chat'}
                        </div>
                        <div
                          className="ap-mono ap-truncate"
                          style={{ fontSize: 10.5, color: 'var(--ap-text-muted)' }}
                        >
                          {sess.model}
                        </div>
                      </div>

                      <div
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 2,
                          flexShrink: 0,
                        }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          type="button"
                          className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                          style={{ padding: '0 4px', height: 24 }}
                          aria-label={`Rename ${sess.title || 'chat'}`}
                          title="Rename chat"
                          onClick={() => {
                            setRenamingId(sess.id);
                            setRenameText(sess.title || '');
                          }}
                        >
                          <EditIcon size={12} />
                        </button>
                        <ConfirmDeleteButton
                          itemName={sess.title || 'chat'}
                          onConfirm={() => onDeleteSession(sess.id)}
                        />
                      </div>
                    </>
                  )}
                </div>
              );
            })
          )}
        </div>
      </aside>
    </>
  );
}
