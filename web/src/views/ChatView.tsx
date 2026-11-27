import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from 'react';
import { api } from '../api/client';
import {
  AlertIcon,
  ArrowUpIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  EditIcon,
  HeadlampMark,
  PlusIcon,
  ProviderGlyph,
  SidebarToggleIcon,
  SlidersIcon,
  StopSquareIcon,
  WrenchIcon,
} from '../components/ApertureIcons';
import { MarkdownBody } from '../components/MarkdownBody';
import {
  CodeBlock,
  ConfirmDeleteButton,
  Modal,
  Toggle,
} from '../components/Primitives';
import {
  formatCompactTokens,
  formatLatency,
  formatUSD,
} from '../lib/format';
import type {
  ChatMCPServerOption,
  ChatMessage,
  ChatModelOption,
  ChatSession,
  ChatToolEvent,
} from '../types/api';

function formatToolArgs(args: unknown): string {
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

function ToolEventCard({ event }: { event: ChatToolEvent }) {
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

export function ChatView() {
  const [models, setModels] = useState<ChatModelOption[]>([]);
  const [mcpServers, setMcpServers] = useState<ChatMCPServerOption[]>([]);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loadingThread, setLoadingThread] = useState(false);

  const [railOpen, setRailOpen] = useState(true);
  const [selectedModel, setSelectedModel] = useState('');
  const [selectedMcpNames, setSelectedMcpNames] = useState<string[]>([]);
  const [systemPrompt, setSystemPrompt] = useState('');

  const [draft, setDraft] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Inline session rename state
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameText, setRenameText] = useState('');
  const renameSubmittingRef = useRef(false);

  // MCP tools popover & System prompt modal
  const [toolsPopoverOpen, setToolsPopoverOpen] = useState(false);
  const toolsPopoverRef = useRef<HTMLDivElement | null>(null);
  const [sysModalOpen, setSysModalOpen] = useState(false);
  const [sysDraft, setSysDraft] = useState('');
  const [sysModalError, setSysModalError] = useState<string | null>(null);
  const [savingSys, setSavingSys] = useState(false);

  // Streaming & auto-scroll refs
  const streamAbortRef = useRef<AbortController | null>(null);
  const threadAbortRef = useRef<AbortController | null>(null);
  const threadScrollRef = useRef<HTMLDivElement | null>(null);
  const stickToBottomRef = useRef(true);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      api.listChatModels({ signal: controller.signal }).catch(() => []),
      api.listChatMCPServers({ signal: controller.signal }).catch(() => []),
      api.listChatSessions(50, { signal: controller.signal }).catch(() => []),
    ]).then(([modelList, serverList, sessionList]) => {
      if (controller.signal.aborted) return;
      setModels(modelList);
      setMcpServers(serverList);
      setSessions(sessionList);
      if (modelList.length > 0) {
        setSelectedModel((prev) => prev || modelList[0].id);
      }
    });

    return () => {
      controller.abort();
      streamAbortRef.current?.abort();
      threadAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!toolsPopoverOpen) return;
    const onPointerDown = (e: MouseEvent) => {
      if (
        toolsPopoverRef.current &&
        !toolsPopoverRef.current.contains(e.target as Node)
      ) {
        setToolsPopoverOpen(false);
      }
    };
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') setToolsPopoverOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [toolsPopoverOpen]);

  const scrollToBottomIfPinned = () => {
    const el = threadScrollRef.current;
    if (!el || !stickToBottomRef.current) return;
    el.scrollTop = el.scrollHeight;
  };

  useEffect(() => {
    scrollToBottomIfPinned();
  }, [messages]);

  const activeSession = useMemo(
    () => sessions.find((s) => s.id === activeSessionId) ?? null,
    [sessions, activeSessionId],
  );

  const selectSession = async (session: ChatSession) => {
    if (streaming) {
      streamAbortRef.current?.abort();
      setStreaming(false);
    }
    threadAbortRef.current?.abort();
    const controller = new AbortController();
    threadAbortRef.current = controller;

    setActiveSessionId(session.id);
    setSelectedModel(session.model || models[0]?.id || '');
    setSelectedMcpNames(session.mcp_servers ?? []);
    setSystemPrompt(session.system_prompt || '');
    setError(null);
    setLoadingThread(true);
    stickToBottomRef.current = true;

    try {
      const detail = await api.getChatSession(session.id, {
        signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      setMessages(detail.messages ?? []);
      setSelectedModel(detail.session.model || session.model);
      setSelectedMcpNames(detail.session.mcp_servers ?? []);
      setSystemPrompt(detail.session.system_prompt || '');
    } catch (err: unknown) {
      if (controller.signal.aborted) return;
      setError(err instanceof Error ? err.message : 'Failed to load conversation');
    } finally {
      if (!controller.signal.aborted) {
        setLoadingThread(false);
      }
    }
  };

  const startNewChat = () => {
    if (streaming) {
      streamAbortRef.current?.abort();
      setStreaming(false);
    }
    threadAbortRef.current?.abort();
    setActiveSessionId(null);
    setMessages([]);
    setSystemPrompt('');
    setError(null);
    stickToBottomRef.current = true;
  };

  const handleModelChange = async (nextModel: string) => {
    setSelectedModel(nextModel);
    if (!activeSessionId) return;
    try {
      const updated = await api.updateChatSession(activeSessionId, {
        model: nextModel,
      });
      setSessions((prev) =>
        prev.map((s) => (s.id === updated.id ? updated : s)),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update session model');
    }
  };

  const handleToggleMcpServer = async (name: string, enabled: boolean) => {
    const nextList = enabled
      ? Array.from(new Set([...selectedMcpNames, name]))
      : selectedMcpNames.filter((item) => item !== name);
    setSelectedMcpNames(nextList);

    if (!activeSessionId) return;
    try {
      const updated = await api.updateChatSession(activeSessionId, {
        mcp_servers: nextList,
      });
      setSessions((prev) =>
        prev.map((s) => (s.id === updated.id ? updated : s)),
      );
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : 'Failed to update attached MCP tools',
      );
    }
  };

  const openSystemPromptModal = () => {
    setSysDraft(systemPrompt);
    setSysModalError(null);
    setSysModalOpen(true);
  };

  const handleSaveSystemPrompt = async (e: FormEvent) => {
    e.preventDefault();
    setSysModalError(null);
    if (!activeSessionId) {
      setSystemPrompt(sysDraft);
      setSysModalOpen(false);
      return;
    }
    setSavingSys(true);
    try {
      const updated = await api.updateChatSession(activeSessionId, {
        system_prompt: sysDraft,
      });
      setSystemPrompt(updated.system_prompt || '');
      setSessions((prev) =>
        prev.map((s) => (s.id === updated.id ? updated : s)),
      );
      setSysModalOpen(false);
    } catch (err: unknown) {
      setSysModalError(
        err instanceof Error ? err.message : 'Failed to save system prompt',
      );
    } finally {
      setSavingSys(false);
    }
  };

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
      const updated = await api.updateChatSession(sessionId, { title: trimmed });
      setSessions((prev) =>
        prev.map((s) => (s.id === updated.id ? updated : s)),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to rename session');
    } finally {
      renameSubmittingRef.current = false;
    }
  };

  const handleDeleteSession = async (sessionId: string) => {
    try {
      await api.deleteChatSession(sessionId);
      setSessions((prev) => prev.filter((s) => s.id !== sessionId));
      if (activeSessionId === sessionId) {
        startNewChat();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete session');
    }
  };

  const handleStopStreaming = () => {
    streamAbortRef.current?.abort();
    streamAbortRef.current = null;
    setStreaming(false);
  };

  const handleSend = async () => {
    const content = draft.trim();
    if (!content || streaming) return;

    const effectiveModel = selectedModel || models[0]?.id || '';
    if (!effectiveModel) {
      setError('No allowed chat models available. Check your Tailnet Grants or Providers.');
      return;
    }

    setError(null);
    setDraft('');
    setStreaming(true);
    stickToBottomRef.current = true;

    let sessionId = activeSessionId;
    try {
      if (!sessionId) {
        const autoTitle =
          content.length > 44 ? `${content.slice(0, 44).trim()}...` : content;
        const created = await api.createChatSession({
          title: autoTitle,
          model: effectiveModel,
          mcp_servers: selectedMcpNames,
          system_prompt: systemPrompt || undefined,
        });
        sessionId = created.id;
        setActiveSessionId(created.id);
        setSessions((prev) => [created, ...prev.filter((s) => s.id !== created.id)]);
      }

      const tempUserId = `temp-user-${Date.now()}`;
      const tempAssistantId = `temp-asst-${Date.now()}`;
      const nowIso = new Date().toISOString();

      setMessages((prev) => [
        ...prev,
        {
          id: tempUserId,
          session_id: sessionId!,
          role: 'user',
          content,
          created_at: nowIso,
        },
        {
          id: tempAssistantId,
          session_id: sessionId!,
          role: 'assistant',
          content: '',
          model: effectiveModel,
          tool_events: [],
          created_at: nowIso,
        },
      ]);

      const controller = new AbortController();
      streamAbortRef.current = controller;

      await api.streamChatMessage(
        sessionId,
        {
          content,
          model: effectiveModel,
          mcp_servers: selectedMcpNames,
        },
        {
          onMessageStart: ({ user_message, session }) => {
            setSessions((prev) => [
              session,
              ...prev.filter((s) => s.id !== session.id),
            ]);
            setMessages((prev) =>
              prev.map((m) => (m.id === tempUserId ? user_message : m)),
            );
          },
          onDelta: ({ text }) => {
            setMessages((prev) =>
              prev.map((m) =>
                m.id === tempAssistantId
                  ? { ...m, content: (m.content || '') + text }
                  : m,
              ),
            );
          },
          onToolStart: (ev) => {
            setMessages((prev) =>
              prev.map((m) => {
                if (m.id !== tempAssistantId) return m;
                const existing = m.tool_events ?? [];
                return {
                  ...m,
                  tool_events: [
                    ...existing,
                    {
                      id: ev.id,
                      server: ev.server,
                      tool: ev.tool,
                      arguments: ev.arguments,
                    },
                  ],
                };
              }),
            );
          },
          onToolResult: (ev) => {
            setMessages((prev) =>
              prev.map((m) => {
                if (m.id !== tempAssistantId) return m;
                const existing = m.tool_events ?? [];
                const updatedEvents = existing.some((t) => t.id === ev.id)
                  ? existing.map((t) =>
                      t.id === ev.id
                        ? {
                            ...t,
                            result: ev.result,
                            is_error: ev.is_error,
                            duration_ms: ev.duration_ms,
                          }
                        : t,
                    )
                  : [
                      ...existing,
                      {
                        id: ev.id,
                        server: ev.server,
                        tool: ev.tool,
                        result: ev.result,
                        is_error: ev.is_error,
                        duration_ms: ev.duration_ms,
                      },
                    ];
                return { ...m, tool_events: updatedEvents };
              }),
            );
          },
          onMessageDone: ({ assistant_message }) => {
            setMessages((prev) =>
              prev.map((m) =>
                m.id === tempAssistantId
                  ? {
                      ...assistant_message,
                      tool_events:
                        assistant_message.tool_events &&
                        assistant_message.tool_events.length > 0
                          ? assistant_message.tool_events
                          : m.tool_events,
                    }
                  : m,
              ),
            );
          },
          onError: (errEvt) => {
            setError(errEvt.message || 'Stream error');
          },
        },
        { signal: controller.signal },
      );
    } catch (err: unknown) {
      if ((err as { name?: string })?.name !== 'AbortError') {
        setError(err instanceof Error ? err.message : 'Failed to send message');
      }
    } finally {
      streamAbortRef.current = null;
      setStreaming(false);
    }
  };

  const handleComposerKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      void handleSend();
    }
  };

  const activeModelOption = useMemo(
    () => models.find((m) => m.id === selectedModel) ?? null,
    [models, selectedModel],
  );

  const availableMcpServers = mcpServers.filter((s) => s.enabled);

  return (
    <div className="ap-chat-shell">
      {railOpen && (
        <aside className="ap-chat-rail" aria-label="Chat history">
          <div className="ap-chat-rail-head">
            <button
              type="button"
              className="ap-btn ap-btn-sm"
              style={{ width: '100%', justifyContent: 'flex-start' }}
              onClick={startNewChat}
            >
              <PlusIcon size={14} />
              <span>New chat</span>
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
                      if (!isRenaming) void selectSession(sess);
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
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 2, flexShrink: 0 }}
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
                            onConfirm={() => handleDeleteSession(sess.id)}
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
      )}

      <div className="ap-chat-main">
        <header className="ap-chat-topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
            <button
              type="button"
              className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
              onClick={() => setRailOpen((prev) => !prev)}
              aria-label={railOpen ? 'Hide chat history' : 'Show chat history'}
              title={railOpen ? 'Hide chat history' : 'Show chat history'}
            >
              <SidebarToggleIcon size={15} />
            </button>
            <span
              className="ap-truncate"
              style={{ fontWeight: 600, fontSize: 13.5 }}
            >
              {activeSession ? activeSession.title || 'Untitled chat' : 'New chat'}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {activeModelOption && (
                <ProviderGlyph
                  type={activeModelOption.provider_type || activeModelOption.provider}
                />
              )}
              <select
                className="ap-select ap-select--sm ap-mono"
                style={{ width: 236, maxWidth: '32vw' }}
                value={selectedModel}
                onChange={(e) => void handleModelChange(e.target.value)}
                aria-label="Select chat model"
              >
                {models.length === 0 ? (
                  <option value="">No models available</option>
                ) : (
                  models.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.id}
                      {m.is_alias ? ' (route)' : ''}
                    </option>
                  ))
                )}
              </select>
            </div>

            {/* MCP Tools Attach Popover */}
            <div ref={toolsPopoverRef} style={{ position: 'relative' }}>
              <button
                type="button"
                className="ap-btn ap-btn-sm"
                onClick={() => setToolsPopoverOpen((prev) => !prev)}
                aria-expanded={toolsPopoverOpen}
                aria-label="Attach MCP Tools"
              >
                <WrenchIcon size={14} />
                <span>Tools</span>
                {selectedMcpNames.length > 0 && (
                  <span className="ap-badge ap-badge--blue ap-tabular">
                    {selectedMcpNames.length}
                  </span>
                )}
              </button>

              {toolsPopoverOpen && (
                <div className="ap-popover" role="dialog" aria-label="MCP Servers">
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 620,
                      padding: '2px 4px',
                      display: 'flex',
                      justifyContent: 'space-between',
                    }}
                  >
                    <span>Attach MCP Tool Servers</span>
                    <span style={{ color: 'var(--ap-text-muted)', fontWeight: 450 }}>
                      {availableMcpServers.length} enabled
                    </span>
                  </div>

                  {availableMcpServers.length === 0 ? (
                    <div
                      style={{
                        padding: '10px 6px',
                        fontSize: 12,
                        color: 'var(--ap-text-muted)',
                      }}
                    >
                      No enabled MCP servers configured on this gateway.
                    </div>
                  ) : (
                    availableMcpServers.map((srv) => {
                      const checked = selectedMcpNames.includes(srv.name);
                      const toolCount = srv.tools?.length ?? 0;
                      return (
                        <div
                          key={srv.name}
                          style={{
                            padding: '8px 8px',
                            borderRadius: 'var(--ap-radius-sm)',
                            background: checked ? 'var(--ap-blue-soft)' : 'var(--ap-subcard-bg)',
                            border: '1px solid var(--ap-border)',
                            display: 'flex',
                            alignItems: 'flex-start',
                            justifyContent: 'space-between',
                            gap: 10,
                          }}
                        >
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: 6,
                              }}
                            >
                              <span className="ap-mono" style={{ fontWeight: 600, fontSize: 12 }}>
                                {srv.name}
                              </span>
                              <span className="ap-badge ap-tabular">
                                {toolCount} {toolCount === 1 ? 'tool' : 'tools'}
                              </span>
                            </div>
                            {srv.error ? (
                              <div
                                style={{
                                  fontSize: 11,
                                  color: 'var(--ap-red)',
                                  marginTop: 3,
                                }}
                              >
                                {srv.error}
                              </div>
                            ) : (
                              (srv.tools ?? []).length > 0 && (
                                <div
                                  className="ap-mono ap-truncate"
                                  style={{
                                    fontSize: 11,
                                    color: 'var(--ap-text-secondary)',
                                    marginTop: 3,
                                  }}
                                  title={(srv.tools ?? []).map((t) => t.name).join(', ')}
                                >
                                  {(srv.tools ?? []).map((t) => t.name).join(', ')}
                                </div>
                              )
                            )}
                          </div>
                          <Toggle
                            checked={checked}
                            onChange={(next) =>
                              void handleToggleMcpServer(srv.name, next)
                            }
                            label={`Attach MCP server ${srv.name}`}
                          />
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>

            <button
              type="button"
              className="ap-btn ap-btn-sm"
              onClick={openSystemPromptModal}
              title="Configure system prompt"
            >
              <SlidersIcon size={14} />
              <span className="ap-action-label">System</span>
              {systemPrompt.trim() && (
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: 'var(--ap-blue)',
                  }}
                />
              )}
            </button>
          </div>
        </header>

        <div
          ref={threadScrollRef}
          className="ap-chat-thread"
          onScroll={() => {
            const el = threadScrollRef.current;
            if (!el) return;
            stickToBottomRef.current =
              el.scrollHeight - el.scrollTop - el.clientHeight < 72;
          }}
        >
          {error && (
            <div
              className="ap-alert ap-alert--danger"
              role="alert"
              style={{ maxWidth: 780, width: '100%', margin: '0 auto 14px' }}
            >
              <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
              <span>{error}</span>
            </div>
          )}

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
                      <ProviderGlyph type={msg.model || selectedModel} />
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
                      ) : streaming ? (
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

        <div className="ap-chat-composer-dock">
          <div className="ap-chat-composer">
            <textarea
              className="ap-chat-textarea"
              placeholder="Ask anything..."
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={handleComposerKeyDown}
              aria-label="Message input"
            />

            <div className="ap-chat-composer-bar">
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="ap-btn ap-btn-ghost ap-btn-sm"
                  onClick={() => setToolsPopoverOpen((prev) => !prev)}
                >
                  <WrenchIcon size={13} />
                  <span>
                    {selectedMcpNames.length > 0
                      ? `${selectedMcpNames.length} MCP attached`
                      : 'Attach MCP'}
                  </span>
                </button>
                <button
                  type="button"
                  className="ap-btn ap-btn-ghost ap-btn-sm"
                  onClick={openSystemPromptModal}
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
                    className="ap-mono ap-truncate"
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
                    onClick={handleStopStreaming}
                    aria-label="Stop generation"
                  >
                    <StopSquareIcon size={11} />
                    <span>Stop</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    className="ap-chat-send-btn"
                    disabled={!draft.trim() || models.length === 0}
                    onClick={() => void handleSend()}
                    aria-label="Send message"
                  >
                    <ArrowUpIcon size={15} />
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      <Modal
        open={sysModalOpen}
        title="System Prompt"
        onClose={() => setSysModalOpen(false)}
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
              onClick={() => setSysModalOpen(false)}
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
    </div>
  );
}
