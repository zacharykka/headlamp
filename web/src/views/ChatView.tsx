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
  CloseIcon,
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

interface ActiveStreamMeta {
  tempUserId: string;
  persistedUserId: string | null;
  tempAssistantId: string;
  assistantProgressed: boolean;
  originalDraft: string;
}

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

function finalizeIncompleteAssistantMessage(
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

  const [railOpen, setRailOpen] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth >= 960 : true,
  );
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
  const bottomToolsBtnRef = useRef<HTMLButtonElement | null>(null);
  const [sysModalOpen, setSysModalOpen] = useState(false);
  const [sysDraft, setSysDraft] = useState('');
  const [sysModalError, setSysModalError] = useState<string | null>(null);
  const [savingSys, setSavingSys] = useState(false);

  // Streaming & auto-scroll refs
  const streamAbortRef = useRef<AbortController | null>(null);
  const activeStreamMetaRef = useRef<ActiveStreamMeta | null>(null);
  const [activeAssistantId, setActiveAssistantId] = useState<string | null>(null);
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
      const target = e.target as Node;
      if (
        (toolsPopoverRef.current && toolsPopoverRef.current.contains(target)) ||
        (bottomToolsBtnRef.current && bottomToolsBtnRef.current.contains(target))
      ) {
        return;
      }
      setToolsPopoverOpen(false);
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

  useEffect(() => {
    if (!railOpen) return;
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (
        e.key === 'Escape' &&
        typeof window !== 'undefined' &&
        window.innerWidth < 960 &&
        !toolsPopoverOpen &&
        !sysModalOpen &&
        !renamingId
      ) {
        setRailOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [railOpen, toolsPopoverOpen, sysModalOpen, renamingId]);

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

  const abortActiveStream = (opts?: { restoreDraft?: boolean }) => {
    const restoreDraft = opts?.restoreDraft ?? true;
    if (streamAbortRef.current) {
      streamAbortRef.current.abort();
      streamAbortRef.current = null;
    }
    const meta = activeStreamMetaRef.current;
    activeStreamMetaRef.current = null;
    setActiveAssistantId(null);
    if (meta) {
      if (!meta.assistantProgressed) {
        const userIdToRemove = meta.persistedUserId ?? meta.tempUserId;
        setMessages((prev) =>
          prev.filter(
            (m) =>
              m.id !== meta.tempUserId &&
              m.id !== userIdToRemove &&
              m.id !== meta.tempAssistantId,
          ),
        );
        if (restoreDraft) {
          setDraft((prev) => prev || meta.originalDraft);
        }
      } else {
        setMessages((prev) =>
          finalizeIncompleteAssistantMessage(
            prev,
            meta.tempAssistantId,
            'aborted',
          ),
        );
      }
    }
    setStreaming(false);
  };

  const selectSession = async (session: ChatSession) => {
    abortActiveStream({ restoreDraft: false });
    threadAbortRef.current?.abort();
    const controller = new AbortController();
    threadAbortRef.current = controller;

    if (typeof window !== 'undefined' && window.innerWidth < 768) {
      setRailOpen(false);
    }

    setActiveSessionId(session.id);
    setMessages([]);
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
    abortActiveStream({ restoreDraft: false });
    threadAbortRef.current?.abort();
    if (typeof window !== 'undefined' && window.innerWidth < 768) {
      setRailOpen(false);
    }
    setActiveSessionId(null);
    setMessages([]);
    if (models.length > 0 && !models.some((m) => m.id === selectedModel)) {
      setSelectedModel(models[0].id);
    }
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
    abortActiveStream({ restoreDraft: true });
  };

  const handleSend = async () => {
    const content = draft.trim();
    if (!content || streaming) return;

    const effectiveModel = selectedModel || models[0]?.id || '';
    if (!effectiveModel) {
      setError('No allowed chat models available. Check your Tailnet Grants or Providers.');
      return;
    }

    streamAbortRef.current?.abort();
    const controller = new AbortController();
    streamAbortRef.current = controller;

    setError(null);
    setDraft('');
    setStreaming(true);
    stickToBottomRef.current = true;

    let sessionId = activeSessionId;
    let sseStarted = false;
    const tempUserId = `temp-user-${Date.now()}`;
    const tempAssistantId = `temp-asst-${Date.now()}`;
    const streamMeta: ActiveStreamMeta = {
      tempUserId,
      persistedUserId: null,
      tempAssistantId,
      assistantProgressed: false,
      originalDraft: content,
    };
    activeStreamMetaRef.current = streamMeta;
    setActiveAssistantId(tempAssistantId);

    const isStaleOrAborted = () =>
      controller.signal.aborted || streamAbortRef.current !== controller;

    try {
      if (!sessionId) {
        const created = await api.createChatSession(
          {
            title: 'New Chat',
            model: effectiveModel,
            mcp_servers: selectedMcpNames,
            system_prompt: systemPrompt || undefined,
          },
          { signal: controller.signal },
        );
        if (isStaleOrAborted()) return;
        sessionId = created.id;
        setActiveSessionId(created.id);
        setSessions((prev) => [created, ...prev.filter((s) => s.id !== created.id)]);
      }

      if (isStaleOrAborted()) return;
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

      await api.streamChatMessage(
        sessionId,
        {
          content,
          model: effectiveModel,
          mcp_servers: selectedMcpNames,
        },
        {
          onMessageStart: ({ user_message, session }) => {
            if (isStaleOrAborted()) return;
            sseStarted = true;
            streamMeta.persistedUserId = user_message.id;
            setSessions((prev) => [
              session,
              ...prev.filter((s) => s.id !== session.id),
            ]);
            setMessages((prev) =>
              prev.map((m) => (m.id === tempUserId ? user_message : m)),
            );
          },
          onDelta: ({ text }) => {
            if (isStaleOrAborted()) return;
            sseStarted = true;
            streamMeta.assistantProgressed = true;
            setMessages((prev) =>
              prev.map((m) =>
                m.id === tempAssistantId
                  ? { ...m, content: (m.content || '') + text }
                  : m,
              ),
            );
          },
          onToolStart: (ev) => {
            if (isStaleOrAborted()) return;
            sseStarted = true;
            streamMeta.assistantProgressed = true;
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
            if (isStaleOrAborted()) return;
            sseStarted = true;
            streamMeta.assistantProgressed = true;
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
            if (isStaleOrAborted()) return;
            sseStarted = true;
            streamMeta.assistantProgressed = true;
            if (activeStreamMetaRef.current === streamMeta) {
              activeStreamMetaRef.current = null;
            }
            setActiveAssistantId((prev) =>
              prev === tempAssistantId ? null : prev,
            );
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
            if (isStaleOrAborted()) return;
            sseStarted = true;
            setError(errEvt.message || 'Stream error');
            if (!streamMeta.assistantProgressed) {
              const userIdToRemove = streamMeta.persistedUserId ?? tempUserId;
              setMessages((prev) =>
                prev.filter(
                  (m) =>
                    m.id !== tempUserId &&
                    m.id !== userIdToRemove &&
                    m.id !== tempAssistantId,
                ),
              );
              setDraft((prev) => prev || content);
            } else {
              setMessages((prev) =>
                finalizeIncompleteAssistantMessage(prev, tempAssistantId, 'error'),
              );
            }
          },
        },
        { signal: controller.signal },
      );

      // Ensure any dangling empty placeholder or unfinished tool card is cleaned up if stream ended without message_done
      if (!isStaleOrAborted() && activeStreamMetaRef.current === streamMeta) {
        activeStreamMetaRef.current = null;
        setActiveAssistantId((prev) => (prev === tempAssistantId ? null : prev));
        setMessages((prev) =>
          finalizeIncompleteAssistantMessage(prev, tempAssistantId, 'error'),
        );
      }
    } catch (err: unknown) {
      const isAbort =
        controller.signal.aborted || (err as { name?: string })?.name === 'AbortError';
      if (isAbort) {
        if (streamAbortRef.current === controller) {
          if (!streamMeta.assistantProgressed) {
            const userIdToRemove = streamMeta.persistedUserId ?? tempUserId;
            setMessages((prev) =>
              prev.filter(
                (m) =>
                  m.id !== tempUserId &&
                  m.id !== userIdToRemove &&
                  m.id !== tempAssistantId,
              ),
            );
            setDraft((prev) => prev || content);
          } else {
            setMessages((prev) =>
              finalizeIncompleteAssistantMessage(prev, tempAssistantId, 'aborted'),
            );
          }
        }
      } else if (streamAbortRef.current === controller) {
        setError(err instanceof Error ? err.message : 'Failed to send message');
        if (!sseStarted || !streamMeta.assistantProgressed) {
          const userIdToRemove = streamMeta.persistedUserId ?? tempUserId;
          setDraft((prev) => prev || content);
          setMessages((prev) =>
            prev.filter(
              (m) =>
                m.id !== tempUserId &&
                m.id !== userIdToRemove &&
                m.id !== tempAssistantId,
            ),
          );
        } else {
          setMessages((prev) =>
            finalizeIncompleteAssistantMessage(prev, tempAssistantId, 'error'),
          );
        }
      }
    } finally {
      if (activeStreamMetaRef.current === streamMeta) {
        activeStreamMetaRef.current = null;
      }
      if (streamAbortRef.current === controller) {
        streamAbortRef.current = null;
        setActiveAssistantId(null);
        setStreaming(false);
      }
    }
  };

  const handleComposerKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229) {
      return;
    }
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  };

  const activeModelOption = useMemo(
    () => models.find((m) => m.id === selectedModel) ?? null,
    [models, selectedModel],
  );

  const isSelectedModelMissing =
    Boolean(selectedModel) && !models.some((m) => m.id === selectedModel);

  const availableMcpServers = mcpServers.filter((s) => s.enabled);
  const missingSelectedMcpNames = useMemo(
    () =>
      selectedMcpNames.filter(
        (name) => !availableMcpServers.some((s) => s.name === name),
      ),
    [selectedMcpNames, availableMcpServers],
  );

  const resolveProviderType = (modelId?: string): string => {
    const target = modelId || selectedModel;
    if (!target) return 'other';
    const match = models.find((m) => m.id === target);
    return match?.provider_type || match?.provider || target;
  };

  return (
    <div className="ap-chat-shell">
      {railOpen && (
        <>
          <div
            className="ap-chat-rail-backdrop"
            onClick={() => setRailOpen(false)}
            aria-hidden="true"
          />
          <aside className="ap-chat-rail" aria-label="Chat history">
            <div className="ap-chat-rail-head">
              <button
                type="button"
                className="ap-btn ap-btn-sm"
                style={{ flex: 1, justifyContent: 'flex-start', minWidth: 0 }}
                onClick={startNewChat}
              >
                <PlusIcon size={14} />
                <span>New chat</span>
              </button>
              <button
                type="button"
                className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact ap-chat-rail-close"
                onClick={() => setRailOpen(false)}
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
        </>
      )}

      <div className="ap-chat-main">
        <header className="ap-chat-topbar">
          <div className="ap-chat-topbar-left">
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
              className="ap-truncate ap-chat-topbar-title"
              style={{ fontWeight: 600, fontSize: 13.5 }}
            >
              {activeSession ? activeSession.title || 'Untitled chat' : 'New chat'}
            </span>
          </div>

          <div className="ap-chat-topbar-right">
            <div className="ap-chat-model-wrap">
              {(activeModelOption || selectedModel) && (
                <ProviderGlyph type={resolveProviderType(selectedModel)} />
              )}
              <select
                className="ap-select ap-select--sm ap-mono ap-chat-model-select"
                value={selectedModel}
                onChange={(e) => void handleModelChange(e.target.value)}
                aria-label="Select chat model"
              >
                {models.length === 0 && !selectedModel ? (
                  <option value="">No models available</option>
                ) : (
                  <>
                    {isSelectedModelMissing && (
                      <option value={selectedModel}>
                        {selectedModel} (unavailable)
                      </option>
                    )}
                    {models.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.id}
                        {m.is_alias ? ' (route)' : ''}
                      </option>
                    ))}
                  </>
                )}
              </select>
            </div>

            {/* MCP Tools Attach Popover */}
            <div ref={toolsPopoverRef} style={{ position: 'relative', flexShrink: 0 }}>
              <button
                type="button"
                className="ap-btn ap-btn-sm"
                onClick={() => setToolsPopoverOpen((prev) => !prev)}
                aria-expanded={toolsPopoverOpen}
                aria-label="Attach MCP Tools"
              >
                <WrenchIcon size={14} />
                <span className="ap-chat-tools-label">Tools</span>
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

                  {missingSelectedMcpNames.map((missingName) => (
                    <div
                      key={missingName}
                      style={{
                        padding: '8px 8px',
                        borderRadius: 'var(--ap-radius-sm)',
                        background: 'var(--ap-amber-soft)',
                        border: '1px solid var(--ap-amber-border)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 10,
                      }}
                    >
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="ap-mono ap-truncate" style={{ fontWeight: 600, fontSize: 12 }}>
                            {missingName}
                          </span>
                          <span className="ap-badge ap-badge--amber">(unavailable)</span>
                        </div>
                      </div>
                      <Toggle
                        checked
                        onChange={() => void handleToggleMcpServer(missingName, false)}
                        label={`Detach unavailable MCP server ${missingName}`}
                      />
                    </div>
                  ))}

                  {availableMcpServers.length === 0 &&
                  missingSelectedMcpNames.length === 0 ? (
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
              className="ap-btn ap-btn-sm ap-btn-icon-compact"
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

        {error && (
          <div className="ap-chat-error-pin">
            <div
              className="ap-alert ap-alert--danger"
              role="alert"
              style={{
                maxWidth: 780,
                width: '100%',
                margin: '0 auto',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 9, minWidth: 0 }}>
                <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
                <span style={{ wordBreak: 'break-word' }}>{error}</span>
              </div>
              <button
                type="button"
                className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
                onClick={() => setError(null)}
                aria-label="Dismiss error"
              >
                <CloseIcon size={13} />
              </button>
            </div>
          </div>
        )}

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
                  ref={bottomToolsBtnRef}
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
                {missingSelectedMcpNames.map((missingName) => (
                  <button
                    key={missingName}
                    type="button"
                    className="ap-badge ap-badge--amber ap-mono"
                    style={{ cursor: 'pointer' }}
                    title={`Remove unavailable MCP server ${missingName}`}
                    onClick={() => void handleToggleMcpServer(missingName, false)}
                  >
                    <span>{missingName} (unavailable) ×</span>
                  </button>
                ))}
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
                    disabled={
                      !draft.trim() || (models.length === 0 && !selectedModel)
                    }
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
