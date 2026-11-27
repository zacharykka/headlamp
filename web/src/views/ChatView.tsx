import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import { api } from '../api/client';
import { AlertIcon, CloseIcon } from '../components/ApertureIcons';
import type {
  ChatMCPServerOption,
  ChatMessage,
  ChatModelOption,
  ChatSession,
} from '../types/api';
import { ChatComposer } from './chat/ChatComposer';
import { ChatSidebar } from './chat/ChatSidebar';
import { ChatThread } from './chat/ChatThread';
import { ChatTopbar } from './chat/ChatTopbar';
import {
  finalizeIncompleteAssistantMessage,
  type ActiveStreamMeta,
} from './chat/ToolEventCard';

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

  const [isRenamingSession, setIsRenamingSession] = useState(false);

  // MCP tools popover & System prompt modal
  const [toolsPopoverOpen, setToolsPopoverOpen] = useState(false);
  const toolsPopoverRef = useRef<HTMLDivElement | null>(null);
  const bottomToolsBtnRef = useRef<HTMLButtonElement | null>(null);
  const [sysModalOpen, setSysModalOpen] = useState(false);

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
        !isRenamingSession
      ) {
        setRailOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [railOpen, toolsPopoverOpen, sysModalOpen, isRenamingSession]);

  useEffect(() => {
    const el = threadScrollRef.current;
    if (!el || !stickToBottomRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [messages]);

  const activeSession = useMemo(
    () => sessions.find((s) => s.id === activeSessionId) ?? null,
    [sessions, activeSessionId],
  );

  const rollbackOrFinalizeStream = (
    meta: ActiveStreamMeta,
    reason: 'aborted' | 'error',
    restoreDraft: boolean,
  ) => {
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
        finalizeIncompleteAssistantMessage(prev, meta.tempAssistantId, reason),
      );
    }
  };

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
      rollbackOrFinalizeStream(meta, 'aborted', restoreDraft);
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

  const handleSaveSystemPrompt = async (nextPrompt: string) => {
    if (!activeSessionId) {
      setSystemPrompt(nextPrompt);
      return;
    }
    const updated = await api.updateChatSession(activeSessionId, {
      system_prompt: nextPrompt,
    });
    setSystemPrompt(updated.system_prompt || '');
    setSessions((prev) =>
      prev.map((s) => (s.id === updated.id ? updated : s)),
    );
  };

  const handleRenameSession = async (sessionId: string, title: string) => {
    try {
      const updated = await api.updateChatSession(sessionId, { title });
      setSessions((prev) =>
        prev.map((s) => (s.id === updated.id ? updated : s)),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to rename session');
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
            setError(errEvt.message || 'Stream error');
            rollbackOrFinalizeStream(streamMeta, 'error', true);
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
      if (streamAbortRef.current === controller) {
        if (!isAbort) {
          setError(err instanceof Error ? err.message : 'Failed to send message');
        }
        rollbackOrFinalizeStream(streamMeta, isAbort ? 'aborted' : 'error', true);
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
        <ChatSidebar
          sessions={sessions}
          activeSessionId={activeSessionId}
          onNewChat={startNewChat}
          onSelectSession={(sess) => void selectSession(sess)}
          onRenameSession={handleRenameSession}
          onDeleteSession={handleDeleteSession}
          onClose={() => setRailOpen(false)}
          onRenamingChange={setIsRenamingSession}
        />
      )}

      <div className="ap-chat-main">
        <ChatTopbar
          railOpen={railOpen}
          onToggleRail={() => setRailOpen((prev) => !prev)}
          activeSession={activeSession}
          models={models}
          selectedModel={selectedModel}
          activeModelOption={activeModelOption}
          isSelectedModelMissing={isSelectedModelMissing}
          resolveProviderType={resolveProviderType}
          onModelChange={(next) => void handleModelChange(next)}
          toolsPopoverOpen={toolsPopoverOpen}
          onToggleToolsPopover={() => setToolsPopoverOpen((prev) => !prev)}
          toolsPopoverRef={toolsPopoverRef}
          availableMcpServers={availableMcpServers}
          missingSelectedMcpNames={missingSelectedMcpNames}
          selectedMcpNames={selectedMcpNames}
          onToggleMcpServer={(name, enabled) =>
            void handleToggleMcpServer(name, enabled)
          }
          systemPrompt={systemPrompt}
          onOpenSystemPrompt={() => setSysModalOpen(true)}
        />

        <ChatThread
          threadScrollRef={threadScrollRef}
          onScroll={() => {
            const el = threadScrollRef.current;
            if (!el) return;
            stickToBottomRef.current =
              el.scrollHeight - el.scrollTop - el.clientHeight < 72;
          }}
          loadingThread={loadingThread}
          messages={messages}
          streaming={streaming}
          activeAssistantId={activeAssistantId}
          resolveProviderType={resolveProviderType}
        />

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

        <ChatComposer
          draft={draft}
          onDraftChange={setDraft}
          onKeyDown={handleComposerKeyDown}
          streaming={streaming}
          onSend={() => void handleSend()}
          onStopStreaming={() => abortActiveStream({ restoreDraft: true })}
          modelsCount={models.length}
          selectedModel={selectedModel}
          selectedMcpNames={selectedMcpNames}
          missingSelectedMcpNames={missingSelectedMcpNames}
          onToggleMcpServer={(name, enabled) =>
            void handleToggleMcpServer(name, enabled)
          }
          onToggleToolsPopover={() => setToolsPopoverOpen((prev) => !prev)}
          bottomToolsBtnRef={bottomToolsBtnRef}
          systemPrompt={systemPrompt}
          onOpenSystemPrompt={() => setSysModalOpen(true)}
          sysModalOpen={sysModalOpen}
          onCloseSysModal={() => setSysModalOpen(false)}
          onSaveSystemPrompt={handleSaveSystemPrompt}
        />
      </div>
    </div>
  );
}
