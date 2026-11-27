import type { RefObject } from 'react';
import {
  ProviderGlyph,
  SidebarToggleIcon,
  SlidersIcon,
  WrenchIcon,
} from '../../components/ApertureIcons';
import { Toggle } from '../../components/Primitives';
import type {
  ChatMCPServerOption,
  ChatModelOption,
  ChatSession,
} from '../../types/api';

interface ChatTopbarProps {
  railOpen: boolean;
  onToggleRail: () => void;
  activeSession: ChatSession | null;
  models: ChatModelOption[];
  selectedModel: string;
  activeModelOption: ChatModelOption | null;
  isSelectedModelMissing: boolean;
  resolveProviderType: (modelId?: string) => string;
  onModelChange: (nextModel: string) => void;
  toolsPopoverOpen: boolean;
  onToggleToolsPopover: () => void;
  toolsPopoverRef: RefObject<HTMLDivElement | null>;
  availableMcpServers: ChatMCPServerOption[];
  missingSelectedMcpNames: string[];
  selectedMcpNames: string[];
  onToggleMcpServer: (name: string, enabled: boolean) => void;
  systemPrompt: string;
  onOpenSystemPrompt: () => void;
}

export function ChatTopbar({
  railOpen,
  onToggleRail,
  activeSession,
  models,
  selectedModel,
  activeModelOption,
  isSelectedModelMissing,
  resolveProviderType,
  onModelChange,
  toolsPopoverOpen,
  onToggleToolsPopover,
  toolsPopoverRef,
  availableMcpServers,
  missingSelectedMcpNames,
  selectedMcpNames,
  onToggleMcpServer,
  systemPrompt,
  onOpenSystemPrompt,
}: ChatTopbarProps) {
  return (
    <header className="ap-chat-topbar">
      <div className="ap-chat-topbar-left">
        <button
          type="button"
          className="ap-btn ap-btn-ghost ap-btn-sm ap-btn-icon-compact"
          onClick={onToggleRail}
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
            onChange={(e) => onModelChange(e.target.value)}
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
            onClick={onToggleToolsPopover}
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
                    onChange={() => onToggleMcpServer(missingName, false)}
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
                        onChange={(next) => onToggleMcpServer(srv.name, next)}
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
          onClick={onOpenSystemPrompt}
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
  );
}
