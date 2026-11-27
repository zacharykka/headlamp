import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { ApiError, api } from './api/client';
import { ChatView } from './views/ChatView';
import { MCPView } from './views/MCPView';

function makeSSEResponse(frames: Array<{ event: string; data: unknown }>): Response {
  const payload = frames
    .map((f) => `event: ${f.event}\ndata: ${JSON.stringify(f.data)}\n\n`)
    .join('');
  const bytes = new TextEncoder().encode(payload);
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream' },
  });
}

describe('Milestone 3: Team Web Chat, Admin MCP Gateway, and API helpers', () => {
  beforeEach(() => {
    window.scrollTo = vi.fn();
  });

  afterEach(() => {
    cleanup();
    document.body.style.overflow = '';
    vi.restoreAllMocks();
  });

  it('streams SSE events in api.streamChatMessage and serializes MCP admin query params', async () => {
    const events: string[] = [];
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        makeSSEResponse([
          {
            event: 'message_start',
            data: {
              user_message: {
                id: 'msg-u1',
                session_id: 'sess-1',
                role: 'user',
                content: 'Search docs',
                created_at: '2026-11-27T05:00:00Z',
              },
              session: {
                id: 'sess-1',
                title: 'Search docs',
                model: 'anthropic/claude-sonnet-4-6',
                mcp_servers: ['docs'],
                created_at: '2026-11-27T05:00:00Z',
                updated_at: '2026-11-27T05:00:00Z',
              },
            },
          },
          {
            event: 'tool_start',
            data: {
              id: 'call-1',
              server: 'docs',
              tool: 'search',
              arguments: { query: 'grants' },
            },
          },
          {
            event: 'tool_result',
            data: {
              id: 'call-1',
              server: 'docs',
              tool: 'search',
              result: '{"hits":2}',
              is_error: false,
              duration_ms: 38,
            },
          },
          {
            event: 'delta',
            data: { text: 'Found **2** matches.' },
          },
          {
            event: 'message_done',
            data: {
              assistant_message: {
                id: 'msg-a1',
                session_id: 'sess-1',
                role: 'assistant',
                content: 'Found **2** matches.',
                model: 'anthropic/claude-sonnet-4-6',
                input_tokens: 120,
                output_tokens: 30,
                cost_usd: 0.0008,
                created_at: '2026-11-27T05:00:01Z',
              },
            },
          },
        ]),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ logs: [] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    await api.streamChatMessage(
      'sess-1',
      { content: 'Search docs', model: 'anthropic/claude-sonnet-4-6', mcp_servers: ['docs'] },
      {
        onMessageStart: () => events.push('start'),
        onToolStart: (t) => events.push(`tool_start:${t.server}/${t.tool}`),
        onToolResult: (t) => events.push(`tool_result:${t.duration_ms}`),
        onDelta: (d) => events.push(`delta:${d.text}`),
        onMessageDone: () => events.push('done'),
      },
    );

    expect(events).toEqual([
      'start',
      'tool_start:docs/search',
      'tool_result:38',
      'delta:Found **2** matches.',
      'done',
    ]);

    await api.listAdminMCPLogs({
      server: 'docs',
      subject: 'alice@tailnet',
      tool: 'search',
      status: 'denied',
      limit: 25,
      offset: 50,
    });

    const mcpUrl = String(fetchSpy.mock.calls[1][0]);
    expect(mcpUrl).toContain('/api/v1/admin/mcp/logs?');
    expect(mcpUrl).toContain('server=docs');
    expect(mcpUrl).toContain('subject=alice%40tailnet');
    expect(mcpUrl).toContain('tool=search');
    expect(mcpUrl).toContain('status=denied');
    expect(mcpUrl).toContain('limit=25');
    expect(mcpUrl).toContain('offset=50');
  });

  it('attaches MCP tools, streams assistant response with collapsible tool card, supports Stop abort, rename, and two-step delete in ChatView', async () => {
    vi.spyOn(api, 'listChatModels').mockResolvedValue([
      {
        id: 'anthropic/claude-sonnet-4-6',
        provider: 'anthropic',
        provider_type: 'anthropic',
        is_alias: false,
      },
    ]);
    vi.spyOn(api, 'listChatMCPServers').mockResolvedValue([
      {
        name: 'docs',
        transport: 'streamable_http',
        enabled: true,
        tools: [{ name: 'search_kb', description: 'Search internal docs' }],
      },
    ]);
    vi.spyOn(api, 'listChatSessions').mockResolvedValue([]);

    const createSessSpy = vi.spyOn(api, 'createChatSession').mockResolvedValue({
      id: 'sess-live',
      title: 'How do grants work?',
      model: 'anthropic/claude-sonnet-4-6',
      mcp_servers: ['docs'],
      created_at: '2026-11-27T05:00:00Z',
      updated_at: '2026-11-27T05:00:00Z',
    });

    const updateSessSpy = vi
      .spyOn(api, 'updateChatSession')
      .mockImplementation(async (id, patch) => ({
        id,
        title: patch.title ?? 'How do grants work?',
        model: patch.model ?? 'anthropic/claude-sonnet-4-6',
        mcp_servers: patch.mcp_servers ?? ['docs'],
        system_prompt: patch.system_prompt ?? '',
        created_at: '2026-11-27T05:00:00Z',
        updated_at: '2026-11-27T05:01:00Z',
      }));

    const deleteSessSpy = vi.spyOn(api, 'deleteChatSession').mockResolvedValue();

    let streamCall = 0;
    let capturedAbortSignal: AbortSignal | undefined;

    vi.spyOn(api, 'streamChatMessage').mockImplementation(
      async (_sessionId, _payload, callbacks, opts) => {
        streamCall += 1;
        if (streamCall === 1) {
          callbacks.onToolStart?.({
            id: 'tc-1',
            server: 'docs',
            tool: 'search_kb',
            arguments: { query: 'headscale grants' },
          });
          callbacks.onToolResult?.({
            id: 'tc-1',
            server: 'docs',
            tool: 'search_kb',
            result: '{"snippet":"[REDACTED:secret] ok"}',
            is_error: false,
            duration_ms: 44,
          });
          callbacks.onDelta?.({ text: 'Use **Headscale** `grants`.' });
          callbacks.onMessageDone?.({
            assistant_message: {
              id: 'asst-1',
              session_id: 'sess-live',
              role: 'assistant',
              content: 'Use **Headscale** `grants`.',
              model: 'anthropic/claude-sonnet-4-6',
              input_tokens: 210,
              output_tokens: 45,
              cost_usd: 0.0014,
              created_at: '2026-11-27T05:00:02Z',
            },
          });
          return;
        }

        // Second stream starts a running tool and stays open until Stop aborts signal
        capturedAbortSignal = opts?.signal;
        callbacks.onToolStart?.({
          id: 'tc-running',
          server: 'docs',
          tool: 'long_scan',
          arguments: {},
        });
        await new Promise<void>((_resolve, reject) => {
          opts?.signal?.addEventListener('abort', () => {
            const abortErr = new Error('Aborted');
            abortErr.name = 'AbortError';
            reject(abortErr);
          });
        });
      },
    );

    render(<ChatView />);

    await waitFor(() => {
      expect(screen.getByDisplayValue(/anthropic\/claude-sonnet-4-6/)).toBeTruthy();
    });

    // Attach MCP server via Tools popover
    fireEvent.click(screen.getByRole('button', { name: 'Attach MCP Tools' }));
    const popover = screen.getByRole('dialog', { name: 'MCP Servers' });
    fireEvent.click(within(popover).getByRole('switch', { name: /Attach MCP server docs/i }));
    fireEvent.keyDown(window, { key: 'Escape' });

    // Safari IME composition keyCode 229 must NOT trigger send (P2-6)
    const input = screen.getByLabelText('Message input');
    fireEvent.change(input, { target: { value: 'How do grants work?' } });
    fireEvent.keyDown(input, { key: 'Enter', keyCode: 229, which: 229 });
    expect(createSessSpy).not.toHaveBeenCalled();

    // Real Enter sends prompt
    fireEvent.keyDown(input, { key: 'Enter', keyCode: 13 });

    await waitFor(() => {
      expect(createSessSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'New Chat',
          model: 'anthropic/claude-sonnet-4-6',
          mcp_servers: ['docs'],
        }),
        expect.objectContaining({ signal: expect.anything() }),
      );
      expect(screen.getByText('docs/search_kb')).toBeTruthy();
      expect(screen.getByText('Headscale')).toBeTruthy();
    });

    // Expand collapsible MCP Tool Call card to inspect arguments & redacted result
    fireEvent.click(screen.getByRole('button', { name: /docs\/search_kb/i }));
    expect(screen.getByText('Tool Arguments')).toBeTruthy();
    expect(screen.getByText('[REDACTED:secret]')).toBeTruthy();

    // Start second stream with an unfinished tool call and click Stop -> aborts signal and marks tool card cancelled (no infinite spinner!)
    fireEvent.change(input, { target: { value: 'Stream forever' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));

    const stopBtn = await screen.findByRole('button', { name: 'Stop generation' });
    expect(screen.getByLabelText('Running tool')).toBeTruthy();
    fireEvent.click(stopBtn);
    await waitFor(() => {
      expect(capturedAbortSignal?.aborted).toBe(true);
      expect(screen.queryByLabelText('Running tool')).toBeNull();
    });

    // Inline session rename
    fireEvent.click(screen.getByRole('button', { name: /Rename How do grants work\?/i }));
    const titleInput = screen.getByLabelText('Session title');
    fireEvent.change(titleInput, { target: { value: 'Tailnet Grants Q&A' } });
    fireEvent.submit(titleInput.closest('form')!);

    await waitFor(() => {
      expect(updateSessSpy).toHaveBeenCalledWith('sess-live', {
        title: 'Tailnet Grants Q&A',
      });
    });

    // Two-step session delete
    fireEvent.click(screen.getByRole('button', { name: 'Delete Tailnet Grants Q&A' }));
    expect(deleteSessSpy).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole('button', { name: 'Confirm delete Tailnet Grants Q&A' }),
    );
    await waitFor(() => {
      expect(deleteSessSpy).toHaveBeenCalledWith('sess-live');
    });
  });

  it('handles pre-SSE draft restore, in-flight createChatSession abort race, unavailable historical model/MCPs, and bottom Attach MCP toggle (P1-5, P2-6)', async () => {
    vi.spyOn(api, 'listChatModels').mockResolvedValue([
      {
        id: 'team/coding',
        provider: 'anthropic-prod',
        provider_type: 'anthropic',
        is_alias: true,
      },
    ]);
    vi.spyOn(api, 'listChatMCPServers').mockResolvedValue([
      { name: 'docs', transport: 'streamable_http', enabled: true, tools: [] },
    ]);
    vi.spyOn(api, 'listChatSessions').mockResolvedValue([
      {
        id: 'sess-legacy',
        title: 'Legacy Session',
        model: 'openai/gpt-4-retired',
        mcp_servers: ['retired-mcp'],
        created_at: '2026-11-26T00:00:00Z',
        updated_at: '2026-11-26T00:00:00Z',
      },
    ]);
    vi.spyOn(api, 'getChatSession').mockResolvedValue({
      session: {
        id: 'sess-legacy',
        title: 'Legacy Session',
        model: 'openai/gpt-4-retired',
        mcp_servers: ['retired-mcp'],
        created_at: '2026-11-26T00:00:00Z',
        updated_at: '2026-11-26T00:00:00Z',
      },
      messages: [],
    });
    const updateSessSpy = vi.spyOn(api, 'updateChatSession').mockResolvedValue({
      id: 'sess-legacy',
      title: 'Legacy Session',
      model: 'openai/gpt-4-retired',
      mcp_servers: [],
      created_at: '2026-11-26T00:00:00Z',
      updated_at: '2026-11-27T00:00:00Z',
    });

    // First createChatSession hangs so we can click New chat mid-flight; second succeeds
    let resolvePendingCreate!: (s: {
      id: string;
      title: string;
      model: string;
      created_at: string;
      updated_at: string;
    }) => void;
    let createCount = 0;
    vi.spyOn(api, 'createChatSession').mockImplementation(() => {
      createCount += 1;
      if (createCount === 1) {
        return new Promise((resolve) => {
          resolvePendingCreate = resolve;
        });
      }
      return Promise.resolve({
        id: 'sess-2',
        title: 'Rate limited prompt',
        model: 'team/coding',
        created_at: '2026-11-27T06:00:00Z',
        updated_at: '2026-11-27T06:00:00Z',
      });
    });

    vi.spyOn(api, 'streamChatMessage').mockRejectedValue(
      new ApiError(429, 'Daily USD budget exceeded'),
    );

    render(<ChatView />);

    await waitFor(() => {
      expect(screen.getByText('Legacy Session')).toBeTruthy();
    });

    // Bottom Attach MCP button opens AND closes cleanly without mousedown reopen race
    const bottomAttachBtn = screen.getByRole('button', { name: /^Attach MCP$/i });
    fireEvent.mouseDown(bottomAttachBtn);
    fireEvent.click(bottomAttachBtn);
    expect(screen.getByRole('dialog', { name: 'MCP Servers' })).toBeTruthy();

    fireEvent.mouseDown(bottomAttachBtn);
    fireEvent.click(bottomAttachBtn);
    expect(screen.queryByRole('dialog', { name: 'MCP Servers' })).toBeNull();

    // Start sending on a new chat, then abort via New chat BEFORE createChatSession resolves
    const input = screen.getByLabelText('Message input') as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: 'Aborted first message' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    fireEvent.click(screen.getByRole('button', { name: /New chat/i }));

    resolvePendingCreate({
      id: 'sess-stale',
      title: 'Stale',
      model: 'team/coding',
      created_at: '2026-11-27T06:00:00Z',
      updated_at: '2026-11-27T06:00:00Z',
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText('Stale')).toBeNull();

    // Pre-SSE HTTP 429 restores draft, removes empty placeholder bubble, and renders pinned alert
    fireEvent.change(input, { target: { value: 'Rate limited prompt' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Daily USD budget exceeded');
    expect(input.value).toBe('Rate limited prompt');

    // Load historical session with unavailable model & MCP server
    fireEvent.click(screen.getByText('Legacy Session'));
    await waitFor(() => {
      expect(
        screen.getByDisplayValue('openai/gpt-4-retired (unavailable)'),
      ).toBeTruthy();
    });
    const detachChip = screen.getByRole('button', {
      name: /retired-mcp \(unavailable\) ×/i,
    });
    fireEvent.click(detachChip);
    await waitFor(() => {
      expect(updateSessSpy).toHaveBeenCalledWith('sess-legacy', {
        mcp_servers: [],
      });
    });
  });

  it('enforces Managed by YAML locks, hides none-auth token preview, opens failed-test diagnostic drawer, and inspects audit logs in MCPView (P2-7, P3-4)', async () => {
    vi.spyOn(api, 'listAdminMCPServers').mockResolvedValue([
      {
        name: 'github-yaml',
        url: 'https://mcp.github.internal/mcp',
        transport: 'streamable_http',
        auth_type: 'bearer',
        auth_header: '',
        has_auth_token: true,
        auth_token_preview: 'ghp_...****',
        enabled: true,
        source: 'config',
        updated_at: '2026-11-27T00:00:00Z',
      },
      {
        name: 'pagerduty-local',
        url: 'https://mcp.pd.internal/sse',
        transport: 'sse',
        auth_type: 'header',
        auth_header: 'X-PD-Token',
        has_auth_token: true,
        auth_token_preview: 'pd_...****',
        enabled: true,
        source: 'local',
        updated_at: '2026-11-27T00:00:00Z',
      },
      {
        name: 'public-docs',
        url: 'https://mcp.docs.internal/mcp',
        transport: 'streamable_http',
        auth_type: 'none',
        auth_header: '',
        has_auth_token: true,
        auth_token_preview: 'stale_...****',
        enabled: true,
        source: 'local',
        updated_at: '2026-11-27T00:00:00Z',
      },
    ]);

    vi.spyOn(api, 'testAdminMCPServer').mockResolvedValueOnce({
      ok: false,
      latency_ms: 8,
      message: 'upstream HTTP 401 Unauthorized',
      tools: [],
    });

    vi.spyOn(api, 'listAdminMCPLogs').mockResolvedValue([
      {
        id: 'mcplog-1',
        created_at: '2026-11-27T04:15:00Z',
        request_id: 'req-mcp-99',
        subject: 'bob@tailnet',
        display_name: 'Bob',
        node_name: 'devbox-01',
        node_ip: '100.64.0.8',
        server_name: 'github-yaml',
        method: 'tools/call',
        tool_name: 'delete_repo',
        status: 'denied',
        latency_ms: 4,
        error_message: 'principal not permitted to invoke github-yaml:delete_repo',
        arguments_preview: '{"repo":"org/core","token":"[REDACTED:secret]"}',
      },
    ]);

    render(<MCPView />);

    await waitFor(() => {
      expect(screen.getByText('github-yaml')).toBeTruthy();
      expect(screen.getByText('bob@tailnet')).toBeTruthy();
    });

    // auth_type === 'none' never renders stale auth_token_preview (P3-4)
    expect(screen.queryByText('stale_...****')).toBeNull();
    expect(screen.getByText('ghp_...****')).toBeTruthy();

    // YAML-managed server locks Edit, Toggle, and Delete
    expect(screen.getByText('Managed by YAML')).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Edit github-yaml' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole('switch', {
          name: 'Enable MCP server github-yaml',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);

    // Local server allows Edit and exposes clear_auth_token toggle
    fireEvent.click(screen.getByRole('button', { name: 'Edit pagerduty-local' }));
    const editDialog = screen.getByRole('dialog', {
      name: /Edit MCP Server \(pagerduty-local\)/i,
    });
    expect(
      within(editDialog).getByRole('switch', { name: 'Clear stored auth token' }),
    ).toBeTruthy();

    fireEvent.change(within(editDialog).getByLabelText(/Custom Header Name/i), {
      target: { value: '   ' },
    });
    fireEvent.click(within(editDialog).getByRole('button', { name: /Save MCP Server/i }));
    const alert = await within(editDialog).findByRole('alert');
    expect(alert.textContent).toContain(
      'Header name is required when auth_type is "header"',
    );
    fireEvent.click(within(editDialog).getByRole('button', { name: /Cancel/i }));

    // Failed Test (ok: false, tools: []) still opens Discovery Drawer with diagnostic alert (P2-7)
    const testButtons = screen.getAllByRole('button', { name: /^Test$/i });
    fireEvent.click(testButtons[0]);
    const discoveryDrawer = await screen.findByRole('dialog', {
      name: /MCP Discovery · github-yaml/i,
    });
    expect(within(discoveryDrawer).getByText('Failed')).toBeTruthy();
    expect(
      within(discoveryDrawer).getAllByText(/upstream HTTP 401 Unauthorized/i).length,
    ).toBeGreaterThan(0);
    fireEvent.click(within(discoveryDrawer).getByRole('button', { name: 'Close' }));

    // Click MCP Audit Log row -> opens Call Inspector Drawer with redaction highlight
    fireEvent.click(screen.getByText('bob@tailnet'));
    const callDrawer = await screen.findByRole('dialog', {
      name: /MCP Call · github-yaml\/delete_repo/i,
    });
    expect(
      within(callDrawer).getByText(
        /principal not permitted to invoke github-yaml:delete_repo/i,
      ),
    ).toBeTruthy();
    expect(within(callDrawer).getByText('[REDACTED:secret]')).toBeTruthy();
  });

  it('defaults non-admin users to Team Chat with 2-item nav and renders MCP Clients tab in Quickstart', async () => {
    vi.spyOn(api, 'getMe').mockResolvedValue({
      principal: {
        subject: 'dev@tailnet',
        display_name: 'Dev User',
        node_name: 'thinkpad',
        node_ip: '100.64.0.22',
        auth_source: 'tailnet',
      },
      is_admin: false,
      policy: {
        subject: 'dev@tailnet',
        roles: ['user'],
        allow_models: ['anthropic/claude-sonnet-4-6'],
        grants_applied: true,
      },
      budget_status: [],
    });
    vi.spyOn(api, 'listChatModels').mockResolvedValue([
      {
        id: 'anthropic/claude-sonnet-4-6',
        provider: 'anthropic',
        provider_type: 'anthropic',
        is_alias: false,
      },
    ]);
    vi.spyOn(api, 'listChatMCPServers').mockResolvedValue([
      { name: 'k8s-cluster', transport: 'streamable_http', enabled: true, tools: [] },
    ]);
    vi.spyOn(api, 'listChatSessions').mockResolvedValue([]);
    vi.spyOn(api, 'getMeUsage').mockResolvedValue({
      summary: {
        request_count: 0,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
        cost_usd: 0,
      },
      series: [],
      logs: [],
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByLabelText('Message input')).toBeTruthy();
    });
    const nav = screen.getByRole('navigation');
    expect(within(nav).getByRole('button', { name: /Team Chat/i })).toBeTruthy();
    expect(within(nav).getByRole('button', { name: /My Usage & SDKs/i })).toBeTruthy();
    expect(within(nav).queryByText(/Administration/i)).toBeNull();

    fireEvent.click(within(nav).getByRole('button', { name: /My Usage & SDKs/i }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Quickstart & My Usage' })).toBeTruthy();
    });

    fireEvent.click(screen.getByRole('tab', { name: 'MCP Clients' }));
    await waitFor(() => {
      expect(screen.getByText(/claude mcp add --transport http k8s-cluster/)).toBeTruthy();
      expect(screen.getByText(/\/mcp\/k8s-cluster/)).toBeTruthy();
    });
  });

  it('never leaks raw secret into createChatSession title and removes unpersisted or rolled-back user bubbles on SSE error (#148 P1-3)', async () => {
    vi.spyOn(api, 'listChatModels').mockResolvedValue([
      {
        id: 'anthropic/claude-sonnet-4-6',
        provider: 'anthropic',
        provider_type: 'anthropic',
        is_alias: false,
      },
    ]);
    vi.spyOn(api, 'listChatMCPServers').mockResolvedValue([]);
    vi.spyOn(api, 'listChatSessions').mockResolvedValue([]);

    const createSessSpy = vi.spyOn(api, 'createChatSession').mockResolvedValue({
      id: 'sess-safe',
      title: 'New Chat',
      model: 'anthropic/claude-sonnet-4-6',
      created_at: '2026-11-27T08:30:00Z',
      updated_at: '2026-11-27T08:30:00Z',
    });

    let callIdx = 0;
    vi.spyOn(api, 'streamChatMessage').mockImplementation(
      async (_sessionId, _payload, callbacks) => {
        callIdx += 1;
        if (callIdx === 1) {
          // Case 1: Pre-persist guardrail block emits SSE error BEFORE message_start
          callbacks.onError?.({
            type: 'guardrail_blocked',
            message: 'Request blocked by guardrail private_key',
          });
          return;
        }
        // Case 2: Round-0 message_start followed by upstream error (rolled back by backend before any delta/tool)
        callbacks.onMessageStart?.({
          user_message: {
            id: 'msg-rolled-back',
            session_id: 'sess-safe',
            role: 'user',
            content: 'Retry normal question',
            created_at: '2026-11-27T08:31:00Z',
          },
          session: {
            id: 'sess-safe',
            title: 'Retry normal question',
            model: 'anthropic/claude-sonnet-4-6',
            created_at: '2026-11-27T08:30:00Z',
            updated_at: '2026-11-27T08:31:00Z',
          },
        });
        callbacks.onError?.({
          type: 'upstream_error',
          message: 'Upstream 429 rate limit',
        });
      },
    );

    const { container } = render(<ChatView />);

    await waitFor(() => {
      expect(screen.getByDisplayValue(/anthropic\/claude-sonnet-4-6/)).toBeTruthy();
    });

    const pemSecret = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecret';
    const input = screen.getByLabelText('Message input') as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: pemSecret } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));

    const blockAlert = await screen.findByRole('alert');
    expect(blockAlert.textContent).toContain('Request blocked by guardrail private_key');

    // 1. Session was created with 'New Chat', NEVER with the raw PEM private key!
    expect(createSessSpy).toHaveBeenCalledTimes(1);
    expect(createSessSpy.mock.calls[0][0].title).toBe('New Chat');

    // 2. Blocked user bubble is removed from the thread and draft is restored for editing
    expect(container.querySelector('.ap-chat-msg-user')).toBeNull();
    expect(container.querySelector('.ap-chat-msg-assistant')).toBeNull();
    expect(input.value).toBe(pemSecret);

    // 3. Round-0 rolled-back message_start + error also removes the rolled-back user bubble
    fireEvent.change(input, { target: { value: 'Retry normal question' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));

    await waitFor(() => {
      expect(screen.getByRole('alert').textContent).toContain('Upstream 429 rate limit');
    });
    expect(container.querySelector('.ap-chat-msg-user')).toBeNull();
    expect(container.querySelector('.ap-chat-msg-assistant')).toBeNull();
  });
});
