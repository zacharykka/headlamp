import { describe, expect, it } from 'vitest';
import { SSEParser, consumeSSEStream, type SSEEventFrame } from './sse';

describe('SSEParser and consumeSSEStream', () => {
  it('parses named events, default message events, comments, and CRLF boundaries across arbitrary splits', () => {
    const parser = new SSEParser();

    const chunks = [
      ': keepalive\r\n\r\n',
      'event: message_start\r\ndata: {"id":"1"',
      ',"role":"user"}\r\n\r',
      '\nevent: delta\ndata: {"text":"Hel',
      'lo"}\n\ndata: plain-first-line\ndata: plain-second-line\n\n',
    ];

    const frames: SSEEventFrame[] = [];
    for (const chunk of chunks) {
      frames.push(...parser.feed(chunk));
    }
    frames.push(...parser.flush());

    expect(frames).toEqual([
      { event: 'message_start', data: '{"id":"1","role":"user"}' },
      { event: 'delta', data: '{"text":"Hello"}' },
      { event: 'message', data: 'plain-first-line\nplain-second-line' },
    ]);
  });

  it('flushes trailing frame when stream closes without double newline', () => {
    const parser = new SSEParser();
    expect(parser.feed('event: message_done\ndata: {"ok":true}')).toEqual([]);
    expect(parser.flush()).toEqual([
      { event: 'message_done', data: '{"ok":true}' },
    ]);
  });

  it('decodes split multi-byte UTF-8 byte sequences cleanly in consumeSSEStream', async () => {
    const payload =
      'event: delta\ndata: {"text":"Tailnet 🚀 网关"}\n\nevent: message_done\ndata: {"done":true}\n\n';
    const bytes = new TextEncoder().encode(payload);

    // Split right inside multi-byte UTF-8 characters
    const slices: Uint8Array[] = [];
    for (let i = 0; i < bytes.length; i += 5) {
      slices.push(bytes.slice(i, i + 5));
    }

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const slice of slices) {
          controller.enqueue(slice);
        }
        controller.close();
      },
    });

    const received: SSEEventFrame[] = [];
    await consumeSSEStream(stream, (frame) => received.push(frame));

    expect(received).toEqual([
      { event: 'delta', data: '{"text":"Tailnet 🚀 网关"}' },
      { event: 'message_done', data: '{"done":true}' },
    ]);
  });
});
