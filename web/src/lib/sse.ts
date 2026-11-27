export interface SSEEventFrame {
  event: string;
  data: string;
}

/**
 * Chunk-boundary-safe Server-Sent Events (SSE) incremental parser.
 * Handles arbitrary UTF-8 stream splits, \r\n or \n line endings, and multi-line data fields.
 */
export class SSEParser {
  private buffer = '';

  feed(chunk: string): SSEEventFrame[] {
    this.buffer += chunk;
    const frames: SSEEventFrame[] = [];

    while (true) {
      const match = /\r?\n\r?\n/.exec(this.buffer);
      if (!match) break;

      const rawBlock = this.buffer.slice(0, match.index);
      this.buffer = this.buffer.slice(match.index + match[0].length);

      const parsed = parseSSEBlock(rawBlock);
      if (parsed) {
        frames.push(parsed);
      }
    }

    return frames;
  }

  flush(): SSEEventFrame[] {
    const rest = this.buffer.trim();
    this.buffer = '';
    if (!rest) return [];
    const parsed = parseSSEBlock(rest);
    return parsed ? [parsed] : [];
  }
}

function parseSSEBlock(block: string): SSEEventFrame | null {
  if (!block.trim()) return null;
  const lines = block.split(/\r?\n/);
  let eventName = 'message';
  const dataLines: string[] = [];

  for (const line of lines) {
    if (!line || line.startsWith(':')) continue;
    const colonIdx = line.indexOf(':');
    const field = colonIdx === -1 ? line : line.slice(0, colonIdx);
    let value = colonIdx === -1 ? '' : line.slice(colonIdx + 1);
    if (value.startsWith(' ')) {
      value = value.slice(1);
    }

    if (field === 'event') {
      eventName = value.trim() || 'message';
    } else if (field === 'data') {
      dataLines.push(value);
    }
  }

  if (dataLines.length === 0) return null;
  return {
    event: eventName,
    data: dataLines.join('\n'),
  };
}

export async function consumeSSEStream(
  stream: ReadableStream<Uint8Array>,
  onFrame: (frame: SSEEventFrame) => void,
): Promise<void> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  const parser = new SSEParser();

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const text = decoder.decode(value, { stream: true });
      for (const frame of parser.feed(text)) {
        onFrame(frame);
      }
    }
    const tail = decoder.decode();
    if (tail) {
      for (const frame of parser.feed(tail)) {
        onFrame(frame);
      }
    }
    for (const frame of parser.flush()) {
      onFrame(frame);
    }
  } finally {
    reader.releaseLock();
  }
}
