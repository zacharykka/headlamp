# LLM Providers Wire Format, Streaming SSE & Cross-Protocol Translation Spec

**English** | [简体中文](./providers_sse.zh-CN.md)

Implementation reference for Headlamp `internal/proxy`, `internal/translate`, and `internal/metering`.

---

## 1. Universal SSE & Metering Invariants

1. **HTTP Headers on Proxied SSE Responses**:
   - `Content-Type: text/event-stream`
   - `Cache-Control: no-cache`
   - `X-Accel-Buffering: no`
   - Never apply `http.Server.WriteTimeout` blindly to long-lived streams; flush after every upstream chunk via `http.Flusher`.
2. **SSE Framing Parser**:
   - Accept both `\r\n` and `\n` line endings.
   - Ignore comment lines starting with `:` and keepalive blank lines.
   - An event consists of optional `event: <name>` and one or more `data: <payload>` lines (joined with `\n`), terminated by an empty line.
   - **Buffer Size Gotcha**: Do **not** use default `bufio.Scanner` (64 KiB max token). Tool calls, base64 images, extended thinking blocks, and OpenAI `response.completed` envelopes regularly exceed 64 KiB. Use `bufio.Reader.ReadBytes('\n')` or a scanner with max buffer >= 8 MiB.
3. **Stream Disconnects & Async Metering**:
   - Once HTTP `200 OK` is written, mid-stream failures arrive as SSE `error` frames or premature EOF.
   - Always record usage asynchronously with a detached context (`context.Background()` + short timeout) on stream completion or client abort so `usage_logs` still captures partial/final usage.
4. **Token Accounting Normalization Matrix (CRITICAL)**:

| Provider / Endpoint | `input` field includes cache? | `output` field includes reasoning? | Normalized Billable Math |
| :--- | :--- | :--- | :--- |
| **OpenAI Chat** (`/v1/chat/completions`) | **YES** (`prompt_tokens` includes `cached_tokens`) | **YES** (`completion_tokens` includes `reasoning_tokens`) | `uncached_in = max(0, prompt_tokens - cached_tokens)`<br>`cache_read = cached_tokens`, `cache_write = 0`<br>`out = completion_tokens` (`reasoning = reasoning_tokens`, informational) |
| **OpenAI Responses** (`/v1/responses`) | **YES** (`input_tokens` includes `cached_tokens`) | **YES** (`output_tokens` includes `reasoning_tokens`) | `uncached_in = max(0, input_tokens - cached_tokens)`<br>`cache_read = cached_tokens`, `cache_write = 0`<br>`out = output_tokens` (`reasoning = reasoning_tokens`, informational) |
| **Anthropic Messages** (`/v1/messages`) | **NO** (`input_tokens` EXCLUDES cache read & write!) | **YES** (`output_tokens` includes thinking tokens) | `uncached_in = input_tokens`<br>`cache_read = cache_read_input_tokens`<br>`cache_write = cache_creation_input_tokens` (or split `5m` / `1h`)<br>`out = output_tokens` |
| **Google Gemini** (`:generateContent` / `:streamGenerateContent`) | **YES** (`promptTokenCount` includes `cachedContentTokenCount`) | **NO** (`candidatesTokenCount` EXCLUDES `thoughtsTokenCount`!) | `uncached_in = max(0, promptTokenCount - cachedContentTokenCount)`<br>`cache_read = cachedContentTokenCount`, `cache_write = 0`<br>`out = candidatesTokenCount + thoughtsTokenCount`<br>`reasoning = thoughtsTokenCount` |
| **Ollama** (`/v1/chat/completions` & `/api/chat`) | N/A (`0` cache) | Included in `completion_tokens` / `eval_count` | `uncached_in = prompt_tokens` (or `prompt_eval_count`)<br>`out = completion_tokens` (or `eval_count`) |

> **Cost Formula**:
> `cost_usd = (uncached_in * price.input + cache_read * price.cache_read + cache_write_5m * price.cache_write + cache_write_1h * price.cache_write_1h + out * price.output) / 1_000_000`

---

## 2. Provider Reference

### 2.1 OpenAI

* **Default Upstream Base URL**: `https://api.openai.com`
* **Headlamp Routes**: `/v1/...` and `/openai/v1/...`
* **Endpoints**:
  * `POST /v1/chat/completions`
  * `POST /v1/responses`
  * `POST /v1/embeddings`
  * `GET /v1/models`
* **Auth & Forwarded Headers**:
  * Managed mode: strip client `Authorization`, set `Authorization: Bearer <UPSTREAM_KEY>`.
  * Passthrough mode: forward client `Authorization` verbatim.
  * Optional headers to forward if present: `OpenAI-Organization`, `OpenAI-Project`, `OpenAI-Beta`.

#### A. Chat Completions (`POST /v1/chat/completions`)

* **Streaming Request Gotcha (`stream_options`)**:
  * When `"stream": true`, OpenAI **omits** `usage` unless `"stream_options": {"include_usage": true}` is set.
  * For OpenAI-compatible upstreams, Headlamp should inject `"stream_options": {"include_usage": true}` if `"stream": true` and `stream_options` is absent.
  * Track whether the client originally requested `include_usage`: if not, you may optionally omit forwarding the trailing empty-choices usage chunk to strict legacy clients (modern OpenAI SDKs, Cursor, and Codex handle `choices: []` cleanly).
* **SSE Wire Format**:
  * No `event:` line; every frame is `data: <JSON>\n\n`, terminated by `data: [DONE]\n\n`.
  * Content chunk:
    ```text
    data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1740000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"},"finish_reason":null}],"usage":null}

    ```
  * Tool call streaming chunk (arguments arrive incrementally as JSON string fragments):
    ```text
    data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1740000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}

    data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1740000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"SF\"}"}}]},"finish_reason":null}]}

    ```
  * Finish chunk: `choices[0].finish_reason` is `"stop" | "length" | "tool_calls" | "content_filter"`.
  * Final usage-only chunk (before `[DONE]`): **`choices` is empty `[]`** (guard against `choices[0]` out-of-bounds!).
    ```json
    {
      "id": "chatcmpl-123",
      "object": "chat.completion.chunk",
      "created": 1740000000,
      "model": "gpt-4o",
      "choices": [],
      "usage": {
        "prompt_tokens": 2500,
        "completion_tokens": 300,
        "total_tokens": 2800,
        "prompt_tokens_details": {
          "cached_tokens": 2000,
          "audio_tokens": 0
        },
        "completion_tokens_details": {
          "reasoning_tokens": 0,
          "audio_tokens": 0,
          "accepted_prediction_tokens": 0,
          "rejected_prediction_tokens": 0
        }
      }
    }
    ```
  * Sentinel: `data: [DONE]\n\n`

#### B. Responses API (`POST /v1/responses`)

* **Streaming**: Enabled with `"stream": true`. Always includes final `usage` in `response.completed` (no `stream_options` needed).
* **SSE Wire Format**: Uses BOTH `event: <type>` and `data: {"type":"<type>","sequence_number":N,...}`. Ends after terminal lifecycle event (no `[DONE]`).
* **Key Lifecycle Events**:
  * `response.created`, `response.in_progress`
  * `response.output_item.added`, `response.content_part.added`
  * `response.output_text.delta` (`delta` string), `response.output_text.done`
  * `response.function_call_arguments.delta`, `response.function_call_arguments.done`
  * `response.reasoning_summary_text.delta`
  * `response.output_item.done`
  * Terminal: `response.completed`, `response.incomplete`, `response.failed`
  * Out-of-band stream error: `event: error`
* **Usage Schema (in `response.completed` / `response.incomplete` and non-streaming top-level `.usage`)**:
  ```text
  event: response.completed
  data: {"type":"response.completed","sequence_number":42,"response":{"id":"resp_123","object":"response","status":"completed","model":"gpt-5","output":[...],"usage":{"input_tokens":2500,"input_tokens_details":{"cached_tokens":2000},"output_tokens":3300,"output_tokens_details":{"reasoning_tokens":3000},"total_tokens":5800}}}

  ```
  * Extract usage from `event.response.usage` (when `event.type == "response.completed"` or `"response.incomplete"`).

#### C. OpenAI Error Response Schema

```json
{
  "error": {
    "message": "Human-readable description",
    "type": "invalid_request_error",
    "param": null,
    "code": "model_not_found"
  }
}
```

| HTTP | `error.type` | `error.code` | Use in Headlamp |
| :--- | :--- | :--- | :--- |
| `400` | `invalid_request_error` | `invalid_request` / `guardrail_blocked` | Bad payload or guardrail block |
| `401` | `authentication_error` | `invalid_api_key` | Missing/invalid identity or fallback token |
| `403` | `permission_error` | `model_not_allowed` | Policy/grants model deny |
| `404` | `invalid_request_error` | `model_not_found` | Unknown route/model |
| `429` | `requests` / `insufficient_quota` | `rate_limit_exceeded` / `insufficient_quota` | RPM/TPM or budget exceeded |
| `502`/`503` | `server_error` | `upstream_error` | Upstream failure |

Mid-stream Responses SSE error frame:
```text
event: error
data: {"type":"error","code":"server_error","message":"...","param":null}

```

---

### 2.2 Anthropic Messages API

* **Default Upstream Base URL**: `https://api.anthropic.com`
* **Headlamp Routes**: `/anthropic/v1/messages`, `/anthropic/v1/messages/count_tokens`, `/anthropic/v1/models`
* **Auth & Required Headers**:
  * `x-api-key: <UPSTREAM_KEY>` (in managed mode, strip both client `x-api-key` and `Authorization`; in passthrough mode, preserve whichever of `x-api-key` or `Authorization: Bearer ...` the client sent, e.g. Claude Code OAuth).
  * `anthropic-version: 2023-06-01` (required; preserve client header if present, default `"2023-06-01"` when translating).
  * `anthropic-beta`: comma-separated feature flags — **must be forwarded untouched** on native passthrough! Common values:
    * `prompt-caching-2024-07-31`
    * `extended-cache-ttl-2025-04-11` (1-hour ephemeral cache TTL)
    * `interleaved-thinking-2025-05-14`
    * `fine-grained-tool-streaming-2025-05-14`
    * `context-1m-2025-08-07`
    * `oauth-2025-04-20`
* **SSE Wire Format**:
  * Every event has `event: <type>\ndata: {"type":"<type>",...}\n\n`. Ends on `event: message_stop` (no `[DONE]`).
  * Strict lifecycle order (interspersed with optional `event: ping` `{"type":"ping"}`):
    1. `message_start` — empty `message.content: []`, initial `message.usage` (contains `input_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, optional `cache_creation`, initial `output_tokens`).
    2. `content_block_start` — declares `index` and `content_block`:
       * Text: `{"type":"text","text":""}`
       * Tool use: `{"type":"tool_use","id":"toolu_...","name":"get_weather","input":{}}`
       * Extended thinking: `{"type":"thinking","thinking":""}`
       * Redacted thinking: `{"type":"redacted_thinking","data":"<opaque_blob>"}` (no deltas)
    3. `content_block_delta` — incremental updates for `index`:
       * Text: `{"type":"text_delta","text":"Hello"}`
       * Tool arguments: `{"type":"input_json_delta","partial_json":"{\"city\":"}`
       * Thinking text: `{"type":"thinking_delta","thinking":"Let me check..."}`
       * Thinking signature: `{"type":"signature_delta","signature":"<opaque_sig>"}` (**must never be dropped or mutated**; required for multi-turn verification)
    4. `content_block_stop` — `{"type":"content_block_stop","index":0}`
    5. `message_delta` — `delta: {"stop_reason":"end_turn"|"max_tokens"|"stop_sequence"|"tool_use"|"pause_turn"|"refusal","stop_sequence":null}` and cumulative `usage`.
    6. `message_stop` — `{"type":"message_stop"}`

* **Usage JSON & Cumulative Gotcha**:
  ```text
  event: message_start
  data: {"type":"message_start","message":{"id":"msg_01...","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-6","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":342,"cache_creation_input_tokens":400,"cache_read_input_tokens":1800,"cache_creation":{"ephemeral_5m_input_tokens":400,"ephemeral_1h_input_tokens":0},"output_tokens":1}}}

  event: message_delta
  data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":145}}
  ```
  * **CRITICAL Gotcha 1 (Cumulative, NOT Additive)**: `message_delta.usage` reports **cumulative** totals (`output_tokens`, and on newer snapshots may also repeat cumulative `input_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`). Always overwrite non-zero fields (take latest/max), **never add** `message_start` and `message_delta` counts together!
  * **CRITICAL Gotcha 2 (Exclusive Input)**: `input_tokens` excludes both `cache_creation_input_tokens` and `cache_read_input_tokens`. Total prompt tokens = `input_tokens + cache_creation_input_tokens + cache_read_input_tokens`.
  * **CRITICAL Gotcha 3 (5m vs 1h Cache Write)**: If `usage.cache_creation` is present, price `ephemeral_5m_input_tokens` at `cache_write` (1.25× input) and `ephemeral_1h_input_tokens` at `cache_write_1h` (2.0× input); otherwise price all `cache_creation_input_tokens` at `cache_write` (5m rate).

* **Anthropic Error Response Schema**:
  ```json
  {
    "type": "error",
    "error": {
      "type": "rate_limit_error",
      "message": "Rate limit or budget exceeded."
    },
    "request_id": "req_headlamp_..."
  }
  ```
  * Status mapping: `400` `invalid_request_error`, `401` `authentication_error`, `403` `permission_error`, `404` `not_found_error`, `413` `request_too_large`, `429` `rate_limit_error`, `500` `api_error`, `529` `overloaded_error`.
  * Mid-stream error frame: `event: error\ndata: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}\n\n`.

---

### 2.3 Google Gemini API

* **Default Upstream Base URL**: `https://generativelanguage.googleapis.com`
* **Headlamp Routes**:
  * Non-streaming: `POST /gemini/v1beta/models/{model}:generateContent`
  * Streaming SSE: `POST /gemini/v1beta/models/{model}:streamGenerateContent?alt=sse`
  * Models list: `GET /gemini/v1beta/models`
* **Model Extraction Gotcha**: The model ID lives in the **URL path**, NOT the JSON body! Parse `{model}` from `/v1beta/models/{model}:{action}` (strip leading `models/` and trailing `:{action}`) for routing, policy checks, and metering.
* **Auth**:
  * Preferred header: `x-goog-api-key: <UPSTREAM_KEY>`.
  * Managed mode: strip client `x-goog-api-key` AND strip any `?key=...` query parameter before forwarding, then set `x-goog-api-key`.
  * Passthrough mode: preserve client `x-goog-api-key` or `?key=...`.
* **Streaming Wire Format**:
  * With `?alt=sse`: standard SSE `data: <GenerateContentResponse JSON>\n\n` (no `event:` line, no `[DONE]`; ends on EOF after final chunk containing `candidates[0].finishReason` such as `"STOP"`, `"MAX_TOKENS"`, `"SAFETY"`, `"RECITATION"`).
  * Without `?alt=sse`: Gemini streams a JSON array `[{...},\n{...}]`. Native passthrough forwards bytes untouched; the metering tap should detect whether `alt=sse` is present (parse SSE `data:` lines) or fallback to streaming `json.Decoder` array elements.
* **Usage Fields (`usageMetadata`)**:
  ```json
  {
    "candidates": [
      {
        "content": {"role": "model", "parts": [{"text": "Answer..."}]},
        "finishReason": "STOP"
      }
    ],
    "usageMetadata": {
      "promptTokenCount": 260,
      "cachedContentTokenCount": 120,
      "candidatesTokenCount": 45,
      "thoughtsTokenCount": 22,
      "totalTokenCount": 327
    },
    "modelVersion": "gemini-2.5-flash"
  }
  ```
  * Multiple chunks may contain `usageMetadata`; each is cumulative — keep overwriting with the latest non-nil `usageMetadata`.
  * **CRITICAL Gotcha**: `thoughtsTokenCount` is **NOT** included in `candidatesTokenCount` (notice `260 + 45 + 22 = 327`), yet Google bills `thoughtsTokenCount` at the **output** token rate! Always compute billable output tokens as `candidatesTokenCount + thoughtsTokenCount`.
  * `cachedContentTokenCount` **IS** a subset of `promptTokenCount`, so uncached input = `max(0, promptTokenCount - cachedContentTokenCount)`.
  * Optional `toolUsePromptTokenCount` (if present, billable at input rate).
* **Gemini Error Response Schema (Google RPC Status)**:
  ```json
  {
    "error": {
      "code": 429,
      "message": "Resource has been exhausted (quota or rate limit exceeded).",
      "status": "RESOURCE_EXHAUSTED"
    }
  }
  ```
  * Status mapping: `400` `INVALID_ARGUMENT`, `401` `UNAUTHENTICATED`, `403` `PERMISSION_DENIED`, `404` `NOT_FOUND`, `429` `RESOURCE_EXHAUSTED`, `500` `INTERNAL`, `503` `UNAVAILABLE`.

---

### 2.4 Ollama (OpenAI-Compatible & Native Basics)

* **Default Upstream Base URL**: `http://127.0.0.1:11434` (or remote tailnet Ollama host)
* **Auth**: Local Ollama ignores `Authorization` / API key; if `api_key` is configured in Headlamp (e.g. Ollama Cloud `https://ollama.com` or reverse-proxied Ollama), inject `Authorization: Bearer <KEY>`.
* **OpenAI-Compatible Endpoints (Recommended for Headlamp routing)**:
  * `POST /v1/chat/completions` — supports `stream: true` and `stream_options: {"include_usage": true}` (returns standard OpenAI SSE chunks + final `choices: []` usage chunk before `data: [DONE]`).
  * `POST /v1/embeddings`, `GET /v1/models`.
  * Modern Ollama also exposes `POST /v1/messages` (Anthropic-compatible) and `POST /v1/responses` (stateless/cloud), but using `/v1/chat/completions` as the primary Ollama upstream target ensures compatibility across all Ollama versions.
* **Native Ollama Endpoints (if configured for native passthrough)**:
  * `POST /api/chat`, `POST /api/generate`, `GET /api/tags`, `POST /api/embed`.
  * Streaming wire format: **NDJSON** (`application/x-ndjson`), one JSON object per line (no `data:` prefix).
  * Final line has `"done": true`, `"done_reason": "stop" | "length"`, `"prompt_eval_count"` (input tokens), `"eval_count"` (output tokens).
  * Error schema: `{"error": "model 'foo' not found"}` (HTTP 400/404/500).

---

## 3. Bidirectional Translation: OpenAI Chat Completions <-> Anthropic Messages

Used by `internal/translate` ONLY when the ingress protocol differs from the routed upstream provider type. Native same-protocol traffic always bypasses translation.

### 3.1 Request Translation Table

| Concept | OpenAI Chat Completions (`/v1/chat/completions`) | Anthropic Messages (`/v1/messages`) | Translation Rules & Gotchas |
| :--- | :--- | :--- | :--- |
| **Model** | `model` | `model` | Replace with mapped upstream model ID. |
| **Max Output** | `max_completion_tokens` (preferred) or `max_tokens` (optional) | `max_tokens` (**REQUIRED**) | **OpenAI -> Anthropic**: prefer `max_completion_tokens`, fallback `max_tokens`, else default `4096` (Anthropic rejects requests missing `max_tokens` with HTTP 400). |
| **Sampling** | `temperature`, `top_p` | `temperature`, `top_p` | Pass through; note newer Claude models reject setting both `temperature` and `top_p` simultaneously when unsupported — preserve only fields explicitly supplied. |
| **Stop Sequences** | `stop`: `string \| []string` | `stop_sequences`: `[]string` | Wrap OpenAI string into 1-element slice. |
| **Streaming** | `stream: bool`, `stream_options.include_usage` | `stream: bool` | Drop `stream_options` when sending to Anthropic (Anthropic rejects unknown fields). |
| **System Prompt** | Messages in `messages[]` with `role: "system"` or `"developer"` | Top-level `system`: `string \| [{type:"text", text:"..."}]` | **OpenAI -> Anthropic**: extract all `system`/`developer` messages from `messages[]`, join with `\n\n` into top-level `system`.<br>**Anthropic -> OpenAI**: prepend a `{"role":"system","content":"..."}` message (join text blocks if `system` is an array). |
| **User Text / Multimodal** | `role: "user"`, `content: string \| [{type:"text",text}, {type:"image_url", image_url:{url}}]` | `role: "user"`, `content: string \| [{type:"text",text}, {type:"image", source:{type:"base64",media_type,data} \| {type:"url",url}}]` | Parse `data:<mime>;base64,<data>` URI into Anthropic `source.type="base64"`; pass `http(s)://` URLs as `source.type="url"`. Reverse builds `data:<mime>;base64,<data>` or `url`. |
| **Assistant Text + Tool Calls** | `role: "assistant"`, `content: string\|null`, `tool_calls: [{id, type:"function", function:{name, arguments}}]` | `role: "assistant"`, `content: [{type:"text",text}?, {type:"tool_use", id, name, input:{...}}]` | **CRITICAL**: OpenAI `function.arguments` is a **JSON string**; Anthropic `tool_use.input` is a **JSON object**. Parse string -> object (empty string `""` -> `{}`); reverse marshals object -> JSON string. Drop `thinking`/`redacted_thinking` blocks when sending to OpenAI (or map if targeting reasoning endpoint). |
| **Tool Results** | One message per result: `role: "tool"`, `tool_call_id`, `content` | Inside `role: "user"` message: `{type:"tool_result", tool_use_id, content, is_error?}` | **CRITICAL (Alternating Role Rule)**: Anthropic requires alternating `user`/`assistant` turns. Consecutive OpenAI `role: "tool"` messages (and any immediately following `role: "user"` message) **MUST be merged** into a single Anthropic `role: "user"` message containing multiple `tool_result` blocks (followed by any text blocks).<br>**Reverse**: explode each `tool_result` block in an Anthropic `user` message into its own OpenAI `role: "tool"` message (before any remaining user text message). |
| **Tool Definitions** | `tools: [{type:"function", function:{name, description, parameters}}]` | `tools: [{name, description, input_schema}]` | `parameters` <-> `input_schema`. If `parameters` is nil/empty, supply `{"type":"object","properties":{}}`. |
| **Tool Choice** | `"auto"` / `"required"` / `"none"` / `{"type":"function","function":{"name":"X"}}` | `{"type":"auto"}` / `{"type":"any"}` / `{"type":"none"}` / `{"type":"tool","name":"X"}` | Exact 1-to-1 mapping. Omit `tool_choice` if `tools` is empty. |
| **Headers** | `Authorization: Bearer ...` | `x-api-key`, `anthropic-version: 2023-06-01` | Inject `anthropic-version: 2023-06-01` when translating OpenAI -> Anthropic. |

### 3.2 Stop Reason & Non-Streaming Response Mapping

| Anthropic `stop_reason` | OpenAI `finish_reason` |
| :--- | :--- |
| `"end_turn"` | `"stop"` |
| `"stop_sequence"` | `"stop"` |
| `"max_tokens"` | `"length"` |
| `"tool_use"` | `"tool_calls"` |
| `"refusal"` | `"content_filter"` |
| `"pause_turn"` | `"stop"` |

* **Anthropic Non-Stream -> OpenAI Non-Stream**:
  * `id`: `resp.ID` (or `"chatcmpl-" + resp.ID`), `object`: `"chat.completion"`, `created`: `time.Now().Unix()`, `model`: requested/response model.
  * Concatenate all `content[i]` where `type == "text"` into `choices[0].message.content` (set `null` if empty and `tool_calls` present).
  * Convert each `content[i]` where `type == "tool_use"` into `choices[0].message.tool_calls[]` (`type: "function"`, `function.arguments: string(json.Marshal(block.Input))`).
  * Usage: `prompt_tokens = usage.InputTokens + usage.CacheCreationInputTokens + usage.CacheReadInputTokens`, `prompt_tokens_details.cached_tokens = usage.CacheReadInputTokens`, `completion_tokens = usage.OutputTokens`, `total_tokens = prompt_tokens + completion_tokens`.
* **OpenAI Non-Stream -> Anthropic Non-Stream**:
  * `id`: `"msg_" + resp.ID`, `type`: `"message"`, `role`: `"assistant"`, `model`: resp.Model.
  * Build `content[]`: non-empty `message.content` -> `{type:"text", text}`; each `message.tool_calls` -> `{type:"tool_use", id, name, input: unmarshalObj(arguments)}`.
  * Usage: `cached = prompt_tokens_details.cached_tokens`, `input_tokens = max(0, prompt_tokens - cached)`, `cache_read_input_tokens = cached`, `output_tokens = completion_tokens`.

### 3.3 Streaming SSE Translation State Machines

#### A. Anthropic Upstream SSE -> OpenAI Client SSE

Maintain per-stream state:
* `id string`, `model string`, `created int64`
* `inTokens, cacheRead, cacheCreate, outTokens int`
* `nextToolIdx int` (starts at `0`; **distinct** from Anthropic `block.index`, because thinking/text blocks occupy earlier indices!)
* `blockToToolIdx map[int]int`
* `finishReason string`

| Incoming Anthropic SSE Event | Outgoing OpenAI Chat SSE Frame(s) |
| :--- | :--- |
| `message_start` | Capture `id`, `model`, `usage` (`inTokens`, `cacheRead`, `cacheCreate`). Emit initial chunk with `choices: [{index:0, delta:{role:"assistant", content:""}, finish_reason:null}]`. |
| `content_block_start` (`text`) | No frame needed (wait for `text_delta`). |
| `content_block_start` (`thinking` / `redacted_thinking`) | No frame needed (optionally ignore or map `thinking_delta` to `delta.reasoning_content` if enabled). |
| `content_block_start` (`tool_use`) | Assign `tIdx := nextToolIdx; nextToolIdx++; blockToToolIdx[ev.Index] = tIdx`. Emit chunk with `delta: {tool_calls: [{index: tIdx, id: cb.ID, type: "function", function: {name: cb.Name, arguments: ""}}]}`. |
| `content_block_delta` (`text_delta`) | Emit chunk with `delta: {content: delta.Text}`. |
| `content_block_delta` (`input_json_delta`) | Look up `tIdx := blockToToolIdx[ev.Index]`. Emit chunk with `delta: {tool_calls: [{index: tIdx, function: {arguments: delta.PartialJSON}}]}`. |
| `content_block_delta` (`thinking_delta` / `signature_delta`) | Skip (or emit `delta.reasoning_content` for `thinking_delta`; always skip `signature_delta`). |
| `content_block_stop` | No frame needed. |
| `message_delta` | Update `outTokens` (and any cumulative input/cache fields if non-zero). Map `delta.stop_reason` -> `finishReason`. Emit finish chunk: `choices: [{index:0, delta:{}, finish_reason: finishReason}]`. |
| `message_stop` | If client requested `stream_options.include_usage` (recommended to always emit when requested), emit usage chunk with `choices: []` and `usage: {prompt_tokens: inTokens+cacheRead+cacheCreate, completion_tokens: outTokens, total_tokens: ..., prompt_tokens_details: {cached_tokens: cacheRead}}`. Then emit `data: [DONE]\n\n`. |
| `ping` | Ignore (or forward SSE comment `: ping\n\n`). |
| `error` | Emit OpenAI error JSON frame and terminate stream. |

#### B. OpenAI Upstream SSE -> Anthropic Client SSE

Maintain per-stream state:
* `msgID string`, `model string`, `started bool`
* `blockIdx int` (starts at `-1`)
* `openBlockType string` (`"" | "text" | "tool_use"`)
* `activeToolIdx int` (OpenAI `tool_calls[].index` currently mapped to `blockIdx`)
* `stopReason string` (default `"end_turn"`)
* `promptTokens, cachedTokens, completionTokens int`

Helper `closeOpenBlock()`: if `openBlockType != ""`, emit `event: content_block_stop` for `blockIdx` and set `openBlockType = ""`.

| Incoming OpenAI Chat SSE Chunk | Outgoing Anthropic SSE Event(s) |
| :--- | :--- |
| First chunk (when `!started`) | Set `started = true`, `msgID = "msg_" + chunk.ID`, `model = chunk.Model`. Emit `event: message_start` with empty `content: []`, `usage: {input_tokens: 0, output_tokens: 0}`. |
| `choices[0].delta.content != ""` | If `openBlockType != "text"`: call `closeOpenBlock()`, `blockIdx++`, `openBlockType = "text"`, emit `content_block_start` (`{type:"text", text:""}`). Emit `content_block_delta` (`{type:"text_delta", text: delta.Content}`). |
| `choices[0].delta.tool_calls` (for each `tc`) | If `openBlockType != "tool_use"` or `tc.Index != activeToolIdx`: call `closeOpenBlock()`, `blockIdx++`, `openBlockType = "tool_use"`, `activeToolIdx = tc.Index`, emit `content_block_start` (`{type:"tool_use", id: tc.ID, name: tc.Function.Name, input: {}}`).<br>If `tc.Function.Arguments != ""`: emit `content_block_delta` (`{type:"input_json_delta", partial_json: tc.Function.Arguments}`). |
| `choices[0].finish_reason != nil` | Map `finish_reason` -> `stopReason` (do NOT emit `message_delta` yet — wait for trailing usage chunk or `[DONE]`!). |
| Usage chunk (`chunk.Usage != nil`, often `choices: []`) | Record `promptTokens`, `cachedTokens`, `completionTokens`. |
| `data: [DONE]` (or EOF) | If `!started`, emit synthetic `message_start`. Call `closeOpenBlock()`. Emit `event: message_delta` with `delta: {stop_reason: stopReason, stop_sequence: null}` and `usage: {input_tokens: max(0, promptTokens-cachedTokens), cache_read_input_tokens: cachedTokens, output_tokens: completionTokens}`. Emit `event: message_stop`. |
