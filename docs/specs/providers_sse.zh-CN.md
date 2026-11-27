# LLM 提供商传输格式、流式 SSE 与跨协议转换规范

[English](./providers_sse.md) | **简体中文**

Headlamp `internal/proxy`、`internal/translate` 和 `internal/metering` 的实现参考。

---

## 1. 通用 SSE 与计量不变量

1. **代理 SSE 响应的 HTTP 响应头**：
   - `Content-Type: text/event-stream`
   - `Cache-Control: no-cache`
   - `X-Accel-Buffering: no`
   - 切勿对长连接流盲目套用 `http.Server.WriteTimeout`；每收到一个上游分片后都应通过 `http.Flusher` 立即刷新输出。
2. **SSE 帧解析器**：
   - 同时兼容 `\r\n` 和 `\n` 换行符。
   - 忽略以 `:` 开头的注释行以及保活空行。
   - 每个事件由可选的 `event: <name>` 行和一行或多行 `data: <payload>` 行（以 `\n` 拼接）组成，以空行结束。
   - **缓冲区大小坑点**：**切勿**使用默认配置的 `bufio.Scanner`（最大 token 仅 64 KiB）。工具调用、base64 图片、扩展思考（extended thinking）块以及 OpenAI 的 `response.completed` 封包经常超过 64 KiB。请使用 `bufio.Reader.ReadBytes('\n')` 或最大缓冲区 `>= 8 MiB` 的 scanner。
3. **流中断与异步计量**：
   - 一旦写出 HTTP `200 OK`，流中途的失败会以 SSE `error` 帧或提前 EOF 的形式出现。
   - 务必在流完成或客户端中止时，使用独立上下文（`context.Background()` + 短超时）异步记录用量，确保 `usage_logs` 仍能捕获部分或最终用量。
4. **Token 计量归一化矩阵（关键）**：

| 提供商 / 端点 | `input` 字段是否包含缓存？ | `output` 字段是否包含推理？ | 归一化计费公式 |
| :--- | :--- | :--- | :--- |
| **OpenAI Chat** (`/v1/chat/completions`) | **是**（`prompt_tokens` 包含 `cached_tokens`） | **是**（`completion_tokens` 包含 `reasoning_tokens`） | `uncached_in = max(0, prompt_tokens - cached_tokens)`<br>`cache_read = cached_tokens`, `cache_write = 0`<br>`out = completion_tokens`（`reasoning = reasoning_tokens`，仅作信息展示） |
| **OpenAI Responses** (`/v1/responses`) | **是**（`input_tokens` 包含 `cached_tokens`） | **是**（`output_tokens` 包含 `reasoning_tokens`） | `uncached_in = max(0, input_tokens - cached_tokens)`<br>`cache_read = cached_tokens`, `cache_write = 0`<br>`out = output_tokens`（`reasoning = reasoning_tokens`，仅作信息展示） |
| **Anthropic Messages** (`/v1/messages`) | **否**（`input_tokens` 不包含缓存读取与缓存写入！） | **是**（`output_tokens` 包含思考 token） | `uncached_in = input_tokens`<br>`cache_read = cache_read_input_tokens`<br>`cache_write = cache_creation_input_tokens`（或拆分为 `5m` / `1h`）<br>`out = output_tokens` |
| **Google Gemini** (`:generateContent` / `:streamGenerateContent`) | **是**（`promptTokenCount` 包含 `cachedContentTokenCount`） | **否**（`candidatesTokenCount` 不包含 `thoughtsTokenCount`！） | `uncached_in = max(0, promptTokenCount - cachedContentTokenCount)`<br>`cache_read = cachedContentTokenCount`, `cache_write = 0`<br>`out = candidatesTokenCount + thoughtsTokenCount`<br>`reasoning = thoughtsTokenCount` |
| **Ollama** (`/v1/chat/completions` 与 `/api/chat`) | 不适用（`0` 缓存） | 包含在 `completion_tokens` / `eval_count` 中 | `uncached_in = prompt_tokens`（或 `prompt_eval_count`）<br>`out = completion_tokens`（或 `eval_count`） |

> **费用公式**：
> `cost_usd = (uncached_in * price.input + cache_read * price.cache_read + cache_write_5m * price.cache_write + cache_write_1h * price.cache_write_1h + out * price.output) / 1_000_000`

---

## 2. 提供商参考

### 2.1 OpenAI

* **默认上游基础 URL**：`https://api.openai.com`
* **Headlamp 路由**：`/v1/...` 与 `/openai/v1/...`
* **端点**：
  * `POST /v1/chat/completions`
  * `POST /v1/responses`
  * `POST /v1/embeddings`
  * `GET /v1/models`
* **鉴权与转发请求头**：
  * 托管模式（managed）：剥离客户端的 `Authorization`，设置为 `Authorization: Bearer <UPSTREAM_KEY>`。
  * 透传模式（passthrough）：原样转发客户端的 `Authorization`。
  * 若存在以下可选请求头则一并转发：`OpenAI-Organization`、`OpenAI-Project`、`OpenAI-Beta`。

#### A. Chat Completions（`POST /v1/chat/completions`）

* **流式请求坑点（`stream_options`）**：
  * 当 `"stream": true` 时，除非同时设置 `"stream_options": {"include_usage": true}`，否则 OpenAI 会**省略** `usage`。
  * 对于 OpenAI 兼容上游，如果请求中 `"stream": true` 且缺少 `stream_options`，Headlamp 应自动注入 `"stream_options": {"include_usage": true}`。
  * 记录客户端最初是否请求了 `include_usage`：若未请求，对于严格的旧版客户端可选择不转发末尾 `choices` 为空的 usage 分片（现代 OpenAI SDK、Cursor 和 Codex 都能妥善处理 `choices: []`）。
* **SSE 传输格式**：
  * 不含 `event:` 行；每一帧均为 `data: <JSON>\n\n`，并以 `data: [DONE]\n\n` 终止。
  * 文本内容分片：
    ```text
    data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1740000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"},"finish_reason":null}],"usage":null}

    ```
  * 工具调用流式分片（参数以 JSON 字符串片段形式增量到达）：
    ```text
    data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1740000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}

    data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1740000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"SF\"}"}}]},"finish_reason":null}]}

    ```
  * 结束分片：`choices[0].finish_reason` 为 `"stop" | "length" | "tool_calls" | "content_filter"`。
  * 末尾纯用量分片（位于 `[DONE]` 之前）：**`choices` 为空数组 `[]`**（注意防范访问 `choices[0]` 越界！）。
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
  * 结束哨兵：`data: [DONE]\n\n`

#### B. Responses API（`POST /v1/responses`）

* **流式传输**：通过 `"stream": true` 开启。始终在 `response.completed` 中附带最终 `usage`（无需设置 `stream_options`）。
* **SSE 传输格式**：同时包含 `event: <type>` 和 `data: {"type":"<type>","sequence_number":N,...}`。在终态生命周期事件后结束（无 `[DONE]`）。
* **关键生命周期事件**：
  * `response.created`、`response.in_progress`
  * `response.output_item.added`、`response.content_part.added`
  * `response.output_text.delta`（`delta` 字符串）、`response.output_text.done`
  * `response.function_call_arguments.delta`、`response.function_call_arguments.done`
  * `response.reasoning_summary_text.delta`
  * `response.output_item.done`
  * 终态事件：`response.completed`、`response.incomplete`、`response.failed`
  * 带外流错误：`event: error`
* **用量 Schema（位于 `response.completed` / `response.incomplete` 以及非流式响应顶层的 `.usage`）**：
  ```text
  event: response.completed
  data: {"type":"response.completed","sequence_number":42,"response":{"id":"resp_123","object":"response","status":"completed","model":"gpt-5","output":[...],"usage":{"input_tokens":2500,"input_tokens_details":{"cached_tokens":2000},"output_tokens":3300,"output_tokens_details":{"reasoning_tokens":3000},"total_tokens":5800}}}

  ```
  * 当 `event.type == "response.completed"` 或 `"response.incomplete"` 时，从 `event.response.usage` 提取用量。

#### C. OpenAI 错误响应 Schema

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

| HTTP | `error.type` | `error.code` | 在 Headlamp 中的用途 |
| :--- | :--- | :--- | :--- |
| `400` | `invalid_request_error` | `invalid_request` / `guardrail_blocked` | 请求载荷无效或被护栏（guardrail）拦截 |
| `401` | `authentication_error` | `invalid_api_key` | 缺少或无效的身份凭据 / 回退令牌 |
| `403` | `permission_error` | `model_not_allowed` | 策略 / grants 拒绝访问该模型 |
| `404` | `invalid_request_error` | `model_not_found` | 未知的路由或模型 |
| `429` | `requests` / `insufficient_quota` | `rate_limit_exceeded` / `insufficient_quota` | 超出 RPM/TPM 限流或预算额度 |
| `502`/`503` | `server_error` | `upstream_error` | 上游故障 |

Responses API 流中途的 SSE 错误帧：
```text
event: error
data: {"type":"error","code":"server_error","message":"...","param":null}

```

---

### 2.2 Anthropic Messages API

* **默认上游基础 URL**：`https://api.anthropic.com`
* **Headlamp 路由**：`/anthropic/v1/messages`、`/anthropic/v1/messages/count_tokens`、`/anthropic/v1/models`
* **鉴权与必需请求头**：
  * `x-api-key: <UPSTREAM_KEY>`（托管模式下，同时剥离客户端的 `x-api-key` 和 `Authorization`；透传模式下，原样保留客户端发送的 `x-api-key` 或 `Authorization: Bearer ...`，例如 Claude Code OAuth）。
  * `anthropic-version: 2023-06-01`（必需；若客户端已提供则保留，跨协议转换时默认设为 `"2023-06-01"`）。
  * `anthropic-beta`：逗号分隔的特性开关 —— 原生透传时**必须原封不动转发**！常见值包括：
    * `prompt-caching-2024-07-31`
    * `extended-cache-ttl-2025-04-11`（1 小时临时缓存 TTL）
    * `interleaved-thinking-2025-05-14`
    * `fine-grained-tool-streaming-2025-05-14`
    * `context-1m-2025-08-07`
    * `oauth-2025-04-20`
* **SSE 传输格式**：
  * 每个事件格式为 `event: <type>\ndata: {"type":"<type>",...}\n\n`，在 `event: message_stop` 处结束（无 `[DONE]`）。
  * 严格的生命周期顺序（期间可能穿插可选的 `event: ping` `{"type":"ping"}`）：
    1. `message_start` —— 空数组 `message.content: []`，初始 `message.usage`（包含 `input_tokens`、`cache_creation_input_tokens`、`cache_read_input_tokens`、可选的 `cache_creation` 以及初始 `output_tokens`）。
    2. `content_block_start` —— 声明 `index` 与 `content_block`：
       * 文本：`{"type":"text","text":""}`
       * 工具调用：`{"type":"tool_use","id":"toolu_...","name":"get_weather","input":{}}`
       * 扩展思考：`{"type":"thinking","thinking":""}`
       * 已隐去思考：`{"type":"redacted_thinking","data":"<opaque_blob>"}`（无增量 delta）
    3. `content_block_delta` —— 针对指定 `index` 的增量更新：
       * 文本：`{"type":"text_delta","text":"Hello"}`
       * 工具参数：`{"type":"input_json_delta","partial_json":"{\"city\":"}`
       * 思考文本：`{"type":"thinking_delta","thinking":"Let me check..."}`
       * 思考签名：`{"type":"signature_delta","signature":"<opaque_sig>"}`（**绝对不能丢弃或篡改**；多轮对话校验必需）
    4. `content_block_stop` —— `{"type":"content_block_stop","index":0}`
    5. `message_delta` —— `delta: {"stop_reason":"end_turn"|"max_tokens"|"stop_sequence"|"tool_use"|"pause_turn"|"refusal","stop_sequence":null}` 以及累计 `usage`。
    6. `message_stop` —— `{"type":"message_stop"}`

* **用量 JSON 与累计值坑点**：
  ```text
  event: message_start
  data: {"type":"message_start","message":{"id":"msg_01...","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-6","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":342,"cache_creation_input_tokens":400,"cache_read_input_tokens":1800,"cache_creation":{"ephemeral_5m_input_tokens":400,"ephemeral_1h_input_tokens":0},"output_tokens":1}}}

  event: message_delta
  data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":145}}
  ```
  * **关键坑点 1（累计值，而非增量值）**：`message_delta.usage` 报告的是**累计**总量（`output_tokens`，在较新快照中也可能重复返回累计的 `input_tokens`、`cache_creation_input_tokens`、`cache_read_input_tokens`）。始终使用非零字段覆盖（取最新值/最大值），**切勿**将 `message_start` 和 `message_delta` 的计数相加！
  * **关键坑点 2（不含缓存的输入计数）**：`input_tokens` 不包含 `cache_creation_input_tokens` 和 `cache_read_input_tokens`。总提示词 token 数 = `input_tokens + cache_creation_input_tokens + cache_read_input_tokens`。
  * **关键坑点 3（5m 与 1h 缓存写入计价）**：若存在 `usage.cache_creation`，则 `ephemeral_5m_input_tokens` 按 `cache_write`（输入的 1.25 倍）计价，`ephemeral_1h_input_tokens` 按 `cache_write_1h`（输入的 2.0 倍）计价；否则全部 `cache_creation_input_tokens` 均按 `cache_write`（5m 费率）计价。

* **Anthropic 错误响应 Schema**：
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
  * 状态码映射：`400` `invalid_request_error`、`401` `authentication_error`、`403` `permission_error`、`404` `not_found_error`、`413` `request_too_large`、`429` `rate_limit_error`、`500` `api_error`、`529` `overloaded_error`。
  * 流中途错误帧：`event: error\ndata: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}\n\n`。

---

### 2.3 Google Gemini API

* **默认上游基础 URL**：`https://generativelanguage.googleapis.com`
* **Headlamp 路由**：
  * 非流式：`POST /gemini/v1beta/models/{model}:generateContent`
  * 流式 SSE：`POST /gemini/v1beta/models/{model}:streamGenerateContent?alt=sse`
  * 模型列表：`GET /gemini/v1beta/models`
* **模型 ID 提取坑点**：模型 ID 位于 **URL 路径**中，而不在 JSON 请求体中！需从 `/v1beta/models/{model}:{action}` 解析 `{model}`（去掉开头的 `models/` 与结尾的 `:{action}`），用于路由、策略校验与计量。
* **鉴权**：
  * 首选请求头：`x-goog-api-key: <UPSTREAM_KEY>`。
  * 托管模式：转发前同时剥离客户端的 `x-goog-api-key` 以及任何 `?key=...` 查询参数，然后设置 `x-goog-api-key`。
  * 透传模式：保留客户端的 `x-goog-api-key` 或 `?key=...`。
* **流式传输格式**：
  * 带 `?alt=sse` 时：标准 SSE `data: <GenerateContentResponse JSON>\n\n`（无 `event:` 行，无 `[DONE]`；在包含 `candidates[0].finishReason`——如 `"STOP"`、`"MAX_TOKENS"`、`"SAFETY"`、`"RECITATION"`——的末尾分片之后以 EOF 结束）。
  * 不带 `?alt=sse` 时：Gemini 以 JSON 数组形式流式返回 `[{...},\n{...}]`。原生透传原样转发字节流；计量旁路（tap）应检测是否存在 `alt=sse`（存在则解析 SSE `data:` 行，否则回退为流式 `json.Decoder` 解析数组元素）。
* **用量字段（`usageMetadata`）**：
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
  * 多个分片都可能包含 `usageMetadata`，每次均为累计值 —— 持续用最新的非空 `usageMetadata` 覆盖即可。
  * **关键坑点**：`thoughtsTokenCount` **不包含**在 `candidatesTokenCount` 中（注意 `260 + 45 + 22 = 327`），但 Google 按**输出** token 费率对 `thoughtsTokenCount` 计费！因此计费输出 token 必须始终计算为 `candidatesTokenCount + thoughtsTokenCount`。
  * `cachedContentTokenCount` **是** `promptTokenCount` 的子集，因此未缓存输入 = `max(0, promptTokenCount - cachedContentTokenCount)`。
  * 可选字段 `toolUsePromptTokenCount`（若存在，按输入费率计费）。
* **Gemini 错误响应 Schema（Google RPC Status）**：
  ```json
  {
    "error": {
      "code": 429,
      "message": "Resource has been exhausted (quota or rate limit exceeded).",
      "status": "RESOURCE_EXHAUSTED"
    }
  }
  ```
  * 状态码映射：`400` `INVALID_ARGUMENT`、`401` `UNAUTHENTICATED`、`403` `PERMISSION_DENIED`、`404` `NOT_FOUND`、`429` `RESOURCE_EXHAUSTED`、`500` `INTERNAL`、`503` `UNAVAILABLE`。

---

### 2.4 Ollama（OpenAI 兼容与原生接口基础）

* **默认上游基础 URL**：`http://127.0.0.1:11434`（或远程 tailnet 中的 Ollama 主机）
* **鉴权**：本地 Ollama 会忽略 `Authorization` / API key；若在 Headlamp 中配置了 `api_key`（例如 Ollama Cloud `https://ollama.com` 或反向代理后的 Ollama），则注入 `Authorization: Bearer <KEY>`。
* **OpenAI 兼容端点（推荐作为 Headlamp 路由目标）**：
  * `POST /v1/chat/completions` —— 支持 `stream: true` 和 `stream_options: {"include_usage": true}`（在 `data: [DONE]` 之前返回标准 OpenAI SSE 分片以及末尾 `choices: []` 用量分片）。
  * `POST /v1/embeddings`、`GET /v1/models`。
  * 现代版 Ollama 也暴露了 `POST /v1/messages`（Anthropic 兼容）和 `POST /v1/responses`（无状态/云端），但将 `/v1/chat/completions` 作为主要 Ollama 上游目标可确保兼容所有版本的 Ollama。
* **原生 Ollama 端点（当配置为原生透传时）**：
  * `POST /api/chat`、`POST /api/generate`、`GET /api/tags`、`POST /api/embed`。
  * 流式传输格式：**NDJSON**（`application/x-ndjson`），每行一个 JSON 对象（无 `data:` 前缀）。
  * 最后一行包含 `"done": true`、`"done_reason": "stop" | "length"`、`"prompt_eval_count"`（输入 token 数）、`"eval_count"`（输出 token 数）。
  * 错误 Schema：`{"error": "model 'foo' not found"}`（HTTP 400/404/500）。

---

## 3. 双向协议转换：OpenAI Chat Completions <-> Anthropic Messages

`internal/translate` **仅在**入口协议与路由到的上游提供商类型不一致时启用。原生同协议流量始终绕过转换层。

### 3.1 请求转换对照表

| 概念 | OpenAI Chat Completions (`/v1/chat/completions`) | Anthropic Messages (`/v1/messages`) | 转换规则与坑点 |
| :--- | :--- | :--- | :--- |
| **模型（Model）** | `model` | `model` | 替换为映射后的上游模型 ID。 |
| **最大输出（Max Output）** | `max_completion_tokens`（优先）或 `max_tokens`（可选） | `max_tokens`（**必填**） | **OpenAI -> Anthropic**：优先使用 `max_completion_tokens`，其次回退至 `max_tokens`，若均缺省则默认 `4096`（Anthropic 会以 HTTP 400 拒绝缺少 `max_tokens` 的请求）。 |
| **采样参数（Sampling）** | `temperature`、`top_p` | `temperature`、`top_p` | 透传；注意较新的 Claude 模型在不支持时会拒绝同时设置 `temperature` 和 `top_p` —— 仅保留显式提供的字段。 |
| **停止序列（Stop Sequences）** | `stop`: `string \| []string` | `stop_sequences`: `[]string` | 将 OpenAI 的单个字符串包装为单元素切片。 |
| **流式传输（Streaming）** | `stream: bool`, `stream_options.include_usage` | `stream: bool` | 发送给 Anthropic 时丢弃 `stream_options`（Anthropic 会拒绝未知字段）。 |
| **系统提示词（System Prompt）** | `messages[]` 中 `role: "system"` 或 `"developer"` 的消息 | 顶层 `system`: `string \| [{type:"text", text:"..."}]` | **OpenAI -> Anthropic**：从 `messages[]` 中提取全部 `system`/`developer` 消息，用 `\n\n` 拼接到顶层 `system`。<br>**Anthropic -> OpenAI**：在头部插入一条 `{"role":"system","content":"..."}` 消息（若 `system` 为数组则拼接其中的文本块）。 |
| **用户文本 / 多模态** | `role: "user"`, `content: string \| [{type:"text",text}, {type:"image_url", image_url:{url}}]` | `role: "user"`, `content: string \| [{type:"text",text}, {type:"image", source:{type:"base64",media_type,data} \| {type:"url",url}}]` | 将 `data:<mime>;base64,<data>` URI 解析为 Anthropic 的 `source.type="base64"`；将 `http(s)://` URL 转为 `source.type="url"`。反向转换则构造 `data:<mime>;base64,<data>` 或 `url`。 |
| **助手文本 + 工具调用** | `role: "assistant"`, `content: string\|null`, `tool_calls: [{id, type:"function", function:{name, arguments}}]` | `role: "assistant"`, `content: [{type:"text",text}?, {type:"tool_use", id, name, input:{...}}]` | **关键**：OpenAI 的 `function.arguments` 是 **JSON 字符串**；Anthropic 的 `tool_use.input` 是 **JSON 对象**。正向需将字符串解析为对象（空字符串 `""` -> `{}`）；反向需将对象序列化为 JSON 字符串。发送给 OpenAI 时丢弃 `thinking`/`redacted_thinking` 块（若目标为推理端点则可另行映射）。 |
| **工具结果（Tool Results）** | 每个结果一条消息：`role: "tool"`, `tool_call_id`, `content` | 置于 `role: "user"` 消息内部：`{type:"tool_result", tool_use_id, content, is_error?}` | **关键（角色交替规则）**：Anthropic 要求 `user`/`assistant` 轮次严格交替。连续的 OpenAI `role: "tool"` 消息（以及紧随其后的任何 `role: "user"` 消息）**必须合并**为单条 Anthropic `role: "user"` 消息，内含多个 `tool_result` 块（后接任意文本块）。<br>**反向**：将 Anthropic `user` 消息中的每个 `tool_result` 块拆分为各自独立的 OpenAI `role: "tool"` 消息（位于剩余用户文本消息之前）。 |
| **工具定义（Tool Definitions）** | `tools: [{type:"function", function:{name, description, parameters}}]` | `tools: [{name, description, input_schema}]` | `parameters` <-> `input_schema`。若 `parameters` 为 `nil` 或空，则补充 `{"type":"object","properties":{}}`。 |
| **工具选择（Tool Choice）** | `"auto"` / `"required"` / `"none"` / `{"type":"function","function":{"name":"X"}}` | `{"type":"auto"}` / `{"type":"any"}` / `{"type":"none"}` / `{"type":"tool","name":"X"}` | 严格一一对应。若 `tools` 为空则省略 `tool_choice`。 |
| **请求头（Headers）** | `Authorization: Bearer ...` | `x-api-key`, `anthropic-version: 2023-06-01` | OpenAI -> Anthropic 转换时注入 `anthropic-version: 2023-06-01`。 |

### 3.2 停止原因与非流式响应映射

| Anthropic `stop_reason` | OpenAI `finish_reason` |
| :--- | :--- |
| `"end_turn"` | `"stop"` |
| `"stop_sequence"` | `"stop"` |
| `"max_tokens"` | `"length"` |
| `"tool_use"` | `"tool_calls"` |
| `"refusal"` | `"content_filter"` |
| `"pause_turn"` | `"stop"` |

* **Anthropic 非流式 -> OpenAI 非流式**：
  * `id`：`resp.ID`（或 `"chatcmpl-" + resp.ID`），`object`：`"chat.completion"`，`created`：`time.Now().Unix()`，`model`：请求或响应中的模型名。
  * 将所有 `type == "text"` 的 `content[i]` 拼接到 `choices[0].message.content`（若为空且存在 `tool_calls` 则置为 `null`）。
  * 将每个 `type == "tool_use"` 的 `content[i]` 转为 `choices[0].message.tool_calls[]`（`type: "function"`，`function.arguments: string(json.Marshal(block.Input))`）。
  * 用量：`prompt_tokens = usage.InputTokens + usage.CacheCreationInputTokens + usage.CacheReadInputTokens`，`prompt_tokens_details.cached_tokens = usage.CacheReadInputTokens`，`completion_tokens = usage.OutputTokens`，`total_tokens = prompt_tokens + completion_tokens`。
* **OpenAI 非流式 -> Anthropic 非流式**：
  * `id`：`"msg_" + resp.ID`，`type`：`"message"`，`role`：`"assistant"`，`model`：`resp.Model`。
  * 构造 `content[]`：非空的 `message.content` -> `{type:"text", text}`；每个 `message.tool_calls` -> `{type:"tool_use", id, name, input: unmarshalObj(arguments)}`。
  * 用量：`cached = prompt_tokens_details.cached_tokens`，`input_tokens = max(0, prompt_tokens - cached)`，`cache_read_input_tokens = cached`，`output_tokens = completion_tokens`。

### 3.3 流式 SSE 转换状态机

#### A. Anthropic 上游 SSE -> OpenAI 客户端 SSE

维护单流状态：
* `id string`、`model string`、`created int64`
* `inTokens, cacheRead, cacheCreate, outTokens int`
* `nextToolIdx int`（从 `0` 开始；与 Anthropic 的 `block.index` **区分开**，因为 thinking/text 块会占用前面的索引！）
* `blockToToolIdx map[int]int`
* `finishReason string`

| 收到 Anthropic SSE 事件 | 输出 OpenAI Chat SSE 帧 |
| :--- | :--- |
| `message_start` | 记录 `id`、`model` 与 `usage`（`inTokens`、`cacheRead`、`cacheCreate`）。输出初始分片：`choices: [{index:0, delta:{role:"assistant", content:""}, finish_reason:null}]`。 |
| `content_block_start`（`text`） | 无需输出帧（等待 `text_delta`）。 |
| `content_block_start`（`thinking` / `redacted_thinking`） | 无需输出帧（可选择忽略，或在启用时将 `thinking_delta` 映射为 `delta.reasoning_content`）。 |
| `content_block_start`（`tool_use`） | 分配 `tIdx := nextToolIdx; nextToolIdx++; blockToToolIdx[ev.Index] = tIdx`。输出分片：`delta: {tool_calls: [{index: tIdx, id: cb.ID, type: "function", function: {name: cb.Name, arguments: ""}}]}`。 |
| `content_block_delta`（`text_delta`） | 输出分片：`delta: {content: delta.Text}`。 |
| `content_block_delta`（`input_json_delta`） | 查找 `tIdx := blockToToolIdx[ev.Index]`。输出分片：`delta: {tool_calls: [{index: tIdx, function: {arguments: delta.PartialJSON}}]}`。 |
| `content_block_delta`（`thinking_delta` / `signature_delta`） | 跳过（或针对 `thinking_delta` 输出 `delta.reasoning_content`；始终跳过 `signature_delta`）。 |
| `content_block_stop` | 无需输出帧。 |
| `message_delta` | 更新 `outTokens`（以及任何非零的累计 input/cache 字段）。将 `delta.stop_reason` 映射为 `finishReason`。输出结束分片：`choices: [{index:0, delta:{}, finish_reason: finishReason}]`。 |
| `message_stop` | 若客户端请求了 `stream_options.include_usage`（建议在请求时始终输出），输出用量分片：`choices: []` 与 `usage: {prompt_tokens: inTokens+cacheRead+cacheCreate, completion_tokens: outTokens, total_tokens: ..., prompt_tokens_details: {cached_tokens: cacheRead}}`。随后输出 `data: [DONE]\n\n`。 |
| `ping` | 忽略（或转发 SSE 注释 `: ping\n\n`）。 |
| `error` | 输出 OpenAI 错误 JSON 帧并终止流。 |

#### B. OpenAI 上游 SSE -> Anthropic 客户端 SSE

维护单流状态：
* `msgID string`、`model string`、`started bool`
* `blockIdx int`（从 `-1` 开始）
* `openBlockType string`（`"" | "text" | "tool_use"`）
* `activeToolIdx int`（当前映射到 `blockIdx` 的 OpenAI `tool_calls[].index`）
* `stopReason string`（默认 `"end_turn"`）
* `promptTokens, cachedTokens, completionTokens int`

辅助操作 `closeOpenBlock()`：若 `openBlockType != ""`，为当前 `blockIdx` 输出 `event: content_block_stop`，并将 `openBlockType` 置为 `""`。

| 收到 OpenAI Chat SSE 分片 | 输出 Anthropic SSE 事件 |
| :--- | :--- |
| 首个分片（当 `!started`） | 设置 `started = true`、`msgID = "msg_" + chunk.ID`、`model = chunk.Model`。输出 `event: message_start`，包含空 `content: []` 与 `usage: {input_tokens: 0, output_tokens: 0}`。 |
| `choices[0].delta.content != ""` | 若 `openBlockType != "text"`：调用 `closeOpenBlock()`，`blockIdx++`，`openBlockType = "text"`，输出 `content_block_start`（`{type:"text", text:""}`）。随后输出 `content_block_delta`（`{type:"text_delta", text: delta.Content}`）。 |
| `choices[0].delta.tool_calls`（遍历每个 `tc`） | 若 `openBlockType != "tool_use"` 或 `tc.Index != activeToolIdx`：调用 `closeOpenBlock()`，`blockIdx++`，`openBlockType = "tool_use"`，`activeToolIdx = tc.Index`，输出 `content_block_start`（`{type:"tool_use", id: tc.ID, name: tc.Function.Name, input: {}}`）。<br>若 `tc.Function.Arguments != ""`：输出 `content_block_delta`（`{type:"input_json_delta", partial_json: tc.Function.Arguments}`）。 |
| `choices[0].finish_reason != nil` | 将 `finish_reason` 映射为 `stopReason`（**此时切勿输出 `message_delta`** —— 需等待末尾用量分片或 `[DONE]`！）。 |
| 用量分片（`chunk.Usage != nil`，通常 `choices: []`） | 记录 `promptTokens`、`cachedTokens`、`completionTokens`。 |
| `data: [DONE]`（或 EOF） | 若 `!started`，输出合成的 `message_start`。调用 `closeOpenBlock()`。输出 `event: message_delta`，包含 `delta: {stop_reason: stopReason, stop_sequence: null}` 与 `usage: {input_tokens: max(0, promptTokens-cachedTokens), cache_read_input_tokens: cachedTokens, output_tokens: completionTokens}`。最后输出 `event: message_stop`。 |
