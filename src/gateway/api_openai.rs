//! OpenAI-compatible Chat Completions route (`POST /v1/chat/completions`).
//!
//! This module ONLY normalizes OpenAI inbound requests into the canonical
//! AgentService/session/run contract and renders canonical durable/live
//! AgentService events as OpenAI outbound responses. It never parses
//! provider wire, never calls provider adapters, and never bypasses the A5
//! serial loop: every run is admitted through `AgentService` and every
//! output value (text, tool calls, usage, finish reason) comes from the
//! run's durable/live canonical events.
//!
//! Inbound normalization:
//! - `model` (optional; the gateway default applies, and the override
//!   enters the loop as the typed session model — never a string marker).
//! - `messages` (system/user/assistant/tool): bounded count and sizes;
//!   content is a string or text parts only; assistant `tool_calls` become
//!   canonical `tool_call` parts; `tool` messages become canonical
//!   `tool_result` parts with the message-level pair id; every tool message
//!   must reference a declared assistant call; the last message must be a
//!   user message (the OpenAI contract).
//! - `tools` (bounded function declarations, canonicalized to
//!   `{name, description, schema_json}`; omitting the field and an explicit
//!   empty array both mean no tools on the OpenAI route), `tool_choice` (string: auto|none|required), `stream`,
//!   `stream_options.include_usage`, and the bounded common options
//!   `temperature`, `top_p`, `max_tokens`/`max_completion_tokens`, `user`.
//! - Every per-request override enters the RSS loop through the TYPED run
//!   context `request` map (`AdmitRunRequest::request_overrides`); the
//!   gateway config remains the only source for provider/profile,
//!   credentials, base_url, and allowlists — a client can never override
//!   them (`reserved_field` rejection), and any field outside the supported
//!   set is rejected typed (`unknown_field`/`unsupported_field`).
//!
//! Outbound rendering:
//! - Buffered (`stream: false`): waits for the durable terminal and returns
//!   the official `chat.completion` shape — `choices[0].message.content`
//!   and `finish_reason`/`usage` from the terminal event. ONLY the FINAL
//!   provider round is rendered: `tool_calls` are filtered to the final
//!   round's `tool.started` events (the A5 loop executes every tool round
//!   internally, so internal rounds never leak as client tool_calls). A
//!   `run.failed` terminal renders the typed provider error (502 when the
//!   failure carries a provider error, 500 otherwise); a `run.cancelled`
//!   terminal renders the typed `run_cancelled` error.
//! - Streaming (`stream: true`): SSE `data: {...}\n\n` chunks. Each
//!   provider round's text/tool deltas are buffered per turn (bounded);
//!   the buffer is dropped when the round advances (that round was
//!   INTERNAL — A5 executed its tools itself) and flushed only when the
//!   terminal confirms the round is the final response. Buffered contract:
//!   at flush, preserved tool chunks are emitted FIRST (tool indices are
//!   explicit, so tool/text ordering is not semantically meaningful for
//!   OpenAI clients), then the text deltas; if the TEXT buffer overflows,
//!   the buffered deltas are replaced by the authoritative terminal text
//!   (lossless fallback) while the bounded tool chunks are still emitted;
//!   if the TOOL buffer itself overflows, the stream ends with a typed
//!   `stream_buffer_overflow` error chunk followed by `[DONE]` — tool
//!   calls are NEVER silently dropped. A `Lagged` live receiver recovers
//!   through the DURABLE catch-up (no silent loss), a keep-alive heartbeat
//!   keeps the connection alive, the first flushed chunk carries the
//!   assistant role, and failure/cancellation renders a typed error chunk
//!   with the SAME type derivation as the buffered contract, followed by
//!   `[DONE]`. Each chunk carries the durable event sequence as the SSE
//!   `id` (Last-Event visibility; replay remains available through the
//!   durable `/v1/runs/{id}/events` cursor), and the response carries the
//!   bounded `x-request-id`. The route subscribes through
//!   `AgentService::attach_subscriber`, so the configured client-disconnect
//!   policy applies, and cancellation stays reachable via the typed
//!   `POST /v1/runs/{id}/stop`.
//!
//! Sessions: the normalized conversation history is persisted INSIDE the
//! admission transaction (`admission.create` commits session + messages +
//! run + idempotency atomically), so a failed admission leaves no partial
//! session and a replayed `Idempotency-Key` never creates a new one. A
//! replayed admission NEVER spawns a second worker: provider calls and
//! tool side effects stay exact-once, and the response attaches to the
//! existing run's history/live stream.
//!
//! Security: the route sits under the gateway guard middleware (bearer
//! auth, per-IP/per-account rate limits, body limit), reuses the canonical
//! `Idempotency-Key` admission contract, and answers every error with the
//! OpenAI `{"error": {...}}` envelope plus a bounded `x-request-id`.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, StatusCode, header::HeaderValue},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::AgentGatewayState;
use crate::domain::{fnv1a64, input_text, timestamp};
use crate::gateway::store::{GatewayEvent, GatewayPersistence};
use crate::service::{
    AdmitError, AdmitRunRequest, SessionMessageDraft, SubscriberGuard, failed_payload,
};

const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

// ---------------------------------------------------------------------------
// Bounded request surface (documented bounds)
// ---------------------------------------------------------------------------

/// Max messages in one request.
const MAX_MESSAGES: usize = 256;
/// Max characters of one message's serialized content.
const MAX_MESSAGE_CHARS: usize = 64 * 1024;
/// Max declared tools in one request.
const MAX_TOOLS: usize = 64;
/// Max characters of one tool name.
const MAX_TOOL_NAME_CHARS: usize = 128;
/// Max characters of one tool description.
const MAX_TOOL_DESCRIPTION_CHARS: usize = 4096;
/// Max characters of one tool's serialized JSON schema.
const MAX_TOOL_SCHEMA_CHARS: usize = 64 * 1024;
/// Max tool calls declared in one assistant message.
const MAX_TOOL_CALLS_PER_MESSAGE: usize = 32;
/// Max characters of one tool call id.
const MAX_TOOL_CALL_ID_CHARS: usize = 128;
/// Max UTF-8 bytes in one durable message content-part array.
const MAX_DURABLE_CONTENT_BYTES: usize = 1_048_576;
/// Max characters of one tool call's serialized arguments.
const MAX_TOOL_CALL_ARGUMENTS_CHARS: usize = 64 * 1024;
/// Max `max_tokens` / `max_completion_tokens` value.
const MAX_OUTPUT_TOKENS: u64 = 65_536;
/// Max characters of the optional `user` metadata field.
const MAX_USER_CHARS: usize = 256;
/// Max characters of an echoed `x-request-id` header value.
const MAX_REQUEST_ID_CHARS: usize = 128;
/// Bounded per-turn SSE stream buffer: at most this many delta chunks may be
/// held for the current provider round before the stream falls back to the
/// authoritative terminal text (which always carries the complete final
/// round text — the fallback is lossless, never a silent drop).
const MAX_STREAM_BUFFERED_DELTAS: usize = 4096;
/// Bounded per-turn text budget for the SSE stream buffer.
const MAX_STREAM_BUFFERED_CHARS: usize = 256 * 1024;
/// Bounded per-turn tool-call chunk budget for the SSE stream buffer.
const MAX_STREAM_BUFFERED_TOOL_CALLS: usize = 64;
/// SSE keep-alive heartbeat interval (comment frames keep the connection
/// alive while the A5 loop works between events).
const SSE_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Gateway-owned provider configuration names: the client can NEVER override
/// the provider/profile, its credentials, its endpoint, or the allowlists.
/// These are rejected with the typed `reserved_field` error before any
/// service work.
const RESERVED_FIELDS: &[&str] = &[
    "provider",
    "provider_options",
    "base_url",
    "api_key",
    "secret",
    "bearer_token",
    "allowlist",
    "allowed_accounts",
    "allowed_chats",
    "allowed_users",
    "profile",
];

/// Well-known OpenAI request fields this route does not support. They are
/// rejected with the typed `unsupported_field` error — an explicit policy,
/// never a silent ignore.
const UNSUPPORTED_FIELDS: &[&str] = &[
    "n",
    "stop",
    "response_format",
    "frequency_penalty",
    "presence_penalty",
    "seed",
    "logprobs",
    "top_logprobs",
    "parallel_tool_calls",
    "reasoning_effort",
    "modalities",
    "audio",
    "prediction",
    "service_tier",
    "store",
    "metadata",
];

/// One typed route error: HTTP status, OpenAI error code, and message.
#[derive(Debug, Clone)]
struct RouteError {
    status: StatusCode,
    code: String,
    message: String,
    error_type: String,
}

impl RouteError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.into(),
            error_type: "invalid_request_error".to_string(),
        }
    }

    fn new_owned(status: StatusCode, code: String, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            error_type: "invalid_request_error".to_string(),
        }
    }

    /// The OpenAI error `type` override (provider failures render the
    /// provider's typed kind).
    fn with_type(mut self, error_type: impl Into<String>) -> Self {
        self.error_type = error_type.into();
        self
    }

    fn response(&self, request_id: &str) -> Response {
        (
            self.status,
            [(X_REQUEST_ID, request_id.to_string())],
            Json(json!({
                "error": {
                    "message": self.message,
                    "type": self.error_type,
                    "code": self.code,
                    "request_id": request_id,
                }
            })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Inbound wire structs (serde; unknown fields land in the extra maps and
// are rejected by the explicit policy below)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(super) struct ChatCompletionRequest {
    model: Option<String>,
    messages: Option<Vec<ChatMessage>>,
    tools: Option<Vec<ChatTool>>,
    tool_choice: Option<Value>,
    stream: Option<bool>,
    stream_options: Option<StreamOptions>,
    temperature: Option<Value>,
    top_p: Option<Value>,
    max_tokens: Option<u64>,
    max_completion_tokens: Option<u64>,
    user: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StreamOptions {
    include_usage: Option<bool>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatMessage {
    role: String,
    content: Option<Value>,
    tool_calls: Option<Vec<ChatToolCall>>,
    tool_call_id: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatToolCall {
    id: Option<String>,
    #[serde(rename = "type")]
    call_type: Option<String>,
    function: Option<ChatFunctionCall>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatFunctionCall {
    name: Option<String>,
    arguments: Option<Value>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatTool {
    #[serde(rename = "type")]
    tool_type: Option<String>,
    function: Option<ChatFunction>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatFunction {
    name: Option<String>,
    description: Option<String>,
    parameters: Option<Value>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

/// One normalized canonical session message.
#[derive(Debug, Clone)]
struct NormalizedMessage {
    role: String,
    /// Canonical content-part array (`text`/`tool_call`/`tool_result` parts).
    content: Value,
    /// Message-level pair id (tool messages only).
    tool_call_id: String,
}

/// The validated, bounded, canonical form of one request.
#[derive(Debug)]
struct NormalizedChat {
    model: Option<String>,
    /// Every message except the final user message (the admission appends
    /// the final user message as the run input, preserving the order).
    messages: Vec<NormalizedMessage>,
    /// The final user message's text content (the run input).
    input: Value,
    /// Canonical tool descriptors `{name, description, schema_json}`.
    /// `None` means the client OMITTED the `tools` field entirely: the RSS
    /// loop falls back to its registry of bounded tools. `Some(vec)` is the
    /// client's explicit declaration — even `Some(vec![])` is EXPLICIT
    /// (tools disabled), never the registry.
    tools: Option<Vec<Value>>,
    tool_choice: Option<String>,
    /// `{temperature?, top_p?}` — only present keys.
    sampling: Value,
    max_output_tokens: Option<u32>,
    /// Preserves the wire spelling requested by the client. OpenAI's current
    /// field is `max_completion_tokens`; legacy-compatible profiles use
    /// `max_tokens`.
    max_output_tokens_field: String,
    stream: bool,
    include_usage: bool,
    /// Typed request metadata (`user`, `include_usage`) — the bounded
    /// client-visible overrides the loop can branch on.
    metadata: Value,
    /// The canonical idempotency hash (same request body -> same hash).
    request_hash: String,
}

// ---------------------------------------------------------------------------
// Validation and normalization
// ---------------------------------------------------------------------------

fn reject_extra_fields(extra: &HashMap<String, Value>) -> Result<(), RouteError> {
    for key in extra.keys() {
        if RESERVED_FIELDS.contains(&key.as_str()) {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "reserved_field",
                format!(
                    "{key} is gateway-owned configuration and cannot be overridden by the client"
                ),
            ));
        }
    }
    for key in extra.keys() {
        if UNSUPPORTED_FIELDS.contains(&key.as_str()) {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "unsupported_field",
                format!("{key} is not supported by this gateway"),
            ));
        }
    }
    if let Some(key) = extra.keys().next() {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "unknown_field",
            format!("unknown request field: {key}"),
        ));
    }
    Ok(())
}

fn bounded_text(
    value: &str,
    max_chars: usize,
    code: &'static str,
    what: &str,
) -> Result<(), RouteError> {
    if value.chars().count() > max_chars {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            code,
            format!("{what} exceeds the {max_chars} character bound"),
        ));
    }
    Ok(())
}

fn durable_content_bytes(value: &Value) -> usize {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .unwrap_or(usize::MAX)
}

fn ensure_durable_content_bytes(value: &Value, what: &str) -> Result<(), RouteError> {
    let bytes = durable_content_bytes(value);
    if bytes > MAX_DURABLE_CONTENT_BYTES {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "message_too_large",
            format!("{what} exceeds the {MAX_DURABLE_CONTENT_BYTES} UTF-8 byte durable bound"),
        ));
    }
    Ok(())
}

/// Normalizes one message's `content` (string or text parts) into the
/// canonical text-part array; returns `None` when the message carries no
/// text content at all.
fn normalize_text_content(content: &Option<Value>) -> Result<Option<Value>, RouteError> {
    let Some(content) = content else {
        return Ok(None);
    };
    match content {
        Value::String(text) => {
            bounded_text(
                text,
                MAX_MESSAGE_CHARS,
                "message_too_large",
                "message content",
            )?;
            if text.is_empty() {
                return Ok(None);
            }
            let normalized = json!([{"type": "text", "text": text}]);
            ensure_durable_content_bytes(&normalized, "message content")?;
            Ok(Some(normalized))
        }
        Value::Array(parts) => {
            let mut normalized = Vec::new();
            for part in parts {
                let Some(part_type) = part.get("type").and_then(Value::as_str) else {
                    return Err(RouteError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_content_part",
                        "content parts must carry a string 'type'",
                    ));
                };
                if part_type != "text" {
                    return Err(RouteError::new(
                        StatusCode::BAD_REQUEST,
                        "unsupported_content_part",
                        format!("content part type '{part_type}' is not supported (text only)"),
                    ));
                }
                let Some(text) = part.get("text").and_then(Value::as_str) else {
                    return Err(RouteError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_content_part",
                        "text content parts must carry a string 'text'",
                    ));
                };
                bounded_text(
                    text,
                    MAX_MESSAGE_CHARS,
                    "message_too_large",
                    "message content",
                )?;
                if !text.is_empty() {
                    normalized.push(json!({"type": "text", "text": text}));
                }
            }
            if normalized.is_empty() {
                return Ok(None);
            }
            let normalized = Value::Array(normalized);
            ensure_durable_content_bytes(&normalized, "message content")?;
            Ok(Some(normalized))
        }
        Value::Null => Ok(None),
        _ => Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "invalid_content",
            "message content must be a string or an array of text parts",
        )),
    }
}

/// Normalizes one assistant `tool_calls` declaration list into canonical
/// `tool_call` parts (bounded).
fn normalize_tool_calls(tool_calls: &Option<Vec<ChatToolCall>>) -> Result<Vec<Value>, RouteError> {
    let Some(tool_calls) = tool_calls else {
        return Ok(Vec::new());
    };
    if tool_calls.len() > MAX_TOOL_CALLS_PER_MESSAGE {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "too_many_tool_calls",
            format!(
                "an assistant message may declare at most {MAX_TOOL_CALLS_PER_MESSAGE} tool calls"
            ),
        ));
    }
    let mut normalized = Vec::new();
    for call in tool_calls {
        reject_extra_fields(&call.extra)?;
        let id = call.id.clone().filter(|id| !id.is_empty()).ok_or_else(|| {
            RouteError::new(
                StatusCode::BAD_REQUEST,
                "invalid_tool_call",
                "assistant tool calls must carry a non-empty 'id'",
            )
        })?;
        bounded_text(
            &id,
            MAX_TOOL_CALL_ID_CHARS,
            "tool_call_id_too_large",
            "tool call id",
        )?;
        if let Some(call_type) = call.call_type.as_deref()
            && call_type != "function"
        {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "invalid_tool_call",
                format!("tool call type '{call_type}' is not supported (function only)"),
            ));
        }
        let function = call.function.as_ref().ok_or_else(|| {
            RouteError::new(
                StatusCode::BAD_REQUEST,
                "invalid_tool_call",
                "assistant tool calls must carry a 'function' object",
            )
        })?;
        reject_extra_fields(&function.extra)?;
        let name = function
            .name
            .clone()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_tool_call",
                    "assistant tool calls must carry a non-empty function name",
                )
            })?;
        bounded_text(
            &name,
            MAX_TOOL_NAME_CHARS,
            "tool_name_too_large",
            "tool name",
        )?;
        let arguments_json = match function.arguments.as_ref() {
            None | Some(Value::Null) => "{}".to_string(),
            Some(Value::String(arguments)) => {
                bounded_text(
                    arguments,
                    MAX_TOOL_CALL_ARGUMENTS_CHARS,
                    "tool_arguments_too_large",
                    "tool call arguments",
                )?;
                arguments.clone()
            }
            Some(Value::Object(_)) => {
                let encoded =
                    serde_json::to_string(&function.arguments).unwrap_or_else(|_| "{}".to_string());
                bounded_text(
                    &encoded,
                    MAX_TOOL_CALL_ARGUMENTS_CHARS,
                    "tool_arguments_too_large",
                    "tool call arguments",
                )?;
                encoded
            }
            Some(_) => {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_tool_call",
                    "tool call arguments must be a string or an object",
                ));
            }
        };
        normalized.push(json!({
            "type": "tool_call",
            "tool_call_id": id,
            "name": name,
            "arguments_json": arguments_json,
        }));
    }
    Ok(normalized)
}

/// Normalizes one message's content into a canonical content-part array:
/// text parts plus (assistant) tool_call parts, or (tool) the tool_result
/// part carrying the message-level pair id.
fn normalize_message_parts(message: &ChatMessage) -> Result<Value, RouteError> {
    let mut parts = Vec::new();
    match message.role.as_str() {
        "assistant" => {
            if let Some(Value::Array(text_parts)) = normalize_text_content(&message.content)? {
                parts.extend(text_parts);
            }
            parts.extend(normalize_tool_calls(&message.tool_calls)?);
        }
        "tool" => {
            if message.tool_calls.is_some() {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_tool_message",
                    "tool messages must not carry tool_calls",
                ));
            }
            let tool_call_id = message
                .tool_call_id
                .clone()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    RouteError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_tool_message",
                        "tool messages must carry a non-empty tool_call_id",
                    )
                })?;
            bounded_text(
                &tool_call_id,
                MAX_TOOL_CALL_ID_CHARS,
                "tool_call_id_too_large",
                "tool_call_id",
            )?;
            // The tool result text: string content passes through; an ARRAY
            // of legal text parts is preserved with fidelity (joined in
            // order); any other typed part or shape is rejected typed —
            // never silently dropped.
            let content = match normalize_text_content(&message.content)? {
                Some(Value::Array(parts)) => parts
                    .iter()
                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                    .collect::<String>(),
                _ => String::new(),
            };
            bounded_text(
                &content,
                MAX_MESSAGE_CHARS,
                "message_too_large",
                "tool result content",
            )?;
            parts.push(json!({
                "type": "tool_result",
                "tool_call_id": tool_call_id,
                "content": content,
                "is_error": false,
            }));
        }
        _ => {
            if let Some(Value::Array(text_parts)) = normalize_text_content(&message.content)? {
                parts.extend(text_parts);
            }
            if message.tool_calls.is_some() {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_message",
                    format!("{} messages must not carry tool_calls", message.role),
                ));
            }
        }
    }
    let normalized = Value::Array(parts);
    ensure_durable_content_bytes(&normalized, "message content")?;
    Ok(normalized)
}

fn normalize_tools(tools: &Option<Vec<ChatTool>>) -> Result<Option<Vec<Value>>, RouteError> {
    let Some(tools) = tools else {
        // Omitted: the loop's registry of bounded tools applies.
        return Ok(None);
    };
    if tools.len() > MAX_TOOLS {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "too_many_tools",
            format!("a request may declare at most {MAX_TOOLS} tools"),
        ));
    }
    let mut normalized = Vec::new();
    for tool in tools {
        reject_extra_fields(&tool.extra)?;
        if let Some(tool_type) = tool.tool_type.as_deref()
            && tool_type != "function"
        {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "invalid_tool",
                format!("tool type '{tool_type}' is not supported (function only)"),
            ));
        }
        let function = tool.function.as_ref().ok_or_else(|| {
            RouteError::new(
                StatusCode::BAD_REQUEST,
                "invalid_tool",
                "tools must carry a 'function' object",
            )
        })?;
        reject_extra_fields(&function.extra)?;
        let name = function
            .name
            .clone()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_tool",
                    "tool functions must carry a non-empty name",
                )
            })?;
        bounded_text(
            &name,
            MAX_TOOL_NAME_CHARS,
            "tool_name_too_large",
            "tool name",
        )?;
        let description = function.description.clone().unwrap_or_default();
        bounded_text(
            &description,
            MAX_TOOL_DESCRIPTION_CHARS,
            "tool_description_too_large",
            "tool description",
        )?;
        let schema_json = match function.parameters.as_ref() {
            None | Some(Value::Null) => "{}".to_string(),
            Some(Value::Object(_)) => {
                let encoded = serde_json::to_string(&function.parameters)
                    .unwrap_or_else(|_| "{}".to_string());
                bounded_text(
                    &encoded,
                    MAX_TOOL_SCHEMA_CHARS,
                    "tool_schema_too_large",
                    "tool schema",
                )?;
                encoded
            }
            Some(_) => {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_tool",
                    "tool parameters must be a JSON object",
                ));
            }
        };
        normalized.push(json!({
            "name": name,
            "description": description,
            "schema_json": schema_json,
        }));
    }
    Ok(Some(normalized))
}

fn normalize_sampling(value: &Option<Value>, what: &str) -> Result<Option<f64>, RouteError> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::Number(number) => {
            let Some(value) = number.as_f64() else {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_sampling",
                    format!("{what} must be a number"),
                ));
            };
            // The official OpenAI sampling ranges: temperature [0, 2] and
            // top_p [0, 1] (negative values are never accepted).
            let (min, max) = match what {
                "temperature" => (0.0, 2.0),
                "top_p" => (0.0, 1.0),
                _ => unreachable!("normalize_sampling supports temperature and top_p"),
            };
            if !(min..=max).contains(&value) {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "out_of_range",
                    format!("{what} must be within [{min}, {max}]"),
                ));
            }
            Ok(Some(value))
        }
        _ => Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "invalid_sampling",
            format!("{what} must be a number or null"),
        )),
    }
}

/// The final user message's text content (the run input).
fn final_user_input(message: &ChatMessage) -> Result<Value, RouteError> {
    let input = message.content.clone().unwrap_or(Value::Null);
    let input = match input {
        Value::String(text) => Value::String(text),
        Value::Array(parts) => {
            let text = parts
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("");
            Value::String(text)
        }
        _ => Value::Null,
    };
    if input.as_str().is_none_or(str::is_empty) {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "empty_message",
            "the final user message must carry non-empty text content",
        ));
    }
    Ok(input)
}

/// Validates and normalizes the parsed request into the canonical bounded
/// form. Every failure is a typed 400 before any session or run work.
fn normalize_request(request: ChatCompletionRequest) -> Result<NormalizedChat, RouteError> {
    reject_extra_fields(&request.extra)?;
    if let Some(stream_options) = &request.stream_options {
        reject_extra_fields(&stream_options.extra)?;
    }
    if request.stream_options.is_some() && request.stream != Some(true) {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "invalid_stream_options",
            "stream_options are only allowed when stream is true",
        ));
    }
    let model = request
        .model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(ToOwned::to_owned);
    if let Some(model) = &model {
        bounded_text(model, MAX_TOOL_NAME_CHARS, "model_too_large", "model")?;
    }

    let messages = request.messages.ok_or_else(|| {
        RouteError::new(
            StatusCode::BAD_REQUEST,
            "missing_messages",
            "the request must carry a 'messages' array",
        )
    })?;
    if messages.is_empty() {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "missing_messages",
            "the 'messages' array must not be empty",
        ));
    }
    if messages.len() > MAX_MESSAGES {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "too_many_messages",
            format!("a request may carry at most {MAX_MESSAGES} messages"),
        ));
    }
    let tools = normalize_tools(&request.tools)?;
    let tool_choice = match request.tool_choice.as_ref() {
        None | Some(Value::Null) => None,
        Some(Value::String(choice)) => match choice.as_str() {
            "auto" | "none" | "required" => Some(choice.clone()),
            _ => {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_tool_choice",
                    format!("tool_choice '{choice}' is not supported (auto|none|required)"),
                ));
            }
        },
        Some(Value::Object(_)) => {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "unsupported_tool_choice",
                "the canonical tool_choice contract is a string (auto|none|required); \
                 function-specific choice objects are not supported",
            ));
        }
        Some(_) => {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "invalid_tool_choice",
                "tool_choice must be a string or null",
            ));
        }
    };
    let temperature = normalize_sampling(&request.temperature, "temperature")?;
    let top_p = normalize_sampling(&request.top_p, "top_p")?;
    if request.max_tokens.is_some() && request.max_completion_tokens.is_some() {
        return Err(RouteError::new(
            StatusCode::BAD_REQUEST,
            "conflicting_output_tokens",
            "max_tokens and max_completion_tokens are aliases; set only one",
        ));
    }
    let max_output_tokens_field = if request.max_completion_tokens.is_some() {
        "max_completion_tokens".to_string()
    } else {
        "max_tokens".to_string()
    };
    let max_output_tokens = request
        .max_tokens
        .or(request.max_completion_tokens)
        .map(|tokens| {
            if tokens > MAX_OUTPUT_TOKENS {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "out_of_range",
                    format!("max output tokens must be at most {MAX_OUTPUT_TOKENS}"),
                ));
            }
            Ok(tokens as u32)
        })
        .transpose()?;
    let user = request
        .user
        .as_deref()
        .map(str::trim)
        .filter(|user| !user.is_empty())
        .map(ToOwned::to_owned);
    if let Some(user) = &user {
        bounded_text(user, MAX_USER_CHARS, "user_too_large", "user")?;
    }

    // Normalize each message; collect the declared assistant tool-call ids
    // so tool messages can be paired (bounded linear scan).
    let mut declared_call_ids: Vec<String> = Vec::new();
    let mut normalized_messages: Vec<NormalizedMessage> = Vec::new();
    let mut input = Value::Null;
    for (index, message) in messages.iter().enumerate() {
        reject_extra_fields(&message.extra)?;
        let role = message.role.trim().to_string();
        if !matches!(role.as_str(), "system" | "user" | "assistant" | "tool") {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "invalid_role",
                format!("message role '{role}' is not supported (system|user|assistant|tool)"),
            ));
        }
        let content = normalize_message_parts(message)?;
        let is_last_user = index + 1 == messages.len();
        // The OpenAI contract: the last message must be a user message
        // (checked after the role validation so an invalid role reports the
        // more specific error).
        if is_last_user && role != "user" {
            return Err(RouteError::new(
                StatusCode::BAD_REQUEST,
                "last_message_not_user",
                "the last message must have role 'user'",
            ));
        }
        if is_last_user {
            // The final user message becomes the run input; it is NOT
            // pre-appended (the admission appends it as the run's message).
            input = final_user_input(message)?;
            continue;
        }
        // A tool message's tool_call_id must reference a declared assistant
        // tool call (the OpenAI pairing contract).
        let mut tool_call_id = String::new();
        if role == "tool" {
            let id = message
                .tool_call_id
                .clone()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    RouteError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_tool_message",
                        "tool messages must carry a non-empty tool_call_id",
                    )
                })?;
            if !declared_call_ids.contains(&id) {
                return Err(RouteError::new(
                    StatusCode::BAD_REQUEST,
                    "tool_call_id_not_declared",
                    format!(
                        "tool_call_id '{id}' does not reference a declared assistant tool call"
                    ),
                ));
            }
            tool_call_id = id;
        }
        if role == "assistant"
            && let Some(calls) = &message.tool_calls
        {
            for call in calls {
                if let Some(id) = call.id.as_deref() {
                    declared_call_ids.push(id.to_string());
                }
            }
        }
        normalized_messages.push(NormalizedMessage {
            role,
            content,
            tool_call_id,
        });
    }

    let include_usage = request
        .stream_options
        .as_ref()
        .and_then(|options| options.include_usage)
        .unwrap_or(false);
    let stream = request.stream.unwrap_or(false);
    let mut sampling = serde_json::Map::new();
    if let Some(temperature) = temperature {
        sampling.insert("temperature".to_string(), json!(temperature));
    }
    if let Some(top_p) = top_p {
        sampling.insert("top_p".to_string(), json!(top_p));
    }
    let mut metadata = serde_json::Map::new();
    if let Some(user) = user.as_deref() {
        metadata.insert("user".to_string(), json!(user));
    }
    metadata.insert("include_usage".to_string(), json!(include_usage));

    let canonical = serde_json::to_string(&json!({
        "model": model,
        "messages": normalized_messages
            .iter()
            .map(|message| json!({"role": message.role, "content": message.content, "tool_call_id": message.tool_call_id}))
            .collect::<Vec<_>>(),
        "input": input_text(&input),
        "tools": tools,
        "tools_explicit": tools.is_some(),
        "tool_choice": tool_choice,
        "stream": stream,
        "include_usage": include_usage,
        "sampling": Value::Object(sampling.clone()),
        "max_output_tokens": max_output_tokens,
        "max_output_tokens_field": max_output_tokens_field,
        // The bounded `user` metadata is part of the request identity: two
        // requests that differ only in `user` must never collide on one
        // idempotency key.
        "user": user,
    }))
    .unwrap_or_default();

    Ok(NormalizedChat {
        model,
        messages: normalized_messages,
        input,
        tools,
        tool_choice,
        sampling: Value::Object(sampling),
        max_output_tokens,
        max_output_tokens_field,
        stream,
        include_usage,
        metadata: Value::Object(metadata),
        request_hash: format!("fnv64:{:016x}", fnv1a64(canonical.as_bytes())),
    })
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub(super) async fn openai_chat_completions_handler(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    body: Result<Json<ChatCompletionRequest>, JsonRejection>,
) -> Response {
    let request_id = request_id_from_headers(&headers);
    let resume = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(parse_chunk_cursor);
    let request = match body {
        Ok(Json(request)) => request,
        Err(rejection) => {
            // Every client parse failure answers the SAME typed contract:
            // syntax errors AND wrong-shape bodies map to 400 with the
            // typed code (never an inconsistent 422), so the error
            // HTTP status/type is uniform across all gateway errors.
            let (status, code) = match rejection.status() {
                StatusCode::BAD_REQUEST => (StatusCode::BAD_REQUEST, "invalid_json"),
                StatusCode::UNPROCESSABLE_ENTITY => (StatusCode::BAD_REQUEST, "invalid_request"),
                other => (other, "invalid_request"),
            };
            return RouteError::new(status, code, rejection.body_text()).response(&request_id);
        }
    };
    let normalized = match normalize_request(request) {
        Ok(normalized) => normalized,
        Err(error) => return error.response(&request_id),
    };

    let model = normalized
        .model
        .clone()
        .unwrap_or_else(|| state.config.model.clone());

    // The typed per-request overrides rendered into the canonical run
    // context `request` map (never string markers, never credentials).
    let request_overrides = json!({
        // OpenAI's omission and an explicit empty array both mean that this
        // request declares no tools.  The registry fallback remains the
        // legacy/Telegram policy; it must never silently appear on the
        // OpenAI-compatible route.  Only a non-empty explicit declaration is
        // forwarded to the loop.
        "tools": normalized.tools.clone().unwrap_or_default(),
        "tools_explicit": true,
        "tool_choice": normalized.tool_choice,
        "sampling": normalized.sampling,
        "max_output_tokens": normalized.max_output_tokens,
        "max_output_tokens_field": normalized.max_output_tokens_field,
        "stream": normalized.stream,
        "metadata": normalized.metadata,
    });

    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    // The normalized conversation history is persisted INSIDE the
    // admission transaction (session + messages + run + idempotency are
    // one atomic durable commit), so a failed admission leaves no partial
    // session and a replayed idempotency key never creates a new one.
    let session_messages = normalized
        .messages
        .iter()
        .map(|message| SessionMessageDraft {
            role: message.role.clone(),
            content: message.content.clone(),
            tool_call_id: message.tool_call_id.clone(),
        })
        .collect::<Vec<_>>();
    let admitted = match state
        .service
        .admit(AdmitRunRequest {
            input: normalized.input.clone(),
            session_id: None,
            model: normalized.model.clone(),
            // The provider/profile ALWAYS comes from the gateway config; the
            // client cannot override it (reserved_field rejection above).
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "api_openai".to_string(),
            idempotency_key,
            idempotency_hash: Some(normalized.request_hash.clone()),
            origin_actor: None,
            request_overrides,
            session_messages,
        })
        .await
    {
        Ok(admitted) => admitted,
        Err(error) => return admit_error_response(&error, &request_id),
    };

    // A replayed admission NEVER spawns a second worker: the run already
    // has its worker (in flight) or is terminal, so provider calls and
    // tool side effects stay exact-once. The response attaches to the
    // existing run's history/live stream instead.
    if !admitted.replayed {
        let worker_run_id = admitted.run_id.clone();
        let worker_input = input_text(&normalized.input);
        let service = state.service();
        tokio::spawn(async move {
            // A worker that exits without committing a terminal (for example
            // a panic) must fail the run rather than leave it started
            // forever.
            let outcome = tokio::task::spawn(
                service
                    .clone()
                    .run_worker(worker_run_id.clone(), worker_input),
            )
            .await;
            if outcome.is_err() {
                service
                    .finish_failed(
                        &worker_run_id,
                        failed_payload(
                            "agent worker exited without a terminal outcome".to_string(),
                        ),
                    )
                    .await;
            }
        });
    }

    if normalized.stream {
        let (history, receiver) = {
            let store = state.store.read();
            let Some(run) = store.runs.get(&admitted.run_id) else {
                return RouteError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "run_not_found",
                    "the admitted run vanished before streaming started",
                )
                .response(&request_id);
            };
            (
                run.events.clone(),
                run.sender.as_ref().map(|sender| sender.subscribe()),
            )
        };
        let guard = state.service.attach_subscriber(&admitted.run_id);
        let created_at = history
            .first()
            .map(|event| event.timestamp)
            .unwrap_or_else(timestamp);
        let persistence = state.service.persistence_handle();
        let stream = completion_sse_stream(
            SseRenderParams {
                run_id: admitted.run_id.clone(),
                model,
                created_at,
                include_usage: normalized.include_usage,
                resume,
            },
            history,
            receiver,
            guard,
            persistence,
        );
        let mut response = Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(SSE_KEEP_ALIVE_INTERVAL))
            .into_response();
        // The SSE response carries the same bounded x-request-id as every
        // other route answer.
        response.headers_mut().insert(
            X_REQUEST_ID,
            HeaderValue::from_str(&request_id).expect("the bounded request id is a valid header"),
        );
        response
    } else {
        let deadline = Duration::from_secs(state.config.run_timeout.as_secs().saturating_add(30));
        let outcome =
            wait_for_buffered_completion(&state, &admitted.run_id, &model, deadline).await;
        match outcome {
            Ok(completion) => (
                StatusCode::OK,
                [(X_REQUEST_ID, request_id)],
                Json(completion),
            )
                .into_response(),
            Err(error) => error.response(&request_id),
        }
    }
}

/// The bounded `x-request-id`: echoes a well-formed inbound value, otherwise
/// generates one.
fn request_id_from_headers(headers: &HeaderMap) -> String {
    let inbound = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value.chars().count() <= MAX_REQUEST_ID_CHARS
                && value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        });
    inbound
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("req-{}", Uuid::new_v4()))
}

fn admit_error_response(error: &AdmitError, request_id: &str) -> Response {
    let (status, code, message) = match error {
        AdmitError::RunLimitReached => (
            StatusCode::TOO_MANY_REQUESTS,
            "run_limit_reached",
            "maximum concurrent run limit reached".to_string(),
        ),
        AdmitError::IdempotencyConflict => (
            StatusCode::CONFLICT,
            "idempotency_key_reused",
            "idempotency key was used with a different request".to_string(),
        ),
        AdmitError::ParentNotFound => (
            StatusCode::NOT_FOUND,
            "parent_run_not_found",
            "parent run not found".to_string(),
        ),
        AdmitError::ParentNotActive => (
            StatusCode::CONFLICT,
            "parent_run_not_active",
            "parent run is terminal or stopping; no child can be admitted".to_string(),
        ),
        AdmitError::SessionNotFound => (
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found".to_string(),
        ),
        AdmitError::Persistence(message) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence_unavailable",
            message.clone(),
        ),
        AdmitError::Invalid(message) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_admission",
            message.clone(),
        ),
        AdmitError::Halting => (
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_halting",
            "gateway is halting; new runs are not admitted".to_string(),
        ),
    };
    RouteError::new(status, code, message).response(request_id)
}

// ---------------------------------------------------------------------------
// Buffered rendering
// ---------------------------------------------------------------------------

/// The provider round (`turn`) an event belongs to; `None` when the event
/// carries no turn field (defensive: turn-less events never trigger a
/// round filter, so nothing is dropped on legacy event shapes).
fn event_turn(event: &GatewayEvent) -> Option<i64> {
    event.data.get("turn").and_then(Value::as_i64)
}

/// The FINAL provider round's tool calls: only `tool.started` events whose
/// turn equals the last observed turn. Internal tool rounds executed by
/// the A5 loop never leak as client tool_calls; when no event carries a
/// turn at all (legacy), every call is kept.
fn final_round_tool_calls(calls: &[(Option<i64>, Value)], final_turn: Option<i64>) -> Vec<Value> {
    calls
        .iter()
        .filter(|(turn, _)| final_turn.is_none() || *turn == final_turn)
        .map(|(_, call)| call.clone())
        .collect()
}

/// Waits for the run's durable terminal (history first, then the live
/// broadcast, then the durable replay fallback) and renders the official
/// buffered completion shape. All data comes from canonical events; a
/// failed/cancelled terminal renders the typed error. Only the FINAL
/// provider round is rendered: text/finish/usage come from the terminal
/// and tool_calls are filtered to the final round's `tool.started` events.
async fn wait_for_buffered_completion(
    state: &AgentGatewayState,
    run_id: &str,
    model: &str,
    deadline: Duration,
) -> Result<Value, RouteError> {
    let guard = state.service.attach_subscriber(run_id);
    // The store read guard is parking_lot's `!Send` guard: it must drop
    // before any await, so the snapshot is taken inside a scoped block.
    let snapshot = {
        let store = state.store.read();
        store.runs.get(run_id).map(|run| {
            (
                run.events.clone(),
                run.sender.as_ref().map(|sender| sender.subscribe()),
            )
        })
    };
    let Some((history, receiver)) = snapshot else {
        return durable_completion(state, run_id, model, deadline, guard).await;
    };

    let mut tool_calls: Vec<(Option<i64>, Value)> = Vec::new();
    let mut last_turn: Option<i64> = None;
    let mut first_timestamp = 0u64;
    let mut terminal: Option<GatewayEvent> = None;
    for event in &history {
        if let Some(turn) = event_turn(event) {
            last_turn = Some(turn);
        }
        if event.event == "tool.started" {
            tool_calls.push((event_turn(event), render_tool_call(&event.data, 0)));
        }
        if first_timestamp == 0 {
            first_timestamp = event.timestamp;
        }
        if event.is_terminal() {
            terminal = Some(event.clone());
            break;
        }
    }
    let mut guard = guard;
    if let Some(terminal) = terminal {
        if let Some(guard) = guard.as_mut() {
            guard.disarm();
        }
        let terminal = if let Some(persistence) = state.service.persistence_handle() {
            hydrate_completed_terminal(&persistence, &terminal)?
        } else {
            terminal
        };
        return buffered_terminal_result(
            run_id,
            model,
            first_timestamp,
            &terminal,
            &final_round_tool_calls(&tool_calls, last_turn),
        );
    }

    let mut receiver = match receiver {
        Some(receiver) => receiver,
        None => {
            return durable_completion(state, run_id, model, deadline, guard).await;
        }
    };
    let outcome = tokio::time::timeout(deadline, async {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if let Some(turn) = event_turn(&event) {
                        last_turn = Some(turn);
                    }
                    if event.event == "tool.started" {
                        tool_calls.push((event_turn(&event), render_tool_call(&event.data, 0)));
                    }
                    if first_timestamp == 0 {
                        first_timestamp = event.timestamp;
                    }
                    if event.is_terminal() {
                        return Ok(event);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // The bounded buffer dropped events; the terminal may be
                    // among them — fall back to the durable replay.
                    return Err(());
                }
                Err(broadcast::error::RecvError::Closed) => return Err(()),
            }
        }
    })
    .await;
    match outcome {
        Ok(Ok(terminal)) => {
            if let Some(guard) = guard.as_mut() {
                guard.disarm();
            }
            let terminal = if let Some(persistence) = state.service.persistence_handle() {
                hydrate_completed_terminal(&persistence, &terminal)?
            } else {
                terminal
            };
            buffered_terminal_result(
                run_id,
                model,
                first_timestamp,
                &terminal,
                &final_round_tool_calls(&tool_calls, last_turn),
            )
        }
        Ok(Err(())) => durable_completion(state, run_id, model, deadline, guard).await,
        Err(_) => {
            // The wait bounded out while the run is still active: the
            // subscriber guard stays armed, so the configured
            // client-disconnect policy still applies when it drops.
            Err(RouteError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "completion_wait_timeout",
                "the run did not reach a terminal within the bounded wait",
            ))
        }
    }
}

/// Durable replay fallback: polls the typed event replay until a terminal
/// event appears (or the deadline expires). Covers replays of already
/// terminal runs whose in-memory handle is gone.
async fn durable_completion(
    state: &AgentGatewayState,
    run_id: &str,
    model: &str,
    deadline: Duration,
    guard: Option<SubscriberGuard>,
) -> Result<Value, RouteError> {
    let Some(persistence) = state.service.persistence_handle() else {
        // No durable store: the run is gone from memory and cannot be
        // replayed.
        return Err(RouteError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "run_not_found",
            "the run is no longer retained",
        ));
    };
    let started = std::time::Instant::now();
    // Resume cursor for the paged durable replay (advances per poll so a
    // terminal beyond the first page is still observed within the window).
    let mut after_seq = 0u64;
    loop {
        if started.elapsed() >= deadline {
            return Err(RouteError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "completion_wait_timeout",
                "the run did not reach a terminal within the bounded wait",
            ));
        }
        // Page forward from the last seen sequence: with the durable
        // retention window (up to 16384 events) the terminal can sit beyond
        // the first page, and replaying only the head would never observe
        // it. Each poll advances the cursor, so every retained event is
        // scanned exactly once until the terminal (or the bounded wait).
        let data = persistence
            .event_replay(&json!({
                "run_id": run_id,
                "after_seq": after_seq,
                "max_events": 2048,
                "max_bytes": 262144,
            }))
            .map_err(|error| {
                RouteError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "persistence_unavailable",
                    format!("durable event replay failed: {error}"),
                )
            })?;
        let mut tool_calls: Vec<(Option<i64>, Value)> = Vec::new();
        let mut last_turn: Option<i64> = None;
        let mut first_timestamp = 0u64;
        let mut terminal = None;
        if let Some(rows) = data.get("rows").and_then(Value::as_array) {
            for row in rows {
                let Some(row) = row.as_array() else {
                    continue;
                };
                let seq = row.first().and_then(Value::as_u64).unwrap_or(0);
                if seq > after_seq {
                    after_seq = seq;
                }
                let event_type = row.get(3).and_then(Value::as_str).unwrap_or("");
                let payload: Value = row
                    .get(4)
                    .and_then(Value::as_str)
                    .and_then(|text| serde_json::from_str(text).ok())
                    .unwrap_or(Value::Null);
                let created_at = row.get(5).and_then(Value::as_u64).unwrap_or(0);
                let event = GatewayEvent {
                    event_id: String::new(),
                    seq: 0,
                    event: event_type.to_string(),
                    run_id: run_id.to_string(),
                    timestamp: created_at,
                    data: payload.clone(),
                };
                if let Some(turn) = event_turn(&event) {
                    last_turn = Some(turn);
                }
                if event_type == "tool.started" {
                    tool_calls.push((event_turn(&event), render_tool_call(&event.data, 0)));
                }
                if first_timestamp == 0 {
                    first_timestamp = created_at;
                }
                if matches!(event_type, "run.completed" | "run.cancelled" | "run.failed") {
                    terminal = Some((event_type.to_string(), payload));
                    break;
                }
            }
        }
        if let Some((event_type, payload)) = terminal {
            let event = GatewayEvent {
                event_id: String::new(),
                seq: 0,
                event: event_type,
                run_id: run_id.to_string(),
                timestamp: first_timestamp,
                data: payload,
            };
            let event = if event.event == "run.completed" {
                hydrate_completed_terminal(&persistence, &event)?
            } else {
                event
            };
            let mut guard = guard;
            if let Some(guard) = guard.as_mut() {
                guard.disarm();
            }
            return buffered_terminal_result(
                run_id,
                model,
                first_timestamp,
                &event,
                &final_round_tool_calls(&tool_calls, last_turn),
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Renders one canonical `tool.started` event as an OpenAI message tool
/// call (the canonical id/name/arguments, never fabricated). The `index`
/// field is the stream-delta shape; the buffered renderer strips it.
fn render_tool_call(data: &Value, index: usize) -> Value {
    let arguments = data
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    json!({
        "id": data.get("tool_call_id").and_then(Value::as_str).unwrap_or(""),
        "type": "function",
        "function": {
            "name": data.get("name").and_then(Value::as_str).unwrap_or(""),
            "arguments": serde_json::to_string(&arguments).unwrap_or_else(|_| "{}".to_string()),
        },
        "index": index,
    })
}

/// Rehydrates a completed terminal from its RSS-owned message reference.
/// Terminal run events are intentionally bounded, so long assistant content
/// may be absent from the event payload while the durable message remains
/// complete.
fn hydrate_completed_terminal(
    persistence: &GatewayPersistence,
    terminal: &GatewayEvent,
) -> Result<GatewayEvent, RouteError> {
    if terminal.data["output"]["message"].is_object() {
        return Ok(terminal.clone());
    }
    let Some(message_id) = terminal.data.get("message_id").and_then(Value::as_str) else {
        return Ok(terminal.clone());
    };
    let Some(session_id) = terminal.data.get("session_id").and_then(Value::as_str) else {
        return Err(RouteError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "terminal_output_unavailable",
            "the terminal message ownership tuple is missing",
        ));
    };
    let data = persistence
        .message_get(message_id, session_id, &terminal.run_id)
        .map_err(|error| {
            RouteError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "terminal_output_unavailable",
                format!("durable assistant message lookup failed: {error}"),
            )
        })?;
    let Some(row) = data
        .get("rows")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(Value::as_array)
    else {
        return Err(RouteError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "terminal_output_unavailable",
            "the durable assistant message was not found",
        ));
    };
    let content = row
        .get(4)
        .and_then(Value::as_str)
        .and_then(|content| serde_json::from_str::<Value>(content).ok())
        .unwrap_or_else(|| json!(""));
    let message = json!({
        "id": row.first().and_then(Value::as_str).unwrap_or(message_id),
        "role": row.get(3).and_then(Value::as_str).unwrap_or("assistant"),
        "content": content,
        "finish_reason": row.get(12).and_then(Value::as_str).unwrap_or("stop"),
    });
    let mut hydrated = terminal.clone();
    hydrated.data["output"] = json!({"message": message});
    Ok(hydrated)
}

/// Maps one terminal canonical event to the buffered route outcome:
/// `run.completed` renders the official shape; `run.failed` renders the
/// typed error (502 for provider failures, 500 otherwise); `run.cancelled`
/// renders the typed cancellation error.
fn buffered_terminal_result(
    run_id: &str,
    model: &str,
    created_at: u64,
    terminal: &GatewayEvent,
    tool_calls: &[Value],
) -> Result<Value, RouteError> {
    match terminal.event.as_str() {
        "run.completed" => {
            let message = &terminal.data["output"]["message"];
            let text = message
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let finish_reason = message
                .get("finish_reason")
                .and_then(Value::as_str)
                .unwrap_or("stop")
                .to_string();
            let usage = openai_usage(terminal.data.get("usage").unwrap_or(&Value::Null));
            let mut message_map = serde_json::Map::new();
            message_map.insert("role".to_string(), json!("assistant"));
            message_map.insert("content".to_string(), json!(text));
            if !tool_calls.is_empty() {
                // Strip the stream-only `index` field from the buffered
                // message shape (OpenAI message tool_calls carry no index).
                let calls = tool_calls
                    .iter()
                    .map(|call| {
                        let mut call = call.clone();
                        if let Some(object) = call.as_object_mut() {
                            object.remove("index");
                        }
                        call
                    })
                    .collect::<Vec<_>>();
                message_map.insert("tool_calls".to_string(), json!(calls));
            }
            Ok(json!({
                "id": run_id,
                "object": "chat.completion",
                "created": created_at / 1000,
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": Value::Object(message_map),
                    "finish_reason": finish_reason,
                }],
                "usage": usage,
            }))
        }
        "run.failed" => {
            let provider_failure = terminal.data.get("provider_error").is_some();
            let status = if provider_failure {
                StatusCode::BAD_GATEWAY
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            // The typed provider error is rendered from the durable
            // terminal: the provider's own code/message/type when the
            // failure carried one.
            let code = terminal
                .data
                .get("error_code")
                .and_then(Value::as_str)
                .unwrap_or("agent_error")
                .to_string();
            let message = terminal
                .data
                .get("error_message")
                .and_then(Value::as_str)
                .unwrap_or("the agent run failed")
                .to_string();
            let error_type = terminal
                .data
                .get("provider_error")
                .and_then(|error| error.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("agent_error")
                .to_string();
            Err(RouteError::new_owned(status, code, message).with_type(error_type))
        }
        "run.cancelled" => Err(RouteError::new_owned(
            StatusCode::INTERNAL_SERVER_ERROR,
            "run_cancelled".to_string(),
            terminal
                .data
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("cancelled")
                .to_string(),
        )
        .with_type("agent_error")),
        other => Err(RouteError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent_error",
            format!("unexpected terminal event: {other}"),
        )),
    }
}

/// Canonical usage -> OpenAI usage names (zeros only when the canonical
/// event carried none — never fabricated nonzero numbers).
fn openai_usage(usage: &Value) -> Value {
    json!({
        "prompt_tokens": usage.get("input_tokens").and_then(Value::as_u64).unwrap_or(0),
        "completion_tokens": usage.get("output_tokens").and_then(Value::as_u64).unwrap_or(0),
        "total_tokens": usage.get("total_tokens").and_then(Value::as_u64).unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Streaming rendering (SSE chunks from canonical live/durable events)
// ---------------------------------------------------------------------------

/// The immutable rendering parameters of one SSE completion stream.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ChunkCursor {
    seq: u64,
    subindex: u32,
}

fn parse_chunk_cursor(value: &str) -> Option<ChunkCursor> {
    if let Some((seq, subindex)) = value.split_once(':') {
        return Some(ChunkCursor {
            seq: seq.parse().ok()?,
            subindex: subindex.parse().ok()?,
        });
    }
    // Accept the pre-subindex numeric form as an event-level cursor for
    // compatibility; all newly emitted ids use the canonical pair form.
    Some(ChunkCursor {
        seq: value.parse().ok()?,
        subindex: 0,
    })
}

fn chunk_id(seq: u64, subindex: u32) -> String {
    format!("{seq}:{subindex}")
}

struct SseRenderParams {
    run_id: String,
    model: String,
    created_at: u64,
    include_usage: bool,
    resume: Option<ChunkCursor>,
}

/// One rendered SSE outbound chunk: the optional Last-Event id, the
/// optional SSE event name (error chunks), and the raw data payload text.
/// Kept as plain data so the renderer stays fully unit-testable (the
/// axum `Event` buffer is private); the stream wrapper converts this to
/// an axum `Event` at the boundary.
struct SseChunk {
    id: Option<String>,
    event: Option<String>,
    data: String,
}

/// Renders the run's canonical events as OpenAI SSE chunks. ONLY the FINAL
/// provider round is rendered: the stream buffers each round's text/tool
/// deltas (bounded), drops the buffer when the round advances (that round
/// was INTERNAL — A5 executed its tools itself, and its text/tool chunks
/// must never reach the client), and flushes it only when the terminal
/// confirms the round is the final response. A `Lagged` live receiver
/// recovers through the DURABLE catch-up (every event was persisted before
/// publish), so no chunk is silently lost; a failed catch-up surfaces the
/// typed error chunk. The first flushed chunk carries the assistant role;
/// failure/cancellation terminals render a typed error chunk with the SAME
/// type as the buffered contract; `[DONE]` is always last. Every chunk
/// carries the durable event sequence as the SSE `id`.
///
/// Buffered/stream contract (explicit): the per-round text buffer holds at
/// most [`MAX_STREAM_BUFFERED_DELTAS`] chunks / [`MAX_STREAM_BUFFERED_CHARS`]
/// characters; the tool buffer holds at most
/// [`MAX_STREAM_BUFFERED_TOOL_CALLS`] chunks. Text overflow falls back to
/// the AUTHORITATIVE terminal text (lossless for text, never a silent
/// drop) while any buffered tool chunks are preserved and streamed. Tool
/// overflow (the final round declared more tool calls than the buffer can
/// carry) ends the stream with the typed `stream_buffer_overflow` error
/// chunk followed by `[DONE]` — explicit, never a silently truncated tool
/// list.
fn completion_sse_stream(
    params: SseRenderParams,
    history: Vec<GatewayEvent>,
    receiver: Option<broadcast::Receiver<GatewayEvent>>,
    guard: Option<SubscriberGuard>,
    persistence: Option<Arc<GatewayPersistence>>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(
        CompletionSse {
            run_id: params.run_id,
            model: params.model,
            created_at: params.created_at,
            include_usage: params.include_usage,
            resume: params.resume,
            history: history.into_iter(),
            receiver,
            guard,
            persistence,
            pending: VecDeque::new(),
            catch_up: VecDeque::new(),
            current_turn: None,
            buffered: VecDeque::new(),
            buffered_tools: VecDeque::new(),
            buffered_chars: 0,
            buffered_tool_calls: 0,
            buffered_overflown: false,
            buffered_tool_overflown: false,
            tool_index: 0,
            first_chunk: true,
            done: false,
            last_seq: 0,
        },
        move |mut state| async move {
            let chunk = state.next_event().await?;
            Some((Ok(chunk.into_event()), state))
        },
    )
}

/// The per-turn bounded SSE rendering state machine (see
/// [`completion_sse_stream`]).
struct CompletionSse {
    run_id: String,
    model: String,
    created_at: u64,
    include_usage: bool,
    resume: Option<ChunkCursor>,
    history: std::vec::IntoIter<GatewayEvent>,
    receiver: Option<broadcast::Receiver<GatewayEvent>>,
    guard: Option<SubscriberGuard>,
    persistence: Option<Arc<GatewayPersistence>>,
    /// Ready-to-send chunks (terminal chunks, [DONE], error chunks).
    pending: VecDeque<SseChunk>,
    /// Events recovered from the durable catch-up (fed through the SAME
    /// rendering path, so the turn filter still applies).
    catch_up: VecDeque<GatewayEvent>,
    /// The provider round whose chunks are buffered.
    current_turn: Option<i64>,
    /// The bounded per-round TEXT delta buffer.
    buffered: VecDeque<(u64, Value)>,
    /// The bounded per-round TOOL-CALL chunk buffer (separate from the text
    /// buffer so text overflow never silently drops tool calls).
    buffered_tools: VecDeque<(u64, Value)>,
    /// The buffered text budget (chars).
    buffered_chars: usize,
    /// The buffered tool-call chunk count.
    buffered_tool_calls: usize,
    /// The TEXT buffer bound was exceeded: flush falls back to the
    /// authoritative terminal text (lossless, never a silent drop) while
    /// buffered tool chunks are preserved.
    buffered_overflown: bool,
    /// The TOOL buffer bound was exceeded in the final round: the stream
    /// ends with the typed `stream_buffer_overflow` error chunk + [DONE]
    /// (explicit, never a silent tool-call truncation).
    buffered_tool_overflown: bool,
    /// Tool-call index within the buffered (final) round.
    tool_index: usize,
    /// The next flushed chunk is the stream's first: it carries the
    /// assistant role (OpenAI delta contract). Cleared immediately when the
    /// first role-bearing delta/tool chunk is buffered.
    first_chunk: bool,
    done: bool,
    /// The seq of the last consumed event (the durable catch-up cursor).
    last_seq: u64,
}

impl SseChunk {
    /// Wraps the plain chunk data as an axum SSE event at the stream
    /// boundary (the renderer itself stays free of the opaque axum buffer).
    fn into_event(self) -> Event {
        let mut event = Event::default();
        if let Some(id) = self.id {
            event = event.id(id);
        }
        if let Some(name) = self.event {
            event = event.event(name);
        }
        event.data(&self.data)
    }
}

impl CompletionSse {
    fn base_chunk(&self, object: &str) -> Value {
        json!({
            "id": self.run_id,
            "object": object,
            "created": self.created_at / 1000,
            "model": self.model,
        })
    }

    fn skip_for_resume(&self, seq: u64, subindex: u32) -> bool {
        self.resume
            .is_some_and(|cursor| ChunkCursor { seq, subindex } <= cursor)
    }

    fn queue_chunk(&mut self, seq: u64, subindex: u32, data: Value) {
        if self.skip_for_resume(seq, subindex) {
            return;
        }
        self.pending.push_back(SseChunk {
            id: Some(chunk_id(seq, subindex)),
            event: None,
            data: data.to_string(),
        });
    }

    /// Adds the role before applying resume filtering.  This preserves the
    /// original stream's role placement when a reconnect skips the first
    /// chunk; a later chunk must not grow a second synthetic role.
    fn queue_delta_chunk(&mut self, seq: u64, subindex: u32, data: Value) {
        let data = if self.first_chunk {
            self.first_chunk = false;
            Self::with_role(data)
        } else {
            data
        };
        self.queue_chunk(seq, subindex, data);
    }

    /// Inserts the assistant role into a delta chunk's `choices[0].delta`
    /// (the OpenAI delta contract puts the role on the first flushed
    /// chunk only).
    fn with_role(data: Value) -> Value {
        let mut data = data;
        if let Some(choice) = data["choices"][0].as_object_mut()
            && let Some(delta) = choice.get_mut("delta").and_then(Value::as_object_mut)
        {
            delta.insert("role".to_string(), json!("assistant"));
        }
        data
    }

    /// Buffers one text delta chunk for the CURRENT provider round. The
    /// buffer is bounded; once the text bound is exceeded the round is
    /// marked overflown and the flush falls back to the authoritative
    /// terminal text — never a silent drop.
    fn buffer_delta(&mut self, event: GatewayEvent) {
        let delta = event
            .data
            .get("delta")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if delta.is_empty() {
            return;
        }
        if self.buffered_overflown
            || self.buffered.len() >= MAX_STREAM_BUFFERED_DELTAS
            || self.buffered_chars.saturating_add(delta.len()) > MAX_STREAM_BUFFERED_CHARS
        {
            self.buffered_overflown = true;
            return;
        }
        let mut chunk = self.base_chunk("chat.completion.chunk");
        let mut delta_map = serde_json::Map::new();
        delta_map.insert("content".to_string(), json!(delta));
        chunk["choices"] =
            json!([{"index": 0, "delta": Value::Object(delta_map), "finish_reason": null}]);
        self.buffered_chars += delta.len();
        self.buffered.push_back((event.seq, chunk));
    }

    /// Buffers one tool-call chunk for the CURRENT provider round in its
    /// OWN bounded buffer (the round's index is assigned at buffer time so
    /// the flush carries final-round indices). When the tool bound is
    /// exceeded the final round's remaining tool calls cannot be carried:
    /// the flush ends with the typed `stream_buffer_overflow` error +
    /// `[DONE]` — explicit, never a silent drop.
    fn buffer_tool(&mut self, event: GatewayEvent) {
        if self.buffered_tool_calls >= MAX_STREAM_BUFFERED_TOOL_CALLS {
            self.buffered_tool_overflown = true;
            return;
        }
        self.buffered_tool_calls += 1;
        let index = self.tool_index;
        self.tool_index += 1;
        let arguments = event
            .data
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));
        let mut chunk = self.base_chunk("chat.completion.chunk");
        let mut delta_map = serde_json::Map::new();
        delta_map.insert(
            "tool_calls".to_string(),
            json!([{
                "index": index,
                "id": event.data.get("tool_call_id").and_then(Value::as_str).unwrap_or(""),
                "type": "function",
                "function": {
                    "name": event.data.get("name").and_then(Value::as_str).unwrap_or(""),
                    "arguments": serde_json::to_string(&arguments).unwrap_or_else(|_| "{}".to_string()),
                }
            }]),
        );
        chunk["choices"] =
            json!([{"index": 0, "delta": Value::Object(delta_map), "finish_reason": null}]);
        self.buffered_tools.push_back((event.seq, chunk));
    }

    /// The buffered round was INTERNAL (a later provider round follows):
    /// drop it — A5 executed that round's tools itself, and its text/tool
    /// chunks must never reach the client.
    fn drop_buffer(&mut self) {
        self.buffered.clear();
        self.buffered_tools.clear();
        self.buffered_chars = 0;
        self.buffered_tool_calls = 0;
        self.buffered_overflown = false;
        self.buffered_tool_overflown = false;
        self.tool_index = 0;
        self.first_chunk = true;
    }

    /// Tracks the provider round of one event. When a DIFFERENT round
    /// appears with a non-empty buffer, the buffered round was internal and
    /// is dropped. Turn-less events never trigger a drop (legacy safety).
    fn note_turn(&mut self, turn: Option<i64>) {
        if let (Some(current), Some(turn)) = (self.current_turn, turn)
            && current != turn
        {
            self.drop_buffer();
        }
        if turn.is_some() {
            self.current_turn = turn;
        }
    }

    /// The terminal confirms the CURRENT buffered round is the FINAL
    /// provider round: flush its bounded buffers (tool chunks first, then
    /// text deltas or the authoritative terminal text on text overflow),
    /// then the final choice chunk, the optional usage chunk, and `[DONE]`.
    /// A tool-bound overflow ends with the typed `stream_buffer_overflow`
    /// error chunk + `[DONE]` instead of a silently truncated tool list.
    fn finish_completed(&mut self, event: GatewayEvent) {
        self.done = true;
        if let Some(guard) = self.guard.as_mut() {
            guard.disarm();
        }
        if self.buffered_tool_overflown {
            // The final round's tool calls exceeded the bounded tool
            // buffer: explicit typed error, never a silent truncation.
            self.drop_buffer();
            let error = json!({
                "error": {
                    "message": "the final provider round declared more tool calls than the bounded stream buffer can carry; the tool-call list was not streamed",
                    "type": "stream_buffer_overflow",
                    "code": "stream_buffer_overflow",
                }
            });
            if !self.skip_for_resume(event.seq, 0) {
                self.pending.push_back(SseChunk {
                    id: Some(chunk_id(event.seq, 0)),
                    event: Some("error".to_string()),
                    data: error.to_string(),
                });
            }
            self.pending.push_back(SseChunk {
                id: None,
                event: None,
                data: "[DONE]".to_string(),
            });
            return;
        }
        // Preserved tool chunks first (bounded, complete). Role placement is
        // decided at flush time, so a text->tool final round still puts the
        // role on the first actual client chunk.
        while let Some((seq, data)) = self.buffered_tools.pop_front() {
            self.queue_delta_chunk(seq, 0, data);
        }
        let mut terminal_subindex = 0u32;
        if self.buffered_overflown {
            // The bounded TEXT buffer was exceeded: the authoritative
            // terminal text (the COMPLETE final round text) is emitted
            // instead — lossless, never a silent drop.
            let text = event.data["output"]["message"]["content"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let mut chunk = self.base_chunk("chat.completion.chunk");
            let mut delta_map = serde_json::Map::new();
            delta_map.insert("content".to_string(), json!(text));
            chunk["choices"] =
                json!([{"index": 0, "delta": Value::Object(delta_map), "finish_reason": null}]);
            self.queue_delta_chunk(event.seq, terminal_subindex, chunk);
            terminal_subindex += 1;
        } else if self.buffered.is_empty() {
            // Defensive: a terminal without any buffered deltas (for
            // example a transport that only appends the assistant message)
            // still delivers the authoritative final text.
            let text = event.data["output"]["message"]["content"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if !text.is_empty() {
                let mut chunk = self.base_chunk("chat.completion.chunk");
                let mut delta_map = serde_json::Map::new();
                delta_map.insert("content".to_string(), json!(text));
                chunk["choices"] =
                    json!([{"index": 0, "delta": Value::Object(delta_map), "finish_reason": null}]);
                self.queue_delta_chunk(event.seq, terminal_subindex, chunk);
                terminal_subindex += 1;
            }
        } else {
            while let Some((seq, data)) = self.buffered.pop_front() {
                self.queue_delta_chunk(seq, 0, data);
            }
        }
        let message = &event.data["output"]["message"];
        let finish_reason = message
            .get("finish_reason")
            .and_then(Value::as_str)
            .unwrap_or("stop")
            .to_string();
        let usage = openai_usage(event.data.get("usage").unwrap_or(&Value::Null));
        let mut final_chunk = self.base_chunk("chat.completion.chunk");
        final_chunk["choices"] = json!([{"index": 0, "delta": {}, "finish_reason": finish_reason}]);
        self.queue_delta_chunk(event.seq, terminal_subindex, final_chunk);
        terminal_subindex += 1;
        if self.include_usage {
            let mut usage_chunk = self.base_chunk("chat.completion.chunk");
            usage_chunk["choices"] = json!([]);
            usage_chunk["usage"] = usage;
            self.queue_chunk(event.seq, terminal_subindex, usage_chunk);
        }
        self.pending.push_back(SseChunk {
            id: None,
            event: None,
            data: "[DONE]".to_string(),
        });
    }

    /// A failure/cancellation terminal: the buffered round never reaches
    /// the client; the typed error chunk (the SAME type as the buffered
    /// 502/500 contract) terminates the stream, followed by `[DONE]`.
    fn finish_failed(&mut self, event: GatewayEvent) {
        self.done = true;
        if let Some(guard) = self.guard.as_mut() {
            guard.disarm();
        }
        self.drop_buffer();
        let (code, message, error_type) = if event.event == "run.failed" {
            let provider_type = event
                .data
                .get("provider_error")
                .and_then(|error| error.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("agent_error")
                .to_string();
            (
                event
                    .data
                    .get("error_code")
                    .and_then(Value::as_str)
                    .unwrap_or("agent_error")
                    .to_string(),
                event
                    .data
                    .get("error_message")
                    .and_then(Value::as_str)
                    .unwrap_or("the agent run failed")
                    .to_string(),
                provider_type,
            )
        } else {
            (
                "run_cancelled".to_string(),
                event
                    .data
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("cancelled")
                    .to_string(),
                "agent_error".to_string(),
            )
        };
        if !self.skip_for_resume(event.seq, 0) {
            self.pending.push_back(SseChunk {
                id: Some(chunk_id(event.seq, 0)),
                event: Some("error".to_string()),
                data: json!({"error": {"message": message, "type": error_type, "code": code}})
                    .to_string(),
            });
        }
        self.pending.push_back(SseChunk {
            id: None,
            event: None,
            data: "[DONE]".to_string(),
        });
    }

    /// The bounded live buffer dropped events: recover through the DURABLE
    /// catch-up (every event was persisted before publish), so no chunk is
    /// silently lost. The catch-up is itself bounded; a replay failure
    /// surfaces the typed error chunk instead of ending silently.
    fn catch_up_durable(&mut self) -> Result<(), RouteError> {
        let Some(persistence) = self.persistence.clone() else {
            return Err(RouteError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "event_lagged",
                "the bounded event buffer dropped chunks and no durable store is available for catch-up",
            ));
        };
        // Page forward through the durable window (bounded by
        // max_events_limit=16384 rows, and per-page result bytes): each
        // page starts AFTER the last seen sequence, so a lag larger than
        // one page is still recovered without silent loss.
        loop {
            let data = persistence
                .event_replay(&json!({
                    "run_id": self.run_id,
                    "after_seq": self.last_seq,
                    "max_events": 2048,
                    "max_bytes": 262144,
                }))
                .map_err(|error| {
                    RouteError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "catch_up_failed",
                        format!("durable event catch-up failed: {error}"),
                    )
                })?;
            let mut page_seen = 0usize;
            if let Some(rows) = data.get("rows").and_then(Value::as_array) {
                for row in rows {
                    let Some(row) = row.as_array() else {
                        continue;
                    };
                    let seq = row.first().and_then(Value::as_u64).unwrap_or(0);
                    if seq <= self.last_seq {
                        continue;
                    }
                    self.last_seq = seq;
                    page_seen += 1;
                    let payload: Value = row
                        .get(4)
                        .and_then(Value::as_str)
                        .and_then(|text| serde_json::from_str(text).ok())
                        .unwrap_or(Value::Null);
                    self.catch_up.push_back(GatewayEvent {
                        event_id: row.get(2).and_then(Value::as_str).unwrap_or("").to_string(),
                        seq,
                        event: row.get(3).and_then(Value::as_str).unwrap_or("").to_string(),
                        run_id: self.run_id.clone(),
                        timestamp: row.get(5).and_then(Value::as_u64).unwrap_or(0),
                        data: payload,
                    });
                }
            }
            // A page smaller than the request means the retained window is
            // exhausted (or a cursor_too_old error already surfaced above).
            if page_seen < 2048 {
                break;
            }
        }
        Ok(())
    }

    /// Ends the stream with the typed error chunk (bounded recoverable
    /// contract: an unrecoverable catch-up failure is explicit, never
    /// silent).
    fn end_with_error(&mut self, error: RouteError) {
        self.done = true;
        self.drop_buffer();
        self.pending.push_back(SseChunk {
            id: None,
            event: Some("error".to_string()),
            data: json!({"error": {"message": error.message, "type": error.error_type, "code": error.code}}).to_string(),
        });
        self.pending.push_back(SseChunk {
            id: None,
            event: None,
            data: "[DONE]".to_string(),
        });
    }

    /// Produces the next SSE chunk, or `None` at the end of the stream.
    async fn next_event(&mut self) -> Option<SseChunk> {
        loop {
            if let Some(chunk) = self.pending.pop_front() {
                return Some(chunk);
            }
            if self.done {
                return None;
            }
            let event = if let Some(event) = self.catch_up.pop_front() {
                event
            } else if let Some(event) = self.history.next() {
                event
            } else if let Some(receiver) = self.receiver.as_mut() {
                match receiver.recv().await {
                    Ok(event) => {
                        // After a durable catch-up the live buffer may
                        // still hold already-recovered events: skip the
                        // duplicates (seq is monotonic).
                        if event.seq <= self.last_seq {
                            continue;
                        }
                        event
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if let Err(error) = self.catch_up_durable() {
                            self.end_with_error(error);
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            } else {
                return None;
            };
            self.last_seq = event.seq.max(self.last_seq);
            match event.event.as_str() {
                "model.delta" => {
                    self.note_turn(event_turn(&event));
                    self.buffer_delta(event);
                }
                "tool.started" => {
                    self.note_turn(event_turn(&event));
                    self.buffer_tool(event);
                }
                "model.started" | "model.completed" => {
                    self.note_turn(event_turn(&event));
                }
                "run.completed" => {
                    let event = if let Some(persistence) = self.persistence.clone() {
                        match hydrate_completed_terminal(&persistence, &event) {
                            Ok(event) => event,
                            Err(error) => {
                                self.end_with_error(error);
                                continue;
                            }
                        }
                    } else {
                        event
                    };
                    self.finish_completed(event);
                }
                "run.failed" | "run.cancelled" => {
                    self.finish_failed(event);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod send_probe {
    use super::*;

    fn assert_send<T: Send>(_: T) {}

    #[tokio::test]
    async fn handler_future_is_send() {
        let state = AgentGatewayState::new(crate::config::AgentGatewayConfig::default())
            .expect("gateway config must validate");
        let fut = openai_chat_completions_handler(
            State(state),
            HeaderMap::new(),
            Ok(Json(ChatCompletionRequest {
                model: None,
                messages: None,
                tools: None,
                tool_choice: None,
                stream: None,
                stream_options: None,
                temperature: None,
                top_p: None,
                max_tokens: None,
                max_completion_tokens: None,
                user: None,
                extra: Default::default(),
            })),
        );
        assert_send(fut);
    }
}

// ---------------------------------------------------------------------------
// StreamTurnBuffer unit tests (pure renderer, no HTTP, no provider)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod stream_turn_buffer {
    use super::*;

    fn gateway_event(seq: u64, event: &str, data: Value) -> GatewayEvent {
        GatewayEvent {
            event_id: format!("event-{seq}"),
            seq,
            event: event.to_string(),
            run_id: "run-1".to_string(),
            timestamp: 1000,
            data,
        }
    }

    fn started(seq: u64, turn: i64) -> GatewayEvent {
        gateway_event(seq, "model.started", json!({"turn": turn}))
    }

    fn delta(seq: u64, turn: i64, text: &str) -> GatewayEvent {
        gateway_event(seq, "model.delta", json!({"turn": turn, "delta": text}))
    }

    fn tool(seq: u64, turn: i64, call_id: &str, name: &str) -> GatewayEvent {
        gateway_event(
            seq,
            "tool.started",
            json!({"turn": turn, "tool_call_id": call_id, "name": name, "arguments": {}}),
        )
    }

    fn completed(seq: u64, turn: i64, text: &str) -> GatewayEvent {
        gateway_event(
            seq,
            "run.completed",
            json!({
                "turn": turn,
                "status": "completed",
                "output": {"message": {"content": text, "finish_reason": "stop"}},
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }),
        )
    }

    fn sse(events: Vec<GatewayEvent>) -> CompletionSse {
        sse_with_resume(events, None)
    }

    fn sse_with_resume(events: Vec<GatewayEvent>, resume: Option<ChunkCursor>) -> CompletionSse {
        CompletionSse {
            run_id: "run-1".to_string(),
            model: "test-model".to_string(),
            created_at: 1000,
            include_usage: false,
            resume,
            history: events.into_iter(),
            receiver: None,
            guard: None,
            persistence: None,
            pending: VecDeque::new(),
            catch_up: VecDeque::new(),
            current_turn: None,
            buffered: VecDeque::new(),
            buffered_tools: VecDeque::new(),
            buffered_chars: 0,
            buffered_tool_calls: 0,
            buffered_overflown: false,
            buffered_tool_overflown: false,
            tool_index: 0,
            first_chunk: true,
            done: false,
            last_seq: 0,
        }
    }

    /// Drives the renderer to completion and returns every SSE data payload
    /// in order (including the terminal `[DONE]`).
    async fn render(events: Vec<GatewayEvent>) -> Vec<String> {
        let mut state = sse(events);
        let mut payloads = Vec::new();
        while let Some(chunk) = state.next_event().await {
            payloads.push(chunk.data.to_string());
        }
        payloads
    }

    /// The OpenAI delta contract: the assistant role appears on the FIRST
    /// flushed delta chunk and on no later chunk. Multiple deltas in the
    /// final round must not repeat the role.
    #[tokio::test]
    async fn multi_delta_final_round_carries_role_only_on_first_chunk() {
        let payloads = render(vec![
            started(1, 1),
            delta(2, 1, "one"),
            delta(3, 1, "two"),
            delta(4, 1, "three"),
            completed(5, 1, "one two three"),
        ])
        .await;
        let role_chunks = payloads
            .iter()
            .filter(|payload| **payload != "[DONE]")
            .filter(|payload| {
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value["choices"][0]["delta"]["role"]
                            .as_str()
                            .map(str::to_string)
                    })
                    == Some("assistant".to_string())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            role_chunks.len(),
            1,
            "exactly one chunk may carry the assistant role, got {role_chunks:?} from {payloads:?}"
        );
        let first_content = payloads
            .iter()
            .filter(|payload| **payload != "[DONE]")
            .find(|payload| {
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value["choices"][0]["delta"]["content"]
                            .as_str()
                            .map(str::to_string)
                    })
                    .is_some()
            })
            .expect("a content delta chunk must exist");
        assert_eq!(
            serde_json::from_str::<Value>(first_content).unwrap()["choices"][0]["delta"]["role"],
            json!("assistant"),
            "the first flushed content chunk must carry the role, got {first_content}"
        );
    }

    /// When a final round contains text followed by tool calls, the tool
    /// chunk is the first flushed chunk. It must carry the one assistant role;
    /// buffering text must not consume that role slot.
    #[tokio::test]
    async fn mixed_text_then_tool_final_round_flushes_role_on_first_chunk() {
        let payloads = render(vec![
            started(1, 1),
            delta(2, 1, "thinking"),
            tool(3, 1, "call-1", "file.read"),
            completed(4, 1, "thinking"),
        ])
        .await;
        let chunks = payloads
            .iter()
            .filter(|payload| **payload != "[DONE]")
            .map(|payload| serde_json::from_str::<Value>(payload).expect("JSON chunk"))
            .collect::<Vec<_>>();
        let role_chunks = chunks
            .iter()
            .filter(|chunk| chunk["choices"][0]["delta"]["role"] == json!("assistant"))
            .count();
        assert_eq!(role_chunks, 1, "assistant role must appear exactly once");
        assert_eq!(
            chunks[0]["choices"][0]["delta"]["tool_calls"][0]["id"],
            json!("call-1"),
            "the first actual flush must be the tool chunk"
        );
        assert!(chunks[0]["choices"][0]["delta"]["role"] == json!("assistant"));
    }

    /// Chunk ids are a stable `(canonical event sequence, subindex)` cursor.
    #[tokio::test]
    async fn chunk_ids_are_seq_and_subindex_and_resume_is_deterministic() {
        let events = vec![
            started(1, 1),
            delta(2, 1, "one"),
            delta(3, 1, "two"),
            completed(4, 1, "one two"),
        ];
        let mut first = sse(events.clone());
        let first_chunk = first.next_event().await.expect("first delta chunk");
        let first_id = first_chunk.id.expect("chunk id");
        assert_eq!(first_id, "2:0");
        let mut resumed = sse_with_resume(events, parse_chunk_cursor(&first_id));
        let resumed_chunk = resumed.next_event().await.expect("resumed chunk");
        assert_eq!(resumed_chunk.id.as_deref(), Some("3:0"));
    }

    /// Multiple tool chunks in the final round: the role appears only on the
    /// first tool delta, never repeated.
    #[tokio::test]
    async fn multi_tool_final_round_carries_role_only_on_first_chunk() {
        let payloads = render(vec![
            started(1, 1),
            tool(2, 1, "call-1", "file.read"),
            tool(3, 1, "call-2", "file.write"),
            tool(4, 1, "call-3", "patch.apply"),
            completed(5, 1, ""),
        ])
        .await;
        let role_chunks = payloads
            .iter()
            .filter(|payload| **payload != "[DONE]")
            .filter(|payload| {
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value["choices"][0]["delta"]["role"]
                            .as_str()
                            .map(str::to_string)
                    })
                    == Some("assistant".to_string())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            role_chunks.len(),
            1,
            "exactly one chunk may carry the assistant role, got {role_chunks:?} from {payloads:?}"
        );
        let tool_chunks = payloads
            .iter()
            .filter(|payload| **payload != "[DONE]")
            .filter(|payload| {
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value["choices"][0]["delta"]["tool_calls"]
                            .as_array()
                            .cloned()
                    })
                    .is_some()
            })
            .collect::<Vec<_>>();
        assert_eq!(tool_chunks.len(), 3, "all three tool calls must stream");
    }

    /// The buffered tool-call bound is exceeded in the FINAL round: the
    /// stream must end with the typed `stream_buffer_overflow` error chunk
    /// followed by `[DONE]` — the overflow is explicit, never a silent drop
    /// of the final round's tool calls.
    #[tokio::test]
    async fn tool_overflow_ends_with_typed_stream_buffer_overflow_and_done() {
        let mut events = vec![started(1, 1)];
        let mut seq = 2;
        for index in 0..=MAX_STREAM_BUFFERED_TOOL_CALLS {
            events.push(tool(seq, 1, &format!("call-{index}"), "file.read"));
            seq += 1;
        }
        events.push(completed(seq, 1, ""));
        let payloads = render(events).await;
        let error = payloads
            .iter()
            .find(|payload| {
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .and_then(|value| value["error"]["code"].as_str().map(str::to_string))
                    == Some("stream_buffer_overflow".to_string())
            })
            .unwrap_or_else(|| {
                panic!("a typed stream_buffer_overflow error chunk is required, got {payloads:?}")
            });
        assert!(
            serde_json::from_str::<Value>(error)
                .ok()
                .and_then(|value| value["error"]["type"].as_str().map(str::to_string))
                == Some("stream_buffer_overflow".to_string()),
            "the error chunk must carry the typed error type, got {error}"
        );
        assert_eq!(payloads.last().map(String::as_str), Some("[DONE]"));
    }

    /// Text overflow is a LOSSLESS fallback to the authoritative terminal
    /// text — and any buffered tool chunks of the final round are preserved,
    /// not silently dropped with the overflown text buffer.
    #[tokio::test]
    async fn text_overflow_preserves_tools_and_emits_terminal_text() {
        let mut events = vec![started(1, 1)];
        let mut seq = 2;
        for _ in 0..(MAX_STREAM_BUFFERED_DELTAS + 10) {
            events.push(delta(seq, 1, "x"));
            seq += 1;
        }
        events.push(tool(seq, 1, "call-1", "file.read"));
        seq += 1;
        events.push(completed(seq, 1, "authoritative final text"));
        let payloads = render(events).await;
        assert!(
            payloads.iter().any(|payload| {
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value["choices"][0]["delta"]["tool_calls"]
                            .as_array()
                            .cloned()
                    })
                    .is_some()
            }),
            "buffered tool chunks must survive text overflow, got {payloads:?}"
        );
        assert!(
            payloads.iter().any(|payload| {
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value["choices"][0]["delta"]["content"]
                            .as_str()
                            .map(str::to_string)
                    })
                    == Some("authoritative final text".to_string())
            }),
            "the authoritative terminal text must be emitted, got {payloads:?}"
        );
        assert_eq!(payloads.last().map(String::as_str), Some("[DONE]"));
    }

    #[test]
    fn inbound_text_parts_use_one_utf8_byte_budget_for_the_whole_message() {
        let mut parts = Vec::new();
        // Every part is below the legacy per-part character bound, while the
        // aggregate UTF-8 byte count is above the durable one-megabyte limit.
        for _ in 0..16 {
            parts.push(json!({"type": "text", "text": "é".repeat(65_000)}));
        }
        let error = normalize_text_content(&Some(Value::Array(parts)))
            .expect_err("all message parts must share one durable byte budget");
        assert_eq!(error.code, "message_too_large");
    }
}
