//! Canonical domain contracts shared by the service, gateways, and RSS.
//!
//! This module freezes the agent contracts (gateway-api plan sections 4.1,
//! 4.2, 4.4, and 4.5): the inbound platform envelope, the structured run
//! context, the canonical provider request/event model, and the tool
//! descriptor. The run context is rendered as the sole argument of the
//! exported `run(context)` callable; scripts receive no ambient input.
//! JSON/VM value conversions and the canonical timestamp also live here so no
//! gateway module re-implements them.

use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_vm::Value as VmValue;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Milliseconds since the Unix epoch; the canonical agent timestamp.
pub(crate) fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// FNV-1a 64-bit hash used for idempotency request hashes (transport
/// adapters derive the same canonical hash shape as the API server).
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Canonical inbound platform envelope (gateway-api plan section 4.1).
///
/// Platform adapters normalize inbound data into this envelope; the default
/// session identity derives from `(profile, platform, account_id, chat_id,
/// thread_id)`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InboundEnvelope {
    pub platform: String,
    pub profile: String,
    pub account_id: String,
    pub chat_id: String,
    pub thread_id: Option<String>,
    pub user_id: String,
    pub message_id: String,
    pub session_hint: Option<String>,
    pub content: String,
    pub attachments: Vec<Value>,
    pub command: Option<String>,
    pub reply_to: Option<String>,
    pub received_at: u64,
    pub metadata: Value,
}

/// Canonical agent run context (gateway-api plan section 4.2).
///
/// The exact structured context is passed to the exported RSS `run(context)`
/// callable as one ordinary argument. AgentService resolves the session/run
/// state and fills this struct; [`RunContext::to_vm_value`] renders it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunContext {
    pub run_id: String,
    pub session_id: String,
    pub parent_run_id: Option<String>,
    pub platform: String,
    pub input: Value,
    pub messages: Value,
    pub system_prompt: Option<String>,
    pub model: String,
    pub provider: Option<String>,
    pub provider_options: Value,
    pub tool_schemas: Value,
    pub limits: Value,
    pub metadata: Value,
    /// Frozen coding system prompt captured once at run admission.
    #[serde(default)]
    pub coding_system_prompt: Option<String>,
}

impl RunContext {
    /// Renders the canonical context as the sole `run(context)` argument.
    pub fn to_vm_value(&self) -> VmValue {
        VmValue::map(vec![
            (VmValue::string("run_id"), VmValue::string(&self.run_id)),
            (
                VmValue::string("session_id"),
                VmValue::string(&self.session_id),
            ),
            (
                VmValue::string("parent_run_id"),
                self.parent_run_id
                    .as_deref()
                    .map(VmValue::string)
                    .unwrap_or(VmValue::Null),
            ),
            (VmValue::string("platform"), VmValue::string(&self.platform)),
            (VmValue::string("input"), json_to_vm_value(&self.input)),
            (
                VmValue::string("messages"),
                json_to_vm_value(&self.messages),
            ),
            (
                VmValue::string("system_prompt"),
                self.system_prompt
                    .as_deref()
                    .map(VmValue::string)
                    .unwrap_or(VmValue::Null),
            ),
            (VmValue::string("model"), VmValue::string(&self.model)),
            (
                VmValue::string("provider"),
                self.provider
                    .as_deref()
                    .map(VmValue::string)
                    .unwrap_or(VmValue::Null),
            ),
            (
                VmValue::string("provider_options"),
                json_to_vm_value(&self.provider_options),
            ),
            (
                VmValue::string("tool_schemas"),
                json_to_vm_value(&self.tool_schemas),
            ),
            (VmValue::string("limits"), json_to_vm_value(&self.limits)),
            (
                VmValue::string("metadata"),
                json_to_vm_value(&self.metadata),
            ),
            (
                VmValue::string("coding_system_prompt"),
                self.coding_system_prompt
                    .as_deref()
                    .map(VmValue::string)
                    .unwrap_or(VmValue::Null),
            ),
        ])
    }
}

/// Canonical provider request model (gateway-api plan section 4.4). RSS
/// provider adapters map wire formats to this shape; this struct is the
/// frozen contract, not a parser.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LlmRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub tools: Vec<ToolDescriptor>,
    pub tool_choice: Option<Value>,
    pub reasoning: Option<Value>,
    pub sampling: Option<Sampling>,
    pub max_output_tokens: Option<u32>,
    pub stream: bool,
    pub provider_options: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: String,
    pub content: Vec<LlmContentBlock>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LlmContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "artifacts")]
    pub artifact: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sampling {
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
}

/// Canonical provider event model (gateway-api plan section 4.4): deltas,
/// tool calls, and completion markers carry the run/session identity and a
/// per-run sequence assigned by the agent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LlmEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub run_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub tool_call: Option<ToolCall>,
    pub created_at: u64,
}

/// One model-requested tool call (gateway-api plan section 4.4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// Canonical token usage reported by a provider (gateway-api plan section
/// 4.4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}

/// Canonical provider completion response (gateway-api plan section 4.4).
/// RSS adapters normalize wire responses into this shape; unknown provider
/// fields remain under the explicit raw field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LlmResponse {
    pub id: String,
    pub model: String,
    pub content: Vec<LlmContentBlock>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub finish_reason: Option<String>,
    pub raw: Value,
}

/// Canonical provider error (gateway-api plan section 4.4): typed code,
/// human message, retry hint, transport status when known, and the raw
/// provider payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub status_code: Option<u16>,
    pub raw: Value,
}

/// Compatibility re-export of the single public tool descriptor contract.
pub use crate::tool_schema::ToolDescriptor;

/// Canonical event envelope attached to one run (gateway-api plan section
/// 4.3): AgentService assigns the durable event identity, the monotonic
/// per-run sequence, and the timestamp.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentEventEnvelope {
    #[serde(rename = "type")]
    pub event_type: String,
    pub run_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub status: String,
    pub output: Option<Value>,
    pub error: Option<Value>,
    pub created_at: u64,
}

/// Converts one JSON value into a VM value (mirror of `vm_value_to_json`).
pub(crate) fn json_to_vm_value(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::Null,
        Value::Bool(value) => VmValue::Bool(*value),
        Value::Number(value) => value
            .as_i64()
            .map(VmValue::Int)
            .or_else(|| value.as_f64().map(VmValue::Float))
            .unwrap_or(VmValue::Null),
        Value::String(value) => VmValue::string(value),
        Value::Array(values) => VmValue::array(values.iter().map(json_to_vm_value).collect()),
        Value::Object(fields) => VmValue::map(
            fields
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

/// Converts one VM value into canonical JSON.
pub(crate) fn vm_value_to_json(value: &VmValue) -> Value {
    match value {
        VmValue::Null => Value::Null,
        VmValue::Int(value) => json!(value),
        VmValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        VmValue::Bool(value) => json!(value),
        VmValue::String(value) => Value::String(value.to_string()),
        VmValue::Bytes(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        VmValue::Array(values) => Value::Array(values.iter().map(vm_value_to_json).collect()),
        VmValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        VmValue::Callable(_) => Value::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &VmValue) -> String {
    match value {
        VmValue::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

/// Canonical input text for an agent run: strings pass through, structured
/// input renders as JSON text, and null renders as the empty string.
pub(crate) fn input_text(input: &Value) -> String {
    match input {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Redacts free-text log messages by truncating at a char boundary, so
/// embedded payload text (which may carry sensitive values) never reaches
/// logs unbounded. Structured ids and typed reasons are logged as fields,
/// never payload originals.
pub(crate) fn truncate_for_log(message: &str, max_chars: usize) -> &str {
    match message.char_indices().nth(max_chars) {
        Some((index, _)) => &message[..index],
        None => message,
    }
}

/// Per-field bound for durable message text/arguments/results. Keeps the
/// 1 MiB `content_json` CHECK from splitting a multi-byte UTF-8 scalar.
pub const MAX_DURABLE_TEXT_CHARS: usize = 65_536;
const MAX_DURABLE_ID_BYTES: usize = 128;

/// Provider pending calls may be retried only when no durable response
/// exists, the request is idempotent, and the request has no effect.
/// Completed provider responses are replayed, never reissued.
pub fn provider_pending_may_retry(
    has_durable_response: bool,
    request_is_idempotent: bool,
    has_effect: bool,
) -> bool {
    !has_durable_response && request_is_idempotent && !has_effect
}

/// Stable event id for a tool lifecycle step: `run + call + event_type`.
pub fn durable_tool_event_id(run_id: &str, tool_call_id: &str, event_type: &str) -> String {
    bound_durable_id(&format!("{run_id}:tool:{tool_call_id}:{event_type}"))
}

/// Stable event id for a provider step: `run + turn + event_type`.
pub fn durable_provider_event_id(run_id: &str, turn: u64, event_type: &str) -> String {
    bound_durable_id(&format!("{run_id}:turn:{turn}:{event_type}"))
}

/// Stable message id: `run + kind + key` (turn ordinal or tool_call_id).
pub fn durable_message_id(run_id: &str, kind: &str, key: &str) -> String {
    bound_durable_id(&format!("{run_id}:{kind}:{key}"))
}

fn bound_durable_id(id: &str) -> String {
    if id.len() <= MAX_DURABLE_ID_BYTES {
        return id.to_string();
    }
    id.chars()
        .scan(0usize, |bytes, ch| {
            let width = ch.len_utf8();
            if *bytes + width > MAX_DURABLE_ID_BYTES {
                None
            } else {
                *bytes += width;
                Some(ch)
            }
        })
        .collect()
}

/// UTF-8-safe character truncation used by durable message fields.
pub fn truncate_utf8_chars(text: &str, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        Some((index, _)) => (text[..index].to_string(), true),
        None => (text.to_string(), false),
    }
}

/// Decode stored `content_json` into the canonical LlmContentBlock array.
/// Legacy shapes (raw text, `{"text":...}`, a single block object) become
/// the same array schema; already-canonical arrays pass through.
pub fn decode_message_content(value: &Value) -> Value {
    Value::Array(
        decode_message_blocks(value)
            .into_iter()
            .map(|block| serde_json::to_value(block).unwrap_or(Value::Object(Default::default())))
            .collect(),
    )
}

/// Decode stored `content_json` into canonical blocks.
pub fn decode_message_blocks(value: &Value) -> Vec<LlmContentBlock> {
    match value {
        Value::Array(items) => items.iter().map(decode_one_block).collect(),
        Value::String(text) => vec![text_block(text)],
        Value::Object(map) => {
            if map.get("type").and_then(Value::as_str).is_some() {
                vec![decode_one_block(value)]
            } else if let Some(text) = map.get("text") {
                let rendered = match text {
                    Value::String(value) => value.clone(),
                    other => other.to_string(),
                };
                vec![text_block(&rendered)]
            } else {
                vec![text_block(&value.to_string())]
            }
        }
        Value::Null => Vec::new(),
        other => vec![text_block(&other.to_string())],
    }
}

fn decode_one_block(value: &Value) -> LlmContentBlock {
    let mut block =
        serde_json::from_value(value.clone()).unwrap_or_else(|_| text_block(&value.to_string()));
    if block.truncated == Some(false) {
        block.truncated = None;
    }
    if block.arguments_json.is_none() {
        if let Some(arguments) = block.arguments.take() {
            block.arguments_json =
                Some(serde_json::to_string(&arguments).unwrap_or_else(|_| arguments.to_string()));
        }
    } else {
        block.arguments = None;
    }
    if let Some(Value::Array(items)) = &block.artifact {
        block.artifact = items.first().cloned();
    }
    block
}

fn text_block(text: &str) -> LlmContentBlock {
    let (text, truncated) = truncate_utf8_chars(text, MAX_DURABLE_TEXT_CHARS);
    LlmContentBlock {
        block_type: "text".to_string(),
        text: Some(text),
        truncated: truncated.then_some(true),
        ..LlmContentBlock::default()
    }
}

/// Encode canonical blocks, bounding text/arguments/result fields.
pub fn encode_message_content(blocks: &[LlmContentBlock]) -> Value {
    Value::Array(
        blocks
            .iter()
            .map(bound_content_block)
            .map(|block| serde_json::to_value(block).unwrap_or(Value::Object(Default::default())))
            .collect(),
    )
}

fn bound_content_block(block: &LlmContentBlock) -> LlmContentBlock {
    let mut bounded = block.clone();
    let mut truncated = block.truncated.unwrap_or(false);
    if let Some(text) = bounded.text.take() {
        let (text, cut) = truncate_utf8_chars(&text, MAX_DURABLE_TEXT_CHARS);
        truncated |= cut;
        bounded.text = Some(text);
    }
    if let Some(content) = bounded.content.take() {
        let (content, cut) = truncate_utf8_chars(&content, MAX_DURABLE_TEXT_CHARS);
        truncated |= cut;
        bounded.content = Some(content);
    }
    if bounded.arguments_json.is_none() {
        if let Some(arguments) = bounded.arguments.take() {
            bounded.arguments_json =
                Some(serde_json::to_string(&arguments).unwrap_or_else(|_| arguments.to_string()));
        }
    } else {
        bounded.arguments = None;
    }
    if let Some(arguments_json) = bounded.arguments_json.take() {
        let (arguments_json, cut) = truncate_utf8_chars(&arguments_json, MAX_DURABLE_TEXT_CHARS);
        truncated |= cut;
        bounded.arguments_json = Some(arguments_json);
    }
    if let Some(result) = bounded.result.take() {
        let (result, cut) = bound_structured_json(result, false);
        truncated |= cut;
        bounded.result = Some(result);
    }
    if let Some(error) = bounded.error.take() {
        let (error, cut) = bound_structured_json(error, true);
        truncated |= cut;
        bounded.error = Some(error);
    }
    if let Some(Value::Array(items)) = &bounded.artifact {
        bounded.artifact = items.first().cloned();
    }
    bounded.truncated = truncated.then_some(true);
    bounded
}

/// Replaces oversized structured `result`/`error` JSON with redacted bounded
/// metadata so persistence cannot fail after an effect solely because the
/// payload exceeded the durable message cap. The original byte count is
/// retained; raw payload bytes are never copied into the replacement.
fn bound_structured_json(value: Value, retain_error_code: bool) -> (Value, bool) {
    let original_bytes = serde_json::to_vec(&value)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    if original_bytes <= MAX_DURABLE_TEXT_CHARS {
        return (value, false);
    }
    let mut redacted = serde_json::Map::new();
    redacted.insert("truncated".to_string(), json!(true));
    redacted.insert("redacted".to_string(), json!(true));
    redacted.insert("original_bytes".to_string(), json!(original_bytes));
    if retain_error_code && let Some(code) = value.get("code").cloned() {
        redacted.insert("code".to_string(), code);
    }
    (Value::Object(redacted), true)
}
