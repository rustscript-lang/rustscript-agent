//! Service-scoped durable provider wrapper for production `run_worker`.
//!
//! `DurableProviderHost` sits outermost around the raw/accounting provider.
//! Before every fresh inner call it durably commits a sanitized
//! `model.requested` boundary. Completed canonical steps are replayed without
//! an inner call or turn metric. Pending retry-safe requests retry the same
//! logical turn without synthesizing an assistant step. Persist failure
//! prevents the provider call. Malformed `ok:true` envelopes are never
//! persisted as success.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use serde_json::{Value as JsonValue, json};

use crate::domain::{LlmContentBlock, MAX_DURABLE_TEXT_CHARS, Usage, decode_message_blocks};
use crate::metrics::Metrics;
use crate::runtime::agent_host::{error_is_retryable_code, typed_fail};
use crate::runtime::rss_runner::RunCancellation;
use crate::service::{AgentService, ProviderCommitOutcome};
use crate::tools::EventCommitError;
use crate::{AgentProviderHost, ProviderPendingDecision};

/// Counts actual inner provider calls. Turn metrics are recorded by
/// [`DurableProviderHost`] only after a fresh successful durable insert.
pub(crate) struct AccountingProvider {
    inner: Arc<dyn AgentProviderHost>,
    metrics: Arc<Metrics>,
}

impl AccountingProvider {
    pub(crate) fn new(inner: Arc<dyn AgentProviderHost>, metrics: Arc<Metrics>) -> Self {
        Self { inner, metrics }
    }
}

impl AgentProviderHost for AccountingProvider {
    fn call(&self, request: &JsonValue, cancellation: &RunCancellation) -> JsonValue {
        let envelope = self.inner.call(request, cancellation);
        let successful = envelope.get("ok").and_then(JsonValue::as_bool) == Some(true);
        let truncated = successful
            && envelope
                .get("response")
                .and_then(|response| response.get("truncated"))
                .and_then(JsonValue::as_bool)
                == Some(true);
        self.metrics.record_model_call();
        if truncated {
            self.metrics.record_truncation();
        }
        envelope
    }
}

/// Outermost production provider: persist/replay canonical steps per turn.
pub(crate) struct DurableProviderHost {
    service: AgentService,
    run_id: String,
    inner: Arc<dyn AgentProviderHost>,
    metrics: Arc<Metrics>,
    turn: AtomicU64,
    attempt: AtomicU64,
}

impl DurableProviderHost {
    pub(crate) fn new(
        service: AgentService,
        run_id: String,
        inner: Arc<dyn AgentProviderHost>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            service,
            run_id,
            inner,
            metrics,
            turn: AtomicU64::new(1),
            attempt: AtomicU64::new(0),
        }
    }

    fn persist_failed() -> JsonValue {
        typed_fail(
            "provider_step_persist_failed",
            "failed to persist provider step",
        )
    }

    fn map_commit_error(error: EventCommitError) -> JsonValue {
        match error {
            EventCommitError::Terminal => typed_fail("run_terminal", "run is terminal"),
            EventCommitError::Cancelled => typed_fail("cancelled", "run was cancelled"),
            EventCommitError::PersistFailed(_) => Self::persist_failed(),
            EventCommitError::MissingParent => typed_fail(
                "missing_tool_parent",
                "tool result parent tool_call is missing",
            ),
            EventCommitError::Corrupt(_) => {
                typed_fail("corrupt_provider_step", "durable provider state is corrupt")
            }
        }
    }

    fn advance_turn(&self) {
        self.turn.fetch_add(1, Ordering::SeqCst);
        self.attempt.store(0, Ordering::SeqCst);
    }

    fn replay_completed(&self, turn: u64) -> Result<Option<JsonValue>, EventCommitError> {
        self.service.replay_provider_envelope(&self.run_id, turn)
    }
}

impl AgentProviderHost for DurableProviderHost {
    fn call(&self, request: &JsonValue, cancellation: &RunCancellation) -> JsonValue {
        let turn = self.turn.load(Ordering::SeqCst);
        match self.replay_completed(turn) {
            Ok(Some(envelope)) => {
                self.advance_turn();
                return envelope;
            }
            Ok(None) => {}
            Err(error) => return Self::map_commit_error(error),
        }
        if self.service.has_provider_request(&self.run_id, turn) {
            match self
                .service
                .recover_pending_provider(&self.run_id, turn, self.inner.as_ref())
            {
                Ok(ProviderPendingDecision::Replay) => {
                    return match self.replay_completed(turn) {
                        Ok(Some(envelope)) => {
                            self.advance_turn();
                            envelope
                        }
                        Ok(None) => Self::map_commit_error(EventCommitError::Corrupt(
                            "durable provider step is incomplete".to_string(),
                        )),
                        Err(error) => Self::map_commit_error(error),
                    };
                }
                Ok(ProviderPendingDecision::Retry) => {}
                Ok(ProviderPendingDecision::Interrupted) => {
                    return typed_fail(
                        "interrupted_provider",
                        "pending provider request is not retryable",
                    );
                }
                Ok(ProviderPendingDecision::RefusedTerminal) => {
                    return typed_fail("cancelled", "run already committed a terminal state");
                }
                Err(error) => return Self::map_commit_error(error),
            }
        }

        let attempt = self.attempt.fetch_add(1, Ordering::SeqCst) + 1;
        if let Err(error) = self
            .service
            .commit_provider_request(&self.run_id, turn, true, request)
        {
            return Self::map_commit_error(error);
        }
        if self.service.take_crash_after_provider_request() {
            self.service.mark_provider_commit_crashed();
            panic!("provider_request_crash");
        }

        let envelope = self.inner.call(request, cancellation);
        if envelope.get("ok").and_then(JsonValue::as_bool) != Some(true) {
            let code = envelope
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(JsonValue::as_str)
                .unwrap_or("provider_error");
            if error_is_retryable_code(code) {
                let status = envelope
                    .get("error")
                    .and_then(|error| error.get("status"))
                    .and_then(JsonValue::as_u64);
                if let Err(error) = self.service.persist_retryable_provider_failure(
                    &self.run_id,
                    turn,
                    attempt,
                    code,
                    status,
                ) {
                    return Self::map_commit_error(error);
                }
            }
            return envelope;
        }
        let step = match canonical_provider_step_from_envelope(&envelope, request) {
            Ok(step) => step,
            Err(failure) => return failure,
        };
        if let Err(error) = validate_provider_blocks(&step.blocks) {
            return Self::map_commit_error(error);
        }
        match self.service.commit_provider_step_with_meta(
            &self.run_id,
            turn,
            &step.blocks,
            step.usage.as_ref(),
            step.finish_reason.as_deref(),
            step.provider.as_deref(),
            step.model.as_deref(),
            None,
            step.truncated,
            step.reasoning.as_ref(),
        ) {
            Ok(ProviderCommitOutcome::Inserted(commit)) => {
                self.metrics.record_turn();
                self.advance_turn();
                if self.service.take_crash_after_provider_commit() {
                    self.service.mark_provider_commit_crashed();
                    panic!("provider_commit_crash");
                }
                commit.envelope
            }
            Ok(ProviderCommitOutcome::Existing(commit)) => {
                self.advance_turn();
                commit.envelope
            }
            Err(error) => Self::map_commit_error(error),
        }
    }
}

pub(crate) struct CanonicalProviderStep {
    pub blocks: Vec<LlmContentBlock>,
    pub usage: Option<Usage>,
    pub finish_reason: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub truncated: Option<bool>,
    pub reasoning: Option<JsonValue>,
}

const SAFE_REQUEST_KEYS: &[&str] = &[
    "model",
    "provider",
    "stream",
    "max_output_tokens",
    "tool_choice",
];

/// Deterministic digest over the canonical safe request shape. Never hashes
/// messages, prompt, provider_options, api_key, or raw headers/body.
pub(crate) fn canonical_provider_request_fingerprint(request: &JsonValue) -> String {
    let mut safe = serde_json::Map::new();
    if let Some(object) = request.as_object() {
        for key in SAFE_REQUEST_KEYS {
            if let Some(value) = object.get(*key) {
                safe.insert((*key).to_string(), value.clone());
            }
        }
    }
    let bytes = serde_json::to_vec(&JsonValue::Object(safe)).unwrap_or_else(|_| b"{}".to_vec());
    format!("sha256:{}", crate::tools::sha256_hex(&bytes))
}

pub(crate) fn canonical_provider_step_from_envelope(
    envelope: &JsonValue,
    request: &JsonValue,
) -> Result<CanonicalProviderStep, JsonValue> {
    let Some(response) = envelope.get("response") else {
        return Err(typed_fail(
            "malformed_payload",
            "provider response is missing",
        ));
    };
    if !response.is_object() {
        return Err(typed_fail(
            "malformed_payload",
            "provider response must be an object",
        ));
    }
    if let Some(finish) = response
        .get("stop_reason")
        .or_else(|| response.get("finish_reason"))
        && !finish.is_string()
        && !finish.is_null()
    {
        return Err(typed_fail(
            "malformed_payload",
            "finish_reason must be a string",
        ));
    }
    if let Some(usage) = response.get("usage") {
        if !usage.is_object() {
            return Err(typed_fail("malformed_payload", "usage must be an object"));
        }
        for key in ["input_tokens", "output_tokens", "total_tokens"] {
            if let Some(value) = usage.get(key)
                && !value.is_null()
                && value.as_u64().is_none()
            {
                return Err(typed_fail(
                    "malformed_payload",
                    "usage fields must be non-negative integers",
                ));
            }
        }
    }
    if let Some(calls) = response.get("tool_calls")
        && !calls.is_array()
        && !calls.is_null()
    {
        return Err(typed_fail(
            "malformed_payload",
            "tool_calls must be an array",
        ));
    }
    Ok(canonical_provider_step(response, request))
}

pub(crate) fn canonical_provider_step(
    response: &JsonValue,
    request: &JsonValue,
) -> CanonicalProviderStep {
    let mut blocks = Vec::new();
    if let Some(content) = response.get("content") {
        blocks = decode_message_blocks(content);
    }
    if blocks.is_empty()
        && let Some(text) = response.get("text").and_then(JsonValue::as_str)
        && !text.is_empty()
    {
        blocks.push(LlmContentBlock {
            block_type: "text".to_string(),
            text: Some(text.to_string()),
            ..LlmContentBlock::default()
        });
    }
    let has_tool_call = blocks.iter().any(|block| block.block_type == "tool_call");
    if !has_tool_call && let Some(calls) = response.get("tool_calls").and_then(JsonValue::as_array)
    {
        for call in calls {
            blocks.push(tool_call_block(call));
        }
    }
    if blocks.is_empty() {
        blocks.push(LlmContentBlock {
            block_type: "text".to_string(),
            text: Some(
                response
                    .get("text")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("")
                    .to_string(),
            ),
            ..LlmContentBlock::default()
        });
    }
    let usage = response.get("usage").and_then(parse_usage);
    let finish_reason = response
        .get("stop_reason")
        .or_else(|| response.get("finish_reason"))
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let model = response
        .get("model")
        .or_else(|| request.get("model"))
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let provider = response
        .get("provider")
        .or_else(|| request.get("provider"))
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let truncated = response.get("truncated").and_then(JsonValue::as_bool);
    let reasoning = response
        .get("reasoning")
        .cloned()
        .filter(|value| !(value.is_null() || value.is_string() && value.as_str() == Some("")));
    CanonicalProviderStep {
        blocks,
        usage,
        finish_reason,
        model,
        provider,
        truncated,
        reasoning,
    }
}

pub(crate) fn validate_provider_blocks(blocks: &[LlmContentBlock]) -> Result<(), EventCommitError> {
    for block in blocks {
        if let Some(text) = block.text.as_deref()
            && text.chars().count() > MAX_DURABLE_TEXT_CHARS
        {
            return Err(EventCommitError::Corrupt(
                "provider text exceeds durable bound".to_string(),
            ));
        }
        if block.block_type != "tool_call" {
            continue;
        }
        let id = block.tool_call_id.as_deref().unwrap_or("");
        let name = block.name.as_deref().unwrap_or("");
        if id.is_empty() || name.is_empty() {
            return Err(EventCommitError::Corrupt(
                "tool_call missing id or name".to_string(),
            ));
        }
        if block.truncated == Some(true) {
            return Err(EventCommitError::Corrupt(
                "tool_call arguments are truncated".to_string(),
            ));
        }
        let Some(args_json) = block.arguments_json.as_deref() else {
            return Err(EventCommitError::Corrupt(
                "tool_call arguments_json is missing".to_string(),
            ));
        };
        if args_json.len() > MAX_DURABLE_TEXT_CHARS {
            return Err(EventCommitError::Corrupt(
                "tool_call arguments exceed durable bound".to_string(),
            ));
        }
        if std::str::from_utf8(args_json.as_bytes()).is_err() {
            return Err(EventCommitError::Corrupt(
                "tool_call arguments_json is not valid UTF-8".to_string(),
            ));
        }
        let parsed: JsonValue = serde_json::from_str(args_json).map_err(|_| {
            EventCommitError::Corrupt("tool_call arguments_json is not JSON".to_string())
        })?;
        if !parsed.is_object() {
            return Err(EventCommitError::Corrupt(
                "tool_call arguments must be a JSON object".to_string(),
            ));
        }
    }
    Ok(())
}

fn tool_call_block(call: &JsonValue) -> LlmContentBlock {
    let arguments_json = if let Some(raw) = call.get("arguments_json").and_then(JsonValue::as_str) {
        Some(raw.to_string())
    } else {
        call.get("arguments").map(ToString::to_string)
    };
    let arguments = call.get("arguments").cloned().or_else(|| {
        arguments_json
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
    });
    LlmContentBlock {
        block_type: "tool_call".to_string(),
        tool_call_id: call
            .get("id")
            .or_else(|| call.get("tool_call_id"))
            .and_then(JsonValue::as_str)
            .map(str::to_string),
        name: call
            .get("name")
            .and_then(JsonValue::as_str)
            .map(str::to_string),
        arguments_json,
        arguments,
        truncated: call.get("truncated").and_then(JsonValue::as_bool),
        ..LlmContentBlock::default()
    }
}

fn parse_usage(value: &JsonValue) -> Option<Usage> {
    if !value.is_object() {
        return None;
    }
    Some(Usage {
        input_tokens: value
            .get("input_tokens")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0),
        output_tokens: value
            .get("output_tokens")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0),
        total_tokens: value
            .get("total_tokens")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0),
    })
}

pub(crate) fn reconstruct_provider_envelope(
    content: &JsonValue,
    metadata: &JsonValue,
    finish_reason: Option<&str>,
) -> Result<JsonValue, EventCommitError> {
    let blocks = decode_message_blocks(content);
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for block in &blocks {
        match block.block_type.as_str() {
            "text" => {
                if let Some(piece) = block.text.as_deref() {
                    text.push_str(piece);
                }
            }
            "tool_call" => {
                if block.truncated == Some(true) {
                    return Err(EventCommitError::Corrupt(
                        "truncated tool_call arguments cannot be replayed".to_string(),
                    ));
                }
                let Some(args_json) = block.arguments_json.as_deref() else {
                    return Err(EventCommitError::Corrupt(
                        "missing tool_call arguments_json".to_string(),
                    ));
                };
                let arguments: JsonValue = serde_json::from_str(args_json).map_err(|_| {
                    EventCommitError::Corrupt("invalid tool_call arguments_json".to_string())
                })?;
                if !arguments.is_object() {
                    return Err(EventCommitError::Corrupt(
                        "tool_call arguments must be a JSON object".to_string(),
                    ));
                }
                tool_calls.push(json!({
                    "id": block.tool_call_id.clone().unwrap_or_default(),
                    "name": block.name.clone().unwrap_or_default(),
                    "arguments": arguments,
                    "arguments_json": args_json,
                }));
            }
            _ => {}
        }
    }
    let mut response = serde_json::Map::new();
    response.insert("text".to_string(), json!(text));
    response.insert("tool_calls".to_string(), json!(tool_calls));
    if let Some(finish) = finish_reason {
        response.insert("stop_reason".to_string(), json!(finish));
        response.insert("finish_reason".to_string(), json!(finish));
    }
    if let Some(usage) = metadata.get("usage") {
        response.insert("usage".to_string(), usage.clone());
    }
    if let Some(model) = metadata
        .get("model")
        .cloned()
        .filter(|value| value.as_str().is_none_or(|model| !model.is_empty()))
    {
        response.insert("model".to_string(), model);
    }
    if let Some(provider) = metadata
        .get("provider")
        .cloned()
        .filter(|value| value.as_str().is_none_or(|provider| !provider.is_empty()))
    {
        response.insert("provider".to_string(), provider);
    }
    if let Some(truncated) = metadata.get("truncated") {
        response.insert("truncated".to_string(), truncated.clone());
    }
    if let Some(reasoning) = metadata.get("reasoning") {
        response.insert("reasoning".to_string(), reasoning.clone());
    }
    Ok(json!({
        "ok": true,
        "response": JsonValue::Object(response),
        "error": {}
    }))
}
