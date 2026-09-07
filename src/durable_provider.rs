//! Service-scoped durable provider wrapper for production `run_worker`.
//!
//! `DurableProviderHost` sits outermost around the raw/accounting provider.
//! Fresh request: persist exactly one sanitized `model.requested` boundary
//! whose `attempt` matches the logical provider attempt about to run, then
//! call inner. Same-turn retry (pending recovery `Retry`): reuse that single
//! request-boundary row, set `attempt` from durable `model.failed.attempt`,
//! and do not append another `model.requested`. Completed canonical steps are
//! replayed without an inner call or turn metric. Pending retry-safe requests
//! retry the same logical turn without synthesizing an assistant step.
//! Persist failure prevents the provider call. Malformed `ok:true` envelopes
//! are never persisted as success.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use serde_json::{Value as JsonValue, json};

use crate::domain::{LlmContentBlock, MAX_DURABLE_TEXT_CHARS, Usage};
use crate::events::EventCommitError;
use crate::metrics::Metrics;
use crate::runtime::agent_host::{provider_error_is_retryable, typed_fail};
use crate::runtime::rss_runner::RunCancellation;
use crate::service::{AgentService, ProviderCommitOutcome};
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

    fn persist_classified_failure(
        &self,
        turn: u64,
        attempt: u64,
        envelope: &JsonValue,
    ) -> Result<(), EventCommitError> {
        let error = envelope.get("error").cloned().unwrap_or_else(|| json!({}));
        let code = error
            .get("code")
            .and_then(JsonValue::as_str)
            .unwrap_or("provider_error");
        let status = error.get("status").and_then(JsonValue::as_u64);
        let retryable = provider_error_is_retryable(&error);
        self.service
            .persist_provider_failure(&self.run_id, turn, attempt, code, status, retryable)
    }

    fn advance_turn(&self) {
        self.turn.fetch_add(1, Ordering::SeqCst);
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
        let attempt = self.service.next_provider_attempt(&self.run_id, turn);
        if self.service.has_provider_request(&self.run_id, turn) {
            match self
                .service
                .recover_pending_provider(&self.run_id, turn, request)
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
        } else if let Err(error) =
            self.service
                .commit_provider_request(&self.run_id, turn, attempt, true, request)
        {
            return Self::map_commit_error(error);
        } else if self.service.take_crash_after_provider_request() {
            self.service.mark_provider_commit_crashed();
            panic!("provider_request_crash");
        }

        let envelope = self.inner.call(request, cancellation);
        if envelope.get("ok").and_then(JsonValue::as_bool) != Some(true) {
            if let Err(error) = self.persist_classified_failure(turn, attempt, &envelope) {
                return Self::map_commit_error(error);
            }
            return envelope;
        }
        let step = match canonical_provider_step_from_envelope(&envelope, request) {
            Ok(step) => step,
            Err(failure) => {
                if let Err(error) = self.persist_classified_failure(turn, attempt, &failure) {
                    return Self::map_commit_error(error);
                }
                return failure;
            }
        };
        if let Err(error) = validate_provider_blocks(&step.blocks) {
            let failure = Self::map_commit_error(error);
            if let Err(persist_error) = self.persist_classified_failure(turn, attempt, &failure) {
                return Self::map_commit_error(persist_error);
            }
            return failure;
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
    format!("sha256:{}", crate::registry::sha256_hex(&bytes))
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
    canonical_provider_step(response, request)
}

pub(crate) fn canonical_provider_step(
    response: &JsonValue,
    request: &JsonValue,
) -> Result<CanonicalProviderStep, JsonValue> {
    let mut blocks = Vec::new();
    if let Some(content) = response.get("content") {
        blocks = decode_provider_blocks_strict(content)
            .map_err(DurableProviderHost::map_commit_error)?;
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
    Ok(CanonicalProviderStep {
        blocks,
        usage,
        finish_reason,
        model,
        provider,
        truncated,
        reasoning,
    })
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

fn decode_provider_blocks_strict(
    content: &JsonValue,
) -> Result<Vec<LlmContentBlock>, EventCommitError> {
    let Some(items) = content.as_array() else {
        return Err(EventCommitError::Corrupt(
            "provider content must be a canonical block array".to_string(),
        ));
    };
    let mut blocks = Vec::with_capacity(items.len());
    for item in items {
        blocks.push(decode_provider_block_strict(item)?);
    }
    Ok(blocks)
}

fn decode_provider_block_strict(value: &JsonValue) -> Result<LlmContentBlock, EventCommitError> {
    let Some(map) = value.as_object() else {
        return Err(EventCommitError::Corrupt(
            "provider content block must be an object".to_string(),
        ));
    };
    if map.is_empty() {
        return Err(EventCommitError::Corrupt(
            "provider content block must not be empty".to_string(),
        ));
    }
    let Some(block_type) = map.get("type").and_then(JsonValue::as_str) else {
        return Err(EventCommitError::Corrupt(
            "provider content block is missing type".to_string(),
        ));
    };
    match block_type {
        "text" => {
            let Some(text) = map.get("text").and_then(JsonValue::as_str) else {
                return Err(EventCommitError::Corrupt(
                    "text block requires string text".to_string(),
                ));
            };
            Ok(LlmContentBlock {
                block_type: "text".to_string(),
                text: Some(text.to_string()),
                truncated: map.get("truncated").and_then(JsonValue::as_bool),
                ..LlmContentBlock::default()
            })
        }
        "tool_call" => {
            let id = map
                .get("tool_call_id")
                .or_else(|| map.get("id"))
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let name = map.get("name").and_then(JsonValue::as_str).unwrap_or("");
            if id.is_empty() || name.is_empty() {
                return Err(EventCommitError::Corrupt(
                    "tool_call missing id or name".to_string(),
                ));
            }
            if map.get("truncated").and_then(JsonValue::as_bool) == Some(true) {
                return Err(EventCommitError::Corrupt(
                    "tool_call arguments are truncated".to_string(),
                ));
            }
            let (arguments_json, arguments) = parse_strict_tool_arguments(map)?;
            Ok(LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some(id.to_string()),
                name: Some(name.to_string()),
                arguments_json,
                arguments,
                truncated: map.get("truncated").and_then(JsonValue::as_bool),
                ..LlmContentBlock::default()
            })
        }
        _ => Err(EventCommitError::Corrupt(format!(
            "unknown provider content block type: {block_type}"
        ))),
    }
}

fn parse_strict_tool_arguments(
    map: &serde_json::Map<String, JsonValue>,
) -> Result<(Option<String>, Option<JsonValue>), EventCommitError> {
    if let Some(raw) = map.get("arguments_json") {
        let text = raw.as_str().ok_or_else(|| {
            EventCommitError::Corrupt("tool_call arguments_json must be a string".to_string())
        })?;
        let parsed: JsonValue = serde_json::from_str(text).map_err(|_| {
            EventCommitError::Corrupt("tool_call arguments_json is not JSON".to_string())
        })?;
        if !parsed.is_object() {
            return Err(EventCommitError::Corrupt(
                "tool_call arguments must be a JSON object".to_string(),
            ));
        }
        return Ok((Some(text.to_string()), None));
    }
    if let Some(arguments) = map.get("arguments") {
        if !arguments.is_object() {
            return Err(EventCommitError::Corrupt(
                "tool_call arguments must be a JSON object".to_string(),
            ));
        }
        let encoded = serde_json::to_string(arguments).map_err(|_| {
            EventCommitError::Corrupt("tool_call arguments could not be encoded".to_string())
        })?;
        return Ok((Some(encoded), None));
    }
    Err(EventCommitError::Corrupt(
        "tool_call arguments_json is missing".to_string(),
    ))
}

pub(crate) fn reconstruct_provider_envelope(
    content: &JsonValue,
    metadata: &JsonValue,
    finish_reason: Option<&str>,
) -> Result<JsonValue, EventCommitError> {
    let blocks = decode_provider_blocks_strict(content)?;
    validate_provider_blocks(&blocks)?;
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
                let id = block.tool_call_id.as_deref().unwrap_or("");
                let name = block.name.as_deref().unwrap_or("");
                if id.is_empty() || name.is_empty() {
                    return Err(EventCommitError::Corrupt(
                        "tool_call missing id or name".to_string(),
                    ));
                }
                tool_calls.push(json!({
                    "id": id,
                    "name": name,
                    "arguments": arguments,
                    "arguments_json": args_json,
                }));
            }
            _ => {
                return Err(EventCommitError::Corrupt(
                    "unknown provider content block type".to_string(),
                ));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventCommitError;
    use crate::gateway::AgentGatewayState;
    use crate::runtime::agent_host::error_is_retryable_code;
    use crate::{AdmitRunRequest, AgentGatewayConfig, AgentProviderHost, ScriptedProvider};

    fn request() -> JsonValue {
        json!({"model": "test-model", "provider": "openai"})
    }

    fn text_ok(text: &str) -> JsonValue {
        json!({
            "text": text,
            "tool_calls": [],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "stop_reason": "stop"
        })
    }

    fn legit_tool_block() -> JsonValue {
        json!({
            "type": "tool_call",
            "tool_call_id": "c1",
            "name": "read_file",
            "arguments": {"path": "a.rs"}
        })
    }

    async fn admitted_state() -> (AgentGatewayState, String, String) {
        let state =
            AgentGatewayState::new(AgentGatewayConfig::default()).expect("in-memory gateway");
        let admitted = state
            .service()
            .admit(AdmitRunRequest {
                input: json!({"message": "hello"}),
                platform: "durable_provider_tests".to_string(),
                ..AdmitRunRequest::default()
            })
            .await
            .expect("admit");
        (state, admitted.run_id, admitted.session_id)
    }

    fn host_for(
        state: &AgentGatewayState,
        run_id: &str,
        inner: ScriptedProvider,
    ) -> DurableProviderHost {
        DurableProviderHost::new(
            AgentService::clone(state.service().as_ref()),
            run_id.to_string(),
            Arc::new(inner),
            state.service().metrics(),
        )
    }

    fn tool_event_count(state: &AgentGatewayState, run_id: &str) -> usize {
        state
            .service()
            .run_events(run_id)
            .into_iter()
            .filter(|event| {
                event
                    .get("event")
                    .and_then(JsonValue::as_str)
                    .is_some_and(|name| name.starts_with("tool."))
            })
            .count()
    }

    #[test]
    fn structural_commit_and_replay_codes_are_not_retryable() {
        for code in [
            "corrupt_provider_step",
            "run_terminal",
            "cancelled",
            "missing_tool_parent",
            "malformed_payload",
            "provider_step_persist_failed",
            "interrupted_provider",
            "deadline_elapsed",
            "unknown_provider_code",
        ] {
            assert!(
                !error_is_retryable_code(code),
                "{code} must be fail-closed non-retryable"
            );
        }
        for code in [
            "unavailable",
            "timeout",
            "rate_limited",
            "overloaded",
            "transport",
        ] {
            assert!(
                error_is_retryable_code(code),
                "{code} is a known transient allowlist code"
            );
        }
    }

    #[test]
    fn map_commit_errors_are_not_retryable() {
        let cases = [
            EventCommitError::Terminal,
            EventCommitError::Cancelled,
            EventCommitError::MissingParent,
            EventCommitError::Corrupt("durable provider state is corrupt".to_string()),
            EventCommitError::PersistFailed("io".to_string()),
        ];
        for error in cases {
            let fail = DurableProviderHost::map_commit_error(error);
            assert_eq!(fail["ok"], json!(false));
            assert_eq!(
                fail["error"]["retryable"],
                json!(false),
                "structural commit/replay errors must not retry: {fail}"
            );
        }
    }

    #[test]
    fn strict_inbound_rejects_non_canonical_content() {
        let cases = [
            json!("hello"),
            json!({"text": "hello"}),
            json!({}),
            json!([{}]),
            json!([{"not": "a block"}]),
            json!([{"type": "thinking", "text": "nope"}]),
            json!([{"type": "text"}]),
            json!([{"type": "tool_call", "name": "read_file", "arguments": {"path": "a.rs"}}]),
            json!([{
                "type": "tool_call",
                "tool_call_id": "c1",
                "name": "",
                "arguments": {"path": "a.rs"}
            }]),
            json!([{
                "type": "tool_call",
                "tool_call_id": "c1",
                "name": "read_file",
                "truncated": true,
                "arguments": {"path": "a.rs"}
            }]),
            json!([{
                "type": "tool_call",
                "tool_call_id": "c1",
                "name": "read_file",
                "arguments": "not-object"
            }]),
            json!([{
                "type": "tool_call",
                "tool_call_id": "c1",
                "name": "read_file",
                "arguments": ["x"]
            }]),
        ];
        for content in cases {
            let envelope = json!({
                "ok": true,
                "response": {
                    "content": content,
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                    "stop_reason": "stop"
                }
            });
            let result = canonical_provider_step_from_envelope(&envelope, &request());
            assert!(
                result.is_err(),
                "non-canonical content must fail closed: {content}"
            );
            let fail = match result {
                Err(fail) => fail,
                Ok(_) => panic!("non-canonical content must fail closed: {content}"),
            };
            assert_eq!(fail["ok"], json!(false));
            assert_eq!(fail["error"]["retryable"], json!(false));
        }
    }

    #[test]
    fn strict_inbound_accepts_legit_text_and_tool_blocks() {
        let envelope = json!({
            "ok": true,
            "response": {
                "content": [
                    {"type": "text", "text": "hello"},
                    legit_tool_block()
                ],
                "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5},
                "model": "test-model",
                "provider": "openai",
                "truncated": false,
                "reasoning": {"tokens": 1},
                "stop_reason": "tool_calls"
            }
        });
        let step = canonical_provider_step_from_envelope(&envelope, &request())
            .expect("canonical text/tool content");
        assert_eq!(step.blocks.len(), 2);
        assert_eq!(step.blocks[0].block_type, "text");
        assert_eq!(step.blocks[0].text.as_deref(), Some("hello"));
        assert_eq!(step.blocks[1].block_type, "tool_call");
        assert_eq!(step.blocks[1].tool_call_id.as_deref(), Some("c1"));
        assert_eq!(step.blocks[1].name.as_deref(), Some("read_file"));
        assert_eq!(step.finish_reason.as_deref(), Some("tool_calls"));
        assert_eq!(step.model.as_deref(), Some("test-model"));
        assert_eq!(step.provider.as_deref(), Some("openai"));
        assert_eq!(step.truncated, Some(false));
        assert_eq!(step.reasoning, Some(json!({"tokens": 1})));
        validate_provider_blocks(&step.blocks).expect("legit tool args");
    }

    #[test]
    fn strict_replay_rejects_malformed_content() {
        let metadata = json!({
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "model": "test-model",
            "provider": "openai"
        });
        let cases = [
            json!("hello"),
            json!({}),
            json!([{}]),
            json!([{"type": "unknown", "text": "x"}]),
            json!([{"type": "tool_call", "tool_call_id": "", "name": "read_file", "arguments_json": "{}"}]),
            json!([{"type": "tool_call", "tool_call_id": "c1", "name": "read_file", "truncated": true, "arguments_json": "{}"}]),
            json!([{"type": "tool_call", "tool_call_id": "c1", "name": "read_file", "arguments_json": "[1]"}]),
        ];
        for content in cases {
            let result = reconstruct_provider_envelope(&content, &metadata, Some("stop"));
            assert!(
                result.is_err(),
                "malformed durable replay must not succeed: {content}"
            );
        }
    }

    #[test]
    fn strict_replay_keeps_legit_blocks_and_exact_metadata() {
        let content = json!([
            {"type": "text", "text": "hello"},
            {
                "type": "tool_call",
                "tool_call_id": "c1",
                "name": "read_file",
                "arguments_json": "{\"path\":\"a.rs\"}"
            }
        ]);
        let metadata = json!({
            "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5},
            "model": "test-model",
            "provider": "openai",
            "truncated": false,
            "reasoning": {"tokens": 1}
        });
        let envelope = reconstruct_provider_envelope(&content, &metadata, Some("tool_calls"))
            .expect("canonical replay");
        assert_eq!(envelope["ok"], json!(true));
        assert_eq!(envelope["response"]["text"], json!("hello"));
        assert_eq!(
            envelope["response"]["tool_calls"],
            json!([{
                "id": "c1",
                "name": "read_file",
                "arguments": {"path": "a.rs"},
                "arguments_json": "{\"path\":\"a.rs\"}"
            }])
        );
        assert_eq!(envelope["response"]["usage"], metadata["usage"]);
        assert_eq!(envelope["response"]["model"], json!("test-model"));
        assert_eq!(envelope["response"]["provider"], json!("openai"));
        assert_eq!(envelope["response"]["truncated"], json!(false));
        assert_eq!(envelope["response"]["reasoning"], json!({"tokens": 1}));
        assert_eq!(envelope["response"]["stop_reason"], json!("tool_calls"));
    }

    #[tokio::test]
    async fn corrupt_inner_response_is_non_retryable_without_tools() {
        let (state, run_id, _) = admitted_state().await;
        let inner = ScriptedProvider::new();
        inner.push_ok(json!({
            "content": [{"type": "tool_call", "name": "read_file", "arguments": {"path": "a.rs"}}],
            "tool_calls": [],
            "stop_reason": "tool_calls"
        }));
        inner.push_ok(text_ok("should not run"));
        let host = host_for(&state, &run_id, inner.clone());
        let cancellation = RunCancellation::new();
        let first = host.call(&request(), &cancellation);
        assert_eq!(first["ok"], json!(false), "{first}");
        assert_eq!(first["error"]["retryable"], json!(false), "{first}");
        assert_eq!(inner.call_count(), 1);
        assert_eq!(tool_event_count(&state, &run_id), 0);
        let failed = state
            .service()
            .run_events(&run_id)
            .into_iter()
            .filter(|event| event["event"] == "model.failed")
            .collect::<Vec<_>>();
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["data"]["retryable"], json!(false));

        let second = host.call(&request(), &cancellation);
        assert_eq!(second["ok"], json!(false), "{second}");
        assert_eq!(second["error"]["retryable"], json!(false), "{second}");
        assert_eq!(inner.call_count(), 1, "corrupt inner must not be reissued");
        assert_eq!(tool_event_count(&state, &run_id), 0);
    }

    fn temporary_db_path() -> std::path::PathBuf {
        let root = std::env::var_os("TEST_TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "rustscript-agent-durable-provider-{}",
                    std::process::id()
                ))
            });
        std::fs::create_dir_all(&root).expect("test database directory");
        root.join(format!("{}.db", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn malformed_durable_replay_is_not_ok_true() {
        let path = temporary_db_path();
        let source = "pub fn run(context: map) -> map { context; }";
        let admitted = {
            let state = AgentGatewayState::with_agent_source_and_sqlite(
                AgentGatewayConfig::default(),
                source,
                &path,
            )
            .expect("sqlite gateway");
            let admitted = state
                .service()
                .admit(AdmitRunRequest {
                    input: json!({"message": "hello"}),
                    platform: "durable_provider_tests".to_string(),
                    ..AdmitRunRequest::default()
                })
                .await
                .expect("admit");
            let content_json = json!([{"type": "unknown", "text": "nope"}]).to_string();
            state
                .persistence()
                .expect("sqlite")
                .step_commit(&json!({
                    "run_id": admitted.run_id,
                    "session_id": admitted.session_id,
                    "event_id": crate::domain::durable_provider_event_id(
                        &admitted.run_id,
                        1,
                        "model.completed"
                    ),
                    "event_type": "model.completed",
                    "payload_json": "{\"turn\":1}",
                    "now_ms": 20,
                    "max_events": 128,
                    "message_id": crate::domain::durable_message_id(&admitted.run_id, "turn", "1"),
                    "role": "assistant",
                    "content_json": content_json,
                    "name": "",
                    "tool_call_id": "",
                    "parent_message_id": "",
                    "token_estimate": 0,
                    "metadata_json": "{\"model\":\"test-model\"}",
                    "finish_reason": "stop"
                }))
                .expect("inject malformed durable step");
            drop(state);
            admitted
        };
        let resumed = AgentGatewayState::with_agent_source_and_sqlite(
            AgentGatewayConfig::default(),
            source,
            &path,
        )
        .expect("reopen");
        let inner = ScriptedProvider::new();
        inner.push_ok(text_ok("should not replay as success"));
        let host = host_for(&resumed, &admitted.run_id, inner.clone());
        let envelope = host.call(&request(), &RunCancellation::new());
        assert_ne!(
            envelope.get("ok").and_then(JsonValue::as_bool),
            Some(true),
            "malformed durable replay must not return ok:true: {envelope}"
        );
        assert_eq!(inner.call_count(), 0);
        drop(resumed);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn nonretryable_failure_redrive_does_not_call_inner() {
        let (state, run_id, _) = admitted_state().await;
        let inner = ScriptedProvider::new();
        inner.push_error(json!({
            "status": 400,
            "type": "invalid_request_error",
            "code": "config",
            "message": "bad config",
            "param": "",
            "request_id": "",
            "retryable": false
        }));
        inner.push_ok(text_ok("should not run"));
        let host = host_for(&state, &run_id, inner.clone());
        let cancellation = RunCancellation::new();
        let first = host.call(&request(), &cancellation);
        assert_eq!(first["ok"], json!(false), "{first}");
        assert_eq!(first["error"]["retryable"], json!(false), "{first}");
        assert_eq!(inner.call_count(), 1);
        let failed = state
            .service()
            .run_events(&run_id)
            .into_iter()
            .find(|event| event["event"] == "model.failed")
            .expect("sanitized model.failed");
        assert_eq!(failed["data"]["retryable"], json!(false));
        assert_eq!(failed["data"]["error_code"], json!("config"));

        let second = host.call(&request(), &cancellation);
        assert_eq!(second["ok"], json!(false), "{second}");
        assert_eq!(
            inner.call_count(),
            1,
            "non-retryable failure must not reissue"
        );
    }

    fn events_named(state: &AgentGatewayState, run_id: &str, name: &str) -> Vec<JsonValue> {
        state
            .service()
            .run_events(run_id)
            .into_iter()
            .filter(|event| event["event"] == name)
            .collect()
    }

    fn retryable_error() -> JsonValue {
        json!({
            "status": 503,
            "type": "server_error",
            "code": "unavailable",
            "message": "down",
            "param": "",
            "request_id": "",
            "retryable": true
        })
    }

    #[test]
    fn canonical_fingerprint_is_exact_digest_without_secrets() {
        let request = json!({
            "model": "gpt-test",
            "provider": "openai",
            "prompt": "SECRET_PROMPT",
            "messages": [{"role": "user", "content": "SECRET_MSG"}],
            "api_key": "SECRET_KEY",
            "provider_options": {"api_key": "SECRET_KEY"},
            "headers": {"authorization": "SECRET_AUTH"},
            "body": "SECRET_BODY"
        });
        let fingerprint = canonical_provider_request_fingerprint(&request);
        assert_eq!(
            fingerprint,
            "sha256:84f36ce2b6ba7b471a73b3bffa624bf004ceaa4f91d9e160161806c31613ba68"
        );
        for needle in [
            "SECRET_PROMPT",
            "SECRET_MSG",
            "SECRET_KEY",
            "SECRET_AUTH",
            "SECRET_BODY",
        ] {
            assert!(
                !fingerprint.contains(needle),
                "fingerprint leaked {needle}: {fingerprint}"
            );
        }
        assert_eq!(
            canonical_provider_request_fingerprint(&json!({
                "model": "gpt-test",
                "provider": "openai"
            })),
            fingerprint
        );
    }

    #[tokio::test]
    async fn fresh_request_attempt_aligns_with_failed_attempt() {
        let (state, run_id, _) = admitted_state().await;
        let inner = ScriptedProvider::new();
        inner.push_error(retryable_error());
        inner.push_ok(text_ok("recovered"));
        let host = host_for(&state, &run_id, inner.clone());
        let cancellation = RunCancellation::new();
        let first = host.call(&request(), &cancellation);
        assert_eq!(first["ok"], json!(false), "{first}");
        let requested = events_named(&state, &run_id, "model.requested");
        assert_eq!(requested.len(), 1, "{requested:?}");
        assert_eq!(requested[0]["data"]["attempt"], json!(1));
        let failed = events_named(&state, &run_id, "model.failed");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0]["data"]["attempt"], json!(1));

        let second = host.call(&request(), &cancellation);
        assert_eq!(second["ok"], json!(true), "{second}");
        let requested = events_named(&state, &run_id, "model.requested");
        assert_eq!(
            requested.len(),
            1,
            "same-turn retry must not append another request boundary: {requested:?}"
        );
        assert_eq!(requested[0]["data"]["attempt"], json!(1));
        assert_eq!(inner.call_count(), 2);
        assert_eq!(events_named(&state, &run_id, "model.completed").len(), 1);
        assert_eq!(state.service().metrics().snapshot().turns, 1);
    }

    #[tokio::test]
    async fn redrive_after_retryable_failure_persists_next_attempt() {
        let (state, run_id, _) = admitted_state().await;
        let inner = ScriptedProvider::new();
        inner.push_error(retryable_error());
        inner.push_error(retryable_error());
        let first_host = host_for(&state, &run_id, inner.clone());
        let cancellation = RunCancellation::new();
        let first = first_host.call(&request(), &cancellation);
        assert_eq!(first["ok"], json!(false), "{first}");
        drop(first_host);

        let second_host = host_for(&state, &run_id, inner.clone());
        let second = second_host.call(&request(), &cancellation);
        assert_eq!(second["ok"], json!(false), "{second}");
        let failed = events_named(&state, &run_id, "model.failed");
        let attempts: Vec<_> = failed
            .iter()
            .filter_map(|event| event["data"]["attempt"].as_u64())
            .collect();
        assert_eq!(attempts, vec![1, 2], "{failed:?}");
        assert_eq!(events_named(&state, &run_id, "model.requested").len(), 1);
        assert_eq!(inner.call_count(), 2);
    }

    #[tokio::test]
    async fn fingerprint_mismatch_or_corrupt_fails_closed_without_inner() {
        let (state, run_id, _) = admitted_state().await;
        state
            .service()
            .commit_provider_request(&run_id, 1, 1, true, &request())
            .expect("request boundary");
        let inner = ScriptedProvider::new();
        inner.push_ok(text_ok("should not run"));
        let host = host_for(&state, &run_id, inner.clone());
        let mismatched = host.call(
            &json!({"model": "other-model", "provider": "openai"}),
            &RunCancellation::new(),
        );
        assert_eq!(mismatched["ok"], json!(false), "{mismatched}");
        assert_eq!(mismatched["error"]["code"], json!("interrupted_provider"));
        assert_eq!(inner.call_count(), 0);
        assert_eq!(tool_event_count(&state, &run_id), 0);
        assert_eq!(events_named(&state, &run_id, "model.completed").len(), 0);

        let (state, run_id, _) = admitted_state().await;
        state
            .service()
            .persist_run_event(
                &run_id,
                &crate::domain::durable_provider_event_id(&run_id, 1, "model.requested"),
                "model.requested",
                json!({
                    "turn": 1,
                    "attempt": 1,
                    "request_fingerprint": "not-a-digest",
                    "retry_safe": true
                }),
            )
            .expect("corrupt fingerprint");
        let inner = ScriptedProvider::new();
        inner.push_ok(text_ok("should not run"));
        let host = host_for(&state, &run_id, inner.clone());
        let corrupt = host.call(&request(), &RunCancellation::new());
        assert_eq!(corrupt["error"]["code"], json!("interrupted_provider"));
        assert_eq!(inner.call_count(), 0);
        assert_eq!(tool_event_count(&state, &run_id), 0);
    }

    #[tokio::test]
    async fn crash_after_request_redrive_retries_once() {
        let (state, run_id, session_id) = admitted_state().await;
        let inner = ScriptedProvider::new();
        inner.push_ok(text_ok("after-redrive"));
        state.service().inject_crash_after_provider_request();
        let host = host_for(&state, &run_id, inner.clone());
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host.call(&request(), &RunCancellation::new())
        }));
        assert!(
            panicked.is_err(),
            "first call must stop at request boundary"
        );
        assert_eq!(inner.call_count(), 0);
        assert_eq!(events_named(&state, &run_id, "model.requested").len(), 1);
        assert_eq!(events_named(&state, &run_id, "model.completed").len(), 0);

        let host = host_for(&state, &run_id, inner.clone());
        let envelope = host.call(&request(), &RunCancellation::new());
        assert_eq!(envelope["ok"], json!(true), "{envelope}");
        assert_eq!(inner.call_count(), 1);
        assert_eq!(events_named(&state, &run_id, "model.requested").len(), 1);
        assert_eq!(events_named(&state, &run_id, "model.completed").len(), 1);
        assert_eq!(
            state
                .service()
                .session_messages(&session_id)
                .iter()
                .filter(|message| message["role"] == "assistant")
                .count(),
            1
        );
        assert_eq!(state.service().metrics().snapshot().turns, 1);
        assert_eq!(tool_event_count(&state, &run_id), 0);
    }

    #[tokio::test]
    async fn request_persist_failpoint_does_not_call_inner() {
        let path = temporary_db_path();
        let source = "pub fn run(context: map) -> map { context; }";
        let state = AgentGatewayState::with_agent_source_and_sqlite(
            crate::AgentGatewayConfig::default(),
            source,
            &path,
        )
        .expect("sqlite gateway");
        let admitted = state
            .service()
            .admit(crate::AdmitRunRequest {
                input: json!({"message": "hello"}),
                platform: "durable_provider_tests".to_string(),
                ..crate::AdmitRunRequest::default()
            })
            .await
            .expect("admit");
        state
            .persistence()
            .expect("sqlite")
            .inject_fail_model_requested_append();
        let inner = ScriptedProvider::new();
        inner.push_ok(text_ok("should not run"));
        let host = host_for(&state, &admitted.run_id, inner.clone());
        let envelope = host.call(&request(), &RunCancellation::new());
        assert_eq!(envelope["ok"], json!(false), "{envelope}");
        assert_eq!(
            envelope["error"]["code"],
            json!("provider_step_persist_failed")
        );
        assert_eq!(inner.call_count(), 0);
        assert_eq!(tool_event_count(&state, &admitted.run_id), 0);
        assert_eq!(
            events_named(&state, &admitted.run_id, "model.requested").len(),
            0
        );
        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
