//! A5 serial agent policy suites.
//!
//! Two pure-RSS policy modules under `rss/agent/` are driven here exactly as
//! the future script-owned runner would drive them: one typed context map
//! into the exported entry, one typed decision map out, executed on
//! synthetic typed inputs (no provider transport, no SQLite in the policy).
//!
//! - `main.rss` — serial loop policy skeleton: turn/max_turns accounting,
//!   typed ProviderError retry/backoff decisions, canonical
//!   `model.started` / `model.completed` event descriptors and the
//!   service-owned `run.failed` terminal descriptor. Provider calls and tool
//!   dispatch are typed BLOCKED capabilities (never fabricated success), and
//!   parallel/task execution is rejected (A6 excluded).
//! - `compact.rss` — durable compaction policy: prefix selection over the
//!   message history that never splits an assistant tool-call message from
//!   its tool-result messages and always keeps a retained tail window, plus
//!   the typed A2 storage command sequence
//!   `compaction.start -> message.compact -> compaction.commit` and the
//!   `compaction.fail` command builder. The execution tests drive the plan
//!   commands through the production A2 storage service
//!   (`rss/storage/main.rss`) and assert the durable outcome.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

fn agent_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent")
}

fn storage_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/storage")
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("agent")
}

fn loop_runner() -> AgentRunner {
    AgentRunner::from_file(agent_root().join("main.rss"), AgentConfig::default())
        .expect("production loop policy should compile")
}

fn compact_runner() -> AgentRunner {
    AgentRunner::from_file(agent_root().join("compact.rss"), AgentConfig::default())
        .expect("production compaction policy should compile")
}

fn storage_runner(root: &std::path::Path) -> AgentRunner {
    AgentRunner::from_file(
        storage_root().join("main.rss"),
        AgentConfig::default().with_sqlite_root(root),
    )
    .expect("production storage entrypoint should compile")
}

/// Converts one VM value into JSON (test-side mirror of the gateway renderer).
fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(values.iter().map(vm_value_to_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

/// Converts one JSON value into a VM value (mirror of the renderer).
fn json_to_vm(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(int) = value.as_i64() {
                Value::Int(int)
            } else {
                Value::Float(value.as_f64().expect("JSON number should be a float"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => {
            Value::Array(values.iter().map(json_to_vm).collect::<Vec<_>>().into())
        }
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm(value)))
                .collect(),
        ),
    }
}

/// Runs one policy entry with a typed context map and returns the decision
/// map as JSON.
fn decide(runner: &AgentRunner, context: JsonValue) -> JsonValue {
    let result = runner
        .run_with_context(json_to_vm(&context))
        .unwrap_or_else(|error| panic!("policy decision failed: {error:?}"));
    let Value::Map(result) = result else {
        panic!("policy entry should return a decision map");
    };
    vm_value_to_json(&Value::Map(result))
}

fn read_fixture(name: &str) -> JsonValue {
    let source =
        fs::read_to_string(fixtures_root().join(name)).expect("agent fixture should be readable");
    serde_json::from_str(&source).expect("agent fixture should be JSON")
}

// ---------------------------------------------------------------------------
// Loop policy context builders
// ---------------------------------------------------------------------------

fn loop_config(parallel: bool, task: bool) -> JsonValue {
    json!({
        "base_retry_delay_ms": 100,
        "max_retry_delay_ms": 400,
        "parallel": parallel,
        "task": task
    })
}

fn provider_ok(text: &str, tool_calls: JsonValue) -> JsonValue {
    json!({
        "ok": true,
        "response": {
            "text": text,
            "tool_calls": tool_calls,
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "reasoning": "",
            "stop_reason": "end_turn"
        },
        "error": {}
    })
}

fn provider_error(status: i64, error_type: &str, code: &str, message: &str) -> JsonValue {
    json!({
        "ok": false,
        "response": {},
        "error": {
            "status": status,
            "type": error_type,
            "code": code,
            "message": message,
            "param": "",
            "request_id": "req-1"
        }
    })
}

fn loop_context(
    phase: &str,
    turn: i64,
    max_turns: i64,
    retry_count: i64,
    max_retries: i64,
    provider: JsonValue,
    config: JsonValue,
) -> JsonValue {
    json!({
        "turn": turn,
        "max_turns": max_turns,
        "retry_count": retry_count,
        "max_retries": max_retries,
        "phase": phase,
        "model": "test-model",
        "provider": provider,
        "config": config
    })
}

fn start_context(turn: i64, max_turns: i64, config: JsonValue) -> JsonValue {
    loop_context("start", turn, max_turns, 0, 2, json!({}), config)
}

fn provider_context(
    turn: i64,
    max_turns: i64,
    retry_count: i64,
    max_retries: i64,
    provider: JsonValue,
) -> JsonValue {
    loop_context(
        "provider_result",
        turn,
        max_turns,
        retry_count,
        max_retries,
        provider,
        loop_config(false, false),
    )
}

// ---------------------------------------------------------------------------
// Loop policy suite (rss/agent/main.rss)
// ---------------------------------------------------------------------------

#[test]
fn loop_start_phase_emits_model_started_and_blocks_provider_call() {
    let runner = loop_runner();
    let decision = decide(&runner, start_context(0, 3, loop_config(false, false)));
    assert_eq!(decision["kind"], json!("blocked"));
    assert_eq!(decision["capability"], json!("provider.call"));
    assert_eq!(decision["turn"], json!(0));
    assert!(
        decision["reason"].as_str().is_some_and(|reason| !reason.is_empty()),
        "blocked provider.call must carry a typed reason"
    );
    let events = decision["events"]
        .as_array()
        .expect("decision should carry event descriptors");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], json!("model.started"));
    assert_eq!(events[0]["turn"], json!(0));
    assert_eq!(events[0]["model"], json!("test-model"));
}

#[test]
fn loop_success_without_tools_advances_turn() {
    let runner = loop_runner();
    let decision = decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_ok("hello", json!([]))),
    );
    assert_eq!(decision["kind"], json!("next.turn"));
    assert_eq!(decision["turn"], json!(1));
    let events = decision["events"]
        .as_array()
        .expect("decision should carry event descriptors");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], json!("model.completed"));
    assert_eq!(events[0]["turn"], json!(0));
    assert_eq!(events[0]["text"], json!("hello"));
    assert_eq!(events[0]["tool_calls"], json!(0));
}

#[test]
fn loop_success_with_tool_calls_blocks_tool_dispatch() {
    let runner = loop_runner();
    let decision = decide(
        &runner,
        provider_context(
            0,
            3,
            0,
            2,
            provider_ok(
                "need a tool",
                json!([{"id": "call-1", "name": "read_file", "arguments": {}}]),
            ),
        ),
    );
    assert_eq!(decision["kind"], json!("blocked"));
    assert_eq!(decision["capability"], json!("tool.dispatch"));
    assert_eq!(decision["turn"], json!(0));
    assert!(
        decision["reason"].as_str().is_some_and(|reason| !reason.is_empty()),
        "blocked tool.dispatch must carry a typed reason"
    );
    let events = decision["events"]
        .as_array()
        .expect("decision should carry event descriptors");
    assert_eq!(events[0]["type"], json!("model.completed"));
    assert_eq!(events[0]["tool_calls"], json!(1));
}

#[test]
fn loop_max_turns_terminates_run_completed() {
    let runner = loop_runner();
    // A fresh turn is refused once the budget is exhausted.
    let refused = decide(&runner, start_context(3, 3, loop_config(false, false)));
    assert_eq!(refused["kind"], json!("run.completed"));
    assert_eq!(refused["turn"], json!(3));
    assert_eq!(
        refused["events"].as_array().expect("events").len(),
        0,
        "refusing a new turn emits no events"
    );
    // Completing the last allowed turn also terminates.
    let completed = decide(
        &runner,
        provider_context(2, 3, 0, 2, provider_ok("done", json!([]))),
    );
    assert_eq!(completed["kind"], json!("run.completed"));
    assert_eq!(completed["turn"], json!(3));
    let events = completed["events"]
        .as_array()
        .expect("decision should carry event descriptors");
    assert_eq!(events[0]["type"], json!("model.completed"));
}

#[test]
fn loop_retryable_error_retries_with_backoff() {
    let runner = loop_runner();
    let decision = decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_error(429, "rate_limit_error", "rate_limited", "slow down")),
    );
    assert_eq!(decision["kind"], json!("retry"));
    assert_eq!(decision["retry_count"], json!(1), "retry count must increment");
    assert_eq!(decision["delay_ms"], json!(100), "first retry uses the base delay");
    assert_eq!(decision["turn"], json!(0), "a retry does not consume a turn");
    assert_eq!(
        decision["events"].as_array().expect("events").len(),
        0,
        "a retry emits no event descriptors"
    );
}

#[test]
fn loop_backoff_doubles_then_caps() {
    let runner = loop_runner();
    let second = decide(
        &runner,
        provider_context(0, 3, 1, 4, provider_error(503, "server_error", "unavailable", "busy")),
    );
    assert_eq!(second["kind"], json!("retry"));
    assert_eq!(second["delay_ms"], json!(200), "second retry doubles the delay");
    assert_eq!(second["retry_count"], json!(2));
    let third = decide(
        &runner,
        provider_context(0, 3, 2, 4, provider_error(503, "server_error", "unavailable", "busy")),
    );
    assert_eq!(third["delay_ms"], json!(400), "third retry doubles again");
    assert_eq!(third["retry_count"], json!(3));
    let capped = decide(
        &runner,
        provider_context(0, 3, 3, 4, provider_error(503, "server_error", "unavailable", "busy")),
    );
    assert_eq!(capped["delay_ms"], json!(400), "backoff is capped at max_retry_delay_ms");
    assert_eq!(capped["retry_count"], json!(4));
}

#[test]
fn loop_nonretryable_error_fails_run() {
    let runner = loop_runner();
    let decision = decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_error(400, "invalid_request_error", "bad_request", "no")),
    );
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["reason"], json!("non_retryable"));
    assert_eq!(decision["turn"], json!(0));
    let error = decision["error"]
        .as_object()
        .expect("run.failed must carry the typed provider error");
    assert_eq!(error["status"], json!(400));
    assert_eq!(error["type"], json!("invalid_request_error"));
    assert_eq!(error["code"], json!("bad_request"));
    assert_eq!(error["message"], json!("no"));
    assert_eq!(error["param"], json!(""));
    assert_eq!(error["request_id"], json!("req-1"));
}

#[test]
fn loop_max_retries_exceeded_fails_run() {
    let runner = loop_runner();
    // 503 is retryable, but the budget is already exhausted.
    let decision = decide(
        &runner,
        provider_context(0, 3, 2, 2, provider_error(503, "server_error", "unavailable", "busy")),
    );
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["reason"], json!("max_retries_exceeded"));
    assert_eq!(decision["error"]["status"], json!(503));
}

#[test]
fn loop_parallel_config_is_rejected() {
    let runner = loop_runner();
    let decision = decide(&runner, start_context(0, 3, loop_config(true, false)));
    assert_eq!(decision["kind"], json!("rejected"));
    assert_eq!(decision["code"], json!("parallel_not_supported"));
    assert!(
        decision["message"].as_str().is_some_and(|message| !message.is_empty()),
        "rejection must carry a typed message"
    );
}

#[test]
fn loop_task_config_is_rejected() {
    let runner = loop_runner();
    let decision = decide(&runner, start_context(0, 3, loop_config(false, true)));
    assert_eq!(decision["kind"], json!("rejected"));
    assert_eq!(decision["code"], json!("task_not_supported"));
}

#[test]
fn loop_unknown_phase_is_rejected() {
    let runner = loop_runner();
    let decision = decide(
        &runner,
        loop_context("mystery", 0, 3, 0, 2, json!({}), loop_config(false, false)),
    );
    assert_eq!(decision["kind"], json!("rejected"));
    assert_eq!(decision["code"], json!("unknown_phase"));
}

#[test]
fn loop_full_serial_run_advances_turns_and_completes() {
    let runner = loop_runner();
    // The harness injects synthetic provider results between policy steps,
    // exactly as the future script-owned runner would after the A3 blocker
    // clears; the policy itself never fabricates a provider success.
    let start = decide(&runner, start_context(0, 3, loop_config(false, false)));
    assert_eq!(start["kind"], json!("blocked"));
    assert_eq!(start["capability"], json!("provider.call"));
    assert_eq!(start["events"][0]["type"], json!("model.started"));

    let step = decide(&runner, provider_context(0, 3, 0, 2, provider_ok("hello", json!([]))));
    assert_eq!(step["kind"], json!("next.turn"));
    assert_eq!(step["turn"], json!(1));

    let start = decide(&runner, start_context(1, 3, loop_config(false, false)));
    assert_eq!(start["kind"], json!("blocked"));
    assert_eq!(start["events"][0]["turn"], json!(1), "turn must increment across steps");

    let step = decide(&runner, provider_context(1, 3, 0, 2, provider_ok("again", json!([]))));
    assert_eq!(step["kind"], json!("next.turn"));
    assert_eq!(step["turn"], json!(2));

    let start = decide(&runner, start_context(2, 3, loop_config(false, false)));
    assert_eq!(start["events"][0]["turn"], json!(2));

    let step = decide(&runner, provider_context(2, 3, 0, 2, provider_ok("done", json!([]))));
    assert_eq!(step["kind"], json!("run.completed"));
    assert_eq!(step["turn"], json!(3));
}

#[test]
fn loop_decisions_never_invent_parallel_or_subagent_actions() {
    let runner = loop_runner();
    let mut decisions = Vec::new();
    decisions.push(decide(&runner, start_context(0, 3, loop_config(false, false))));
    decisions.push(decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_ok("hello", json!([]))),
    ));
    decisions.push(decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_ok("t", json!([{"id": "c", "name": "n", "arguments": {}}]))),
    ));
    decisions.push(decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_error(429, "rate_limit_error", "rl", "slow")),
    ));
    decisions.push(decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_error(400, "invalid_request_error", "br", "no")),
    ));
    for decision in &decisions {
        let text = decision.to_string();
        assert!(
            !text.contains("subagent") && !text.contains("parallel") && !text.contains("\"task\""),
            "the serial loop policy must never invent parallel/task actions: {text}"
        );
    }
}

#[test]
fn loop_canonical_event_shapes() {
    let runner = loop_runner();
    let started = decide(&runner, start_context(0, 3, loop_config(false, false)));
    let started_event = started["events"][0]
        .as_object()
        .expect("model.started event descriptor");
    let mut started_keys: Vec<&String> = started_event.keys().collect();
    started_keys.sort();
    assert_eq!(started_keys, vec!["model", "turn", "type"]);

    let completed = decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_ok("hi", json!([]))),
    );
    let completed_event = completed["events"][0]
        .as_object()
        .expect("model.completed event descriptor");
    let mut completed_keys: Vec<&String> = completed_event.keys().collect();
    completed_keys.sort();
    assert_eq!(completed_keys, vec!["text", "tool_calls", "turn", "type"]);

    let failed = decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_error(400, "invalid_request_error", "br", "no")),
    );
    let failed_error = failed["error"]
        .as_object()
        .expect("run.failed must carry the typed provider error");
    let mut error_keys: Vec<&String> = failed_error.keys().collect();
    error_keys.sort();
    assert_eq!(
        error_keys,
        vec!["code", "message", "param", "request_id", "status", "type"]
    );
}

#[test]
fn loop_fixture_context_deserializes() {
    let context = read_fixture("loop_context.json");
    assert_eq!(context["phase"], json!("start"));
    assert_eq!(context["turn"], json!(0));
    assert_eq!(context["max_turns"], json!(3));
    assert_eq!(context["config"]["parallel"], json!(false));
    // The fixture is a valid decision input: the policy accepts it.
    let runner = loop_runner();
    let decision = decide(&runner, context);
    assert_eq!(decision["kind"], json!("blocked"));
    assert_eq!(decision["capability"], json!("provider.call"));
}
