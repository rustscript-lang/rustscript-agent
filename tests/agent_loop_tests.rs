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

use rustscript_agent::{
    AdmitRunRequest, AgentConfig, AgentGatewayConfig, AgentGatewayState, AgentRunner, ToolRegistry,
    builtin_entries,
};
use rustscript_vm::Value;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

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
        decision["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
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
    assert_eq!(
        decision["turn"],
        json!(1),
        "the tool cycle consumes the turn budget: the run continues at turn + 1"
    );
    assert_eq!(
        decision["events"][0]["turn"],
        json!(0),
        "the completed model call still belongs to the turn it started in"
    );
    assert!(
        decision["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
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
        provider_context(
            0,
            3,
            0,
            2,
            provider_error(429, "rate_limit_error", "rate_limited", "slow down"),
        ),
    );
    assert_eq!(decision["kind"], json!("retry"));
    assert_eq!(
        decision["retry_count"],
        json!(1),
        "retry count must increment"
    );
    assert_eq!(
        decision["delay_ms"],
        json!(100),
        "first retry uses the base delay"
    );
    assert_eq!(
        decision["turn"],
        json!(0),
        "a retry does not consume a turn"
    );
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
        provider_context(
            0,
            3,
            1,
            4,
            provider_error(503, "server_error", "unavailable", "busy"),
        ),
    );
    assert_eq!(second["kind"], json!("retry"));
    assert_eq!(
        second["delay_ms"],
        json!(200),
        "second retry doubles the delay"
    );
    assert_eq!(second["retry_count"], json!(2));
    let third = decide(
        &runner,
        provider_context(
            0,
            3,
            2,
            4,
            provider_error(503, "server_error", "unavailable", "busy"),
        ),
    );
    assert_eq!(third["delay_ms"], json!(400), "third retry doubles again");
    assert_eq!(third["retry_count"], json!(3));
    let capped = decide(
        &runner,
        provider_context(
            0,
            3,
            3,
            4,
            provider_error(503, "server_error", "unavailable", "busy"),
        ),
    );
    assert_eq!(
        capped["delay_ms"],
        json!(400),
        "backoff is capped at max_retry_delay_ms"
    );
    assert_eq!(capped["retry_count"], json!(4));
}

#[test]
fn loop_nonretryable_error_fails_run() {
    let runner = loop_runner();
    let decision = decide(
        &runner,
        provider_context(
            0,
            3,
            0,
            2,
            provider_error(400, "invalid_request_error", "bad_request", "no"),
        ),
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
        provider_context(
            0,
            3,
            2,
            2,
            provider_error(503, "server_error", "unavailable", "busy"),
        ),
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
        decision["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()),
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

    let step = decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_ok("hello", json!([]))),
    );
    assert_eq!(step["kind"], json!("next.turn"));
    assert_eq!(step["turn"], json!(1));

    let start = decide(&runner, start_context(1, 3, loop_config(false, false)));
    assert_eq!(start["kind"], json!("blocked"));
    assert_eq!(
        start["events"][0]["turn"],
        json!(1),
        "turn must increment across steps"
    );

    let step = decide(
        &runner,
        provider_context(1, 3, 0, 2, provider_ok("again", json!([]))),
    );
    assert_eq!(step["kind"], json!("next.turn"));
    assert_eq!(step["turn"], json!(2));

    let start = decide(&runner, start_context(2, 3, loop_config(false, false)));
    assert_eq!(start["events"][0]["turn"], json!(2));

    let step = decide(
        &runner,
        provider_context(2, 3, 0, 2, provider_ok("done", json!([]))),
    );
    assert_eq!(step["kind"], json!("run.completed"));
    assert_eq!(step["turn"], json!(3));
}

#[test]
fn loop_decisions_never_invent_parallel_or_subagent_actions() {
    let runner = loop_runner();
    let mut decisions = Vec::new();
    decisions.push(decide(
        &runner,
        start_context(0, 3, loop_config(false, false)),
    ));
    decisions.push(decide(
        &runner,
        provider_context(0, 3, 0, 2, provider_ok("hello", json!([]))),
    ));
    decisions.push(decide(
        &runner,
        provider_context(
            0,
            3,
            0,
            2,
            provider_ok("t", json!([{"id": "c", "name": "n", "arguments": {}}])),
        ),
    ));
    decisions.push(decide(
        &runner,
        provider_context(
            0,
            3,
            0,
            2,
            provider_error(429, "rate_limit_error", "rl", "slow"),
        ),
    ));
    decisions.push(decide(
        &runner,
        provider_context(
            0,
            3,
            0,
            2,
            provider_error(400, "invalid_request_error", "br", "no"),
        ),
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
        provider_context(
            0,
            3,
            0,
            2,
            provider_error(400, "invalid_request_error", "br", "no"),
        ),
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

// ---------------------------------------------------------------------------
// Compaction policy context builders (rss/agent/compact.rss)
// ---------------------------------------------------------------------------

fn compact_config(max_context_messages: i64, retained_tail: i64) -> JsonValue {
    json!({
        "max_context_messages": max_context_messages,
        "retained_tail": retained_tail,
        "now_ms": 1000,
        "model": "test-model",
        "token_estimate": 100
    })
}

fn compact_context(
    messages: JsonValue,
    max_context_messages: i64,
    retained_tail: i64,
) -> JsonValue {
    json!({
        "session_id": "session-1",
        "run_id": "run-1",
        "compaction_id": "compaction-1",
        "generation": 1,
        "messages": messages,
        "config": compact_config(max_context_messages, retained_tail)
    })
}

fn msg_user(ordinal: i64, text: &str) -> JsonValue {
    json!({"ordinal": ordinal, "role": "user", "tool_call_id": "", "content": [{"type": "text", "text": text}]})
}

fn msg_assistant(ordinal: i64, text: &str) -> JsonValue {
    json!({"ordinal": ordinal, "role": "assistant", "tool_call_id": "", "content": [{"type": "text", "text": text}]})
}

fn msg_tool_call(ordinal: i64, call_id: &str) -> JsonValue {
    json!({"ordinal": ordinal, "role": "assistant", "tool_call_id": "", "content": [{"type": "tool_call", "tool_call_id": call_id, "name": "read_file", "arguments_json": "{}"}]})
}

fn msg_tool_result(ordinal: i64, call_id: &str) -> JsonValue {
    json!({"ordinal": ordinal, "role": "tool", "tool_call_id": call_id, "content": [{"type": "tool_result", "tool_call_id": call_id, "content": "ok", "is_error": false}]})
}

// ---------------------------------------------------------------------------
// Compaction policy suite (rss/agent/compact.rss) — pure decisions
// ---------------------------------------------------------------------------

#[test]
fn compact_plan_selects_prefix_and_keeps_tail() {
    let runner = compact_runner();
    let plan = decide(
        &runner,
        compact_context(
            json!([
                msg_user(1, "hello"),
                msg_tool_call(2, "call-1"),
                msg_tool_result(3, "call-1"),
                msg_assistant(4, "done"),
                msg_user(5, "next")
            ]),
            4,
            2,
        ),
    );
    assert_eq!(plan["kind"], json!("compact.plan"));
    // 5 messages, window 4, tail 2: the compacted prefix is ordinals 1..3;
    // the retained tail is every message after ordinal 3 (the storage
    // contract records retained_tail_ordinal == source_end_ordinal).
    assert_eq!(
        plan["generation"],
        json!(2),
        "plan generation is session generation + 1"
    );
    assert_eq!(plan["source_start_ordinal"], json!(1));
    assert_eq!(plan["source_end_ordinal"], json!(3));
    assert_eq!(plan["retained_tail_ordinal"], json!(3));
    assert_eq!(
        plan["commands"][1]["payload"]["end_ordinal"],
        json!(3),
        "message.compact marks the compacted prefix only"
    );
    assert_eq!(
        plan["commands"][2]["payload"]["end_ordinal"],
        json!(3),
        "compaction.commit marks the compacted prefix only"
    );
    assert!(
        plan["summary_json"]
            .as_str()
            .is_some_and(|summary| summary.contains("source_end_ordinal")),
        "plan must carry a JSON summary of the compacted range"
    );
}

#[test]
fn compact_plan_preserves_tool_call_result_pair() {
    let runner = compact_runner();
    // The tool result for call-1 lands at ordinal 4, inside the naive tail;
    // the boundary must be pushed past it so the pair is never split.
    let plan = decide(
        &runner,
        compact_context(
            json!([
                msg_user(1, "hello"),
                msg_tool_call(2, "call-1"),
                msg_user(3, "more"),
                msg_tool_result(4, "call-1"),
                msg_user(5, "next")
            ]),
            4,
            2,
        ),
    );
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_end_ordinal"], json!(4));
    assert_eq!(
        plan["commands"][2]["payload"]["end_ordinal"],
        json!(4),
        "boundary must include the tool result"
    );
    assert_eq!(plan["retained_tail_ordinal"], json!(4));
}

#[test]
fn compact_plan_cascades_across_nested_tool_pairs() {
    let runner = compact_runner();
    // call-2's result at ordinal 6 becomes part of the prefix only after the
    // boundary is pushed past call-1's result; the fixpoint must cascade.
    let plan = decide(
        &runner,
        compact_context(
            json!([
                msg_user(1, "hello"),
                msg_tool_call(2, "call-1"),
                msg_user(3, "more"),
                msg_tool_result(4, "call-1"),
                msg_tool_call(5, "call-2"),
                msg_tool_result(6, "call-2"),
                msg_user(7, "next")
            ]),
            4,
            2,
        ),
    );
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_end_ordinal"], json!(6));
    assert_eq!(
        plan["commands"][2]["payload"]["end_ordinal"],
        json!(6),
        "boundary must cascade across nested pairs"
    );
    assert_eq!(plan["retained_tail_ordinal"], json!(6));
}

#[test]
fn compact_plan_skips_history_within_window() {
    let runner = compact_runner();
    let decision = decide(
        &runner,
        compact_context(
            json!([msg_user(1, "a"), msg_assistant(2, "b"), msg_user(3, "c")]),
            5,
            2,
        ),
    );
    assert_eq!(decision["kind"], json!("compact.skip"));
    assert_eq!(decision["reason"], json!("history_within_window"));
    assert_eq!(decision["messages"], json!(3));
}

#[test]
fn compact_plan_skips_when_tail_covers_history() {
    let runner = compact_runner();
    let decision = decide(
        &runner,
        compact_context(
            json!([msg_user(1, "a"), msg_assistant(2, "b"), msg_user(3, "c")]),
            2,
            3,
        ),
    );
    assert_eq!(decision["kind"], json!("compact.skip"));
    assert_eq!(decision["reason"], json!("history_within_retained_tail"));
}

#[test]
fn compact_plan_commands_match_typed_storage_contract() {
    let runner = compact_runner();
    let plan = decide(
        &runner,
        compact_context(
            json!([
                msg_user(1, "hello"),
                msg_tool_call(2, "call-1"),
                msg_tool_result(3, "call-1"),
                msg_assistant(4, "done"),
                msg_user(5, "next")
            ]),
            4,
            2,
        ),
    );
    let commands = plan["commands"]
        .as_array()
        .expect("compact.plan must carry the typed command sequence");
    assert_eq!(commands.len(), 3, "start -> message.compact -> commit");
    assert_eq!(commands[0]["op"], json!("compaction.start"));
    assert_eq!(commands[1]["op"], json!("message.compact"));
    assert_eq!(commands[2]["op"], json!("compaction.commit"));

    let start_payload = commands[0]["payload"]
        .as_object()
        .expect("compaction.start payload");
    assert_eq!(start_payload["id"], json!("compaction-1"));
    assert_eq!(start_payload["session_id"], json!("session-1"));
    assert_eq!(start_payload["run_id"], json!("run-1"));
    assert_eq!(start_payload["generation"], json!(2));
    assert_eq!(start_payload["source_start_ordinal"], json!(1));
    assert_eq!(start_payload["source_end_ordinal"], json!(3));
    assert_eq!(start_payload["retained_tail_ordinal"], json!(3));
    assert_eq!(start_payload["model"], json!("test-model"));
    assert_eq!(start_payload["token_estimate"], json!(100));
    assert_eq!(start_payload["now_ms"], json!(1000));

    let compact_payload = commands[1]["payload"]
        .as_object()
        .expect("message.compact payload");
    assert_eq!(compact_payload["session_id"], json!("session-1"));
    assert_eq!(compact_payload["start_ordinal"], json!(1));
    assert_eq!(compact_payload["end_ordinal"], json!(3));

    let commit_payload = commands[2]["payload"]
        .as_object()
        .expect("compaction.commit payload");
    assert_eq!(commit_payload["id"], json!("compaction-1"));
    assert_eq!(commit_payload["session_id"], json!("session-1"));
    assert_eq!(commit_payload["start_ordinal"], json!(1));
    assert_eq!(commit_payload["end_ordinal"], json!(3));
    assert_eq!(commit_payload["generation"], json!(2));
    assert_eq!(commit_payload["completed_at_ms"], json!(1000));
}

#[test]
fn compact_fail_command_builds_typed_payload() {
    let runner = compact_runner();
    let fail = decide(
        &runner,
        json!({
            "command": "fail",
            "compaction_id": "compaction-1",
            "error_message": "commit guard rejected the compaction",
            "completed_at_ms": 1000
        }),
    );
    assert_eq!(fail["op"], json!("compaction.fail"));
    let payload = fail["payload"]
        .as_object()
        .expect("compaction.fail payload");
    assert_eq!(payload["id"], json!("compaction-1"));
    assert_eq!(
        payload["error_message"],
        json!("commit guard rejected the compaction")
    );
    assert_eq!(payload["completed_at_ms"], json!(1000));
}

#[test]
fn compact_fixture_context_deserializes() {
    let context = read_fixture("compaction_context.json");
    assert_eq!(context["session_id"], json!("session-1"));
    assert_eq!(context["generation"], json!(1));
    assert_eq!(
        context["messages"]
            .as_array()
            .expect("fixture messages")
            .len(),
        5
    );
    assert_eq!(context["config"]["max_context_messages"], json!(4));
    assert_eq!(context["config"]["retained_tail"], json!(2));
    // The fixture is a valid plan input.
    let runner = compact_runner();
    let plan = decide(&runner, context);
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_end_ordinal"], json!(3));
    assert_eq!(plan["retained_tail_ordinal"], json!(3));
}

// ---------------------------------------------------------------------------
// Compaction execution through the A2 typed storage service
// ---------------------------------------------------------------------------

/// Base directory for this suite's temporary storage state. Honors
/// `RUSTSCRIPT_AGENT_TEST_TMP` (CI sets it to a runner-local directory and
/// this suite owns the unique `agent-tests` subdir there); without it,
/// development state stays under /mnt/TEMP/rustscript (workspace rule).
fn agent_test_root() -> PathBuf {
    std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/TEMP/rustscript"))
        .join("agent-tests")
}

fn temporary_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    temporary_root_in(&agent_test_root(), label, nonce)
}

/// The path builder itself: the base directory is explicit so the unit test
/// below pins the layout without touching the process-global env var
/// (parallel tests must never set it). The pid + nanosecond nonce keeps
/// concurrent tests in this process from colliding.
fn temporary_root_in(root: &std::path::Path, label: &str, nonce: u128) -> PathBuf {
    let path = root.join(format!("{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("temporary storage root should be created");
    path
}

#[test]
fn agent_test_artifacts_land_under_an_explicit_root() {
    let base = std::env::temp_dir().join(format!("agent-root-{}", std::process::id()));
    let root = temporary_root_in(&base, "layout", 1);
    assert!(
        root.starts_with(&base),
        "the storage root must live under the explicit root, got {root:?}"
    );
    assert!(
        root.file_name()
            .expect("root name")
            .to_string_lossy()
            .starts_with("layout-"),
        "the label must prefix the unique directory name"
    );
    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
    fs::remove_dir_all(&base).expect("temporary root should be removed");
}

fn storage_command(
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
) -> Value {
    Value::map(vec![
        (Value::string("op"), Value::string(op)),
        (Value::string("request_id"), Value::string(request_id)),
        (Value::string("db_path"), Value::string(db_name)),
        (Value::string("db_mode"), Value::string("read_write_create")),
        (Value::string("busy_timeout_ms"), Value::Int(1_000)),
        (Value::string("max_rows"), Value::Int(128)),
        (Value::string("max_bytes"), Value::Int(65_536)),
        (Value::string("max_events"), Value::Int(128)),
        (Value::string("max_messages"), Value::Int(128)),
        (Value::string("now_ms"), Value::Int(now_ms)),
        (
            Value::string("payload_json"),
            Value::string(payload.to_string()),
        ),
    ])
}

fn run_storage_result(
    runner: &AgentRunner,
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
) -> Result<JsonValue, rustscript_agent::RunError> {
    let result =
        runner.run_with_context(storage_command(db_name, request_id, op, payload, now_ms))?;
    let Value::Map(result) = result else {
        panic!("storage entrypoint should return a result map");
    };
    Ok(vm_value_to_json(&Value::Map(result)))
}

fn run_storage(
    runner: &AgentRunner,
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
) -> JsonValue {
    run_storage_result(runner, db_name, request_id, op, payload, now_ms)
        .unwrap_or_else(|error| panic!("storage op {op} failed: {error:?}"))
}

fn result_data(result: &JsonValue) -> JsonValue {
    result.get("data").cloned().unwrap_or(JsonValue::Null)
}

fn query_rows(result: &JsonValue) -> Vec<JsonMap<String, JsonValue>> {
    let data = result_data(result);
    let columns = data
        .get("columns")
        .and_then(JsonValue::as_array)
        .expect("SQLite query data should contain columns");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .expect("SQLite query data should contain rows")
        .iter()
        .map(|row| {
            columns
                .iter()
                .zip(row.as_array().expect("SQLite row should be an array"))
                .map(|(column, value)| {
                    (
                        column
                            .as_str()
                            .expect("SQLite column names should be strings")
                            .to_string(),
                        value.clone(),
                    )
                })
                .collect()
        })
        .collect()
}

fn first_query_row(result: &JsonValue) -> JsonMap<String, JsonValue> {
    query_rows(result)
        .into_iter()
        .next()
        .expect("query should yield one row")
}

fn session_payload(session_id: &str, now_ms: i64) -> JsonValue {
    json!({
        "id": session_id,
        "profile": "default",
        "platform": "test",
        "account_id": "account-1",
        "chat_id": "chat-1",
        "thread_id": "",
        "user_id": "user-1",
        "generation": 1,
        "system_prompt": "",
        "model": "test-model",
        "provider": "test-provider",
        "toolset_hash": "test-tools",
        "metadata_json": "{}",
        "title": "",
        "end_reason": "",
        "now_ms": now_ms,
    })
}

fn run_payload(run_id: &str, session_id: &str, now_ms: i64) -> JsonValue {
    json!({
        "id": run_id,
        "session_id": session_id,
        "parent_run_id": "",
        "input_json": "{\"message\":\"hello\"}",
        "provider": "test-provider",
        "model": "test-model",
        "script_hash": "test-script",
        "idempotency_scope": "api:chat",
        "idempotency_key": run_id,
        "now_ms": now_ms,
    })
}

fn transition_payload(run_id: &str, from_status: &str, to_status: &str, now_ms: i64) -> JsonValue {
    json!({
        "run_id": run_id,
        "from_status": from_status,
        "to_status": to_status,
        "error_code": "",
        "error_message": "",
        "recovery_reason": "",
        "now_ms": now_ms,
    })
}

fn append_message(
    storage: &AgentRunner,
    db_name: &str,
    message_id: &str,
    role: &str,
    tool_call_id: &str,
    content_json: &str,
    now_ms: i64,
) {
    let appended = run_storage(
        storage,
        db_name,
        &format!("append-{message_id}"),
        "message.append",
        json!({
            "id": message_id,
            "session_id": "session-1",
            "role": role,
            "content_json": content_json,
            "name": "",
            "tool_call_id": tool_call_id,
            "parent_message_id": "",
            "token_estimate": 1,
            "metadata_json": "{}",
            "run_id": "",
            "finish_reason": "",
            "now_ms": now_ms,
        }),
        now_ms,
    );
    assert_eq!(
        appended["ok"],
        json!(true),
        "message {message_id} should append"
    );
}

/// Seeds a session, a run, the compacting status, and the five-message
/// history used by the durable compaction tests.
fn seed_compaction_history(storage: &AgentRunner, db_name: &str) {
    run_storage(storage, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        storage,
        db_name,
        "session-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );
    run_storage(
        storage,
        db_name,
        "run-1",
        "run.create",
        run_payload("run-1", "session-1", 3),
        3,
    );
    let running = run_storage(
        storage,
        db_name,
        "run-running",
        "run.transition",
        transition_payload("run-1", "queued", "running", 4),
        4,
    );
    assert_eq!(
        running["ok"],
        json!(true),
        "queued -> running must be an allowed transition"
    );
    let compacting = run_storage(
        storage,
        db_name,
        "run-compacting",
        "run.transition",
        transition_payload("run-1", "running", "compacting", 5),
        5,
    );
    assert_eq!(
        compacting["ok"],
        json!(true),
        "running -> compacting must be an allowed transition"
    );
    append_message(
        storage,
        db_name,
        "m-1",
        "user",
        "",
        r#"[{"type":"text","text":"hello"}]"#,
        6,
    );
    append_message(
        storage,
        db_name,
        "m-2",
        "assistant",
        "",
        r#"[{"type":"tool_call","tool_call_id":"call-1","name":"read_file","arguments_json":"{}"}]"#,
        7,
    );
    append_message(
        storage,
        db_name,
        "m-3",
        "tool",
        "call-1",
        r#"[{"type":"tool_result","tool_call_id":"call-1","content":"ok","is_error":false}]"#,
        8,
    );
    append_message(
        storage,
        db_name,
        "m-4",
        "assistant",
        "",
        r#"[{"type":"text","text":"done"}]"#,
        9,
    );
    append_message(
        storage,
        db_name,
        "m-5",
        "user",
        "",
        r#"[{"type":"text","text":"next"}]"#,
        10,
    );
}

/// Rebuilds the structured policy context from the durable message history
/// (message.list), exactly as the future script-owned runner would.
fn durable_history_context(storage: &AgentRunner, db_name: &str) -> JsonValue {
    let listed = run_storage(
        storage,
        db_name,
        "history",
        "message.list",
        json!({"session_id": "session-1", "after_ordinal": 0}),
        1000,
    );
    let mut messages = Vec::new();
    for row in query_rows(&listed) {
        let ordinal = row["ordinal"].as_i64().unwrap_or(0);
        let role = row["role"].as_str().unwrap_or("").to_string();
        let tool_call_id = row["tool_call_id"].as_str().unwrap_or("").to_string();
        let content_json = row["content_json"].as_str().unwrap_or("{}").to_string();
        let content: JsonValue = serde_json::from_str(&content_json).unwrap_or(JsonValue::Null);
        messages.push(json!({"ordinal": ordinal, "role": role, "tool_call_id": tool_call_id, "content": content}));
    }
    json!({
        "session_id": "session-1",
        "run_id": "run-1",
        "compaction_id": "compaction-1",
        "generation": 1,
        "messages": messages,
        "config": compact_config(4, 2)
    })
}

/// Executes the plan's typed command sequence against the A2 storage service.
///
/// `compaction.start` is successful only when a pending row is actually
/// created (a guarded insert that matches no run/session returns ok with an
/// EMPTY result), and `compaction.commit` is successful only when its first
/// statement matched the pending row (`rows_affected == 1`). `message.compact`
/// is expected to be a guarded no-op before the commit (it only marks rows
/// once the compaction is committed) so only a hard failure rejects it.
fn execute_plan(storage: &AgentRunner, db_name: &str, plan: &JsonValue) -> Result<(), String> {
    let commands = plan["commands"]
        .as_array()
        .expect("compact.plan should carry commands");
    for command in commands {
        let op = command["op"].as_str().expect("command should carry an op");
        let payload = command["payload"].clone();
        let result = run_storage_result(storage, db_name, &format!("exec-{op}"), op, payload, 1000)
            .map_err(|error| format!("{op} invocation failed: {error:?}"))?;
        if result["ok"] != json!(true) {
            return Err(format!("{op} failed with code {}", result["code"]));
        }
        match op {
            "compaction.start" => {
                let rows = result["data"]["rows"]
                    .as_array()
                    .expect("compaction.start should carry rows");
                if rows.is_empty() {
                    return Err("compaction.start created no pending compaction row".to_string());
                }
            }
            "compaction.commit" => {
                let affected = result["data"]["results"][0]["rows_affected"]
                    .as_i64()
                    .unwrap_or(0);
                if affected == 0 {
                    return Err("compaction.commit matched no pending compaction".to_string());
                }
            }
            "message.compact" => {}
            other => return Err(format!("unexpected plan command {other}")),
        }
    }
    Ok(())
}

#[test]
fn compaction_flow_commits_durably_and_retains_tail() {
    let root = temporary_root("compaction-flow");
    let storage = storage_runner(&root);
    let db_name = "flow.db";
    seed_compaction_history(&storage, db_name);

    // The policy plans from the DURABLE history and produces the typed
    // command sequence; the harness executes it through the storage service.
    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_start_ordinal"], json!(1));
    assert_eq!(plan["source_end_ordinal"], json!(3));
    assert_eq!(plan["retained_tail_ordinal"], json!(3));
    execute_plan(&storage, db_name, &plan).expect("compaction plan should execute");

    // The compaction row is committed.
    let compaction = run_storage(
        &storage,
        db_name,
        "compaction-get",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        1000,
    );
    let row = first_query_row(&compaction);
    assert_eq!(row["state"], json!("committed"));
    assert_eq!(row["generation"], json!(2));
    assert_eq!(row["source_start_ordinal"], json!(1));
    assert_eq!(row["source_end_ordinal"], json!(3));
    assert_eq!(row["retained_tail_ordinal"], json!(3));

    // The prefix is marked compacted; the retained tail is untouched.
    let listed = run_storage(
        &storage,
        db_name,
        "messages",
        "message.list",
        json!({"session_id": "session-1", "after_ordinal": 0}),
        1000,
    );
    let compacted: Vec<i64> = query_rows(&listed)
        .iter()
        .map(|row| row["compacted"].as_i64().unwrap_or(0))
        .collect();
    assert_eq!(
        compacted,
        vec![1, 1, 1, 0, 0],
        "prefix compacted, tail retained"
    );

    // The session generation advanced exactly once.
    let session = run_storage(
        &storage,
        db_name,
        "session-get",
        "session.get",
        json!({"session_id": "session-1"}),
        1000,
    );
    let session_row = first_query_row(&session);
    assert_eq!(session_row["generation"], json!(2));

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

#[test]
fn compaction_failure_marks_failed_and_preserves_history() {
    let root = temporary_root("compaction-failure");
    let storage = storage_runner(&root);
    let db_name = "failure.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    assert_eq!(plan["kind"], json!("compact.plan"));

    // Step 1: compaction.start creates the pending row.
    let start = run_storage(
        &storage,
        db_name,
        "step-start",
        "compaction.start",
        plan["commands"][0]["payload"].clone(),
        1000,
    );
    assert_eq!(start["ok"], json!(true));
    assert!(
        !start["data"]["rows"]
            .as_array()
            .expect("compaction.start rows")
            .is_empty(),
        "pending compaction row must exist"
    );
    // Step 2: message.compact is the guarded no-op before the commit.
    let sweep = run_storage(
        &storage,
        db_name,
        "step-sweep",
        "message.compact",
        plan["commands"][1]["payload"].clone(),
        1000,
    );
    assert_eq!(sweep["ok"], json!(true));

    // The run leaves the compacting status before the commit, so the commit
    // guard matches no pending row: a real failure, detected by the harness
    // through the typed result (rows_affected == 0).
    run_storage(
        &storage,
        db_name,
        "run-leaves-compacting",
        "run.transition",
        transition_payload("run-1", "compacting", "running", 1000),
        1000,
    );
    let commit = run_storage(
        &storage,
        db_name,
        "step-commit",
        "compaction.commit",
        plan["commands"][2]["payload"].clone(),
        1000,
    );
    assert_eq!(
        commit["ok"],
        json!(true),
        "the storage envelope itself succeeds"
    );
    assert_eq!(
        commit["data"]["results"][0]["rows_affected"],
        json!(0),
        "the commit guard must match nothing once the run left compacting"
    );

    // Any failure in the sequence routes to compaction.fail.
    let fail = decide(
        &compact,
        json!({
            "command": "fail",
            "compaction_id": "compaction-1",
            "error_message": "commit guard rejected the compaction",
            "completed_at_ms": 1000
        }),
    );
    assert_eq!(fail["op"], json!("compaction.fail"));
    let failed = run_storage(
        &storage,
        db_name,
        "step-fail",
        "compaction.fail",
        fail["payload"].clone(),
        1000,
    );
    assert_eq!(failed["ok"], json!(true));

    // The compaction is durably failed and nothing was half-committed.
    let compaction = run_storage(
        &storage,
        db_name,
        "compaction-get",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        1000,
    );
    let row = first_query_row(&compaction);
    assert_eq!(row["state"], json!("failed"));
    assert_eq!(
        row["error_message"],
        json!("commit guard rejected the compaction"),
        "the typed failure reason must be recorded"
    );
    let listed = run_storage(
        &storage,
        db_name,
        "messages",
        "message.list",
        json!({"session_id": "session-1", "after_ordinal": 0}),
        1000,
    );
    let compacted: Vec<i64> = query_rows(&listed)
        .iter()
        .map(|row| row["compacted"].as_i64().unwrap_or(0))
        .collect();
    assert_eq!(
        compacted,
        vec![0, 0, 0, 0, 0],
        "a failed compaction must leave the original history fully intact"
    );
    let session = run_storage(
        &storage,
        db_name,
        "session-get",
        "session.get",
        json!({"session_id": "session-1"}),
        1000,
    );
    let session_row = first_query_row(&session);
    assert_eq!(
        session_row["generation"],
        json!(1),
        "generation must not advance"
    );

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

// ---------------------------------------------------------------------------
// Post-review edge suites: backoff boundaries, tool-cycle turn budget
// ---------------------------------------------------------------------------

#[test]
fn loop_backoff_base_above_cap_clamps_to_cap() {
    let runner = loop_runner();
    let config = json!({
        "base_retry_delay_ms": 1000,
        "max_retry_delay_ms": 400,
        "parallel": false,
        "task": false
    });
    let first = decide(
        &runner,
        loop_context(
            "provider_result",
            0,
            3,
            0,
            2,
            provider_error(503, "server_error", "unavailable", "busy"),
            config.clone(),
        ),
    );
    assert_eq!(first["kind"], json!("retry"));
    assert_eq!(
        first["delay_ms"],
        json!(400),
        "a base above the cap must clamp to the cap on entry"
    );
    let second = decide(
        &runner,
        loop_context(
            "provider_result",
            0,
            3,
            1,
            2,
            provider_error(503, "server_error", "unavailable", "busy"),
            config,
        ),
    );
    assert_eq!(second["delay_ms"], json!(400), "doubling stays capped");
}

#[test]
fn loop_backoff_saturates_without_overflow_for_huge_inputs() {
    let runner = loop_runner();
    // A base just above half of i64::MAX must saturate at the cap on the
    // first doubling instead of overflowing the signed range.
    let near_max = i64::MAX / 2 + 1;
    let decision = decide(
        &runner,
        loop_context(
            "provider_result",
            0,
            3,
            1,
            2,
            provider_error(429, "rate_limit_error", "rl", "slow"),
            json!({
                "base_retry_delay_ms": near_max,
                "max_retry_delay_ms": i64::MAX,
                "parallel": false,
                "task": false
            }),
        ),
    );
    assert_eq!(decision["kind"], json!("retry"));
    assert_eq!(
        decision["delay_ms"],
        json!(i64::MAX),
        "doubling must saturate at the cap, never overflow"
    );
    // A very large retry count must terminate with the capped delay.
    let many = decide(
        &runner,
        loop_context(
            "provider_result",
            0,
            3,
            100_000,
            100_001,
            provider_error(503, "server_error", "unavailable", "busy"),
            json!({
                "base_retry_delay_ms": 100,
                "max_retry_delay_ms": 400,
                "parallel": false,
                "task": false
            }),
        ),
    );
    assert_eq!(many["kind"], json!("retry"));
    assert_eq!(many["delay_ms"], json!(400), "delay saturates at the cap");
    assert_eq!(many["retry_count"], json!(100_001));
}

#[test]
fn loop_backoff_zero_and_negative_inputs_are_clamped() {
    let runner = loop_runner();
    // Zero base: an immediate retry (delay 0), defined and bounded.
    let zero = decide(
        &runner,
        loop_context(
            "provider_result",
            0,
            3,
            0,
            2,
            provider_error(429, "rate_limit_error", "rl", "slow"),
            json!({
                "base_retry_delay_ms": 0,
                "max_retry_delay_ms": 400,
                "parallel": false,
                "task": false
            }),
        ),
    );
    assert_eq!(zero["kind"], json!("retry"));
    assert_eq!(zero["delay_ms"], json!(0));
    // Negative base and negative cap clamp to zero.
    let negative = decide(
        &runner,
        loop_context(
            "provider_result",
            0,
            3,
            0,
            2,
            provider_error(429, "rate_limit_error", "rl", "slow"),
            json!({
                "base_retry_delay_ms": -500,
                "max_retry_delay_ms": -1,
                "parallel": false,
                "task": false
            }),
        ),
    );
    assert_eq!(negative["delay_ms"], json!(0));
    // A zero cap clamps any base to zero.
    let zero_cap = decide(
        &runner,
        loop_context(
            "provider_result",
            0,
            3,
            0,
            2,
            provider_error(429, "rate_limit_error", "rl", "slow"),
            json!({
                "base_retry_delay_ms": 100,
                "max_retry_delay_ms": 0,
                "parallel": false,
                "task": false
            }),
        ),
    );
    assert_eq!(zero_cap["delay_ms"], json!(0));
}

#[test]
fn loop_tool_cycles_consume_turn_budget_and_terminate() {
    let runner = loop_runner();
    // max_turns = 2: every provider result asks for tools; each tool-call
    // cycle consumes the turn budget, so the run must terminate once the
    // budget is exhausted instead of looping forever inside turn 0.
    let first = decide(
        &runner,
        provider_context(
            0,
            2,
            0,
            2,
            provider_ok("t", json!([{"id": "c1", "name": "n", "arguments": {}}])),
        ),
    );
    assert_eq!(first["kind"], json!("blocked"));
    assert_eq!(first["capability"], json!("tool.dispatch"));
    assert_eq!(
        first["turn"],
        json!(1),
        "the tool cycle consumes the turn budget"
    );
    assert_eq!(
        first["events"][0]["turn"],
        json!(0),
        "the completed model call belongs to the turn it started in"
    );
    assert_eq!(first["events"][0]["tool_calls"], json!(1));

    let second = decide(
        &runner,
        provider_context(
            1,
            2,
            0,
            2,
            provider_ok("t", json!([{"id": "c2", "name": "n", "arguments": {}}])),
        ),
    );
    assert_eq!(second["kind"], json!("blocked"));
    assert_eq!(second["turn"], json!(2));

    // The budget is exhausted: the next start phase terminates the run.
    let completed = decide(&runner, start_context(2, 2, loop_config(false, false)));
    assert_eq!(completed["kind"], json!("run.completed"));
    assert_eq!(completed["turn"], json!(2));
}

#[test]
fn loop_multi_call_response_pins_tool_call_count() {
    let runner = loop_runner();
    // tool_calls on model.completed is the exact number of tool_call
    // entries in the response array (pinned semantics: 0 for text-only,
    // N for N calls in one response).
    let decision = decide(
        &runner,
        provider_context(
            0,
            3,
            0,
            2,
            provider_ok(
                "two tools",
                json!([
                    {"id": "call-1", "name": "read_file", "arguments": {}},
                    {"id": "call-2", "name": "search_files", "arguments": {}}
                ]),
            ),
        ),
    );
    assert_eq!(decision["kind"], json!("blocked"));
    assert_eq!(decision["capability"], json!("tool.dispatch"));
    assert_eq!(decision["events"][0]["tool_calls"], json!(2));
    assert_eq!(
        decision["turn"],
        json!(1),
        "the tool cycle consumes the turn budget"
    );
}

// ---------------------------------------------------------------------------
// Post-review edge suites: compaction prefix boundaries
// ---------------------------------------------------------------------------

#[test]
fn compact_plan_multi_call_message_pulls_all_results_into_prefix() {
    let runner = compact_runner();
    // One assistant message issues TWO tool calls; call-1's result sits
    // inside the naive prefix while call-2's result straddles the boundary.
    // The fixpoint must pull BOTH results in (multi-call pairing).
    let plan = decide(
        &runner,
        compact_context(
            json!([
                msg_user(1, "hello"),
                json!({"ordinal": 2, "role": "assistant", "tool_call_id": "", "content": [
                    {"type": "tool_call", "tool_call_id": "call-1", "name": "read_file", "arguments_json": "{}"},
                    {"type": "tool_call", "tool_call_id": "call-2", "name": "search_files", "arguments_json": "{}"}
                ]}),
                msg_user(3, "more"),
                msg_tool_result(4, "call-1"),
                msg_user(5, "next"),
                msg_tool_result(6, "call-2"),
                msg_user(7, "done")
            ]),
            5,
            2,
        ),
    );
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_start_ordinal"], json!(1));
    assert_eq!(
        plan["source_end_ordinal"],
        json!(6),
        "both results of the multi-call message must land in the prefix"
    );
    assert_eq!(plan["retained_tail_ordinal"], json!(6));
}

#[test]
fn compact_plan_missing_tool_result_compacts_call_as_is() {
    let runner = compact_runner();
    // An assistant tool-call message whose result never arrived has nothing
    // to preserve: the boundary stays at the naive position and the call is
    // compacted as-is (pairs are never SPLIT; a call with no result in the
    // history is compacted whole).
    let plan = decide(
        &runner,
        compact_context(
            json!([
                msg_user(1, "hello"),
                msg_tool_call(2, "call-1"),
                msg_user(3, "more"),
                msg_user(4, "next")
            ]),
            2,
            1,
        ),
    );
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_start_ordinal"], json!(1));
    assert_eq!(plan["source_end_ordinal"], json!(3));
    assert_eq!(plan["retained_tail_ordinal"], json!(3));
}

#[test]
fn compact_plan_full_compaction_documents_empty_tail_rule() {
    let runner = compact_runner();
    // Pair preservation can force the boundary onto the last message: the
    // only way the fixpoint reaches the end is a tool result whose call
    // sits in the prefix, and keeping that single result as the sole tail
    // would split the pair. This is the documented full-compaction rule:
    // the retained tail is empty ONLY in this forced case (see compact.rss).
    let plan = decide(
        &runner,
        compact_context(
            json!([
                msg_user(1, "hello"),
                msg_user(2, "more"),
                msg_tool_call(3, "call-1"),
                msg_user(4, "next"),
                msg_user(5, "again"),
                msg_tool_result(6, "call-1")
            ]),
            4,
            2,
        ),
    );
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_start_ordinal"], json!(1));
    assert_eq!(
        plan["source_end_ordinal"],
        json!(6),
        "the boundary is forced onto the last message"
    );
    assert_eq!(plan["retained_tail_ordinal"], json!(6));
    // The retained tail is every message AFTER source_end_ordinal: empty.
    let source_end = plan["source_end_ordinal"].as_i64().expect("source end");
    let tail_count = json!([
        msg_user(1, "hello"),
        msg_user(2, "more"),
        msg_tool_call(3, "call-1"),
        msg_user(4, "next"),
        msg_user(5, "again"),
        msg_tool_result(6, "call-1")
    ])
    .as_array()
    .expect("messages")
    .iter()
    .filter(|message| message["ordinal"].as_i64().unwrap_or(0) > source_end)
    .count();
    assert_eq!(
        tail_count, 0,
        "documented full compaction: no retained tail in the forced case"
    );
}

// ---------------------------------------------------------------------------
// Post-review edge suites: compaction.start durable recovery contract
// ---------------------------------------------------------------------------

/// `compaction.start` with the same session+generation and the SAME payload
/// is an idempotent resume: it returns the existing pending row (never a
/// duplicate insert, never a silent empty result), and the caller can
/// proceed straight to `message.compact` + `compaction.commit`.
#[test]
fn compaction_start_is_idempotent_for_same_pending_payload() {
    let root = temporary_root("compaction-idempotent");
    let storage = storage_runner(&root);
    let db_name = "idempotent.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    let start_payload = plan["commands"][0]["payload"].clone();

    let first = run_storage(
        &storage,
        db_name,
        "start-1",
        "compaction.start",
        start_payload.clone(),
        1000,
    );
    assert_eq!(first["ok"], json!(true));
    let first_row = first_query_row(&first);
    assert_eq!(first_row["id"], json!("compaction-1"));
    assert_eq!(first_row["state"], json!("pending"));

    // Crash-and-retry with the same payload resumes the SAME pending row.
    let resumed = run_storage(
        &storage,
        db_name,
        "start-2",
        "compaction.start",
        start_payload.clone(),
        1000,
    );
    assert_eq!(resumed["ok"], json!(true));
    let resumed_row = first_query_row(&resumed);
    assert_eq!(resumed_row["id"], json!("compaction-1"));
    assert_eq!(resumed_row["state"], json!("pending"));
    assert_eq!(
        resumed_row["source_end_ordinal"],
        json!(3),
        "the resumed row must be the original durable record"
    );

    // The resumed plan executes to completion exactly once.
    execute_plan(&storage, db_name, &plan).expect("resumed plan should execute");

    let compaction = run_storage(
        &storage,
        db_name,
        "compaction-get",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        1000,
    );
    let row = first_query_row(&compaction);
    assert_eq!(row["state"], json!("committed"));

    // A second commit matches no pending row: exactly-once generation.
    let again = run_storage(
        &storage,
        db_name,
        "commit-again",
        "compaction.commit",
        plan["commands"][2]["payload"].clone(),
        1000,
    );
    assert_eq!(
        again["data"]["results"][0]["rows_affected"],
        json!(0),
        "a repeated commit must match nothing"
    );
    let session = run_storage(
        &storage,
        db_name,
        "session-get",
        "session.get",
        json!({"session_id": "session-1"}),
        1000,
    );
    let session_row = first_query_row(&session);
    assert_eq!(
        session_row["generation"],
        json!(2),
        "the session generation must advance exactly once"
    );

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

/// `compaction.start` with the same session+generation but a DIFFERENT
/// payload (a different id, or a different range under the same id) is a
/// typed conflict: never a silent `ok` with an empty row set, and never a
/// clobber of the pending record.
#[test]
fn compaction_start_rejects_different_payload_on_pending() {
    let root = temporary_root("compaction-conflict");
    let storage = storage_runner(&root);
    let db_name = "conflict.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    let start_payload = plan["commands"][0]["payload"].clone();
    run_storage(
        &storage,
        db_name,
        "start-1",
        "compaction.start",
        start_payload.clone(),
        1000,
    );

    // Different id, same session+generation: typed conflict.
    let mut other_id = start_payload.clone();
    other_id["id"] = json!("compaction-2");
    let conflicting = run_storage(
        &storage,
        db_name,
        "start-other-id",
        "compaction.start",
        other_id,
        1000,
    );
    assert_eq!(conflicting["ok"], json!(false));
    assert_eq!(conflicting["code"], json!("compaction_pending_conflict"));

    // Same id, different range: typed conflict.
    let mut other_range = start_payload.clone();
    other_range["source_end_ordinal"] = json!(5);
    other_range["retained_tail_ordinal"] = json!(5);
    let conflicting_range = run_storage(
        &storage,
        db_name,
        "start-other-range",
        "compaction.start",
        other_range,
        1000,
    );
    assert_eq!(conflicting_range["ok"], json!(false));
    assert_eq!(
        conflicting_range["code"],
        json!("compaction_pending_conflict")
    );

    // The original pending record is untouched and still commit-able.
    let original = run_storage(
        &storage,
        db_name,
        "compaction-get",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        1000,
    );
    let row = first_query_row(&original);
    assert_eq!(row["state"], json!("pending"));
    assert_eq!(row["source_end_ordinal"], json!(3));
    execute_plan(&storage, db_name, &plan).expect("original plan should still execute");

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

/// `compaction.start` targeting an already-committed session+generation is a
/// typed rejection: the caller must advance its session generation first.
#[test]
fn compaction_start_rejects_committed_generation() {
    let root = temporary_root("compaction-committed");
    let storage = storage_runner(&root);
    let db_name = "committed.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    execute_plan(&storage, db_name, &plan).expect("plan should execute and commit");

    let restart = run_storage(
        &storage,
        db_name,
        "start-after-commit",
        "compaction.start",
        plan["commands"][0]["payload"].clone(),
        1000,
    );
    assert_eq!(restart["ok"], json!(false));
    assert_eq!(restart["code"], json!("compaction_already_committed"));

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

/// Reusing a compaction id for a DIFFERENT session or generation is a typed
/// conflict, never a SQLite constraint error or a silent empty result.
#[test]
fn compaction_start_id_conflict_is_typed() {
    let root = temporary_root("compaction-id-conflict");
    let storage = storage_runner(&root);
    let db_name = "id-conflict.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    let start_payload = plan["commands"][0]["payload"].clone();
    run_storage(
        &storage,
        db_name,
        "start-1",
        "compaction.start",
        start_payload.clone(),
        1000,
    );

    let mut other_generation = start_payload.clone();
    other_generation["generation"] = json!(3);
    let conflicting = run_storage(
        &storage,
        db_name,
        "start-id-reuse",
        "compaction.start",
        other_generation,
        1000,
    );
    assert_eq!(conflicting["ok"], json!(false));
    assert_eq!(conflicting["code"], json!("compaction_id_conflict"));

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

/// Every `compaction.start` guard rejection is a typed error envelope, never
/// an `ok: true` with an empty row set: the caller can never claim a durable
/// record that does not exist.
#[test]
fn compaction_start_guard_rejections_are_typed_not_silent() {
    // Run status guard: the run left `compacting` before the start.
    let root_status = temporary_root("compaction-guard-status");
    let storage_status = storage_runner(&root_status);
    let db_status = "guard-status.db";
    seed_compaction_history(&storage_status, db_status);
    run_storage(
        &storage_status,
        db_status,
        "run-leaves-compacting",
        "run.transition",
        transition_payload("run-1", "compacting", "running", 1000),
        1000,
    );
    let compact = compact_runner();
    let plan_status = decide(
        &compact,
        durable_history_context(&storage_status, db_status),
    );
    let rejected = run_storage(
        &storage_status,
        db_status,
        "start-guard-status",
        "compaction.start",
        plan_status["commands"][0]["payload"].clone(),
        1000,
    );
    assert_eq!(rejected["ok"], json!(false));
    assert_eq!(rejected["code"], json!("compaction_start_rejected"));
    assert_eq!(
        rejected["data"]["rows"],
        JsonValue::Null,
        "a rejected start must not claim any row"
    );
    fs::remove_dir_all(&root_status).expect("temporary storage root should be removed");

    // Generation guard: the plan targets a generation the session is not at.
    let root_generation = temporary_root("compaction-guard-generation");
    let storage_generation = storage_runner(&root_generation);
    let db_generation = "guard-generation.db";
    seed_compaction_history(&storage_generation, db_generation);
    let mut wrong_generation = plan_status["commands"][0]["payload"].clone();
    wrong_generation["generation"] = json!(5);
    let rejected_generation = run_storage(
        &storage_generation,
        db_generation,
        "start-guard-generation",
        "compaction.start",
        wrong_generation,
        1000,
    );
    assert_eq!(rejected_generation["ok"], json!(false));
    assert_eq!(
        rejected_generation["code"],
        json!("compaction_start_rejected")
    );
    fs::remove_dir_all(&root_generation).expect("temporary storage root should be removed");

    // Range guard: the retained-tail marker falls outside the source range.
    let root_range = temporary_root("compaction-guard-range");
    let storage_range = storage_runner(&root_range);
    let db_range = "guard-range.db";
    seed_compaction_history(&storage_range, db_range);
    let mut wrong_range = plan_status["commands"][0]["payload"].clone();
    wrong_range["source_start_ordinal"] = json!(5);
    wrong_range["source_end_ordinal"] = json!(3);
    wrong_range["retained_tail_ordinal"] = json!(1);
    let rejected_range = run_storage(
        &storage_range,
        db_range,
        "start-guard-range",
        "compaction.start",
        wrong_range,
        1000,
    );
    assert_eq!(rejected_range["ok"], json!(false));
    assert_eq!(rejected_range["code"], json!("compaction_start_rejected"));
    fs::remove_dir_all(&root_range).expect("temporary storage root should be removed");

    // Message-endpoint guard: no message exists at the source end ordinal.
    let root_endpoints = temporary_root("compaction-guard-endpoints");
    let storage_endpoints = storage_runner(&root_endpoints);
    let db_endpoints = "guard-endpoints.db";
    seed_compaction_history(&storage_endpoints, db_endpoints);
    let mut wrong_endpoints = plan_status["commands"][0]["payload"].clone();
    wrong_endpoints["source_end_ordinal"] = json!(9);
    wrong_endpoints["retained_tail_ordinal"] = json!(9);
    let rejected_endpoints = run_storage(
        &storage_endpoints,
        db_endpoints,
        "start-guard-endpoints",
        "compaction.start",
        wrong_endpoints,
        1000,
    );
    assert_eq!(rejected_endpoints["ok"], json!(false));
    assert_eq!(
        rejected_endpoints["code"],
        json!("compaction_start_rejected")
    );
    fs::remove_dir_all(&root_endpoints).expect("temporary storage root should be removed");
}

/// P1 crash window: a process that dies between `compaction.start` and
/// `compaction.commit` leaves a `pending` row. Restart recovery fails both
/// the interrupted run and its pending compaction, so the session is never
/// stuck: a fresh compaction can start (the failed row is reset) and commit,
/// and the session generation advances exactly once.
#[test]
fn restart_recovery_fails_pending_compaction_then_new_start_commits() {
    let root = temporary_root("compaction-crash-window");
    let storage = storage_runner(&root);
    let db_name = "crash-window.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    let start_payload = plan["commands"][0]["payload"].clone();
    run_storage(
        &storage,
        db_name,
        "start-before-crash",
        "compaction.start",
        start_payload.clone(),
        1000,
    );

    // Simulate the process interrupt/reopen: the gateway startup recovery
    // fails every interrupted active run and its pending compaction.
    let recovery = run_storage(
        &storage,
        db_name,
        "recovery-after-crash",
        "recovery.recover_active",
        json!({
            "reason": "gateway_restart",
            "details_json": "{}",
            "now_ms": 2000,
            "max_rows": 128,
            "max_bytes": 65_536,
            "max_events": 128,
        }),
        2000,
    );
    assert_eq!(recovery["ok"], json!(true));
    assert_eq!(recovery["recovered"], json!(1));

    let run = run_storage(
        &storage,
        db_name,
        "run-after-recovery",
        "run.get",
        json!({"run_id": "run-1"}),
        2000,
    );
    let run_row = first_query_row(&run);
    assert_eq!(run_row["status"], json!("failed"));
    assert_eq!(run_row["recovery_reason"], json!("gateway_restart"));

    let failed = run_storage(
        &storage,
        db_name,
        "compaction-after-recovery",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        2000,
    );
    let failed_row = first_query_row(&failed);
    assert_eq!(failed_row["state"], json!("failed"));
    assert_eq!(
        failed_row["error_message"],
        json!("run interrupted during gateway restart"),
        "the pending compaction must be durably failed by restart recovery"
    );

    // The session is NOT stuck: the runner starts a fresh compaction run
    // (the recovered run is terminal) and retries the SAME compaction id —
    // the failed row is reset to pending — commits, and the session
    // generation advances exactly once. The single row per
    // (session, generation) keeps its audit identity across
    // failed -> pending -> committed.
    run_storage(
        &storage,
        db_name,
        "run-2",
        "run.create",
        run_payload("run-2", "session-1", 2000),
        2000,
    );
    run_storage(
        &storage,
        db_name,
        "run-2-running",
        "run.transition",
        transition_payload("run-2", "queued", "running", 2000),
        2000,
    );
    run_storage(
        &storage,
        db_name,
        "run-2-compacting",
        "run.transition",
        transition_payload("run-2", "running", "compacting", 2000),
        2000,
    );
    let mut retry_payload = start_payload.clone();
    retry_payload["run_id"] = json!("run-2");
    let restarted = run_storage(
        &storage,
        db_name,
        "start-after-recovery",
        "compaction.start",
        retry_payload,
        2000,
    );
    assert_eq!(restarted["ok"], json!(true));
    let restarted_row = first_query_row(&restarted);
    assert_eq!(restarted_row["id"], json!("compaction-1"));
    assert_eq!(restarted_row["state"], json!("pending"));

    run_storage(
        &storage,
        db_name,
        "sweep-after-recovery",
        "message.compact",
        plan["commands"][1]["payload"].clone(),
        2000,
    );
    let mut commit_payload = plan["commands"][2]["payload"].clone();
    commit_payload["completed_at_ms"] = json!(2000);
    let committed = run_storage(
        &storage,
        db_name,
        "commit-after-recovery",
        "compaction.commit",
        commit_payload,
        2000,
    );
    assert_eq!(
        committed["data"]["results"][0]["rows_affected"],
        json!(1),
        "the retry compaction must commit"
    );

    // The retried row went failed -> pending -> committed with the same id.
    let committed_row = run_storage(
        &storage,
        db_name,
        "compaction-committed",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        2000,
    );
    assert_eq!(first_query_row(&committed_row)["state"], json!("committed"));

    let session = run_storage(
        &storage,
        db_name,
        "session-after-recovery",
        "session.get",
        json!({"session_id": "session-1"}),
        2000,
    );
    let session_row = first_query_row(&session);
    assert_eq!(
        session_row["generation"],
        json!(2),
        "exactly-once generation across the crash window"
    );

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

/// P3: a retry of a FAILED compaction resets the row to pending with the
/// same audit identity AND clears the stale failure timestamp
/// (`completed_at_ms = 0`), so a later commit records only its own time.
#[test]
fn failed_retry_reset_clears_completed_at_ms() {
    let root = temporary_root("compaction-failed-reset");
    let storage = storage_runner(&root);
    let db_name = "failed-reset.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    assert_eq!(plan["kind"], json!("compact.plan"));
    run_storage(
        &storage,
        db_name,
        "start",
        "compaction.start",
        plan["commands"][0]["payload"].clone(),
        1000,
    );
    run_storage(
        &storage,
        db_name,
        "fail",
        "compaction.fail",
        json!({
            "id": "compaction-1",
            "error_message": "boom",
            "completed_at_ms": 1000,
        }),
        1000,
    );
    let failed_row = first_query_row(&run_storage(
        &storage,
        db_name,
        "get-failed",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        1000,
    ));
    assert_eq!(failed_row["state"], json!("failed"));
    assert_eq!(failed_row["completed_at_ms"], json!(1000));

    // Retry with the SAME id: the failed row is reset to pending and the
    // stale failure timestamp must be cleared.
    let restarted = run_storage(
        &storage,
        db_name,
        "retry-start",
        "compaction.start",
        plan["commands"][0]["payload"].clone(),
        1001,
    );
    assert_eq!(restarted["ok"], json!(true));
    let pending_row = first_query_row(&restarted);
    assert_eq!(pending_row["id"], json!("compaction-1"));
    assert_eq!(pending_row["state"], json!("pending"));
    assert_eq!(
        pending_row["completed_at_ms"],
        json!(0),
        "the failed -> pending reset must clear the stale completed_at_ms"
    );

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

/// P3: a retry that would silently REPLACE a failed compaction's audit id
/// is a typed conflict — the failed row keeps its identity, and the caller
/// must resume with the original id.
#[test]
fn failed_retry_with_different_id_is_a_typed_conflict() {
    let root = temporary_root("compaction-failed-id-conflict");
    let storage = storage_runner(&root);
    let db_name = "failed-id-conflict.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    run_storage(
        &storage,
        db_name,
        "start",
        "compaction.start",
        plan["commands"][0]["payload"].clone(),
        1000,
    );
    run_storage(
        &storage,
        db_name,
        "fail",
        "compaction.fail",
        json!({
            "id": "compaction-1",
            "error_message": "boom",
            "completed_at_ms": 1000,
        }),
        1000,
    );

    // A fresh plan id for the same session+generation must not silently
    // replace the failed row's audit id.
    let mut different = plan["commands"][0]["payload"].clone();
    different["id"] = json!("compaction-2");
    let conflicted = run_storage(
        &storage,
        db_name,
        "conflict-start",
        "compaction.start",
        different,
        1001,
    );
    assert_eq!(conflicted["ok"], json!(false));
    assert_eq!(conflicted["code"], json!("compaction_failed_conflict"));

    let row = first_query_row(&run_storage(
        &storage,
        db_name,
        "get-after-conflict",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        1001,
    ));
    assert_eq!(
        row["id"],
        json!("compaction-1"),
        "the failed row's audit identity must survive the rejected retry"
    );
    assert_eq!(row["state"], json!("failed"));

    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

/// P3: restart recovery fails EVERY pending compaction — after a restart
/// any pending row is an interrupted leftover, even when its run is already
/// terminal (the crash window between the run terminal commit and
/// `compaction.fail`).
#[test]
fn recovery_fails_pending_compaction_even_when_run_is_terminal() {
    let root = temporary_root("compaction-recovery-orphan");
    let storage = storage_runner(&root);
    let db_name = "recovery-orphan.db";
    seed_compaction_history(&storage, db_name);

    let compact = compact_runner();
    let plan = decide(&compact, durable_history_context(&storage, db_name));
    run_storage(
        &storage,
        db_name,
        "start",
        "compaction.start",
        plan["commands"][0]["payload"].clone(),
        1000,
    );
    // The run leaves compacting with a terminal transition BEFORE any
    // compaction.fail is committed (the crash window the recovery closes).
    let terminal = run_storage(
        &storage,
        db_name,
        "run-terminal",
        "run.transition",
        transition_payload("run-1", "compacting", "failed", 1001),
        1001,
    );
    assert_eq!(terminal["ok"], json!(true));

    // Restart recovery: NO run is recovered (run-1 is already terminal),
    // yet the pending compaction is still an interrupted leftover and must
    // be durably failed.
    let recovery = run_storage(
        &storage,
        db_name,
        "recovery",
        "recovery.recover_active",
        json!({
            "reason": "gateway_restart",
            "details_json": "{}",
            "now_ms": 2000,
            "max_rows": 128,
            "max_bytes": 65_536,
            "max_events": 128,
        }),
        2000,
    );
    assert_eq!(recovery["ok"], json!(true));
    assert_eq!(recovery["recovered"], json!(0), "no run may be recovered");

    let row = first_query_row(&run_storage(
        &storage,
        db_name,
        "compaction-after-recovery",
        "compaction.get",
        json!({"compaction_id": "compaction-1"}),
        2000,
    ));
    assert_eq!(
        row["state"],
        json!("failed"),
        "every pending compaction must be failed by restart recovery"
    );
    assert_eq!(
        row["error_message"],
        json!("run interrupted during gateway restart"),
        "the typed recovery failure reason must be recorded"
    );
    fs::remove_dir_all(&root).expect("temporary storage root should be removed");
}

#[tokio::test]
async fn agent_loop_receives_an_admission_snapshot_with_real_tool_schemas() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(context: map) -> map { context; }",
    )
    .expect("agent source should compile");
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"prompt": "inspect"}),
            platform: "agent_loop_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admission should succeed");
    let context = service
        .run_context(&admitted.run_id)
        .expect("the loop should receive a captured context");

    assert!(
        context
            .tool_schemas
            .as_array()
            .is_some_and(|schemas| schemas.iter().any(|schema| schema["name"] == "read_file"))
    );
    assert_eq!(
        context.metadata["registry_identity"],
        context.metadata["toolset_hash"]
    );
    assert!(
        context
            .provider_options
            .as_object()
            .is_some_and(|options| { !options.is_empty() })
    );
    for field in [
        "max_turns",
        "max_tool_calls",
        "max_tool_output_bytes",
        "workspace_root",
    ] {
        assert!(!context.limits[field].is_null(), "missing limit {field}");
    }
}

#[tokio::test]
async fn registry_mismatch_is_observed_as_durable_failure_before_rss_source() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(context: map) -> string { \"RSS_SENTINEL\"; }",
    )
    .expect("agent source should compile");
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"prompt": "must not reach RSS"}),
            platform: "agent_loop_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admission should succeed");
    let changed_registry = ToolRegistry::new(builtin_entries().into_iter().take(1))
        .expect("a one-tool registry should validate");
    service
        .set_tool_registry(changed_registry)
        .expect("the changed registry should be accepted");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events = service.run_events(&admitted.run_id);
    let terminal = events
        .last()
        .expect("the worker should commit an observable terminal event");
    assert_eq!(terminal["event"], "run.failed");
    assert_eq!(terminal["data"]["error_code"], "run_context_mismatch");
    assert!(
        !events
            .iter()
            .any(|event| event.to_string().contains("RSS_SENTINEL")),
        "the RSS source must not be invoked after pre-entry context failure"
    );
}
