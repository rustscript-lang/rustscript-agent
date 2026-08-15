//! A6 parallel execution policy suite (`rss/agent/parallel.rss`).
//!
//! The policy is a pure decision function: given a batch of child tasks it
//! returns a typed `parallel.plan` (bounded-concurrency windows, ordered
//! result slots, race/fail-fast supervision rules) or a typed
//! `parallel.rejected` (depth/fanout/invalid-config). Because RustScript is
//! synchronous and single-threaded, the plan cannot itself run children in
//! the script, so it is marked `executable:false` with a typed
//! `blocked_reason` naming the narrowed script-internal task surface; the
//! native supervisor (`crate::runtime::subagent_supervisor`) consumes the
//! plan and does the bounded-concurrency/ordered/race/fail-fast work, and no
//! success or execution event is ever fabricated.

use std::path::PathBuf;

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

fn agent_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent")
}

fn parallel_runner() -> AgentRunner {
    AgentRunner::from_file(agent_root().join("parallel.rss"), AgentConfig::default())
        .expect("production parallel policy should compile")
}

/// Converts one VM value into JSON (test-side mirror of the gateway renderer).
fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => json!(value),
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

/// Converts one JSON value into a VM value.
fn json_to_vm(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => value
            .as_i64()
            .map(Value::Int)
            .unwrap_or_else(|| Value::Float(value.as_f64().expect("number should be a float"))),
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

fn decide(runner: &AgentRunner, context: JsonValue) -> JsonValue {
    let result = runner
        .run_with_context(json_to_vm(&context))
        .unwrap_or_else(|error| panic!("parallel decision failed: {error:?}"));
    let Value::Map(result) = result else {
        panic!("parallel entry should return a decision map");
    };
    vm_value_to_json(&Value::Map(result))
}

fn batch(n: i64) -> JsonValue {
    (0..n)
        .map(|i| json!({"index": i, "id": format!("t{i}")}))
        .collect::<Vec<_>>()
        .into()
}

fn plan_context(
    batch_len: i64,
    mode: &str,
    max_concurrency: i64,
    max_fanout: i64,
    current_fanout: i64,
    depth: i64,
    max_depth: i64,
) -> JsonValue {
    json!({
        "parent_run_id": "p1",
        "batch": batch(batch_len),
        "mode": mode,
        "max_concurrency": max_concurrency,
        "max_fanout": max_fanout,
        "current_fanout": current_fanout,
        "depth": depth,
        "max_depth": max_depth,
    })
}

#[test]
fn parallel_batch_is_chunked_into_bounded_concurrency_windows() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(5, "all", 2, 0, 0, 0, 0));
    assert_eq!(decision["kind"], json!("parallel.plan"));
    assert_eq!(
        decision["windows"],
        json!([[0, 1], [2, 3], [4]]),
        "5 items under max_concurrency=2 must yield ceil(5/2) windows"
    );
    assert_eq!(decision["supervision"]["max_concurrency"], json!(2));
    assert_eq!(decision["supervision"]["fanout_used"], json!(5));
}

#[test]
fn parallel_concurrency_one_yields_one_window_per_item() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(3, "all", 1, 0, 0, 0, 0));
    assert_eq!(decision["kind"], json!("parallel.plan"));
    assert_eq!(decision["windows"], json!([[0], [1], [2]]));
}

#[test]
fn parallel_concurrency_at_least_batch_yields_one_window() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(3, "all", 5, 0, 0, 0, 0));
    assert_eq!(decision["kind"], json!("parallel.plan"));
    assert_eq!(decision["windows"], json!([[0, 1, 2]]));
}

#[test]
fn parallel_empty_batch_yields_no_windows() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(0, "all", 2, 0, 0, 0, 0));
    assert_eq!(decision["kind"], json!("parallel.plan"));
    assert_eq!(decision["windows"], json!([]));
    assert_eq!(decision["ordered_slots"], json!([]));
}

#[test]
fn parallel_ordered_slots_preserve_submission_order() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(4, "all", 2, 0, 0, 0, 0));
    assert_eq!(
        decision["ordered_slots"],
        json!([
            {"index": 0, "window": 0},
            {"index": 1, "window": 0},
            {"index": 2, "window": 1},
            {"index": 3, "window": 1},
        ])
    );
}

#[test]
fn parallel_mode_all_uses_none_cancel_rule() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(2, "all", 1, 0, 0, 0, 0));
    assert_eq!(decision["supervision"]["mode"], json!("all"));
    assert_eq!(decision["supervision"]["cancel_rule"], json!("none"));
}

#[test]
fn parallel_race_cancels_losers_on_first_success() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(2, "race", 1, 0, 0, 0, 0));
    assert_eq!(decision["supervision"]["mode"], json!("race"));
    assert_eq!(
        decision["supervision"]["cancel_rule"],
        json!("cancel_losers_on_first_success")
    );
}

#[test]
fn parallel_fail_fast_cancels_siblings_on_first_failure() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(2, "fail_fast", 1, 0, 0, 0, 0));
    assert_eq!(decision["supervision"]["mode"], json!("fail_fast"));
    assert_eq!(
        decision["supervision"]["cancel_rule"],
        json!("cancel_siblings_on_first_failure")
    );
}

#[test]
fn parallel_zero_concurrency_is_invalid_config() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(2, "all", 0, 0, 0, 0, 0));
    assert_eq!(decision["kind"], json!("parallel.rejected"));
    assert_eq!(decision["code"], json!("invalid_config"));
}

#[test]
fn parallel_depth_at_budget_is_rejected() {
    let runner = parallel_runner();
    // depth == max_depth means the nesting budget is exhausted.
    let decision = decide(&runner, plan_context(2, "all", 1, 0, 0, 3, 3));
    assert_eq!(decision["kind"], json!("parallel.rejected"));
    assert_eq!(decision["code"], json!("depth_exceeded"));
}

#[test]
fn parallel_fanout_over_budget_is_rejected() {
    let runner = parallel_runner();
    // current_fanout 3 + batch 3 = 6 > max_fanout 5.
    let decision = decide(&runner, plan_context(3, "all", 1, 5, 3, 0, 0));
    assert_eq!(decision["kind"], json!("parallel.rejected"));
    assert_eq!(decision["code"], json!("fanout_exceeded"));
}

#[test]
fn parallel_fanout_within_budget_plans() {
    let runner = parallel_runner();
    // current_fanout 2 + batch 2 = 4 <= max_fanout 4.
    let decision = decide(&runner, plan_context(2, "all", 1, 4, 2, 0, 0));
    assert_eq!(decision["kind"], json!("parallel.plan"));
    assert_eq!(decision["supervision"]["fanout_used"], json!(4));
}

#[test]
fn parallel_plan_is_an_honest_decision_never_a_fabricated_success() {
    let runner = parallel_runner();
    let decision = decide(&runner, plan_context(2, "all", 1, 0, 0, 0, 0));
    // The plan names the windows/supervision the native supervisor must run,
    // and it is explicitly non-executable-from-the-script with a typed
    // blocked_reason naming the narrowed script-internal task surface — never
    // a fabricated success and never a fabricated execution event.
    assert_eq!(decision["executable"], json!(false));
    assert!(
        decision["blocked_reason"]
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "plan must carry a typed blocked_reason"
    );
    // No execution events are invented before a child is really admitted.
    assert_eq!(decision["events"], json!([]));
}
