//! A6 subagent supervision policy suite (`rss/agent/subagents.rss`).
//!
//! The policy is a pure decision function: given a proposed child run under a
//! parent, it returns a typed `subagent.admit` (an honest, non-executable
//! authorization naming the child, its ordinal, its isolation, and a typed
//! `blocked_reason`), a typed `subagent.cancel` (parent-cancellation
//! propagation to pending/active children), or a typed `subagent.rejected`
//! (depth/fanout/terminal-parent). The decision NEVER fabricates a
//! `subagent.started` event or a `run.link_child` command before the child is
//! really admitted: those lifecycle artifacts belong to the native supervisor
//! (`crate::runtime::subagent_supervisor`), which produces them only after a
//! genuine admission+link. A terminal parent never gets new admissions or
//! events (no post-terminal side effects).

use std::path::PathBuf;

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

fn agent_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent")
}

fn subagent_runner() -> AgentRunner {
    AgentRunner::from_file(agent_root().join("subagents.rss"), AgentConfig::default())
        .expect("production subagent policy should compile")
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
        .unwrap_or_else(|error| panic!("subagent decision failed: {error:?}"));
    let Value::Map(result) = result else {
        panic!("subagent entry should return a decision map");
    };
    vm_value_to_json(&Value::Map(result))
}

fn admit_context(
    depth: i64,
    max_depth: i64,
    current_fanout: i64,
    max_fanout: i64,
    parent_status: &str,
    children: JsonValue,
) -> JsonValue {
    json!({
        "parent_run_id": "p1",
        "child": {"id": "c1", "input": "child work"},
        "depth": depth,
        "max_depth": max_depth,
        "current_fanout": current_fanout,
        "max_fanout": max_fanout,
        "parent_status": parent_status,
        "children": children,
    })
}

#[test]
fn subagent_active_parent_admits_child_decision_is_honest_and_non_executable() {
    let runner = subagent_runner();
    let decision = decide(&runner, admit_context(1, 3, 0, 4, "active", json!([])));
    assert_eq!(decision["kind"], json!("subagent.admit"));
    assert_eq!(decision["parent_run_id"], json!("p1"));
    assert_eq!(decision["child_run_id"], json!("c1"));
    assert_eq!(decision["ordinal"], json!(0));
    // The decision is an authorization, not a claim of execution: it never
    // fabricates a subagent.started event or a run.link_child before the
    // child is really admitted.
    assert_eq!(decision["events"], json!([]));
    assert_eq!(decision["executable"], json!(false));
    assert!(
        decision["blocked_reason"]
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "the decision must carry a typed blocked_reason"
    );
}

#[test]
fn subagent_child_state_is_isolated_from_parent() {
    let runner = subagent_runner();
    let decision = decide(&runner, admit_context(1, 3, 1, 4, "active", json!([])));
    let isolation = &decision["isolation"];
    assert_eq!(isolation["separate_run_context"], json!(true));
    assert_eq!(isolation["shared_history"], json!(false));
    assert_eq!(isolation["parent_link"], json!("p1"));
}

#[test]
fn subagent_admit_ordinal_advances_with_existing_fanout() {
    let runner = subagent_runner();
    // Two children already admitted -> this child takes ordinal 2.
    let decision = decide(&runner, admit_context(1, 3, 2, 4, "active", json!([])));
    assert_eq!(decision["kind"], json!("subagent.admit"));
    assert_eq!(decision["ordinal"], json!(2));
}

#[test]
fn subagent_admit_never_fabricates_started_event_or_link() {
    let runner = subagent_runner();
    let decision = decide(&runner, admit_context(1, 3, 0, 4, "active", json!([])));
    let events = decision["events"]
        .as_array()
        .expect("events should be an array");
    assert_eq!(events.len(), 0, "no fabricated subagent.started event");
    // No run.link_child command is invented before the native supervisor
    // really admits and links the child.
    assert!(decision.get("link").is_none());
}

#[test]
fn subagent_cancelling_parent_propagates_cancel_to_active_children() {
    let runner = subagent_runner();
    let decision = decide(
        &runner,
        admit_context(
            1,
            3,
            2,
            4,
            "stopping",
            json!([
                {"child_run_id": "c1", "state": "active"},
                {"child_run_id": "c2", "state": "pending"},
                {"child_run_id": "c3", "state": "completed"},
            ]),
        ),
    );
    assert_eq!(decision["kind"], json!("subagent.cancel"));
    assert_eq!(decision["reason"], json!("parent_cancelled"));
    // Terminal children are never cancelled; only pending/active are listed.
    assert_eq!(decision["child_run_ids"], json!(["c1", "c2"]));
    // Cancellation is not an admission and emits no new events.
    assert_eq!(decision["events"], json!([]));
}

#[test]
fn subagent_terminal_parent_refuses_admission_without_events() {
    let runner = subagent_runner();
    for status in ["completed", "cancelled", "failed"] {
        let decision = decide(&runner, admit_context(1, 3, 0, 4, status, json!([])));
        assert_eq!(decision["kind"], json!("subagent.rejected"), "{status}");
        assert_eq!(decision["code"], json!("parent_terminal"), "{status}");
        // No post-terminal side effects: no admission, no new events.
        assert_eq!(decision["events"], json!([]), "{status}");
    }
}

#[test]
fn subagent_depth_at_budget_is_rejected() {
    let runner = subagent_runner();
    let decision = decide(&runner, admit_context(3, 3, 0, 4, "active", json!([])));
    assert_eq!(decision["kind"], json!("subagent.rejected"));
    assert_eq!(decision["code"], json!("depth_exceeded"));
}

#[test]
fn subagent_fanout_at_budget_is_rejected() {
    let runner = subagent_runner();
    let decision = decide(&runner, admit_context(1, 3, 4, 4, "active", json!([])));
    assert_eq!(decision["kind"], json!("subagent.rejected"));
    assert_eq!(decision["code"], json!("fanout_exceeded"));
}

#[test]
fn subagent_fanout_within_budget_admits() {
    let runner = subagent_runner();
    let decision = decide(&runner, admit_context(1, 3, 3, 4, "active", json!([])));
    assert_eq!(decision["kind"], json!("subagent.admit"));
}
