//! Real main/default/native authenticated provider behavior.
#![cfg(feature = "config-fixture")]
#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
pub mod provider_opaque_fixture;
use provider_opaque_fixture::{FixtureHome, json_to_vm_value, vm_value_to_json};
use rustscript_agent::auth::oauth::ScriptedHttpsTransport;
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
const ID: &str = "synthetic-openai";
const OLD: &str = "SYNTHETIC_EXISTING_ACCESS";
fn real_loop(home: &FixtureHome, transport: Arc<ScriptedHttpsTransport>) -> Value {
    let runner = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"),
        AgentConfig::default(),
    )
    .expect("compile actual main")
    .with_host(AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    })
    .with_skip_sleep(true)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)));
    vm_value_to_json(
        &runner
            .run_with_context(json_to_vm_value(&json!({
                "credential_id": ID, "provider": "openai", "model": "requested-model",
                "input": {"message": "same logical request"}, "config": {"max_retries": 2},
                "limits": {"max_turns": 8, "max_tool_calls": 8}
            })))
            .expect("real main decision"),
    )
}
fn completed() -> Value {
    json!({"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "completed answer"}}]})
}

#[test]
fn insufficient_quota_is_terminal_without_model_retry_or_refresh() {
    let home =
        FixtureHome::for_profile("quota-loop", "openai", "https://api.openai.com/v1", ID, OLD);
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(429, json!({"error": {"type": "insufficient_quota", "code": "insufficient_quota", "message": "public quota exhausted", "param": "project", "request_id": "quota-request"}}));
    transport.push_json(200, completed());
    let decision = real_loop(&home, transport.clone());
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "quota denial is not a transient rate limit; public decision: {decision}"
    );
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["status"], json!(429));
    assert_eq!(decision["error"]["code"], json!("insufficient_quota"));
    assert_eq!(decision["error"]["type"], json!("insufficient_quota"));
    assert_eq!(decision["error"]["param"], json!("project"));
    assert_eq!(decision["error"]["request_id"], json!("quota-request"));
    assert_eq!(decision["retry_count"], json!(0));
    assert_eq!(decision["turn"], json!(0));
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(sent[0].method, "POST");
    assert!(
        sent[0]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {OLD}"))
    );
    assert!(!sent[0].body.contains(OLD));
    assert!(!decision.to_string().contains(OLD));
    assert!(
        home.stored_auth() == before,
        "quota does not refresh credentials"
    );
}

fn check_native_send(
    sent: &rustscript_agent::auth::oauth::PreparedHttpsRequest,
    bodies_equal_to: Option<&str>,
) {
    assert_eq!(sent.url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(sent.method, "POST");
    assert!(
        sent.headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {OLD}"))
    );
    assert!(!sent.body.contains(OLD));
    let wire: Value = serde_json::from_str(&sent.body).expect("public model request JSON");
    assert_eq!(wire["model"], json!("requested-model"));
    if let Some(expected) = bodies_equal_to {
        assert_eq!(sent.body, expected);
    }
}

#[test]
fn transient_rate_limit_429_completes_after_two_sends() {
    let home = FixtureHome::for_profile(
        "quota-transient",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(429, json!({"error": {"type": "rate_limit_error", "message": "public slow down", "param": "p", "request_id": "rl-1"}}));
    transport.push_json(200, completed());
    let decision = real_loop(&home, transport.clone());
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        2,
        "transient 429 retries once; public decision: {decision}"
    );
    check_native_send(&sent[0], None);
    check_native_send(&sent[1], Some(&sent[0].body));
    assert_eq!(decision["kind"], json!("run.completed"));
    assert_eq!(decision["answer"], json!("completed answer"));
    assert_eq!(decision["retry_count"], json!(0));
    assert!(!decision.to_string().contains(OLD));
    assert!(
        home.stored_auth() == before,
        "transient retry does not refresh credentials"
    );
}

#[test]
fn repeated_429_exhausts_existing_two_retry_policy_after_three_sends() {
    let home = FixtureHome::for_profile(
        "quota-exhaust",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    for i in 0..3 {
        transport.push_json(429, json!({"error": {"type": "rate_limit_error", "message": "public slow down", "param": "p", "request_id": format!("rl-{i}")}}));
    }
    let decision = real_loop(&home, transport.clone());
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        3,
        "2-retry policy stops after 3 sends; public decision: {decision}"
    );
    check_native_send(&sent[0], None);
    check_native_send(&sent[1], Some(&sent[0].body));
    check_native_send(&sent[2], Some(&sent[0].body));
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["status"], json!(429));
    assert_eq!(decision["error"]["code"], json!("retry_exhausted"));
    assert_eq!(decision["retry_count"], json!(2));
    assert_eq!(decision["turn"], json!(0));
    assert!(!decision.to_string().contains(OLD));
    assert!(
        home.stored_auth() == before,
        "exhaustion does not refresh credentials"
    );
}

#[test]
fn insufficient_quota_without_code_is_terminal() {
    let home = FixtureHome::for_profile(
        "quota-nocode",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(429, json!({"error": {"type": "insufficient_quota", "message": "public quota exhausted", "param": "project", "request_id": "quota-nocode"}}));
    transport.push_json(200, completed());
    let decision = real_loop(&home, transport.clone());
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "explicit quota type without code is terminal; public decision: {decision}"
    );
    check_native_send(&sent[0], None);
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["status"], json!(429));
    assert_eq!(decision["error"]["code"], json!("insufficient_quota"));
    assert_eq!(decision["error"]["type"], json!("insufficient_quota"));
    assert_eq!(decision["error"]["param"], json!("project"));
    assert_eq!(decision["error"]["request_id"], json!("quota-nocode"));
    assert_eq!(decision["retry_count"], json!(0));
    assert_eq!(decision["turn"], json!(0));
    assert!(!decision.to_string().contains(OLD));
    assert!(
        home.stored_auth() == before,
        "quota does not refresh credentials"
    );
}

#[test]
fn unrelated_invalid_request_error_stays_nonretryable() {
    let home = FixtureHome::for_profile(
        "quota-unrelated",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(400, json!({"error": {"type": "invalid_request_error", "message": "public bad request", "param": "p", "request_id": "bad-1"}}));
    transport.push_json(200, completed());
    let decision = real_loop(&home, transport.clone());
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "unrelated error is not retried; public decision: {decision}"
    );
    check_native_send(&sent[0], None);
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["status"], json!(400));
    assert_eq!(decision["error"]["type"], json!("invalid_request_error"));
    assert_eq!(decision["retry_count"], json!(0));
    assert_eq!(decision["turn"], json!(0));
    assert!(!decision.to_string().contains(OLD));
    assert!(
        home.stored_auth() == before,
        "unrelated error does not refresh credentials"
    );
}

#[test]
fn quota_looking_unknown_type_under_429_keeps_rate_limit_behavior() {
    let home = FixtureHome::for_profile(
        "quota-unknown",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(429, json!({"error": {"type": "quota_exceeded", "message": "public unknown quota wording", "param": "p", "request_id": "q-1"}}));
    transport.push_json(200, completed());
    let decision = real_loop(&home, transport.clone());
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        2,
        "unknown quota-like type is not wildcard-mapped; public decision: {decision}"
    );
    check_native_send(&sent[0], None);
    check_native_send(&sent[1], Some(&sent[0].body));
    assert_eq!(decision["kind"], json!("run.completed"));
    assert_eq!(decision["answer"], json!("completed answer"));
    assert!(!decision.to_string().contains(OLD));
    assert!(
        home.stored_auth() == before,
        "transient retry does not refresh credentials"
    );
}
