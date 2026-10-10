//! Authenticated default serial-loop credential forwarding (first slice).
//!
//! The actual `rss/agent/main.rss` serial loop drives the production default
//! provider through the native `AuthHostFactory` bridge. `build_llm_request`
//! must relay the public `context.credential_id` into every provider request;
//! without that relay the default adapter fails closed with
//! `missing_credential` before any native send.

#![cfg(feature = "config-fixture")]

#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;

use provider_opaque_fixture::{FixtureHome, json_to_vm_value, vm_value_to_json};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::oauth::ScriptedHttpsTransport;
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use serde_json::{Value as JsonValue, json};

const PROVIDER: &str = "openai";
const BASE_URL: &str = "https://api.openai.com/v1";
const CREDENTIAL: &str = "synthetic-openai";
const ACCESS: &str = "SYNTHETIC_LOOP_ACCESS";
const EXPECTED_URL: &str = "https://api.openai.com/v1/chat/completions";

/// Actual serial-loop runner: real `main.rss`, default config, default
/// provider (no override), native auth factory, finite deadline.
fn loop_runner(home: &FixtureHome, transport: Arc<ScriptedHttpsTransport>) -> AgentRunner {
    let bridges = AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"),
        AgentConfig::default(),
    )
    .expect("actual serial loop source should compile")
    .with_host(bridges)
    .with_skip_sleep(true)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

fn loop_context(credential_id: &str) -> rustscript_vm::Value {
    json_to_vm_value(&json!({
        "credential_id": credential_id,
        "provider": PROVIDER,
        "model": "request-model",
        "input": {"message": "hello serial loop"},
        "config": {"max_retries": 2},
        "limits": {"max_turns": 8, "max_tool_calls": 32}
    }))
}

/// Canonical OpenAI Chat completion carrying assistant text and no tool call.
fn chat_text_body(text: &str) -> JsonValue {
    json!({
        "id": "chatcmpl-loop",
        "choices": [{
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": text}
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
    })
}

fn rate_limited_body() -> JsonValue {
    json!({
        "error": {
            "message": "Rate limit reached for requests",
            "type": "rate_limit_error",
            "code": "rate_limit_exceeded"
        }
    })
}

fn loop_home() -> FixtureHome {
    FixtureHome::for_profile("loop", PROVIDER, BASE_URL, CREDENTIAL, ACCESS)
}

fn assert_no_guest_secret(rendered: &str, label: &str) {
    for secret in [ACCESS, "SYNTHETIC_REFRESH_TOKEN", "host_home"] {
        assert!(
            !rendered.contains(secret),
            "{label} leaked guest secret {secret}"
        );
    }
}

#[test]
fn authenticated_default_serial_loop_forwards_public_credential() {
    let home = loop_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, chat_text_body("loop answer"));
    let runner = loop_runner(&home, transport.clone());

    let decision = vm_value_to_json(
        &runner
            .run_with_context(loop_context(CREDENTIAL))
            .expect("authenticated serial loop completes"),
    );
    assert_eq!(
        decision["kind"],
        json!("run.completed"),
        "unexpected loop decision: {decision}"
    );
    assert_eq!(decision["answer"], json!("loop answer"));

    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "exactly one native request on the happy path"
    );
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].url, EXPECTED_URL);
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_LOOP_ACCESS")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public OpenAI wire JSON");
    assert_eq!(wire["model"], json!("request-model"));
    assert_eq!(
        wire["messages"],
        json!([{"role": "user", "content": [{"type": "text", "text": "hello serial loop"}]}])
    );
    assert_no_guest_secret(&decision.to_string(), "happy-loop decision");
    assert_no_guest_secret(&sent[0].body, "happy-loop wire body");
}

#[test]
fn serial_loop_without_credential_fails_closed_before_send() {
    let home = loop_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = loop_runner(&home, transport.clone());

    let decision = vm_value_to_json(
        &runner
            .run_with_context(loop_context(""))
            .expect("missing credential returns a canonical failure"),
    );
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["code"], json!("missing_credential"));
    assert!(transport.take_sent().is_empty());
}

#[test]
fn serial_loop_with_unadmitted_credential_sends_nothing() {
    let home = loop_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = loop_runner(&home, transport.clone());

    let decision = vm_value_to_json(
        &runner
            .run_with_context(loop_context("not-admitted"))
            .expect("unadmitted reference returns a canonical failure"),
    );
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["code"], json!("credential_not_admitted"));
    assert!(transport.take_sent().is_empty());
    assert_no_guest_secret(&decision.to_string(), "unadmitted decision");
}

#[test]
fn serial_loop_retries_rate_limit_then_completes_with_identical_body() {
    let home = loop_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(429, rate_limited_body());
    transport.push_json(200, chat_text_body("retried answer"));
    let runner = loop_runner(&home, transport.clone());

    let decision = vm_value_to_json(
        &runner
            .run_with_context(loop_context(CREDENTIAL))
            .expect("rate-limited loop recovers on retry"),
    );
    assert_eq!(
        decision["kind"],
        json!("run.completed"),
        "unexpected retry decision: {decision}"
    );
    assert_eq!(decision["answer"], json!("retried answer"));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 2, "one retry must resend exactly once");
    for request in &sent {
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, EXPECTED_URL);
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer SYNTHETIC_LOOP_ACCESS")
        );
    }
    assert_eq!(
        sent[0].body, sent[1].body,
        "retry must resend the byte-identical public body"
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public OpenAI wire JSON");
    assert_eq!(wire["messages"].as_array().map(Vec::len), Some(1));
    assert_no_guest_secret(&decision.to_string(), "retry decision");
    assert_no_guest_secret(&sent[0].body, "retry wire body");
}

#[test]
fn serial_loop_exhausts_bounded_retries_on_repeated_rate_limit() {
    let home = loop_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    for _ in 0..3 {
        transport.push_json(429, rate_limited_body());
    }
    let runner = loop_runner(&home, transport.clone());

    let decision = vm_value_to_json(
        &runner
            .run_with_context(loop_context(CREDENTIAL))
            .expect("exhausted retries return a canonical failure"),
    );
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["reason"], json!("retry_exhausted"));
    assert_eq!(decision["error"]["code"], json!("retry_exhausted"));

    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        3,
        "max_retries=2 must bound the loop at exactly max_retries+1 sends"
    );
    for request in &sent {
        assert_eq!(request.url, EXPECTED_URL);
    }
    assert!(
        sent.iter().all(|request| request.body == sent[0].body),
        "every bounded retry must carry the identical public body"
    );
    assert_no_guest_secret(&decision.to_string(), "exhaustion decision");
}
