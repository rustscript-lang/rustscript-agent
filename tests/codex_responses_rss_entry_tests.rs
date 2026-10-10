//! Codex Responses admitted-path business tests (Task8 access-only scope).
//!
//! Drives the REAL production `rss/llm/harness.rss` entry with a native
//! `AuthHostFactory` (via the trusted fixture home) and an injected counted
//! transport. When the entry context carries the native `host_home`, the
//! Responses adapter is routed through the opaque Responses entry
//! (`rss/providers/opaque_responses.rss`): it builds a Codex-compatible
//! Responses body, sends through the native opaque transport, and consumes the
//! sanitized response/stream records with the pure Responses codec. No live
//! network, no raw credentials in requests.

#![cfg(feature = "config-fixture")]

#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;

#[path = "support/opaque_chat_stream.rs"]
#[allow(dead_code)]
mod opaque_chat_stream;

use provider_opaque_fixture::{
    FixtureHome, canonical_request, harness_context, harness_runner, read_provider_fixture,
    sse_events, vm_value_to_json,
};

use std::sync::Arc;
use std::time::Duration;

use opaque_chat_stream::StreamTransport;
use rustscript_agent::auth::oauth::ScriptedHttpsTransport;
use rustscript_agent::{AgentRunner, RunCancellation};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

const PROVIDER: &str = "openai-codex";
const BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
const CREDENTIAL: &str = "fixture-codex";
const ACCESS: &str = "SYNTHETIC_ACCESS_TOKEN";
const EXPECTED_URL: &str = "https://chatgpt.com/backend-api/codex/responses";

fn run_harness(
    runner: &AgentRunner,
    kind: &str,
    request: JsonValue,
    profile: JsonValue,
    credential_id: &str,
) -> JsonValue {
    let context = harness_context(kind, request, profile, credential_id);
    let mut sink = DiscardSink;
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    vm_value_to_json(
        &runner
            .run_named_with_context_and_events("run_harness", context, &mut sink, &cancellation)
            .unwrap_or_else(|error| panic!("harness {kind} run failed: {error:?}")),
    )
}

struct DiscardSink;

impl rustscript_agent::RunEventSink for DiscardSink {
    fn deliver(&mut self, _value: Value) -> Result<(), rustscript_agent::RunDeliveryError> {
        Ok(())
    }
}

fn codex_home() -> FixtureHome {
    FixtureHome::for_profile("responses", PROVIDER, BASE_URL, CREDENTIAL, ACCESS)
}

fn codex_profile() -> JsonValue {
    json!({
        "provider": "openai-codex",
        "base_url": BASE_URL,
        "model": "gpt-6.1-sol",
    })
}

fn message_body(text: &str) -> JsonValue {
    json!({
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "model": "gpt-6.1-sol",
        "output": [
            {"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
             "content": [{"type": "output_text", "text": text}]}
        ],
        "usage": {"input_tokens": 9, "output_tokens": 4, "total_tokens": 13},
        "error": null
    })
}

fn function_call_body() -> JsonValue {
    json!({
        "id": "resp_2",
        "object": "response",
        "status": "completed",
        "model": "gpt-6.1-sol",
        "output": [
            {"type": "function_call", "id": "fc_1", "call_id": "call_xy", "name": "read_file",
             "arguments": "{\"path\": \"README.md\"}"}
        ],
        "usage": {"input_tokens": 3, "output_tokens": 4, "total_tokens": 7},
        "error": null
    })
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
fn admitted_responses_buffered_message_returns_canonical_text() {
    let home = codex_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, message_body("responses answer"));
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(false),
        codex_profile(),
        CREDENTIAL,
    );
    assert_eq!(result["ok"], json!(true), "{result}");
    assert_eq!(
        result["response"]["text"],
        json!("responses answer"),
        "{result}"
    );
    assert_eq!(result["response"]["stop_reason"], json!("stop"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(9));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(13));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native request");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].url, EXPECTED_URL);
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_ACCESS_TOKEN")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("responses wire JSON");
    assert_eq!(wire["model"], json!("test-model"));
    assert_eq!(wire["stream"], json!(false));
    assert_eq!(wire["store"], json!(false));
    assert!(
        wire.get("instructions").is_some(),
        "instructions always present: {wire}"
    );
    assert_eq!(wire["input"][0]["role"], json!("user"));
    assert_no_guest_secret(&result.to_string(), "buffered decision");
    assert_no_guest_secret(&sent[0].body, "buffered wire body");
}

#[test]
fn admitted_responses_uses_profile_model_only_when_request_model_is_empty() {
    let home = codex_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, message_body("profile fallback"));
    let runner = harness_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request(false);
    request["model"] = json!("");

    let result = run_harness(
        &runner,
        "openai_responses",
        request,
        codex_profile(),
        CREDENTIAL,
    );
    assert_eq!(result["ok"], json!(true), "{result}");
    assert_eq!(result["response"]["text"], json!("profile fallback"));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("responses wire JSON");
    assert_eq!(wire["model"], json!("gpt-6.1-sol"));
}

#[test]
fn admitted_responses_buffered_function_call_returns_canonical_tool_call() {
    let home = codex_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, function_call_body());
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(false),
        codex_profile(),
        CREDENTIAL,
    );
    assert_eq!(result["ok"], json!(true), "{result}");
    let calls = &result["response"]["tool_calls"];
    assert_eq!(calls.as_array().map(Vec::len), Some(1), "{result}");
    assert_eq!(calls[0]["id"], json!("call_xy"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(calls[0]["arguments"], json!({"path": "README.md"}));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, EXPECTED_URL);
}

#[test]
fn admitted_responses_stream_returns_canonical_text_and_tool() {
    let home = codex_home();
    let transcript = read_provider_fixture("openai_responses/stream.sse");
    let chunks: Vec<Vec<u8>> = sse_events(&transcript)
        .into_iter()
        .map(String::into_bytes)
        .collect();
    let transport = Arc::new(StreamTransport::new(200, "text/event-stream", chunks, true));
    let runner = harness_runner(&home, Arc::clone(&transport));

    let request = {
        let mut request = canonical_request(true);
        request["stream"] = json!(true);
        request
    };
    let result = run_harness(
        &runner,
        "openai_responses",
        request,
        codex_profile(),
        CREDENTIAL,
    );
    assert_eq!(result["ok"], json!(true), "{result}");
    assert_eq!(
        result["response"]["text"],
        json!("The Responses adapter streams."),
        "{result}"
    );
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(42));
    let calls = &result["response"]["tool_calls"];
    assert_eq!(calls.as_array().map(Vec::len), Some(1), "{result}");
    assert_eq!(calls[0]["id"], json!("call_xy"));
    assert_eq!(calls[0]["arguments"], json!({"path": "README.md"}));

    let sent = transport.counts.sent.lock().expect("sent").clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, EXPECTED_URL);
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("responses stream wire JSON");
    assert_eq!(wire["stream"], json!(true));
    assert_eq!(wire["store"], json!(false));
}

#[test]
fn admitted_responses_upstream_error_maps_canonical_error() {
    let home = codex_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        400,
        json!({"error": {"message": "bad request", "type": "invalid_request_error", "code": "bad_model"}}),
    );
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(false),
        codex_profile(),
        CREDENTIAL,
    );
    assert_eq!(result["ok"], json!(false), "{result}");
    assert_eq!(result["error"]["status"], json!(400));
    assert_eq!(result["error"]["type"], json!("invalid_request_error"));
    assert_eq!(result["error"]["code"], json!("invalid_request_error"));
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn admitted_responses_quota_429_maps_retryable_error() {
    let home = codex_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        429,
        json!({"error": {"message": "Rate limit reached", "type": "rate_limit_error", "code": "rate_limit_exceeded"}}),
    );
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(false),
        codex_profile(),
        CREDENTIAL,
    );
    assert_eq!(result["ok"], json!(false), "{result}");
    assert_eq!(result["error"]["status"], json!(429));
    assert_eq!(result["error"]["retryable"], json!(true));
}

#[test]
fn admitted_responses_access_only_401_returns_reauth_with_zero_refresh() {
    // Access-only credential: no refresh token. A 401 must surface the typed
    // reauthentication failure WITHOUT any refresh/token-endpoint request.
    let home = codex_home().without_refresh_token(CREDENTIAL);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(401, json!({"error": {"message": "unauthorized"}}));
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(false),
        codex_profile(),
        CREDENTIAL,
    );
    assert_eq!(result["ok"], json!(false), "{result}");
    assert_eq!(
        result["error"]["code"],
        json!("reauth_required"),
        "{result}"
    );

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one send, no refresh");
    for request in &sent {
        assert!(
            !request.url.contains("/oauth/token"),
            "no refresh endpoint may be called: {}",
            request.url
        );
        assert_eq!(request.url, EXPECTED_URL);
    }
}

#[test]
fn admitted_responses_missing_credential_fails_before_send() {
    let home = codex_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(false),
        codex_profile(),
        "",
    );
    assert_eq!(result["ok"], json!(false), "{result}");
    assert_eq!(
        result["error"]["code"],
        json!("missing_credential"),
        "{result}"
    );
    assert!(transport.take_sent().is_empty());
}

#[test]
fn responses_adapter_without_native_home_fails_closed_legacy() {
    // The legacy explicit-custom adapter selection carries no native transport
    // context, so it fails closed with the typed `not_implemented` guard and
    // never sends. This is the retained legacy negative path, not the admitted
    // production Responses entry.
    use rustscript_agent::{AgentConfig, AgentHostBridges};
    let home = codex_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let bridges = AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(Arc::clone(&transport))),
        ..AgentHostBridges::default()
    };
    let runner = AgentRunner::from_file(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss"),
        AgentConfig::default(),
    )
    .expect("harness compiles")
    .with_host(bridges);
    // A direct call into the facade with no host_home is exercised through the
    // profile:custom adapter path.
    let mut options = canonical_request(false);
    options["provider_options"] = json!({
        "base_url": BASE_URL,
        "model": "gpt-6.1-sol",
        "adapter": "openai_responses"
    });
    let result = run_harness(
        &runner,
        "profile:custom",
        options,
        json!({}),
        "synthetic-custom",
    );
    assert_eq!(result["ok"], json!(false), "{result}");
    assert_eq!(
        result["error"]["code"],
        json!("not_implemented"),
        "{result}"
    );
    assert!(transport.take_sent().is_empty());
}

#[test]
fn admitted_responses_accumulates_refusal_deltas_through_done_exact_text() {
    let home = codex_home();
    let expected = "I cannot help with that request.";
    let transcript = format!(
        "event: response.refusal.delta\ndata: {}\n\nevent: response.refusal.delta\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"type": "response.refusal.delta", "delta": "I cannot "}),
        json!({"type": "response.refusal.delta", "delta": "help with that request."})
    );
    let chunks: Vec<Vec<u8>> = sse_events(&transcript)
        .into_iter()
        .map(String::into_bytes)
        .collect();
    let transport = Arc::new(StreamTransport::new(200, "text/event-stream", chunks, true));
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(true),
        codex_profile(),
        CREDENTIAL,
    );

    assert_eq!(result["ok"], json!(true), "{result}");
    assert_eq!(result["response"]["text"], json!(expected), "{result}");
    assert_eq!(result["response"]["tool_calls"], json!([]), "{result}");
    assert_eq!(
        transport
            .counts
            .starts
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one native stream start"
    );
    assert_eq!(
        transport.counts.sent.lock().expect("sent requests").len(),
        1,
        "one Responses request"
    );
    assert_eq!(
        transport
            .counts
            .drops
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "native stream resource released"
    );
}
