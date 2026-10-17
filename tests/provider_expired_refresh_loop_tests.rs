//! Expired OAuth refresh through the real authenticated default serial loop.
#![cfg(feature = "config-fixture")]
#[path = "support/opaque_chat_stream.rs"]
mod opaque_chat_stream;
#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
pub mod provider_opaque_fixture;
use provider_opaque_fixture::{FixtureHome, json_to_vm_value, vm_value_to_json};
use rustscript_agent::auth::oauth::{
    BoundedHttpsStream, BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest,
    RawHttpsResponse, ScriptedHttpsTransport,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
const NOW: i64 = 1_900_000_000_000;
const ID: &str = "synthetic-openai";
const OLD_ACCESS: &str = "SYNTHETIC_EXPIRED_ACCESS";
const NEW_ACCESS: &str = "SYNTHETIC_REFRESHED_ACCESS";
const NEW_REFRESH: &str = "SYNTHETIC_ROTATED_REFRESH";
#[test]
fn expired_default_loop_refreshes_then_uses_persisted_rotated_access() {
    let home = FixtureHome::for_profile(
        "expired-loop",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD_ACCESS,
    )
    .with_expiry(ID, NOW - 1);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        200,
        json!({"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH,
        "token_type": "Bearer", "expires_in": 3600}),
    );
    transport.push_json(
        200,
        json!({"id": "refresh-completion", "choices": [{"finish_reason": "stop",
        "message": {"role": "assistant", "content": "refreshed answer"}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}}),
    );
    let runner = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"),
        AgentConfig::default(),
    )
    .expect("compile actual main")
    .with_host(AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport.clone())),
        ..AgentHostBridges::default()
    })
    .with_skip_sleep(true)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)));
    let decision = vm_value_to_json(
        &runner
            .run_with_context(json_to_vm_value(&json!({
                "credential_id": ID, "provider": "openai", "model": "request-model",
                "input": {"message": "refresh this request"}, "config": {"max_retries": 2},
                "limits": {"max_turns": 8, "max_tool_calls": 32}
            })))
            .expect("actual loop returns a public decision"),
    );
    let sent = transport.take_sent();
    assert_eq!(
        sent.first().map(|request| request.url.as_str()),
        Some("https://api.openai.com/oauth/token"),
        "expired credential must refresh before model transport; public decision: {decision}"
    );
    assert_eq!(
        decision["kind"],
        json!("run.completed"),
        "public decision: {decision}"
    );
    assert_eq!(decision["answer"], json!("refreshed answer"));
    assert_eq!(sent.len(), 2, "one refresh then one model request");
    assert_eq!(sent[0].url, "https://api.openai.com/oauth/token");
    assert_eq!(sent[1].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[1].method, "POST");
    assert!(sent[0].body.contains("grant_type=refresh_token"));
    assert!(
        sent[1]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {NEW_ACCESS}")),
        "native model request uses refreshed access"
    );
    let wire: serde_json::Value = serde_json::from_str(&sent[1].body).expect("public model wire");
    assert_eq!(wire["model"], json!("request-model"));
    let persisted = home.stored_auth();
    let credential = &persisted["credentials"][ID];
    assert_eq!(credential["generation"].as_i64(), Some(5));
    assert!(credential["access_token"].as_str() == Some(NEW_ACCESS));
    assert!(credential["refresh_token"].as_str() == Some(NEW_REFRESH));
    assert_eq!(credential["expires_at_ms"].as_i64(), Some(NOW + 3_600_000));
    let public = decision.to_string() + &sent[1].body;
    for secret in [
        OLD_ACCESS,
        NEW_ACCESS,
        NEW_REFRESH,
        "SYNTHETIC_REFRESH_TOKEN",
    ] {
        assert!(
            !public.contains(secret),
            "public output must not contain credentials"
        );
    }
}

fn fixture(label: &str) -> FixtureHome {
    FixtureHome::for_profile(label, "openai", "https://api.openai.com/v1", ID, OLD_ACCESS)
}
fn completion() -> serde_json::Value {
    json!({"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "refreshed answer"}}]})
}
fn rotated_tokens() -> serde_json::Value {
    json!({"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH, "token_type": "Bearer", "expires_in": 3600})
}
fn actual_loop(home: &FixtureHome, transport: Arc<ScriptedHttpsTransport>) -> serde_json::Value {
    let runner = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"),
        AgentConfig::default(),
    )
    .expect("compile main")
    .with_host(AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    })
    .with_skip_sleep(true)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)));
    let decision = vm_value_to_json(&runner.run_with_context(json_to_vm_value(&json!({
        "credential_id": ID, "provider": "openai", "model": "request-model", "input": {"message": "test refresh boundary"},
        "config": {"max_retries": 2}, "limits": {"max_turns": 8, "max_tool_calls": 8}
    }))).expect("real loop decision"));
    for secret in [
        OLD_ACCESS,
        NEW_ACCESS,
        NEW_REFRESH,
        "SYNTHETIC_REFRESH_TOKEN",
    ] {
        assert!(
            !decision.to_string().contains(secret),
            "public decision must exclude private slots"
        );
    }
    decision
}
fn unchanged_single_model(home: FixtureHome) {
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, completion());
    let decision = actual_loop(&home, transport.clone());
    assert_eq!(
        decision["kind"],
        json!("run.completed"),
        "public decision: {decision}"
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert!(
        sent[0]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {OLD_ACCESS}"))
    );
    assert!(
        home.stored_auth() == before,
        "no persistence mutation without refresh"
    );
}
#[test]
fn outside_refresh_window_sends_only_original_model_request() {
    unchanged_single_model(fixture("outside-window").with_expiry(ID, NOW + 3_600_000));
}
#[test]
fn zero_configured_skew_keeps_near_expiry_credential_unchanged() {
    unchanged_single_model(
        fixture("zero-skew")
            .with_expiry(ID, NOW + 4_000)
            .with_refresh_skew_seconds("openai", 0),
    );
}
#[test]
fn configured_refresh_window_rotates_nonexpired_credential() {
    let home = fixture("inside-window")
        .with_expiry(ID, NOW + 4_000)
        .with_refresh_skew_seconds("openai", 5);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, rotated_tokens());
    transport.push_json(200, completion());
    let decision = actual_loop(&home, transport.clone());
    assert_eq!(
        decision["kind"],
        json!("run.completed"),
        "public decision: {decision}"
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].url, "https://api.openai.com/oauth/token");
    assert_eq!(sent[1].url, "https://api.openai.com/v1/chat/completions");
    assert!(
        sent[1]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {NEW_ACCESS}"))
    );
    assert_eq!(
        home.stored_auth()["credentials"][ID]["generation"].as_i64(),
        Some(5)
    );
}
#[test]
fn api_key_kind_never_enters_oauth_refresh() {
    unchanged_single_model(fixture("api-key").with_expiry(ID, NOW - 1).with_api_key(ID));
}
#[test]
fn required_refresh_without_private_refresh_token_sends_nothing() {
    let home = fixture("missing-refresh")
        .with_expiry(ID, NOW - 1)
        .without_refresh_token(ID);
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let decision = actual_loop(&home, transport.clone());
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["code"], json!("refresh_unavailable"));
    assert!(
        transport.take_sent().is_empty(),
        "neither token nor model transport is authorized"
    );
    assert!(home.stored_auth() == before);
}
fn rejected_refresh(status: u16, response: serde_json::Value, expected: &str) {
    let home = fixture("rejected-refresh").with_expiry(ID, NOW - 1);
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(status, response);
    let decision = actual_loop(&home, transport.clone());
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(
        decision["error"]["code"],
        json!(expected),
        "public failure: {decision}"
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "one token request and zero model requests");
    assert_eq!(sent[0].url, "https://api.openai.com/oauth/token");
    assert!(
        home.stored_auth() == before,
        "failed refresh cannot mutate persisted slots/generation"
    );
}
#[test]
fn rejected_refresh_never_reaches_model_or_changes_persistence() {
    rejected_refresh(400, json!({"error": "invalid_grant"}), "reauth_required");
}
#[test]
fn malformed_refresh_never_reaches_model_or_changes_persistence() {
    rejected_refresh(
        200,
        json!({"token_type": "Bearer", "expires_in": 3600}),
        "refresh_response_invalid",
    );
}
struct RefreshThenStream {
    refresh: ScriptedHttpsTransport,
    stream: opaque_chat_stream::StreamTransport,
    refresh_count: std::sync::atomic::AtomicUsize,
}
impl BoundedHttpsTransport for RefreshThenStream {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        assert_eq!(
            request.url, "https://api.openai.com/oauth/token",
            "buffered model downgrade forbidden"
        );
        self.refresh_count.fetch_add(1, Ordering::SeqCst);
        self.refresh.send(request, context)
    }
    fn start_stream(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        assert_eq!(
            self.refresh_count.load(Ordering::SeqCst),
            1,
            "token refresh precedes native reader publication"
        );
        self.stream.start_stream(request, context)
    }
}
#[test]
fn expired_stream_refreshes_before_incremental_reader_and_cleans_up() {
    let home = fixture("expired-stream").with_expiry(ID, NOW - 1);
    let refresh = ScriptedHttpsTransport::new();
    refresh.push_json(200, rotated_tokens());
    let transport = Arc::new(RefreshThenStream {refresh, stream: opaque_chat_stream::StreamTransport::new(200, "text/event-stream", vec![
        concat!("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"fresh streamed answer\"},\"finish_reason\":\"stop\"}]}\n\n", "data: [DONE]\n\n").as_bytes().to_vec()
    ], false), refresh_count: std::sync::atomic::AtomicUsize::new(0)});
    let source =
        "use agent; pub fn run(context: map) -> map { agent::provider_call(context[\"request\"]) }";
    let runner = AgentRunner::from_source(source, AgentConfig::default())
        .expect("restricted outer stream entry")
        .with_host(AgentHostBridges {
            auth_host_factory: Some(home.auth_factory(transport.clone())),
            ..AgentHostBridges::default()
        })
        .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)));
    let result = vm_value_to_json(&runner.run_with_context(json_to_vm_value(&json!({"request": {
        "credential_id": ID, "provider": "openai", "model": "request-model", "stream": true,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "stream after refresh"}]}], "tools": []
    }}))).expect("actual default stream result"));
    assert_eq!(result["ok"], json!(true), "public stream result: {result}");
    assert_eq!(result["response"]["text"], json!("fresh streamed answer"));
    let counts = &transport.stream.counts;
    assert_eq!(counts.starts.load(Ordering::SeqCst), 1);
    assert_eq!(counts.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        counts.eof.load(Ordering::SeqCst),
        0,
        "terminal SSE without raw EOF"
    );
    assert_eq!(counts.cancels.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    let sent = counts.sent.lock().expect("native stream request");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert!(
        sent[0]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {NEW_ACCESS}"))
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&sent[0].body).expect("stream wire")["model"],
        json!("request-model")
    );
    assert_eq!(
        home.stored_auth()["credentials"][ID]["generation"].as_i64(),
        Some(5)
    );
    for secret in [
        OLD_ACCESS,
        NEW_ACCESS,
        NEW_REFRESH,
        "SYNTHETIC_REFRESH_TOKEN",
    ] {
        assert!(!result.to_string().contains(secret));
    }
}

#[test]
fn valid_oauth_without_refresh_configuration_preserves_model_access() {
    unchanged_single_model(
        fixture("valid-no-oauth-config")
            .with_expiry(ID, NOW + 3_600_000)
            .without_oauth_configuration("openai"),
    );
}
#[test]
fn expired_oauth_without_refresh_configuration_sends_nothing() {
    let home = fixture("expired-no-oauth-config")
        .with_expiry(ID, NOW - 1)
        .without_oauth_configuration("openai");
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let decision = actual_loop(&home, transport.clone());
    assert_eq!(decision["kind"], json!("run.failed"));
    assert_eq!(decision["error"]["code"], json!("refresh_unavailable"));
    assert!(transport.take_sent().is_empty());
    assert!(home.stored_auth() == before);
}
