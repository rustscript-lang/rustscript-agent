//! Real main/default/native authenticated provider behavior.
#![cfg(feature = "config-fixture")]
#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
pub mod provider_opaque_fixture;
use provider_opaque_fixture::{FixtureHome, json_to_vm_value, vm_value_to_json};
use rustscript_agent::auth::{
    host::{AuthHost, auth_host_catalog},
    oauth::{
        BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse,
        ScriptedHttpsTransport,
    },
};
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, CancellationReason, RunCancellation,
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value as VmValue, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    thread,
    time::{Duration, Instant},
};
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

const FLAGS_MODEL_BODY: &str =
    r#"{"model":"requested-model","messages":[{"role":"user","content":"public tracer request"}]}"#;

#[derive(Clone, Copy, Debug)]
enum NativeFailureBoundary {
    Cancellation,
    Deadline,
    Revocation,
}

struct BoundaryTokenTransport {
    boundary: NativeFailureBoundary,
    cancellation: RunCancellation,
    revoke_target: Arc<Mutex<Option<Weak<AuthHost>>>>,
    sent: Mutex<Vec<(String, String)>>,
}

impl BoundaryTokenTransport {
    fn new(boundary: NativeFailureBoundary, cancellation: RunCancellation) -> Self {
        Self {
            boundary,
            cancellation,
            revoke_target: Arc::new(Mutex::new(None)),
            sent: Mutex::new(Vec::new()),
        }
    }

    fn set_revoke_target(&self, target: Weak<AuthHost>) {
        *self.revoke_target.lock().unwrap_or_else(|p| p.into_inner()) = Some(target);
    }

    fn take_sent(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.sent.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn trigger(&self, context: &OAuthIoContext) {
        match self.boundary {
            NativeFailureBoundary::Cancellation => {
                self.cancellation.request(CancellationReason::Requested);
            }
            NativeFailureBoundary::Deadline => {
                let remaining = context.deadline().saturating_duration_since(Instant::now());
                thread::sleep(remaining + Duration::from_millis(2));
            }
            NativeFailureBoundary::Revocation => {
                let host = self
                    .revoke_target
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .expect("public revoke target installed without a strong cycle");
                host.revoke();
            }
        }
    }
}

impl BoundedHttpsTransport for BoundaryTokenTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        self.sent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((request.method.clone(), request.url.clone()));
        let (status, body) = match request.url.as_str() {
            "https://api.openai.com/v1/chat/completions" => (
                401,
                r#"{"error":{"type":"authentication_error","code":"invalid_token","message":"provider rejected access"}}"#,
            ),
            "https://api.openai.com/oauth/token" => {
                self.trigger(context);
                (
                    200,
                    r#"{"access_token":"SYNTHETIC_REPLACEMENT_ACCESS","token_type":"Bearer","expires_in":3600}"#,
                )
            }
            _ => {
                return Err(OAuthError::Transport {
                    message: "unexpected tracer URL".to_string(),
                });
            }
        };
        Ok(RawHttpsResponse {
            status,
            headers: BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: body.as_bytes().to_vec(),
        })
    }
}

fn compile_provider_runtime_vm() -> (Vm, Arc<rustscript_vm::HostApiCatalog>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/provider_runtime.rss");
    let source = fs::read_to_string(&path).expect("production provider_runtime RSS");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile production provider_runtime against the real auth catalog");
    (Vm::new_shared(Arc::new(compiled.program)), catalog)
}

fn bind_provider_runtime_vm(
    mut vm: Vm,
    catalog: &rustscript_vm::HostApiCatalog,
    host: &AuthHost,
) -> Vm {
    let mut registry = HostFunctionRegistry::restricted();
    host.register(&mut registry, catalog)
        .expect("register real auth host catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted native registry");
    assert!(matches!(
        vm.run().expect("run production RSS root"),
        VmStatus::Halted
    ));
    vm
}

fn vm_record(entries: Vec<(&str, VmValue)>) -> VmValue {
    VmValue::map(
        entries
            .into_iter()
            .map(|(key, value)| (VmValue::string(key), value))
            .collect(),
    )
}

fn vm_field<'a>(value: &'a VmValue, name: &str) -> &'a VmValue {
    let VmValue::Map(entries) = value else {
        panic!("expected native VM record")
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            VmValue::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native VM field {name}"))
}

fn provider_intent() -> VmValue {
    vm_record(vec![
        ("credential_id", VmValue::string(ID)),
        ("method", VmValue::string("POST")),
        ("path", VmValue::string("/v1/chat/completions")),
        (
            "public_headers",
            VmValue::array(vec![
                vm_record(vec![
                    ("name", VmValue::string("accept")),
                    ("value", VmValue::string("application/json")),
                ]),
                vm_record(vec![
                    ("name", VmValue::string("content-type")),
                    ("value", VmValue::string("application/json")),
                ]),
            ]),
        ),
        ("public_body", VmValue::string(FLAGS_MODEL_BODY)),
    ])
}

fn assert_provider_failure_boundary(boundary: NativeFailureBoundary, label: &str) {
    let (vm, catalog) = compile_provider_runtime_vm();
    let home = FixtureHome::for_profile(label, "openai", "https://api.openai.com/v1", ID, OLD);
    let timeout = if matches!(boundary, NativeFailureBoundary::Deadline) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(30)
    };
    let cancellation = RunCancellation::with_timeout(timeout);
    let transport = Arc::new(BoundaryTokenTransport::new(boundary, cancellation.clone()));
    let host = Arc::new(
        home.auth_factory(transport.clone())(cancellation.clone()).expect("real fixture AuthHost"),
    );
    transport.set_revoke_target(Arc::downgrade(&host));
    let before = home.stored_auth();
    let mut vm = bind_provider_runtime_vm(vm, catalog.as_ref(), &host);
    let bound = host.bind_vm(&mut vm).expect("bind public native owner");
    let call = vm
        .resolve_exported_callable("call__m0")
        .expect("production provider_runtime::call export after module-name disambiguation");
    let result = vm
        .invoke_callable(
            call,
            &[
                vm_record(vec![("home", vm_field(&bound, "host_home").clone())]),
                provider_intent(),
            ],
        )
        .expect("invoke real provider_runtime::call");

    assert_eq!(vm_field(&result, "ok"), &VmValue::Bool(false));
    let error = vm_field(&result, "error");
    assert_eq!(vm_field(error, "code"), &VmValue::string("policy_inactive"));
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        2,
        "one model request and one token request only"
    );
    assert_eq!(
        sent[0],
        (
            "POST".to_string(),
            "https://api.openai.com/v1/chat/completions".to_string()
        )
    );
    assert_eq!(
        sent[1],
        (
            "POST".to_string(),
            "https://api.openai.com/oauth/token".to_string()
        )
    );
    assert!(
        home.stored_auth() == before,
        "failed token send must not save credentials"
    );
    let public = vm_value_to_json(&result).to_string();
    for secret in [
        OLD,
        "SYNTHETIC_REPLACEMENT_ACCESS",
        "SYNTHETIC_REFRESH_TOKEN",
    ] {
        assert!(
            !public.contains(secret),
            "private token appeared in public result"
        );
    }
    let (cancelled, deadline_exceeded, revoked) = match boundary {
        NativeFailureBoundary::Cancellation => (true, false, false),
        NativeFailureBoundary::Deadline => (false, true, false),
        NativeFailureBoundary::Revocation => (false, false, true),
    };
    assert_eq!(
        vm_field(error, "cancelled"),
        &VmValue::Bool(cancelled),
        "{boundary:?}"
    );
    assert_eq!(
        vm_field(error, "deadline_exceeded"),
        &VmValue::Bool(deadline_exceeded),
        "{boundary:?}"
    );
    assert_eq!(
        vm_field(error, "revoked"),
        &VmValue::Bool(revoked),
        "{boundary:?}"
    );
}

#[test]
fn production_provider_call_preserves_native_cancel_during_token_send() {
    assert_provider_failure_boundary(NativeFailureBoundary::Cancellation, "flags-cancel");
}

#[test]
fn production_provider_call_preserves_native_deadline_during_token_send() {
    assert_provider_failure_boundary(NativeFailureBoundary::Deadline, "flags-deadline");
}

#[test]
fn production_provider_call_preserves_native_revocation_during_token_send() {
    assert_provider_failure_boundary(NativeFailureBoundary::Revocation, "flags-revocation");
}

const NEW: &str = "SYNTHETIC_REPLACEMENT_ACCESS";
#[test]
fn valid_oauth_model_401_refreshes_once_and_retries_same_request() {
    let home =
        FixtureHome::for_profile("model-401", "openai", "https://api.openai.com/v1", ID, OLD);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(401, json!({"error": {"type": "authentication_error", "code": "invalid_token", "message": "provider rejected access"}}));
    transport.push_json(
        200,
        json!({"access_token": NEW, "token_type": "Bearer", "expires_in": 3600}),
    );
    transport.push_json(200, completed());
    let decision = real_loop(&home, transport.clone());
    let sent = transport.take_sent();
    assert_eq!(
        sent.get(1).map(|r| r.url.as_str()),
        Some("https://api.openai.com/oauth/token"),
        "401 must trigger token request inside the same provider call; public decision: {decision}"
    );
    assert_eq!(
        decision["kind"],
        json!("run.completed"),
        "public decision: {decision}"
    );
    assert_eq!(decision["answer"], json!("completed answer"));
    assert_eq!(decision["turn"], json!(1));
    assert_eq!(
        decision["retry_count"],
        json!(0),
        "internal auth retry does not advance outer retry state"
    );
    assert_eq!(sent.len(), 3, "model, token, model exactly once each");
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(sent[2].url, sent[0].url);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[2].method, sent[0].method);
    assert_eq!(
        sent[0].body, sent[2].body,
        "same public model intent and history"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&sent[2].body).expect("public wire")["model"],
        json!("requested-model")
    );
    assert!(
        sent[0]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {OLD}"))
    );
    assert!(
        sent[2]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {NEW}"))
    );
    assert!(sent[1].body.contains("grant_type=refresh_token"));
    let persisted = home.stored_auth();
    assert_eq!(persisted["credentials"][ID]["generation"].as_i64(), Some(5));
    assert!(persisted["credentials"][ID]["access_token"].as_str() == Some(NEW));
    for secret in [OLD, NEW, "SYNTHETIC_REFRESH_TOKEN"] {
        assert!(!decision.to_string().contains(secret));
        assert!(!sent[0].body.contains(secret));
        assert!(!sent[2].body.contains(secret));
    }
}

fn model_unauthorized() -> Value {
    json!({"error": {"type": "authentication_error", "code": "invalid_token", "message": "provider rejected access"}})
}

fn assert_public_failure(decision: &Value, code: &str) {
    assert_eq!(
        decision["kind"],
        json!("run.failed"),
        "public decision: {decision}"
    );
    assert_eq!(
        decision["error"]["code"],
        json!(code),
        "public decision: {decision}"
    );
    assert_eq!(
        decision["retry_count"],
        json!(0),
        "no outer retry: {decision}"
    );
    for secret in [OLD, NEW, "SYNTHETIC_REFRESH_TOKEN"] {
        assert!(!decision.to_string().contains(secret));
    }
}

#[test]
fn repeated_oauth_401_stops_after_one_refresh_and_model_retry() {
    let home = FixtureHome::for_profile(
        "repeated-401",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(401, model_unauthorized());
    transport.push_json(
        200,
        json!({"access_token": NEW, "token_type": "Bearer", "expires_in": 3600}),
    );
    transport.push_json(401, model_unauthorized());

    let decision = real_loop(&home, transport.clone());
    assert_public_failure(&decision, "reauth_required");
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 3, "one model, one refresh, one retried model");
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(sent[1].url, "https://api.openai.com/oauth/token");
    assert_eq!(sent[2].url, sent[0].url);
    assert_eq!(sent[0].body, sent[2].body);
    let persisted = home.stored_auth();
    assert_ne!(persisted, before, "the accepted refresh is persisted once");
    assert_eq!(persisted["credentials"][ID]["generation"].as_i64(), Some(5));
    assert_eq!(
        persisted["credentials"][ID]["access_token"].as_str(),
        Some(NEW)
    );
    assert_eq!(
        persisted["credentials"][ID]["refresh_token"].as_str(),
        Some("SYNTHETIC_REFRESH_TOKEN")
    );
}

#[test]
fn preflight_refreshed_oauth_401_does_not_refresh_again() {
    let home = FixtureHome::for_profile(
        "preflight-401",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    )
    .with_expiry(ID, 1_899_999_999_999);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"access_token": NEW, "refresh_token": "SYNTHETIC_ROTATED_REFRESH", "token_type": "Bearer", "expires_in": 3600}));
    transport.push_json(401, model_unauthorized());

    let decision = real_loop(&home, transport.clone());
    assert_public_failure(&decision, "reauth_required");
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        2,
        "preflight refresh and one model request only"
    );
    assert_eq!(sent[0].url, "https://api.openai.com/oauth/token");
    assert_eq!(sent[1].url, "https://api.openai.com/v1/chat/completions");
    assert!(
        sent[1]
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {NEW}"))
    );
    let persisted = home.stored_auth();
    assert_eq!(persisted["credentials"][ID]["generation"].as_i64(), Some(5));
    assert_eq!(
        persisted["credentials"][ID]["access_token"].as_str(),
        Some(NEW)
    );
    assert_eq!(
        persisted["credentials"][ID]["refresh_token"].as_str(),
        Some("SYNTHETIC_ROTATED_REFRESH")
    );
}

#[test]
fn invalid_grant_after_model_401_requires_reauthentication_without_save() {
    let home = FixtureHome::for_profile(
        "invalid-grant-401",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(401, model_unauthorized());
    transport.push_json(
        400,
        json!({"error": "invalid_grant", "error_description": "private refresh description"}),
    );

    let decision = real_loop(&home, transport.clone());
    assert_public_failure(&decision, "reauth_required");
    assert!(!decision.to_string().contains("private refresh description"));
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        2,
        "one model and one rejected refresh; no model retry"
    );
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(sent[1].url, "https://api.openai.com/oauth/token");
    assert_eq!(
        home.stored_auth(),
        before,
        "rejected refresh leaves persistence unchanged"
    );
}

#[test]
fn malformed_refresh_after_model_401_preserves_refresh_response_failure_code() {
    let home = FixtureHome::for_profile(
        "malformed-401",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(401, model_unauthorized());
    transport.push_json(200, json!({"token_type": "Bearer", "expires_in": 3600}));

    let decision = real_loop(&home, transport.clone());
    assert_public_failure(&decision, "refresh_response_invalid");
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        2,
        "one model and one malformed refresh; no model retry"
    );
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(sent[1].url, "https://api.openai.com/oauth/token");
    assert_eq!(
        home.stored_auth(),
        before,
        "malformed refresh leaves persistence unchanged"
    );
}

#[test]
fn missing_refresh_token_after_model_401_requires_reauthentication_without_token_send() {
    let home = FixtureHome::for_profile(
        "missing-refresh-401",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    )
    .without_refresh_token(ID);
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(401, model_unauthorized());

    let decision = real_loop(&home, transport.clone());
    assert_public_failure(&decision, "reauth_required");
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "missing refresh token prevents token and model retries"
    );
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(home.stored_auth(), before);
}

#[test]
fn api_key_401_keeps_native_http_classification_without_oauth_retry() {
    let home = FixtureHome::for_profile(
        "api-key-401",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    )
    .with_api_key(ID);
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(401, model_unauthorized());

    let decision = real_loop(&home, transport.clone());
    assert_public_failure(&decision, "http_error");
    assert_eq!(decision["error"]["status"], json!(401));
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "API-key rejection sends no token request or retry"
    );
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(home.stored_auth(), before);
}

#[test]
fn unrelated_oauth_403_keeps_native_http_classification_without_refresh() {
    let home = FixtureHome::for_profile(
        "unrelated-403",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    );
    let before = home.stored_auth();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(403, json!({"error": {"type": "permission_error", "code": "access_denied", "message": "Synthetic permission denial"}}));

    let decision = real_loop(&home, transport.clone());
    assert_public_failure(&decision, "http_error");
    assert_eq!(decision["error"]["status"], json!(403));
    assert_eq!(decision["error"]["type"], json!("permission_error"));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "403 sends no token request or model retry");
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(home.stored_auth(), before);
    assert!(!decision.to_string().contains("access_denied"));
}
