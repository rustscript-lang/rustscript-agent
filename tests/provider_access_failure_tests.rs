//! Real default-RSS adoption of the fallible access result.
//!
//! A stored credential that is still readable but past its access lifetime
//! must surface the canonical public `access_unavailable` result without any
//! native transport, while a valid credential keeps producing the existing
//! authenticated canonical OpenAI Chat result.

#![cfg(feature = "config-fixture")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::{
    host::{AuthHost, auth_host_catalog},
    oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    },
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use serde_json::{Value as JsonValue, json};

/// Clearly past UNIX-millisecond expiry: the real store clock always treats it
/// as an exhausted access lifetime.
const PAST_EXPIRY_MS: &str = "1000000000000";
/// Clearly future UNIX-millisecond expiry (2030-03): a healthy access lifetime.
const FUTURE_EXPIRY_MS: &str = "1900003600000";

const ACCESS_MARKER: &str = "SYNTHETIC_OPENAI_ACCESS";
const REFRESH_MARKER: &str = "SYNTHETIC_REFRESH_TOKEN";

/// Outer RSS entry: forward the public request through the production bridge.
/// The default provider (not an injected one) handles dispatch.
const OUTER_SOURCE: &str = r#"
use agent;
pub fn run(context: map) -> map {
    let request: map = context["request"];
    agent::provider_call(request)
}
"#;

/// Real RSS probe that reads native metadata and issues an access handle
/// through the actual restricted auth catalog.
const METADATA_PROBE_SOURCE: &str = r#"
use auth;
use config;

struct MetadataPresence {
    metadata: AuthMetadataEnvelope?
}

pub fn run(home: resource<auth.host_home>, credential_id: string) -> map {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    let policy: resource<auth.policy> = snapshot.policy_handle;
    let loaded: AuthMetadataResultEnvelope = auth::load_metadata_result(credential_id, &policy);
    let loaded_ok: bool = loaded.ok;
    let loaded_error: AuthBridgeFailure? = loaded.error;
    let holder: MetadataPresence = { metadata: loaded.value };
    let metadata_present: bool = holder.has("metadata");
    let mut generation: int = 0;
    let mut status: string = "";
    let mut meta_ok: bool = false;
    if metadata_present {
        let envelope: AuthMetadataEnvelope = holder.metadata;
        let meta: AuthMetadata = envelope.metadata;
        generation = meta.generation;
        status = meta.status;
        meta_ok = envelope.ok;
    }
    let issued: AccessHandleResultEnvelope = auth::access_handle_result(credential_id, generation, &policy);
    let issued_ok: bool = issued.ok;
    let maybe_issue_error: AuthBridgeFailure? = issued.error;
    let mut issue_error_present: bool = false;
    let mut issued_error_code: string = "";
    if maybe_issue_error != null {
        let failure: AuthBridgeFailure = maybe_issue_error;
        issued_error_code = failure.code;
        issue_error_present = true;
    }
    {
        snapshot_ok: snapshot.ok,
        metadata_ok: loaded_ok,
        metadata_error_present: loaded_error != null,
        metadata_present: metadata_present,
        metadata_envelope_ok: meta_ok,
        metadata_generation: generation,
        metadata_status: status,
        issued_ok: issued_ok,
        issued_error_present: issue_error_present,
        issued_error_code: issued_error_code
    }
}
"#;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss")
}

fn synthetic_config() -> String {
    fs::read_to_string(fixture_dir().join("config.yaml"))
        .expect("read config fixture")
        .replace("openai-codex", "openai")
        .replace(
            "https://chatgpt.com/backend-api/codex",
            "https://api.openai.com/v1",
        )
        .replace("fixture-codex", "synthetic-openai")
}

fn synthetic_auth(expiry_ms: &str) -> String {
    fs::read_to_string(fixture_dir().join("auth.yaml"))
        .expect("read auth fixture")
        .replace("1788440000000", expiry_ms)
        .replace("openai-codex", "openai")
        .replace("fixture-codex", "synthetic-openai")
        .replace("SYNTHETIC_ACCESS_TOKEN", ACCESS_MARKER)
}

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new(expiry_ms: &str) -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let home = root.join(format!("provider-access-failure-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create private fixture home");
        fs::write(home.join("config.yaml"), synthetic_config()).expect("write private config");
        fs::write(home.join("auth.yaml"), synthetic_auth(expiry_ms)).expect("write private auth");
        #[cfg(unix)]
        {
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        Self(home)
    }

    /// Controlled synthetic credential repair: rewrite only the stored expiry.
    fn set_expiry(&self, expiry_ms: &str) {
        fs::write(self.0.join("auth.yaml"), synthetic_auth(expiry_ms))
            .expect("rewrite private auth expiry");
        #[cfg(unix)]
        fs::set_permissions(self.0.join("auth.yaml"), fs::Permissions::from_mode(0o600))
            .expect("restore private file mode");
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_factory(
    home: &FixtureHome,
    transport: Arc<dyn rustscript_agent::auth::oauth::BoundedHttpsTransport>,
) -> Arc<dyn Fn(RunCancellation) -> Result<AuthHost, String> + Send + Sync> {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let home_path = home.0.clone();
    Arc::new(move |cancellation: RunCancellation| {
        AuthHost::new(home_path.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    })
}

/// Outer runner with a native auth host factory and no injected provider.
fn outer_runner(
    home: &FixtureHome,
    transport: Arc<dyn rustscript_agent::auth::oauth::BoundedHttpsTransport>,
    cancellation: RunCancellation,
) -> AgentRunner {
    let bridges = AgentHostBridges {
        auth_host_factory: Some(fixture_factory(home, transport)),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_source(OUTER_SOURCE, AgentConfig::default())
        .expect("compile outer provider bridge source")
        .with_host(bridges)
        .with_cancellation(cancellation)
}

fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite JSON number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => {
            Value::Array(Arc::new(values.iter().map(json_to_vm_value).collect()))
        }
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

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
                .filter_map(|(key, value)| match key {
                    Value::String(key) => Some((key.to_string(), vm_value_to_json(value))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn public_request() -> JsonValue {
    json!({
        "provider": "openai",
        "model": "request-model",
        "stream": false,
        "credential_id": "synthetic-openai",
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": "hello access adoption"}]
        }],
        "tools": [{
            "name": "lookup",
            "description": "Look something up",
            "schema_json": "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}}}"
        }],
        "sampling": {"temperature": 0.25},
        "max_output_tokens": 64
    })
}

fn context(request: JsonValue) -> Value {
    Value::map(vec![(Value::string("request"), json_to_vm_value(&request))])
}

fn finite() -> RunCancellation {
    RunCancellation::with_timeout(Duration::from_secs(30))
}

/// One canonical OpenAI Chat completion with usage and a tool call.
fn canonical_chat_body() -> JsonValue {
    json!({
        "id": "chatcmpl-access",
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": "Found one match.",
                "tool_calls": [{
                    "id": "call_access",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"query\":\"rustscript\"}"}
                }]
            }
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
    })
}

fn assert_no_secret_leak(rendered: &str) {
    for secret in [ACCESS_MARKER, REFRESH_MARKER, "SYNTHETIC_RESPONSE_ACCESS"] {
        assert!(!rendered.contains(secret), "public output leaked {secret}");
    }
}

#[test]
fn default_provider_expired_credential_is_access_unavailable_without_send() {
    let home = FixtureHome::new(PAST_EXPIRY_MS);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = outer_runner(&home, transport.clone(), finite());

    let result = vm_value_to_json(
        &runner
            .run_with_context(context(public_request()))
            .expect("expired stored credential returns a canonical public result"),
    );

    assert_eq!(
        result["ok"],
        json!(false),
        "expired access must not report success: {result}"
    );
    assert_eq!(
        result["error"]["code"],
        json!("access_unavailable"),
        "expired stored credential must surface the canonical access code: {result}"
    );
    assert!(
        transport.take_sent().is_empty(),
        "expired access must not reach the native transport"
    );
    assert_no_secret_leak(&result.to_string());
}

#[test]
fn default_provider_valid_credential_is_authenticated_control() {
    let home = FixtureHome::new(FUTURE_EXPIRY_MS);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, canonical_chat_body());
    let runner = outer_runner(&home, transport.clone(), finite());

    let result = vm_value_to_json(
        &runner
            .run_with_context(context(public_request()))
            .expect("valid stored credential completes the default dispatch"),
    );

    assert_eq!(result["ok"], json!(true), "control result: {result}");
    assert_eq!(result["response"]["text"], json!("Found one match."));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(3));
    assert_eq!(result["response"]["usage"]["output_tokens"], json!(4));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));
    assert_eq!(
        result["response"]["tool_calls"][0]["id"],
        json!("call_access")
    );
    assert_eq!(result["response"]["tool_calls"][0]["name"], json!("lookup"));
    assert_eq!(
        result["response"]["tool_calls"][0]["arguments"]["query"],
        json!("rustscript")
    );

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one authenticated native send");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].url, "https://api.openai.com/v1/chat/completions",
        "the trusted authority must win"
    );
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {ACCESS_MARKER}").as_str())
    );
    assert_no_secret_leak(&result.to_string());
}

#[test]
fn default_provider_recovers_after_synthetic_credential_expiry_repair() {
    let home = FixtureHome::new(PAST_EXPIRY_MS);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, canonical_chat_body());
    let runner = outer_runner(&home, transport.clone(), finite());

    let failed = vm_value_to_json(
        &runner
            .run_with_context(context(public_request()))
            .expect("expired invocation returns a canonical public result"),
    );
    assert_eq!(failed["ok"], json!(false), "expired run: {failed}");
    assert_eq!(failed["error"]["code"], json!("access_unavailable"));
    assert!(
        transport.take_sent().is_empty(),
        "the failed invocation must not send"
    );

    // Controlled repair of the synthetic stored expiry, then the same runner.
    home.set_expiry(FUTURE_EXPIRY_MS);
    let recovered = vm_value_to_json(
        &runner
            .run_with_context(context(public_request()))
            .expect("repaired invocation completes"),
    );
    assert_eq!(
        recovered["ok"],
        json!(true),
        "the prior expiry failure must not persist as a caller failure: {recovered}"
    );
    assert_eq!(recovered["response"]["text"], json!("Found one match."));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "only the repaired invocation sends");
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {ACCESS_MARKER}").as_str())
    );
    assert_no_secret_leak(&failed.to_string());
    assert_no_secret_leak(&recovered.to_string());
}

#[test]
fn expired_credential_metadata_reads_as_active_generation4_via_real_rss() {
    let home = FixtureHome::new(PAST_EXPIRY_MS);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let host = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("native auth host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let catalog = auth_host_catalog();
    let mut vm = probe_vm(catalog.as_ref());
    let context = host.bind_vm(&mut vm).expect("bind native owner");
    let output = invoke(
        &mut vm,
        "run",
        &[
            vm_field(&context, "host_home").clone(),
            Value::string("synthetic-openai"),
        ],
    )
    .expect("real RSS metadata and access-issuance probe");
    let output = vm_value_to_json(&output);

    assert_eq!(
        output["snapshot_ok"],
        json!(true),
        "policy snapshot: {output}"
    );
    assert_eq!(
        output["metadata_ok"],
        json!(true),
        "expired credential metadata must still be readable: {output}"
    );
    assert_eq!(
        output["metadata_present"],
        json!(true),
        "metadata envelope value must be present: {output}"
    );
    assert_eq!(
        output["metadata_generation"],
        json!(4),
        "stored generation stays unchanged: {output}"
    );
    assert_eq!(
        output["metadata_status"],
        json!("active"),
        "stored status stays unchanged: {output}"
    );
    assert_eq!(
        output["issued_ok"],
        json!(false),
        "expired access issuance must fail: {output}"
    );
    assert_eq!(
        output["issued_error_code"],
        json!("access_unavailable"),
        "issuance must report the canonical access code: {output}"
    );
    assert!(transport.take_sent().is_empty(), "issuance sends nothing");
}

fn probe_vm(catalog: &rustscript_vm::HostApiCatalog) -> Vm {
    let root = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
    );
    let dir = root.join(format!("provider-access-probe-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create probe module directory");
    let path = dir.join("main.rss");
    fs::write(&path, METADATA_PROBE_SOURCE).expect("write probe source");
    let source = fs::read_to_string(&path).expect("read probe source");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::new(catalog.clone())),
    )
    .expect("compile real RSS probe against the exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = FixtureHome::new(FUTURE_EXPIRY_MS);
    AuthHost::new(
        registration_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host")
    .register(&mut registry, catalog)
    .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, rustscript_vm::VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

fn vm_field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected RSS record, got {value:?}")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RSS field {name} in {value:?}"))
}
