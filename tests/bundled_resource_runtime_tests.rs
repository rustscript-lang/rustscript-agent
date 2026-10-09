//! Actual bundled-resource runtime consumers.
//!
//! These tests drive the REAL production consumers of the embedded bundled
//! catalog: the coding-agent `rss/agent/main.rss` loop through a scripted
//! provider, the default provider dispatcher with an injected native auth
//! host, and the typed SQLite storage worker. Everything runs through the
//! production `AgentRunner` bundled entry points; no fake result is injected.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::{
    host::AuthHost,
    oauth::{
        BoundedHttpsTransport, OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel,
        ScriptedClock, ScriptedHttpsTransport,
    },
};
use rustscript_agent::{
    AgentConfig, AgentGatewayConfig, AgentHostBridges, AgentRunner, GatewayPersistence,
    RunCancellation, RunError, ScriptedProvider, bundled_tool_registry,
};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

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
        JsonValue::Array(values) => Value::Array(
            values
                .iter()
                .map(json_to_vm_value)
                .collect::<Vec<_>>()
                .into(),
        ),
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

fn assigned_temp() -> PathBuf {
    let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(PathBuf::from)
        .expect("RUSTSCRIPT_AGENT_TEST_TMP must be assigned for these tests");
    fs::create_dir_all(&root).expect("create assigned test temp");
    root
}

// ---------------------------------------------------------------------------
// Vertical 1: bundled coding-agent Main loop with a scripted provider.
// ---------------------------------------------------------------------------

fn text_response(text: &str) -> JsonValue {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

fn loop_context() -> JsonValue {
    let identity = bundled_tool_registry()
        .expect("bundled RSS registry validates")
        .identity()
        .to_string();
    json!({
        "run_id": "run-bundled",
        "session_id": "session-bundled",
        "model": "bundled-model",
        "provider": "openai",
        "credential_id": "",
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": "hello bundled"}]
        }],
        "tools": [],
        "provider_options": {},
        "limits": {"max_turns": 3, "max_tool_calls": 8, "workspace_root": ""},
        "metadata": {"registry_identity": identity},
        "config": {
            "base_retry_delay_ms": 100,
            "max_retry_delay_ms": 400,
            "max_retries": 2,
            "parallel": false,
            "task": false
        }
    })
}

#[test]
fn bundled_main_runs_real_serial_loop_with_scripted_provider() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("bundled-answer"));
    let runner = AgentRunner::from_bundled("rss/agent/main.rss", AgentConfig::default())
        .expect("embedded coding-agent Main must compile")
        .with_provider(Arc::new(provider.clone()));

    let result = runner
        .run_with_context(json_to_vm_value(&loop_context()))
        .unwrap_or_else(|error| panic!("bundled Main loop failed: {error:?}"));
    let decision = vm_value_to_json(&result);

    assert_eq!(decision["kind"], json!("run.completed"), "{decision}");
    assert_eq!(decision["answer"], json!("bundled-answer"));
    assert_eq!(provider.call_count(), 1);
    let request = &provider.requests()[0];
    assert_eq!(request["model"], json!("bundled-model"));
    assert_eq!(request["provider"], json!("openai"));
    assert_eq!(request["messages"][0]["role"], json!("user"));
}

// ---------------------------------------------------------------------------
// Vertical 2: default provider dispatcher with injected native auth host.
// ---------------------------------------------------------------------------

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let home = assigned_temp().join(format!("bundled-home-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create private fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("read config fixture")
            .replace("openai-codex", "openai")
            .replace(
                "https://chatgpt.com/backend-api/codex",
                "https://api.openai.com/v1",
            )
            .replace("fixture-codex", "synthetic-openai");
        fs::write(home.join("config.yaml"), config).expect("write private config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900003600000")
            .replace("openai-codex", "openai")
            .replace("fixture-codex", "synthetic-openai")
            .replace("SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_OPENAI_ACCESS");
        fs::write(home.join("auth.yaml"), auth).expect("write private auth fixture");
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
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_factory(
    home: &FixtureHome,
    transport: Arc<dyn BoundedHttpsTransport>,
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

fn public_request() -> JsonValue {
    json!({
        "provider": "openai",
        "model": "request-model",
        "stream": false,
        "credential_id": "synthetic-openai",
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": "hello bundled dispatch"}]
        }],
        "tools": [],
        "max_output_tokens": 64,
        "provider_options": {
            "base_url": "http://127.0.0.1:1/must-not-be-used",
            "model": "hostile-public-model"
        }
    })
}

fn canonical_chat_body() -> JsonValue {
    json!({
        "id": "chatcmpl-bundled",
        "choices": [{
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "Bundled dispatch answer."}
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
    })
}

struct DiscardSink;

impl rustscript_agent::RunEventSink for DiscardSink {
    fn deliver(&mut self, _value: Value) -> Result<(), rustscript_agent::RunDeliveryError> {
        Ok(())
    }
}

#[test]
fn bundled_default_dispatcher_runs_with_injected_native_auth() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, canonical_chat_body());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let bridges = AgentHostBridges {
        auth_host_factory: Some(fixture_factory(&home, transport.clone())),
        ..AgentHostBridges::default()
    };
    let runner = AgentRunner::from_bundled_named(
        "rss/llm/provider_dispatch.rss",
        "dispatch",
        AgentConfig::default(),
    )
    .expect("embedded provider dispatcher must compile")
    .with_host(bridges)
    .with_cancellation(cancellation.clone());

    let context = json_to_vm_value(&json!({ "request": public_request() }));
    let result = runner
        .run_named_with_context_and_events("dispatch", context, &mut DiscardSink, &cancellation)
        .unwrap_or_else(|error| panic!("bundled dispatch failed: {error:?}"));
    let result = vm_value_to_json(&result);

    assert_eq!(result["ok"], json!(true), "{result}");
    assert_eq!(
        result["response"]["text"],
        json!("Bundled dispatch answer.")
    );
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native buffered request");
    assert_eq!(
        sent[0].url, "https://api.openai.com/v1/chat/completions",
        "native trusted authority must win over the public hostile base_url"
    );
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_OPENAI_ACCESS")
    );
    let rendered = result.to_string();
    for secret in [
        "SYNTHETIC_OPENAI_ACCESS",
        "host_home",
        "hostile-public-model",
    ] {
        assert!(
            !rendered.contains(secret),
            "result leaked {secret}: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// Vertical 3: bundled typed SQLite storage worker roundtrip in assigned temp.
// ---------------------------------------------------------------------------

#[test]
fn bundled_storage_worker_roundtrips_in_assigned_temp() {
    let dir = assigned_temp().join(format!("bundled-storage-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create storage dir");
    let db_path = dir.join("state.db");
    let config = AgentGatewayConfig::default();
    let persistence =
        GatewayPersistence::open(&config, &db_path).expect("bundled storage worker must open");

    let created = persistence
        .session_create(&json!({
            "id": "bundled-session",
            "profile": "gateway",
            "platform": "test",
            "account_id": "account-bundled",
            "chat_id": "chat-bundled",
            "thread_id": "",
            "user_id": "",
            "generation": 1,
            "system_prompt": "",
            "model": "bundled-model",
            "provider": "openai",
            "toolset_hash": "",
            "metadata_json": "{}",
            "title": "bundled",
            "end_reason": "",
            "now_ms": 4_000_000,
        }))
        .expect("bundled storage session.create");
    assert!(
        created.to_string().contains("bundled-session"),
        "session.create must persist the session: {created}"
    );

    let touched = persistence
        .session_touch(&json!({
            "session_id": "bundled-session",
            "status": "active",
            "generation": 1,
            "system_prompt": "",
            "model": "bundled-model",
            "provider": "openai",
            "toolset_hash": "",
            "metadata_json": "{}",
            "title": "bundled-touched",
            "end_reason": "",
            "now_ms": 4_000_001,
        }))
        .expect("bundled storage session.touch roundtrip");
    assert!(
        touched.to_string().contains("bundled-touched"),
        "session.touch must roundtrip the update: {touched}"
    );
    persistence.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Static, private bundled admission errors and exact-root entry binding.
// ---------------------------------------------------------------------------

#[test]
fn bundled_unknown_resource_is_static_and_never_echoes_the_key() {
    let key = "rss/does/not/exist.rss";
    let error = match AgentRunner::from_bundled(key, AgentConfig::default()) {
        Ok(_) => panic!("unknown bundled resource must be rejected"),
        Err(error) => error,
    };
    let rendered = error.to_string();
    assert!(
        !rendered.contains(key) && !rendered.contains("rss/"),
        "unknown-resource error must not echo the key: {rendered}"
    );
}

#[test]
fn bundled_invalid_export_is_static_and_rejected() {
    let export = "definitely_not_an_export";
    let error = match AgentRunner::from_bundled_named(
        "rss/tools/registry.rss",
        export,
        AgentConfig::default(),
    ) {
        Ok(_) => panic!("missing bundled export must be rejected"),
        Err(error) => error,
    };
    let rendered = error.to_string();
    assert!(
        !rendered.contains(export),
        "invalid-export error must not echo the export: {rendered}"
    );
}

#[test]
fn bundled_runner_binds_only_its_exact_logical_entry() {
    let runner = AgentRunner::from_bundled("rss/tools/registry.rss", AgentConfig::default())
        .expect("bundled registry runner must compile");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
    let error = runner
        .run_named_with_context_and_events(
            "a_sibling_entry",
            Value::map(vec![]),
            &mut DiscardSink,
            &cancellation,
        )
        .expect_err("a bundled runner must reject any non-origin entry");
    assert!(
        matches!(error, RunError::NoEntry),
        "unexpected error: {error:?}"
    );
}
