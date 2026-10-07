#![cfg(feature = "config-fixture")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::{
    host::AuthHost,
    oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    },
};
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, CancellationReason, RunCancellation, RunEventSink,
    runtime::rss_runner::RunDeliveryError,
};
use rustscript_vm::Value;
use serde_json::json;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new(generation: u64) -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let home = root.join(format!("opaque-bridge-home-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create private fixture home");
        #[cfg(unix)]
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), home.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1900003600000")
            .replace("generation: 4", &format!("generation: {generation}"));
        fs::write(home.join("auth.yaml"), auth).expect("write private auth fixture");
        #[cfg(unix)]
        for name in ["config.yaml", "auth.yaml"] {
            fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                .expect("fixture file mode");
        }
        Self(home)
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ModuleTree(PathBuf);

impl ModuleTree {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let tree = root.join(format!("opaque-bridge-modules-{}", uuid::Uuid::new_v4()));
        let agent = tree.join("rss/agent");
        let providers = tree.join("rss/providers");
        fs::create_dir_all(&agent).expect("create agent module directory");
        fs::create_dir_all(&providers).expect("create provider module directory");
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fs::copy(
            repo.join("tests/fixtures/provider_bridge/main.rss"),
            agent.join("main.rss"),
        )
        .expect("copy fixture driver");
        fs::copy(
            repo.join("rss/agent/provider_runtime.rss"),
            agent.join("provider_runtime.rss"),
        )
        .expect("copy checked-in provider runtime helper");
        fs::copy(
            repo.join("rss/providers/opaque_bridge.rss"),
            providers.join("opaque_bridge.rss"),
        )
        .expect("copy checked-in opaque bridge helper");
        Self(tree)
    }

    fn entry(&self) -> PathBuf {
        self.0.join("rss/agent/main.rss")
    }
}

impl Drop for ModuleTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_runner(
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
    cancellation: Option<RunCancellation>,
) -> AgentRunner {
    let modules = ModuleTree::new();
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let home_path = home.0.clone();
    let factory = Arc::new(move |cancellation: RunCancellation| {
        AuthHost::new(home_path.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    });
    let bridges = AgentHostBridges {
        auth_host_factory: Some(factory),
        ..AgentHostBridges::default()
    };
    let mut runner = AgentRunner::from_file(modules.entry(), AgentConfig::default())
        .expect("compile fixture driver and checked-in RSS helpers")
        .with_host(bridges);
    if let Some(cancellation) = cancellation {
        runner = runner.with_cancellation(cancellation);
    }
    // AgentRunner::from_file compiles the module tree before returning.
    drop(modules);
    runner
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected public response map")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing public field {name}"))
}

fn string_context(fields: &[(&str, &str)]) -> Value {
    Value::map(
        fields
            .iter()
            .map(|(name, value)| (Value::string(*name), Value::string(*value)))
            .collect(),
    )
}

#[derive(Default)]
struct EventCapture(Vec<Value>);

impl RunEventSink for EventCapture {
    fn deliver(&mut self, value: Value) -> Result<(), RunDeliveryError> {
        self.0.push(value);
        Ok(())
    }
}

#[test]
fn agent_runner_uses_metadata_selected_access_handle_and_native_buffered_transport() {
    let home = FixtureHome::new(9);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        200,
        json!({
            "access_token": "SYNTHETIC_RESPONSE_ACCESS",
            "refresh_token": "SYNTHETIC_RESPONSE_REFRESH",
            "public": "accepted"
        }),
    );
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let runner = fixture_runner(&home, Arc::clone(&transport), Some(cancellation.clone()));
    let mut events = EventCapture::default();
    let result = runner
        .run_with_context_and_events(Value::map(vec![]), &mut events, &cancellation)
        .expect("same-VM RSS transport");

    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(field(&result, "error_code"), &Value::string(""));
    assert_eq!(field(&result, "cancelled"), &Value::Bool(false));
    assert_eq!(field(&result, "deadline_exceeded"), &Value::Bool(false));
    assert_eq!(field(&result, "revoked"), &Value::Bool(false));
    assert_eq!(field(&result, "status"), &Value::Int(200));
    assert_eq!(
        field(&result, "body"),
        &Value::string(r#"{"public":"accepted"}"#)
    );
    assert_eq!(field(&result, "retry_after_ms"), &Value::Int(0));
    let rendered = format!("{result:?}{:?}", events.0);
    for secret in [
        "SYNTHETIC_ACCESS_TOKEN",
        "SYNTHETIC_REFRESH_TOKEN",
        "SYNTHETIC_RESPONSE_ACCESS",
        "SYNTHETIC_RESPONSE_REFRESH",
        "fixture-codex",
    ] {
        assert!(!rendered.contains(secret), "public output leaked {secret}");
    }
    assert!(events.0.is_empty(), "the transport tracer emits no events");

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, "https://auth.openai.com/oauth/token");
    assert_eq!(sent[0].method, "GET");
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_ACCESS_TOKEN")
    );
    assert_eq!(
        sent[0].headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    assert!(!format!("{:?}", sent[0]).contains("SYNTHETIC_ACCESS_TOKEN"));
}

#[test]
fn native_path_denial_sends_nothing_and_returns_only_public_fallback() {
    let home = FixtureHome::new(9);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let runner = fixture_runner(&home, Arc::clone(&transport), Some(cancellation.clone()));
    let mut events = EventCapture::default();
    let result = runner
        .run_with_context_and_events(
            string_context(&[("path", "/outside-policy")]),
            &mut events,
            &cancellation,
        )
        .expect("native path denial returns a public native failure");
    assert_eq!(field(&result, "ok"), &Value::Bool(false));
    assert_eq!(field(&result, "error_code"), &Value::string("path_denied"));
    assert_eq!(field(&result, "cancelled"), &Value::Bool(false));
    assert_eq!(field(&result, "deadline_exceeded"), &Value::Bool(false));
    assert_eq!(field(&result, "revoked"), &Value::Bool(false));
    assert_eq!(field(&result, "status"), &Value::Int(0));
    assert_eq!(field(&result, "body"), &Value::string(""));
    assert_eq!(field(&result, "retry_after_ms"), &Value::Int(0));
    assert!(events.0.is_empty());
    assert!(transport.take_sent().is_empty());
}

#[test]
fn native_header_denial_sends_nothing_and_returns_only_public_fallback() {
    let home = FixtureHome::new(9);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let runner = fixture_runner(&home, Arc::clone(&transport), Some(cancellation.clone()));
    let mut events = EventCapture::default();
    let result = runner
        .run_with_context_and_events(
            string_context(&[("header_name", "authorization")]),
            &mut events,
            &cancellation,
        )
        .expect("native header denial returns a public native failure");

    assert_eq!(field(&result, "ok"), &Value::Bool(false));
    assert_eq!(
        field(&result, "error_code"),
        &Value::string("header_denied")
    );
    assert_eq!(field(&result, "cancelled"), &Value::Bool(false));
    assert_eq!(field(&result, "deadline_exceeded"), &Value::Bool(false));
    assert_eq!(field(&result, "revoked"), &Value::Bool(false));
    assert_eq!(field(&result, "status"), &Value::Int(0));
    assert_eq!(field(&result, "body"), &Value::string(""));
    assert_eq!(field(&result, "retry_after_ms"), &Value::Int(0));
    assert!(events.0.is_empty());
    assert!(transport.take_sent().is_empty());
}

#[test]
fn unknown_credential_is_denied_before_native_send() {
    let home = FixtureHome::new(9);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let runner = fixture_runner(&home, Arc::clone(&transport), Some(cancellation.clone()));
    let mut events = EventCapture::default();
    let result = runner.run_with_context_and_events(
        string_context(&[("credential_id", "unknown-credential")]),
        &mut events,
        &cancellation,
    );

    let result = result.expect("unknown credential returns a public native failure");
    assert_eq!(field(&result, "ok"), &Value::Bool(false));
    assert_eq!(
        field(&result, "error_code"),
        &Value::string("credential_not_admitted")
    );
    assert_eq!(field(&result, "cancelled"), &Value::Bool(false));
    assert_eq!(field(&result, "deadline_exceeded"), &Value::Bool(false));
    assert_eq!(field(&result, "revoked"), &Value::Bool(false));
    assert!(events.0.is_empty());
    assert!(transport.take_sent().is_empty());
}

#[test]
fn canceled_or_expired_run_is_denied_before_native_send() {
    for cancellation in [
        {
            let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
            cancellation.request(CancellationReason::Requested);
            cancellation
        },
        RunCancellation::with_timeout(Duration::ZERO),
    ] {
        let home = FixtureHome::new(9);
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let runner = fixture_runner(&home, Arc::clone(&transport), Some(cancellation.clone()));
        let mut events = EventCapture::default();
        let result =
            runner.run_with_context_and_events(Value::map(vec![]), &mut events, &cancellation);

        assert!(result.is_err());
        assert!(events.0.is_empty());
        assert!(transport.take_sent().is_empty());
    }
}
