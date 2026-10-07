#![cfg(feature = "config-fixture")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

use rustscript_agent::auth::{
    host::AuthHost,
    oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    },
};
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, CancellationReason, RunCancellation,
};
use rustscript_vm::Value;
use serde_json::json;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let home = root.join(format!("task7-auth-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create private fixture home");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        }
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), home.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(home.join("auth.yaml"), auth).expect("copy auth fixture");
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

fn source() -> &'static str {
    r#"
use auth;
use config;
use oauth;
pub fn run(context: map) -> map {
    let home: resource<auth.host_home> = context["host_home"];
    let snapshot = config::load_snapshot(&home);
    let snapshot_ok: bool = snapshot.ok;
    let policy: resource<auth.policy> = snapshot.policy_handle;
    let metadata = auth::load_metadata("fixture-codex", &policy);
    let access = auth::access_handle("fixture-codex", 4, &policy);
    let access_ok: bool = access.ok;
    let request: TransportPublicRequest = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "GET",
        path: "/backend-api/codex/responses",
        public_headers: [],
        public_body: ""
    };
    let credential_use: TransportCredentialUse = {
        kind: "access",
        access_handle: access.handle,
        refresh_handle: null,
        code_handle: null,
        verifier_handle: null,
        device_handle: null
    };
    let response: TransportResultEnvelope = oauth::transport_result(&request, &credential_use);
    let transport_ok: bool = response.ok;
    let maybe_response: TransportResponseEnvelope? = response.value;
    let public_response: TransportResponseEnvelope = maybe_response.unwrap_or({
        ok: false, error: null, status: 0, public_headers: [],
        body_without_secret_fields: "", retry_after_ms: null,
        access_slot: null, refresh_slot: null, device_handle: null
    });
    {
        snapshot_ok: snapshot_ok,
        metadata_ok: metadata.ok,
        access_ok: access_ok,
        transport_ok: transport_ok,
        transport_error: response.error,
        status: public_response.status
    }
}
"#
}

fn fixture_runner(
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
    calls: Arc<AtomicUsize>,
) -> AgentRunner {
    let callback = Arc::new(ScriptedCallback::new());
    let browser = Arc::new(ScriptedBrowser::new());
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let oauth_cancel = Arc::new(ScriptedCancel::new());
    let oauth = Arc::new(OAuthHost::new(
        transport,
        callback,
        browser,
        clock,
        oauth_cancel,
    ));
    let home_path = home.0.clone();
    let factory = Arc::new(move |cancellation: RunCancellation| {
        calls.fetch_add(1, Ordering::SeqCst);
        AuthHost::new(home_path.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    });
    let bridges = AgentHostBridges {
        auth_host_factory: Some(factory),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_source(source(), AgentConfig::default())
        .expect("compile RSS runner")
        .with_host(bridges)
        .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("RSS result must be a map")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing public result field {name}"))
}

fn queue_responses(transport: &ScriptedHttpsTransport, count: usize) {
    for _ in 0..count {
        transport.push_json(200, json!({"id":"fixture-response","ok":true}));
    }
}

#[test]
fn runner_binds_native_owner_for_real_rss_snapshot_metadata_access_transport() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_responses(&transport, 1);
    let calls = Arc::new(AtomicUsize::new(0));
    let runner = fixture_runner(&home, Arc::clone(&transport), Arc::clone(&calls));
    let result = runner
        .run_with_context(Value::map(vec![]))
        .expect("RSS auth flow");
    assert_eq!(field(&result, "snapshot_ok"), &Value::Bool(true));
    assert_eq!(field(&result, "metadata_ok"), &Value::Bool(true));
    assert_eq!(field(&result, "access_ok"), &Value::Bool(true));
    assert_eq!(
        field(&result, "transport_ok"),
        &Value::Bool(true),
        "RSS result: {result:?}"
    );
    assert_eq!(field(&result, "status"), &Value::Int(200));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let injected = sent[0].headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization") && value == "Bearer SYNTHETIC_ACCESS_TOKEN"
    });
    assert!(
        injected,
        "final access credential must be injected only at native transport"
    );
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!rendered.contains("SYNTHETIC_REFRESH_TOKEN"));
}

#[test]
fn each_invocation_gets_a_fresh_owner_and_factory_absence_fails_closed() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_responses(&transport, 2);
    let calls = Arc::new(AtomicUsize::new(0));
    let runner = fixture_runner(&home, Arc::clone(&transport), Arc::clone(&calls));
    let barrier = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let runner = runner.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                runner
                    .run_with_context(Value::map(vec![]))
                    .expect("concurrent invocation")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for worker in workers {
        let result = worker.join().expect("runner thread");
        assert_eq!(field(&result, "transport_ok"), &Value::Bool(true));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(transport.take_sent().len(), 2);

    let no_factory_transport = Arc::new(ScriptedHttpsTransport::new());
    queue_responses(&no_factory_transport, 1);
    let absent = AgentRunner::from_source(source(), AgentConfig::default())
        .expect("compile without auth factory")
        .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)));
    assert!(absent.run_with_context(Value::map(vec![])).is_err());
    assert!(no_factory_transport.take_sent().is_empty());
}

#[test]
fn auth_binding_requires_and_shares_finite_cancellation() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let runner = fixture_runner(&home, Arc::clone(&transport), Arc::clone(&calls));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    cancellation.request(CancellationReason::Deadline);
    let error = runner
        .with_cancellation(cancellation)
        .run_with_context(Value::map(vec![]))
        .expect_err("request cancellation must be authoritative for native auth binding");
    assert!(
        error.to_string().contains("cancel")
            || error.to_string().contains("deadline")
            || error.to_string().contains("policy_inactive"),
        "unexpected cancellation error: {error}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(transport.take_sent().is_empty());

    let no_deadline_calls = Arc::new(AtomicUsize::new(0));
    let home_path = home.0.clone();
    let factory_calls = Arc::clone(&no_deadline_calls);
    let factory = Arc::new(move |cancellation| {
        factory_calls.fetch_add(1, Ordering::SeqCst);
        AuthHost::new(home_path.clone(), cancellation)
    });
    let bridges = AgentHostBridges {
        auth_host_factory: Some(factory),
        ..AgentHostBridges::default()
    };
    let no_deadline = AgentRunner::from_source(source(), AgentConfig::default())
        .expect("compile finite-cancellation case")
        .with_host(bridges);
    assert!(no_deadline.run_with_context(Value::map(vec![])).is_err());
    assert_eq!(no_deadline_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn caller_cannot_replace_native_host_home() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let runner = fixture_runner(&home, Arc::clone(&transport), Arc::clone(&calls));
    let context = Value::map(vec![(Value::string("host_home"), Value::Int(99))]);
    let error = runner
        .run_with_context(context)
        .expect_err("caller host_home must be rejected");
    assert!(error.to_string().contains("host_home"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(transport.take_sent().is_empty());
}
