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
        BoundedHttpsTransport, OAuthError, OAuthHost, OAuthIoContext, PreparedHttpsRequest,
        RawHttpsResponse, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
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
    fixture_runner_with_source(home, transport, calls, source())
}

fn fixture_runner_with_source(
    home: &FixtureHome,
    transport: Arc<dyn BoundedHttpsTransport>,
    calls: Arc<AtomicUsize>,
    source: &str,
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
    AgentRunner::from_source(source, AgentConfig::default())
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

fn event_source() -> String {
    source()
        .replace("use oauth;", "use oauth;\nuse stream;")
        .replace(
            "    let request: TransportPublicRequest = {",
            "    stream::emit({ event: \"auth-ready\" });\n    let request: TransportPublicRequest = {",
        )
}

fn carrier_source() -> String {
    source()
        .replace("use oauth;", "use oauth;\nuse stream;")
        .replace(
            "    let request: TransportPublicRequest = {",
            "    stream::emit({ policy_handle: policy, access_handle: access.handle });\n    let fresh_snapshot = config::load_snapshot(&home);\n    let fresh_policy: resource<auth.policy> = fresh_snapshot.policy_handle;\n    let fresh_access = auth::access_handle(\"fixture-codex\", 4, &fresh_policy);\n    let request: TransportPublicRequest = {",
        )
        .replace("        policy_handle: policy,", "        policy_handle: fresh_policy,")
        .replace("        access_handle: access.handle,", "        access_handle: fresh_access.handle,")
}

fn foreign_source() -> String {
    source()
        .replace(
            "    let request: TransportPublicRequest = {",
            "    let foreign_policy: resource<auth.policy> = context[\"foreign_policy\"];\n    let foreign_access: resource<auth.access> = context[\"foreign_access\"];\n    let request: TransportPublicRequest = {",
        )
        .replace("        policy_handle: policy,", "        policy_handle: foreign_policy,")
        .replace("        access_handle: access.handle,", "        access_handle: foreign_access,")
}

struct EventCaptureSink {
    sender: std::sync::mpsc::SyncSender<Value>,
}

impl rustscript_agent::RunEventSink for EventCaptureSink {
    fn deliver(
        &mut self,
        value: Value,
    ) -> Result<(), rustscript_agent::runtime::rss_runner::RunDeliveryError> {
        self.sender
            .send(value)
            .map_err(|_| rustscript_agent::runtime::rss_runner::RunDeliveryError::Closed)
    }
}

#[test]
fn auth_configured_event_sink_uses_supplied_cancellation_and_completes_native_transport() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_responses(&transport, 1);
    let calls = Arc::new(AtomicUsize::new(0));
    let runner = fixture_runner_with_source(
        &home,
        transport.clone(),
        Arc::clone(&calls),
        &event_source(),
    )
    .with_cancellation(RunCancellation::new());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let mut sink = EventCaptureSink { sender };
    let result = runner
        .run_with_context_and_events(Value::map(vec![]), &mut sink, &cancellation)
        .expect("auth-configured event run");
    assert_eq!(field(&result, "snapshot_ok"), &Value::Bool(true));
    assert_eq!(field(&result, "metadata_ok"), &Value::Bool(true));
    assert_eq!(field(&result, "access_ok"), &Value::Bool(true));
    assert_eq!(field(&result, "transport_ok"), &Value::Bool(true));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(receiver.try_recv(), Ok(Value::Map(_))));
    assert_eq!(transport.take_sent().len(), 1);
}

fn carrier_values(value: &Value) -> (Value, Value) {
    let Value::Map(fields) = value else {
        panic!("event carrier must be a map")
    };
    let get = |name: &str| {
        fields
            .iter()
            .find_map(|(key, value)| match key {
                Value::String(key) if key.as_ref() == name => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing carrier field {name}"))
    };
    (get("policy_handle"), get("access_handle"))
}

fn foreign_context(carrier: &Value) -> Value {
    let (policy, access) = carrier_values(carrier);
    Value::map(vec![
        (Value::string("foreign_policy"), policy),
        (Value::string("foreign_access"), access),
    ])
}

struct BlockingCarrierSink {
    captured: std::sync::mpsc::SyncSender<Value>,
    release: std::sync::mpsc::Receiver<()>,
}

impl rustscript_agent::RunEventSink for BlockingCarrierSink {
    fn deliver(
        &mut self,
        value: Value,
    ) -> Result<(), rustscript_agent::runtime::rss_runner::RunDeliveryError> {
        self.captured
            .send(value)
            .map_err(|_| rustscript_agent::runtime::rss_runner::RunDeliveryError::Closed)?;
        self.release
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| rustscript_agent::runtime::rss_runner::RunDeliveryError::Closed)
    }
}

#[test]
fn authentic_event_carriers_are_foreign_while_owner_is_live_and_owner_survives_rejection() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_responses(&transport, 2);
    let calls = Arc::new(AtomicUsize::new(0));
    let producer = fixture_runner_with_source(
        &home,
        transport.clone(),
        Arc::clone(&calls),
        &carrier_source(),
    );
    let rejecting_target = fixture_runner_with_source(
        &home,
        transport.clone(),
        Arc::clone(&calls),
        &foreign_source(),
    );
    let (carrier_tx, carrier_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let cancel = RunCancellation::with_timeout(Duration::from_secs(5));
    let producer_cancel = cancel.clone();
    let producer_thread = thread::spawn(move || {
        producer.run_with_context_and_events(
            Value::map(vec![]),
            &mut BlockingCarrierSink {
                captured: carrier_tx,
                release: release_rx,
            },
            &producer_cancel,
        )
    });
    let carrier = carrier_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("authentic native event carrier");
    let foreign = rejecting_target
        .run_with_context(foreign_context(&carrier))
        .expect_err("foreign-owner handles are rejected by the typed transport call");
    assert!(foreign.to_string().contains("resource_invalid"));
    assert!(
        transport.take_sent().is_empty(),
        "foreign handles must not send"
    );
    release_tx.send(()).expect("release producer sink");
    let producer_result = producer_thread
        .join()
        .expect("producer thread")
        .expect("live producer completes after the foreign rejection");
    assert_eq!(field(&producer_result, "transport_ok"), &Value::Bool(true));
    assert_eq!(transport.take_sent().len(), 1);
}

struct CaptureAndRejectSink {
    captured: Arc<std::sync::Mutex<Option<Value>>>,
}

impl rustscript_agent::RunEventSink for CaptureAndRejectSink {
    fn deliver(
        &mut self,
        value: Value,
    ) -> Result<(), rustscript_agent::runtime::rss_runner::RunDeliveryError> {
        *self.captured.lock().expect("carrier lock") = Some(value);
        Err(
            rustscript_agent::runtime::rss_runner::RunDeliveryError::Rejected {
                code: "fixture_reject",
                message: "native fixture rejection".to_string(),
            },
        )
    }
}

struct CaptureAndPanicSink {
    captured: Arc<std::sync::Mutex<Option<Value>>>,
}

impl rustscript_agent::RunEventSink for CaptureAndPanicSink {
    fn deliver(
        &mut self,
        value: Value,
    ) -> Result<(), rustscript_agent::runtime::rss_runner::RunDeliveryError> {
        *self.captured.lock().expect("carrier lock") = Some(value);
        panic!("fixture sink panic after native carrier capture");
    }
}

#[test]
fn authentic_carriers_fail_after_success_rejection_and_sink_unwind() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_responses(&transport, 4);
    let calls = Arc::new(AtomicUsize::new(0));
    let producer = fixture_runner_with_source(
        &home,
        transport.clone(),
        Arc::clone(&calls),
        &carrier_source(),
    );
    let target = fixture_runner_with_source(
        &home,
        transport.clone(),
        Arc::clone(&calls),
        &foreign_source(),
    );

    let (success_tx, success_rx) = std::sync::mpsc::sync_channel(1);
    let mut success_sink = EventCaptureSink { sender: success_tx };
    let result = producer
        .run_with_context_and_events(
            Value::map(vec![]),
            &mut success_sink,
            &RunCancellation::with_timeout(Duration::from_secs(5)),
        )
        .expect("producer success");
    assert_eq!(field(&result, "transport_ok"), &Value::Bool(true));
    let success_carrier = success_rx.recv().expect("success carrier");
    let before = transport.take_sent().len();
    let stale = target
        .run_with_context(foreign_context(&success_carrier))
        .expect_err("stale carrier handles are rejected");
    assert!(stale.to_string().contains("resource_invalid"));
    assert!(
        transport.take_sent().is_empty(),
        "stale handles must not send"
    );
    assert_eq!(before, 1);

    let rejected_carrier = Arc::new(std::sync::Mutex::new(None));
    let rejected = producer
        .run_with_context_and_events(
            Value::map(vec![]),
            &mut CaptureAndRejectSink {
                captured: Arc::clone(&rejected_carrier),
            },
            &RunCancellation::with_timeout(Duration::from_secs(5)),
        )
        .expect_err("fixture sink rejects event");
    assert!(rejected.to_string().contains("fixture_reject"));
    let rejected_carrier = rejected_carrier
        .lock()
        .expect("carrier lock")
        .take()
        .expect("rejected sink captured authentic event");
    assert!(transport.take_sent().is_empty());
    let rejected_reuse = target
        .run_with_context(foreign_context(&rejected_carrier))
        .expect_err("rejected carrier handles are rejected");
    assert!(rejected_reuse.to_string().contains("resource_invalid"));
    assert!(
        transport.take_sent().is_empty(),
        "rejected handles must not send"
    );

    let panic_carrier = Arc::new(std::sync::Mutex::new(None));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = producer.run_with_context_and_events(
            Value::map(vec![]),
            &mut CaptureAndPanicSink {
                captured: Arc::clone(&panic_carrier),
            },
            &RunCancellation::with_timeout(Duration::from_secs(5)),
        );
    }));
    assert!(
        unwind.is_err(),
        "sink panic must unwind through the public call"
    );
    let panic_carrier = panic_carrier
        .lock()
        .expect("carrier lock")
        .take()
        .expect("panicking sink captured authentic event");
    let panic_reuse = target
        .run_with_context(foreign_context(&panic_carrier))
        .expect_err("unwound carrier handles are rejected");
    assert!(panic_reuse.to_string().contains("resource_invalid"));
    assert!(
        transport.take_sent().is_empty(),
        "unwound handles must not send"
    );
}

struct PendingCheckTransport {
    entered: std::sync::mpsc::SyncSender<()>,
}

impl BoundedHttpsTransport for PendingCheckTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.entered.send(()).map_err(|_| OAuthError::Transport {
            message: "pending test observer closed".to_string(),
        })?;
        loop {
            context.check()?;
            thread::sleep(Duration::from_millis(2));
        }
    }
}

fn assert_pending_run_not_successful(
    receiver: std::sync::mpsc::Receiver<
        Result<Value, rustscript_agent::runtime::rss_runner::RunError>,
    >,
) {
    match receiver.recv_timeout(Duration::from_secs(3)) {
        Ok(Ok(result)) => assert_eq!(
            field(&result, "transport_ok"),
            &Value::Bool(false),
            "pending cancellation/deadline must not return successful native transport"
        ),
        Ok(Err(error)) => assert!(
            error.to_string().contains("cancel") || error.to_string().contains("deadline"),
            "unexpected pending native failure: {error}"
        ),
        Err(error) => panic!("pending native run did not terminate within bound: {error}"),
    }
}

#[test]
fn supplied_cancellation_and_deadline_interrupt_pending_native_transport() {
    for deadline_case in [false, true] {
        let home = FixtureHome::new();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let transport: Arc<dyn BoundedHttpsTransport> = Arc::new(PendingCheckTransport {
            entered: entered_tx,
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = fixture_runner_with_source(&home, transport, calls, source());
        let cancellation = if deadline_case {
            RunCancellation::with_timeout(Duration::from_millis(250))
        } else {
            RunCancellation::with_timeout(Duration::from_secs(5))
        };
        let worker_cancel = cancellation.clone();
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let result = runner.run_with_context_and_events(
                Value::map(vec![]),
                &mut NoopSink,
                &worker_cancel,
            );
            let _ = result_tx.send(result);
        });
        entered_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("native transport entered pending state");
        if !deadline_case {
            cancellation.request(CancellationReason::Requested);
        }
        assert_pending_run_not_successful(result_rx);
        worker.join().expect("pending transport worker");
    }
}

struct NoopSink;

impl rustscript_agent::RunEventSink for NoopSink {
    fn deliver(
        &mut self,
        _value: Value,
    ) -> Result<(), rustscript_agent::runtime::rss_runner::RunDeliveryError> {
        Ok(())
    }
}

struct ProviderCapture {
    calls: AtomicUsize,
    request: std::sync::Mutex<Option<serde_json::Value>>,
}

impl ProviderCapture {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            request: std::sync::Mutex::new(None),
        }
    }
}

impl rustscript_agent::runtime::AgentProviderHost for ProviderCapture {
    fn call(
        &self,
        request: &serde_json::Value,
        _cancellation: &RunCancellation,
    ) -> serde_json::Value {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.request.lock().expect("provider capture") = Some(request.clone());
        json!({"ok": true, "response": {"text": "ok", "tool_calls": []}, "error": {}})
    }
}

fn provider_resource_source() -> &'static str {
    r#"
use agent;
use auth;
use config;
pub fn run(context: map) -> map {
    let home: resource<auth.host_home> = context["host_home"];
    let snapshot = config::load_snapshot(&home);
    let policy: resource<auth.policy> = snapshot.policy_handle;
    let access = auth::access_handle("fixture-codex", 4, &policy);
    let request: map = agent::provider_call({
        envelope: {
            items: [{
                policy_handle: policy,
                access_handle: access.handle
            }]
        }
    });
    { provider_ok: request.ok }
}
"#
}

#[test]
fn provider_json_rejects_nested_live_auth_resources_before_callback() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let capture = Arc::new(ProviderCapture::new());
    let runner = fixture_runner_with_source(&home, transport, calls, provider_resource_source())
        .with_provider(capture.clone());

    let outcome = runner.run_with_context(Value::map(vec![]));
    let error = match outcome {
        Err(error) => error,
        Ok(_) => panic!("live auth resource reached provider JSON boundary"),
    };
    assert!(
        error.to_string().contains("opaque_nonserializable"),
        "provider boundary returned an unexpected error class"
    );
    assert_eq!(capture.calls.load(Ordering::SeqCst), 0);
    assert!(capture.request.lock().expect("provider capture").is_none());
}

#[test]
fn provider_json_preserves_ordinary_public_nested_values() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let capture = Arc::new(ProviderCapture::new());
    let source = r#"
use agent;
pub fn run(context: map) -> map {
    let result: map = agent::provider_call({
        ordinary_integer: 42,
        nested: { label: "public", values: [1, 2, 3] }
    });
    { provider_ok: result.ok }
}
"#;
    let runner =
        fixture_runner_with_source(&home, transport, calls, source).with_provider(capture.clone());

    let outcome = runner.run_with_context(Value::map(vec![]));
    assert!(outcome.is_ok(), "ordinary provider request failed");
    assert_eq!(capture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        capture.request.lock().expect("provider capture").as_ref(),
        Some(&json!({
            "ordinary_integer": 42,
            "nested": { "label": "public", "values": [1, 2, 3] }
        }))
    );
}
