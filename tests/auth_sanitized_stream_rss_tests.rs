//! Real RSS behavior for the typed `oauth.stream` guest binding.
//!
//! These tests drive the accepted sanitized authenticated incremental reader
//! through the exact catalog, restricted registry and the new typed start/
//! read/close records. The transport is a counted scripted incremental stream
//! whose buffered `send` panics, so any HTTP fallback fails the test.

use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::{
            BoundedHttpsStream, BoundedHttpsTransport, OAuthClock, OAuthError, OAuthHost,
            OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse, RawHttpsResponseHead,
            ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        },
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmError, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const CREDENTIAL_ID: &str = "fixture-codex";
const GENERATION: i64 = 4;
const STREAM_PATH: &str = "/oauth/token";
const RESPONSE_SECRET: &str = "STREAM_RESPONSE_ACCESS_PRIVATE_7a3f";
const READ_BODY_SECRET: &str = "STREAM_RAW_BODY_PRIVATE_0c91";

enum Injected {
    Chunk(Vec<u8>),
    Eof,
    ReadError(OAuthError),
}

#[derive(Default)]
struct InjectedState {
    starts: usize,
    reads: usize,
    eofs: usize,
    cancels: usize,
    drops: usize,
    sent: Vec<PreparedHttpsRequest>,
    queue: VecDeque<Injected>,
}

struct InjectedTransport {
    state: Arc<Mutex<InjectedState>>,
    status: u16,
    headers: BTreeMap<String, String>,
}

struct InjectedStream {
    state: Arc<Mutex<InjectedState>>,
    head: RawHttpsResponseHead,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl BoundedHttpsStream for InjectedStream {
    fn head(&self) -> &RawHttpsResponseHead {
        &self.head
    }

    fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, OAuthError> {
        let mut state = locked(&self.state);
        state.reads += 1;
        match state.queue.pop_front() {
            Some(Injected::Chunk(bytes)) => Ok(Some(bytes)),
            Some(Injected::Eof) => {
                state.eofs += 1;
                Ok(None)
            }
            Some(Injected::ReadError(error)) => Err(error),
            None => Err(OAuthError::Transport {
                message: "injected stream exhausted".to_string(),
            }),
        }
    }

    fn cancel(&mut self) {
        locked(&self.state).cancels += 1;
    }
}

impl Drop for InjectedStream {
    fn drop(&mut self) {
        locked(&self.state).drops += 1;
    }
}

impl BoundedHttpsTransport for InjectedTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        _context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        panic!("the sanitized stream path must not fall back to buffered send");
    }

    fn start_stream(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        context.check()?;
        let mut state = locked(&self.state);
        state.starts += 1;
        state.sent.push(request.clone());
        drop(state);
        Ok(Box::new(InjectedStream {
            state: Arc::clone(&self.state),
            head: RawHttpsResponseHead {
                status: self.status,
                headers: self.headers.clone(),
            },
        }))
    }
}

fn event_stream(
    status: u16,
    queue: Vec<Injected>,
) -> (Arc<InjectedTransport>, Arc<Mutex<InjectedState>>) {
    let state = Arc::new(Mutex::new(InjectedState {
        queue: VecDeque::from(queue),
        ..InjectedState::default()
    }));
    let headers = [("content-type".to_string(), "text/event-stream".to_string())]
        .into_iter()
        .collect();
    (
        Arc::new(InjectedTransport {
            state: Arc::clone(&state),
            status,
            headers,
        }),
        state,
    )
}

struct PrivateHome(PathBuf);

impl PrivateHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!(
            "auth-sanitized-stream-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create private home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("read config fixture")
            .replace("auth.openai.com", "auth.example.test");
        fs::write(path.join("config.yaml"), config).expect("write synthetic .test config");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("write auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        Self(path)
    }
}

impl Drop for PrivateHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
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

fn fixture_vm(host: &AuthHost, catalog: &rustscript_vm::HostApiCatalog) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/auth_sanitized_stream/main.rss");
    let source = fs::read_to_string(&path).expect("real sanitized stream RSS fixture");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::new(catalog.clone())),
    )
    .expect("compile real sanitized stream RSS against exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    host.register(&mut registry, catalog)
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

fn native_host_with_clock(
    home: &PrivateHome,
    cancellation: RunCancellation,
    transport: Arc<dyn BoundedHttpsTransport>,
) -> (
    AuthHost,
    Arc<rustscript_vm::HostApiCatalog>,
    Arc<ScriptedClock>,
) {
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let clock_trait: Arc<dyn OAuthClock> = clock.clone();
    let host = AuthHost::new(home.0.clone(), cancellation)
        .expect("native auth host")
        .with_oauth_host(Arc::new(OAuthHost::new(
            transport,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            clock_trait,
            Arc::new(ScriptedCancel::new()),
        )));
    (host, auth_host_catalog(), clock)
}

fn native_host(
    home: &PrivateHome,
    cancellation: RunCancellation,
    transport: Arc<dyn BoundedHttpsTransport>,
) -> (AuthHost, Arc<rustscript_vm::HostApiCatalog>) {
    let (host, catalog, _clock) = native_host_with_clock(home, cancellation, transport);
    (host, catalog)
}

fn bind_policy(host: &AuthHost, vm: &mut Vm) -> Value {
    let context = host.bind_vm(vm).expect("bind native owner");
    invoke(vm, "snapshot", &[field(&context, "host_home").clone()]).expect("native policy snapshot")
}

fn markers(values: &[&str]) -> Value {
    Value::array(values.iter().map(|value| Value::string(*value)).collect())
}

fn start_args(policy: &Value, markers_value: Value) -> Vec<Value> {
    vec![
        Value::string(CREDENTIAL_ID),
        Value::Int(GENERATION),
        Value::string(STREAM_PATH),
        markers_value,
        policy.clone(),
    ]
}

#[test]
fn guest_stream_publishes_first_json_record_pre_eof_without_secrets() {
    let chunk = format!(
        "data: {{\"type\":\"delta\",\"text\":\"hi\",\"access_token\":\"{RESPONSE_SECRET}\",\"nested\":{{\"Authorization\":\"x\"}}}}\n\n"
    );
    let (transport, state) = event_stream(
        200,
        vec![Injected::Chunk(chunk.into_bytes()), Injected::Eof],
    );
    let home = PrivateHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let (host, catalog) = native_host(&home, cancellation, transport);
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let view = invoke(
        &mut vm,
        "stream_first_json_result",
        &start_args(&policy, markers(&["DONE"])),
    )
    .expect("guest stream callable returns a typed result");

    assert_eq!(field(&view, "ok"), &Value::Bool(true), "{view:?}");
    assert_eq!(field(&view, "status"), &Value::Int(200));
    assert_eq!(
        field(&view, "content_type"),
        &Value::string("text/event-stream")
    );
    assert_eq!(field(&view, "read_ok"), &Value::Bool(true), "{view:?}");
    assert_eq!(field(&view, "kind"), &Value::string("json"));
    assert_eq!(field(&view, "literal_index"), &Value::Int(-1));
    assert_eq!(field(&view, "close_ok"), &Value::Bool(true));
    let json = match field(&view, "json") {
        Value::String(json) => json.to_string(),
        other => panic!("expected json string, got {other:?}"),
    };
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("published record is json");
    assert_eq!(parsed["type"], "delta");
    assert_eq!(parsed["text"], "hi");
    assert!(parsed.get("access_token").is_none());
    assert!(parsed["nested"].get("Authorization").is_none());
    assert!(!json.contains(RESPONSE_SECRET));
    assert!(!format!("{view:?}").contains(RESPONSE_SECRET));
    assert!(!format!("{view:?}").contains(READ_BODY_SECRET));

    let state = locked(&state);
    assert_eq!(
        state.starts, 1,
        "exactly one incremental start; no buffered fallback"
    );
    assert_eq!(state.sent.len(), 1);
    assert_eq!(state.sent[0].method, "GET");
    assert_eq!(state.sent[0].url, "https://auth.example.test/oauth/token");
    assert_eq!(
        state.sent[0]
            .headers
            .get("authorization")
            .map(String::as_str),
        Some("Bearer SYNTHETIC_ACCESS_TOKEN"),
        "the shared helper injects the final native Authorization"
    );
    assert_eq!(state.eofs, 0, "the first record is published before EOF");
    assert!(state.reads >= 1);
}

#[test]
fn guest_stream_orders_literal_json_then_terminal_eof() {
    let (transport, state) = event_stream(
        200,
        vec![
            Injected::Chunk(b"data: DONE\n\ndata: {\"after\":\"x\"}\n\n".to_vec()),
            Injected::Eof,
        ],
    );
    let home = PrivateHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let (host, catalog) = native_host(&home, cancellation, transport);
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&["DONE"])),
    )
    .expect("open typed stream");
    assert_eq!(field(&opened, "ok"), &Value::Bool(true), "{opened:?}");
    let stream = field(&opened, "stream").clone();
    assert!(
        !matches!(stream, Value::Null),
        "stream resource is published"
    );

    let first = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("read one");
    assert_eq!(field(&first, "ok"), &Value::Bool(true), "{first:?}");
    assert_eq!(field(&first, "kind"), &Value::string("literal"));
    assert_eq!(field(&first, "literal_index"), &Value::Int(0));
    assert_eq!(field(&first, "json"), &Value::string(""));

    let second = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("read two");
    assert_eq!(field(&second, "kind"), &Value::string("json"), "{second:?}");
    assert_eq!(field(&second, "json"), &Value::string("{\"after\":\"x\"}"));

    let third = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("read three");
    assert_eq!(field(&third, "kind"), &Value::string("eof"), "{third:?}");
    assert_eq!(field(&third, "json"), &Value::string(""));

    let fourth = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("read eof ack");
    assert_eq!(field(&fourth, "kind"), &Value::string("eof"));

    assert_eq!(
        invoke(&mut vm, "stream_close", &[stream]).expect("explicit close"),
        Value::Null
    );
    let state = locked(&state);
    assert_eq!(state.starts, 1);
    assert_eq!(state.eofs, 1, "EOF observed exactly once");
}

#[test]
fn guest_stream_terminal_eof_survives_owner_cancellation() {
    let (transport, state) = event_stream(200, vec![Injected::Eof]);
    let home = PrivateHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let (host, catalog) = native_host(&home, cancellation.clone(), transport);
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&[])),
    )
    .expect("open typed stream");
    let stream = field(&opened, "stream").clone();
    let first = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("read one");
    assert_eq!(field(&first, "kind"), &Value::string("eof"));

    cancellation.request(CancellationReason::Requested);
    let after = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("completed EOF stays a typed record");
    assert_eq!(field(&after, "kind"), &Value::string("eof"), "{after:?}");
    assert_eq!(field(&after, "json"), &Value::string(""));
    assert_eq!(
        locked(&state).reads,
        1,
        "no revival read after cancellation"
    );
}

#[test]
fn guest_stream_cancellation_cannot_publish_buffered_records() {
    let (transport, state) = event_stream(
        200,
        vec![Injected::Chunk(
            b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n".to_vec(),
        )],
    );
    let home = PrivateHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let (host, catalog) = native_host(&home, cancellation.clone(), transport);
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&[])),
    )
    .expect("open typed stream");
    let stream = field(&opened, "stream").clone();
    let first = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("read one");
    assert_eq!(field(&first, "kind"), &Value::string("json"), "{first:?}");
    assert_eq!(field(&first, "json"), &Value::string("{\"a\":1}"));

    cancellation.request(CancellationReason::Requested);
    let rejected = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("rejected read is a typed result");
    assert_eq!(field(&rejected, "ok"), &Value::Bool(false), "{rejected:?}");
    assert_eq!(field(&rejected, "code"), &Value::string("policy_inactive"));
    assert_eq!(
        locked(&state).reads,
        1,
        "no new raw read after cancellation"
    );
    assert!(
        locked(&state).cancels >= 1,
        "rejected active read cancels the transport immediately"
    );
    assert!(
        locked(&state).drops >= 1,
        "rejected active read releases the transport immediately"
    );
    assert_eq!(
        invoke(&mut vm, "stream_close", &[stream]).expect("cleanup after cancellation"),
        Value::Null
    );
}

#[test]
fn guest_stream_fails_closed_on_malformed_non_json_and_read_error() {
    // Malformed, non-JSON and transport read failures all fail closed: the raw
    // bytes and host diagnostics stay private, no record is published, and the
    // reader is cancelled then released.
    let cases: [(&str, Injected, &str); 3] = [
        (
            "invalid-json",
            Injected::Chunk(b"data: {broken\n\n".to_vec()),
            "malformed_response",
        ),
        (
            "non-json",
            Injected::Chunk(b"data: hello world\n\n".to_vec()),
            "malformed_response",
        ),
        (
            "read-error",
            Injected::ReadError(OAuthError::Transport {
                message: READ_BODY_SECRET.to_string(),
            }),
            "transport_error",
        ),
    ];
    for (name, injected, expected_code) in cases {
        let (transport, state) = event_stream(200, vec![injected]);
        let home = PrivateHome::new();
        let (host, catalog) = native_host(
            &home,
            RunCancellation::with_timeout(Duration::from_secs(30)),
            transport,
        );
        let mut vm = fixture_vm(&host, catalog.as_ref());
        let policy = bind_policy(&host, &mut vm);
        let opened = invoke(
            &mut vm,
            "stream_open_result",
            &start_args(&policy, markers(&["DONE"])),
        )
        .expect("open typed stream");
        let stream = field(&opened, "stream").clone();
        let read = invoke(&mut vm, "stream_read_one_result", &[stream]).expect("read one");
        assert_eq!(
            field(&read, "ok"),
            &Value::Bool(false),
            "case {name}: {read:?}"
        );
        assert_eq!(
            field(&read, "code"),
            &Value::string(expected_code),
            "case {name}: {read:?}"
        );
        let rendered = format!("{read:?}");
        assert!(
            !rendered.contains(READ_BODY_SECRET),
            "case {name}: transport diagnostics leaked"
        );
        assert!(
            !rendered.contains("broken") && !rendered.contains("hello world"),
            "case {name}: raw body leaked into the typed record"
        );
        assert!(
            locked(&state).cancels >= 1,
            "case {name}: terminal failure cancels the reader"
        );
        assert!(
            locked(&state).drops >= 1,
            "case {name}: terminal failure releases the reader"
        );
    }
}

#[test]
fn guest_stream_unsupported_mime_fails_read_without_reading_body() {
    let state = Arc::new(Mutex::new(InjectedState {
        queue: VecDeque::from(vec![Injected::Chunk(b"raw body".to_vec())]),
        ..InjectedState::default()
    }));
    let transport: Arc<dyn BoundedHttpsTransport> = Arc::new(InjectedTransport {
        state: Arc::clone(&state),
        status: 500,
        headers: [("content-type".to_string(), "text/plain".to_string())]
            .into_iter()
            .collect(),
    });
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);
    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&["DONE"])),
    )
    .expect("open typed stream");
    assert_eq!(field(&opened, "status"), &Value::Int(500));
    assert_eq!(field(&opened, "content_type"), &Value::string(""));
    let stream = field(&opened, "stream").clone();
    let read = invoke(&mut vm, "stream_read_one_result", &[stream]).expect("read one");
    assert_eq!(field(&read, "ok"), &Value::Bool(false));
    assert_eq!(field(&read, "code"), &Value::string("malformed_response"));
    assert_eq!(
        locked(&state).reads,
        0,
        "no body bytes read for unsupported mime"
    );
}

#[test]
fn guest_stream_invalid_markers_do_not_consume_access_and_retry_succeeds() {
    let (transport, state) = event_stream(
        200,
        vec![Injected::Chunk(b"data: {\"body\":true}\n\n".to_vec())],
    );
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let view = invoke(
        &mut vm,
        "stream_marker_retry_result",
        &[
            Value::string(CREDENTIAL_ID),
            Value::Int(GENERATION),
            Value::string(STREAM_PATH),
            markers(&["DUP", "DUP"]),
            markers(&["DONE"]),
            policy,
        ],
    )
    .expect("marker retry view");

    assert_eq!(field(&view, "reject_ok"), &Value::Bool(false), "{view:?}");
    assert_eq!(
        field(&view, "reject_code"),
        &Value::string("invalid_intent")
    );
    assert_eq!(field(&view, "retry_ok"), &Value::Bool(true), "{view:?}");
    assert_eq!(field(&view, "retry_status"), &Value::Int(200));
    assert_eq!(
        locked(&state).starts,
        1,
        "rejected markers consume no transport start and the access handle stays retryable"
    );
}

#[test]
fn guest_stream_unsupported_credential_kind_rejected_without_transport() {
    let (transport, state) = event_stream(
        200,
        vec![Injected::Chunk(b"data: {\"body\":true}\n\n".to_vec())],
    );
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let view = invoke(
        &mut vm,
        "stream_refresh_usage_then_access_result",
        &start_args(&policy, markers(&["DONE"])),
    )
    .expect("credential kind view");

    assert_eq!(field(&view, "reject_ok"), &Value::Bool(false), "{view:?}");
    assert_eq!(
        field(&view, "reject_code"),
        &Value::string("credential_use_unsupported")
    );
    assert_eq!(field(&view, "retry_ok"), &Value::Bool(true), "{view:?}");
    assert_eq!(locked(&state).starts, 1);
}

#[test]
fn guest_stream_close_releases_reader_and_stale_handle_is_rejected() {
    let (transport, state) =
        event_stream(200, vec![Injected::Chunk(b"data: {\"a\":1}\n\n".to_vec())]);
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);

    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&[])),
    )
    .expect("open typed stream");
    let stream = field(&opened, "stream").clone();
    let baseline = vm.host_context().resource_count();
    assert_eq!(
        invoke(&mut vm, "stream_close", std::slice::from_ref(&stream)).expect("close"),
        Value::Null
    );
    assert_eq!(
        vm.host_context().resource_count(),
        baseline - 1,
        "close releases the stream resource"
    );
    assert!(
        locked(&state).cancels >= 1,
        "the underlying reader is cancelled"
    );
    assert!(
        locked(&state).drops >= 1,
        "the underlying reader is dropped"
    );

    let failure = invoke(&mut vm, "stream_read_one_result", &[stream])
        .expect_err("a closed stream handle cannot be read");
    let text = failure.to_string();
    assert!(
        text.contains("resource_invalid") || text.contains("resource_already_closed"),
        "stale handle rejected, got {text}"
    );
}

#[test]
fn guest_stream_json_mime_error_body_is_sanitized() {
    // Buffered `application/json` error body: status/content-type survive and
    // the published record is sanitized strict JSON with no credential.
    let body = br#"{"error":"bad_request","access_token":"STREAM_RESPONSE_ACCESS_PRIVATE_7a3f","nested":{"Cookie":"c","Refresh_Token":"r"}}"#
        .to_vec();
    let state = Arc::new(Mutex::new(InjectedState {
        queue: VecDeque::from(vec![Injected::Chunk(body), Injected::Eof]),
        ..InjectedState::default()
    }));
    let transport: Arc<dyn BoundedHttpsTransport> = Arc::new(InjectedTransport {
        state: Arc::clone(&state),
        status: 401,
        headers: [("content-type".to_string(), "application/json".to_string())]
            .into_iter()
            .collect(),
    });
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);
    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&["DONE"])),
    )
    .expect("open typed stream");
    assert_eq!(field(&opened, "ok"), &Value::Bool(true), "{opened:?}");
    assert_eq!(field(&opened, "status"), &Value::Int(401));
    assert_eq!(
        field(&opened, "content_type"),
        &Value::string("application/json")
    );
    let stream = field(&opened, "stream").clone();
    let read = invoke(&mut vm, "stream_read_one_result", &[stream]).expect("read one");
    assert_eq!(field(&read, "ok"), &Value::Bool(true), "{read:?}");
    assert_eq!(field(&read, "kind"), &Value::string("json"));
    let json = match field(&read, "json") {
        Value::String(json) => json.to_string(),
        other => panic!("expected sanitized json, got {other:?}"),
    };
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("sanitized json parses");
    assert_eq!(parsed["error"], "bad_request");
    assert!(parsed.get("access_token").is_none());
    assert!(parsed["nested"].get("Cookie").is_none());
    assert!(parsed["nested"].get("Refresh_Token").is_none());
    assert!(!json.contains(RESPONSE_SECRET));
    assert!(!format!("{read:?}").contains(RESPONSE_SECRET));
}

#[test]
fn guest_stream_buffered_expiry_blocks_the_second_record() {
    let (transport, state) = event_stream(
        200,
        vec![Injected::Chunk(
            b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n".to_vec(),
        )],
    );
    let home = PrivateHome::new();
    let (host, catalog, clock) = native_host_with_clock(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);
    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&[])),
    )
    .expect("open typed stream");
    let stream = field(&opened, "stream").clone();
    let first = invoke(
        &mut vm,
        "stream_read_one_result",
        std::slice::from_ref(&stream),
    )
    .expect("read one");
    assert_eq!(field(&first, "kind"), &Value::string("json"), "{first:?}");
    assert_eq!(field(&first, "json"), &Value::string("{\"a\":1}"));

    clock.expire();
    let second = invoke(&mut vm, "stream_read_one_result", &[stream]).expect("read two");
    assert_eq!(field(&second, "ok"), &Value::Bool(false), "{second:?}");
    assert_eq!(field(&second, "code"), &Value::string("deadline_exceeded"));
    assert_eq!(
        locked(&state).reads,
        1,
        "expiry is checked before touching the withheld second record"
    );
    assert!(
        locked(&state).cancels >= 1,
        "expiry cancels the underlying reader"
    );
}

#[test]
fn guest_stream_vm_drop_releases_an_open_reader() {
    let (transport, state) =
        event_stream(200, vec![Injected::Chunk(b"data: {\"a\":1}\n\n".to_vec())]);
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);
    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&[])),
    )
    .expect("open typed stream");
    assert!(
        !matches!(field(&opened, "stream"), Value::Null),
        "a real open stream exists before the VM is dropped"
    );
    drop(vm);
    assert!(
        locked(&state).cancels >= 1,
        "dropping the VM with an open stream cancels the reader"
    );
    assert!(
        locked(&state).drops >= 1,
        "dropping the VM releases the reader"
    );
}

/// Discover the exact live execution-scope capacity on a throwaway VM by
/// filling it with genuine issued access capabilities until the host rejects
/// one more.
fn discover_resource_capacity(home: &PrivateHome) -> usize {
    let (transport, _state) = event_stream(200, vec![Injected::Eof]);
    let (host, catalog) = native_host(
        home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);
    let mut capacity = vm.host_context().resource_count();
    loop {
        let step = invoke(
            &mut vm,
            "stream_limit_step",
            &[
                Value::string(CREDENTIAL_ID),
                Value::Int(GENERATION),
                policy.clone(),
            ],
        )
        .expect("quota step");
        if field(&step, "ok") != &Value::Bool(true) {
            break;
        }
        capacity = vm.host_context().resource_count();
    }
    capacity
}

#[test]
fn guest_stream_publication_limit_is_unreachable_through_the_accepted_issuer() {
    // Narrow execution proof for the specified "publication failure" item.
    // The contract algorithm predicts `resource_limit` when the oauth.stream
    // resource is claimed with no free slot. Through the accepted issuer path
    // that exact transition is unreachable: `stream_start_result` consumes the
    // one-shot access handle and `close_if_terminal` closes the Access
    // resource (freeing its slot) before the stream resource is claimed, so a
    // start at LIMIT-1 always succeeds and never cancels/drops the reader.
    // The real host LIMIT is still enforced at the capability-issue boundary.
    let (transport, state) = event_stream(
        200,
        vec![
            Injected::Chunk(b"data: {\"a\":1}\n\n".to_vec()),
            Injected::Eof,
        ],
    );
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);
    let capacity = discover_resource_capacity(&PrivateHome::new());

    let mut held: Vec<Value> = Vec::new();
    while vm.host_context().resource_count() < capacity {
        let step = invoke(
            &mut vm,
            "stream_limit_step",
            &[
                Value::string(CREDENTIAL_ID),
                Value::Int(GENERATION),
                policy.clone(),
            ],
        )
        .expect("quota step");
        assert_eq!(field(&step, "ok"), &Value::Bool(true), "{step:?}");
        held.push(field(&step, "handle").clone());
    }
    assert_eq!(
        vm.host_context().resource_count(),
        capacity,
        "the scope is filled to its exact live capacity"
    );

    // (a) The real host LIMIT is enforced at the accepted issuer boundary.
    let overflow = invoke(
        &mut vm,
        "stream_limit_step",
        &[
            Value::string(CREDENTIAL_ID),
            Value::Int(GENERATION),
            policy.clone(),
        ],
    )
    .expect("overflow step");
    assert_eq!(field(&overflow, "ok"), &Value::Bool(false), "{overflow:?}");
    assert_eq!(field(&overflow, "code"), &Value::string("resource_limit"));

    // Free exactly one real slot, then publish a stream into it: the transition
    // to a rejected publication is unreachable, the reader is never cancelled.
    let release = held.pop().expect("at least one held capability");
    assert_eq!(
        invoke(&mut vm, "stream_release_result", &[release]).expect("release one"),
        Value::Null
    );
    assert_eq!(vm.host_context().resource_count(), capacity - 1);

    let view = invoke(
        &mut vm,
        "stream_publication_probe",
        &start_args(&policy, markers(&[])),
    )
    .expect("publication probe view");
    assert_eq!(
        field(&view, "ok"),
        &Value::Bool(true),
        "publication at LIMIT-1 succeeds; the resource_limit transition is unreachable: {view:?}"
    );
    let st = locked(&state);
    assert_eq!(st.starts, 1, "the stream started");
    assert_eq!(
        st.cancels, 0,
        "no cancel because publication was never rejected"
    );
    assert_eq!(
        st.drops, 0,
        "no release because no unpublished reader exists"
    );
}

#[test]
fn guest_stream_same_vm_rebind_is_structurally_unreachable() {
    // Narrow execution proof for the specified Owner-mismatch transition.
    // The contract's algorithm requires rebinding the SAME VM to a second
    // AuthHost through public `bind_vm` after a stream is issued. That is not
    // reachable: `AuthHost::bind_vm` returns `already_bound` while a `Bound`
    // owner exists, no public call clears `Bound` while keeping resources
    // live, and `Vm::reset_for_reuse` closes every resource (including this
    // stream) so no foreign live stream can survive to be re-read.
    let (transport, state) =
        event_stream(200, vec![Injected::Chunk(b"data: {\"a\":1}\n\n".to_vec())]);
    let home = PrivateHome::new();
    let (host, catalog) = native_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = fixture_vm(&host, catalog.as_ref());
    let policy = bind_policy(&host, &mut vm);
    let opened = invoke(
        &mut vm,
        "stream_open_result",
        &start_args(&policy, markers(&[])),
    )
    .expect("open typed stream");
    let stream = field(&opened, "stream").clone();

    let (second_transport, _second_state) = event_stream(200, vec![Injected::Eof]);
    let second = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("second host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        second_transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let rebind = second.bind_vm(&mut vm).expect_err("second bind must fail");
    assert!(
        format!("{rebind:?}").contains("already_bound"),
        "unexpected rebind failure: {rebind:?}"
    );

    // The original owner still governs the live stream unchanged.
    let read = invoke(&mut vm, "stream_read_one_result", &[stream]).expect("read one");
    assert_eq!(field(&read, "kind"), &Value::string("json"), "{read:?}");
    assert_eq!(locked(&state).starts, 1);
}
