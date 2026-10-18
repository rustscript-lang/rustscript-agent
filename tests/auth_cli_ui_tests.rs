use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{
            AuthHost, PublicDeviceInstruction, RunOAuthCancel, SystemOAuthClock, auth_host_catalog,
            device_instruction_channel,
        },
        oauth::{
            BoundedHttpsTransport, BrowserOpener, CallbackWaiter, OAuthError, OAuthHost,
            OAuthIoContext, PreparedHttpsRequest, RawCallbackInput, RawHttpsResponse,
        },
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const RSS_SOURCE: &str = r#"
use auth;
use config;
use oauth;

pub fn snapshot(home: resource<auth.host_home>) -> resource<auth.policy> {
    config::load_snapshot(&home).policy_handle
}

pub fn emit_instruction(verification_url: string, user_code: string, expires_in_seconds: int) -> DeviceInstructionResultEnvelope {
    oauth::emit_device_instruction_result(verification_url, user_code, expires_in_seconds)
}

pub fn now_result(policy: resource<auth.policy>) -> OAuthNowResultEnvelope {
    oauth::now_ms_result(&policy)
}

pub fn wait_result(policy: resource<auth.policy>, millis: int) -> OAuthWaitResultEnvelope {
    oauth::wait_ms_result(&policy, millis)
}

pub fn send_result(policy: resource<auth.policy>) -> TransportResultEnvelope {
    let request = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "GET",
        path: "/oauth/token",
        public_headers: [],
        public_body: ""
    };
    let usage = {kind: "none"};
    oauth::transport_result(&request, &usage)
}
"#;

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
        let home = root.join(format!(
            "auth-cli-ui-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&home).expect("create private auth home");
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixtures.join("config.yaml"), home.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixtures.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(home.join("auth.yaml"), auth).expect("write auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture mode");
            }
        }
        Self(home)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn registered_vm(auth: &AuthHost) -> Vm {
    let catalog = auth_host_catalog();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/timing_contract.rss");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        RSS_SOURCE,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile real RSS against auth host catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted auth catalog");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    vm
}

fn bound_vm(auth: &AuthHost) -> (Vm, Value) {
    let mut vm = registered_vm(auth);
    let host_home = auth.bind_vm(&mut vm).expect("bind actual VM owner");
    (vm, field(&host_home, "host_home").clone())
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS record, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn map_keys(value: &Value) -> Vec<String> {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS record, got {value:?}");
    };
    let mut keys: Vec<String> = entries
        .iter()
        .map(|(key, _)| match key {
            Value::String(key) => key.to_string(),
            other => panic!("unexpected non-string key {other:?}"),
        })
        .collect();
    keys.sort();
    keys
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let entry = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(entry, args).expect("RSS call")
}

fn text(value: &Value) -> &str {
    let Value::String(text) = value else {
        panic!("expected string, got {value:?}");
    };
    text
}

fn emit(vm: &mut Vm, url: &str, user_code: &str, expires: i64) -> Value {
    invoke(
        vm,
        "emit_instruction",
        &[
            Value::string(url),
            Value::string(user_code),
            Value::Int(expires),
        ],
    )
}

fn assert_device_result(value: &Value, ok: bool, code: Option<&str>) {
    assert_eq!(
        map_keys(value),
        vec!["error".to_owned(), "ok".to_owned(), "value".to_owned()]
    );
    assert_eq!(field(value, "ok"), &Value::Bool(ok));
    match code {
        Some(code) => {
            assert_eq!(field(value, "value"), &Value::Null);
            let error = field(value, "error");
            assert_eq!(
                map_keys(error),
                vec![
                    "cancelled".to_owned(),
                    "code".to_owned(),
                    "deadline_exceeded".to_owned(),
                    "revoked".to_owned(),
                ]
            );
            assert_eq!(text(field(error, "code")), code);
        }
        None => {
            assert_eq!(field(value, "value"), &Value::Bool(true));
            assert_eq!(field(value, "error"), &Value::Null);
        }
    }
}

fn assert_failure_flags(value: &Value, cancelled: bool, deadline: bool, revoked: bool) {
    let error = field(value, "error");
    assert_eq!(field(error, "cancelled"), &Value::Bool(cancelled));
    assert_eq!(field(error, "deadline_exceeded"), &Value::Bool(deadline));
    assert_eq!(field(error, "revoked"), &Value::Bool(revoked));
}

fn standard_cancellation() -> RunCancellation {
    RunCancellation::with_timeout(Duration::from_secs(30))
}

fn test_oauth_host(
    transport: Arc<dyn BoundedHttpsTransport>,
    cancellation: RunCancellation,
) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new(
        transport,
        Arc::new(UnusedCallback),
        Arc::new(UnusedBrowser),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation)),
    ))
}

struct UnusedCallback;

impl CallbackWaiter for UnusedCallback {
    fn wait_one(&self, _: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        Err(OAuthError::Transport {
            message: "unused test callback".to_owned(),
        })
    }
}

struct UnusedBrowser;

impl BrowserOpener for UnusedBrowser {
    fn open(&self, _: &str, _: &OAuthIoContext) -> Result<(), OAuthError> {
        Err(OAuthError::Transport {
            message: "unused test browser".to_owned(),
        })
    }
}

struct CancelDuringTransport {
    cancellation: RunCancellation,
    calls: AtomicUsize,
}

impl BoundedHttpsTransport for CancelDuringTransport {
    fn send(
        &self,
        _: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.cancellation.request(CancellationReason::Requested);
        context.check()?;
        unreachable!("requested cancellation is observed by the OAuth I/O context")
    }
}

struct TokenOnlyCancelDuringTransport {
    cancellation: RunCancellation,
    calls: AtomicUsize,
}

impl BoundedHttpsTransport for TokenOnlyCancelDuringTransport {
    fn send(
        &self,
        _: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.cancellation.token().cancel();
        context.check()?;
        unreachable!("token-only cancellation is observed by the OAuth I/O context")
    }
}

struct WaitForDeadline {
    calls: AtomicUsize,
}

impl BoundedHttpsTransport for WaitForDeadline {
    fn send(
        &self,
        _: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        loop {
            match context.check() {
                Err(failure @ OAuthError::DeadlineExceeded) => return Err(failure),
                Err(failure) => return Err(failure),
                Ok(()) => thread::sleep(Duration::from_millis(2)),
            }
        }
    }
}

#[test]
fn real_rss_emits_public_instruction_to_its_bound_owner_queue() {
    const VERIFICATION_URL: &str = "https://login.example.test/device?user_code=PUBLIC%2D7QK";
    const USER_CODE: &str = "PUBLIC-7QK";
    const SENTINEL: &str = "SYNTHETIC_PRIVATE_TOKEN_41c7";
    let home = TempHome::new("delivery");
    let (sender, receiver) = device_instruction_channel();
    let auth = AuthHost::new(home.0.clone(), standard_cancellation())
        .expect("auth host")
        .with_device_instruction_sender(sender);
    let (mut vm, _host_home) = bound_vm(&auth);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config before");
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth before");
    let mut entries_before: Vec<_> = fs::read_dir(&home.0)
        .expect("home entries before")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect();
    entries_before.sort();

    let result = emit(&mut vm, VERIFICATION_URL, USER_CODE, 600);
    assert_device_result(&result, true, None);
    let instruction = receiver.try_recv().expect("queued public instruction");
    assert_eq!(
        instruction,
        PublicDeviceInstruction {
            verification_url: VERIFICATION_URL.to_owned(),
            user_code: USER_CODE.to_owned(),
            expires_in_seconds: 600,
        }
    );
    assert!(
        receiver.try_recv().is_err(),
        "one call enqueues exactly once"
    );
    let rendered = format!("{result:?}{instruction:?}");
    assert!(!rendered.contains(SENTINEL));
    assert!(!rendered.contains("access_token"));
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config after"),
        config_before
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth after"),
        auth_before
    );
    let mut entries_after: Vec<_> = fs::read_dir(&home.0)
        .expect("home entries after")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect();
    entries_after.sort();
    assert_eq!(entries_after, entries_before);
    assert_eq!(vm.host_context().resource_count(), 1);
}

#[test]
fn bound_vm_owner_selects_its_own_instruction_queue() {
    let home_a = TempHome::new("owner-a");
    let home_b = TempHome::new("owner-b");
    let (sender_a, receiver_a) = device_instruction_channel();
    let (sender_b, receiver_b) = device_instruction_channel();
    let auth_a = AuthHost::new(home_a.0.clone(), standard_cancellation())
        .expect("owner A host")
        .with_device_instruction_sender(sender_a);
    let auth_b = AuthHost::new(home_b.0.clone(), standard_cancellation())
        .expect("owner B host")
        .with_device_instruction_sender(sender_b);
    let (mut vm_a, _) = bound_vm(&auth_a);
    let (mut vm_b, _) = bound_vm(&auth_b);

    assert_device_result(
        &emit(&mut vm_a, "https://a.example.test/device", "PUBLIC-A", 300),
        true,
        None,
    );
    assert_device_result(
        &emit(&mut vm_b, "https://b.example.test/device", "PUBLIC-B", 420),
        true,
        None,
    );
    assert_eq!(
        receiver_a.try_recv().expect("A owner queue").user_code,
        "PUBLIC-A"
    );
    assert_eq!(
        receiver_b.try_recv().expect("B owner queue").user_code,
        "PUBLIC-B"
    );
    assert!(receiver_a.try_recv().is_err());
    assert!(receiver_b.try_recv().is_err());
}

#[test]
fn device_instruction_failures_are_typed_and_never_acknowledged() {
    let home = TempHome::new("failures");
    let auth = AuthHost::new(home.0.clone(), standard_cancellation()).expect("auth host");
    let (mut vm, _) = bound_vm(&auth);
    let unavailable = emit(&mut vm, "https://login.example.test/device", "PUBLIC", 60);
    assert_device_result(&unavailable, false, Some("ui_unavailable"));
    assert_failure_flags(&unavailable, false, false, false);

    let (sender, receiver) = device_instruction_channel();
    let queued_home = TempHome::new("full");
    let queued_auth = AuthHost::new(queued_home.0.clone(), standard_cancellation())
        .expect("queue host")
        .with_device_instruction_sender(sender);
    let (mut queued_vm, _) = bound_vm(&queued_auth);
    for index in 0..4 {
        let code = format!("PUBLIC-{index}");
        assert_device_result(
            &emit(
                &mut queued_vm,
                "https://login.example.test/device",
                &code,
                60,
            ),
            true,
            None,
        );
    }
    let full = emit(
        &mut queued_vm,
        "https://login.example.test/device",
        "PUBLIC-5",
        60,
    );
    assert_device_result(&full, false, Some("ui_sink_full"));
    assert_failure_flags(&full, false, false, false);
    for index in 0..4 {
        assert_eq!(
            receiver
                .try_recv()
                .expect("all four queued records")
                .user_code,
            format!("PUBLIC-{index}")
        );
    }
    assert!(
        receiver.try_recv().is_err(),
        "full failure adds no fifth record"
    );

    let (closed_sender, closed_receiver) = device_instruction_channel();
    drop(closed_receiver);
    let closed_home = TempHome::new("closed");
    let closed_auth = AuthHost::new(closed_home.0.clone(), standard_cancellation())
        .expect("closed queue host")
        .with_device_instruction_sender(closed_sender);
    let (mut closed_vm, _) = bound_vm(&closed_auth);
    let closed = emit(
        &mut closed_vm,
        "https://login.example.test/device",
        "PUBLIC",
        60,
    );
    assert_device_result(&closed, false, Some("ui_sink_closed"));
    assert_failure_flags(&closed, false, false, false);
}

#[test]
fn invalid_device_instructions_are_rejected_without_queue_changes() {
    const SECRET: &str = "SYNTHETIC_QUERY_SECRET_aa91";
    let home = TempHome::new("invalid");
    let (sender, receiver) = device_instruction_channel();
    let auth = AuthHost::new(home.0.clone(), standard_cancellation())
        .expect("auth host")
        .with_device_instruction_sender(sender);
    let (mut vm, _) = bound_vm(&auth);
    let mut invalid_cases: Vec<(String, String, i64)> = vec![
        (
            "http://login.example.test/device".into(),
            "PUBLIC".into(),
            60,
        ),
        (
            "https://user:pass@login.example.test/device".into(),
            "PUBLIC".into(),
            60,
        ),
        (
            "https://login.example.test/device#fragment".into(),
            "PUBLIC".into(),
            60,
        ),
        (
            format!("https://login.example.test/device?ACCESS_TOKEN={SECRET}"),
            "PUBLIC".into(),
            60,
        ),
        (
            format!("https://login.example.test/device?%63ode={SECRET}"),
            "PUBLIC".into(),
            60,
        ),
        (String::new(), "PUBLIC".into(), 60),
        (
            "https://login.example.test/device".into(),
            String::new(),
            60,
        ),
        (
            "https://login.example.test/device".into(),
            "BAD\nCODE".into(),
            60,
        ),
        (
            "https://login.example.test/device\u{0001}".into(),
            "PUBLIC".into(),
            60,
        ),
        (
            "https://login.example.test/device".into(),
            "PUBLIC".into(),
            0,
        ),
        (
            "https://login.example.test/device".into(),
            "PUBLIC".into(),
            -1,
        ),
    ];
    invalid_cases.push((
        format!("https://login.example.test/{}", "x".repeat(2048)),
        "PUBLIC".into(),
        60,
    ));
    invalid_cases.push((
        "https://login.example.test/device".into(),
        "x".repeat(129),
        60,
    ));

    for (url, code, expires) in invalid_cases {
        let result = emit(&mut vm, &url, &code, expires);
        assert_device_result(&result, false, Some("ui_instruction_invalid"));
        assert_failure_flags(&result, false, false, false);
        assert!(!format!("{result:?}").contains(SECRET));
    }
    assert!(
        receiver.try_recv().is_err(),
        "invalid calls never enter the queue"
    );
}

#[test]
fn unbound_revoked_cancelled_and_expired_owners_do_not_deliver() {
    let unbound_home = TempHome::new("unbound");
    let (unbound_sender, unbound_receiver) = device_instruction_channel();
    let unbound_auth = AuthHost::new(unbound_home.0.clone(), standard_cancellation())
        .expect("unbound host")
        .with_device_instruction_sender(unbound_sender);
    let mut unbound_vm = registered_vm(&unbound_auth);
    let unbound = emit(
        &mut unbound_vm,
        "https://login.example.test/device",
        "PUBLIC",
        60,
    );
    assert_device_result(&unbound, false, Some("host_unbound"));
    assert_failure_flags(&unbound, false, false, false);
    assert!(unbound_receiver.try_recv().is_err());

    let revoked_home = TempHome::new("revoked");
    let (revoked_sender, revoked_receiver) = device_instruction_channel();
    let revoked_auth = AuthHost::new(revoked_home.0.clone(), standard_cancellation())
        .expect("revoked host")
        .with_device_instruction_sender(revoked_sender);
    let (mut revoked_vm, _) = bound_vm(&revoked_auth);
    revoked_auth.revoke();
    let revoked = emit(
        &mut revoked_vm,
        "https://login.example.test/device",
        "PUBLIC",
        60,
    );
    assert_device_result(&revoked, false, Some("policy_inactive"));
    assert_failure_flags(&revoked, false, false, true);
    assert!(revoked_receiver.try_recv().is_err());

    let cancelled_home = TempHome::new("cancelled");
    let (cancelled_sender, cancelled_receiver) = device_instruction_channel();
    let cancellation = standard_cancellation();
    let cancelled_auth = AuthHost::new(cancelled_home.0.clone(), cancellation.clone())
        .expect("cancelled host")
        .with_device_instruction_sender(cancelled_sender);
    let (mut cancelled_vm, _) = bound_vm(&cancelled_auth);
    cancellation.request(CancellationReason::Requested);
    let cancelled = emit(
        &mut cancelled_vm,
        "https://login.example.test/device",
        "PUBLIC",
        60,
    );
    assert_device_result(&cancelled, false, Some("policy_inactive"));
    assert_failure_flags(&cancelled, true, false, false);
    assert!(cancelled_receiver.try_recv().is_err());

    let deadline_home = TempHome::new("deadline");
    let (deadline_sender, deadline_receiver) = device_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(3));
    let deadline = cancellation.deadline_instant().expect("finite deadline");
    let deadline_auth = AuthHost::new(deadline_home.0.clone(), cancellation)
        .expect("deadline host")
        .with_device_instruction_sender(deadline_sender);
    let (mut deadline_vm, _) = bound_vm(&deadline_auth);
    thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5));
    let expired = emit(
        &mut deadline_vm,
        "https://login.example.test/device",
        "PUBLIC",
        60,
    );
    assert_device_result(&expired, false, Some("policy_inactive"));
    assert_failure_flags(&expired, false, true, false);
    assert!(deadline_receiver.try_recv().is_err());
}

#[test]
fn real_rss_system_clock_and_invocation_cancel_adapter_drive_oauth_context() {
    let clock_home = TempHome::new("system-clock");
    let clock_cancellation = standard_cancellation();
    let clock_transport = Arc::new(EmptyTransport {
        calls: AtomicUsize::new(0),
    });
    let clock_auth = AuthHost::new(clock_home.0.clone(), standard_cancellation())
        .expect("clock auth host")
        .with_oauth_host(test_oauth_host(clock_transport, clock_cancellation));
    let (mut clock_vm, clock_home_value) = bound_vm(&clock_auth);
    let policy = invoke(&mut clock_vm, "snapshot", &[clock_home_value]);
    let before_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock after epoch")
        .as_millis() as i64;
    let now = invoke(&mut clock_vm, "now_result", std::slice::from_ref(&policy));
    let after_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock after epoch")
        .as_millis() as i64;
    assert_eq!(field(&now, "ok"), &Value::Bool(true));
    let Value::Int(returned_ms) = field(&now, "value") else {
        panic!("native clock returns the public integer time");
    };
    assert!((before_ms..=after_ms).contains(returned_ms));
    assert_eq!(field(&now, "error"), &Value::Null);

    let process_cancellation = RunCancellation::new();
    let owner_cancellation = standard_cancellation();
    let cancel_transport = Arc::new(CancelDuringTransport {
        cancellation: process_cancellation.clone(),
        calls: AtomicUsize::new(0),
    });
    let transport_home = TempHome::new("cancel-context");
    let transport_auth = AuthHost::new(transport_home.0.clone(), owner_cancellation.clone())
        .expect("transport auth host")
        .with_oauth_host(test_oauth_host(
            cancel_transport.clone(),
            process_cancellation.clone(),
        ));
    let (mut transport_vm, host_home) = bound_vm(&transport_auth);
    let policy = invoke(&mut transport_vm, "snapshot", &[host_home]);
    let started = Instant::now();
    let cancelled = invoke(&mut transport_vm, "send_result", &[policy]);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(cancel_transport.calls.load(Ordering::Acquire), 1);
    assert_eq!(field(&cancelled, "ok"), &Value::Bool(false));
    assert_eq!(text(field(field(&cancelled, "error"), "code")), "cancelled");
    assert_eq!(
        field(field(&cancelled, "error"), "cancelled"),
        &Value::Bool(true)
    );
    assert_eq!(
        field(field(&cancelled, "error"), "deadline_exceeded"),
        &Value::Bool(false)
    );
    assert!(process_cancellation.requested().is_some());
    assert!(process_cancellation.token().is_cancelled());
    assert!(owner_cancellation.requested().is_none());
    assert!(!owner_cancellation.token().is_cancelled());

    let token_only_cancellation = RunCancellation::new();
    let token_only_owner_cancellation = standard_cancellation();
    let token_only_transport = Arc::new(TokenOnlyCancelDuringTransport {
        cancellation: token_only_cancellation.clone(),
        calls: AtomicUsize::new(0),
    });
    let token_only_home = TempHome::new("token-only-cancel-context");
    let token_only_auth = AuthHost::new(
        token_only_home.0.clone(),
        token_only_owner_cancellation.clone(),
    )
    .expect("token-only transport auth host")
    .with_oauth_host(test_oauth_host(
        token_only_transport.clone(),
        token_only_cancellation.clone(),
    ));
    let (mut token_only_vm, host_home) = bound_vm(&token_only_auth);
    let policy = invoke(&mut token_only_vm, "snapshot", &[host_home]);
    let token_only_started = Instant::now();
    let token_only_result = invoke(&mut token_only_vm, "send_result", &[policy]);
    assert!(token_only_started.elapsed() < Duration::from_secs(1));
    assert_eq!(token_only_transport.calls.load(Ordering::Acquire), 1);
    assert_eq!(field(&token_only_result, "ok"), &Value::Bool(false));
    assert_eq!(
        text(field(field(&token_only_result, "error"), "code")),
        "cancelled"
    );
    assert_eq!(
        field(field(&token_only_result, "error"), "cancelled"),
        &Value::Bool(true)
    );
    assert_eq!(
        field(field(&token_only_result, "error"), "deadline_exceeded"),
        &Value::Bool(false)
    );
    assert!(token_only_cancellation.requested().is_none());
    assert!(token_only_cancellation.token().is_cancelled());
    assert!(token_only_owner_cancellation.requested().is_none());
    assert!(!token_only_owner_cancellation.token().is_cancelled());

    let deadline_transport = Arc::new(WaitForDeadline {
        calls: AtomicUsize::new(0),
    });
    let deadline_home = TempHome::new("oauth-deadline");
    let owner_cancellation = RunCancellation::with_timeout(Duration::from_secs(3));
    let deadline_auth = AuthHost::new(deadline_home.0.clone(), owner_cancellation)
        .expect("deadline auth host")
        .with_oauth_host(test_oauth_host(
            deadline_transport.clone(),
            RunCancellation::new(),
        ));
    let (mut deadline_vm, host_home) = bound_vm(&deadline_auth);
    let policy = invoke(&mut deadline_vm, "snapshot", &[host_home]);
    let deadline_started = Instant::now();
    let deadline_result = invoke(&mut deadline_vm, "send_result", &[policy]);
    assert!(deadline_started.elapsed() < Duration::from_secs(3));
    assert_eq!(deadline_transport.calls.load(Ordering::Acquire), 1);
    assert_eq!(field(&deadline_result, "ok"), &Value::Bool(false));
    assert_eq!(
        text(field(field(&deadline_result, "error"), "code")),
        "deadline_exceeded"
    );
    assert_eq!(
        field(field(&deadline_result, "error"), "deadline_exceeded"),
        &Value::Bool(true)
    );
    assert_eq!(
        field(field(&deadline_result, "error"), "cancelled"),
        &Value::Bool(false)
    );
}

struct EmptyTransport {
    calls: AtomicUsize,
}

impl BoundedHttpsTransport for EmptyTransport {
    fn send(
        &self,
        _: &PreparedHttpsRequest,
        _: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(RawHttpsResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: b"{}".to_vec(),
        })
    }
}
