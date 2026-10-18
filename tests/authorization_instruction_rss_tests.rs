use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{
            AuthHost, RunOAuthCancel, SystemOAuthClock, auth_host_catalog,
            authorization_instruction_channel,
        },
        native_https::NativeHttpsTransport,
        oauth::{BrowserOpener, OAuthError, OAuthHost, OAuthIoContext},
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostApiCatalog, HostFunctionRegistry, SourceFlavor, Value, Vm,
    VmStatus, compile_source_at_path_with_flavor_and_options,
};
use url::Url;

const CALLBACK_CODE: &str = "SYNTHETIC_CALLBACK_CODE_ONLY";

struct TestHome(PathBuf);

impl TestHome {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned private test temp"),
        );
        let path = root.join(format!(
            "authorization-instruction-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create isolated fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy synthetic configured provider policy");
        fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
            .expect("write empty synthetic credential store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("restrict fixture home");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("restrict fixture file");
            }
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NoopBrowser;

impl BrowserOpener for NoopBrowser {
    fn open(&self, _authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()
    }
}

fn native_oauth(cancellation: &RunCancellation) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        Arc::new(NoopBrowser),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ))
}

fn authorization_contract_source() -> (PathBuf, String) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let mut source = fs::read_to_string(&path).expect("read real callback RSS contract");
    source.push_str(
        r#"

pub fn emit_instruction(
    callback_handle: resource<oauth.callback>
) -> AuthorizationInstructionResultEnvelope {
    oauth::emit_authorization_instruction_result(&callback_handle)
}

pub fn emit_instruction_decision(
    callback_handle: resource<oauth.callback>
) -> map {
    let ack: AuthorizationInstructionResultEnvelope =
        oauth::emit_authorization_instruction_result(&callback_handle);
    if ack.ok.copy() => {
        {action: "await_callback", ack: ack}
    } else => {
        {action: "retain_callback_report_delivery_failure", ack: ack}
    }
}
"#,
    );
    (path, source)
}

fn compile_contract(path: &Path, source: &str) -> (Vm, Arc<HostApiCatalog>) {
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile real RSS plus typed instruction caller against restricted catalog");
    (Vm::new_shared(Arc::new(compiled.program)), catalog)
}

fn register_and_run(auth: &AuthHost, vm: &mut Vm, catalog: &HostApiCatalog) {
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog)
        .expect("register exact auth module descriptors");
    registry
        .bind_vm_cached(vm)
        .expect("bind actual restricted auth catalog");
    assert!(matches!(
        vm.run().expect("execute RSS declarations"),
        VmStatus::Halted
    ));
}

fn restricted_vm(auth: &AuthHost, path: &Path, source: &str) -> Vm {
    let (mut vm, catalog) = compile_contract(path, source);
    register_and_run(auth, &mut vm, catalog.as_ref());
    vm
}

#[cfg(feature = "config-fixture")]
fn assert_no_live_oauth_flows(auth: &AuthHost) {
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
}

#[cfg(not(feature = "config-fixture"))]
fn assert_no_live_oauth_flows(_auth: &AuthHost) {}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS record");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing typed RSS field {name}"))
}

fn string_field(value: &Value, name: &str) -> String {
    let Value::String(value) = field(value, name) else {
        panic!("expected string field {name}");
    };
    value.to_string()
}

fn intent() -> Value {
    Value::map(vec![
        (
            Value::string("credential_id"),
            Value::string("fixture-codex"),
        ),
        (Value::string("path"), Value::string("/codex/device")),
        (
            Value::string("flow"),
            Value::string("authorization_code_pkce"),
        ),
        (Value::string("callback_mode"), Value::string("browser")),
        (
            Value::string("scopes"),
            Value::array(vec![Value::string("scope.synthetic")]),
        ),
        (
            Value::string("public_query"),
            Value::array(vec![
                Value::map(vec![
                    (Value::string("name"), Value::string("client_id")),
                    (Value::string("value"), Value::string("public-client-id")),
                ]),
                Value::map(vec![
                    (Value::string("name"), Value::string("response_type")),
                    (Value::string("value"), Value::string("code")),
                ]),
            ]),
        ),
    ])
}

fn callback_address(redirect_uri: &str) -> SocketAddr {
    let redirect = Url::parse(redirect_uri).expect("native redirect URI");
    SocketAddr::new(
        Ipv4Addr::LOCALHOST.into(),
        redirect.port().expect("ephemeral callback port"),
    )
}

fn assert_port_released(begun: &Value) {
    let address = callback_address(&string_field(begun, "redirect_uri"));
    drop(TcpListener::bind(address).expect("native callback listener released"));
}

fn send_loopback_callback(redirect_uri: &str, state: &str) -> TcpStream {
    let mut callback = Url::parse(redirect_uri).expect("native redirect URI");
    callback
        .query_pairs_mut()
        .append_pair("state", state)
        .append_pair("code", CALLBACK_CODE);
    let request = format!(
        "GET {}?{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        callback.path(),
        callback.query().expect("callback query"),
        callback.port().expect("native callback port"),
    );
    let mut stream =
        TcpStream::connect_timeout(&callback_address(redirect_uri), Duration::from_millis(500))
            .expect("connect to actual loopback callback listener");
    stream
        .write_all(request.as_bytes())
        .expect("send synthetic callback over loopback");
    stream
}

fn read_callback_receipt(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set bounded receipt read");
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .expect("read receipt after native wait processes callback");
    String::from_utf8(bytes).expect("receipt is UTF-8")
}

fn begin(vm: &mut Vm, bound: &Value) -> Value {
    let callable = vm
        .resolve_exported_callable("begin")
        .expect("real RSS begin");
    vm.invoke_callable(callable, &[field(bound, "host_home"), intent()])
        .expect("native PKCE begin through real RSS")
}

fn emit(vm: &mut Vm, callback: &Value) -> Value {
    let callable = vm
        .resolve_exported_callable("emit_instruction")
        .expect("typed RSS instruction emitter");
    vm.invoke_callable(callable, std::slice::from_ref(callback))
        .expect("typed sanitized acknowledgement")
}

fn emit_decision(vm: &mut Vm, callback: &Value) -> Value {
    let callable = vm
        .resolve_exported_callable("emit_instruction_decision")
        .expect("RSS-owned instruction success/failure decision");
    vm.invoke_callable(callable, std::slice::from_ref(callback))
        .expect("typed RSS decision and sanitized acknowledgement")
}

fn callback_state(begun: &Value) -> String {
    Url::parse(&string_field(begun, "authorization_url"))
        .expect("native generated authorization URL")
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("native generated OAuth state")
}

fn wait_for_callback(vm: &mut Vm, begun: &Value) -> Value {
    let callback = field(begun, "callback_handle");
    let mut socket =
        send_loopback_callback(&string_field(begun, "redirect_uri"), &callback_state(begun));
    let wait = vm.resolve_exported_callable("wait").expect("real RSS wait");
    let waited = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect("real native callback wait through RSS");
    assert_eq!(field(&waited, "outcome"), Value::string("success"));
    let receipt = read_callback_receipt(&mut socket);
    assert!(receipt.starts_with("HTTP/1.1 200 OK"));
    assert!(receipt.contains("Callback received"));
    assert!(!receipt.contains(CALLBACK_CODE));
    field(&waited, "code_handle")
}

fn close_resource(vm: &mut Vm, name: &str, resource: Value) {
    let close = vm.resolve_exported_callable(name).expect("real RSS close");
    vm.invoke_callable(close, &[resource])
        .expect("close actual host-issued resource");
}

fn close_flow(vm: &mut Vm, begun: &Value, code: Option<Value>) {
    close_resource(vm, "close_callback", field(begun, "callback_handle"));
    close_resource(vm, "close_verifier", field(begun, "verifier_handle"));
    if let Some(code) = code {
        close_resource(vm, "close_code", code);
    }
}

fn assert_failure(ack: &Value, code: &str) {
    assert_eq!(field(ack, "ok"), Value::Bool(false));
    assert_eq!(field(ack, "value"), Value::Null);
    let failure = field(ack, "error");
    assert_eq!(field(&failure, "code"), Value::string(code));
    assert!(matches!(field(&failure, "cancelled"), Value::Bool(_)));
    assert!(matches!(
        field(&failure, "deadline_exceeded"),
        Value::Bool(_)
    ));
    assert!(matches!(field(&failure, "revoked"), Value::Bool(_)));
}

#[test]
fn native_instructions_are_fifo_bounded_and_full_does_not_consume_callbacks() {
    let home = TestHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let (sender, receiver) = authorization_instruction_channel();
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("default configured login AuthHost")
        .with_oauth_host(native_oauth(&cancellation))
        .with_authorization_instruction_sender(sender);
    let (path, source) = authorization_contract_source();
    let mut vm = restricted_vm(&auth, &path, &source);
    let bound = auth.bind_vm(&mut vm).expect("bind actual owner");
    let mut flows = Vec::new();

    for index in 0..5 {
        let begun = begin(&mut vm, &bound);
        let callback = field(&begun, "callback_handle");
        let decision = emit_decision(&mut vm, &callback);
        let action = if index < 4 {
            "await_callback"
        } else {
            "retain_callback_report_delivery_failure"
        };
        assert_eq!(field(&decision, "action"), Value::string(action));
        let ack = field(&decision, "ack");
        if index < 4 {
            assert_eq!(field(&ack, "ok"), Value::Bool(true));
            assert_eq!(field(&ack, "value"), Value::Bool(true));
            assert_eq!(field(&ack, "error"), Value::Null);
            assert!(!format!("{ack:?}").contains(&string_field(&begun, "authorization_url")));
        } else {
            assert_failure(&ack, "ui_sink_full");
            assert!(!format!("{ack:?}").contains(&string_field(&begun, "authorization_url")));
        }
        flows.push(begun);
    }

    let queued: Vec<_> = receiver.try_iter().collect();
    assert_eq!(queued.len(), 4);
    for (index, instruction) in queued.iter().enumerate() {
        assert_eq!(
            instruction.authorization_url,
            string_field(&flows[index], "authorization_url")
        );
        assert_eq!(
            instruction.redirect_uri,
            string_field(&flows[index], "redirect_uri")
        );
        let debug = format!("{instruction:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("state="));
        assert!(!debug.contains("code_challenge="));
    }

    let rejected_code = wait_for_callback(&mut vm, &flows[4]);
    let sibling_code = wait_for_callback(&mut vm, &flows[0]);
    assert!(matches!(rejected_code, Value::Int(_)));
    assert!(matches!(sibling_code, Value::Int(_)));

    for (index, flow) in flows.iter().enumerate() {
        let code = if index == 0 {
            Some(sibling_code.clone())
        } else if index == 4 {
            Some(rejected_code.clone())
        } else {
            None
        };
        close_flow(&mut vm, flow, code);
    }
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_no_live_oauth_flows(&auth);
    for flow in &flows {
        assert_port_released(flow);
    }
}

fn failed_enqueue_keeps_callback_live(closed: bool, expected_code: &str) {
    let home = TestHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut host = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("default configured login AuthHost")
        .with_oauth_host(native_oauth(&cancellation));
    if closed {
        let (sender, receiver) = authorization_instruction_channel();
        drop(receiver);
        host = host.with_authorization_instruction_sender(sender);
    }
    let (path, source) = authorization_contract_source();
    let mut vm = restricted_vm(&host, &path, &source);
    let bound = host.bind_vm(&mut vm).expect("bind actual owner");
    let begun = begin(&mut vm, &bound);
    let callback = field(&begun, "callback_handle");
    let decision = emit_decision(&mut vm, &callback);
    assert_eq!(
        field(&decision, "action"),
        Value::string("retain_callback_report_delivery_failure")
    );
    let ack = field(&decision, "ack");
    assert_failure(&ack, expected_code);
    assert!(!format!("{ack:?}").contains(&string_field(&begun, "authorization_url")));

    let code = wait_for_callback(&mut vm, &begun);
    close_flow(&mut vm, &begun, Some(code));
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_no_live_oauth_flows(&host);
    assert_port_released(&begun);
}

#[test]
fn missing_and_closed_queue_errors_are_typed_without_consuming_the_callback() {
    failed_enqueue_keeps_callback_live(false, "ui_unavailable");
    failed_enqueue_keeps_callback_live(true, "ui_sink_closed");
}

#[test]
fn closed_callback_resource_hard_traps_without_enqueueing_or_consuming_sibling() {
    let home = TestHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let (sender, receiver) = authorization_instruction_channel();
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("default configured login AuthHost")
        .with_oauth_host(native_oauth(&cancellation))
        .with_authorization_instruction_sender(sender);
    let (path, source) = authorization_contract_source();
    let mut vm = restricted_vm(&auth, &path, &source);
    let bound = auth.bind_vm(&mut vm).expect("bind actual owner");
    let closed_target = begin(&mut vm, &bound);
    let sibling = begin(&mut vm, &bound);
    let stale_callback = field(&closed_target, "callback_handle");

    close_resource(
        &mut vm,
        "close_callback",
        field(&closed_target, "callback_handle"),
    );
    assert_port_released(&closed_target);
    let resources_after_close = vm.host_context().resource_count();
    let emitter = vm
        .resolve_exported_callable("emit_instruction")
        .expect("real RSS instruction emitter");
    let failure = vm
        .invoke_callable(emitter, std::slice::from_ref(&stale_callback))
        .expect_err("closed callback capability must hard-trap at resource borrow");
    assert!(
        failure
            .to_string()
            .contains("resource error [resource_already_closed] in resource::table"),
        "{failure}"
    );
    assert_eq!(vm.host_context().resource_count(), resources_after_close);
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));

    close_resource(
        &mut vm,
        "close_verifier",
        field(&closed_target, "verifier_handle"),
    );
    let sibling_decision = emit_decision(&mut vm, &field(&sibling, "callback_handle"));
    assert_eq!(
        field(&sibling_decision, "action"),
        Value::string("await_callback")
    );
    let sibling_ack = field(&sibling_decision, "ack");
    assert_eq!(field(&sibling_ack, "ok"), Value::Bool(true));
    assert_eq!(field(&sibling_ack, "value"), Value::Bool(true));
    let instruction = receiver.try_recv().expect("live sibling enqueued");
    assert_eq!(
        instruction.authorization_url,
        string_field(&sibling, "authorization_url")
    );
    assert_eq!(
        instruction.redirect_uri,
        string_field(&sibling, "redirect_uri")
    );

    let code = wait_for_callback(&mut vm, &sibling);
    assert!(matches!(code, Value::Int(_)));
    close_flow(&mut vm, &sibling, Some(code));
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_no_live_oauth_flows(&auth);
    assert_port_released(&closed_target);
    assert_port_released(&sibling);
}

fn run_owner_failure_case(revoke: bool) {
    let home = TestHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("default configured login AuthHost")
        .with_oauth_host(native_oauth(&cancellation));
    let (path, source) = authorization_contract_source();
    let mut vm = restricted_vm(&auth, &path, &source);
    let bound = auth.bind_vm(&mut vm).expect("bind actual owner");
    let begun = begin(&mut vm, &bound);
    if revoke {
        auth.revoke();
    } else {
        cancellation.request(CancellationReason::Requested);
    }
    let ack = emit(&mut vm, &field(&begun, "callback_handle"));
    assert_failure(
        &ack,
        if revoke {
            "policy_inactive"
        } else {
            "callback_cancelled"
        },
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_no_live_oauth_flows(&auth);
    assert_port_released(&begun);
}

#[test]
fn owner_revoke_and_cancellation_trigger_security_cleanup_with_sanitized_results() {
    run_owner_failure_case(true);
    run_owner_failure_case(false);
}

#[test]
fn elapsed_native_owner_deadline_cleans_flow_and_returns_typed_fact() {
    let home = TestHome::new();
    let (path, source) = authorization_contract_source();
    let (mut vm, catalog) = compile_contract(&path, &source);
    // Owner-independent preparation: install the restricted auth registry/catalog and
    // execute the RSS declaration run under the original ten-second setup budget.
    // AuthHost::register installs only the static auth module descriptors and never
    // creates or binds an Owner, so this compile/setup I/O does not consume the timed
    // 750ms owner deadline; no assertion, budget or production path changes.
    let preparation = AuthHost::new_for_login(
        home.path(),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    )
    .expect("preparation AuthHost installs declarations under original setup budget");
    register_and_run(&preparation, &mut vm, catalog.as_ref());

    let cancellation = RunCancellation::with_timeout(Duration::from_millis(750));
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("short-deadline fixture AuthHost")
        .with_oauth_host(native_oauth(&cancellation));
    let bound = auth.bind_vm(&mut vm).expect("bind short-deadline owner");
    let begun = begin(&mut vm, &bound);
    std::thread::sleep(Duration::from_millis(800));

    let ack = emit(&mut vm, &field(&begun, "callback_handle"));
    assert_failure(&ack, "callback_timeout");
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_no_live_oauth_flows(&auth);
    assert_port_released(&begun);
}

#[test]
fn foreign_vm_and_wrong_resource_cannot_authorize_instruction_emission() {
    let home = TestHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("default configured login AuthHost")
        .with_oauth_host(native_oauth(&cancellation));
    let (path, source) = authorization_contract_source();
    let mut vm = restricted_vm(&auth, &path, &source);
    let bound = auth.bind_vm(&mut vm).expect("bind source owner");
    let begun = begin(&mut vm, &bound);
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    let initial_resources = vm.host_context().resource_count();
    let wrong_resource = vm
        .resolve_exported_callable("emit_instruction")
        .expect("typed RSS instruction emitter");
    assert!(
        vm.invoke_callable(wrong_resource, std::slice::from_ref(&verifier))
            .is_err()
    );
    assert_eq!(vm.host_context().resource_count(), initial_resources);

    let mut foreign_vm = restricted_vm(&auth, &path, &source);
    let _foreign_bound = auth
        .bind_vm(&mut foreign_vm)
        .expect("bind sibling VM owner");
    let foreign_call = foreign_vm
        .resolve_exported_callable("emit_instruction")
        .expect("typed RSS emitter in foreign VM");
    assert!(
        foreign_vm
            .invoke_callable(foreign_call, std::slice::from_ref(&callback))
            .is_err()
    );
    assert_eq!(vm.host_context().resource_count(), initial_resources);

    let ack = emit(&mut vm, &callback);
    assert_eq!(field(&ack, "ok"), Value::Bool(false));
    assert_failure(&ack, "ui_unavailable");
    let code = wait_for_callback(&mut vm, &begun);
    close_flow(&mut vm, &begun, Some(code));
    drop(foreign_vm);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_no_live_oauth_flows(&auth);
    assert_port_released(&begun);
}

#[test]
fn vm_teardown_reclaims_native_listener_after_actual_queue_enqueue() {
    let home = TestHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let (sender, receiver) = authorization_instruction_channel();
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("default configured login AuthHost")
        .with_oauth_host(native_oauth(&cancellation))
        .with_authorization_instruction_sender(sender);
    let (path, source) = authorization_contract_source();
    let mut vm = restricted_vm(&auth, &path, &source);
    let bound = auth.bind_vm(&mut vm).expect("bind actual owner");
    let begun = begin(&mut vm, &bound);
    let ack = emit(&mut vm, &field(&begun, "callback_handle"));
    assert_eq!(field(&ack, "ok"), Value::Bool(true));
    let queued = receiver.try_recv().expect("actual instruction enqueued");
    assert_eq!(
        queued.authorization_url,
        string_field(&begun, "authorization_url")
    );
    let address = callback_address(&string_field(&begun, "redirect_uri"));

    drop(vm);
    assert_no_live_oauth_flows(&auth);
    drop(TcpListener::bind(address).expect("VM teardown released native callback port"));
}
