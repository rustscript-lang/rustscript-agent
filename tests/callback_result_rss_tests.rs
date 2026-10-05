use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{AuthHost, RunOAuthCancel, SystemOAuthClock, auth_host_catalog},
        native_https::NativeHttpsTransport,
        oauth::{BrowserOpener, OAuthError, OAuthHost, OAuthIoContext},
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use url::Url;

const NATIVE_CALLBACK_CODE: &str = "NATIVE_RSS_CALLBACK_CODE_MARKER";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CallbackRequest {
    #[default]
    Valid,
    MismatchedState,
    InvalidMethod,
}

#[derive(Default)]
struct LoopbackBrowser {
    opened: AtomicBool,
    stream: Mutex<Option<TcpStream>>,
    request: CallbackRequest,
}

impl LoopbackBrowser {
    fn with_request(request: CallbackRequest) -> Self {
        Self {
            request,
            ..Self::default()
        }
    }

    fn was_opened(&self) -> bool {
        self.opened.load(Ordering::Acquire)
    }

    fn receipt(&self) -> String {
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("native callback stream");
        let mut receipt = Vec::new();
        stream
            .read_to_end(&mut receipt)
            .expect("read native callback receipt");
        String::from_utf8(receipt).expect("native callback receipt was not UTF-8")
    }
}

impl BrowserOpener for LoopbackBrowser {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        let authorization = Url::parse(authorization_url).map_err(|_| OAuthError::Transport {
            message: "test authorization URL invalid".into(),
        })?;
        let redirect_uri = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "test callback redirect missing".into(),
            })?;
        let state = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "test callback state missing".into(),
            })?;
        let mut callback = Url::parse(&redirect_uri).map_err(|_| OAuthError::Transport {
            message: "test callback URL invalid".into(),
        })?;
        let port = callback.port().ok_or_else(|| OAuthError::Transport {
            message: "test callback port missing".into(),
        })?;
        let state = if self.request == CallbackRequest::MismatchedState {
            "FOREIGN_CALLBACK_STATE_MARKER"
        } else {
            state.as_str()
        };
        callback
            .query_pairs_mut()
            .append_pair("state", state)
            .append_pair("code", NATIVE_CALLBACK_CODE);
        let target = format!(
            "{}?{}",
            callback.path(),
            callback.query().unwrap_or_default()
        );
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream =
            TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(|_| {
                OAuthError::Transport {
                    message: "test loopback connection failed".into(),
                }
            })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| OAuthError::Transport {
                message: "test callback receipt timeout setup failed".into(),
            })?;
        let method = if self.request == CallbackRequest::InvalidMethod {
            "POST"
        } else {
            "GET"
        };
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|_| OAuthError::Transport {
                message: "test callback request write failed".into(),
            })?;
        *self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(stream);
        self.opened.store(true, Ordering::Release);
        Ok(())
    }
}

#[derive(Default)]
struct NoopBrowser;

impl BrowserOpener for NoopBrowser {
    fn open(&self, _authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        Ok(())
    }
}

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let base =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = base.join(format!("callback-result-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create private auth home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml")).expect("copy config");
        fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
            .expect("write empty auth store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("home file mode");
            }
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn callback_contract_with_rss_branch() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let mut source = fs::read_to_string(path).expect("read actual callback RSS contract");
    source.push_str(
        r#"

pub fn branch_after_begin_failure(
    home: resource<auth.host_home>,
    intent: BoundedPublicOAuthIntent
) -> map {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    let first: PkceBeginResultEnvelope =
        oauth::pkce_begin_result(&snapshot.policy_handle, intent);
    if first.ok => {
        {
            branch: "first_succeeded",
            first_ok: true,
            first_error: first.error,
            second_ok: true,
            second_error: null
        }
    } else => {
        let unsupported: BoundedPublicOAuthIntent = {
            credential_id: "fixture-codex",
            path: "/codex/device",
            flow: "device_code",
            callback_mode: "manual",
            scopes: ["scope.synthetic"],
            public_query: [
                {name: "client_id", value: "public-client-id"},
                {name: "response_type", value: "code"}
            ]
        };
        let second: PkceBeginResultEnvelope =
            oauth::pkce_begin_result(&snapshot.policy_handle, unsupported);
        {
            branch: "after_error",
            first_ok: false,
            first_error: first.error,
            second_ok: second.ok,
            second_error: second.error
        }
    }
}

pub fn branch_after_wait_failure(
    callback_handle: resource<oauth.callback>
) -> map {
    let waited: CallbackResultEnvelope =
        oauth::callback_wait_result(&callback_handle);
    if waited.ok => {
        {
            branch: "wait_succeeded",
            wait_error: null,
            next_action: "continue"
        }
    } else => {
        {
            branch: "after_wait_failure",
            wait_error: waited.error,
            next_action: "stop_and_report"
        }
    }
}
"#,
    );
    source
}

fn compiled_callback_rss() -> Vm {
    let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &source_path,
        &callback_contract_with_rss_branch(),
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile actual callback RSS against restricted auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = TempHome::new("registration");
    let host = AuthHost::new_for_login(
        registration_home.path(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("configured registration host");
    host.register(&mut registry, catalog.as_ref())
        .expect("register exact production auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted auth catalog");
    assert!(matches!(
        vm.run().expect("run RSS declarations"),
        VmStatus::Halted
    ));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected named envelope")
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing named envelope field"))
}

fn public_intent(callback_mode: &str) -> Value {
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
        (Value::string("callback_mode"), Value::string(callback_mode)),
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

#[test]
fn callback_results_allow_rss_branch_after_unavailable_begin() {
    let home = TempHome::new("rss-error-branch");
    let auth = AuthHost::new_for_login(
        home.path(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("configured login admission without an OAuth host");
    let mut vm = compiled_callback_rss();
    let owner = auth.bind_vm(&mut vm).expect("bind real host owner");
    let owner_home = field(&owner, "host_home");
    let begin_result = vm
        .resolve_exported_callable("begin_result")
        .expect("typed RSS begin_result passthrough");
    let passthrough = vm
        .invoke_callable(begin_result, &[owner_home.clone(), public_intent("manual")])
        .expect("typed PKCE begin failure is returned as data");
    assert_eq!(field(&passthrough, "ok"), Value::Bool(false));
    assert_eq!(
        field(&field(&passthrough, "error"), "code"),
        Value::string("callback_unavailable")
    );

    let branch = vm
        .resolve_exported_callable("branch_after_begin_failure")
        .expect("RSS-controlled branch export");
    let result = vm
        .invoke_callable(branch, &[owner_home, public_intent("manual")])
        .expect("RSS returns typed callback failure as data");

    assert_eq!(field(&result, "branch"), Value::string("after_error"));
    assert_eq!(field(&result, "first_ok"), Value::Bool(false));
    assert_eq!(
        field(&field(&result, "first_error"), "code"),
        Value::string("callback_unavailable")
    );
    assert_eq!(field(&result, "second_ok"), Value::Bool(false));
    assert_eq!(
        field(&field(&result, "second_error"), "code"),
        Value::string("oauth_flow_unsupported")
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn native_callback_result_reports_malformed_and_mismatched_facts() {
    for (request, expected_code, expected_receipt) in [
        (
            CallbackRequest::MismatchedState,
            "state_mismatch",
            "HTTP/1.1 200 OK",
        ),
        (
            CallbackRequest::InvalidMethod,
            "invalid_intent",
            "HTTP/1.1 400 Bad Request",
        ),
    ] {
        let home = TempHome::new("typed-bad-callback");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let browser = Arc::new(LoopbackBrowser::with_request(request));
        let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
            Arc::new(NativeHttpsTransport::new()),
            browser.clone(),
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        ));
        let auth = AuthHost::new_for_login(home.path(), cancellation)
            .expect("configured login admission")
            .with_oauth_host(oauth);
        let mut vm = compiled_callback_rss();
        let owner = auth.bind_vm(&mut vm).expect("bind real host owner");
        let begin = vm
            .resolve_exported_callable("begin_result")
            .expect("typed RSS begin_result");
        let begun = vm
            .invoke_callable(
                begin,
                &[field(&owner, "host_home"), public_intent("browser")],
            )
            .expect("native PKCE begin result");
        assert_eq!(field(&begun, "ok"), Value::Bool(true));
        let begin_value = field(&begun, "value");
        let callback = field(&begin_value, "callback_handle");
        let redirect_uri = match field(&begin_value, "redirect_uri") {
            Value::String(value) => value.to_string(),
            _ => panic!("native redirect URI must be public text"),
        };
        let branch = vm
            .resolve_exported_callable("branch_after_wait_failure")
            .expect("RSS failure branch export");
        let result = vm
            .invoke_callable(branch, &[callback])
            .expect("native callback failure is returned as typed facts");
        assert_eq!(
            field(&result, "branch"),
            Value::string("after_wait_failure")
        );
        assert_eq!(
            field(&result, "next_action"),
            Value::string("stop_and_report")
        );
        let failure = field(&result, "wait_error");
        assert_eq!(field(&failure, "code"), Value::string(expected_code));
        assert_eq!(field(&failure, "revoked"), Value::Bool(false));
        assert_eq!(field(&failure, "cancelled"), Value::Bool(false));
        assert_eq!(field(&failure, "deadline_exceeded"), Value::Bool(false));
        let receipt = browser.receipt();
        assert!(receipt.starts_with(expected_receipt));
        assert!(!receipt.contains(NATIVE_CALLBACK_CODE));
        assert!(!receipt.contains("FOREIGN_CALLBACK_STATE_MARKER"));
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_callback_port_released(&redirect_uri);
    }
}

#[test]
fn native_callback_result_reports_cancellation_and_reclaims_partial_socket() {
    let home = TempHome::new("typed-callback-cancel");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        Arc::new(NoopBrowser),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("configured login admission")
        .with_oauth_host(oauth);
    let mut vm = compiled_callback_rss();
    let owner = auth.bind_vm(&mut vm).expect("bind real host owner");
    let begin = vm
        .resolve_exported_callable("begin_result")
        .expect("typed RSS begin_result");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), public_intent("browser")],
        )
        .expect("native PKCE begin result");
    let begin_value = field(&begun, "value");
    let callback = field(&begin_value, "callback_handle");
    let redirect_uri = match field(&begin_value, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("native redirect URI must be public text"),
    };
    let mut partial =
        TcpStream::connect_timeout(&callback_address(&redirect_uri), Duration::from_millis(500))
            .expect("connect to native callback listener");
    partial
        .write_all(b"GET /callback?state=partial")
        .expect("send bounded partial callback request");
    let wait = vm
        .resolve_exported_callable("wait_result")
        .expect("typed RSS wait_result");
    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        started_tx.send(()).expect("signal callback wait start");
        let result = vm.invoke_callable(wait, std::slice::from_ref(&callback));
        (result, vm.host_context().resource_count())
    });
    started_rx
        .recv_timeout(Duration::from_millis(750))
        .expect("callback wait worker started within native budget");
    thread::sleep(Duration::from_millis(60));
    let cancelled_at = Instant::now();
    cancellation.request(CancellationReason::Requested);
    let (result, resource_count) = worker.join().expect("callback wait worker joined");
    assert!(cancelled_at.elapsed() <= Duration::from_millis(750));
    let result = result.expect("cancellation returned as typed callback facts");
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    let failure = field(&result, "error");
    assert_eq!(field(&failure, "code"), Value::string("callback_cancelled"));
    assert_eq!(field(&failure, "cancelled"), Value::Bool(true));
    assert_eq!(field(&failure, "deadline_exceeded"), Value::Bool(false));
    assert_eq!(field(&failure, "revoked"), Value::Bool(false));
    assert_eq!(field(&result, "value"), Value::Null);
    assert_eq!(resource_count, 2);
    drop(partial);
    assert_callback_port_released(&redirect_uri);
}

#[test]
fn native_callback_result_reports_deadline_and_reclaims_listener() {
    let mut vm = compiled_callback_rss();
    let home = TempHome::new("typed-callback-timeout");
    let cancellation = RunCancellation::with_timeout(Duration::from_millis(750));
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        Arc::new(NoopBrowser),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("configured deadline-bounded admission")
        .with_oauth_host(oauth);
    let owner = auth.bind_vm(&mut vm).expect("bind real host owner");
    let begin = vm
        .resolve_exported_callable("begin_result")
        .expect("typed RSS begin_result");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), public_intent("browser")],
        )
        .expect("native PKCE begin before deadline");
    let begin_value = field(&begun, "value");
    let callback = field(&begin_value, "callback_handle");
    let redirect_uri = match field(&begin_value, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("native redirect URI must be public text"),
    };
    let wait = vm
        .resolve_exported_callable("wait_result")
        .expect("typed RSS wait_result");
    let result = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect("deadline returned as typed callback facts");
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    let failure = field(&result, "error");
    assert_eq!(field(&failure, "code"), Value::string("callback_timeout"));
    assert_eq!(field(&failure, "deadline_exceeded"), Value::Bool(true));
    assert_eq!(field(&failure, "cancelled"), Value::Bool(false));
    assert_eq!(field(&failure, "revoked"), Value::Bool(false));
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_callback_port_released(&redirect_uri);
}

#[test]
fn native_callback_result_reports_explicit_revoke_without_leaking_flow() {
    let home = TempHome::new("typed-callback-revoke");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        Arc::new(NoopBrowser),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("configured login admission")
        .with_oauth_host(oauth);
    let mut vm = compiled_callback_rss();
    let owner = auth.bind_vm(&mut vm).expect("bind real host owner");
    let begin = vm
        .resolve_exported_callable("begin_result")
        .expect("typed RSS begin_result");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), public_intent("browser")],
        )
        .expect("native PKCE begin result");
    let begin_value = field(&begun, "value");
    let callback = field(&begin_value, "callback_handle");
    let redirect_uri = match field(&begin_value, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("native redirect URI must be public text"),
    };
    auth.revoke();
    let branch = vm
        .resolve_exported_callable("branch_after_wait_failure")
        .expect("RSS terminal-error branch export");
    let result = vm
        .invoke_callable(branch, &[callback])
        .expect("revocation returned as typed callback facts");
    assert_eq!(
        field(&result, "branch"),
        Value::string("after_wait_failure")
    );
    assert_eq!(
        field(&result, "next_action"),
        Value::string("stop_and_report")
    );
    let failure = field(&result, "wait_error");
    assert_eq!(field(&failure, "code"), Value::string("policy_inactive"));
    assert_eq!(field(&failure, "revoked"), Value::Bool(true));
    assert_eq!(field(&failure, "cancelled"), Value::Bool(false));
    assert_eq!(field(&failure, "deadline_exceeded"), Value::Bool(false));
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_callback_port_released(&redirect_uri);
}

#[test]
fn native_callback_result_vm_drop_releases_open_listener() {
    let home = TempHome::new("typed-callback-vm-drop");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        Arc::new(NoopBrowser),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("configured login admission")
        .with_oauth_host(oauth);
    let mut vm = compiled_callback_rss();
    let owner = auth.bind_vm(&mut vm).expect("bind real host owner");
    let begin = vm
        .resolve_exported_callable("begin_result")
        .expect("typed RSS begin_result");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), public_intent("browser")],
        )
        .expect("native PKCE begin result");
    let begin_value = field(&begun, "value");
    let redirect_uri = match field(&begin_value, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("native redirect URI must be public text"),
    };
    assert_eq!(vm.host_context().resource_count(), 4);
    drop(begun);
    drop(owner);
    drop(vm);
    assert_callback_port_released(&redirect_uri);
}

fn callback_address(redirect_uri: &str) -> SocketAddr {
    let redirect = Url::parse(redirect_uri).expect("native callback redirect URI");
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        redirect.port().expect("native callback port"),
    )
}

fn assert_callback_port_released(redirect_uri: &str) {
    drop(
        TcpListener::bind(callback_address(redirect_uri)).expect("native callback listener closed"),
    );
}

#[test]
fn native_callback_results_preserve_live_family() {
    let home = TempHome::new("native-loopback");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let browser = Arc::new(LoopbackBrowser::default());
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        browser.clone(),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("configured generation-zero login admission")
        .with_oauth_host(oauth);
    let mut vm = compiled_callback_rss();
    let owner = auth.bind_vm(&mut vm).expect("bind real host owner");
    let begin = vm
        .resolve_exported_callable("begin_result")
        .expect("typed RSS begin_result");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), public_intent("browser")],
        )
        .expect("native PKCE begin result envelope");
    assert_eq!(
        field(&begun, "ok"),
        Value::Bool(true),
        "native callback begin dependency result: {:?}",
        field(&begun, "error")
    );
    let begin_value = field(&begun, "value");
    let callback = field(&begin_value, "callback_handle");
    let callback_for_stale_rejection = callback.clone();
    let verifier = field(&begin_value, "verifier_handle");
    let redirect_uri = match field(&begin_value, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("native redirect URI must be public text"),
    };
    assert!(matches!(callback, Value::Int(_)));
    assert!(matches!(verifier, Value::Int(_)));
    assert!(browser.was_opened());

    let wait = vm
        .resolve_exported_callable("wait_result")
        .expect("typed RSS wait_result");
    let first_generation = auth.reload().expect("publish next policy generation");
    let second_generation = auth.reload().expect("publish another policy generation");
    assert!(second_generation > first_generation);
    let mut foreign_vm = compiled_callback_rss();
    let _foreign_owner = auth
        .bind_vm(&mut foreign_vm)
        .expect("bind a distinct VM owner after policy reload");
    let foreign_wait = foreign_vm
        .resolve_exported_callable("wait_result")
        .expect("typed wait_result in second VM");
    let foreign_failure = foreign_vm
        .invoke_callable(foreign_wait, std::slice::from_ref(&callback))
        .expect_err("callback capability cannot cross VM arenas");
    assert!(
        foreign_failure
            .to_string()
            .contains("resource_handle_wrong_table"),
        "foreign arena must fail closed: {foreign_failure}"
    );
    assert_eq!(vm.host_context().resource_count(), 4);
    drop(foreign_vm);

    let wrong_type = vm
        .invoke_callable(wait.clone(), std::slice::from_ref(&verifier))
        .expect_err("verifier capability cannot be used as a callback");
    assert!(
        wrong_type.to_string().contains("resource_"),
        "wrong callback resource type must trap: {wrong_type}"
    );
    assert_eq!(vm.host_context().resource_count(), 4);

    let waited = vm
        .invoke_callable(wait.clone(), std::slice::from_ref(&callback))
        .expect("native loopback callback wait result envelope");
    assert_eq!(
        field(&waited, "ok"),
        Value::Bool(true),
        "native callback wait result: {:?}",
        field(&waited, "error")
    );
    let wait_value = field(&waited, "value");
    assert_eq!(field(&wait_value, "outcome"), Value::string("success"));
    let code = field(&wait_value, "code_handle");
    assert!(matches!(code, Value::Int(_)));
    let receipt = browser.receipt();
    assert!(receipt.starts_with("HTTP/1.1 200 OK"));
    assert!(receipt.contains("Callback received"));
    assert!(!receipt.contains(NATIVE_CALLBACK_CODE));

    let replay = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect("callback replay is a typed failure result");
    assert_eq!(field(&replay, "ok"), Value::Bool(false));
    assert_eq!(
        field(&field(&replay, "error"), "code"),
        Value::string("handle_replayed")
    );
    assert_eq!(vm.host_context().resource_count(), 5);

    for (name, handle) in [
        ("close_callback", callback),
        ("close_verifier", verifier),
        ("close_code", code),
    ] {
        let close = vm
            .resolve_exported_callable(name)
            .expect("typed resource close export");
        vm.invoke_callable(close, &[handle])
            .expect("close the preserved callback family");
    }
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_callback_port_released(&redirect_uri);
    let stale_wait = vm
        .resolve_exported_callable("wait_result")
        .expect("typed RSS wait_result remains registered");
    let stale = vm
        .invoke_callable(
            stale_wait,
            std::slice::from_ref(&callback_for_stale_rejection),
        )
        .expect_err("closed callback handle remains a hard stale-resource rejection");
    assert!(
        stale.to_string().contains("resource_already_closed"),
        "stale capability must not become a typed business failure: {stale}"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}
