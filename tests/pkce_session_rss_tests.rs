use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
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
    runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner},
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use url::Url;

const ENTRY: &str = "/__rustscript_agent_auth_bundle__/rss/auth/pkce_session_test.rss";
const MODULE: &str = "/__rustscript_agent_auth_bundle__/rss/auth/pkce_session.rss";
const CALLBACK_CODE: &str = "PKCE_SESSION_SYNTHETIC_CALLBACK_CODE";
const TEST_SOURCE: &str = r#"
use auth; use config; use oauth; use self::pkce_session as session;
struct PkceStartResult { ok: bool, code: string, selected_mode: string, fallback_used: bool, value: PkceBeginEnvelope? }
struct PkceSessionResult { ok: bool, code: string, selected_mode: string, fallback_used: bool, begin: PkceBeginEnvelope?, waited: CallbackEnvelope? }
pub fn policy(home: resource<auth.host_home>) -> resource<auth.policy> { let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home); snapshot.policy_handle }
pub fn start(policy: resource<auth.policy>, intent: BoundedPublicOAuthIntent, allow: bool) -> PkceStartResult { session::begin(policy, intent, allow) }
pub fn finish_session(start: PkceStartResult) -> PkceSessionResult { session::finish(start) }
pub fn run_session(policy: resource<auth.policy>, intent: BoundedPublicOAuthIntent, allow: bool) -> PkceSessionResult {
    let started: PkceStartResult = session::begin(policy, intent, allow);
    session::finish(started)
}
pub fn close_callback(handle: resource<oauth.callback>) -> null { oauth::close_callback(handle) }
pub fn close_verifier(handle: resource<oauth.verifier>) -> null { oauth::close_verifier(handle) }
pub fn close_code(handle: resource<oauth.authorization_code>) -> null { oauth::close_code(handle) }
pub fn wait_callback(handle: resource<oauth.callback>) -> CallbackResultEnvelope { oauth::callback_wait_result(&handle) }
"#;

const RUNNER_ENTRY: &str = "rss/auth/pkce_session_runner.rss";
const BUNDLE_MODULE: &str = "rss/auth/pkce_session.rss";
const RUNNER_SOURCE: &str = r#"
use auth;
use config;
use oauth;
use self::pkce_session as session;

struct AuthCommandInput {
    operation: string,
    provider: string?,
    credential_id: string?
}
struct AuthEntryResult {
    ok: bool,
    operation: string,
    credential_id: string?,
    generation: int,
    status: string,
    error: string?
}
struct PkceStartResult {
    ok: bool,
    code: string,
    selected_mode: string,
    fallback_used: bool,
    value: PkceBeginEnvelope?
}
struct PkceSessionResult {
    ok: bool,
    code: string,
    selected_mode: string,
    fallback_used: bool,
    begin: PkceBeginEnvelope?,
    waited: CallbackEnvelope?
}
struct BeginEnvelopePresence {
    value: PkceBeginEnvelope?
}
struct CallbackEnvelopePresence {
    value: CallbackEnvelope?
}
struct AuthorizationCodePresence {
    value: resource<oauth.authorization_code>?
}

pub fn run(home: resource<auth.host_home>, command: AuthCommandInput) -> AuthEntryResult {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    let intent: BoundedPublicOAuthIntent = {
        credential_id: "fixture-codex",
        path: "/codex/device",
        flow: "authorization_code_pkce",
        callback_mode: "browser",
        scopes: ["scope.synthetic"],
        public_query: [
            {name: "client_id", value: "synthetic-client"},
            {name: "response_type", value: "code"}
        ]
    };
    let started: PkceStartResult = session::begin(snapshot.policy_handle, intent, false);
    let session_result: PkceSessionResult = session::finish(started);
    let operation: string = command.operation.copy();
    let begin_key_present: bool = session_result.has("begin");
    let waited_key_present: bool = session_result.has("waited");
    let result_ok: bool = session_result.ok;
    let result_code: string = session_result.code;
    let begin_holder: BeginEnvelopePresence = if begin_key_present => {
        {value: session_result.begin}
    } else => {
        {value: null}
    };
    let waited_holder: CallbackEnvelopePresence = if waited_key_present => {
        {value: session_result.waited}
    } else => {
        {value: null}
    };
    let begin_present: bool = begin_holder.has("value");
    let waited_present: bool = waited_holder.has("value");
    if result_ok && begin_present && waited_present => {
        let begin: PkceBeginEnvelope = begin_holder.value;
        let waited: CallbackEnvelope = waited_holder.value;
        let code_holder: AuthorizationCodePresence = {value: waited.code_handle};
        let code_present: bool = code_holder.has("value");
        if code_present => {
            let code: resource<oauth.authorization_code> = code_holder.value;
            oauth::close_code(code);
            oauth::close_callback(begin.callback_handle);
            oauth::close_verifier(begin.verifier_handle);
            {
                ok: true,
                operation: operation,
                credential_id: null,
                generation: 0,
                status: "success",
                error: null
            }
        } else => {
            oauth::close_callback(begin.callback_handle);
            oauth::close_verifier(begin.verifier_handle);
            {
                ok: false,
                operation: operation,
                credential_id: null,
                generation: 0,
                status: "failed",
                error: "host_failure"
            }
        }
    } else if !result_ok => {
        {
            ok: false,
            operation: operation,
            credential_id: null,
            generation: 0,
            status: "failed",
            error: result_code
        }
    } else => {
        {
            ok: false,
            operation: operation,
            credential_id: null,
            generation: 0,
            status: "failed",
            error: "host_failure"
        }
    }
}
"#;

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!("pkce-session-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create isolated home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy synthetic config");
        fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
            .expect("empty auth store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("restrict home");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("restrict file");
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

#[derive(Clone, Copy)]
enum BrowserResult {
    Valid,
    MismatchedState,
    InvalidMethod,
    TransportFailure,
    Pending,
}

struct LoopbackBrowser {
    result: BrowserResult,
    opens: AtomicUsize,
    redirect_uri: Mutex<Option<String>>,
    state: Mutex<Option<String>>,
    stream: Mutex<Option<TcpStream>>,
}

impl LoopbackBrowser {
    fn new(result: BrowserResult) -> Self {
        Self {
            result,
            opens: AtomicUsize::new(0),
            redirect_uri: Mutex::new(None),
            state: Mutex::new(None),
            stream: Mutex::new(None),
        }
    }

    fn redirect_uri(&self) -> String {
        self.redirect_uri
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("captured redirect")
    }

    fn receipt(&self) -> String {
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .expect("callback stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bounded receipt read");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).expect("callback receipt");
        String::from_utf8(bytes).expect("receipt UTF-8")
    }

    fn send_valid_callback(&self) {
        let redirect_uri = self.redirect_uri();
        let state = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("captured generated state");
        let mut callback = Url::parse(&redirect_uri).expect("native callback URI");
        let port = callback.port().expect("ephemeral callback port");
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", CALLBACK_CODE);
        let target = format!(
            "{}?{}",
            callback.path(),
            callback.query().unwrap_or_default()
        );
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .expect("pending native listener accepts callback");
        stream
            .write_all(format!("GET {target} HTTP/1.1").as_bytes())
            .expect("write callback request line");
        stream
            .write_all(&[13, 10])
            .expect("write request line terminator");
        stream
            .write_all(format!("Host: 127.0.0.1:{port}").as_bytes())
            .expect("write callback host");
        stream
            .write_all(&[13, 10])
            .expect("write host line terminator");
        stream
            .write_all(b"Connection: close")
            .expect("write connection header");
        stream
            .write_all(&[13, 10, 13, 10])
            .expect("finish callback request");
        *self.stream.lock().unwrap_or_else(|p| p.into_inner()) = Some(stream);
    }
}

impl BrowserOpener for LoopbackBrowser {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        self.opens.fetch_add(1, Ordering::AcqRel);
        let authorization = Url::parse(authorization_url).map_err(|_| OAuthError::Transport {
            message: "synthetic authorization URL invalid".into(),
        })?;
        let redirect_uri = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "synthetic redirect missing".into(),
            })?;
        *self.redirect_uri.lock().unwrap_or_else(|p| p.into_inner()) = Some(redirect_uri.clone());
        if matches!(self.result, BrowserResult::TransportFailure) {
            return Err(OAuthError::Transport {
                message: "synthetic browser transport failure".into(),
            });
        }
        let state = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "synthetic state missing".into(),
            })?;
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = Some(state.clone());
        if matches!(self.result, BrowserResult::Pending) {
            return Ok(());
        }
        let mut callback = Url::parse(&redirect_uri).map_err(|_| OAuthError::Transport {
            message: "synthetic callback invalid".into(),
        })?;
        let port = callback.port().ok_or_else(|| OAuthError::Transport {
            message: "synthetic callback port missing".into(),
        })?;
        let state = if matches!(self.result, BrowserResult::MismatchedState) {
            "FOREIGN_STATE_MARKER"
        } else {
            state.as_str()
        };
        callback
            .query_pairs_mut()
            .append_pair("state", state)
            .append_pair("code", CALLBACK_CODE);
        let target = format!(
            "{}?{}",
            callback.path(),
            callback.query().unwrap_or_default()
        );
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream =
            TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(|_| {
                OAuthError::Transport {
                    message: "synthetic callback connect failed".into(),
                }
            })?;
        let method = if matches!(self.result, BrowserResult::InvalidMethod) {
            "POST"
        } else {
            "GET"
        };
        write!(
            stream,
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        )
        .map_err(|_| OAuthError::Transport {
            message: "synthetic callback write failed".into(),
        })?;
        *self.stream.lock().unwrap_or_else(|p| p.into_inner()) = Some(stream);
        Ok(())
    }
}

fn compiled_vm() -> Vm {
    let catalog = auth_host_catalog();
    let module_source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/pkce_session.rss"),
    )
    .expect("real session RSS");
    let mut options =
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    options.set_module_override_source(MODULE, &module_source);
    let compiled = compile_source_at_path_with_flavor_and_options(
        ENTRY,
        TEST_SOURCE,
        SourceFlavor::RustScript,
        options,
    )
    .expect("compile wrapper and actual PKCE session module with the production catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = TempHome::new("registration");
    let registration_host = AuthHost::new_for_login(
        registration_home.path(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host");
    registration_host
        .register(&mut registry, catalog.as_ref())
        .expect("register exact catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted catalog");
    assert!(matches!(
        vm.run().expect("run RSS declarations"),
        VmStatus::Halted
    ));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected typed named result")
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing result field {name}"))
}

fn optional_field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected typed named result")
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or(Value::Null)
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> rustscript_vm::VmResult<Value> {
    let callable = vm.resolve_exported_callable(name)?;
    vm.invoke_callable(callable, args)
}

fn public_intent_with(
    credential_id: &str,
    path: &str,
    mode: &str,
    query: &[(&str, &str)],
) -> Value {
    Value::map(vec![
        (Value::string("credential_id"), Value::string(credential_id)),
        (Value::string("path"), Value::string(path)),
        (
            Value::string("flow"),
            Value::string("authorization_code_pkce"),
        ),
        (Value::string("callback_mode"), Value::string(mode)),
        (
            Value::string("scopes"),
            Value::array(vec![Value::string("scope.synthetic")]),
        ),
        (
            Value::string("public_query"),
            Value::array(
                query
                    .iter()
                    .map(|(name, value)| {
                        Value::map(vec![
                            (Value::string("name"), Value::string(*name)),
                            (Value::string("value"), Value::string(*value)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn public_intent(mode: &str) -> Value {
    public_intent_with(
        "fixture-codex",
        "/codex/device",
        mode,
        &[("client_id", "synthetic-client"), ("response_type", "code")],
    )
}

fn create_auth(
    home: &TempHome,
    browser: Arc<LoopbackBrowser>,
    cancellation: &RunCancellation,
) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        browser,
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("configured synthetic login host")
        .with_oauth_host(oauth)
}

fn closed_runner() -> AuthEntryRunner {
    let sources = [
        (RUNNER_ENTRY, RUNNER_SOURCE),
        (BUNDLE_MODULE, include_str!("../rss/auth/pkce_session.rss")),
    ];
    AuthEntryRunner::from_bundle(RUNNER_ENTRY, &sources)
        .expect("compile actual closed two-source auth bundle")
}

fn run_auth_entry(
    runner: &AuthEntryRunner,
    home: &TempHome,
    browser: Arc<LoopbackBrowser>,
    cancellation: &RunCancellation,
) -> Result<(Value, Arc<OAuthHost>), AuthEntryError> {
    let oauth_slot = Arc::new(Mutex::new(None));
    let observer_slot = oauth_slot.clone();
    let input = AuthCommandInput {
        operation: "pkce-run".to_owned(),
        provider: Some("fixture-provider".to_owned()),
        credential_id: Some("fixture-codex".to_owned()),
    };
    let host_home = home.path().to_path_buf();
    let result = runner.run_with_host_factory(input, cancellation, move |child| {
        let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
            Arc::new(NativeHttpsTransport::new()),
            browser,
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(child.clone())),
        ));
        *observer_slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(oauth.clone());
        AuthHost::new_for_login(host_home, child).map(|auth| auth.with_oauth_host(oauth))
    });
    let oauth = oauth_slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .expect("runner factory constructed native OAuth host");
    result.map(|value| (value, oauth))
}

#[cfg(feature = "config-fixture")]
fn assert_no_native_runner_flows(oauth: Arc<OAuthHost>) {
    let home = TempHome::new("runner-flow-observer");
    let observer = AuthHost::new_for_login(
        home.path(),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    )
    .expect("construct native flow observer")
    .with_oauth_host(oauth);
    assert_eq!(
        observer
            .fixture_live_oauth_flow_count()
            .expect("runner native flow count"),
        0
    );
}

fn callback_address(redirect_uri: &str) -> SocketAddr {
    let redirect = Url::parse(redirect_uri).expect("redirect URI");
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        redirect.port().expect("ephemeral port"),
    )
}

fn assert_port_released(redirect_uri: &str) {
    drop(TcpListener::bind(callback_address(redirect_uri)).expect("native listener reclaimed"));
}

fn start_for(vm: &mut Vm, policy: &Value, mode: &str, allow_fallback: bool) -> Value {
    invoke(
        vm,
        "start",
        &[
            policy.clone(),
            public_intent(mode),
            Value::Bool(allow_fallback),
        ],
    )
    .expect("RSS begin result")
}

fn run_for(vm: &mut Vm, policy: &Value, mode: &str, allow_fallback: bool) -> Value {
    invoke(
        vm,
        "run_session",
        &[
            policy.clone(),
            public_intent(mode),
            Value::Bool(allow_fallback),
        ],
    )
    .expect("same-invocation RSS begin and finish")
}

#[test]
fn typed_session_begin_finish_hands_off_and_closes_native_capabilities() {
    let home = TempHome::new("success");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let browser = Arc::new(LoopbackBrowser::new(BrowserResult::Valid));
    let auth = create_auth(&home, browser.clone(), &cancellation);
    let mut vm = compiled_vm();
    let owner = auth.bind_vm(&mut vm).expect("bind real Owner");
    let policy =
        invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("real configured policy");
    let session = run_for(&mut vm, &policy, "browser", false);
    assert_eq!(field(&session, "ok"), Value::Bool(true));
    assert_eq!(field(&session, "selected_mode"), Value::string("browser"));
    let begin = field(&session, "begin");
    let redirect_uri = match field(&begin, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("public redirect"),
    };
    assert_eq!(browser.redirect_uri(), redirect_uri);
    assert_eq!(field(&session, "code"), Value::string("ok"));
    assert_eq!(browser.opens.load(Ordering::Acquire), 1);
    let receipt = browser.receipt();
    assert!(receipt.starts_with("HTTP/1.1 200 OK"));
    assert!(!receipt.contains(CALLBACK_CODE));
    let waited = field(&session, "waited");
    let code = field(&waited, "code_handle");
    let session_begin = field(&session, "begin");
    let callback = field(&session_begin, "callback_handle");
    let verifier = field(&session_begin, "verifier_handle");
    for (name, handle) in [
        ("close_code", code),
        ("close_callback", callback),
        ("close_verifier", verifier),
    ] {
        invoke(&mut vm, name, &[handle]).expect("owned capability close");
    }
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "native resource arena restored to Owner baseline"
    );
    assert_port_released(&redirect_uri);
}

#[test]
fn modes_fallback_and_failure_branches_are_sanitized_and_bounded() {
    let home = TempHome::new("modes");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let browser = Arc::new(LoopbackBrowser::new(BrowserResult::TransportFailure));
    let auth = create_auth(&home, browser.clone(), &cancellation);
    let mut vm = compiled_vm();
    let owner = auth.bind_vm(&mut vm).expect("bind Owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");

    let unknown = run_for(&mut vm, &policy, "attacker-controlled-mode", true);
    assert_eq!(field(&unknown, "ok"), Value::Bool(false));
    assert_eq!(
        field(&unknown, "code"),
        Value::string("oauth_callback_mode_unsupported")
    );
    assert_eq!(field(&unknown, "selected_mode"), Value::string(""));
    assert_eq!(optional_field(&unknown, "begin"), Value::Null);

    let no_fallback = run_for(&mut vm, &policy, "browser", false);
    assert_eq!(field(&no_fallback, "ok"), Value::Bool(false));
    assert_eq!(
        field(&no_fallback, "code"),
        Value::string("transport_error")
    );
    assert_eq!(
        field(&no_fallback, "selected_mode"),
        Value::string("browser")
    );
    assert_eq!(field(&no_fallback, "fallback_used"), Value::Bool(false));
    assert_eq!(optional_field(&no_fallback, "waited"), Value::Null);

    let fallback = run_for(&mut vm, &policy, "browser", true);
    assert_eq!(field(&fallback, "ok"), Value::Bool(false));
    assert_eq!(field(&fallback, "code"), Value::string("invalid_intent"));
    assert_eq!(field(&fallback, "selected_mode"), Value::string("manual"));
    assert_eq!(field(&fallback, "fallback_used"), Value::Bool(true));
    assert_eq!(
        browser.opens.load(Ordering::Acquire),
        2,
        "only the two initial browser attempts invoke the browser; manual retry does not"
    );
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "rollback leaves no capability in the arena"
    );
    assert_port_released(&browser.redirect_uri());

    let manual = run_for(&mut vm, &policy, "manual", false);
    assert_eq!(field(&manual, "ok"), Value::Bool(false));
    assert_eq!(field(&manual, "code"), Value::string("invalid_intent"));
    assert_eq!(field(&manual, "selected_mode"), Value::string("manual"));
    assert_eq!(field(&manual, "fallback_used"), Value::Bool(false));
    assert_eq!(
        browser.opens.load(Ordering::Acquire),
        2,
        "manual rejection does not reopen the browser"
    );
    assert_eq!(vm.host_context().resource_count(), 2);

    let none = run_for(&mut vm, &policy, "none", false);
    assert_eq!(field(&none, "ok"), Value::Bool(false));
    assert_eq!(field(&none, "code"), Value::string("invalid_intent"));
    assert_eq!(field(&none, "selected_mode"), Value::string("none"));
    assert_eq!(field(&none, "fallback_used"), Value::Bool(false));
    assert_eq!(
        browser.opens.load(Ordering::Acquire),
        2,
        "none rejection does not open the browser"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn native_wait_failure_returns_no_stale_capability() {
    for (scenario, expected_code, expected_receipt) in [
        (
            BrowserResult::MismatchedState,
            "state_mismatch",
            "HTTP/1.1 200 OK",
        ),
        (
            BrowserResult::InvalidMethod,
            "invalid_intent",
            "HTTP/1.1 400 Bad Request",
        ),
    ] {
        let home = TempHome::new("wait-failure");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let browser = Arc::new(LoopbackBrowser::new(scenario));
        let auth = create_auth(&home, browser.clone(), &cancellation);
        let mut vm = compiled_vm();
        let owner = auth.bind_vm(&mut vm).expect("bind Owner");
        let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
        let failed = run_for(&mut vm, &policy, "browser", false);
        assert_eq!(field(&failed, "ok"), Value::Bool(false));
        assert_eq!(field(&failed, "code"), Value::string(expected_code));
        assert_eq!(field(&failed, "selected_mode"), Value::string("browser"));
        assert_eq!(field(&failed, "fallback_used"), Value::Bool(false));
        assert_eq!(optional_field(&failed, "begin"), Value::Null);
        assert_eq!(optional_field(&failed, "waited"), Value::Null);
        assert!(!format!("{failed:?}").contains(CALLBACK_CODE));
        assert!(browser.receipt().starts_with(expected_receipt));
        assert_eq!(vm.host_context().resource_count(), 2);
        #[cfg(feature = "config-fixture")]
        assert_eq!(
            auth.fixture_live_oauth_flow_count()
                .expect("terminal flow count"),
            0
        );
        assert_port_released(&browser.redirect_uri());
    }
}

#[test]
fn missing_backend_and_denied_inputs_stop_without_fallback_or_browser_open() {
    let home = TempHome::new("denied-inputs");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(LoopbackBrowser::new(BrowserResult::Valid));
    let auth = create_auth(&home, browser.clone(), &cancellation);
    let mut vm = compiled_vm();
    let owner = auth.bind_vm(&mut vm).expect("bind admitted Owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");

    let denied = [
        (
            public_intent_with(
                "unadmitted-credential",
                "/codex/device",
                "browser",
                &[("client_id", "synthetic-client")],
            ),
            "credential_not_admitted",
        ),
        (
            public_intent_with(
                "fixture-codex",
                "/not-admitted",
                "browser",
                &[("client_id", "synthetic-client")],
            ),
            "path_denied",
        ),
        (
            public_intent_with(
                "fixture-codex",
                "/codex/device",
                "browser",
                &[("authority", "attacker.invalid")],
            ),
            "oauth_intent_invalid",
        ),
    ];
    for (intent, expected_code) in denied {
        let result = invoke(
            &mut vm,
            "run_session",
            &[policy.clone(), intent, Value::Bool(true)],
        )
        .expect("denied begin result is sanitized data");
        assert_eq!(field(&result, "ok"), Value::Bool(false));
        assert_eq!(field(&result, "code"), Value::string(expected_code));
        assert_eq!(field(&result, "selected_mode"), Value::string("browser"));
        assert_eq!(field(&result, "fallback_used"), Value::Bool(false));
        assert_eq!(optional_field(&result, "begin"), Value::Null);
        assert_eq!(optional_field(&result, "waited"), Value::Null);
        assert_eq!(browser.opens.load(Ordering::Acquire), 0);
        assert_eq!(vm.host_context().resource_count(), 2);
        #[cfg(feature = "config-fixture")]
        assert_eq!(
            auth.fixture_live_oauth_flow_count()
                .expect("no denied flow"),
            0
        );
    }

    let missing_home = TempHome::new("missing-backend");
    let missing_cancel = RunCancellation::with_timeout(Duration::from_secs(10));
    let missing_auth = AuthHost::new_for_login(missing_home.path(), missing_cancel)
        .expect("admitted config with no OAuth backend");
    let mut missing_vm = compiled_vm();
    let missing_owner = missing_auth
        .bind_vm(&mut missing_vm)
        .expect("bind missing-backend Owner");
    let missing_policy = invoke(
        &mut missing_vm,
        "policy",
        &[field(&missing_owner, "host_home")],
    )
    .expect("policy");
    let missing = run_for(&mut missing_vm, &missing_policy, "browser", true);
    assert_eq!(field(&missing, "ok"), Value::Bool(false));
    assert_eq!(
        field(&missing, "code"),
        Value::string("callback_unavailable")
    );
    assert_eq!(field(&missing, "selected_mode"), Value::string("browser"));
    assert_eq!(field(&missing, "fallback_used"), Value::Bool(false));
    assert_eq!(missing_vm.host_context().resource_count(), 2);
    assert_eq!(browser.opens.load(Ordering::Acquire), 0);
}

#[test]
fn cancelled_and_expired_begin_contexts_are_typed_terminal_failures() {
    let cancelled_home = TempHome::new("pre-cancelled-begin");
    let cancelled = RunCancellation::with_timeout(Duration::from_secs(10));
    let cancelled_browser = Arc::new(LoopbackBrowser::new(BrowserResult::Valid));
    let cancelled_auth = create_auth(&cancelled_home, cancelled_browser.clone(), &cancelled);
    let mut cancelled_vm = compiled_vm();
    let cancelled_owner = cancelled_auth
        .bind_vm(&mut cancelled_vm)
        .expect("bind Owner");
    let cancelled_policy = invoke(
        &mut cancelled_vm,
        "policy",
        &[field(&cancelled_owner, "host_home")],
    )
    .expect("policy");
    cancelled.request(CancellationReason::Requested);
    let cancelled_result = run_for(&mut cancelled_vm, &cancelled_policy, "browser", true);
    assert_eq!(field(&cancelled_result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&cancelled_result, "code"),
        Value::string("policy_inactive")
    );
    assert_eq!(
        field(&cancelled_result, "fallback_used"),
        Value::Bool(false)
    );
    assert_eq!(cancelled_browser.opens.load(Ordering::Acquire), 0);
    assert_eq!(cancelled_vm.host_context().resource_count(), 2);

    let expired_home = TempHome::new("expired-begin");
    let expired_browser = Arc::new(LoopbackBrowser::new(BrowserResult::Valid));
    let mut expired_vm = compiled_vm();
    let expired = RunCancellation::with_timeout(Duration::from_millis(750));
    let expired_auth = create_auth(&expired_home, expired_browser.clone(), &expired);
    let expired_owner = expired_auth
        .bind_vm(&mut expired_vm)
        .expect("bind finite Owner");
    let expired_policy = invoke(
        &mut expired_vm,
        "policy",
        &[field(&expired_owner, "host_home")],
    )
    .expect("policy");
    let deadline = expired.deadline_instant().expect("finite native deadline");
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !remaining.is_zero() {
        thread::sleep(remaining + Duration::from_millis(1));
    }
    assert!(
        expired.deadline_passed(),
        "the begin context is genuinely expired"
    );
    let expired_result = run_for(&mut expired_vm, &expired_policy, "browser", true);
    assert_eq!(field(&expired_result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&expired_result, "code"),
        Value::string("policy_inactive")
    );
    assert_eq!(field(&expired_result, "fallback_used"), Value::Bool(false));
    assert_eq!(expired_browser.opens.load(Ordering::Acquire), 0);
    assert_eq!(expired_vm.host_context().resource_count(), 2);
}

#[test]
fn pending_listener_is_reclaimed_when_its_vm_is_dropped() {
    let home = TempHome::new("pending-vm-drop");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(LoopbackBrowser::new(BrowserResult::Pending));
    let auth = create_auth(&home, browser.clone(), &cancellation);
    let mut vm = compiled_vm();
    let owner = auth.bind_vm(&mut vm).expect("bind Owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let started = start_for(&mut vm, &policy, "browser", false);
    assert_eq!(field(&started, "ok"), Value::Bool(true));
    let begin = field(&started, "value");
    let redirect_uri = match field(&begin, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("native redirect URI"),
    };
    assert_eq!(browser.opens.load(Ordering::Acquire), 1);
    assert_eq!(vm.host_context().resource_count(), 4);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("pending native flow"),
        1
    );
    drop(started);
    drop(owner);
    drop(vm);
    assert_port_released(&redirect_uri);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("VM-drop cleanup"),
        0
    );
}

#[test]
fn pending_wait_cancellation_and_deadline_return_terminal_codes_and_release_resources() {
    let cancel_home = TempHome::new("pending-cancel");
    let mut cancel_vm = compiled_vm();
    let cancel = RunCancellation::with_timeout(Duration::from_secs(10));
    let cancel_browser = Arc::new(LoopbackBrowser::new(BrowserResult::Pending));
    let cancel_auth = create_auth(&cancel_home, cancel_browser.clone(), &cancel);
    let cancel_owner = cancel_auth.bind_vm(&mut cancel_vm).expect("bind Owner");
    let cancel_policy = invoke(
        &mut cancel_vm,
        "policy",
        &[field(&cancel_owner, "host_home")],
    )
    .expect("policy");
    let cancel_start = start_for(&mut cancel_vm, &cancel_policy, "browser", false);
    let cancel_redirect = cancel_browser.redirect_uri();
    assert_eq!(cancel_browser.opens.load(Ordering::Acquire), 1);
    assert_eq!(cancel_vm.host_context().resource_count(), 4);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        cancel_auth
            .fixture_live_oauth_flow_count()
            .expect("pending cancel flow"),
        1
    );
    // The worker signals before invoke; assertions cover terminal cleanup, not wait-entry ordering.
    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        started_tx.send(()).expect("signal worker scheduling");
        let result = invoke(&mut cancel_vm, "finish_session", &[cancel_start]);
        let resource_count = cancel_vm.host_context().resource_count();
        (result, resource_count, cancel_vm)
    });
    started_rx
        .recv_timeout(Duration::from_millis(750))
        .expect("finish worker is scheduled within the native budget");
    thread::sleep(Duration::from_millis(60));
    let cancelled_at = Instant::now();
    cancel.request(CancellationReason::Requested);
    let (result, resource_count, cancel_vm) = worker.join().expect("cancelled finish worker");
    assert!(cancelled_at.elapsed() <= Duration::from_millis(750));
    let result = result.expect("cancellation returns as RSS session data");
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(field(&result, "code"), Value::string("callback_cancelled"));
    assert_eq!(field(&result, "fallback_used"), Value::Bool(false));
    assert_eq!(optional_field(&result, "begin"), Value::Null);
    assert_eq!(optional_field(&result, "waited"), Value::Null);
    assert_eq!(resource_count, 2);
    assert_port_released(&cancel_redirect);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        cancel_auth
            .fixture_live_oauth_flow_count()
            .expect("cancelled native flow"),
        0
    );
    drop(cancel_vm);

    let deadline_home = TempHome::new("pending-deadline");
    let deadline_browser = Arc::new(LoopbackBrowser::new(BrowserResult::Pending));
    let mut deadline_vm = compiled_vm();
    let deadline = RunCancellation::with_timeout(Duration::from_millis(750));
    let deadline_auth = create_auth(&deadline_home, deadline_browser.clone(), &deadline);
    let deadline_owner = deadline_auth
        .bind_vm(&mut deadline_vm)
        .expect("bind finite Owner");
    let deadline_policy = invoke(
        &mut deadline_vm,
        "policy",
        &[field(&deadline_owner, "host_home")],
    )
    .expect("policy");
    let deadline_start = start_for(&mut deadline_vm, &deadline_policy, "browser", false);
    assert_eq!(
        field(&deadline_start, "ok"),
        Value::Bool(true),
        "begin must finish before deadline wait"
    );
    let deadline_redirect = deadline_browser.redirect_uri();
    assert_eq!(deadline_browser.opens.load(Ordering::Acquire), 1);
    assert_eq!(deadline_vm.host_context().resource_count(), 4);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        deadline_auth
            .fixture_live_oauth_flow_count()
            .expect("pending deadline flow"),
        1
    );
    let wait_started = Instant::now();
    let result = invoke(&mut deadline_vm, "finish_session", &[deadline_start])
        .expect("deadline returns as RSS session data");
    assert!(wait_started.elapsed() <= Duration::from_millis(750));
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(field(&result, "code"), Value::string("callback_timeout"));
    assert_eq!(field(&result, "fallback_used"), Value::Bool(false));
    assert_eq!(optional_field(&result, "begin"), Value::Null);
    assert_eq!(optional_field(&result, "waited"), Value::Null);
    assert_eq!(deadline_vm.host_context().resource_count(), 2);
    assert_port_released(&deadline_redirect);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        deadline_auth
            .fixture_live_oauth_flow_count()
            .expect("deadline native flow"),
        0
    );
}

#[test]
fn wrong_resource_and_foreign_vm_trap_without_invalidating_the_originating_flow() {
    let home = TempHome::new("foreign-resource-origin");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(LoopbackBrowser::new(BrowserResult::Pending));
    let auth = create_auth(&home, browser.clone(), &cancellation);
    let mut vm = compiled_vm();
    let owner = auth.bind_vm(&mut vm).expect("bind originating Owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let started = start_for(&mut vm, &policy, "browser", false);
    assert_eq!(field(&started, "ok"), Value::Bool(true));
    let begin = field(&started, "value");
    let callback = field(&begin, "callback_handle");
    let verifier = field(&begin, "verifier_handle");
    let redirect_uri = match field(&begin, "redirect_uri") {
        Value::String(value) => value.to_string(),
        _ => panic!("native redirect URI"),
    };
    assert_eq!(vm.host_context().resource_count(), 4);

    let wrong_type = invoke(&mut vm, "wait_callback", &[verifier])
        .expect_err("a verifier is not a callback resource");
    assert!(
        wrong_type.to_string().contains("resource_"),
        "typed native rejection: {wrong_type}"
    );
    assert_eq!(vm.host_context().resource_count(), 4);

    let foreign_home = TempHome::new("foreign-resource-target");
    let foreign_auth = AuthHost::new_for_login(
        foreign_home.path(),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    )
    .expect("separate native Owner");
    let mut foreign_vm = compiled_vm();
    let foreign_owner = foreign_auth
        .bind_vm(&mut foreign_vm)
        .expect("bind foreign VM Owner");
    let foreign_error = invoke(&mut foreign_vm, "wait_callback", &[callback])
        .expect_err("originating callback capability cannot cross VM resource tables");
    assert!(
        foreign_error
            .to_string()
            .contains("resource_handle_wrong_table"),
        "foreign VM must hard-trap: {foreign_error}"
    );
    assert_eq!(foreign_vm.host_context().resource_count(), 1);
    assert_eq!(vm.host_context().resource_count(), 4);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("origin flow remains live"),
        1
    );
    drop(foreign_owner);
    drop(foreign_vm);

    browser.send_valid_callback();
    let completed = invoke(&mut vm, "finish_session", &[started])
        .expect("originating callback family remains usable after rejected foreign attempts");
    assert_eq!(field(&completed, "ok"), Value::Bool(true));
    assert_eq!(field(&completed, "code"), Value::string("ok"));
    assert!(browser.receipt().starts_with("HTTP/1.1 200 OK"));
    let completed_begin = field(&completed, "begin");
    let waited = field(&completed, "waited");
    for (name, handle) in [
        ("close_code", field(&waited, "code_handle")),
        ("close_callback", field(&completed_begin, "callback_handle")),
        ("close_verifier", field(&completed_begin, "verifier_handle")),
    ] {
        invoke(&mut vm, name, &[handle]).expect("explicit originating capability close");
    }
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_port_released(&redirect_uri);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("all origin flow resources closed"),
        0
    );
}

#[test]
fn closed_auth_entry_runner_completes_native_success_before_sanitized_projection() {
    let runner = closed_runner();
    let home = TempHome::new("runner-success");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(LoopbackBrowser::new(BrowserResult::Valid));
    let (result, _oauth) = run_auth_entry(&runner, &home, browser.clone(), &cancellation)
        .expect("closed runner invokes real PKCE session");
    assert_eq!(field(&result, "ok"), Value::Bool(true));
    assert_eq!(field(&result, "operation"), Value::string("pkce-run"));
    assert_eq!(optional_field(&result, "credential_id"), Value::Null);
    assert_eq!(field(&result, "generation"), Value::Int(0));
    assert_eq!(field(&result, "status"), Value::string("success"));
    assert_eq!(optional_field(&result, "error"), Value::Null);
    let public_result = format!("{result:?}");
    assert!(!public_result.contains(CALLBACK_CODE));
    assert!(!public_result.contains("synthetic-client"));
    assert_eq!(browser.opens.load(Ordering::Acquire), 1);
    assert!(browser.receipt().starts_with("HTTP/1.1 200 OK"));
    assert_port_released(&browser.redirect_uri());
    #[cfg(feature = "config-fixture")]
    assert_no_native_runner_flows(_oauth);
    assert!(
        !cancellation.watcher_is_armed(),
        "runner disarms its child watcher on return"
    );
}

#[test]
fn closed_auth_entry_runner_projects_typed_failure_and_reclaims_native_state() {
    let runner = closed_runner();
    let home = TempHome::new("runner-failure");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(LoopbackBrowser::new(BrowserResult::TransportFailure));
    let (result, _oauth) = run_auth_entry(&runner, &home, browser.clone(), &cancellation)
        .expect("native begin failure is projected as sanitized runner data");
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(field(&result, "operation"), Value::string("pkce-run"));
    assert_eq!(optional_field(&result, "credential_id"), Value::Null);
    assert_eq!(field(&result, "generation"), Value::Int(0));
    assert_eq!(field(&result, "status"), Value::string("failed"));
    assert_eq!(field(&result, "error"), Value::string("transport_error"));
    let public_result = format!("{result:?}");
    assert!(!public_result.contains(CALLBACK_CODE));
    assert!(!public_result.contains("synthetic-client"));
    assert_eq!(browser.opens.load(Ordering::Acquire), 1);
    assert_port_released(&browser.redirect_uri());
    #[cfg(feature = "config-fixture")]
    assert_no_native_runner_flows(_oauth);
    assert!(
        !cancellation.watcher_is_armed(),
        "runner disarms its child watcher on error data"
    );
}
