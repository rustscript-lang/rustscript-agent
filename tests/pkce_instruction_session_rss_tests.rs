#![cfg(unix)]

//! DD EXACT2: real authorization-instruction PKCE session workflow.
//!
//! Every test drives the actual closed three-source `AuthEntryRunner`
//! (`rss/auth/pkce_instruction_session.rss`, together with the real `rss/auth/pkce_session.rss`
//! and a typed wrapper) through the restricted auth catalog and an actual native
//! `OAuthHost` owned by the same restricted VM Owner. The native receiver reads
//! the AA bounded instruction queue, derives the generated state from the real
//! captured authorization URL and writes the callback URL to the owned private
//! descriptor; no guest-supplied URL is ever injected.

#[path = "support/owned_fd_observer.rs"]
mod owned_fd_observer;

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll, Waker},
    thread,
    time::{Duration, Instant},
};

use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{
            AuthHost, AuthorizationInstructionSender, PublicAuthorizationInstruction,
            RunOAuthCancel, SystemOAuthClock, auth_host_catalog, authorization_instruction_channel,
        },
        native_browser::NativeBrowserOpener,
        native_https::NativeHttpsTransport,
        oauth::{BrowserOpener, OAuthError, OAuthHost, OAuthIoContext},
    },
    runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner},
};
use rustscript_vm::{Value, Vm};
use url::Url;

const RUNNER_ENTRY: &str = "rss/auth/pkce_instruction_runner.rss";
const SESSION: &str = "rss/auth/pkce_session.rss";
const INSTRUCTION: &str = "rss/auth/pkce_instruction_session.rss";
const CALLBACK_CODE: &str = "DD_INSTRUCTION_SESSION_CALLBACK_CODE";

/// Typed public wrapper. It declares the pinned per-unit `run` result shape and
/// closes every owned capability before returning a sanitized public report.
const RUNNER_SOURCE: &str = r#"
use auth;
use config;
use oauth;
use self::pkce_instruction_session::{run as instruction_run};

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

fn run_for(
    policy: resource<auth.policy>,
    mode: string,
    allow_fallback: bool
) -> PkceSessionResult {
    let intent: BoundedPublicOAuthIntent = {
        credential_id: "fixture-codex",
        path: "/codex/device",
        flow: "authorization_code_pkce",
        callback_mode: mode,
        scopes: ["scope.synthetic"],
        public_query: [
            {name: "client_id", value: "synthetic-client"},
            {name: "response_type", value: "code"}
        ]
    };
    instruction_run(policy, intent, allow_fallback)
}

pub fn run(home: resource<auth.host_home>, command: AuthCommandInput) -> AuthEntryResult {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    let operation: string = command.operation.copy();
    let session_result: PkceSessionResult = if operation == "manual" => {
        run_for(snapshot.policy_handle, "manual", false)
    } else if operation == "none" => {
        run_for(snapshot.policy_handle, "none", false)
    } else if operation == "fallback" => {
        run_for(snapshot.policy_handle, "browser", true)
    } else => {
        run_for(snapshot.policy_handle, "browser", false)
    };
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
            {ok: true, operation: operation, credential_id: null, generation: 0, status: "success", error: null}
        } else => {
            oauth::close_callback(begin.callback_handle);
            oauth::close_verifier(begin.verifier_handle);
            {ok: false, operation: operation, credential_id: null, generation: 0, status: "failed", error: "host_failure"}
        }
    } else if !result_ok => {
        {ok: false, operation: operation, credential_id: null, generation: 0, status: "failed", error: result_code}
    } else => {
        {ok: false, operation: operation, credential_id: null, generation: 0, status: "failed", error: "host_failure"}
    }
}
"#;

/// Direct same-invocation inspector. It keeps the opaque family open and only
/// closes on explicit request so tests can assert scoped cleanup and public
/// opacity. It never copies or serializes a handle.
const INSPECT_SOURCE: &str = r#"
use auth;
use config;
use oauth;
use self::pkce_instruction_session as instruction;

struct PkceSessionResult {
    ok: bool,
    code: string,
    selected_mode: string,
    fallback_used: bool,
    begin: PkceBeginEnvelope?,
    waited: CallbackEnvelope?
}
struct PkceStartResult {
    ok: bool,
    code: string,
    selected_mode: string,
    fallback_used: bool,
    value: PkceBeginEnvelope?
}

pub fn policy(home: resource<auth.host_home>) -> resource<auth.policy> {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    snapshot.policy_handle
}
pub fn run_instruction(
    policy: resource<auth.policy>,
    intent: BoundedPublicOAuthIntent,
    allow: bool
) -> PkceSessionResult {
    instruction::run(policy, intent, allow)
}
pub fn begin_flow(
    policy: resource<auth.policy>,
    intent: BoundedPublicOAuthIntent
) -> PkceBeginEnvelope {
    oauth::pkce_begin(&policy, intent)
}
pub fn emit(handle: resource<oauth.callback>) -> AuthorizationInstructionResultEnvelope {
    oauth::emit_authorization_instruction_result(&handle)
}
pub fn wait(handle: resource<oauth.callback>) -> CallbackResultEnvelope {
    oauth::callback_wait_result(&handle)
}
pub fn close_callback(handle: resource<oauth.callback>) -> null { oauth::close_callback(handle) }
pub fn close_verifier(handle: resource<oauth.verifier>) -> null { oauth::close_verifier(handle) }
pub fn close_code(handle: resource<oauth.authorization_code>) -> null { oauth::close_code(handle) }
"#;

/// Test-only exports around actual production RSS functions. The production
/// instruction-session module remains the exact prefix of this override.
const INSTRUCTION_PROBE_EXPORTS: &str = r#"
pub fn probe_begin_native(
    policy_handle: resource<auth.policy>,
    intent: BoundedPublicOAuthIntent,
    allow_manual_fallback: bool
) -> PkceStartResult {
    session::begin(policy_handle, intent, allow_manual_fallback)
}
pub fn probe_instruction_prepared(start: PkceStartResult) -> PkceSessionResult {
    instruction_session(start)
}
"#;

fn runner_bundle() -> AuthEntryRunner {
    use rustscript_vm::{
        CompileSourceFileOptions, SourceFlavor, compile_source_at_path_with_flavor_and_options,
    };
    let catalog = auth_host_catalog();
    let mut options =
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    options.set_module_override_source(
        "/__rustscript_agent_auth_bundle__/rss/auth/pkce_session.rss",
        include_str!("../rss/auth/pkce_session.rss"),
    );
    options.set_module_override_source(
        "/__rustscript_agent_auth_bundle__/rss/auth/pkce_instruction_session.rss",
        include_str!("../rss/auth/pkce_instruction_session.rss"),
    );
    compile_source_at_path_with_flavor_and_options(
        "/__rustscript_agent_auth_bundle__/rss/auth/pkce_instruction_runner.rss",
        RUNNER_SOURCE,
        SourceFlavor::RustScript,
        options,
    )
    .expect("compile real closed-runner caller with detailed diagnostic");
    let sources = [
        (RUNNER_ENTRY, RUNNER_SOURCE),
        (SESSION, include_str!("../rss/auth/pkce_session.rss")),
        (
            INSTRUCTION,
            include_str!("../rss/auth/pkce_instruction_session.rss"),
        ),
    ];
    AuthEntryRunner::from_bundle(RUNNER_ENTRY, &sources)
        .expect("compile actual closed three-source instruction-session bundle")
}

fn inspect_vm() -> Vm {
    use rustscript_vm::{
        CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };
    let catalog = auth_host_catalog();
    let mut options =
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    options.set_module_override_source(
        "/__rustscript_agent_auth_bundle__/rss/auth/pkce_session.rss",
        include_str!("../rss/auth/pkce_session.rss"),
    );
    let instruction_source = format!(
        "{}{}",
        include_str!("../rss/auth/pkce_instruction_session.rss"),
        INSTRUCTION_PROBE_EXPORTS
    );
    options.set_module_override_source(
        "/__rustscript_agent_auth_bundle__/rss/auth/pkce_instruction_session.rss",
        instruction_source,
    );
    let compiled = compile_source_at_path_with_flavor_and_options(
        "/__rustscript_agent_auth_bundle__/rss/auth/pkce_instruction_inspect.rss",
        INSPECT_SOURCE,
        SourceFlavor::RustScript,
        options,
    )
    .expect("compile actual instruction session with the production catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = TempHome::new("registration");
    let registration_host = AuthHost::new_for_login(
        registration_home.path(),
        RunCancellation::with_timeout(Duration::from_secs(10)),
    )
    .expect("registration host");
    registration_host
        .register(&mut registry, catalog.as_ref())
        .expect("register exact restricted catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind actual restricted auth catalog");
    assert!(matches!(
        vm.run().expect("run RSS declarations"),
        VmStatus::Halted
    ));
    vm
}

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned private test temp"),
        );
        let path = root.join(format!("dd-instruction-{label}-{}", uuid::Uuid::new_v4()));
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

impl Drop for TempHome {
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

struct FailingBrowser;

impl BrowserOpener for FailingBrowser {
    fn open(&self, _authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        Err(OAuthError::Transport {
            message: "synthetic deterministic browser transport failure".into(),
        })
    }
}

/// Real loopback browser: it delivers the callback generated by the native URL
/// to the owned listener so a browser-mode wait can succeed.
#[derive(Default)]
struct LoopbackBrowser {
    opens: AtomicUsize,
    redirects: Mutex<Vec<String>>,
}

impl LoopbackBrowser {
    fn opens(&self) -> usize {
        self.opens.load(Ordering::Acquire)
    }

    fn redirects(&self) -> Vec<String> {
        self.redirects
            .lock()
            .expect("native redirect observer")
            .clone()
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
        self.redirects
            .lock()
            .map_err(|_| OAuthError::Transport {
                message: "native redirect observer unavailable".into(),
            })?
            .push(redirect_uri.clone());
        let state = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "synthetic state missing".into(),
            })?;
        let port = Url::parse(&redirect_uri)
            .ok()
            .and_then(|url| url.port())
            .ok_or_else(|| OAuthError::Transport {
                message: "synthetic callback port missing".into(),
            })?;
        let request = format!(
            "GET /callback?state={state}&code={CALLBACK_CODE} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream =
            TcpStream::connect_timeout(&address, Duration::from_millis(500)).map_err(|_| {
                OAuthError::Transport {
                    message: "synthetic callback connect failed".into(),
                }
            })?;
        stream
            .write_all(request.as_bytes())
            .map_err(|_| OAuthError::Transport {
                message: "synthetic callback write failed".into(),
            })?;
        Ok(())
    }
}

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn assert_fd_closed(fd: i32) {
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
}

fn assert_direct_child_reaped(pid: i32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(result, -1, "direct native launcher is no longer waitable");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "NativeBrowserOpener reaped the direct launcher"
    );
}

fn failing_native_browser(home: &TempHome) -> (NativeBrowserOpener, PathBuf, PathBuf) {
    let executable = home.path().join("native-browser-failure");
    let pids = home.path().join("native-browser-pids");
    let attempted_urls = home.path().join("native-browser-urls");
    fs::write(
        &executable,
        "#!/bin/sh\nprintf '%s\\n' \"$$\" >> \"$HOME/native-browser-pids\"\nprintf '%s\\n' \"$1\" >> \"$HOME/native-browser-urls\"\nexit 23\n",
    )
    .expect("write assigned native launcher fixture");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make assigned native launcher executable");
    let browser = NativeBrowserOpener::new(
        executable,
        BTreeMap::from([(
            "HOME".to_owned(),
            home.path().to_string_lossy().into_owned(),
        )]),
    )
    .expect("construct native opener with only fixture HOME");
    (browser, pids, attempted_urls)
}

fn callback_address(redirect_uri: &str) -> SocketAddr {
    let redirect = Url::parse(redirect_uri).expect("native redirect URI");
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        redirect.port().expect("ephemeral callback port"),
    )
}

fn assert_port_released(redirect_uri: &str) {
    drop(
        TcpListener::bind(callback_address(redirect_uri))
            .expect("native callback listener released"),
    );
}

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

fn optional_field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS record");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or(Value::Null)
}

fn string_field(value: &Value, name: &str) -> String {
    match field(value, name) {
        Value::String(value) => value.to_string(),
        other => panic!("expected string field {name}, got {other:?}"),
    }
}

fn public_intent(mode: &str) -> Value {
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
        (Value::string("callback_mode"), Value::string(mode)),
        (
            Value::string("scopes"),
            Value::array(vec![Value::string("scope.synthetic")]),
        ),
        (
            Value::string("public_query"),
            Value::array(vec![Value::map(vec![
                (Value::string("name"), Value::string("client_id")),
                (Value::string("value"), Value::string("synthetic-client")),
            ])]),
        ),
    ])
}

fn input(operation: &str) -> AuthCommandInput {
    AuthCommandInput {
        operation: operation.to_owned(),
        provider: Some("fixture-provider".to_owned()),
        credential_id: Some("fixture-codex".to_owned()),
    }
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> rustscript_vm::VmResult<Value> {
    let callable = vm.resolve_exported_callable(name)?;
    vm.invoke_callable(callable, args)
}

/// Native receiver over the actual AA queue: it reads each enqueued public
/// instruction, derives the generated state from the real authorization URL
/// and writes the callback URL to the owned private descriptor. It reads until
/// it observes `expected` instructions or the sender disconnects, so it remains
/// available throughout the VM invocation without dropping the sender.
fn serve_queue(
    receiver: mpsc::Receiver<PublicAuthorizationInstruction>,
    writer: Option<OwnedFd>,
    expected: usize,
) -> thread::JoinHandle<Vec<PublicAuthorizationInstruction>> {
    thread::spawn(move || {
        let mut writer = writer.map(fs::File::from);
        let mut observed = Vec::new();
        while observed.len() < expected {
            match receiver.recv() {
                Ok(instruction) => {
                    if let Some(writer) = writer.as_mut() {
                        let state =
                            Url::parse(&instruction.authorization_url)
                                .ok()
                                .and_then(|url| {
                                    url.query_pairs().find_map(|(key, value)| {
                                        (key == "state").then(|| value.into_owned())
                                    })
                                });
                        if let Some(state) = state {
                            let mut callback = Url::parse(&instruction.redirect_uri)
                                .expect("captured redirect URI");
                            callback
                                .query_pairs_mut()
                                .append_pair("state", &state)
                                .append_pair("code", CALLBACK_CODE);
                            let _ = writeln!(writer, "{}", callback.as_str());
                        }
                    }
                    observed.push(instruction);
                }
                Err(_) => break,
            }
        }
        observed
    })
}

fn run_public(
    runner: &AuthEntryRunner,
    home: &TempHome,
    operation: &str,
    browser: Arc<dyn BrowserOpener>,
    manual: Option<OwnedFd>,
    sender: Option<AuthorizationInstructionSender>,
    cancellation: &RunCancellation,
) -> Result<Value, AuthEntryError> {
    let root = home.path().to_path_buf();
    runner.run_with_host_factory(input(operation), cancellation, move |child| {
        let oauth = OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser,
            manual,
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(child.clone())),
        )
        .map_err(|_| "native_callback_inputs_unavailable".to_owned())?;
        let mut host = AuthHost::new_for_login(root, child)?.with_oauth_host(Arc::new(oauth));
        if let Some(sender) = sender {
            host = host.with_authorization_instruction_sender(sender);
        }
        Ok(host)
    })
}

fn inspect_host(
    home: &TempHome,
    browser: Arc<dyn BrowserOpener>,
    manual: Option<OwnedFd>,
    sender: Option<AuthorizationInstructionSender>,
    cancellation: &RunCancellation,
) -> AuthHost {
    let oauth = OAuthHost::new_with_native_inputs(
        Arc::new(NativeHttpsTransport::new()),
        browser,
        manual,
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    )
    .expect("trusted native callback inputs");
    let mut host = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("admitted configured login host")
        .with_oauth_host(Arc::new(oauth));
    if let Some(sender) = sender {
        host = host.with_authorization_instruction_sender(sender);
    }
    host
}

fn close_session_family(vm: &mut Vm, session: &Value) {
    let begin = field(session, "begin");
    let waited = field(session, "waited");
    if let Value::Map(_) = begin {
        if let Value::Map(_) = waited {
            let code = field(&waited, "code_handle");
            if !matches!(code, Value::Null) {
                invoke(vm, "close_code", &[code]).expect("close code");
            }
        }
        invoke(vm, "close_callback", &[field(&begin, "callback_handle")]).expect("close callback");
        invoke(vm, "close_verifier", &[field(&begin, "verifier_handle")]).expect("close verifier");
    }
}

#[test]
fn fd_observer_rejects_retained_owner_and_reused_integer() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "fd_observer_rejects_retained_owner_and_reused_integer",
    ) {
        return;
    }
    owned_fd_observer::retained_and_reused_control(assert_fd_closed);
}

#[test]
fn manual_mode_real_runner_enqueues_before_finish_and_closes_family() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "manual_mode_real_runner_enqueues_before_finish_and_closes_family",
    ) {
        return;
    }
    let runner = runner_bundle();
    let home = TempHome::new("runner-manual");
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(raw_fd);
    let (sender, receiver) = authorization_instruction_channel();
    let server = serve_queue(receiver, Some(writer), 1);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let result = run_public(
        &runner,
        &home,
        "manual",
        Arc::new(NoopBrowser),
        Some(reader),
        Some(sender),
        &cancellation,
    )
    .expect("closed runner executes the real instruction session");
    let fd_observation =
        owned_fd_observer::observe_closed(raw_fd, input_identity, assert_fd_closed);
    assert_eq!(
        field(&result, "ok"),
        Value::Bool(true),
        "closed runner result: {result:?}"
    );
    assert_eq!(field(&result, "status"), Value::string("success"));
    assert_eq!(optional_field(&result, "error"), Value::Null);
    let observed = server.join().expect("native queue observer");
    assert_eq!(
        observed.len(),
        1,
        "exactly one capability-derived instruction"
    );
    assert!(!format!("{result:?}").contains(CALLBACK_CODE));
    assert!(!format!("{observed:?}").contains(CALLBACK_CODE));
    fd_observation.assert();
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn none_mode_real_runner_enqueues_before_finish_and_closes_family() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "none_mode_real_runner_enqueues_before_finish_and_closes_family",
    ) {
        return;
    }
    let runner = runner_bundle();
    let home = TempHome::new("runner-none");
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(raw_fd);
    let (sender, receiver) = authorization_instruction_channel();
    let server = serve_queue(receiver, Some(writer), 1);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let result = run_public(
        &runner,
        &home,
        "none",
        Arc::new(NoopBrowser),
        Some(reader),
        Some(sender),
        &cancellation,
    )
    .expect("closed runner executes the real instruction session");
    let fd_observation =
        owned_fd_observer::observe_closed(raw_fd, input_identity, assert_fd_closed);
    assert_eq!(field(&result, "ok"), Value::Bool(true));
    assert_eq!(field(&result, "status"), Value::string("success"));
    assert_eq!(server.join().expect("native queue observer").len(), 1);
    fd_observation.assert();
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn browser_transport_failure_single_manual_fallback_succeeds_and_delivers() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "browser_transport_failure_single_manual_fallback_succeeds_and_delivers",
    ) {
        return;
    }
    let runner = runner_bundle();
    let home = TempHome::new("runner-fallback");
    let (browser, launcher_pids, attempted_urls) = failing_native_browser(&home);
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(raw_fd);
    let (sender, receiver) = authorization_instruction_channel();
    let server = serve_queue(receiver, Some(writer), 1);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let result = run_public(
        &runner,
        &home,
        "fallback",
        Arc::new(browser),
        Some(reader),
        Some(sender),
        &cancellation,
    )
    .expect("closed runner executes the real instruction session");
    let fd_observation =
        owned_fd_observer::observe_closed(raw_fd, input_identity, assert_fd_closed);
    assert_eq!(field(&result, "ok"), Value::Bool(true));
    assert_eq!(field(&result, "status"), Value::string("success"));
    let observed = server.join().expect("native queue observer");
    assert_eq!(
        observed.len(),
        1,
        "the delivered flow is the one manual fallback"
    );
    assert!(observed[0].authorization_url.starts_with("https://"));
    let launched = fs::read_to_string(launcher_pids).expect("native launcher PID receipt");
    let pids = launched
        .lines()
        .map(|pid| pid.parse::<i32>().expect("direct launcher PID"))
        .collect::<Vec<_>>();
    assert_eq!(pids.len(), 1, "one actual browser subprocess invocation");
    assert_direct_child_reaped(pids[0]);
    let attempted_urls = fs::read_to_string(attempted_urls)
        .expect("private native launcher URL receipt")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(attempted_urls.len(), 1, "one failed browser URL attempt");
    let failed_redirect = Url::parse(&attempted_urls[0])
        .ok()
        .and_then(|url| {
            url.query_pairs()
                .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
        })
        .expect("private failed-browser redirect");
    assert_port_released(&failed_redirect);
    fd_observation.assert();
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn manual_success_reports_manual_mode_and_opaque_capability() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "manual_success_reports_manual_mode_and_opaque_capability",
    ) {
        return;
    }
    let home = TempHome::new("inspect-manual");
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(raw_fd);
    let (sender, receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(
        &home,
        Arc::new(NoopBrowser),
        Some(reader),
        Some(sender),
        &cancellation,
    );
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let server = serve_queue(receiver, Some(writer), 1);
    let session = invoke(
        &mut vm,
        "run_instruction",
        &[policy.clone(), public_intent("manual"), Value::Bool(false)],
    )
    .expect("same-invocation instruction session");
    let fd_observation =
        owned_fd_observer::observe_closed(raw_fd, input_identity, assert_fd_closed);

    assert_eq!(
        field(&session, "ok"),
        Value::Bool(true),
        "session failure code={}, selected_mode={}",
        string_field(&session, "code"),
        string_field(&session, "selected_mode")
    );
    assert_eq!(field(&session, "fallback_used"), Value::Bool(false));
    let begin = field(&session, "begin");
    let waited = field(&session, "waited");
    assert!(!matches!(begin, Value::Null));
    assert!(!matches!(waited, Value::Null));
    assert_eq!(field(&waited, "outcome"), Value::string("success"));
    assert!(matches!(field(&waited, "code_handle"), Value::Int(_)));

    // Delivery precedes finish: the native receiver only produces the callback
    // after it consumes the enqueued instruction, so a successful wait proves
    // the enqueue happened first.
    let observed = server.join().expect("native queue observer");
    assert_eq!(observed.len(), 1);
    assert_eq!(
        observed[0].authorization_url,
        string_field(&begin, "authorization_url"),
        "the enqueued instruction is exactly the capability-derived URL"
    );
    assert_eq!(
        observed[0].redirect_uri,
        string_field(&begin, "redirect_uri")
    );
    let debug = format!("{waited:?}");
    assert!(!debug.contains(CALLBACK_CODE));
    assert!(!debug.contains("state="));
    assert!(!debug.contains("code_challenge="));

    close_session_family(&mut vm, &session);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_port_released(&string_field(&begin, "redirect_uri"));
    fd_observation.assert();
}

#[test]
fn browser_fallback_reports_manual_mode_with_one_enqueue() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "browser_fallback_reports_manual_mode_with_one_enqueue",
    ) {
        return;
    }
    let home = TempHome::new("inspect-fallback");
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(raw_fd);
    let (sender, receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(
        &home,
        Arc::new(FailingBrowser),
        Some(reader),
        Some(sender),
        &cancellation,
    );
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let server = serve_queue(receiver, Some(writer), 1);
    let session = invoke(
        &mut vm,
        "run_instruction",
        &[policy, public_intent("browser"), Value::Bool(true)],
    )
    .expect("same-invocation instruction session");
    let fd_observation =
        owned_fd_observer::observe_closed(raw_fd, input_identity, assert_fd_closed);

    assert_eq!(field(&session, "ok"), Value::Bool(true));
    assert_eq!(field(&session, "selected_mode"), Value::string("manual"));
    assert_eq!(field(&session, "fallback_used"), Value::Bool(true));
    assert_eq!(server.join().expect("native queue observer").len(), 1);
    close_session_family(&mut vm, &session);
    assert_eq!(vm.host_context().resource_count(), 2);
    fd_observation.assert();
}

#[test]
fn forbidden_fallback_keeps_transport_error_without_enqueue_or_fd_use() {
    let home = TempHome::new("inspect-forbidden-fallback");
    let (reader, _writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let (sender, receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(
        &home,
        Arc::new(FailingBrowser),
        Some(reader),
        Some(sender),
        &cancellation,
    );
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let session = invoke(
        &mut vm,
        "run_instruction",
        &[policy, public_intent("browser"), Value::Bool(false)],
    )
    .expect("sanitized failure data");

    assert_eq!(field(&session, "ok"), Value::Bool(false));
    assert_eq!(field(&session, "code"), Value::string("transport_error"));
    assert_eq!(field(&session, "selected_mode"), Value::string("browser"));
    assert_eq!(field(&session, "fallback_used"), Value::Bool(false));
    assert_eq!(optional_field(&session, "begin"), Value::Null);
    assert_eq!(optional_field(&session, "waited"), Value::Null);
    assert_eq!(
        receiver.try_iter().count(),
        0,
        "no enqueue without a live begin"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    // The owned descriptor is untouched because the fallback was forbidden.
    assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
}

#[test]
fn missing_queue_stops_typed_without_wait_or_new_begin_and_sibling_survives() {
    let home = TempHome::new("inspect-missing-queue");
    let browser = Arc::new(LoopbackBrowser::default());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(&home, browser.clone(), None, None, &cancellation);
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");

    // A sibling family opened directly and left live.
    let sibling = invoke(
        &mut vm,
        "begin_flow",
        &[policy.clone(), public_intent("browser")],
    )
    .expect("sibling begin");
    let sibling_redirect = string_field(&sibling, "redirect_uri");
    assert_eq!(vm.host_context().resource_count(), 4);

    let failed = invoke(
        &mut vm,
        "run_instruction",
        &[policy, public_intent("browser"), Value::Bool(false)],
    )
    .expect("missing queue returns sanitized data");
    assert_eq!(field(&failed, "ok"), Value::Bool(false));
    assert_eq!(field(&failed, "code"), Value::string("ui_unavailable"));
    assert_eq!(optional_field(&failed, "begin"), Value::Null);
    assert_eq!(optional_field(&failed, "waited"), Value::Null);
    // Only the failing family was closed; its native listener is released
    // before the unrelated sibling is waited or disposed.
    assert_eq!(vm.host_context().resource_count(), 4);
    let redirects = browser.redirects();
    assert_eq!(redirects.len(), 2, "one actual begin per family");
    assert_port_released(&redirects[1]);

    let wait_result = invoke(&mut vm, "wait", &[field(&sibling, "callback_handle")])
        .expect("sibling callback remains usable");
    assert_eq!(field(&wait_result, "ok"), Value::Bool(true));
    let waited = field(&wait_result, "value");
    assert!(!matches!(waited, Value::Null));
    assert_eq!(field(&waited, "outcome"), Value::string("success"));
    invoke(&mut vm, "close_code", &[field(&waited, "code_handle")]).expect("close sibling code");
    invoke(
        &mut vm,
        "close_callback",
        &[field(&sibling, "callback_handle")],
    )
    .expect("close sibling callback");
    invoke(
        &mut vm,
        "close_verifier",
        &[field(&sibling, "verifier_handle")],
    )
    .expect("close sibling verifier");
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_port_released(&sibling_redirect);
    assert!(browser.opens() >= 1);
}

#[test]
fn closed_queue_stops_with_typed_fact_and_scoped_cleanup() {
    let home = TempHome::new("inspect-closed-queue");
    let browser = Arc::new(LoopbackBrowser::default());
    let (sender, receiver) = authorization_instruction_channel();
    drop(receiver);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(&home, browser.clone(), None, Some(sender), &cancellation);
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let session = invoke(
        &mut vm,
        "run_instruction",
        &[policy, public_intent("browser"), Value::Bool(false)],
    )
    .expect("closed queue returns sanitized data");
    assert_eq!(field(&session, "ok"), Value::Bool(false));
    assert_eq!(field(&session, "code"), Value::string("ui_sink_closed"));
    assert_eq!(field(&session, "selected_mode"), Value::string("browser"));
    assert_eq!(optional_field(&session, "begin"), Value::Null);
    assert_eq!(optional_field(&session, "waited"), Value::Null);
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "scoped cleanup leaves no capability in the arena"
    );
    let redirects = browser.redirects();
    assert_eq!(redirects.len(), 1, "closed queue attempt has no retry");
    assert_eq!(browser.opens(), 1, "closed queue attempt does not re-open");
    assert_port_released(&redirects[0]);
}

#[test]
fn full_queue_stops_with_typed_fact_and_scoped_cleanup() {
    let home = TempHome::new("inspect-full-queue");
    let browser = Arc::new(LoopbackBrowser::default());
    let (sender, receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(&home, browser.clone(), None, Some(sender), &cancellation);
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");

    // Fill the four-slot bounded queue with successful sessions.
    for _ in 0..4 {
        let session = invoke(
            &mut vm,
            "run_instruction",
            &[policy.clone(), public_intent("browser"), Value::Bool(false)],
        )
        .expect("filled session");
        assert_eq!(field(&session, "ok"), Value::Bool(true));
        close_session_family(&mut vm, &session);
    }
    assert_eq!(vm.host_context().resource_count(), 2);

    let full = invoke(
        &mut vm,
        "run_instruction",
        &[policy.clone(), public_intent("browser"), Value::Bool(false)],
    )
    .expect("full queue returns sanitized data");
    assert_eq!(field(&full, "ok"), Value::Bool(false));
    assert_eq!(field(&full, "code"), Value::string("ui_sink_full"));
    assert_eq!(optional_field(&full, "begin"), Value::Null);
    assert_eq!(vm.host_context().resource_count(), 2);
    let redirects = browser.redirects();
    assert_eq!(redirects.len(), 5, "four successes and one failed begin");
    assert_eq!(browser.opens(), 5, "full queue failure does not re-open");
    assert_port_released(&redirects[4]);

    // Draining one instruction allows a fresh sibling family to succeed.
    let drained = receiver.try_recv().expect("queued sibling instruction");
    assert!(drained.authorization_url.starts_with("https://"));
    let sibling = invoke(
        &mut vm,
        "run_instruction",
        &[policy, public_intent("browser"), Value::Bool(false)],
    )
    .expect("sibling session after drain");
    assert_eq!(field(&sibling, "ok"), Value::Bool(true));
    close_session_family(&mut vm, &sibling);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn owner_cancellation_propagates_sanitized_code_without_new_begin() {
    let home = TempHome::new("inspect-cancelled");
    let browser = Arc::new(LoopbackBrowser::default());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(&home, browser.clone(), None, None, &cancellation);
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    cancellation.request(CancellationReason::Requested);
    let session = invoke(
        &mut vm,
        "run_instruction",
        &[policy, public_intent("browser"), Value::Bool(true)],
    )
    .expect("cancelled begin returns sanitized data");
    assert_eq!(field(&session, "ok"), Value::Bool(false));
    assert_eq!(field(&session, "code"), Value::string("policy_inactive"));
    assert_eq!(field(&session, "selected_mode"), Value::string("browser"));
    assert_eq!(field(&session, "fallback_used"), Value::Bool(false));
    assert_eq!(optional_field(&session, "begin"), Value::Null);
    assert_eq!(optional_field(&session, "waited"), Value::Null);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(browser.opens(), 0, "cancellation must not open the browser");
}

#[test]
fn successful_native_begin_then_owner_cancel_hardtraps_and_drains_vm() {
    let home = TempHome::new("inspect-post-begin-cancel");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(LoopbackBrowser::default());
    let (sender, receiver) = authorization_instruction_channel();
    let mut vm = inspect_vm();
    let host = inspect_host(&home, browser.clone(), None, Some(sender), &cancellation);
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let baseline = vm.host_context().resource_count();
    assert_eq!(baseline, 2, "owner baseline before native begin");
    let started = invoke(
        &mut vm,
        "probe_begin_native",
        &[policy, public_intent("browser"), Value::Bool(false)],
    )
    .expect("actual successful native session::begin");
    assert_eq!(field(&started, "ok"), Value::Bool(true));
    assert_eq!(field(&started, "code"), Value::string("ok"));
    assert_eq!(field(&started, "selected_mode"), Value::string("browser"));
    assert_eq!(field(&started, "fallback_used"), Value::Bool(false));
    let begin = field(&started, "value");
    assert!(!matches!(begin, Value::Null));
    let redirect = string_field(&begin, "redirect_uri");
    assert_eq!(vm.host_context().resource_count(), baseline + 2);
    assert_eq!(browser.opens(), 1, "one actual successful browser begin");
    assert_eq!(browser.redirects(), vec![redirect.clone()]);
    assert!(
        matches!(
            TcpListener::bind(callback_address(&redirect)),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse
        ),
        "successful begin owns a live native callback listener"
    );
    assert!(
        receiver.try_recv().is_err(),
        "begin alone delivers no instruction"
    );

    cancellation.request(CancellationReason::Requested);
    let rejected = invoke(
        &mut vm,
        "probe_instruction_prepared",
        std::slice::from_ref(&started),
    );
    let error = rejected.expect_err("VM admission rejects the same closed capability family");
    let error = error.to_string();
    assert!(
        error.contains("resource_already_closed"),
        "pinned VM closed-capability rejection: {error}"
    );
    assert!(
        receiver.try_recv().is_err(),
        "rejected helper sends no instruction"
    );
    assert_eq!(browser.opens(), 1, "rejection triggers no second opener");
    assert_eq!(browser.redirects(), vec![redirect.clone()]);

    // Keep the actual lazy-admission state in the proof; production reset
    // drains every remaining VM resource under its existing one-second bound.
    let post_rejection_arena = vm.host_context().resource_count();
    assert!(
        post_rejection_arena <= baseline + 2,
        "measured post-rejection VM resource arena count: {post_rejection_arena}"
    );
    println!("post-rejection VM resource arena count: {post_rejection_arena}");

    vm.reset_for_reuse()
        .expect("start production VM reset and drain");
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    loop {
        let mut context = Context::from_waker(Waker::noop());
        match vm.poll_reset_for_reuse(&mut context) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(error)) => panic!("production VM drain failed: {error:?}"),
            Poll::Pending if Instant::now() >= deadline => {
                panic!("production VM drain exceeded its one-second bound")
            }
            Poll::Pending => thread::sleep(Duration::from_millis(1)),
        }
    }
    assert_eq!(
        vm.host_context().resource_count(),
        0,
        "VM arena after drain"
    );
    assert_port_released(&redirect);
}

#[test]
fn vm_teardown_reclaims_listener_after_real_enqueue() {
    let home = TempHome::new("inspect-teardown");
    let browser = Arc::new(LoopbackBrowser::default());
    let (sender, receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let mut vm = inspect_vm();
    let host = inspect_host(&home, browser.clone(), None, Some(sender), &cancellation);
    let owner = host.bind_vm(&mut vm).expect("bind actual owner");
    let policy = invoke(&mut vm, "policy", &[field(&owner, "host_home")]).expect("policy");
    let session = invoke(
        &mut vm,
        "run_instruction",
        &[policy, public_intent("browser"), Value::Bool(false)],
    )
    .expect("same-invocation instruction session");
    assert_eq!(field(&session, "ok"), Value::Bool(true));
    let begin = field(&session, "begin");
    let redirect = string_field(&begin, "redirect_uri");
    let queued = receiver.try_recv().expect("actual instruction enqueued");
    assert_eq!(
        queued.authorization_url,
        string_field(&begin, "authorization_url")
    );

    drop(vm);
    assert_port_released(&redirect);
}

#[test]
fn sanitized_public_report_carries_no_raw_material() {
    let runner = runner_bundle();
    let home = TempHome::new("runner-opaque");
    let (reader, writer) = pipe_pair();
    let (sender, receiver) = authorization_instruction_channel();
    let server = serve_queue(receiver, Some(writer), 1);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let result = run_public(
        &runner,
        &home,
        "manual",
        Arc::new(NoopBrowser),
        Some(reader),
        Some(sender),
        &cancellation,
    )
    .expect("closed runner executes the real instruction session");
    let observed = server.join().expect("native queue observer");
    assert_eq!(observed.len(), 1);
    let public = format!("{result:?}");
    assert!(!public.contains(CALLBACK_CODE));
    assert!(!public.contains("state="));
    assert!(!public.contains("code_challenge="));
    assert!(!public.contains("code_verifier"));
    assert!(!public.contains(&observed[0].authorization_url));
    assert!(!public.contains(&observed[0].redirect_uri));
    assert_eq!(field(&result, "ok"), Value::Bool(true));
}
