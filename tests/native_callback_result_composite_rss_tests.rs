use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    net::TcpListener,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
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
        native_browser::NativeBrowserOpener,
        native_https::NativeHttpsTransport,
        oauth::{BrowserOpener, OAuthError, OAuthHost, OAuthIoContext},
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use url::Url;

const CALLBACK_CODE: &str = "NATIVE_XY_CALLBACK_CODE_MARKER";
const FOREIGN_STATE: &str = "NATIVE_XY_FOREIGN_STATE_MARKER";

const GUEST_RESULT_CALLERS: &str = r#"

fn integration_error_facts(error: map) -> map {
    let mut code: string = "";
    let mut cancelled: bool = false;
    let mut deadline_exceeded: bool = false;
    let mut revoked: bool = false;
    if error.has("code") {
        if type(error["code"]) == "string" {
            let coerced: string = error["code"];
            code = coerced;
        }
    }
    if error.has("cancelled") {
        if type(error["cancelled"]) == "bool" {
            let coerced: bool = error["cancelled"];
            cancelled = coerced;
        }
    }
    if error.has("deadline_exceeded") {
        if type(error["deadline_exceeded"]) == "bool" {
            let coerced: bool = error["deadline_exceeded"];
            deadline_exceeded = coerced;
        }
    }
    if error.has("revoked") {
        if type(error["revoked"]) == "bool" {
            let coerced: bool = error["revoked"];
            revoked = coerced;
        }
    }
    {code: code, cancelled: cancelled, deadline_exceeded: deadline_exceeded, revoked: revoked}
}

pub fn integration_begin_branch(
    home: resource<auth.host_home>,
    intent: BoundedPublicOAuthIntent
) -> map {
    let begun: PkceBeginResultEnvelope = begin_result(home, intent);
    if begun.ok => {
        {branch: "continue", ok: true, value: begun.value, error: null}
    } else => {
        {branch: "stop", ok: false, value: begun.value, error: integration_error_facts(begun.error)}
    }
}

pub fn integration_wait_branch(callback_handle: resource<oauth.callback>) -> map {
    let waited: CallbackResultEnvelope = wait_result(callback_handle);
    if waited.ok => {
        {branch: "continue", ok: true, value: waited.value, error: null}
    } else => {
        {branch: "stop", ok: false, value: waited.value, error: integration_error_facts(waited.error)}
    }
}

pub fn integration_probe_native_pair(
    home: resource<auth.host_home>,
    code_handle: resource<oauth.authorization_code>,
    verifier_handle: resource<oauth.verifier>
) -> map {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    let request: TransportPublicRequest = {
        policy_handle: snapshot.policy_handle,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/codex/device",
        public_headers: [
            {name: "accept", value: "application/json"},
            {name: "accept", value: "application/json"}
        ],
        public_body: "grant_type=authorization_code"
    };
    let usage: TransportCredentialUse = {
        kind: "code_verifier",
        access_handle: null,
        refresh_handle: null,
        code_handle: code_handle,
        verifier_handle: verifier_handle,
        device_handle: null
    };
    let response: TransportResultEnvelope = oauth::transport_result(&request, &usage);
    if response.ok => {
        {branch: "continue", ok: true, error: null}
    } else => {
        {branch: "stop", ok: false, error: integration_error_facts(response.error)}
    }
}
"#;

struct FreshLoginHome(PathBuf);

impl FreshLoginHome {
    fn new(label: &str) -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP test-home root"),
        );
        let path = root.join(format!(
            "native-callback-result-composite-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create isolated auth home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy admitted provider config");
        fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
            .expect("write empty test auth store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("restrict isolated home");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("restrict isolated auth files");
            }
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for FreshLoginHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct NoopBrowser {
    opens: AtomicUsize,
}

impl NoopBrowser {
    fn open_count(&self) -> usize {
        self.opens.load(Ordering::Acquire)
    }
}

impl BrowserOpener for NoopBrowser {
    fn open(&self, _authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        self.opens.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

const FD_OBSERVER_CHILD_MARKER: &str = "RUSTSCRIPT_NATIVE_CALLBACK_RSS_FD_OBSERVER_CHILD";
const FD_OBSERVER_CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const FD_OBSERVER_CHILD_OUTPUT_LIMIT: usize = 64 * 1024;

struct OwnedTestChild(Option<Child>);

impl OwnedTestChild {
    fn wait_before(
        &mut self,
        deadline: Instant,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        loop {
            let child = self.0.as_mut().expect("owned child is still present");
            if let Some(status) = child.try_wait()? {
                self.0.take();
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                self.kill_and_wait();
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_and_wait(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for OwnedTestChild {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

struct BoundedChildOutput {
    bytes: Vec<u8>,
    discarded: usize,
}

fn capture_child_output(mut reader: impl Read) -> std::io::Result<BoundedChildOutput> {
    let mut output = BoundedChildOutput {
        bytes: Vec::with_capacity(FD_OBSERVER_CHILD_OUTPUT_LIMIT),
        discarded: 0,
    };
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(read) => {
                let keep = read.min(FD_OBSERVER_CHILD_OUTPUT_LIMIT - output.bytes.len());
                output.bytes.extend_from_slice(&buffer[..keep]);
                output.discarded += read - keep;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn fd_observer_child_is_current_test(test_name: &str) -> bool {
    let Ok(marker) = std::env::var(FD_OBSERVER_CHILD_MARKER) else {
        return false;
    };
    let mut parts = marker.splitn(3, ':');
    let (Some(marked_test), Some(parent_pid), Some(nonce)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if marked_test != test_name
        || parent_pid.parse::<libc::pid_t>().ok() != Some(unsafe { libc::getppid() })
        || uuid::Uuid::parse_str(nonce).is_err()
    {
        return false;
    }
    std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|args| args[0] == "--exact" && args[1] == test_name)
}

fn spawn_fd_observer_child_unless_child(test_name: &str) -> bool {
    if fd_observer_child_is_current_test(test_name) {
        return false;
    }

    let deadline = Instant::now() + FD_OBSERVER_CHILD_TIMEOUT;
    let nonce = uuid::Uuid::new_v4();
    let marker = format!("{test_name}:{}:{nonce}", std::process::id());
    let mut child = OwnedTestChild(Some(
        Command::new(std::env::current_exe().expect("native test executable path"))
            .args(["--exact", test_name, "--nocapture"])
            .env_clear()
            .envs(
                [
                    "PATH",
                    "HOME",
                    "RUSTC",
                    "RUSTUP_HOME",
                    "RUSTUP_TOOLCHAIN",
                    "CARGO_HOME",
                    "LD_LIBRARY_PATH",
                    "TMPDIR",
                    "TEMP",
                    "TMP",
                    "TEST_TMPDIR",
                    "RUSTSCRIPT_AGENT_TEST_TMP",
                    "RUSTSCRIPT_AGENT_TEST_TMPDIR",
                ]
                .into_iter()
                .filter_map(|key| std::env::var_os(key).map(|value| (key, value))),
            )
            .env(FD_OBSERVER_CHILD_MARKER, marker)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn isolated FD-observer child"),
    ));
    let stdout = child
        .0
        .as_mut()
        .expect("owned child is still present")
        .stdout
        .take()
        .expect("child stdout is piped");
    let stderr = child
        .0
        .as_mut()
        .expect("owned child is still present")
        .stderr
        .take()
        .expect("child stderr is piped");
    let stdout_reader = thread::spawn(move || capture_child_output(stdout));
    let stderr_reader = thread::spawn(move || capture_child_output(stderr));

    let status = child.wait_before(deadline);
    let stdout = stdout_reader
        .join()
        .expect("child stdout reader joined")
        .expect("read child stdout");
    let stderr = stderr_reader
        .join()
        .expect("child stderr reader joined")
        .expect("read child stderr");
    let stdout_text = String::from_utf8_lossy(&stdout.bytes);
    let stderr_text = String::from_utf8_lossy(&stderr.bytes);
    let output = format!("{stdout_text}\n{stderr_text}");
    let truncated = stdout.discarded + stderr.discarded;
    let ran_exactly_one_named_test = output
        .lines()
        .filter(|line| line.trim() == "running 1 test")
        .count()
        == 1
        && output
            .lines()
            .filter(|line| line.trim() == format!("test {test_name} ... ok"))
            .count()
            == 1
        && output.lines().any(|line| {
            line.trim()
                .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
        });
    let status = status.expect("child wait completed without an I/O error");
    assert!(
        matches!(status, Some(ref exit) if exit.success())
            && ran_exactly_one_named_test
            && truncated == 0,
        "isolated FD-observer child {test_name} did not pass its one exact test: status={status:?}, ran_exactly_one_named_test={ran_exactly_one_named_test}, truncated_output_bytes={truncated}, stdout={stdout_text}, stderr={stderr_text}"
    );
    true
}

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn rss_source_with_native_result_callers() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let mut source = fs::read_to_string(path).expect("read actual callback RSS source");
    source.push_str(GUEST_RESULT_CALLERS);
    source
}

fn typed_vm() -> Vm {
    let catalog = auth_host_catalog();
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &config_path,
        &rss_source_with_native_result_callers(),
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile actual callback RSS callers against exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = FreshLoginHome::new("catalog-registration");
    let registration_auth = AuthHost::new_for_login(
        registration_home.path(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("construct real catalog registration host");
    registration_auth
        .register(&mut registry, catalog.as_ref())
        .expect("register the same exact auth catalog snapshot");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted auth catalog");
    assert!(matches!(
        vm.run().expect("run actual RSS declarations"),
        VmStatus::Halted
    ));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS result map");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RSS result field"))
}

fn field_if_present(value: &Value, name: &str) -> Option<Value> {
    let Value::Map(entries) = value else {
        panic!("expected typed RSS result map");
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value.clone()),
        _ => None,
    })
}

fn assert_null_or_absent(value: &Value, name: &str) {
    assert!(matches!(
        field_if_present(value, name),
        None | Some(Value::Null)
    ));
}

fn string_field(value: &Value, name: &str) -> String {
    let Value::String(value) = field(value, name) else {
        panic!("expected string RSS field");
    };
    value.to_string()
}

fn public_query(name: &str, value: &str) -> Value {
    Value::map(vec![
        (Value::string("name"), Value::string(name)),
        (Value::string("value"), Value::string(value)),
    ])
}

fn configured_intent(mode: &str) -> Value {
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
            Value::array(vec![
                public_query("client_id", "public-client-id"),
                public_query("response_type", "code"),
            ]),
        ),
    ])
}

fn begin_branch(vm: &mut Vm, owner: &Value, mode: &str) -> Value {
    let callable = vm
        .resolve_exported_callable("integration_begin_branch")
        .expect("compiled RSS begin business branch");
    vm.invoke_callable(
        callable,
        &[field(owner, "host_home"), configured_intent(mode)],
    )
    .expect("execute guest branch on native begin result")
}

fn wait_branch(vm: &mut Vm, callback: &Value) -> Value {
    let callable = vm
        .resolve_exported_callable("integration_wait_branch")
        .expect("compiled RSS wait business branch");
    vm.invoke_callable(callable, std::slice::from_ref(callback))
        .expect("execute guest branch on native callback result")
}

fn result_envelope(branch: &Value) -> Value {
    branch.clone()
}

fn branch_error_code(branch: &Value) -> String {
    string_field(&field(branch, "error"), "code")
}

fn callback_parts(authorization_url: &str) -> (String, String) {
    let authorization = Url::parse(authorization_url).expect("native generated authorization URL");
    let redirect = authorization
        .query_pairs()
        .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
        .expect("native redirect URI in authorization URL");
    let state = authorization
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("native generated callback state");
    (redirect, state)
}

fn callback_url(redirect_uri: &str, state: &str) -> String {
    let mut callback = Url::parse(redirect_uri).expect("native loopback redirect URI");
    callback
        .query_pairs_mut()
        .append_pair("code", CALLBACK_CODE)
        .append_pair("state", state);
    callback.to_string()
}

fn callback_port(redirect_uri: &str) -> u16 {
    Url::parse(redirect_uri)
        .expect("native callback URI")
        .port()
        .expect("ephemeral native callback port")
}

fn assert_callback_port_bound(redirect_uri: &str) {
    assert!(TcpListener::bind(("127.0.0.1", callback_port(redirect_uri))).is_err());
}

fn assert_callback_port_released(redirect_uri: &str) {
    drop(
        TcpListener::bind(("127.0.0.1", callback_port(redirect_uri)))
            .expect("native callback port released"),
    );
}

fn assert_fd_closed(fd: i32) {
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
}

#[cfg(feature = "config-fixture")]
fn assert_native_flow_count(auth: &AuthHost, expected: usize) {
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("fixture-gated native OAuth flow observer"),
        expected
    );
}

#[cfg(not(feature = "config-fixture"))]
fn assert_native_flow_count(_auth: &AuthHost, _expected: usize) {}

fn oauth_host(
    input: Option<OwnedFd>,
    browser: Arc<dyn BrowserOpener>,
    cancellation: &RunCancellation,
) -> Arc<OAuthHost> {
    Arc::new(
        OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser,
            input,
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        )
        .expect("construct actual native callback inputs"),
    )
}

fn auth_host(
    home: &FreshLoginHome,
    oauth: Arc<OAuthHost>,
    cancellation: RunCancellation,
) -> AuthHost {
    AuthHost::new_for_login(home.path(), cancellation)
        .expect("admit configured login home")
        .with_oauth_host(oauth)
}

fn assert_redacted(value: &Value) {
    let rendered = format!("{value:?}");
    assert!(!rendered.contains(CALLBACK_CODE));
    assert!(!rendered.contains(FOREIGN_STATE));
}

fn close_success_family(vm: &mut Vm, begun: &Value, waited: &Value) {
    let begin_value = field(begun, "value");
    let wait_value = field(waited, "value");
    for (name, handle) in [
        ("close_callback", field(&begin_value, "callback_handle")),
        ("close_verifier", field(&begin_value, "verifier_handle")),
        ("close_code", field(&wait_value, "code_handle")),
    ] {
        let close = vm
            .resolve_exported_callable(name)
            .expect("typed resource close export");
        vm.invoke_callable(close, &[handle])
            .expect("explicitly close native callback capability");
    }
}

fn write_callback(writer: OwnedFd, redirect_uri: &str, state: &str) {
    let mut writer = File::from(writer);
    writer
        .write_all(format!("{}\n", callback_url(redirect_uri, state)).as_bytes())
        .expect("send actual generated callback URL through owned pipe");
}

fn invoke_pair_probe(vm: &mut Vm, owner: &Value, code: Value, verifier: Value) -> Value {
    let callable = vm
        .resolve_exported_callable("integration_probe_native_pair")
        .expect("compiled RSS native exchange-pair probe");
    vm.invoke_callable(callable, &[field(owner, "host_home"), code, verifier])
        .expect("execute actual typed code/verifier transport admission")
}

fn assert_pair_rejected_before_transport(probe: &Value) {
    assert_eq!(string_field(probe, "branch"), "stop");
    assert_eq!(branch_error_code(probe), "invalid_headers");
    assert_eq!(field(probe, "ok"), Value::Bool(false));
    assert_redacted(probe);
}

fn compiled_loopback_launcher(directory: &Path) -> (PathBuf, PathBuf) {
    let source_path = directory.join("xy-owned-loopback-launcher.rs");
    let executable = directory.join("xy-owned-loopback-launcher");
    let report = directory.join("xy-launcher-urls");
    let program = r#"
use std::{env, fs::OpenOptions, io::Write, net::TcpStream};
const REPORT: &str = __REPORT__;
const CALLBACK_CODE: &str = "NATIVE_XY_CALLBACK_CODE_MARKER";
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16).expect("high hex") as u8;
            let low = (bytes[index + 2] as char).to_digit(16).expect("low hex") as u8;
            output.push((high << 4) | low);
            index += 3;
        } else if bytes[index] == b'+' {
            output.push(b' ');
            index += 1;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).expect("decoded URL component")
}
fn parameter(query: &str, name: &str) -> String {
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then(|| decode(value))
    }).expect("authorization query parameter")
}
fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    assert_eq!(args.len(), 1, "launcher receives one authorization URL");
    let authorization_url = &args[0];
    OpenOptions::new().create(true).append(true).open(REPORT)
        .expect("open private invocation receipt")
        .write_all(format!("{authorization_url}\n").as_bytes())
        .expect("record helper invocation");
    let (_, query) = authorization_url.split_once('?').expect("authorization query");
    let redirect = parameter(query, "redirect_uri");
    let state = parameter(query, "state");
    let host_port = redirect.strip_prefix("http://127.0.0.1:").expect("loopback redirect")
        .split('/').next().expect("ephemeral port");
    let request = format!(
        "GET /callback?state={state}&code={CALLBACK_CODE} HTTP/1.1\r\nHost: 127.0.0.1:{host_port}\r\n\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", host_port.parse::<u16>().expect("port")))
        .expect("connect to real native listener");
    stream.write_all(request.as_bytes()).expect("send callback request");
}
"#;
    let report_literal = format!("{:?}", report.to_string_lossy());
    fs::write(&source_path, program.replace("__REPORT__", &report_literal))
        .expect("write assigned-TEMP browser launcher fixture");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let result = Command::new(rustc)
        .arg("--edition=2024")
        .arg(&source_path)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile trusted loopback launcher before flow checks");
    assert!(
        result.status.success(),
        "loopback launcher compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    (executable, report)
}

#[test]
fn fd_observer_rejects_retained_owner_and_reused_integer() {
    if spawn_fd_observer_child_unless_child("fd_observer_rejects_retained_owner_and_reused_integer")
    {
        return;
    }
    let (reader, writer) = pipe_pair();
    let number = reader.as_raw_fd();
    assert!(
        std::panic::catch_unwind(|| assert_fd_closed(number)).is_err(),
        "retained owned descriptor must reject closure"
    );
    drop(reader);
    assert_fd_closed(number);
    let replacement = File::open("/dev/null").expect("open a different owned descriptor");
    assert_eq!(
        replacement.as_raw_fd(),
        number,
        "isolated namespace reuses the lowest free descriptor"
    );
    assert!(
        std::panic::catch_unwind(|| assert_fd_closed(number)).is_err(),
        "a reused integer is not proof the original owner leaked"
    );
    drop(replacement);
    assert_fd_closed(number);
    drop(writer);
}

#[test]
fn real_native_manual_and_none_typed_results_drive_guest_and_keep_pair_usable() {
    if spawn_fd_observer_child_unless_child(
        "real_native_manual_and_none_typed_results_drive_guest_and_keep_pair_usable",
    ) {
        return;
    }
    for mode in ["manual", "none"] {
        let home = FreshLoginHome::new(mode);
        let mut vm = typed_vm();
        let (reader, writer) = pipe_pair();
        let raw_fd = reader.as_raw_fd();
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let browser = Arc::new(NoopBrowser::default());
        let oauth = oauth_host(Some(reader), browser.clone(), &cancellation);
        let auth = auth_host(&home, oauth, cancellation);
        let owner = auth
            .bind_vm(&mut vm)
            .expect("bind concrete native AuthHost owner");
        assert_native_flow_count(&auth, 0);

        let begun = begin_branch(&mut vm, &owner, mode);
        assert_eq!(string_field(&begun, "branch"), "continue");
        let begin_result = result_envelope(&begun);
        assert_eq!(field(&begin_result, "ok"), Value::Bool(true));
        assert_null_or_absent(&begin_result, "error");
        let begin_value = field(&begin_result, "value");
        let (redirect_uri, state) =
            callback_parts(&string_field(&begin_value, "authorization_url"));
        assert_callback_port_bound(&redirect_uri);
        write_callback(writer, &redirect_uri, &state);

        let callback = field(&begin_value, "callback_handle");
        let waited = wait_branch(&mut vm, &callback);
        assert_eq!(string_field(&waited, "branch"), "continue");
        let wait_result = result_envelope(&waited);
        assert_eq!(field(&wait_result, "ok"), Value::Bool(true));
        assert_null_or_absent(&wait_result, "error");
        let wait_value = field(&wait_result, "value");
        assert_eq!(string_field(&wait_value, "outcome"), "success");
        assert_eq!(browser.open_count(), 0);
        assert_eq!(vm.host_context().resource_count(), 5);
        assert_native_flow_count(&auth, 1);
        assert_redacted(&waited);
        // The consumed input closes when wait returns. Check before pair probes
        // perform config file IO which may reuse the released FD integer.
        assert_fd_closed(raw_fd);

        // Duplicate public headers fail after the real code/verifier pair has passed
        // native owner/provenance admission, but before any HTTPS request is sent.
        let first_probe = invoke_pair_probe(
            &mut vm,
            &owner,
            field(&wait_value, "code_handle"),
            field(&begin_value, "verifier_handle"),
        );
        assert_pair_rejected_before_transport(&first_probe);
        assert_eq!(vm.host_context().resource_count(), 5);
        assert_native_flow_count(&auth, 1);

        let replay = wait_branch(&mut vm, &callback);
        assert_eq!(string_field(&replay, "branch"), "stop");
        assert_eq!(branch_error_code(&replay), "handle_replayed");
        assert_eq!(
            string_field(&field(&result_envelope(&replay), "error"), "code"),
            "handle_replayed"
        );
        assert_eq!(vm.host_context().resource_count(), 5);
        let second_probe = invoke_pair_probe(
            &mut vm,
            &owner,
            field(&wait_value, "code_handle"),
            field(&begin_value, "verifier_handle"),
        );
        assert_pair_rejected_before_transport(&second_probe);
        assert_native_flow_count(&auth, 1);

        close_success_family(&mut vm, &begin_result, &wait_result);
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_native_flow_count(&auth, 0);
        assert_callback_port_released(&redirect_uri);
    }
}

#[test]
fn native_browser_wait_and_manual_flow_share_host_without_reserving_fd_in_browser() {
    if spawn_fd_observer_child_unless_child(
        "native_browser_wait_and_manual_flow_share_host_without_reserving_fd_in_browser",
    ) {
        return;
    }
    let home = FreshLoginHome::new("browser-manual-isolation");
    // Compile the trusted Rust launcher before any callback wait timing begins.
    let (launcher, report) = compiled_loopback_launcher(home.path());
    let browser: Arc<dyn BrowserOpener> = Arc::new(
        NativeBrowserOpener::new(launcher, BTreeMap::new())
            .expect("trusted compiled loopback launcher"),
    );
    let mut vm = typed_vm();
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let oauth = oauth_host(Some(reader), browser, &cancellation);
    let auth = auth_host(&home, oauth, cancellation);
    let owner = auth
        .bind_vm(&mut vm)
        .expect("bind same concrete native host");
    assert_native_flow_count(&auth, 0);

    let browser_begin = begin_branch(&mut vm, &owner, "browser");
    assert_eq!(string_field(&browser_begin, "branch"), "continue");
    let browser_begin_result = result_envelope(&browser_begin);
    let browser_value = field(&browser_begin_result, "value");
    let browser_url = string_field(&browser_value, "authorization_url");
    let browser_redirect = string_field(&browser_value, "redirect_uri");
    assert_callback_port_bound(&browser_redirect);
    assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
    assert_eq!(
        fs::read_to_string(&report)
            .expect("compiled launcher invocation receipt")
            .trim(),
        browser_url
    );

    let browser_callback = field(&browser_value, "callback_handle");
    let browser_wait = wait_branch(&mut vm, &browser_callback);
    assert_eq!(string_field(&browser_wait, "branch"), "continue");
    let browser_wait_result = result_envelope(&browser_wait);
    let browser_wait_value = field(&browser_wait_result, "value");
    assert_eq!(string_field(&browser_wait_value, "outcome"), "success");
    assert_redacted(&browser_wait);
    assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
    assert_callback_port_released(&browser_redirect);
    assert_native_flow_count(&auth, 1);
    close_success_family(&mut vm, &browser_begin_result, &browser_wait_result);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_native_flow_count(&auth, 0);

    let manual_begin = begin_branch(&mut vm, &owner, "manual");
    assert_eq!(string_field(&manual_begin, "branch"), "continue");
    let manual_begin_result = result_envelope(&manual_begin);
    let manual_value = field(&manual_begin_result, "value");
    let (manual_redirect, manual_state) =
        callback_parts(&string_field(&manual_value, "authorization_url"));
    assert_callback_port_bound(&manual_redirect);
    write_callback(writer, &manual_redirect, &manual_state);

    let manual_callback = field(&manual_value, "callback_handle");
    let manual_wait = wait_branch(&mut vm, &manual_callback);
    assert_eq!(string_field(&manual_wait, "branch"), "continue");
    let manual_wait_result = result_envelope(&manual_wait);
    let manual_wait_value = field(&manual_wait_result, "value");
    assert_eq!(string_field(&manual_wait_value, "outcome"), "success");
    assert_redacted(&manual_wait);
    assert_eq!(
        fs::read_to_string(&report)
            .expect("manual flow must not relaunch BrowserOpener")
            .lines()
            .count(),
        1
    );
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&manual_redirect);
    assert_native_flow_count(&auth, 1);
    close_success_family(&mut vm, &manual_begin_result, &manual_wait_result);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_native_flow_count(&auth, 0);
}

#[test]
fn consumed_input_and_wrong_vm_or_type_leave_the_live_sibling_flow_usable() {
    if spawn_fd_observer_child_unless_child(
        "consumed_input_and_wrong_vm_or_type_leave_the_live_sibling_flow_usable",
    ) {
        return;
    }
    let home = FreshLoginHome::new("consumed-input-foreign-vm");
    let mut vm = typed_vm();
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = oauth_host(Some(reader), browser.clone(), &cancellation);
    let auth = auth_host(&home, oauth, cancellation);
    let owner = auth
        .bind_vm(&mut vm)
        .expect("bind originating native owner");

    let first_begin = begin_branch(&mut vm, &owner, "manual");
    assert_eq!(string_field(&first_begin, "branch"), "continue");
    let first_result = result_envelope(&first_begin);
    let first_value = field(&first_result, "value");
    let (redirect_uri, state) = callback_parts(&string_field(&first_value, "authorization_url"));
    assert_callback_port_bound(&redirect_uri);
    assert_native_flow_count(&auth, 1);

    let consumed_begin = begin_branch(&mut vm, &owner, "manual");
    assert_eq!(string_field(&consumed_begin, "branch"), "stop");
    assert_eq!(branch_error_code(&consumed_begin), "transport_error");
    let consumed_result = result_envelope(&consumed_begin);
    assert_eq!(field(&consumed_result, "ok"), Value::Bool(false));
    assert_null_or_absent(&consumed_result, "value");
    assert_eq!(
        string_field(&field(&consumed_result, "error"), "code"),
        "transport_error"
    );
    assert_eq!(vm.host_context().resource_count(), 4);
    assert_native_flow_count(&auth, 1);

    let mut foreign_vm = typed_vm();
    let _foreign_owner = auth
        .bind_vm(&mut foreign_vm)
        .expect("bind distinct real VM owner");
    let foreign_wait = foreign_vm
        .resolve_exported_callable("integration_wait_branch")
        .expect("same compiled RSS wait branch");
    let foreign_callback = field(&first_value, "callback_handle");
    let foreign_trap = foreign_vm
        .invoke_callable(foreign_wait, std::slice::from_ref(&foreign_callback))
        .expect_err("capability from another VM table must remain a hard trap");
    assert!(
        foreign_trap
            .to_string()
            .contains("resource_handle_wrong_table")
    );
    assert_eq!(vm.host_context().resource_count(), 4);
    assert_native_flow_count(&auth, 1);
    drop(foreign_vm);

    let wrong_wait = vm
        .resolve_exported_callable("integration_wait_branch")
        .expect("compiled RSS wait branch");
    let wrong_resource = vm
        .invoke_callable(
            wrong_wait,
            std::slice::from_ref(&field(&first_value, "verifier_handle")),
        )
        .expect_err("wrong typed resource must trap before consuming the callback");
    assert!(wrong_resource.to_string().contains("resource_"));
    assert_eq!(vm.host_context().resource_count(), 4);
    assert_native_flow_count(&auth, 1);
    assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
    assert_callback_port_bound(&redirect_uri);

    write_callback(writer, &redirect_uri, &state);
    let callback = field(&first_value, "callback_handle");
    let waited = wait_branch(&mut vm, &callback);
    assert_eq!(string_field(&waited, "branch"), "continue");
    let waited_result = result_envelope(&waited);
    assert_eq!(
        string_field(&field(&waited_result, "value"), "outcome"),
        "success"
    );
    assert_redacted(&waited);
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
    assert_native_flow_count(&auth, 1);
    close_success_family(&mut vm, &first_result, &waited_result);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_native_flow_count(&auth, 0);
    assert_eq!(browser.open_count(), 0);
}

#[test]
fn manual_state_mismatch_and_malformed_url_are_typed_sanitized_guest_failures() {
    if spawn_fd_observer_child_unless_child(
        "manual_state_mismatch_and_malformed_url_are_typed_sanitized_guest_failures",
    ) {
        return;
    }
    for (label, input, expected_code) in [
        ("state-mismatch", "state", "state_mismatch"),
        ("malformed-url", "malformed", "malformed_response"),
    ] {
        let home = FreshLoginHome::new(label);
        let mut vm = typed_vm();
        let (reader, writer) = pipe_pair();
        let raw_fd = reader.as_raw_fd();
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let browser = Arc::new(NoopBrowser::default());
        let oauth = oauth_host(Some(reader), browser.clone(), &cancellation);
        let auth = auth_host(&home, oauth, cancellation);
        let owner = auth.bind_vm(&mut vm).expect("bind manual failure owner");

        let begun = begin_branch(&mut vm, &owner, "manual");
        assert_eq!(string_field(&begun, "branch"), "continue");
        let begin_result = result_envelope(&begun);
        let begin_value = field(&begin_result, "value");
        let (redirect_uri, _state) =
            callback_parts(&string_field(&begin_value, "authorization_url"));
        assert_callback_port_bound(&redirect_uri);
        if input == "state" {
            let mut mismatched = Url::parse(&redirect_uri).expect("native redirect URI");
            mismatched
                .query_pairs_mut()
                .append_pair("code", CALLBACK_CODE)
                .append_pair("state", FOREIGN_STATE);
            let mut writer = File::from(writer);
            writer
                .write_all(format!("{}\n", mismatched.as_str()).as_bytes())
                .expect("send actual mismatched-state callback on owned input");
        } else {
            let mut writer = File::from(writer);
            writer
                .write_all(b"MALFORMED_NATIVE_URL_MARKER\n")
                .expect("send malformed callback line on owned input");
        }

        let callback = field(&begin_value, "callback_handle");
        let decision = wait_branch(&mut vm, &callback);
        assert_eq!(string_field(&decision, "branch"), "stop");
        assert_eq!(branch_error_code(&decision), expected_code);
        let wait_result = result_envelope(&decision);
        assert_eq!(field(&wait_result, "ok"), Value::Bool(false));
        assert_null_or_absent(&wait_result, "value");
        let failure = field(&wait_result, "error");
        assert_eq!(string_field(&failure, "code"), expected_code);
        assert_eq!(field(&failure, "cancelled"), Value::Bool(false));
        assert_eq!(field(&failure, "deadline_exceeded"), Value::Bool(false));
        assert_eq!(field(&failure, "revoked"), Value::Bool(false));
        let rendered = format!("{decision:?}");
        assert!(!rendered.contains(CALLBACK_CODE));
        assert!(!rendered.contains(FOREIGN_STATE));
        assert!(!rendered.contains("MALFORMED_NATIVE_URL_MARKER"));
        assert_eq!(browser.open_count(), 0);
        assert_fd_closed(raw_fd);
        assert_callback_port_released(&redirect_uri);
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_native_flow_count(&auth, 0);
    }
}

#[test]
fn missing_native_manual_input_is_returned_as_typed_begin_failure() {
    let home = FreshLoginHome::new("missing-input");
    let mut vm = typed_vm();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = oauth_host(None, browser.clone(), &cancellation);
    let auth = auth_host(&home, oauth, cancellation);
    let owner = auth
        .bind_vm(&mut vm)
        .expect("bind browser-only native owner");

    let begun = begin_branch(&mut vm, &owner, "manual");
    assert_eq!(string_field(&begun, "branch"), "stop");
    assert_eq!(branch_error_code(&begun), "transport_error");
    let result = result_envelope(&begun);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_null_or_absent(&result, "value");
    assert_eq!(
        string_field(&field(&result, "error"), "code"),
        "transport_error"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(browser.open_count(), 0);
    assert_native_flow_count(&auth, 0);
}

#[test]
fn pending_manual_result_cancellation_closes_fd_listener_and_guest_resources() {
    if spawn_fd_observer_child_unless_child(
        "pending_manual_result_cancellation_closes_fd_listener_and_guest_resources",
    ) {
        return;
    }
    let home = FreshLoginHome::new("pending-cancel");
    // Compile the real restricted RSS fixture and prepare the OS pipe before timing.
    let mut vm = typed_vm();
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = oauth_host(Some(reader), browser, &cancellation);
    let auth = auth_host(&home, oauth, cancellation.clone());
    let owner = auth
        .bind_vm(&mut vm)
        .expect("bind cancellable native owner");
    let begun = begin_branch(&mut vm, &owner, "manual");
    assert_eq!(string_field(&begun, "branch"), "continue");
    let begin_result = result_envelope(&begun);
    let begin_value = field(&begin_result, "value");
    let (redirect_uri, _state) = callback_parts(&string_field(&begin_value, "authorization_url"));
    let callback = field(&begin_value, "callback_handle");

    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        started_tx.send(()).expect("signal wait-call worker start");
        let decision = wait_branch(&mut vm, &callback);
        let count = vm.host_context().resource_count();
        (decision, count)
    });
    started_rx
        .recv_timeout(Duration::from_millis(750))
        .expect("wait-call worker started within the accepted budget");
    // The signal precedes invocation; terminal facts and OS cleanup are the proof.
    // It does not prove the worker entered the inner ppoll on every schedule.
    thread::sleep(Duration::from_millis(60));
    let cancelled_at = Instant::now();
    cancellation.request(CancellationReason::Requested);
    let (decision, resource_count) = worker.join().expect("join native callback wait worker");
    assert!(cancelled_at.elapsed() <= Duration::from_millis(750));
    assert_eq!(string_field(&decision, "branch"), "stop");
    assert_eq!(branch_error_code(&decision), "callback_cancelled");
    let result = result_envelope(&decision);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        string_field(&field(&result, "error"), "code"),
        "callback_cancelled"
    );
    assert_eq!(
        field(&field(&result, "error"), "cancelled"),
        Value::Bool(true)
    );
    assert_eq!(
        field(&field(&result, "error"), "deadline_exceeded"),
        Value::Bool(false)
    );
    assert_eq!(resource_count, 2);
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
    assert_native_flow_count(&auth, 0);
    drop(writer);
}

#[test]
fn pending_manual_result_uses_real_deadline_and_rolls_back_native_resources() {
    if spawn_fd_observer_child_unless_child(
        "pending_manual_result_uses_real_deadline_and_rolls_back_native_resources",
    ) {
        return;
    }
    let home = FreshLoginHome::new("pending-deadline");
    // Build RSS and prepare the pipe before starting the original 750ms deadline.
    let mut vm = typed_vm();
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_millis(750));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = oauth_host(Some(reader), browser, &cancellation);
    let auth = auth_host(&home, oauth, cancellation);
    let owner = auth
        .bind_vm(&mut vm)
        .expect("bind real-deadline native owner");
    let begun = begin_branch(&mut vm, &owner, "manual");
    assert_eq!(string_field(&begun, "branch"), "continue");
    let begin_result = result_envelope(&begun);
    let begin_value = field(&begin_result, "value");
    let (redirect_uri, _state) = callback_parts(&string_field(&begin_value, "authorization_url"));
    let callback = field(&begin_value, "callback_handle");

    let wait_started = Instant::now();
    let decision = wait_branch(&mut vm, &callback);
    assert!(wait_started.elapsed() <= Duration::from_secs(10));
    assert_eq!(string_field(&decision, "branch"), "stop");
    assert_eq!(branch_error_code(&decision), "callback_timeout");
    let result = result_envelope(&decision);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        string_field(&field(&result, "error"), "code"),
        "callback_timeout"
    );
    assert_eq!(
        field(&field(&result, "error"), "deadline_exceeded"),
        Value::Bool(true)
    );
    assert_eq!(
        field(&field(&result, "error"), "cancelled"),
        Value::Bool(false)
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
    assert_native_flow_count(&auth, 0);
    drop(writer);
}

#[test]
fn vm_teardown_closes_unread_manual_fd_and_redirect_for_typed_begin_result() {
    if spawn_fd_observer_child_unless_child(
        "vm_teardown_closes_unread_manual_fd_and_redirect_for_typed_begin_result",
    ) {
        return;
    }
    let home = FreshLoginHome::new("vm-teardown");
    let mut vm = typed_vm();
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = oauth_host(Some(reader), browser, &cancellation);
    let auth = auth_host(&home, oauth, cancellation);
    let owner = auth.bind_vm(&mut vm).expect("bind VM-teardown owner");
    let begun = begin_branch(&mut vm, &owner, "none");
    assert_eq!(string_field(&begun, "branch"), "continue");
    let begin_result = result_envelope(&begun);
    let begin_value = field(&begin_result, "value");
    let redirect_uri = string_field(&begin_value, "redirect_uri");
    assert_callback_port_bound(&redirect_uri);
    assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
    assert_native_flow_count(&auth, 1);

    drop(begun);
    drop(begin_result);
    drop(owner);
    drop(vm);
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
    assert_native_flow_count(&auth, 0);
    drop(writer);
}
