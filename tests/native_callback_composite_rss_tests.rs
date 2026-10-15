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
    },
    thread,
    time::{Duration, Instant},
};

use rustscript_agent::{
    RunCancellation,
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

const CALLBACK_CODE: &str = "NATIVE_COMPOSITE_OPAQUE_CODE_MARKER";

struct FreshLoginHome(PathBuf);

impl FreshLoginHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!(
            "native-callback-composite-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create isolated auth home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy admitted provider config");
        fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
            .expect("write fresh auth store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("restrict auth home");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("restrict auth file");
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

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn typed_vm(source: &str, config_path: &Path) -> Vm {
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        config_path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile real callback RSS against the production catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = FreshLoginHome::new("registration");
    let registration_host = AuthHost::new_for_login(
        registration_home.path(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("construct real login admission for catalog registration");
    registration_host
        .register(&mut registry, catalog.as_ref())
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted production catalog");
    assert!(matches!(
        vm.run().expect("run RSS declarations"),
        VmStatus::Halted
    ));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected typed envelope")
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing typed envelope field"))
}

fn string_field(value: &Value, name: &str) -> String {
    let Value::String(value) = field(value, name) else {
        panic!("expected string field")
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

fn callback_parts(authorization_url: &str) -> (String, String) {
    let authorization = Url::parse(authorization_url).expect("RSS authorization URL");
    let redirect = authorization
        .query_pairs()
        .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
        .expect("real redirect URI");
    let state = authorization
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("generated callback state");
    (redirect, state)
}

fn callback_port(redirect_uri: &str) -> u16 {
    Url::parse(redirect_uri)
        .expect("real callback URI")
        .port()
        .expect("owned callback port")
}

fn assert_callback_port_bound(redirect_uri: &str) {
    assert!(TcpListener::bind(("127.0.0.1", callback_port(redirect_uri))).is_err());
}

fn assert_callback_port_released(redirect_uri: &str) {
    drop(
        TcpListener::bind(("127.0.0.1", callback_port(redirect_uri)))
            .expect("callback port released"),
    );
}

fn assert_fd_closed(fd: i32) {
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
}

const FD_OBSERVER_CHILD_MARKER: &str = "RUSTSCRIPT_NATIVE_CALLBACK_COMPOSITE_RSS_FD_OBSERVER_CHILD";

fn expect_fd_observer_rejection(fd: i32, stage: &str) {
    let payload = std::panic::catch_unwind(|| assert_fd_closed(fd))
        .expect_err("FD observer must reject an actually-retained or reused integer");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&'static str>().copied())
        .unwrap_or("");
    assert!(
        message.contains("left == right"),
        "FD observer rejection at {stage} must carry the actual assert payload, got {message:?}"
    );
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

fn compiled_loopback_launcher(directory: &Path) -> (PathBuf, PathBuf) {
    let source_path = directory.join("owned-loopback-launcher.rs");
    let executable = directory.join("owned-loopback-launcher");
    let report = directory.join("launcher-urls");
    let program = r#"
use std::{env, fs::OpenOptions, io::Write, net::TcpStream};
const REPORT: &str = __REPORT__;
const CALLBACK_CODE: &str = "NATIVE_COMPOSITE_BROWSER_CODE_MARKER";
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
    assert_eq!(args.len(), 1, "launcher receives exactly one authorization URL");
    let authorization_url = &args[0];
    OpenOptions::new().create(true).append(true).open(REPORT)
        .expect("open invocation report")
        .write_all(format!("{authorization_url}\n").as_bytes())
        .expect("record literal authorization URL");
    let (_, query) = authorization_url.split_once('?').expect("authorization query");
    let redirect = parameter(query, "redirect_uri");
    let state = parameter(query, "state");
    let host_port = redirect.strip_prefix("http://127.0.0.1:").expect("loopback URI")
        .split('/').next().expect("port");
    let port = host_port.parse::<u16>().expect("numeric ephemeral port");
    let request = format!(
        "GET /callback?state={state}&code={CALLBACK_CODE} HTTP/1.1\r\nHost: 127.0.0.1:{host_port}\r\n\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("real loopback listener");
    stream.write_all(request.as_bytes()).expect("send real callback request");
}
"#;
    let report_literal = format!("{:?}", report.to_string_lossy());
    fs::write(&source_path, program.replace("__REPORT__", &report_literal))
        .expect("write temporary launcher source");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let result = Command::new(rustc)
        .arg("--edition=2024")
        .arg(&source_path)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile owned browser launcher");
    assert!(
        result.status.success(),
        "owned launcher compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    (executable, report)
}

fn close_flow_resources(vm: &mut Vm, begun: &Value, waited: &Value) {
    for (export, resource) in [
        ("close_callback", field(begun, "callback_handle")),
        ("close_verifier", field(begun, "verifier_handle")),
        ("close_code", field(waited, "code_handle")),
    ] {
        let close = vm
            .resolve_exported_callable(export)
            .expect("typed close export");
        vm.invoke_callable(close, &[resource])
            .expect("close native resource");
    }
}

#[test]
fn real_default_typed_rss_manual_wait_uses_owned_input_and_opaque_code() {
    if spawn_fd_observer_child_unless_child(
        "real_default_typed_rss_manual_wait_uses_owned_input_and_opaque_code",
    ) {
        return;
    }
    let home = FreshLoginHome::new("manual");
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = Arc::new(
        OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser.clone(),
            Some(reader),
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        )
        .expect("trusted native callback inputs"),
    );
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("admit configured login home")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("read production callback RSS");
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &config_path);
    let owner = auth.bind_vm(&mut vm).expect("bind actual auth owner to VM");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), configured_intent("manual")],
        )
        .expect("manual begin through real restricted typed RSS");
    let authorization_url = string_field(&begun, "authorization_url");
    let (redirect_uri, state) = callback_parts(&authorization_url);
    let mut callback = Url::parse(&redirect_uri).expect("host callback URI");
    callback
        .query_pairs_mut()
        .append_pair("code", CALLBACK_CODE)
        .append_pair("state", &state);
    let mut writer = File::from(writer);
    writer
        .write_all(format!("{}\n", callback.as_str()).as_bytes())
        .expect("write host-side callback URL");
    drop(writer);

    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let callback_handle = field(&begun, "callback_handle");
    let waited = vm
        .invoke_callable(wait.clone(), std::slice::from_ref(&callback_handle))
        .expect("manual callback through the per-flow owned descriptor");
    assert_eq!(field(&waited, "outcome"), Value::string("success"));
    assert!(matches!(field(&waited, "code_handle"), Value::Int(_)));
    assert_eq!(browser.open_count(), 0);
    assert!(!format!("{waited:?}").contains(CALLBACK_CODE));
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
    let replay = vm
        .invoke_callable(wait, &[callback_handle])
        .expect_err("manual callback handle rejects replay");
    assert!(replay.to_string().contains("handle_replayed"));
    assert!(!replay.to_string().contains(CALLBACK_CODE));
    close_flow_resources(&mut vm, &begun, &waited);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn real_default_typed_rss_manual_state_mismatch_revokes_session_resources() {
    if spawn_fd_observer_child_unless_child(
        "real_default_typed_rss_manual_state_mismatch_revokes_session_resources",
    ) {
        return;
    }
    let home = FreshLoginHome::new("manual-state-mismatch");
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = Arc::new(
        OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser.clone(),
            Some(reader),
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        )
        .expect("trusted native callback inputs"),
    );
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("admit configured login home")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("read production callback RSS");
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &config_path);
    let owner = auth.bind_vm(&mut vm).expect("bind actual auth owner to VM");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), configured_intent("manual")],
        )
        .expect("manual begin through real restricted typed RSS");
    let authorization_url = string_field(&begun, "authorization_url");
    let (redirect_uri, _generated_state) = callback_parts(&authorization_url);
    let mut callback = Url::parse(&redirect_uri).expect("host callback URI");
    callback
        .query_pairs_mut()
        .append_pair("code", CALLBACK_CODE)
        .append_pair("state", "FOREIGN_COMPOSITE_STATE_MARKER");
    let mut writer = File::from(writer);
    writer
        .write_all(format!("{}\n", callback.as_str()).as_bytes())
        .expect("write mismatched callback URL outside RSS");
    drop(writer);

    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let failure = vm
        .invoke_callable(wait, &[field(&begun, "callback_handle")])
        .expect_err("manual state mismatch fails closed");
    assert!(failure.to_string().contains("state_mismatch"));
    assert!(!failure.to_string().contains(CALLBACK_CODE));
    assert!(
        !failure
            .to_string()
            .contains("FOREIGN_COMPOSITE_STATE_MARKER")
    );
    assert_eq!(browser.open_count(), 0);
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn real_default_typed_rss_none_mode_uses_owned_input_and_opaque_code() {
    if spawn_fd_observer_child_unless_child(
        "real_default_typed_rss_none_mode_uses_owned_input_and_opaque_code",
    ) {
        return;
    }
    let home = FreshLoginHome::new("none");
    let (reader, writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = Arc::new(
        OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser.clone(),
            Some(reader),
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        )
        .expect("trusted native callback inputs"),
    );
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("admit configured login home")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("read production callback RSS");
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &config_path);
    let owner = auth.bind_vm(&mut vm).expect("bind actual auth owner to VM");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), configured_intent("none")],
        )
        .expect("none begin through real restricted typed RSS");
    let authorization_url = string_field(&begun, "authorization_url");
    let (redirect_uri, state) = callback_parts(&authorization_url);
    assert_callback_port_bound(&redirect_uri);
    let mut callback = Url::parse(&redirect_uri).expect("host callback URI");
    callback
        .query_pairs_mut()
        .append_pair("code", CALLBACK_CODE)
        .append_pair("state", &state);
    let mut writer = File::from(writer);
    writer
        .write_all(format!("{}\n", callback.as_str()).as_bytes())
        .expect("write host-side callback URL");
    drop(writer);
    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let waited = vm
        .invoke_callable(wait, &[field(&begun, "callback_handle")])
        .expect("none callback through per-flow FD session");
    assert_eq!(field(&waited, "outcome"), Value::string("success"));
    assert!(matches!(field(&waited, "code_handle"), Value::Int(_)));
    assert_eq!(browser.open_count(), 0);
    assert!(!format!("{waited:?}").contains(CALLBACK_CODE));
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
    close_flow_resources(&mut vm, &begun, &waited);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn missing_native_fd_fails_closed_before_publishing_rss_resources() {
    let home = FreshLoginHome::new("missing-fd");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = Arc::new(
        OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser.clone(),
            None,
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        )
        .expect("native browser-only inputs are valid"),
    );
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("admit configured login home")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("read production callback RSS");
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &config_path);
    let owner = auth.bind_vm(&mut vm).expect("bind actual auth owner to VM");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let error = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), configured_intent("manual")],
        )
        .expect_err("manual preparation requires an explicitly owned input");
    assert!(error.to_string().contains("transport_error"));
    assert_eq!(browser.open_count(), 0);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn vm_owner_teardown_revokes_unwaited_manual_fd_and_redirect_socket() {
    if spawn_fd_observer_child_unless_child(
        "vm_owner_teardown_revokes_unwaited_manual_fd_and_redirect_socket",
    ) {
        return;
    }
    let home = FreshLoginHome::new("vm-teardown");
    let (reader, _writer) = pipe_pair();
    let raw_fd = reader.as_raw_fd();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = Arc::new(
        OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser,
            Some(reader),
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        )
        .expect("trusted native callback inputs"),
    );
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("admit configured login home")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("read production callback RSS");
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &config_path);
    let owner = auth.bind_vm(&mut vm).expect("bind actual auth owner to VM");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), configured_intent("manual")],
        )
        .expect("prepare owned per-flow input");
    let redirect_uri = string_field(&begun, "redirect_uri");
    assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
    assert_callback_port_bound(&redirect_uri);
    drop(vm);
    assert_fd_closed(raw_fd);
    assert_callback_port_released(&redirect_uri);
}

#[test]
fn real_default_typed_rss_browser_launcher_and_manual_fd_are_isolated() {
    let home = FreshLoginHome::new("browser-manual-isolation");
    let (launcher, report) = compiled_loopback_launcher(home.path());
    let browser = Arc::new(
        NativeBrowserOpener::new(launcher, BTreeMap::new()).expect("trusted compiled launcher"),
    );
    let (reader, writer) = pipe_pair();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let oauth = Arc::new(
        OAuthHost::new_with_native_inputs(
            Arc::new(NativeHttpsTransport::new()),
            browser,
            Some(reader),
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation.clone())),
        )
        .expect("trusted native callback inputs"),
    );
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("admit configured login home")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("read production callback RSS");
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &config_path);
    let owner = auth.bind_vm(&mut vm).expect("bind actual auth owner to VM");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");

    let browser_begun = vm
        .invoke_callable(
            begin.clone(),
            &[field(&owner, "host_home"), configured_intent("browser")],
        )
        .expect("browser begin launches only the compiled owned helper");
    let browser_url = string_field(&browser_begun, "authorization_url");
    let browser_redirect = string_field(&browser_begun, "redirect_uri");
    assert_callback_port_bound(&browser_redirect);
    assert_eq!(
        fs::read_to_string(&report)
            .expect("launcher URL receipt")
            .trim(),
        browser_url
    );
    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let browser_waited = vm
        .invoke_callable(wait, &[field(&browser_begun, "callback_handle")])
        .expect("compiled launcher callback is processed by native loopback wait");
    assert_eq!(field(&browser_waited, "outcome"), Value::string("success"));
    assert!(matches!(
        field(&browser_waited, "code_handle"),
        Value::Int(_)
    ));
    assert!(!format!("{browser_waited:?}").contains("NATIVE_COMPOSITE_BROWSER_CODE_MARKER"));
    assert_callback_port_released(&browser_redirect);
    close_flow_resources(&mut vm, &browser_begun, &browser_waited);
    assert_eq!(vm.host_context().resource_count(), 2);

    let manual_begun = vm
        .invoke_callable(
            begin,
            &[field(&owner, "host_home"), configured_intent("manual")],
        )
        .expect("manual begin reserves the still-unused FD");
    let manual_url = string_field(&manual_begun, "authorization_url");
    let (manual_redirect, manual_state) = callback_parts(&manual_url);
    assert_callback_port_bound(&manual_redirect);
    let mut callback = Url::parse(&manual_redirect).expect("host callback URI");
    callback
        .query_pairs_mut()
        .append_pair("code", CALLBACK_CODE)
        .append_pair("state", &manual_state);
    let mut writer = File::from(writer);
    writer
        .write_all(format!("{}\n", callback.as_str()).as_bytes())
        .expect("write host-side manual URL");
    drop(writer);
    let manual_waited = vm
        .invoke_callable(
            vm.resolve_exported_callable("wait")
                .expect("typed RSS wait"),
            &[field(&manual_begun, "callback_handle")],
        )
        .expect("manual flow never launches the BrowserOpener");
    assert_eq!(field(&manual_waited, "outcome"), Value::string("success"));
    assert_eq!(
        fs::read_to_string(&report)
            .expect("launcher report remains unchanged")
            .lines()
            .count(),
        1,
    );
    assert!(!format!("{manual_waited:?}").contains(CALLBACK_CODE));
    assert_callback_port_released(&manual_redirect);
    close_flow_resources(&mut vm, &manual_begun, &manual_waited);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn fd_observer_rejects_retained_owner_and_reused_integer() {
    if spawn_fd_observer_child_unless_child("fd_observer_rejects_retained_owner_and_reused_integer")
    {
        return;
    }
    let (reader, writer) = pipe_pair();
    let number = reader.as_raw_fd();
    expect_fd_observer_rejection(number, "retained owned descriptor");
    drop(reader);
    assert_fd_closed(number);
    let replacement = File::open("/dev/null").expect("open a different owned descriptor");
    assert_eq!(
        replacement.as_raw_fd(),
        number,
        "isolated namespace reuses the lowest free descriptor"
    );
    expect_fd_observer_rejection(number, "reused integer");
    drop(replacement);
    assert_fd_closed(number);
    drop(writer);
}
