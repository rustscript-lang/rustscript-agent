#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustscript_agent::auth::native_browser::NativeBrowserOpener;
use rustscript_agent::auth::oauth::{
    BoundedPublicOAuthIntent, BrowserOpener, CallbackMode, OAuthCancel, OAuthClock, OAuthFlowKind,
    OAuthHost, ScriptedHttpsTransport, TrustedEndpoint, TrustedTransportPolicy,
};
use url::Url;

const DEFAULT_BUDGET: Duration = Duration::from_secs(10);
const CANCEL_BUDGET: Duration = Duration::from_millis(750);
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
                .expect("RUSTSCRIPT_AGENT_TEST_TMP must be assigned by the gate runner"),
        );
        fs::create_dir_all(&root).expect("create assigned test temp root");
        let path = root.join(format!(
            "native-browser-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create test fixture directory");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn helper(&self, name: &str, body: &str, extra: &str) -> PathBuf {
        let source = self.path(&format!("{name}.rs"));
        let executable = self.path(name);
        let program = format!(
            r#"use std::{{env, fs, io::Write, net::TcpStream, os::unix::process::CommandExt, process::Command, thread, time::Duration}};
const STARTED: &str = {started:?};
const DESCENDANT: &str = {descendant:?};
const SIBLING: &str = {sibling:?};
{extra}
{body}
"#,
            started = self.path("started").to_string_lossy(),
            descendant = self.path("descendant-survived").to_string_lossy(),
            sibling = self.path("sibling-survived").to_string_lossy(),
        );
        fs::write(&source, program).expect("write helper source");
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let result = Command::new(rustc)
            .arg("--edition=2024")
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("compile owned helper");
        assert!(
            result.status.success(),
            "helper compilation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        executable
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        self.0
            .as_mut()
            .expect("owned child")
            .wait()
            .expect("wait child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Default)]
struct TestCancel(AtomicBool);

impl OAuthCancel for TestCancel {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct RealClock;

impl OAuthClock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

fn policy(budget: Duration) -> TrustedTransportPolicy {
    TrustedTransportPolicy {
        generation: 7,
        transport_identity: None,
        run_id: "native-browser-os-tests".into(),
        deadline: Instant::now() + budget,
        endpoints: vec![TrustedEndpoint {
            authority: "auth.example.test".into(),
            path_prefix: "/oauth".into(),
        }],
        allowed_header_names: BTreeSet::new(),
    }
}

fn intent() -> BoundedPublicOAuthIntent {
    BoundedPublicOAuthIntent {
        flow: OAuthFlowKind::AuthorizationCodePkce,
        callback_mode: CallbackMode::Browser,
        path: "/oauth/authorize".into(),
        scopes: vec!["fixture.scope".into()],
        public_query: BTreeMap::from([("client_id".into(), "fixture-client".into())]),
        credential_id: "fixture-credential".into(),
    }
}

fn intent_mode(mode: &str) -> BoundedPublicOAuthIntent {
    let mut result = intent();
    result.public_query.insert("mode".into(), mode.into());
    result
}

fn host(browser: Arc<dyn BrowserOpener>, cancel: Arc<dyn OAuthCancel>) -> OAuthHost {
    OAuthHost::new_with_native_callbacks(
        Arc::new(ScriptedHttpsTransport::new()),
        browser,
        Arc::new(RealClock),
        cancel,
    )
}

fn opener(executable: PathBuf, environment: BTreeMap<String, String>) -> NativeBrowserOpener {
    NativeBrowserOpener::new(executable, environment).expect("trusted test launcher")
}

fn wait_for(path: &std::path::Path, budget: Duration) -> bool {
    let until = Instant::now() + budget;
    while Instant::now() < until {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    path.exists()
}

fn assert_direct_child_reaped(pid: i32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as u32,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(result, -1, "direct launcher is no longer waitable");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "direct launcher was reaped by this test process"
    );
}

#[test]
fn native_pkce_browser_launcher_delivers_real_loopback_callback() {
    let scratch = Scratch::new();
    let helper = scratch.helper(
        "loopback-helper",
        r#"
fn decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16).expect("high digit") as u8;
            let low = (bytes[index + 2] as char).to_digit(16).expect("low digit") as u8;
            result.push((high << 4) | low);
            index += 3;
        } else if bytes[index] == b'+' {
            result.push(b' ');
            index += 1;
        } else {
            result.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(result).expect("decoded UTF-8")
}
fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    assert_eq!(args.len(), 1, "launcher receives exactly one URL argument");
    let url = args[0].to_str().expect("URL is UTF-8");
    let query = url.split_once('?').expect("authorization query").1;
    let mut redirect = None;
    let mut state = None;
    for item in query.split('&') {
        if let Some((key, value)) = item.split_once('=') {
            match key {
                "redirect_uri" => redirect = Some(decode(value)),
                "state" => state = Some(decode(value)),
                _ => {}
            }
        }
    }
    let redirect = redirect.expect("redirect URI");
    let state = state.expect("state");
    let port = redirect
        .strip_prefix("http://127.0.0.1:").expect("loopback URI")
        .split('/').next().expect("port")
        .parse::<u16>().expect("numeric port");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("loopback listener");
    let request = format!(
        "GET /callback?state={state}&code=NATIVE_HELPER_AUTH_CODE HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("send callback");
}
"#,
        "",
    );
    let browser = Arc::new(opener(helper, BTreeMap::new()));
    let oauth = host(browser, Arc::new(TestCancel::default()));
    let begun = oauth
        .pkce_begin(&policy(DEFAULT_BUDGET), intent())
        .expect("native launcher acknowledges the authorization URL");
    let callback = oauth
        .callback_wait(&begun.callback_handle)
        .expect("native loopback accepts the helper callback");
    assert!(callback.code_handle.is_some());
    let debug = format!("{callback:?}");
    assert!(!debug.contains("NATIVE_HELPER_AUTH_CODE"));
    let redirect = Url::parse(&begun.authorization_url)
        .expect("authorization URL")
        .query_pairs()
        .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
        .expect("redirect URI");
    let parsed = Url::parse(&redirect).expect("loopback redirect");
    let port = parsed.port().expect("ephemeral callback port");
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
}

#[test]
fn launcher_receives_one_unchanged_url_and_only_approved_environment_with_fd_confinement() {
    let scratch = Scratch::new();
    let inherited_fd_path = scratch.path("sentinel-fd");
    let inherited_fd = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&inherited_fd_path)
        .expect("open descriptor sentinel");
    let fd = inherited_fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0,
        "make sentinel descriptor inheritable before exec"
    );

    let report = scratch.path("launch-report");
    let helper = scratch.helper(
        "inspect-helper",
        r#"
unsafe extern "C" { fn fcntl(fd: i32, command: i32, ...) -> i32; }
fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let url = args.first().and_then(|arg| arg.to_str()).unwrap_or("<non-utf8>");
    let fd_open = unsafe { fcntl(SENTINEL_FD, 1) } >= 0;
    let value = |key: &str| env::var(key).unwrap_or_else(|_| "<absent>".into());
    let result = format!(
        "argc={}\nurl={}\nhome={}\ndisplay={}\npath={}\nbrowser={}\npreload={}\ncredential={}\nfd_open={}\n",
        args.len(), url, value("HOME"), value("DISPLAY"), value("PATH"),
        value("BROWSER"), value("LD_PRELOAD"), value("NATIVE_BROWSER_TEST_SECRET"), fd_open
    );
    fs::write(REPORT, result).expect("write child report");
}
"#,
        &format!(
            "const REPORT: &str = {:?};\nconst SENTINEL_FD: i32 = {fd};",
            report.to_string_lossy()
        ),
    );
    let mut environment = BTreeMap::new();
    environment.insert("HOME".into(), scratch.0.to_string_lossy().into_owned());
    environment.insert("DISPLAY".into(), ":native-browser-fixture".into());
    let browser = Arc::new(opener(helper, environment));

    let previous_browser = std::env::var_os("BROWSER");
    let previous_secret = std::env::var_os("NATIVE_BROWSER_TEST_SECRET");
    unsafe {
        std::env::set_var("BROWSER", "ambient-browser-must-not-be-inherited");
        std::env::set_var(
            "NATIVE_BROWSER_TEST_SECRET",
            "ambient-secret-must-not-be-inherited",
        );
    }
    let restore = AmbientRestore {
        browser: previous_browser,
        secret: previous_secret,
    };
    let oauth = host(browser, Arc::new(TestCancel::default()));
    let begun = oauth
        .pkce_begin(&policy(DEFAULT_BUDGET), intent())
        .expect("compiled owned helper exits successfully");
    drop(restore);

    let output = fs::read_to_string(report).expect("helper report");
    assert!(output.contains("argc=1\n"), "{output}");
    assert!(
        output.contains(&format!("url={}\n", begun.authorization_url)),
        "the input URL is one unchanged argv value: {output}"
    );
    assert!(
        output.contains(&format!("home={}\n", scratch.0.display())),
        "{output}"
    );
    assert!(
        output.contains("display=:native-browser-fixture\n"),
        "{output}"
    );
    assert!(output.contains("path=/usr/bin:/bin\n"), "{output}");
    assert!(output.contains("browser=<absent>\n"), "{output}");
    assert!(output.contains("preload=<absent>\n"), "{output}");
    assert!(output.contains("credential=<absent>\n"), "{output}");
    assert!(output.contains("fd_open=false\n"), "{output}");
    drop(inherited_fd);
}

struct AmbientRestore {
    browser: Option<std::ffi::OsString>,
    secret: Option<std::ffi::OsString>,
}

impl Drop for AmbientRestore {
    fn drop(&mut self) {
        unsafe {
            if let Some(value) = self.browser.take() {
                std::env::set_var("BROWSER", value);
            } else {
                std::env::remove_var("BROWSER");
            }
            if let Some(value) = self.secret.take() {
                std::env::set_var("NATIVE_BROWSER_TEST_SECRET", value);
            } else {
                std::env::remove_var("NATIVE_BROWSER_TEST_SECRET");
            }
        }
    }
}

fn process_fixture(scratch: &Scratch) -> PathBuf {
    scratch.helper(
        "process-helper",
        r#"
unsafe extern "C" { fn raise(signal: i32) -> i32; }
fn spawn_descendant() {
    let executable = env::current_exe().expect("helper executable");
    Command::new(executable).arg("descendant").env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().expect("start same-group descendant");
}
fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    assert_eq!(args.len(), 1, "the native launcher passes one URL");
    let arg = args[0].to_string_lossy();
    if arg == "descendant" {
        thread::sleep(Duration::from_millis(1500));
        fs::write(DESCENDANT, "survived").expect("record descendant completion");
        return;
    }
    if arg == "sibling" {
        thread::sleep(Duration::from_millis(200));
        fs::write(SIBLING, "survived").expect("record sibling completion");
        return;
    }
    fs::write(STARTED, format!("{}", std::process::id())).expect("record launcher pid");
    spawn_descendant();
    if arg.contains("mode=nonzero") { std::process::exit(23); }
    if arg.contains("mode=signal") {
        unsafe { raise(15); }
        std::process::exit(24);
    }
    if arg.contains("mode=cancel") || arg.contains("mode=deadline") {
        thread::sleep(Duration::from_secs(10));
        return;
    }
    if arg.contains("mode=ack") { return; }
    std::process::exit(25);
}
"#,
        "",
    )
}

#[test]
fn successful_launcher_exit_is_only_ack_and_does_not_kill_owned_descendant_group() {
    let scratch = Scratch::new();
    let helper = process_fixture(&scratch);
    let browser = Arc::new(opener(helper, BTreeMap::new()));
    let oauth = host(browser, Arc::new(TestCancel::default()));
    oauth
        .pkce_begin(&policy(DEFAULT_BUDGET), intent_mode("ack"))
        .expect("zero exit acknowledges launcher only");
    assert!(wait_for(
        &scratch.path("descendant-survived"),
        Duration::from_secs(2)
    ));
}

#[test]
fn nonzero_exit_and_signal_kill_only_the_owned_launcher_group_and_reap_direct_child() {
    for mode in ["nonzero", "signal"] {
        let scratch = Scratch::new();
        let helper = process_fixture(&scratch);
        let browser = Arc::new(opener(helper, BTreeMap::new()));
        let oauth = host(browser, Arc::new(TestCancel::default()));
        let result = oauth.pkce_begin(&policy(DEFAULT_BUDGET), intent_mode(mode));
        assert!(result.is_err(), "{mode} launcher outcome is an error");
        let pid = fs::read_to_string(scratch.path("started"))
            .expect("launcher reached its fixture")
            .parse::<i32>()
            .expect("launcher pid");
        assert_direct_child_reaped(pid);
        thread::sleep(Duration::from_millis(1600));
        assert!(
            !scratch.path("descendant-survived").exists(),
            "{mode} cleanup terminated the same-group descendant"
        );
    }
}

#[test]
fn cancellation_kills_owned_launcher_group_within_budget_and_preserves_unrelated_group() {
    let scratch = Scratch::new();
    let helper = process_fixture(&scratch);
    let sibling = Command::new(&helper)
        .arg("sibling")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("spawn unrelated sibling group");
    let mut sibling = ChildGuard::new(sibling);
    let cancel = Arc::new(TestCancel::default());
    let browser = Arc::new(opener(helper, BTreeMap::new()));
    let oauth = Arc::new(host(browser, cancel.clone()));
    let worker_cancel = Arc::clone(&cancel);
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = oauth.pkce_begin(&policy(Duration::from_secs(5)), intent_mode("cancel"));
        let _ = sender.send(result.map(|_| ()).map_err(|error| error.code()));
    });
    assert!(wait_for(&scratch.path("started"), Duration::from_secs(1)));
    let pid = fs::read_to_string(scratch.path("started"))
        .expect("launcher pid marker")
        .parse::<i32>()
        .expect("launcher pid");
    let cancelled_at = Instant::now();
    worker_cancel.0.store(true, Ordering::Release);
    let result = receiver
        .recv_timeout(CANCEL_BUDGET)
        .expect("cancel cleanup returns within the preserved 750ms budget");
    assert_eq!(result, Err("cancelled"));
    assert!(cancelled_at.elapsed() < CANCEL_BUDGET);
    worker.join().expect("launcher worker joined");
    assert_direct_child_reaped(pid);
    assert!(wait_for(
        &scratch.path("sibling-survived"),
        Duration::from_secs(1)
    ));
    assert!(sibling.wait().success());
    thread::sleep(Duration::from_millis(1600));
    assert!(
        !scratch.path("descendant-survived").exists(),
        "cancellation killed the launcher process group"
    );
}

#[test]
fn deadline_kills_owned_launcher_group_without_a_second_grace_period() {
    let scratch = Scratch::new();
    let helper = process_fixture(&scratch);
    let browser = Arc::new(opener(helper, BTreeMap::new()));
    let oauth = host(browser, Arc::new(TestCancel::default()));
    let started_at = Instant::now();
    let result = oauth.pkce_begin(&policy(CANCEL_BUDGET), intent_mode("deadline"));
    assert!(
        started_at.elapsed() < CANCEL_BUDGET + Duration::from_millis(100),
        "deadline cleanup has no second grace interval"
    );
    assert_eq!(
        result.expect_err("deadline terminates the launcher").code(),
        "deadline_exceeded"
    );
    let pid = fs::read_to_string(scratch.path("started"))
        .expect("launcher reached its fixture")
        .parse::<i32>()
        .expect("launcher pid");
    assert_direct_child_reaped(pid);
    thread::sleep(Duration::from_millis(1600));
    assert!(!scratch.path("descendant-survived").exists());
}

#[test]
fn invalid_launcher_path_fails_before_any_subprocess_effect() {
    let scratch = Scratch::new();
    let non_executable = scratch.path("non-executable-launcher");
    fs::write(&non_executable, b"fixture launcher is never executed").expect("write fixture");
    let original = fs::read(&non_executable).expect("read fixture");
    let browser = Arc::new(
        NativeBrowserOpener::new(non_executable.clone(), BTreeMap::new())
            .expect("absolute trusted path is structurally admitted"),
    );
    let oauth = host(browser, Arc::new(TestCancel::default()));
    let result = oauth.pkce_begin(&policy(DEFAULT_BUDGET), intent());
    assert!(result.is_err());
    assert_eq!(
        fs::read(non_executable).expect("fixture remains unchanged"),
        original
    );
}

#[test]
fn launcher_environment_policy_rejects_denied_names_before_invocation() {
    let scratch = Scratch::new();
    let helper = scratch.helper("unused-helper", "fn main() {}", "");
    let denied = NativeBrowserOpener::new(
        helper.clone(),
        BTreeMap::from([("BROWSER".into(), "forbidden".into())]),
    );
    assert!(denied.is_err());
    let control = NativeBrowserOpener::new(
        helper,
        BTreeMap::from([("HOME".into(), "invalid\nvalue".into())]),
    );
    assert!(control.is_err());
}

#[test]
fn callback_port_is_released_when_launcher_open_fails_after_native_callback_setup() {
    let scratch = Scratch::new();
    let helper = scratch.helper(
        "failing-helper",
        r#"fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    assert_eq!(args.len(), 1);
    fs::write(RECEIVED_URL, args[0].to_string_lossy().as_bytes()).expect("record URL");
    std::process::exit(19);
}"#,
        &format!(
            "const RECEIVED_URL: &str = {:?};",
            scratch.path("received-url").to_string_lossy()
        ),
    );
    let browser = Arc::new(opener(helper, BTreeMap::new()));
    let oauth = host(browser, Arc::new(TestCancel::default()));
    let result = oauth.pkce_begin(&policy(DEFAULT_BUDGET), intent());
    assert!(result.is_err());
    let authorization = fs::read_to_string(scratch.path("received-url")).expect("captured URL");
    let redirect = Url::parse(&authorization)
        .expect("authorization URL")
        .query_pairs()
        .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
        .expect("callback redirect URI");
    let callback = Url::parse(&redirect).expect("callback URL");
    let port = callback.port().expect("ephemeral callback port");
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
}
