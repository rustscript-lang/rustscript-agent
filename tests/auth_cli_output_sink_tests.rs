use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{
            AuthHost, DeviceInstructionSender, DeviceInstructionSink, NativeDeviceInstructionOutput,
        },
        oauth::{
            OAuthError, OAuthHost, OAuthIoContext, ScriptedBrowser, ScriptedCallback,
            ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
        },
        store::AuthStore,
    },
    runtime::{AuthCommandInput, AuthEntryRunner},
};
use rustscript_vm::Value;
use std::{
    fs,
    io::Read,
    os::fd::{FromRawFd, OwnedFd},
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const ENTRY_PATH: &str = "rss/auth/login.rss";
const LOGIN_SOURCES: &[(&str, &str)] = &[
    (ENTRY_PATH, include_str!("../rss/auth/login.rss")),
    (
        "rss/auth/pkce_login.rss",
        include_str!("../rss/auth/pkce_login.rss"),
    ),
    (
        "rss/auth/pkce_instruction_session.rss",
        include_str!("../rss/auth/pkce_instruction_session.rss"),
    ),
    (
        "rss/auth/pkce_session.rss",
        include_str!("../rss/auth/pkce_session.rss"),
    ),
    (
        "rss/auth/token_metadata.rss",
        include_str!("../rss/auth/token_metadata.rss"),
    ),
    (
        "rss/auth/token_save.rss",
        include_str!("../rss/auth/token_save.rss"),
    ),
    (
        "rss/auth/codex_device.rss",
        include_str!("../rss/auth/codex_device.rss"),
    ),
    ("rss/auth/types.rss", include_str!("../rss/auth/types.rss")),
];
const USER_CODE: &str = "PUBLIC-CODE-7QK";
const DEVICE_SECRET: &str = "SYNTHETIC_DEVICE_SECRET_61c4";
const CODE_SECRET: &str = "SYNTHETIC_AUTH_CODE_SECRET_28b1";
const VERIFIER_SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const ACCESS_SECRET: &str = "SYNTHETIC_ACCESS_TOKEN_SECRET_a513";
const REFRESH_SECRET: &str = "SYNTHETIC_REFRESH_TOKEN_SECRET_d6e2";
const START_MS: u64 = 1_900_000_000_000;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 test TEMP"),
        );
        fs::create_dir_all(&root).expect("create assigned test TEMP");
        let home = root.join(format!("task6-native-output-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).expect("create fixture home");
        let config = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/codex_device/config.yaml");
        fs::copy(config, home.join("config.yaml")).expect("copy configured provider");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
                .expect("config mode");
        }
        Self(home)
    }

    fn entries(&self) -> Vec<String> {
        let mut entries = fs::read_dir(&self.0)
            .expect("read fixture home")
            .map(|entry| {
                entry
                    .expect("fixture entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 entry name")
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn runner() -> AuthEntryRunner {
    AuthEntryRunner::from_bundle(ENTRY_PATH, LOGIN_SOURCES).expect("compile real login RSS bundle")
}

fn oauth_host(transport: Arc<ScriptedHttpsTransport>) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(START_MS)),
        Arc::new(ScriptedCancel::new()),
    ))
}

fn run_login(
    runner: &AuthEntryRunner,
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
    sender: DeviceInstructionSender,
    cancellation: &RunCancellation,
) -> Result<Value, rustscript_agent::runtime::AuthEntryError> {
    let home_path = home.0.clone();
    runner.run_with_host_factory(
        AuthCommandInput {
            operation: "auth.login".to_owned(),
            provider: Some("openai-codex".to_owned()),
            credential_id: None,
        },
        cancellation,
        move |child| {
            Ok(AuthHost::new_for_login(home_path, child)?
                .with_oauth_host(oauth_host(transport))
                .with_device_instruction_sender(sender))
        },
    )
}

fn queue_success(transport: &ScriptedHttpsTransport) {
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}","public":"poll-ok"}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","token_type":"Bearer","expires_in":3600,"public":"exchange-ok"}}"#
        ),
    );
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected typed RSS record: {value:?}");
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn text(value: &Value) -> &str {
    let Value::String(value) = value else {
        panic!("expected RSS string, got {value:?}");
    };
    value
}

fn assert_no_secret(value: &str) {
    for secret in [
        DEVICE_SECRET,
        CODE_SECRET,
        VERIFIER_SECRET,
        ACCESS_SECRET,
        REFRESH_SECRET,
    ] {
        assert!(!value.contains(secret), "private OAuth material leaked");
    }
}

#[cfg(unix)]
fn pipe(flags: i32) -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: `descriptors` has space for both descriptors returned by pipe2.
    let result = unsafe { libc::pipe2(descriptors.as_mut_ptr(), flags | libc::O_CLOEXEC) };
    assert_eq!(result, 0, "create a real Unix pipe");
    // SAFETY: pipe2 returned two newly owned descriptors.
    unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    }
}

#[cfg(unix)]
fn fill_pipe(fd: std::os::fd::RawFd) {
    let bytes = [b'x'; 4096];
    loop {
        // SAFETY: `bytes` is a live readable buffer and fd is the pipe's write end.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            continue;
        }
        assert_eq!(
            written, -1,
            "a nonblocking pipe stops accepting bytes when full"
        );
        // SAFETY: errno is thread-local and valid to inspect after write returned -1.
        let errno = unsafe { *libc::__errno_location() };
        assert_eq!(errno, libc::EAGAIN);
        return;
    }
}

#[cfg(unix)]
struct SignalingNativeSink {
    output: NativeDeviceInstructionOutput,
    entered: std::sync::mpsc::SyncSender<()>,
}

#[cfg(unix)]
impl DeviceInstructionSink for SignalingNativeSink {
    fn emit(
        &self,
        instruction: &rustscript_agent::auth::host::PublicDeviceInstruction,
        context: &OAuthIoContext,
    ) -> Result<(), OAuthError> {
        let _ = self.entered.send(());
        self.output.emit(instruction, context)
    }
}

#[cfg(unix)]
#[test]
fn real_rss_native_pipe_acknowledges_written_instruction_before_poll_and_saves_generation_one() {
    let home = FixtureHome::new();
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let entries_before = home.entries();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_success(&transport);
    let (read_fd, write_fd) = pipe(0);
    let sink: Arc<dyn DeviceInstructionSink> =
        Arc::new(NativeDeviceInstructionOutput::from_fd(write_fd));
    let sender = DeviceInstructionSender::from_sink(sink);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));

    let result = run_login(&runner(), &home, transport.clone(), sender, &cancellation)
        .expect("run the real typed auth.login RSS entry");
    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(text(field(&result, "status")))
            .expect("redacted login summary")["status"],
        "active"
    );
    assert_eq!(transport.take_sent().len(), 3, "start, poll, exchange");
    let stored = AuthStore::from_home(&home.0)
        .expect("open native auth store")
        .load_metadata("fixture-codex")
        .expect("native save after acknowledged output");
    assert_eq!(stored.generation, 1);
    assert!(stored.has_refresh_token);
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );

    drop(result);
    let mut reader = fs::File::from(read_fd);
    let mut rendered = Vec::new();
    reader
        .read_to_end(&mut rendered)
        .expect("read real pipe output");
    assert_eq!(
        rendered,
        format!(
            "Open https://auth.example.test/codex/device\nCode: {USER_CODE}\nExpires in 900 seconds\n"
        )
        .as_bytes()
    );
    let rendered = String::from_utf8(rendered).expect("public instruction is UTF-8");
    assert_no_secret(&rendered);
    let mut expected_entries = entries_before;
    expected_entries.extend(["auth.yaml".to_owned(), "auth.yaml.lock".to_owned()]);
    expected_entries.sort();
    assert_eq!(home.entries(), expected_entries);
}

#[cfg(unix)]
#[test]
fn dev_full_output_failure_is_static_and_stops_real_rss_before_poll_or_save() {
    let home = FixtureHome::new();
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let entries_before = home.entries();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    let file = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open the real Unix /dev/full device");
    let sink: Arc<dyn DeviceInstructionSink> =
        Arc::new(NativeDeviceInstructionOutput::from_fd(file.into()));
    let sender = DeviceInstructionSender::from_sink(sink);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));

    let result = run_login(&runner(), &home, transport.clone(), sender, &cancellation)
        .expect("RSS reports native output failure as a typed result");
    assert_eq!(field(&result, "ok"), &Value::Bool(false));
    assert_eq!(text(field(&result, "status")), "ui_sink_closed");
    assert_eq!(text(field(&result, "error")), "ui_sink_closed");
    assert_eq!(transport.take_sent().len(), 1, "only device-start ran");
    assert!(!home.0.join("auth.yaml").exists());
    assert!(!home.0.join("auth.yaml.lock").exists());
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(home.entries(), entries_before);
    let rendered = format!("{result:?}");
    assert_no_secret(&rendered);
    assert!(!rendered.contains("No space left"));
}

#[cfg(unix)]
#[test]
fn closed_pipe_output_failure_is_static_and_stops_real_rss_before_poll_or_save() {
    let home = FixtureHome::new();
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let entries_before = home.entries();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    let (read_fd, write_fd) = pipe(0);
    drop(read_fd);
    let sink: Arc<dyn DeviceInstructionSink> =
        Arc::new(NativeDeviceInstructionOutput::from_fd(write_fd));
    let sender = DeviceInstructionSender::from_sink(sink);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));

    let result = run_login(&runner(), &home, transport.clone(), sender, &cancellation)
        .expect("RSS reports closed native output as a typed result");
    assert_eq!(field(&result, "ok"), &Value::Bool(false));
    assert_eq!(text(field(&result, "status")), "ui_sink_closed");
    assert_eq!(text(field(&result, "error")), "ui_sink_closed");
    assert_eq!(transport.take_sent().len(), 1, "only device-start ran");
    assert!(!home.0.join("auth.yaml").exists());
    assert!(!home.0.join("auth.yaml.lock").exists());
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(home.entries(), entries_before);
    let rendered = format!("{result:?}");
    assert_no_secret(&rendered);
    assert!(!rendered.contains("Broken pipe"));
}

#[cfg(unix)]
#[test]
fn full_pipe_cancellation_stops_real_rss_without_poll_or_store_mutation() {
    let home = FixtureHome::new();
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let entries_before = home.entries();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    let (read_fd, write_fd) = pipe(libc::O_NONBLOCK);
    fill_pipe(std::os::fd::AsRawFd::as_raw_fd(&write_fd));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let sink: Arc<dyn DeviceInstructionSink> = Arc::new(SignalingNativeSink {
        output: NativeDeviceInstructionOutput::from_fd(write_fd),
        entered: entered_tx,
    });
    let sender = DeviceInstructionSender::from_sink(sink);
    let runner = runner();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
    let cancel_signal = cancellation.clone();
    let cancel_thread = thread::spawn(move || {
        entered_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("RSS reaches the full native output after device start");
        thread::sleep(Duration::from_millis(30));
        cancel_signal.request(CancellationReason::Requested);
    });
    let started = Instant::now();

    let run_result = run_login(&runner, &home, transport.clone(), sender, &cancellation);
    cancel_thread.join().expect("cancel signal thread");
    assert!(started.elapsed() < Duration::from_secs(2));
    match &run_result {
        Ok(result) => {
            assert_eq!(field(result, "ok"), &Value::Bool(false));
            assert_eq!(text(field(result, "status")), "instruction_failed");
            assert_no_secret(&format!("{result:?}"));
        }
        Err(rustscript_agent::runtime::AuthEntryError::Cancelled(_)) => {}
        Err(other) => panic!("unexpected auth runner failure: {other:?}"),
    }
    assert_eq!(transport.take_sent().len(), 1, "cancellation precedes poll");
    assert!(!home.0.join("auth.yaml").exists());
    assert!(!home.0.join("auth.yaml.lock").exists());
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(home.entries(), entries_before);
    drop(read_fd);
}
