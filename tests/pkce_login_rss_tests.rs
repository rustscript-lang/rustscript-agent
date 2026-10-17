#![cfg(unix)]
#[path = "support/owned_fd_observer.rs"]
mod owned_fd_observer;

use rustscript_agent::cli::execute_auth_cli;
use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{
            AuthHost, AuthorizationInstructionSender, RunOAuthCancel,
            authorization_instruction_channel,
        },
        oauth::{
            BoundedHttpsTransport, BrowserOpener, OAuthClock, OAuthError, OAuthHost,
            OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse, ScriptedClock,
            ScriptedHttpsTransport,
        },
    },
    runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner},
};
use rustscript_vm::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use url::Url;
const AUTH_ENTRY_PATH: &str = "rss/auth/commands.rss";
const AUTH_SOURCES: &[(&str, &str)] = &[
    (AUTH_ENTRY_PATH, include_str!("../rss/auth/commands.rss")),
    (
        "rss/config/selection.rss",
        include_str!("../rss/config/selection.rss"),
    ),
    ("rss/auth/login.rss", include_str!("../rss/auth/login.rss")),
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

struct IsolatedHome(PathBuf);

impl IsolatedHome {
    fn configured_pkce() -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 test TEMP"),
        );
        fs::create_dir_all(&root).expect("create assigned test TEMP");
        let home = root.join(format!("pkce-login-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).expect("create isolated auth home");
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex_device/config.yaml");
        let config = fs::read_to_string(fixture)
            .expect("read synthetic public provider fixture")
            .replace("flow: codex-device", "flow: authorization_code_pkce");
        fs::write(home.join("config.yaml"), config).expect("write synthetic PKCE config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
                .expect("restrict synthetic home");
            fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
                .expect("restrict synthetic config");
        }
        Self(home)
    }
}

impl Drop for IsolatedHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct CallbackFromBrowser {
    opened: Arc<AtomicBool>,
    request_sent: Arc<AtomicBool>,
    callback_accepted: Arc<AtomicBool>,
}

impl BrowserOpener for CallbackFromBrowser {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        self.opened.store(true, Ordering::Release);
        context.check()?;
        let parsed = Url::parse(authorization_url).expect("generated authorization URL");
        let mut state = None;
        let mut redirect_uri = None;
        for (name, value) in parsed.query_pairs() {
            if name == "state" {
                state = Some(value.into_owned());
            } else if name == "redirect_uri" {
                redirect_uri = Some(value.into_owned());
            }
        }
        let state = state.expect("generated PKCE state");
        let redirect_uri = redirect_uri.expect("generated loopback redirect");
        let port = Url::parse(&redirect_uri)
            .ok()
            .and_then(|url| url.port())
            .expect("loopback callback port");
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream =
            TcpStream::connect_timeout(&address, Duration::from_millis(500)).map_err(|_| {
                OAuthError::Transport {
                    message: "synthetic loopback callback failed".to_owned(),
                }
            })?;
        let request = format!(
            "GET /callback?state={state}&code=SYNTHETIC_AUTHORIZATION_CODE HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|_| OAuthError::Transport {
                message: "synthetic loopback callback failed".to_owned(),
            })?;
        self.request_sent.store(true, Ordering::Release);
        context.check()?;
        let callback_accepted = Arc::clone(&self.callback_accepted);
        thread::spawn(move || {
            let mut response = Vec::new();
            let accepted = stream.read_to_end(&mut response).is_ok()
                && response.starts_with(b"HTTP/1.1 200 OK");
            callback_accepted.store(accepted, Ordering::Release);
        });
        Ok(())
    }
}

fn result_ok(value: &Value) -> bool {
    let Value::Map(fields) = value else {
        panic!("expected typed RSS result, got {value:?}");
    };
    fields.iter().any(|(key, value)| {
        matches!(key, Value::String(name) if name.as_ref() == "ok") && value == &Value::Bool(true)
    })
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
fn configured_pkce_login_runs_the_production_rss_entry_and_persists_a_credential() {
    let home = IsolatedHome::configured_pkce();
    let runner = AuthEntryRunner::from_bundle(AUTH_ENTRY_PATH, AUTH_SOURCES)
        .expect("compile the exact production command bundle");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"access_token":"SYNTHETIC_ACCESS_SECRET","refresh_token":"SYNTHETIC_REFRESH_SECRET","token_type":"Bearer","expires_in":3600}"#);
    let opened = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = authorization_instruction_channel();
    let home_path = home.0.clone();
    let transport_for_host = Arc::clone(&transport);
    let opened_for_host = Arc::clone(&opened);
    let sent_for_host = Arc::clone(&sent);
    let accepted_for_host = Arc::clone(&accepted);
    let result = runner.run_with_host_factory(
        AuthCommandInput {
            operation: "auth.login".to_owned(),
            provider: Some("openai-codex".to_owned()),
            credential_id: None,
        },
        &cancellation,
        move |child| {
            let oauth = OAuthHost::new_with_native_inputs(
                transport_for_host,
                Arc::new(CallbackFromBrowser {
                    opened: opened_for_host,
                    request_sent: sent_for_host,
                    callback_accepted: accepted_for_host,
                }),
                None,
                Arc::new(ScriptedClock::new(1_900_000_000_000)),
                Arc::new(RunOAuthCancel::new(child.clone())),
            )
            .map_err(|_| "native_callback_setup_failed".to_owned())?;
            Ok(AuthHost::new_for_login(home_path, child)?
                .with_oauth_host(Arc::new(oauth))
                .with_authorization_instruction_sender(sender))
        },
    );
    let requests = transport.take_sent();
    let value = result.unwrap_or_else(|error| panic!("production command login failed: {error:?}; browser_opened={}; callback_sent={}; callback_accepted={}; token_requests={}",opened.load(Ordering::Acquire),sent.load(Ordering::Acquire),accepted.load(Ordering::Acquire),requests.len()));
    assert!(
        result_ok(&value),
        "production command login returned failure: {value:?}; browser_opened={}; callback_sent={}; callback_accepted={}; token_requests={}; auth_yaml_present={}",
        opened.load(Ordering::Acquire),
        sent.load(Ordering::Acquire),
        accepted.load(Ordering::Acquire),
        requests.len(),
        home.0.join("auth.yaml").is_file()
    );
    assert!(
        home.0.join("auth.yaml").is_file(),
        "successful login must persist credential"
    );
    assert!(
        receiver.try_recv().is_ok(),
        "PKCE must enqueue a public instruction"
    );
    assert_eq!(requests.len(), 1, "exactly one token exchange");
    let exchange_fields: Vec<(String, String)> =
        url::form_urlencoded::parse(requests[0].body.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
    let field_names: Vec<String> = exchange_fields
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    assert_eq!(
        field_names,
        vec![
            "grant_type",
            "client_id",
            "code",
            "code_verifier",
            "redirect_uri"
        ]
    );
    assert_eq!(
        exchange_fields
            .iter()
            .find(|(name, _)| name == "grant_type")
            .map(|(_, value)| value.as_str()),
        Some("authorization_code")
    );
    assert_eq!(
        exchange_fields
            .iter()
            .find(|(name, _)| name == "code")
            .map(|(_, value)| value.as_str()),
        Some("SYNTHETIC_AUTHORIZATION_CODE")
    );
    assert!(
        exchange_fields
            .iter()
            .find(|(name, _)| name == "code_verifier")
            .is_some_and(|(_, value)| !value.is_empty())
    );
    assert!(
        exchange_fields
            .iter()
            .find(|(name, _)| name == "redirect_uri")
            .is_some_and(|(_, value)| value.starts_with("http://127.0.0.1:"))
    );

    let config_before = fs::read(home.0.join("config.yaml")).expect("read configuration bytes");
    let persisted: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(home.0.join("auth.yaml")).expect("read persisted credential"),
    )
    .expect("decode native credential store");
    let credential = &persisted["credentials"]["fixture-codex"];
    assert!(
        credential["access_token"].as_str() == Some("SYNTHETIC_ACCESS_SECRET"),
        "access token persisted without exposing its value"
    );
    assert!(
        credential["refresh_token"].as_str() == Some("SYNTHETIC_REFRESH_SECRET"),
        "refresh token persisted without exposing its value"
    );
    assert_eq!(
        credential["generation"].as_u64(),
        Some(1),
        "one successful save advances initial generation"
    );
    assert_eq!(credential["provider"].as_str(), Some("openai-codex"));
    assert_eq!(
        credential["source"].as_str(),
        Some("authorization-code-pkce")
    );

    let command = |operation: &str, provider: Option<&str>, credential_id: Option<&str>| {
        let command_home = home.0.clone();
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let output = execute_auth_cli(
            &runner,
            AuthCommandInput {
                operation: operation.to_owned(),
                provider: provider.map(str::to_owned),
                credential_id: credential_id.map(str::to_owned),
            },
            &cancellation,
            move |child| AuthHost::new_for_commands(command_home, child),
        );
        for secret in [
            "SYNTHETIC_ACCESS_SECRET",
            "SYNTHETIC_REFRESH_SECRET",
            "SYNTHETIC_AUTHORIZATION_CODE",
        ] {
            assert!(
                !output.stdout.contains(secret) && !output.stderr.contains(secret),
                "public command output is redacted"
            );
        }
        assert!(
            !output.stdout.contains("access_token") && !output.stdout.contains("refresh_token"),
            "public output omits token fields"
        );
        assert_eq!(output.exit_code, 0, "business command succeeds");
        assert!(
            output.stderr.is_empty(),
            "successful command has no error output"
        );
        serde_json::from_str::<serde_json::Value>(output.stdout.trim()).expect("public JSON report")
    };
    let status = command("auth.status", Some("openai-codex"), None);
    assert_eq!(status["credential_id"], "fixture-codex");
    assert_eq!(status["status"], "active");
    assert_eq!(status["generation"], 1);
    let logout = command("auth.logout", None, Some("fixture-codex"));
    assert_eq!(logout["status"], "deleted");
    let after_logout: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(home.0.join("auth.yaml")).expect("read store after logout"),
    )
    .expect("decode logged-out store");
    assert!(
        after_logout["credentials"]
            .as_mapping()
            .expect("credential mapping")
            .is_empty(),
        "logout removes the persisted credential"
    );
    let missing = command("auth.status", Some("openai-codex"), None);
    assert_eq!(missing["status"], "missing");
    assert_eq!(missing["generation"], 0);
    let repeated = command("auth.logout", None, Some("fixture-codex"));
    assert_eq!(repeated["status"], "already_absent");
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("read final configuration"),
        config_before,
        "status/logout preserve configuration bytes"
    );
}

fn run_production_entry(
    runner: &AuthEntryRunner,
    home: &IsolatedHome,
    cancellation: &RunCancellation,
    transport: Arc<dyn BoundedHttpsTransport>,
    callback: (Arc<dyn BrowserOpener>, Option<OwnedFd>),
    clock: Arc<dyn OAuthClock>,
    sender: AuthorizationInstructionSender,
) -> Result<Value, AuthEntryError> {
    let (browser, manual) = callback;
    let home_path = home.0.clone();
    runner.run_with_host_factory(
        AuthCommandInput {
            operation: "auth.login".to_owned(),
            provider: Some("openai-codex".to_owned()),
            credential_id: None,
        },
        cancellation,
        move |child| {
            let oauth = OAuthHost::new_with_native_inputs(
                transport,
                browser,
                manual,
                clock,
                Arc::new(RunOAuthCancel::new(child.clone())),
            )
            .map_err(|_| "native_callback_setup_failed".to_owned())?;
            Ok(AuthHost::new_for_login(home_path, child)?
                .with_oauth_host(Arc::new(oauth))
                .with_authorization_instruction_sender(sender))
        },
    )
}

fn result_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(fields) = value else {
        return None;
    };
    fields.iter().find_map(|(key, field)| {
        matches!(key, Value::String(key) if key.as_ref() == name).then_some(field)
    })
}

fn result_text(value: &Value, name: &str) -> Option<String> {
    match result_field(value, name) {
        Some(Value::String(text)) => Some(text.as_ref().to_owned()),
        _ => None,
    }
}

fn failed_entry(outcome: &Result<Value, AuthEntryError>) -> bool {
    match outcome {
        Err(_) => true,
        Ok(value) => result_field(value, "ok") == Some(&Value::Bool(false)),
    }
}

fn assert_failed_code(outcome: &Result<Value, AuthEntryError>, expected: &str) {
    let Some(value) = outcome.as_ref().ok() else {
        panic!("production entry returned a runner error");
    };
    assert_eq!(result_text(value, "error").as_deref(), Some(expected));
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

fn assert_listener_released(uri: &str) {
    let port = Url::parse(uri)
        .ok()
        .and_then(|parsed| parsed.port())
        .expect("native callback listener port");
    drop(TcpListener::bind(("127.0.0.1", port)).expect("callback listener was released"));
}

fn query_value(url: &str, key: &str) -> Option<String> {
    Url::parse(url).ok().and_then(|parsed| {
        parsed
            .query_pairs()
            .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
    })
}

struct ObservedLoopbackBrowser {
    wrong_state: bool,
    redirect_uri: Arc<Mutex<Option<String>>>,
    accepted: Arc<AtomicBool>,
}

impl BrowserOpener for ObservedLoopbackBrowser {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        let state =
            query_value(authorization_url, "state").ok_or_else(|| OAuthError::Transport {
                message: "synthetic callback setup failed".to_owned(),
            })?;
        let redirect = query_value(authorization_url, "redirect_uri").ok_or_else(|| {
            OAuthError::Transport {
                message: "synthetic callback setup failed".to_owned(),
            }
        })?;
        *self
            .redirect_uri
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(redirect.clone());
        let port = Url::parse(&redirect)
            .ok()
            .and_then(|parsed| parsed.port())
            .ok_or_else(|| OAuthError::Transport {
                message: "synthetic callback setup failed".to_owned(),
            })?;
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream =
            TcpStream::connect_timeout(&address, Duration::from_millis(500)).map_err(|_| {
                OAuthError::Transport {
                    message: "synthetic loopback callback failed".to_owned(),
                }
            })?;
        let callback_state = if self.wrong_state {
            "SYNTHETIC_WRONG_STATE"
        } else {
            state.as_str()
        };
        let request = format!(
            "GET /callback?state={callback_state}&code=SYNTHETIC_AUTHORIZATION_CODE HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|_| OAuthError::Transport {
                message: "synthetic loopback callback failed".to_owned(),
            })?;
        context.check()?;
        let accepted = Arc::clone(&self.accepted);
        thread::spawn(move || {
            let mut response = Vec::new();
            let ok = stream.read_to_end(&mut response).is_ok()
                && response.starts_with(b"HTTP/1.1 200 OK");
            accepted.store(ok, Ordering::Release);
        });
        Ok(())
    }
}

struct FailingBrowser {
    attempts: Arc<AtomicUsize>,
    redirect_uri: Arc<Mutex<Option<String>>>,
}

impl BrowserOpener for FailingBrowser {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        self.attempts.fetch_add(1, Ordering::AcqRel);
        *self
            .redirect_uri
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            query_value(authorization_url, "redirect_uri");
        Err(OAuthError::Transport {
            message: "synthetic browser launch failure".to_owned(),
        })
    }
}

fn production_runner() -> AuthEntryRunner {
    AuthEntryRunner::from_bundle(AUTH_ENTRY_PATH, AUTH_SOURCES)
        .expect("compile the exact production command bundle")
}

const VALID_TOKEN_RESPONSE: &str = r#"{"access_token":"SYNTHETIC_ACCESS_SECRET","refresh_token":"SYNTHETIC_REFRESH_SECRET","token_type":"Bearer","expires_in":3600}"#;

#[test]
fn production_entry_falls_back_to_native_manual_fd_after_browser_failure() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "production_entry_falls_back_to_native_manual_fd_after_browser_failure",
    ) {
        return;
    }
    let runner = production_runner();
    let home = IsolatedHome::configured_pkce();
    let (reader, writer) = pipe_pair();
    let reader_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(reader_fd);
    let attempted_redirect = Arc::new(Mutex::new(None));
    let browser_attempts = Arc::new(AtomicUsize::new(0));
    let browser = Arc::new(FailingBrowser {
        attempts: Arc::clone(&browser_attempts),
        redirect_uri: Arc::clone(&attempted_redirect),
    });
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, VALID_TOKEN_RESPONSE);
    let (sender, receiver) = authorization_instruction_channel();
    let callback_writer = thread::spawn(move || {
        let instruction = receiver.recv().expect("production PKCE instruction");
        let state = query_value(&instruction.authorization_url, "state")
            .expect("state in production authorization URL");
        let mut callback = Url::parse(&instruction.redirect_uri).expect("manual redirect URI");
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", "SYNTHETIC_AUTHORIZATION_CODE");
        let mut writer = fs::File::from(writer);
        writeln!(writer, "{}", callback.as_str()).expect("write native manual callback FD");
        instruction.redirect_uri
    });
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let outcome = run_production_entry(
        &runner,
        &home,
        &cancellation,
        transport.clone(),
        (browser, Some(reader)),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        sender,
    );
    let fd_observation =
        owned_fd_observer::observe_closed(reader_fd, input_identity, assert_fd_closed);
    let manual_redirect = callback_writer.join().expect("manual callback producer");
    assert!(outcome.as_ref().is_ok_and(result_ok));
    assert_eq!(browser_attempts.load(Ordering::Acquire), 1);
    let browser_redirect = attempted_redirect
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
        .expect("failed browser callback listener");
    assert_listener_released(&browser_redirect);
    assert_listener_released(&manual_redirect);
    fd_observation.assert();
    assert_eq!(transport.take_sent().len(), 1);
    let saved: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(home.0.join("auth.yaml")).expect("native credential store after fallback"),
    )
    .expect("decode credential store");
    assert_eq!(
        saved["credentials"]["fixture-codex"]["generation"].as_u64(),
        Some(1)
    );
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn production_entry_rejects_wrong_state_before_exchange_or_save() {
    let runner = production_runner();
    let home = IsolatedHome::configured_pkce();
    let redirect_uri = Arc::new(Mutex::new(None));
    let accepted = Arc::new(AtomicBool::new(false));
    let browser = Arc::new(ObservedLoopbackBrowser {
        wrong_state: true,
        redirect_uri: Arc::clone(&redirect_uri),
        accepted: Arc::clone(&accepted),
    });
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, VALID_TOKEN_RESPONSE);
    let (sender, _receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let outcome = run_production_entry(
        &runner,
        &home,
        &cancellation,
        transport.clone(),
        (browser, None),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        sender,
    );
    assert!(outcome.as_ref().is_ok_and(|value| !result_ok(value)));
    assert_failed_code(&outcome, "state_mismatch");
    assert!(
        transport.take_sent().is_empty(),
        "wrong state sends no token exchange"
    );
    assert!(
        !home.0.join("auth.yaml").exists(),
        "wrong state creates no credential file"
    );
    let redirect = redirect_uri
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
        .expect("browser callback listener");
    assert_listener_released(&redirect);
    assert!(!cancellation.watcher_is_armed());
}

struct MutatingTransport {
    home: PathBuf,
    calls: AtomicUsize,
    written: Mutex<Option<Vec<u8>>>,
}

impl BoundedHttpsTransport for MutatingTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        self.calls.fetch_add(1, Ordering::AcqRel);
        let external_store = concat!(
            "version: 1\ncredentials:\n  fixture-codex:\n",
            "    provider: openai-codex\n    kind: oauth\n",
            "    source: codex-device\n    token_type: Bearer\n",
            "    access_token: EXTERNAL_ACCESS_SENTINEL\n",
            "    refresh_token: EXTERNAL_REFRESH_SENTINEL\n",
            "    expires_at_ms: 1900003600000\n    scopes: []\n",
            "    account_id: acct_external\n    generation: 1\n",
            "    status: active\n    last_refresh_at_ms: 1900000000000\n"
        );
        fs::write(self.home.join("auth.yaml"), external_store).map_err(|_| {
            OAuthError::Transport {
                message: "synthetic store mutation failed".to_owned(),
            }
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                self.home.join("auth.yaml"),
                fs::Permissions::from_mode(0o600),
            )
            .map_err(|_| OAuthError::Transport {
                message: "synthetic store mutation failed".to_owned(),
            })?;
        }
        *self
            .written
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(external_store.as_bytes().to_vec());
        Ok(RawHttpsResponse {
            status: 200,
            headers: Default::default(),
            body: VALID_TOKEN_RESPONSE.as_bytes().to_vec(),
        })
    }
}

#[test]
fn production_entry_preserves_newer_store_generation_during_token_exchange() {
    let runner = production_runner();
    let home = IsolatedHome::configured_pkce();
    let redirect_uri = Arc::new(Mutex::new(None));
    let accepted = Arc::new(AtomicBool::new(false));
    let browser = Arc::new(ObservedLoopbackBrowser {
        wrong_state: false,
        redirect_uri: Arc::clone(&redirect_uri),
        accepted: Arc::clone(&accepted),
    });
    let transport = Arc::new(MutatingTransport {
        home: home.0.clone(),
        calls: AtomicUsize::new(0),
        written: Mutex::new(None),
    });
    let (sender, _receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let outcome = run_production_entry(
        &runner,
        &home,
        &cancellation,
        transport.clone(),
        (browser, None),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        sender,
    );
    assert!(outcome.as_ref().is_ok_and(result_ok));
    assert_eq!(transport.calls.load(Ordering::Acquire), 1);
    let saved: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(home.0.join("auth.yaml")).expect("credential store after concurrent write"),
    )
    .expect("decode credential store");
    let credential = &saved["credentials"]["fixture-codex"];
    assert_eq!(credential["generation"].as_u64(), Some(1));
    assert!(
        credential["access_token"].as_str() == Some("EXTERNAL_ACCESS_SENTINEL"),
        "external access credential preserved"
    );
    assert!(
        credential["refresh_token"].as_str() == Some("EXTERNAL_REFRESH_SENTINEL"),
        "external refresh credential preserved"
    );
    let external_bytes = transport
        .written
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(
        external_bytes.as_ref().is_some_and(
            |before| fs::read(home.0.join("auth.yaml")).is_ok_and(|after| after == *before)
        ),
        "conflicting login leaves the complete concurrent credential store byte-identical"
    );
    assert_eq!(credential["account_id"].as_str(), Some("acct_external"));
    let redirect = redirect_uri
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
        .expect("browser callback listener");
    assert_listener_released(&redirect);
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn production_entry_child_cancellation_closes_pending_manual_callback_resources() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "production_entry_child_cancellation_closes_pending_manual_callback_resources",
    ) {
        return;
    }
    let runner = production_runner();
    let home = IsolatedHome::configured_pkce();
    let (reader, _writer) = pipe_pair();
    let reader_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(reader_fd);
    let attempted_redirect = Arc::new(Mutex::new(None));
    let browser = Arc::new(FailingBrowser {
        attempts: Arc::new(AtomicUsize::new(0)),
        redirect_uri: attempted_redirect,
    });
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, VALID_TOKEN_RESPONSE);
    let (sender, receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let cancel_from_callback = cancellation.clone();
    let callback_waiting = thread::spawn(move || {
        let instruction = receiver.recv().expect("manual fallback instruction");
        thread::sleep(Duration::from_millis(100));
        cancel_from_callback.request(CancellationReason::Requested);
        instruction.redirect_uri
    });
    let outcome = run_production_entry(
        &runner,
        &home,
        &cancellation,
        transport.clone(),
        (browser, Some(reader)),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        sender,
    );
    let fd_observation =
        owned_fd_observer::observe_closed(reader_fd, input_identity, assert_fd_closed);
    let redirect = callback_waiting.join().expect("child cancellation trigger");
    assert!(failed_entry(&outcome));
    assert!(cancellation.requested().is_some());
    assert!(transport.take_sent().is_empty());
    assert!(!home.0.join("auth.yaml").exists());
    fd_observation.assert();
    assert_listener_released(&redirect);
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn production_entry_callback_timeout_closes_pending_manual_callback_resources() {
    if owned_fd_observer::spawn_fd_observer_child_unless_child(
        "production_entry_callback_timeout_closes_pending_manual_callback_resources",
    ) {
        return;
    }
    let runner = production_runner();
    let home = IsolatedHome::configured_pkce();
    let (reader, _writer) = pipe_pair();
    let reader_fd = reader.as_raw_fd();
    let input_identity = owned_fd_observer::input_identity(reader_fd);
    let attempted_redirect = Arc::new(Mutex::new(None));
    let browser = Arc::new(FailingBrowser {
        attempts: Arc::new(AtomicUsize::new(0)),
        redirect_uri: attempted_redirect,
    });
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, VALID_TOKEN_RESPONSE);
    let (sender, receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let expire_clock = Arc::clone(&clock);
    let callback_waiting = thread::spawn(move || {
        let instruction = receiver.recv().expect("manual fallback instruction");
        thread::sleep(Duration::from_millis(100));
        expire_clock.expire();
        instruction.redirect_uri
    });
    let outcome = run_production_entry(
        &runner,
        &home,
        &cancellation,
        transport.clone(),
        (browser, Some(reader)),
        clock,
        sender,
    );
    let fd_observation =
        owned_fd_observer::observe_closed(reader_fd, input_identity, assert_fd_closed);
    let redirect = callback_waiting.join().expect("callback timeout trigger");
    assert!(outcome.as_ref().is_ok_and(|value| !result_ok(value)));
    assert_failed_code(&outcome, "callback_timeout");
    assert!(transport.take_sent().is_empty());
    assert!(!home.0.join("auth.yaml").exists());
    fd_observation.assert();
    assert_listener_released(&redirect);
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn production_entry_malformed_token_metadata_never_saves_credentials() {
    let runner = production_runner();
    let home = IsolatedHome::configured_pkce();
    let redirect_uri = Arc::new(Mutex::new(None));
    let accepted = Arc::new(AtomicBool::new(false));
    let browser = Arc::new(ObservedLoopbackBrowser {
        wrong_state: false,
        redirect_uri: Arc::clone(&redirect_uri),
        accepted: Arc::clone(&accepted),
    });
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"access_token":"SYNTHETIC_INVALID_METADATA_ACCESS","refresh_token":"SYNTHETIC_INVALID_METADATA_REFRESH","token_type":"Bearer","expires_in":"invalid"}"#,
    );
    let (sender, _receiver) = authorization_instruction_channel();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let outcome = run_production_entry(
        &runner,
        &home,
        &cancellation,
        transport.clone(),
        (browser, None),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        sender,
    );
    assert!(outcome.as_ref().is_ok_and(|value| !result_ok(value)));
    assert_failed_code(&outcome, "invalid_token_metadata");
    assert_eq!(transport.take_sent().len(), 1);
    assert!(!home.0.join("auth.yaml").exists());
    let redirect = redirect_uri
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
        .expect("browser callback listener");
    assert_listener_released(&redirect);
    assert!(!cancellation.watcher_is_armed());
}
