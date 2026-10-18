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
        native_callback::NativeLoopbackCallbacks,
        native_https::NativeHttpsTransport,
        oauth::{BrowserOpener, OAuthError, OAuthHost, OAuthIoContext},
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use url::Url;

const CALLBACK_CODE: &str = "NATIVE_RSS_CALLBACK_CODE_MARKER";

struct FreshLoginHome(PathBuf);

impl FreshLoginHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!(
            "native-callback-rss-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create private login home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy configured provider policy");
        fs::write(path.join("auth.yaml"), "version: 1\ncredentials: {}\n")
            .expect("write empty fresh auth store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("restrict fresh home");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("restrict home file");
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

#[derive(Clone, Copy)]
enum CallbackReply {
    Matching,
    MismatchedState,
    InvalidMethod,
}

struct LoopbackRedirectClient {
    reply: CallbackReply,
    authorization_url: Mutex<Option<String>>,
    redirect_uri: Mutex<Option<String>>,
    stream: Mutex<Option<TcpStream>>,
}

impl LoopbackRedirectClient {
    fn new() -> Self {
        Self::with_reply(CallbackReply::Matching)
    }

    fn with_reply(reply: CallbackReply) -> Self {
        Self {
            reply,
            authorization_url: Mutex::new(None),
            redirect_uri: Mutex::new(None),
            stream: Mutex::new(None),
        }
    }

    fn authorization_url(&self) -> String {
        self.authorization_url
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .expect("browser received authorization URL")
    }

    fn redirect_uri(&self) -> String {
        self.redirect_uri
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .expect("browser received configured redirect URI")
    }

    fn was_opened(&self) -> bool {
        self.authorization_url
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    fn read_receipt(&self) -> String {
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("redirect client socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set bounded receipt read");
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .expect("read callback receipt");
        String::from_utf8(bytes).expect("callback receipt is UTF-8")
    }
}

impl BrowserOpener for LoopbackRedirectClient {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        let authorization = Url::parse(authorization_url).map_err(|_| OAuthError::Transport {
            message: "test authorization URL invalid".into(),
        })?;
        let redirect_uri = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "test redirect URI missing".into(),
            })?;
        let state = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "test state missing".into(),
            })?;
        let mut callback = Url::parse(&redirect_uri).map_err(|_| OAuthError::Transport {
            message: "test callback URI invalid".into(),
        })?;
        let port = callback.port().ok_or_else(|| OAuthError::Transport {
            message: "test callback port missing".into(),
        })?;
        let callback_state = match self.reply {
            CallbackReply::MismatchedState => "FOREIGN_CALLBACK_STATE_MARKER",
            CallbackReply::Matching | CallbackReply::InvalidMethod => &state,
        };
        callback
            .query_pairs_mut()
            .append_pair("state", callback_state)
            .append_pair("code", CALLBACK_CODE);
        let target = format!(
            "{}?{}",
            callback.path(),
            callback.query().unwrap_or_default()
        );
        let method = if matches!(self.reply, CallbackReply::InvalidMethod) {
            "POST"
        } else {
            "GET"
        };
        let request = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream =
            TcpStream::connect_timeout(&address, Duration::from_millis(500)).map_err(|_| {
                OAuthError::Transport {
                    message: "test callback connect failed".into(),
                }
            })?;
        stream
            .write_all(request.as_bytes())
            .map_err(|_| OAuthError::Transport {
                message: "test callback write failed".into(),
            })?;
        *self
            .authorization_url
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(authorization_url.to_owned());
        *self
            .redirect_uri
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(redirect_uri);
        *self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(stream);
        Ok(())
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

fn native_oauth_host(
    browser: Arc<dyn BrowserOpener>,
    cancellation: &RunCancellation,
) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        browser,
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ))
}

fn callback_address(redirect_uri: &str) -> SocketAddr {
    let redirect = Url::parse(redirect_uri).expect("native redirect URI");
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        redirect.port().expect("ephemeral callback port"),
    )
}

fn assert_callback_port_bound(redirect_uri: &str) {
    assert!(TcpListener::bind(callback_address(redirect_uri)).is_err());
}

fn assert_callback_port_released(redirect_uri: &str) {
    drop(TcpListener::bind(callback_address(redirect_uri)).expect("callback listener released"));
}

fn typed_vm(source: &str, config_path: &Path) -> Vm {
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        config_path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile actual callback RSS against production auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = FreshLoginHome::new("registration");
    let registration_host = AuthHost::new_for_login(
        registration_home.path(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("configured login host for restricted catalog registration");
    registration_host
        .register(&mut registry, catalog.as_ref())
        .expect("register exact production auth catalog");
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

fn configured_intent(credential_id: &str) -> Value {
    Value::map(vec![
        (Value::string("credential_id"), Value::string(credential_id)),
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
                public_query("client_id", "public-client-id"),
                public_query("response_type", "code"),
            ]),
        ),
    ])
}

fn query_value(url: &Url, wanted: &str) -> String {
    url.query_pairs()
        .find_map(|(key, value)| (key == wanted).then(|| value.into_owned()))
        .unwrap_or_else(|| panic!("missing expected public query field"))
}

#[test]
fn native_pkce_and_callback_wait_work_through_restricted_typed_rss() {
    let home = FreshLoginHome::new("configured-absent-credential");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let browser = Arc::new(LoopbackRedirectClient::new());
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        Arc::new(NativeHttpsTransport::new()),
        browser.clone(),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("configured fresh-home login admission")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("real typed callback RSS source");
    let compile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &compile_path);
    let owner = auth.bind_vm(&mut vm).expect("bind configured VM owner");

    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let owner_home = field(&owner, "host_home");
    let unconfigured = vm
        .invoke_callable(
            begin.clone(),
            &[owner_home.clone(), configured_intent("unconfigured-orphan")],
        )
        .expect_err("unconfigured credential must be denied before native effects");
    assert!(unconfigured.to_string().contains("credential_not_admitted"));
    assert!(!browser.was_opened());
    assert_eq!(vm.host_context().resource_count(), 2);

    let begun = vm
        .invoke_callable(begin, &[owner_home, configured_intent("fixture-codex")])
        .expect("native PKCE begin through real typed RSS");
    let authorization_url =
        Url::parse(&string_field(&begun, "authorization_url")).expect("bounded authorization URL");
    let redirect_uri = string_field(&begun, "redirect_uri");
    assert_eq!(authorization_url.path(), "/codex/device");
    assert_eq!(
        query_value(&authorization_url, "client_id"),
        "public-client-id"
    );
    assert_eq!(query_value(&authorization_url, "response_type"), "code");
    assert_eq!(query_value(&authorization_url, "scope"), "scope.synthetic");
    assert_eq!(
        query_value(&authorization_url, "code_challenge_method"),
        "S256"
    );
    assert_eq!(
        query_value(&authorization_url, "redirect_uri"),
        redirect_uri
    );
    assert_eq!(browser.authorization_url(), authorization_url.as_str());
    assert_eq!(browser.redirect_uri(), redirect_uri);

    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    let mut foreign_vm = typed_vm(&source, &compile_path);
    let _foreign_owner = auth.bind_vm(&mut foreign_vm).expect("bind second VM owner");
    let foreign_wait = foreign_vm
        .resolve_exported_callable("wait")
        .expect("second typed RSS wait");
    let cross_vm = foreign_vm
        .invoke_callable(foreign_wait, std::slice::from_ref(&callback))
        .expect_err("native callback resource cannot cross VM arenas");
    assert!(cross_vm.to_string().contains("resource_handle_wrong_table"));
    assert_eq!(vm.host_context().resource_count(), 4);
    drop(foreign_vm);

    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let waited = vm
        .invoke_callable(wait.clone(), std::slice::from_ref(&callback))
        .expect("native loopback callback wait through typed RSS");
    assert_eq!(field(&waited, "outcome"), Value::string("success"));
    let code = field(&waited, "code_handle");
    assert!(matches!(code, Value::Int(_)));
    let receipt = browser.read_receipt();
    assert!(receipt.starts_with("HTTP/1.1 200 OK"));
    assert!(receipt.contains("Callback received"));
    assert!(!receipt.contains(CALLBACK_CODE));

    let replay = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect_err("native callback handle cannot issue a second code");
    assert!(replay.to_string().contains("handle_replayed"));

    for (name, resource) in [
        ("close_callback", callback),
        ("close_verifier", verifier),
        ("close_code", code),
    ] {
        let close = vm
            .resolve_exported_callable(name)
            .expect("typed close export");
        vm.invoke_callable(close, &[resource])
            .expect("retire callback resource family");
    }
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_callback_port_released(&redirect_uri);
}

#[test]
fn injected_native_waiter_does_not_admit_pkce_without_native_constructor() {
    let home = FreshLoginHome::new("injected-native-waiter");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let browser = Arc::new(NoopBrowser::default());
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(NativeHttpsTransport::new()),
        Arc::new(NativeLoopbackCallbacks),
        browser.clone(),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation.clone())),
    ));
    let auth = AuthHost::new_for_login(home.path(), cancellation)
        .expect("configured login admission")
        .with_oauth_host(oauth);
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("real typed callback RSS source");
    let compile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &compile_path);
    let owner = auth.bind_vm(&mut vm).expect("bind configured VM owner");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");

    let failure = vm
        .invoke_callable(
            begin,
            &[
                field(&owner, "host_home"),
                configured_intent("fixture-codex"),
            ],
        )
        .expect_err("injecting the native waiter type must not grant native admission");
    assert!(failure.to_string().contains("callback_unavailable"));
    assert_eq!(browser.open_count(), 0);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn malformed_and_mismatched_native_callbacks_revoke_rss_resources() {
    for (reply, expected, expected_receipt) in [
        (
            CallbackReply::MismatchedState,
            "state_mismatch",
            "HTTP/1.1 200 OK",
        ),
        (
            CallbackReply::InvalidMethod,
            "invalid_intent",
            "HTTP/1.1 400 Bad Request",
        ),
    ] {
        let home = FreshLoginHome::new("bad-native-callback");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
        let browser = Arc::new(LoopbackRedirectClient::with_reply(reply));
        let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
            .expect("configured login admission")
            .with_oauth_host(native_oauth_host(browser.clone(), &cancellation));
        let source_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
        let source = fs::read_to_string(&source_path).expect("real typed callback RSS source");
        let compile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config_auth_rss/config.yaml");
        let mut vm = typed_vm(&source, &compile_path);
        let owner = auth.bind_vm(&mut vm).expect("bind configured VM owner");
        let begin = vm
            .resolve_exported_callable("begin")
            .expect("typed RSS begin");
        let begun = vm
            .invoke_callable(
                begin,
                &[
                    field(&owner, "host_home"),
                    configured_intent("fixture-codex"),
                ],
            )
            .expect("native PKCE begin");
        let callback = field(&begun, "callback_handle");
        let redirect_uri = string_field(&begun, "redirect_uri");
        assert_callback_port_bound(&redirect_uri);

        let wait = vm
            .resolve_exported_callable("wait")
            .expect("typed RSS wait");
        let failure = vm
            .invoke_callable(wait, std::slice::from_ref(&callback))
            .expect_err("bad native callback must fail closed");
        assert!(failure.to_string().contains(expected));
        assert!(!failure.to_string().contains(CALLBACK_CODE));
        let receipt = browser.read_receipt();
        assert!(receipt.starts_with(expected_receipt));
        assert!(!receipt.contains(CALLBACK_CODE));
        assert!(!receipt.contains("FOREIGN_CALLBACK_STATE_MARKER"));
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_callback_port_released(&redirect_uri);
    }
}

#[test]
fn native_callback_wait_cancellation_closes_partial_socket_and_resources() {
    let home = FreshLoginHome::new("native-callback-cancel");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let browser = Arc::new(NoopBrowser::default());
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("configured login admission")
        .with_oauth_host(native_oauth_host(browser, &cancellation));
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("real typed callback RSS source");
    let compile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &compile_path);
    let owner = auth.bind_vm(&mut vm).expect("bind configured VM owner");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[
                field(&owner, "host_home"),
                configured_intent("fixture-codex"),
            ],
        )
        .expect("native PKCE begin");
    let callback = field(&begun, "callback_handle");
    let redirect_uri = string_field(&begun, "redirect_uri");
    assert_callback_port_bound(&redirect_uri);
    let mut partial =
        TcpStream::connect_timeout(&callback_address(&redirect_uri), Duration::from_millis(500))
            .expect("connect to native callback listener");
    partial
        .write_all(b"GET /callback?state=partial")
        .expect("send bounded partial callback request");

    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        started_tx.send(()).expect("signal callback wait start");
        let result = vm.invoke_callable(wait, std::slice::from_ref(&callback));
        let failure = result.err().map(|failure| failure.to_string());
        (failure, vm.host_context().resource_count())
    });
    started_rx
        .recv_timeout(Duration::from_millis(750))
        .expect("callback wait worker started within native budget");
    thread::sleep(Duration::from_millis(60));
    let cancelled_at = Instant::now();
    cancellation.request(CancellationReason::Requested);
    let (failure, resources) = worker.join().expect("callback wait worker joined");
    assert!(cancelled_at.elapsed() <= Duration::from_millis(750));
    assert!(
        failure
            .as_deref()
            .is_some_and(|failure| failure.contains("callback_cancelled"))
    );
    assert_eq!(resources, 2);
    drop(partial);
    assert_callback_port_released(&redirect_uri);
}

#[test]
fn native_callback_deadline_reclaims_listener_and_opaque_family() {
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("real typed callback RSS source");
    let compile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &compile_path);
    let home = FreshLoginHome::new("native-callback-deadline");
    let cancellation = RunCancellation::with_timeout(Duration::from_millis(750));
    let browser = Arc::new(NoopBrowser::default());
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("configured login admission")
        .with_oauth_host(native_oauth_host(browser, &cancellation));
    let owner = auth.bind_vm(&mut vm).expect("bind configured VM owner");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[
                field(&owner, "host_home"),
                configured_intent("fixture-codex"),
            ],
        )
        .expect("native PKCE begin within finite owner deadline");
    let callback = field(&begun, "callback_handle");
    let redirect_uri = string_field(&begun, "redirect_uri");
    assert_callback_port_bound(&redirect_uri);

    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let failure = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect_err("callback wait must honor the owner deadline");
    assert!(failure.to_string().contains("callback_timeout"));
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_callback_port_released(&redirect_uri);
}

#[test]
fn native_owner_revoke_and_vm_reset_close_callback_listener() {
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("real typed callback RSS source");
    let compile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");

    let home = FreshLoginHome::new("native-callback-revoke");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("configured login admission")
        .with_oauth_host(native_oauth_host(
            Arc::new(NoopBrowser::default()),
            &cancellation,
        ));
    let mut vm = typed_vm(&source, &compile_path);
    let owner = auth.bind_vm(&mut vm).expect("bind configured VM owner");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[
                field(&owner, "host_home"),
                configured_intent("fixture-codex"),
            ],
        )
        .expect("native PKCE begin");
    let callback = field(&begun, "callback_handle");
    let redirect_uri = string_field(&begun, "redirect_uri");
    assert_callback_port_bound(&redirect_uri);
    auth.revoke();
    let wait = vm
        .resolve_exported_callable("wait")
        .expect("typed RSS wait");
    let revoked = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect_err("revoked owner must not wait");
    assert!(revoked.to_string().contains("policy_inactive"));
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_callback_port_released(&redirect_uri);

    let reset_home = FreshLoginHome::new("native-callback-reset");
    let reset_cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let reset_auth = AuthHost::new_for_login(reset_home.path(), reset_cancellation.clone())
        .expect("configured login admission")
        .with_oauth_host(native_oauth_host(
            Arc::new(NoopBrowser::default()),
            &reset_cancellation,
        ));
    let mut reset_vm = typed_vm(&source, &compile_path);
    let reset_owner = reset_auth
        .bind_vm(&mut reset_vm)
        .expect("bind VM for teardown");
    let reset_begin = reset_vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let reset_begun = reset_vm
        .invoke_callable(
            reset_begin,
            &[
                field(&reset_owner, "host_home"),
                configured_intent("fixture-codex"),
            ],
        )
        .expect("native flow before VM reset");
    let reset_redirect = string_field(&reset_begun, "redirect_uri");
    assert_callback_port_bound(&reset_redirect);
    reset_vm.reset_for_reuse().expect("reset VM resources");
    assert_eq!(reset_vm.host_context().resource_count(), 0);
    assert_callback_port_released(&reset_redirect);
}

#[cfg(feature = "config-fixture")]
#[test]
fn native_owner_does_not_enable_fixture_callback_injection() {
    let home = FreshLoginHome::new("native-fixture-injection");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let auth = AuthHost::new_for_login(home.path(), cancellation.clone())
        .expect("configured login admission")
        .with_oauth_host(native_oauth_host(
            Arc::new(NoopBrowser::default()),
            &cancellation,
        ));
    let source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    let source = fs::read_to_string(&source_path).expect("real typed callback RSS source");
    let compile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let mut vm = typed_vm(&source, &compile_path);
    let owner = auth.bind_vm(&mut vm).expect("bind configured VM owner");
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS begin");
    let begun = vm
        .invoke_callable(
            begin,
            &[
                field(&owner, "host_home"),
                configured_intent("fixture-codex"),
            ],
        )
        .expect("native PKCE begin without fixture permission");
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    let redirect_uri = string_field(&begun, "redirect_uri");

    let failure = auth
        .fixture_inject_matching_callback(&mut vm, &callback, CALLBACK_CODE)
        .expect_err("native capability must not authorize synthetic injection");
    assert!(failure.to_string().contains("callback_unavailable"));
    assert_eq!(vm.host_context().resource_count(), 4);

    for (name, resource) in [("close_callback", callback), ("close_verifier", verifier)] {
        let close = vm
            .resolve_exported_callable(name)
            .expect("typed close export");
        vm.invoke_callable(close, &[resource])
            .expect("close native callback family");
    }
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_callback_port_released(&redirect_uri);
}
