use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use rustscript_agent::auth::oauth::{
    BoundedPublicOAuthIntent, BrowserOpener, CallbackMode, OAuthError, OAuthFlowKind, OAuthHost,
    OAuthIoContext, RawCallbackInput, ScriptedBrowser, ScriptedCancel, ScriptedClock,
    ScriptedHttpsTransport, TrustedEndpoint, TrustedTransportPolicy,
};
use url::Url;

const CALLBACK_CODE: &str = "NATIVE_TEST_AUTH_CODE_MARKER";
const CANCEL_BUDGET: Duration = Duration::from_millis(750);

struct RedirectingBrowser {
    connected: Arc<AtomicBool>,
    redirects: Arc<Mutex<Vec<String>>>,
    socket: Mutex<Option<TcpStream>>,
    fail_after_open: bool,
}

impl RedirectingBrowser {
    fn new(fail_after_open: bool) -> Self {
        Self {
            connected: Arc::new(AtomicBool::new(false)),
            redirects: Arc::new(Mutex::new(Vec::new())),
            socket: Mutex::new(None),
            fail_after_open,
        }
    }

    fn connected(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.connected)
    }

    fn redirects(&self) -> Vec<String> {
        self.redirects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn read_receipt(&self) -> String {
        let mut guard = self.socket.lock().unwrap_or_else(|e| e.into_inner());
        let mut stream = guard.take().expect("browser callback socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).expect("read HTTP receipt");
        String::from_utf8(bytes).expect("UTF-8 receipt")
    }
}

impl BrowserOpener for RedirectingBrowser {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        let authorization = Url::parse(authorization_url).expect("authorization URL");
        let redirect = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
            .expect("redirect URI");
        self.redirects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(redirect.clone());
        let mut callback = Url::parse(&redirect).expect("callback URI");
        let port = callback.port().expect("ephemeral port");
        let state = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .expect("state");
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", CALLBACK_CODE);
        let target = format!("{}?{}", callback.path(), callback.query().unwrap());
        let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut stream = match TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
            Ok(stream) => stream,
            Err(_) => {
                self.connected.store(false, Ordering::Release);
                return if self.fail_after_open {
                    Err(OAuthError::Transport {
                        message: "fixture browser callback connect failed".into(),
                    })
                } else {
                    Ok(())
                };
            }
        };
        self.connected.store(true, Ordering::Release);
        stream
            .write_all(request.as_bytes())
            .map_err(|_| OAuthError::Transport {
                message: "fixture browser callback write failed".into(),
            })?;
        if self.fail_after_open {
            drop(stream);
            return Err(OAuthError::Transport {
                message: "fixture browser failed after open".into(),
            });
        }
        *self.socket.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream);
        Ok(())
    }
}

fn policy() -> TrustedTransportPolicy {
    TrustedTransportPolicy {
        generation: 1,
        run_id: "native-loopback-tests".into(),
        deadline: Instant::now() + Duration::from_secs(10),
        endpoints: vec![TrustedEndpoint {
            authority: "auth.example.test".into(),
            path_prefix: "/oauth".into(),
        }],
        allowed_header_names: BTreeSet::new(),
    }
}

fn intent(mode: CallbackMode) -> BoundedPublicOAuthIntent {
    BoundedPublicOAuthIntent {
        flow: OAuthFlowKind::AuthorizationCodePkce,
        callback_mode: mode,
        path: "/oauth/authorize".into(),
        scopes: Vec::new(),
        public_query: BTreeMap::new(),
        credential_id: "primary".into(),
    }
}

fn native_host(browser: Arc<dyn BrowserOpener>, cancel: Arc<ScriptedCancel>) -> OAuthHost {
    OAuthHost::new_with_native_callbacks(
        Arc::new(ScriptedHttpsTransport::new()),
        browser,
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        cancel,
    )
}

fn query_value(url: &str, wanted: &str) -> String {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == wanted).then(|| value.into_owned()))
        .unwrap_or_else(|| panic!("missing {wanted}"))
}

fn address(uri: &str) -> SocketAddr {
    let parsed = Url::parse(uri).expect("callback URI");
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/callback");
    let port = parsed.port().expect("ephemeral port");
    assert_ne!(port, 0);
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn request_target(state: &str, code: &str) -> String {
    let mut url = Url::parse("http://127.0.0.1/callback").unwrap();
    url.query_pairs_mut()
        .append_pair("state", state)
        .append_pair("code", code);
    format!("{}?{}", url.path(), url.query().unwrap())
}

fn valid_request(uri: &str, state: &str, code: &str) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        request_target(state, code),
        address(uri).port()
    )
}

fn send(uri: &str, raw: &str) -> TcpStream {
    let mut stream = TcpStream::connect_timeout(&address(uri), Duration::from_millis(500))
        .expect("connect to native callback listener");
    stream.write_all(raw.as_bytes()).expect("write request");
    stream.shutdown(Shutdown::Write).expect("finish request");
    stream
}

fn response(mut stream: TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read response");
    String::from_utf8(bytes).expect("UTF-8 response")
}

fn assert_released(uri: &str) {
    drop(TcpListener::bind(address(uri)).expect("callback port released"));
}

#[test]
fn browser_redirect_reaches_listener_and_returns_only_opaque_single_use_code() {
    let browser = Arc::new(RedirectingBrowser::new(false));
    let connected = browser.connected();
    let host = native_host(browser.clone(), Arc::new(ScriptedCancel::new()));
    assert!(host.has_native_callbacks());
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("begin");
    assert!(
        connected.load(Ordering::Acquire),
        "browser could not connect during open"
    );
    let uri = query_value(&begun.authorization_url, "redirect_uri");
    let state = query_value(&begun.authorization_url, "state");
    let callback = host
        .callback_wait(&begun.callback_handle)
        .expect("valid native callback");
    assert!(callback.code_handle.is_some());
    let debug = format!("{callback:?}");
    assert!(!debug.contains(CALLBACK_CODE));
    assert!(!debug.contains(&state));
    let receipt = browser.read_receipt();
    assert!(receipt.starts_with("HTTP/1.1 200 OK"), "{receipt}");
    assert!(receipt.contains("Callback received"), "{receipt}");
    assert!(!receipt.contains(CALLBACK_CODE));
    assert!(!receipt.contains(&state));
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .unwrap_err()
            .code(),
        "handle_replayed"
    );
    assert!(TcpStream::connect_timeout(&address(&uri), Duration::from_millis(100)).is_err());
    assert_released(&uri);
}

#[test]
fn overlapping_flows_reject_foreign_state_and_release_only_the_selected_session() {
    let host = native_host(
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedCancel::new()),
    );
    let a = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("flow A");
    let b = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("flow B");
    let uri_a = query_value(&a.authorization_url, "redirect_uri");
    let uri_b = query_value(&b.authorization_url, "redirect_uri");
    assert_ne!(address(&uri_a).port(), address(&uri_b).port());
    let foreign = send(
        &uri_b,
        &valid_request(
            &uri_b,
            &query_value(&a.authorization_url, "state"),
            "FOREIGN_CODE_MARKER",
        ),
    );
    let failure = host
        .callback_wait(&b.callback_handle)
        .expect_err("foreign state rejected");
    assert_eq!(failure.code(), "state_mismatch");
    let reply = response(foreign);
    assert!(reply.starts_with("HTTP/1.1 200 OK"));
    assert!(!reply.contains("FOREIGN_CODE_MARKER"));
    assert_released(&uri_b);
    let own = send(
        &uri_a,
        &valid_request(
            &uri_a,
            &query_value(&a.authorization_url, "state"),
            "FLOW_A_CODE_MARKER",
        ),
    );
    assert!(
        host.callback_wait(&a.callback_handle)
            .expect("flow A state")
            .code_handle
            .is_some()
    );
    assert!(response(own).starts_with("HTTP/1.1 200 OK"));
    assert_released(&uri_a);
}

#[test]
fn malformed_protocol_state_and_oversized_inputs_fail_closed() {
    let host = native_host(
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedCancel::new()),
    );
    let cases = [
        "wrong method",
        "wrong path",
        "wrong host",
        "duplicate host",
        "absolute target",
        "duplicate state",
        "missing code",
        "duplicate code",
        "bad escape",
        "invalid utf8",
        "body",
        "transfer encoding",
    ];
    for case in cases {
        let begun = host
            .pkce_begin(&policy(), intent(CallbackMode::Browser))
            .expect("listener");
        let uri = query_value(&begun.authorization_url, "redirect_uri");
        let state = query_value(&begun.authorization_url, "state");
        let port = address(&uri).port();
        let good = valid_request(&uri, &state, "BAD_CODE_MARKER");
        let raw = match case {
            "wrong method" => good.replacen("GET ", "POST ", 1),
            "wrong path" => good.replacen("/callback?", "/other?", 1),
            "wrong host" => {
                good.replace(&format!("127.0.0.1:{port}"), &format!("localhost:{port}"))
            }
            "duplicate host" => {
                good.replace("\r\n\r\n", &format!("\r\nHost: 127.0.0.1:{port}\r\n\r\n"))
            }
            "absolute target" => good.replacen(
                "/callback?",
                &format!("http://127.0.0.1:{port}/callback?"),
                1,
            ),
            "duplicate state" => good.replacen("&code=", &format!("&state={state}&code="), 1),
            "missing code" => good.replace("&code=BAD_CODE_MARKER", ""),
            "duplicate code" => good.replace("&code=BAD_CODE_MARKER", "&code=ONE&code=TWO"),
            "bad escape" => good.replace(&state, "%Q0"),
            "invalid utf8" => good.replace(&state, "%FF"),
            "body" => good.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"),
            "transfer encoding" => {
                good.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n")
            }
            _ => unreachable!(),
        };
        let socket = send(&uri, &raw);
        let failure = host.callback_wait(&begun.callback_handle).expect_err(case);
        assert_eq!(failure.code(), "invalid_intent", "{case}: {failure}");
        let reply = response(socket);
        assert!(
            reply.starts_with("HTTP/1.1 400 Bad Request"),
            "{case}: {reply}"
        );
        assert!(!reply.contains("BAD_CODE_MARKER"), "{case}: {reply}");
        assert_released(&uri);
    }

    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("oversized listener");
    let uri = query_value(&begun.authorization_url, "redirect_uri");
    let huge = format!(
        "GET /callback?x={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        "x".repeat(9000),
        address(&uri).port()
    );
    let socket = send(&uri, &huge);
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .expect_err("request cap")
            .code(),
        "invalid_intent"
    );
    assert!(response(socket).starts_with("HTTP/1.1 400 Bad Request"));
    assert_released(&uri);
}

#[test]
fn unsupported_modes_device_flow_and_injection_fail_closed() {
    let host = native_host(
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedCancel::new()),
    );
    for mode in [CallbackMode::Manual, CallbackMode::None] {
        let error = host
            .pkce_begin(&policy(), intent(mode))
            .expect_err("mode unsupported");
        assert_eq!(error.code(), "invalid_intent");
        assert!(error.to_string().contains("unsupported"));
    }
    let mut device = intent(CallbackMode::Browser);
    device.flow = OAuthFlowKind::DeviceCode;
    let error = host
        .pkce_begin(&policy(), device)
        .expect_err("device flow excluded");
    assert_eq!(error.code(), "invalid_intent");
    assert!(error.to_string().contains("device_code"));
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("browser flow");
    assert_eq!(
        host.inject_matching_callback(&begun.callback_handle, "INJECTION_MARKER")
            .unwrap_err()
            .code(),
        "transport_error"
    );
    assert!(host.has_native_callbacks());
}

#[test]
fn idle_and_partial_request_cancellation_release_listener_within_owner_budget() {
    for partial in [None, Some("GET /callback?state=incomplete")] {
        let cancel = Arc::new(ScriptedCancel::new());
        let host = native_host(Arc::new(ScriptedBrowser::new()), Arc::clone(&cancel));
        let begun = host
            .pkce_begin(&policy(), intent(CallbackMode::Browser))
            .expect("listener");
        let uri = query_value(&begun.authorization_url, "redirect_uri");
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            host.callback_wait(&begun.callback_handle)
        });
        ready_rx.recv_timeout(CANCEL_BUDGET).expect("wait started");
        let mut client = TcpStream::connect_timeout(&address(&uri), Duration::from_millis(500))
            .expect("connect while waiting");
        if let Some(bytes) = partial {
            client.write_all(bytes.as_bytes()).unwrap();
        }
        let started = Instant::now();
        cancel.cancel();
        let result = worker.join().expect("wait thread joined");
        assert!(started.elapsed() <= CANCEL_BUDGET, "cancel exceeded 750 ms");
        assert_eq!(
            result.expect_err("cancelled wait").code(),
            "callback_cancelled"
        );
        assert_released(&uri);
    }
}

#[test]
fn browser_failure_and_host_drop_release_owned_ports_with_retained_handle() {
    let browser = Arc::new(RedirectingBrowser::new(true));
    let host = native_host(browser.clone(), Arc::new(ScriptedCancel::new()));
    assert_eq!(
        host.pkce_begin(&policy(), intent(CallbackMode::Browser))
            .unwrap_err()
            .code(),
        "transport_error"
    );
    assert!(browser.connected.load(Ordering::Acquire));
    let uri = browser.redirects().pop().expect("browser saw redirect");
    assert_released(&uri);

    let host = native_host(
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedCancel::new()),
    );
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("flow before host drop");
    let uri = query_value(&begun.authorization_url, "redirect_uri");
    let retained = begun.callback_handle;
    drop(host);
    assert!(format!("{retained:?}").contains("OpaqueCallbackHandle"));
    assert_released(&uri);
}

#[test]
fn raw_callback_debug_redacts_query_and_manual_url_contents() {
    for input in [
        RawCallbackInput::Query {
            state: "RAW_STATE_MARKER".into(),
            code: "RAW_CODE_MARKER".into(),
        },
        RawCallbackInput::ManualUrl(
            "http://127.0.0.1/callback?state=RAW_STATE_MARKER&code=RAW_CODE_MARKER".into(),
        ),
    ] {
        let debug = format!("{input:?}");
        assert!(!debug.contains("RAW_STATE_MARKER"));
        assert!(!debug.contains("RAW_CODE_MARKER"));
    }
}

#[test]
fn injected_constructor_keeps_the_fixture_callback_path_separate_from_native() {
    let host = OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(rustscript_agent::auth::oauth::ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    );
    assert!(!host.has_native_callbacks());
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("injected browser flow");
    host.inject_matching_callback(&begun.callback_handle, "FIXTURE_CODE_MARKER")
        .expect("injected fixture callback");
    assert!(
        host.callback_wait(&begun.callback_handle)
            .expect("injected callback wait")
            .code_handle
            .is_some()
    );
}

// Red-test history for the initial feature gate uses an actual connect attempt
// during BrowserOpener::open; the current synthetic redirect failed it.
#[test]
fn native_redirect_listener_is_ready_during_browser_open() {
    let browser = Arc::new(RedirectingBrowser::new(false));
    let connected = browser.connected();
    let host = native_host(browser, Arc::new(ScriptedCancel::new()));
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("begin");
    assert!(
        connected.load(Ordering::Acquire),
        "browser could not connect to the prepared loopback listener"
    );
    let uri = query_value(&begun.authorization_url, "redirect_uri");
    assert!(
        host.callback_wait(&begun.callback_handle)
            .unwrap()
            .code_handle
            .is_some()
    );
    assert_released(&uri);
}
