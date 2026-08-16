//! Telegram adapter fixture tests.
//!
//! Every Bot API interaction runs against a local fixture server (never the
//! real Telegram network). The fixture records requests and scripts
//! getUpdates results and failure responses, so the tests can assert exact
//! wire behavior: long-poll parameters, bounded 429/5xx retries, typed 4xx
//! failures, token redaction, envelope mapping, allowlists, dedup, commands,
//! render actions, and restart persistence.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, Query, State},
    http::{Method, Request, StatusCode},
    response::IntoResponse,
    routing::post,
};
use futures_util::StreamExt;
use rustscript_agent::config::TelegramConfig;
use rustscript_agent::gateway::telegram::{TelegramApi, TelegramError};
use rustscript_agent::service::AdmitRunRequest;
use rustscript_vm::IoPolicy;
use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// One recorded Bot API request: method, query string, and JSON body.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub query: HashMap<String, String>,
    pub body: Value,
}

/// Scripted failure for one Bot API method; each entry is consumed once.
#[derive(Clone, Debug)]
pub enum FailureScript {
    RateLimit {
        retry_after: u64,
    },
    Server {
        status: u16,
    },
    BadRequest {
        error_code: i64,
        description: String,
    },
}

#[derive(Clone, Default)]
pub struct FixtureState {
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
    pub updates: Arc<Mutex<VecDeque<Value>>>,
    pub failures: Arc<Mutex<HashMap<String, VecDeque<FailureScript>>>>,
    pub next_message_id: Arc<AtomicI64>,
    /// Bot tokens seen on the `/bot{token}/{method}` path (the fixture
    /// verifies every request carries the token path).
    pub tokens: Arc<Mutex<Vec<String>>>,
    /// When set, every Bot API method responds with a large chunked body
    /// (used to exercise the client's bounded response cap).
    pub huge_chunked: Arc<std::sync::atomic::AtomicBool>,
    /// One-shot deterministic delivery barrier: the first `sendMessage`
    /// whose text starts with the armed prefix is held at the fixture (the
    /// request is recorded, the response is delayed) until the paired
    /// oneshot sender is released. Tests use this to interleave reset
    /// epochs with in-flight renderer sends without wall-clock races.
    pub hold_first_send_matching: Arc<Mutex<Option<SendHold>>>,
}

/// One armed send hold: the prefix to match and the release receiver.
type SendHold = (String, tokio::sync::oneshot::Receiver<()>);

/// Arms the one-shot send barrier; returns the release handle.
fn hold_first_send(state: &FixtureState, prefix: &str) -> tokio::sync::oneshot::Sender<()> {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    *state.hold_first_send_matching.lock().expect("hold lock") =
        Some((prefix.to_string(), release_rx));
    release_tx
}

impl FixtureState {
    pub fn request_count(&self, method: &str) -> usize {
        self.requests
            .lock()
            .expect("requests lock")
            .iter()
            .filter(|request| request.method == method)
            .count()
    }

    pub fn last_body(&self, method: &str) -> Value {
        self.requests
            .lock()
            .expect("requests lock")
            .iter()
            .rev()
            .find(|request| request.method == method)
            .map(|request| request.body.clone())
            .unwrap_or(Value::Null)
    }

    pub fn sent_texts(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("requests lock")
            .iter()
            .filter(|request| request.method == "sendMessage")
            .filter_map(|request| request.body.get("text").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect()
    }

    pub fn edit_texts(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("requests lock")
            .iter()
            .filter(|request| request.method == "editMessageText")
            .filter_map(|request| request.body.get("text").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect()
    }

    /// Scripts failures for `method` (consumed FIFO).
    pub fn script_failures(&self, method: &str, failures: Vec<FailureScript>) {
        self.failures
            .lock()
            .expect("failures lock")
            .insert(method.to_string(), VecDeque::from(failures));
    }
}

fn fixture_ok_result(result: Value) -> axum::response::Response {
    Json(json!({ "ok": true, "result": result })).into_response()
}

async fn bot_api_handler(
    State(state): State<FixtureState>,
    Path((token, method)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    body: String,
) -> axum::response::Response {
    state
        .tokens
        .lock()
        .expect("tokens lock")
        .push(token.clone());
    if state.huge_chunked.load(Ordering::SeqCst) {
        // A bounded-but-oversized chunked body: 256 × 1 KiB. The client
        // must abort at its cap; the fixture must survive the abort.
        let chunks = futures_util::stream::repeat_with(|| {
            Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b'x'; 1024]))
        })
        .take(256);
        return axum::response::Response::new(axum::body::Body::from_stream(chunks));
    }
    let parsed: Value = if body.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).unwrap_or(Value::Null)
    };
    state
        .requests
        .lock()
        .expect("requests lock")
        .push(RecordedRequest {
            method: method.clone(),
            query,
            body: parsed.clone(),
        });
    // Consume one scripted failure for this method, if any (FIFO).
    let failure = state
        .failures
        .lock()
        .expect("failures lock")
        .get_mut(&method)
        .and_then(|queue| queue.pop_front());
    if let Some(failure) = failure {
        return match failure {
            FailureScript::RateLimit { retry_after } => (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "ok": false,
                    "error_code": 429,
                    "description": "Too Many Requests: retry after",
                    "parameters": { "retry_after": retry_after },
                })),
            )
                .into_response(),
            FailureScript::Server { status } => {
                let code = axum::http::StatusCode::from_u16(status)
                    .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                (code, "fixture server error").into_response()
            }
            FailureScript::BadRequest {
                error_code,
                description,
            } => (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error_code": error_code, "description": description })),
            )
                .into_response(),
        };
    }
    match method.as_str() {
        "getMe" => {
            let fixture: Value = serde_json::from_str(include_str!(
                "fixtures/telegram/get_me.json"
            ))
            .expect("get_me fixture");
            Json(fixture).into_response()
        }
        "getUpdates" => {
            let next = state.updates.lock().expect("updates lock").pop_front();
            match next {
                Some(result) => Json(result).into_response(),
                None => fixture_ok_result(json!([])),
            }
        }
        "sendMessage" | "editMessageText" => {
            let message_id = state.next_message_id.fetch_add(1, Ordering::SeqCst) + 1;
            // One-shot deterministic barrier: the first sendMessage whose
            // text starts with the armed prefix waits for the test's
            // release before the response is written (the request itself is
            // already recorded above).
            if method == "sendMessage" {
                let hold = {
                    let mut holds = state
                        .hold_first_send_matching
                        .lock()
                        .expect("hold lock");
                    let text = parsed
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    match holds.as_ref() {
                        Some((prefix, _)) if text.starts_with(prefix) => holds.take(),
                        _ => None,
                    }
                };
                if let Some((_prefix, receiver)) = hold {
                    let _ = receiver.await;
                }
            }
            fixture_ok_result(json!({
                "message_id": message_id,
                "date": 1700000000,
                "chat": { "id": 555, "type": "private" },
                "text": parsed.get("text").cloned().unwrap_or(Value::Null),
            }))
        }
        other => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error_code": 404, "description": format!("unknown method {other}") })),
        )
            .into_response(),
    }
}

/// Spawns the fixture Bot API server on an ephemeral local port.
async fn spawn_fixture() -> (String, FixtureState) {
    let state = FixtureState::default();
    let app = Router::new()
        .route("/bot{token}/{method}", post(bot_api_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("fixture listener should bind");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("fixture server");
    });
    (format!("http://{address}"), state)
}

/// Loads one fixture JSON file from `tests/fixtures/telegram` (paths are
/// relative to this test source file).
fn fixture_json(name: &str) -> Value {
    serde_json::from_str(match name {
        "updates_dm.json" => include_str!("fixtures/telegram/updates_dm.json"),
        "updates_group_topic.json" => include_str!("fixtures/telegram/updates_group_topic.json"),
        "updates_group_general.json" => {
            include_str!("fixtures/telegram/updates_group_general.json")
        }
        "updates_denied.json" => include_str!("fixtures/telegram/updates_denied.json"),
        "updates_duplicate.json" => include_str!("fixtures/telegram/updates_duplicate.json"),
        "updates_commands.json" => include_str!("fixtures/telegram/updates_commands.json"),
        other => panic!("unknown fixture {other}"),
    })
    .expect("fixture JSON should parse")
}

fn test_config(api_base: &str) -> TelegramConfig {
    TelegramConfig {
        bot_token: "123456:TEST-SECRET-TOKEN".to_string(),
        api_base: api_base.to_string(),
        // Integration tests compile without cfg(test); the explicit escape
        // hatch permits the local http fixture base.
        allow_insecure_localhost: true,
        poll_timeout: std::time::Duration::from_secs(5),
        poll_interval: std::time::Duration::from_millis(20),
        max_429_retries: 2,
        max_429_backoff: std::time::Duration::from_secs(1),
        max_5xx_retries: 2,
        max_edit_interval: std::time::Duration::ZERO,
        max_response_body_bytes: 1024 * 1024,
        new_wait_timeout: std::time::Duration::from_secs(10),
        // Existing tests queue updates before spawning and expect them to
        // be processed; the drop-pending default is covered by its own
        // tests and the config default.
        drop_pending_updates: false,
        unauthorized_failure_bound: 3,
        dedup_capacity: 64,
        allowed_accounts: vec!["fixture_bot".to_string()],
        allowed_chats: vec![555, -1001234],
        allowed_users: vec![555],
    }
}

#[tokio::test]
async fn client_get_me_and_send_message_reach_the_fixture() {
    let (base, state) = spawn_fixture().await;
    let api = TelegramApi::new(&test_config(&base));
    let me = api.get_me().await.expect("getMe should succeed");
    assert_eq!(me.username.as_deref(), Some("fixture_bot"));
    assert_eq!(me.id, 1001);

    let message = api
        .send_message(555, None, "hello from the bot")
        .await
        .expect("sendMessage should succeed");
    assert!(message.message_id > 0);
    assert_eq!(state.request_count("sendMessage"), 1);
    let body = state.last_body("sendMessage");
    assert_eq!(body["chat_id"], 555);
    assert_eq!(body["text"], "hello from the bot");
    assert!(body.get("message_thread_id").is_none());
}

#[tokio::test]
async fn client_get_updates_sends_long_poll_parameters_and_parses_messages() {
    let (base, state) = spawn_fixture().await;
    state
        .updates
        .lock()
        .expect("updates lock")
        .push_back(fixture_json("updates_dm.json"));
    let api = TelegramApi::new(&test_config(&base));
    let updates = api
        .get_updates(Some(41), 30, 50)
        .await
        .expect("getUpdates should succeed");
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].update_id, 11);
    let message = updates[0].message.as_ref().expect("message update");
    assert_eq!(message.chat.id, 555);
    assert_eq!(message.chat.chat_type, "private");
    assert_eq!(message.from.as_ref().expect("sender").id, 555);
    assert_eq!(message.text.as_deref(), Some("hello"));

    let body = state.last_body("getUpdates");
    assert_eq!(body["offset"], 41);
    assert_eq!(body["timeout"], 30);
    assert_eq!(body["limit"], 50);
    assert_eq!(body["allowed_updates"], json!(["message"]));
}

#[tokio::test]
async fn client_429_is_retried_with_bounded_backoff_then_succeeds() {
    let (base, state) = spawn_fixture().await;
    state.script_failures(
        "sendMessage",
        vec![
            FailureScript::RateLimit { retry_after: 1 },
            FailureScript::RateLimit { retry_after: 1 },
        ],
    );
    let api = TelegramApi::new(&test_config(&base));
    let started = std::time::Instant::now();
    api.send_message(555, None, "after rate limit")
        .await
        .expect("the third attempt must succeed");
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(1),
        "the retry must honor retry_after"
    );
    assert_eq!(
        state.request_count("sendMessage"),
        3,
        "two rate-limited attempts then one success"
    );
}

#[tokio::test]
async fn client_429_exhaustion_returns_a_typed_rate_limited_error() {
    let (base, state) = spawn_fixture().await;
    state.script_failures(
        "sendMessage",
        vec![
            FailureScript::RateLimit { retry_after: 1 },
            FailureScript::RateLimit { retry_after: 1 },
            FailureScript::RateLimit { retry_after: 1 },
            FailureScript::RateLimit { retry_after: 1 },
        ],
    );
    let api = TelegramApi::new(&test_config(&base));
    let error = api
        .send_message(555, None, "never sent")
        .await
        .expect_err("the retry budget must be bounded");
    assert!(
        matches!(error, TelegramError::RateLimited { retry_after: 1 }),
        "exhausted retries must surface the typed rate-limit error: {error:?}"
    );
    assert_eq!(
        state.request_count("sendMessage"),
        3,
        "max_429_retries=2 allows at most three attempts"
    );
}

#[tokio::test]
async fn client_5xx_is_retried_a_limited_number_of_times() {
    let (base, state) = spawn_fixture().await;
    state.script_failures(
        "sendMessage",
        vec![
            FailureScript::Server { status: 500 },
            FailureScript::Server { status: 502 },
            FailureScript::Server { status: 503 },
            FailureScript::Server { status: 500 },
        ],
    );
    let api = TelegramApi::new(&test_config(&base));
    let error = api
        .send_message(555, None, "server trouble")
        .await
        .expect_err("5xx retries must be bounded");
    assert!(
        matches!(error, TelegramError::Server { status: 503 }),
        "the surfaced error is the final attempt's typed server error: {error:?}"
    );
    assert_eq!(
        state.request_count("sendMessage"),
        3,
        "max_5xx_retries=2 allows at most three attempts"
    );
}

#[tokio::test]
async fn client_other_4xx_is_typed_and_not_retried() {
    let (base, state) = spawn_fixture().await;
    state.script_failures(
        "sendMessage",
        vec![
            FailureScript::BadRequest {
                error_code: 400,
                description: "Bad Request: chat not found".to_string(),
            },
            FailureScript::BadRequest {
                error_code: 400,
                description: "Bad Request: chat not found".to_string(),
            },
        ],
    );
    let api = TelegramApi::new(&test_config(&base));
    let error = api
        .send_message(999, None, "unknown chat")
        .await
        .expect_err("4xx must fail without retrying");
    match error {
        TelegramError::Api {
            error_code,
            description,
        } => {
            assert_eq!(error_code, 400);
            assert!(description.contains("chat not found"));
        }
        other => panic!("expected a typed API error, got {other:?}"),
    }
    assert_eq!(
        state.request_count("sendMessage"),
        1,
        "non-429 4xx errors must not be retried"
    );
}

#[tokio::test]
async fn client_response_over_the_body_cap_is_a_typed_error_and_the_fixture_survives() {
    let (base, state) = spawn_fixture().await;
    state.huge_chunked.store(true, Ordering::SeqCst);
    let config = TelegramConfig {
        max_response_body_bytes: 1024,
        ..test_config(&base)
    };
    let api = TelegramApi::new(&config);
    let error = api
        .get_updates(None, 5, 50)
        .await
        .expect_err("the chunked body exceeds the cap");
    assert!(
        matches!(error, TelegramError::ResponseTooLarge { limit: 1024 }),
        "over-limit bodies must be a typed response-too-large failure: {error:?}"
    );
    // The fixture must have seen the token path even for the aborted
    // request, and must keep serving after the client abort (panic-safe).
    assert!(
        state
            .tokens
            .lock()
            .expect("tokens lock")
            .iter()
            .any(|token| token == "123456:TEST-SECRET-TOKEN"),
        "every request must carry the /bot<token>/<method> path"
    );
    state.huge_chunked.store(false, Ordering::SeqCst);
    let me = api
        .get_me()
        .await
        .expect("the fixture must keep serving after the client abort");
    assert_eq!(me.username.as_deref(), Some("fixture_bot"));
}

#[tokio::test]
async fn client_requests_carry_the_bot_token_path() {
    let (base, state) = spawn_fixture().await;
    let api = TelegramApi::new(&test_config(&base));
    api.get_me().await.expect("getMe should succeed");
    api.send_message(555, None, "token path check")
        .await
        .expect("sendMessage should succeed");
    let tokens = state.tokens.lock().expect("tokens lock");
    assert!(
        !tokens.is_empty(),
        "the fixture must have observed at least one request"
    );
    for token in tokens.iter() {
        assert_eq!(
            token, "123456:TEST-SECRET-TOKEN",
            "every request must hit the /bot<token>/<method> path"
        );
    }
    // The token must never leak into the query string: the api_base
    // validation rejects query-bearing bases and the client builds the URL
    // with the token only in the path segment.
    let requests = state.requests.lock().expect("requests lock");
    for request in requests.iter() {
        for (key, value) in request.query.iter() {
            assert!(
                !key.contains("TEST-SECRET-TOKEN") && !value.contains("TEST-SECRET-TOKEN"),
                "the bot token must never appear in a query parameter: {key}={value}"
            );
        }
    }
}

#[tokio::test]
async fn client_https_api_base_is_handled_by_a_tls_connector() {
    // A plain-text listener proves the https scheme is routed into a real
    // TLS handshake: the client must speak a TLS ClientHello, never a
    // plaintext HTTP request (an http-only connector would reject the
    // https URL or send plaintext bytes).
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("fixture listener should bind");
    let address = listener.local_addr().expect("fixture address");
    let (greeting_tx, greeting_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.expect("accept fixture request");
        let mut head = [0_u8; 5];
        let read = stream.read(&mut head).await.unwrap_or(0);
        let _ = greeting_tx.send((head, read));
        // Answer with non-TLS bytes so the handshake fails fast.
        let _ = stream.write_all(b"this is not a TLS server\r\n").await;
        let _ = stream.shutdown().await;
    });
    let config = TelegramConfig {
        api_base: format!("https://{address}"),
        ..test_config("http://127.0.0.1:1")
    };
    let api = TelegramApi::new(&config);
    let error = api
        .get_me()
        .await
        .expect_err("the TLS handshake must fail against a plain-text server");
    assert!(
        matches!(error, TelegramError::Transport(_)),
        "https failure must be a typed transport failure: {error:?}"
    );
    assert!(
        format!("{error}").contains("TLS") || format!("{error}").contains("corrupt"),
        "the transport error should surface the TLS handshake reason: {error}"
    );
    let (head, read) = tokio::time::timeout(std::time::Duration::from_secs(5), greeting_rx)
        .await
        .expect("the connector must attempt a connection for https")
        .expect("greeting channel");
    assert_eq!(
        read, 5,
        "the client must send its handshake promptly, got {read} bytes"
    );
    assert_eq!(
        &head[..3],
        &[0x16, 0x03, 0x01],
        "the first bytes must be a TLS ClientHello record (0x16 0x03 0x01), got {head:02x?}"
    );
}

#[test]
fn telegram_config_debug_redacts_the_bot_token() {
    let config = test_config("http://127.0.0.1:1");
    let debug = format!("{config:?}");
    assert!(
        !debug.contains("TEST-SECRET-TOKEN"),
        "Debug output must never contain the bot token: {debug}"
    );
    assert!(
        debug.contains("REDACTED"),
        "Debug output must mark the token"
    );
}

#[test]
fn api_base_http_is_rejected_outside_localhost_without_the_escape_hatch() {
    // Integration tests compile without cfg(test), so the escape must be
    // explicit: the token is never sent over cleartext in production.
    let remote = TelegramConfig {
        api_base: "http://telegram.example.com".to_string(),
        allow_insecure_localhost: false,
        ..test_config("http://127.0.0.1:1")
    };
    assert!(
        remote.validate().is_err(),
        "a non-localhost http api_base must be rejected"
    );
    let localhost = TelegramConfig {
        api_base: "http://127.0.0.1:1".to_string(),
        allow_insecure_localhost: false,
        ..test_config("http://127.0.0.1:1")
    };
    assert!(
        localhost.validate().is_err(),
        "localhost http requires the explicit escape hatch"
    );
    let escaped = TelegramConfig {
        api_base: "http://127.0.0.1:1".to_string(),
        allow_insecure_localhost: true,
        ..test_config("http://127.0.0.1:1")
    };
    escaped
        .validate()
        .expect("the explicit escape hatch permits localhost http");
    let production = TelegramConfig {
        api_base: "https://api.telegram.org".to_string(),
        allow_insecure_localhost: false,
        ..test_config("http://127.0.0.1:1")
    };
    production
        .validate()
        .expect("the production https base must validate");
}

// ---------------------------------------------------------------------------
// Adapter integration tests (fixture server, no real Telegram).
// ---------------------------------------------------------------------------

use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app,
    gateway::telegram::{TelegramAdapter, spawn_telegram_adapter},
    gateway::utf16_len,
};
use uuid::Uuid;

/// Base directory for this suite's temporary artifacts. Honors
/// `RUSTSCRIPT_AGENT_TEST_TMP` (CI sets it to a runner-local directory and
/// this suite owns the unique `telegram-tests` subdir there); without it,
/// development state stays under /mnt/TEMP/rustscript (workspace rule).
fn telegram_test_root() -> std::path::PathBuf {
    std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/mnt/TEMP/rustscript"))
        .join("telegram-tests")
}

/// Temporary gateway SQLite path (a fresh unique name per call, so parallel
/// tests can never collide).
fn telegram_db_path(label: &str) -> std::path::PathBuf {
    telegram_db_path_in(&telegram_test_root(), label)
}

/// The path builder itself: the base directory is explicit so the unit test
/// below pins the layout without touching the process-global env var
/// (parallel tests must never set it).
fn telegram_db_path_in(root: &std::path::Path, label: &str) -> std::path::PathBuf {
    std::fs::create_dir_all(root).expect("telegram test root should be created");
    root.join(format!("{label}-{}.db", Uuid::new_v4()))
}

#[test]
fn telegram_test_artifacts_land_under_an_explicit_root() {
    let base = std::env::temp_dir().join(format!("telegram-root-{}", Uuid::new_v4()));
    let db = telegram_db_path_in(&base, "layout");
    assert!(
        db.starts_with(&base),
        "the database must live under the explicit root, got {db:?}"
    );
    assert_eq!(db.parent(), Some(base.as_path()));
    assert!(
        db.file_name()
            .expect("db file name")
            .to_string_lossy()
            .starts_with("layout-"),
        "the label must prefix the unique file name"
    );
    std::fs::remove_dir_all(&base).expect("temporary root should be removed");
}

/// Polls until `condition` holds, panicking after the timeout.
async fn wait_until(timeout: std::time::Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if condition() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition was not met within {timeout:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// One raw HTTP GET over a plain TCP stream (no HTTP client dependency).
async fn http_get(host_port: &str, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(host_port)
        .await
        .expect("connect to the gateway");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

fn push_update(state: &FixtureState, fixture: Value) {
    state
        .updates
        .lock()
        .expect("updates lock")
        .push_back(fixture);
}

/// Last `getUpdates` offset the fixture saw, if any.
fn last_poll_offset(state: &FixtureState) -> Option<i64> {
    state
        .last_body("getUpdates")
        .get("offset")
        .and_then(Value::as_i64)
}

fn test_state(
    source: &str,
    db_path: &std::path::Path,
    overrides: impl FnOnce(AgentGatewayConfig) -> AgentGatewayConfig,
) -> AgentGatewayState {
    let config = overrides(AgentGatewayConfig::default());
    AgentGatewayState::with_agent_source_and_sqlite(config, source, db_path)
        .expect("SQLite state should open")
}

async fn spawn_adapter(state: AgentGatewayState, config: TelegramConfig) -> TelegramAdapter {
    spawn_telegram_adapter(state, config)
        .await
        .expect("telegram adapter should spawn")
}

const ECHO_SOURCE: &str = r#"
use stream;
pub fn run(input: map) -> string {
    stream::emit({"type": "model.delta", "delta": "hello world"});
    "ok";
}
"#;

#[tokio::test]
async fn adapter_denies_everything_by_default_and_advances_the_offset() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("deny-default");
    let config = TelegramConfig {
        bot_token: "123456:TEST-SECRET-TOKEN".to_string(),
        api_base: base.clone(),
        // Empty allowlists: deny-by-default.
        allowed_accounts: vec![],
        allowed_chats: vec![],
        allowed_users: vec![],
        ..test_config(&base)
    };
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), config).await;
    wait_until(std::time::Duration::from_secs(15), || {
        adapter.processed_updates() >= 1
    })
    .await;
    // The update was denied: no reply, no session, but the offset advanced
    // so the update is never re-fetched.
    assert_eq!(
        state.request_count("sendMessage"),
        0,
        "denied updates must not produce replies"
    );
    let persistence = gateway.persistence().expect("persistence");
    let session = persistence
        .session_get("telegram:fixture_bot:555:")
        .expect("session read");
    assert_eq!(
        session["rows"].as_array().map(Vec::len),
        Some(0),
        "denied updates must not create sessions"
    );
    wait_until(std::time::Duration::from_secs(15), || {
        last_poll_offset(&state) == Some(12)
    })
    .await;
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_maps_dm_group_and_topic_to_stable_sessions() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    push_update(&state, fixture_json("updates_group_topic.json"));
    push_update(&state, fixture_json("updates_group_general.json"));
    let db = telegram_db_path("envelope");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        adapter.processed_updates() >= 3
    })
    .await;
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .filter(|text| *text == "[done]")
            .count()
            >= 3
    })
    .await;
    let persistence = gateway.persistence().expect("persistence");
    for (session_id, chat_id, thread_id) in [
        ("telegram:fixture_bot:555:", "555", ""),
        ("telegram:fixture_bot:-1001234:7", "-1001234", "7"),
        ("telegram:fixture_bot:-1001234:", "-1001234", ""),
    ] {
        let session = persistence.session_get(session_id).expect("session read");
        let row = &session["rows"][0];
        assert_eq!(row[2], json!("telegram"), "platform for {session_id}");
        assert_eq!(row[3], json!("fixture_bot"), "account for {session_id}");
        assert_eq!(row[4], json!(chat_id), "chat id for {session_id}");
        assert_eq!(row[5], json!(thread_id), "thread id for {session_id}");
    }
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_deduplicates_duplicate_updates_and_messages() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_duplicate.json"));
    let db = telegram_db_path("dedup");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        adapter.processed_updates() >= 2
    })
    .await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let sends = state.sent_texts();
    assert_eq!(
        sends.iter().filter(|text| *text == "hello world").count(),
        1,
        "the duplicated message must admit exactly one run: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        1,
        "one run must render one terminal line: {sends:?}"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_commands_new_status_compact_respond_explicitly() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_commands.json"));
    let db = telegram_db_path("commands");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        adapter.processed_updates() >= 3
    })
    .await;
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("New conversation started"))
    })
    .await;
    let sends = state.sent_texts();
    assert!(
        sends
            .iter()
            .any(|text| text.starts_with("Session telegram:fixture_bot:555:")
                && text.contains("no runs yet")),
        "/status must describe the fresh session: {sends:?}"
    );
    let compact = sends
        .iter()
        .find(|text| text.contains("nothing to compact"))
        .expect("/compact must reply");
    assert!(
        compact.contains("nothing to compact"),
        "/compact must answer with the typed no-run state, got: {compact}"
    );
    assert!(
        !compact.contains("completed"),
        "/compact must not advertise itself as done: {compact}"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

const EVENTS_SOURCE: &str = r#"
use stream;
pub fn run(input: map) -> string {
    stream::emit({"type": "model.delta", "delta": "Hel"});
    stream::emit({"type": "model.delta", "delta": "lo"});
    stream::emit({"type": "tool.requested", "tool_call": {"id": "t1", "name": "web_search"}});
    stream::emit({"type": "approval.required", "tool_call": {"id": "t1", "name": "web_search"}, "approval_id": "a1"});
    stream::emit({"type": "approval.resolved", "tool_call": {"id": "t1", "name": "web_search"}, "state": "approved"});
    "Hello world!";
}
"#;

#[tokio::test]
async fn adapter_renders_delta_edits_and_status_lines_from_agent_events() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("render");
    let gateway = test_state(EVENTS_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    let sends = state.sent_texts();
    assert_eq!(
        sends.first().map(String::as_str),
        Some("Hel"),
        "the first delta opens the message: {sends:?}"
    );
    assert_eq!(
        state.edit_texts(),
        vec![
            "Hello".to_string(),
            // The worker's Complete value is rendered as JSON text, so the
            // output string carries its JSON quotes.
            "\"Hello world!\"".to_string()
        ],
        "later deltas edit the same message and the terminal delta finalizes"
    );
    for expected in [
        "[tool] web_search requested",
        "[approval] web_search requires approval (pending) — /approve a1 or /deny a1",
        "[approval] web_search: approved",
        "[done]",
    ] {
        assert!(
            sends.iter().any(|text| text == expected),
            "missing render {expected:?} in {sends:?}"
        );
    }
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_status_sends_never_rewrite_the_delta_edit_target() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("edit-target");
    let gateway = test_state(EVENTS_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    // The opening delta is the first sendMessage, so the fixture returns
    // message id 1 for it; every editMessageText must keep targeting that
    // delta message even though tool/approval/terminal status lines were
    // sent in between (those sends return ids 2, 3, ... and must never
    // become the edit target).
    // Snapshot under the lock and drop the guard: the adapter keeps
    // talking to the fixture, which needs the same lock.
    let requests = state.requests.lock().expect("requests lock").clone();
    let mut edit_targets = Vec::new();
    for request in requests.iter() {
        if request.method == "editMessageText" {
            edit_targets.push(
                request
                    .body
                    .get("message_id")
                    .and_then(Value::as_i64)
                    .unwrap_or(-1),
            );
        }
    }
    assert!(
        !edit_targets.is_empty(),
        "the interleaved run must produce edits"
    );
    for target in edit_targets {
        assert_eq!(
            target, 1,
            "every edit must target the delta message, never a status line"
        );
    }
    let sends = state.sent_texts();
    assert!(
        sends
            .iter()
            .any(|text| text == "[tool] web_search requested")
            && sends.iter().any(|text| text
                == "[approval] web_search requires approval (pending) — /approve a1 or /deny a1")
            && sends
                .iter()
                .any(|text| text == "[approval] web_search: approved")
            && sends.iter().any(|text| text == "[done]"),
        "the status lines must still be delivered as separate sends: {sends:?}"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_chunks_oversized_output_at_4096_utf16() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let big = "x".repeat(9000);
    let source = format!(
        r#"
        use stream;
        pub fn run(input: map) -> string {{
            stream::emit({{"type": "model.delta", "delta": "{big}"}});
            "ok";
        }}
        "#
    );
    let db = telegram_db_path("chunk");
    let gateway = test_state(&source, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    let sends = state.sent_texts();
    let edits = state.edit_texts();
    for text in sends.iter().chain(edits.iter()) {
        assert!(
            utf16_len(text) <= 4096,
            "every sent/edited text must fit Telegram's cap: {} units",
            utf16_len(text)
        );
    }
    assert_eq!(
        sends
            .iter()
            .filter(|text| *text != "[done]")
            .map(String::as_str)
            .collect::<String>()
            .len(),
        9000,
        "the delta must be delivered losslessly across chunks"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_persists_offset_and_cursor_across_restart_without_duplicates() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("restart");

    // Phase 1: one message, one run, fully rendered.
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    wait_until(std::time::Duration::from_secs(15), || {
        last_poll_offset(&state) == Some(12)
    })
    .await;
    adapter.shutdown().await;
    drop(gateway);
    let sends_after_phase1 = state.sent_texts().len();

    // Phase 2: a fresh gateway on the same durable state. The poller must
    // resume at offset 12 (no re-fetch) and the renderer cursor must be at
    // the run's high-water (no duplicate delivery).
    let restored = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter2 = spawn_adapter(restored.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        last_poll_offset(&state) == Some(12) && state.request_count("getUpdates") >= 3
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        state.sent_texts().len(),
        sends_after_phase1,
        "restart must not re-deliver rendered output: {:?}",
        state.sent_texts()
    );
    adapter2.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

/// Holding fixture: accepts one HTTP request and parks the response until
/// the test releases it (the same pattern as the gateway restart tests).
fn spawn_holding_fixture() -> (
    u16,
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read fixture request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = arrived_tx.send(());
        release_rx.recv().expect("wait for release");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nagent-ok")
            .expect("write fixture response");
    });
    (port, arrived_rx, release_tx, handle)
}

fn holding_config(port: u16) -> AgentGatewayConfig {
    let http = rustscript_vm::HttpConfig {
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_schemes: vec!["http".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
    AgentGatewayConfig {
        http,
        ..AgentGatewayConfig::default()
    }
}

fn holding_config_and_source(port: u16) -> (AgentGatewayConfig, String) {
    let source = format!(
        r#"
        use http;
        use stream;
        pub fn run(input: map) -> string {{
            stream::emit({{"type": "model.delta", "delta": "before"}});
            http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
            "done";
        }}
        "#
    );
    (holding_config(port), source)
}

/// Source whose runs echo the input text and park in a holding HTTP call
/// only for the `second` message, so a later run on the same gateway can
/// complete on its own.
fn park_on_second_source(port: u16) -> String {
    format!(
        r#"
        use http;
        use stream;
        pub fn run(input: map) -> string {{
            let text: string = input["input"];
            stream::emit({{"type": "model.delta", "delta": text}});
            if text == "second" {{
                http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
            }}
            "ok";
        }}
        "#
    )
}

/// Source that emits one >2×4096-UTF-16 delta, so the renderer splits it
/// into three send chunks: `A`×4096, `B`×4096, and a trailing `BC`.
fn chunked_delta_source() -> String {
    let delta = format!("{}B{}C", "A".repeat(4096), "B".repeat(4096));
    format!(
        r#"
        use stream;
        pub fn run(input: map) -> string {{
            stream::emit({{"type": "model.delta", "delta": "{delta}"}});
            "ok";
        }}
        "#
    )
}

/// Source that parks the first run (input `start`) in a pure CPU loop; a
/// later run on the same gateway completes on its own. The CPU loop is
/// interrupted by `/new`'s typed cancellation (epoch watcher), so the
/// cancel path is real: nothing external releases the run.
const CANCEL_ON_START_SOURCE: &str = r#"
use stream;
pub fn run(input: map) -> string {
    let text: string = input["input"];
    stream::emit({"type": "model.delta", "delta": "before"});
    if text == "start" {
        while true {
            1;
        }
    }
    "ok";
}
"#;

#[tokio::test]
async fn adapter_resumes_undelivered_events_after_restart() {
    let (base, state) = spawn_fixture().await;
    // Deterministic delivery barrier: the phase-1 renderer's first send is
    // held at the fixture, so the run's terminal commits durably while the
    // delivery cursor still lags behind it. No wall-clock HTTP timeout is
    // involved anywhere in this test.
    let release = hold_first_send(&state, "hello world");
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("resume");

    // Phase 1: the run completes durably (terminal events retained) but the
    // renderer is blocked before its first send, so the cursor never
    // advances and the terminal is genuinely undelivered at shutdown.
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        // The blocked request is recorded on arrival, so this is the
        // deterministic signal that the barrier is armed.
        state.sent_texts().iter().any(|text| text == "hello world")
    })
    .await;
    // Deterministic sync on the durable terminal: the assistant message is
    // committed atomically with run.completed (the session's last_message_seq
    // advances past zero only at that commit).
    let persistence = gateway.persistence().expect("persistence");
    wait_until(std::time::Duration::from_secs(15), || {
        persistence
            .session_get("telegram:fixture_bot:555:")
            .map(|session| {
                session["rows"]
                    .as_array()
                    .and_then(|rows| rows.first())
                    .and_then(|row| row.get(14))
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    > 0
            })
            .unwrap_or(false)
    })
    .await;
    adapter.shutdown().await;
    drop(gateway);

    // Phase 2: the same durable state resumes. The undelivered terminal is
    // rendered by the restart catch-up (cursor < retained high-water), and
    // the session gate is released once the resumed renderer ends.
    let restored = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter2 = spawn_adapter(restored.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    // The resumed catch-up re-delivers the undelivered delta exactly once:
    // the phase-1 attempt was held (recorded at arrival) and never
    // completed, so the wire log shows it twice ("hello world" attempts)
    // while the terminal is delivered exactly once.
    let sends = state.sent_texts();
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        1,
        "the resumed terminal must be delivered exactly once: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "hello world").count(),
        2,
        "the undelivered delta must be re-sent exactly once: {sends:?}"
    );
    // The resume renderer's final flush is the last action before its gate
    // release; wait for it so the new message below is provably admitted
    // after the gate is free (the terminal flush edits the final message).
    wait_until(std::time::Duration::from_secs(15), || {
        !state.edit_texts().is_empty()
    })
    .await;
    // The gate is released: a new message is admitted and completes.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 30,
                "message": {
                    "message_id": 300,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "after restart"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(20), || {
        state
            .sent_texts()
            .iter()
            .filter(|text| *text == "[done]")
            .count()
            >= 2
    })
    .await;
    let sends = state.sent_texts();
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        2,
        "the new run must complete: {sends:?}"
    );
    assert!(
        !sends.iter().any(|text| text.contains("already active")),
        "the gate must be released before the new message arrives: {sends:?}"
    );
    adapter2.shutdown().await;
    drop(release);
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_resume_releases_the_gate_so_new_messages_are_admitted() {
    let (base, state) = spawn_fixture().await;
    let (port, _arrived, release_tx, holding) = spawn_holding_fixture();
    let (config, source) = holding_config_and_source(port);
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("resume-gate");

    // Phase 1: the run parks inside an HTTP call after one delta.
    let gateway = test_state(&source, &db, |_config| config.clone());
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "before")
    })
    .await;
    adapter.shutdown().await;
    drop(gateway);

    // Phase 2: the same durable state restarts. The recovered (terminal)
    // run's catch-up renderer must end as soon as it renders the terminal
    // event and release the session gate; only then does the new message
    // arrive, so it is admitted and completes without /new. The new run
    // uses a source that completes on its own (the holding fixture already
    // served its single connection to the phase-1 worker).
    let restored = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter2 = spawn_adapter(restored.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.starts_with("[failed]"))
    })
    .await;
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 30,
                "message": {
                    "message_id": 300,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "after restart"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(20), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    let sends = state.sent_texts();
    assert_eq!(
        sends.iter().filter(|text| *text == "hello world").count(),
        1,
        "the new message must be admitted after the resume released the gate: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        1,
        "the new run must complete: {sends:?}"
    );
    assert!(
        !sends.iter().any(|text| text.contains("already active")),
        "the gate must be released before the new message arrives: {sends:?}"
    );
    adapter2.shutdown().await;
    let _ = release_tx.send(());
    holding.join().expect("holding fixture");
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_new_cancels_and_waits_before_resetting_the_session() {
    let (base, state) = spawn_fixture().await;
    // Deterministic barrier: the cancelled run's terminal render ("[stopped]")
    // is held at the fixture, so the epoch bump provably happens while the
    // old renderer is mid-send. No 50ms polling race decides the ordering.
    let release = hold_first_send(&state, "[stopped]");
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 11,
                "message": {
                    "message_id": 101,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "start"
                }
            }]
        }),
    );
    let db = telegram_db_path("new-cancel");
    let gateway = test_state(CANCEL_ON_START_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    // The run parks in a pure CPU loop; /new's stop must interrupt it
    // through the epoch watcher — a real cancellation, because nothing
    // external ever releases the run.
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "before")
    })
    .await;
    // /new from the same chat: the active run must be cancelled and the
    // reset must wait for its terminal transition.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 20,
                "message": {
                    "message_id": 200,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "/new"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("Stopping the active run"))
    })
    .await;
    // The CPU loop is interrupted by the typed cancellation, the renderer
    // attempts the cancelled-run terminal render, and the barrier holds it
    // at the fixture (recorded on arrival).
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[stopped]")
    })
    .await;
    // The reset waits for the terminal transition, bumps the epoch, wipes
    // the session, and only then confirms.
    wait_until(std::time::Duration::from_secs(20), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("New conversation started"))
    })
    .await;
    let sends = state.sent_texts();
    let new_index = sends
        .iter()
        .position(|text| text.contains("New conversation started"))
        .expect("the /new confirmation must be present");
    // The old run's delta ("before") and its in-flight terminal render were
    // recorded before the confirmation; nothing from the old run may be
    // recorded after it.
    assert_eq!(
        sends.len(),
        new_index + 1,
        "the old renderer must not output anything after the reset: {sends:?}"
    );
    assert!(
        !sends.iter().any(|text| text == "[done]"),
        "the cancelled run must not complete: {sends:?}"
    );
    // The durable session is fresh: no messages.
    let persistence = gateway.persistence().expect("persistence");
    let session = persistence
        .session_get("telegram:fixture_bot:555:")
        .expect("session read");
    let rows = session["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1, "the recreated session must exist");
    assert!(
        rows[0][14].is_null() || rows[0][14] == json!(0),
        "the recreated session must have no messages: {}",
        rows[0][14]
    );
    // Release the held terminal render: the old renderer's flush must be
    // stopped by the stale epoch (no further old-run output), and the gate
    // released by /new lets the next message through to completion.
    drop(release);
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 30,
                "message": {
                    "message_id": 300,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "after reset"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(20), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    let sends = state.sent_texts();
    assert!(
        !sends.iter().any(|text| text.contains("already active")),
        "the gate must be released after /new: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "[stopped]").count(),
        1,
        "the cancelled run's terminal render stays a single in-flight send: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        1,
        "the post-reset run must complete exactly once: {sends:?}"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

/// P2-1 regression: `/new` while the old renderer is still draining must
/// not let the old renderer's late gate drop delete the NEW run's gate.
/// The old run's terminal send is held at the fixture across the reset, so
/// its GateGuard drops only after a new run is already gated.
#[tokio::test]
async fn adapter_new_late_old_renderer_drop_keeps_the_new_gate() {
    let (base, state) = spawn_fixture().await;
    let (port, _arrived, release_tx, holding) = spawn_holding_fixture();
    let source = park_on_second_source(port);
    // Hold the old run's terminal send ("[done]") so the old renderer stays
    // alive past the /new reset; its GateGuard drops only after we release.
    let release = hold_first_send(&state, "[done]");
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("new-gate");
    let gateway = test_state(&source, &db, |_config| holding_config(port));
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    // run1 ("hello"): delta sent, terminal "[done]" held at the fixture.
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    // /new: run1 is terminal, so the reset proceeds immediately (epoch
    // bump first, then the cascade delete and the confirmation).
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 20,
                "message": {
                    "message_id": 200,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "/new"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("New conversation started"))
    })
    .await;
    // A new run is admitted and gated; it parks in a holding HTTP call so
    // it stays active (the gate must remain held for the whole test).
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 30,
                "message": {
                    "message_id": 300,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "second"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "second")
    })
    .await;
    // While the old renderer is still alive (its terminal send held), the
    // third message must be rejected: the new run holds the gate.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 40,
                "message": {
                    "message_id": 400,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "third"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .filter(|text| text.contains("already active"))
            .count()
            >= 1
    })
    .await;
    // Release the old renderer's held send: its epoch is stale, so it stops
    // without further output, and its GateGuard drops. The compare-and-
    // remove must NOT touch the new run's gate entry.
    drop(release);
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 50,
                "message": {
                    "message_id": 500,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "fourth"
                }
            }]
        }),
    );
    // Deterministic wait on either outcome: the fix rejects the fourth
    // message (the new run's gate survived the late drop); the bug admits
    // it (its delta would be sent).
    wait_until(std::time::Duration::from_secs(20), || {
        state
            .sent_texts()
            .iter()
            .filter(|text| text.contains("already active"))
            .count()
            >= 2
            || state.sent_texts().iter().any(|text| text == "fourth")
    })
    .await;
    let sends = state.sent_texts();
    assert_eq!(
        sends
            .iter()
            .filter(|text| text.contains("already active"))
            .count(),
        2,
        "the third and fourth messages must be rejected while the new run is gated: {sends:?}"
    );
    assert!(
        !sends.iter().any(|text| text == "fourth"),
        "the fourth message must not be admitted while the new run is gated: {sends:?}"
    );
    // Release the parked run: it completes, its renderer ends and releases
    // the gate (compare-and-remove of its own run id).
    let _ = release_tx.send(());
    holding.join().expect("holding fixture");
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .filter(|text| *text == "[done]")
            .count()
            >= 2
    })
    .await;
    // With the gate released after the new run ended, the next message is
    // admitted and completes.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 60,
                "message": {
                    "message_id": 600,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "fifth"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(20), || {
        state
            .sent_texts()
            .iter()
            .filter(|text| *text == "[done]")
            .count()
            >= 3
    })
    .await;
    let sends = state.sent_texts();
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        3,
        "the run after the gate release must complete: {sends:?}"
    );
    assert!(
        sends.iter().any(|text| text == "fifth"),
        "the message after the gate release must be admitted: {sends:?}"
    );
    assert_eq!(
        sends
            .iter()
            .filter(|text| text.contains("already active"))
            .count(),
        2,
        "no further rejection after the gate release: {sends:?}"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

/// P3 TOCTOU regression: `/new` bumping the session epoch while a renderer
/// action is in flight must stop every SUBSEQUENT action of the old run.
/// The old run's delta splits into three sends; the middle one is held at
/// the fixture across the reset, so the trailing chunk can only be sent if
/// the epoch is not re-checked after the network returns.
#[tokio::test]
async fn adapter_new_epoch_bump_mid_send_stops_the_old_renderer() {
    let (base, state) = spawn_fixture().await;
    let source = chunked_delta_source();
    // The middle chunk (B×4096) of the old run's delta is held across the
    // reset; the trailing chunk ("C") is the observable TOCTOU probe.
    let release = hold_first_send(&state, "B");
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("new-epoch");
    let gateway = test_state(&source, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    // run1: the first chunk is delivered, the middle chunk is held.
    wait_until(std::time::Duration::from_secs(15), || {
        state.request_count("sendMessage") >= 2
    })
    .await;
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 20,
                "message": {
                    "message_id": 200,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "/new"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("New conversation started"))
    })
    .await;
    // The bump landed while the middle chunk was in flight; releasing it
    // lets the old renderer continue. With the per-action epoch re-check it
    // stops; without it, the trailing "BC" chunk is sent after the reset.
    drop(release);
    // A new run after the reset: its chunks and terminal are the positive
    // wait condition that provably follows the old renderer's continuation.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 30,
                "message": {
                    "message_id": 300,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "second"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(20), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    let sends = state.sent_texts();
    let confirmation = sends
        .iter()
        .position(|text| text.contains("New conversation started"))
        .expect("the /new confirmation must be present");
    assert_eq!(
        sends.iter().filter(|text| *text == "BC").count(),
        1,
        "only the post-reset run may send the trailing chunk: {sends:?}"
    );
    assert!(
        sends[confirmation + 1..]
            .iter()
            .all(|text| *text == "A".repeat(4096)
                || *text == "B".repeat(4096)
                || *text == "BC"
                || *text == "[done]"),
        "no old-run output may follow the /new confirmation: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        1,
        "only the post-reset run may complete: {sends:?}"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_new_wait_timeout_keeps_the_session_and_run() {
    let (base, state) = spawn_fixture().await;
    let db = telegram_db_path("new-timeout");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    // Create the telegram session through the public API surface, then
    // admit a run WITHOUT a worker: it never reaches terminal, so /new's
    // bounded wait must expire and leave the session and run intact.
    let app = rustscript_agent::build_agent_gateway_app(gateway.clone());
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/api/sessions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "session_id": "telegram:fixture_bot:555:",
                        "source": "telegram",
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    let status = response.status();
    assert!(
        status.is_success(),
        "session creation must succeed: {status}"
    );
    let admitted = gateway
        .service()
        .admit(AdmitRunRequest {
            input: json!("parked"),
            session_id: Some("telegram:fixture_bot:555:".to_string()),
            platform: "telegram".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admission must succeed");
    assert_eq!(admitted.status, "started");
    let mut telegram = test_config(&base);
    telegram.new_wait_timeout = std::time::Duration::from_millis(400);
    let adapter = spawn_adapter(gateway.clone(), telegram).await;
    // /new while the run never stops within the bound: the reset must fail
    // with a typed reply and delete nothing.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 20,
                "message": {
                    "message_id": 200,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "/new"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("Could not stop the active run"))
    })
    .await;
    assert!(
        !state
            .sent_texts()
            .iter()
            .any(|text| text.contains("New conversation started")),
        "a failed reset must not advertise a new conversation"
    );
    // The session and its run are untouched.
    let persistence = gateway.persistence().expect("persistence");
    let session = persistence
        .session_get("telegram:fixture_bot:555:")
        .expect("session read");
    assert_eq!(
        session["rows"].as_array().map(Vec::len),
        Some(1),
        "the session must survive a failed reset"
    );
    let run = persistence.run_get(&admitted.run_id).expect("run read");
    assert_eq!(
        run["rows"].as_array().map(Vec::len),
        Some(1),
        "the run must survive a failed reset"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_drops_pending_updates_on_first_boot_by_default() {
    let (base, state) = spawn_fixture().await;
    // Pending before the adapter starts (the bot was offline): the safe
    // default must not replay old updates into sessions.
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("drop-pending");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    // test_config opts out of the drop to keep queue-before-spawn tests
    // working; this test re-enables the safe first-boot default (the
    // config default itself is asserted by the unit test).
    let mut telegram = test_config(&base);
    telegram.drop_pending_updates = true;
    let adapter = spawn_adapter(gateway.clone(), telegram).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.request_count("getUpdates") >= 2
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        adapter.processed_updates(),
        0,
        "pending updates must be drained without processing on first boot"
    );
    assert_eq!(
        state.sent_texts().len(),
        0,
        "no pending update may produce output"
    );
    // A NEW message after boot is processed normally.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 30,
                "message": {
                    "message_id": 300,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "after boot"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        adapter.processed_updates() >= 1
    })
    .await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "hello world")
    })
    .await;
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_replays_pending_updates_when_drop_is_disabled() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("keep-pending");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let mut telegram = test_config(&base);
    telegram.drop_pending_updates = false;
    let adapter = spawn_adapter(gateway.clone(), telegram).await;
    wait_until(std::time::Duration::from_secs(15), || {
        adapter.processed_updates() >= 1
    })
    .await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "hello world")
    })
    .await;
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

/// P3 fail-closed drain: a drain round that fails is retried a bounded
/// number of times; once a round succeeds, the drained watermark is
/// persisted BEFORE anything is processed, so only updates that arrive
/// after the drain are ever admitted.
#[tokio::test]
async fn adapter_drop_pending_drain_retries_then_persists_before_processing() {
    let (base, state) = spawn_fixture().await;
    // The pending update is queued while the bot was offline; the first
    // drain round fails (the client exhausts its bounded 5xx budget) and
    // the drain's bounded retry succeeds.
    push_update(&state, fixture_json("updates_dm.json"));
    state.script_failures(
        "getUpdates",
        vec![
            FailureScript::Server { status: 500 },
            FailureScript::Server { status: 500 },
            FailureScript::Server { status: 500 },
        ],
    );
    let db = telegram_db_path("drop-pending-retry");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let mut telegram = test_config(&base);
    telegram.drop_pending_updates = true;
    let adapter = spawn_adapter(gateway.clone(), telegram).await;
    // Deterministic sync: the drain's five getUpdates calls (3 client
    // attempts on the failed round, the successful retry, and the empty
    // confirmation round) precede any processing. Only AFTER the drain is a
    // new update pushed, so it cannot be drained by mistake.
    wait_until(std::time::Duration::from_secs(20), || {
        state.request_count("getUpdates") >= 5
    })
    .await;
    // The pending update is drained without processing; only a NEW update
    // that arrives after the drain is admitted.
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 30,
                "message": {
                    "message_id": 300,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "after boot"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(20), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    let sends = state.sent_texts();
    assert_eq!(
        adapter.processed_updates(),
        1,
        "only the post-drain update may be processed"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "hello world").count(),
        1,
        "the drained pending update must never be rendered: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        1,
        "only the post-drain run completes: {sends:?}"
    );
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

/// P3 fail-closed drain: when every bounded retry fails, the adapter must
/// NOT fall through to the normal poll (no pending update may be admitted),
/// and its shutdown must not persist a zero offset — a restart re-runs the
/// drain instead of bypassing it.
#[tokio::test]
async fn adapter_drop_pending_drain_failure_disables_polling_without_zero_offset() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    // The client exhausts its bounded 5xx budget on every drain attempt
    // (3 attempts × 3 client calls).
    let script_failures = vec![
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
        FailureScript::Server { status: 500 },
    ];
    state.script_failures("getUpdates", script_failures.clone());
    let db = telegram_db_path("drop-pending-fail");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let mut telegram = test_config(&base);
    telegram.drop_pending_updates = true;
    let adapter = spawn_adapter(gateway.clone(), telegram).await;
    // The drain fails after its bounded attempts: the adapter must stop
    // (fail-closed) instead of processing the pending queue.
    wait_until(std::time::Duration::from_secs(20), || {
        state.request_count("getUpdates") >= 9
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let count = state.request_count("getUpdates");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        state.request_count("getUpdates"),
        count,
        "the adapter must not continue polling after a failed drain (fail-closed)"
    );
    assert_eq!(
        adapter.processed_updates(),
        0,
        "no update may be processed after a failed drain"
    );
    assert_eq!(
        state.sent_texts().len(),
        0,
        "no pending update may produce output after a failed drain"
    );
    adapter.shutdown().await;
    // Fail-closed persistence: nothing was persisted (no zero write), so a
    // restart re-runs the drain instead of bypassing it.
    state.script_failures("getUpdates", script_failures);
    let mut telegram2 = test_config(&base);
    telegram2.drop_pending_updates = true;
    let adapter2 = spawn_adapter(gateway.clone(), telegram2).await;
    // The restart re-runs the full bounded drain (9 getUpdates calls) and
    // fails closed again; the zero-write prohibition is proven by the
    // drain being attempted at all.
    wait_until(std::time::Duration::from_secs(20), || {
        state.request_count("getUpdates") >= count + 9
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let count2 = state.request_count("getUpdates");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        state.request_count("getUpdates"),
        count2,
        "the restarted adapter must fail closed again (the drain was re-run)"
    );
    assert_eq!(adapter2.processed_updates(), 0);
    adapter2.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_stops_polling_after_bounded_unauthorized_failures() {
    let (base, state) = spawn_fixture().await;
    state.script_failures(
        "getUpdates",
        vec![
            FailureScript::BadRequest {
                error_code: 401,
                description: "Unauthorized".to_string(),
            },
            FailureScript::BadRequest {
                error_code: 401,
                description: "Unauthorized".to_string(),
            },
        ],
    );
    let db = telegram_db_path("unauthorized");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let mut telegram = test_config(&base);
    telegram.drop_pending_updates = false;
    telegram.unauthorized_failure_bound = 2;
    let adapter = spawn_adapter(gateway.clone(), telegram).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.request_count("getUpdates") >= 2
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let count = state.request_count("getUpdates");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        state.request_count("getUpdates"),
        count,
        "the poller must stop after the unauthorized bound (no infinite 401 loop)"
    );
    assert_eq!(adapter.processed_updates(), 0);
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_stop_command_cancels_the_active_run() {
    let (base, state) = spawn_fixture().await;
    let (port, _arrived, release_tx, holding) = spawn_holding_fixture();
    let (config, source) = holding_config_and_source(port);
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("stop");
    let gateway = test_state(&source, &db, |_config| config.clone());
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "before")
    })
    .await;
    // /stop from the same chat (same allowlisted user).
    push_update(
        &state,
        json!({
            "ok": true,
            "result": [{
                "update_id": 20,
                "message": {
                    "message_id": 200,
                    "date": 1700000000,
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555, "is_bot": false, "first_name": "Alice"},
                    "text": "/stop"
                }
            }]
        }),
    );
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("Stopping the active run"))
    })
    .await;
    let _ = release_tx.send(());
    holding.join().expect("holding fixture");
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "[stopped]")
    })
    .await;
    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

// ---------------------------------------------------------------------------
// A8 → A5 wiring: /run, /approve, /deny, /compact against the REAL service.
// ---------------------------------------------------------------------------

/// One canonical update fixture for a private-chat text message.
fn update_fixture(
    update_id: i64,
    message_id: i64,
    chat_id: i64,
    user_id: i64,
    text: &str,
) -> Value {
    json!({
        "ok": true,
        "result": [{
            "update_id": update_id,
            "message": {
                "message_id": message_id,
                "date": 1700000000,
                "chat": {"id": chat_id, "type": "private"},
                "from": {"id": user_id, "is_bot": false, "first_name": "Alice"},
                "text": text
            }
        }]
    })
}

/// Source whose runs echo the run input as a delta (for /run argument flow).
const RUN_ECHO_SOURCE: &str = r#"
use stream;
pub fn run(input: map) -> string {
    let text: string = input["input"];
    stream::emit({"type": "model.delta", "delta": text});
    "ok";
}
"#;

/// Scripted provider server for the REAL A5 production loop (one thread,
/// sequential connections, scripted per-request responses).
struct ScriptedProvider {
    port: u16,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    shutdown: std::sync::mpsc::Sender<()>,
}

impl ScriptedProvider {
    fn port(&self) -> u16 {
        self.port
    }

    fn request_count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for ScriptedProvider {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

fn spawn_scripted_provider(responses: Vec<(u16, String)>) -> ScriptedProvider {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let count = std::sync::Arc::clone(&requests);
    std::thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        let mut served = 0usize;
        loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    let mut content_length = None;
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(read) => {
                                request.extend_from_slice(&buffer[..read]);
                                let text = String::from_utf8_lossy(&request);
                                if content_length.is_none() {
                                    content_length = text.lines().find_map(|line| {
                                        line.to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                                    });
                                }
                                let head_end = text.find("\r\n\r\n").unwrap_or(0);
                                if let Some(length) = content_length
                                    && request.len() >= head_end + 4 + length
                                {
                                    break;
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(std::time::Duration::from_millis(2));
                            }
                            Err(_) => break,
                        }
                    }
                    let (status, body) = responses.get(served).cloned().unwrap_or_else(|| {
                        responses.last().cloned().unwrap_or((200, String::new()))
                    });
                    served += 1;
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    ScriptedProvider {
        port,
        requests,
        shutdown: shutdown_tx,
    }
}

fn wire_text(text: &str) -> String {
    json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
    .to_string()
}

fn wire_tool_calls(calls: Value) -> String {
    json!({
        "id": "chatcmpl-2",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "", "tool_calls": calls},
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4}
    })
    .to_string()
}

fn tool_call(id: &str, name: &str, arguments: Value) -> Value {
    json!({
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": arguments.to_string()}
    })
}

/// The production-loop gateway config for one scripted provider.
fn a5_gateway_config(server_port: u16, root: &std::path::Path) -> AgentGatewayConfig {
    AgentGatewayConfig {
        provider: Some("openai_chat".to_string()),
        model: "test-model".to_string(),
        provider_options: json!({
            "base_url": format!("http://127.0.0.1:{server_port}"),
            "api_key": "test-key",
            "model": "test-model"
        }),
        http: rustscript_vm::HttpConfig {
            allowed_schemes: vec!["http".to_string()],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            allowed_ports: vec![server_port],
            allow_private_ips: true,
            ..rustscript_vm::HttpConfig::default()
        },
        io: IoPolicy {
            allowed_roots: vec![root.to_string_lossy().into_owned()],
            allow_write: true,
            allow_process: false,
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 1024 * 1024,
        },
        run_timeout: std::time::Duration::from_secs(60),
        base_retry_delay_ms: 20,
        max_retry_delay_ms: 40,
        stream: false,
        ..AgentGatewayConfig::default()
    }
}

/// The durable status of one run (column 3 of `run.get` rows).
fn durable_run_status(gateway: &AgentGatewayState, run_id: &str) -> String {
    let persistence = gateway.persistence().expect("durable persistence");
    let data = persistence.run_get(run_id).expect("run get");
    data.get("rows")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(Value::as_array)
        .and_then(|row| row.get(3))
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string()
}

/// The durable origin actor of one run (column 21 of `run.get` rows — the
/// v5 `runs.origin_actor` column appended after the v1 run columns).
fn durable_run_origin(gateway: &AgentGatewayState, run_id: &str) -> String {
    let persistence = gateway.persistence().expect("durable persistence");
    let data = persistence.run_get(run_id).expect("run get");
    data.get("rows")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(Value::as_array)
        .and_then(|row| row.get(20))
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string()
}

/// The durable approval row (`approval.get` columns: id, run_id, session_id,
/// tool_call_id, tool_name, arguments_json, risk_class, state, ...,
/// resolver, decision_reason).
fn durable_approval_row(gateway: &AgentGatewayState, approval_id: &str) -> Vec<Value> {
    let persistence = gateway.persistence().expect("durable persistence");
    let data = persistence.approval_get(approval_id).expect("approval get");
    data.get("rows")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(Value::as_array)
        .cloned()
        .expect("approval row")
}

/// The bridge-generated approval id carried by the run's durable
/// `approval.required` event.
fn parked_approval_id(gateway: &AgentGatewayState, run_id: &str) -> String {
    let persistence = gateway.persistence().expect("durable persistence");
    let data = persistence
        .event_replay(&json!({
            "run_id": run_id,
            "after_seq": 1,
            "max_events": 512,
            "max_bytes": 65536,
        }))
        .expect("event replay");
    data.get("rows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .find_map(|row| {
            if row.get(3).and_then(Value::as_str) != Some("approval.required") {
                return None;
            }
            let payload: Value = row
                .get(4)
                .and_then(Value::as_str)
                .and_then(|payload| serde_json::from_str(payload).ok())?;
            payload
                .get("approval_id")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .expect("approval.required must carry the bridge approval id")
}

/// Waits for the `/run` reply, then returns the echoed durable run id.
async fn run_id_from_reply(state: &FixtureState) -> String {
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.starts_with("Run "))
    })
    .await;
    state
        .sent_texts()
        .iter()
        .find(|text| text.starts_with("Run "))
        .expect("run reply")
        .strip_prefix("Run ")
        .expect("run reply prefix")
        .split(' ')
        .next()
        .expect("run id")
        .to_string()
}

async fn wait_for_durable_status(gateway: &AgentGatewayState, run_id: &str, status: &str) {
    wait_until(std::time::Duration::from_secs(40), || {
        durable_run_status(gateway, run_id) == status
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_run_command_admits_a_real_run_and_echoes_its_durable_identity() {
    let (base, state) = spawn_fixture().await;
    push_update(
        &state,
        update_fixture(20, 109, 555, 555, "/run hello there"),
    );
    let db = telegram_db_path("run-command");
    let gateway = test_state(RUN_ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    // The /run reply echoes the durable run id and the admission status.
    let run_id = run_id_from_reply(&state).await;
    let reply = state
        .sent_texts()
        .iter()
        .find(|text| text.starts_with("Run "))
        .expect("run reply")
        .clone();
    assert!(
        reply.contains(&run_id) && reply.contains("started"),
        "the /run reply must echo the durable run id and status, got: {reply}"
    );
    assert_eq!(
        reply,
        format!("Run {run_id} started (status: started)."),
        "the reply must carry exactly the durable admission status"
    );
    assert!(
        !reply.contains("TEST-SECRET-TOKEN"),
        "the reply must never contain a secret"
    );

    // The worker REALLY ran with the command's argument as the input.
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| text == "hello there")
    })
    .await;
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    wait_for_durable_status(&gateway, &run_id, "completed").await;

    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_run_command_duplicate_update_admits_only_one_run() {
    let (base, state) = spawn_fixture().await;
    // Same message_id (durable idempotency key), two update_ids.
    push_update(&state, update_fixture(21, 105, 555, 555, "/run dup"));
    push_update(&state, update_fixture(22, 105, 555, 555, "/run dup"));
    let db = telegram_db_path("run-dedup");
    let gateway = test_state(RUN_ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let sends = state.sent_texts();
    assert_eq!(
        sends.iter().filter(|text| *text == "dup").count(),
        1,
        "the duplicated /run update must admit exactly one run: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| text.starts_with("Run ")).count(),
        1,
        "exactly one /run confirmation reply: {sends:?}"
    );
    assert_eq!(
        sends.iter().filter(|text| *text == "[done]").count(),
        1,
        "one run must render one terminal line: {sends:?}"
    );

    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

/// P3: a bare `/run` (no input text) is a usage error — it must reply with
/// the usage line and MUST NOT admit a run (no durable run, no worker, no
/// identity echo).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_bare_run_returns_usage_without_admitting() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, update_fixture(26, 107, 555, 555, "/run"));
    let db = telegram_db_path("bare-run");
    let gateway = test_state(RUN_ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("Usage: /run"))
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let sends = state.sent_texts();
    assert!(
        !sends.iter().any(|text| text.starts_with("Run ")),
        "a bare /run must never admit a run: {sends:?}"
    );
    let usage = sends
        .iter()
        .find(|text| text.contains("Usage: /run"))
        .expect("bare /run usage reply");
    assert!(
        usage.starts_with("Usage: /run"),
        "the reply must be the typed usage line, got: {usage}"
    );

    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_approve_command_resolves_the_real_parked_approval_and_executes_the_tool() {
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-approve-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("approve root");
    let server = spawn_scripted_provider(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("approved.txt"), "content": "approved"})
            )])),
        ),
        (200, wire_text("approved and done")),
    ]);
    let db = telegram_db_path("a8-approve");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    // /run admits the run; the production loop parks it on a durable approval.
    push_update(
        &state,
        update_fixture(30, 110, 555, 555, "/run write the file"),
    );
    let run_id = run_id_from_reply(&state).await;
    wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
    assert!(
        !root.join("approved.txt").exists(),
        "the tool must not execute while waiting"
    );
    let approval_id = parked_approval_id(&gateway, &run_id);

    // The renderer surfaces the REAL approval id and the resolution commands.
    let expected_line = format!(
        "[approval] file.write requires approval (pending) — /approve {approval_id} or /deny {approval_id}"
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().contains(&expected_line)
    })
    .await;

    // /approve with the explicit id resolves the durable row exactly once.
    push_update(
        &state,
        update_fixture(31, 111, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_for_durable_status(&gateway, &run_id, "completed").await;
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("Approval {approval_id} approved; the run continues."))
    })
    .await;
    assert_eq!(
        std::fs::read_to_string(root.join("approved.txt")).expect("written"),
        "approved",
        "the approved tool must really execute"
    );
    let row = durable_approval_row(&gateway, &approval_id);
    assert_eq!(row[7], json!("approved"), "durable approval state");
    assert_eq!(
        row[13],
        json!("telegram:555"),
        "the actor must be persisted"
    );
    assert_eq!(
        row[14],
        json!("approved via telegram message 555:111"),
        "the reason must be persisted"
    );
    assert_eq!(server.request_count(), 2, "exactly one resume");

    // A second /approve is a typed no-op and NEVER resumes the run.
    push_update(
        &state,
        update_fixture(32, 112, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("already resolved"))
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        server.request_count(),
        2,
        "the second /approve must never resume the run"
    );

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_deny_command_folds_a_typed_denial_and_the_loop_continues() {
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-deny-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("deny root");
    let server = spawn_scripted_provider(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("denied.txt"), "content": "denied"})
            )])),
        ),
        (200, wire_text("the tool was denied")),
    ]);
    let db = telegram_db_path("a8-deny");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    push_update(
        &state,
        update_fixture(40, 120, 555, 555, "/run write the file"),
    );
    let run_id = run_id_from_reply(&state).await;
    wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
    let approval_id = parked_approval_id(&gateway, &run_id);

    push_update(
        &state,
        update_fixture(41, 121, 555, 555, &format!("/deny {approval_id}")),
    );
    wait_for_durable_status(&gateway, &run_id, "completed").await;
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("Approval {approval_id} denied; the run continues."))
    })
    .await;
    assert!(
        !root.join("denied.txt").exists(),
        "the denied tool must never execute"
    );
    let row = durable_approval_row(&gateway, &approval_id);
    assert_eq!(row[7], json!("denied"), "durable approval state");
    assert_eq!(
        row[13],
        json!("telegram:555"),
        "the actor must be persisted"
    );
    assert_eq!(
        row[14],
        json!("denied via telegram message 555:121"),
        "the reason must be persisted"
    );
    assert_eq!(
        server.request_count(),
        2,
        "the loop continued after the denial"
    );

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_approval_command_errors_are_typed_and_never_resume() {
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-approval-errors-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("errors root");
    let server = spawn_scripted_provider(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("approved.txt"), "content": "approved"})
            )])),
        ),
        (200, wire_text("approved and done")),
    ]);
    let db = telegram_db_path("a8-approval-errors");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    push_update(
        &state,
        update_fixture(50, 130, 555, 555, "/run write the file"),
    );
    let run_id = run_id_from_reply(&state).await;
    wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
    let approval_id = parked_approval_id(&gateway, &run_id);

    // Typed usage errors: missing id, unknown id, and ambiguous multi-token id.
    push_update(&state, update_fixture(51, 131, 555, 555, "/approve"));
    push_update(&state, update_fixture(52, 132, 555, 555, "/approve nope"));
    push_update(
        &state,
        update_fixture(53, 133, 555, 555, &format!("/approve {approval_id} extra")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("Usage: /approve <approval_id>."))
    })
    .await;
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("No such approval: nope"))
    })
    .await;
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("one id only"))
    })
    .await;
    assert_eq!(
        durable_run_status(&gateway, &run_id),
        "waiting_approval",
        "usage errors must not touch the parked run"
    );

    // Cross-session oracle: the same approval id from another chat is a
    // typed PERMISSION error with the IDENTICAL observable shape as an
    // unknown id (existence/state must never leak across sessions), never
    // resumes, and must not consume the park.
    push_update(
        &state,
        update_fixture(54, 134, -1001234, 555, &format!("/approve {approval_id}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("No such approval: {approval_id}."))
    })
    .await;
    assert_eq!(
        durable_run_status(&gateway, &run_id),
        "waiting_approval",
        "a foreign-chat /approve must never resume the run"
    );
    assert_eq!(
        durable_approval_row(&gateway, &approval_id)[7],
        json!("pending"),
        "the foreign-chat attempt must leave the row pending"
    );

    // The owning chat can still resolve the SAME approval.
    push_update(
        &state,
        update_fixture(55, 135, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_for_durable_status(&gateway, &run_id, "completed").await;
    assert_eq!(
        std::fs::read_to_string(root.join("approved.txt")).expect("written"),
        "approved"
    );

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_approval_requires_the_durable_origin_actor() {
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-owner-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("owner root");
    let server = spawn_scripted_provider(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("approved.txt"), "content": "approved"})
            )])),
        ),
        (200, wire_text("approved and done")),
    ]);
    let db = telegram_db_path("a8-owner");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    // Both 555 (the /run initiator) and 777 are allowlisted — the allowlist
    // is only the ENTRY permission and must never substitute for the
    // per-run durable origin actor.
    let mut telegram = test_config(&base);
    telegram.allowed_users = vec![555, 777];
    let adapter = spawn_adapter(gateway.clone(), telegram).await;

    // /run by 555 parks the run on a durable approval.
    push_update(
        &state,
        update_fixture(30, 110, 555, 555, "/run write the file"),
    );
    let run_id = run_id_from_reply(&state).await;
    wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
    let approval_id = parked_approval_id(&gateway, &run_id);

    // The durable origin actor of the run is the initiator telegram:555.
    assert_eq!(
        durable_run_origin(&gateway, &run_id),
        "telegram:555",
        "the run must durably record its origin actor"
    );

    // A different allowlisted user in the SAME chat must not resolve or
    // consume the park: identical oracle shape, row stays pending, run stays
    // parked.
    push_update(
        &state,
        update_fixture(31, 111, 555, 777, &format!("/approve {approval_id}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("No such approval: {approval_id}."))
    })
    .await;
    assert_eq!(
        durable_run_status(&gateway, &run_id),
        "waiting_approval",
        "a non-owner /approve must never resume the run"
    );
    assert_eq!(
        durable_approval_row(&gateway, &approval_id)[7],
        json!("pending"),
        "a non-owner attempt must never consume the park"
    );
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(server.request_count(), 1, "no tool round for a non-owner");

    // The ORIGINAL initiator can still resolve the same approval.
    push_update(
        &state,
        update_fixture(32, 112, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_for_durable_status(&gateway, &run_id, "completed").await;
    assert_eq!(
        std::fs::read_to_string(root.join("approved.txt")).expect("written"),
        "approved"
    );
    assert_eq!(
        durable_approval_row(&gateway, &approval_id)[13],
        json!("telegram:555"),
        "the resolving actor is the durable origin actor"
    );

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// P2 cross-session oracle: resolving a REAL approval from a foreign chat
/// and probing an id that never existed must produce the IDENTICAL typed
/// reply shape (modulo the id itself) — existence and state never leak
/// across sessions. Only an approval that passes the session AND the
/// durable-owner check may reveal already-resolved/expired details.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_cross_session_approval_oracle_returns_identical_shapes() {
    // A known UUID that was never requested: the canonical probe id.
    const NEVER_ID: &str = "00000000-0000-0000-0000-000000000000";
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-oracle-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("oracle root");
    let server = spawn_scripted_provider(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("approved.txt"), "content": "approved"})
            )])),
        ),
        (200, wire_text("approved and done")),
    ]);
    let db = telegram_db_path("a8-oracle");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    // Chat 555 admits and parks a REAL approval.
    push_update(
        &state,
        update_fixture(30, 110, 555, 555, "/run write the file"),
    );
    let run_id = run_id_from_reply(&state).await;
    wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
    let approval_id = parked_approval_id(&gateway, &run_id);

    // Probe 1 — a never-existing id in the owning chat (owner, same session):
    // the canonical "no such approval" shape.
    push_update(
        &state,
        update_fixture(33, 113, 555, 555, &format!("/approve {NEVER_ID}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("No such approval: {NEVER_ID}."))
    })
    .await;

    // Probe 2 — the REAL approval id from a FOREIGN chat/session: exactly
    // the same observable shape as the never-existing id.
    push_update(
        &state,
        update_fixture(34, 114, -1001234, 555, &format!("/approve {approval_id}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("No such approval: {approval_id}."))
    })
    .await;

    // The two replies are the identical template modulo the id: strip the
    // id position and compare.
    let sent_texts = state.sent_texts();
    let never_reply = sent_texts
        .iter()
        .find(|text| **text == format!("No such approval: {NEVER_ID}."))
        .expect("never-id reply");
    let foreign_reply = sent_texts
        .iter()
        .find(|text| **text == format!("No such approval: {approval_id}."))
        .expect("foreign-chat reply");
    assert_eq!(
        never_reply.replace(NEVER_ID, "<id>"),
        foreign_reply.replace(&approval_id, "<id>"),
        "foreign-session and never-existing probes must be byte-identical in shape"
    );

    // Neither probe consumed the park: the owner still resolves.
    push_update(
        &state,
        update_fixture(35, 115, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_for_durable_status(&gateway, &run_id, "completed").await;
    // The owner's second /approve passes the session+owner checks and only
    // THEN reveals the already-resolved detail (state never leaked to the
    // foreign probes).
    push_update(
        &state,
        update_fixture(36, 116, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| {
            *text == format!("Approval {approval_id} is already resolved (state: approved).")
        })
    })
    .await;

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// A pre-v5 run (empty durable `origin_actor`, exactly what an existing
/// database admitted before the v5 origin column carried) with a pending
/// approval must be typed-rejected with the IDENTICAL shape as an unknown
/// id — even from the owning chat and session. The owner-less row is safely
/// rejected (never resolved, never resumed, never consumed), because no
/// durable actor can be verified for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_approval_ownerless_old_row_is_a_typed_no_op() {
    const NEVER_ID: &str = "00000000-0000-0000-0000-000000000000";
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-old-ownerless-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("old-row root");
    let server = spawn_scripted_provider(vec![]);
    let db = telegram_db_path("a8-old-ownerless");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    // Craft the pre-v5 durable state: the telegram session, a run whose
    // origin_actor is EMPTY (a v4-era admission), and its pending approval.
    let persistence = gateway.persistence().expect("durable persistence");
    let session_id = "telegram:fixture_bot:555:";
    let now = 1_000_000u64;
    let run_id = Uuid::new_v4().to_string();
    let approval_id = Uuid::new_v4().to_string();
    persistence
        .session_create(&json!({
            "id": session_id,
            "profile": "telegram",
            "platform": "telegram",
            "account_id": "fixture_bot",
            "chat_id": "555",
            "thread_id": "",
            "user_id": "555",
            "generation": 1,
            "system_prompt": "",
            "model": "test-model",
            "provider": "",
            "toolset_hash": "",
            "metadata_json": "{}",
            "title": "",
            "end_reason": "",
            "now_ms": now,
        }))
        .expect("old-row session");
    persistence
        .admission_create(&json!({
            "session_id": session_id,
            "session_new": 0,
            "profile": "telegram",
            "platform": "telegram",
            "account_id": "fixture_bot",
            "model": "test-model",
            "provider": "openai_chat",
            "system_prompt": "",
            "run_id": run_id,
            "parent_run_id": "",
            "input_json": "{\"text\":\"old row\"}",
            "message_id": Uuid::new_v4().to_string(),
            "message_run_id": run_id,
            "script_hash": "",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "origin_actor": "",
            "event_id": Uuid::new_v4().to_string(),
            "now_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("old-row admission");
    persistence
        .approval_request(&json!({
            "id": approval_id,
            "run_id": run_id,
            "session_id": session_id,
            "tool_call_id": "call-old",
            "tool_name": "file.write",
            "arguments_json": "{}",
            "risk_class": "write",
            "decision_scope": "one_time",
            "one_time": 1,
            "requested_at_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("old-row approval request");
    assert_eq!(
        durable_run_origin(&gateway, &run_id),
        "",
        "the pre-v5 row must carry no durable origin actor"
    );
    assert_eq!(
        durable_approval_row(&gateway, &approval_id)[7],
        json!("pending"),
        "the crafted approval must be pending"
    );

    // The owner chat probes the never-existing id and the REAL owner-less
    // approval: both are the identical typed shape, and the park survives.
    push_update(
        &state,
        update_fixture(40, 120, 555, 555, &format!("/approve {NEVER_ID}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("No such approval: {NEVER_ID}."))
    })
    .await;
    push_update(
        &state,
        update_fixture(41, 121, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| *text == format!("No such approval: {approval_id}."))
    })
    .await;
    let sent_texts = state.sent_texts();
    let never_reply = sent_texts
        .iter()
        .find(|text| **text == format!("No such approval: {NEVER_ID}."))
        .expect("never-id reply");
    let old_reply = sent_texts
        .iter()
        .find(|text| **text == format!("No such approval: {approval_id}."))
        .expect("ownerless-id reply");
    assert_eq!(
        never_reply.replace(NEVER_ID, "<id>"),
        old_reply.replace(&approval_id, "<id>"),
        "an owner-less pre-v5 approval must be byte-identical to a never-existing id"
    );
    assert_eq!(
        durable_approval_row(&gateway, &approval_id)[7],
        json!("pending"),
        "the owner-less attempt must never consume the park"
    );
    assert_eq!(
        durable_run_status(&gateway, &run_id),
        "running",
        "the owner-less run must never be resumed"
    );
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        server.request_count(),
        0,
        "no tool round for an owner-less row"
    );

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The durable origin binding must hold across a gateway restart: the owner
/// check reads the DURABLE runs.origin_actor (never an in-memory-only map),
/// so a fresh process on the same database enforces the same contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_approval_owner_binding_survives_restart() {
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-restart-owner-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("restart root");
    let server = spawn_scripted_provider(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("approved.txt"), "content": "approved"})
            )])),
        ),
        (200, wire_text("approved and done")),
        // Phase 2 runs on the SAME scripted provider (the responses repeat
        // the LAST entry once exhausted): the phase-2 `/run` must park on a
        // fresh tool round, so the phase-1 approve and the phase-2 run each
        // need their own tool/text pair (4 responses total).
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-2",
                "file.write",
                json!({"path": root.join("approved.txt"), "content": "approved again"})
            )])),
        ),
        (200, wire_text("approved and done again")),
    ]);
    let db = telegram_db_path("a8-restart-owner");
    let mut telegram = test_config(&base);
    telegram.allowed_users = vec![555, 777];

    // Phase 1: a fresh gateway parks a run; 777 is rejected with the oracle
    // shape; the durable origin column records telegram:555.
    {
        let mut config = a5_gateway_config(server.port(), &root);
        config.approval_mode = "manual".to_string();
        let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
            .expect("phase 1 gateway");
        let adapter = spawn_adapter(gateway.clone(), telegram.clone()).await;
        push_update(
            &state,
            update_fixture(30, 110, 555, 555, "/run write the file"),
        );
        let run_id = run_id_from_reply(&state).await;
        wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
        let approval_id = parked_approval_id(&gateway, &run_id);
        assert_eq!(
            durable_run_origin(&gateway, &run_id),
            "telegram:555",
            "the origin actor must be durably persisted"
        );
        push_update(
            &state,
            update_fixture(31, 111, 555, 777, &format!("/approve {approval_id}")),
        );
        wait_until(std::time::Duration::from_secs(30), || {
            state
                .sent_texts()
                .iter()
                .any(|text| *text == format!("No such approval: {approval_id}."))
        })
        .await;
        assert_eq!(
            durable_approval_row(&gateway, &approval_id)[7],
            json!("pending"),
            "phase 1: the non-owner attempt must leave the row pending"
        );
        // The stop leaves the park cleanly (and expires the row — P3), so
        // the phase-2 run starts from a stable gate. The OWNER resolves it
        // first so the durable row is terminal before the restart.
        push_update(
            &state,
            update_fixture(32, 112, 555, 555, &format!("/approve {approval_id}")),
        );
        wait_for_durable_status(&gateway, &run_id, "completed").await;
        // The renderer must flush the terminal before shutdown: a trailing
        // delivery cursor would make the phase-2 adapter's resume re-render
        // the phase-1 run and hold the active-run gate against the new /run.
        wait_until(std::time::Duration::from_secs(30), || {
            state.sent_texts().iter().any(|text| text == "[done]")
        })
        .await;
        adapter.shutdown().await;
        drop(gateway);
    }

    // Phase 2: a fresh gateway on the SAME durable database (no in-memory
    // carry-over) enforces the identical owner contract.
    {
        let mut config = a5_gateway_config(server.port(), &root);
        config.approval_mode = "manual".to_string();
        let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
            .expect("phase 2 gateway");
        let adapter = spawn_adapter(gateway.clone(), telegram).await;
        // The restart's undelivered catch-up renderer (if any) must finish
        // and release the session gate BEFORE the new /run is admitted.
        let sent_before_resume = state.sent_texts().len();
        wait_until(std::time::Duration::from_secs(30), || {
            state
                .sent_texts()
                .iter()
                .skip(sent_before_resume)
                .any(|text| text == "[done]")
        })
        .await;
        push_update(
            &state,
            update_fixture(37, 117, 555, 555, "/run write the file again"),
        );
        // The fixture retains phase-1 replies; only a NEW "Run " reply can
        // belong to the phase-2 admission, so wait past the phase-1 count.
        let sent_before = state.sent_texts().len();
        wait_until(std::time::Duration::from_secs(30), || {
            state.sent_texts().len() > sent_before
                && state
                    .sent_texts()
                    .iter()
                    .skip(sent_before)
                    .any(|text| text.starts_with("Run "))
        })
        .await;
        let run_id = state
            .sent_texts()
            .iter()
            .skip(sent_before)
            .find(|text| text.starts_with("Run "))
            .expect("phase-2 run reply")
            .strip_prefix("Run ")
            .expect("run reply prefix")
            .split(' ')
            .next()
            .expect("run id")
            .to_string();
        wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
        let approval_id = parked_approval_id(&gateway, &run_id);
        push_update(
            &state,
            update_fixture(38, 118, 555, 777, &format!("/approve {approval_id}")),
        );
        wait_until(std::time::Duration::from_secs(30), || {
            state
                .sent_texts()
                .iter()
                .any(|text| *text == format!("No such approval: {approval_id}."))
        })
        .await;
        assert_eq!(
            durable_run_status(&gateway, &run_id),
            "waiting_approval",
            "phase 2: the non-owner must still be rejected after a restart"
        );
        push_update(
            &state,
            update_fixture(39, 119, 555, 555, &format!("/approve {approval_id}")),
        );
        wait_for_durable_status(&gateway, &run_id, "completed").await;
        adapter.shutdown().await;
        drop(gateway);
    }

    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// One API approval-resolution request through the real router; returns
/// (status, body) — used by the cross-gate race below.
async fn api_approve(app: &axum::Router, run_id: &str, approval_id: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/runs/{run_id}/approvals/{approval_id}/approve"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"actor": "reviewer-alice", "reason": "cross-gate race"}).to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

/// Cross-gate exact-once: the API surface (A7) and the Telegram surface (A8)
/// resolve the SAME durable approval concurrently. Exactly one resume may
/// reach the provider; the losing resolver must get a typed no-resume reply
/// (API `409 already_resolved`/`no_pending_approval`, Telegram "already
/// resolved"/"is not waiting on this gateway") and the durable approval row
/// is resolved exactly once by exactly one of the two actors.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_and_telegram_resolving_the_same_approval_resume_exactly_once() {
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-cross-race-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("race root");
    let server = spawn_scripted_provider(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("raced.txt"), "content": "raced"})
            )])),
        ),
        (200, wire_text("raced and done")),
    ]);
    let db = telegram_db_path("a8-cross-race");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    let app = build_agent_gateway_app(gateway.clone());

    // /run admits the run (durable origin_actor = telegram:555) and the
    // production loop parks it on a durable approval.
    push_update(
        &state,
        update_fixture(30, 110, 555, 555, "/run race the approval"),
    );
    let run_id = run_id_from_reply(&state).await;
    wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
    let approval_id = parked_approval_id(&gateway, &run_id);
    let provider_calls_before = server.request_count();
    assert_eq!(
        provider_calls_before, 1,
        "exactly one admission round before the race"
    );

    // Race the two surfaces on the SAME durable approval id.
    let (api_result, _) = tokio::join!(api_approve(&app, &run_id, &approval_id), async {
        push_update(
            &state,
            update_fixture(31, 111, 555, 555, &format!("/approve {approval_id}")),
        );
    });

    // Exactly one resume: the run completes and the provider saw exactly one
    // more request — never two.
    wait_for_durable_status(&gateway, &run_id, "completed").await;
    wait_until(std::time::Duration::from_secs(10), || {
        server.request_count() > provider_calls_before
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(
        server.request_count(),
        provider_calls_before + 1,
        "concurrent API + Telegram resolution must resume exactly once"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("raced.txt")).expect("written"),
        "raced",
        "the single resumed run must execute the approved tool"
    );

    // Exactly one resolver won; the other got a typed no-resume reply. The
    // API loser is `409` with `already_resolved` or `no_pending_approval`;
    // the Telegram loser replies "already resolved" or "is not waiting on
    // this gateway". Either side may win — never both.
    let api_won = matches!(api_result, (StatusCode::OK, _));
    let api_lost_typed = matches!(
        api_result,
        (StatusCode::CONFLICT, ref body)
            if body["error"]["code"] == json!("already_resolved")
                || body["error"]["code"] == json!("no_pending_approval")
    );
    assert!(
        api_won || api_lost_typed,
        "the API resolution must be a typed winner or a typed no-op, got {api_result:?}"
    );
    let telegram_won = state
        .sent_texts()
        .iter()
        .any(|text| text.contains("the run continues"));
    let telegram_lost_typed = state.sent_texts().iter().any(|text| {
        text.contains("already resolved") || text.contains("is not waiting on this gateway")
    });
    assert!(
        telegram_won || telegram_lost_typed,
        "the Telegram resolution must be a typed winner or a typed no-op"
    );
    assert_ne!(
        api_won, telegram_won,
        "exactly one surface may win the race"
    );

    // The durable approval row is resolved exactly once by exactly one of
    // the two actors.
    let row = durable_approval_row(&gateway, &approval_id);
    assert_eq!(row[7], json!("approved"), "durable approval state");
    let resolver = row[13].as_str().expect("resolver").to_string();
    assert!(
        resolver == "reviewer-alice" || resolver == "telegram:555",
        "the durable resolver must be exactly one of the two racing actors, got {resolver:?}"
    );

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_approval_after_stop_is_a_typed_no_op() {
    let (base, state) = spawn_fixture().await;
    let root = telegram_test_root().join(format!("a8-stop-race-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("race root");
    let server = spawn_scripted_provider(vec![(
        200,
        wire_tool_calls(json!([tool_call(
            "call-1",
            "file.write",
            json!({"path": root.join("never.txt"), "content": "never"})
        )])),
    )]);
    let db = telegram_db_path("a8-stop-race");
    let mut config = a5_gateway_config(server.port(), &root);
    config.approval_mode = "manual".to_string();
    let gateway = AgentGatewayState::with_default_agent_program_and_sqlite(config, &db)
        .expect("gateway with the built-in production loop");
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    push_update(
        &state,
        update_fixture(60, 140, 555, 555, "/run write the file"),
    );
    let run_id = run_id_from_reply(&state).await;
    wait_for_durable_status(&gateway, &run_id, "waiting_approval").await;
    let approval_id = parked_approval_id(&gateway, &run_id);

    // /stop cancels the parked run (typed); the P3 park consumption cancels
    // the durable approval row via the A5 `approval.cancel` op — expired
    // promptly, NOT left pending for the default TTL.
    push_update(&state, update_fixture(61, 141, 555, 555, "/stop"));
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("Stopping the active run"))
    })
    .await;
    wait_for_durable_status(&gateway, &run_id, "cancelled").await;
    // The consumed park's approval row must transition to expired WITHOUT
    // waiting for the TTL expiry sweep.
    wait_until(std::time::Duration::from_secs(20), || {
        durable_approval_row(&gateway, &approval_id)[7] == json!("expired")
    })
    .await;
    assert_eq!(
        durable_approval_row(&gateway, &approval_id)[13],
        json!("gateway-stop"),
        "the stop-consuming cancel records the gateway-stop resolver"
    );
    // A late /approve of the same durable id is a typed no-op: the owner
    // passes the session+owner checks and only THEN sees the expired detail;
    // the run is never resumed.
    push_update(
        &state,
        update_fixture(62, 142, 555, 555, &format!("/approve {approval_id}")),
    );
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| {
            *text == format!("Approval {approval_id} is already resolved (state: expired).")
        })
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        durable_run_status(&gateway, &run_id),
        "cancelled",
        "a late /approve must never resurrect a stopped run"
    );
    assert_eq!(
        server.request_count(),
        1,
        "no tool round may start after the stop"
    );
    assert!(
        !root.join("never.txt").exists(),
        "the tool must never execute"
    );

    adapter.shutdown().await;
    drop(gateway);
    std::fs::remove_file(&db).expect("temporary db should be removed");
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_compact_reports_typed_availability_for_active_and_terminal_runs() {
    let (base, state) = spawn_fixture().await;
    // A real ACTIVE run without the A5 provider chain: the legacy source
    // parks in a holding HTTP call, so the run stays durably non-terminal
    // and its renderer holds the session gate.
    let (port, _arrived, release_tx, holding) = spawn_holding_fixture();
    let (config, source) = holding_config_and_source(port);
    push_update(
        &state,
        update_fixture(70, 150, 555, 555, "/run write the file"),
    );
    let db = telegram_db_path("a8-compact");
    let gateway = test_state(&source, &db, |_config| config.clone());
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;

    // The run is durably active (parked mid-run; the session gate is held).
    let run_id = run_id_from_reply(&state).await;
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| text == "before")
    })
    .await;
    assert!(
        !matches!(
            durable_run_status(&gateway, &run_id).as_str(),
            "completed" | "failed" | "cancelled"
        ),
        "the run must be durably active while /compact is tested"
    );

    // Active run: /compact answers the typed loop-managed state; there is
    // no manual compaction trigger on the service.
    push_update(&state, update_fixture(71, 151, 555, 555, "/compact"));
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("no manual compaction trigger"))
    })
    .await;
    let sends = state.sent_texts();
    let active_compact = sends
        .iter()
        .find(|text| text.contains("no manual compaction trigger"))
        .expect("active /compact reply");
    assert!(
        !active_compact.contains("completed"),
        "an active-run /compact must never claim a compaction happened"
    );

    // Release the run: it completes, its renderer delivers the terminal
    // line, and the session gate is released.
    let _ = release_tx.send(());
    holding.join().expect("holding fixture");
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    wait_for_durable_status(&gateway, &run_id, "completed").await;

    // Terminal run: /compact answers the typed no-active-run state.
    push_update(&state, update_fixture(73, 153, 555, 555, "/compact"));
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("nothing to compact"))
    })
    .await;

    adapter.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_status_reflects_durable_state_across_restart() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("status-durable");

    // Phase 1: one completed run, then /status reports the durable status.
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(30), || {
        state.sent_texts().iter().any(|text| text == "[done]")
    })
    .await;
    push_update(&state, update_fixture(23, 200, 555, 555, "/status"));
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("latest run") && text.contains("completed"))
    })
    .await;
    let phase1 = state
        .sent_texts()
        .iter()
        .find(|text| text.contains("latest run"))
        .expect("phase 1 /status reply")
        .clone();
    adapter.shutdown().await;
    drop(gateway);

    // Phase 2: a fresh gateway on the SAME durable state reports the same
    // completed run without any in-memory carry-over.
    let restored = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter2 = spawn_adapter(restored.clone(), test_config(&base)).await;
    push_update(&state, update_fixture(24, 201, 555, 555, "/status"));
    wait_until(std::time::Duration::from_secs(30), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.contains("latest run") && text.contains("completed"))
    })
    .await;
    let phase2 = state
        .sent_texts()
        .iter()
        .rfind(|text| text.contains("latest run"))
        .expect("phase 2 /status reply")
        .clone();
    assert_eq!(phase1, phase2, "/status must read the durable state");
    assert!(
        !phase2.contains("TEST-SECRET-TOKEN"),
        "the status reply must never contain a secret"
    );

    adapter2.shutdown().await;
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_shutdown_is_bounded() {
    let (base, state) = spawn_fixture().await;
    let db = telegram_db_path("shutdown");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.request_count("getUpdates") >= 1
    })
    .await;
    let started = std::time::Instant::now();
    adapter.shutdown().await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "shutdown must be bounded"
    );
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn gateway_binary_runs_telegram_and_api_on_one_agent_service() {
    let (base, state) = spawn_fixture().await;
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("binary");
    let root = telegram_test_root();
    std::fs::create_dir_all(&root).expect("telegram test root");
    let script = root.join(format!("binary-{}.rss", Uuid::new_v4()));
    std::fs::write(&script, ECHO_SOURCE).expect("write agent script");
    let bin = env!("CARGO_BIN_EXE_rustscript-agent-gateway");
    let mut child = tokio::process::Command::new(bin)
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .env("RUSTSCRIPT_AGENT_STATE_DB", &db)
        .env("RUSTSCRIPT_AGENT_SCRIPT", &script)
        .env(
            "RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN",
            "123456:TEST-SECRET-TOKEN",
        )
        .env("RUSTSCRIPT_AGENT_TELEGRAM_API_BASE", &base)
        .env("RUSTSCRIPT_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST", "1")
        .env("RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_ACCOUNTS", "fixture_bot")
        .env("RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_CHATS", "555")
        .env("RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_USERS", "555")
        // The update is queued before the binary starts: opt out of the
        // safe first-boot drop so it is processed.
        .env("RUSTSCRIPT_AGENT_TELEGRAM_DROP_PENDING_UPDATES", "0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("gateway binary should spawn");
    // The binary's Telegram adapter must process the queued update through
    // the shared AgentService and render it to the fixture.
    wait_until(std::time::Duration::from_secs(20), || {
        state.sent_texts().iter().any(|text| text == "hello world")
    })
    .await;
    // Graceful stop: SIGINT halts the service and shuts the adapter down
    // (bounded), then the process exits.
    let pid = child.id().expect("child pid");
    std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("send SIGINT");
    let exited = tokio::time::timeout(std::time::Duration::from_secs(15), child.wait())
        .await
        .expect("the gateway must exit within the bound after SIGINT")
        .expect("child wait");
    assert!(exited.success(), "graceful shutdown must exit cleanly");
    std::fs::remove_file(&script).expect("temporary script should be removed");
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

// ---------------------------------------------------------------------------
// Token redaction in logs.
// ---------------------------------------------------------------------------

use std::sync::OnceLock;
use tracing_core::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

/// Process-wide captured log lines; the subscriber is installed exactly
/// once and every test can read the same sink.
static CAPTURED_LOGS: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

struct MessageVisitor {
    text: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if !self.text.is_empty() {
            self.text.push(' ');
        }
        self.text.push_str(&format!("{}={value:?}", field.name()));
    }
}

struct CaptureSubscriber {
    messages: Arc<Mutex<Vec<String>>>,
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut visitor = MessageVisitor {
            text: String::new(),
        };
        event.record(&mut visitor);
        self.messages
            .lock()
            .expect("messages lock")
            .push(visitor.text);
    }
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

fn install_log_capture() -> Arc<Mutex<Vec<String>>> {
    CAPTURED_LOGS
        .get_or_init(|| {
            let messages = Arc::new(Mutex::new(Vec::<String>::new()));
            let subscriber = CaptureSubscriber {
                messages: Arc::clone(&messages),
            };
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other global subscriber");
            messages
        })
        .clone()
}

#[tokio::test]
async fn gateway_binary_survives_telegram_startup_failure_and_serves_the_api() {
    let db = telegram_db_path("binary-degraded");
    let root = telegram_test_root();
    std::fs::create_dir_all(&root).expect("telegram test root");
    let script = root.join(format!("binary-degraded-{}.rss", Uuid::new_v4()));
    std::fs::write(&script, ECHO_SOURCE).expect("write agent script");
    let bin = env!("CARGO_BIN_EXE_rustscript-agent-gateway");
    let mut child = tokio::process::Command::new(bin)
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .env("RUSTSCRIPT_AGENT_STATE_DB", &db)
        .env("RUSTSCRIPT_AGENT_SCRIPT", &script)
        .env(
            "RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN",
            "123456:TEST-SECRET-TOKEN",
        )
        // A dead local endpoint: getMe fails at startup, which must NOT
        // terminate the gateway: the adapter degrades in the background
        // (bounded retries) while the API keeps serving.
        .env("RUSTSCRIPT_AGENT_TELEGRAM_API_BASE", "http://127.0.0.1:1")
        .env("RUSTSCRIPT_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("gateway binary should spawn");
    let stderr = child.stderr.take().expect("stderr");
    let mut lines = tokio::io::BufReader::new(stderr).lines();
    // The API must come up: read stderr until the listening line.
    let mut address = None;
    while let Some(line) =
        tokio::time::timeout(std::time::Duration::from_secs(20), lines.next_line())
            .await
            .expect("the gateway must print its listening address")
            .expect("stderr line")
    {
        if let Some(position) = line.find("listening on http://") {
            address = Some(line[position + "listening on http://".len()..].to_string());
            break;
        }
    }
    let address = address.expect("listening address");
    // The API is alive despite the telegram startup failure.
    let health = http_get(&address, "/health/detailed").await;
    assert!(
        health.contains("200 OK") && health.contains("\"status\":\"ok\""),
        "the API must serve health with the telegram adapter degraded: {health}"
    );
    // The degraded state is recorded (redacted) on stderr.
    let mut degraded = false;
    while let Some(line) =
        tokio::time::timeout(std::time::Duration::from_secs(20), lines.next_line())
            .await
            .expect("the degraded line must be printed")
            .expect("stderr line")
    {
        if line.contains("degraded") {
            degraded = true;
            assert!(
                !line.contains("TEST-SECRET-TOKEN"),
                "the degraded log must not leak the token: {line}"
            );
            break;
        }
    }
    assert!(
        degraded,
        "the telegram startup failure must be logged as degraded"
    );
    let pid = child.id().expect("child pid");
    std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("send SIGINT");
    let exited = tokio::time::timeout(std::time::Duration::from_secs(15), child.wait())
        .await
        .expect("the gateway must exit within the bound after SIGINT")
        .expect("child wait");
    assert!(exited.success(), "graceful shutdown must exit cleanly");
    std::fs::remove_file(&script).expect("temporary script should be removed");
    std::fs::remove_file(&db).expect("temporary db should be removed");
}

#[tokio::test]
async fn adapter_logs_never_contain_the_bot_token() {
    let messages = install_log_capture();
    let (base, state) = spawn_fixture().await;
    // Exercise the error paths too: rate-limited delivery (bounded retries
    // then a logged typed failure) and the poll loop's own logging.
    state.script_failures(
        "sendMessage",
        vec![
            FailureScript::RateLimit { retry_after: 1 },
            FailureScript::RateLimit { retry_after: 1 },
            FailureScript::RateLimit { retry_after: 1 },
            FailureScript::RateLimit { retry_after: 1 },
        ],
    );
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("redact");
    let gateway = test_state(ECHO_SOURCE, &db, |config| config);
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        adapter.processed_updates() >= 1
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    adapter.shutdown().await;
    let captured = messages.lock().expect("messages lock");
    assert!(
        !captured.is_empty(),
        "the adapter must have produced log lines to inspect"
    );
    for line in captured.iter() {
        assert!(
            !line.contains("TEST-SECRET-TOKEN"),
            "log line leaked the bot token: {line}"
        );
    }
    std::fs::remove_file(&db).expect("temporary db should be removed");
}
