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
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::post,
};
use futures_util::StreamExt;
use rustscript_agent::config::{RunLimits, TelegramConfig};
use rustscript_agent::gateway::telegram::{TelegramApi, TelegramError};
use rustscript_agent::service::AdmitRunRequest;
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
    AgentGatewayConfig, AgentGatewayState,
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
    let workspace = TelegramWorkspaceGuard::create_in(&base);
    let workspace_path = workspace.path().to_path_buf();
    assert!(
        workspace_path.starts_with(&base),
        "the workspace must live under the explicit root, got {workspace_path:?}"
    );
    assert_eq!(
        workspace_path.parent(),
        Some(base.join("workspaces").as_path()),
        "unique workspaces must stay isolated under workspaces/"
    );
    workspace.cleanup();
    assert!(
        !workspace_path.exists(),
        "explicit workspace cleanup must remove the unique directory"
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

/// Unique per-call workspace for Telegram adapter tests. Exclusive artifact
/// flocks are keyed by `RunLimits.workspace_root`; sharing cwd would collide
/// an in-process restart with a parked phase-1 worker.
struct TelegramWorkspaceGuard {
    path: std::path::PathBuf,
    cleaned: bool,
}

impl TelegramWorkspaceGuard {
    fn create_in(root: &std::path::Path) -> Self {
        let path = root.join("workspaces").join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).expect("telegram test workspace should be created");
        Self {
            path,
            cleaned: false,
        }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn cleanup(mut self) {
        std::fs::remove_dir_all(&self.path).unwrap_or_else(|error| {
            panic!(
                "telegram test workspace should be removed ({}): {error}",
                self.path.display()
            )
        });
        self.cleaned = true;
    }
}

impl Drop for TelegramWorkspaceGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Owns `AgentGatewayState` for the full adapter-test lifetime and the unique
/// workspace that isolates artifact flocks. Call [`Self::cleanup`] after the
/// adapter shuts down so removal errors surface; `Drop` is best-effort only.
struct TelegramTestGateway {
    state: AgentGatewayState,
    workspace: TelegramWorkspaceGuard,
}

impl TelegramTestGateway {
    fn workspace(&self) -> &std::path::Path {
        self.workspace.path()
    }

    fn cleanup(self) {
        let TelegramTestGateway { state, workspace } = self;
        drop(state);
        workspace.cleanup();
    }
}

impl std::ops::Deref for TelegramTestGateway {
    type Target = AgentGatewayState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

fn test_state(
    source: &str,
    db_path: &std::path::Path,
    overrides: impl FnOnce(AgentGatewayConfig) -> AgentGatewayConfig,
) -> TelegramTestGateway {
    let config = overrides(AgentGatewayConfig::default());
    let state = AgentGatewayState::with_agent_source_and_sqlite(config, source, db_path)
        .expect("SQLite state should open");
    let workspace = TelegramWorkspaceGuard::create_in(&telegram_test_root());
    state
        .service()
        .set_run_limits(
            RunLimits::new(64, 128, 1024 * 1024, workspace.path())
                .expect("telegram test workspace should validate"),
        )
        .expect("telegram test run limits should apply");
    TelegramTestGateway { state, workspace }
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
        .find(|text| text.contains("/compact"))
        .expect("/compact must reply");
    assert!(
        compact.contains("not available") || compact.contains("blocked"),
        "/compact must be explicitly unavailable, got: {compact}"
    );
    assert!(
        !compact.contains("completed"),
        "/compact must not advertise itself as done: {compact}"
    );
    adapter.shutdown().await;
    gateway.cleanup();
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
        "[approval] web_search requires approval (pending)",
        "[approval] web_search: approved",
        "[done]",
    ] {
        assert!(
            sends.iter().any(|text| text == expected),
            "missing render {expected:?} in {sends:?}"
        );
    }
    adapter.shutdown().await;
    gateway.cleanup();
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
            && sends
                .iter()
                .any(|text| text == "[approval] web_search requires approval (pending)")
            && sends
                .iter()
                .any(|text| text == "[approval] web_search: approved")
            && sends.iter().any(|text| text == "[done]"),
        "the status lines must still be delivered as separate sends: {sends:?}"
    );
    adapter.shutdown().await;
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    restored.cleanup();
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
    let workspace = gateway.workspace().to_path_buf();
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
    gateway.cleanup();
    assert!(
        !workspace.exists(),
        "explicit cleanup must remove the unique workspace"
    );

    // Phase 2: the same durable state resumes. The undelivered terminal is
    // rendered by the restart catch-up (cursor < retained high-water), and
    // the session gate is released once the resumed renderer ends.
    let restored = test_state(ECHO_SOURCE, &db, |config| config);
    let restored_workspace = restored.workspace().to_path_buf();
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
    restored.cleanup();
    assert!(
        !restored_workspace.exists(),
        "explicit cleanup must remove the resumed unique workspace"
    );
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
    gateway.cleanup();

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
    assert_eq!(
        sends
            .iter()
            .filter(|text| text.starts_with("[failed]"))
            .count(),
        1,
        "only the recovered interrupted run should fail: {sends:?}"
    );
    assert!(
        !sends
            .iter()
            .any(|text| text.contains("artifact_store_busy") || text.contains("already active")),
        "the resumed follow-up run must not collide on the parked worker's artifact flock or the session gate: {sends:?}"
    );
    adapter2.shutdown().await;
    restored.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
    gateway.cleanup();
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
