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
use rustscript_agent::config::TelegramConfig;
use rustscript_agent::gateway::telegram::{TelegramApi, TelegramError};
use serde_json::{Value, json};
use tokio::net::TcpListener;

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
    Path((_token, method)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    body: String,
) -> axum::response::Response {
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

/// Temporary gateway SQLite path under /mnt/TEMP/rustscript (workspace
/// rule: all development temporary state lives there).
fn telegram_db_path(label: &str) -> std::path::PathBuf {
    let root = std::path::PathBuf::from("/mnt/TEMP/rustscript/telegram-tests");
    std::fs::create_dir_all(&root).expect("telegram test root should be created");
    root.join(format!("{label}-{}.db", Uuid::new_v4()))
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

fn holding_config_and_source(port: u16) -> (AgentGatewayConfig, String) {
    let http = rustscript_vm::HttpConfig {
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_schemes: vec!["http".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
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
    (
        AgentGatewayConfig {
            http,
            ..AgentGatewayConfig::default()
        },
        source,
    )
}

#[tokio::test]
async fn adapter_resumes_undelivered_events_after_restart() {
    let (base, state) = spawn_fixture().await;
    let (port, _arrived, release_tx, holding) = spawn_holding_fixture();
    let (config, source) = holding_config_and_source(port);
    push_update(&state, fixture_json("updates_dm.json"));
    let db = telegram_db_path("resume");

    // Phase 1: the run emits one delta and parks inside an HTTP call.
    let gateway = test_state(&source, &db, |_config| config.clone());
    let adapter = spawn_adapter(gateway.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state.sent_texts().iter().any(|text| text == "before")
    })
    .await;
    adapter.shutdown().await;

    // Phase 2: the same durable state recovers the interrupted run (typed
    // recovery appends run.failed); the renderer resumes from the delivery
    // cursor and delivers the missing terminal output.
    let restored = test_state(&source, &db, |_config| config.clone());
    let adapter2 = spawn_adapter(restored.clone(), test_config(&base)).await;
    wait_until(std::time::Duration::from_secs(15), || {
        state
            .sent_texts()
            .iter()
            .any(|text| text.starts_with("[failed]"))
    })
    .await;
    assert_eq!(
        state
            .sent_texts()
            .iter()
            .filter(|text| *text == "before")
            .count(),
        1,
        "the already-delivered delta must not be re-sent"
    );
    adapter2.shutdown().await;
    let _ = release_tx.send(());
    holding.join().expect("holding fixture");
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
    let root = std::path::PathBuf::from("/mnt/TEMP/rustscript/telegram-tests");
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
