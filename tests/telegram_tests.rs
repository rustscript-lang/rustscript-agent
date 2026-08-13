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
        other => panic!("unknown fixture {other}"),
    })
    .expect("fixture JSON should parse")
}

fn test_config(api_base: &str) -> TelegramConfig {
    TelegramConfig {
        bot_token: "123456:TEST-SECRET-TOKEN".to_string(),
        api_base: api_base.to_string(),
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
