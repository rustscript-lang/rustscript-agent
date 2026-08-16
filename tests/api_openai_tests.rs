//! A7 OpenAI-compatible Chat Completions (`POST /v1/chat/completions`) —
//! HTTP end-to-end fixtures through the REAL router, the REAL AgentService
//! with the built-in production serial loop program (`rss/agent/main.rss`),
//! the REAL SQLite state, and a controllable scripted provider.
//!
//! The API layer only normalizes OpenAI inbound requests into the canonical
//! AgentService/session/run contract and renders canonical durable/live
//! events as OpenAI outbound responses; it never parses provider wire and
//! never bypasses the A5 loop.
//!
//! Coverage: buffered text, streamed text (SSE chunks + `[DONE]`), buffered
//! and streamed tool-call rounds with real usage and real tool execution,
//! typed provider errors, cancel and client-disconnect policy, malformed /
//! unknown-field / oversize / auth / rate-limit / idempotency boundaries,
//! and multi-turn canonical message normalization.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};
use rustscript_vm::{HttpConfig, IoPolicy};
use serde_json::{Value as JsonValue, json};
use tower::ServiceExt;

fn temporary_root(label: &str) -> PathBuf {
    let base = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/mnt/TEMP/rustscript/openai-api-tests"));
    let root = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temporary root should be created");
    root
}

// ---------------------------------------------------------------------------
// Scripted provider servers
// ---------------------------------------------------------------------------

struct ScriptedServer {
    port: u16,
    shutdown: mpsc::Sender<()>,
}

impl ScriptedServer {
    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

fn spawn_scripted_server(responses: Vec<(u16, String)>, delay_ms: u64) -> ScriptedServer {
    spawn_scripted_server_counted(responses, delay_ms).0
}

/// Like [`spawn_scripted_server_counted`] but also records every provider
/// request body (for asserting the exact wire the loop sent upstream).
fn spawn_scripted_server_capturing(
    responses: Vec<(u16, String)>,
    delay_ms: u64,
) -> (
    ScriptedServer,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Vec<String>>>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let served = Arc::new(AtomicUsize::new(0));
    let served_for_thread = Arc::clone(&served);
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_for_thread = Arc::clone(&captured);
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        let mut round = 0usize;
        loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    served_for_thread.fetch_add(1, Ordering::SeqCst);
                    let body = read_request_body_captured(&mut stream);
                    captured_for_thread
                        .lock()
                        .expect("captured bodies lock")
                        .push(body);
                    if delay_ms > 0 {
                        thread::sleep(Duration::from_millis(delay_ms));
                    }
                    let (status, body) = responses.get(round).cloned().unwrap_or_else(|| {
                        responses.last().cloned().unwrap_or((200, String::new()))
                    });
                    round += 1;
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
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    (
        ScriptedServer {
            port,
            shutdown: shutdown_tx,
        },
        served,
        captured,
    )
}

/// Like [`spawn_scripted_server`] but also returns a counter of accepted
/// provider connections — one connection per provider round, so tests can
/// assert exact-once provider call counts across replays.
fn spawn_scripted_server_counted(
    responses: Vec<(u16, String)>,
    delay_ms: u64,
) -> (ScriptedServer, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let served = Arc::new(AtomicUsize::new(0));
    let served_for_thread = Arc::clone(&served);
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        let mut round = 0usize;
        loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    served_for_thread.fetch_add(1, Ordering::SeqCst);
                    read_request_body(&mut stream);
                    if delay_ms > 0 {
                        thread::sleep(Duration::from_millis(delay_ms));
                    }
                    let (status, body) = responses.get(round).cloned().unwrap_or_else(|| {
                        responses.last().cloned().unwrap_or((200, String::new()))
                    });
                    round += 1;
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
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    (
        ScriptedServer {
            port,
            shutdown: shutdown_tx,
        },
        served,
    )
}

fn spawn_scripted_sse_server(responses: Vec<String>, delay_ms: u64) -> ScriptedServer {
    spawn_scripted_sse_server_counted(responses, delay_ms).0
}

/// Like [`spawn_scripted_sse_server`] but also returns a counter of accepted
/// provider connections (one connection per provider round).
fn spawn_scripted_sse_server_counted(
    responses: Vec<String>,
    delay_ms: u64,
) -> (ScriptedServer, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let served = Arc::new(AtomicUsize::new(0));
    let served_for_thread = Arc::clone(&served);
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        let mut round = 0usize;
        loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    served_for_thread.fetch_add(1, Ordering::SeqCst);
                    read_request_body(&mut stream);
                    if delay_ms > 0 {
                        thread::sleep(Duration::from_millis(delay_ms));
                    }
                    let body = responses
                        .get(round)
                        .cloned()
                        .unwrap_or_else(|| responses.last().cloned().unwrap_or_default());
                    round += 1;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    (
        ScriptedServer {
            port,
            shutdown: shutdown_tx,
        },
        served,
    )
}

fn read_request_body(stream: &mut std::net::TcpStream) {
    let _ = read_request_body_captured(stream);
}

/// Reads one full HTTP request (headers + body) and returns the raw body
/// bytes as a string (for asserting the exact provider wire).
fn read_request_body_captured(stream: &mut std::net::TcpStream) -> String {
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
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&request);
    let head_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let start = (head_end + 4).min(text.len());
    text[start..].to_string()
}

// ---------------------------------------------------------------------------
// Wire fixtures (the scripted upstream provider's OpenAI Chat wire)
// ---------------------------------------------------------------------------

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

fn wire_tool_calls(calls: JsonValue) -> String {
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

fn wire_error(status: u16, error_type: &str, code: &str, message: &str) -> (u16, String) {
    (
        status,
        json!({"error": {"type": error_type, "code": code, "message": message}}).to_string(),
    )
}

fn tool_call(id: &str, name: &str, arguments: JsonValue) -> JsonValue {
    json!({
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": arguments.to_string()}
    })
}

fn sse_text_stream_chunked(text: &str, chunk_size: usize) -> String {
    let mut body = String::new();
    for (index, chunk) in text.as_bytes().chunks(chunk_size).enumerate() {
        let content = String::from_utf8(chunk.to_vec()).expect("test text is UTF-8");
        let mut delta = json!({"content": content});
        if index == 0 {
            delta["role"] = json!("assistant");
        }
        body.push_str(&format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-long",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": delta, "finish_reason": null}]
            })
        ));
    }
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-long",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        })
    ));
    body.push_str("data: [DONE]\n\n");
    body
}

fn sse_text_stream(text: &str) -> String {
    let mut body = String::new();
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-3",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}]
        })
    ));
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-3",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        })
    ));
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-3",
            "object": "chat.completion.chunk",
            "choices": [],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })
    ));
    body.push_str("data: [DONE]\n\n");
    body
}

fn sse_tool_stream(call: &JsonValue) -> String {
    let mut body = String::new();
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-4",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [call]}, "finish_reason": null}]
        })
    ));
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-4",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
        })
    ));
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-4",
            "object": "chat.completion.chunk",
            "choices": [],
            "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4}
        })
    ));
    body.push_str("data: [DONE]\n\n");
    body
}

// ---------------------------------------------------------------------------
// Gateway harness: real state + real SQLite + built-in agent program
// ---------------------------------------------------------------------------

fn spawn_state(
    server_port: u16,
    root: &std::path::Path,
    mutate: impl FnOnce(&mut AgentGatewayConfig),
) -> AgentGatewayState {
    let mut config = AgentGatewayConfig {
        provider: Some("openai_chat".to_string()),
        model: "test-model".to_string(),
        provider_options: json!({
            "base_url": format!("http://127.0.0.1:{server_port}"),
            "api_key": "test-key",
            "model": "test-model"
        }),
        http: HttpConfig {
            allowed_schemes: vec!["http".to_string()],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            allowed_ports: vec![server_port],
            allow_private_ips: true,
            ..HttpConfig::default()
        },
        io: IoPolicy {
            allowed_roots: vec![root.to_string_lossy().into_owned()],
            allow_write: true,
            allow_process: false,
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 1024 * 1024,
        },
        run_timeout: Duration::from_secs(60),
        base_retry_delay_ms: 20,
        max_retry_delay_ms: 40,
        ..AgentGatewayConfig::default()
    };
    mutate(&mut config);
    AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
        .expect("gateway state with the built-in agent program")
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// One POST /v1/chat/completions request; returns (status, JSON body).
async fn chat_completion(
    app: &axum::Router,
    body: JsonValue,
    bearer: Option<&str>,
) -> (StatusCode, JsonValue) {
    let (status, response) = chat_raw(app, body, bearer).await;
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "response should be JSON: {error} ({})",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

/// One raw POST /v1/chat/completions request (headers readable before the
/// body is consumed — needed for streaming and disconnect tests).
async fn chat_raw(
    app: &axum::Router,
    body: JsonValue,
    bearer: Option<&str>,
) -> (StatusCode, axum::response::Response) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    (response.status(), response)
}

async fn get_request(
    app: &axum::Router,
    uri: &str,
    bearer: Option<&str>,
) -> (StatusCode, JsonValue) {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request should build"))
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

async fn post_request(
    app: &axum::Router,
    uri: &str,
    body: Option<JsonValue>,
    bearer: Option<&str>,
) -> (StatusCode, JsonValue) {
    let mut builder = Request::builder().method(Method::POST).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).expect("request should build"))
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

/// Polls GET /v1/runs until a run exists (any status — a disconnect can
/// cancel a run before the poll observes it); returns its run_id.
async fn wait_for_active_run(app: &axum::Router, deadline: Duration) -> String {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        let (status, body) = get_request(app, "/v1/runs", None).await;
        assert_eq!(status, StatusCode::OK, "run list must answer");
        if let Some(runs) = body["data"].as_array()
            && let Some(run) = runs.first()
        {
            return run["run_id"].as_str().expect("run id").to_string();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no run appeared within {deadline:?}");
}

async fn wait_for_run_status(app: &axum::Router, run_id: &str, expected: &str, deadline: Duration) {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        let (status, view) = get_request(app, &format!("/v1/runs/{run_id}"), None).await;
        assert_eq!(status, StatusCode::OK, "run status endpoint must answer");
        if view["status"] == json!(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("run {run_id} did not reach durable status {expected} within {deadline:?}");
}

/// The durable `run.cancelled` event's `reason` for one run (via the typed
/// event replay), or `None` when no such event exists yet.
async fn durable_cancel_reason(state: &AgentGatewayState, run_id: &str) -> Option<String> {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .event_replay(&json!({
            "run_id": run_id,
            "after_seq": 1,
            "max_events": 512,
            "max_bytes": 65536,
        }))
        .expect("event replay");
    let mut reason = None;
    if let Some(rows) = data.get("rows").and_then(JsonValue::as_array) {
        for row in rows {
            if let Some(row) = row.as_array()
                && row.get(3).and_then(JsonValue::as_str) == Some("run.cancelled")
            {
                let payload: JsonValue =
                    serde_json::from_str(row.get(4).and_then(JsonValue::as_str).unwrap_or("{}"))
                        .unwrap_or(JsonValue::Null);
                reason = payload["reason"].as_str().map(str::to_string);
            }
        }
    }
    reason
}

fn file_write_tool() -> JsonValue {
    json!({
        "type": "function",
        "function": {
            "name": "file.write",
            "description": "write a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["path", "content"]
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Cycle 1 (RED): buffered text completion
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_buffered_text_completion_returns_the_official_shape() {
    let root = temporary_root("openai-buffered-text");
    let server = spawn_scripted_server(vec![(200, wire_text("hello from the agent"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, body) = chat_completion(
        &app,
        json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], json!("chat.completion"));
    assert_eq!(body["model"], json!("test-model"));
    assert!(body["id"].is_string(), "the completion id must be a string");
    assert!(body["created"].is_number());
    assert_eq!(body["choices"][0]["index"], json!(0));
    assert_eq!(
        body["choices"][0]["message"]["content"],
        json!("hello from the agent")
    );
    assert_eq!(body["choices"][0]["message"]["role"], json!("assistant"));
    assert_eq!(body["choices"][0]["finish_reason"], json!("stop"));
    // Usage comes from the canonical provider events, never fabricated.
    assert_eq!(body["usage"]["prompt_tokens"], json!(1));
    assert_eq!(body["usage"]["completion_tokens"], json!(1));
    assert_eq!(body["usage"]["total_tokens"], json!(2));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_buffered_model_override_flows_typed_into_the_loop() {
    let root = temporary_root("openai-model-override");
    let server = spawn_scripted_server(vec![(200, wire_text("ok"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, body) = chat_completion(
        &app,
        json!({
            "model": "deepseek-v4-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["model"], json!("deepseek-v4-flash"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Cycle 2 (RED): streamed text completion
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_stream_text_completion_emits_sse_chunks_and_done() {
    let root = temporary_root("openai-stream-text");
    let server = spawn_scripted_sse_server(vec![sse_text_stream("streamed hello")], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, response) = chat_raw(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true,
            "stream_options": {"include_usage": true}
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(bytes.to_vec()).expect("SSE body should be UTF-8");
    // SSE blocks may carry an `id:` line before the `data:` line (each
    // chunk carries the durable event sequence as the Last-Event id).
    let payloads = text
        .split("\n\n")
        .filter_map(|block| block.lines().find_map(|line| line.strip_prefix("data: ")))
        .collect::<Vec<_>>();

    let parsed = payloads
        .iter()
        .filter(|payload| **payload != "[DONE]")
        .map(|payload| {
            serde_json::from_str::<JsonValue>(payload).expect("chunk payload should be JSON")
        })
        .collect::<Vec<_>>();
    assert!(
        parsed
            .iter()
            .any(|payload| payload["object"] == "chat.completion.chunk"),
        "chunks must be chat.completion.chunk objects"
    );
    assert!(
        parsed.iter().any(
            |payload| payload["choices"][0]["delta"]["role"] == "assistant"
                && payload["choices"][0]["delta"]["content"] == "streamed hello"
        ),
        "the text delta must be streamed: {text}"
    );
    // include_usage: the final usage chunk precedes [DONE].
    let usage_chunk = payloads
        .iter()
        .find(|payload| payload.contains("\"usage\"") && payload.contains("\"prompt_tokens\":1"))
        .expect("include_usage must emit a usage chunk");
    assert!(usage_chunk.contains("\"choices\":[]"));
    assert_eq!(
        payloads.last().copied(),
        Some("[DONE]"),
        "[DONE] must be the last event"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_stream_output_over_one_megabyte_fails_typed_without_success_terminal() {
    let root = temporary_root("openai-stream-output-limit");
    let oversized = "x".repeat(1_048_577);
    let server = spawn_scripted_sse_server(vec![sse_text_stream_chunked(&oversized, 32 * 1024)], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, response) = chat_raw(
        &app,
        json!({
            "messages": [{"role": "user", "content": "large output"}],
            "stream": true
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(bytes.to_vec()).expect("SSE body should be UTF-8");
    assert!(
        text.contains("\"code\":\"output_too_large\""),
        "typed output limit error required: {text}"
    );
    assert!(
        text.trim_end().ends_with("data: [DONE]"),
        "SSE must finish with [DONE]: {text}"
    );
    assert!(
        !text.contains("\"finish_reason\":\"stop\""),
        "oversized output must not report success: {text}"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Cycle 3 (RED): tool calls + usage (buffered and streamed)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_buffered_tool_round_does_not_leak_internal_tool_calls() {
    let root = temporary_root("openai-buffered-tools");
    std::fs::write(root.join("input.txt"), "tool input").expect("seed the input file");
    let (server, served) = spawn_scripted_server_counted(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.read",
                    json!({"path": root.join("input.txt").to_string_lossy().into_owned()})
                )])),
            ),
            (200, wire_text("the tool ran and the answer is final")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "read the file"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "file.read",
                    "description": "read a file",
                    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
                }
            }],
            "tool_choice": "auto",
            "stream": false
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["choices"][0]["message"]["content"],
        json!("the tool ran and the answer is final")
    );
    // The A5 loop executed the tool round INTERNALLY: the client-visible
    // completion renders ONLY the final provider round, so no internal
    // tool call may leak into message.tool_calls.
    assert!(
        body["choices"][0]["message"]["tool_calls"].is_null(),
        "internal tool rounds must never leak as client tool_calls: {body}"
    );
    assert_eq!(body["choices"][0]["finish_reason"], json!("stop"));
    // Usage comes from the FINAL provider round's canonical events.
    assert_eq!(body["usage"]["total_tokens"], json!(2));
    // Exactly two provider calls: the internal tool round + the final text
    // round. A replayed or double-spawned worker would call more.
    assert_eq!(served.load(Ordering::SeqCst), 2);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_stream_tool_round_streams_only_the_final_round() {
    let root = temporary_root("openai-stream-tools");
    let call = tool_call(
        "call-2",
        "file.write",
        json!({"path": root.join("written.txt").to_string_lossy().into_owned(), "content": "written via stream"}),
    );
    let (server, served) = spawn_scripted_sse_server_counted(
        vec![sse_tool_stream(&call), sse_text_stream("write completed")],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        // file.write is write-risk; the all mode approves it without a park.
        config.approval_mode = "all".to_string();
    });
    let app = build_agent_gateway_app(state);

    let (status, response) = chat_raw(
        &app,
        json!({
            "messages": [{"role": "user", "content": "write the file"}],
            "tools": [file_write_tool()],
            "tool_choice": "auto",
            "stream": true,
            "stream_options": {"include_usage": false}
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(bytes.to_vec()).expect("SSE body should be UTF-8");
    let payloads = text
        .split("\n\n")
        .filter_map(|block| block.lines().find_map(|line| line.strip_prefix("data: ")))
        .collect::<Vec<_>>();

    let parsed = payloads
        .iter()
        .filter(|payload| **payload != "[DONE]")
        .map(|payload| {
            serde_json::from_str::<JsonValue>(payload).expect("chunk payload should be JSON")
        })
        .collect::<Vec<_>>();
    // The A5 loop executed the tool round INTERNALLY: the client-visible
    // stream renders ONLY the final provider round, so no internal tool-call
    // delta may be streamed to the client.
    assert!(
        !parsed
            .iter()
            .any(|payload| payload["choices"][0]["delta"]["tool_calls"].is_array()),
        "internal tool rounds must never leak as streamed tool_calls: {text}"
    );
    assert!(
        parsed
            .iter()
            .any(|payload| payload["choices"][0]["delta"]["content"] == "write completed"),
        "the final text delta must be streamed: {text}"
    );
    // The FIRST streamed chunk carries the assistant role (OpenAI delta
    // contract for the first chunk of a response).
    let first = parsed
        .first()
        .expect("at least the final text chunk must be streamed");
    assert_eq!(
        first["choices"][0]["delta"]["role"],
        json!("assistant"),
        "the first chunk must carry the assistant role: {text}"
    );
    // include_usage omitted: no usage chunk, but [DONE] still terminates.
    assert!(
        !payloads.iter().any(|payload| payload.contains("\"usage\"")),
        "usage must be omitted without include_usage: {text}"
    );
    assert_eq!(payloads.last().copied(), Some("[DONE]"));
    // The A5 loop really executed the tool through the bounded harness —
    // exactly once (a second worker would write and call the provider twice).
    assert_eq!(
        std::fs::read_to_string(root.join("written.txt")).expect("written file"),
        "written via stream"
    );
    assert_eq!(served.load(Ordering::SeqCst), 2);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Cycle 4 (RED): typed provider error, cancel, disconnect
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_provider_error_is_a_typed_gateway_error() {
    let root = temporary_root("openai-provider-error");
    let server = spawn_scripted_server(
        vec![wire_error(
            500,
            "server_error",
            "model_not_found",
            "the model does not exist",
        )],
        0,
    );
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"]["code"], json!("model_not_found"));
    assert_eq!(body["error"]["type"], json!("server_error"));
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("does not exist"))
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_cancel_via_stop_returns_a_typed_cancelled_error() {
    let root = temporary_root("openai-cancel");
    let server = spawn_scripted_server(vec![(200, wire_text("too late"))], 3_000);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let app_for_chat = app.clone();
    let chat = tokio::spawn(async move {
        chat_completion(
            &app_for_chat,
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "stream": false
            }),
            None,
        )
        .await
    });
    let run_id = wait_for_active_run(&app, Duration::from_secs(30)).await;
    let (stop_status, _) = post_request(&app, &format!("/v1/runs/{run_id}/stop"), None, None).await;
    assert_eq!(stop_status, StatusCode::OK);

    let (status, body) = chat
        .await
        .expect("the chat request must resolve after the stop");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], json!("run_cancelled"));
    assert_eq!(body["error"]["message"], json!("requested"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_client_disconnect_cancels_the_run_when_configured() {
    let root = temporary_root("openai-disconnect");
    let server = spawn_scripted_server(vec![(200, wire_text("nobody hears"))], 3_000);
    let state = spawn_state(server.port(), &root, |config| {
        config.client_disconnect_policy =
            rustscript_agent::config::ClientDisconnectPolicy::CancelOnDisconnect;
    });
    let app = build_agent_gateway_app(state.clone());

    let (status, response) = chat_raw(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The client disconnects before any terminal: the body (and the SSE
    // subscriber guard inside it) is dropped while the run is still active.
    drop(response);

    // The last-subscriber disconnect requests the typed client_disconnect
    // cancellation exactly once.
    let run_id = wait_for_active_run(&app, Duration::from_secs(10)).await;
    wait_for_run_status(&app, &run_id, "cancelled", Duration::from_secs(30)).await;
    let started = std::time::Instant::now();
    let reason = loop {
        if let Some(reason) = durable_cancel_reason(&state, &run_id).await {
            break reason;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "cancelled event missing"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(reason, "client_disconnect");

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Cycle 5 (RED): malformed / unknown fields / oversize / auth / rate /
// idempotency / multi-turn canonical messages
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_malformed_and_invalid_requests_are_rejected_typed() {
    let root = temporary_root("openai-malformed");
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    // Malformed JSON: typed 400 before any service work.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body readable");
    let body: JsonValue = serde_json::from_slice(&bytes).expect("error body should be JSON");
    assert_eq!(body["error"]["code"], json!("invalid_json"));

    // Unknown top-level field: rejected typed (explicit unknown-field policy).
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hi"}],
            "bogus_field": 42
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("unknown_field"));

    // Reserved provider-configuration fields can never be overridden by the
    // client (secret/base_url/allowlist live in the gateway config only).
    for reserved in [
        "provider",
        "provider_options",
        "base_url",
        "api_key",
        "allowlist",
    ] {
        let (status, body) = chat_completion(
            &app,
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                reserved: "anything"
            }),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{reserved} must be rejected"
        );
        assert_eq!(body["error"]["code"], json!("reserved_field"));
    }

    // Unknown message role.
    let (status, body) = chat_completion(
        &app,
        json!({"messages": [{"role": "wizard", "content": "hi"}]}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("invalid_role"));

    // The last message must be a user message (OpenAI contract).
    let (status, body) = chat_completion(
        &app,
        json!({"messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "yo"}]}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("last_message_not_user"));

    // A tool message without a matching prior assistant tool call (the
    // tool message must not be last, so the pairing check is what fires).
    let (status, body) = chat_completion(
        &app,
        json!({"messages": [
            {"role": "user", "content": "hi"},
            {"role": "tool", "tool_call_id": "call-ghost", "content": "result"},
            {"role": "user", "content": "go"}
        ]}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("tool_call_id_not_declared"));

    // Object tool_choice (a specific function) is not part of the canonical
    // string|null contract: typed unsupported, never silently ignored.
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "function", "function": {"name": "file.read"}}
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("unsupported_tool_choice"));

    // Out-of-range sampling bound.
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 5.0
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("out_of_range"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_oversize_body_is_rejected_by_the_body_limit() {
    let root = temporary_root("openai-oversize");
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 0);
    let state = spawn_state(server.port(), &root, |config| {
        config.max_body_bytes = 2048;
    });
    let app = build_agent_gateway_app(state);

    let big_content = "x".repeat(4096);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"messages": [{"role": "user", "content": big_content}]}).to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("body-limit errors carry x-request-id")
        .to_string();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body-limit error body should be readable");
    let error: JsonValue = serde_json::from_slice(&body).expect("OpenAI error should be JSON");
    assert_eq!(error["error"]["type"], json!("invalid_request_error"));
    assert_eq!(error["error"]["request_id"], json!(request_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_bearer_and_rate_limits_apply() {
    let root = temporary_root("openai-rate");
    let server = spawn_scripted_server(vec![(200, wire_text("limited"))], 0);
    let state = spawn_state(server.port(), &root, |config| {
        config.bearer_token = Some("test-token".to_string());
        config.rate_limit = rustscript_agent::config::RateLimitConfig {
            enabled: true,
            ip_burst: 10,
            account_burst: 2,
            window: Duration::from_secs(60),
            max_buckets: 16,
        };
    });
    let app = build_agent_gateway_app(state);

    let (status, _) = chat_completion(
        &app,
        json!({"messages": [{"role": "user", "content": "hi"}]}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = chat_completion(
        &app,
        json!({"messages": [{"role": "user", "content": "hi"}]}),
        Some("wrong-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = chat_completion(
        &app,
        json!({"messages": [{"role": "user", "content": "one"}]}),
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = chat_completion(
        &app,
        json!({"messages": [{"role": "user", "content": "two"}]}),
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The third verified request exceeds the account burst.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-token")
                .body(Body::from(
                    json!({"messages": [{"role": "user", "content": "three"}]}).to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().get("retry-after").is_some());

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_idempotency_key_replays_the_same_run() {
    let root = temporary_root("openai-idempotency");
    let server = spawn_scripted_server(vec![(200, wire_text("same answer"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let body = json!({
        "messages": [{"role": "user", "content": "hello"}],
        "stream": false
    });
    let (status, first) = chat_completion_with_key(&app, body.clone(), "key-1").await;
    assert_eq!(status, StatusCode::OK);
    let (status, second) = chat_completion_with_key(&app, body, "key-1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        first["id"], second["id"],
        "the same idempotency key must replay the same run"
    );
    assert_eq!(
        first["choices"][0]["message"]["content"],
        second["choices"][0]["message"]["content"]
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

async fn chat_completion_with_key(
    app: &axum::Router,
    body: JsonValue,
    key: &str,
) -> (StatusCode, JsonValue) {
    let builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("idempotency-key", key);
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&bytes).expect("response should be JSON"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_multi_turn_messages_normalize_into_canonical_history() {
    let root = temporary_root("openai-multi-turn");
    let server = spawn_scripted_server(vec![(200, wire_text("multi-turn answer"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [
                {"role": "system", "content": "you are terse"},
                {"role": "user", "content": "first question"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call-1", "type": "function", "function": {"name": "file.read", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call-1", "content": "the file content"},
                {"role": "user", "content": "second question"}
            ],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["choices"][0]["message"]["content"],
        json!("multi-turn answer")
    );

    // The canonical session carries the normalized roles and content parts.
    let run_id = body["id"].as_str().expect("completion id");
    let (run_status, run) = get_request(&app, &format!("/v1/runs/{run_id}"), None).await;
    assert_eq!(run_status, StatusCode::OK);
    let session_id = run["session_id"].as_str().expect("session id");
    let (messages_status, messages) =
        get_request(&app, &format!("/api/sessions/{session_id}/messages"), None).await;
    assert_eq!(messages_status, StatusCode::OK);
    let data = messages["data"].as_array().expect("messages array");
    let roles = data
        .iter()
        .map(|message| message["role"].as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>();
    // The pre-appended canonical history, plus the run's terminal assistant
    // message (the completion answer) appended by the durable terminal.
    assert_eq!(
        roles,
        vec!["system", "user", "assistant", "tool", "user", "assistant"]
    );
    // The assistant message carries the canonical tool_call part.
    let assistant = &data[2];
    let parts = assistant["content"].as_array().expect("content parts");
    assert_eq!(parts[0]["type"], json!("tool_call"));
    assert_eq!(parts[0]["tool_call_id"], json!("call-1"));
    assert_eq!(parts[0]["name"], json!("file.read"));
    assert_eq!(parts[0]["arguments_json"], json!("{}"));
    // The tool message carries the canonical tool_result part with the
    // message-level pair id.
    let tool = &data[3];
    assert_eq!(tool["tool_call_id"], json!("call-1"));
    let parts = tool["content"].as_array().expect("content parts");
    assert_eq!(parts[0]["type"], json!("tool_result"));
    assert_eq!(parts[0]["tool_call_id"], json!("call-1"));
    assert_eq!(parts[0]["content"], json!("the file content"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Cycle 6 (RED): OpenAI API review findings — exact-once replay, final-round
// rendering, transactional sessions, sampling ranges, SSE contract
// ---------------------------------------------------------------------------

/// GET /api/sessions data length (in-memory session count).
async fn session_count(app: &axum::Router) -> usize {
    let (status, body) = get_request(app, "/api/sessions", None).await;
    assert_eq!(status, StatusCode::OK, "session list must answer");
    body["data"].as_array().expect("sessions array").len()
}

/// POST /v1/chat/completions with an inbound `x-request-id` header.
async fn chat_completion_with_request_id(
    app: &axum::Router,
    body: JsonValue,
    request_id: &str,
) -> (StatusCode, axum::response::Response) {
    let builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-request-id", request_id);
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    (response.status(), response)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_idempotent_replay_while_inflight_never_spawns_a_second_worker() {
    let root = temporary_root("openai-replay-inflight");
    let (server, served) =
        spawn_scripted_server_counted(vec![(200, wire_text("same answer"))], 1_500);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let body = json!({
        "messages": [{"role": "user", "content": "hello"}],
        "stream": false
    });
    let body_for_first = body.clone();
    let first_app = app.clone();
    let first = tokio::spawn(async move {
        chat_completion_with_key(&first_app, body_for_first, "key-inflight").await
    });
    // The first run is in flight (the provider sleeps 1.5s per round).
    let _run_id = wait_for_active_run(&app, Duration::from_secs(30)).await;
    let (status, replayed) = chat_completion_with_key(&app, body, "key-inflight").await;
    assert_eq!(status, StatusCode::OK);
    let (first_status, first_body) = first.await.expect("first request resolves");
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(
        first_body["id"], replayed["id"],
        "the replay must answer the SAME run"
    );
    assert_eq!(
        first_body["choices"][0]["message"]["content"],
        replayed["choices"][0]["message"]["content"]
    );
    // The replay must never spawn a second worker: the provider was called
    // exactly once for the whole run (a second worker would call it again).
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "a replayed admission must never spawn a second worker (provider calls)"
    );
    // And the replay created no second session.
    assert_eq!(session_count(&app).await, 1);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_idempotent_replay_is_checked_before_a_full_capacity_permit() {
    let root = temporary_root("openai-replay-before-permit");
    let (server, served) =
        spawn_scripted_server_counted(vec![(200, wire_text("same answer"))], 1_500);
    let state = spawn_state(server.port(), &root, |config| {
        config.max_concurrent_runs = 1;
    });
    let app = build_agent_gateway_app(state);

    let body = json!({
        "messages": [{"role": "user", "content": "hello"}],
        "stream": false
    });
    let first_app = app.clone();
    let first_body = body.clone();
    let first = tokio::spawn(async move {
        chat_completion_with_key(&first_app, first_body, "key-capacity-replay").await
    });
    wait_for_active_run(&app, Duration::from_secs(30)).await;

    // The only permit is occupied by the original request. A replay must
    // still attach to that run; it is not a new admission and must not be
    // rejected by the bounded new-run capacity gate.
    let (status, replay) = chat_completion_with_key(&app, body, "key-capacity-replay").await;
    assert_eq!(status, StatusCode::OK);
    let (first_status, first_body) = first.await.expect("first request resolves");
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(replay["id"], first_body["id"]);
    assert_eq!(served.load(Ordering::SeqCst), 1);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_concurrent_same_key_replays_create_one_session_one_worker() {
    let root = temporary_root("openai-concurrent-replay");
    let (server, served) = spawn_scripted_server_counted(vec![(200, wire_text("one run"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let body = json!({
        "messages": [{"role": "user", "content": "hello"}],
        "stream": false
    });
    let app_a = app.clone();
    let app_b = app.clone();
    let body_a = body.clone();
    let body_b = body.clone();
    let (first, second) = tokio::join!(
        tokio::spawn(async move { chat_completion_with_key(&app_a, body_a, "key-race").await }),
        tokio::spawn(async move { chat_completion_with_key(&app_b, body_b, "key-race").await })
    );
    let (first_status, first_body) = first.expect("first concurrent request resolves");
    let (second_status, second_body) = second.expect("second concurrent request resolves");
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(
        first_body["id"], second_body["id"],
        "concurrent replays of one key must answer the same run"
    );
    // Exactly one session, exactly one worker (one provider call), and the
    // tool/session side effects happened exactly once.
    assert_eq!(session_count(&app).await, 1);
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "concurrent replays must not spawn a second worker"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_rejected_and_failed_admissions_leave_no_orphan_sessions() {
    let root = temporary_root("openai-no-orphans");
    let (server, _served) = spawn_scripted_server_counted(vec![(200, wire_text("ok"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // 409: the same idempotency key with a DIFFERENT body is a typed
    // conflict — the replayed request must not have created a session.
    let (status, _) = chat_completion_with_key(
        &app,
        json!({"messages": [{"role": "user", "content": "hello"}], "stream": false}),
        "key-conflict",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = chat_completion_with_key(
        &app,
        json!({"messages": [{"role": "user", "content": "a different body"}], "stream": false}),
        "key-conflict",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("idempotency_key_reused"));
    assert_eq!(
        session_count(&app).await,
        1,
        "an idempotency conflict must not create an orphan session"
    );

    // 429: the run limit is checked before any durable work — the rejected
    // request must not create a session. The first request holds the only
    // capacity slot for ~2s (provider delay).
    let (slow, _) = spawn_scripted_server_counted(vec![(200, wire_text("slow"))], 2_000);
    let slow_state_root = root.join("slow-state");
    std::fs::create_dir_all(&slow_state_root).expect("slow-state root should be created");
    let state_slow = spawn_state(slow.port(), &slow_state_root, |config| {
        config.max_concurrent_runs = 1;
    });
    let app_slow = build_agent_gateway_app(state_slow);
    let hold_app = app_slow.clone();
    let hold = tokio::spawn(async move {
        chat_completion(
            &hold_app,
            json!({"messages": [{"role": "user", "content": "hold"}], "stream": false}),
            None,
        )
        .await
    });
    wait_for_active_run(&app_slow, Duration::from_secs(30)).await;
    let (status, body) = chat_completion(
        &app_slow,
        json!({"messages": [{"role": "user", "content": "limited"}], "stream": false}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], json!("run_limit_reached"));
    let (hold_status, _) = hold.await.expect("held request resolves");
    assert_eq!(hold_status, StatusCode::OK);
    assert_eq!(
        session_count(&app_slow).await,
        1,
        "a run-limit rejection must not create an orphan session"
    );

    // Mid-failure: the storage worker dies before the admission transaction
    // commits — the request answers the typed persistence error and leaves
    // NO session behind (the transaction rolled back).
    let (server_dead, _) = spawn_scripted_server_counted(vec![(200, wire_text("unused"))], 0);
    let dead_state_root = root.join("dead-state");
    std::fs::create_dir_all(&dead_state_root).expect("dead-state root should be created");
    let state_dead = spawn_state(server_dead.port(), &dead_state_root, |_| {});
    let app_dead = build_agent_gateway_app(state_dead.clone());
    state_dead
        .persistence()
        .expect("durable persistence")
        .shutdown();
    let (status, body) = chat_completion(
        &app_dead,
        json!({"messages": [{"role": "user", "content": "hello"}], "stream": false}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], json!("persistence_unavailable"));
    assert_eq!(
        session_count(&app_dead).await,
        0,
        "a mid-admission storage failure must leave no partial session"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_tool_message_array_content_is_preserved_and_other_parts_rejected() {
    let root = temporary_root("openai-tool-array-content");
    let (server, _) = spawn_scripted_server_counted(vec![(200, wire_text("ok"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    // A tool message with an ARRAY of legal text parts: the text is
    // preserved with fidelity (joined in order into the tool result).
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [
                {"role": "user", "content": "run it"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call-arr", "type": "function", "function": {"name": "file.read", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call-arr", "content": [
                    {"type": "text", "text": "part-a"},
                    {"type": "text", "text": "part-b"}
                ]},
                {"role": "user", "content": "continue"}
            ],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let run_id = body["id"].as_str().expect("completion id");
    let (run_status, run) = get_request(&app, &format!("/v1/runs/{run_id}"), None).await;
    assert_eq!(run_status, StatusCode::OK);
    let session_id = run["session_id"].as_str().expect("session id");
    let (messages_status, messages) =
        get_request(&app, &format!("/api/sessions/{session_id}/messages"), None).await;
    assert_eq!(messages_status, StatusCode::OK);
    let data = messages["data"].as_array().expect("messages array");
    let tool = data
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("the tool message must be persisted");
    let parts = tool["content"].as_array().expect("content parts");
    assert_eq!(parts[0]["type"], json!("tool_result"));
    assert_eq!(
        parts[0]["content"],
        json!("part-apart-b"),
        "legal text parts of a tool-role array content must be preserved with fidelity"
    );

    // A non-text part in a tool-role array content is rejected typed (never
    // silently dropped).
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [
                {"role": "user", "content": "run it"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call-img", "type": "function", "function": {"name": "file.read", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call-img", "content": [
                    {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}}
                ]},
                {"role": "user", "content": "continue"}
            ],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("unsupported_content_part"));

    // An object tool-role content is rejected typed.
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [
                {"role": "user", "content": "run it"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call-obj", "type": "function", "function": {"name": "file.read", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call-obj", "content": {"type": "text", "text": "nope"}},
                {"role": "user", "content": "continue"}
            ],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("invalid_content"));

    // A tool message as the LAST message is not a valid conversation ending
    // (the OpenAI contract requires a final user message).
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [
                {"role": "user", "content": "run it"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call-last", "type": "function", "function": {"name": "file.read", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call-last", "content": "result"}
            ],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!("last_message_not_user"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_sampling_bounds_match_the_official_ranges() {
    let root = temporary_root("openai-sampling-ranges");
    let (server, _) = spawn_scripted_server_counted(vec![(200, wire_text("ok"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    // temperature: official range [0, 2].
    for temperature in [-0.5, 2.5, 3.0] {
        let (status, body) = chat_completion(
            &app,
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                "temperature": temperature
            }),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "temperature {temperature} must be rejected"
        );
        assert_eq!(body["error"]["code"], json!("out_of_range"));
    }
    for temperature in [0.0, 1.0, 2.0] {
        let (status, _) = chat_completion(
            &app,
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                "temperature": temperature
            }),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "temperature {temperature} must be accepted"
        );
    }

    // top_p: official range [0, 1].
    for top_p in [-0.1, 1.5, 2.0] {
        let (status, body) = chat_completion(
            &app,
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                "top_p": top_p
            }),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "top_p {top_p} must be rejected"
        );
        assert_eq!(body["error"]["code"], json!("out_of_range"));
    }
    for top_p in [0.0, 0.5, 1.0] {
        let (status, _) = chat_completion(
            &app,
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                "top_p": top_p
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "top_p {top_p} must be accepted");
    }

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_idempotency_hash_includes_user() {
    let root = temporary_root("openai-hash-user");
    let (server, _) = spawn_scripted_server_counted(vec![(200, wire_text("ok"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, _) = chat_completion_with_key(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "user": "alice"
        }),
        "key-user",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The same key with a DIFFERENT `user` is a different request: the
    // canonical request hash must include the user metadata field.
    let (status, body) = chat_completion_with_key(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "user": "bob"
        }),
        "key-user",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("idempotency_key_reused"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_sse_responses_carry_x_request_id() {
    let root = temporary_root("openai-sse-request-id");
    let server = spawn_scripted_sse_server(vec![sse_text_stream("hello")], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let (status, response) = chat_completion_with_request_id(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true
        }),
        "req-abc-123",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req-abc-123"),
        "the SSE response must carry the bounded x-request-id"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_stream_provider_error_chunk_type_matches_the_buffered_contract() {
    let root = temporary_root("openai-stream-error-type");
    let server = spawn_scripted_server(
        vec![wire_error(
            500,
            "server_error",
            "model_not_found",
            "the model does not exist",
        )],
        0,
    );
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state.clone());

    let (status, response) = chat_raw(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(bytes.to_vec()).expect("SSE body should be UTF-8");
    let payloads = text
        .split("\n\n")
        .filter_map(|block| block.lines().find_map(|line| line.strip_prefix("data: ")))
        .collect::<Vec<_>>();
    let error_chunk = payloads
        .iter()
        .find(|payload| payload.contains("\"error\""))
        .expect("a typed error chunk must be streamed");
    let error: JsonValue = serde_json::from_str(error_chunk).expect("error chunk JSON");
    // The run id comes from the run list (the error chunk carries only the
    // OpenAI error envelope, like the buffered contract).
    let (runs_status, runs) = get_request(&app, "/v1/runs", None).await;
    assert_eq!(runs_status, StatusCode::OK);
    let run_id = runs["data"][0]["run_id"]
        .as_str()
        .expect("run id")
        .to_string();
    // The streamed error carries the SAME typed kind as the buffered
    // contract derives from the durable terminal: the provider's own error
    // type when the terminal carries a provider_error, else the typed
    // agent_error fallback — never a hardcoded, inconsistent kind.
    let durable = state
        .persistence()
        .expect("durable persistence")
        .event_replay(&json!({
            "run_id": run_id,
            "after_seq": 1,
            "max_events": 512,
            "max_bytes": 65536,
        }))
        .expect("event replay");
    let mut provider_type = None;
    let mut terminal_code = None;
    if let Some(rows) = durable.get("rows").and_then(JsonValue::as_array) {
        for row in rows {
            if let Some(row) = row.as_array()
                && row.get(3).and_then(JsonValue::as_str) == Some("run.failed")
            {
                let payload: JsonValue =
                    serde_json::from_str(row.get(4).and_then(JsonValue::as_str).unwrap_or("{}"))
                        .unwrap_or(JsonValue::Null);
                provider_type = payload["provider_error"]["type"]
                    .as_str()
                    .map(str::to_string);
                terminal_code = payload["error_code"].as_str().map(str::to_string);
            }
        }
    }
    let expected_type = provider_type.unwrap_or_else(|| "agent_error".to_string());
    assert_eq!(
        error["error"]["type"],
        json!(expected_type),
        "the streamed error chunk type must match the buffered derivation from the durable terminal"
    );
    assert_eq!(
        error["error"]["code"],
        json!(terminal_code.expect("the durable terminal must carry error_code")),
        "the streamed error chunk code must match the durable terminal's error_code"
    );
    assert_eq!(payloads.last().copied(), Some("[DONE]"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_stream_lagged_recovers_via_durable_catch_up_without_silent_loss() {
    let root = temporary_root("openai-stream-lagged");
    // One provider round that streams MANY deltas: the broadcast buffer
    // (capacity 1) overflows while the client has not polled the SSE body,
    // so the live receiver observes Lagged.
    let mut sse_body = String::new();
    for index in 0..10 {
        sse_body.push_str(&format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-lag",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": format!("delta-{index} ")}, "finish_reason": null}]
            })
        ));
    }
    sse_body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-lag",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        })
    ));
    sse_body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-lag",
            "object": "chat.completion.chunk",
            "choices": [],
            "usage": {"prompt_tokens": 1, "completion_tokens": 10, "total_tokens": 11}
        })
    ));
    sse_body.push_str("data: [DONE]\n\n");
    let server = spawn_scripted_sse_server(vec![sse_body], 0);
    let state = spawn_state(server.port(), &root, |config| {
        config.broadcast_capacity = 1;
    });
    let app = build_agent_gateway_app(state);

    let (status, response) = chat_raw(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true,
            "stream_options": {"include_usage": true}
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The client stalls long enough for the bounded live buffer to drop
    // events (the worker publishes the whole round in the meantime).
    tokio::time::sleep(Duration::from_millis(800)).await;
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(bytes.to_vec()).expect("SSE body should be UTF-8");
    let payloads = text
        .split("\n\n")
        .filter_map(|block| block.lines().find_map(|line| line.strip_prefix("data: ")))
        .collect::<Vec<_>>();
    // The Lagged stream recovers through the durable catch-up: no typed
    // event_lagged error, the final round's full text is delivered, and
    // [DONE] terminates.
    assert!(
        !payloads
            .iter()
            .any(|payload| payload.contains("event_lagged")),
        "Lagged must recover via durable catch-up, never an error chunk: {text}"
    );
    let parsed = payloads
        .iter()
        .filter(|payload| **payload != "[DONE]")
        .map(|payload| {
            serde_json::from_str::<JsonValue>(payload).expect("chunk payload should be JSON")
        })
        .collect::<Vec<_>>();
    let full_text = parsed
        .iter()
        .filter_map(|payload| payload["choices"][0]["delta"]["content"].as_str())
        .collect::<String>();
    assert_eq!(
        full_text,
        "delta-0 delta-1 delta-2 delta-3 delta-4 delta-5 delta-6 delta-7 delta-8 delta-9 ",
        "the final round's text must be delivered without silent loss"
    );
    assert!(
        parsed
            .iter()
            .any(|payload| payload["usage"]["total_tokens"] == json!(11)),
        "the usage chunk must be delivered"
    );
    assert_eq!(payloads.last().copied(), Some("[DONE]"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_buffered_long_terminal_output_rehydrates_from_durable_message() {
    let root = temporary_root("openai-long-buffered");
    let long_text = "buffered-long-output-".repeat(4_000);
    let (server, served, _) =
        spawn_scripted_server_capturing(vec![(200, wire_text(&long_text))], 0);
    let state = spawn_state(server.port(), &root, |config| {
        config.max_event_bytes = 1_024;
    });
    let app = build_agent_gateway_app(state);
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "long"}],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "buffered response: {body}");
    assert_eq!(body["choices"][0]["message"]["content"], json!(long_text));
    assert_eq!(served.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_stream_long_terminal_output_rehydrates_from_durable_message() {
    let root = temporary_root("openai-long-stream");
    let long_text = "stream-long-output-".repeat(4_000);
    let (server, served) =
        spawn_scripted_sse_server_counted(vec![sse_text_stream_chunked(&long_text, 4096)], 0);
    let state = spawn_state(server.port(), &root, |config| {
        config.max_event_bytes = 1_024;
    });
    let app = build_agent_gateway_app(state);
    let (status, response) = chat_raw(
        &app,
        json!({
            "messages": [{"role": "user", "content": "long"}],
            "stream": true
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8");
    let payloads = text
        .split("\n\n")
        .filter_map(|block| block.lines().find_map(|line| line.strip_prefix("data: ")))
        .filter(|payload| *payload != "[DONE]")
        .filter_map(|payload| serde_json::from_str::<JsonValue>(payload).ok())
        .collect::<Vec<_>>();
    let rendered = payloads
        .iter()
        .filter_map(|payload| payload["choices"][0]["delta"]["content"].as_str())
        .collect::<Vec<_>>()
        .join("");
    assert_eq!(rendered, long_text);
    assert_eq!(served.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// OpenAI's omission and an explicit empty `tools` array have the same
/// official meaning: no tools. Legacy/Telegram callers retain their registry
/// fallback policy outside this route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_empty_tools_array_and_omission_both_disable_tools() {
    let root = temporary_root("openai-tools-schema");
    let (server, served, captured) =
        spawn_scripted_server_capturing(vec![(200, wire_text("done"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    // Explicit `tools: []`: the upstream request must NOT declare tools.
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], json!("done"));

    // Omitted `tools`: the official no-tools semantics are preserved upstream.
    let (status, body) = chat_completion(
        &app,
        json!({
            "messages": [{"role": "user", "content": "hi"}],
            "stream": false
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["choices"][0]["message"]["content"], json!("done"));

    drop(app);
    assert_eq!(served.load(Ordering::SeqCst), 2, "two provider calls");
    let bodies = captured.lock().expect("captured bodies lock").clone();
    assert_eq!(bodies.len(), 2);
    let explicit: JsonValue = serde_json::from_str(&bodies[0]).expect("wire body is JSON");
    assert!(
        explicit.get("tools").is_none() || explicit["tools"].as_array().is_some_and(Vec::is_empty),
        "tools: [] must reach the provider as no tools, got {explicit}"
    );
    let omitted: JsonValue = serde_json::from_str(&bodies[1]).expect("wire body is JSON");
    assert!(
        omitted.get("tools").is_none() || omitted["tools"].as_array().is_some_and(Vec::is_empty),
        "omitted tools must reach the provider as no tools, got {omitted}"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}
