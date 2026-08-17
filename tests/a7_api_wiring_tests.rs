//! A7 API wiring — HTTP end-to-end fixtures through the REAL router, the
//! REAL AgentService with the built-in production serial loop program
//! (`rss/agent/main.rss`), the REAL SQLite state, and a controllable
//! scripted provider.
//!
//! Coverage: run status/list over the durable store (never a fabricated
//! `started`), approval approve/deny wired to
//! `AgentService::resolve_run_approval` (run + approval id, actor/reason,
//! exact-once / AlreadyResolved / expired typed states), session compact as
//! the REAL RSS-owned compaction (typed skip within the window, typed 409
//! while a run is active — never a fabricated commit), and the auth /
//! rate-limit / pagination / error-envelope / SSE replay boundaries.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
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
        .unwrap_or_else(|| std::env::temp_dir().join("rustscript-agent-a7-api-tests"));
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
// Scripted provider server (per-request responses, optional delay)
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
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    thread::spawn(move || {
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
                            Err(_) => break,
                        }
                    }
                    if delay_ms > 0 {
                        thread::sleep(Duration::from_millis(delay_ms));
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
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    ScriptedServer {
        port,
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

fn tool_call(id: &str, name: &str, arguments: JsonValue) -> JsonValue {
    json!({
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": arguments.to_string()}
    })
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
        stream: false,
        ..AgentGatewayConfig::default()
    };
    mutate(&mut config);
    AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
        .expect("gateway state with the built-in agent program")
}

/// One request with a JSON body through the real router (oneshot).
async fn json_request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: JsonValue,
) -> (StatusCode, JsonValue) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
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

/// One GET request with an optional bearer token.
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
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

/// POSTs a JSON body with an optional bearer token; returns (status, body).
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
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

/// Creates a run through the real API route and returns its run_id.
async fn create_run(app: &axum::Router, session_id: Option<&str>) -> String {
    let body = match session_id {
        Some(id) => json!({"session_id": id, "input": "hello"}),
        None => json!({"input": "hello"}),
    };
    let (status, run) = json_request(app, Method::POST, "/v1/runs", body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "run admission must accept");
    run["run_id"].as_str().expect("run id").to_string()
}

/// Polls GET /v1/runs/{run_id} until the durable status matches (or panics).
async fn wait_for_status(app: &axum::Router, run_id: &str, expected: &str, deadline: Duration) {
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

/// The durable approval row's `resolver` (column 13) and `decision_reason`
/// (column 14) for one approval id.
fn durable_approval_resolution(state: &AgentGatewayState, approval_id: &str) -> (String, String) {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .approval_get(approval_id)
        .expect("approval get must succeed");
    let row = data
        .get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .cloned()
        .expect("approval row");
    (
        row[13].as_str().unwrap_or("").to_string(),
        row[14].as_str().unwrap_or("").to_string(),
    )
}

/// The number of durable compaction rows for one session.
fn durable_compaction_count(state: &AgentGatewayState, session_id: &str) -> usize {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .compaction_latest(session_id)
        .expect("compaction.latest must succeed");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Cycle 2 (RED): approval approve/deny wiring
// ---------------------------------------------------------------------------

/// Polls the durable event replay until the run's `approval.required` event
/// carries the bridge-generated approval id.
async fn wait_for_approval_id(
    state: &AgentGatewayState,
    run_id: &str,
    deadline: Duration,
) -> String {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        let persistence = state.persistence().expect("durable persistence");
        let data = persistence
            .event_replay(&json!({
                "run_id": run_id,
                "after_seq": 1,
                "max_events": 512,
                "max_bytes": 65536,
            }))
            .expect("event replay");
        if let Some(rows) = data.get("rows").and_then(JsonValue::as_array) {
            for row in rows {
                if let Some(row) = row.as_array()
                    && row.get(3).and_then(JsonValue::as_str) == Some("approval.required")
                {
                    let payload: JsonValue = serde_json::from_str(
                        row.get(4).and_then(JsonValue::as_str).unwrap_or("{}"),
                    )
                    .unwrap_or(JsonValue::Null);
                    if let Some(id) = payload["approval_id"].as_str() {
                        return id.to_string();
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("approval.required event not found for run {run_id}");
}

/// Waits until the run HANDLE is terminal (the whole worker chain finished;
/// the durable status becomes visible a microsecond before the handle is
/// marked terminal, so tests that observed the status must also wait for the
/// handle before the runtime is dropped).
async fn wait_for_terminal_handle(state: &AgentGatewayState, run_id: &str, deadline: Duration) {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        if let Some(handle) = state.service().handle(run_id)
            && handle.is_terminal()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("run {run_id} did not reach a terminal handle within {deadline:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_approval_approve_resumes_and_completes_the_run() {
    let root = temporary_root("a7-approve");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("approved.txt"), "content": "approved"})
                )])),
            ),
            (200, wire_text("approved and done")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        config.approval_mode = "manual".to_string();
    });
    let app = build_agent_gateway_app(state.clone());

    let run_id = create_run(&app, None).await;
    wait_for_status(&app, &run_id, "waiting_approval", Duration::from_secs(30)).await;
    let approval_id = wait_for_approval_id(&state, &run_id, Duration::from_secs(30)).await;
    assert!(
        !root.join("approved.txt").exists(),
        "the tool must not run while waiting"
    );

    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/approve"),
        Some(json!({"actor": "reviewer-alice", "reason": "safe write"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("approved"));
    assert_eq!(body["run_id"], json!(run_id));
    assert_eq!(body["approval_id"], json!(approval_id));
    assert_eq!(body["actor"], json!("reviewer-alice"));
    assert_eq!(body["reason"], json!("safe write"));

    wait_for_status(&app, &run_id, "completed", Duration::from_secs(30)).await;
    wait_for_terminal_handle(&state, &run_id, Duration::from_secs(10)).await;
    assert_eq!(
        std::fs::read_to_string(root.join("approved.txt")).expect("written"),
        "approved"
    );
    // The actor and the reason are recorded on the durable approval row.
    let (resolver, reason) = durable_approval_resolution(&state, &approval_id);
    assert_eq!(resolver, "reviewer-alice");
    assert_eq!(reason, "safe write");

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_approval_resolution_errors_are_typed_and_exactly_once() {
    let root = temporary_root("a7-approve-errors");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("approved.txt"), "content": "approved"})
                )])),
            ),
            (200, wire_text("approved and done")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        config.approval_mode = "manual".to_string();
    });
    let app = build_agent_gateway_app(state.clone());

    let run_id = create_run(&app, None).await;
    wait_for_status(&app, &run_id, "waiting_approval", Duration::from_secs(30)).await;
    let approval_id = wait_for_approval_id(&state, &run_id, Duration::from_secs(30)).await;

    // Unknown run: 404 typed (even with a bogus approval id).
    let (status, body) = post_request(
        &app,
        "/v1/runs/never-existed/approvals/some-id/approve",
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], json!("run_not_found"));

    // Wrong approval id: typed conflict, and the park survives.
    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/wrong-id/approve"),
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("approval_id_mismatch"));

    // The correct id still resolves after the mismatch (park not consumed).
    let (status, _) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/approve"),
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    wait_for_status(&app, &run_id, "completed", Duration::from_secs(30)).await;
    wait_for_terminal_handle(&state, &run_id, Duration::from_secs(10)).await;

    // Exact-once: a second approve on the same id finds no park.
    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/approve"),
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("no_pending_approval"));

    // A run that was never parked (fresh run still spinning up) — the
    // durable status is running, not waiting_approval: typed conflict.
    let second = create_run(&app, None).await;
    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{second}/approvals/{approval_id}/approve"),
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("no_pending_approval"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_approval_deny_folds_the_denied_tool_result_and_continues() {
    let root = temporary_root("a7-deny");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("denied.txt"), "content": "denied"})
                )])),
            ),
            (200, wire_text("the tool was denied")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        config.approval_mode = "manual".to_string();
    });
    let app = build_agent_gateway_app(state.clone());

    let run_id = create_run(&app, None).await;
    wait_for_status(&app, &run_id, "waiting_approval", Duration::from_secs(30)).await;
    let approval_id = wait_for_approval_id(&state, &run_id, Duration::from_secs(30)).await;

    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/deny"),
        Some(json!({"actor": "reviewer-bob", "reason": "not allowed"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("denied"));
    assert_eq!(body["actor"], json!("reviewer-bob"));
    assert_eq!(body["reason"], json!("not allowed"));

    wait_for_status(&app, &run_id, "completed", Duration::from_secs(30)).await;
    wait_for_terminal_handle(&state, &run_id, Duration::from_secs(10)).await;
    assert!(
        !root.join("denied.txt").exists(),
        "the denied tool must never execute"
    );
    // The loop continued past the typed denial (the model answered).
    let (resolver, reason) = durable_approval_resolution(&state, &approval_id);
    assert_eq!(resolver, "reviewer-bob");
    assert_eq!(reason, "not allowed");

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Cycle 3 (RED): expiry, stop race, compact, security, SSE replay
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_approval_expiry_surfaces_typed_states_and_never_downgrades() {
    let root = temporary_root("a7-expiry");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("expired.txt"), "content": "expired"})
                )])),
            ),
            (200, wire_text("the approval expired")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        config.approval_mode = "manual".to_string();
        // The janitor must never race the test's deterministic expiry.
        config.janitor_interval = Duration::from_secs(60);
    });
    let app = build_agent_gateway_app(state.clone());

    let run_id = create_run(&app, None).await;
    wait_for_status(&app, &run_id, "waiting_approval", Duration::from_secs(30)).await;
    let approval_id = wait_for_approval_id(&state, &run_id, Duration::from_secs(30)).await;

    // Drive the durable expiry deterministically through the REAL storage
    // command the janitor uses (the row's expires_at is request + 600s).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    state
        .persistence()
        .expect("durable persistence")
        .approval_expire(&json!({"now_ms": now + 601_000}))
        .expect("approval.expire must succeed");

    // An approve on the expired row is the strict AlreadyResolved no-op
    // (the park is restored, never a downgrade to a deny).
    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/approve"),
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("already_resolved"));

    // A deny on the already-terminal row resumes with the typed expired
    // outcome (status `expired`, never a fabricated fresh deny).
    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/deny"),
        Some(json!({"actor": "reviewer-carol"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("expired"));

    wait_for_status(&app, &run_id, "completed", Duration::from_secs(30)).await;
    wait_for_terminal_handle(&state, &run_id, Duration::from_secs(10)).await;
    assert!(
        !root.join("expired.txt").exists(),
        "the expired approval must never execute the tool"
    );
    // The durable row stayed terminal (expired) — the late deny never
    // transitioned it, and the typed outcome was surfaced through the API.
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .approval_get(&approval_id)
        .expect("approval get must succeed");
    let row = data
        .get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .cloned()
        .expect("approval row");
    assert_eq!(row[7].as_str(), Some("expired"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_stop_racing_the_approval_park_cancels_and_resolution_is_rejected() {
    let root = temporary_root("a7-stop-race");
    // The provider stalls; the run parks on the approval before any tool.
    let server = spawn_scripted_server(
        vec![(
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("raced.txt"), "content": "raced"})
            )])),
        )],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        config.approval_mode = "manual".to_string();
    });
    let app = build_agent_gateway_app(state.clone());

    let run_id = create_run(&app, None).await;
    wait_for_status(&app, &run_id, "waiting_approval", Duration::from_secs(30)).await;
    let approval_id = wait_for_approval_id(&state, &run_id, Duration::from_secs(30)).await;

    // Stop while parked: the parked run has no worker; the stop must cancel
    // it typed (the park is removed, the run commits cancelled).
    let (status, body) = post_request(&app, &format!("/v1/runs/{run_id}/stop"), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("stopping"));
    wait_for_status(&app, &run_id, "cancelled", Duration::from_secs(30)).await;
    wait_for_terminal_handle(&state, &run_id, Duration::from_secs(10)).await;

    // The resolution after the stop is a typed conflict — no park, no
    // post-stop approval.resolved, no tool execution.
    let (status, body) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/approve"),
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("no_pending_approval"));
    assert!(
        !root.join("raced.txt").exists(),
        "the stopped run's tool must never execute"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_session_compact_is_real_and_refuses_active_runs() {
    let root = temporary_root("a7-compact");
    let server = spawn_scripted_server(
        vec![
            // Run 1: text-only — completes without an approval (terminal).
            (200, wire_text("done")),
            // Run 2: tool call — parks on the approval (active).
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("compact.txt"), "content": "compact"})
                )])),
            ),
            (200, wire_text("done")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        config.approval_mode = "manual".to_string();
    });
    let app = build_agent_gateway_app(state.clone());

    // A session whose run is TERMINAL (completed): the endpoint runs the
    // REAL RSS-owned compaction — the two-message history is within the
    // default window, so the honest answer is a typed skip (never a
    // fabricated compaction, never a fake commit).
    let terminal_run = create_run(&app, None).await;
    wait_for_status(&app, &terminal_run, "completed", Duration::from_secs(30)).await;
    wait_for_terminal_handle(&state, &terminal_run, Duration::from_secs(10)).await;
    let (_, terminal_view) = get_request(&app, &format!("/v1/runs/{terminal_run}"), None).await;
    let terminal_session = terminal_view["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{terminal_session}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the real compact entry: {body}");
    assert_eq!(body["status"], json!("skipped"));
    assert_eq!(body["reason"], json!("history_within_window"));
    assert_eq!(durable_compaction_count(&state, &terminal_session), 0);

    // A session whose run is ACTIVE (parked waiting_approval): the manual
    // compact is refused with the typed 409 — compaction is loop-managed
    // while a run is active, never a concurrent double compaction.
    let active_run = create_run(&app, None).await;
    wait_for_status(
        &app,
        &active_run,
        "waiting_approval",
        Duration::from_secs(30),
    )
    .await;
    let (_, active_view) = get_request(&app, &format!("/v1/runs/{active_run}"), None).await;
    let active_session = active_view["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{active_session}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("run_active_conflict"));
    // No fake success: no durable compaction row was created.
    assert_eq!(durable_compaction_count(&state, &active_session), 0);

    // The active run is untouched (still parked and resolvable).
    let (_, active_after) = get_request(&app, &format!("/v1/runs/{active_run}"), None).await;
    assert_eq!(active_after["status"], json!("waiting_approval"));
    let (_, terminal_after) = get_request(&app, &format!("/v1/runs/{terminal_run}"), None).await;
    assert_eq!(terminal_after["status"], json!("completed"));

    // Unknown session: 404 typed (the session boundary holds).
    let (status, body) =
        post_request(&app, "/api/sessions/never-existed/compact", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], json!("session_not_found"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_new_routes_enforce_auth_and_rate_limits() {
    let root = temporary_root("a7-auth");
    let server = spawn_scripted_server(vec![(200, wire_text("done"))], 0);
    let state = spawn_state(server.port(), &root, |config| {
        config.bearer_token = Some("secret-token".to_string());
    });
    let app = build_agent_gateway_app(state.clone());

    // Every new route rejects unauthenticated / cross-account requests
    // before any service work.
    let (status, _) = get_request(&app, "/v1/runs", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get_request(&app, "/v1/runs/any", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post_request(
        &app,
        "/v1/runs/any/approvals/any/approve",
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get_request(&app, "/v1/runs", Some("wrong-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = get_request(&app, "/v1/runs", Some("secret-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], json!("list"));

    // Rate limit: burst 1 on the shared test peer — the second request is
    // denied typed with Retry-After.
    let root2 = temporary_root("a7-ratelimit");
    let server2 = spawn_scripted_server(vec![(200, wire_text("done"))], 0);
    let state2 = spawn_state(server2.port(), &root2, |config| {
        config.rate_limit = rustscript_agent::config::RateLimitConfig {
            enabled: true,
            ip_burst: 1,
            account_burst: 1,
            window: Duration::from_secs(60),
            max_buckets: 16,
        };
    });
    let app2 = build_agent_gateway_app(state2);
    let (status, _) = get_request(&app2, "/v1/runs", None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = get_request(&app2, "/v1/runs", None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], json!("rate_limited"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
    std::fs::remove_dir_all(&root2).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_invalid_bodies_are_rejected() {
    let root = temporary_root("a7-invalid-body");
    let server = spawn_scripted_server(vec![(200, wire_text("done"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // Malformed JSON on the approval route: 400 before any service work.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/runs/any/approvals/any/approve")
                .header("content-type", "application/json")
                .body(Body::from("not-json"))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // A non-object JSON body: rejected (axum 0.8 answers 422 for a JSON
    // data error).
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/runs/any/approvals/any/approve")
                .header("content-type", "application/json")
                .body(Body::from("[1,2,3]"))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert!(
        response.status().is_client_error(),
        "a non-object body must be rejected"
    );

    // Invalid list query: rejected as a client error (axum 0.8 answers 422
    // for a failed query-string deserialization).
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/runs?limit=abc")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert!(
        response.status().is_client_error(),
        "invalid query must be rejected"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Reads the SSE body of one events request (the terminal event ends the
/// stream) and returns the raw text.
async fn sse_body(app: &axum::Router, run_id: &str, query: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/runs/{run_id}/events{query}"))
                .header("accept", "text/event-stream")
                .body(Body::empty())
                .expect("SSE request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8")
}

/// The `seq` of one SSE event, parsed from the SSE payload (the mirror's
/// authoritative sequence — the durable stream carries extra bookkeeping
/// rows, so durable seqs must never be crossed with the SSE mirror).
fn sse_event_seq(text: &str, event_name: &str) -> u64 {
    for chunk in text.split("\n\n") {
        if chunk.contains(&format!("event: {event_name}")) {
            let data = chunk
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap_or("{}");
            let value: JsonValue = serde_json::from_str(data).unwrap_or(JsonValue::Null);
            if let Some(seq) = value["seq"].as_u64() {
                return seq;
            }
        }
    }
    panic!("SSE stream did not contain {event_name}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_events_replay_with_cursors_after_approval_resolution() {
    let root = temporary_root("a7-replay");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("replay.txt"), "content": "replay"})
                )])),
            ),
            (200, wire_text("approved and replayed")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, |config| {
        config.approval_mode = "manual".to_string();
    });
    let app = build_agent_gateway_app(state.clone());

    let run_id = create_run(&app, None).await;
    wait_for_status(&app, &run_id, "waiting_approval", Duration::from_secs(30)).await;
    let approval_id = wait_for_approval_id(&state, &run_id, Duration::from_secs(30)).await;

    let (status, _) = post_request(
        &app,
        &format!("/v1/runs/{run_id}/approvals/{approval_id}/approve"),
        Some(json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    wait_for_status(&app, &run_id, "completed", Duration::from_secs(30)).await;
    wait_for_terminal_handle(&state, &run_id, Duration::from_secs(10)).await;

    // Full replay from the beginning: the wired approval flow's events are
    // ordered and the stream ends at the terminal.
    let full = sse_body(&app, &run_id, "?after_seq=0").await;
    let required_at = full
        .find("event: approval.required")
        .expect("approval.required");
    let resolved_at = full
        .find("event: approval.resolved")
        .expect("approval.resolved");
    let completed_at = full.find("event: run.completed").expect("run.completed");
    assert!(
        required_at < resolved_at && resolved_at < completed_at,
        "approval.required -> approval.resolved -> run.completed in order"
    );
    assert!(full.contains(&format!("\"approval_id\":\"{approval_id}\"")));

    // Cursor replay (the mirror's own seq): after the required event only
    // the later events appear.
    let required_seq = sse_event_seq(&full, "approval.required");
    let tail = sse_body(&app, &run_id, &format!("?after_seq={required_seq}")).await;
    assert!(!tail.contains("event: approval.required"));
    assert!(tail.contains("event: approval.resolved"));
    assert!(tail.contains("event: run.completed"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_get_run_reports_the_durable_status_and_unknown_runs_404() {
    let root = temporary_root("a7-run-status");
    let server = spawn_scripted_server(vec![(200, wire_text("hello back"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let run_id = create_run(&app, None).await;
    wait_for_status(&app, &run_id, "completed", Duration::from_secs(30)).await;

    let (status, view) = get_request(&app, &format!("/v1/runs/{run_id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["object"], json!("hermes.run"));
    assert_eq!(view["run_id"], json!(run_id));
    assert_eq!(view["status"], json!("completed"));
    assert!(view["session_id"].is_string());
    assert_eq!(view["platform"], json!("api_server"));
    assert!(view["event_count"].as_u64().unwrap_or(0) >= 4);
    // Mirror event seqs are 1-based: the retained window is seq 1..N.
    assert_eq!(
        view["last_event_seq"].as_u64().unwrap_or(0),
        view["event_count"].as_u64().unwrap_or(0)
    );
    assert!(view["error"].is_null(), "a completed run has no error");

    // A run that never started must 404 — never a fabricated "started".
    let (status, body) = get_request(&app, "/v1/runs/never-started", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], json!("run_not_found"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a7_run_list_paginates_and_filters_over_the_durable_store() {
    let root = temporary_root("a7-run-list");
    let server = spawn_scripted_server(vec![(200, wire_text("done"))], 0);
    let state = spawn_state(server.port(), &root, |_| {});
    let app = build_agent_gateway_app(state);

    let first = create_run(&app, None).await;
    let second = create_run(&app, None).await;
    wait_for_status(&app, &first, "completed", Duration::from_secs(30)).await;
    wait_for_status(&app, &second, "completed", Duration::from_secs(30)).await;

    let (status, list) = get_request(&app, "/v1/runs", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["object"], json!("list"));
    let data = list["data"].as_array().expect("run list data");
    assert_eq!(data.len(), 2);
    // Newest first.
    assert_eq!(data[0]["run_id"], json!(second));
    assert_eq!(data[1]["run_id"], json!(first));
    assert_eq!(list["limit"], json!(50));
    assert_eq!(list["offset"], json!(0));
    assert_eq!(list["has_more"], json!(false));

    // Pagination: limit 1 over 2 runs has_more true.
    let (status, page) = get_request(&app, "/v1/runs?limit=1&offset=0", None).await;
    assert_eq!(status, StatusCode::OK);
    let page_data = page["data"].as_array().expect("page data");
    assert_eq!(page_data.len(), 1);
    assert_eq!(page_data[0]["run_id"], json!(second));
    assert_eq!(page["has_more"], json!(true));

    // The second page starts at the older run.
    let (status, page2) = get_request(&app, "/v1/runs?limit=1&offset=1", None).await;
    assert_eq!(status, StatusCode::OK);
    let page2_data = page2["data"].as_array().expect("page data");
    assert_eq!(page2_data.len(), 1);
    assert_eq!(page2_data[0]["run_id"], json!(first));
    assert_eq!(page2["has_more"], json!(false));

    // Filtering: the first run's session_id returns only that run.
    let first_session = data[1]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    let (status, filtered) =
        get_request(&app, &format!("/v1/runs?session_id={first_session}"), None).await;
    assert_eq!(status, StatusCode::OK);
    let filtered_data = filtered["data"].as_array().expect("filtered data");
    assert_eq!(filtered_data.len(), 1);
    assert_eq!(filtered_data[0]["run_id"], json!(first));

    // Status filter: completed matches, waiting_approval matches nothing here.
    let (status, completed) = get_request(&app, "/v1/runs?status=completed", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        completed["data"].as_array().expect("completed data").len(),
        2
    );
    let (status, waiting) = get_request(&app, "/v1/runs?status=waiting_approval", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(waiting["data"].as_array().expect("waiting data").len(), 0);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}
