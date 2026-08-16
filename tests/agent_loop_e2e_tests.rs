//! A5/A6 production serial loop — end-to-end fixtures through the REAL service.
//!
//! Every fixture drives `AgentGatewayState::with_default_agent_program[_and_sqlite]`
//! (the built-in `rss/agent/main.rss` program compiled at construction — no
//! test-injected source) against a local scripted provider HTTP server, and
//! asserts the durable outcome through `GatewayPersistence` (events replay +
//! run records). Coverage: text-only round, tool round (real io root),
//! provider retry/error, cancel, approval wait/resume exact-once + deny,
//! max-turn runaway, durable compaction, and the A6 native supervisor
//! wiring: real child runs through AgentService (bounded concurrency on the
//! real wire, race/fail-fast cancellation, approval-gated batches, exact-once
//! child lifecycle events, depth/fanout rejection, parent-stop propagation,
//! and durable child links that survive a restart).

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustscript_agent::{
    AdmitRunRequest, AgentConfig, AgentGatewayConfig, AgentGatewayState, AgentRunner, AgentService,
};
use rustscript_vm::{HttpConfig, IoPolicy, SqlitePolicy, Value as VmValue};
use serde_json::{Value as JsonValue, json};

fn temporary_root(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("rustscript-agent-e2e-tests");
    let root = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("temporary root should be created");
    root
}

// ---------------------------------------------------------------------------
// Scripted provider server (per-request responses, optional delay)
// ---------------------------------------------------------------------------

struct ScriptedServer {
    port: u16,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Every request's raw bytes (headers + body), in serving order.
    bodies: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    shutdown: mpsc::Sender<()>,
}

impl ScriptedServer {
    fn port(&self) -> u16 {
        self.port
    }

    fn request_count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The raw request text (HTTP head + body) of the `index`-th request.
    fn raw_request(&self, index: usize) -> Option<String> {
        self.bodies.lock().expect("bodies lock").get(index).cloned()
    }

    /// The JSON body of the `index`-th request, parsed.
    fn request_body(&self, index: usize) -> Option<JsonValue> {
        let raw = self.raw_request(index)?;
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).ok()
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
    let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let count = std::sync::Arc::clone(&requests);
    let recorded = std::sync::Arc::clone(&bodies);
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
                                thread::sleep(Duration::from_millis(2));
                            }
                            Err(_) => break,
                        }
                    }
                    recorded
                        .lock()
                        .expect("bodies lock")
                        .push(String::from_utf8_lossy(&request).into_owned());
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
        requests,
        bodies,
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

/// The OpenAI Responses wire text response: the `output` item array with a
/// single assistant `message` carrying `output_text` parts.
fn wire_responses_text(text: &str) -> String {
    json!({
        "id": "resp-1",
        "object": "response",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text}]
        }],
        "status": "completed"
    })
    .to_string()
}

/// The Anthropic Messages wire text response: the top-level `content` block
/// array with one `text` block and a `stop_reason`.
fn wire_anthropic_text(text: &str) -> String {
    json!({
        "id": "msg-1",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1}
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

// ---------------------------------------------------------------------------
// Service harness
// ---------------------------------------------------------------------------

fn base_config(server_port: u16, root: &std::path::Path, sqlite: bool) -> AgentGatewayConfig {
    let config = AgentGatewayConfig {
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
        run_timeout: Duration::from_secs(60),
        base_retry_delay_ms: 20,
        max_retry_delay_ms: 40,
        // The fixtures speak plain JSON; the buffered transport is the
        // correct wire path (the SSE transport is exercised by the streaming
        // suites).
        stream: false,
        ..AgentGatewayConfig::default()
    };
    let _ = sqlite;
    config
}

fn spawn_state(
    server_port: u16,
    root: &std::path::Path,
    sqlite: bool,
    mutate: impl FnOnce(&mut AgentGatewayConfig),
) -> AgentGatewayState {
    let mut config = base_config(server_port, root, sqlite);
    mutate(&mut config);
    if sqlite {
        AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
            .expect("gateway state with the built-in agent program")
    } else {
        AgentGatewayState::with_default_agent_program(config)
            .expect("gateway state with the built-in agent program")
    }
}

async fn admit_and_wait(
    service: &Arc<AgentService>,
    input: &str,
    deadline: Duration,
) -> rustscript_agent::AdmittedRun {
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!(input),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    // The gateway API server spawns the run worker after admission; the
    // fixture harness mirrors that exactly (admission alone never starts
    // the loop).
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), input.to_string()),
    );
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        if let Some(handle) = service.handle(&admitted.run_id)
            && handle.is_terminal()
        {
            return admitted;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "run {} did not reach a terminal within {deadline:?}",
        admitted.run_id
    );
}

fn wait_for(deadline: Duration, mut predicate: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("condition did not hold within {deadline:?}");
}

/// Replays the run's durable events: `(seq, event_type, payload)` rows in
/// sequence order.
fn replayed_events(state: &AgentGatewayState, run_id: &str) -> Vec<(i64, String, JsonValue)> {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .event_replay(&json!({
            "run_id": run_id,
            "after_seq": 1,
            "max_events": 512,
            "max_bytes": 65536,
        }))
        .expect("event replay");
    let mut events = Vec::new();
    if let Some(rows) = data.get("rows").and_then(JsonValue::as_array) {
        for row in rows {
            if let Some(row) = row.as_array() {
                let seq = row[0].as_i64().unwrap_or(0);
                let event_type = row[3].as_str().unwrap_or("?").to_string();
                // The durable stream carries service-owned bookkeeping
                // (the admission's `run.started` and the terminal
                // `message.delta`); the canonical script-visible stream
                // excludes them.
                if event_type == "run.started" || event_type == "message.delta" {
                    continue;
                }
                let payload = row[4]
                    .as_str()
                    .and_then(|text| serde_json::from_str(text).ok())
                    .unwrap_or(JsonValue::Null);
                events.push((seq, event_type, payload));
            }
        }
    }
    events
}

fn durable_run_status(state: &AgentGatewayState, run_id: &str) -> String {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence.run_get(run_id).expect("run get");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .and_then(|row| row.get(3))
        .and_then(JsonValue::as_str)
        .unwrap_or("?")
        .to_string()
}

fn event_types(events: &[(i64, String, JsonValue)]) -> Vec<String> {
    events
        .iter()
        .map(|(_, event_type, _)| event_type.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_text_only_round_completes_with_durable_canonical_events() {
    let root = temporary_root("e2e-text-only");
    let server = spawn_scripted_server(vec![(200, wire_text("hello back"))], 0);
    let state = spawn_state(server.port(), &root, true, |_| {});
    let admitted = admit_and_wait(&state.service(), "hello", Duration::from_secs(30)).await;

    let events = replayed_events(&state, &admitted.run_id);
    assert_eq!(
        event_types(&events),
        vec![
            "model.started",
            "model.delta",
            "model.completed",
            "run.completed"
        ],
        "canonical event stream in order"
    );
    assert_eq!(events[0].2["model"], json!("test-model"));
    assert_eq!(events[1].2["delta"], json!("hello back"));
    assert_eq!(events[2].2["text"], json!("hello back"));
    assert_eq!(
        events[3].2["output"]["message"]["content"],
        json!("hello back")
    );
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    assert_eq!(server.request_count(), 1);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tool_round_executes_file_tool_and_backfills_the_result() {
    let root = temporary_root("e2e-tool-round");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("out.txt"), "content": "written by the loop"})
                )])),
            ),
            (200, wire_text("file written")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
    });
    let admitted =
        admit_and_wait(&state.service(), "write the file", Duration::from_secs(30)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let written = fs::read_to_string(root.join("out.txt")).expect("file tool should have written");
    assert_eq!(written, "written by the loop");
    let events = replayed_events(&state, &admitted.run_id);
    let types = event_types(&events);
    assert!(types.contains(&"tool.started".to_string()));
    assert!(types.contains(&"tool.completed".to_string()));
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_provider_retry_backs_off_then_completes() {
    let root = temporary_root("e2e-retry");
    let server = spawn_scripted_server(
        vec![
            wire_error(429, "rate_limit_error", "rate_limit_exceeded", "slow down"),
            wire_error(429, "rate_limit_error", "rate_limit_exceeded", "slow down"),
            (200, wire_text("after retries")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.max_retries = 2;
    });
    let admitted = admit_and_wait(&state.service(), "retry me", Duration::from_secs(30)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    // One model.started per turn, never per retry attempt.
    let started = events
        .iter()
        .filter(|(_, event_type, _)| event_type == "model.started")
        .count();
    assert_eq!(started, 1);
    assert_eq!(server.request_count(), 3);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_nonretryable_provider_error_fails_the_run_typed() {
    let root = temporary_root("e2e-error");
    let server = spawn_scripted_server(
        vec![wire_error(
            400,
            "invalid_request_error",
            "bad_param",
            "bad parameter",
        )],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |_| {});
    let admitted = admit_and_wait(&state.service(), "fail me", Duration::from_secs(30)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "failed");
    let events = replayed_events(&state, &admitted.run_id);
    assert_eq!(
        event_types(&events).last().map(String::as_str),
        Some("run.failed")
    );
    let failed = events.last().expect("run.failed event").2.clone();
    assert_eq!(failed["error_code"], json!("bad_param"));
    assert_eq!(failed["provider_error"]["status"], json!(400));
    assert_eq!(
        failed["provider_error"]["type"],
        json!("invalid_request_error")
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_cancel_mid_run_commits_typed_cancelled_terminal() {
    let root = temporary_root("e2e-cancel");
    // The provider stalls; the run is mid-loop when stop() lands.
    let server = spawn_scripted_server(vec![(200, wire_text("never reached"))], 30_000);
    let state = spawn_state(server.port(), &root, true, |_| {});
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("cancel me"),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    // The run worker is spawned after admission exactly like the API server
    // does; the provider stalls so the run is mid-loop when stop() lands.
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "cancel me".to_string()),
    );
    // Wait until the run is actively awaiting the provider.
    wait_for(Duration::from_secs(10), || server.request_count() >= 1);
    let status = state.service().stop(&admitted.run_id).expect("stop");
    assert_eq!(status, "stopping");
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(handle) = state.service().handle(&admitted.run_id)
            && handle.is_terminal()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");
    let events = replayed_events(&state, &admitted.run_id);
    assert_eq!(
        event_types(&events).last().map(String::as_str),
        Some("run.cancelled")
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_approval_wait_resume_is_exactly_once_and_completes() {
    let root = temporary_root("e2e-approval");
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
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
    });
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("needs approval"),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    // The run worker is spawned after admission exactly like the API server.
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "needs approval".to_string()),
    );

    // The run parks on the durable pending approval.
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });
    assert!(
        !root.join("approved.txt").exists(),
        "the tool must not run while waiting"
    );

    // Approve: the run resumes exactly once and completes.
    state
        .service()
        .resolve_run_approval(&admitted.run_id, true)
        .expect("approval resolution");
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(handle) = state.service().handle(&admitted.run_id)
            && handle.is_terminal()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    assert_eq!(
        fs::read_to_string(root.join("approved.txt")).expect("written"),
        "approved"
    );
    let events = replayed_events(&state, &admitted.run_id);
    let types = event_types(&events);
    assert!(types.contains(&"approval.required".to_string()));
    assert!(types.contains(&"approval.resolved".to_string()));

    // A second resolution is a typed no-op (exact-once).
    let second = state.service().resolve_run_approval(&admitted.run_id, true);
    assert!(
        second.is_err(),
        "the second resolution must not resume the run again"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_approval_denied_folds_a_typed_tool_result_and_the_loop_continues() {
    let root = temporary_root("e2e-approval-deny");
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
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
    });
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("deny it"),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    // The run worker is spawned after admission exactly like the API server.
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "deny it".to_string()),
    );
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });

    state
        .service()
        .resolve_run_approval(&admitted.run_id, false)
        .expect("denial resolution");
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(handle) = state.service().handle(&admitted.run_id)
            && handle.is_terminal()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // The denied file was never written; the model saw the typed
    // `approval_denied` tool result and answered.
    assert!(!root.join("denied.txt").exists());
    let second = server.request_body(1).expect("second provider request");
    let serialized = second.to_string();
    assert!(
        serialized.contains("approval_denied"),
        "the deny resume must carry the typed approval_denied code"
    );
    let events = replayed_events(&state, &admitted.run_id);
    let types = event_types(&events);
    assert!(types.contains(&"approval.resolved".to_string()));
    assert!(types.contains(&"model.completed".to_string()));
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_max_turn_runaway_terminates_bounded() {
    let root = temporary_root("e2e-runaway");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("a.txt"), "content": "a"})
                )])),
            ),
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-2",
                    "file.write",
                    json!({"path": root.join("b.txt"), "content": "b"})
                )])),
            ),
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-3",
                    "file.write",
                    json!({"path": root.join("c.txt"), "content": "c"})
                )])),
            ),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.max_turns = 2;
        config.approval_mode = "all".to_string();
    });
    let admitted = admit_and_wait(&state.service(), "run away", Duration::from_secs(30)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // Exactly two model rounds before the bound.
    let events = replayed_events(&state, &admitted.run_id);
    let started = events
        .iter()
        .filter(|(_, event_type, _)| event_type == "model.started")
        .count();
    assert_eq!(started, 2);
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_compaction_executes_durably_and_advances_generation() {
    let root = temporary_root("e2e-compaction");
    let state = spawn_state(0, &root, true, |_| {});
    let persistence = state.persistence().expect("durable persistence");

    // Seed a durable history through the typed repository (the same shape the
    // serial loop plans over), then reopen so the in-memory session matches.
    let seed =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .expect("seed state");
    let seed_persistence = seed.persistence().expect("seed persistence");
    seed_persistence
        .session_create(&json!({
            "id": "session-1",
            "profile": "default",
            "platform": "test",
            "account_id": "account-1",
            "chat_id": "chat-1",
            "thread_id": "",
            "user_id": "user-1",
            "generation": 1,
            "system_prompt": "",
            "model": "test-model",
            "provider": "openai_chat",
            "toolset_hash": "test-tools",
            "metadata_json": "{}",
            "title": "",
            "end_reason": "",
            "now_ms": 0
        }))
        .expect("session create");
    for index in 1..=8 {
        let role = if index % 2 == 1 { "user" } else { "assistant" };
        let content = if role == "user" {
            format!(r#"[{{"type":"text","text":"message {index}"}}]"#)
        } else {
            format!(r#"[{{"type":"text","text":"reply {index}"}}]"#)
        };
        seed_persistence
            .message_append(&json!({
                "id": format!("m-{index}"),
                "session_id": "session-1",
                "role": role,
                "content_json": content,
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 0,
                "metadata_json": "{}",
                "run_id": "seed-run",
                "finish_reason": "",
                "now_ms": 0
            }))
            .expect("message append");
    }
    drop(seed_persistence);

    // The production loop runs against the seeded session: the history
    // exceeds the window, so it plans and the service executes the durable
    // compaction before the first provider call.
    let server = spawn_scripted_server(vec![(200, wire_text("compacted and answered"))], 0);
    let mut config = base_config(server.port(), &root, true);
    config.max_context_messages = 6;
    config.retained_tail = 2;
    config.provider = Some("openai_chat".to_string());
    config.provider_options = json!({
        "base_url": format!("http://127.0.0.1:{}", server.port()),
        "api_key": "test-key",
        "model": "test-model"
    });
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_hosts = vec!["127.0.0.1".to_string()];
    config.http.allowed_ports = vec![server.port()];
    config.http.allow_private_ips = true;
    config.run_timeout = Duration::from_secs(60);
    let state =
        AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
            .expect("reopened state with the built-in agent program");
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("compact"),
            session_id: Some("session-1".to_string()),
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    // The run worker is spawned after admission exactly like the API server.
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "compact".to_string()),
    );
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(handle) = state.service().handle(&admitted.run_id)
            && handle.is_terminal()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // The compaction row is committed and the session generation advanced.
    let compaction = persistence
        .compaction_get("compact:session-1:2")
        .expect("compaction get");
    let rows = compaction
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][10], json!("committed"), "state column");
    assert_eq!(rows[0][3], json!(2), "generation column");
    let events = replayed_events(&state, &admitted.run_id);
    let types = event_types(&events);
    assert!(types.contains(&"compact.started".to_string()));
    assert!(types.contains(&"compact.completed".to_string()));

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// A6 native supervisor wiring: real child runs through AgentService
// ---------------------------------------------------------------------------

/// One rule of the concurrency probe server: the first rule whose needle
/// appears in the request body wins (status, body, hold delay).
#[derive(Clone)]
struct ProbeRule {
    needle: String,
    status: u16,
    body: String,
    delay_ms: u64,
}

/// Thread-per-connection fixture server that counts concurrent in-flight
/// requests (the real 2-concurrency timing probe) and answers each request
/// from the rule table (so child runs can be scripted to succeed, fail, or
/// stall by their input text).
struct ProbeServer {
    port: u16,
    requests: Arc<AtomicUsize>,
    peak_concurrent: Arc<AtomicUsize>,
    /// Request bodies in connection-accept order (each as raw HTTP text).
    bodies: Arc<Mutex<Vec<String>>>,
    shutdown: mpsc::Sender<()>,
}

impl ProbeServer {
    fn port(&self) -> u16 {
        self.port
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// The observed peak of concurrently in-flight requests.
    fn peak_concurrent(&self) -> usize {
        self.peak_concurrent.load(Ordering::SeqCst)
    }

    /// The JSON body of the Nth request (0-based, connection order).
    fn request_body(&self, index: usize) -> Option<JsonValue> {
        let bodies = self.bodies.lock().expect("probe bodies lock");
        let raw = bodies.get(index)?;
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().trim_end();
        serde_json::from_str(body).ok()
    }

    /// All captured raw request bodies in connection order.
    fn request_bodies(&self) -> Vec<String> {
        self.bodies.lock().expect("probe bodies lock").clone()
    }
}

impl Drop for ProbeServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

fn spawn_probe_server(rules: Vec<ProbeRule>) -> ProbeServer {
    spawn_probe_server_impl(rules, None)
}

/// A probe server that serves the canonical 429 rate-limit error for the
/// FIRST request whose body contains `throttle_needle` (a retryable
/// provider round), then serves the rule table for every later request —
/// the provider retry must succeed on its second attempt.
fn spawn_probe_server_with_first_round_429(
    throttle_needle: &str,
    rules: Vec<ProbeRule>,
) -> ProbeServer {
    spawn_probe_server_impl(rules, Some(throttle_needle.to_string()))
}

fn spawn_probe_server_impl(rules: Vec<ProbeRule>, throttle: Option<String>) -> ProbeServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let requests = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let count = Arc::clone(&requests);
    let active_for_loop = Arc::clone(&active);
    let peak_for_loop = Arc::clone(&peak);
    let bodies_for_loop = Arc::clone(&bodies);
    let throttled = Arc::new(AtomicBool::new(false));
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    count.fetch_add(1, Ordering::SeqCst);
                    let active_conn = Arc::clone(&active_for_loop);
                    let peak_conn = Arc::clone(&peak_for_loop);
                    let bodies_conn = Arc::clone(&bodies_for_loop);
                    let rules_for_conn = rules.clone();
                    let throttle_for_conn = throttle.clone();
                    let throttled_for_conn = Arc::clone(&throttled);
                    thread::spawn(move || {
                        let in_flight = active_conn.fetch_add(1, Ordering::SeqCst) + 1;
                        peak_conn.fetch_max(in_flight, Ordering::SeqCst);
                        let body = read_request_body(&stream);
                        bodies_conn
                            .lock()
                            .expect("probe bodies lock")
                            .push(body.clone());
                        // The first-round 429 throttle: the FIRST request
                        // whose body carries the needle is answered with the
                        // retryable rate-limit error; every later request
                        // falls through to the rule table.
                        if let Some(needle) = throttle_for_conn.as_deref()
                            && body.contains(needle)
                            && !throttled_for_conn.swap(true, Ordering::SeqCst)
                        {
                            let (status, response_body) = wire_error(
                                429,
                                "rate_limit_error",
                                "rate_limit_exceeded",
                                "slow down",
                            );
                            let response = format!(
                                "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                response_body.len(),
                                response_body
                            );
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.flush();
                            active_conn.fetch_sub(1, Ordering::SeqCst);
                            return;
                        }
                        let matched = rules_for_conn
                            .iter()
                            .find(|rule| body.contains(&rule.needle));
                        let (status, response_body, delay_ms) = matched
                            .map(|rule| (rule.status, rule.body.clone(), rule.delay_ms))
                            .unwrap_or((200, String::new(), 0));
                        if delay_ms > 0 {
                            thread::sleep(Duration::from_millis(delay_ms));
                        }
                        let reason = if status == 200 { "OK" } else { "Error" };
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            response_body.len(),
                            response_body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        active_conn.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    ProbeServer {
        port,
        requests,
        peak_concurrent: peak,
        bodies,
        shutdown: shutdown_tx,
    }
}

fn read_request_body(stream: &TcpStream) -> String {
    let mut stream = stream.try_clone().expect("clone fixture stream");
    stream
        .set_nonblocking(true)
        .expect("nonblocking fixture stream");
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
    String::from_utf8_lossy(&request).into_owned()
}

/// Deterministic FNV-1a 64-bit hash (the service's child admission key
/// hash — the test replica lets a fixture pre-admit the exact child the
/// executor would admit).
fn fnv1a64(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Admits a run with a STRUCTURED input (the parallel/task delegation
/// request) and spawns the worker exactly like the API server does.
async fn admit_structured(
    service: &Arc<AgentService>,
    input: JsonValue,
) -> rustscript_agent::AdmittedRun {
    let admitted = service
        .admit(AdmitRunRequest {
            input,
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: JsonValue::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), String::new()),
    );
    admitted
}

fn child_events<'a>(
    events: &'a [(i64, String, JsonValue)],
    event_type: &str,
) -> Vec<&'a JsonValue> {
    events
        .iter()
        .filter(|(_, ty, _)| ty == event_type)
        .map(|(_, _, payload)| payload)
        .collect()
}

/// The parent's continuation request body carries the folded tool messages
/// (`tool_call_id` parts); child requests carry only plain user text.
const PARENT_RULE: &str = "tool_call_id";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_execution_admits_real_children_with_bounded_concurrency_and_ordered_slots() {
    let root = temporary_root("e2e-parallel-real");
    let mut rules = Vec::new();
    for index in 0..4 {
        rules.push(ProbeRule {
            needle: format!("job-{index}"),
            status: 200,
            body: wire_text(&format!("R-{index}")),
            delay_ms: 300,
        });
    }
    rules.push(ProbeRule {
        needle: PARENT_RULE.to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    });
    let server = spawn_probe_server(rules);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "parent_marker": "PARENT",
            "tasks": [
                {"id": "t0", "input": "job-0"},
                {"id": "t1", "input": "job-1"},
                {"id": "t2", "input": "job-2"},
                {"id": "t3", "input": "job-3"},
            ],
            "mode": "all",
            "max_concurrency": 2,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // Four children really ran (one provider round each) plus the parent's
    // continuation round.
    assert_eq!(server.request_count(), 5);
    // The parent's continuation request (the round after the folded results)
    // must be provider-legal: every tool result follows a matching assistant
    // tool call in the SAME request (no dangling results — real OpenAI
    // Chat/Responses and Anthropic contracts reject those).
    let continuation = server
        .request_body(4)
        .expect("the parent continuation request body");
    assert!(
        !request_has_dangling_tool_result(&continuation),
        "the parent continuation request must carry no dangling tool result: {continuation}"
    );
    // The plan's max_concurrency=2 was enforced with REAL overlap: the peak
    // of concurrent in-flight provider requests is exactly 2, never more.
    assert_eq!(
        server.peak_concurrent(),
        2,
        "bounded concurrency must hold on the real wire"
    );

    // Child lifecycle events exactly once per child, all before the parent's
    // terminal: 4 started + 4 completed.
    let events = replayed_events(&state, &admitted.run_id);
    let started = child_events(&events, "subagent.started");
    let completed = child_events(&events, "subagent.completed");
    assert_eq!(
        started.len(),
        4,
        "one subagent.started per real child admission"
    );
    assert_eq!(
        completed.len(),
        4,
        "one subagent.completed per durable child terminal"
    );
    let run_completed_seq = events
        .iter()
        .find(|(_, ty, _)| ty == "run.completed")
        .map(|(seq, _, _)| *seq)
        .expect("parent terminal");
    for (seq, _, _) in &events {
        assert!(
            *seq <= run_completed_seq,
            "no child event after the parent terminal"
        );
    }

    // Durable child links: one row per child under the parent.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 4, "durable child_run_links rows");
    // Every child is a REAL run: durable row exists, parent_run_id links back,
    // its session is independent of the parent's session, status completed.
    let parent_session = {
        let data = persistence
            .run_get(&admitted.run_id)
            .expect("parent run row");
        data.get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .and_then(|row| row.get(1))
            .and_then(JsonValue::as_str)
            .expect("parent session id")
            .to_string()
    };
    for row in rows {
        let child_id = row
            .get(1)
            .and_then(JsonValue::as_str)
            .expect("child id")
            .to_string();
        let child = persistence.run_get(&child_id).expect("child run row");
        let child_row = child
            .get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .expect("child row");
        assert_eq!(
            child_row.get(2).and_then(JsonValue::as_str),
            Some(admitted.run_id.as_str()),
            "child run must carry the parent link"
        );
        assert_eq!(
            child_row.get(3).and_then(JsonValue::as_str),
            Some("completed"),
            "child run reaches a durable completed terminal"
        );
        let child_session = child_row.get(1).and_then(JsonValue::as_str).unwrap_or("");
        assert_ne!(
            child_session, parent_session,
            "each child gets an isolated session, never the parent's"
        );
    }

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_race_first_success_cancels_losers_and_never_starts_the_rest() {
    let root = temporary_root("e2e-parallel-race");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "fast".to_string(),
            status: 200,
            body: wire_text("R-fast"),
            delay_ms: 50,
        },
        ProbeRule {
            needle: "slow".to_string(),
            status: 200,
            body: wire_text("R-slow"),
            delay_ms: 600,
        },
        ProbeRule {
            needle: PARENT_RULE.to_string(),
            status: 200,
            body: wire_text("parent done"),
            delay_ms: 0,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [
                {"id": "t0", "input": "fast"},
                {"id": "t1", "input": "slow"},
                {"id": "t2", "input": "never-2"},
                {"id": "t3", "input": "never-3"},
            ],
            "mode": "race",
            "max_concurrency": 2,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    let started = child_events(&events, "subagent.started");
    let completed = child_events(&events, "subagent.completed");
    // Only the two racing children were ever admitted (both started, exactly
    // once each); the remaining slots never started.
    assert_eq!(started.len(), 2, "only the racing pair is admitted");
    assert_eq!(
        completed.len(),
        2,
        "both admitted children reach a durable terminal"
    );
    let statuses: Vec<&str> = completed
        .iter()
        .map(|payload| payload["status"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(statuses.len(), 2);
    assert!(
        statuses.contains(&"completed"),
        "the race winner completes: {statuses:?}"
    );
    assert!(
        statuses.contains(&"cancelled"),
        "the race loser is cancelled: {statuses:?}"
    );
    // Only the two racing children have durable run rows (the never-started
    // slots admit nothing).
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(
        rows.len(),
        2,
        "never-started slots leave no links and no runs"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_fail_fast_first_failure_cancels_siblings_and_never_starts_the_rest() {
    let root = temporary_root("e2e-parallel-failfast");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "boom".to_string(),
            status: 400,
            body: wire_error(400, "invalid_request_error", "bad_request", "boom").1,
            delay_ms: 50,
        },
        ProbeRule {
            needle: PARENT_RULE.to_string(),
            status: 200,
            body: wire_text("parent done"),
            delay_ms: 0,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [
                {"id": "t0", "input": "boom"},
                {"id": "t1", "input": "never-1"},
                {"id": "t2", "input": "never-2"},
            ],
            "mode": "fail_fast",
            "max_concurrency": 1,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    let started = child_events(&events, "subagent.started");
    let completed = child_events(&events, "subagent.completed");
    assert_eq!(
        started.len(),
        1,
        "only the first sibling is admitted before the failure"
    );
    assert_eq!(completed.len(), 1);
    assert_eq!(
        completed[0]["status"],
        json!("failed"),
        "the failed sibling reaches a durable failed terminal"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(
        rows.len(),
        1,
        "fail-fast siblings are cancelled before admission"
    );
    assert_eq!(
        server.request_count(),
        2,
        "the failed child's provider round plus the parent's"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// A6 sparse-parallel ordinal fix — REAL E2E. One parent run drives a
/// fail-fast parallel batch whose slots t1 and t2 are cancelled before they
/// start: they consume ordinal identities 1 and 2 but create NO
/// child_run_links row (links.len() == 1 while 3 ordinals are consumed). The
/// durable parent-level ordinal allocator must reserve the full range [0,1,2]
/// so ANY follow-up batch of the same parent starts strictly past it — never
/// reusing 1 or 2. Under the OLD `links.len()` ordinal base a follow-up batch
/// would resume at ordinal 1 and collide.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_sparse_batch_reserves_refused_ordinals_durably_for_followup_batches() {
    let root = temporary_root("e2e-parallel-sparse-ordinals");
    let server = spawn_scripted_server(
        vec![
            (
                400,
                wire_error(400, "invalid_request_error", "bad_request", "boom").1,
            ),
            (200, wire_text("parent done")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    // First batch is fail-fast: slot t0 is ADMITTED (ordinal 0) and fails;
    // the interior/tail slots t1 and t2 are cancelled BEFORE they ever start
    // — they consume ordinal identities 1 and 2 but create NO child_run_links
    // row (a SPARSE batch: links.len() understates the ordinals consumed).
    // The durable parent-level ordinal allocator must reserve the full range
    // [0,1,2] so a later batch of the SAME parent never reuses 1 or 2.
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [
                {"id": "t0", "input": "boom"},
                {"id": "t1", "input": "never-1"},
                {"id": "t2", "input": "never-2"},
            ],
            "mode": "fail_fast",
            "max_concurrency": 1,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    assert_eq!(
        server.request_count(),
        2,
        "the failing child's provider round plus the parent's continuation"
    );

    // Only t0 was ever admitted; t1/t2 never started (cancelled before
    // admission), so exactly one subagent.started at ordinal 0.
    let events = replayed_events(&state, &admitted.run_id);
    let started = child_events(&events, "subagent.started");
    assert_eq!(started.len(), 1, "only the admitted child starts");
    assert_eq!(started[0]["ordinal"], json!(0));

    // The sparse batch CONSUMED three ordinals (0,1,2), but only ordinal 0
    // has a durable child link. The durable allocator high-water must be 3 —
    // a `links.len()` base (1) would under-reserve the refused slots.
    let persistence = state.persistence().expect("durable persistence");
    assert_eq!(
        persistence
            .parent_ordinal_next(&admitted.run_id, "parallel")
            .expect("durable parent ordinal high-water"),
        3,
        "the durable allocator must reserve the refused/cancelled-before-start ordinals (links.len() would under-reserve)"
    );
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let link_rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(link_rows.len(), 1, "only the admitted child is linked");
    assert_eq!(link_rows[0][2], json!(0));

    // A SECOND batch of the same parent is allocated strictly PAST the
    // consumed range — the durable allocator grants base 3 for a 2-slot
    // follow-up (ordinals 3,4), never reusing 0, 1, or 2.
    assert_eq!(
        persistence
            .allocate_ordinals(&admitted.run_id, "parallel", 2)
            .expect("follow-up batch allocation"),
        3,
        "a follow-up batch must never reuse a consumed sparse ordinal"
    );
    assert_eq!(
        persistence
            .parent_ordinal_next(&admitted.run_id, "parallel")
            .expect("high-water after follow-up"),
        5
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_batch_approval_parks_durably_then_resumes_and_executes_children() {
    let root = temporary_root("e2e-parallel-approval");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "job-0".to_string(),
            status: 200,
            body: wire_text("R-0"),
            delay_ms: 0,
        },
        ProbeRule {
            needle: PARENT_RULE.to_string(),
            status: 200,
            body: wire_text("parent done"),
            delay_ms: 0,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
        config.parallel = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [{"id": "t0", "input": "job-0"}],
            "mode": "all",
            "max_concurrency": 1,
        }),
    )
    .await;

    // The parallel delegation is approval-gated (A4): the run parks on the
    // durable pending approval and no child is admitted while waiting.
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });
    let parked_events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&parked_events, "subagent.started").is_empty(),
        "no child starts while the batch approval is pending"
    );

    state
        .service()
        .resolve_run_approval(&admitted.run_id, true)
        .expect("approval resolution");
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    let types = event_types(&events);
    assert!(types.contains(&"approval.required".to_string()));
    assert!(types.contains(&"approval.resolved".to_string()));
    // After the durable approval, the child is really admitted exactly once
    // and reaches its durable terminal exactly once.
    assert_eq!(child_events(&events, "subagent.started").len(), 1);
    assert_eq!(child_events(&events, "subagent.completed").len(), 1);
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_subagent_real_child_admission_is_linked_isolated_and_folded() {
    let root = temporary_root("e2e-subagent-real");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "child job".to_string(),
            status: 200,
            body: wire_text("R-child"),
            delay_ms: 0,
        },
        ProbeRule {
            needle: PARENT_RULE.to_string(),
            status: 200,
            body: wire_text("parent done"),
            delay_ms: 0,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.task = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "child": {"id": "c1", "input": "child job"},
            "depth": 0,
            "max_depth": 4,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    let started = child_events(&events, "subagent.started");
    let completed = child_events(&events, "subagent.completed");
    assert_eq!(started.len(), 1, "exactly one real child admission");
    assert_eq!(completed.len(), 1, "exactly one durable child terminal");
    assert_eq!(completed[0]["status"], json!("completed"));
    assert!(
        started[0]["seq"].is_null() || completed[0].get("child_run_id").is_some(),
        "the completed event carries the real child run id"
    );

    // The child is a REAL run: durable row, parent link, isolated session.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 1);
    // The durable link row (admission contract): relation "subagent"; the
    // state REALLY advances pending (admission) -> active (native link) ->
    // the child's terminal — the observed child terminal is completed here.
    let relation = rows[0].get(3).and_then(JsonValue::as_str).unwrap_or("?");
    assert_eq!(relation, "subagent");
    let link_state = rows[0].get(4).and_then(JsonValue::as_str).unwrap_or("?");
    assert_eq!(
        link_state, "completed",
        "the durable link state must advance to the child's observed terminal"
    );
    let child_id = rows[0]
        .get(1)
        .and_then(JsonValue::as_str)
        .expect("child id");
    let child = persistence.run_get(child_id).expect("child run row");
    let child_row = child
        .get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .expect("child row");
    assert_eq!(
        child_row.get(2).and_then(JsonValue::as_str),
        Some(admitted.run_id.as_str()),
        "child run carries the parent link"
    );
    assert_eq!(
        child_row.get(3).and_then(JsonValue::as_str),
        Some("completed")
    );
    let parent_session = {
        let data = persistence
            .run_get(&admitted.run_id)
            .expect("parent run row");
        data.get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .and_then(|row| row.get(1))
            .and_then(JsonValue::as_str)
            .expect("parent session id")
            .to_string()
    };
    assert_ne!(
        child_row.get(1).and_then(JsonValue::as_str).unwrap_or(""),
        parent_session,
        "the child's session is independent"
    );
    // The parent's continuation provider round carries the child outcome
    // folded into history (the loop kept reasoning with the real result).
    assert_eq!(server.request_count(), 2);
    // The continuation request is provider-legal: the folded child result is
    // preceded by the matching assistant tool call in the same request.
    let continuation = server
        .request_body(1)
        .expect("the parent continuation request body");
    assert!(
        !request_has_dangling_tool_result(&continuation),
        "the subagent continuation request must carry no dangling tool result: {continuation}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The parent continuation request after a parallel handoff must be legal on
/// EVERY direct adapter wire: OpenAI Chat (dedicated `tool` messages),
/// OpenAI Responses (`function_call` / `function_call_output` items), and
/// Anthropic Messages (`tool_use` / `tool_result` blocks) all reject a tool
/// result that does not follow a matching assistant tool call in the same
/// request. Delegation is input-driven, so the loop itself must synthesize
/// the matching pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_continuation_request_has_no_dangling_tool_results_on_every_adapter() {
    for provider in ["openai_chat", "openai_responses", "anthropic_messages"] {
        let root = temporary_root(&format!("e2e-no-dangling-{provider}"));
        // The child requests carry the task needle; the parent's continuation
        // request carries the folded child output ("R-0") regardless of the
        // provider wire shape.
        let server = spawn_probe_server(vec![
            ProbeRule {
                needle: "job-0".to_string(),
                status: 200,
                body: match provider {
                    "openai_responses" => wire_responses_text("R-0"),
                    "anthropic_messages" => wire_anthropic_text("R-0"),
                    _ => wire_text("R-0"),
                },
                delay_ms: 0,
            },
            ProbeRule {
                needle: "job-1".to_string(),
                status: 200,
                body: match provider {
                    "openai_responses" => wire_responses_text("R-1"),
                    "anthropic_messages" => wire_anthropic_text("R-1"),
                    _ => wire_text("R-1"),
                },
                delay_ms: 0,
            },
            ProbeRule {
                needle: "R-0".to_string(),
                status: 200,
                body: match provider {
                    "openai_responses" => wire_responses_text("parent done"),
                    "anthropic_messages" => wire_anthropic_text("parent done"),
                    _ => wire_text("parent done"),
                },
                delay_ms: 0,
            },
        ]);
        let state = spawn_state(server.port(), &root, true, |config| {
            config.provider = Some(provider.to_string());
            config.approval_mode = "all".to_string();
            config.parallel = true;
        });
        let admitted = admit_structured(
            &state.service(),
            json!({
                "tasks": [
                    {"id": "t0", "input": "job-0"},
                    {"id": "t1", "input": "job-1"},
                ],
                "mode": "all",
                "max_concurrency": 2,
            }),
        )
        .await;
        wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;
        assert_eq!(
            durable_run_status(&state, &admitted.run_id),
            "completed",
            "provider {provider} completes after folding the results"
        );
        assert_eq!(
            server.request_count(),
            3,
            "provider {provider} child rounds + continuation"
        );
        let bodies = server.request_bodies();
        let continuation = bodies
            .iter()
            .find(|raw| raw.contains("R-0"))
            .and_then(|raw| serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap_or_default()).ok())
            .unwrap_or_else(|| {
                panic!(
                    "provider {provider}: no captured body carries the folded child output; bodies: {:?}",
                    bodies.iter().map(|raw| raw.chars().take(1600).collect::<String>()).collect::<Vec<_>>()
                )
            });
        assert!(
            !request_has_dangling_tool_result(&continuation),
            "provider {provider} continuation must carry no dangling tool result: {continuation}"
        );
        fs::remove_dir_all(&root).expect("temporary root should be removed");
    }
}

/// The DENIED delegation path (approval_mode never — no approval gate, no
/// handoff) folds the typed denial as a full matching pair: the parent's
/// continuation request must be provider-legal with no dangling tool result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_denied_delegation_continuation_request_has_no_dangling_tool_result() {
    let root = temporary_root("e2e-denied-delegation");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "approval_denied".to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "never".to_string();
        config.task = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({"child": {"id": "c1", "input": "child job"}}),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&events, "subagent.started").is_empty(),
        "a denied delegation never starts a child"
    );
    // The parent's continuation request folds the typed denial and is
    // provider-legal (the synthesized assistant tool_call precedes the
    // tool result).
    assert_eq!(
        server.request_count(),
        1,
        "only the parent continuation round"
    );
    let continuation = server
        .request_body(0)
        .expect("the parent continuation request body");
    assert!(
        continuation.to_string().contains("approval_denied"),
        "the typed denial must reach the provider in history: {continuation}"
    );
    assert!(
        !request_has_dangling_tool_result(&continuation),
        "the denied-delegation continuation must carry no dangling tool result: {continuation}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The NATIVE deny policy (A4 `NativeDenyPolicy` through
/// `ApprovalBridge::decide`) is production-reachable for parallel
/// delegation: the typed denial is folded, the loop continues reasoning,
/// and NO child is ever admitted or started — even though the RSS
/// approval gate (approval_mode all) approved the handoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_native_deny_policy_folds_typed_denial_and_never_starts_children() {
    let root = temporary_root("e2e-parallel-native-deny");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "approval_denied".to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.native_deny_tools = vec!["parallel.run".to_string()];
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [{"id": "t0", "input": "job-0"}, {"id": "t1", "input": "job-1"}],
            "mode": "all",
            "max_concurrency": 2,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&events, "subagent.started").is_empty(),
        "a natively-denied parallel batch never starts a child"
    );
    assert!(
        child_events(&events, "subagent.completed").is_empty(),
        "a natively-denied parallel batch never completes a child"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    assert!(
        links["rows"].as_array().is_none_or(Vec::is_empty),
        "a natively-denied parallel batch leaves no child links"
    );
    // The typed denial reaches the provider in history and the continuation
    // request stays provider-legal (no dangling tool result).
    assert_eq!(
        server.request_count(),
        1,
        "only the parent continuation round"
    );
    let continuation = server
        .request_body(0)
        .expect("the parent continuation request body");
    assert!(
        continuation.to_string().contains("approval_denied"),
        "the native denial must be folded into history: {continuation}"
    );
    assert!(
        !request_has_dangling_tool_result(&continuation),
        "the denied continuation must carry no dangling tool result: {continuation}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The NATIVE deny policy denies SUBAGENT delegation by risk class
/// (`execute`): the typed denial is folded and no child is ever admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_subagent_native_deny_policy_folds_typed_denial_and_never_starts_the_child() {
    let root = temporary_root("e2e-subagent-native-deny");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "approval_denied".to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.task = true;
        config.native_deny_risks = vec!["execute".to_string()];
    });
    let admitted = admit_structured(
        &state.service(),
        json!({"child": {"id": "c1", "input": "child job"}}),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&events, "subagent.started").is_empty(),
        "a natively-denied subagent never starts"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    assert!(
        links["rows"].as_array().is_none_or(Vec::is_empty),
        "a natively-denied subagent leaves no child link"
    );
    assert_eq!(
        server.request_count(),
        1,
        "only the parent continuation round"
    );
    let continuation = server
        .request_body(0)
        .expect("the parent continuation request body");
    assert!(
        continuation.to_string().contains("approval_denied"),
        "the risk-class native denial must be folded into history: {continuation}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The `native_hard_deny` CONFIG surface (fed to the RSS approval policy,
/// not approval_mode never) denies delegation in production: the typed
/// denial is folded and no child is ever admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_native_hard_deny_config_denies_delegation_in_production() {
    let root = temporary_root("e2e-hard-deny-config");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "approval_denied".to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.native_hard_deny = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [{"id": "t0", "input": "job-0"}],
            "mode": "all",
            "max_concurrency": 1,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&events, "subagent.started").is_empty(),
        "native_hard_deny must deny the delegation before any child starts"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    assert!(
        links["rows"].as_array().is_none_or(Vec::is_empty),
        "native_hard_deny leaves no child links"
    );
    let continuation = server
        .request_body(0)
        .expect("the parent continuation request body");
    assert!(
        continuation.to_string().contains("approval_denied"),
        "native_hard_deny must fold the typed denial: {continuation}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// A natively-denied delegation NEVER parks: in approval_mode auto (which
/// would otherwise park the execute-class delegation), no durable approval
/// row is created and the loop continues with the typed denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_native_deny_prevents_the_park_in_auto_mode() {
    let root = temporary_root("e2e-native-deny-no-park");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "approval_denied".to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "auto".to_string();
        config.task = true;
        config.native_deny_tools = vec!["subagent.run".to_string()];
    });
    let admitted = admit_structured(
        &state.service(),
        json!({"child": {"id": "c1", "input": "child job"}}),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&events, "subagent.started").is_empty(),
        "a natively-denied delegation never starts a child"
    );
    assert!(
        event_types(&events)
            .iter()
            .all(|ty| ty != "approval.required"),
        "a natively-denied delegation must never create a durable approval park"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    assert!(
        links["rows"].as_array().is_none_or(Vec::is_empty),
        "a natively-denied delegation leaves no child links"
    );
    // The run completed by itself (no park, no resume): the typed denial was
    // folded and the loop continued immediately.
    assert_eq!(
        server.request_count(),
        1,
        "only the parent continuation round"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// A retryable provider error (429) on the parent's FIRST provider round
/// after a handoff must NEVER re-enter the delegation gate: the RSS loop
/// state carries the delegation-completed flag, so the retry goes directly
/// to the provider phase. With UNLIMITED fanout (max_fanout = 0), a gate
/// re-entry would re-admit every child — this test proves the child
/// calls, subagent.started/completed events, folded result pairs, and
/// durable links are all EXACT-ONCE. (This replaces the previous
/// mirror-fanout e2e whose premise — the retry re-entering the gate and
/// triggering a second handoff — was the bug being fixed; the policy-level
/// fanout rejection stays covered by `parallel_tests.rs`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parallel_unlimited_fanout_429_retry_is_exact_once() {
    let root = temporary_root("e2e-parallel-429-exact-once");
    let mut rules = Vec::new();
    for index in 0..4 {
        rules.push(ProbeRule {
            needle: format!("job-{index}"),
            status: 200,
            body: wire_text(&format!("R-{index}")),
            delay_ms: 0,
        });
    }
    rules.push(ProbeRule {
        needle: PARENT_RULE.to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    });
    // The FIRST request whose body carries "R-0" (the parent's first
    // continuation after the folded results) is a retryable 429; the
    // retried attempt succeeds.
    let server = spawn_probe_server_with_first_round_429("R-0", rules);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.base_retry_delay_ms = 0;
        config.max_retry_delay_ms = 0;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [
                {"id": "t0", "input": "job-0"},
                {"id": "t1", "input": "job-1"},
                {"id": "t2", "input": "job-2"},
                {"id": "t3", "input": "job-3"},
            ],
            "mode": "all",
            "max_concurrency": 2,
            // UNLIMITED fanout: a gate re-entry would admit 4 MORE
            // children (the deterministic slot keys replay) and duplicate
            // every lifecycle artifact.
            "max_fanout": 0,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // 4 child rounds + 2 parent attempts (the first throttled 429, the
    // retried continuation) — never 4 + 4 + 2.
    assert_eq!(
        server.request_count(),
        6,
        "exactly four child rounds and two parent attempts — the retry must not re-admit children"
    );
    // The successful (second) parent continuation carries the folded
    // result pair EXACTLY ONCE per child: 4 assistant tool calls + 4 tool
    // results, never 8.
    let bodies = server.request_bodies();
    let continuations = bodies
        .iter()
        .filter(|raw| raw.contains(PARENT_RULE))
        .collect::<Vec<_>>();
    assert_eq!(
        continuations.len(),
        2,
        "two parent continuation requests (throttled 429 + retried success)"
    );
    let final_continuation: JsonValue = continuations
        .last()
        .and_then(|raw| serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap_or_default()).ok())
        .expect("the final continuation body");
    // On the OpenAI Chat wire a tool result is a `role: "tool"` message
    // with a message-level `tool_call_id` (string content) — one per folded
    // child result, exactly once per child.
    let tool_results = final_continuation
        .get("messages")
        .and_then(JsonValue::as_array)
        .map(|messages| {
            messages
                .iter()
                .filter(|message| {
                    message["role"] == "tool"
                        && message["tool_call_id"]
                            .as_str()
                            .is_some_and(|id| !id.is_empty())
                })
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        tool_results, 4,
        "the result pair is folded exactly once per child in the final continuation"
    );
    assert!(
        !request_has_dangling_tool_result(&final_continuation),
        "the final continuation carries no dangling tool result"
    );

    // Child lifecycle events exactly once per child: 4 started + 4
    // completed, all before the parent's terminal.
    let events = replayed_events(&state, &admitted.run_id);
    let started = child_events(&events, "subagent.started");
    let completed = child_events(&events, "subagent.completed");
    assert_eq!(started.len(), 4, "one subagent.started per real child");
    assert_eq!(
        completed.len(),
        4,
        "one subagent.completed per durable child terminal"
    );
    let run_completed_seq = events
        .iter()
        .find(|(_, ty, _)| ty == "run.completed")
        .map(|(seq, _, _)| *seq)
        .expect("parent terminal");
    for (seq, _, _) in &events {
        assert!(
            *seq <= run_completed_seq,
            "no child event after the parent terminal"
        );
    }

    // Durable links: exactly one row per child, every child completed.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(rows.len(), 4, "one durable child_run_links row per child");
    for row in &rows {
        let child_id = row.get(1).and_then(JsonValue::as_str).expect("child id");
        assert_eq!(
            durable_run_status(&state, child_id),
            "completed",
            "every child reaches a durable completed terminal: {child_id}"
        );
        assert_eq!(
            row.get(4).and_then(JsonValue::as_str),
            Some("completed"),
            "the child link state stays terminal — never regressed to active"
        );
    }

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The `supervise_batch_bounded` grace-drop path (children still in flight
/// when the deadline + grace expire) must NOT leak: the RAII guard cancels
/// the admitted children, every child reaches a durable terminal, and the
/// capacity permits are all released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_grace_drop_cancels_in_flight_children_and_releases_permits() {
    let root = temporary_root("e2e-grace-drop");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "hung".to_string(),
        status: 200,
        body: wire_text("never"),
        delay_ms: 8_000,
    }]);
    let max_concurrent = 4usize;
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.max_concurrent_runs = max_concurrent;
        // The batch deadline + a SHORT grace expire while both children are
        // hung on their provider rounds: the children's own deadlines land
        // AFTER the batch's grace window, so the in-flight slot futures are
        // REALLY dropped (the grace-drop window) and the RAII guard must
        // compensate.
        config.run_timeout = Duration::from_secs(2);
        config.cancellation_grace = Duration::from_millis(20);
    });
    let service = state.service();
    let admitted = admit_structured(
        &service,
        json!({
            "tasks": [
                {"id": "t0", "input": "hung"},
                {"id": "t1", "input": "hung"},
            ],
            "mode": "all",
            "max_concurrency": 2,
        }),
    )
    .await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");
    // Every admitted child reaches a DURABLE terminal (cancelled) within a
    // bounded time — no orphaned run holds a permit forever.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!rows.is_empty(), "the admitted children are durably linked");
    for row in &rows {
        let child_id = row.get(1).and_then(JsonValue::as_str).expect("child id");
        wait_for(Duration::from_secs(30), || {
            durable_run_status(&state, child_id) != "started"
                && durable_run_status(&state, child_id) != "running"
        });
        assert!(
            matches!(
                durable_run_status(&state, child_id).as_str(),
                "cancelled" | "failed"
            ),
            "the grace-dropped child reaches a durable terminal: {child_id}"
        );
    }
    // All capacity permits are released: the parent AND both children are
    // terminal, so every permit is back.
    wait_for(Duration::from_secs(30), || {
        service.available_capacity() == max_concurrent
    });
    assert_eq!(
        service.available_capacity(),
        max_concurrent,
        "the grace drop must release every permit"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// An admission whose storage critical section stalls LONGER than the batch
/// deadline + grace (the admission is still in flight when the slot future
/// is dropped) must NOT orphan the child: the PRE-admission RAII guard
/// (created before the `admit` await) starts a provably-bounded compensation
/// watcher that, the moment the detached admission completes, immediately
/// cancels the child, commits its durable terminal, and releases the
/// permit/handle/link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_admission_in_flight_drop_stalling_past_grace_is_compensated() {
    let root = temporary_root("e2e-admission-stall");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "hung".to_string(),
        status: 200,
        body: wire_text("never"),
        delay_ms: 8_000,
    }]);
    let max_concurrent = 4usize;
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.max_concurrent_runs = max_concurrent;
        // The batch deadline + a SHORT grace expire while the child's
        // admission is still blocked in its storage critical section (the
        // store write lock): the slot future is REALLY dropped with the
        // admission in flight.
        config.run_timeout = Duration::from_secs(2);
        config.cancellation_grace = Duration::from_millis(20);
    });
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({
                "tasks": [{"id": "t0", "input": "hung"}],
                "mode": "all",
                "max_concurrency": 1,
            }),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: JsonValue::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("the parent admission should succeed");
    // The store WRITE lock is now free (the parent admission completed).
    // Hold the shared READ lock (readers barge past waiting writers) so the
    // child's admission critical section stalls past the batch grace. The
    // guard is a synchronous parking_lot guard: it must not span an await,
    // so the stall uses a synchronous sleep (the second runtime worker keeps
    // the parent's tasks running).
    let store = state.store();
    let store_guard = store.read();
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), String::new()),
    );
    std::thread::sleep(Duration::from_millis(2_500));
    drop(store_guard);
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");
    // The child never ran a provider round: no worker was ever spawned on
    // it (the parent never reached the provider either).
    assert_eq!(
        server.request_count(),
        0,
        "the stalled admission's child must never execute a provider round"
    );
    // The late-completing admission really created one child link; the
    // compensation durably terminates the child and releases every permit.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        rows.len(),
        1,
        "the detached admission created one child link"
    );
    let child_id = rows[0]
        .get(1)
        .and_then(JsonValue::as_str)
        .expect("child id")
        .to_string();
    wait_for(Duration::from_secs(30), || {
        matches!(
            durable_run_status(&state, &child_id).as_str(),
            "cancelled" | "failed"
        )
    });
    let child_status = durable_run_status(&state, &child_id);
    assert!(
        matches!(child_status.as_str(), "cancelled" | "failed"),
        "the admission-in-flight child reaches a durable terminal: {child_status}"
    );
    // If the parent already committed its terminal, the active-parent guard
    // intentionally rejects this late mirror update. A terminal state is also
    // valid when the update won before the parent terminal race.
    let observed_link_state = persistence
        .list_children(&admitted.run_id)
        .expect("list children")
        .get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get(4))
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        matches!(
            observed_link_state.as_str(),
            "pending" | "active" | "completed" | "failed" | "cancelled"
        ),
        "the durable link retains a valid lifecycle state: {observed_link_state}"
    );
    // Every capacity permit is released (parent + child both terminal).
    wait_for(Duration::from_secs(30), || {
        service.available_capacity() == max_concurrent
    });
    assert_eq!(
        service.available_capacity(),
        max_concurrent,
        "the in-flight admission drop must release every permit"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// A6 final P2 (review round): compensation watcher lifecycle + durable
// canonical-event append
// ---------------------------------------------------------------------------

/// Final P2 #1 (RED): the pre-admission compensation watcher must NOT give up
/// after the old wall-clock bound — `terminal_commit_retry_window × 5` polls
/// of 100 ms (500 ms with the SHORT 1 s window configured here) — and leave
/// an orphan. The detached admission is stalled LONGER than the old bound
/// (2.5 s): with the old watcher the child would stay durably `running` with
/// a held permit and no worker. The watcher must keep polling (bounded only
/// by service shutdown), find the late-completing admission, and compensate
/// it past the old give-up point.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_admission_in_flight_drop_past_old_watcher_bound_is_still_compensated() {
    let root = temporary_root("e2e-admission-past-bound");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "hung".to_string(),
        status: 200,
        body: wire_text("never"),
        delay_ms: 8_000,
    }]);
    let max_concurrent = 4usize;
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.max_concurrent_runs = max_concurrent;
        // A SHORT terminal-commit window: the OLD watcher bound was
        // window × 5 attempts × 100 ms = 500 ms. The 2.5 s stall below
        // exceeds it, so only a watcher without a wall-clock give-up can
        // still compensate the late admission.
        config.terminal_commit_retry_window = Duration::from_secs(1);
        config.run_timeout = Duration::from_secs(2);
        config.cancellation_grace = Duration::from_millis(20);
    });
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({
                "tasks": [{"id": "t0", "input": "hung"}],
                "mode": "all",
                "max_concurrency": 1,
            }),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: JsonValue::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("the parent admission should succeed");
    // The store READ lock stalls the child's admission critical section past
    // the batch grace (the slot future is REALLY dropped with the admission
    // in flight) AND past the OLD watcher give-up point.
    let store = state.store();
    let store_guard = store.read();
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), String::new()),
    );
    std::thread::sleep(Duration::from_millis(2_500));
    drop(store_guard);
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");
    // The child never ran a provider round: no worker was ever spawned on it.
    assert_eq!(
        server.request_count(),
        0,
        "the stalled admission's child must never execute a provider round"
    );
    // The late-completing admission really created one child link.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        rows.len(),
        1,
        "the detached admission created one child link"
    );
    let child_id = rows[0]
        .get(1)
        .and_then(JsonValue::as_str)
        .expect("child id")
        .to_string();
    // THE P2 assertion: the child still reaches a durable terminal although
    // the admission completed AFTER the old watcher give-up point (500 ms).
    wait_for(Duration::from_secs(10), || {
        matches!(
            durable_run_status(&state, &child_id).as_str(),
            "cancelled" | "failed"
        )
    });
    let child_status = durable_run_status(&state, &child_id);
    assert!(
        matches!(child_status.as_str(), "cancelled" | "failed"),
        "the admission-in-flight child is compensated past the old watcher \
         bound: {child_status}"
    );
    // The child may finish after the parent terminal. In that race the
    // active-parent guard intentionally rejects a late link-state write;
    // a terminal link is also valid when the write won before the race.
    let observed_link_state = persistence
        .list_children(&admitted.run_id)
        .expect("list children")
        .get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get(4))
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        matches!(
            observed_link_state.as_str(),
            "pending" | "active" | "completed" | "failed" | "cancelled"
        ),
        "the durable link retains a valid lifecycle state: {observed_link_state}"
    );
    // Every capacity permit is released (parent + child both terminal).
    wait_for(Duration::from_secs(10), || {
        service.available_capacity() == max_concurrent
    });

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Final P2 #1 (RED): the compensation watcher's lifecycle is bounded by
/// service shutdown, and a storage that NEVER returns leaves no
/// permanently-running durable row on the normal recovery path. The
/// admission is stalled forever: the watcher keeps polling (deduplicated per
/// deterministic slot key — at most one watcher per key), exits when the
/// service stops admitting (the SIGINT path), and the late admission — if it
/// ever completes after the watcher exited — is durably failed by the
/// restart-recovery orphan sweep when the state is reopened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_compensation_watcher_stops_on_shutdown_and_restart_recovers() {
    let root = temporary_root("e2e-watcher-shutdown");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "hung".to_string(),
        status: 200,
        body: wire_text("never"),
        delay_ms: 8_000,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.max_concurrent_runs = 4;
        config.terminal_commit_retry_window = Duration::from_secs(1);
        config.run_timeout = Duration::from_secs(2);
        config.cancellation_grace = Duration::from_millis(20);
    });
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({
                "tasks": [{"id": "t0", "input": "hung"}],
                "mode": "all",
                "max_concurrency": 1,
            }),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: JsonValue::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("the parent admission should succeed");
    let store = state.store();
    // The admission is stalled FOREVER (the read lock is released only at
    // the end of the test).
    let store_guard = store.read();
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), String::new()),
    );
    // The batch grace-drop happened (~2 s): exactly ONE watcher is live for
    // the deterministic slot key (repeated drops of the same key never spawn
    // a second watcher), still polling because the admission never returned.
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(
        service.compensation_watcher_count(),
        1,
        "one deduplicated watcher per deterministic admission key"
    );
    // Service shutdown (SIGINT path): admission closes and the watcher ends
    // with the service — it never outlives the process.
    service.stop_admission();
    wait_for(Duration::from_secs(5), || {
        service.compensation_watcher_count() == 0
    });
    // Storage NEVER returned: the admission commit is transactional, so no
    // durable child row (and no durable link) was ever created by the
    // stalled admission.
    let persistence = state.persistence().expect("durable persistence");
    assert!(
        persistence
            .list_children(&admitted.run_id)
            .expect("list children")
            .get("rows")
            .and_then(JsonValue::as_array)
            .map(|rows| rows.is_empty())
            .unwrap_or(true),
        "no durable child link exists while the admission never completed"
    );
    // Release the stall: the detached admission now completes AFTER the
    // watcher exited (the shutdown/restart window) and lands durably
    // `running` with no worker and no watcher.
    drop(store_guard);
    wait_for(Duration::from_secs(10), || {
        persistence
            .run_list("", "running")
            .ok()
            .map(|data| {
                data.get("rows")
                    .and_then(JsonValue::as_array)
                    .is_some_and(|rows| !rows.is_empty())
            })
            .unwrap_or(false)
    });
    // The normal recovery path (restart) must not leave permanently-running
    // rows: the restart-recovery orphan sweep durably fails every interrupted
    // `running` row on the next open.
    let reopened = spawn_state_with_db(server.port(), &root, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let reopened_persistence = reopened.persistence().expect("durable persistence");
    let running = reopened_persistence
        .run_list("", "running")
        .expect("run list after restart");
    assert_eq!(
        running
            .get("rows")
            .and_then(JsonValue::as_array)
            .map(|rows| rows.len())
            .unwrap_or(0),
        0,
        "restart recovery leaves no permanently-running rows"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Final P2 #1 (RED): the compensation-watcher task count is bounded by the
/// admission/concurrency upper bound — a watcher exists only for a REAL
/// in-flight admission, never for a slot the admission refused. With
/// `max_concurrent_runs = 3` (the parent holds one permit) a 4-task batch
/// admits exactly 2 children; the 2 refused slots are typed failures and
/// produce no watcher, so the live watcher count never exceeds
/// `capacity - 1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_compensation_watcher_count_is_bounded_by_admission_capacity() {
    let root = temporary_root("e2e-watcher-bound");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "hung".to_string(),
        status: 200,
        body: wire_text("never"),
        delay_ms: 8_000,
    }]);
    let capacity = 3usize;
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
        config.max_concurrent_runs = capacity;
        config.terminal_commit_retry_window = Duration::from_secs(1);
        // A WIDE deadline margin: the children are admitted (links appear)
        // and the store READ lock is taken LONG before the batch deadline
        // fires, so the grace-drop always lands while the compensation is
        // stalled — even under heavy parallel-suite load.
        config.run_timeout = Duration::from_secs(4);
        config.cancellation_grace = Duration::from_millis(20);
    });
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({
                "tasks": [
                    {"id": "t0", "input": "hung"},
                    {"id": "t1", "input": "hung"},
                    {"id": "t2", "input": "hung"},
                    {"id": "t3", "input": "hung"},
                ],
                "mode": "all",
                "max_concurrency": 4,
            }),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: JsonValue::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("the parent admission should succeed");
    // The children are admitted FIRST (the store is free), then the store
    // READ lock is taken to stall the batch-grace compensation: every
    // watcher stays registered while its durable terminal commit waits for
    // the write lock — a STABLE, observable count. Synchronization is the
    // DURABLE link row (created at admission time, independent of the
    // provider server's serial connection handling).
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), String::new()),
    );
    let persistence = state.persistence().expect("durable persistence");
    wait_for(Duration::from_secs(10), || {
        persistence
            .list_children(&admitted.run_id)
            .ok()
            .map(|data| {
                data.get("rows")
                    .and_then(JsonValue::as_array)
                    .is_some_and(|rows| rows.len() >= capacity - 1)
            })
            .unwrap_or(false)
    });
    let store = state.store();
    let store_guard = store.read();
    // The batch grace-drop lands while the compensation is stalled by the
    // store READ lock: the parent holds one permit, so exactly
    // `capacity - 1` children were admitted and are in flight. The refused
    // slots (capacity) are typed failures and spawn NO watcher, so the live
    // count is bounded by the admission upper bound — and stays stable
    // until the lock is released.
    std::thread::sleep(Duration::from_millis(4_500));
    wait_for(Duration::from_secs(10), || {
        service.compensation_watcher_count() == capacity - 1
    });
    // Releasing the store lets the compensation terminal commits land; every
    // watcher then exits and unregisters (no leaked watcher tasks).
    drop(store_guard);
    wait_for(Duration::from_secs(15), || {
        service.compensation_watcher_count() == 0
    });

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Final P2 #2 (RED): the canonical `subagent.completed` append is never
/// `let _=`-ignored. A durable append fault (injected) is retried with the
/// bounded retry; when storage recovers the event lands EXACTLY once (never
/// a duplicate) and the child's real outcome is folded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_subagent_completed_append_fault_is_retried_exactly_once() {
    let root = temporary_root("e2e-completed-retry");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "child job".to_string(),
            status: 200,
            body: wire_text("R-child"),
            delay_ms: 0,
        },
        ProbeRule {
            needle: PARENT_RULE.to_string(),
            status: 200,
            body: wire_text("parent done"),
            delay_ms: 0,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.task = true;
    });
    // Fault injection: the FIRST durable `subagent.completed` append fails;
    // the bounded retry must recover and still emit the event exactly once.
    state
        .persistence()
        .expect("durable persistence")
        .fail_next_event_appends("subagent.completed", 1);
    let admitted = admit_structured(
        &state.service(),
        json!({
            "child": {"id": "c1", "input": "child job"},
            "depth": 0,
            "max_depth": 4,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // The child really completed: its durable terminal is committed.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 1);
    let child_id = rows[0]
        .get(1)
        .and_then(JsonValue::as_str)
        .expect("child id")
        .to_string();
    assert_eq!(durable_run_status(&state, &child_id), "completed");
    // The retried canonical event exists EXACTLY once (no duplicate) and the
    // started event is untouched by the fault.
    let events = replayed_events(&state, &admitted.run_id);
    assert_eq!(child_events(&events, "subagent.started").len(), 1);
    assert_eq!(
        child_events(&events, "subagent.completed").len(),
        1,
        "the retried append emits subagent.completed exactly once"
    );
    // The child's real output was folded into the parent's continuation
    // (the retry path never turns a recovered event into a typed failure).
    assert!(
        server
            .request_bodies()
            .iter()
            .filter(|raw| raw.contains(PARENT_RULE))
            .any(|raw| raw.contains("R-child")),
        "the parent folds the child's real completed output"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Final P2 #2 (RED): when the durable `subagent.completed` append keeps
/// failing past the bounded retries, the failure is promoted to a TYPED
/// parent failure — the child's outcome/output never reaches the parent's
/// history before (or without) the durable event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_subagent_completed_append_failure_promotes_to_typed_parent_failure() {
    let root = temporary_root("e2e-completed-fail");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "child job".to_string(),
            status: 200,
            body: wire_text("R-child"),
            delay_ms: 0,
        },
        ProbeRule {
            needle: PARENT_RULE.to_string(),
            status: 200,
            body: wire_text("parent done"),
            delay_ms: 0,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.task = true;
    });
    // Fault injection: EVERY `subagent.completed` append fails (far more
    // than the bounded retry attempts) — the durable event can never land.
    state
        .persistence()
        .expect("durable persistence")
        .fail_next_event_appends("subagent.completed", 32);
    let admitted = admit_structured(
        &state.service(),
        json!({
            "child": {"id": "c1", "input": "child job"},
            "depth": 0,
            "max_depth": 4,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    // The parent still completes: the typed slot failure is folded and the
    // loop continues reasoning.
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // The child's DURABLE terminal is completed (the child really ran), but
    // no `subagent.completed` event ever became durable.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 1);
    let child_id = rows[0]
        .get(1)
        .and_then(JsonValue::as_str)
        .expect("child id")
        .to_string();
    assert_eq!(durable_run_status(&state, &child_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert_eq!(child_events(&events, "subagent.started").len(), 1);
    assert_eq!(
        child_events(&events, "subagent.completed").len(),
        0,
        "no subagent.completed event exists when the durable append failed"
    );
    // The parent's durable history carries the TYPED failure, never the
    // child's completed output — the outcome must not precede the durable
    // event.
    let parent_row = persistence
        .run_get(&admitted.run_id)
        .expect("parent run row");
    let parent_session = parent_row
        .get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .and_then(|row| row.get(1))
        .and_then(JsonValue::as_str)
        .expect("parent session id")
        .to_string();
    let messages = durable_message_rows(&state, &parent_session);
    let rendered: Vec<String> = messages
        .iter()
        .map(|(_, _, content, _)| serde_json::to_string(content).unwrap_or_default())
        .collect();
    assert!(
        rendered
            .iter()
            .any(|text| text.contains("completed_event_append_failed")),
        "the typed append failure is folded into the parent's history"
    );
    assert!(
        rendered.iter().all(|text| !text.contains("R-child")),
        "the child's completed output must never precede the durable event"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// A REPLAYED child admission (the deterministic slot key already admitted —
/// for example a re-executed handoff) must never re-drive the child: no
/// second worker, no re-emitted `subagent.started`/`subagent.completed`, no
/// link regression. The executor awaits the EXISTING run's terminal and
/// reports its durable outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_replayed_child_admission_never_re_drives_a_terminal_child() {
    let root = temporary_root("e2e-replay-terminal-child");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "job-0".to_string(),
            status: 200,
            body: wire_text("R-0"),
            delay_ms: 0,
        },
        // The parent's continuation carries the folded pair (message-level
        // tool_call_id on the OpenAI wire) and the child's output text.
        ProbeRule {
            needle: PARENT_RULE.to_string(),
            status: 200,
            body: wire_text("parent done"),
            delay_ms: 0,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let service = state.service();
    // Admit the parent with the structured delegation input FIRST (its run
    // id keys the deterministic child idempotency key).
    let parent = service
        .admit(AdmitRunRequest {
            input: json!({
                "tasks": [{"id": "t0", "input": "job-0"}],
                "mode": "all",
                "max_concurrency": 1,
            }),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: JsonValue::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("the parent admission should succeed");
    // Admit the child DIRECTLY with the exact deterministic key/hash
    // `execute_child` derives for slot 0 of the parallel batch, and drive it
    // to its durable terminal (provider round #1).
    let slot_key = format!("child:{}:parallel:0", parent.run_id);
    let slot_hash = fnv1a64(&format!(
        "{slot_key}:{}:test-model",
        serde_json::to_string(&json!("job-0")).expect("input json")
    ));
    let child = service
        .admit(AdmitRunRequest {
            input: json!("job-0"),
            session_id: None,
            model: Some("test-model".to_string()),
            provider: None,
            parent_run_id: Some(parent.run_id.clone()),
            instructions: None,
            platform: "agent:child".to_string(),
            idempotency_key: Some(slot_key),
            idempotency_hash: Some(slot_hash),
            origin_actor: None,
            request_overrides: JsonValue::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("the direct child admission should succeed");
    tokio::spawn(
        service
            .clone()
            .run_worker(child.run_id.clone(), String::new()),
    );
    wait_terminal(&service, &child.run_id, Duration::from_secs(60)).await;
    assert_eq!(durable_run_status(&state, &child.run_id), "completed");
    // The child link already reached its terminal (pending -> completed).
    let persistence = state.persistence().expect("durable persistence");
    let _ = persistence
        .link_state(&json!({
            "parent_run_id": parent.run_id,
            "child_run_id": child.run_id,
            "ordinal": 0,
            "relation": "",
            "state": "completed",
            "now_ms": 0,
        }))
        .expect("link state");
    let requests_after_child = server.request_count();

    // NOW the parent runs: the gate approves, the handoff executes, and
    // `execute_child` re-admits the SAME slot -> idempotent replay of the
    // terminal child.
    tokio::spawn(
        service
            .clone()
            .run_worker(parent.run_id.clone(), String::new()),
    );
    wait_terminal(&service, &parent.run_id, Duration::from_secs(60)).await;
    assert_eq!(durable_run_status(&state, &parent.run_id), "completed");
    assert_eq!(
        server.request_count(),
        requests_after_child + 1,
        "the replay must not re-drive the terminal child: exactly one parent continuation round"
    );
    // No lifecycle artifact is re-emitted for the replayed child.
    let events = replayed_events(&state, &parent.run_id);
    assert_eq!(
        child_events(&events, "subagent.started").len(),
        0,
        "a replayed admission never re-emits subagent.started"
    );
    assert_eq!(
        child_events(&events, "subagent.completed").len(),
        0,
        "a replayed admission never re-emits subagent.completed"
    );
    // The child's durable status is untouched (still completed — never
    // re-driven) and the link stays terminal (never regressed to active).
    assert_eq!(
        durable_run_status(&state, &child.run_id),
        "completed",
        "the replayed child is never re-driven"
    );
    let links = persistence
        .list_children(&parent.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(rows.len(), 1, "exactly one durable link row");
    assert_eq!(
        rows[0].get(4).and_then(JsonValue::as_str),
        Some("completed"),
        "the link state stays terminal — never regressed to active"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Re-entering `run_worker` on an ALREADY-TERMINAL run must be a strict
/// no-op: no provider call, no message, no event side effects. Every
/// `run_worker` entry first checks the authoritative active status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_run_worker_on_a_terminal_run_is_a_strict_noop() {
    let root = temporary_root("e2e-run-worker-terminal-noop");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "hello".to_string(),
        status: 200,
        body: wire_text("hi"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |_| {});
    let service = state.service();
    let admitted = admit_and_wait(&service, "hello", Duration::from_secs(60)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let requests_after_first = server.request_count();
    let events_after_first = replayed_events(&state, &admitted.run_id);

    // Re-enter the worker on the terminal run (as a replayed admission
    // would) and give it time to do damage if it were going to.
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), String::new()),
    );
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        server.request_count(),
        requests_after_first,
        "a terminal run must never execute a provider round"
    );
    assert_eq!(
        replayed_events(&state, &admitted.run_id),
        events_after_first,
        "a terminal run must never emit new events"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// A stop that lands while a child is in flight and another slot is still
/// QUEUED must never start the queued child: the pre-admit re-check (and
/// the supervision cancel) is authoritative after the stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_stop_with_a_queued_slot_never_starts_the_queued_child() {
    let root = temporary_root("e2e-stop-queued-slot");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: "hung".to_string(),
        status: 200,
        body: wire_text("never"),
        delay_ms: 8_000,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let service = state.service();
    let admitted = admit_structured(
        &service,
        json!({
            "tasks": [
                {"id": "t0", "input": "hung"},
                {"id": "t1", "input": "never-1"},
            ],
            "mode": "all",
            // Only ONE slot in flight at a time: slot 1 is queued behind
            // the hung slot 0 when the stop lands.
            "max_concurrency": 1,
        }),
    )
    .await;
    // Wait until the in-flight child is REALLY started (the durable
    // subagent.started event), THEN stop: the stop must never start the
    // queued slot 1.
    wait_for(Duration::from_secs(15), || {
        replayed_events(&state, &admitted.run_id)
            .iter()
            .any(|(_, ty, _)| ty == "subagent.started")
    });
    service.stop(&admitted.run_id).expect("stop");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");
    let events = replayed_events(&state, &admitted.run_id);
    let started = child_events(&events, "subagent.started");
    assert_eq!(
        started.len(),
        1,
        "exactly the in-flight child started; the queued child never starts after the stop"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    assert_eq!(
        links["rows"].as_array().map(Vec::len).unwrap_or(0),
        1,
        "the queued child leaves no link"
    );
    // Nothing follows the parent's terminal.
    let events = replayed_events(&state, &admitted.run_id);
    assert_eq!(
        event_types(&events).last().map(String::as_str),
        Some("run.cancelled"),
        "nothing may follow the parent's terminal"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_subagent_admission_refused_is_never_started_and_folds_typed() {
    let root = temporary_root("e2e-subagent-refused");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: PARENT_RULE.to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.task = true;
        // The parent holds the ONLY capacity permit: the child admission is
        // refused by the real semaphore.
        config.max_concurrent_runs = 1;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({"child": {"id": "c1", "input": "child job"}}),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&events, "subagent.started").is_empty(),
        "a refused admission must never emit subagent.started"
    );
    assert!(
        child_events(&events, "subagent.completed").is_empty(),
        "a refused admission must never emit subagent.completed"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 0, "no child link for a refused admission");
    // The typed refusal is folded and the parent continues (its own provider
    // round still runs).
    assert_eq!(server.request_count(), 1);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_subagent_depth_rejection_never_admits_nor_starts() {
    let root = temporary_root("e2e-subagent-depth");
    let server = spawn_probe_server(vec![ProbeRule {
        needle: PARENT_RULE.to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    }]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.task = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "child": {"id": "c1", "input": "child job"},
            // The nesting budget is already exhausted: the subagent policy
            // rejects the admission (depth_exceeded), so nothing starts.
            "depth": 1,
            "max_depth": 1,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    assert!(
        child_events(&events, "subagent.started").is_empty(),
        "a depth-rejected admission must never start a child"
    );
    let links = state
        .persistence()
        .expect("durable persistence")
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 0, "no child link for a rejected admission");
    assert_eq!(
        server.request_count(),
        1,
        "the parent continues reasoning after the rejection"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_parent_stop_propagates_cancellation_to_in_flight_children() {
    let root = temporary_root("e2e-parent-stop");
    let server = spawn_probe_server(vec![
        ProbeRule {
            needle: "slow-1".to_string(),
            status: 200,
            body: wire_text("R-slow-1"),
            delay_ms: 30_000,
        },
        ProbeRule {
            needle: "slow-2".to_string(),
            status: 200,
            body: wire_text("R-slow-2"),
            delay_ms: 30_000,
        },
    ]);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let service = state.service();
    let admitted = admit_structured(
        &service,
        json!({
            "tasks": [
                {"id": "t0", "input": "slow-1"},
                {"id": "t1", "input": "slow-2"},
            ],
            "mode": "all",
            "max_concurrency": 2,
        }),
    )
    .await;
    // Both children are admitted and stalled on their provider rounds.
    wait_for(Duration::from_secs(15), || server.request_count() >= 2);
    let status = service.stop(&admitted.run_id).expect("stop");
    assert_eq!(status, "stopping");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(60)).await;

    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");
    // Parent cancellation propagates: both children are durably cancelled.
    let persistence = state.persistence().expect("durable persistence");
    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let child_id = row.get(1).and_then(JsonValue::as_str).expect("child id");
        assert_eq!(
            durable_run_status(&state, child_id),
            "cancelled",
            "the stopped parent's child must be cancelled durably"
        );
    }
    // No post-terminal side effects: no child event lands after the parent's
    // run.cancelled terminal.
    let events = replayed_events(&state, &admitted.run_id);
    let cancelled_seq = events
        .iter()
        .find(|(_, ty, _)| ty == "run.cancelled")
        .map(|(seq, _, _)| *seq)
        .expect("parent cancelled terminal");
    assert_eq!(
        event_types(&events).last().map(String::as_str),
        Some("run.cancelled"),
        "nothing may follow the parent's terminal"
    );
    for (seq, ty, _) in &events {
        assert!(
            *seq <= cancelled_seq,
            "no event may land after the parent's terminal: {ty} at seq {seq}"
        );
    }

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_child_links_and_child_events_survive_restart() {
    let root = temporary_root("e2e-a6-restart");
    let mut rules = Vec::new();
    for index in 0..2 {
        rules.push(ProbeRule {
            needle: format!("job-{index}"),
            status: 200,
            body: wire_text(&format!("R-{index}")),
            delay_ms: 0,
        });
    }
    rules.push(ProbeRule {
        needle: PARENT_RULE.to_string(),
        status: 200,
        body: wire_text("parent done"),
        delay_ms: 0,
    });
    let server = spawn_probe_server(rules);
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.parallel = true;
    });
    let admitted = admit_structured(
        &state.service(),
        json!({
            "tasks": [
                {"id": "t0", "input": "job-0"},
                {"id": "t1", "input": "job-1"},
            ],
            "mode": "all",
            "max_concurrency": 1,
        }),
    )
    .await;
    wait_terminal(&state.service(), &admitted.run_id, Duration::from_secs(60)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");

    // Reopen the durable state (restart): the child links, the child run
    // rows (with parent identity), and the child lifecycle events all
    // survive in the state database.
    let mut config = base_config(server.port(), &root, true);
    config.approval_mode = "all".to_string();
    let reopened =
        AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
            .expect("reopened state with the built-in agent program");
    let persistence = reopened.persistence().expect("durable persistence");

    let links = persistence
        .list_children(&admitted.run_id)
        .expect("list children");
    let rows = links
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("link rows");
    assert_eq!(rows.len(), 2, "durable child links survive a restart");
    for row in rows {
        let child_id = row.get(1).and_then(JsonValue::as_str).expect("child id");
        let child = persistence.run_get(child_id).expect("child run row");
        let child_row = child
            .get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .expect("child row");
        assert_eq!(
            child_row.get(2).and_then(JsonValue::as_str),
            Some(admitted.run_id.as_str()),
            "the child's parent identity survives a restart"
        );
        assert_eq!(
            child_row.get(3).and_then(JsonValue::as_str),
            Some("completed"),
            "the child's durable terminal survives a restart"
        );
    }
    let events = persistence
        .event_replay(&json!({
            "run_id": admitted.run_id,
            "after_seq": 1,
            "max_events": 512,
            "max_bytes": 65536,
        }))
        .expect("event replay after restart");
    let mut started = 0;
    let mut completed = 0;
    if let Some(rows) = events.get("rows").and_then(JsonValue::as_array) {
        for row in rows {
            if let Some(row) = row.as_array() {
                let ty = row.get(3).and_then(JsonValue::as_str).unwrap_or("?");
                if ty == "subagent.started" {
                    started += 1;
                }
                if ty == "subagent.completed" {
                    completed += 1;
                }
            }
        }
    }
    assert_eq!(started, 2, "child started events survive a restart");
    assert_eq!(completed, 2, "child completed events survive a restart");

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// A5 review-fix fixtures (findings A-J): RED behavior tests
// ---------------------------------------------------------------------------

/// Admits a run (optionally against an existing session) and spawns the
/// worker exactly like the API server does.
async fn admit_and_spawn(
    service: &Arc<AgentService>,
    input: &str,
    session_id: Option<String>,
    platform: &str,
) -> rustscript_agent::AdmittedRun {
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!(input),
            session_id,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: platform.to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), input.to_string()),
    );
    admitted
}

/// Polls until the run handle reaches a terminal state (bounded).
async fn wait_terminal(service: &AgentService, run_id: &str, deadline: Duration) {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        if let Some(handle) = service.handle(run_id)
            && handle.is_terminal()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("run {run_id} did not reach a terminal within {deadline:?}");
}

/// Polls with a tight (1ms) cadence until the predicate holds.
fn wait_tight(deadline: Duration, mut predicate: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("condition did not hold within {deadline:?}");
}

/// Seeds a durable session with `count` alternating user/assistant text
/// messages (the same shape the serial loop plans over).
fn seed_durable_history(root: &std::path::Path, session_id: &str, count: usize) {
    let seed =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .expect("seed state");
    let seed_persistence = seed.persistence().expect("seed persistence");
    seed_persistence
        .session_create(&json!({
            "id": session_id,
            "profile": "default",
            "platform": "test",
            "account_id": "account-1",
            "chat_id": "chat-1",
            "thread_id": "",
            "user_id": "user-1",
            "generation": 1,
            "system_prompt": "",
            "model": "test-model",
            "provider": "openai_chat",
            "toolset_hash": "test-tools",
            "metadata_json": "{}",
            "title": "",
            "end_reason": "",
            "now_ms": 0
        }))
        .expect("session create");
    for index in 1..=count {
        let role = if index % 2 == 1 { "user" } else { "assistant" };
        let content = if role == "user" {
            format!(r#"[{{"type":"text","text":"message {index}"}}]"#)
        } else {
            format!(r#"[{{"type":"text","text":"reply {index}"}}]"#)
        };
        seed_persistence
            .message_append(&json!({
                "id": format!("m-{index}"),
                "session_id": session_id,
                "role": role,
                "content_json": content,
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 0,
                "metadata_json": "{}",
                "run_id": "seed-run",
                "finish_reason": "",
                "now_ms": 0
            }))
            .expect("message append");
    }
    drop(seed_persistence);
}

/// Builds a state over a specific SQLite path (for seeded-session fixtures).
fn spawn_state_with_db(
    server_port: u16,
    root: &std::path::Path,
    mutate: impl FnOnce(&mut AgentGatewayConfig),
) -> AgentGatewayState {
    let mut config = base_config(server_port, root, true);
    mutate(&mut config);
    AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
        .expect("gateway state with the built-in agent program")
}

/// One session's durable message rows: `(ordinal, role, content, compacted)`
/// read through the TYPED storage program's `message.list` repository
/// command (the raw rows; no Rust-side dead contract).
fn durable_message_rows(
    state: &AgentGatewayState,
    session_id: &str,
) -> Vec<(i64, String, JsonValue, bool)> {
    let persistence = state.persistence().expect("durable persistence");
    let root = persistence.db_root().expect("durable sqlite root");
    let storage = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/storage/main.rss"),
        AgentConfig::default().with_sqlite_root(root),
    )
    .expect("production storage entrypoint should compile");
    let input = json!({
        "op": "message.list",
        "request_id": "test",
        "db_path": persistence.db_file_name(),
        "db_mode": "read_write_create",
        "busy_timeout_ms": 5000,
        "max_rows": 1000,
        "max_bytes": 65536,
        "max_events": 128,
        "max_messages": 128,
        "now_ms": 0,
        "payload_json": json!({"session_id": session_id, "after_ordinal": 0}).to_string()
    });
    let result = storage
        .run_with_context(json_to_vm_value(&input))
        .unwrap_or_else(|error| panic!("message.list failed: {error:?}"));
    let data = vm_value_to_json(&result);
    // The storage envelope nests the raw query result under `data`.
    let rows = data
        .get("data")
        .and_then(|data| data.get("rows"))
        .and_then(JsonValue::as_array);
    let mut parsed = Vec::new();
    if let Some(array) = rows {
        for row in array {
            if let Some(row) = row.as_array() {
                parsed.push((
                    row.get(2).and_then(JsonValue::as_i64).unwrap_or(0),
                    row.get(3)
                        .and_then(JsonValue::as_str)
                        .unwrap_or("?")
                        .to_string(),
                    row.get(4)
                        .and_then(JsonValue::as_str)
                        .and_then(|text| serde_json::from_str(text).ok())
                        .unwrap_or(JsonValue::Null),
                    row.get(9).and_then(JsonValue::as_i64).unwrap_or(0) != 0,
                ));
            }
        }
    }
    parsed
}

fn json_to_vm_value(value: &JsonValue) -> VmValue {
    match value {
        JsonValue::Null => VmValue::Null,
        JsonValue::Bool(value) => VmValue::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(int) = value.as_i64() {
                VmValue::Int(int)
            } else {
                VmValue::Float(value.as_f64().expect("JSON number should be a float"))
            }
        }
        JsonValue::String(value) => VmValue::string(value),
        JsonValue::Array(values) => VmValue::Array(
            values
                .iter()
                .map(json_to_vm_value)
                .collect::<Vec<_>>()
                .into(),
        ),
        JsonValue::Object(entries) => VmValue::map(
            entries
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

fn vm_value_to_json(value: &VmValue) -> JsonValue {
    match value {
        VmValue::Null => JsonValue::Null,
        VmValue::Int(value) => json!(value),
        VmValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        VmValue::Bool(value) => json!(value),
        VmValue::String(value) => JsonValue::String(value.to_string()),
        VmValue::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        VmValue::Array(values) => JsonValue::Array(values.iter().map(vm_value_to_json).collect()),
        VmValue::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        VmValue::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &VmValue) -> String {
    match value {
        VmValue::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

/// The durable state of one approval row (`pending` | `approved` | `denied` |
/// `expired`), or `None` when no such row exists.
fn durable_approval_state(state: &AgentGatewayState, approval_id: &str) -> Option<String> {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence.approval_get(approval_id).ok()?;
    data.get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .and_then(|row| row.get(7))
        .and_then(JsonValue::as_str)
        .map(|state| state.to_string())
}

/// The durable state of one compaction row, or `None` when it does not exist.
fn durable_compaction_state(state: &AgentGatewayState, compaction_id: &str) -> Option<String> {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence.compaction_get(compaction_id).ok()?;
    data.get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .and_then(|row| row.get(10))
        .and_then(JsonValue::as_str)
        .map(|state| state.to_string())
}

/// The reason carried by the run's durable `run.cancelled` event.
fn cancelled_reason(state: &AgentGatewayState, run_id: &str) -> Option<String> {
    replayed_events(state, run_id)
        .iter()
        .find(|(_, event_type, _)| event_type == "run.cancelled")
        .and_then(|(_, _, payload)| payload["reason"].as_str().map(String::from))
}

// -- A: resolve fault recovery (the park must never be lost on errors) ------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a1_resolve_transition_failure_keeps_the_park_retryable() {
    let root = temporary_root("a1-resolve-retry");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("a1.txt"), "content": "a1"})
                )])),
            ),
            (200, wire_text("resumed and done")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });

    // External interference: the durable run leaves `waiting_approval` before
    // the resolution lands, so the typed transition cannot match.
    let persistence = state.persistence().expect("durable persistence");
    persistence
        .run_transition(&json!({
            "run_id": admitted.run_id,
            "from_status": "waiting_approval",
            "to_status": "running",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "test interference",
            "now_ms": 0,
        }))
        .expect("external transition");
    let first = service.resolve_run_approval(&admitted.run_id, true);
    assert!(
        first.is_err(),
        "the failed transition must surface as a typed error"
    );

    // Restore the durable status and retry: the park must still be there, so
    // the run resumes instead of wedging.
    persistence
        .run_transition(&json!({
            "run_id": admitted.run_id,
            "from_status": "running",
            "to_status": "waiting_approval",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "test restore",
            "now_ms": 0,
        }))
        .expect("restore transition");
    service
        .resolve_run_approval(&admitted.run_id, true)
        .expect("the retry must find the park and resume");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(15)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "completed",
        "the retried resolution must resume the run exactly once"
    );
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2_failed_resolution_keeps_stop_reachable() {
    let root = temporary_root("a2-resolve-stop");
    let server = spawn_scripted_server(
        vec![(
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("a2.txt"), "content": "a2"})
            )])),
        )],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });

    // Break the resolution (the durable status no longer matches), then stop:
    // stop() must still terminate the run even though the resolution failed.
    let persistence = state.persistence().expect("durable persistence");
    persistence
        .run_transition(&json!({
            "run_id": admitted.run_id,
            "from_status": "waiting_approval",
            "to_status": "running",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "test interference",
            "now_ms": 0,
        }))
        .expect("external transition");
    assert!(
        service
            .resolve_run_approval(&admitted.run_id, true)
            .is_err()
    );
    let status = service.stop(&admitted.run_id).expect("stop must work");
    assert_eq!(status, "stopping");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(15)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "cancelled",
        "a failed resolution must never wedge the run away from stop"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// -- B: stop/cancel re-checked before durable approval/compaction writes -----

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_stop_before_the_approval_park_never_wedges_the_run() {
    let root = temporary_root("b1-stop-approval-race");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("b1.txt"), "content": "b1"})
                )])),
            ),
            (200, wire_text("unused")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;

    // Stop as soon as the provider answered the tool-call round: the durable
    // park lands a few storage round trips later, so the stop races the park.
    // The terminal bound is generous: the full-suite parallel load can
    // stretch the park/stop race well past interactive latencies.
    wait_tight(Duration::from_secs(30), || server.request_count() >= 1);
    let status = service.stop(&admitted.run_id).expect("stop");
    assert_eq!(status, "stopping");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(45)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "cancelled",
        "a stop racing the approval park must still terminate the run"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_stop_during_compaction_creates_no_compaction_row() {
    let root = temporary_root("b2-stop-compaction");
    seed_durable_history(&root, "session-1", 8);
    // The provider stalls forever: the run is mid-compaction when stop lands.
    let server = spawn_scripted_server(vec![(200, wire_text("never reached"))], 30_000);
    let state = spawn_state_with_db(server.port(), &root, |config| {
        config.max_context_messages = 6;
        config.retained_tail = 2;
    });
    let service = state.service();
    let admitted =
        admit_and_spawn(&service, "compact", Some("session-1".to_string()), "test").await;

    // The plan step emitted compact.started; execution (and any durable
    // compaction row) follows.
    wait_tight(Duration::from_secs(10), || {
        replayed_events(&state, &admitted.run_id)
            .iter()
            .any(|(_, event_type, _)| event_type == "compact.started")
    });
    let status = service.stop(&admitted.run_id).expect("stop");
    assert_eq!(status, "stopping");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(15)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "cancelled",
        "a stop racing the compaction must still terminate the run"
    );
    // No compaction row may exist: nothing was persisted after the stop.
    assert_eq!(
        durable_compaction_state(&state, "compact:session-1:2"),
        None,
        "no compaction row may be created after the stop"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// -- C: the park carries the original run deadline ---------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c1_park_time_counts_against_the_run_deadline() {
    let root = temporary_root("c1-deadline-resume");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("c1.txt"), "content": "c1"})
                )])),
            ),
            (200, wire_text("unused")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
        config.run_timeout = Duration::from_secs(2);
        config.janitor_interval = Duration::from_secs(3600);
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });

    // The whole-run deadline passes while the run is parked.
    tokio::time::sleep(Duration::from_secs(3)).await;
    service
        .resolve_run_approval(&admitted.run_id, true)
        .expect("resolution");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(15)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "cancelled",
        "park time must count against the run wall clock; the resume cannot reset the deadline"
    );
    assert_eq!(
        cancelled_reason(&state, &admitted.run_id).as_deref(),
        Some("deadline")
    );
    assert!(
        !root.join("c1.txt").exists(),
        "the tool must never dispatch after the deadline"
    );
    assert_eq!(server.request_count(), 1);
    // The resume must cancel BEFORE any loop step: the typed deadline is
    // checked against the ORIGINAL deadline, so the loop is never invoked
    // again — exactly ONE model round (the pre-park one) ever started.
    let events = replayed_events(&state, &admitted.run_id);
    let started = events
        .iter()
        .filter(|(_, event_type, _)| event_type == "model.started")
        .count();
    assert_eq!(
        started, 1,
        "no loop step may start after the deadline (only the pre-park round)"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// -- D: expiry sweep runs off the async runtime and expires rows -------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d1_expiry_sweep_expires_the_row_and_resumes_with_a_typed_result() {
    let root = temporary_root("d1-expiry");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("d1.txt"), "content": "d1"})
                )])),
            ),
            (200, wire_text("expired and continued")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
        config.approval_timeout = Duration::from_millis(400);
        config.janitor_interval = Duration::from_millis(200);
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });

    // The sweep expires the parked approval and resumes the run with the
    // typed expired tool result; the loop folds it and continues.
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(20)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    assert!(
        !root.join("d1.txt").exists(),
        "the expired tool must never dispatch"
    );
    assert_eq!(server.request_count(), 2);
    let events = replayed_events(&state, &admitted.run_id);
    let resolved = events
        .iter()
        .find(|(_, event_type, _)| event_type == "approval.resolved")
        .expect("approval.resolved event");
    assert_eq!(resolved.2["resolved"], json!(false));
    // The model saw the typed `approval_expired` tool result (never the
    // generic deny code).
    let second = server.request_body(1).expect("second provider request");
    let serialized = second.to_string();
    assert!(
        serialized.contains("approval_expired"),
        "the expired resume must carry the typed approval_expired code"
    );
    // The sweep must have called approval.expire: the durable row is
    // `expired`, never left pending.
    let approval_id = resolved.2["approval_id"].as_str().unwrap_or("").to_string();
    assert!(!approval_id.is_empty(), "resolved must carry the real id");
    assert_eq!(
        durable_approval_state(&state, &approval_id).as_deref(),
        Some("expired"),
        "the sweep must durably expire the pending approval row"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// -- E: a second compaction in the same run commits with a fresh generation --

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e1_second_compaction_in_the_same_run_commits_with_a_fresh_generation() {
    let root = temporary_root("e1-double-compaction");
    seed_durable_history(&root, "session-1", 8);
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("e1a.txt"), "content": "a"})
                )])),
            ),
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-2",
                    "file.write",
                    json!({"path": root.join("e1b.txt"), "content": "b"})
                )])),
            ),
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-3",
                    "file.write",
                    json!({"path": root.join("e1c.txt"), "content": "c"})
                )])),
            ),
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-4",
                    "file.write",
                    json!({"path": root.join("e1d.txt"), "content": "d"})
                )])),
            ),
        ],
        0,
    );
    let state = spawn_state_with_db(server.port(), &root, |config| {
        config.max_context_messages = 6;
        config.retained_tail = 2;
        config.approval_mode = "all".to_string();
        config.max_turns = 4;
    });
    let service = state.service();
    let admitted = admit_and_spawn(
        &service,
        "compact repeatedly",
        Some("session-1".to_string()),
        "test",
    )
    .await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    assert_eq!(
        durable_compaction_state(&state, "compact:session-1:2").as_deref(),
        Some("committed"),
        "the first compaction commits"
    );
    assert_eq!(
        durable_compaction_state(&state, "compact:session-1:3").as_deref(),
        Some("committed"),
        "a second compaction in the same run must commit with a refreshed generation"
    );
    assert!(root.join("e1a.txt").exists());
    assert!(root.join("e1d.txt").exists());

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// -- G: durable-first tool-cycle messages and real max-turn text -------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_tool_cycle_messages_are_persisted_durably() {
    let root = temporary_root("g1-durable-tool-messages");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("g1.txt"), "content": "g1"})
                )])),
            ),
            (200, wire_text("done")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "use the tool", None, "test").await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");

    let rows = durable_message_rows(&state, &admitted.session_id);
    let roles: Vec<String> = rows.iter().map(|(_, role, _, _)| role.clone()).collect();
    assert_eq!(
        roles,
        vec!["user", "assistant", "tool", "assistant"],
        "the assistant tool-call and the tool result must be persisted durably"
    );
    let assistant = rows
        .iter()
        .find(|(_, role, _, _)| role == "assistant")
        .and_then(|(_, _, content, _)| content.as_array())
        .expect("assistant parts");
    assert_eq!(assistant[0]["type"], json!("tool_call"));
    assert_eq!(assistant[0]["tool_call_id"], json!("call-1"));
    let tool = rows
        .iter()
        .find(|(_, role, _, _)| role == "tool")
        .and_then(|(_, _, content, _)| content.as_array())
        .expect("tool parts");
    assert_eq!(tool[0]["type"], json!("tool_result"));
    assert_eq!(tool[0]["tool_call_id"], json!("call-1"));

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g2_max_turn_terminal_carries_the_current_round_text() {
    let root = temporary_root("g2-max-turn-text");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                json!({
                    "id": "chatcmpl-2",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "first answer",
                            "tool_calls": [tool_call("call-1", "file.write", json!({"path": root.join("g2a.txt"), "content": "a"}))]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                })
                .to_string(),
            ),
            (
                200,
                json!({
                    "id": "chatcmpl-3",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "second answer",
                            "tool_calls": [tool_call("call-2", "file.write", json!({"path": root.join("g2b.txt"), "content": "b"}))]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                })
                .to_string(),
            ),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "all".to_string();
        config.max_turns = 2;
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "run away", None, "test").await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    let completed = events
        .iter()
        .find(|(_, event_type, _)| event_type == "run.completed")
        .expect("run.completed event");
    assert_eq!(
        completed.2["output"]["message"]["content"],
        json!("second answer"),
        "the max-turn terminal must carry the last completed round's real text"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g3_new_run_history_filters_compacted_rows_even_within_the_window() {
    let root = temporary_root("g3-compacted-filter");
    seed_durable_history(&root, "session-1", 8);
    let server = spawn_scripted_server(
        vec![(200, wire_text("run one")), (200, wire_text("run two"))],
        0,
    );
    let state = spawn_state_with_db(server.port(), &root, |config| {
        config.max_context_messages = 6;
        config.retained_tail = 2;
    });
    let service = state.service();

    // Run 1 compacts the durable prefix.
    let first = admit_and_spawn(&service, "compact", Some("session-1".to_string()), "test").await;
    wait_terminal(&service, &first.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &first.run_id), "completed");
    assert_eq!(
        durable_compaction_state(&state, "compact:session-1:2").as_deref(),
        Some("committed")
    );

    // Run 2: the compacted rows are filtered from its provider history even
    // though the durable count still exceeds the window.
    let second = admit_and_spawn(&service, "again", Some("session-1".to_string()), "test").await;
    wait_terminal(&service, &second.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &second.run_id), "completed");
    let second_request = server
        .request_body(1)
        .expect("the second provider request body");
    let texts: Vec<String> = second_request["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|message| message["content"].as_array())
        .flatten()
        .filter_map(|part| part["text"].as_str().map(String::from))
        .collect();
    assert!(
        !texts
            .iter()
            .any(|text| text.contains("message 1") || text.contains("message 6")),
        "compacted rows must be filtered from the new run's history: {texts:?}"
    );
    assert_eq!(
        durable_compaction_state(&state, "compact:session-1:3"),
        None,
        "the filtered history must not re-plan the already committed generation"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// -- H: approval.required carries the real bridge id, exactly once -----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_approval_required_carries_the_real_bridge_approval_id_exactly_once() {
    let root = temporary_root("h1-approval-id");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("h1.txt"), "content": "h1"})
                )])),
            ),
            (200, wire_text("approved")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });
    service
        .resolve_run_approval(&admitted.run_id, true)
        .expect("resolution");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");

    let events = replayed_events(&state, &admitted.run_id);
    let required: Vec<_> = events
        .iter()
        .filter(|(_, event_type, _)| event_type == "approval.required")
        .collect();
    assert_eq!(
        required.len(),
        1,
        "exactly one approval.required event per park"
    );
    let approval_id = required[0].2["approval_id"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        !approval_id.is_empty(),
        "approval.required must carry the bridge-generated approval id"
    );
    let resolved = events
        .iter()
        .find(|(_, event_type, _)| event_type == "approval.resolved")
        .expect("approval.resolved event");
    assert_eq!(
        resolved.2["approval_id"],
        json!(approval_id),
        "resolved must carry the same id"
    );
    // The id resolves to the real durable pending row for this tool call.
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .approval_get(&approval_id)
        .expect("approval get");
    let row = data["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .expect("approval row");
    assert_eq!(row[3], json!("call-1"), "tool_call_id");
    assert_eq!(row[7], json!("approved"), "state");
    assert!(root.join("h1.txt").exists());

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// A5 review fixes: compaction pair preservation, approval retry decision
// memory, the AlreadyResolved no-op, and the unknown compaction command.
// ---------------------------------------------------------------------------

/// Seeds one session with `count` durable text messages; the caller then
/// appends the tool-pair rows through the same handle.
fn seed_pair_session(persistence: &Arc<rustscript_agent::GatewayPersistence>) -> String {
    seed_pair_session_with_provider(persistence, "openai_chat")
}

fn seed_pair_session_with_provider(
    persistence: &Arc<rustscript_agent::GatewayPersistence>,
    provider: &str,
) -> String {
    let session_id = "session-1";
    persistence
        .session_create(&json!({
            "id": session_id,
            "profile": "default",
            "platform": "test",
            "account_id": "account-1",
            "chat_id": "chat-1",
            "thread_id": "",
            "user_id": "user-1",
            "generation": 1,
            "system_prompt": "",
            "model": "test-model",
            "provider": provider,
            "toolset_hash": "test-tools",
            "metadata_json": "{}",
            "title": "",
            "end_reason": "",
            "now_ms": 0
        }))
        .expect("session create");
    session_id.to_string()
}

fn seed_text_message(
    persistence: &Arc<rustscript_agent::GatewayPersistence>,
    session_id: &str,
    index: usize,
) {
    let role = if index % 2 == 1 { "user" } else { "assistant" };
    let text = format!("message {index}");
    persistence
        .message_append(&json!({
            "id": format!("m-{index}"),
            "session_id": session_id,
            "role": role,
            "content_json": format!(r#"[{{"type":"text","text":"{text}"}}]"#),
            "name": "",
            "tool_call_id": "",
            "parent_message_id": "",
            "token_estimate": 0,
            "metadata_json": "{}",
            "run_id": "seed-run",
            "finish_reason": "",
            "now_ms": 0
        }))
        .expect("message append");
}

fn seed_straddling_pair_history(persistence: &Arc<rustscript_agent::GatewayPersistence>) {
    seed_straddling_pair_history_with_provider(persistence, "openai_chat")
}

/// A durable history whose tool pair straddles the naive compaction boundary:
/// window 6 / retained_tail 2 with the admission input appended as the last
/// message -> naive boundary 7 cuts between the assistant tool-call
/// (ordinal 7) and its tool result (ordinal 8). The pair ids are stored in
/// BOTH the durable `tool_call_id` column and the content parts.
fn seed_straddling_pair_history_with_provider(
    persistence: &Arc<rustscript_agent::GatewayPersistence>,
    provider: &str,
) {
    let session_id = seed_pair_session_with_provider(persistence, provider);
    for index in 1..=6 {
        seed_text_message(persistence, &session_id, index);
    }
    persistence
        .message_append(&json!({
            "id": "m-7",
            "session_id": session_id,
            "role": "assistant",
            "content_json": r#"[{"type":"tool_call","tool_call_id":"call-pair","name":"file.read","arguments_json":"{}"}]"#,
            "name": "",
            "tool_call_id": "call-pair",
            "parent_message_id": "",
            "token_estimate": 0,
            "metadata_json": "{}",
            "run_id": "seed-run",
            "finish_reason": "tool_calls",
            "now_ms": 0
        }))
        .expect("assistant tool-call row");
    persistence
        .message_append(&json!({
            "id": "m-8",
            "session_id": session_id,
            "role": "tool",
            "content_json": r#"[{"type":"tool_result","tool_call_id":"call-pair","content":"{\"ok\":true}","is_error":false}]"#,
            "name": "",
            "tool_call_id": "call-pair",
            "parent_message_id": "",
            "token_estimate": 0,
            "metadata_json": "{}",
            "run_id": "seed-run",
            "finish_reason": "",
            "now_ms": 0
        }))
        .expect("tool result row");
}

/// True when one provider request contains a tool result with no preceding
/// assistant tool call carrying the same id in the SAME request (a dangling
/// result). Understands every wire shape the serial loop can emit:
/// - OpenAI Chat: `messages` with assistant `tool_calls` (`id`) and `tool`
///   messages whose content is a STRING with a message-level `tool_call_id`;
/// - OpenAI Responses: `input` items `{type: "function_call", call_id}` and
///   `{type: "function_call_output", call_id, output}`;
/// - Anthropic Messages: `messages` with assistant `tool_use` parts (`id`)
///   and `user` messages whose content parts are `tool_result` blocks
///   (`tool_use_id`);
/// - the canonical content-part shapes (`tool_call` / `tool_result` with
///   `tool_call_id`) are handled as well.
fn request_has_dangling_tool_result(body: &JsonValue) -> bool {
    let items = body
        .get("messages")
        .or_else(|| body.get("input"))
        .and_then(JsonValue::as_array);
    let Some(items) = items else {
        return false;
    };
    let mut open_calls: Vec<String> = Vec::new();
    for item in items {
        let role = item["role"].as_str().unwrap_or("");
        let item_type = item["type"].as_str().unwrap_or("");
        if role == "assistant" {
            // OpenAI Chat: the assistant wire message carries `tool_calls`.
            if let Some(calls) = item["tool_calls"].as_array() {
                for call in calls {
                    if let Some(id) = call["id"].as_str()
                        && !id.is_empty()
                    {
                        open_calls.push(id.to_string());
                    }
                }
            }
            // Anthropic / canonical: content parts with tool_use (`id`) or
            // tool_call (`tool_call_id`).
            if let Some(parts) = item["content"].as_array() {
                for part in parts {
                    if part["type"] == "tool_call"
                        && let Some(id) = part["tool_call_id"].as_str().filter(|id| !id.is_empty())
                    {
                        open_calls.push(id.to_string());
                    }
                    if part["type"] == "tool_use"
                        && let Some(id) = part["id"].as_str()
                        && !id.is_empty()
                    {
                        open_calls.push(id.to_string());
                    }
                }
            }
        } else if role == "tool" {
            // OpenAI Chat: the tool message content is a STRING and the call
            // id rides at message level.
            if let Some(id) = item["tool_call_id"].as_str()
                && !consume_open_tool_result(id, &mut open_calls)
            {
                return true;
            }
            // Canonical: content parts.
            if let Some(parts) = item["content"].as_array() {
                for part in parts {
                    if part["type"] == "tool_result"
                        && let Some(id) = part["tool_call_id"].as_str()
                        && !consume_open_tool_result(id, &mut open_calls)
                    {
                        return true;
                    }
                }
            }
        } else if role == "user" {
            // Anthropic: tool results arrive as `user`-role messages whose
            // content parts are tool_result blocks carrying `tool_use_id`.
            if let Some(parts) = item["content"].as_array() {
                for part in parts {
                    if part["type"] == "tool_result"
                        && let Some(id) = part["tool_use_id"]
                            .as_str()
                            .or_else(|| part["tool_call_id"].as_str())
                        && !consume_open_tool_result(id, &mut open_calls)
                    {
                        return true;
                    }
                }
            }
        }
        if item_type == "function_call"
            && let Some(id) = item["call_id"].as_str()
            && !id.is_empty()
        {
            open_calls.push(id.to_string());
        }
        if item_type == "function_call_output"
            && let Some(id) = item["call_id"].as_str()
            && !consume_open_tool_result(id, &mut open_calls)
        {
            return true;
        }
    }
    false
}

/// Consumes one tool result id against the open assistant calls. Returns
/// false (dangling) when the id is empty or no matching open call exists.
fn consume_open_tool_result(id: &str, open_calls: &mut Vec<String>) -> bool {
    if id.is_empty() {
        return false;
    }
    if let Some(position) = open_calls.iter().position(|open| open == id) {
        open_calls.remove(position);
        true
    } else {
        false
    }
}

/// Self-test of the dangling-result helper across every wire shape the loop
/// can emit. The previous helper only understood canonical content-part
/// arrays under the `tool` role: it MISSED the OpenAI Chat wire (content is a
/// string, the id rides at message level), the OpenAI Responses items, and
/// the Anthropic `user`-role tool_result blocks — so the compaction E2E
/// dangling assertion was vacuous.
#[test]
fn dangling_tool_result_helper_detects_every_wire_shape() {
    // OpenAI Chat wire: assistant tool_calls array + tool message with a
    // string content and a message-level tool_call_id.
    let chat_dangling = json!({
        "messages": [
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "call-1", "type": "function", "function": {"name": "file.write", "arguments": "{}"}}
            ]},
            {"role": "tool", "content": "ok", "tool_call_id": "call-9"}
        ]
    });
    assert!(
        request_has_dangling_tool_result(&chat_dangling),
        "the OpenAI Chat wire shape must be understood: {chat_dangling}"
    );
    let chat_matched = json!({
        "messages": [
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "call-1", "type": "function", "function": {"name": "file.write", "arguments": "{}"}}
            ]},
            {"role": "tool", "content": "ok", "tool_call_id": "call-1"}
        ]
    });
    assert!(
        !request_has_dangling_tool_result(&chat_matched),
        "a matched OpenAI Chat pair must not be flagged: {chat_matched}"
    );

    // Canonical content-part shape (the loop's in-run messages).
    let canonical_dangling = json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "tool_call", "tool_call_id": "call-1", "name": "file.write", "arguments_json": "{}"}
            ]},
            {"role": "tool", "content": [
                {"type": "tool_result", "tool_call_id": "call-9", "content": "ok", "is_error": false}
            ]}
        ]
    });
    assert!(
        request_has_dangling_tool_result(&canonical_dangling),
        "the canonical content-part shape must be understood: {canonical_dangling}"
    );

    // OpenAI Responses wire: input items with function_call /
    // function_call_output.
    let responses_dangling = json!({
        "input": [
            {"role": "assistant", "content": "let me check"},
            {"type": "function_call", "call_id": "call-1", "name": "file.write", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "call-9", "output": "ok"}
        ]
    });
    assert!(
        request_has_dangling_tool_result(&responses_dangling),
        "the OpenAI Responses wire shape must be understood: {responses_dangling}"
    );
    let responses_matched = json!({
        "input": [
            {"role": "assistant", "content": "let me check"},
            {"type": "function_call", "call_id": "call-1", "name": "file.write", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "call-1", "output": "ok"}
        ]
    });
    assert!(
        !request_has_dangling_tool_result(&responses_matched),
        "a matched Responses pair must not be flagged: {responses_matched}"
    );

    // Anthropic wire: user-role messages with tool_result blocks carrying
    // the official tool_use_id.
    let anthropic_dangling = json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "text", "text": "let me"},
                {"type": "tool_use", "id": "call-1", "name": "file.write", "input": {}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "call-9", "content": "ok"}
            ]}
        ]
    });
    assert!(
        request_has_dangling_tool_result(&anthropic_dangling),
        "the Anthropic user/tool_result wire shape must be understood: {anthropic_dangling}"
    );
    let anthropic_matched = json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "text", "text": "let me"},
                {"type": "tool_use", "id": "call-1", "name": "file.write", "input": {}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "call-1", "content": "ok"}
            ]}
        ]
    });
    assert!(
        !request_has_dangling_tool_result(&anthropic_matched),
        "a matched Anthropic pair must not be flagged: {anthropic_matched}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_compaction_pair_boundary_preserves_the_pair_and_provider_sees_no_dangling_result() {
    let root = temporary_root("e2e-compaction-pair");
    let seed =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .expect("seed state");
    let seed_persistence = seed.persistence().expect("seed persistence");
    seed_straddling_pair_history(&seed_persistence);
    drop(seed_persistence);

    // The production loop runs against the seeded session: the compaction
    // gate plans over the loaded durable history and the boundary must push
    // past the tool result so the provider never sees a dangling result.
    let server = spawn_scripted_server(vec![(200, wire_text("compacted and answered"))], 0);
    let mut config = base_config(server.port(), &root, true);
    config.max_context_messages = 6;
    config.retained_tail = 2;
    config.provider = Some("openai_chat".to_string());
    config.provider_options = json!({
        "base_url": format!("http://127.0.0.1:{}", server.port()),
        "api_key": "test-key",
        "model": "test-model"
    });
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_hosts = vec!["127.0.0.1".to_string()];
    config.http.allowed_ports = vec![server.port()];
    config.http.allow_private_ips = true;
    config.run_timeout = Duration::from_secs(60);
    let state =
        AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
            .expect("reopened state with the built-in agent program");
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("compact"),
            session_id: Some("session-1".to_string()),
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "compact".to_string()),
    );
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(handle) = state.service().handle(&admitted.run_id)
            && handle.is_terminal()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    // The committed range must cover BOTH halves of the straddling pair.
    let persistence = state.persistence().expect("durable persistence");
    let compaction = persistence
        .compaction_get("compact:session-1:2")
        .expect("compaction get");
    let rows = compaction
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][10], json!("committed"), "state column");
    assert_eq!(
        rows[0][5],
        json!(8),
        "source_end_ordinal must cover the tool result (the boundary pushed past the pair)"
    );
    assert_eq!(rows[0][4], json!(1), "source_start_ordinal");
    // The provider's single request must not contain a dangling tool_result.
    let body = server.request_body(0).expect("provider request body");
    assert!(
        !request_has_dangling_tool_result(&body),
        "the provider must never see a tool result without its assistant call: {body}"
    );
    let types = event_types(&replayed_events(&state, &admitted.run_id));
    assert!(types.contains(&"compact.completed".to_string()));

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The dangling-result assertion must be TRIGGERABLE: when the retained tail
/// keeps the seeded pair (naive boundary 6, pair at 7..8), the provider's
/// post-compaction request carries the pair in the OpenAI Chat WIRE shape
/// (assistant `tool_calls` + a `tool` message whose content is a STRING with
/// a message-level `tool_call_id`). The helper must understand that shape or
/// the assertion below can never fire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_compaction_retained_pair_reaches_the_provider_with_no_dangling_tool_result() {
    let root = temporary_root("e2e-compaction-retained-pair");
    let seed =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .expect("seed state");
    let seed_persistence = seed.persistence().expect("seed persistence");
    seed_straddling_pair_history(&seed_persistence);
    drop(seed_persistence);

    let server = spawn_scripted_server(vec![(200, wire_text("compacted and answered"))], 0);
    let mut config = base_config(server.port(), &root, true);
    config.max_context_messages = 6;
    // Tail 3 keeps the pair (ordinals 7..8) OUT of the compacted prefix, so
    // the post-compaction provider request carries it in the OpenAI Chat
    // wire shape.
    config.retained_tail = 3;
    config.provider = Some("openai_chat".to_string());
    config.provider_options = json!({
        "base_url": format!("http://127.0.0.1:{}", server.port()),
        "api_key": "test-key",
        "model": "test-model"
    });
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_hosts = vec!["127.0.0.1".to_string()];
    config.http.allowed_ports = vec![server.port()];
    config.http.allow_private_ips = true;
    config.run_timeout = Duration::from_secs(60);
    let state =
        AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
            .expect("reopened state with the built-in agent program");
    let service = state.service();
    let admitted =
        admit_and_spawn(&service, "compact", Some("session-1".to_string()), "test").await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");

    // The compacted prefix covers 1..6 only; the pair stays in the tail.
    let persistence = state.persistence().expect("durable persistence");
    let compaction = persistence
        .compaction_get("compact:session-1:2")
        .expect("compaction get");
    let rows = compaction
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("rows");
    assert_eq!(rows[0][5], json!(6), "source_end_ordinal");
    // The provider request carries the retained pair in the OpenAI Chat wire
    // shape, and the dangling assertion is therefore non-vacuous.
    let body = server.request_body(0).expect("provider request body");
    let messages = body
        .get("messages")
        .and_then(JsonValue::as_array)
        .expect("messages");
    let tool_message = messages
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("the retained tool result must reach the provider");
    assert_eq!(
        tool_message["tool_call_id"],
        json!("call-pair"),
        "the OpenAI Chat wire must carry the pair id at message level: {body}"
    );
    assert!(
        tool_message["content"].is_string(),
        "the OpenAI Chat wire renders tool content as a string: {body}"
    );
    assert!(
        messages.iter().any(|message| {
            message["role"] == "assistant"
                && message["tool_calls"]
                    .as_array()
                    .is_some_and(|calls| calls.iter().any(|call| call["id"] == "call-pair"))
        }),
        "the retained assistant tool call must reach the provider: {body}"
    );
    assert!(
        !request_has_dangling_tool_result(&body),
        "the provider must never see a tool result without its assistant call: {body}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The same triggerable invariant through the ANTHROPIC wire: the retained
/// pair reaches `/v1/messages` as a `user`-role tool_result block carrying
/// the official `tool_use_id` (never a `tool` role), and the helper detects
/// the Anthropic shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_compaction_retained_pair_anthropic_wire_has_no_dangling_tool_result() {
    let root = temporary_root("e2e-compaction-anthropic-pair");
    let seed =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .expect("seed state");
    let seed_persistence = seed.persistence().expect("seed persistence");
    seed_straddling_pair_history_with_provider(&seed_persistence, "anthropic_messages");
    drop(seed_persistence);

    let server = spawn_scripted_server(vec![(200, wire_text("compacted and answered"))], 0);
    let mut config = base_config(server.port(), &root, true);
    config.max_context_messages = 6;
    config.retained_tail = 3;
    config.provider = Some("anthropic_messages".to_string());
    config.provider_options = json!({
        "base_url": format!("http://127.0.0.1:{}", server.port()),
        "api_key": "test-key",
        "model": "test-model"
    });
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_hosts = vec!["127.0.0.1".to_string()];
    config.http.allowed_ports = vec![server.port()];
    config.http.allow_private_ips = true;
    config.run_timeout = Duration::from_secs(60);
    let state =
        AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
            .expect("reopened state with the built-in agent program");
    let service = state.service();
    let admitted =
        admit_and_spawn(&service, "compact", Some("session-1".to_string()), "test").await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");

    let body = server.request_body(0).expect("provider request body");
    let messages = body
        .get("messages")
        .and_then(JsonValue::as_array)
        .expect("messages");
    let tool_message = messages
        .iter()
        .find(|message| {
            message["content"]
                .as_array()
                .is_some_and(|parts| parts.iter().any(|part| part["type"] == "tool_result"))
        })
        .unwrap_or_else(|| panic!("the retained tool result must reach the provider: {body}"));
    assert_eq!(
        tool_message["role"],
        json!("user"),
        "the Anthropic wire must render the tool result as a user-role message: {body}"
    );
    assert_eq!(
        tool_message["content"][0]["tool_use_id"],
        json!("call-pair"),
        "the official tool_use_id must preserve the pair id: {body}"
    );
    for message in messages {
        assert_ne!(
            message["role"],
            json!("tool"),
            "the Anthropic wire may never carry a tool role: {body}"
        );
    }
    assert!(
        !request_has_dangling_tool_result(&body),
        "the provider must never see a tool result without its assistant call: {body}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// P2: invoke_loop_step drains the fresh delivery path BEFORE every terminal
// ---------------------------------------------------------------------------
//
// Every cancel/error/join/timeout branch of one loop step must drain the
// step's delivery channel first and only then commit the typed terminal, so
// tail events are durably appended and replayed BEFORE the terminal. The
// fixtures drive a small custom loop program (entry `agent_run`) through the
// REAL service + SQLite path.

fn loop_program_runner(name: &str, port: u16) -> AgentRunner {
    AgentRunner::from_file_with_entry(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/a5-loop-programs")
            .join(name),
        AgentConfig::new(HttpConfig {
            allowed_schemes: vec!["http".to_string()],
            allowed_hosts: vec!["127.0.0.1".to_string()],
            allowed_ports: vec![port],
            allow_private_ips: true,
            ..HttpConfig::default()
        }),
        rustscript_agent::PRODUCTION_LOOP_ENTRY,
    )
    .expect("loop fixture program should compile")
}

fn spawn_state_with_program(
    server_port: u16,
    root: &std::path::Path,
    program: AgentRunner,
    mutate: impl FnOnce(&mut AgentGatewayConfig),
) -> AgentGatewayState {
    let mut config = base_config(server_port, root, true);
    mutate(&mut config);
    AgentGatewayState::with_program_and_sqlite(config, program, root.join("state.db"))
        .expect("gateway state with the fixture loop program")
}

// ---------------------------------------------------------------------------
// P2: controllable approval-park race control (SQLite lock helper)
// ---------------------------------------------------------------------------
//
// The approval park sequence is: durable `approval.request` -> stopping
// re-check -> durable run transition -> park insert -> `approval.required`
// event append. A stop that lands between the re-check and the event append
// must not leave a park or a post-stop event behind (the old code parked the
// run until the 600s expiry sweep). The helper below makes that window
// controllable: phase A blocks `approval.request` with an exclusive SQLite
// lock; the poll-shared phase then holds a SHARED lock from the moment the
// durable row commits, so the run transition's writer statements block and
// the stop lands BEFORE the park insert.

/// Writes the "0" marker files the race-control helper waits on.
fn write_race_markers(root: &std::path::Path) -> PathBuf {
    let markers = root.join("markers");
    fs::create_dir_all(&markers).expect("markers dir");
    for name in [
        "phase_held",
        "phase_done",
        "phase_release",
        "shared_held",
        "shared_done",
        "no_pending",
    ] {
        fs::write(markers.join(name), "0").expect("marker file");
    }
    markers
}

fn marker_is_one(markers: &std::path::Path, name: &str) -> bool {
    fs::read_to_string(markers.join(name))
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

/// Runs one race-control helper invocation on a std thread (the RSS sqlite
/// pump needs a Tokio runtime handle entered on the thread).
fn run_lock_helper(
    root: &std::path::Path,
    db_path: &std::path::Path,
    command: &str,
    run_id: &str,
) -> std::thread::JoinHandle<()> {
    let config = AgentConfig {
        http: HttpConfig::default(),
        sqlite: SqlitePolicy::default(),
        io: IoPolicy {
            allowed_roots: Vec::new(),
            allow_write: true,
            allow_process: false,
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 1024 * 1024,
        },
        fuel: None,
    }
    .with_io_root(root.to_string_lossy().into_owned())
    .with_sqlite_root(root.to_string_lossy().into_owned());
    let runner = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/a5-loop-programs/approval_race_lock.rss"),
        config,
    )
    .expect("approval race lock helper should compile");
    let db_file_name = db_path
        .file_name()
        .expect("db file name")
        .to_string_lossy()
        .into_owned();
    let command = command.to_string();
    let run_id = run_id.to_string();
    let markers_dir = root.join("markers").to_string_lossy().into_owned();
    let runtime = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        let _guard = runtime.enter();
        let context = VmValue::map(vec![
            (VmValue::string("command"), VmValue::string(command)),
            (VmValue::string("db_path"), VmValue::string(db_file_name)),
            (VmValue::string("run_id"), VmValue::string(run_id)),
            (VmValue::string("markers_dir"), VmValue::string(markers_dir)),
        ]);
        if let Err(error) = runner.run_with_context(context) {
            panic!("approval race lock helper failed: {error:?}");
        }
    })
}

/// A stop landing AFTER the durable approval row exists but BEFORE the park
/// insert + `approval.required` append completes must cancel the run typed
/// (never park it until the 600s approval_timeout expiry sweep) and must not
/// produce a post-stop `approval.required` event. The fixture drives the
/// custom `approval.wait`-only program so the park sequence is the only
/// storage traffic the lock helper has to control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_stop_racing_the_park_insert_cancels_typed_without_a_post_stop_event() {
    let root = temporary_root("p2-park-insert-race");
    // The provider delay widens the margin between the phase-A hold and the
    // park's durable approval.request arrival (the custom program performs
    // one delayed provider round before yielding approval.wait).
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 800);
    let program = loop_program_runner("approval_wait_only.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        config.approval_mode = "manual".to_string();
        // The default expiry horizon: a wrongly parked run would sit here
        // until the sweep, far beyond the test's bounded wait.
        config.approval_timeout = Duration::from_secs(600);
        config.janitor_interval = Duration::from_secs(3600);
        config.run_timeout = Duration::from_secs(60);
    });
    let service = state.service();
    let markers = write_race_markers(&root);
    let db_path = root.join("state.db");

    // Admit FIRST (admission itself needs the DB, which the hold blocks).
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    // Phase A: the continuous RESERVED hold blocks the durable
    // approval.request (the custom program emits nothing, so no earlier
    // storage traffic exists).
    let lock_thread = run_lock_helper(&root, &db_path, "hold-begin", "");
    wait_tight(Duration::from_secs(10), || {
        marker_is_one(&markers, "phase_held")
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Poll for the durable row; the moment it commits (the phase-A hold has
    // ended), poll-shared occupies RESERVED so the run transition's writer
    // statements block — the stop below lands AFTER the row but BEFORE the
    // park insert completes.
    let poll_thread = run_lock_helper(&root, &db_path, "poll-shared", &admitted.run_id);
    wait_tight(Duration::from_secs(15), || {
        marker_is_one(&markers, "shared_held")
    });

    let status = service.stop(&admitted.run_id).expect("stop");
    assert_eq!(status, "stopping");
    // The poll-shared hold auto-ends; the transition then completes and the
    // re-check must cancel the run typed (never park it until the sweep).

    // The run must cancel typed well before the 600s expiry sweep.
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(20)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "cancelled",
        "a stop racing the park insert must never leave the run parked until the expiry sweep"
    );
    assert_eq!(
        cancelled_reason(&state, &admitted.run_id).as_deref(),
        Some("requested"),
        "the stop's typed reason must be committed"
    );
    let types = event_types(&replayed_events(&state, &admitted.run_id));
    assert!(
        !types.contains(&"approval.required".to_string()),
        "a stop racing the park insert must not produce a post-stop approval.required event"
    );

    lock_thread.join().expect("lock helper");
    poll_thread.join().expect("poll helper");
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The durable approval request must run on a blocking thread: with ONE
/// Tokio worker, a SQLite-stalled `request_pending` must not stall other
/// tasks on the runtime. The fixture drives the custom `approval.wait`-only
/// program so request_pending is the run's FIRST (and only) storage traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_approval_request_pending_never_blocks_tokio_workers() {
    let root = temporary_root("p2-request-pending-worker");
    // The provider delay widens the margin between the phase-A hold and the
    // park's durable approval.request arrival (the custom program performs
    // one delayed provider round before yielding approval.wait).
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 800);
    let program = loop_program_runner("approval_wait_only.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        config.approval_mode = "manual".to_string();
        config.approval_timeout = Duration::from_secs(600);
        config.run_timeout = Duration::from_secs(60);
    });
    let service = state.service();
    let markers = write_race_markers(&root);
    let db_path = root.join("state.db");

    // A heartbeat task on the SINGLE tokio worker keeps beating while the
    // park's durable approval request is blocked on the SQLite lock.
    let beats = std::sync::Arc::new(std::sync::Mutex::new(Vec::<std::time::Instant>::new()));
    let beats_for_task = std::sync::Arc::clone(&beats);
    tokio::spawn(async move {
        loop {
            beats_for_task
                .lock()
                .expect("beats lock")
                .push(std::time::Instant::now());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    // Admit FIRST (admission itself needs the DB, which the hold blocks).
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    let lock_thread = run_lock_helper(&root, &db_path, "hold-begin", "");
    // Async poll (the single worker must stay free to drive the heartbeat).
    let held = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if marker_is_one(&markers, "phase_held") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(held.is_ok(), "the phase-A hold must be established");
    // The park's request_pending arrives after the delayed provider round
    // (well inside the phase-A hold) and blocks on the exclusive lock. On
    // the old code this call occupied the ONLY tokio worker, freezing every
    // other task (including the heartbeat).
    tokio::time::sleep(Duration::from_millis(2000)).await;
    {
        let all_beats = beats.lock().expect("beats lock");
        let max_gap = all_beats.windows(2).map(|pair| pair[1] - pair[0]).max();
        assert!(
            max_gap.is_none_or(|gap| gap < Duration::from_millis(300)),
            "the tokio worker must not be occupied by the durable approval request (max heartbeat gap {max_gap:?})"
        );
    }

    // The phase-A hold auto-ends; the park then completes.
    wait_for(Duration::from_secs(20), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });
    let status = service.stop(&admitted.run_id).expect("stop");
    assert_eq!(status, "stopping");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(15)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");

    lock_thread.join().expect("lock helper");
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// In-memory-only mode must mirror the loop's tool-cycle messages into the
/// session: the production loop supports multiple runs per session, so a
/// second run on the same session must seed the first run's assistant
/// tool-call and tool result (silently dropping them would corrupt the
/// conversation history).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_in_memory_tool_cycle_messages_reach_the_next_run_in_the_same_session() {
    let root = temporary_root("p2-in-memory-session");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("mem.txt"), "content": "mem"})
                )])),
            ),
            (200, wire_text("done")),
            (200, wire_text("second answer")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, false, |config| {
        config.run_timeout = Duration::from_secs(30);
        // In-memory mode has no durable approval bridge: auto-approve the
        // tool round so the loop never yields approval.wait.
        config.approval_mode = "all".to_string();
    });
    let service = state.service();

    // Run 1: a tool round executes file.write against the real io root.
    let first = admit_and_spawn(&service, "use the tool", None, "test").await;
    wait_terminal(&service, &first.run_id, Duration::from_secs(30)).await;
    assert_eq!(
        fs::read_to_string(root.join("mem.txt")).expect("written"),
        "mem"
    );

    // Run 2: the SAME in-memory session; its provider request must carry
    // run 1's tool cycle (the assistant tool call + the tool result).
    let second =
        admit_and_spawn(&service, "continue", Some(first.session_id.clone()), "test").await;
    wait_terminal(&service, &second.run_id, Duration::from_secs(30)).await;

    let body = server.request_body(2).expect("second run provider request");
    let messages = body
        .get("messages")
        .and_then(JsonValue::as_array)
        .expect("messages");
    let tool_message = messages
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("run 2 must see run 1's tool result");
    assert_eq!(
        tool_message["tool_call_id"],
        json!("call-1"),
        "the tool result must reach the next run in the same in-memory session: {body}"
    );
    assert!(
        messages.iter().any(|message| {
            message["role"] == "assistant"
                && message["tool_calls"]
                    .as_array()
                    .is_some_and(|calls| calls.iter().any(|call| call["id"] == "call-1"))
        }),
        "run 2 must see run 1's assistant tool call: {body}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The invocation-error branch: eight emitted tail events must all be
/// durably appended (in emission order) BEFORE the `run.failed` terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tail_events_are_durable_and_ordered_before_the_failed_terminal() {
    let root = temporary_root("e2e-drain-error");
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 0);
    let program = loop_program_runner("emit_then_fail.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        // A small bounded channel forces the delivery task to lag the worker,
        // so the terminal commit would race in-flight appends.
        config.event_channel_capacity = 2;
        config.run_timeout = Duration::from_secs(30);
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "fail after events", None, "test").await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "failed");

    let events = replayed_events(&state, &admitted.run_id);
    let started: Vec<i64> = events
        .iter()
        .filter(|(_, event_type, _)| event_type == "model.started")
        .map(|(seq, _, _)| *seq)
        .collect();
    assert_eq!(
        started.len(),
        8,
        "every tail event must be durably appended before the terminal: {events:?}"
    );
    for pair in started.windows(2) {
        assert!(
            pair[0] < pair[1],
            "tail events must replay in emission order"
        );
    }
    let terminal_seq = events
        .iter()
        .find(|(_, event_type, _)| event_type == "run.failed")
        .map(|(seq, _, _)| *seq)
        .expect("run.failed terminal");
    assert!(
        started.last().is_none_or(|last| *last < terminal_seq),
        "the terminal must be replayed after every tail event: {events:?}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The delivery outcome must be checked on the ERROR branch too: a schema
/// violation recorded while the worker later fails typed must surface as the
/// typed `invalid_event_schema` terminal (the old code skipped the delivery
/// check entirely on the error branches).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_schema_violation_surfaces_typed_even_when_the_worker_fails() {
    let root = temporary_root("e2e-drain-schema");
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 0);
    let program = loop_program_runner("emit_then_fail_with_invalid_event.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        config.event_channel_capacity = 2;
        config.run_timeout = Duration::from_secs(30);
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "invalid event then fail", None, "test").await;
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "failed");

    let events = replayed_events(&state, &admitted.run_id);
    let failed = events
        .iter()
        .find(|(_, event_type, _)| event_type == "run.failed")
        .expect("run.failed terminal");
    assert_eq!(
        failed.2["error_code"],
        json!("invalid_event_schema"),
        "the delivery outcome must be checked on the error branch too: {events:?}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The cancellation branch: the tail event emitted before the stalled
/// provider call must be durably replayed BEFORE the typed `run.cancelled`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tail_events_are_durable_before_the_cancelled_terminal() {
    let root = temporary_root("e2e-drain-cancel");
    let server = spawn_scripted_server(vec![(200, wire_text("never reached"))], 30_000);
    let program = loop_program_runner("emit_then_stall.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        config.run_timeout = Duration::from_secs(60);
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "stall", None, "test").await;
    wait_tight(Duration::from_secs(10), || server.request_count() >= 1);
    let status = service.stop(&admitted.run_id).expect("stop");
    assert_eq!(status, "stopping");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");

    let events = replayed_events(&state, &admitted.run_id);
    let started_seq = events
        .iter()
        .find(|(_, event_type, _)| event_type == "model.started")
        .map(|(seq, _, _)| *seq)
        .expect("the tail model.started event must be durable");
    let terminal_seq = events
        .iter()
        .find(|(_, event_type, _)| event_type == "run.cancelled")
        .map(|(seq, _, _)| *seq)
        .expect("run.cancelled terminal");
    assert!(
        started_seq < terminal_seq,
        "the tail event must replay before the terminal: {events:?}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The deadline branch: the same invariant with the typed `deadline` reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tail_events_are_durable_before_the_deadline_terminal() {
    let root = temporary_root("e2e-drain-deadline");
    let server = spawn_scripted_server(vec![(200, wire_text("never reached"))], 30_000);
    let program = loop_program_runner("emit_then_stall.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        config.run_timeout = Duration::from_secs(2);
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "stall", None, "test").await;
    wait_tight(Duration::from_secs(10), || server.request_count() >= 1);
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(30)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "cancelled");
    assert_eq!(
        cancelled_reason(&state, &admitted.run_id).as_deref(),
        Some("deadline"),
        "the step deadline must cancel with the typed deadline reason"
    );

    let events = replayed_events(&state, &admitted.run_id);
    let started_seq = events
        .iter()
        .find(|(_, event_type, _)| event_type == "model.started")
        .map(|(seq, _, _)| *seq)
        .expect("the tail model.started event must be durable");
    let terminal_seq = events
        .iter()
        .find(|(_, event_type, _)| event_type == "run.cancelled")
        .map(|(seq, _, _)| *seq)
        .expect("run.cancelled terminal");
    assert!(
        started_seq < terminal_seq,
        "the tail event must replay before the terminal: {events:?}"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_approval_transition_failure_retry_remembers_the_durable_decision_and_executes_the_approved_action()
 {
    let root = temporary_root("a1b-approve-retry-memory");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("a1b.txt"), "content": "a1b"})
                )])),
            ),
            (200, wire_text("resumed and done")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });

    // External interference: the durable run leaves `waiting_approval` before
    // the resolution lands, so the typed transition cannot match.
    let persistence = state.persistence().expect("durable persistence");
    persistence
        .run_transition(&json!({
            "run_id": admitted.run_id,
            "from_status": "waiting_approval",
            "to_status": "running",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "test interference",
            "now_ms": 0,
        }))
        .expect("external transition");
    let first = service.resolve_run_approval(&admitted.run_id, true);
    assert!(
        first.is_err(),
        "the failed transition must surface as a typed error"
    );

    // Restore the durable status and retry: the park must remember the
    // DURABLE approve (the bridge already transitioned the row to
    // `approved`), so the retry must NOT re-resolve and must NOT downgrade
    // the approve to a deny.
    persistence
        .run_transition(&json!({
            "run_id": admitted.run_id,
            "from_status": "running",
            "to_status": "waiting_approval",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "test restore",
            "now_ms": 0,
        }))
        .expect("restore transition");
    service
        .resolve_run_approval(&admitted.run_id, true)
        .expect("the retry must find the park and resume");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(15)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    assert_eq!(server.request_count(), 2);

    // The approved action REALLY executed: the file was written, and the
    // durable approval row stayed `approved` (never downgraded).
    assert_eq!(
        fs::read_to_string(root.join("a1b.txt")).expect("the approved write must execute"),
        "a1b"
    );
    let approved = persistence
        .approval_get(&durable_parked_approval_id(&state, &admitted.run_id))
        .expect("approval get");
    let row = approved["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .expect("approval row");
    assert_eq!(
        row[7],
        json!("approved"),
        "the durable row must stay approved"
    );
    // The model saw a REAL tool success in the second round, not a denial:
    // the wire `tool` message carries the serialized result with `ok:true`
    // and no `is_error` flag.
    let second = server.request_body(1).expect("second provider request");
    let messages = second["messages"].as_array().expect("messages");
    let tool = messages
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("tool message in the second round");
    let content = tool["content"].as_str().unwrap_or("").to_string();
    assert!(
        content.contains("\"ok\":true"),
        "the approved tool result must be the real success payload, got: {content}"
    );
    assert!(
        !content.contains("\"is_error\":true"),
        "the approved tool result must never carry the error flag"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The approval id parked for one run (the single `approval.required` event
/// carries it).
fn durable_parked_approval_id(state: &AgentGatewayState, run_id: &str) -> String {
    replayed_events(state, run_id)
        .iter()
        .find(|(_, event_type, _)| event_type == "approval.required")
        .and_then(|(_, _, data)| data["approval_id"].as_str().map(str::to_string))
        .expect("approval.required must carry the bridge id")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_already_resolved_is_a_typed_noop_and_never_resumes_with_a_deny() {
    let root = temporary_root("a1c-already-resolved");
    let server = spawn_scripted_server(
        vec![
            (
                200,
                wire_tool_calls(json!([tool_call(
                    "call-1",
                    "file.write",
                    json!({"path": root.join("a1c.txt"), "content": "a1c"})
                )])),
            ),
            (200, wire_text("expired and continued")),
        ],
        0,
    );
    let state = spawn_state(server.port(), &root, true, |config| {
        config.approval_mode = "manual".to_string();
        // Keep the janitor out of the race window: the test expires the row
        // directly and resolves through the same public path the sweep uses.
        config.janitor_interval = Duration::from_secs(3600);
    });
    let service = state.service();
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    wait_for(Duration::from_secs(15), || {
        durable_run_status(&state, &admitted.run_id) == "waiting_approval"
    });
    let approval_id = durable_parked_approval_id(&state, &admitted.run_id);

    // The row is durably expired (the sweep's typed command) BEFORE any
    // resolution: a later approve resolve sees `AlreadyResolved`.
    let persistence = state.persistence().expect("durable persistence");
    persistence
        .approval_expire(&json!({ "now_ms": i64::MAX }))
        .expect("durable expire");
    assert_eq!(
        durable_approval_state(&state, &approval_id).as_deref(),
        Some("expired")
    );

    // AlreadyResolved is a strict typed no-op: no transition, no resume, no
    // `resolved:false` deny recovery — the park stays reachable for the
    // expiry resume path.
    let first = service.resolve_run_approval(&admitted.run_id, true);
    assert!(
        first.is_err(),
        "an already-resolved approval must be a typed no-op"
    );
    assert!(
        first.unwrap_err().contains("already resolved"),
        "the no-op error must be the typed already-resolved error"
    );
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "waiting_approval",
        "the no-op must not transition or resume the run"
    );
    assert!(
        !replayed_events(&state, &admitted.run_id)
            .iter()
            .any(|(_, event_type, _)| event_type == "approval.resolved"),
        "the no-op must not emit approval.resolved"
    );

    // The expiry resume (the sweep's own path) resumes with the typed
    // `approval_expired` tool result and the loop continues.
    service
        .resolve_run_approval(&admitted.run_id, false)
        .expect("the expiry resume must find the restored park");
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(15)).await;
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    assert!(
        !root.join("a1c.txt").exists(),
        "the expired tool must never dispatch"
    );
    let body = server.request_body(1).expect("second provider request");
    let serialized = body.to_string();
    assert!(
        serialized.contains("approval_expired"),
        "the expired resume must carry the typed approval_expired code"
    );
    let resolved_events = replayed_events(&state, &admitted.run_id);
    let resolved = resolved_events
        .iter()
        .find(|(_, event_type, _)| event_type == "approval.resolved")
        .expect("approval.resolved event");
    assert_eq!(resolved.2["resolved"], json!(false));

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Copies the crate's `rss/` module tree into `root/rss` so a test can patch
/// one policy module and recompile the production loop against the patched
/// tree (the module graph resolves relative to the entry file).
fn e2e_copy_rss_tree(root: &std::path::Path) -> PathBuf {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss");
    let target = root.join("rss");
    e2e_copy_dir(&source, &target);
    target
}

fn e2e_copy_dir(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir_all(target).expect("copy dir create");
    for entry in fs::read_dir(source).expect("copy dir read") {
        let entry = entry.expect("copy dir entry");
        let from = entry.path();
        let to = target.join(entry.file_name());
        if from.is_dir() {
            e2e_copy_dir(&from, &to);
        } else {
            fs::copy(&from, &to).expect("copy file");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_unknown_compaction_command_is_a_typed_failure_and_the_run_continues() {
    let root = temporary_root("e2e-unknown-compaction-op");
    // A seeded durable history beyond the window forces the compaction gate.
    let seed =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .expect("seed state");
    let seed_persistence = seed.persistence().expect("seed persistence");
    let session_id = seed_pair_session(&seed_persistence);
    for index in 1..=8 {
        seed_text_message(&seed_persistence, &session_id, index);
    }
    drop(seed_persistence);

    // Patch compact.rss so the PLANNED command sequence carries an unknown
    // command FIRST (a plan that drifts from the storage contract): the
    // service must treat it as a typed failure — never a silent continue and
    // never a fabricated compaction.
    let rss_root = e2e_copy_rss_tree(&root);
    let compact_path = rss_root.join("agent/compact.rss");
    let source = fs::read_to_string(&compact_path).expect("copied compact policy");
    let old_commands =
        "        commands: [\n            {\n                op: \"compaction.start\",";
    let new_commands = "        commands: [\n            {\n                op: \"compact.purge\",\n                payload: {\n                    id: compaction_id,\n                    session_id: session_id\n                }\n            },\n            {\n                op: \"compaction.start\",";
    assert!(
        source.contains(old_commands),
        "the compact policy fixture anchor must match the copied module"
    );
    fs::write(&compact_path, source.replace(old_commands, new_commands))
        .expect("patched compact policy should be written");

    let server = spawn_scripted_server(
        vec![(200, wire_text("continued after the typed failure"))],
        0,
    );
    let mut config = base_config(server.port(), &root, true);
    config.max_context_messages = 6;
    config.retained_tail = 2;
    config.provider = Some("openai_chat".to_string());
    config.provider_options = json!({
        "base_url": format!("http://127.0.0.1:{}", server.port()),
        "api_key": "test-key",
        "model": "test-model"
    });
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_hosts = vec!["127.0.0.1".to_string()];
    config.http.allowed_ports = vec![server.port()];
    config.http.allow_private_ips = true;
    config.run_timeout = Duration::from_secs(60);
    let agent_config = rustscript_agent::AgentConfig {
        http: config.http.clone(),
        sqlite: config.sqlite.clone(),
        io: config.io.clone(),
        fuel: config.fuel,
    };
    let program = AgentRunner::from_file_with_entry(
        rss_root.join("agent/main.rss"),
        agent_config,
        rustscript_agent::PRODUCTION_LOOP_ENTRY,
    )
    .expect("patched production loop program should compile");
    let state = AgentGatewayState::with_program_and_sqlite(config, program, root.join("state.db"))
        .expect("state with the patched program");
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("compact"),
            session_id: Some(session_id.to_string()),
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "test".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
            request_overrides: serde_json::Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
        .expect("admission should succeed");
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "compact".to_string()),
    );
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(handle) = state.service().handle(&admitted.run_id)
            && handle.is_terminal()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The typed failure never wedges the run: it continues to the provider
    // and completes; NO compaction row was ever created.
    assert_eq!(durable_run_status(&state, &admitted.run_id), "completed");
    let events = replayed_events(&state, &admitted.run_id);
    let completed = events
        .iter()
        .find(|(_, event_type, _)| event_type == "compact.completed")
        .expect("compact.completed event");
    assert_eq!(completed.2["ok"], json!(false));
    let error = completed.2["error"].as_str().unwrap_or("").to_string();
    assert!(
        error.contains("unknown compaction command"),
        "the typed failure must name the unknown command, got: {error}"
    );
    let persistence = state.persistence().expect("durable persistence");
    let compaction = persistence
        .compaction_get("compact:session-1:2")
        .expect("compaction get");
    let rows = compaction
        .get("rows")
        .and_then(JsonValue::as_array)
        .expect("rows");
    assert!(
        rows.is_empty(),
        "no compaction row may be created when the first command is unknown"
    );
    assert_eq!(
        server.request_count(),
        1,
        "the loop continues to the provider"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Final P2: deadline-orphaned approval compensation and drain truncation
// ---------------------------------------------------------------------------
//
// P2-1: `park_for_approval`'s blocking `approval.request` is bounded by the
// remaining run deadline. When the deadline fires first, the request
// completes LATER in the background — and if its insert wins the lock race,
// a pending approval row exists with NO park and NO `approval.required`
// event. The compensation must durably cancel that SPECIFIC row the moment
// the background request completes (never leave it pending until the 600s
// approval_timeout sweep), and the run must still reach its typed terminal.
//
// P2-2: when a step's bounded delivery drain cannot finish within the
// cancellation grace (a runaway worker keeps the channel fed while the
// delivery task is stalled), the step must durably write the typed
// `run.truncated` marker BEFORE the terminal — never silently drop the
// tail.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_deadline_orphaned_approval_is_compensated_immediately() {
    let root = temporary_root("p2-deadline-orphan-approval");
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 800);
    let program = loop_program_runner("approval_wait_only.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        config.approval_mode = "manual".to_string();
        // A wrongly orphaned row would sit pending until this horizon, far
        // beyond the test's short assertion window.
        config.approval_timeout = Duration::from_secs(600);
        // The janitor can never be the cleaner inside the test window.
        config.janitor_interval = Duration::from_secs(3600);
        // The run deadline lands while the durable approval.request is
        // still blocked: the request can only complete AFTER the deadline.
        config.run_timeout = Duration::from_millis(1200);
    });
    let service = state.service();
    let markers = write_race_markers(&root);
    let db_path = root.join("state.db");

    // Admit FIRST (admission itself needs the DB, which the hold blocks).
    let admitted = admit_and_spawn(&service, "needs approval", None, "test").await;
    // Hold RESERVED until the test says release: the durable
    // approval.request blocks, the run deadline fires, and the request
    // completes only AFTER the release — strictly later than the timeout.
    let lock_thread = run_lock_helper(&root, &db_path, "hold-until-release", "");
    wait_tight(Duration::from_secs(10), || {
        marker_is_one(&markers, "phase_held")
    });
    // The assertion window: from now on, a pending orphan row for this run
    // must NOT survive (the poll helper signals `no_pending` the moment no
    // pending row exists — with the fix that is long before the 600s
    // approval_timeout horizon).
    let no_pending_thread = run_lock_helper(&root, &db_path, "wait-no-pending", &admitted.run_id);
    // The provider round (~800ms) plus the deadline (1200ms) elapse while
    // the request is still blocked on the lock.
    tokio::time::sleep(Duration::from_millis(1600)).await;
    fs::write(markers.join("phase_release"), "1").expect("release marker");

    // The run must cancel typed well before the 600s expiry sweep.
    wait_terminal(&service, &admitted.run_id, Duration::from_secs(20)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "cancelled",
        "the run must reach its typed terminal"
    );
    assert_eq!(
        cancelled_reason(&state, &admitted.run_id).as_deref(),
        Some("deadline"),
        "the run deadline's typed reason must be committed"
    );
    // The compensation contract: in a SHORT window after the terminal, no
    // pending orphan row exists for this run (either the storage guard
    // rejected the late insert, or the compensation durably cancelled the
    // specific row the moment the background request completed).
    wait_tight(Duration::from_secs(8), || {
        marker_is_one(&markers, "no_pending")
    });
    let types = event_types(&replayed_events(&state, &admitted.run_id));
    assert!(
        !types.contains(&"approval.required".to_string()),
        "a deadline-orphaned request must never produce an approval.required event"
    );

    lock_thread.join().expect("lock helper");
    no_pending_thread.join().expect("no-pending helper");
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_drain_timeout_writes_truncation_marker_before_terminal() {
    let root = temporary_root("p2-drain-truncation");
    let server = spawn_scripted_server(vec![(200, wire_text("unused"))], 0);
    let program = loop_program_runner("drain_stall.rss", server.port());
    let state = spawn_state_with_program(server.port(), &root, program, |config| {
        // The runaway worker's burst (200 events) far exceeds the tiny
        // channel, so backpressure wedges the worker while the delivery
        // task is stalled on the SQLite hold.
        config.event_channel_capacity = 4;
        config.cancellation_grace = Duration::from_millis(300);
        config.run_timeout = Duration::from_millis(1500);
        config.approval_mode = "all".to_string();
    });
    let service = state.service();
    let markers = write_race_markers(&root);
    let db_path = root.join("state.db");

    // Admit FIRST (admission needs the DB, which the hold blocks).
    let admitted = admit_and_spawn(&service, "runaway", None, "test").await;
    // Hold RESERVED: the delivery task stalls on the FIRST event's durable
    // append while the worker fills the bounded channel and blocks on
    // backpressure. The step deadline fires, and the step's bounded drain
    // cannot finish within the cancellation grace.
    let lock_thread = run_lock_helper(&root, &db_path, "hold-until-release", "");
    wait_tight(Duration::from_secs(10), || {
        marker_is_one(&markers, "phase_held")
    });
    // The step deadline (1500ms) plus both grace windows (300ms each)
    // elapse while the hold is up: the drain times out.
    tokio::time::sleep(Duration::from_millis(2300)).await;
    fs::write(markers.join("phase_release"), "1").expect("release marker");

    wait_terminal(&service, &admitted.run_id, Duration::from_secs(20)).await;
    assert_eq!(
        durable_run_status(&state, &admitted.run_id),
        "cancelled",
        "the deadline terminal must commit"
    );
    assert_eq!(
        cancelled_reason(&state, &admitted.run_id).as_deref(),
        Some("deadline"),
        "the typed deadline reason must be committed"
    );

    let events = replayed_events(&state, &admitted.run_id);
    let types = event_types(&events);
    let marker_index = types
        .iter()
        .position(|event_type| event_type == "run.truncated")
        .expect("the typed truncation marker must be durably recorded");
    let terminal_index = types
        .iter()
        .position(|event_type| event_type == "run.cancelled")
        .expect("the typed terminal must be recorded");
    assert!(
        marker_index < terminal_index,
        "the truncation marker must be durable BEFORE the terminal"
    );
    assert_eq!(
        terminal_index,
        types.len() - 1,
        "no event may be replayed after the terminal"
    );
    let marker = &events[marker_index].2;
    assert_eq!(marker["reason"], json!("delivery_drain_timeout"));
    assert_eq!(marker["dropped"], json!(true));
    assert!(
        marker["grace_ms"].as_i64().unwrap_or(0) > 0,
        "the marker carries the drain bound"
    );
    let delivered_deltas = types
        .iter()
        .filter(|event_type| *event_type == "model.delta")
        .count();
    assert!(
        delivered_deltas < 200,
        "the truncated tail must never be silently delivered in full (got {delivered_deltas})"
    );

    lock_thread.join().expect("lock helper");
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}
