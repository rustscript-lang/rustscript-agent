//! A5 production serial loop policy suites.
//!
//! These suites drive the PRODUCTION loop program (`rss/agent/main.rss`)
//! through the real embedding path (`AgentRunner` + `RunEventSink` +
//! `RunCancellation`): one typed context map in, one discriminated decision
//! map out, real provider transports over local fixture HTTP/SSE servers,
//! real `io::*` tool dispatch against a temp root, real SQLite for the
//! compaction path. The policy-only "blocked" skeleton is gone: every
//! provider call and tool dispatch is executed for real, and the confirmed
//! core gap (bounded foreground terminal) returns a typed
//! `capability_unavailable` tool result — never a fabricated success.
//!
//! The fixture servers record the request count and replay scripted wire
//! responses (the same pattern as `tests/provider_tests.rs`).

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rustscript_agent::{
    AgentConfig, AgentRunner, PRODUCTION_LOOP_ENTRY, RunCancellation, RunDeliveryError,
    RunEventSink,
};
use rustscript_vm::{IoPolicy, Value};
use serde_json::{Map as JsonMap, Value as JsonValue, json};

fn agent_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent")
}

fn temporary_root(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("rustscript-agent-loop-tests");
    let root = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("temporary root should be created");
    root
}

// ---------------------------------------------------------------------------
// Fixture HTTP/SSE servers (scripted, request-counted)
// ---------------------------------------------------------------------------

struct ScriptedServer {
    port: u16,
    requests: Arc<AtomicUsize>,
    shutdown: mpsc::Sender<()>,
}

impl ScriptedServer {
    fn port(&self) -> u16 {
        self.port
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

use std::sync::Arc;

/// Serves one scripted JSON body per request (responses[i] for the i-th
/// request); further requests reuse the last body. Records the request count.
fn spawn_scripted_json_server(responses: Vec<(u16, String)>) -> ScriptedServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let requests = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let count = Arc::clone(&requests);
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
                    count.fetch_add(1, Ordering::SeqCst);
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
        shutdown: shutdown_tx,
    }
}

/// One SSE body per request; the same transcript pattern as the provider
/// streaming fixtures (delta chunks then `[DONE]`).
fn spawn_scripted_sse_server(responses: Vec<String>) -> ScriptedServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let requests = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let count = Arc::clone(&requests);
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
                    count.fetch_add(1, Ordering::SeqCst);
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
                    let body = responses
                        .get(served)
                        .cloned()
                        .unwrap_or_else(|| responses.last().cloned().unwrap_or_default());
                    served += 1;
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
    ScriptedServer {
        port,
        requests,
        shutdown: shutdown_tx,
    }
}

// ---------------------------------------------------------------------------
// Wire fixtures (OpenAI Chat wire, as consumed by rss/llm/openai_chat.rss)
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

fn sse_text_stream(text: &str) -> String {
    let mut body = String::new();
    for chunk in text.chars().collect::<Vec<_>>().chunks(2) {
        let piece: String = chunk.iter().collect();
        body.push_str(&format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-3",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": null}]
            })
        ));
    }
    body.push_str("data: {}\n\n");
    body.push_str(&format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-3",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })
    ));
    body.push_str("data: [DONE]\n\n");
    body
}

fn tool_call(id: &str, name: &str, arguments: JsonValue) -> JsonValue {
    json!({
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": arguments.to_string()}
    })
}

// ---------------------------------------------------------------------------
// Runner helpers
// ---------------------------------------------------------------------------

fn loop_runner(port: u16, root: &std::path::Path) -> AgentRunner {
    let mut config = AgentConfig::for_hosts(["127.0.0.1"]);
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_ports = vec![port];
    config.http.allow_private_ips = true;
    config = config.with_sqlite_root(root).with_io_policy(IoPolicy {
        allowed_roots: vec![root.to_string_lossy().into_owned()],
        allow_write: true,
        allow_process: false,
        max_read_bytes: 1024 * 1024,
        max_write_bytes: 1024 * 1024,
    });
    AgentRunner::from_file_with_entry(agent_root().join("main.rss"), config, PRODUCTION_LOOP_ENTRY)
        .expect("production loop program should compile")
}

#[derive(Default)]
struct RecordingSink {
    events: Vec<JsonValue>,
}

impl RunEventSink for RecordingSink {
    fn deliver(&mut self, value: Value) -> Result<(), RunDeliveryError> {
        self.events.push(vm_value_to_json(&value));
        Ok(())
    }
}

fn run_loop(runner: &AgentRunner, context: JsonValue) -> (JsonValue, Vec<JsonValue>) {
    let mut sink = RecordingSink::default();
    let cancellation = RunCancellation::new();
    let result = runner
        .run_with_context_and_events(json_to_vm_value(&context), &mut sink, &cancellation)
        .unwrap_or_else(|error| panic!("loop invocation failed: {error:?}"));
    let Value::Map(result) = result else {
        panic!("loop entry should return a decision map");
    };
    (vm_value_to_json(&Value::Map(result)), sink.events)
}

/// Drives the loop the way the service does: a `retry` decision is followed
/// by a re-invocation with the carried state (retry_count + 1, same turn,
/// carried messages). Events accumulate across invocations.
fn run_loop_driven(runner: &AgentRunner, context: JsonValue) -> (JsonValue, Vec<JsonValue>) {
    let mut sink = RecordingSink::default();
    let cancellation = RunCancellation::new();
    let mut current = context;
    let decision = loop {
        let result = runner
            .run_with_context_and_events(json_to_vm_value(&current), &mut sink, &cancellation)
            .unwrap_or_else(|error| panic!("loop invocation failed: {error:?}"));
        let Value::Map(result) = result else {
            panic!("loop entry should return a decision map");
        };
        let decision = vm_value_to_json(&Value::Map(result));
        if decision["kind"] == json!("retry") {
            current["phase"] = json!("start");
            current["retry_count"] = decision["retry_count"].clone();
            current["turn"] = decision["turn"].clone();
            current["messages"] = decision["messages"].clone();
            current["last_text"] = decision["last_text"].clone();
            continue;
        }
        break decision;
    };
    (decision, sink.events)
}

fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(int) = value.as_i64() {
                Value::Int(int)
            } else {
                Value::Float(value.as_f64().expect("JSON number should be a float"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => Value::Array(
            values
                .iter()
                .map(json_to_vm_value)
                .collect::<Vec<_>>()
                .into(),
        ),
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(values.iter().map(vm_value_to_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

fn event_types(events: &[JsonValue]) -> Vec<String> {
    events
        .iter()
        .map(|event| event["type"].as_str().unwrap_or("?").to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Context builders
// ---------------------------------------------------------------------------

fn loop_config(mode: &str) -> JsonValue {
    json!({
        "base_retry_delay_ms": 40,
        "max_retry_delay_ms": 160,
        "max_context_messages": 0,
        "retained_tail": 4,
        "approval_mode": mode,
        "native_hard_deny": false,
        "stream": false,
        "parallel": false,
        "task": false,
        "max_output_tokens": 128,
        "now_ms": 0
    })
}

fn base_context(port: u16, config: JsonValue) -> JsonValue {
    json!({
        "run_id": "run-1",
        "session_id": "session-1",
        "phase": "start",
        "turn": 0,
        "retry_count": 0,
        "max_turns": 4,
        "max_retries": 2,
        "model": "test-model",
        "provider": "openai_chat",
        "provider_options": {
            "base_url": format!("http://127.0.0.1:{port}"),
            "api_key": "test-key",
            "model": "test-model"
        },
        "system_prompt": "",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
        "config": config
    })
}

fn result_kind(decision: &JsonValue) -> String {
    decision["kind"].as_str().unwrap_or("?").to_string()
}

// ---------------------------------------------------------------------------
// Suites
// ---------------------------------------------------------------------------

#[test]
fn loop_text_only_round_emits_canonical_events_and_completes() {
    let root = temporary_root("text-only");
    let server = spawn_scripted_json_server(vec![(200, wire_text("hello back"))]);
    let runner = loop_runner(server.port(), &root);
    let (decision, events) = run_loop(&runner, base_context(server.port(), loop_config("auto")));

    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("hello back"));
    assert_eq!(decision["turn"], json!(1));
    assert_eq!(
        event_types(&events),
        vec!["model.started", "model.delta", "model.completed"]
    );
    assert_eq!(events[0]["turn"], json!(0));
    assert_eq!(events[0]["model"], json!("test-model"));
    assert_eq!(events[1]["delta"], json!("hello back"));
    assert_eq!(events[2]["text"], json!("hello back"));
    assert_eq!(events[2]["tool_calls"], json!(0));
    assert_eq!(server.request_count(), 1);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_stream_transport_emits_the_same_canonical_event_stream() {
    let root = temporary_root("stream");
    let server = spawn_scripted_sse_server(vec![sse_text_stream("streamed")]);
    let runner = loop_runner(server.port(), &root);
    let mut config = loop_config("auto");
    config["stream"] = json!(true);
    let (decision, events) = run_loop(&runner, base_context(server.port(), config));

    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("streamed"));
    assert_eq!(
        event_types(&events),
        vec!["model.started", "model.delta", "model.completed"]
    );
    assert_eq!(events[1]["delta"], json!("streamed"));
    assert_eq!(server.request_count(), 1);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_tool_round_dispatches_file_write_and_backfills_the_tool_result() {
    let root = temporary_root("tool-round");
    let server = spawn_scripted_json_server(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("out.txt"), "content": "written by the loop"})
            )])),
        ),
        (200, wire_text("file written")),
    ]);
    let runner = loop_runner(server.port(), &root);
    let (decision, events) = run_loop(&runner, base_context(server.port(), loop_config("all")));

    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("file written"));
    assert_eq!(decision["turn"], json!(2));
    assert_eq!(
        event_types(&events),
        vec![
            "model.started",
            "model.delta",
            "model.completed",
            "tool.started",
            "tool.completed",
            "model.started",
            "model.delta",
            "model.completed",
        ]
    );
    assert_eq!(events[3]["tool_call_id"], json!("call-1"));
    assert_eq!(events[3]["name"], json!("file.write"));
    assert_eq!(server.request_count(), 2);

    let written = fs::read_to_string(root.join("out.txt")).expect("file tool should have written");
    assert_eq!(written, "written by the loop");
    // The tool result is backfilled into the carried message state: the
    // second provider request carried the tool message. The fixture only
    // checks the wire indirectly here; the decision messages are asserted
    // by the message-list suites below.
    assert!(decision["messages"].is_array());

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_terminal_tool_returns_typed_unavailable_never_fabricated_success() {
    let root = temporary_root("terminal-gap");
    let server = spawn_scripted_json_server(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "terminal.run",
                json!({"command": "echo hi"})
            )])),
        ),
        (200, wire_text("done")),
    ]);
    let runner = loop_runner(server.port(), &root);
    let (decision, events) = run_loop(&runner, base_context(server.port(), loop_config("all")));

    assert_eq!(result_kind(&decision), "run.completed");
    let tool_result = decision["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("tool message backfilled");
    let part = tool_result["content"]
        .as_array()
        .expect("content parts")
        .first()
        .expect("one part");
    assert_eq!(part["type"], json!("tool_result"));
    assert_eq!(part["is_error"], json!(true));
    let content = part["content"].as_str().expect("content string");
    assert!(
        content.contains("capability_unavailable")
            && content.contains("process_timeout_unavailable"),
        "terminal gap must be typed, got: {content}"
    );
    assert_eq!(events[4]["type"], json!("tool.completed"));
    assert_eq!(events[4]["ok"], json!(false));

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_provider_retry_applies_backoff_and_completes_without_reemitting_started() {
    let root = temporary_root("retry");
    let server = spawn_scripted_json_server(vec![
        wire_error(429, "rate_limit_error", "rate_limit_exceeded", "slow down"),
        wire_error(429, "rate_limit_error", "rate_limit_exceeded", "slow down"),
        (200, wire_text("after retries")),
    ]);
    let runner = loop_runner(server.port(), &root);
    let mut context = base_context(server.port(), loop_config("auto"));
    context["max_retries"] = json!(2);
    let (decision, events) = run_loop_driven(&runner, context);

    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("after retries"));
    assert_eq!(decision["turn"], json!(1));
    // One model.started per turn, never per retry attempt.
    assert_eq!(
        event_types(&events),
        vec!["model.started", "model.delta", "model.completed"]
    );
    assert_eq!(server.request_count(), 3);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_nonretryable_provider_error_fails_the_run_typed() {
    let root = temporary_root("nonretryable");
    let server = spawn_scripted_json_server(vec![wire_error(
        400,
        "invalid_request_error",
        "bad_param",
        "bad parameter",
    )]);
    let runner = loop_runner(server.port(), &root);
    let (decision, events) = run_loop(&runner, base_context(server.port(), loop_config("auto")));

    assert_eq!(result_kind(&decision), "run.failed");
    assert_eq!(decision["reason"], json!("non_retryable"));
    assert_eq!(decision["error"]["status"], json!(400));
    assert_eq!(decision["error"]["type"], json!("invalid_request_error"));
    assert_eq!(decision["error"]["code"], json!("bad_param"));
    assert_eq!(event_types(&events), vec!["model.started"]);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_max_retries_exceeded_fails_the_run_typed() {
    let root = temporary_root("retries-exceeded");
    let server = spawn_scripted_json_server(vec![
        wire_error(500, "server_error", "server_error", "boom"),
        wire_error(500, "server_error", "server_error", "boom"),
        wire_error(500, "server_error", "server_error", "boom"),
    ]);
    let runner = loop_runner(server.port(), &root);
    let mut context = base_context(server.port(), loop_config("auto"));
    context["max_retries"] = json!(1);
    let (decision, _) = run_loop_driven(&runner, context);

    assert_eq!(result_kind(&decision), "run.failed");
    assert_eq!(decision["reason"], json!("max_retries_exceeded"));
    assert_eq!(decision["error"]["status"], json!(500));
    // The start attempt plus one retry; the second retry is refused.
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_max_turn_runaway_terminates_bounded() {
    let root = temporary_root("runaway");
    // The provider ALWAYS requests a tool; the loop must stop at max_turns.
    let server = spawn_scripted_json_server(vec![
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
    ]);
    let runner = loop_runner(server.port(), &root);
    let mut context = base_context(server.port(), loop_config("all"));
    context["max_turns"] = json!(2);
    let (decision, events) = run_loop(&runner, context);

    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["turn"], json!(2));
    // Exactly two model rounds happened before the bound.
    let started = events
        .iter()
        .filter(|event| event["type"] == "model.started")
        .count();
    assert_eq!(started, 2);
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_approval_pending_yields_a_wait_decision_with_typed_approval() {
    let root = temporary_root("approval-wait");
    let server = spawn_scripted_json_server(vec![(
        200,
        wire_tool_calls(json!([tool_call(
            "call-1",
            "file.write",
            json!({"path": root.join("out.txt"), "content": "needs approval"})
        )])),
    )]);
    let runner = loop_runner(server.port(), &root);
    let (decision, events) = run_loop(&runner, base_context(server.port(), loop_config("manual")));

    assert_eq!(result_kind(&decision), "approval.wait");
    assert_eq!(decision["approval"]["tool_call_id"], json!("call-1"));
    assert_eq!(decision["approval"]["tool_name"], json!("file.write"));
    assert_eq!(decision["approval"]["risk_class"], json!("write"));
    assert_eq!(
        decision["approval"]["arguments"]["path"],
        json!(root.join("out.txt"))
    );
    // The loop yields the typed wait decision WITHOUT emitting the durable
    // approval.required event: the service emits it after the bridge
    // persisted the real approval id (exactly once per park), so the last
    // script-visible event here is the tool start, never a placeholder.
    assert_eq!(
        events.last().expect("last event")["type"],
        json!("tool.started")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["type"] == "approval.required"),
        "the loop must not emit a placeholder approval.required"
    );
    // The run must not have dispatched the tool while waiting.
    assert!(!root.join("out.txt").exists());
    assert_eq!(server.request_count(), 1);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_approval_resume_dispatches_exactly_once_and_completes() {
    let root = temporary_root("approval-resume");
    let server = spawn_scripted_json_server(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("out.txt"), "content": "approved"})
            )])),
        ),
        (200, wire_text("approved and done")),
    ]);
    let runner = loop_runner(server.port(), &root);
    let (wait, _) = run_loop(&runner, base_context(server.port(), loop_config("manual")));
    assert_eq!(result_kind(&wait), "approval.wait");

    let mut resume = base_context(server.port(), loop_config("manual"));
    resume["phase"] = json!("approval.resume");
    resume["approval"] = json!({
        "approval_id": "approval-1",
        "tool_call_id": "call-1",
        "tool_name": "file.write",
        "arguments": {"path": root.join("out.txt"), "content": "approved"},
        "risk_class": "write",
        "resolved": true,
        "reason": ""
    });
    resume["tool_calls"] = wait["tool_calls"].clone();
    resume["tool_index"] = wait["tool_index"].clone();
    resume["messages"] = wait["messages"].clone();
    resume["turn"] = wait["turn"].clone();
    let (decision, events) = run_loop(&runner, resume);

    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("approved and done"));
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "approval.resolved")
    );
    let approved_event = events
        .iter()
        .find(|event| event["type"] == "approval.resolved")
        .expect("resolved event");
    assert_eq!(approved_event["resolved"], json!(true));
    assert_eq!(
        fs::read_to_string(root.join("out.txt")).expect("written"),
        "approved"
    );
    // One tool round + one text round.
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_approval_denied_produces_a_typed_tool_result_and_the_loop_continues() {
    let root = temporary_root("approval-deny");
    let server = spawn_scripted_json_server(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("out.txt"), "content": "denied"})
            )])),
        ),
        (200, wire_text("the tool was denied")),
    ]);
    let runner = loop_runner(server.port(), &root);
    let (wait, _) = run_loop(&runner, base_context(server.port(), loop_config("manual")));
    assert_eq!(result_kind(&wait), "approval.wait");

    let mut resume = base_context(server.port(), loop_config("manual"));
    resume["phase"] = json!("approval.resume");
    resume["approval"] = json!({
        "approval_id": "approval-1",
        "tool_call_id": "call-1",
        "tool_name": "file.write",
        "arguments": {"path": root.join("out.txt"), "content": "denied"},
        "risk_class": "write",
        "resolved": false,
        "reason": "approval denied"
    });
    resume["tool_calls"] = wait["tool_calls"].clone();
    resume["tool_index"] = wait["tool_index"].clone();
    resume["messages"] = wait["messages"].clone();
    resume["turn"] = wait["turn"].clone();
    let (decision, events) = run_loop(&runner, resume);

    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("the tool was denied"));
    let tool_message = decision["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("tool message");
    let part = tool_message["content"]
        .as_array()
        .expect("content")
        .first()
        .expect("part");
    assert_eq!(part["type"], json!("tool_result"));
    assert_eq!(part["is_error"], json!(true));
    assert!(
        part["content"]
            .as_str()
            .expect("content")
            .contains("approval_denied")
    );
    // The file was never written.
    assert!(!root.join("out.txt").exists());
    let resolved = events
        .iter()
        .find(|event| event["type"] == "approval.resolved")
        .expect("resolved event");
    assert_eq!(resolved["resolved"], json!(false));
    assert_eq!(server.request_count(), 2);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_parallel_and_task_config_yield_typed_handoffs_never_fabricated_actions() {
    let root = temporary_root("handoff");
    let server = spawn_scripted_json_server(vec![(200, wire_text("unused"))]);
    let runner = loop_runner(server.port(), &root);

    let mut parallel = base_context(server.port(), loop_config("auto"));
    parallel["config"]["parallel"] = json!(true);
    let (decision, _) = run_loop(&runner, parallel);
    assert_eq!(result_kind(&decision), "parallel.handoff");
    assert_eq!(decision["executable"], json!(false));
    assert!(
        decision["blocked_reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    assert_eq!(server.request_count(), 0);

    let mut task = base_context(server.port(), loop_config("auto"));
    task["config"]["task"] = json!(true);
    let (decision, _) = run_loop(&runner, task);
    assert_eq!(result_kind(&decision), "subagent.handoff");
    assert_eq!(decision["executable"], json!(false));
    assert_eq!(server.request_count(), 0);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Durable compaction executed by the loop
// ---------------------------------------------------------------------------

fn storage_runner(root: &std::path::Path) -> AgentRunner {
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/storage/main.rss"),
        AgentConfig::default().with_sqlite_root(root),
    )
    .expect("production storage entrypoint should compile")
}

fn run_storage(runner: &AgentRunner, db_name: &str, op: &str, payload: JsonValue) -> JsonValue {
    let input = json!({
        "op": op,
        "request_id": "test",
        "db_path": db_name,
        "db_mode": "read_write_create",
        "busy_timeout_ms": 5000,
        "max_rows": 1000,
        "max_bytes": 65536,
        "max_events": 128,
        "max_messages": 128,
        "now_ms": 0,
        "payload_json": payload.to_string()
    });
    let result = runner
        .run_with_context(json_to_vm_value(&input))
        .unwrap_or_else(|error| panic!("storage op {op} failed: {error:?}"));
    vm_value_to_json(&result)
}

fn seed_loop_compaction_history(storage: &AgentRunner, db_name: &str) {
    run_storage(storage, db_name, "migrate", json!({}));
    run_storage(
        storage,
        db_name,
        "session.create",
        json!({
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
        }),
    );
    run_storage(
        storage,
        db_name,
        "run.create",
        json!({
            "id": "run-1",
            "session_id": "session-1",
            "parent_run_id": "",
            "status": "queued",
            "model": "test-model",
            "provider": "openai_chat",
            "input_json": "\"hello\"",
            "script_hash": "test-script",
            "idempotency_scope": "api:chat",
            "idempotency_key": "run-1",
            "now_ms": 0
        }),
    );
    let running = run_storage(
        storage,
        db_name,
        "run.transition",
        json!({"run_id": "run-1", "from_status": "queued", "to_status": "running", "error_code": "", "error_message": "", "recovery_reason": "", "now_ms": 0}),
    );
    assert_eq!(running["ok"], json!(true), "queued -> running");
    for index in 1..=8 {
        let role = if index % 2 == 1 { "user" } else { "assistant" };
        let content = if role == "user" {
            format!(r#"[{{"type":"text","text":"message {index}"}}]"#)
        } else {
            format!(r#"[{{"type":"text","text":"reply {index}"}}]"#)
        };
        run_storage(
            storage,
            db_name,
            "message.append",
            json!({
                "id": format!("m-{index}"),
                "session_id": "session-1",
                "role": role,
                "content_json": content,
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 0,
                "metadata_json": "{}",
                "run_id": "run-1",
                "finish_reason": "",
                "now_ms": 0
            }),
        );
    }
}

fn durable_history_context(port: u16, root: &std::path::Path) -> JsonValue {
    let mut context = base_context(port, loop_config("auto"));
    context["run_id"] = json!("run-1");
    context["config"]["max_context_messages"] = json!(6);
    context["config"]["retained_tail"] = json!(2);
    context["config"]["generation"] = json!(1);
    context["config"]["message_count"] = json!(8);
    context["config"]["compaction_id"] = json!("compact:session-1:2");
    // The in-run message list mirrors the durable history (the service seeds
    // it from the loaded session) with internal ordinals 1..n.
    let mut messages = Vec::new();
    for index in 1..=8 {
        let role = if index % 2 == 1 { "user" } else { "assistant" };
        let text = format!("message {index}");
        messages.push(json!({
            "ordinal": index,
            "role": role,
            "content": [{"type": "text", "text": text}]
        }));
    }
    context["messages"] = json!(messages);
    let _ = root;
    context
}

/// Simulates the service executing the plan commands (the loop plans; the
/// service executes typed storage commands — durable sequencing). Returns
/// `(ok, error_message)`.
fn execute_compaction_plan(
    storage: &AgentRunner,
    db_name: &str,
    plan: &JsonValue,
) -> (bool, String) {
    let commands = plan["commands"].as_array().expect("plan commands");
    for command in commands {
        let op = command["op"].as_str().expect("command op");
        let payload = command["payload"].clone();
        let result = run_storage(storage, db_name, op, payload);
        if result["ok"] != json!(true) {
            let code = result["code"].as_str().unwrap_or("unknown").to_string();
            let message = result["message"].as_str().unwrap_or("").to_string();
            return (false, format!("{op} failed: {code} {message}"));
        }
    }
    (true, String::new())
}

/// Converts one raw SQLite row (array of values) into an object using the
/// given column names (the raw storage result rows are arrays).
fn row_to_map(columns: &[&str], row: &JsonValue) -> JsonMap<String, JsonValue> {
    let mut map = JsonMap::new();
    if let Some(values) = row.as_array() {
        for (index, column) in columns.iter().enumerate() {
            if let Some(value) = values.get(index) {
                map.insert(column.to_string(), value.clone());
            }
        }
    }
    map
}

const COMPACTION_COLUMNS: &[&str] = &[
    "id",
    "session_id",
    "run_id",
    "generation",
    "source_start_ordinal",
    "source_end_ordinal",
    "retained_tail_ordinal",
    "summary_json",
    "token_estimate",
    "model",
    "state",
    "error_message",
    "created_at_ms",
    "completed_at_ms",
];

const MESSAGE_COLUMNS: &[&str] = &[
    "id",
    "session_id",
    "ordinal",
    "role",
    "content_json",
    "name",
    "tool_call_id",
    "parent_message_id",
    "token_estimate",
    "compacted",
    "metadata_json",
    "run_id",
    "finish_reason",
    "created_at_ms",
];

const SESSION_COLUMNS: &[&str] = &[
    "id",
    "profile",
    "platform",
    "account_id",
    "chat_id",
    "thread_id",
    "user_id",
    "generation",
    "status",
    "system_prompt",
    "model",
    "provider",
    "toolset_hash",
    "metadata_json",
    "last_message_seq",
    "created_at_ms",
    "updated_at_ms",
    "title",
    "end_reason",
];

#[test]
fn loop_compaction_plans_then_executes_start_mark_commit() {
    let root = temporary_root("loop-compaction");
    let storage = storage_runner(&root);
    let db_name = "loop-compaction.db";
    seed_loop_compaction_history(&storage, db_name);

    let server = spawn_scripted_json_server(vec![(200, wire_text("compacted and answered"))]);
    let runner = loop_runner(server.port(), &root);
    let context = durable_history_context(server.port(), &root);

    // First invocation: the long history exceeds the window -> compact plan.
    let (plan_decision, events) = run_loop(&runner, context);
    assert_eq!(result_kind(&plan_decision), "compact");
    assert_eq!(plan_decision["plan"]["kind"], json!("compact.plan"));
    let plan = plan_decision["plan"].clone();
    assert_eq!(plan["source_start_ordinal"], json!(1));
    assert_eq!(plan["source_end_ordinal"], json!(6));
    assert_eq!(plan["retained_tail_ordinal"], json!(6));
    assert_eq!(plan["generation"], json!(2));
    assert!(!events.iter().any(|event| event["type"] == "model.started"));
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "compact.started")
    );

    // The service transitions the run to 'compacting' and executes the plan
    // commands durably.
    let compacting = run_storage(
        &storage,
        db_name,
        "run.transition",
        json!({"run_id": "run-1", "from_status": "running", "to_status": "compacting", "error_code": "", "error_message": "", "recovery_reason": "", "now_ms": 0}),
    );
    assert_eq!(compacting["ok"], json!(true), "running -> compacting");
    let (ok, error) = execute_compaction_plan(&storage, db_name, &plan);
    assert!(ok, "plan commands should execute: {error}");
    let running = run_storage(
        &storage,
        db_name,
        "run.transition",
        json!({"run_id": "run-1", "from_status": "compacting", "to_status": "running", "error_code": "", "error_message": "", "recovery_reason": "", "now_ms": 0}),
    );
    assert_eq!(running["ok"], json!(true), "compacting -> running");

    // Second invocation: phase "compact.result" with the durable outcome —
    // the loop trims the prefix and continues with the provider call.
    let mut result_context = base_context(server.port(), loop_config("auto"));
    result_context["phase"] = json!("compact.result");
    result_context["compact_ok"] = json!(true);
    result_context["compact_error"] = json!("");
    result_context["plan"] = plan;
    result_context["messages"] = plan_decision["messages"].clone();
    result_context["turn"] = plan_decision["turn"].clone();
    let (decision, events) = run_loop(&runner, result_context);
    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("compacted and answered"));
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "compact.completed")
    );
    assert_eq!(server.request_count(), 1);

    // The compaction row is committed, the prefix marked, generation advanced.
    let compaction = run_storage(
        &storage,
        db_name,
        "compaction.get",
        json!({"compaction_id": plan_decision["plan"]["commands"][0]["payload"]["id"]}),
    );
    let rows = compaction["data"]["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    let row = row_to_map(COMPACTION_COLUMNS, &rows[0]);
    assert_eq!(row["state"], json!("committed"));
    assert_eq!(row["generation"], json!(2));
    assert_eq!(row["source_start_ordinal"], json!(1));
    assert_eq!(row["source_end_ordinal"], json!(6));

    let listed = run_storage(
        &storage,
        db_name,
        "message.list",
        json!({"session_id": "session-1", "after_ordinal": 0}),
    );
    let compacted_flags: Vec<i64> = listed["data"]["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| {
            row_to_map(MESSAGE_COLUMNS, row)["compacted"]
                .as_i64()
                .unwrap_or(0)
        })
        .collect();
    assert_eq!(
        compacted_flags,
        vec![1, 1, 1, 1, 1, 1, 0, 0],
        "prefix compacted, retained tail untouched"
    );

    let session = run_storage(
        &storage,
        db_name,
        "session.get",
        json!({"session_id": "session-1"}),
    );
    let session_rows = session["data"]["rows"].as_array().expect("rows");
    let session_row = row_to_map(SESSION_COLUMNS, &session_rows[0]);
    assert_eq!(session_row["generation"], json!(2));

    // The carried message list was trimmed to the retained tail.
    let trimmed = decision["messages"].as_array().expect("messages");
    assert_eq!(trimmed.len(), 2);
    assert_eq!(trimmed[0]["ordinal"], json!(7));

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_compaction_failure_records_fail_durably_and_keeps_history_recoverable() {
    let root = temporary_root("loop-compaction-fail");
    let storage = storage_runner(&root);
    let db_name = "loop-compaction-fail.db";
    seed_loop_compaction_history(&storage, db_name);

    let server = spawn_scripted_json_server(vec![(200, wire_text("after failed compaction"))]);
    let runner = loop_runner(server.port(), &root);
    let context = durable_history_context(server.port(), &root);
    let (plan_decision, _) = run_loop(&runner, context);
    assert_eq!(result_kind(&plan_decision), "compact");

    // The run stays 'running' (the service transition was never applied):
    // compaction.start must reject with a typed guard failure — no pending
    // row is fabricated. The service resumes the loop with compact_ok: false
    // and the typed error; the loop keeps the full history.
    let plan = plan_decision["plan"].clone();
    let (ok, error) = execute_compaction_plan(&storage, db_name, &plan);
    assert!(!ok, "the start guard must reject while the run is running");
    assert!(
        error.contains("compaction_start_rejected"),
        "the guard rejection must be typed, got: {error}"
    );

    let mut result_context = base_context(server.port(), loop_config("auto"));
    result_context["phase"] = json!("compact.result");
    result_context["compact_ok"] = json!(false);
    result_context["compact_error"] = json!(error.clone());
    result_context["plan"] = plan.clone();
    result_context["messages"] = plan_decision["messages"].clone();
    result_context["turn"] = plan_decision["turn"].clone();
    let (decision, events) = run_loop(&runner, result_context);
    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(decision["text"], json!("after failed compaction"));
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "compact.completed")
    );
    // The full history was retained (no trim on failure).
    assert_eq!(decision["messages"].as_array().expect("messages").len(), 8);

    // No compaction row exists: the guard rejection fabricated nothing.
    let compaction = run_storage(
        &storage,
        db_name,
        "compaction.get",
        json!({"compaction_id": plan["commands"][0]["payload"]["id"]}),
    );
    let rows = compaction["data"]["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 0, "a rejected start must not fabricate a row");

    // No message was compacted and the session generation is unchanged
    // (fully recoverable).
    let listed = run_storage(
        &storage,
        db_name,
        "message.list",
        json!({"session_id": "session-1", "after_ordinal": 0}),
    );
    assert!(
        listed["data"]["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .all(|row| {
                row_to_map(MESSAGE_COLUMNS, row)["compacted"]
                    .as_i64()
                    .unwrap_or(0)
                    == 0
            }),
        "no message compacted on failure"
    );

    let session = run_storage(
        &storage,
        db_name,
        "session.get",
        json!({"session_id": "session-1"}),
    );
    let session_rows = session["data"]["rows"].as_array().expect("rows");
    let session_row = row_to_map(SESSION_COLUMNS, &session_rows[0]);
    assert_eq!(session_row["generation"], json!(1));

    // Recoverable: after the service applies the run transition, the exact
    // same plan executes and commits (failed guard -> retry succeeds).
    let compacting = run_storage(
        &storage,
        db_name,
        "run.transition",
        json!({"run_id": "run-1", "from_status": "running", "to_status": "compacting", "error_code": "", "error_message": "", "recovery_reason": "", "now_ms": 0}),
    );
    assert_eq!(compacting["ok"], json!(true), "running -> compacting");
    let (ok, error) = execute_compaction_plan(&storage, db_name, &plan);
    assert!(ok, "the retried plan should execute: {error}");
    let compaction = run_storage(
        &storage,
        db_name,
        "compaction.get",
        json!({"compaction_id": plan["commands"][0]["payload"]["id"]}),
    );
    let rows = compaction["data"]["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    let row = row_to_map(COMPACTION_COLUMNS, &rows[0]);
    assert_eq!(row["state"], json!("committed"));

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[test]
fn loop_within_window_skips_compaction() {
    let root = temporary_root("loop-compaction-skip");
    let server = spawn_scripted_json_server(vec![(200, wire_text("short history"))]);
    let runner = loop_runner(server.port(), &root);
    let mut context = base_context(server.port(), loop_config("auto"));
    context["config"]["max_context_messages"] = json!(6);
    let (decision, _) = run_loop(&runner, context);
    assert_eq!(result_kind(&decision), "run.completed");
    assert_eq!(server.request_count(), 1);

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The decision protocol must never contain a fabricated parallel/subagent
/// action and never claim a terminal tool result as success.
#[test]
fn loop_decisions_never_fabricate_parallel_subagent_or_terminal_success() {
    let root = temporary_root("no-fabrication");
    let server = spawn_scripted_json_server(vec![(200, wire_text("ok"))]);
    let runner = loop_runner(server.port(), &root);
    let (decision, _) = run_loop(&runner, base_context(server.port(), loop_config("all")));
    let serialized = decision.to_string();
    for forbidden in [
        "\"subagent.started\"",
        "\"subagent.completed\"",
        "\"parallel.plan\"",
        "\"run.link_child\"",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "decision must not fabricate {forbidden}"
        );
    }
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Backoff edge semantics through the production loop: a base above the cap
/// clamps to the cap on entry and doubling stays capped.
#[test]
fn loop_backoff_base_above_cap_clamps_to_cap() {
    let root = temporary_root("backoff-cap");
    let server = spawn_scripted_json_server(vec![wire_error(
        429,
        "rate_limit_error",
        "rate_limit_exceeded",
        "slow down",
    )]);
    let runner = loop_runner(server.port(), &root);
    let mut context = base_context(server.port(), loop_config("auto"));
    context["config"]["base_retry_delay_ms"] = json!(1000);
    context["config"]["max_retry_delay_ms"] = json!(400);
    context["max_retries"] = json!(4);
    let (decision, _) = run_loop(&runner, context);
    assert_eq!(result_kind(&decision), "retry");
    assert_eq!(decision["delay_ms"], json!(400), "clamped on entry");
    let mut second_context = base_context(server.port(), loop_config("auto"));
    second_context["config"]["base_retry_delay_ms"] = json!(1000);
    second_context["config"]["max_retry_delay_ms"] = json!(400);
    second_context["max_retries"] = json!(4);
    second_context["retry_count"] = decision["retry_count"].clone();
    let (second, _) = run_loop(&runner, second_context);
    assert_eq!(result_kind(&second), "retry");
    assert_eq!(second["delay_ms"], json!(400), "doubling stays capped");
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Backoff must saturate at the cap without overflow for huge inputs.
#[test]
fn loop_backoff_saturates_without_overflow_for_huge_inputs() {
    let root = temporary_root("backoff-saturate");
    let server = spawn_scripted_json_server(vec![wire_error(
        429,
        "rate_limit_error",
        "rate_limit_exceeded",
        "slow down",
    )]);
    let runner = loop_runner(server.port(), &root);
    let near_max = i64::MAX / 2 + 1;

    let mut context = base_context(server.port(), loop_config("auto"));
    context["config"]["base_retry_delay_ms"] = json!(near_max);
    context["config"]["max_retry_delay_ms"] = json!(i64::MAX);
    context["max_retries"] = json!(4);
    context["retry_count"] = json!(1);
    let (decision, _) = run_loop(&runner, context);
    assert_eq!(result_kind(&decision), "retry");
    assert_eq!(
        decision["delay_ms"],
        json!(i64::MAX),
        "the first doubling saturates, never overflows"
    );

    // A very large retry count must terminate with the capped delay.
    let mut many = base_context(server.port(), loop_config("auto"));
    many["config"]["base_retry_delay_ms"] = json!(100);
    many["config"]["max_retry_delay_ms"] = json!(400);
    many["max_retries"] = json!(200_000);
    many["retry_count"] = json!(100_000);
    let (decision, _) = run_loop(&runner, many);
    assert_eq!(result_kind(&decision), "retry");
    assert_eq!(
        decision["delay_ms"],
        json!(400),
        "delay saturates at the cap"
    );
    assert_eq!(decision["retry_count"], json!(100_001));
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// Zero and negative backoff inputs are clamped (defined, bounded behavior).
#[test]
fn loop_backoff_zero_and_negative_inputs_are_clamped() {
    let root = temporary_root("backoff-zero");
    let server = spawn_scripted_json_server(vec![wire_error(
        429,
        "rate_limit_error",
        "rate_limit_exceeded",
        "slow down",
    )]);
    let runner = loop_runner(server.port(), &root);

    let mut zero = base_context(server.port(), loop_config("auto"));
    zero["config"]["base_retry_delay_ms"] = json!(0);
    zero["config"]["max_retry_delay_ms"] = json!(400);
    zero["max_retries"] = json!(4);
    let (decision, _) = run_loop(&runner, zero);
    assert_eq!(result_kind(&decision), "retry");
    assert_eq!(
        decision["delay_ms"],
        json!(0),
        "zero base retries immediately"
    );

    let mut negative = base_context(server.port(), loop_config("auto"));
    negative["config"]["base_retry_delay_ms"] = json!(-500);
    negative["config"]["max_retry_delay_ms"] = json!(-1);
    negative["max_retries"] = json!(4);
    let (decision, _) = run_loop(&runner, negative);
    assert_eq!(
        decision["delay_ms"],
        json!(0),
        "negative inputs clamp to zero"
    );

    let mut zero_cap = base_context(server.port(), loop_config("auto"));
    zero_cap["config"]["base_retry_delay_ms"] = json!(500);
    zero_cap["config"]["max_retry_delay_ms"] = json!(0);
    zero_cap["max_retries"] = json!(4);
    let (decision, _) = run_loop(&runner, zero_cap);
    assert_eq!(decision["delay_ms"], json!(0), "a zero cap clamps any base");
    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// A5 review fixes: typed approval envelope failure, compaction pair
// preservation, and the typed expired tool result.
// ---------------------------------------------------------------------------

/// Copies the crate's `rss/` module tree into `root/rss` so a test can patch
/// one policy module and recompile the production loop against the patched
/// tree (the module graph resolves relative to the entry file).
fn copy_rss_tree(root: &std::path::Path) -> PathBuf {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss");
    let target = root.join("rss");
    copy_dir(&source, &target);
    target
}

fn copy_dir(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir_all(target).expect("copy dir create");
    for entry in fs::read_dir(source).expect("copy dir read") {
        let entry = entry.expect("copy dir entry");
        let from = entry.path();
        let to = target.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to);
        } else {
            fs::copy(&from, &to).expect("copy file");
        }
    }
}

/// Compiles the production loop from a (possibly patched) rss tree.
fn patched_loop_runner(
    port: u16,
    root: &std::path::Path,
    rss_root: &std::path::Path,
) -> AgentRunner {
    let mut config = AgentConfig::for_hosts(["127.0.0.1"]);
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_ports = vec![port];
    config.http.allow_private_ips = true;
    config = config.with_sqlite_root(root).with_io_policy(IoPolicy {
        allowed_roots: vec![root.to_string_lossy().into_owned()],
        allow_write: true,
        allow_process: false,
        max_read_bytes: 1024 * 1024,
        max_write_bytes: 1024 * 1024,
    });
    AgentRunner::from_file_with_entry(
        rss_root.join("agent/main.rss"),
        config,
        PRODUCTION_LOOP_ENTRY,
    )
    .expect("patched production loop program should compile")
}

/// An approval policy envelope that OMITS the `action` key is a typed
/// `invalid_approval_action` failure — never a silent deny and never a
/// pending wait. The patched policy fixture returns the non-conforming
/// envelope only for the fixture-only `missing-action` mode (the real policy
/// never does).
#[test]
fn loop_approval_envelope_missing_action_fails_typed_invalid_approval_action() {
    let root = temporary_root("approval-missing-action");
    let rss_root = copy_rss_tree(&root);
    let approval_path = rss_root.join("harness/approval.rss");
    let source = fs::read_to_string(&approval_path).expect("copied approval policy");
    let old_envelope = "        {\n            ok: true,\n            decision: {\n                tool_name: tool_name,\n                risk_class: risk_class,\n                mode: mode,\n                action: action,\n                native_hard_deny: hard_deny\n            }\n        }";
    let new_envelope = "        let envelope: map = if mode == \"missing-action\" => {\n            {\n                ok: true,\n                decision: {\n                    tool_name: tool_name,\n                    risk_class: risk_class,\n                    mode: mode,\n                    native_hard_deny: hard_deny\n                }\n            }\n        } else => {\n            {\n                ok: true,\n                decision: {\n                    tool_name: tool_name,\n                    risk_class: risk_class,\n                    mode: mode,\n                    action: action,\n                    native_hard_deny: hard_deny\n                }\n            }\n        };\n        envelope";
    assert!(
        source.contains(old_envelope),
        "the approval policy fixture anchor must match the copied module"
    );
    fs::write(&approval_path, source.replace(old_envelope, new_envelope))
        .expect("patched approval policy should be written");

    let server = spawn_scripted_json_server(vec![(
        200,
        wire_tool_calls(json!([tool_call(
            "call-1",
            "file.write",
            json!({"path": root.join("x.txt"), "content": "x"})
        )])),
    )]);
    let runner = patched_loop_runner(server.port(), &root, &rss_root);
    let mut context = base_context(server.port(), loop_config("auto"));
    context["config"]["approval_mode"] = json!("missing-action");
    let (decision, events) = run_loop(&runner, context);

    assert_eq!(
        result_kind(&decision),
        "run.failed",
        "a non-conforming approval envelope must fail the run typed"
    );
    assert_eq!(
        decision["error"]["code"],
        json!("invalid_approval_action"),
        "the typed failure carries the invalid_approval_action code"
    );
    assert!(
        !events.iter().any(|event| event["type"] == "tool.completed"),
        "the missing action must never become a silent tool denial"
    );
    assert_eq!(
        server.request_count(),
        1,
        "the loop must not continue to a second provider round after the typed failure"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// The compaction boundary must push forward (fixpoint) so a tool pair
/// straddling the naive boundary is never split — even when the pair ids
/// arrive ONLY inside the content parts (the durable service context shape),
/// compact.rss must read them from the parts.
#[test]
fn loop_compaction_plan_falls_back_to_content_parts_for_pair_ids() {
    let root = temporary_root("compaction-pair-parts");
    let server = spawn_scripted_json_server(vec![(200, wire_text("answered"))]);
    let runner = loop_runner(server.port(), &root);
    let mut context = base_context(server.port(), loop_config("auto"));
    context["run_id"] = json!("run-1");
    context["config"]["max_context_messages"] = json!(6);
    context["config"]["retained_tail"] = json!(2);
    context["config"]["generation"] = json!(1);
    context["config"]["message_count"] = json!(8);
    context["config"]["compaction_id"] = json!("compact:session-1:2");
    // NOTE: the entries carry NO message-level `tool_call_id` (the service
    // context shape before the review fix); the pair ids live only in the
    // content parts.
    let mut messages = Vec::new();
    for index in 1..=5 {
        let role = if index % 2 == 1 { "user" } else { "assistant" };
        messages.push(json!({
            "ordinal": index,
            "role": role,
            "content": [{"type": "text", "text": format!("message {index}")}]
        }));
    }
    // The tool pair straddles the naive boundary (6): the assistant call is
    // the last prefix message and its tool result is the first tail message.
    messages.push(json!({
        "ordinal": 6,
        "role": "assistant",
        "content": [{"type": "tool_call", "tool_call_id": "call-pair", "name": "file.read", "arguments_json": "{}"}]
    }));
    messages.push(json!({
        "ordinal": 7,
        "role": "tool",
        "content": [{"type": "tool_result", "tool_call_id": "call-pair", "content": "{}", "is_error": false}]
    }));
    messages.push(json!({
        "ordinal": 8,
        "role": "user",
        "content": [{"type": "text", "text": "message 8"}]
    }));
    context["messages"] = json!(messages);

    let (decision, _) = run_loop(&runner, context);
    assert_eq!(result_kind(&decision), "compact");
    let plan = decision["plan"].clone();
    assert_eq!(plan["kind"], json!("compact.plan"));
    assert_eq!(plan["source_start_ordinal"], json!(1));
    assert_eq!(
        plan["source_end_ordinal"],
        json!(7),
        "the boundary must push across the tool result so the pair is never split"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// An expired approval resume folds a typed `approval_expired` tool result
/// into the conversation (never the generic deny code) and the loop
/// continues.
#[test]
fn loop_approval_resume_expired_folds_a_typed_approval_expired_tool_result() {
    let root = temporary_root("approval-expired");
    let server = spawn_scripted_json_server(vec![
        (
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("expired.txt"), "content": "expired"})
            )])),
        ),
        (200, wire_text("expired and continued")),
    ]);
    let runner = loop_runner(server.port(), &root);
    let (wait, _) = run_loop(&runner, base_context(server.port(), loop_config("manual")));
    assert_eq!(result_kind(&wait), "approval.wait");

    let mut resume = base_context(server.port(), loop_config("manual"));
    resume["phase"] = json!("approval.resume");
    resume["approval"] = json!({
        "approval_id": "approval-1",
        "tool_call_id": "call-1",
        "tool_name": "file.write",
        "arguments": {"path": root.join("expired.txt"), "content": "expired"},
        "risk_class": "write",
        "resolved": false,
        "outcome": "expired",
        "reason": "approval expired"
    });
    resume["tool_calls"] = wait["tool_calls"].clone();
    resume["tool_index"] = wait["tool_index"].clone();
    resume["messages"] = wait["messages"].clone();
    resume["turn"] = wait["turn"].clone();
    let (decision, events) = run_loop(&runner, resume);

    assert_eq!(result_kind(&decision), "run.completed");
    assert!(
        !root.join("expired.txt").exists(),
        "the expired tool must never dispatch"
    );
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "approval.resolved")
    );
    // The canonical tool message the model sees carries the typed expiry.
    let messages = decision["messages"].as_array().expect("messages");
    let tool_message = messages
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("the typed tool message must be appended");
    let part_content = tool_message["content"][0]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        part_content.contains("approval_expired"),
        "the expired resume must carry the typed approval_expired code, got: {part_content}"
    );
    assert!(
        !part_content.contains("approval_denied"),
        "the expired resume must never use the deny code"
    );

    fs::remove_dir_all(&root).expect("temporary root should be removed");
}
