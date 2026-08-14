//! Provider protocol adapter tests.
//!
//! Each test compiles the production RSS adapter modules (through the generic
//! `rss/llm/harness.rss` entry) and drives them over a real local HTTP/SSE
//! fixture. Fixture servers record the exact wire request (method, path,
//! headers, body) and replay real provider transcripts from
//! `tests/fixtures/providers/`.
//!
//! # Core consume (pd-vm compiler revision fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e)
//!
//! The four A3 core blockers are fixed in the pinned core revision (B1:
//! callable-schema identity across module merging; B2: tail expression-if
//! branch-local typing; B3: shared mutable closure captures; B4: runtime
//! string-key map encoding — see
//! `plans/2026-08-14_a3-rustscript-core-unblock.md`). The committed B1–B4
//! regression set in `tests/fixtures/core-repros/` runs by default through
//! `tests/core_repro_driver.rs` (positive assertions plus the preserved
//! by-value-capture rejection control).
//!
//! The residual slot-aliasing defect reported at d8cf291 (plan §11a) is
//! fixed by `fd4b570` (`fix(compiler): keep parameters live for the whole
//! body`): the liveness allocator seeds parameter slots into the body
//! live-out and re-marks them after every statement, so a local defined
//! after body entry can no longer be colored onto a parameter slot.
//! The OpenAI Chat suites below run by default and pass against the
//! pinned revision, including the streaming path (buffered, stream
//! aggregation, cancellation, and the EOF-without-`[DONE]` fail-closed
//! guard from the A3 review P2). The committed `param_aliasing_*` repro
//! pair in `tests/fixtures/core-repros/` (driven by
//! `tests/core_repro_driver.rs`) guards the fix independently of the wire
//! fixtures.
//!
//! The streaming adapter is implemented and correct (`openai_chat_stream`
//! in `rss/llm/openai_chat.rss`, with `http::client::sse` exposed in the
//! restricted registry). The `openai_responses` and `anthropic_messages`
//! adapters remain typed `not_implemented` stubs (no production adapter is
//! claimed); their transcript-reference suites stay `#[ignore]`d until
//! that agent work exists. Four buffered suites are green and remain so:
//! the structured provider-error mapping
//! (`openai_chat_provider_error_is_structured`), the P1 standard-wire
//! guard (`openai_chat_wire_format_is_standard`), and the two marker-splice
//! preservation guards
//! (`openai_chat_wire_preserves_marker_like_user_text`,
//! `openai_chat_wire_preserves_marker_like_tool_schema`).

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rustscript_agent::{
    AgentConfig, AgentRunner, RunCancellation, RunDeliveryError, RunError, RunEventSink,
};
use rustscript_vm::Value;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

// ---------------------------------------------------------------------------
// Fixture infrastructure
// ---------------------------------------------------------------------------

/// One recorded client request: raw head + body and the decoded body text.
#[derive(Debug)]
struct RecordedRequest {
    raw: String,
    body: String,
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/providers")
}

fn read_fixture(relative: &str) -> String {
    fs::read_to_string(fixture_root().join(relative))
        .unwrap_or_else(|error| panic!("fixture {relative} should be readable: {error}"))
}

/// Reads one HTTP/1.1 request (head plus content-length body) from the socket.
fn read_http_request(stream: &mut std::net::TcpStream) -> RecordedRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut content_length = None;
    loop {
        let read = stream.read(&mut buffer).expect("read fixture request");
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&request);
        if content_length.is_none() {
            for line in text.lines() {
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse::<usize>().ok();
                }
            }
        }
        if let Some(length) = content_length {
            let head_end = text.find("\r\n\r\n").map(|index| index + 4).unwrap_or(0);
            if request.len() >= head_end + length {
                break;
            }
        }
        if text.contains("\r\n\r\n") && content_length == Some(0) {
            break;
        }
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    RecordedRequest { raw: text, body }
}

/// Accepts one connection with a bounded wait so tests cannot hang when the
/// adapter under test never opens a connection.
fn accept_bounded(listener: &TcpListener) -> Option<std::net::TcpStream> {
    listener.set_nonblocking(true).expect("fixture nonblocking");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("fixture blocking mode");
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("fixture accept failed: {error}"),
        }
    }
}

/// Spawns a one-shot JSON fixture that records the request and replies with a
/// fixed status and body.
fn spawn_json_fixture(
    status: u16,
    body: String,
) -> (u16, mpsc::Receiver<RecordedRequest>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let Some(mut stream) = accept_bounded(&listener) else {
            return;
        };
        let request = read_http_request(&mut stream);
        sender.send(request).expect("record fixture request");
        let reason = if status == 200 { "OK" } else { "Error" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Provider-Fixture: 1\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write fixture response");
    });
    (port, receiver, handle)
}

/// Spawns an SSE fixture. Each event string is one full SSE dispatch (for
/// example `"data: {...}\n\n"`). When `hold_open` is true the connection is
/// kept open after the events until the client closes it.
fn spawn_sse_fixture(
    events: Vec<String>,
    hold_open: bool,
) -> (u16, mpsc::Receiver<RecordedRequest>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let Some(mut stream) = accept_bounded(&listener) else {
            return;
        };
        let request = read_http_request(&mut stream);
        sender.send(request).expect("record fixture request");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .expect("write fixture head");
        for event in &events {
            let chunk = format!("{:x}\r\n{}\r\n", event.len(), event);
            stream
                .write_all(chunk.as_bytes())
                .expect("write fixture event");
            stream.flush().expect("flush fixture event");
        }
        if hold_open {
            // Wait for the client to close (cancellation drops the stream);
            // a read timeout bounds the wait so the fixture never hangs.
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("fixture read timeout");
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
        } else {
            stream.write_all(b"0\r\n\r\n").expect("write fixture end");
        }
    });
    (port, receiver, handle)
}

/// Splits a `.sse` transcript file into one event per dispatch (blank-line
/// separated).
fn sse_events(transcript: &str) -> Vec<String> {
    transcript
        .split("\n\n")
        .map(str::trim_end)
        .filter(|event| !event.is_empty())
        .map(|event| format!("{event}\n\n"))
        .collect()
}

fn http_config(port: u16) -> AgentConfig {
    let mut config = AgentConfig::for_hosts(["127.0.0.1"]);
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_ports = vec![port];
    config.http.allow_private_ips = true;
    config
}

fn harness_runner(port: u16) -> AgentRunner {
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss"),
        http_config(port),
    )
    .expect("production adapter harness should compile")
}

/// Collects every delivered event value in order.
#[derive(Clone, Default)]
struct RecordingSink {
    values: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
}

impl RunEventSink for RecordingSink {
    fn deliver(&mut self, value: Value) -> Result<(), RunDeliveryError> {
        self.values
            .lock()
            .expect("recording sink lock should not be poisoned")
            .push(value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical request construction
// ---------------------------------------------------------------------------

/// Loads the canonical request fixture and applies test overrides.
fn canonical_request(port: u16, stream: bool) -> JsonValue {
    let mut request: JsonValue = serde_json::from_str(&read_fixture("requests/chat_request.json"))
        .expect("canonical request fixture should be JSON");
    request["provider_options"] = json!({
        "base_url": format!("http://127.0.0.1:{port}"),
        "api_key": "test-key",
    });
    request["stream"] = json!(stream);
    request
}

fn profile(provider: &str, port: u16) -> JsonValue {
    json!({
        "provider": provider,
        "base_url": format!("http://127.0.0.1:{port}"),
        "api_key": "test-key",
        "model": "",
        "capabilities": {"stream": true, "tools": true, "usage": true, "reasoning": false},
    })
}

/// Runs the adapter harness entry with the given kind and request, collecting
/// emitted events.
fn run_adapter(
    kind: &str,
    request: JsonValue,
    profile: JsonValue,
    runner: &AgentRunner,
) -> (JsonValue, Vec<JsonValue>) {
    let context = Value::map(vec![
        (Value::string("kind"), Value::string(kind)),
        (Value::string("request"), json_to_vm_value(&request)),
        (Value::string("profile"), json_to_vm_value(&profile)),
    ]);
    let mut sink = RecordingSink::default();
    let result = runner
        .run_with_context_and_events(context, &mut sink, &RunCancellation::new())
        .unwrap_or_else(|error| panic!("adapter {kind} run failed: {error:?}"));
    let events = sink
        .values
        .lock()
        .expect("sink lock")
        .iter()
        .map(vm_value_to_json)
        .collect();
    (vm_value_to_json(&result), events)
}

fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite json number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => Value::Array(std::sync::Arc::new(
            values.iter().map(json_to_vm_value).collect::<Vec<_>>(),
        )),
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

/// Converts one VM value into JSON (test-side mirror of the gateway renderer).
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

fn request_line(recorded: &RecordedRequest) -> &str {
    recorded.raw.lines().next().expect("request line")
}

fn header(recorded: &RecordedRequest, name: &str) -> Option<String> {
    recorded.raw.lines().find_map(|line| {
        let (head, value) = line.split_once(':')?;
        head.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn response_of(result: &JsonValue) -> &JsonMap<String, JsonValue> {
    result["response"].as_object().expect("response object")
}

fn error_of(result: &JsonValue) -> &JsonMap<String, JsonValue> {
    result["error"].as_object().expect("error object")
}

// ---------------------------------------------------------------------------
// S1: OpenAI Chat Completions, buffered
// ---------------------------------------------------------------------------

#[test]
fn openai_chat_non_stream_text_usage_and_reasoning() {
    let body = read_fixture("openai_chat/response.json");
    let (port, requests, fixture) = spawn_json_fixture(200, body);
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let (result, events) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(
        response["text"],
        json!("The RustScript agent framework keeps provider policy in RSS.")
    );
    assert_eq!(
        response["reasoning"],
        json!("User asked about the framework; summarize the ownership boundary.")
    );
    assert_eq!(response["stop_reason"], json!("stop"));
    assert_eq!(response["usage"]["input_tokens"], json!(12));
    assert_eq!(response["usage"]["output_tokens"], json!(15));
    assert_eq!(response["usage"]["total_tokens"], json!(27));
    assert_eq!(response["tool_calls"], json!([]));
    assert!(
        events.is_empty(),
        "buffered calls emit no events: {events:?}"
    );

    let recorded = requests.recv().expect("recorded request");
    assert_eq!(request_line(&recorded), "POST /chat/completions HTTP/1.1");
    assert_eq!(
        header(&recorded, "authorization").as_deref(),
        Some("Bearer test-key")
    );
    assert_eq!(
        header(&recorded, "content-type").as_deref(),
        Some("application/json")
    );
    let wire: JsonValue = serde_json::from_str(&recorded.body).expect("wire body is JSON");
    assert_eq!(wire["model"], json!("test-model"));
    assert_eq!(wire["stream"], json!(false));
    assert_eq!(wire["max_tokens"], json!(128));
    assert_eq!(wire["temperature"], json!(0.7));
    assert_eq!(wire["messages"][0]["role"], json!("user"));
    assert_eq!(wire["messages"][0]["content"][0]["text"], json!("hello"));
    assert_eq!(wire["messages"][1]["role"], json!("tool"));
    assert_eq!(wire["messages"][1]["tool_call_id"], json!("call_ab12"));
    assert_eq!(wire["messages"][1]["content"], json!("ok"));
    assert_eq!(wire["messages"][2]["role"], json!("assistant"));
    assert_eq!(
        wire["messages"][2]["content"],
        json!("Let me read the file.")
    );
    assert_eq!(
        wire["messages"][2]["tool_calls"][0]["function"]["arguments"],
        json!("{\"path\":\"README.md\"}")
    );
    assert_eq!(
        wire["tools"][0]["function"]["parameters"]["required"][0],
        json!("path")
    );
}

#[test]
fn openai_chat_non_stream_tool_calls() {
    let body = read_fixture("openai_chat/response_tools.json");
    let (port, requests, fixture) = spawn_json_fixture(200, body);
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(response["text"], json!(""));
    assert_eq!(response["stop_reason"], json!("tool_calls"));
    assert_eq!(response["usage"]["total_tokens"], json!(30));
    let calls = response["tool_calls"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["id"], json!("call_ab12"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(calls[0]["arguments"]["path"], json!("README.md"));
    assert_eq!(calls[0]["arguments"]["lines"], json!(40));
    assert_eq!(calls[1]["id"], json!("call_cd34"));
    assert_eq!(calls[1]["name"], json!("search_files"));
    assert_eq!(calls[1]["arguments"]["pattern"], json!("provider"));

    let recorded = requests.recv().expect("recorded request");
    assert_eq!(request_line(&recorded), "POST /chat/completions HTTP/1.1");
}

#[test]
fn openai_chat_provider_error_is_structured() {
    let body = read_fixture("openai_chat/error.json");
    let (port, _requests, fixture) = spawn_json_fixture(400, body);
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(false), "{result}");
    let error = error_of(&result);
    assert_eq!(error["status"], json!(400));
    assert_eq!(error["type"], json!("invalid_request_error"));
    assert_eq!(error["code"], json!("model_not_found"));
    assert_eq!(error["param"], json!("model"));
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("does not exist")
    );
}

/// P1 wire-format guard: the recorded request must carry the standard OpenAI
/// chat-completions wire shape (user `content` as a parts array, tool/assistant
/// content as plain strings, no custom `content_parts` field, tool schemas
/// spliced in place, `tool_choice` not an empty string). The fixture replies
/// 400 so the run follows the already-green error path; the wire is built and
/// recorded before the response is parsed, which keeps this assertion
/// independent of the core-blocked response-parse path.
#[test]
fn openai_chat_wire_format_is_standard() {
    let body = read_fixture("openai_chat/error.json");
    let (port, requests, fixture) = spawn_json_fixture(400, body);
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(false), "{result}");

    let recorded = requests.recv().expect("recorded request");
    assert_eq!(request_line(&recorded), "POST /chat/completions HTTP/1.1");
    let wire: JsonValue = serde_json::from_str(&recorded.body).expect("wire body is JSON");

    assert!(
        !recorded.body.contains("content_parts"),
        "wire must not contain the custom content_parts field: {}",
        recorded.body
    );
    assert_eq!(wire["messages"][0]["role"], json!("user"));
    assert_eq!(wire["messages"][0]["content"][0]["type"], json!("text"));
    assert_eq!(wire["messages"][0]["content"][0]["text"], json!("hello"));
    assert_eq!(wire["messages"][1]["role"], json!("tool"));
    assert_eq!(wire["messages"][1]["tool_call_id"], json!("call_ab12"));
    assert_eq!(wire["messages"][1]["content"], json!("ok"));
    assert_eq!(wire["messages"][2]["role"], json!("assistant"));
    assert_eq!(
        wire["messages"][2]["content"],
        json!("Let me read the file.")
    );
    assert_eq!(
        wire["messages"][2]["tool_calls"][0]["function"]["arguments"],
        json!("{\"path\":\"README.md\"}")
    );
    assert_eq!(
        wire["tools"][0]["function"]["parameters"]["required"][0],
        json!("path")
    );
    // Empty `tool_choice` is OMITTED from the wire body entirely (the struct
    // encoder drops null optional fields; OpenAI treats an absent tool_choice
    // as the default `auto`). The old `wire["tool_choice"] == null` assertion
    // passed vacuously because serde_json indexes a missing key as Null —
    // asserting absence on the parsed map plus a literal body check keeps that
    // masking from hiding a regression that would emit `"tool_choice":null` or
    // an empty string instead.
    assert!(
        !wire
            .as_object()
            .expect("wire body is a JSON object")
            .contains_key("tool_choice"),
        "empty tool_choice must be omitted from the wire body: {wire}"
    );
    assert!(
        !recorded.body.contains("tool_choice"),
        "wire body must not mention tool_choice at all: {}",
        recorded.body
    );
}

/// Marker-splice collision guard (P3, user text): the wire splices user
/// content parts and tool schemas through literal markers
/// (`__RSS_USER_PARTS_<i>__`, `__RSS_TOOL_SCHEMA_<i>__`), and
/// `string_replace_literal` replaces every occurrence. A collision requires
/// user text to be EXACTLY the full quoted marker string — marker-like
/// fragments in ordinary or adversarial text (prefixes, embedded occurrences,
/// suffixed forms) must pass through byte-identical. A collision-free
/// structured build is blocked by the core (json::encode accepts only
/// struct-shaped values, so the splice mechanism is forced; see the plan's
/// P3 marker note).
#[test]
fn openai_chat_wire_preserves_marker_like_user_text() {
    let body = read_fixture("openai_chat/error.json");
    let (port, requests, fixture) = spawn_json_fixture(400, body);
    let runner = harness_runner(port);
    let mut request = canonical_request(port, false);
    request["messages"] = json!([
        {
            "role": "user",
            "content": [{"type": "text", "text": "__RSS_USER_PARTS_"}]
        },
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "prefix __RSS_TOOL_SCHEMA__ suffix"}
            ]
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "__RSS_USER_PARTS_0__ but not alone"
                },
                {
                    "type": "text",
                    "text": "__RSS_USER_PARTS_1__"
                }
            ]
        }
    ]);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");
    assert!(result["ok"] == json!(false), "{result}");

    let recorded = requests.recv().expect("recorded request");
    let wire: JsonValue = serde_json::from_str(&recorded.body).expect("wire body is JSON");
    let messages = wire["messages"].as_array().expect("messages array");
    let texts = messages
        .iter()
        .filter(|message| message["role"] == json!("user"))
        .flat_map(|message| {
            message["content"]
                .as_array()
                .expect("user content parts array")
                .iter()
                .map(|part| part["text"].as_str().expect("text part").to_string())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        texts,
        vec![
            "__RSS_USER_PARTS_",
            "prefix __RSS_TOOL_SCHEMA__ suffix",
            "__RSS_USER_PARTS_0__ but not alone",
            "__RSS_USER_PARTS_1__",
        ],
        "marker-like user text must survive the splice byte-identical: {wire}"
    );
}

/// Marker-splice collision guard (P3, tool schemas): a tool schema whose JSON
/// text embeds the marker strings inside longer values (the only shapes
/// ordinary or adversarial schemas can carry without being exactly the
/// quoted marker) must be spliced in byte-identical across multi-tool passes.
#[test]
fn openai_chat_wire_preserves_marker_like_tool_schema() {
    let body = read_fixture("openai_chat/error.json");
    let (port, requests, fixture) = spawn_json_fixture(400, body);
    let runner = harness_runner(port);
    let mut request = canonical_request(port, false);
    request["tools"] = json!([
        {
            "name": "read_file",
            "description": "schema __RSS_TOOL_SCHEMA_0__ here",
            "schema_json": "{\"type\":\"object\",\"description\":\"marker __RSS_TOOL_SCHEMA_1__ inside\",\"properties\":{\"path\":{\"type\":\"string\"}}}"
        },
        {
            "name": "search_files",
            "description": "parts __RSS_USER_PARTS_0__ mention",
            "schema_json": "{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\"}}}"
        }
    ]);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");
    assert!(result["ok"] == json!(false), "{result}");

    let recorded = requests.recv().expect("recorded request");
    let wire: JsonValue = serde_json::from_str(&recorded.body).expect("wire body is JSON");
    let tools = wire["tools"].as_array().expect("tools array");
    assert_eq!(
        tools[0]["function"]["parameters"],
        json!({"type":"object","description":"marker __RSS_TOOL_SCHEMA_1__ inside","properties":{"path":{"type":"string"}}}),
        "tool schema must be spliced in byte-identical: {wire}"
    );
    assert_eq!(
        tools[1]["function"]["parameters"],
        json!({"type":"object","properties":{"pattern":{"type":"string"}}}),
        "second tool schema must survive the multi-pass splice: {wire}"
    );
    assert_eq!(
        tools[0]["function"]["description"],
        json!("schema __RSS_TOOL_SCHEMA_0__ here")
    );
    assert_eq!(
        tools[1]["function"]["description"],
        json!("parts __RSS_USER_PARTS_0__ mention")
    );
}

#[test]
fn openai_chat_malformed_payload_is_typed() {
    let body = read_fixture("openai_chat/malformed.json");
    let (port, _requests, fixture) = spawn_json_fixture(200, body);
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(false), "{result}");
    let error = error_of(&result);
    assert_eq!(error["code"], json!("malformed_payload"));
    assert_eq!(error["status"], json!(200));
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("choices[0].message"),
        "{error:?}"
    );
}

#[test]
fn openai_chat_invalid_json_fails_as_typed_invocation_error() {
    let (port, _requests, fixture) = spawn_json_fixture(200, "{not json".to_string());
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let context = Value::map(vec![
        (Value::string("kind"), Value::string("openai_chat")),
        (Value::string("request"), json_to_vm_value(&request)),
        (
            Value::string("profile"),
            json_to_vm_value(&profile("openai", port)),
        ),
    ]);
    let error = runner
        .run_with_context(context)
        .expect_err("invalid JSON must fail the invocation, not fabricate a response");
    fixture.join().expect("fixture thread");

    assert!(
        matches!(
            error,
            RunError::Invocation(rustscript_vm::InvocationError::Host { .. })
        ),
        "expected a typed host failure, got {error:?}"
    );
    assert!(error.to_string().contains("json_decode failed"), "{error}");
}

// ---------------------------------------------------------------------------
// S2: OpenAI Chat Completions, streaming (http::client::sse)
// ---------------------------------------------------------------------------
//
// The streaming adapter (`openai_chat_stream`) is implemented against core
// revision fd4b570 (B1 callable schemas + B3 shared BorrowMut capture
// cells + the §11a parameter-liveness fix): the SSE callback aggregates
// text/usage/tool-call deltas into captured accumulator locals read after
// the stream completes, and `http::client::sse` is exposed in the
// restricted registry. The suites below run by default and pass at the
// pinned revision.

#[test]
fn openai_chat_stream_text_and_usage() {
    let events = sse_events(&read_fixture("openai_chat/stream.sse"));
    let (port, requests, fixture) = spawn_sse_fixture(events, false);
    let runner = harness_runner(port);
    let request = canonical_request(port, true);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(response["text"], json!("The RustScript agent owns policy."));
    assert_eq!(response["stop_reason"], json!("stop"));
    assert_eq!(response["usage"]["input_tokens"], json!(12));
    assert_eq!(response["usage"]["output_tokens"], json!(15));
    assert_eq!(response["usage"]["total_tokens"], json!(27));
    assert_eq!(response["tool_calls"], json!([]));

    let recorded = requests.recv().expect("recorded request");
    assert_eq!(request_line(&recorded), "POST /chat/completions HTTP/1.1");
    assert_eq!(
        header(&recorded, "authorization").as_deref(),
        Some("Bearer test-key")
    );
    let wire: JsonValue = serde_json::from_str(&recorded.body).expect("wire body is JSON");
    assert_eq!(wire["stream"], json!(true));
    assert_eq!(wire["stream_options"]["include_usage"], json!(true));
}

#[test]
fn openai_chat_stream_tool_call_chunk_aggregation() {
    let events = sse_events(&read_fixture("openai_chat/stream_tools.sse"));
    let (port, requests, fixture) = spawn_sse_fixture(events, false);
    let runner = harness_runner(port);
    let request = canonical_request(port, true);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(response["text"], json!(""));
    assert_eq!(response["stop_reason"], json!("tool_calls"));
    let calls = response["tool_calls"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["id"], json!("call_ab12"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(calls[0]["arguments"], json!({"path": "README.md"}));
    assert_eq!(calls[1]["id"], json!("call_cd34"));
    assert_eq!(calls[1]["name"], json!("search_files"));
    assert_eq!(calls[1]["arguments"], json!({"pattern": "provider"}));
    assert_eq!(response["usage"]["total_tokens"], json!(30));

    let recorded = requests.recv().expect("recorded request");
    let wire: JsonValue = serde_json::from_str(&recorded.body).expect("wire body is JSON");
    assert_eq!(wire["stream"], json!(true));
}

#[test]
fn openai_chat_stream_cancellation_is_typed() {
    // The held-open fixture must not terminate the stream itself: drop the
    // terminal `data: [DONE]` event so only cancellation can end the run.
    let mut events = sse_events(&read_fixture("openai_chat/stream.sse"));
    assert_eq!(
        events.pop().as_deref(),
        Some("data: [DONE]\n\n"),
        "the stream transcript must end with the [DONE] event"
    );
    let (port, _requests, fixture) = spawn_sse_fixture(events, true);
    let runner = harness_runner(port);
    let request = canonical_request(port, true);
    let context = Value::map(vec![
        (Value::string("kind"), Value::string("openai_chat")),
        (Value::string("request"), json_to_vm_value(&request)),
        (
            Value::string("profile"),
            json_to_vm_value(&profile("openai", port)),
        ),
    ]);

    let cancellation = RunCancellation::new();
    let trigger = cancellation.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        trigger.request(rustscript_vm::CancellationReason::Requested);
    });
    let mut sink = RecordingSink::default();
    let error = runner
        .run_with_context_and_events(context, &mut sink, &cancellation)
        .expect_err("cancelling a held-open stream must terminate the run");
    canceller.join().expect("canceller thread");
    fixture.join().expect("fixture thread");

    assert!(
        matches!(
            error,
            RunError::Invocation(rustscript_vm::InvocationError::Cancelled { .. })
        ),
        "expected a typed cancellation, got {error:?}"
    );
}

/// A3 review P2 guard: the adapter must fail CLOSED when the server EOFs the
/// SSE body without the terminal `data: [DONE]` event. The transport reports
/// `outcome: "eof"` (the callback sees the `kind: "end"` item and returns
/// continue), and the adapter must not surface the accumulated partial text
/// as `ok`. The failure is the canonical typed provider error (stable
/// type/code/message), distinct from cancellation (which stays a typed
/// `Cancelled` invocation error) and from a legal `[DONE]` stream (which
/// stops the callback and reports `outcome: "stopped"`).
#[test]
fn openai_chat_stream_eof_without_done_fails_closed() {
    // One valid text delta, then immediate EOF: no `data: [DONE]`, no usage
    // event. `hold_open` false lets the fixture close the chunked body.
    let events = vec![
        "data: {\"id\":\"chatcmpl-eof1\",\"object\":\"chat.completion.chunk\",\"created\":1755000009,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"partial \"},\"finish_reason\":null}]}\n\n".to_string(),
    ];
    let (port, requests, fixture) = spawn_sse_fixture(events, false);
    let runner = harness_runner(port);
    let request = canonical_request(port, true);

    let (result, _) = run_adapter("openai_chat", request, profile("openai", port), &runner);
    fixture.join().expect("fixture thread");

    assert!(
        result["ok"] == json!(false),
        "EOF without [DONE] must fail closed, got {result}"
    );
    let error = error_of(&result);
    assert_eq!(error["type"], json!("api_error"));
    assert_eq!(error["code"], json!("stream_eof_without_done"));
    assert_eq!(error["status"], json!(200));
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("[DONE]"),
        "{error:?}"
    );

    let recorded = requests.recv().expect("recorded request");
    assert_eq!(request_line(&recorded), "POST /chat/completions HTTP/1.1");
    let wire: JsonValue = serde_json::from_str(&recorded.body).expect("wire body is JSON");
    assert_eq!(wire["stream"], json!(true));
}

// ---------------------------------------------------------------------------
// S3: OpenAI Responses adapter (blocked references)
// ---------------------------------------------------------------------------
//
// `openai_responses.rss` is a typed `not_implemented` stub. The buffered and
// streaming transcripts under `tests/fixtures/providers/openai_responses/`
// document the wire contract; these tests stay ignored until the adapter is
// implemented. The streaming transcript mirrors the real Responses API
// transport: every
// payload event carries an `event:` line whose value matches the `type`
// field of its `data:` JSON payload, and the stream ends with a bare
// `data: [DONE]`.

#[ignore = "openai_responses adapter is a not_implemented stub (see module doc)"]
#[test]
fn openai_responses_buffered_transcript_is_referenced() {
    let body = read_fixture("openai_responses/response.json");
    let (port, _requests, fixture) = spawn_json_fixture(200, body);
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let (result, _) = run_adapter(
        "openai_responses",
        request,
        profile("openai", port),
        &runner,
    );
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
}

#[ignore = "openai_responses adapter is a not_implemented stub (see module doc)"]
#[test]
fn openai_responses_stream_transcript_matches_real_transport_and_is_referenced() {
    let events = sse_events(&read_fixture("openai_responses/stream.sse"));

    // Real Responses API transport shape: each payload event is an
    // `event: <type>` / `data: {json}` pair with the event name matching the
    // payload's `type` field, and the stream ends with a bare `data: [DONE]`
    // terminator.
    let (done, payload_events) = events
        .split_last()
        .expect("stream fixture must have at least one event");
    for event in payload_events {
        let event_line = event
            .lines()
            .find(|line| line.starts_with("event: "))
            .unwrap_or_else(|| panic!("event must carry an event: line: {event}"));
        let data_line = event
            .lines()
            .find(|line| line.starts_with("data: "))
            .unwrap_or_else(|| panic!("event must carry a data: line: {event}"));
        let event_name = event_line.strip_prefix("event: ").expect("event name");
        let payload: JsonValue =
            serde_json::from_str(data_line.strip_prefix("data: ").expect("data payload"))
                .unwrap_or_else(|error| panic!("data payload must be JSON ({error}): {event}"));
        assert_eq!(
            payload["type"].as_str(),
            Some(event_name),
            "event: line must match the data.type field: {event}"
        );
    }
    assert!(
        done.starts_with("data:") && done.contains("[DONE]"),
        "stream must end with a bare data: [DONE] terminator, got: {done}"
    );

    let (port, _requests, fixture) = spawn_sse_fixture(events, false);
    let runner = harness_runner(port);
    let request = canonical_request(port, true);

    let (result, _) = run_adapter(
        "openai_responses",
        request,
        profile("openai", port),
        &runner,
    );
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
}

// ---------------------------------------------------------------------------
// S4: Anthropic Messages adapter (blocked references)
// ---------------------------------------------------------------------------
//
// `anthropic_messages.rss` is a typed `not_implemented` stub. The buffered and
// streaming transcripts under `tests/fixtures/providers/anthropic/` document
// the wire contract; these tests stay ignored until the adapter is
// implemented.

#[ignore = "anthropic_messages adapter is a not_implemented stub (see module doc)"]
#[test]
fn anthropic_messages_buffered_transcript_is_referenced() {
    let body = read_fixture("anthropic/response.json");
    let (port, _requests, fixture) = spawn_json_fixture(200, body);
    let runner = harness_runner(port);
    let request = canonical_request(port, false);

    let (result, _) = run_adapter(
        "anthropic_messages",
        request,
        profile("anthropic", port),
        &runner,
    );
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
}

#[ignore = "anthropic_messages adapter is a not_implemented stub (see module doc)"]
#[test]
fn anthropic_messages_stream_transcript_is_referenced() {
    let events = sse_events(&read_fixture("anthropic/stream.sse"));
    let (port, _requests, fixture) = spawn_sse_fixture(events, false);
    let runner = harness_runner(port);
    let request = canonical_request(port, true);

    let (result, _) = run_adapter(
        "anthropic_messages",
        request,
        profile("anthropic", port),
        &runner,
    );
    fixture.join().expect("fixture thread");

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
}
