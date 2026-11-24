//! Compiler + restricted-VM execution of the pure RSS OpenAI Chat stream codec.
//!
//! Runs the committed production body builder and codec state machine through
//! the real restricted registry and asserts canonical wire/canonical business
//! results. The records are public, resource-free maps.

use std::path::PathBuf;
use std::sync::Arc;

use rustscript_agent::runtime::{
    AgentConfig, AgentRunner, RunCancellation, RunDeliveryError, RunEventSink,
};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

struct CodecSources(PathBuf);

impl Drop for CodecSources {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn codec_vm() -> (AgentRunner, CodecSources) {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sources =
        CodecSources(std::env::temp_dir().join(format!("chat-codec-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir_all(sources.0.join("llm")).expect("create codec module root");
    let entry = sources.0.join("codec.rss");
    std::fs::copy(
        repo.join("tests/fixtures/providers/opaque_stream_codec.rss"),
        &entry,
    )
    .expect("copy codec entry");
    for name in ["openai_chat.rss", "openai_stream_codec.rss", "types.rss"] {
        let module = PathBuf::from("llm").join(name);
        std::fs::copy(repo.join("rss").join(&module), sources.0.join(&module))
            .expect("copy current production codec module");
    }
    let runner = AgentRunner::from_file(entry, AgentConfig::default())
        .expect("compile production codec fixture against the restricted catalog");
    (runner, sources)
}

struct NoEvents;

impl RunEventSink for NoEvents {
    fn deliver(&mut self, value: Value) -> Result<(), RunDeliveryError> {
        panic!("pure codec unexpectedly emitted an event: {value:?}");
    }
}

fn invoke(runner: &AgentRunner, name: &str, input: &JsonValue) -> Value {
    runner
        .run_named_with_context_and_events(
            name,
            json_to_value(input),
            &mut NoEvents,
            &RunCancellation::new(),
        )
        .expect("RSS invoke")
}

fn json_to_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite JSON number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => {
            Value::Array(Arc::new(values.iter().map(json_to_value).collect()))
        }
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_value(value)))
                .collect(),
        ),
    }
}

fn value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(values.iter().map(value_to_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    let key = match key {
                        Value::String(key) => key.to_string(),
                        other => value_to_json(other).to_string(),
                    };
                    (key, value_to_json(value))
                })
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

#[test]
fn stream_body_marks_stream_and_include_usage() {
    let (vm, _sources) = codec_vm();
    let request = json!({
        "model": "gpt-test",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
        "sampling": {"temperature": 0.5}
    });
    let body = invoke(&vm, "request_body", &request);
    let Value::String(body) = body else {
        panic!("request_body must return a string");
    };
    let decoded: JsonValue = serde_json::from_str(&body).expect("decode stream body");
    assert_eq!(decoded["stream"], json!(true), "body: {body}");
    assert_eq!(
        decoded["stream_options"]["include_usage"],
        json!(true),
        "body: {body}"
    );
    assert_eq!(decoded["model"], json!("gpt-test"));
    assert_eq!(decoded["messages"][0]["role"], json!("user"));
    assert_eq!(decoded["messages"][0]["content"][0]["text"], json!("hello"));
    assert_eq!(decoded["temperature"], json!(0.5));
    assert!(
        decoded["tools"].is_null(),
        "no tools when none supplied: {body}"
    );
}

#[test]
fn split_text_usage_and_done_produce_canonical_response() {
    let (vm, _sources) = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hel"}}]},
        {"choices": [{"index": 0, "delta": {"content": "lo "}}]},
        {"choices": [{"index": 0, "delta": {"content": "world"}, "finish_reason": "stop"}]},
        {"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}}
    ]);
    let result = invoke(&vm, "collect", &json!({"chunks": chunks, "done": true}));
    let result = value_to_json(&result);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    let response = &result["response"];
    assert_eq!(response["text"], json!("Hello world"), "result: {result}");
    assert_eq!(response["stop_reason"], json!("stop"));
    assert_eq!(response["usage"]["input_tokens"], json!(7));
    assert_eq!(response["usage"]["output_tokens"], json!(3));
    assert_eq!(response["usage"]["total_tokens"], json!(10));
    assert_eq!(response["tool_calls"], json!([]));
}

fn tool_arguments(call: &JsonValue) -> JsonValue {
    serde_json::from_str(
        call["arguments_json"]
            .as_str()
            .expect("typed argument text"),
    )
    .expect("valid tool arguments")
}

fn collect(vm: &AgentRunner, chunks: &JsonValue, done: bool) -> JsonValue {
    let result = invoke(vm, "collect", &json!({"chunks": chunks, "done": done}));
    value_to_json(&result)
}

#[test]
fn stream_body_preserves_user_text_and_splices_tool_schemas() {
    let (vm, _sources) = codec_vm();
    // The user text deliberately looks like an internal splice marker; it must
    // survive verbatim while the real marker slot is replaced by the parts
    // array. The tool schema is spliced raw into `parameters`.
    let request = json!({
        "model": "gpt-test",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "__RSS_TOOL_SCHEMA_0__ and more"}]}],
        "tools": [{"name": "read_file", "description": "reads", "schema_json": "{\"type\":\"object\"}"}],
        "tool_choice": "auto"
    });
    let body = invoke(&vm, "request_body", &request);
    let Value::String(body) = body else {
        panic!("request_body must return a string");
    };
    let decoded: JsonValue = serde_json::from_str(&body).expect("decode stream body");
    assert_eq!(decoded["messages"][0]["content"][0]["type"], json!("text"));
    assert_eq!(
        decoded["messages"][0]["content"][0]["text"],
        json!("__RSS_TOOL_SCHEMA_0__ and more"),
        "user text is preserved verbatim: {body}"
    );
    assert_eq!(decoded["tools"][0]["type"], json!("function"));
    assert_eq!(decoded["tools"][0]["function"]["name"], json!("read_file"));
    assert_eq!(
        decoded["tools"][0]["function"]["parameters"],
        json!({"type": "object"}),
        "schema_json is spliced raw: {body}"
    );
    assert_eq!(decoded["tool_choice"], json!("auto"));
    assert_eq!(decoded["stream"], json!(true));
}

#[test]
fn role_only_and_empty_heartbeat_have_no_text() {
    let (vm, _sources) = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"role": "assistant"}}]},
        {"choices": []}
    ]);
    let result = collect(&vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["response"]["text"], json!(""));
    assert_eq!(result["response"]["stop_reason"], json!(""));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(0));
}

#[test]
fn usage_on_choices_bearing_chunk_is_processed() {
    let (vm, _sources) = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"content": "x"}}],
         "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}}
    ]);
    let result = collect(&vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["response"]["text"], json!("x"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(5));
    assert_eq!(result["response"]["usage"]["output_tokens"], json!(2));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));
}

#[test]
fn split_tool_arguments_merge_across_two_indices() {
    let (vm, _sources) = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "call_a", "type": "function", "function": {"name": "read_file", "arguments": "{\"pa"}}
        ]}}]},
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": "th\":\"a\"}"}}
        ]}}]},
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 1, "id": "call_b", "function": {"name": "search", "arguments": "{\"q\":1}"}}
        ]}, "finish_reason": "tool_calls"}]}
    ]);
    let result = collect(&vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    let calls = &result["response"]["tool_calls"];
    assert_eq!(calls.as_array().map(Vec::len), Some(2), "result: {result}");
    assert_eq!(calls[0]["id"], json!("call_a"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(tool_arguments(&calls[0]), json!({"path": "a"}));
    assert_eq!(calls[1]["id"], json!("call_b"));
    assert_eq!(calls[1]["name"], json!("search"));
    assert_eq!(tool_arguments(&calls[1]), json!({"q": 1}));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));
}

#[test]
fn eof_without_done_fails_and_never_returns_partial_text() {
    let (vm, _sources) = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"content": "partial"}}]}
    ]);
    let result = collect(&vm, &chunks, false);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(result["error"]["code"], json!("stream_eof_without_done"));
    assert_eq!(
        result["response"],
        json!({}),
        "no partial success: {result}"
    );
}

#[test]
fn malformed_delta_fails_statically_and_done_does_not_repair() {
    let (vm, _sources) = codec_vm();
    // A choice without a delta map is a semantic protocol violation.
    let chunks = json!([{"choices": [{"index": 0, "finish_reason": "stop"}]}]);
    // Even a subsequent DONE must not repair the failed state.
    let result = collect(&vm, &chunks, true);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(result["error"]["code"], json!("malformed_payload"));
    assert_eq!(result["error"]["type"], json!("malformed_payload"));
    let message = result["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("stop"),
        "static message must not echo input: {message}"
    );
}

#[test]
fn negative_tool_index_is_malformed() {
    let (vm, _sources) = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": -5, "id": "call_x", "function": {"name": "n", "arguments": "{}"}}
        ]}}]}
    ]);
    let result = collect(&vm, &chunks, true);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(result["error"]["code"], json!("malformed_payload"));
    let message = result["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("-5"),
        "static message must not echo input: {message}"
    );
}

#[test]
fn records_after_done_are_ignored() {
    let (vm, _sources) = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"content": "ok"}}]}
    ]);
    let late = json!({
        "choices": [{"index": 0, "delta": {"content": "LATE"}}],
        "usage": {"total_tokens": 99}
    });
    let result = invoke(&vm, "late_record", &json!({"chunks": chunks, "late": late}));
    let result = value_to_json(&result);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(
        result["response"]["text"],
        json!("ok"),
        "late text ignored: {result}"
    );
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(0));
}

/// The streaming body builder shares `chat_tool_result_output`. A durable
/// background block with empty text must still put the public handle on the
/// wire tool message.
#[test]
fn stream_body_encodes_durable_background_handle_in_tool_content() {
    const HANDLE: &str = "fedcba9876543210fedcba9876543210";
    let (vm, _sources) = codec_vm();
    let request = json!({
        "model": "gpt-test",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "start a background process"}]},
            {"role": "assistant", "content": [
                {"type": "tool_call", "tool_call_id": "call-bg", "name": "terminal",
                 "arguments_json": "{\"argv\":[\"/bin/echo\",\"fixture\"],\"background\":true}"}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_call_id": "call-bg", "content": "",
                 "is_error": false, "result": {
                     "process_id": HANDLE, "background": true, "status": "running"
                 }}
            ]}
        ]
    });
    let body = invoke(&vm, "request_body", &request);
    let Value::String(body) = body else {
        panic!("request_body must return a string");
    };
    let decoded: JsonValue = serde_json::from_str(&body).expect("decode stream body");
    assert_eq!(
        decoded["stream"],
        json!(true),
        "stream builder must mark stream"
    );
    let messages = decoded["messages"].as_array().expect("wire messages");
    let tool = messages
        .iter()
        .find(|message| message["role"] == "tool" && message["tool_call_id"] == "call-bg")
        .expect("stream tool message");
    let content = tool["content"].as_str().unwrap_or("");
    assert!(
        !content.is_empty(),
        "empty stream tool content dropped durable background handle {HANDLE}"
    );
    let parsed: JsonValue = serde_json::from_str(content).expect("tool content must be JSON");
    assert_eq!(parsed["content"], json!(""));
    assert_eq!(parsed["result"]["process_id"], json!(HANDLE));
    assert_eq!(parsed["result"]["background"], json!(true));
    assert_eq!(parsed["result"]["status"], json!("running"));
    assert_eq!(parsed["truncated"], json!(false));
    assert_eq!(tool["tool_call_id"], json!("call-bg"));
}
