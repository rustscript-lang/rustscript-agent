//! Compiler + restricted-VM execution of the pure RSS OpenAI Chat stream codec.
//!
//! Runs the committed production body builder and codec state machine through
//! the real restricted registry and asserts canonical wire/canonical business
//! results. The records are public, resource-free maps.

use std::path::PathBuf;
use std::sync::Arc;

use rustscript_agent::auth::host::auth_host_catalog;
use rustscript_vm::{
    compile_source_at_path_with_flavor_and_options, register_http_builtin_module_from_catalog,
    CapabilityProfile, CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm,
    VmStatus,
};
use serde_json::{json, Value as JsonValue};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/providers/opaque_stream_codec.rss")
}

fn codec_vm() -> Vm {
    let path = fixture_path();
    let source = std::fs::read_to_string(&path).expect("read committed codec fixture");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile production codec fixture against the restricted catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    // Mirrors build_restricted_registry_with_builtins: start empty (installing
    // the standard modules on top of restricted() would conflict on identity),
    // install the frozen HTTP module from the exact catalog, then admit only
    // the explicit builtin list. openai_chat.rss carries transitive http/bytes
    // declarations, so their imports must be admitted without invoking HTTP.
    let mut registry = HostFunctionRegistry::empty();
    registry.set_capability_profile(CapabilityProfile::deny_all());
    register_http_builtin_module_from_catalog(&mut registry, catalog.as_ref())
        .expect("install frozen http module from the restricted catalog");
    for name in [
        "json::encode",
        "json::decode",
        "bytes::to_utf8",
        "bytes::to_utf8_lossy",
        "bytes::to_array_u8",
        "bytes::from_utf8",
        "http::request::new",
        "http::request::set_header",
        "http::request::set_body_text",
        "http::request::set_body_bytes",
        "http::client::request",
        "http::client::sse",
        "http::response::status",
        "http::response::url",
        "http::response::header_values",
        "http::response::header_names",
        "http::response::body",
        "http::headers::values",
        "http::headers::names",
        "http::sse_summary::outcome",
        "http::sse_summary::status",
        "http::sse_summary::headers",
        "http::sse_summary::url",
        "http::sse_summary::items",
        "http::sse_summary::bytes_received",
        "http::sse_summary::bytes_sent",
    ] {
        // Same admission shape as build_restricted_registry_with_builtins:
        // authorize names already installed from the catalog, else admit the
        // namespaced builtin. openai_chat.rss carries transitive http/bytes
        // declarations, so those imports must be admitted without the test
        // ever invoking HTTP.
        if registry.contains_name(name) {
            registry.authorize_registered_builtin_import(name);
        } else {
            registry
                .allow_builtin(name)
                .expect("admit standard builtin");
        }
    }
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(
        vm.run().expect("RSS declarations"),
        VmStatus::Halted
    ));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args).expect("RSS invoke")
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
    let mut vm = codec_vm();
    let request = json!({
        "model": "gpt-test",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
        "sampling": {"temperature": 0.5}
    });
    let body = invoke(&mut vm, "request_body", &[json_to_value(&request)]);
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
    let mut vm = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hel"}}]},
        {"choices": [{"index": 0, "delta": {"content": "lo "}}]},
        {"choices": [{"index": 0, "delta": {"content": "world"}, "finish_reason": "stop"}]},
        {"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}}
    ]);
    let result = invoke(
        &mut vm,
        "collect",
        &[json_to_value(&chunks), Value::Bool(true)],
    );
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

fn collect(vm: &mut Vm, chunks: &JsonValue, done: bool) -> JsonValue {
    let result = invoke(vm, "collect", &[json_to_value(chunks), Value::Bool(done)]);
    value_to_json(&result)
}

#[test]
fn stream_body_preserves_user_text_and_splices_tool_schemas() {
    let mut vm = codec_vm();
    // The user text deliberately looks like an internal splice marker; it must
    // survive verbatim while the real marker slot is replaced by the parts
    // array. The tool schema is spliced raw into `parameters`.
    let request = json!({
        "model": "gpt-test",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "__RSS_TOOL_SCHEMA_0__ and more"}]}],
        "tools": [{"name": "read_file", "description": "reads", "schema_json": "{\"type\":\"object\"}"}],
        "tool_choice": "auto"
    });
    let body = invoke(&mut vm, "request_body", &[json_to_value(&request)]);
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
    let mut vm = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"role": "assistant"}}]},
        {"choices": []}
    ]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["response"]["text"], json!(""));
    assert_eq!(result["response"]["stop_reason"], json!(""));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(0));
}

#[test]
fn usage_on_choices_bearing_chunk_is_processed() {
    let mut vm = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"content": "x"}}],
         "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}}
    ]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["response"]["text"], json!("x"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(5));
    assert_eq!(result["response"]["usage"]["output_tokens"], json!(2));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));
}

#[test]
fn split_tool_arguments_merge_across_two_indices() {
    let mut vm = codec_vm();
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
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    let calls = &result["response"]["tool_calls"];
    assert_eq!(calls.as_array().map(Vec::len), Some(2), "result: {result}");
    assert_eq!(calls[0]["id"], json!("call_a"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(calls[0]["arguments"], json!({"path": "a"}));
    assert_eq!(calls[1]["id"], json!("call_b"));
    assert_eq!(calls[1]["name"], json!("search"));
    assert_eq!(calls[1]["arguments"], json!({"q": 1}));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));
}

#[test]
fn eof_without_done_fails_and_never_returns_partial_text() {
    let mut vm = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"content": "partial"}}]}
    ]);
    let result = collect(&mut vm, &chunks, false);
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
    let mut vm = codec_vm();
    // A choice without a delta map is a semantic protocol violation.
    let chunks = json!([{"choices": [{"index": 0, "finish_reason": "stop"}]}]);
    // Even a subsequent DONE must not repair the failed state.
    let result = collect(&mut vm, &chunks, true);
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
    let mut vm = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": -5, "id": "call_x", "function": {"name": "n", "arguments": "{}"}}
        ]}}]}
    ]);
    let result = collect(&mut vm, &chunks, true);
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
    let mut vm = codec_vm();
    let chunks = json!([
        {"choices": [{"index": 0, "delta": {"content": "ok"}}]}
    ]);
    let late = json!({
        "choices": [{"index": 0, "delta": {"content": "LATE"}}],
        "usage": {"total_tokens": 99}
    });
    let result = invoke(
        &mut vm,
        "late_record",
        &[json_to_value(&chunks), json_to_value(&late)],
    );
    let result = value_to_json(&result);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(
        result["response"]["text"],
        json!("ok"),
        "late text ignored: {result}"
    );
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(0));
}
