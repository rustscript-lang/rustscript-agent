//! Compiler + restricted-VM execution of the pure RSS OpenAI Responses codec.
//!
//! Runs the committed production codec state machine and body builder through
//! the real restricted registry and asserts canonical wire/canonical business
//! results. The records are public, resource-free maps.

use std::path::PathBuf;
use std::sync::Arc;

use rustscript_agent::auth::host::auth_host_catalog;
use rustscript_vm::{
    CapabilityProfile, CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm,
    VmStatus, compile_source_at_path_with_flavor_and_options,
    register_http_builtin_module_from_catalog,
};
use serde_json::{Value as JsonValue, json};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/providers/responses_codec.rss")
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
    ] {
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

fn collect(vm: &mut Vm, chunks: &JsonValue, done: bool) -> JsonValue {
    let result = invoke(vm, "collect", &[json_to_value(chunks), Value::Bool(done)]);
    value_to_json(&result)
}

#[test]
fn request_body_carries_instructions_and_stream_store_flags() {
    let mut vm = codec_vm();
    let request = json!({
        "model": "gpt-6.1-sol",
        "messages": [
            {"role": "system", "content": [{"type": "text", "text": "be brief"}]},
            {"role": "user", "content": [{"type": "text", "text": "hello"}]}
        ],
        "sampling": {"temperature": 0.5},
        "max_output_tokens": 128
    });
    let body = invoke(&mut vm, "request_body", &[json_to_value(&request)]);
    let Value::String(body) = body else {
        panic!("request_body must return a string");
    };
    let decoded: JsonValue = serde_json::from_str(&body).expect("decode responses body");
    assert_eq!(decoded["model"], json!("gpt-6.1-sol"), "body: {body}");
    assert_eq!(decoded["instructions"], json!("be brief"), "body: {body}");
    assert_eq!(decoded["stream"], json!(false), "body: {body}");
    assert_eq!(decoded["store"], json!(false), "body: {body}");
    assert_eq!(decoded["input"][0]["type"], json!("message"));
    assert_eq!(decoded["input"][0]["role"], json!("user"));
    assert_eq!(
        decoded["input"][0]["content"][0]["type"],
        json!("input_text")
    );
    assert_eq!(decoded["input"][0]["content"][0]["text"], json!("hello"));
    assert_eq!(decoded["temperature"], json!(0.5));
    assert_eq!(decoded["max_output_tokens"], json!(128));
    assert!(
        decoded.get("tools").is_none(),
        "no tools key when none supplied: {body}"
    );
}

#[test]
fn continuation_input_maps_tool_result_and_function_call() {
    let mut vm = codec_vm();
    let request = json!({
        "model": "gpt-6.1-sol",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "read it"}]},
            {"role": "assistant", "content": [
                {"type": "text", "text": "ok"},
                {"type": "tool_call", "tool_call_id": "call_1", "name": "read_file", "arguments_json": "{\"path\":\"a\"}"}
            ]},
            {"role": "user", "content": [{"type": "tool_result", "tool_call_id": "call_1", "content": "file body", "is_error": false}]}
        ]
    });
    let body = invoke(&mut vm, "request_body", &[json_to_value(&request)]);
    let Value::String(body) = body else {
        panic!("request_body must return a string");
    };
    let decoded: JsonValue = serde_json::from_str(&body).expect("decode responses body");
    let input = decoded["input"].as_array().expect("input array");
    assert_eq!(input.len(), 4, "body: {body}");
    assert_eq!(input[0]["type"], json!("message"));
    assert_eq!(input[0]["role"], json!("user"));
    assert_eq!(input[1]["type"], json!("message"));
    assert_eq!(input[1]["role"], json!("assistant"));
    assert_eq!(input[1]["content"][0]["type"], json!("output_text"));
    assert_eq!(input[2]["type"], json!("function_call"));
    assert_eq!(input[2]["call_id"], json!("call_1"));
    assert_eq!(input[2]["name"], json!("read_file"));
    assert_eq!(input[2]["arguments"], json!("{\"path\":\"a\"}"));
    assert_eq!(input[3]["type"], json!("function_call_output"));
    assert_eq!(input[3]["call_id"], json!("call_1"));
    assert_eq!(input[3]["output"], json!("file body"));
}

#[test]
fn tool_schemas_are_emitted_as_flat_function_tools() {
    let mut vm = codec_vm();
    let request = json!({
        "model": "gpt-6.1-sol",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        "tools": [{"name": "read_file", "description": "reads", "schema_json": "{\"type\":\"object\"}"}],
        "tool_choice": "auto"
    });
    let body = invoke(&mut vm, "request_body", &[json_to_value(&request)]);
    let Value::String(body) = body else {
        panic!("request_body must return a string");
    };
    let decoded: JsonValue = serde_json::from_str(&body).expect("decode responses body");
    assert_eq!(
        decoded["tools"][0]["type"],
        json!("function"),
        "body: {body}"
    );
    assert_eq!(decoded["tools"][0]["name"], json!("read_file"));
    assert_eq!(
        decoded["tools"][0]["parameters"],
        json!({"type": "object"}),
        "schema_json spliced: {body}"
    );
    assert_eq!(decoded["tool_choice"], json!("auto"));
}

#[test]
fn production_descriptor_schema_maps_as_wire_object() {
    let mut vm = codec_vm();
    let request = json!({
        "model": "gpt-6.1-sol",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        "tools": [{
            "name": "manual_access_noop",
            "description": "non-executable sentinel",
            "schema": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": false
            }
        }]
    });
    let body = invoke(&mut vm, "request_body", &[json_to_value(&request)]);
    let Value::String(body) = body else {
        panic!("request_body must return a string");
    };
    let decoded: JsonValue = serde_json::from_str(&body).expect("decode Responses body");
    assert_eq!(decoded["tools"][0]["parameters"]["type"], "object");
    assert_eq!(decoded["tools"][0]["parameters"]["required"], json!([]));
    assert_eq!(
        decoded["tools"][0]["parameters"]["additionalProperties"],
        false
    );
}

#[test]
fn completed_event_yields_canonical_text_and_usage() {
    let mut vm = codec_vm();
    let chunks = json!([
        {"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}},
        {"type": "response.output_text.delta", "output_index": 0, "delta": "Hel"},
        {"type": "response.output_text.delta", "output_index": 0, "delta": "lo"},
        {"type": "response.completed", "response": {
            "id": "resp_1", "object": "response", "status": "completed", "model": "gpt-6.1-sol",
            "output": [{"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                        "content": [{"type": "output_text", "text": "Hello world"}]}],
            "usage": {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}
        }}
    ]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    let response = &result["response"];
    assert_eq!(response["text"], json!("Hello world"), "result: {result}");
    assert_eq!(response["stop_reason"], json!("stop"));
    assert_eq!(response["usage"]["input_tokens"], json!(7));
    assert_eq!(response["usage"]["output_tokens"], json!(3));
    assert_eq!(response["usage"]["total_tokens"], json!(10));
    assert_eq!(response["tool_calls"], json!([]));
}

#[test]
fn completed_empty_assistant_output_fails_closed() {
    let mut vm = codec_vm();
    let chunks = json!([{
        "type": "response.completed",
        "response": {
            "status": "completed",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": ""}]
            }]
        }
    }]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(
        result["ok"],
        json!(false),
        "empty completion must fail closed"
    );
    assert_eq!(result["error"]["code"], json!("empty_responses_output"));
    assert_eq!(result["response"], json!({}));
}

#[test]
fn accumulated_deltas_without_response_object_use_zero_usage() {
    let mut vm = codec_vm();
    let chunks = json!([
        {"type": "response.output_text.delta", "output_index": 0, "delta": "partial"}
    ]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["response"]["text"], json!("partial"));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(0));
}

#[test]
fn function_call_item_is_mapped_to_canonical_tool_call() {
    let mut vm = codec_vm();
    let chunks = json!([
        {"type": "response.function_call_arguments.delta", "output_index": 1, "delta": "{\"path\":"},
        {"type": "response.function_call_arguments.delta", "output_index": 1, "delta": "\"README.md\"}"},
        {"type": "response.output_item.done", "output_index": 1, "item": {
            "type": "function_call", "id": "fc_1", "call_id": "call_xy", "name": "read_file",
            "arguments": "{\"path\": \"README.md\"}", "status": "completed"}},
        {"type": "response.completed", "response": {
            "id": "resp_2", "status": "completed",
            "output": [{"type": "function_call", "id": "fc_1", "call_id": "call_xy", "name": "read_file",
                        "arguments": "{\"path\": \"README.md\"}"}],
            "usage": {"input_tokens": 3, "output_tokens": 4, "total_tokens": 7}
        }}
    ]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    let calls = &result["response"]["tool_calls"];
    assert_eq!(calls.as_array().map(Vec::len), Some(1), "result: {result}");
    assert_eq!(calls[0]["id"], json!("call_xy"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(calls[0]["arguments"], json!({"path": "README.md"}));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));
}

#[test]
fn accumulated_arguments_without_final_done_event_report_canonical_call() {
    // A stream that carries a completed function_call item and terminates via
    // the bare `[DONE]` marker (no `response.completed` object) still reports
    // the accumulated call from the item.
    let mut vm = codec_vm();
    let chunks = json!([
        {"type": "response.output_item.done", "output_index": 0, "item": {
            "type": "function_call", "id": "fc_9", "call_id": "call_9", "name": "search",
            "arguments": "{\"q\":1}"}}
    ]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    let calls = &result["response"]["tool_calls"];
    assert_eq!(calls.as_array().map(Vec::len), Some(1), "result: {result}");
    assert_eq!(calls[0]["id"], json!("call_9"));
    assert_eq!(calls[0]["arguments"], json!({"q": 1}));
}

#[test]
fn response_failed_event_is_terminal_and_static() {
    let mut vm = codec_vm();
    let chunks = json!([
        {"type": "response.output_text.delta", "output_index": 0, "delta": "x"},
        {"type": "response.failed", "response": {"id": "resp_4", "status": "failed",
            "error": {"code": "server_error", "message": "SECRET_INPUT"}}}
    ]);
    // Even a later DONE must not repair the failed state.
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(result["error"]["code"], json!("responses_failed"));
    assert_eq!(
        result["response"],
        json!({}),
        "no partial success: {result}"
    );
    let message = result["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("SECRET_INPUT"),
        "static message must not echo input: {message}"
    );
}

#[test]
fn eof_without_terminal_event_fails_and_never_returns_partial_text() {
    let mut vm = codec_vm();
    let chunks =
        json!([{"type": "response.output_text.delta", "output_index": 0, "delta": "partial"}]);
    let result = collect(&mut vm, &chunks, false);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(
        result["error"]["code"],
        json!("stream_eof_without_response_completed")
    );
    assert_eq!(result["response"], json!({}), "no partial: {result}");
}

#[test]
fn missing_output_index_on_args_delta_is_malformed() {
    let mut vm = codec_vm();
    let chunks = json!([{"type": "response.function_call_arguments.delta", "delta": "{}"}]);
    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(result["error"]["code"], json!("malformed_payload"));
    let message = result["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("{}"),
        "static message must not echo input: {message}"
    );
}

#[test]
fn buffered_body_parses_text_reasoning_and_usage() {
    let mut vm = codec_vm();
    let body = json!({
        "id": "resp_5", "object": "response", "status": "completed", "model": "gpt-6.1-sol",
        "output": [
            {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "thought"}]},
            {"type": "message", "id": "msg_2", "role": "assistant",
             "content": [{"type": "output_text", "text": "final answer"}]}
        ],
        "usage": {"input_tokens": 11, "output_tokens": 22, "total_tokens": 33},
        "error": null
    });
    let result = invoke(&mut vm, "parse_body", &[json_to_value(&body)]);
    let result = value_to_json(&result);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["response"]["text"], json!("final answer"));
    assert_eq!(result["response"]["reasoning"], json!("thought"));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(33));
    assert_eq!(result["response"]["stop_reason"], json!("stop"));
}

#[test]
fn buffered_error_body_maps_public_error() {
    let mut vm = codec_vm();
    let text = "{\"error\":{\"message\":\"bad request\",\"type\":\"invalid_request_error\",\"code\":\"bad\"}}";
    let result = invoke(
        &mut vm,
        "parse_error",
        &[Value::string(text), Value::Int(400)],
    );
    let result = value_to_json(&result);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(result["error"]["status"], json!(400));
    assert_eq!(result["error"]["type"], json!("invalid_request_error"));
    assert_eq!(result["error"]["code"], json!("bad"));
}

#[test]
fn completed_refusal_content_becomes_exact_visible_text() {
    let mut vm = codec_vm();
    let expected = "I cannot help with that request.";
    let chunks = json!([
        {"type": "response.refusal.delta", "delta": "draft refusal"},
        {"type": "response.completed", "response": {
            "status": "completed",
            "output": [{"type": "message", "role": "assistant",
                        "content": [{"type": "refusal", "refusal": expected}]}],
            "usage": {"input_tokens": 2, "output_tokens": 6, "total_tokens": 8}
        }}
    ]);

    let result = collect(&mut vm, &chunks, true);
    assert_eq!(
        result["response"]["text"],
        json!(expected),
        "result: {result}"
    );
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["response"]["stop_reason"], json!("stop"));
    assert_eq!(result["response"]["tool_calls"], json!([]));
}

#[test]
fn accumulated_refusal_deltas_without_final_body_use_exact_visible_text() {
    let mut vm = codec_vm();
    let chunks = json!([
        {"type": "response.refusal.delta", "delta": "I cannot "},
        {"type": "response.refusal.delta", "delta": "help with that request."}
    ]);

    let result = collect(&mut vm, &chunks, true);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(
        result["response"]["text"],
        json!("I cannot help with that request."),
        "result: {result}"
    );
    assert_eq!(result["response"]["stop_reason"], json!(""));
    assert_eq!(result["response"]["tool_calls"], json!([]));
}

#[test]
fn empty_refusal_content_and_delta_remain_fail_closed() {
    // Direct regression coverage: empty refusal values do not create visible text.
    let mut vm = codec_vm();
    let completed = json!([{
        "type": "response.completed",
        "response": {
            "status": "completed",
            "output": [{"type": "message", "role": "assistant",
                        "content": [{"type": "refusal", "refusal": ""}]}
            ]
        }
    }]);
    let completed_result = collect(&mut vm, &completed, true);
    assert_eq!(completed_result["ok"], json!(false));
    assert_eq!(
        completed_result["error"]["code"],
        json!("empty_responses_output")
    );

    let delta_result = collect(
        &mut vm,
        &json!([{"type": "response.refusal.delta", "delta": ""}]),
        true,
    );
    assert_eq!(delta_result["ok"], json!(false));
    assert_eq!(
        delta_result["error"]["code"],
        json!("empty_responses_output")
    );
}
