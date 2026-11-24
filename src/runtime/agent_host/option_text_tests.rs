//! Round-7 text-carrier tests for the provider, refresh and approval slots.
//!
//! Every case compiles a real RSS probe against the published agent catalog,
//! registers the real restricted agent module, binds a fresh VM, installs the
//! real `AgentHostState` with a scripted provider host, and then drives the
//! exported guest functions. Nothing is asserted against the adapter in
//! isolation: the text bound, the refusal codes and the field fidelity are read
//! back out of the guest-visible value.

use super::*;
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, VmStatus,
    compile_source_at_path_with_flavor_and_options, compile_source_with_flavor_and_options,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CANCEL: Duration = Duration::from_secs(30);
const MIB: usize = 1024 * 1024;

const PROBE: &str = r#"
use agent;
use json;

/// The same projection `rss/agent/provider_body.rss` performs, declared here so
/// the test reads the boundary exactly as the agent loop does.
struct Failure {
    status: Option<int>,
    type: Option<string>,
    code: Option<string>,
    message: Option<string>,
    param: Option<string>,
    request_id: Option<string>,
    retryable: Option<bool>
}

struct Call {
    id: Option<string>,
    name: Option<string>,
    arguments_json: Option<string>
}

struct Response {
    text: Option<string>,
    tool_calls: Option<array<Call>>
}

fn text_of(value: Option<string>) -> string {
    match value {
        Some(inner) => inner,
        None => "",
    }
}

fn int_of(value: Option<int>) -> int {
    match value {
        Some(inner) => inner,
        None => -1,
    }
}

fn bool_of(value: Option<bool>) -> bool {
    match value {
        Some(inner) => inner,
        None => false,
    }
}

pub fn call(request: string) -> AgentProviderEnvelope {
    agent::provider_call(request)
}

pub fn failure_body(body: string) -> map {
    let mut out: map = { code: "", type: "", message: "", param: "", request_id: "", status: -1, retryable: false };
    if body != "" {
        let decoded: Failure = json::decode::<Failure>(body);
        out.code = text_of(decoded.code.copy());
        out.type = text_of(decoded.type.copy());
        out.message = text_of(decoded.message.copy());
        out.param = text_of(decoded.param.copy());
        out.request_id = text_of(decoded.request_id.copy());
        out.status = int_of(decoded.status.copy());
        out.retryable = bool_of(decoded.retryable.copy());
    }
    out
}

pub fn response_body(body: string) -> map {
    let mut out: map = { text: "", calls: 0, first_id: "", first_name: "", first_arguments: "" };
    if body != "" {
        let decoded: Response = json::decode::<Response>(body);
        out.text = text_of(decoded.text.copy());
        let list: array<Call> = match decoded.tool_calls {
            Some(items) => items,
            None => []
        };
        out.calls = list.length;
        if list.length > 0 {
            let first: Call = list[0].copy();
            out.first_id = text_of(first.id.copy());
            out.first_name = text_of(first.name.copy());
            out.first_arguments = text_of(first.arguments_json.copy());
        }
    }
    out
}

pub fn refresh(context: string) -> AgentRefreshEnvelope {
    agent::refresh_context(context)
}

pub fn approvals(operation: string, payload: string) -> AgentApprovalStorageEnvelope {
    agent::approval_storage(operation, payload)
}

pub fn envelope_text(text: string) -> string {
    let encoded = agent::json_text({ ok: text });
    encoded.text
}

pub fn run() -> map {
    { ok: true }
}
"#;

fn probe_vm(provider: Arc<dyn AgentProviderHost>) -> Vm {
    let catalog = agent_host_catalog();
    let options = CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone());
    let compiled = compile_source_with_flavor_and_options(PROBE, SourceFlavor::RustScript, options)
        .expect("compile the text-carrier probe against the published catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    register_agent_host_functions(&mut registry, catalog.as_ref())
        .expect("register the published agent descriptors");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind the restricted registry");
    vm.host_context().set_module_state(AgentHostState {
        child_call: None,
        child_read: None,
        provider,
        cancellation: RunCancellation::with_timeout(CANCEL),
        sleeps: Arc::new(Mutex::new(SleepLog::default())),
        skip_sleep: true,
        metrics: None,
        lifecycle: None,
        capability_owner: None,
        filesystem: None,
        processes: None,
        artifacts: None,
        leases: Arc::new(Mutex::new(HashMap::new())),
        control_hook: None,
        pinned_tool: None,
        allow_stateless_pin: false,
        expected_call: None,
        plugin_state_call: None,
        provider_arguments: Default::default(),
    });
    assert!(matches!(
        vm.run().expect("probe root frame"),
        VmStatus::Halted
    ));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let callable = vm
        .resolve_exported_callable(name)
        .unwrap_or_else(|_| panic!("export {name}"));
    vm.invoke_callable(callable, args)
        .unwrap_or_else(|error| panic!("invoke {name}: {error}"))
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected a map, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn text_field(value: &Value, name: &str) -> String {
    match field(value, name) {
        Value::String(text) => text.as_str().to_string(),
        other => panic!("{name} is not a string: {other:?}"),
    }
}

fn parse(text: &str) -> JsonValue {
    serde_json::from_str(text).expect("body is JSON text")
}

fn provider_with(envelope: JsonValue) -> Arc<ScriptedProvider> {
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_envelope(envelope);
    provider
}

/// An approval host that answers with a real storage shape, so the adapter's
/// positional row projection is exercised end to end.
struct ApprovalProvider {
    answer: JsonValue,
    seen: Mutex<Vec<(String, JsonValue)>>,
}

impl AgentProviderHost for ApprovalProvider {
    fn call(&self, _request: &JsonValue, _cancellation: &RunCancellation) -> JsonValue {
        typed_fail("scripted_exhausted", "no provider outcome")
    }

    fn approval_storage(
        &self,
        operation: &str,
        payload: &JsonValue,
        _cancellation: &RunCancellation,
    ) -> JsonValue {
        self.seen
            .lock()
            .expect("approval log")
            .push((operation.to_string(), payload.clone()));
        self.answer.clone()
    }
}

#[test]
fn provider_call_carries_the_request_text_and_returns_body_text() {
    let provider = provider_with(json!({
        "ok": true,
        "response": {
            "text": "calling a tool",
            "tool_calls": [
                {"id": "call-1", "name": "read_file", "arguments": {"path": "note.txt"}}
            ]
        }
    }));
    let mut vm = probe_vm(provider.clone());

    let request = r#"{"provider":"openai","model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"#;
    let envelope = invoke(&mut vm, "call", &[Value::string(request)]);

    assert_eq!(field(&envelope, "ok"), Value::Bool(true));
    assert_eq!(field(&envelope, "error"), Value::string(""));
    // The provider received the parsed object, not a string wrapper.
    let seen = provider.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0], parse(request));

    // The guest decodes the body text exactly as the loop does, and the
    // adapter's `arguments_json` injection makes the open arguments readable.
    let body = text_field(&envelope, "response");
    let response = invoke(&mut vm, "response_body", &[Value::string(body)]);
    assert_eq!(field(&response, "text"), Value::string("calling a tool"));
    assert_eq!(field(&response, "calls"), Value::Int(1));
    assert_eq!(field(&response, "first_id"), Value::string("call-1"));
    assert_eq!(field(&response, "first_name"), Value::string("read_file"));
    assert_eq!(
        field(&response, "first_arguments"),
        Value::string(r#"{"path":"note.txt"}"#)
    );
}

#[test]
fn provider_call_refuses_a_request_that_is_not_a_json_object() {
    let provider = provider_with(json!({"ok": true, "response": {"text": ""}}));
    let mut vm = probe_vm(provider.clone());

    for bad in ["not json", "[1,2]", "null"] {
        let envelope = invoke(&mut vm, "call", &[Value::string(bad)]);
        assert_eq!(field(&envelope, "ok"), Value::Bool(false), "refused: {bad}");
        assert_eq!(field(&envelope, "response"), Value::string(""));
        let error = parse(&text_field(&envelope, "error"));
        assert_eq!(error["code"], json!("invalid_request"), "refused: {bad}");
    }
    assert!(
        provider.requests().is_empty(),
        "a refused request never reaches the provider"
    );
}

#[test]
fn provider_call_refuses_a_request_over_the_four_mib_bound() {
    let provider = provider_with(json!({"ok": true, "response": {"text": ""}}));
    let mut vm = probe_vm(provider.clone());

    let oversized = format!("{{\"blob\":\"{}\"}}", "a".repeat(4 * MIB + 1));
    let envelope = invoke(&mut vm, "call", &[Value::string(oversized)]);

    assert_eq!(field(&envelope, "ok"), Value::Bool(false));
    let error = parse(&text_field(&envelope, "error"));
    assert_eq!(error["code"], json!("payload_too_large"));
    assert!(
        provider.requests().is_empty(),
        "an oversized request never reaches the provider"
    );
}

#[test]
fn provider_call_refuses_a_response_body_over_the_four_mib_bound() {
    let provider = provider_with(json!({
        "ok": true,
        "response": {"text": "x".repeat(4 * MIB + 64)}
    }));
    let mut vm = probe_vm(provider);

    let envelope = invoke(&mut vm, "call", &[Value::string("{}")]);

    assert_eq!(
        field(&envelope, "ok"),
        Value::Bool(false),
        "an over-bound body is refused, not published"
    );
    assert_eq!(field(&envelope, "response"), Value::string(""));
    let error = parse(&text_field(&envelope, "error"));
    assert_eq!(error["code"], json!("provider_body_too_large"));
    assert_eq!(error["status"], json!(0));
    assert_eq!(error["retryable"], json!(false));
}

#[test]
fn provider_failure_body_keeps_the_retry_decision_fields() {
    let provider = provider_with(json!({
        "ok": false,
        "error": {
            "status": 429,
            "type": "rate_limit_error",
            "code": "rate_limit_exceeded",
            "message": "slow down",
            "param": "model",
            "request_id": "req_123",
            "retryable": true
        }
    }));
    let mut vm = probe_vm(provider);

    let envelope = invoke(&mut vm, "call", &[Value::string("{}")]);
    assert_eq!(field(&envelope, "ok"), Value::Bool(false));
    assert_eq!(field(&envelope, "response"), Value::string(""));

    let body = text_field(&envelope, "error");
    let failure = invoke(&mut vm, "failure_body", &[Value::string(body)]);
    // The three fields the round-4 review found missing, plus the ones the
    // retry classifier already read.
    assert_eq!(field(&failure, "type"), Value::string("rate_limit_error"));
    assert_eq!(field(&failure, "param"), Value::string("model"));
    assert_eq!(field(&failure, "request_id"), Value::string("req_123"));
    assert_eq!(
        field(&failure, "code"),
        Value::string("rate_limit_exceeded")
    );
    assert_eq!(field(&failure, "message"), Value::string("slow down"));
    assert_eq!(field(&failure, "status"), Value::Int(429));
    assert_eq!(field(&failure, "retryable"), Value::Bool(true));
}

#[test]
fn refresh_context_carries_text_and_reports_the_typed_refusal() {
    let mut vm = probe_vm(Arc::new(ScriptedProvider::new()));

    // The scripted host has no durable refresh, so the fixed envelope reports
    // `ok` with `storage_available: false` — never a dynamic body.
    let refreshed = invoke(
        &mut vm,
        "refresh",
        &[Value::string(r#"{"run_id":"run-1","messages":[]}"#)],
    );
    assert_eq!(field(&refreshed, "ok"), Value::Bool(true));
    assert_eq!(field(&refreshed, "storage_available"), Value::Bool(false));
    assert_eq!(field(&refreshed, "code"), Value::string(""));

    let refused = invoke(&mut vm, "refresh", &[Value::string("[1]")]);
    assert_eq!(field(&refused, "ok"), Value::Bool(false));
    assert_eq!(field(&refused, "code"), Value::string("invalid_request"));

    let oversized = format!("{{\"blob\":\"{}\"}}", "a".repeat(4 * MIB + 1));
    let refused = invoke(&mut vm, "refresh", &[Value::string(oversized)]);
    assert_eq!(field(&refused, "ok"), Value::Bool(false));
    assert_eq!(field(&refused, "code"), Value::string("payload_too_large"));
}

#[test]
fn approval_storage_parses_the_payload_text_and_projects_rows_by_name() {
    let provider = Arc::new(ApprovalProvider {
        answer: json!({
            "ok": true,
            "result": {
                "columns": ["id", "run_id", "session_id", "tool_call_id", "tool_name",
                            "arguments_json", "risk_class", "state", "decision_scope",
                            "one_time", "requested_at_ms", "expires_at_ms",
                            "resolved_at_ms", "resolver", "decision_reason"],
                "rows": [[
                    "approval-1", "run-1", "session-1", "call-1", "write_file",
                    "{\"path\":\"a.txt\"}", "write", "pending", "single_call",
                    1, 10, 20, null, null, null
                ]]
            }
        }),
        seen: Mutex::new(Vec::new()),
    });
    let mut vm = probe_vm(provider.clone());

    let payload = r#"{"run_id":"run-1","id":"approval-1","session_id":"session-1"}"#;
    let stored = invoke(
        &mut vm,
        "approvals",
        &[Value::string("request"), Value::string(payload)],
    );

    // The host parsed the text and forwarded a real object to the provider.
    let seen = provider.seen.lock().expect("approval log");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "request");
    assert_eq!(seen[0].1, parse(payload));
    drop(seen);

    assert_eq!(field(&stored, "ok"), Value::Bool(true));
    assert_eq!(field(&stored, "code"), Value::string(""));
    assert_eq!(field(&stored, "rows_affected"), Value::Int(0));
    let Value::Array(rows) = field(&stored, "rows") else {
        panic!("rows must be an array");
    };
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(field(row, "id"), Value::string("approval-1"));
    assert_eq!(field(row, "run_id"), Value::string("run-1"));
    assert_eq!(field(row, "session_id"), Value::string("session-1"));
    assert_eq!(field(row, "tool_call_id"), Value::string("call-1"));
    assert_eq!(field(row, "tool_name"), Value::string("write_file"));
    assert_eq!(
        field(row, "arguments_json"),
        Value::string(r#"{"path":"a.txt"}"#)
    );
    assert_eq!(field(row, "risk_class"), Value::string("write"));
    assert_eq!(field(row, "state"), Value::string("pending"));
    assert_eq!(field(row, "decision_scope"), Value::string("single_call"));
    assert_eq!(field(row, "one_time"), Value::Int(1));
    assert_eq!(field(row, "requested_at_ms"), Value::Int(10));
    assert_eq!(field(row, "expires_at_ms"), Value::Int(20));
}

#[test]
fn approval_storage_reports_rows_affected_and_refuses_malformed_text() {
    let provider = Arc::new(ApprovalProvider {
        answer: json!({"ok": true, "result": {"rows_affected": 1}}),
        seen: Mutex::new(Vec::new()),
    });
    let mut vm = probe_vm(provider);

    let resolved = invoke(
        &mut vm,
        "approvals",
        &[
            Value::string("resolve"),
            Value::string(r#"{"id":"approval-1","state":"approved"}"#),
        ],
    );
    assert_eq!(field(&resolved, "ok"), Value::Bool(true));
    assert_eq!(field(&resolved, "rows_affected"), Value::Int(1));
    match field(&resolved, "rows") {
        Value::Array(rows) => assert!(rows.is_empty()),
        other => panic!("rows must be an array: {other:?}"),
    }

    let refused = invoke(
        &mut vm,
        "approvals",
        &[Value::string("get"), Value::string("nope")],
    );
    assert_eq!(field(&refused, "ok"), Value::Bool(false));
    assert_eq!(field(&refused, "code"), Value::string("invalid_request"));
    assert_eq!(field(&refused, "rows_affected"), Value::Int(0));

    let oversized = format!("{{\"blob\":\"{}\"}}", "a".repeat(4 * MIB + 1));
    let refused = invoke(
        &mut vm,
        "approvals",
        &[Value::string("get"), Value::string(oversized)],
    );
    assert_eq!(field(&refused, "ok"), Value::Bool(false));
    assert_eq!(field(&refused, "code"), Value::string("payload_too_large"));
}

/// The real agent loop, compiled from `rss/agent/main.rss` against the
/// published catalog and driven through the real host state: a text provider
/// round trip must complete, and a provider tool call must reach the tool
/// boundary (its arguments crossed as text, so parsing them cannot crash the
/// loop).
fn main_loop_vm(provider: Arc<dyn AgentProviderHost>) -> Vm {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss");
    let source = std::fs::read_to_string(&path).expect("read the real agent main");
    let catalog = agent_host_catalog();
    let options = CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone());
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        options,
    )
    .expect("compile the real agent main against the published catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    for builtin in crate::runtime::host_compose::RESTRICTED_STANDARD_BUILTINS {
        registry.allow_builtin(builtin).expect("admit builtin");
    }
    register_agent_host_functions(&mut registry, catalog.as_ref())
        .expect("register the published agent descriptors");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind the restricted registry");
    vm.host_context().set_module_state(AgentHostState {
        child_call: None,
        child_read: None,
        provider,
        cancellation: RunCancellation::with_timeout(CANCEL),
        sleeps: Arc::new(Mutex::new(SleepLog::default())),
        skip_sleep: true,
        metrics: None,
        lifecycle: None,
        capability_owner: None,
        filesystem: None,
        processes: None,
        artifacts: None,
        leases: Arc::new(Mutex::new(HashMap::new())),
        control_hook: None,
        pinned_tool: None,
        allow_stateless_pin: true,
        expected_call: None,
        plugin_state_call: None,
        provider_arguments: Default::default(),
    });
    assert!(matches!(
        vm.run().expect("main root frame"),
        VmStatus::Halted
    ));
    vm
}

fn loop_context() -> Value {
    super::json_to_vm_value(&json!({
        "profile_id": "profile-1",
        "session_id": "session-1",
        "run_id": "run-1",
        "provider": "openai",
        "model": "request-model",
        "input": {"message": "say hi"},
        "config": {"max_retries": 0},
        "limits": {"max_turns": 2, "max_tool_calls": 2}
    }))
}

#[test]
fn main_loop_completes_a_text_carried_provider_turn() {
    let provider = provider_with(json!({
        "ok": true,
        "response": {"text": "hello from the provider"}
    }));
    let mut vm = main_loop_vm(provider.clone());

    let decision = invoke(&mut vm, "run", &[loop_context()]);
    assert_eq!(field(&decision, "kind"), Value::string("run.completed"));
    assert_eq!(
        field(&decision, "answer"),
        Value::string("hello from the provider")
    );

    // The request reached the provider as a parsed object with the canonical
    // message array the loop built.
    let seen = provider.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request["provider"], json!("openai"));
    assert_eq!(request["_provider_step_key"], json!("business:0"));
    let messages = request["messages"].as_array().expect("messages array");
    assert!(
        messages
            .iter()
            .any(|message| message["role"] == json!("user")),
        "the seeded user message is on the wire: {request}"
    );
}

#[test]
fn main_loop_reaches_the_tool_boundary_with_text_carried_arguments() {
    let provider = provider_with(json!({
        "ok": true,
        "response": {
            "text": "",
            "tool_calls": [{
                "id": "call-1",
                "name": "read_file",
                "arguments": {"path": "note.txt"},
                "arguments_json": "{\"path\":\"note.txt\"}"
            }]
        }
    }));
    let mut vm = main_loop_vm(provider.clone());

    let decision = invoke(&mut vm, "run", &[loop_context()]);
    assert_eq!(field(&decision, "kind"), Value::string("run.failed"));
    // The call was dispatched — one tool call consumed, and the loop moved on
    // to a second provider turn — so the text-only arguments were accepted by
    // the dispatcher instead of crashing a typed decode. The scripted provider
    // simply has no second outcome.
    assert_eq!(field(&decision, "tool_calls_used"), Value::Int(1));
    assert_eq!(
        field(&decision, "reason"),
        Value::string("scripted_exhausted"),
        "decision: {decision:?}"
    );

    // The follow-up request proves the fidelity of the rebuilt assistant
    // tool_call: the provider's own `arguments_json` text is carried verbatim,
    // not re-encoded from a missing map.
    let seen = provider.requests();
    assert_eq!(seen.len(), 2, "the loop took a second provider turn");
    let followup = &seen[1];
    let mut carried: Option<&JsonValue> = None;
    for message in followup["messages"].as_array().expect("messages") {
        for block in message["content"].as_array().cloned().unwrap_or_default() {
            if block["type"] == json!("tool_call") {
                carried = Some(&followup["messages"]);
                assert_eq!(block["tool_call_id"], json!("call-1"));
                assert_eq!(block["name"], json!("read_file"));
                assert_eq!(
                    block["arguments_json"],
                    json!("{\"path\":\"note.txt\"}"),
                    "the provider's arguments text must be carried verbatim"
                );
            }
        }
    }
    assert!(
        carried.is_some(),
        "follow-up carries the tool_call: {followup}"
    );
}
