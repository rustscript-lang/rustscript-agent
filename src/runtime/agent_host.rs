//! Bounded native RSS host bridge for the serial provider/tool loop.
//!
//! `rss/agent/main.rss` builds canonical requests and dispatches tools only
//! through these host functions. Provider adapters stay in RSS; this module
//! does not add an OpenAI-compatible inference path.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustscript_vm::{
    CallOutcome, CallReturn, HostApiBuilder, HostApiCatalog, HostFunctionRegistry,
    HostFunctionSchema, HostParamSchema, HostTypeSchema, Value, Vm, VmError, VmResult,
    catalog_import_schemas, standard_host_catalog,
};
use serde_json::{Value as JsonValue, json};

use super::rss_runner::RunCancellation;
use crate::domain::{ToolCall, json_to_vm_value, vm_value_to_json};
use crate::tools::{DispatchContext, ToolResult};

const PROVIDER_CALL: &str = "agent::provider_call";
const TOOL_DISPATCH: &str = "agent::tool_dispatch";
const SLEEP_MS: &str = "agent::sleep_ms";
const CONTROL_CHECK: &str = "agent::control_check";

/// Combined catalog: standard host surfaces plus the agent loop bridges.
pub fn agent_host_catalog() -> Arc<HostApiCatalog> {
    static CATALOG: std::sync::OnceLock<Arc<HostApiCatalog>> = std::sync::OnceLock::new();
    Arc::clone(CATALOG.get_or_init(|| {
        let standard = standard_host_catalog();
        let mut builder = HostApiBuilder::new();
        for resource in standard.resources() {
            builder.resource(resource.clone());
        }
        for function in standard.functions() {
            builder.function(function.clone());
        }
        let response = HostTypeSchema::Map(Box::new(HostTypeSchema::Unknown));
        builder.function(HostFunctionSchema::with_return(
            PROVIDER_CALL,
            vec![HostParamSchema::value("request", HostTypeSchema::Unknown)],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            TOOL_DISPATCH,
            vec![HostParamSchema::value("call", HostTypeSchema::Unknown)],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            SLEEP_MS,
            vec![HostParamSchema::value("delay_ms", HostTypeSchema::Int)],
            HostTypeSchema::Int,
        ));
        builder.function(HostFunctionSchema::with_return(
            CONTROL_CHECK,
            vec![],
            response,
        ));
        Arc::new(builder.build().expect("agent host catalog must build"))
    }))
}

const SLEEP_CHUNK_MS: u64 = 10;
const SLEEP_CAP_MS: u64 = 60_000;
const SLEEP_LOG_CAP: usize = 32;

/// Bounded ring of requested backoff delays plus a dropped-entry count.
#[derive(Clone, Debug, Default)]
pub struct SleepLog {
    entries: VecDeque<i64>,
    dropped: u64,
}

impl SleepLog {
    fn push(&mut self, requested_ms: i64) {
        if self.entries.len() == SLEEP_LOG_CAP {
            self.entries.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.entries.push_back(requested_ms);
    }

    pub(crate) fn requested(&self) -> Vec<i64> {
        self.entries.iter().copied().collect()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Native provider invocation used by `agent::provider_call`.
pub trait AgentProviderHost: Send + Sync {
    fn call(&self, request: &JsonValue, cancellation: &RunCancellation) -> JsonValue;
}

/// Injectable host bridges for one compiled runner.
#[derive(Clone, Default)]
pub struct AgentHostBridges {
    pub provider: Option<Arc<dyn AgentProviderHost>>,
    pub dispatcher: Option<Arc<DispatchContext>>,
    /// Shared with the runner invocation; never an independent cancellation root.
    pub cancellation: Option<RunCancellation>,
    pub sleeps: Arc<Mutex<SleepLog>>,
    pub skip_sleep: bool,
}

/// Per-VM state installed before `run(context)`.
#[derive(Clone)]
pub struct AgentHostState {
    pub provider: Arc<dyn AgentProviderHost>,
    pub dispatcher: Option<Arc<DispatchContext>>,
    pub cancellation: RunCancellation,
    pub sleeps: Arc<Mutex<SleepLog>>,
    pub skip_sleep: bool,
}

impl AgentHostState {
    fn control_error(&self) -> Option<JsonValue> {
        if self.cancellation.requested().is_some() {
            return Some(typed_fail("cancelled", "run was cancelled"));
        }
        if self.cancellation.deadline_passed() {
            return Some(typed_fail("deadline_elapsed", "run deadline elapsed"));
        }
        None
    }

    fn provider_call(&self, request: &JsonValue) -> JsonValue {
        if let Some(error) = self.control_error() {
            return error;
        }
        normalize_provider_envelope(self.provider.call(request, &self.cancellation))
    }

    fn tool_dispatch(&self, call: &JsonValue) -> JsonValue {
        if let Some(error) = self.control_error() {
            return error_with_block(error, call, None);
        }
        let parsed = match parse_tool_call(call) {
            Ok(parsed) => parsed,
            Err(message) => {
                return error_with_block(typed_fail("malformed_payload", &message), call, None);
            }
        };
        let Some(dispatcher) = self.dispatcher.as_ref() else {
            return error_with_block(
                typed_fail(
                    "dispatcher_missing",
                    "native tool dispatcher is not configured",
                ),
                call,
                Some(&parsed),
            );
        };
        let result = dispatcher.dispatch_one(&parsed);
        let mut envelope = tool_result_envelope(&parsed, result);
        if let Some(error) = self.control_error() {
            envelope["terminal"] = json!(true);
            envelope["control"] = error.get("error").cloned().unwrap_or(error);
        }
        envelope
    }

    fn sleep_ms(&self, delay_ms: i64) -> i64 {
        let requested = delay_ms.max(0);
        let capped = u64::try_from(requested)
            .unwrap_or(u64::MAX)
            .min(SLEEP_CAP_MS);
        let requested_capped = i64::try_from(capped).unwrap_or(i64::MAX);
        let mut slept = 0_u64;
        if !self.skip_sleep && capped > 0 {
            while slept < capped {
                if self.control_error().is_some() {
                    break;
                }
                let remaining = capped - slept;
                let mut chunk = remaining.min(SLEEP_CHUNK_MS);
                if let Some(deadline) = self.cancellation.deadline_instant() {
                    let until = deadline.saturating_duration_since(Instant::now());
                    let until_ms = u64::try_from(until.as_millis()).unwrap_or(u64::MAX);
                    if until_ms == 0 {
                        break;
                    }
                    chunk = chunk.min(until_ms);
                }
                thread::sleep(Duration::from_millis(chunk));
                slept += chunk;
            }
        }
        self.sleeps
            .lock()
            .expect("sleep log lock")
            .push(requested_capped);
        if self.skip_sleep {
            requested_capped
        } else {
            i64::try_from(slept).unwrap_or(i64::MAX)
        }
    }
}

/// Scripted provider for loop tests: canned envelopes, recorded requests.
#[derive(Clone, Default)]
pub struct ScriptedProvider {
    inner: Arc<ScriptedProviderInner>,
}

#[derive(Default)]
struct ScriptedProviderInner {
    state: Mutex<ScriptedProviderState>,
}

#[derive(Default)]
struct ScriptedProviderState {
    outcomes: VecDeque<JsonValue>,
    requests: Vec<JsonValue>,
    calls: u64,
}

impl ScriptedProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_ok(&self, response: JsonValue) {
        self.inner
            .state
            .lock()
            .expect("scripted provider")
            .outcomes
            .push_back(json!({
                "ok": true,
                "response": response,
                "error": {}
            }));
    }

    pub fn push_error(&self, error: JsonValue) {
        self.inner
            .state
            .lock()
            .expect("scripted provider")
            .outcomes
            .push_back(json!({
                "ok": false,
                "response": {},
                "error": error
            }));
    }

    pub fn push_envelope(&self, envelope: JsonValue) {
        self.inner
            .state
            .lock()
            .expect("scripted provider")
            .outcomes
            .push_back(envelope);
    }

    pub fn requests(&self) -> Vec<JsonValue> {
        self.inner
            .state
            .lock()
            .expect("scripted provider")
            .requests
            .clone()
    }

    pub fn call_count(&self) -> u64 {
        self.inner.state.lock().expect("scripted provider").calls
    }

    /// Blocks inside `call` until the shared run cancellation fires (tests).
    pub fn hang(&self) {
        self.push_hang();
    }

    /// Queues a call that waits for the shared run cancellation root.
    pub fn push_hang(&self) {
        self.inner
            .state
            .lock()
            .expect("scripted provider")
            .outcomes
            .push_back(json!({ "__hang": true }));
    }
}

impl AgentProviderHost for ScriptedProvider {
    fn call(&self, request: &JsonValue, cancellation: &RunCancellation) -> JsonValue {
        {
            let mut state = self.inner.state.lock().expect("scripted provider");
            state.calls = state.calls.saturating_add(1);
            state.requests.push(request.clone());
        }
        let outcome = self
            .inner
            .state
            .lock()
            .expect("scripted provider")
            .outcomes
            .pop_front()
            .unwrap_or_else(|| {
                typed_fail(
                    "scripted_exhausted",
                    "scripted provider has no remaining outcomes",
                )
            });
        if outcome.get("__hang").and_then(JsonValue::as_bool) == Some(true) {
            while cancellation.requested().is_none() && !cancellation.deadline_passed() {
                thread::sleep(Duration::from_millis(5));
            }
            if cancellation.deadline_passed() && cancellation.requested().is_none() {
                return typed_fail("deadline_elapsed", "run deadline elapsed");
            }
            return typed_fail("cancelled", "run was cancelled");
        }
        outcome
    }
}

pub fn register_agent_host_functions(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
) -> VmResult<()> {
    register_named(registry, catalog, PROVIDER_CALL, 1, provider_call_adapter)?;
    register_named(registry, catalog, TOOL_DISPATCH, 1, tool_dispatch_adapter)?;
    register_named(registry, catalog, SLEEP_MS, 1, sleep_ms_adapter)?;
    register_named(registry, catalog, CONTROL_CHECK, 0, control_check_adapter)?;
    Ok(())
}

fn register_named(
    registry: &mut HostFunctionRegistry,
    catalog: &HostApiCatalog,
    name: &str,
    arity: u8,
    adapter: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) -> VmResult<()> {
    for schema in catalog_import_schemas(catalog, name) {
        registry.register_exact_static(name, arity, schema, adapter)?;
    }
    registry.register_static(name, arity, adapter);
    registry.allow_builtin(name)?;
    Ok(())
}

fn provider_call_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let request = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    let json = vm_value_to_json(&request);
    return_json(state.provider_call(&json))
}

fn tool_dispatch_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let call = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    let json = vm_value_to_json(&call);
    return_json(state.tool_dispatch(&json))
}

fn sleep_ms_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let delay = match args.first() {
        Some(Value::Int(value)) => *value,
        _ => 0,
    };
    let state = installed_state(vm)?;
    let slept = state.sleep_ms(delay);
    Ok(CallOutcome::Return(CallReturn::One(Value::Int(slept))))
}

fn control_check_adapter(vm: &mut Vm, _args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    let result = state
        .control_error()
        .unwrap_or_else(|| json!({"ok": true, "error": {}}));
    return_json(result)
}

fn installed_state(vm: &mut Vm) -> VmResult<AgentHostState> {
    vm.host_context()
        .module_state::<AgentHostState>()
        .cloned()
        .ok_or_else(|| VmError::HostError("agent host state is not installed".to_string()))
}

fn return_json(value: JsonValue) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::One(json_to_vm_value(
        &value,
    ))))
}

fn typed_fail(code: &str, message: &str) -> JsonValue {
    json!({
        "ok": false,
        "response": {},
        "error": {
            "status": 0,
            "type": error_type_for(code),
            "code": code,
            "message": message,
            "param": "",
            "request_id": "",
            "retryable": error_is_retryable_code(code)
        }
    })
}

fn error_is_retryable_code(code: &str) -> bool {
    !matches!(
        code,
        "setup"
            | "config"
            | "adapter_unavailable"
            | "malformed_payload"
            | "scripted_exhausted"
            | "cancelled"
            | "deadline_elapsed"
            | "dispatcher_missing"
            | "adapter_failed"
            | "unsupported_parallel"
            | "unsupported_task"
    )
}

fn error_type_for(code: &str) -> &'static str {
    match code {
        "malformed_payload" => "malformed_payload",
        "cancelled" | "deadline_elapsed" => "invalid_request_error",
        _ => "api_error",
    }
}

fn normalize_provider_envelope(result: JsonValue) -> JsonValue {
    if !result.is_object() {
        return typed_fail(
            "malformed_payload",
            "provider returned a non-object envelope",
        );
    }
    if result.get("ok").and_then(JsonValue::as_bool) != Some(true) {
        if result.get("error").is_some_and(JsonValue::is_object) {
            return result;
        }
        return typed_fail("malformed_payload", "provider error envelope is malformed");
    }
    let Some(response) = result.get("response") else {
        return typed_fail("malformed_payload", "provider response is missing");
    };
    if !response.is_object() {
        return typed_fail("malformed_payload", "provider response is not an object");
    }
    if response
        .get("tool_calls")
        .is_some_and(|calls| !calls.is_array())
    {
        return typed_fail("malformed_payload", "provider tool_calls is not an array");
    }
    result
}

fn parse_tool_call(value: &JsonValue) -> Result<ToolCall, String> {
    let id = value
        .get("id")
        .or_else(|| value.get("tool_call_id"))
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let name = value
        .get("name")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    if id.is_empty() || name.is_empty() {
        return Err("tool call is missing id or name".to_string());
    }
    let arguments = if let Some(arguments) = value.get("arguments") {
        if !arguments.is_object() {
            return Err("tool call arguments must be an object".to_string());
        }
        arguments.clone()
    } else if let Some(raw) = value.get("arguments_json") {
        let text = raw
            .as_str()
            .ok_or_else(|| "arguments_json must be a string".to_string())?;
        let parsed: JsonValue = serde_json::from_str(text)
            .map_err(|error| format!("malformed arguments_json: {error}"))?;
        if !parsed.is_object() {
            return Err("arguments_json must decode to an object".to_string());
        }
        parsed
    } else {
        json!({})
    };
    Ok(ToolCall {
        id,
        name,
        arguments,
    })
}

fn tool_result_envelope(call: &ToolCall, result: ToolResult) -> JsonValue {
    let code = result
        .error
        .as_ref()
        .map(|error| error.code.as_str())
        .unwrap_or("");
    let terminal = matches!(
        code,
        "cancelled" | "deadline_elapsed" | "max_tool_calls" | "event_persist_failed"
    );
    let error = result
        .error
        .as_ref()
        .map(|error| json!({"code": error.code, "message": error.message}))
        .unwrap_or_else(|| json!({}));
    json!({
        "ok": result.ok,
        "terminal": terminal,
        "error": if result.ok { json!({}) } else { error.clone() },
        "content_block": {
            "type": "tool_result",
            "tool_call_id": call.id,
            "name": call.name,
            "content": result.content,
            "is_error": !result.ok,
            "result": result,
            "error": error,
            "artifact": result.artifacts,
            "truncated": result.truncated
        }
    })
}

fn error_with_block(fail: JsonValue, call: &JsonValue, parsed: Option<&ToolCall>) -> JsonValue {
    let id = parsed
        .map(|call| call.id.clone())
        .or_else(|| {
            call.get("id")
                .or_else(|| call.get("tool_call_id"))
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let name = parsed
        .map(|call| call.name.clone())
        .or_else(|| {
            call.get("name")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let error = fail.get("error").cloned().unwrap_or_else(|| json!({}));
    json!({
        "ok": false,
        "terminal": true,
        "error": error.clone(),
        "content_block": {
            "type": "tool_result",
            "tool_call_id": id,
            "name": name,
            "content": "",
            "is_error": true,
            "result": {},
            "error": error,
            "artifact": [],
            "truncated": false
        }
    })
}
