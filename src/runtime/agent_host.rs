//! Bounded native RSS host bridge for the serial provider/tool loop.
//!
//! `rss/agent/main.rss` builds canonical requests and dispatches tools only
//! through these host functions. Provider adapters stay in RSS; this module
//! does not add an OpenAI-compatible inference path.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

/// Native provider invocation used by `agent::provider_call`.
pub trait AgentProviderHost: Send + Sync {
    fn call(&self, request: &JsonValue) -> JsonValue;
}

/// Injectable host bridges for one compiled runner.
#[derive(Clone, Default)]
pub struct AgentHostBridges {
    pub provider: Option<Arc<dyn AgentProviderHost>>,
    pub dispatcher: Option<Arc<DispatchContext>>,
    pub sleeps: Arc<Mutex<Vec<i64>>>,
    pub skip_sleep: bool,
}

/// Per-VM state installed before `run(context)`.
#[derive(Clone)]
pub struct AgentHostState {
    pub provider: Arc<dyn AgentProviderHost>,
    pub dispatcher: Option<Arc<DispatchContext>>,
    pub cancellation: RunCancellation,
    pub sleeps: Arc<Mutex<Vec<i64>>>,
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
        let result = self.provider.call(request);
        if let Some(error) = self.control_error() {
            return error;
        }
        normalize_provider_envelope(result)
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
        if let Some(error) = self.control_error() {
            return error_with_block(error, call, Some(&parsed));
        }
        tool_result_envelope(&parsed, result)
    }

    fn sleep_ms(&self, delay_ms: i64) -> i64 {
        let delay = delay_ms.max(0);
        self.sleeps.lock().expect("sleep log lock").push(delay);
        if !self.skip_sleep && delay > 0 {
            let capped = u64::try_from(delay).unwrap_or(u64::MAX).min(60_000);
            thread::sleep(Duration::from_millis(capped));
        }
        delay
    }
}

/// Scripted provider for loop tests: canned envelopes, recorded requests.
#[derive(Clone, Default)]
pub struct ScriptedProvider {
    inner: Arc<ScriptedProviderInner>,
}

#[derive(Default)]
struct ScriptedProviderInner {
    outcomes: Mutex<VecDeque<JsonValue>>,
    requests: Mutex<Vec<JsonValue>>,
    calls: AtomicU64,
}

impl ScriptedProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_ok(&self, response: JsonValue) {
        self.inner
            .outcomes
            .lock()
            .expect("scripted outcomes")
            .push_back(json!({
                "ok": true,
                "response": response,
                "error": {}
            }));
    }

    pub fn push_error(&self, error: JsonValue) {
        self.inner
            .outcomes
            .lock()
            .expect("scripted outcomes")
            .push_back(json!({
                "ok": false,
                "response": {},
                "error": error
            }));
    }

    pub fn push_envelope(&self, envelope: JsonValue) {
        self.inner
            .outcomes
            .lock()
            .expect("scripted outcomes")
            .push_back(envelope);
    }

    pub fn requests(&self) -> Vec<JsonValue> {
        self.inner
            .requests
            .lock()
            .expect("scripted requests")
            .clone()
    }

    pub fn call_count(&self) -> u64 {
        self.inner.calls.load(Ordering::SeqCst)
    }
}

impl AgentProviderHost for ScriptedProvider {
    fn call(&self, request: &JsonValue) -> JsonValue {
        self.inner.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .requests
            .lock()
            .expect("scripted requests")
            .push(request.clone());
        self.inner
            .outcomes
            .lock()
            .expect("scripted outcomes")
            .pop_front()
            .unwrap_or_else(|| {
                typed_fail(
                    "scripted_exhausted",
                    "scripted provider has no remaining outcomes",
                )
            })
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
            "request_id": ""
        }
    })
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
        arguments.clone()
    } else if let Some(text) = value.get("arguments_json").and_then(JsonValue::as_str) {
        serde_json::from_str(text).unwrap_or_else(|_| json!({}))
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
