//! Direct AgentRunner harness for `rss/tools/dispatch_entry.rss`.
//! Production workers dispatch only through `rss/agent/main.rss` → `tools::dispatch`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use rustscript_agent::{AgentConfig, AgentRunner, AgentService, ToolCall, ToolResult};
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};

static DISPATCH_RUNNER: OnceLock<AgentRunner> = OnceLock::new();

fn dispatch_entry_runner() -> AgentRunner {
    DISPATCH_RUNNER
        .get_or_init(|| {
            let path =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/tools/dispatch_entry.rss");
            AgentRunner::from_file(&path, AgentConfig::default()).unwrap_or_else(|error| {
                panic!("compile rss/tools/dispatch_entry.rss: {error}");
            })
        })
        .clone()
}

fn json_to_vm_value(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::Null,
        Value::Bool(value) => VmValue::Bool(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                VmValue::Int(value)
            } else {
                VmValue::Float(value.as_f64().expect("finite json number"))
            }
        }
        Value::String(value) => VmValue::string(value),
        Value::Array(values) => VmValue::Array(std::sync::Arc::new(
            values.iter().map(json_to_vm_value).collect::<Vec<_>>(),
        )),
        Value::Object(entries) => VmValue::map(
            entries
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

fn vm_value_to_json(value: &VmValue) -> Value {
    match value {
        VmValue::Null => Value::Null,
        VmValue::Int(value) => json!(value),
        VmValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        VmValue::Bool(value) => json!(value),
        VmValue::String(value) => Value::String(value.to_string()),
        VmValue::Bytes(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        VmValue::Array(values) => Value::Array(values.iter().map(vm_value_to_json).collect()),
        VmValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        VmValue::Callable(_) => Value::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &VmValue) -> String {
    match value {
        VmValue::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

fn envelope_to_tool_result(envelope: &Value, call: &ToolCall) -> ToolResult {
    if let Some(payload) = envelope
        .get("content_block")
        .and_then(|block| block.get("result"))
        && let Ok(result) = serde_json::from_value::<ToolResult>(payload.clone())
    {
        return result;
    }
    let ok = envelope.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if ok {
        return ToolResult::success(format!("ran {}", call.name), json!({}));
    }
    let code = envelope
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("adapter_failed");
    let message = envelope
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("RSS dispatch failed");
    ToolResult::failure(code, message)
}

pub fn dispatch_rss(
    service: &Arc<AgentService>,
    run_id: &str,
    calls: &[ToolCall],
) -> Result<Vec<ToolResult>, String> {
    let Some(host) = service
        .capability_host_bridges(run_id)
        .map_err(|error| error.to_string())?
    else {
        return Ok(calls
            .iter()
            .map(|_| ToolResult::failure("cancelled", "capability host is closed"))
            .collect());
    };
    let context = service
        .run_context(run_id)
        .ok_or_else(|| format!("missing run context for {run_id}"))?;
    let registry = service
        .run_registry_snapshot(run_id)
        .ok_or_else(|| format!("missing registry snapshot for {run_id}"))?;
    let identity = registry.identity().to_string();
    let runner = dispatch_entry_runner();
    let mut results = Vec::with_capacity(calls.len());
    for call in calls {
        let input = json!({
            "call": {
                "id": call.id,
                "name": call.name,
                "arguments": call.arguments,
            },
            "registry": registry.schemas(),
            "registry_identity": identity,
            "admitted_registry_identity": identity,
            "run_id": context.run_id,
            "config": context.limits,
        });
        match runner
            .clone()
            .with_host(host.clone())
            .run_with_context(json_to_vm_value(&input))
        {
            Ok(value) => results.push(envelope_to_tool_result(&vm_value_to_json(&value), call)),
            Err(error) => results.push(ToolResult::failure(
                "adapter_failed",
                format!("RSS dispatch failed: {error}"),
            )),
        }
    }
    Ok(results)
}
