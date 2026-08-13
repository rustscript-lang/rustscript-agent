//! Canonical domain contracts shared by the service, gateways, and RSS.
//!
//! This module freezes the agent contracts (gateway-api plan sections 4.1 and
//! 4.2): the inbound platform envelope and the structured run context. The
//! run context is rendered as the sole argument of the exported
//! `run(context)` callable; scripts receive no ambient input. JSON/VM value
//! conversions and the canonical timestamp also live here so no gateway
//! module re-implements them.

use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};

/// Milliseconds since the Unix epoch; the canonical agent timestamp.
pub(crate) fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Canonical agent run context (gateway-api plan section 4.2).
///
/// The exact structured context is passed to the exported RSS `run(context)`
/// callable as one ordinary argument. AgentService resolves the session/run
/// state and fills this struct; [`RunContext::to_vm_value`] renders it.
#[derive(Clone, Debug, PartialEq)]
pub struct RunContext {
    pub run_id: String,
    pub session_id: String,
    pub parent_run_id: Option<String>,
    pub platform: String,
    pub input: Value,
    pub messages: Value,
    pub system_prompt: Option<String>,
    pub model: String,
    pub provider: Option<String>,
}

impl RunContext {
    /// Renders the canonical context as the sole `run(context)` argument.
    pub fn to_vm_value(&self) -> VmValue {
        VmValue::map(vec![
            (VmValue::string("run_id"), VmValue::string(&self.run_id)),
            (VmValue::string("session_id"), VmValue::string(&self.session_id)),
            (
                VmValue::string("parent_run_id"),
                self.parent_run_id
                    .as_deref()
                    .map(VmValue::string)
                    .unwrap_or(VmValue::Null),
            ),
            (VmValue::string("platform"), VmValue::string(&self.platform)),
            (
                VmValue::string("input"),
                json_to_vm_value(&self.input),
            ),
            (
                VmValue::string("messages"),
                json_to_vm_value(&self.messages),
            ),
            (
                VmValue::string("system_prompt"),
                self.system_prompt
                    .as_deref()
                    .map(VmValue::string)
                    .unwrap_or(VmValue::Null),
            ),
            (VmValue::string("model"), VmValue::string(&self.model)),
            (
                VmValue::string("provider"),
                self.provider
                    .as_deref()
                    .map(VmValue::string)
                    .unwrap_or(VmValue::Null),
            ),
        ])
    }
}

/// Converts one JSON value into a VM value (mirror of `vm_value_to_json`).
pub(crate) fn json_to_vm_value(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::Null,
        Value::Bool(value) => VmValue::Bool(*value),
        Value::Number(value) => value
            .as_i64()
            .map(VmValue::Int)
            .or_else(|| value.as_f64().map(VmValue::Float))
            .unwrap_or(VmValue::Null),
        Value::String(value) => VmValue::string(value),
        Value::Array(values) => VmValue::array(values.iter().map(json_to_vm_value).collect()),
        Value::Object(fields) => VmValue::map(
            fields
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

/// Converts one VM value into canonical JSON.
pub(crate) fn vm_value_to_json(value: &VmValue) -> Value {
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

/// Canonical input text for an agent run: strings pass through, structured
/// input renders as JSON text, and null renders as the empty string.
pub(crate) fn input_text(input: &Value) -> String {
    match input {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
