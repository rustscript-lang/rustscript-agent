//! Agent event schema and bounded live delivery.
//!
//! Script-visible events arrive exclusively through `stream::emit(value)`.
//! AgentService validates each event against the canonical agent event
//! schema, assigns the per-run monotonic sequence, appends it durably, and
//! only then publishes it to live subscribers. Delivery is one bounded path:
//! the worker blocks on the bounded channel when the delivery task is busy,
//! which pauses invocation polling (backpressure). Nothing is published after
//! the run commits a terminal state.

use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};

/// Canonical script-visible event types (gateway-api plan section 4.3).
pub const CANONICAL_SCRIPT_EVENTS: &[&str] = &[
    "model.started",
    "model.delta",
    "model.completed",
    "tool.requested",
    "approval.required",
    "approval.resolved",
    "tool.started",
    "tool.output",
    "tool.completed",
    "compact.started",
    "compact.completed",
    "subagent.started",
    "subagent.completed",
];

/// Service-owned event types that scripts must not emit.
pub const SERVICE_OWNED_EVENTS: &[&str] = &[
    "run.started",
    "run.completed",
    "run.cancelled",
    "run.failed",
    "message.delta",
];

/// Validates one `stream::emit(value)` payload against the agent event schema.
///
/// The payload must be a map carrying a `type` string naming a canonical
/// script-visible event. Terminal/service-owned event names are rejected.
/// Returns the canonical event type on success.
pub fn validate_script_event(value: &VmValue) -> Result<&str, &'static str> {
    let VmValue::Map(entries) = value else {
        return Err("script event payload must be a map");
    };
    let Some(VmValue::String(event_type)) = entries.get(&VmValue::string("type")) else {
        return Err("script event payload must carry a string 'type' field");
    };
    if CANONICAL_SCRIPT_EVENTS.contains(&event_type.as_str()) {
        Ok(event_type.as_str())
    } else if SERVICE_OWNED_EVENTS.contains(&event_type.as_str()) {
        Err("script events must not use service-owned event types")
    } else {
        Err("script event type is not a canonical agent event")
    }
}

/// Renders one emitted script event payload as the canonical event data map.
///
/// The emitted map is passed through unchanged (the `type` discriminator is
/// preserved); AgentService attaches run identity, sequence, and timestamp in
/// `GatewayEvent`.
pub fn script_event_data(value: &VmValue) -> Value {
    crate::domain::vm_value_to_json(value)
}

/// Builds the canonical error payload for a schema-violating event.
pub fn schema_violation_error(reason: &str) -> Value {
    json!({
        "status": "failed",
        "error_code": "invalid_event_schema",
        "error_message": format!("script event rejected by the agent event schema: {reason}"),
    })
}
