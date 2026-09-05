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
    "tool.failed",
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

/// Durable event append failures shared by provider and lifecycle committers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventCommitError {
    Terminal,
    Cancelled,
    PersistFailed(String),
    MissingParent,
    Corrupt(String),
}

/// Durable-first event sink used by lifecycle committers. Implementations must
/// not publish after the run has committed a terminal state.
pub trait DurableEventCommitter: Send + Sync {
    fn is_terminal(&self) -> bool;
    fn stop_requested(&self) -> bool {
        false
    }
    fn commit(&self, event_type: &str, data: Value) -> Result<(), EventCommitError>;
    /// Persist a tool step. Default forwards to [`Self::commit`]; production
    /// committers attach a durable tool_result message for output/completed/failed.
    fn commit_step(
        &self,
        event_type: &str,
        data: Value,
        result: Option<&crate::tool_result::ToolResult>,
    ) -> Result<(), EventCommitError> {
        let _ = result;
        self.commit(event_type, data)
    }
    /// Read-only pre-effect prepare: resolve the durable assistant tool-call
    /// parent. Missing or name-mismatched parents return
    /// [`EventCommitError::MissingParent`]. Default is a no-op success so
    /// in-memory test committers keep working.
    fn prepare_tool_parent(
        &self,
        tool_call_id: &str,
        name: &str,
    ) -> Result<(String, String), EventCommitError> {
        let _ = tool_call_id;
        Ok((String::new(), name.to_string()))
    }
    /// Read-only pre-effect replay: return a canonical completed/failed/
    /// interrupted `ToolResult` when durable state already has one. Default
    /// is `Ok(None)` so in-memory test committers keep executing.
    /// Corrupt canonical state must return [`EventCommitError::Corrupt`].
    fn replay_durable_tool_result(
        &self,
        tool_call_id: &str,
        name: &str,
    ) -> Result<Option<crate::tool_result::ToolResult>, EventCommitError> {
        let _ = (tool_call_id, name);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_script_events_are_accepted() {
        for event_type in CANONICAL_SCRIPT_EVENTS {
            let value = VmValue::map(vec![(
                VmValue::string("type"),
                VmValue::string(*event_type),
            )]);
            assert_eq!(
                validate_script_event(&value),
                Ok(*event_type),
                "{event_type} must be a canonical script event"
            );
        }
    }

    #[test]
    fn non_canonical_and_service_owned_events_are_rejected() {
        let service_owned = VmValue::map(vec![(
            VmValue::string("type"),
            VmValue::string("run.completed"),
        )]);
        assert!(
            validate_script_event(&service_owned).is_err(),
            "service-owned terminal events must be rejected"
        );
        let unknown = VmValue::map(vec![(
            VmValue::string("type"),
            VmValue::string("not_a_canonical_event"),
        )]);
        assert!(
            validate_script_event(&unknown).is_err(),
            "unknown event types must be rejected"
        );
        let missing_type = VmValue::map(vec![]);
        assert!(
            validate_script_event(&missing_type).is_err(),
            "events without a type field must be rejected"
        );
        assert!(
            validate_script_event(&VmValue::string("nope")).is_err(),
            "non-map payloads must be rejected"
        );
    }
}
