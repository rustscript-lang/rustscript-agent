//! Host-map adapters for `agent_runtime::tool_prepare` and `tool_commit`.

use serde_json::{Value, json};

use super::lifecycle::CapabilityLifecycle;
use super::types::{
    CapabilityOwner, CapabilityRisk, CommitOutcome, LifecycleError, PrepareMetadata, PrepareOutcome,
};

/// Host envelope for a typed failed prepare/commit.
pub fn error_envelope(error: &LifecycleError) -> Value {
    json!({
        "ok": false,
        "kind": "error",
        "error": {
            "code": error.code(),
            "message": error.message(),
        }
    })
}

/// Host envelope for a typed failed capability primitive.
pub fn capability_error_envelope(error: &super::types::CapabilityError) -> Value {
    json!({
        "ok": false,
        "kind": "error",
        "error": {
            "code": error.code(),
            "message": error.message(),
        }
    })
}

/// Parse RSS/host map metadata. Public tool names stay opaque strings.
pub fn parse_prepare_metadata(value: &Value) -> Result<PrepareMetadata, LifecycleError> {
    let object = value.as_object().ok_or_else(|| {
        LifecycleError::InvalidMetadata("prepare metadata must be a map".to_string())
    })?;
    let field = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let tool_name = if object.contains_key("name") {
        field("name")
    } else {
        field("tool_name")
    };
    Ok(PrepareMetadata {
        run_id: field("run_id"),
        call_id: field("call_id"),
        tool_name,
        argument_digest: field("argument_digest"),
        registry_identity: field("registry_identity"),
        risk_class: CapabilityRisk::parse(&field("risk_class"))?,
        summary: field("summary"),
    })
}

/// Prepare through the host map contract.
pub fn tool_prepare(
    lifecycle: &CapabilityLifecycle,
    owner: &CapabilityOwner,
    metadata: PrepareMetadata,
) -> Value {
    match lifecycle.prepare(owner, metadata) {
        Ok(PrepareOutcome::Execute {
            execution_token,
            deadline_ms,
        }) => json!({
            "ok": true,
            "kind": "execute",
            "execution_token": execution_token,
            "deadline_ms": deadline_ms,
        }),
        Ok(PrepareOutcome::Replay { result }) => json!({
            "ok": true,
            "kind": "replay",
            "result": result,
        }),
        Err(error) => error_envelope(&error),
    }
}

/// Commit through the host map contract.
pub fn tool_commit(
    lifecycle: &CapabilityLifecycle,
    owner: &CapabilityOwner,
    token: &str,
    result: Value,
) -> Value {
    match lifecycle.commit(owner, token, result) {
        Ok(CommitOutcome { envelope }) => envelope,
        Err(error) => error_envelope(&error),
    }
}
