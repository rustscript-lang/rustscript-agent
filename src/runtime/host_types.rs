//! Descriptor-owned named structs for fixed agent host shapes.
//!
//! Runtime values remain maps. Nested payloads that are genuinely open JSON
//! stay `HostTypeSchema::Unknown` and are listed in
//! [`crate::runtime::host_compose::DYNAMIC_HOST_SLOTS`].

#![allow(dead_code)]

use rustscript_vm::{HostNamedStruct, HostStructField, HostTypeSchema};

fn field(name: &'static str, ty: HostTypeSchema) -> HostStructField {
    HostStructField::new(name, ty)
}

fn optional(ty: HostTypeSchema) -> HostTypeSchema {
    HostTypeSchema::Optional(Box::new(ty))
}

fn option(ty: HostTypeSchema) -> HostTypeSchema {
    HostTypeSchema::Option(Box::new(ty))
}

fn named<T: HostNamedStruct>() -> HostTypeSchema {
    T::host_type_schema()
}

macro_rules! named_struct {
    ($ident:ident, $name:literal, [ $(($field:literal, $ty:expr)),+ $(,)? ]) => {
        pub struct $ident;
        impl HostNamedStruct for $ident {
            const NAME: &'static str = $name;
            fn host_struct_fields() -> Vec<HostStructField> {
                vec![$(field($field, $ty),)+]
            }
        }
    };
}

named_struct!(
    AgentProviderError,
    "AgentProviderError",
    [
        ("status", HostTypeSchema::Int),
        ("type", HostTypeSchema::String),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String),
        ("param", HostTypeSchema::String),
        ("request_id", HostTypeSchema::String),
        ("retryable", HostTypeSchema::Bool)
    ]
);

named_struct!(
    AgentControlResult,
    "AgentControlResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentParsedJsonObject,
    "AgentParsedJsonObject",
    [
        ("ok", HostTypeSchema::Bool),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String),
        ("value", HostTypeSchema::String)
    ]
);

// `agent::provider_call` result: the envelope is a fixed shape; only its two
// bodies are provider-defined, so they cross the boundary as serialized JSON
// text (`json::decode::<map>` on the guest side). `error` is empty when `ok`,
// `response` is empty otherwise.
named_struct!(
    AgentProviderEnvelope,
    "AgentProviderEnvelope",
    [
        ("ok", HostTypeSchema::Bool),
        ("error", HostTypeSchema::String),
        ("response", HostTypeSchema::String)
    ]
);

named_struct!(
    AgentCapabilityError,
    "AgentCapabilityError",
    [
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String)
    ]
);

// `agent::refresh_context`. The guest sends its transcript as serialized text
// and gets a *fixed* envelope back: byte/UTF-8/object checks stay in the host.
//
// The durable transcript refresh also produces a compacted message array, but
// this pin admits no open-array host return, and the agent loop cannot append
// to a remotely materialized array. So the refreshed transcript is **not**
// carried back across the boundary: the loop keeps its own append-only
// transcript and only `ok`/`storage_available` (and the typed refusal) cross.
named_struct!(
    AgentRefreshEnvelope,
    "AgentRefreshEnvelope",
    [
        ("ok", HostTypeSchema::Bool),
        ("storage_available", HostTypeSchema::Bool),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String)
    ]
);

// One `approvals` row, projected positionally from the storage command's
// `columns`/`rows` result. Every column the agent loop reads is named here, so
// the guest never indexes a dynamic row array. `resolved_at_ms`/`resolver`/
// `decision_reason` stay host-side: the loop does not read them.
named_struct!(
    AgentApprovalRow,
    "AgentApprovalRow",
    [
        ("id", HostTypeSchema::String),
        ("run_id", HostTypeSchema::String),
        ("session_id", HostTypeSchema::String),
        ("tool_call_id", HostTypeSchema::String),
        ("tool_name", HostTypeSchema::String),
        ("arguments_json", HostTypeSchema::String),
        ("risk_class", HostTypeSchema::String),
        ("state", HostTypeSchema::String),
        ("decision_scope", HostTypeSchema::String),
        ("one_time", HostTypeSchema::Int),
        ("requested_at_ms", HostTypeSchema::Int),
        ("expires_at_ms", HostTypeSchema::Int)
    ]
);

// `agent::approval_storage`: the payload crosses as serialized text (the host
// parses it), and the storage answer is projected onto this fixed shape.
named_struct!(
    AgentApprovalStorageEnvelope,
    "AgentApprovalStorageEnvelope",
    [
        ("ok", HostTypeSchema::Bool),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String),
        (
            "rows",
            HostTypeSchema::Array(Box::new(named::<AgentApprovalRow>()))
        ),
        ("rows_affected", HostTypeSchema::Int)
    ]
);

// Capability and agent-runtime returns are fixed shapes. Every field the
// adapter emits is declared: a field that is always present on the success
// branch is concrete (`String`/`Int`/`Bool`/`Bytes`, empty or zero on the
// failure branch); a field the host can genuinely omit is a logical
// `Option<T>` carrier, built by the adapter from what it observed, never
// inferred from a physical null. Open JSON never crosses as a structure: it
// is serialized text (`String`) that the host parses/serializes, because this
// pin's typed boundary rejects `Map(Unknown)` on both sides.
named_struct!(
    AgentFsMetadataResult,
    "AgentFsMetadataResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("file_type", HostTypeSchema::String),
        ("len", HostTypeSchema::Int),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentFsListEntry,
    "AgentFsListEntry",
    [
        ("name", HostTypeSchema::String),
        ("file_type", HostTypeSchema::String),
        ("len", HostTypeSchema::Int)
    ]
);

named_struct!(
    AgentFsListResult,
    "AgentFsListResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("cursor", HostTypeSchema::Int),
        ("next_cursor", option(HostTypeSchema::Int)),
        ("truncated", HostTypeSchema::Bool),
        (
            "entries",
            HostTypeSchema::Array(Box::new(named::<AgentFsListEntry>()))
        ),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentFsReadResult,
    "AgentFsReadResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("offset", HostTypeSchema::Int),
        ("truncated", HostTypeSchema::Bool),
        ("len", HostTypeSchema::Int),
        ("bytes", HostTypeSchema::Bytes),
        ("hash", option(HostTypeSchema::String)),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentFsWriteResult,
    "AgentFsWriteResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("hash", HostTypeSchema::String),
        ("len", HostTypeSchema::Int),
        ("durable", HostTypeSchema::Bool),
        ("staging_cleaned", HostTypeSchema::Bool),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentProcessLimits,
    "AgentProcessLimits",
    [
        ("timeout_ms", optional(HostTypeSchema::Int)),
        ("stdout_limit", optional(HostTypeSchema::Int)),
        ("stderr_limit", optional(HostTypeSchema::Int)),
        ("total_limit", optional(HostTypeSchema::Int)),
        ("stdin_limit", optional(HostTypeSchema::Int)),
        ("log_limit", optional(HostTypeSchema::Int)),
        ("close_after_initial", optional(HostTypeSchema::Bool))
    ]
);

named_struct!(
    AgentProcessSpawnResult,
    "AgentProcessSpawnResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("handle", HostTypeSchema::String),
        ("pid", HostTypeSchema::Int),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentProcessSnapshot,
    "AgentProcessSnapshot",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("handle", HostTypeSchema::String),
        ("running", HostTypeSchema::Bool),
        ("exit_code", option(HostTypeSchema::Int)),
        ("signal", option(HostTypeSchema::Int)),
        ("stdout", HostTypeSchema::String),
        ("stderr", HostTypeSchema::String),
        ("stdout_bytes", HostTypeSchema::Bytes),
        ("stderr_bytes", HostTypeSchema::Bytes),
        ("truncated", HostTypeSchema::Bool),
        ("stdout_offset", HostTypeSchema::Int),
        ("stdout_next_offset", HostTypeSchema::Int),
        ("stdout_truncated", HostTypeSchema::Bool),
        ("stdout_gap", HostTypeSchema::Bool),
        ("stdout_eof", HostTypeSchema::Bool),
        ("stderr_offset", HostTypeSchema::Int),
        ("stderr_next_offset", HostTypeSchema::Int),
        ("stderr_truncated", HostTypeSchema::Bool),
        ("stderr_gap", HostTypeSchema::Bool),
        ("stderr_eof", HostTypeSchema::Bool),
        ("signaled", HostTypeSchema::Bool),
        ("unknown", HostTypeSchema::Bool),
        ("deadline_elapsed", HostTypeSchema::Bool),
        ("cancelled", HostTypeSchema::Bool),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentProcessWriteResult,
    "AgentProcessWriteResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("wrote_bytes", HostTypeSchema::Int),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentProcessCloseResult,
    "AgentProcessCloseResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentClockResult,
    "AgentClockResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("ms", HostTypeSchema::Int),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

// Directory/artifact reference: `metadata` is the durable artifact metadata
// object, serialized to text by the host (it is provider/plugin defined) and
// parsed by the host on the way back in.
named_struct!(
    AgentArtifactRef,
    "AgentArtifactRef",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("id", HostTypeSchema::String),
        ("len", HostTypeSchema::Int),
        ("hash", HostTypeSchema::String),
        ("metadata", HostTypeSchema::String),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentArtifactGetResult,
    "AgentArtifactGetResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("len", HostTypeSchema::Int),
        ("bytes", HostTypeSchema::Bytes),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

// `agent::json_text`: the one native bridge that turns a guest value into
// canonical JSON text. Open payloads cross as text in both directions because
// this pin admits neither `Map(Unknown)` host returns nor a guest-side
// serializer.
named_struct!(
    AgentJsonText,
    "AgentJsonText",
    [
        ("ok", HostTypeSchema::Bool),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String),
        ("text", HostTypeSchema::String),
        ("bytes", HostTypeSchema::Int)
    ]
);

// `agent::preview_arguments`: the closed projection of one tool call's
// arguments that the owner-facing approval preview renders.
//
// The arguments themselves are open provider JSON and cross the boundary as
// text; the *preview* never needs that openness, so this struct names exactly
// the fields `guardian::action_preview` reads and nothing else. Every field is
// a logical `Option<T>` (`None` = the provider did not send that field), which
// keeps "absent" distinguishable from "present but empty". A parse failure is
// an explicit refusal — `ok: false` with a `code` — never an empty struct that
// silently degrades the preview into a fail-closed approval.
named_struct!(
    AgentPreviewArguments,
    "AgentPreviewArguments",
    [
        ("ok", HostTypeSchema::Bool),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String),
        ("path", option(HostTypeSchema::String)),
        ("content", option(HostTypeSchema::String)),
        ("old_string", option(HostTypeSchema::String)),
        ("new_string", option(HostTypeSchema::String)),
        ("replace_all", option(HostTypeSchema::Bool)),
        (
            "argv",
            option(HostTypeSchema::Array(Box::new(HostTypeSchema::String)))
        ),
        ("stdin", option(HostTypeSchema::String)),
        ("cwd", option(HostTypeSchema::String)),
        ("timeout_ms", option(HostTypeSchema::Int)),
        ("max_output_bytes", option(HostTypeSchema::Int)),
        ("background", option(HostTypeSchema::Bool)),
        ("action", option(HostTypeSchema::String)),
        ("process_id", option(HostTypeSchema::String)),
        ("data", option(HostTypeSchema::String)),
        ("offset", option(HostTypeSchema::Int)),
        ("limit", option(HostTypeSchema::Int))
    ]
);

// The projected canonical tool result a pinned/managed invocation returns to
// the guest. `data` is the tool's own open payload: text, for the same reason.
named_struct!(
    AgentCanonicalToolResult,
    "AgentCanonicalToolResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("content", HostTypeSchema::String),
        ("data", HostTypeSchema::String),
        ("truncated", HostTypeSchema::Bool),
        (
            "artifacts",
            HostTypeSchema::Array(Box::new(HostTypeSchema::String))
        ),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

// `agent_runtime::tool_prepare|tool_replay|approval_attest|tool_commit`.
// `result` is the replayed/committed canonical result as JSON text.
named_struct!(
    AgentToolEnvelope,
    "AgentToolEnvelope",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("execution_token", HostTypeSchema::String),
        ("deadline_ms", HostTypeSchema::Int),
        ("call_id", HostTypeSchema::String),
        ("result", HostTypeSchema::String),
        ("error", option(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    PinnedToolInvokeRequest,
    "PinnedToolInvokeRequest",
    [
        ("tool_name", HostTypeSchema::String),
        ("call_id", HostTypeSchema::String),
        ("canonical_arguments", HostTypeSchema::String),
        ("canonical_input", HostTypeSchema::String),
        ("run_id", HostTypeSchema::String),
        ("registry_identity", HostTypeSchema::String),
        ("argument_digest", HostTypeSchema::String),
        ("risk_class", HostTypeSchema::String),
        ("summary", HostTypeSchema::String),
        ("untrusted_graph_id", HostTypeSchema::String)
    ]
);

named_struct!(
    PinnedPluginChildInvokeRequest,
    "PinnedPluginChildInvokeRequest",
    [("canonical_arguments", HostTypeSchema::String)]
);

named_struct!(
    ManagedPublicationRef,
    "ManagedPublicationRef",
    [
        ("format", HostTypeSchema::String),
        ("effect_id", HostTypeSchema::String),
        ("workspace_id", HostTypeSchema::String),
        ("branch_id", HostTypeSchema::String),
        ("epoch", HostTypeSchema::Int),
        ("base_head", HostTypeSchema::String),
        ("base_head_version", HostTypeSchema::Int),
        ("candidate_head", option(HostTypeSchema::String)),
        ("observed_head", HostTypeSchema::String),
        ("observed_head_version", HostTypeSchema::Int),
        ("status", HostTypeSchema::String)
    ]
);

named_struct!(
    PinnedToolInvokeResult,
    "PinnedToolInvokeResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("text", HostTypeSchema::String),
        ("content", HostTypeSchema::String),
        ("kind", HostTypeSchema::String),
        ("code", HostTypeSchema::String),
        ("message", HostTypeSchema::String),
        ("canonical_result", HostTypeSchema::String),
        ("guest_result", HostTypeSchema::String),
        (
            "managed_publication",
            option(named::<ManagedPublicationRef>())
        )
    ]
);

named_struct!(
    AgentPluginStateSnapshot,
    "AgentPluginStateSnapshot",
    [
        ("ok", HostTypeSchema::Bool),
        ("schema", HostTypeSchema::Int),
        ("revision", HostTypeSchema::Int),
        ("document", HostTypeSchema::String),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentPluginStateWriteResult,
    "AgentPluginStateWriteResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("schema", HostTypeSchema::Int),
        ("revision", HostTypeSchema::Int),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);
