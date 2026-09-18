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
        ("error", optional(named::<AgentCapabilityError>()))
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

named_struct!(
    AgentFsMetadataResult,
    "AgentFsMetadataResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("file_type", optional(HostTypeSchema::String)),
        ("len", optional(HostTypeSchema::Int)),
        ("error", optional(named::<AgentCapabilityError>()))
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
        ("cursor", optional(HostTypeSchema::Int)),
        ("next_cursor", optional(HostTypeSchema::Int)),
        ("truncated", optional(HostTypeSchema::Bool)),
        (
            "entries",
            optional(HostTypeSchema::Array(Box::new(named::<AgentFsListEntry>())))
        ),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentFsWriteResult,
    "AgentFsWriteResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("hash", optional(HostTypeSchema::String)),
        ("len", optional(HostTypeSchema::Int)),
        ("durable", optional(HostTypeSchema::Bool)),
        ("staging_cleaned", optional(HostTypeSchema::Bool)),
        ("error", optional(named::<AgentCapabilityError>()))
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
        ("handle", optional(HostTypeSchema::String)),
        ("pid", optional(HostTypeSchema::Int)),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentProcessSnapshot,
    "AgentProcessSnapshot",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("handle", optional(HostTypeSchema::String)),
        ("running", optional(HostTypeSchema::Bool)),
        ("exit_code", optional(HostTypeSchema::Int)),
        ("signal", optional(HostTypeSchema::Int)),
        ("stdout", optional(HostTypeSchema::String)),
        ("stderr", optional(HostTypeSchema::String)),
        ("stdout_bytes", optional(HostTypeSchema::Bytes)),
        ("stderr_bytes", optional(HostTypeSchema::Bytes)),
        ("truncated", optional(HostTypeSchema::Bool)),
        ("stdout_offset", optional(HostTypeSchema::Int)),
        ("stdout_next_offset", optional(HostTypeSchema::Int)),
        ("stdout_truncated", optional(HostTypeSchema::Bool)),
        ("stdout_gap", optional(HostTypeSchema::Bool)),
        ("stdout_eof", optional(HostTypeSchema::Bool)),
        ("stderr_offset", optional(HostTypeSchema::Int)),
        ("stderr_next_offset", optional(HostTypeSchema::Int)),
        ("stderr_truncated", optional(HostTypeSchema::Bool)),
        ("stderr_gap", optional(HostTypeSchema::Bool)),
        ("stderr_eof", optional(HostTypeSchema::Bool)),
        ("signaled", optional(HostTypeSchema::Bool)),
        ("unknown", optional(HostTypeSchema::Bool)),
        ("deadline_elapsed", optional(HostTypeSchema::Bool)),
        ("cancelled", optional(HostTypeSchema::Bool)),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentProcessWriteResult,
    "AgentProcessWriteResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("wrote_bytes", optional(HostTypeSchema::Int)),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentProcessCloseResult,
    "AgentProcessCloseResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentClockResult,
    "AgentClockResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("ms", optional(HostTypeSchema::Int)),
        ("code", optional(HostTypeSchema::String)),
        ("message", optional(HostTypeSchema::String)),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentToolEnvelope,
    "AgentToolEnvelope",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", optional(HostTypeSchema::String)),
        ("token", optional(HostTypeSchema::String)),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);

named_struct!(
    AgentFsReadResult,
    "AgentFsReadResult",
    [
        ("ok", HostTypeSchema::Bool),
        ("kind", HostTypeSchema::String),
        ("bytes", optional(HostTypeSchema::Bytes)),
        ("len", optional(HostTypeSchema::Int)),
        ("error", optional(named::<AgentCapabilityError>()))
    ]
);
