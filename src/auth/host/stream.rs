//! Thin typed guest binding for the accepted sanitized authenticated reader.
//!
//! This is the resource host seam only. `oauth.stream` privately owns the
//! accepted `SanitizedAccessSseStream` plus its `Owner`. Networking, SSE
//! framing, sanitization, Authorization injection and the incremental reader
//! all live in the existing Core/`oauth` layers; this module only maps the
//! fixed guest start/read/close records onto them. Provider event meaning,
//! terminal-marker semantics and every retry/refresh/fallback decision remain
//! RSS work.

use std::sync::{Arc, Mutex};

use rustscript_vm::resource::{CloseProgress, HostResource, ResourceCloseReason, ResourceResult};
use rustscript_vm::{
    CallOutcome, HostFunctionDescriptor, HostParamPassing, HostParamSchema, HostResourceType,
    HostResourceTypeMeta, HostTypeSchema, ResourceTypeKey, Value, Vm, VmResult,
};

use crate::auth::oauth::sanitized_sse::{SanitizedAccessSseStream, SanitizedSseRecord};

use super::flow;
use super::{
    Bound, Owner, OwnerResource, TransportCredential, admit_transport, array, borrow, desc, error,
    field, handle, issue, key, named, object, opt, param, policy_owner, policy_owner_for_cleanup,
    result, string, transport_credential, transport_request_type, transport_use_type,
};

/// Host-private stream resource. The accepted reader is owned through interior
/// synchronization so the guest only ever sees the opaque key.
pub(super) struct Stream {
    owner: Arc<Owner>,
    state: Mutex<StreamState>,
}

struct StreamState {
    reader: Option<SanitizedAccessSseStream>,
    /// Completion fact only: true once the reader observed terminal EOF.
    eof: bool,
}

enum StreamRecord {
    Json(String),
    Literal(usize),
    Eof,
}

impl StreamState {
    fn read(&mut self) -> Result<StreamRecord, crate::auth::oauth::OAuthError> {
        if self.eof {
            return Ok(StreamRecord::Eof);
        }
        let Some(reader) = self.reader.as_mut() else {
            return Ok(StreamRecord::Eof);
        };
        match reader.read_record() {
            Ok(Some(SanitizedSseRecord::Json(text))) => Ok(StreamRecord::Json(text)),
            Ok(Some(SanitizedSseRecord::Literal(index))) => Ok(StreamRecord::Literal(index)),
            Ok(None) => {
                self.eof = true;
                if let Some(reader) = self.reader.as_mut() {
                    reader.cancel();
                }
                Ok(StreamRecord::Eof)
            }
            Err(failure) => Err(failure),
        }
    }

    fn cancel(&mut self) {
        if let Some(mut reader) = self.reader.take() {
            reader.cancel();
        }
    }
}

impl Stream {
    fn cancel_reader(&self) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .cancel();
    }
}

impl HostResource for Stream {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(Self::KEY).expect("static resource key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        self.cancel_reader();
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for Stream {
    const KEY: &'static str = "oauth.stream";
    const DESCRIPTION: &'static str = "Sanitized authenticated incremental stream";
}

impl OwnerResource for Stream {
    fn owner(&self) -> Arc<Owner> {
        self.owner.clone()
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.cancel_reader();
    }
}

fn head_type() -> HostTypeSchema {
    named(
        "OAuthStreamHead",
        vec![
            ("status", HostTypeSchema::Int),
            ("content_type", HostTypeSchema::String),
            ("retry_after_ms", opt(HostTypeSchema::Int)),
        ],
    )
}

fn stream_envelope_type() -> HostTypeSchema {
    named(
        "OAuthStreamEnvelope",
        vec![("head", head_type()), ("stream", key(Stream::KEY))],
    )
}

fn record_type() -> HostTypeSchema {
    named(
        "OAuthStreamRecord",
        vec![
            ("kind", HostTypeSchema::String),
            ("json", HostTypeSchema::String),
            ("literal_index", opt(HostTypeSchema::Int)),
        ],
    )
}

pub(super) fn stream_start_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::stream_start_result",
        vec![
            borrow("request", transport_request_type()),
            borrow("credential_use", transport_use_type()),
            param("public_markers", array(HostTypeSchema::String)),
        ],
        super::fallible::result_type("OAuthStreamStartResultEnvelope", stream_envelope_type()),
        stream_start_result_call,
    )
}

pub(super) fn stream_read_result_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::stream_read_result",
        vec![borrow("stream", key(Stream::KEY))],
        super::fallible::result_type("OAuthStreamReadResultEnvelope", record_type()),
        stream_read_result_call,
    )
}

pub(super) fn stream_close_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::stream_close",
        vec![HostParamSchema::with_passing(
            "stream",
            key(Stream::KEY),
            HostParamPassing::TakeOwned,
        )],
        HostTypeSchema::Null,
        stream_close_call,
    )
}

pub(super) fn stream_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<Stream>()
}

fn stream_start_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let request = args.first().ok_or_else(|| error("invalid_request"))?;
    let policy = field(request, "policy_handle")?;
    let owner = policy_owner_for_cleanup(vm, policy)?;
    let outcome = stream_start_call(vm, args);
    super::fallible::wrap_value(owner, outcome)
}

fn stream_start_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let request = args.first().ok_or_else(|| error("invalid_request"))?;
    let usage = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let markers = args.get(2).ok_or_else(|| error("invalid_request"))?;
    let id = string(field(request, "credential_id")?)?;
    let owner = policy_owner(vm, field(request, "policy_handle")?, id)?;
    let credential = transport_credential(vm, usage, &owner, id)?;
    // Only the one-shot access credential may open a sanitized stream.
    let TransportCredential::Access(_, access) = &credential else {
        return Err(error("credential_use_unsupported"));
    };
    let access = access.clone();
    let Value::Array(marker_values) = markers else {
        return Err(error("invalid_request"));
    };
    let mut public_markers = Vec::with_capacity(marker_values.len());
    for marker in marker_values.iter() {
        public_markers.push(string(marker)?.to_owned());
    }
    let (oauth, policy, public_request) = admit_transport(vm, &owner, &credential, request, id)?;
    let started = oauth.start_access_sse_scoped(
        &policy,
        public_request,
        access,
        flow::owner_cancellation(&owner),
        public_markers,
    );
    // A local admission failure keeps the live resource retryable; once the
    // store entry is terminal the Core alias is closed even on start errors.
    let closed = credential.close_if_terminal(vm);
    let owner_inactive = owner.check().is_err();
    let reader = match started {
        Ok(reader) => {
            if let Err(failure) = closed {
                let mut reader = reader;
                reader.cancel();
                return Err(failure);
            }
            reader
        }
        Err(failure) => {
            return Err(if failure.code() == "cancelled" && owner_inactive {
                error("policy_inactive")
            } else {
                error(failure.code())
            });
        }
    };
    if let Err(failure) = owner.check() {
        let mut reader = reader;
        reader.cancel();
        return Err(failure);
    }
    let (status, content_type, retry_after_ms) = {
        let head = reader.head();
        (head.status, head.content_type.clone(), head.retry_after_ms)
    };
    let stream = issue(
        vm,
        Stream {
            owner: owner.clone(),
            state: Mutex::new(StreamState {
                reader: Some(reader),
                eof: false,
            }),
        },
    )?;
    if let Err(failure) = owner.check() {
        if let Ok(handle) = handle(&stream) {
            let _ = vm
                .host_context()
                .close_resource::<Stream>(handle, ResourceCloseReason::Requested);
        }
        return Err(failure);
    }
    result(object(vec![
        (
            "head",
            object(vec![
                ("status", Value::Int(i64::from(status))),
                ("content_type", Value::string(content_type)),
                (
                    "retry_after_ms",
                    retry_after_ms
                        .and_then(|n| i64::try_from(n).ok())
                        .map(Value::Int)
                        .unwrap_or(Value::Null),
                ),
            ]),
        ),
        ("stream", stream),
    ]))
}

/// Resource-key + bound-owner validation without an active-owner check, so a
/// completed EOF survives later cancellation or revocation.
fn stream_owner(vm: &mut Vm, value: &Value) -> VmResult<Arc<Owner>> {
    let context = vm.host_context();
    let entry = context
        .borrow_resource_with_key::<Stream>(
            handle(value)?,
            &ResourceTypeKey::new(Stream::KEY).expect("static key"),
        )
        .map_err(|_| error("resource_invalid"))?;
    let owner = entry.owner();
    let bound = context
        .scope_state::<Bound>()
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(&owner, &bound.0) {
        return Err(error("owner_mismatch"));
    }
    Ok(owner)
}

fn stream_read_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let value = args.first().ok_or_else(|| error("invalid_request"))?;
    let owner = stream_owner(vm, value)?;
    let outcome = stream_read_call(vm, args);
    super::fallible::wrap_value(owner, outcome)
}

fn stream_read_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let value = args.first().ok_or_else(|| error("invalid_request"))?;
    let record = {
        let context = vm.host_context();
        let entry = context
            .borrow_resource_with_key::<Stream>(
                handle(value)?,
                &ResourceTypeKey::new(Stream::KEY).expect("static key"),
            )
            .map_err(|_| error("resource_invalid"))?;
        let owner = entry.owner();
        let bound = context
            .scope_state::<Bound>()
            .ok_or_else(|| error("host_unbound"))?;
        if !Arc::ptr_eq(&owner, &bound.0) {
            return Err(error("owner_mismatch"));
        }
        let mut state = entry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Terminal EOF is a completion fact that active cancellation cannot
        // undo; only a still-active stream revalidates the owner.
        if state.eof {
            StreamRecord::Eof
        } else {
            if let Err(failure) = owner.check() {
                state.cancel();
                return Err(failure);
            }
            match state.read() {
                Ok(record) => record,
                Err(failure) => {
                    state.cancel();
                    return Err(error(failure.code()));
                }
            }
        }
    };
    result(record_value(record))
}

fn record_value(record: StreamRecord) -> Value {
    match record {
        StreamRecord::Json(json) => object(vec![
            ("kind", Value::string("json")),
            ("json", Value::string(json)),
            ("literal_index", Value::Null),
        ]),
        StreamRecord::Literal(index) => object(vec![
            ("kind", Value::string("literal")),
            ("json", Value::string("")),
            (
                "literal_index",
                i64::try_from(index).map(Value::Int).unwrap_or(Value::Null),
            ),
        ]),
        StreamRecord::Eof => object(vec![
            ("kind", Value::string("eof")),
            ("json", Value::string("")),
            ("literal_index", Value::Null),
        ]),
    }
}

fn stream_close_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let value = args.first().ok_or_else(|| error("invalid_request"))?;
    stream_owner(vm, value)?;
    vm.host_context()
        .close_resource::<Stream>(handle(value)?, ResourceCloseReason::Requested)
        .map_err(|_| error("resource_invalid"))?;
    result(Value::Null)
}
