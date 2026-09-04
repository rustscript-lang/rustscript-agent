//! Bounded native RSS host bridge for the serial provider/tool loop.
//!
//! `rss/agent/main.rss` builds canonical requests and dispatches tools only
//! through these host functions. Provider adapters stay in RSS; this module
//! does not add an OpenAI-compatible inference path.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustscript_vm::{
    CallOutcome, CallReturn, CancellationReason, HostApiBuilder, HostApiCatalog,
    HostFunctionRegistry, HostFunctionSchema, HostParamSchema, HostTypeSchema, Value, Vm, VmError,
    VmResult, catalog_import_schemas, standard_host_catalog,
};
use serde_json::{Value as JsonValue, json};

use super::rss_runner::RunCancellation;
use crate::capabilities::{
    ArtifactCapability, CapabilityError, CapabilityLifecycle, CapabilityOwner, CapabilityRisk,
    ExecutionLease, FilesystemCapability, FsRead, LifecycleError, ProcessCapability, ProcessLimits,
    ProcessSnapshot, capability_error_envelope, parse_prepare_metadata, tool_commit, tool_prepare,
};
use crate::domain::{ToolCall, json_to_vm_value, vm_value_to_json};
use crate::metrics::Metrics;
use crate::tools::{DispatchContext, ToolResult};

const PROVIDER_CALL: &str = "agent::provider_call";
const TOOL_DISPATCH: &str = "agent::tool_dispatch";
const SLEEP_MS: &str = "agent::sleep_ms";
const CONTROL_CHECK: &str = "agent::control_check";
const TOOL_PREPARE: &str = "agent_runtime::tool_prepare";
const TOOL_COMMIT: &str = "agent_runtime::tool_commit";
const CAP_FS_METADATA: &str = "cap::fs_metadata";
const CAP_FS_READ_RANGE: &str = "cap::fs_read_range";
const CAP_FS_LIST: &str = "cap::fs_list";
const CAP_FS_WRITE_ATOMIC: &str = "cap::fs_write_atomic";
const CAP_PROCESS_SPAWN: &str = "cap::process_spawn";
const CAP_PROCESS_POLL: &str = "cap::process_poll";
const CAP_PROCESS_WAIT: &str = "cap::process_wait";
const CAP_PROCESS_LOG: &str = "cap::process_log";
const CAP_PROCESS_WRITE: &str = "cap::process_write";
const CAP_PROCESS_CLOSE: &str = "cap::process_close";
const CAP_PROCESS_KILL: &str = "cap::process_kill";
const CAP_ARTIFACT_PUT: &str = "cap::artifact_put";
const CAP_ARTIFACT_PUT_RESULT: &str = "cap::artifact_put_result";
const CAP_ARTIFACT_GET: &str = "cap::artifact_get";
const CAP_ARTIFACT_REFERENCE: &str = "cap::artifact_reference";
const CAP_CLOCK_MONOTONIC_MS: &str = "cap::clock_monotonic_ms";

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
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            TOOL_PREPARE,
            vec![HostParamSchema::value("metadata", HostTypeSchema::Unknown)],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            TOOL_COMMIT,
            vec![
                HostParamSchema::value("execution_token", HostTypeSchema::String),
                HostParamSchema::value("result", HostTypeSchema::Unknown),
            ],
            response.clone(),
        ));
        let token = HostParamSchema::value("execution_token", HostTypeSchema::String);
        let path = HostParamSchema::value("path", HostTypeSchema::String);
        let handle = HostParamSchema::value("handle", HostTypeSchema::String);
        let offset = HostParamSchema::value("offset", HostTypeSchema::Int);
        let limit = HostParamSchema::value("limit", HostTypeSchema::Int);
        let cursor = HostParamSchema::value("cursor", HostTypeSchema::Int);
        builder.function(HostFunctionSchema::with_return(
            CAP_FS_METADATA,
            vec![token.clone(), path.clone()],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_FS_READ_RANGE,
            vec![token.clone(), path.clone(), offset, limit.clone()],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_FS_LIST,
            vec![token.clone(), path.clone(), cursor.clone(), limit.clone()],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_FS_WRITE_ATOMIC,
            vec![
                token.clone(),
                path,
                HostParamSchema::value("expected_hash", HostTypeSchema::String),
                HostParamSchema::value("bytes", HostTypeSchema::Unknown),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_PROCESS_SPAWN,
            vec![
                token.clone(),
                HostParamSchema::value(
                    "argv",
                    HostTypeSchema::Array(Box::new(HostTypeSchema::String)),
                ),
                HostParamSchema::value("cwd", HostTypeSchema::String),
                HostParamSchema::value(
                    "env_names",
                    HostTypeSchema::Array(Box::new(HostTypeSchema::String)),
                ),
                HostParamSchema::value("limits", HostTypeSchema::Unknown),
                HostParamSchema::value("stdin", HostTypeSchema::Unknown),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_PROCESS_POLL,
            vec![token.clone(), handle.clone(), cursor.clone(), limit.clone()],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_PROCESS_WAIT,
            vec![
                token.clone(),
                handle.clone(),
                HostParamSchema::value("timeout_ms", HostTypeSchema::Int),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_PROCESS_LOG,
            vec![token.clone(), handle.clone(), cursor, limit],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_PROCESS_WRITE,
            vec![
                token.clone(),
                handle.clone(),
                HostParamSchema::value("bytes", HostTypeSchema::Unknown),
                HostParamSchema::value("timeout_ms", HostTypeSchema::Int),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_PROCESS_CLOSE,
            vec![token.clone(), handle.clone()],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_PROCESS_KILL,
            vec![token.clone(), handle],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_ARTIFACT_PUT,
            vec![
                token.clone(),
                HostParamSchema::value("bytes", HostTypeSchema::Unknown),
                HostParamSchema::value("metadata", HostTypeSchema::Unknown),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_ARTIFACT_PUT_RESULT,
            vec![
                token.clone(),
                HostParamSchema::value("bytes", HostTypeSchema::Unknown),
                HostParamSchema::value("metadata", HostTypeSchema::Unknown),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_ARTIFACT_GET,
            vec![
                token.clone(),
                HostParamSchema::value("id", HostTypeSchema::String),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_ARTIFACT_REFERENCE,
            vec![
                token.clone(),
                HostParamSchema::value("id", HostTypeSchema::String),
            ],
            response.clone(),
        ));
        builder.function(HostFunctionSchema::with_return(
            CAP_CLOCK_MONOTONIC_MS,
            vec![token],
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

pub type ControlCheckHook = Arc<dyn Fn(&RunCancellation) + Send + Sync>;

/// Injectable host bridges for one compiled runner.
#[derive(Clone, Default)]
pub struct AgentHostBridges {
    pub provider: Option<Arc<dyn AgentProviderHost>>,
    pub dispatcher: Option<Arc<DispatchContext>>,
    /// Shared with the runner invocation; never an independent cancellation root.
    pub cancellation: Option<RunCancellation>,
    pub sleeps: Arc<Mutex<SleepLog>>,
    pub skip_sleep: bool,
    pub metrics: Option<Arc<Metrics>>,
    pub lifecycle: Option<Arc<CapabilityLifecycle>>,
    pub capability_owner: Option<CapabilityOwner>,
    pub filesystem: Option<Arc<FilesystemCapability>>,
    pub processes: Option<Arc<ProcessCapability>>,
    pub artifacts: Option<Arc<ArtifactCapability>>,
    /// Optional test hook invoked from `agent::control_check` before reading
    /// cancellation/deadline. Production callers leave this unset.
    pub control_hook: Option<ControlCheckHook>,
}

/// Per-VM state installed before `run(context)`.
#[derive(Clone)]
pub struct AgentHostState {
    pub provider: Arc<dyn AgentProviderHost>,
    pub dispatcher: Option<Arc<DispatchContext>>,
    pub cancellation: RunCancellation,
    pub sleeps: Arc<Mutex<SleepLog>>,
    pub skip_sleep: bool,
    pub metrics: Option<Arc<Metrics>>,
    pub lifecycle: Option<Arc<CapabilityLifecycle>>,
    pub capability_owner: Option<CapabilityOwner>,
    pub filesystem: Option<Arc<FilesystemCapability>>,
    pub processes: Option<Arc<ProcessCapability>>,
    pub artifacts: Option<Arc<ArtifactCapability>>,
    pub(crate) leases: Arc<Mutex<HashMap<String, ExecutionLease>>>,
    pub(crate) control_hook: Option<ControlCheckHook>,
}

impl AgentHostState {
    fn control_error(&self) -> Option<JsonValue> {
        if let Some(hook) = &self.control_hook {
            hook(&self.cancellation);
        }
        if let Some(reason) = self.cancellation.requested() {
            return Some(match reason {
                CancellationReason::Deadline => {
                    typed_fail("deadline_elapsed", "run deadline elapsed")
                }
                _ => typed_fail("cancelled", "run was cancelled"),
            });
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

    fn capability_prepare(&self, metadata: &JsonValue) -> JsonValue {
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return crate::capabilities::host::error_envelope(&LifecycleError::InvalidMetadata(
                "capability lifecycle is not installed".to_string(),
            ));
        };
        let Some(owner) = self.capability_owner.as_ref() else {
            return crate::capabilities::host::error_envelope(&LifecycleError::InvalidMetadata(
                "capability owner is not installed".to_string(),
            ));
        };
        let envelope = match parse_prepare_metadata(metadata) {
            Ok(metadata) => tool_prepare(lifecycle, owner, metadata),
            Err(error) => return crate::capabilities::host::error_envelope(&error),
        };
        if envelope.get("ok") == Some(&JsonValue::Bool(true))
            && envelope.get("kind") == Some(&JsonValue::String("execute".to_string()))
            && let Some(token) = envelope.get("execution_token").and_then(JsonValue::as_str)
            && let Ok(lease) = lifecycle.lease(token)
        {
            self.leases
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(token.to_string(), lease);
        }
        envelope
    }

    fn capability_commit(&self, token: &str, result: &JsonValue) -> JsonValue {
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return crate::capabilities::host::error_envelope(&LifecycleError::InvalidMetadata(
                "capability lifecycle is not installed".to_string(),
            ));
        };
        let Some(owner) = self.capability_owner.as_ref() else {
            return crate::capabilities::host::error_envelope(&LifecycleError::InvalidMetadata(
                "capability owner is not installed".to_string(),
            ));
        };
        let envelope = tool_commit(lifecycle, owner, token, result.clone());
        let Some(mut lease) = self
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(token)
        else {
            return envelope;
        };
        if envelope.get("ok") == Some(&JsonValue::Bool(true)) {
            lease.disarm();
        }
        envelope
    }

    fn missing_capability(name: &str) -> JsonValue {
        capability_error_envelope(&CapabilityError::new(
            "invalid_metadata",
            format!("{name} capability is not installed"),
        ))
    }

    fn cap_fs_metadata(&self, token: String, path: String) -> JsonValue {
        let Some(fs) = self.filesystem.as_ref() else {
            return Self::missing_capability("filesystem");
        };
        match fs.metadata(&token, &path) {
            Ok(meta) => json!({
                "ok": true,
                "kind": "fs_metadata",
                "file_type": meta.file_type,
                "len": meta.len,
            }),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_fs_read_range(&self, token: String, path: String, offset: u64, limit: usize) -> Value {
        let Some(fs) = self.filesystem.as_ref() else {
            return json_to_vm_value(&Self::missing_capability("filesystem"));
        };
        match fs.read_range(&token, &path, offset, limit) {
            Ok(read) => fs_read_value(read),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        }
    }

    fn cap_fs_list(&self, token: String, path: String, cursor: u64, limit: usize) -> JsonValue {
        let Some(fs) = self.filesystem.as_ref() else {
            return Self::missing_capability("filesystem");
        };
        match fs.list(&token, &path, cursor, limit) {
            Ok(list) => json!({
                "ok": true,
                "kind": "fs_list",
                "cursor": list.cursor,
                "next_cursor": list.next_cursor,
                "truncated": list.truncated,
                "entries": list.entries.iter().map(|entry| json!({
                    "name": entry.name,
                    "file_type": entry.file_type,
                    "len": entry.len,
                })).collect::<Vec<_>>(),
            }),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_fs_write_atomic(
        &self,
        token: String,
        path: String,
        expected_hash: String,
        bytes: Vec<u8>,
    ) -> JsonValue {
        let Some(fs) = self.filesystem.as_ref() else {
            return Self::missing_capability("filesystem");
        };
        match fs.write_atomic(&token, &path, &expected_hash, &bytes) {
            Ok(write) => json!({
                "ok": true,
                "kind": "fs_write",
                "hash": write.hash,
                "len": write.len,
                "durable": write.durable,
                "staging_cleaned": write.staging_cleaned,
            }),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_process_spawn(
        &self,
        token: String,
        argv: Vec<String>,
        cwd: String,
        env_names: Vec<String>,
        limits: ProcessLimits,
        stdin: Vec<u8>,
    ) -> JsonValue {
        let Some(processes) = self.processes.as_ref() else {
            return Self::missing_capability("process");
        };
        let stdin = if stdin.is_empty() {
            None
        } else {
            Some(stdin.as_slice())
        };
        match processes.spawn_with(&token, &argv, &cwd, &env_names, limits, stdin) {
            Ok(spawned) => json!({
                "ok": true,
                "kind": "process_spawn",
                "handle": spawned.handle,
                "pid": spawned.pid,
            }),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_process_poll(&self, token: String, handle: String, cursor: u64, limit: usize) -> Value {
        let Some(processes) = self.processes.as_ref() else {
            return json_to_vm_value(&Self::missing_capability("process"));
        };
        match processes.poll(&token, &handle, cursor, limit) {
            Ok(snapshot) => process_snapshot_value("process_poll", &snapshot),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        }
    }

    fn cap_process_wait(&self, token: String, handle: String, timeout_ms: Option<u64>) -> Value {
        let Some(processes) = self.processes.as_ref() else {
            return json_to_vm_value(&Self::missing_capability("process"));
        };
        match processes.wait(&token, &handle, timeout_ms) {
            Ok(snapshot) => process_snapshot_value("process_wait", &snapshot),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        }
    }

    fn cap_process_log(&self, token: String, handle: String, cursor: u64, limit: usize) -> Value {
        let Some(processes) = self.processes.as_ref() else {
            return json_to_vm_value(&Self::missing_capability("process"));
        };
        match processes.log(&token, &handle, cursor, limit) {
            Ok(snapshot) => process_snapshot_value("process_log", &snapshot),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        }
    }

    fn cap_process_write(
        &self,
        token: String,
        handle: String,
        bytes: Vec<u8>,
        timeout_ms: Option<u64>,
    ) -> JsonValue {
        let Some(processes) = self.processes.as_ref() else {
            return Self::missing_capability("process");
        };
        match processes.write_stdin(&token, &handle, &bytes, timeout_ms) {
            Ok(wrote_bytes) => {
                json!({"ok": true, "kind": "process_write", "wrote_bytes": wrote_bytes})
            }
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_process_close(&self, token: String, handle: String) -> JsonValue {
        let Some(processes) = self.processes.as_ref() else {
            return Self::missing_capability("process");
        };
        match processes.close_stdin(&token, &handle) {
            Ok(()) => json!({"ok": true, "kind": "process_close"}),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_process_kill(&self, token: String, handle: String) -> JsonValue {
        let Some(processes) = self.processes.as_ref() else {
            return Self::missing_capability("process");
        };
        match processes.kill(&token, &handle) {
            Ok(()) => json!({"ok": true, "kind": "process_kill"}),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_artifact_put(&self, token: String, bytes: Vec<u8>, metadata: Value) -> JsonValue {
        let Some(artifacts) = self.artifacts.as_ref() else {
            return Self::missing_capability("artifact");
        };
        let json_meta = vm_value_to_json(&metadata);
        match artifacts.put(&token, &bytes, &json_meta) {
            Ok(refer) => json!({
                "ok": true,
                "kind": "artifact_put",
                "id": refer.id,
                "len": refer.len,
                "hash": refer.hash,
                "metadata": refer.metadata,
            }),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_artifact_put_result(&self, token: String, bytes: Vec<u8>, metadata: Value) -> JsonValue {
        let Some(artifacts) = self.artifacts.as_ref() else {
            return Self::missing_capability("artifact");
        };
        let json_meta = vm_value_to_json(&metadata);
        match artifacts.put_result(&token, &bytes, &json_meta) {
            Ok(refer) => json!({
                "ok": true,
                "kind": "artifact_put_result",
                "id": refer.id,
                "len": refer.len,
                "hash": refer.hash,
                "metadata": refer.metadata,
            }),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_clock_monotonic_ms(&self, token: String) -> JsonValue {
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return Self::missing_capability("lifecycle");
        };
        let Some(owner) = self.capability_owner.as_ref() else {
            return Self::missing_capability("lifecycle");
        };
        match lifecycle.authorize(owner, &token, CapabilityRisk::Read) {
            Ok(_) => match lifecycle.monotonic_ms() {
                Some(ms) if ms <= i64::MAX as u64 => json!({
                    "ok": true,
                    "kind": "clock_monotonic",
                    "ms": ms,
                }),
                _ => capability_error_envelope(&CapabilityError::new(
                    "internal_error",
                    "monotonic clock overflow",
                )),
            },
            Err(error) => {
                let error = CapabilityError::from(error);
                json!({
                    "ok": false,
                    "kind": "error",
                    "code": error.code(),
                    "message": error.message(),
                    "error": {
                        "code": error.code(),
                        "message": error.message(),
                    }
                })
            }
        }
    }

    fn cap_artifact_get(&self, token: String, id: String) -> Value {
        let Some(artifacts) = self.artifacts.as_ref() else {
            return json_to_vm_value(&Self::missing_capability("artifact"));
        };
        match artifacts.get(&token, &id) {
            Ok(bytes) => Value::map(vec![
                (Value::string("ok"), Value::Bool(true)),
                (Value::string("kind"), Value::string("artifact_get")),
                (
                    Value::string("len"),
                    Value::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
                ),
                (Value::string("bytes"), Value::bytes(bytes)),
            ]),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        }
    }

    fn cap_artifact_reference(&self, token: String, id: String) -> JsonValue {
        let Some(artifacts) = self.artifacts.as_ref() else {
            return Self::missing_capability("artifact");
        };
        match artifacts.reference(&token, &id) {
            Ok(refer) => json!({
                "ok": true,
                "kind": "artifact_reference",
                "id": refer.id,
                "len": refer.len,
                "hash": refer.hash,
                "metadata": refer.metadata,
            }),
            Err(error) => capability_error_envelope(&error),
        }
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
        if let Some(metrics) = &self.metrics
            && !result.replayed
        {
            metrics.account_tool_attempt(!result.ok, result.truncated);
        }
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
    register_named(registry, catalog, TOOL_PREPARE, 1, tool_prepare_adapter)?;
    register_named(registry, catalog, TOOL_COMMIT, 2, tool_commit_adapter)?;
    register_named(
        registry,
        catalog,
        CAP_FS_METADATA,
        2,
        cap_fs_metadata_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_FS_READ_RANGE,
        4,
        cap_fs_read_range_adapter,
    )?;
    register_named(registry, catalog, CAP_FS_LIST, 4, cap_fs_list_adapter)?;
    register_named(
        registry,
        catalog,
        CAP_FS_WRITE_ATOMIC,
        4,
        cap_fs_write_atomic_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_PROCESS_SPAWN,
        6,
        cap_process_spawn_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_PROCESS_POLL,
        4,
        cap_process_poll_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_PROCESS_WAIT,
        3,
        cap_process_wait_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_PROCESS_LOG,
        4,
        cap_process_log_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_PROCESS_WRITE,
        4,
        cap_process_write_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_PROCESS_CLOSE,
        2,
        cap_process_close_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_PROCESS_KILL,
        2,
        cap_process_kill_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_ARTIFACT_PUT,
        3,
        cap_artifact_put_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_ARTIFACT_PUT_RESULT,
        3,
        cap_artifact_put_result_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_ARTIFACT_GET,
        2,
        cap_artifact_get_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_ARTIFACT_REFERENCE,
        2,
        cap_artifact_reference_adapter,
    )?;
    register_named(
        registry,
        catalog,
        CAP_CLOCK_MONOTONIC_MS,
        1,
        cap_clock_monotonic_ms_adapter,
    )?;
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

fn tool_prepare_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let metadata = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    return_json(state.capability_prepare(&vm_value_to_json(&metadata)))
}

fn tool_commit_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let token = match args.first() {
        Some(Value::String(value)) => value.to_string(),
        _ => String::new(),
    };
    let result = args.get(1).cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    return_json(state.capability_commit(&token, &vm_value_to_json(&result)))
}

fn cap_fs_metadata_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "path")?,
            ))
        },
        |(token, path)| return_json(state.cap_fs_metadata(token, path)),
    )
}

fn cap_fs_read_range_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "path")?,
                arg_u64(args, 2, "offset")?,
                arg_positive_usize(args, 3, "limit")?,
            ))
        },
        |(token, path, offset, limit)| {
            return_value(state.cap_fs_read_range(token, path, offset, limit))
        },
    )
}

fn cap_fs_list_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "path")?,
                arg_u64(args, 2, "cursor")?,
                arg_positive_usize(args, 3, "limit")?,
            ))
        },
        |(token, path, cursor, limit)| return_json(state.cap_fs_list(token, path, cursor, limit)),
    )
}

fn cap_fs_write_atomic_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "path")?,
                arg_string(args, 2, "expected_hash")?,
                arg_bytes(args, 3, "bytes")?,
            ))
        },
        |(token, path, expected_hash, bytes)| {
            return_json(state.cap_fs_write_atomic(token, path, expected_hash, bytes))
        },
    )
}

fn cap_process_spawn_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string_list(args, 1, "argv")?,
                arg_string(args, 2, "cwd")?,
                arg_string_list(args, 3, "env_names")?,
                arg_process_limits(args.get(4))?,
                arg_bytes(args, 5, "stdin")?,
            ))
        },
        |(token, argv, cwd, env_names, limits, stdin)| {
            return_json(state.cap_process_spawn(token, argv, cwd, env_names, limits, stdin))
        },
    )
}

fn cap_process_poll_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "handle")?,
                arg_u64(args, 2, "cursor")?,
                arg_positive_usize(args, 3, "limit")?,
            ))
        },
        |(token, handle, cursor, limit)| {
            return_value(state.cap_process_poll(token, handle, cursor, limit))
        },
    )
}

fn cap_process_wait_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "handle")?,
                arg_timeout(args, 2, "timeout_ms")?,
            ))
        },
        |(token, handle, timeout_ms)| {
            return_value(state.cap_process_wait(token, handle, timeout_ms))
        },
    )
}

fn cap_process_log_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "handle")?,
                arg_u64(args, 2, "cursor")?,
                arg_positive_usize(args, 3, "limit")?,
            ))
        },
        |(token, handle, cursor, limit)| {
            return_value(state.cap_process_log(token, handle, cursor, limit))
        },
    )
}

fn cap_process_write_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "handle")?,
                arg_bytes(args, 2, "bytes")?,
                arg_timeout(args, 3, "timeout_ms")?.filter(|ms| *ms > 0),
            ))
        },
        |(token, handle, bytes, timeout_ms)| {
            return_json(state.cap_process_write(token, handle, bytes, timeout_ms))
        },
    )
}

fn cap_process_close_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "handle")?,
            ))
        },
        |(token, handle)| return_json(state.cap_process_close(token, handle)),
    )
}

fn cap_process_kill_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "handle")?,
            ))
        },
        |(token, handle)| return_json(state.cap_process_kill(token, handle)),
    )
}

fn cap_artifact_put_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_bytes(args, 1, "bytes")?,
                args.get(2).cloned().unwrap_or(Value::Null),
            ))
        },
        |(token, bytes, metadata)| return_json(state.cap_artifact_put(token, bytes, metadata)),
    )
}

fn cap_artifact_put_result_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_bytes(args, 1, "bytes")?,
                args.get(2).cloned().unwrap_or(Value::Null),
            ))
        },
        |(token, bytes, metadata)| {
            return_json(state.cap_artifact_put_result(token, bytes, metadata))
        },
    )
}

fn cap_clock_monotonic_ms_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || arg_string(args, 0, "execution_token"),
        |token| return_json(state.cap_clock_monotonic_ms(token)),
    )
}

fn cap_artifact_get_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "id")?,
            ))
        },
        |(token, id)| return_value(state.cap_artifact_get(token, id)),
    )
}

fn cap_artifact_reference_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    decode_then(
        || {
            Ok((
                arg_string(args, 0, "execution_token")?,
                arg_string(args, 1, "id")?,
            ))
        },
        |(token, id)| return_json(state.cap_artifact_reference(token, id)),
    )
}

fn installed_state(vm: &mut Vm) -> VmResult<AgentHostState> {
    vm.host_context()
        .module_state::<AgentHostState>()
        .cloned()
        .ok_or_else(|| VmError::HostError("agent host state is not installed".to_string()))
}

fn return_json(value: JsonValue) -> VmResult<CallOutcome> {
    return_value(json_to_vm_value(&value))
}

fn return_value(value: Value) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::One(value)))
}

fn decode_then<T>(
    decode: impl FnOnce() -> Result<T, JsonValue>,
    then: impl FnOnce(T) -> VmResult<CallOutcome>,
) -> VmResult<CallOutcome> {
    match decode() {
        Ok(value) => then(value),
        Err(error) => return_json(error),
    }
}

fn invalid_request(message: impl Into<String>) -> JsonValue {
    capability_error_envelope(&CapabilityError::new("invalid_request", message.into()))
}

fn fs_read_value(read: FsRead) -> Value {
    let mut fields = vec![
        (Value::string("ok"), Value::Bool(true)),
        (Value::string("kind"), Value::string("fs_read")),
        (
            Value::string("offset"),
            Value::Int(i64::try_from(read.offset).unwrap_or(i64::MAX)),
        ),
        (Value::string("truncated"), Value::Bool(read.truncated)),
        (
            Value::string("len"),
            Value::Int(i64::try_from(read.bytes.len()).unwrap_or(i64::MAX)),
        ),
        (Value::string("bytes"), Value::bytes(read.bytes)),
    ];
    if let Some(hash) = read.hash {
        fields.push((Value::string("hash"), Value::string(hash)));
    }
    Value::map(fields)
}

fn arg_string(args: &[Value], index: usize, name: &str) -> Result<String, JsonValue> {
    match args.get(index) {
        Some(Value::String(value)) => Ok(value.to_string()),
        _ => Err(invalid_request(format!("{name} must be a string"))),
    }
}

fn arg_u64(args: &[Value], index: usize, name: &str) -> Result<u64, JsonValue> {
    match args.get(index) {
        Some(Value::Int(value)) => u64::try_from(*value)
            .map_err(|_| invalid_request(format!("{name} must be a non-negative integer"))),
        _ => Err(invalid_request(format!(
            "{name} must be a non-negative integer"
        ))),
    }
}

fn arg_usize(args: &[Value], index: usize, name: &str) -> Result<usize, JsonValue> {
    usize::try_from(arg_u64(args, index, name)?)
        .map_err(|_| invalid_request(format!("{name} is out of range")))
}

fn arg_positive_usize(args: &[Value], index: usize, name: &str) -> Result<usize, JsonValue> {
    let value = arg_usize(args, index, name)?;
    if value == 0 {
        return Err(invalid_request(format!("{name} must be positive")));
    }
    Ok(value)
}

fn arg_timeout(args: &[Value], index: usize, name: &str) -> Result<Option<u64>, JsonValue> {
    match args.get(index) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Int(value)) => u64::try_from(*value)
            .map(Some)
            .map_err(|_| invalid_request(format!("{name} must be a non-negative integer"))),
        _ => Err(invalid_request(format!(
            "{name} must be a non-negative integer"
        ))),
    }
}

fn arg_bytes(args: &[Value], index: usize, name: &str) -> Result<Vec<u8>, JsonValue> {
    match args.get(index) {
        Some(Value::Bytes(value)) => Ok(value.as_ref().to_vec()),
        _ => Err(invalid_request(format!("{name} must be bytes"))),
    }
}

fn arg_string_list(args: &[Value], index: usize, name: &str) -> Result<Vec<String>, JsonValue> {
    match args.get(index) {
        Some(Value::Array(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values.iter() {
                match value {
                    Value::String(text) => out.push(text.to_string()),
                    _ => {
                        return Err(invalid_request(format!(
                            "{name} must be an array of strings"
                        )));
                    }
                }
            }
            Ok(out)
        }
        _ => Err(invalid_request(format!(
            "{name} must be an array of strings"
        ))),
    }
}

fn arg_process_limits(value: Option<&Value>) -> Result<ProcessLimits, JsonValue> {
    let mut limits = ProcessLimits::default();
    let JsonValue::Object(fields) = value.map(vm_value_to_json).unwrap_or(JsonValue::Null) else {
        return Err(invalid_request("limits must be a map"));
    };
    if let Some(timeout_ms) = json_u64_field(&fields, "timeout_ms")? {
        limits.timeout_ms = timeout_ms;
    }
    if let Some(stdout_limit) = json_usize_field(&fields, "stdout_limit")? {
        limits.stdout_limit = stdout_limit;
    }
    if let Some(stderr_limit) = json_usize_field(&fields, "stderr_limit")? {
        limits.stderr_limit = stderr_limit;
    }
    if let Some(total_limit) = json_usize_field(&fields, "total_limit")? {
        limits.total_limit = total_limit;
    }
    if let Some(stdin_limit) = json_usize_field(&fields, "stdin_limit")? {
        limits.stdin_limit = stdin_limit;
    }
    if let Some(log_limit) = json_usize_field(&fields, "log_limit")? {
        limits.log_limit = log_limit;
    }
    Ok(limits)
}

fn json_u64_field(
    fields: &serde_json::Map<String, JsonValue>,
    name: &str,
) -> Result<Option<u64>, JsonValue> {
    let Some(value) = fields.get(name) else {
        return Ok(None);
    };
    if let Some(parsed) = value.as_u64() {
        return Ok(Some(parsed));
    }
    if let Some(parsed) = value.as_i64() {
        return u64::try_from(parsed)
            .map(Some)
            .map_err(|_| invalid_request(format!("{name} must be a non-negative integer")));
    }
    Err(invalid_request(format!(
        "{name} must be a non-negative integer"
    )))
}

fn json_usize_field(
    fields: &serde_json::Map<String, JsonValue>,
    name: &str,
) -> Result<Option<usize>, JsonValue> {
    match json_u64_field(fields, name)? {
        Some(parsed) => usize::try_from(parsed)
            .map(Some)
            .map_err(|_| invalid_request(format!("{name} is out of range"))),
        None => Ok(None),
    }
}

fn process_snapshot_value(kind: &str, snapshot: &ProcessSnapshot) -> Value {
    Value::map(vec![
        (Value::string("ok"), Value::Bool(true)),
        (Value::string("kind"), Value::string(kind)),
        (Value::string("handle"), Value::string(&snapshot.handle)),
        (Value::string("running"), Value::Bool(snapshot.running)),
        (
            Value::string("exit_code"),
            snapshot
                .exit_code
                .map(i64::from)
                .map(Value::Int)
                .unwrap_or(Value::Null),
        ),
        (
            Value::string("signal"),
            snapshot
                .signal
                .map(i64::from)
                .map(Value::Int)
                .unwrap_or(Value::Null),
        ),
        (Value::string("stdout"), Value::string(&snapshot.stdout)),
        (Value::string("stderr"), Value::string(&snapshot.stderr)),
        (
            Value::string("stdout_bytes"),
            Value::bytes(snapshot.stdout_bytes.clone()),
        ),
        (
            Value::string("stderr_bytes"),
            Value::bytes(snapshot.stderr_bytes.clone()),
        ),
        (Value::string("truncated"), Value::Bool(snapshot.truncated)),
        (
            Value::string("stdout_offset"),
            Value::Int(i64::try_from(snapshot.stdout_cursor.offset).unwrap_or(i64::MAX)),
        ),
        (
            Value::string("stdout_next_offset"),
            Value::Int(i64::try_from(snapshot.stdout_cursor.next_offset).unwrap_or(i64::MAX)),
        ),
        (
            Value::string("stdout_truncated"),
            Value::Bool(snapshot.stdout_cursor.truncated),
        ),
        (
            Value::string("stdout_gap"),
            Value::Bool(snapshot.stdout_cursor.gap),
        ),
        (
            Value::string("stdout_eof"),
            Value::Bool(snapshot.stdout_cursor.eof),
        ),
        (
            Value::string("stderr_offset"),
            Value::Int(i64::try_from(snapshot.stderr_cursor.offset).unwrap_or(i64::MAX)),
        ),
        (
            Value::string("stderr_next_offset"),
            Value::Int(i64::try_from(snapshot.stderr_cursor.next_offset).unwrap_or(i64::MAX)),
        ),
        (
            Value::string("stderr_truncated"),
            Value::Bool(snapshot.stderr_cursor.truncated),
        ),
        (
            Value::string("stderr_gap"),
            Value::Bool(snapshot.stderr_cursor.gap),
        ),
        (
            Value::string("stderr_eof"),
            Value::Bool(snapshot.stderr_cursor.eof),
        ),
        (Value::string("signaled"), Value::Bool(snapshot.signaled)),
        (Value::string("unknown"), Value::Bool(snapshot.unknown)),
        (
            Value::string("deadline_elapsed"),
            Value::Bool(snapshot.deadline_elapsed),
        ),
        (Value::string("cancelled"), Value::Bool(snapshot.cancelled)),
    ])
}

pub(crate) fn typed_fail(code: &str, message: &str) -> JsonValue {
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

const NON_RETRYABLE_ERROR_CODES: &[&str] = &[
    "setup",
    "config",
    "adapter_unavailable",
    "malformed_payload",
    "scripted_exhausted",
    "cancelled",
    "deadline_elapsed",
    "dispatcher_missing",
    "adapter_failed",
    "unsupported_parallel",
    "unsupported_task",
    "provider_step_persist_failed",
    "interrupted_provider",
    "corrupt_provider_step",
    "run_terminal",
    "missing_tool_parent",
];

const TRANSIENT_ERROR_CODES: &[&str] = &[
    "unavailable",
    "timeout",
    "rate_limited",
    "overloaded",
    "transport",
];

fn is_non_retryable_error_code(code: &str) -> bool {
    NON_RETRYABLE_ERROR_CODES.contains(&code)
}

pub(crate) fn error_is_retryable_code(code: &str) -> bool {
    if is_non_retryable_error_code(code) {
        return false;
    }
    TRANSIENT_ERROR_CODES.contains(&code)
}

pub(crate) fn provider_error_is_retryable(error: &JsonValue) -> bool {
    let code = error.get("code").and_then(JsonValue::as_str).unwrap_or("");
    if is_non_retryable_error_code(code) {
        return false;
    }
    if let Some(flag) = error.get("retryable").and_then(JsonValue::as_bool) {
        return flag;
    }
    if error_is_retryable_code(code) {
        return true;
    }
    let status = error.get("status").and_then(JsonValue::as_u64).unwrap_or(0);
    let error_type = error.get("type").and_then(JsonValue::as_str).unwrap_or("");
    matches!(status, 408 | 429)
        || (500..=599).contains(&status)
        || matches!(
            error_type,
            "rate_limit_error" | "overloaded_error" | "server_error" | "timeout_error"
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
