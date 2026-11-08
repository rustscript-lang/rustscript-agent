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
    CallOutcome, CallReturn, HostApiCatalog, HostFunctionDescriptor, HostFunctionRegistry,
    HostFunctionSchema, HostModuleDescriptor, HostNamedStruct, HostParamSchema, HostTypeSchema,
    Value, Vm, VmError, VmResult,
};

use super::cancellation::CancellationReason;
use serde_json::{Value as JsonValue, json};

use super::rss_runner::RunCancellation;
use crate::auth::host::{AuthHost, auth_host_module, validate_provider_json_resources};
use crate::capabilities::{
    ArtifactCapability, CapabilityError, CapabilityLifecycle, CapabilityOwner, CapabilityRisk,
    ExecutionLease, FilesystemCapability, FsRead, LifecycleError, ProcessCapability, ProcessLimits,
    ProcessSnapshot, capability_error_envelope, parse_prepare_metadata, tool_commit, tool_prepare,
};
use crate::domain::{json_to_vm_value, vm_value_to_json};
use crate::metrics::Metrics;

const PROVIDER_CALL: &str = "agent::provider_call";
const REFRESH_CONTEXT: &str = "agent::refresh_context";
const UTF8_BYTE_LEN: &str = "agent::utf8_byte_len";
const UTF8_TRUNCATE: &str = "agent::utf8_truncate";
const SLEEP_MS: &str = "agent::sleep_ms";
const CONTROL_CHECK: &str = "agent::control_check";
const TOOL_PREPARE: &str = "agent_runtime::tool_prepare";
const TOOL_REPLAY: &str = "agent_runtime::tool_replay";
const APPROVAL_ATTEST: &str = "agent_runtime::approval_attest";
#[cfg(test)]
thread_local! { static APPROVAL_ATTEST_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
const APPROVAL_STORAGE: &str = "agent::approval_storage";
const TOOL_COMMIT: &str = "agent_runtime::tool_commit";
const INVOKE_PINNED_TOOL: &str = "agent_runtime::invoke_pinned_tool";
/// Caller-role-only bridge for the one captured stateless caller→callee call.
/// It is never part of `is_tool_lease`, is absent from the child registry, and
/// is authorized only in a pinned caller registry whose program imports it.
pub(crate) const INVOKE_PINNED_PLUGIN_CHILD: &str = "agent_runtime::invoke_pinned_plugin_child";
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
const PARSE_JSON_OBJECT: &str = "agent::parse_json_object";
const PARSE_JSON_OBJECT_MAX_BYTES: usize = 64 * 1024;
const STATE_READ: &str = "state::read";
const STATE_WRITE: &str = "state::write";

/// Combined catalog: standard host surfaces plus the agent loop bridges.
pub fn agent_host_catalog() -> Arc<HostApiCatalog> {
    static CATALOG: std::sync::OnceLock<Arc<HostApiCatalog>> = std::sync::OnceLock::new();
    Arc::clone(CATALOG.get_or_init(|| {
        super::host_compose::compose_with_standard(&[agent_host_module(), auth_host_module()])
    }))
}

const AGENT_HOST_FUNCTIONS: &[fn() -> HostFunctionDescriptor] = &[
    provider_call_descriptor,
    refresh_context_descriptor,
    utf8_byte_len_descriptor,
    utf8_truncate_descriptor,
    sleep_ms_descriptor,
    control_check_descriptor,
    tool_replay_descriptor,
    approval_attest_descriptor,
    approval_storage_descriptor,
    tool_prepare_descriptor,
    tool_commit_descriptor,
    invoke_pinned_tool_descriptor,
    invoke_pinned_plugin_child_descriptor,
    cap_fs_metadata_descriptor,
    cap_fs_read_range_descriptor,
    cap_fs_list_descriptor,
    cap_fs_write_atomic_descriptor,
    cap_process_spawn_descriptor,
    cap_process_poll_descriptor,
    cap_process_wait_descriptor,
    cap_process_log_descriptor,
    cap_process_write_descriptor,
    cap_process_close_descriptor,
    cap_process_kill_descriptor,
    cap_artifact_put_descriptor,
    cap_artifact_put_result_descriptor,
    cap_artifact_get_descriptor,
    cap_artifact_reference_descriptor,
    cap_clock_monotonic_ms_descriptor,
    parse_json_object_descriptor,
    state_read_descriptor,
    state_write_descriptor,
];

pub fn agent_host_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "agent",
        functions: AGENT_HOST_FUNCTIONS,
        resources: &[],
    }
}

/// Child tools do not install provider, approval, auth, or storage adapters.
pub(crate) fn retained_tool_host_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "retained-tool",
        functions: &[
            utf8_byte_len_descriptor,
            utf8_truncate_descriptor,
            sleep_ms_descriptor,
            control_check_descriptor,
            tool_prepare_descriptor,
            tool_commit_descriptor,
            invoke_pinned_plugin_child_descriptor,
            cap_fs_metadata_descriptor,
            cap_fs_read_range_descriptor,
            cap_fs_list_descriptor,
            cap_fs_write_atomic_descriptor,
            cap_process_spawn_descriptor,
            cap_process_poll_descriptor,
            cap_process_wait_descriptor,
            cap_process_log_descriptor,
            cap_process_write_descriptor,
            cap_process_close_descriptor,
            cap_process_kill_descriptor,
            cap_artifact_put_descriptor,
            cap_artifact_put_result_descriptor,
            cap_artifact_get_descriptor,
            cap_artifact_reference_descriptor,
            cap_clock_monotonic_ms_descriptor,
            parse_json_object_descriptor,
            state_read_descriptor,
            state_write_descriptor,
        ],
        resources: &[],
    }
}

fn token_param() -> HostParamSchema {
    HostParamSchema::value("execution_token", HostTypeSchema::String)
}

fn stack_desc(
    name: &'static str,
    params: Vec<HostParamSchema>,
    ret: HostTypeSchema,
    adapter: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) -> HostFunctionDescriptor {
    super::host_compose::static_stack_descriptor(
        HostFunctionSchema::with_return(name, params, ret),
        adapter,
    )
}

fn provider_call_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        PROVIDER_CALL,
        vec![HostParamSchema::value("request", HostTypeSchema::Unknown)],
        HostTypeSchema::Unknown,
        provider_call_adapter,
    )
}

fn refresh_context_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        REFRESH_CONTEXT,
        vec![HostParamSchema::value("context", HostTypeSchema::Unknown)],
        HostTypeSchema::Unknown,
        refresh_context_adapter,
    )
}

fn utf8_byte_len_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        UTF8_BYTE_LEN,
        vec![HostParamSchema::value("text", HostTypeSchema::String)],
        HostTypeSchema::Int,
        utf8_byte_len_adapter,
    )
}

fn utf8_truncate_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        UTF8_TRUNCATE,
        vec![
            HostParamSchema::value("text", HostTypeSchema::String),
            HostParamSchema::value("max_bytes", HostTypeSchema::Int),
        ],
        HostTypeSchema::String,
        utf8_truncate_adapter,
    )
}

fn sleep_ms_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        SLEEP_MS,
        vec![HostParamSchema::value("delay_ms", HostTypeSchema::Int)],
        HostTypeSchema::Int,
        sleep_ms_adapter,
    )
}

fn control_check_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CONTROL_CHECK,
        vec![],
        super::host_types::AgentControlResult::host_type_schema(),
        control_check_adapter,
    )
}

fn tool_replay_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        TOOL_REPLAY,
        vec![HostParamSchema::value("metadata", HostTypeSchema::Unknown)],
        super::host_types::AgentToolEnvelope::host_type_schema(),
        tool_replay_adapter,
    )
}

fn approval_attest_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        APPROVAL_ATTEST,
        vec![HostParamSchema::value("metadata", HostTypeSchema::Unknown)],
        super::host_types::AgentToolEnvelope::host_type_schema(),
        approval_attest_adapter,
    )
}

fn approval_storage_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        APPROVAL_STORAGE,
        vec![
            HostParamSchema::value("operation", HostTypeSchema::String),
            HostParamSchema::value("payload", HostTypeSchema::Unknown),
        ],
        HostTypeSchema::Unknown,
        approval_storage_adapter,
    )
}

fn tool_prepare_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        TOOL_PREPARE,
        vec![HostParamSchema::value("metadata", HostTypeSchema::Unknown)],
        super::host_types::AgentToolEnvelope::host_type_schema(),
        tool_prepare_adapter,
    )
}

fn tool_commit_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        TOOL_COMMIT,
        vec![
            token_param(),
            HostParamSchema::value("result", HostTypeSchema::Unknown),
        ],
        super::host_types::AgentToolEnvelope::host_type_schema(),
        tool_commit_adapter,
    )
}

fn invoke_pinned_tool_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        INVOKE_PINNED_TOOL,
        vec![HostParamSchema::value(
            "request",
            super::host_types::PinnedToolInvokeRequest::host_type_schema(),
        )],
        super::host_types::PinnedToolInvokeResult::host_type_schema(),
        invoke_pinned_tool_adapter,
    )
}

fn invoke_pinned_plugin_child_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        INVOKE_PINNED_PLUGIN_CHILD,
        vec![HostParamSchema::value(
            "request",
            super::host_types::PinnedPluginChildInvokeRequest::host_type_schema(),
        )],
        super::host_types::PinnedToolInvokeResult::host_type_schema(),
        invoke_pinned_plugin_child_adapter,
    )
}

/// The narrow child runtime surface: pure string helpers, the existing
/// filesystem metadata/range descriptors, and the two state descriptors that
/// write the callee's own run root. No lifecycle, provider, auth, storage,
/// process, artifact, or caller bridge descriptor is present.
pub(crate) fn retained_child_host_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "retained-child",
        functions: &[
            utf8_byte_len_descriptor,
            utf8_truncate_descriptor,
            cap_fs_metadata_descriptor,
            cap_fs_read_range_descriptor,
            state_read_descriptor,
            state_write_descriptor,
        ],
        resources: &[],
    }
}

fn cap_fs_metadata_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_FS_METADATA,
        vec![
            token_param(),
            HostParamSchema::value("path", HostTypeSchema::String),
        ],
        super::host_types::AgentFsMetadataResult::host_type_schema(),
        cap_fs_metadata_adapter,
    )
}

fn cap_fs_read_range_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_FS_READ_RANGE,
        vec![
            token_param(),
            HostParamSchema::value("path", HostTypeSchema::String),
            HostParamSchema::value("offset", HostTypeSchema::Int),
            HostParamSchema::value("limit", HostTypeSchema::Int),
        ],
        super::host_types::AgentFsReadResult::host_type_schema(),
        cap_fs_read_range_adapter,
    )
}

fn cap_fs_list_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_FS_LIST,
        vec![
            token_param(),
            HostParamSchema::value("path", HostTypeSchema::String),
            HostParamSchema::value("cursor", HostTypeSchema::Int),
            HostParamSchema::value("limit", HostTypeSchema::Int),
        ],
        super::host_types::AgentFsListResult::host_type_schema(),
        cap_fs_list_adapter,
    )
}

fn cap_fs_write_atomic_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_FS_WRITE_ATOMIC,
        vec![
            token_param(),
            HostParamSchema::value("path", HostTypeSchema::String),
            HostParamSchema::value("expected_hash", HostTypeSchema::String),
            HostParamSchema::value("bytes", HostTypeSchema::Bytes),
        ],
        super::host_types::AgentFsWriteResult::host_type_schema(),
        cap_fs_write_atomic_adapter,
    )
}

fn cap_process_spawn_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_PROCESS_SPAWN,
        vec![
            token_param(),
            HostParamSchema::value(
                "argv",
                HostTypeSchema::Array(Box::new(HostTypeSchema::String)),
            ),
            HostParamSchema::value("cwd", HostTypeSchema::String),
            HostParamSchema::value(
                "env_names",
                HostTypeSchema::Array(Box::new(HostTypeSchema::String)),
            ),
            HostParamSchema::value(
                "limits",
                super::host_types::AgentProcessLimits::host_type_schema(),
            ),
            HostParamSchema::value("stdin", HostTypeSchema::Bytes),
        ],
        super::host_types::AgentProcessSpawnResult::host_type_schema(),
        cap_process_spawn_adapter,
    )
}

fn cap_process_poll_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_PROCESS_POLL,
        vec![
            token_param(),
            HostParamSchema::value("handle", HostTypeSchema::String),
            HostParamSchema::value("cursor", HostTypeSchema::Int),
            HostParamSchema::value("limit", HostTypeSchema::Int),
        ],
        super::host_types::AgentProcessSnapshot::host_type_schema(),
        cap_process_poll_adapter,
    )
}

fn cap_process_wait_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_PROCESS_WAIT,
        vec![
            token_param(),
            HostParamSchema::value("handle", HostTypeSchema::String),
            HostParamSchema::value("timeout_ms", HostTypeSchema::Int),
        ],
        super::host_types::AgentProcessSnapshot::host_type_schema(),
        cap_process_wait_adapter,
    )
}

fn cap_process_log_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_PROCESS_LOG,
        vec![
            token_param(),
            HostParamSchema::value("handle", HostTypeSchema::String),
            HostParamSchema::value("cursor", HostTypeSchema::Int),
            HostParamSchema::value("limit", HostTypeSchema::Int),
        ],
        super::host_types::AgentProcessSnapshot::host_type_schema(),
        cap_process_log_adapter,
    )
}

fn cap_process_write_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_PROCESS_WRITE,
        vec![
            token_param(),
            HostParamSchema::value("handle", HostTypeSchema::String),
            HostParamSchema::value("bytes", HostTypeSchema::Bytes),
            HostParamSchema::value("timeout_ms", HostTypeSchema::Int),
        ],
        super::host_types::AgentProcessWriteResult::host_type_schema(),
        cap_process_write_adapter,
    )
}

fn cap_process_close_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_PROCESS_CLOSE,
        vec![
            token_param(),
            HostParamSchema::value("handle", HostTypeSchema::String),
        ],
        super::host_types::AgentProcessCloseResult::host_type_schema(),
        cap_process_close_adapter,
    )
}

fn cap_process_kill_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_PROCESS_KILL,
        vec![
            token_param(),
            HostParamSchema::value("handle", HostTypeSchema::String),
        ],
        super::host_types::AgentProcessCloseResult::host_type_schema(),
        cap_process_kill_adapter,
    )
}

fn cap_artifact_put_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_ARTIFACT_PUT,
        vec![
            token_param(),
            HostParamSchema::value("bytes", HostTypeSchema::Bytes),
            HostParamSchema::value("metadata", HostTypeSchema::Unknown),
        ],
        HostTypeSchema::Unknown,
        cap_artifact_put_adapter,
    )
}

fn cap_artifact_put_result_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_ARTIFACT_PUT_RESULT,
        vec![
            token_param(),
            HostParamSchema::value("bytes", HostTypeSchema::Bytes),
            HostParamSchema::value("metadata", HostTypeSchema::Unknown),
        ],
        HostTypeSchema::Unknown,
        cap_artifact_put_result_adapter,
    )
}

fn cap_artifact_get_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_ARTIFACT_GET,
        vec![
            token_param(),
            HostParamSchema::value("id", HostTypeSchema::String),
        ],
        HostTypeSchema::Unknown,
        cap_artifact_get_adapter,
    )
}

fn cap_artifact_reference_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_ARTIFACT_REFERENCE,
        vec![
            token_param(),
            HostParamSchema::value("id", HostTypeSchema::String),
        ],
        HostTypeSchema::Unknown,
        cap_artifact_reference_adapter,
    )
}

fn cap_clock_monotonic_ms_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        CAP_CLOCK_MONOTONIC_MS,
        vec![token_param()],
        super::host_types::AgentClockResult::host_type_schema(),
        cap_clock_monotonic_ms_adapter,
    )
}

fn parse_json_object_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        PARSE_JSON_OBJECT,
        vec![HostParamSchema::value("text", HostTypeSchema::String)],
        HostTypeSchema::Unknown,
        parse_json_object_adapter,
    )
}

fn state_read_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        STATE_READ,
        vec![],
        super::host_types::AgentPluginStateSnapshot::host_type_schema(),
        state_read_adapter,
    )
}

fn state_write_descriptor() -> HostFunctionDescriptor {
    stack_desc(
        STATE_WRITE,
        vec![
            HostParamSchema::value("expected_revision", HostTypeSchema::Int),
            HostParamSchema::value("document", HostTypeSchema::String),
        ],
        super::host_types::AgentPluginStateWriteResult::host_type_schema(),
        state_write_adapter,
    )
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

    /// Optional durable-context refresh invoked by RSS before each provider turn.
    fn refresh_context(
        &self,
        _context: &JsonValue,
        _cancellation: &RunCancellation,
    ) -> Option<JsonValue> {
        None
    }

    /// Forwards RSS-owned approval persistence commands through the active run.
    fn approval_storage(
        &self,
        _operation: &str,
        _payload: &JsonValue,
        _cancellation: &RunCancellation,
    ) -> JsonValue {
        typed_fail(
            "approval_storage_unavailable",
            "approval storage is unavailable",
        )
    }
}

pub type ControlCheckHook = Arc<dyn Fn(&RunCancellation) + Send + Sync>;
pub type AuthHostFactory =
    Arc<dyn Fn(RunCancellation) -> std::result::Result<AuthHost, String> + Send + Sync>;

/// Program compiled from a verified capture or the closed embedded catalog.
/// Fields are sealed by the factory. Callers cannot swap the program under a
/// retained identity.
#[derive(Clone)]
pub struct PinnedToolProgram {
    pub(crate) harness_selection: crate::plugins::HarnessSelection,
    pub(crate) managed: Option<Arc<crate::effects::broker::ManagedRunBinding>>,
    execution_authority: NativeExecutionAuthority,
    managed_contract: Option<crate::effects::broker::ManagedEntryContract>,
    managed_policy_catalog: Option<Arc<crate::effects::authority::ManagedToolPolicyCatalog>>,
    /// Captured stateless caller→callee template, present only for the one
    /// admitted two-package read topology.
    pub(crate) child: Option<Arc<PinnedPluginChildTemplate>>,
    pub(crate) state: Option<crate::plugins::StateDeclaration>,
    pub(crate) state_binding: Option<crate::plugins::PluginStateBinding>,
    pub(crate) state_store: Option<crate::plugins::PluginStateStore>,
    program: Arc<rustscript_vm::Program>,
    entry: String,
    pub(crate) graph_id: String,
    pub(crate) package_id: String,
    pub(crate) artifact_id: String,
    export: String,
    pub(crate) run_id: String,
    pub(crate) session_id: String,
    profile: String,
    ref_id: String,
    generation: u64,
    registry_identity: String,
    pub(crate) workspace: std::path::PathBuf,
    registry: Result<Arc<HostFunctionRegistry>, String>,
    expects_dispatch_input: bool,
}

#[derive(Clone)]
pub(crate) struct PinnedToolCode {
    pub(crate) harness_selection: crate::plugins::HarnessSelection,
    pub(crate) managed_contract: Option<crate::effects::broker::ManagedEntryContract>,
    pub(crate) managed_policy_catalog:
        Option<Arc<crate::effects::authority::ManagedToolPolicyCatalog>>,
    pub(crate) child: Option<Arc<PinnedPluginChildTemplate>>,
    pub(crate) state: Option<crate::plugins::StateDeclaration>,
    pub(crate) program: Arc<rustscript_vm::Program>,
    pub(crate) entry: String,
    pub(crate) package_id: String,
    pub(crate) artifact_id: String,
    pub(crate) export: String,
    pub(crate) registry: Result<Arc<HostFunctionRegistry>, String>,
    pub(crate) expects_dispatch_input: bool,
}

#[derive(Clone)]
pub(crate) struct PinnedToolReceipt {
    pub(crate) graph_id: String,
    pub(crate) generation: u64,
    pub(crate) ref_id: String,
    pub(crate) run_id: String,
    pub(crate) session_id: String,
    pub(crate) profile: String,
    pub(crate) registry_identity: String,
    pub(crate) workspace: std::path::PathBuf,
}

/// Sealed Native execution authority. A persistent pin retains the original
/// control-store owner object; it is never rebuilt from caller JSON, a fresh
/// open of the same path, or a compatibility bypass. The explicit stateless
/// shape exists only for the closed embedded dispatcher factory.
#[derive(Clone)]
pub(crate) enum NativeExecutionAuthority {
    Persistent {
        persistence: Arc<crate::gateway::store::GatewayPersistence>,
    },
    ExplicitStateless,
}

impl NativeExecutionAuthority {
    fn same_owner(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Persistent { persistence: left }, Self::Persistent { persistence: right }) => {
                Arc::ptr_eq(left, right)
            }
            (Self::ExplicitStateless, Self::ExplicitStateless) => true,
            _ => false,
        }
    }
}

/// Data-only identity of the captured callee, exposed for admission auditing.
/// It grants no execution authority and carries no token or selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedChildIdentity {
    pub package_id: String,
    pub artifact_id: String,
    pub export: String,
    pub entry: String,
    pub edge_alias: String,
    pub tool_name: String,
    pub registry_identity: String,
}

/// Immutable per-graph template for the one captured stateless caller→callee
/// call. It seals both captured programs/entries/registries/catalogs, the
/// single plugin edge, the delegated effect tuple and the durable graph
/// identity. Runtime values (owner, call, arguments, state) never enter it.
#[derive(Clone)]
pub(crate) struct PinnedPluginChildTemplate {
    pub(crate) caller_package: String,
    pub(crate) caller_catalog: Arc<crate::effects::authority::ManagedToolPolicyCatalog>,
    pub(crate) callee_package: String,
    pub(crate) callee_artifact: String,
    pub(crate) callee_export: String,
    pub(crate) callee_tool: String,
    pub(crate) callee_code: crate::effects::ManagedCodeIdentity,
    pub(crate) callee_catalog: Arc<crate::effects::authority::ManagedToolPolicyCatalog>,
    pub(crate) callee_program: Arc<rustscript_vm::Program>,
    pub(crate) callee_entry: String,
    pub(crate) callee_registry: std::result::Result<Arc<HostFunctionRegistry>, String>,
    pub(crate) callee_state: Option<crate::plugins::StateDeclaration>,
    pub(crate) callee_contract: Option<crate::effects::broker::ManagedEntryContract>,
    pub(crate) edge_alias: String,
    pub(crate) from_entry: String,
    pub(crate) to_entry: String,
    pub(crate) effect: crate::effects::broker::ManagedEffectRequirement,
    pub(crate) run_id: String,
    pub(crate) session_id: String,
    pub(crate) profile: String,
    pub(crate) workspace: std::path::PathBuf,
}

/// Native-only per-call gate for the one child invocation. The claim is
/// exclusive; no mutex guard survives the durable write or the callee VM.
pub(crate) struct ChildCallGate {
    state: std::sync::Mutex<ChildGateState>,
    complete: std::sync::Mutex<Option<crate::effects::broker::ManagedDelegationComplete>>,
    attempts: std::sync::atomic::AtomicUsize,
    /// Test-only count of contenders refused because another attempt already
    /// owned a non-executable (Persisting/Invoking) claim.
    #[cfg(test)]
    refused_claims: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildGateState {
    NotInvoked,
    Persisting(u64),
    Invoking(u64),
    Complete,
    Aborted,
}

impl ChildCallGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(ChildGateState::NotInvoked),
            complete: std::sync::Mutex::new(None),
            attempts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            refused_claims: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, ChildGateState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    /// Exclusive `NotInvoked → Persisting(claim)`. Every other caller sees a
    /// non-executable state and is refused without touching this claim.
    pub(crate) fn claim(&self) -> Option<u64> {
        let mut state = self.lock();
        if *state != ChildGateState::NotInvoked {
            #[cfg(test)]
            self.refused_claims
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return None;
        }
        let claim = self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst) as u64
            + 1;
        *state = ChildGateState::Persisting(claim);
        Some(claim)
    }
    /// Only the acknowledged intent writer may become executable.
    pub(crate) fn invoke(&self, claim: u64) -> bool {
        let mut state = self.lock();
        if *state != ChildGateState::Persisting(claim) {
            return false;
        }
        *state = ChildGateState::Invoking(claim);
        true
    }
    /// Any failure before intent or an unrepresentable/failed child result
    /// ends the gate in the non-executable `Aborted` state. A completed claim
    /// stays terminal, and a losing contender never reaches this path.
    pub(crate) fn abort(&self) {
        let mut state = self.lock();
        if *state != ChildGateState::Complete {
            *state = ChildGateState::Aborted;
        }
    }
    fn complete(&self, complete: crate::effects::broker::ManagedDelegationComplete) {
        *self
            .complete
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(complete);
        *self.lock() = ChildGateState::Complete;
    }
    fn take_complete(&self) -> Option<crate::effects::broker::ManagedDelegationComplete> {
        let state = self.lock();
        if *state != ChildGateState::Complete {
            return None;
        }
        self.complete
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
    pub(crate) fn invoking(&self) -> Option<u64> {
        match *self.lock() {
            ChildGateState::Invoking(claim) => Some(claim),
            _ => None,
        }
    }
    /// Test-only view of the exact gate phase.
    #[cfg(test)]
    pub(crate) fn state(&self) -> ChildGateState {
        *self.lock()
    }
    /// Test-only count of contenders refused by an owned claim.
    #[cfg(test)]
    pub(crate) fn refused_claims(&self) -> usize {
        self.refused_claims
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Per-call crate-private plumbing from the pinned caller into the retained
/// runner: the immutable template plus this call's exclusive gate.
#[derive(Clone)]
pub(crate) struct ChildCallRuntime {
    pub(crate) gate: Arc<ChildCallGate>,
    pub(crate) template: Arc<PinnedPluginChildTemplate>,
    /// The sealed caller pin for this run: the bridge never learns it from
    /// guest JSON or from the caller VM's own (absent) pinned slot.
    pub(crate) pinned: PinnedToolProgram,
    /// The child-side state authority for the S2 callee. It shares the staged
    /// `Arc`, so the publication the child staged survives the child VM exit
    /// and the caller side can hand it to `prepare_result`. `None` until the
    /// callee run binding exists (S1 stays `None` for the whole call).
    pub(crate) child_state_call: Option<PluginStateCall>,
}

/// Private child filesystem adapter. It exposes only metadata and range reads
/// over the parent's already confined managed view, never a generic
/// capability handle, `Deref`, or guest-reachable value.
pub(crate) struct ChildFilesystemReadAdapter {
    filesystem: Arc<FilesystemCapability>,
    token: String,
    gate: Arc<ChildCallGate>,
    call: std::sync::Weak<crate::effects::broker::ManagedCallContext>,
    pinned: PinnedToolProgram,
    cancellation: RunCancellation,
}

/// Encoded `{"ok":true,"kind":"fs_metadata","file_type":<type>,"len":<u64>}`
/// frame in the unit the settles use: UTF-8 JSON bytes, where every key and
/// text carries its quotes. The widest file-type name and a 20-digit length are
/// counted; the measurement tests prove the real builder fits inside it.
#[cfg(test)]
const FS_METADATA_KEYS: [&str; 4] = ["ok", "kind", "file_type", "len"];
const FS_METADATA_FRAME_BOUND: u64 = 2          // braces
    + (2 + 2) + 1 + 4 + 1                       // "ok":true,
    + (2 + 4) + 1 + (2 + 11) + 1                // "kind":"fs_metadata",
    + (2 + 9) + 1 + (2 + 9) + 1                 // "file_type":"directory",
    + (2 + 3) + 1 + 20; // "len":<u64>
/// Child-visible metadata refusal: `{"ok":false,"kind":"error","error":{"code":
/// …, "message":…}}`. `code` and `message` are machine labels or
/// confined-filesystem static text, and any byte of them can expand to a
/// six-byte `\u00XX` escape in the encoded frame. The preflight charges this
/// whole refusal allowance before the filesystem access, so an error frame can
/// never settle above its own precharge.
#[cfg(test)]
const FS_METADATA_ERROR_KEYS: [&str; 2] = ["code", "message"];
const FS_METADATA_ERROR_TEXT: u64 = 6 * 48 + 6 * 336;
/// Fixed encoded structure: braces, the four quoted keys, four colons, the
/// separators, the boolean and the two empty-string quote pairs.
const FS_METADATA_ERROR_STRUCTURE: u64 = 60;
const FS_METADATA_ERROR_BOUND: u64 = FS_METADATA_ERROR_STRUCTURE + FS_METADATA_ERROR_TEXT;
#[cfg(test)]
const FS_METADATA_OUTER_KEYS: [&str; 3] = ["ok", "kind", "error"];
/// One metadata operation precharges the wider of its success frame and its
/// bounded refusal.
const FS_METADATA_BOUND: u64 = if FS_METADATA_FRAME_BOUND > FS_METADATA_ERROR_BOUND {
    FS_METADATA_FRAME_BOUND
} else {
    FS_METADATA_ERROR_BOUND
};
/// Exact `fs_read_value` frame: seven keys plus `true`/`false`, `"fs_read"`,
/// two u64 decimal widths and the 64-character hash. The raw payload is
/// charged separately at its own `Vec<u8>` length.
const FS_READ_KEYS: [&str; 7] = ["ok", "kind", "offset", "truncated", "len", "bytes", "hash"];
const FS_READ_FRAME_VALUES: u64 = 4 + 7 + 20 + 5 + 20 + 64;
const FS_READ_FRAME_BOUND: u64 = json_object_frame(&FS_READ_KEYS, FS_READ_FRAME_VALUES);

/// Frame size of one typed map with the given keys: braces, one colon per key,
/// the separators between entries, and the supplied value widths. Strings count
/// their UTF-8 bytes without JSON quotes, matching
/// [`vm_value_typed_bytes`].
const fn json_object_frame(keys: &[&str], values: u64) -> u64 {
    let mut total = 2 + values;
    let mut index = 0;
    while index < keys.len() {
        total += keys[index].len() as u64 + 1;
        index += 1;
    }
    total + keys.len().saturating_sub(1) as u64
}

/// Exact byte size of one VM value in the Native typed representation the guest
/// receives: byte buffers count their raw payload (never a lossy UTF-8 view),
/// strings their UTF-8 bytes, numbers their decimal text, and containers add
/// their structural frame. This never allocates, so it can bound a value before
/// it is converted.
fn vm_value_typed_bytes(value: &Value) -> u64 {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Int(number) => number.to_string().len() as u64,
        Value::Float(number) => number.to_string().len() as u64,
        Value::String(text) => text.len() as u64,
        Value::Bytes(bytes) => bytes.len() as u64,
        Value::Array(items) => {
            2 + items.iter().map(vm_value_typed_bytes).sum::<u64>()
                + items.len().saturating_sub(1) as u64
        }
        Value::Map(entries) => {
            2 + entries
                .iter()
                .map(|(key, value)| vm_value_typed_bytes(key) + 1 + vm_value_typed_bytes(value))
                .sum::<u64>()
                + entries.len().saturating_sub(1) as u64
        }
        Value::Callable(_) => 0,
    }
}

/// Converts one guest commit result into canonical JSON without losing bytes.
/// A `Value::Bytes` buffer that is exactly valid UTF-8 becomes the same string;
/// anything else is refused, because the canonical JSON envelope has no byte
/// type and a lossy replacement would silently corrupt the tool result.
fn guest_result_json(value: &Value) -> std::result::Result<JsonValue, String> {
    Ok(match value {
        Value::Null => JsonValue::Null,
        Value::Int(number) => json!(number),
        Value::Float(number) => serde_json::Number::from_f64(*number)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(flag) => JsonValue::Bool(*flag),
        Value::String(text) => JsonValue::String(text.to_string()),
        Value::Bytes(bytes) => JsonValue::String(
            std::str::from_utf8(bytes)
                .map_err(|_| "guest result contains bytes that are not UTF-8".to_string())?
                .to_string(),
        ),
        Value::Array(items) => JsonValue::Array(
            items
                .iter()
                .map(guest_result_json)
                .collect::<std::result::Result<_, String>>()?,
        ),
        Value::Map(entries) => {
            let mut object = serde_json::Map::new();
            for (key, item) in entries.iter() {
                let key = guest_result_key(key)?;
                object.insert(key, guest_result_json(item)?);
            }
            JsonValue::Object(object)
        }
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    })
}

/// One guest map key, spelled exactly as the canonical result does. A string
/// key passes through, a byte key must be exactly valid UTF-8, and any other
/// key keeps its strict JSON-text form; no key ever reaches a lossy
/// `String::from_utf8_lossy` view.
fn guest_result_key(key: &Value) -> std::result::Result<String, String> {
    match key {
        Value::String(text) => Ok(text.to_string()),
        other => Ok(guest_result_json(other)?.to_string()),
    }
}

/// Refuses, without allocating, any child-result byte buffer that is not
/// exactly valid UTF-8. The canonical result envelope has no byte type, so a
/// lossy replacement would silently corrupt the delegated result.
fn validate_guest_result(value: &Value) -> std::result::Result<(), String> {
    match value {
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map(|_| ())
            .map_err(|_| "guest result contains bytes that are not UTF-8".to_string()),
        Value::Array(items) => items.iter().try_for_each(validate_guest_result),
        Value::Map(entries) => entries.iter().try_for_each(|(key, item)| {
            validate_guest_result(key)?;
            validate_guest_result(item)
        }),
        _ => Ok(()),
    }
}

/// Streaming view of one guest VM value in exactly the canonical JSON encoding
/// [`guest_result_json`] produces. It exists so a child result can be measured
/// through the bounded counting writer before any complete JSON tree is
/// allocated; byte buffers are validated, never replaced.
struct GuestResultJson<'a>(&'a Value);

impl serde::Serialize for GuestResultJson<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self.0 {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(flag) => serializer.serialize_bool(*flag),
            Value::Int(number) => serializer.serialize_i64(*number),
            Value::Float(number) => serializer.serialize_f64(*number),
            Value::String(text) => serializer.serialize_str(text),
            Value::Bytes(bytes) => serializer
                .serialize_str(std::str::from_utf8(bytes).map_err(serde::ser::Error::custom)?),
            Value::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for item in items.iter() {
                    sequence.serialize_element(&GuestResultJson(item))?;
                }
                sequence.end()
            }
            Value::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, item) in entries.iter() {
                    let key = guest_result_key(key).map_err(serde::ser::Error::custom)?;
                    map.serialize_entry(&key, &GuestResultJson(item))?;
                }
                map.end()
            }
            Value::Callable(_) => serializer.serialize_str("<callable>"),
        }
    }
}

/// The exact typed refusals the sealed execution guard can raise inside a
/// managed admission. They stay distinguishable from a generic denial.
fn is_execution_refusal(message: &str) -> bool {
    matches!(
        message,
        "plugin_graph_revoked" | "plugin_graph_pin_required" | "cancelled" | "deadline_elapsed"
    )
}
fn json_bytes(value: &JsonValue) -> u64 {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len() as u64)
        .unwrap_or(u64::MAX)
}

impl ChildFilesystemReadAdapter {
    /// Child-visible failures keep the existing capability error envelope, so a
    /// representable refusal becomes the child's canonical error result while an
    /// internal/unrepresentable failure aborts the delegation.
    fn fail(&self, code: &str, message: &str) -> JsonValue {
        capability_error_envelope(&CapabilityError::new(code, message))
    }
    /// A refusal raised by the execution guard inside the admission keeps its
    /// exact typed code; the managed authorizer only knows the generic
    /// operation-denied envelope. Cancellation and deadline stay distinguishable
    /// from a plain view/operation denial.
    fn native_error(&self, error: &CapabilityError) -> JsonValue {
        let code = match error.code() {
            "managed_operation_denied" if is_execution_refusal(error.message()) => error.message(),
            other => other,
        };
        self.fail(code, error.message())
    }
    /// Every child operation re-checks the claim, the original cancellation
    /// and deadline, the managed view/operation permission and the original
    /// pinned graph revocation immediately before the confined IO. Cancellation
    /// and deadline keep their exact typed codes ahead of the generic view
    /// refusal; the graph tombstone is re-read again inside the admission.
    fn check(
        &self,
    ) -> std::result::Result<Arc<crate::effects::broker::ManagedCallContext>, JsonValue> {
        if self.gate.invoking().is_none() {
            return Err(self.fail(
                "pinned_child_gate_closed",
                "child call gate is not invokable",
            ));
        }
        let call = self.call.upgrade().ok_or_else(|| {
            self.fail(
                "managed_call_unavailable",
                "managed parent call is unavailable",
            )
        })?;
        if self.cancellation.requested().is_some() {
            return Err(self.fail("cancelled", "run was cancelled"));
        }
        if self.cancellation.deadline_passed() {
            return Err(self.fail("deadline_elapsed", "run deadline elapsed"));
        }
        if let Err(message) = call.check_child_operable() {
            return Err(self.fail("managed_view_unavailable", &message));
        }
        if let Err(code) = self
            .pinned
            .check_execution_authority(Some(&self.cancellation))
        {
            return Err(self.fail(code, code));
        }
        Ok(call)
    }
    /// Re-reads the original pinned graph tombstone (with the sealed execution
    /// authority, epoch and original clock) inside the managed admission. The
    /// managed authorizer runs this in the same linearized boundary as the
    /// token/branch checks and before the operation is counted, so a revocation
    /// committed after [`Self::check`] still refuses the read before any IO.
    fn admission_guard(&self) -> std::result::Result<(), String> {
        self.pinned
            .check_execution_authority(Some(&self.cancellation))
            .map_err(|code| code.to_string())
    }
    /// Charges one Native return exactly once against the shared parent meter.
    fn settle(
        &self,
        call: &crate::effects::broker::ManagedCallContext,
        mut charge: crate::effects::broker::ManagedMeterCharge,
        actual: u64,
    ) -> std::result::Result<(), JsonValue> {
        call.meter()
            .settle_exact(&mut charge, actual)
            .map_err(|message| self.fail("managed_output_budget_exceeded", &message))
    }
    fn preflight(
        &self,
        call: &crate::effects::broker::ManagedCallContext,
        bound: u64,
        what: &str,
    ) -> std::result::Result<crate::effects::broker::ManagedMeterCharge, JsonValue> {
        if bound > call.meter().remaining() {
            return Err(self.fail(
                "managed_output_budget_exceeded",
                &format!("managed output meter cannot fit {what}"),
            ));
        }
        call.meter()
            .charge_new(bound, what)
            .map_err(|message| self.fail("managed_output_budget_exceeded", &message))
    }
    /// The child capability keeps the existing `cap::fs_*` ABI. The empty
    /// sentinel is discarded and a non-empty token is refused before IO; the
    /// private parent token never crosses the guest boundary.
    fn metadata(&self, execution_token: &str, path: &str) -> JsonValue {
        if !execution_token.is_empty() {
            return self.fail(
                "invalid_metadata",
                "child filesystem reads do not accept an execution token",
            );
        }
        let call = match self.check() {
            Ok(call) => call,
            Err(error) => return error,
        };
        let charge = match self.preflight(&call, FS_METADATA_BOUND, "child fs metadata") {
            Ok(charge) => charge,
            Err(error) => return error,
        };
        let guard = || self.admission_guard();
        let envelope = match self
            .filesystem
            .metadata_guarded(&self.token, path, Some(&guard))
        {
            Ok(meta) => json!({
                "ok": true,
                "kind": "fs_metadata",
                "file_type": meta.file_type,
                "len": meta.len,
            }),
            Err(error) => self.native_error(&error),
        };
        if self.settle(&call, charge, json_bytes(&envelope)).is_err() {
            return self.fail(
                "managed_output_budget_exceeded",
                "child metadata frame exceeded its preflight bound",
            );
        }
        envelope
    }
    fn read_range(&self, execution_token: &str, path: &str, offset: u64, limit: usize) -> Value {
        if !execution_token.is_empty() {
            return json_to_vm_value(&self.fail(
                "invalid_metadata",
                "child filesystem reads do not accept an execution token",
            ));
        }
        let call = match self.check() {
            Ok(call) => call,
            Err(error) => return json_to_vm_value(&error),
        };
        // The requested raw range bound is validated first; the preflight adds
        // the exact frame allowance. An over-budget request is refused, never
        // silently clamped into a valid truncated result.
        let Some(bound) = (limit as u64).checked_add(FS_READ_FRAME_BOUND) else {
            return json_to_vm_value(&self.fail(
                "managed_output_budget_exceeded",
                "child range request overflowed its bound",
            ));
        };
        let charge = match self.preflight(&call, bound, "child fs read_range") {
            Ok(charge) => charge,
            Err(error) => return json_to_vm_value(&error),
        };
        let guard = || self.admission_guard();
        let value =
            match self
                .filesystem
                .read_range_guarded(&self.token, path, offset, limit, Some(&guard))
            {
                Ok(read) => fs_read_value(read),
                Err(error) => json_to_vm_value(&self.native_error(&error)),
            };
        // The raw payload is charged at its `Vec<u8>` length plus the exact
        // source-derived frame, never through a lossy UTF-8 JSON view.
        let actual = vm_value_typed_bytes(&value);
        if self.settle(&call, charge, actual).is_err() {
            return json_to_vm_value(&self.fail(
                "managed_output_budget_exceeded",
                "child read frame exceeded its preflight bound",
            ));
        }
        value
    }
}

impl PinnedToolProgram {
    /// Data-only identity of the captured callee for owner-facing audit. It
    /// confers no execution authority, token, effect, or child selector.
    pub fn captured_child_identity(&self) -> Option<CapturedChildIdentity> {
        let template = self.child.as_ref()?;
        Some(CapturedChildIdentity {
            package_id: template.callee_package.clone(),
            artifact_id: template.callee_artifact.clone(),
            export: template.callee_export.clone(),
            entry: template.callee_entry.clone(),
            edge_alias: template.edge_alias.clone(),
            tool_name: template.callee_tool.clone(),
            registry_identity: template.callee_code.registry_identity.clone(),
        })
    }
    /// Caller-role replay proof. The parent effect id is durable data that
    /// cannot be re-derived before the row is read; it is verified against the
    /// record's own effect id by the broker.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn derive_child_proof(
        &self,
        caller_code: &crate::effects::ManagedCodeIdentity,
        call_id: &str,
        caller_tool: &str,
        parent_canonical: &str,
        parent_effect_id: &str,
        epoch: u64,
        expected_head: &str,
        expected_head_version: u64,
        child_arguments: crate::effects::journal::ManagedArgumentIdentity,
    ) -> std::result::Result<crate::effects::journal::ManagedDelegationIntent, String> {
        let template = self.child.as_ref().ok_or("pinned_child_unavailable")?;
        self.derive_child_request(caller_tool, parent_canonical)?;
        Ok(crate::effects::journal::ManagedDelegationIntent {
            parent_call_id: call_id.into(),
            parent_effect_id: parent_effect_id.into(),
            caller_code: caller_code.clone(),
            callee_code: template.callee_code.clone(),
            edge_alias: template.edge_alias.clone(),
            from_entry: template.from_entry.clone(),
            to_entry: template.to_entry.clone(),
            effect: crate::effects::journal::ManagedDelegationEffect {
                kind: template.effect.kind.clone(),
                scope: template.effect.scope.clone(),
                recovery: template.effect.recovery.clone(),
            },
            callee_tool: template.callee_tool.clone(),
            child_arguments,
            epoch,
            expected_head: expected_head.into(),
            expected_head_version,
        })
    }

    /// Source-derived child readiness for the parent prepare boundary: the
    /// exact one Complete child invocation with a representable result.
    pub(crate) fn child_template(&self) -> Option<&Arc<PinnedPluginChildTemplate>> {
        self.child.as_ref()
    }
    /// Deterministic Native derivation of the one expected child request:
    /// the caller descriptor and the sole callee descriptor must both accept
    /// the original parent argument object, which is the identity projection.
    pub(crate) fn derive_child_request(
        &self,
        caller_tool: &str,
        parent_canonical: &str,
    ) -> std::result::Result<JsonValue, String> {
        let template = self.child.as_ref().ok_or("pinned_child_unavailable")?;
        let parent: JsonValue =
            serde_json::from_str(parent_canonical).map_err(|_| "managed canonical arguments")?;
        if !parent.is_object() {
            return Err("managed canonical arguments".into());
        }
        template
            .caller_catalog
            .validate_arguments(caller_tool, &parent)
            .map_err(|_| "managed caller descriptor rejected arguments".to_string())?;
        template
            .callee_catalog
            .validate_arguments(&template.callee_tool, &parent)
            .map_err(|_| "managed callee descriptor rejected arguments".to_string())?;
        Ok(parent)
    }
}

impl PinnedToolProgram {
    pub(crate) fn same_native_binding(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.program, &other.program)
            && self
                .execution_authority
                .same_owner(&other.execution_authority)
            && self.entry == other.entry
            && self.graph_id == other.graph_id
            && self.ref_id == other.ref_id
            && self.package_id == other.package_id
            && self.artifact_id == other.artifact_id
            && self.export == other.export
            && self.run_id == other.run_id
            && self.session_id == other.session_id
            && self.profile == other.profile
            && self.generation == other.generation
            && self.registry_identity == other.registry_identity
            && self.workspace == other.workspace
            && self.state == other.state
            && match (&self.state_binding, &other.state_binding) {
                (None, None) => true,
                (Some(left), Some(right)) => left == right,
                _ => false,
            }
            && match (&self.managed, &other.managed) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.child, &other.child) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }

    pub(crate) fn restore_managed_binding(
        &mut self,
        runtime: &Arc<crate::effects::broker::ManagedEffectRuntime>,
        authority: Arc<crate::runtime::rss_runner::WorkspaceAuthority>,
        saved: &crate::effects::journal::ManagedRunQueryBinding,
        registry: Arc<crate::registry::ToolRegistrySnapshot>,
        cancel: RunCancellation,
    ) -> Result<(), String> {
        if saved.owner.run_id != self.run_id
            || saved.owner.session_id != self.session_id
            || saved.owner.profile != self.profile
            || registry.identity() != self.registry_identity
        {
            return Err("plugin_graph_pin_required".into());
        }
        let code = crate::effects::ManagedCodeIdentity {
            graph_id: self.graph_id.clone(),
            activation_generation: self.generation,
            graph_ref_id: self.ref_id.clone(),
            package_id: self.package_id.clone(),
            artifact_id: self.artifact_id.clone(),
            export: self.export.clone(),
            registry_identity: self.registry_identity.clone(),
            effect_contract_version: 1,
        };
        self.managed = Some(
            runtime.restore_run_binding(
                authority,
                saved,
                (
                    code,
                    self.managed_contract
                        .clone()
                        .ok_or("plugin_graph_pin_required")?,
                    self.managed_policy_catalog
                        .clone()
                        .ok_or("plugin_graph_pin_required")?,
                    registry,
                ),
                cancel,
            )?,
        );
        Ok(())
    }

    pub(crate) fn seal(
        code: PinnedToolCode,
        receipt: PinnedToolReceipt,
        execution_authority: NativeExecutionAuthority,
    ) -> Self {
        Self {
            managed: None,
            execution_authority,
            harness_selection: code.harness_selection,
            managed_contract: code.managed_contract,
            managed_policy_catalog: code.managed_policy_catalog,
            child: code.child,
            state: code.state,
            state_binding: None,
            state_store: None,
            program: code.program,
            entry: code.entry,
            package_id: code.package_id,
            artifact_id: code.artifact_id,
            export: code.export,
            registry: code.registry,
            expects_dispatch_input: code.expects_dispatch_input,
            graph_id: receipt.graph_id,
            generation: receipt.generation,
            ref_id: receipt.ref_id,
            run_id: receipt.run_id,
            session_id: receipt.session_id,
            profile: receipt.profile,
            registry_identity: receipt.registry_identity,
            workspace: receipt.workspace,
        }
    }

    /// Fresh execution authorization against the original control-store owner.
    /// Every persistent execution re-reads the exact sealed graph revocation
    /// under the run cancellation; a tombstone refuses with the revocation
    /// code, while a missing authority, a cancelled/expired wait, or any typed
    /// query/decode failure refuses closed. Positive results are never cached.
    /// The explicit stateless shape needs no control-store owner.
    /// The original cancellation reason is checked at entry and again at the
    /// read return boundary, before the revocation verdict is accepted: an
    /// original requested/expired root keeps its existing classification and
    /// takes precedence over a revoked or failed query.
    pub(crate) fn check_execution_authority(
        &self,
        cancel: Option<&RunCancellation>,
    ) -> Result<(), &'static str> {
        let persistence = match &self.execution_authority {
            NativeExecutionAuthority::Persistent { persistence } => persistence,
            NativeExecutionAuthority::ExplicitStateless => return Ok(()),
        };
        let cancel = cancel.ok_or("plugin_graph_pin_required")?;
        // Repository method dispatch installed this run as a same-store
        // revocation listener. A durable query would observe the requested
        // cancellation first and mask the typed revocation that caused it, so
        // this live fact takes precedence over the open-clock checks.
        if self
            .managed
            .as_ref()
            .is_some_and(|binding| binding.is_revoked())
        {
            return Err("plugin_graph_revoked");
        }
        cancel.ensure_open()?;
        let query = crate::plugins::PluginControlStore::new(persistence)
            .graph_revocation_for_execution(&self.graph_id, cancel);
        cancel.ensure_open()?;
        let revoked = query.map_err(|_| "plugin_graph_pin_required")?;
        if revoked.is_some() {
            return Err("plugin_graph_revoked");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_native_code_identity_for_test(
        &self,
        code: crate::effects::ManagedCodeIdentity,
    ) -> Self {
        let mut changed = self.clone();
        changed.graph_id = code.graph_id;
        changed.generation = code.activation_generation;
        changed.ref_id = code.graph_ref_id;
        changed.package_id = code.package_id;
        changed.artifact_id = code.artifact_id;
        changed.export = code.export;
        changed.registry_identity = code.registry_identity;
        changed
    }

    pub fn entry(&self) -> &str {
        &self.entry
    }

    pub(crate) fn ref_id(&self) -> &str {
        &self.ref_id
    }
    pub(crate) fn declared_export(&self) -> &str {
        &self.export
    }

    pub fn graph_id(&self) -> &str {
        &self.graph_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Original sealed identity only. This path does not confer workspace IO
    /// authority and must never be used to construct filesystem capabilities.
    pub(crate) fn workspace_identity(&self) -> &std::path::Path {
        &self.workspace
    }

    pub fn shares_program(&self, other: &Arc<rustscript_vm::Program>) -> bool {
        Arc::ptr_eq(&self.program, other)
    }
}

/// One approved tool call. The child may not replace its identity fields.
#[derive(Clone)]
pub(crate) struct ExpectedCallGrant {
    managed_call: Option<Arc<crate::effects::broker::ManagedCallContext>>,
    managed_policy: Option<Arc<crate::effects::authority::SealedManagedCallPolicy>>,
    pub run_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub registry_identity: String,
    pub risk_class: String,
    pub summary: String,
    outcome: Arc<Mutex<PinnedCallOutcome>>,
    pub(crate) plugin_state_call: Option<PluginStateCall>,
}

/// Native-only evidence for one child invocation. Guest return values cannot
/// populate this witness or borrow a sibling invocation's execution token.
#[derive(Clone, Default)]
enum PinnedCallOutcome {
    #[default]
    Pending,
    Preparing,
    Closing,
    Executing {
        token: String,
    },
    Complete {
        result: Arc<JsonValue>,
    },
    Failed {
        error: JsonValue,
    },
}

impl PinnedCallOutcome {
    fn resolve(
        &self,
        child: &JsonValue,
        publication: Option<crate::effects::ManagedPublicationRef>,
    ) -> JsonValue {
        match self {
            Self::Complete { result } => {
                match crate::capabilities::lifecycle::validate_canonical_result(result) {
                    Ok(()) => {
                        if let Some(publication) = publication {
                            let mut outcome = pinned_tool_result_with_limit(
                                result,
                                crate::config::MAX_TOOL_OUTPUT_BYTES,
                            );
                            outcome["managed_publication"] = json!(publication);
                            outcome
                        } else {
                            pinned_tool_result(result)
                        }
                    }
                    Err(error) => {
                        pinned_tool_result(&crate::capabilities::host::error_envelope(&error))
                    }
                }
            }
            Self::Failed { error } if error.get("ok") == Some(&JsonValue::Bool(false)) => {
                pinned_tool_result(error)
            }
            Self::Pending | Self::Preparing | Self::Closing | Self::Executing { .. }
                if child.get("ok") == Some(&JsonValue::Bool(false)) =>
            {
                pinned_tool_result(child)
            }
            Self::Pending
            | Self::Preparing
            | Self::Closing
            | Self::Executing { .. }
            | Self::Failed { .. } => pinned_outcome(
                false,
                "",
                "",
                "pinned_result_uncommitted",
                "pinned tool did not complete a matching durable commit or replay",
                "",
            ),
        }
    }
}

impl ExpectedCallGrant {
    fn matches(&self, metadata: &crate::capabilities::PrepareMetadata) -> bool {
        self.run_id == metadata.run_id
            && self.call_id == metadata.call_id
            && self.tool_name == metadata.tool_name
            && self.argument_digest == metadata.argument_digest
            && self.registry_identity == metadata.registry_identity
            && self.risk_class == metadata.risk_class.as_str()
            && self.summary == metadata.summary
            && self.managed_policy.as_ref().is_none_or(|policy| {
                policy.expected_risk() == metadata.risk_class
                    && self
                        .managed_call
                        .as_ref()
                        .is_some_and(|call| Arc::ptr_eq(policy, &call.policy))
            })
    }
}

/// Injectable host bridges for one compiled runner.
#[derive(Clone, Default)]
pub struct AgentHostBridges {
    pub provider: Option<Arc<dyn AgentProviderHost>>,
    pub auth_host_factory: Option<AuthHostFactory>,
    /// Shared with the runner invocation; never an independent cancellation root.
    pub cancellation: Option<RunCancellation>,
    pub sleeps: Arc<Mutex<SleepLog>>,
    pub skip_sleep: bool,
    #[allow(dead_code)]
    pub metrics: Option<Arc<Metrics>>,
    pub lifecycle: Option<Arc<CapabilityLifecycle>>,
    pub capability_owner: Option<CapabilityOwner>,
    pub filesystem: Option<Arc<FilesystemCapability>>,
    pub processes: Option<Arc<ProcessCapability>>,
    pub artifacts: Option<Arc<ArtifactCapability>>,
    /// Optional test hook invoked from `agent::control_check` before reading
    /// cancellation/deadline. Production callers leave this unset.
    pub control_hook: Option<ControlCheckHook>,
    /// Callable program retained for this run. Absent until admission pins one.
    pub pinned_tool: Option<PinnedToolProgram>,
    /// Set only by a Native host that is explicitly stateless. A missing pin
    /// on a persistent host is a failure, not a reason to compile the embedding.
    pub allow_stateless_pin: bool,
}

/// One sealed state call. It is created only inside `invoke_pinned_tool` from
/// an already sealed pin and the run's durable binding, never from request JSON.
#[derive(Clone)]
pub struct PluginStateCall {
    pub store: crate::plugins::PluginStateStore,
    pub run_id: String,
    pub session_id: String,
    pub profile: String,
    pub graph_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub scope: crate::plugins::PluginStateScope,
    pub schema: u32,
    pub call_id: String,
    pub can_read: bool,
    pub can_write: bool,
    /// True only when admission sealed a managed effect binding for this run.
    /// Direct mode never has one, so guest state cannot be committed without a
    /// Native effect receipt.
    pub managed_effect_commit: bool,
    pub cancellation: crate::RunCancellation,
    staged: Arc<Mutex<Option<StagedPluginState>>>,
}

#[derive(Clone)]
pub(crate) struct StagedPluginState {
    payload: crate::plugins::PluginStatePayload,
    revision: u64,
    publication: crate::effects::journal::ManagedPreparedStatePublication,
    /// Native reservation owner for the staged object. Held from the
    /// reserve-before-put until the publication is taken for prepare; the
    /// prepare/commit path then carries it until the run settles.
    reservation: Option<crate::plugins::PluginStateCandidateLease>,
}

impl PluginStateCall {
    fn snapshot(&self) -> JsonValue {
        if !self.can_read {
            return state_read_failure(
                "plugin_state_undeclared",
                "state read requires a declared workspace.fs.read effect",
            );
        }
        let staged = self
            .staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .cloned();
        if self.scope == crate::plugins::PluginStateScope::Invocation {
            return json!({
                "ok": true,
                "schema": self.schema,
                "revision": staged.as_ref().map_or(1, |staged| staged.revision),
                "document": staged.as_ref().map_or("{}", |staged| staged.payload.as_str()),
                "durable": false,
                "error": null,
            });
        }
        let binding = match self.store.binding(&self.run_id) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                return state_read_failure(
                    "plugin_state_binding_missing",
                    "run state binding is missing",
                );
            }
            Err(error) => return state_read_failure(error.code, &error.message),
        };
        if !self.matches(&binding.binding) {
            return state_read_failure(
                "plugin_state_unauthorized",
                "run state binding does not match the sealed Native identity",
            );
        }
        if let Err(error) =
            self.store
                .authorize(&binding.binding, &self.profile, &self.graph_id, now_ms())
        {
            return state_read_failure(error.code, &error.message);
        }
        json!({
            "ok": true,
            "schema": staged.as_ref().map_or(binding.binding.schema, |staged| staged.publication.schema_version),
            "revision": staged.as_ref().map_or(binding.binding.revision, |staged| staged.revision),
            "document": staged.as_ref().map_or_else(|| binding.payload.as_str().to_string(), |staged| staged.payload.as_str().to_string()),
            "error": null,
        })
    }

    fn write(&self, expected_revision: i64, document: &str) -> JsonValue {
        if !self.can_write {
            return state_write_failure(
                "plugin_state_undeclared",
                "state write requires a declared workspace.fs.write effect",
            );
        }
        if !self.managed_effect_commit {
            return state_write_failure(
                "plugin_state_effect_unavailable",
                "state write requires the managed effect commit",
            );
        }
        let Ok(expected_revision) = u64::try_from(expected_revision) else {
            return state_write_failure("plugin_state_conflict", "state revision is invalid");
        };
        let payload = match crate::plugins::PluginStatePayload::parse(document) {
            Ok(payload) => payload,
            Err(error) => return state_write_failure(error.code, &error.message),
        };
        if self.scope == crate::plugins::PluginStateScope::Invocation {
            let current = self
                .staged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .map_or(1, |staged| staged.revision);
            if current != expected_revision {
                return state_write_failure(
                    "plugin_state_conflict",
                    "state revision does not match",
                );
            }
            let revision = 2;
            let publication = crate::effects::journal::ManagedPreparedStatePublication {
                owner_kind: "invocation".into(),
                owner_id: self.call_id.clone(),
                workspace_id: "invocation".into(),
                branch_id: "invocation".into(),
                plugin_id: self.package_id.clone(),
                package_id: self.package_id.clone(),
                artifact_id: self.artifact_id.clone(),
                schema_version: self.schema,
                expected_revision: 1,
                expected_object_id: "ephemeral".into(),
                object_id: format!("ephemeral:{}:{}:{}", self.run_id, self.call_id, revision),
                ephemeral: true,
            };
            *self
                .staged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(StagedPluginState {
                payload,
                revision,
                publication,
                reservation: None,
            });
            return json!({
                "ok": true,
                "schema": self.schema,
                "revision": revision,
                "durable": false,
                "error": null,
            });
        }
        let binding = match self.store.binding(&self.run_id) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                return state_write_failure(
                    "plugin_state_binding_missing",
                    "run state binding is missing",
                );
            }
            Err(error) => return state_write_failure(error.code, &error.message),
        };
        if !self.matches(&binding.binding) {
            return state_write_failure(
                "plugin_state_unauthorized",
                "run state binding does not match the sealed Native identity",
            );
        }
        if let Err(error) =
            self.store
                .authorize(&binding.binding, &self.profile, &self.graph_id, now_ms())
        {
            return state_write_failure(error.code, &error.message);
        }
        let current_revision = self
            .staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map_or(binding.binding.revision, |staged| staged.revision);
        if current_revision != expected_revision {
            return state_write_failure("plugin_state_conflict", "state revision does not match");
        }
        let (object, reservation) = match self.store.put_object_reserved(
            &binding.binding.package_id,
            &binding.binding.artifact_id,
            binding.binding.schema,
            &payload,
        ) {
            Ok(owned) => owned,
            Err(error) => return state_write_failure(error.code, &error.message),
        };
        let revision = binding.binding.revision.saturating_add(1);
        let publication = crate::effects::journal::ManagedPreparedStatePublication {
            owner_kind: binding.binding.owner_kind.clone(),
            owner_id: binding.binding.owner_id.clone(),
            workspace_id: binding.binding.workspace_id.clone(),
            branch_id: binding.binding.branch_id.clone(),
            plugin_id: binding.binding.plugin_id.clone(),
            package_id: object.package_id.clone(),
            artifact_id: object.artifact_id.clone(),
            schema_version: object.schema,
            expected_revision: binding.binding.revision,
            expected_object_id: binding.binding.object_id.clone(),
            object_id: object.object_id,
            ephemeral: false,
        };
        *self
            .staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(StagedPluginState {
            payload,
            revision,
            publication,
            reservation: Some(reservation),
        });
        json!({
            "ok": true,
            "schema": binding.binding.schema,
            "revision": revision,
            "durable": false,
            "error": null,
        })
    }

    pub(crate) fn acquire_state_writer(
        &self,
        publication: &crate::effects::journal::ManagedPreparedStatePublication,
    ) -> Result<crate::plugins::PluginStateWriterLease, crate::plugins::PluginStateError> {
        let key = crate::plugins::PluginStateRootKey {
            owner_kind: publication.owner_kind.clone(),
            owner_id: publication.owner_id.clone(),
            workspace_id: publication.workspace_id.clone(),
            branch_id: publication.branch_id.clone(),
            plugin_id: publication.plugin_id.clone(),
        };
        self.store.acquire_writer_key(&key, &self.cancellation)
    }

    fn commit_staged_if_any(&self) -> Result<bool, crate::plugins::PluginStateError> {
        let staged = self
            .staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(staged) = staged else {
            return Ok(false);
        };
        if !self.managed_effect_commit || staged.publication.ephemeral {
            return Err(crate::plugins::PluginStateError::new(
                "plugin_state_effect_unavailable",
                "state requires the managed effect commit",
            ));
        }
        let binding = self.store.binding(&self.run_id)?.ok_or_else(|| {
            crate::plugins::PluginStateError::new(
                "plugin_state_binding_missing",
                "run state binding is missing",
            )
        })?;
        self.store
            .commit_with_cancellation(&binding, &staged.payload, &self.cancellation)?;
        Ok(true)
    }

    pub(crate) fn take_state_publication(
        &self,
    ) -> Option<(
        crate::effects::journal::ManagedPreparedStatePublication,
        Option<crate::plugins::PluginStateCandidateLease>,
    )> {
        self.staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .map(|staged| (staged.publication, staged.reservation))
    }

    fn matches(&self, binding: &crate::plugins::PluginStateBinding) -> bool {
        binding.run_id == self.run_id
            && binding.session_id == self.session_id
            && binding.plugin_id == self.package_id
            && binding.package_id == self.package_id
            && binding.artifact_id == self.artifact_id
            && binding.owner_kind == self.scope.as_str()
            && binding.graph_id == self.graph_id
    }
}

/// Caller-side handoff for the one managed state publication. The S2 caller
/// is stateless, so the only publication comes from the child
/// [`PluginStateCall`] held by [`ChildCallRuntime`]; the S1 caller-only path
/// keeps flowing through the caller's own call. The returned writer lease is
/// acquired before `prepare_result` and must be held across prepare and
/// commit, fencing the callee root key for the whole durable decision.
pub(crate) struct DelegatedStateHandoff {
    pub(crate) publication: crate::effects::journal::ManagedPreparedStatePublication,
    pub(crate) owner: Option<crate::plugins::PluginStateCandidateLease>,
    pub(crate) writer: Option<crate::plugins::PluginStateWriterLease>,
}

pub(crate) fn take_managed_state_handoff(
    caller: Option<&PluginStateCall>,
    child: Option<&PluginStateCall>,
) -> Result<Option<DelegatedStateHandoff>, crate::plugins::PluginStateError> {
    let caller_staged = caller.and_then(|call| call.take_state_publication());
    let child_staged = child.and_then(|call| call.take_state_publication());
    match (caller_staged, child_staged) {
        (Some(_), Some(_)) => Err(crate::plugins::PluginStateError::new(
            "managed_prepare_failed",
            "both the caller and the child staged plugin state; refusing to silently drop either",
        )),
        (Some((publication, owner)), None) => {
            let call = caller.expect("a caller publication implies a caller state call");
            let writer = if publication.ephemeral {
                None
            } else {
                Some(call.acquire_state_writer(&publication)?)
            };
            Ok(Some(DelegatedStateHandoff {
                publication,
                owner,
                writer,
            }))
        }
        (None, Some((publication, owner))) => {
            let call = child.expect("a child publication implies a child state call");
            let writer = if publication.ephemeral {
                None
            } else {
                Some(call.acquire_state_writer(&publication)?)
            };
            Ok(Some(DelegatedStateHandoff {
                publication,
                owner,
                writer,
            }))
        }
        (None, None) => Ok(None),
    }
}

/// Production constructor for the S2 child state call. It returns `None` for
/// the S1 stateless path (no callee declaration) and for any declaration
/// that is not run-scoped schema 1 without a migration. Otherwise it builds
/// the child [`PluginStateCall`] from the callee's own declaration, contract
/// and live run binding; a missing store/binding or an identity mismatch is
/// a typed error, never a silent `None` and never a panic. Each argument is
/// one independently proven identity/declaration fact of that single child
/// call, so a bag struct would only hide which fact a caller must supply.
#[allow(clippy::too_many_arguments)]
pub(crate) fn child_state_call_for(
    store: Option<&crate::plugins::PluginStateStore>,
    callee_package: &str,
    callee_artifact: &str,
    callee_state: Option<&crate::plugins::StateDeclaration>,
    callee_contract: Option<&crate::effects::broker::ManagedEntryContract>,
    run_id: &str,
    session_id: &str,
    profile: &str,
    graph_id: &str,
    call_id: &str,
    cancellation: &RunCancellation,
) -> Result<Option<PluginStateCall>, crate::plugins::PluginStateError> {
    let Some(declaration) = callee_state else {
        return Ok(None);
    };
    if declaration.scope != "run" || declaration.schema != 1 || declaration.migration.is_some() {
        return Ok(None);
    }
    let Some(store) = store else {
        return Err(crate::plugins::PluginStateError::new(
            "plugin_state_binding_missing",
            "sealed run has no durable plugin state binding",
        ));
    };
    let contract = callee_contract.ok_or_else(|| {
        crate::plugins::PluginStateError::new(
            "plugin_state_binding_missing",
            "sealed run has no durable plugin state binding",
        )
    })?;
    let declared = |kind: &str| {
        contract
            .effects
            .iter()
            .any(|effect| effect.kind == kind && effect.scope == "bound_workspace")
    };
    let snapshot = store
        .binding(run_id)
        .map_err(|error| crate::plugins::PluginStateError::new(error.code, error.message))?;
    let Some(snapshot) = snapshot else {
        return Err(crate::plugins::PluginStateError::new(
            "plugin_state_binding_missing",
            "run state binding is missing",
        ));
    };
    let binding = &snapshot.binding;
    let schema = u32::try_from(declaration.schema).map_err(|_| {
        crate::plugins::PluginStateError::new("plugin_state_invalid", "state schema is invalid")
    })?;
    if binding.plugin_id != callee_package
        || binding.package_id != callee_package
        || binding.artifact_id != callee_artifact
        || binding.schema != schema
        || binding.graph_id != graph_id
        || binding.owner_kind != "run"
        || binding.owner_id != run_id
    {
        return Err(crate::plugins::PluginStateError::new(
            "plugin_state_unauthorized",
            "run state binding does not match the sealed Native identity",
        ));
    }
    Ok(Some(PluginStateCall {
        store: store.clone(),
        run_id: run_id.to_string(),
        session_id: session_id.to_string(),
        profile: profile.to_string(),
        graph_id: graph_id.to_string(),
        package_id: callee_package.to_string(),
        artifact_id: callee_artifact.to_string(),
        scope: crate::plugins::PluginStateScope::Run,
        schema,
        call_id: call_id.to_string(),
        can_read: declared("workspace.fs.read"),
        can_write: declared("workspace.fs.write"),
        managed_effect_commit: true,
        cancellation: cancellation.clone(),
        staged: Arc::new(Mutex::new(None)),
    }))
}

fn state_read_failure(code: &str, message: &str) -> JsonValue {
    json!({
        "ok": false,
        "schema": 0,
        "revision": 0,
        "document": "",
        "error": { "code": code, "message": message },
    })
}

fn state_write_failure(code: &str, message: &str) -> JsonValue {
    json!({
        "ok": false,
        "schema": 0,
        "revision": 0,
        "error": { "code": code, "message": message },
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Per-VM state installed before `run(context)`.
#[derive(Clone)]
pub struct AgentHostState {
    pub provider: Arc<dyn AgentProviderHost>,
    pub cancellation: RunCancellation,
    pub sleeps: Arc<Mutex<SleepLog>>,
    pub skip_sleep: bool,
    #[allow(dead_code)]
    pub metrics: Option<Arc<Metrics>>,
    pub lifecycle: Option<Arc<CapabilityLifecycle>>,
    pub capability_owner: Option<CapabilityOwner>,
    pub filesystem: Option<Arc<FilesystemCapability>>,
    pub processes: Option<Arc<ProcessCapability>>,
    pub artifacts: Option<Arc<ArtifactCapability>>,
    pub(crate) leases: Arc<Mutex<HashMap<String, ExecutionLease>>>,
    pub(crate) control_hook: Option<ControlCheckHook>,
    pub(crate) pinned_tool: Option<PinnedToolProgram>,
    pub(crate) allow_stateless_pin: bool,
    pub(crate) expected_call: Option<ExpectedCallGrant>,
    pub plugin_state_call: Option<PluginStateCall>,
    pub(crate) provider_arguments: Arc<Mutex<HashMap<(String, String), JsonValue>>>,
    /// Crate-private caller-side plumbing for the one captured child call.
    pub(crate) child_call: Option<Arc<ChildCallRuntime>>,
    /// Crate-private child-side adapter; only child-role closures see it.
    pub(crate) child_read: Option<Arc<ChildFilesystemReadAdapter>>,
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
        let envelope = normalize_provider_envelope(self.provider.call(request, &self.cancellation));
        let mut parents = self
            .provider_arguments
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        parents.clear();
        if let Some(calls) = envelope
            .get("response")
            .and_then(|response| response.get("tool_calls"))
            .and_then(JsonValue::as_array)
        {
            for call in calls {
                let key = (
                    call.get("id")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("")
                        .to_string(),
                    call.get("name")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("")
                        .to_string(),
                );
                let arguments = call
                    .get("arguments")
                    .filter(|value| value.is_object())
                    .cloned()
                    .or_else(|| {
                        let text = call.get("arguments_json")?.as_str()?;
                        if json_object_rejected(text) {
                            return None;
                        }
                        serde_json::from_str::<JsonValue>(text)
                            .ok()
                            .filter(JsonValue::is_object)
                    })
                    .unwrap_or(JsonValue::Null);
                if let std::collections::hash_map::Entry::Vacant(entry) = parents.entry(key.clone())
                {
                    entry.insert(arguments);
                } else {
                    parents.insert(key, JsonValue::Null);
                }
            }
        }
        envelope
    }

    fn approval_storage(&self, operation: &str, payload: &JsonValue) -> JsonValue {
        if let Some(error) = self.control_error() {
            return error;
        }
        self.provider
            .approval_storage(operation, payload, &self.cancellation)
    }

    fn refresh_context(&self, context: &JsonValue) -> JsonValue {
        if let Some(error) = self.control_error() {
            return error;
        }
        self.provider
            .refresh_context(context, &self.cancellation)
            .unwrap_or_else(|| {
                json!({
                    "ok": true,
                    "messages": context.get("messages").cloned().unwrap_or_else(|| json!([])),
                })
            })
    }

    #[cfg(all(test, feature = "workspace-io-fault"))]
    pub(crate) fn invoke_managed_boundary_for_test(&self, request: &JsonValue) -> JsonValue {
        self.invoke_pinned_tool(request)
    }

    #[cfg(all(test, feature = "workspace-io-fault"))]
    pub(crate) fn changed_managed_child_prepare_for_test(
        &self,
        call: Arc<crate::effects::broker::ManagedCallContext>,
        canonical: &str,
        changed: &JsonValue,
    ) -> JsonValue {
        let mut child = self.clone();
        child.pinned_tool = None;
        child.expected_call = Some(ExpectedCallGrant {
            managed_policy: Some(Arc::clone(&call.policy)),
            run_id: call.identity.owner.run_id.clone(),
            call_id: call.identity.call_id.clone(),
            tool_name: call.identity.tool_name.clone(),
            argument_digest: canonical.into(),
            registry_identity: call.identity.code.registry_identity.clone(),
            risk_class: call.policy.expected_risk().as_str().into(),
            summary: "probe".into(),
            outcome: Arc::new(Mutex::new(PinnedCallOutcome::Pending)),
            plugin_state_call: None,
            managed_call: Some(call),
        });
        child.capability_prepare(changed).unwrap_or_else(|message| {
            pinned_outcome(false, "", "", "pinned_tool_prepare_aborted", &message, "")
        })
    }

    fn capability_prepare(&self, metadata: &JsonValue) -> Result<JsonValue, String> {
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return Ok(crate::capabilities::host::error_envelope(
                &LifecycleError::InvalidMetadata(
                    "capability lifecycle is not installed".to_string(),
                ),
            ));
        };
        let Some(owner) = self.capability_owner.as_ref() else {
            return Ok(crate::capabilities::host::error_envelope(
                &LifecycleError::InvalidMetadata("capability owner is not installed".to_string()),
            ));
        };
        let parsed = match parse_prepare_metadata(metadata) {
            Ok(metadata) => metadata,
            Err(error) => return Ok(crate::capabilities::host::error_envelope(&error)),
        };
        if let Some(grant) = &self.expected_call
            && !grant.matches(&parsed)
        {
            return Ok(pinned_call_mismatch());
        }
        let mut outcome = self.expected_call.as_ref().map(|grant| {
            grant
                .outcome
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        });
        if outcome
            .as_deref()
            .is_some_and(|outcome| !matches!(outcome, PinnedCallOutcome::Pending))
        {
            return Ok(pinned_call_mismatch());
        }
        if let Some(outcome) = outcome.as_deref_mut() {
            *outcome = PinnedCallOutcome::Preparing;
        }
        drop(outcome);
        let mut envelope = tool_prepare(lifecycle, owner, parsed);
        if let Some(call) = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.managed_call.as_ref())
            && envelope.get("kind").and_then(JsonValue::as_str) == Some("execute")
            && let Some(token) = envelope.get("execution_token").and_then(JsonValue::as_str)
        {
            let bound = lifecycle
                .authorize(owner, token, call.policy.expected_risk())
                .map_err(|e| e.code().to_string())
                .and_then(|claims| {
                    call.bind_execution(token, &claims, lifecycle.as_ref().clone(), owner.clone())
                });
            if let Err(message) = bound {
                if let Ok(lease) = lifecycle.lease(token) {
                    drop(lease);
                }
                // Only the actual Native-origin injected cut leaves this
                // witness. A guest cannot construct it, so every ordinary
                // prepare/bind/auth refusal keeps the recoverable envelope.
                #[cfg(feature = "workspace-io-fault")]
                if call.take_after_intent_cut() {
                    return Err(message);
                }
                envelope = typed_fail("managed_view_unavailable", &message);
            }
        }
        let complete_result = envelope.get("result").cloned().map(Arc::new);
        let mut outcome = self
            .expected_call
            .as_ref()
            .map(|grant| grant.outcome.lock().unwrap_or_else(|p| p.into_inner()));
        if envelope.get("ok") == Some(&JsonValue::Bool(true))
            && envelope.get("kind") == Some(&JsonValue::String("execute".to_string()))
            && let Some(token) = envelope.get("execution_token").and_then(JsonValue::as_str)
            && let Ok(lease) = lifecycle.lease(token)
        {
            self.leases
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(token.to_string(), lease);
            if let Some(outcome) = outcome.as_deref_mut() {
                *outcome = PinnedCallOutcome::Executing {
                    token: token.to_string(),
                };
            }
        } else if let Some(outcome) = outcome.as_deref_mut() {
            *outcome = if envelope.get("ok") == Some(&JsonValue::Bool(true))
                && envelope.get("kind").and_then(JsonValue::as_str) == Some("replay")
                && let Some(result) = complete_result.as_ref()
            {
                PinnedCallOutcome::Complete {
                    result: Arc::clone(result),
                }
            } else {
                PinnedCallOutcome::Failed {
                    error: envelope.clone(),
                }
            };
        }
        Ok(envelope)
    }

    /// Caller-role bridge for the one captured stateless child call. The
    /// request carries only bounded canonical arguments: no callee selector,
    /// call/run/owner/registry/edge/code/risk/effect identity, token, digest
    /// or mapping. Every other identity is Native-derived.
    fn invoke_pinned_plugin_child(&self, request: &Value) -> JsonValue {
        let canonical = match request {
            Value::Map(entries) if entries.len() == 1 => match entries.iter().next() {
                Some((Value::String(key), Value::String(value)))
                    if key.as_str() == "canonical_arguments" =>
                {
                    value.as_str()
                }
                _ => {
                    return pinned_outcome(
                        false,
                        "",
                        "",
                        "pinned_child_request_invalid",
                        "child request must carry exactly one canonical_arguments string",
                        "",
                    );
                }
            },
            _ => {
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "pinned_child_request_invalid",
                    "child request must be one named record",
                    "",
                );
            }
        };
        self.invoke_pinned_plugin_child_canonical(canonical)
    }

    fn invoke_pinned_plugin_child_canonical(&self, canonical: &str) -> JsonValue {
        let Some(runtime) = self.child_call.clone() else {
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_child_unavailable",
                "this invocation carries no exclusive child gate",
                "",
            );
        };
        let pinned = runtime.pinned.clone();
        let template = Arc::clone(&runtime.template);
        if let Some(error) = self.binding_mismatch(&pinned) {
            return error;
        }
        // Sealed-template identity cross-check: the captured child belongs to
        // exactly this caller/graph/run/workspace identity.
        if template.caller_package != pinned.package_id
            || template.run_id != pinned.run_id
            || template.session_id != pinned.session_id
            || template.profile != pinned.profile
            || template.workspace != pinned.workspace
            || template.callee_code.package_id != template.callee_package
            || template.callee_code.artifact_id != template.callee_artifact
            || template.callee_code.export != template.callee_export
            || template.callee_code.graph_id != pinned.graph_id
            || template.callee_code.graph_ref_id != pinned.ref_id()
            || template.callee_code.activation_generation != pinned.generation()
        {
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_child_unavailable",
                "captured child template does not match the sealed caller identity",
                "",
            );
        }
        let Some(call) = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.managed_call.clone())
        else {
            return pinned_outcome(
                false,
                "",
                "",
                "managed_call_unavailable",
                "no managed parent call is installed",
                "",
            );
        };
        // Count the full typed request encoding before copying or parsing it.
        let encoded = match count_typed_child_request(canonical) {
            Ok(bytes) => bytes,
            Err(message) => {
                return pinned_outcome(false, "", "", "pinned_child_request_invalid", &message, "");
            }
        };
        if encoded > call.meter().remaining() {
            return pinned_outcome(
                false,
                "",
                "",
                "managed_output_budget_exceeded",
                "typed child request exceeds the remaining aggregate budget",
                "",
            );
        }
        // Charge before the first Native-owned copy or parse of the request.
        let _request_charge = match call.meter().charge_new(encoded, "typed delegation request") {
            Ok(charge) => charge,
            Err(message) => {
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "managed_output_budget_exceeded",
                    &message,
                    "",
                );
            }
        };
        // The parsed projection is the same representation as the charged
        // typed request: adopt the charge instead of charging it twice.
        let _object_charge = call.meter().adopt(&_request_charge);
        let expected = match pinned.derive_child_request(&call.identity.tool_name, call.original())
        {
            Ok(object) => object,
            Err(message) => {
                return pinned_outcome(false, "", "", "managed_descriptor_rejected", &message, "");
            }
        };
        let Ok(parsed) = serde_json::from_str::<JsonValue>(canonical) else {
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_child_request_invalid",
                "child arguments are not JSON",
                "",
            );
        };
        if parsed != expected {
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_child_projection_mismatch",
                "child arguments differ from the original parent argument projection",
                "",
            );
        }
        let Some(claim) = runtime.gate.claim() else {
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_child_already_claimed",
                "another attempt already owns this call's child gate",
                "",
            );
        };
        if let Err(message) = call.check_child_operable() {
            runtime.gate.abort();
            return pinned_outcome(false, "", "", "managed_view_unavailable", &message, "");
        }
        let proof = crate::effects::journal::ManagedDelegationIntent {
            parent_call_id: call.identity.call_id.clone(),
            parent_effect_id: call.effect_id.clone(),
            caller_code: call.identity.code.clone(),
            callee_code: template.callee_code.clone(),
            edge_alias: template.edge_alias.clone(),
            from_entry: template.from_entry.clone(),
            to_entry: template.to_entry.clone(),
            effect: crate::effects::journal::ManagedDelegationEffect {
                kind: template.effect.kind.clone(),
                scope: template.effect.scope.clone(),
                recovery: template.effect.recovery.clone(),
            },
            callee_tool: template.callee_tool.clone(),
            child_arguments: call.identity.argument_identity.clone(),
            epoch: call.identity.epoch,
            expected_head: call.identity.expected_head.clone(),
            expected_head_version: call.identity.expected_head_version,
        };
        match call.delegate_intent(proof.clone()) {
            Ok(crate::effects::journal::IntentCasOutcome::WrittenByThisAttempt) => {}
            Ok(crate::effects::journal::IntentCasOutcome::Refused) => {
                runtime.gate.abort();
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "managed_delegation_intent_refused",
                    "the parent intent row refused this delegation write",
                    "",
                );
            }
            Ok(crate::effects::journal::IntentCasOutcome::Unknown) => {
                runtime.gate.abort();
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "managed_delegation_intent_unknown",
                    "the delegation intent write result is unknown; no child executed",
                    "",
                );
            }
            Err(message) => {
                runtime.gate.abort();
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "managed_delegation_intent_unknown",
                    &message,
                    "",
                );
            }
        }
        if !runtime.gate.invoke(claim) {
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_child_gate_closed",
                "the child gate is no longer owned by this attempt",
                "",
            );
        }
        // One child VM in its own captured program/entry/registry. It receives
        // no lifecycle, owner, provider, process, artifact, storage or full
        // filesystem slot; only the private narrow read adapter plus, on the
        // S2 path, the callee's own run state call (shared staged Arc, so the
        // caller side observes the child publication after the VM exits).
        let runner_context = json!({
            "prepare": {
                "run_id": pinned.run_id,
                "call_id": call.identity.call_id,
                "tool_name": template.callee_tool,
                "name": template.callee_tool,
                "argument_digest": call.original(),
                "registry_identity": template.callee_code.registry_identity,
                "risk_class": "read",
                "summary": "delegated read",
            },
            "arguments": expected,
        });
        let filesystem = match call.adapters(&self.execution_token()) {
            Ok(adapter) => Arc::clone(&adapter.filesystem),
            Err(message) => {
                runtime.gate.abort();
                return pinned_outcome(false, "", "", "managed_view_unavailable", &message, "");
            }
        };
        let adapter = Arc::new(ChildFilesystemReadAdapter {
            filesystem,
            token: self.execution_token(),
            gate: Arc::clone(&runtime.gate),
            call: Arc::downgrade(&call),
            pinned: pinned.clone(),
            cancellation: self.cancellation.clone(),
        });
        let child_host = AgentHostBridges {
            provider: None,
            auth_host_factory: None,
            cancellation: Some(self.cancellation.clone()),
            sleeps: Default::default(),
            skip_sleep: self.skip_sleep,
            metrics: None,
            lifecycle: None,
            capability_owner: None,
            filesystem: None,
            processes: None,
            artifacts: None,
            control_hook: None,
            pinned_tool: None,
            allow_stateless_pin: false,
        };
        // One real callee VM entry. Counted for tests so a losing contender can
        // prove it never launched the child.
        #[cfg(test)]
        call.note_child_invocation();
        let child_value = match super::rss_runner::invoke_retained_child(
            Arc::clone(&template.callee_program),
            &template.callee_entry,
            child_host,
            json_to_vm_value(&runner_context),
            &self.cancellation,
            &template.callee_registry,
            adapter,
            runtime.child_state_call.clone(),
        ) {
            Ok(value) => value,
            Err(message) => {
                runtime.gate.abort();
                return pinned_outcome(false, "", "", "pinned_child_failed", &message, "");
            }
        };
        // Bound the child VM value in its typed representation before it is
        // converted: the walk never allocates, so an oversized result is refused
        // before the complete JSON copy and the canonical string exist.
        let typed = vm_value_typed_bytes(&child_value);
        if typed > call.meter().remaining() {
            runtime.gate.abort();
            return pinned_outcome(
                false,
                "",
                "",
                "managed_output_budget_exceeded",
                "the child result exceeds the remaining aggregate budget",
                "",
            );
        }
        // Refuse invalid bytes first, then measure the exact canonical encoding
        // through the bounded counting writer. Only a result that already fits
        // is converted into a complete JSON tree; the lossy byte conversion is
        // never reached on this path.
        if let Err(message) = validate_guest_result(&child_value) {
            runtime.gate.abort();
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_child_result_unrepresentable",
                &message,
                "",
            );
        }
        if let Err(message) = crate::effects::journal::BoundedJsonCounter::measure(
            &GuestResultJson(&child_value),
            call.meter().remaining(),
        ) {
            runtime.gate.abort();
            return pinned_outcome(
                false,
                "",
                "",
                "managed_output_budget_exceeded",
                &message,
                "",
            );
        }
        let child_json = match guest_result_json(&child_value) {
            Ok(value) => value,
            Err(message) => {
                runtime.gate.abort();
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "pinned_child_result_unrepresentable",
                    &message,
                    "",
                );
            }
        };
        let canonical_result = match canonical_child_result(&child_json, call.meter().remaining()) {
            Ok(result) => result,
            Err(message) => {
                runtime.gate.abort();
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "pinned_child_result_unrepresentable",
                    &message,
                    "",
                );
            }
        };
        if let Err(message) = call.meter().charge_new(
            canonical_result.as_str().len() as u64,
            "canonical child result",
        ) {
            runtime.gate.abort();
            return pinned_outcome(
                false,
                "",
                "",
                "managed_output_budget_exceeded",
                &message,
                "",
            );
        }
        let object = match call.store_child_result(&canonical_result) {
            Ok(object) => object,
            Err(message) => {
                runtime.gate.abort();
                return pinned_outcome(
                    false,
                    "",
                    "",
                    "pinned_child_result_unretained",
                    &message,
                    "",
                );
            }
        };
        let (child_result, lease) = object.into_complete_parts();
        runtime
            .gate
            .complete(crate::effects::broker::ManagedDelegationComplete {
                proof,
                child_result,
                _lease: lease,
            });
        // The bridge itself completed, so the child owns a retained canonical
        // result. A representable child error is surfaced as the caller-facing
        // failure code while the same result stays the Complete proof value.
        let child_view: JsonValue =
            serde_json::from_str(canonical_result.as_str()).unwrap_or(JsonValue::Null);
        if child_view.get("ok") == Some(&JsonValue::Bool(false)) {
            let code = child_view
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(JsonValue::as_str)
                .unwrap_or("delegated_child_failed");
            let message = child_view
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(JsonValue::as_str)
                .unwrap_or("the delegated read failed");
            return pinned_outcome(
                false,
                "",
                "delegated",
                code,
                message,
                canonical_result.as_str(),
            );
        }
        pinned_outcome(true, "", "delegated", "", "", canonical_result.as_str())
    }

    /// The parent's Native execution token, read from the sealed grant
    /// outcome. It never comes from request JSON and is never returned.
    fn execution_token(&self) -> String {
        self.expected_call
            .as_ref()
            .and_then(|grant| {
                match &*grant
                    .outcome
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                {
                    PinnedCallOutcome::Executing { token } => Some(token.clone()),
                    _ => None,
                }
            })
            .unwrap_or_default()
    }

    fn invoke_pinned_tool(&self, request: &JsonValue) -> JsonValue {
        let pinned = match self.pinned_tool.clone() {
            Some(pinned) => pinned,
            None => {
                if !self.allow_stateless_pin {
                    return pinned_outcome(
                        false,
                        "",
                        "",
                        "pinned_tool_missing",
                        "this run has no retained tool program",
                        "",
                    );
                }
                match self.stateless_default_binding() {
                    Some(pinned) => pinned,
                    None => {
                        return pinned_outcome(
                            false,
                            "",
                            "",
                            "pinned_tool_missing",
                            "this run has no retained tool program",
                            "",
                        );
                    }
                }
            }
        };
        if let Some(error) = self.binding_mismatch(&pinned) {
            return error;
        }
        let field = |key: &str| {
            request
                .get(key)
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string()
        };
        let requested_run = field("run_id");
        if !requested_run.is_empty() && requested_run != pinned.run_id {
            return pinned_binding_mismatch();
        }
        let requested_registry = field("registry_identity");
        if !requested_registry.is_empty() && requested_registry != pinned.registry_identity {
            return pinned_binding_mismatch();
        }
        let _ignored_graph = request.get("untrusted_graph_id");
        let canonical = field("canonical_arguments");
        let digest = field("argument_digest");
        if canonical.is_empty() || digest != canonical || json_object_rejected(&canonical) {
            return pinned_call_mismatch();
        }
        let Ok(arguments) = serde_json::from_str::<JsonValue>(&canonical) else {
            return pinned_call_mismatch();
        };
        if !arguments.is_object() {
            return pinned_call_mismatch();
        }
        let call_id = field("call_id");
        let tool_name = field("tool_name");
        let expected = match self.lifecycle.as_ref().zip(self.capability_owner.as_ref()) {
            Some((lifecycle, owner)) => {
                match lifecycle.parent_arguments(owner, &call_id, &tool_name) {
                    Ok(Some(arguments)) => Some(arguments),
                    Ok(None) => self
                        .provider_arguments
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .get(&(call_id.clone(), tool_name.clone()))
                        .cloned(),
                    Err(_) => None,
                }
            }
            None => None,
        };
        if expected.as_ref() != Some(&arguments) {
            return pinned_call_mismatch();
        }
        // Fresh execution authorization from the original control-store owner,
        // after the sealed owner/run/registry/parent checks and before any
        // replay or child dispatch. The envelope carries the exact typed code
        // in both fields so outer layers that only propagate messages keep
        // the exact refusal observable. Historical receipts stay queryable;
        // only execution is refused here.
        if let Err(code) = pinned.check_execution_authority(Some(&self.cancellation)) {
            return pinned_outcome(false, "", "", code, code, "");
        }
        if let Some(binding) = &pinned.managed {
            let replay = if pinned.child.is_some() {
                // Re-derived from the current sealed pin and the original
                // parent arguments without launching either VM. The durable
                // effect id/epoch/head are verified against the record.
                match pinned.derive_child_proof(
                    &binding.code,
                    &call_id,
                    &tool_name,
                    &canonical,
                    "",
                    0,
                    "",
                    0,
                    binding
                        .call(&call_id)
                        .map(|call| call.identity.argument_identity.clone())
                        .unwrap_or(crate::effects::journal::ManagedArgumentIdentity::Inline {
                            canonical_arguments: canonical.clone(),
                        }),
                ) {
                    Ok(proof) => binding.replay_live(
                        &call_id,
                        &tool_name,
                        Some(&arguments),
                        Some(&canonical),
                        crate::effects::broker::ExpectedDelegation::Required(Box::new(proof)),
                    ),
                    Err(_) => {
                        return pinned_outcome(
                            false,
                            "",
                            "",
                            "managed_descriptor_rejected",
                            "the current pin rejected the original parent arguments",
                            "",
                        );
                    }
                }
            } else {
                binding.replay_live(
                    &call_id,
                    &tool_name,
                    Some(&arguments),
                    Some(&canonical),
                    crate::effects::broker::ExpectedDelegation::Absent,
                )
            };
            match replay {
                Ok(Some(replay)) => {
                    let mut outcome = pinned_tool_result_with_limit(
                        &replay.result,
                        crate::config::MAX_TOOL_OUTPUT_BYTES,
                    );
                    outcome["managed_publication"] = json!(replay.outcome.publication);
                    outcome["kind"] = json!("replay");
                    return outcome;
                }
                Ok(None) => {}
                Err(message) => {
                    // The execution guard speaks the exact typed codes; every
                    // other replay failure keeps the existing managed envelope.
                    // The code rides in both fields so message-only outer
                    // layers keep the exact refusal observable.
                    let code = match message.as_str() {
                        "plugin_graph_revoked" => "plugin_graph_revoked",
                        "plugin_graph_pin_required" => "plugin_graph_pin_required",
                        "cancelled" => "cancelled",
                        "deadline_elapsed" => "deadline_elapsed",
                        _ => {
                            return pinned_outcome(
                                false,
                                "",
                                "",
                                "managed_effect_denied",
                                &message,
                                "",
                            );
                        }
                    };
                    return pinned_outcome(false, "", "", code, code, "");
                }
            }
        }
        let risk_class = field("risk_class");
        let summary = field("summary");
        let managed_policy = match parse_prepare_metadata(&json!({
            "run_id":pinned.run_id, "call_id":call_id, "tool_name":tool_name, "argument_digest":canonical, "registry_identity":pinned.registry_identity, "risk_class":risk_class, "summary":summary
        })).map_err(|e| format!("{e:?}")).and_then(|metadata| self.checked_managed_policy(&metadata, Some(&arguments))) {
            Ok(policy) => policy,
            Err(message) => return pinned_outcome(false, "", "", "managed_effect_denied", &message, ""),
        };
        let canonical_input = field("canonical_input");
        let context = if pinned.expects_dispatch_input {
            if canonical_input.is_empty() || json_object_rejected(&canonical_input) {
                return pinned_call_mismatch();
            }
            let Ok(input) = serde_json::from_str::<JsonValue>(&canonical_input) else {
                return pinned_call_mismatch();
            };
            let call_arguments = input
                .get("call")
                .and_then(|call| call.get("arguments"))
                .cloned()
                .unwrap_or(JsonValue::Null);
            let call = input.get("call").unwrap_or(&JsonValue::Null);
            if call_arguments != arguments
                || call
                    .get("id")
                    .and_then(JsonValue::as_str)
                    .filter(|id| !id.is_empty())
                    .or_else(|| call.get("tool_call_id").and_then(JsonValue::as_str))
                    != Some(call_id.as_str())
                || call.get("name").and_then(JsonValue::as_str) != Some(tool_name.as_str())
            {
                return pinned_call_mismatch();
            }
            json!({
                "call": call,
                "prepared_context": {
                    "kind": "execute",
                    "prepare": {
                        "run_id": pinned.run_id,
                        "call_id": call_id.clone(),
                        "tool_name": tool_name.clone(),
                        "name": tool_name.clone(),
                        "argument_digest": canonical.clone(),
                        "registry_identity": pinned.registry_identity,
                        "risk_class": risk_class.clone(),
                        "summary": summary.clone(),
                    },
                    "arguments": arguments,
                    "config": input.get("config").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({})),
                }
            })
        } else {
            json!({
                "prepare": {
                    "run_id": pinned.run_id,
                    "call_id": call_id.clone(),
                    "tool_name": tool_name.clone(),
                    "name": tool_name.clone(),
                    "argument_digest": canonical.clone(),
                    "registry_identity": pinned.registry_identity,
                    "risk_class": risk_class.clone(),
                    "summary": summary.clone(),
                },
                "arguments": arguments
            })
        };
        let outcome = Arc::new(Mutex::new(PinnedCallOutcome::Pending));
        let mut grant = ExpectedCallGrant {
            managed_call: match pinned.managed.as_ref() {
                Some(binding) => match binding.register(
                    &call_id,
                    &tool_name,
                    &canonical,
                    match managed_policy.as_ref() {
                        Some(policy) => Arc::clone(policy),
                        None => return pinned_binding_mismatch(),
                    },
                    self.lifecycle
                        .as_ref()
                        .map_or(0, |life| life.original_deadline_ms()),
                    pinned.child_template().is_some(),
                ) {
                    Ok(call) => Some(call),
                    Err(message) => {
                        return pinned_outcome(
                            false,
                            "",
                            "",
                            "managed_effect_denied",
                            &message,
                            "",
                        );
                    }
                },
                None => None,
            },
            managed_policy,
            run_id: pinned.run_id.clone(),
            call_id: call_id.clone(),
            tool_name,
            argument_digest: canonical,
            registry_identity: pinned.registry_identity.clone(),
            risk_class,
            summary,
            outcome: Arc::clone(&outcome),
            plugin_state_call: None,
        };
        if grant.call_id.is_empty() || grant.tool_name.is_empty() {
            return pinned_call_mismatch();
        }
        let plugin_state_call = if pinned.state.is_some() {
            match self.plugin_state_call_for(&pinned, &call_id, grant.managed_call.is_some()) {
                Some(call) => Some(call),
                None => {
                    return pinned_outcome(
                        false,
                        "",
                        "",
                        "plugin_state_binding_missing",
                        "sealed run has no durable plugin state binding",
                        "",
                    );
                }
            }
        } else {
            None
        };
        grant.plugin_state_call = plugin_state_call;
        let managed_call = grant.managed_call.clone();
        let host = AgentHostBridges {
            provider: None,
            auth_host_factory: None,
            cancellation: Some(self.cancellation.clone()),
            sleeps: Arc::clone(&self.sleeps),
            skip_sleep: self.skip_sleep,
            metrics: self.metrics.clone(),
            lifecycle: self.lifecycle.clone(),
            capability_owner: self.capability_owner.clone(),
            filesystem: self.filesystem.clone(),
            processes: self.processes.clone(),
            artifacts: self.artifacts.clone(),
            control_hook: self.control_hook.clone(),
            pinned_tool: None,
            allow_stateless_pin: false,
        };
        // The exclusive child gate exists before the caller VM starts and is
        // attached to this call for its whole lifetime.
        let child_gate = Arc::new(ChildCallGate::new());
        #[cfg(test)]
        if let Some(binding) = pinned.managed.as_ref()
            && let Some(observer) = binding.runtime.child_gate_observer.lock().clone()
        {
            observer(Arc::clone(&child_gate));
        }
        let child_call = match pinned.child_template().cloned() {
            Some(template) => {
                // S2 populates the child call from the callee run binding;
                // S1 has no callee run declaration and stays None.
                let child_state_call = match self.child_state_call_for_pinned(
                    &template,
                    pinned.state_store.as_ref(),
                    &call_id,
                ) {
                    Ok(call) => call,
                    Err(error) => {
                        return pinned_outcome(false, "", "", error.code, &error.message, "");
                    }
                };
                Some(Arc::new(ChildCallRuntime {
                    gate: Arc::clone(&child_gate),
                    template,
                    pinned: pinned.clone(),
                    child_state_call,
                }))
            }
            None => None,
        };
        match super::rss_runner::invoke_retained_tool_with_child(
            Arc::clone(&pinned.program),
            &pinned.entry,
            host,
            json_to_vm_value(&context),
            &self.cancellation,
            &pinned.registry,
            Some(grant),
            child_call,
        ) {
            Ok(value) => {
                let snapshot = outcome
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                snapshot.resolve(
                    &vm_value_to_json(&value),
                    managed_call.as_ref().and_then(|call| call.publication()),
                )
            }
            Err(error) => pinned_outcome(false, "", "", "pinned_tool_failed", &error, ""),
        }
    }

    fn plugin_state_call_for(
        &self,
        pinned: &PinnedToolProgram,
        call_id: &str,
        managed_effect_commit: bool,
    ) -> Option<PluginStateCall> {
        let store = pinned.state_store.clone()?;
        let declaration = pinned.state.as_ref()?;
        let scope = crate::plugins::PluginStateScope::parse(&declaration.scope)?;
        let declared = |kind: &str| {
            pinned.managed_contract.as_ref().is_some_and(|contract| {
                contract
                    .effects
                    .iter()
                    .any(|effect| effect.kind == kind && effect.scope == "bound_workspace")
            })
        };
        if scope == crate::plugins::PluginStateScope::Invocation {
            return Some(PluginStateCall {
                store,
                run_id: pinned.run_id.clone(),
                session_id: pinned.session_id.clone(),
                profile: pinned.profile.clone(),
                graph_id: pinned.graph_id.clone(),
                package_id: pinned.package_id.clone(),
                artifact_id: pinned.artifact_id.clone(),
                scope,
                schema: u32::try_from(declaration.schema).ok()?,
                call_id: call_id.to_string(),
                can_read: declared("workspace.fs.read"),
                can_write: declared("workspace.fs.write"),
                managed_effect_commit,
                cancellation: self.cancellation.clone(),
                staged: Arc::new(Mutex::new(None)),
            });
        }
        let binding = pinned.state_binding.as_ref()?;
        Some(PluginStateCall {
            store,
            run_id: pinned.run_id.clone(),
            session_id: pinned.session_id.clone(),
            profile: pinned.profile.clone(),
            graph_id: pinned.graph_id.clone(),
            package_id: binding.package_id.clone(),
            artifact_id: binding.artifact_id.clone(),
            scope,
            schema: binding.schema,
            call_id: call_id.to_string(),
            can_read: declared("workspace.fs.read"),
            can_write: declared("workspace.fs.write"),
            managed_effect_commit: pinned.managed.is_some(),
            cancellation: self.cancellation.clone(),
            staged: Arc::new(Mutex::new(None)),
        })
    }

    fn child_state_call_for_pinned(
        &self,
        template: &PinnedPluginChildTemplate,
        store: Option<&crate::plugins::PluginStateStore>,
        call_id: &str,
    ) -> Result<Option<PluginStateCall>, crate::plugins::PluginStateError> {
        child_state_call_for(
            store,
            &template.callee_package,
            &template.callee_artifact,
            template.callee_state.as_ref(),
            template.callee_contract.as_ref(),
            &template.run_id,
            &template.session_id,
            &template.profile,
            &template.callee_code.graph_id,
            call_id,
            &self.cancellation,
        )
    }

    fn stateless_default_binding(&self) -> Option<PinnedToolProgram> {
        let owner = self.capability_owner.as_ref()?;
        let lifecycle = self.lifecycle.as_ref()?;
        let runtime = super::native_tools::shared_embedded_runtime().ok()?;
        Some(runtime.binding_for(
            owner.run(),
            owner.session(),
            owner.profile(),
            lifecycle.registry_identity(),
            lifecycle.workspace().to_path_buf(),
        ))
    }

    fn binding_mismatch(&self, pinned: &PinnedToolProgram) -> Option<JsonValue> {
        if let Some(managed) = &pinned.managed
            && (!managed.matches_contract(pinned.managed_contract.as_ref())
                || !managed.matches_policy_catalog(pinned.managed_policy_catalog.as_ref())
                || managed.owner.run_id != pinned.run_id
                || managed.owner.session_id != pinned.session_id
                || managed.owner.profile != pinned.profile
                || !same_workspace(
                    std::path::Path::new(managed.authority.canonical_path()),
                    &pinned.workspace,
                )
                || managed.code.graph_id != pinned.graph_id
                || managed.code.activation_generation != pinned.generation
                || managed.code.graph_ref_id != pinned.ref_id
                || managed.code.package_id != pinned.package_id
                || managed.code.artifact_id != pinned.artifact_id
                || managed.code.export != pinned.export
                || managed.code.registry_identity != pinned.registry_identity
                || managed.code.effect_contract_version != 1)
        {
            return Some(pinned_binding_mismatch());
        }
        let Some(owner) = self.capability_owner.as_ref() else {
            return Some(pinned_binding_mismatch());
        };
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return Some(pinned_binding_mismatch());
        };
        if pinned.run_id.is_empty()
            || pinned.session_id.is_empty()
            || pinned.ref_id.is_empty()
            || pinned.profile.is_empty()
            || pinned.entry.is_empty()
            || pinned.export.is_empty()
            || pinned.package_id.is_empty()
            || pinned.artifact_id.is_empty()
            || owner.run() != pinned.run_id
            || owner.session() != pinned.session_id
            || owner.profile() != pinned.profile
            || lifecycle.registry_identity() != pinned.registry_identity
            || !same_workspace(lifecycle.workspace(), &pinned.workspace)
        {
            return Some(pinned_binding_mismatch());
        }
        None
    }

    fn capability_replay(&self, metadata: &JsonValue) -> JsonValue {
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
        match parse_prepare_metadata(metadata)
            .and_then(|metadata| lifecycle.replay_completed(owner, &metadata))
        {
            Ok(replayed) => json!({
                "ok": true,
                "kind": if replayed { "replay" } else { "fresh" }
            }),
            Err(error) => crate::capabilities::host::error_envelope(&error),
        }
    }

    fn checked_managed_policy(
        &self,
        metadata: &crate::capabilities::PrepareMetadata,
        parent: Option<&JsonValue>,
    ) -> Result<Option<Arc<crate::effects::authority::SealedManagedCallPolicy>>, String> {
        let Some(pinned) = self.pinned_tool.as_ref() else {
            return Ok(None);
        };
        let Some(binding) = pinned.managed.as_ref() else {
            return Ok(None);
        };
        if self.binding_mismatch(pinned).is_some()
            || metadata.run_id != pinned.run_id
            || metadata.registry_identity != pinned.registry_identity
        {
            return Err("managed pinned binding mismatch".into());
        }
        if json_object_rejected(&metadata.argument_digest) {
            return Err("managed canonical arguments invalid".into());
        }
        let args: JsonValue = serde_json::from_str(&metadata.argument_digest)
            .map_err(|_| "managed canonical arguments invalid")?;
        let native_parent = match parent {
            Some(value) => Some(value.clone()),
            None => {
                let lifecycle = self.lifecycle.as_ref().ok_or("managed lifecycle missing")?;
                let owner = self
                    .capability_owner
                    .as_ref()
                    .ok_or("managed owner missing")?;
                lifecycle
                    .parent_arguments(owner, &metadata.call_id, &metadata.tool_name)
                    .map_err(|_| "managed parent mismatch")?
                    .or_else(|| {
                        self.provider_arguments
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&(metadata.call_id.clone(), metadata.tool_name.clone()))
                            .cloned()
                    })
            }
        };
        if !args.is_object() || native_parent.as_ref() != Some(&args) {
            return Err("managed parent arguments mismatch".into());
        }
        binding
            .seal_call_policy(
                &metadata.tool_name,
                metadata.risk_class,
                &metadata.argument_digest,
            )
            .map(Some)
    }

    fn capability_approval_attest(&self, metadata: &JsonValue) -> JsonValue {
        #[cfg(test)]
        APPROVAL_ATTEST_CALLS.with(|count| count.set(count.get() + 1));
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
        let result = parse_prepare_metadata(metadata).and_then(|metadata| {
            self.checked_managed_policy(&metadata, None)
                .map_err(LifecycleError::InvalidMetadata)?;
            lifecycle.attest_approval(owner, metadata)
        });
        match result {
            Ok(()) => json!({ "ok": true, "kind": "attested" }),
            Err(error) => crate::capabilities::host::error_envelope(&error),
        }
    }

    /// Bounds and charges the guest's own commit result before it is copied into
    /// JSON. The precharge walks the borrowed VM value with raw byte lengths (a
    /// `Value::Bytes` buffer counts its payload, never a lossy UTF-8 view) and
    /// never allocates, so an over-budget guest result is refused before the
    /// conversion exists. The converted envelope is a distinct representation
    /// and is charged again where it is materialized.
    fn capability_commit_value(&self, token: &str, result: &Value) -> JsonValue {
        let delegating = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.managed_call.as_ref())
            .filter(|call| call.delegates());
        if let Some(call) = delegating {
            let bound = vm_value_typed_bytes(result);
            if bound > call.meter().remaining() {
                return typed_fail(
                    "managed_output_budget_exceeded",
                    "the guest tool result exceeds the remaining aggregate budget",
                );
            }
            if let Err(message) = call.meter().charge_new(bound, "guest tool result") {
                return typed_fail("managed_output_budget_exceeded", &message);
            }
        }
        match guest_result_json(result) {
            Ok(converted) => self.capability_commit(token, &converted),
            Err(message) => typed_fail("guest_result_unrepresentable", &message),
        }
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
        let mut outcome = self.expected_call.as_ref().map(|grant| {
            grant
                .outcome
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        });
        if outcome.as_deref().is_some_and(|outcome| {
            !matches!(outcome, PinnedCallOutcome::Executing { token: expected } if expected == token)
        }) || (self.expected_call.is_some()
            && !self
                .leases
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(token))
        {
            return pinned_call_mismatch();
        }
        if let Some(outcome) = outcome.as_deref_mut() {
            *outcome = PinnedCallOutcome::Closing;
        }
        drop(outcome);
        let caller_call = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.plugin_state_call.as_ref());
        // S2 holds the callee authority on the call side: the stateless
        // caller grant is empty, so the child call is the only source of a
        // staged publication. Never read the caller slot alone.
        let child_call = self
            .child_call
            .as_ref()
            .and_then(|runtime| runtime.child_state_call.as_ref());
        let managed_state_commit = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.managed_call.as_ref())
            .is_some();
        if !managed_state_commit
            && let Some(call) = caller_call
            && let Err(error) = call.commit_staged_if_any()
        {
            return typed_fail(error.code, &error.message);
        }
        let handoff = if managed_state_commit {
            match take_managed_state_handoff(caller_call, child_call) {
                Ok(handoff) => handoff,
                Err(error) => return typed_fail(error.code, &error.message),
            }
        } else {
            None
        };
        // The writer lease is acquired inside the handoff before
        // `prepare_result` and this binding holds it across prepare and the
        // commit below, fencing the callee root key for the whole decision.
        // No second acquisition happens here: re-entering the writer key would
        // block on the lease this call already holds.
        let (state_publication, state_owner, _state_writer) = match handoff {
            Some(handoff) => (Some(handoff.publication), handoff.owner, handoff.writer),
            None => (None, None, None),
        };
        let envelope = if let Some(call) = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.managed_call.as_ref())
        {
            // A delegating parent prepare requires exactly one Complete child
            // invocation with a representable Native result. A skipped or
            // aborted child, or a second prepare, is refused here.
            let delegation = match self.child_call.as_ref() {
                Some(runtime) => match runtime.gate.take_complete() {
                    Some(complete) => Some(complete),
                    None => {
                        return typed_fail(
                            "managed_delegation_incomplete",
                            "the captured child call must complete exactly once before prepare",
                        );
                    }
                },
                None => None,
            };
            match call.prepare_result(token, result, state_publication, state_owner, delegation) {
                Ok(prepared) => tool_commit(lifecycle, owner, token, prepared.original.clone()),
                Err(message) => typed_fail("managed_prepare_failed", &message),
            }
        } else {
            tool_commit(lifecycle, owner, token, result.clone())
        };
        let complete_result = envelope.get("result").cloned().map(Arc::new);
        let mut outcome = self
            .expected_call
            .as_ref()
            .map(|grant| grant.outcome.lock().unwrap_or_else(|p| p.into_inner()));
        if let Some(outcome) = outcome.as_deref_mut() {
            *outcome = if envelope.get("ok") == Some(&JsonValue::Bool(true))
                && envelope.get("kind").and_then(JsonValue::as_str) == Some("committed")
                && envelope.get("call_id").and_then(JsonValue::as_str)
                    == self
                        .expected_call
                        .as_ref()
                        .map(|grant| grant.call_id.as_str())
                && let Some(result) = complete_result.as_ref()
            {
                PinnedCallOutcome::Complete {
                    result: Arc::clone(result),
                }
            } else {
                PinnedCallOutcome::Failed {
                    error: envelope.clone(),
                }
            };
        }
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

    fn filesystem_for(&self, token: &str) -> Option<Arc<FilesystemCapability>> {
        if let Some(call) = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.managed_call.as_ref())
        {
            return call
                .adapters(token)
                .ok()
                .map(|adapter| Arc::clone(&adapter.filesystem));
        }
        self.filesystem.clone()
    }

    fn processes_for(&self, token: &str) -> Option<Arc<ProcessCapability>> {
        if let Some(call) = self
            .expected_call
            .as_ref()
            .and_then(|grant| grant.managed_call.as_ref())
        {
            return call
                .adapters(token)
                .ok()
                .map(|adapter| Arc::clone(&adapter.processes));
        }
        self.processes.clone()
    }

    fn missing_capability(name: &str) -> JsonValue {
        if matches!(name, "filesystem" | "process") {
            return capability_error_envelope(&CapabilityError::new(
                "workspace_unavailable",
                "workspace authority is unavailable",
            ));
        }
        capability_error_envelope(&CapabilityError::new(
            "invalid_metadata",
            format!("{name} capability is not installed"),
        ))
    }

    /// The shared meter for a delegating parent call; `None` keeps caller-only
    /// byte behavior unchanged.
    fn caller_meter(&self) -> Option<Arc<crate::effects::broker::ManagedOutputMeter>> {
        self.expected_call
            .as_ref()?
            .managed_call
            .as_ref()
            .filter(|call| call.delegates())
            .map(|call| Arc::clone(call.meter()))
    }

    fn cap_fs_metadata(&self, token: String, path: String) -> JsonValue {
        if let Some(child) = &self.child_read {
            return child.metadata(&token, &path);
        }
        let Some(fs) = self.filesystem_for(&token) else {
            return Self::missing_capability("filesystem");
        };
        let meter = self.caller_meter();
        let mut charge = match &meter {
            Some(meter) => match meter.charge_new(FS_METADATA_BOUND, "caller fs metadata") {
                Ok(charge) => Some(charge),
                Err(message) => return typed_fail("managed_output_budget_exceeded", &message),
            },
            None => None,
        };
        let envelope = match fs.metadata(&token, &path) {
            Ok(meta) => json!({
                "ok": true,
                "kind": "fs_metadata",
                "file_type": meta.file_type,
                "len": meta.len,
            }),
            Err(error) => capability_error_envelope(&error),
        };
        if let (Some(meter), Some(charge)) = (&meter, charge.as_mut())
            && let Err(message) = meter.settle_exact(charge, json_bytes(&envelope))
        {
            return typed_fail("managed_output_budget_exceeded", &message);
        }
        envelope
    }

    fn cap_fs_read_range(&self, token: String, path: String, offset: u64, limit: usize) -> Value {
        if let Some(child) = &self.child_read {
            return child.read_range(&token, &path, offset, limit);
        }
        let Some(fs) = self.filesystem_for(&token) else {
            return json_to_vm_value(&Self::missing_capability("filesystem"));
        };
        let meter = self.caller_meter();
        let mut charge = match &meter {
            Some(meter) => match (limit as u64).checked_add(FS_READ_FRAME_BOUND) {
                Some(bound) => match meter.charge_new(bound, "caller fs read_range") {
                    Ok(charge) => Some(charge),
                    Err(message) => {
                        return json_to_vm_value(&typed_fail(
                            "managed_output_budget_exceeded",
                            &message,
                        ));
                    }
                },
                None => {
                    return json_to_vm_value(&typed_fail(
                        "managed_output_budget_exceeded",
                        "range request overflowed its bound",
                    ));
                }
            },
            None => None,
        };
        let value = match fs.read_range(&token, &path, offset, limit) {
            Ok(read) => fs_read_value(read),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        };
        if let (Some(meter), Some(charge)) = (&meter, charge.as_mut())
            && let Err(message) = meter.settle_exact(charge, vm_value_typed_bytes(&value))
        {
            return json_to_vm_value(&typed_fail("managed_output_budget_exceeded", &message));
        }
        value
    }

    fn cap_fs_list(&self, token: String, path: String, cursor: u64, limit: usize) -> JsonValue {
        let Some(fs) = self.filesystem_for(&token) else {
            return Self::missing_capability("filesystem");
        };
        // The delegated read contract is metadata/range only, and a directory
        // listing has no source-derived bounded frame that could be charged
        // before the Native IO. A delegating caller therefore cannot reach it;
        // the prepare-time import fence is the primary refusal, this is the
        // runtime one.
        if self.caller_meter().is_some() {
            return typed_fail(
                "managed_operation_denied",
                "delegated read calls admit only metadata and range reads",
            );
        }
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
        let Some(fs) = self.filesystem_for(&token) else {
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
        let Some(processes) = self.processes_for(&token) else {
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
        let Some(processes) = self.processes_for(&token) else {
            return json_to_vm_value(&Self::missing_capability("process"));
        };
        match processes.poll(&token, &handle, cursor, limit) {
            Ok(snapshot) => process_snapshot_value("process_poll", &snapshot),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        }
    }

    fn cap_process_wait(&self, token: String, handle: String, timeout_ms: Option<u64>) -> Value {
        let Some(processes) = self.processes_for(&token) else {
            return json_to_vm_value(&Self::missing_capability("process"));
        };
        match processes.wait(&token, &handle, timeout_ms) {
            Ok(snapshot) => process_snapshot_value("process_wait", &snapshot),
            Err(error) => json_to_vm_value(&capability_error_envelope(&error)),
        }
    }

    fn cap_process_log(&self, token: String, handle: String, cursor: u64, limit: usize) -> Value {
        let Some(processes) = self.processes_for(&token) else {
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
        let Some(processes) = self.processes_for(&token) else {
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
        let Some(processes) = self.processes_for(&token) else {
            return Self::missing_capability("process");
        };
        match processes.close_stdin(&token, &handle) {
            Ok(()) => json!({"ok": true, "kind": "process_close"}),
            Err(error) => capability_error_envelope(&error),
        }
    }

    fn cap_process_kill(&self, token: String, handle: String) -> JsonValue {
        let Some(processes) = self.processes_for(&token) else {
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
    agent_host_module().install_from_catalog(registry, catalog)?;
    Ok(())
}

fn provider_call_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let request = args.first().cloned().unwrap_or(Value::Null);
    validate_provider_json_resources(vm, &request)?;
    let state = installed_state(vm)?;
    let json = vm_value_to_json(&request);
    return_json(state.provider_call(&json))
}

fn refresh_context_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let context = args.first().cloned().unwrap_or(Value::Null);
    validate_provider_json_resources(vm, &context)?;
    let state = installed_state(vm)?;
    return_json(state.refresh_context(&vm_value_to_json(&context)))
}

fn utf8_byte_len_adapter(_vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let bytes = match args.first() {
        Some(Value::String(value)) => value.len(),
        _ => 0,
    };
    Ok(CallOutcome::Return(CallReturn::One(Value::Int(
        i64::try_from(bytes).unwrap_or(i64::MAX),
    ))))
}

fn utf8_truncate_adapter(_vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let text = match args.first() {
        Some(Value::String(value)) => value.as_str(),
        _ => "",
    };
    let limit = match args.get(1) {
        Some(Value::Int(value)) => usize::try_from((*value).max(0)).unwrap_or(usize::MAX),
        _ => 0,
    };
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    return_json(JsonValue::String(text[..end].to_string()))
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
    let result = state.control_error().unwrap_or_else(|| json!({"ok": true}));
    return_json(result)
}

fn parse_json_object_adapter(_vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let text = match args.first() {
        Some(Value::String(value)) => value.as_str(),
        _ => return return_json(malformed_json_object()),
    };
    return_json(parse_json_object(text))
}

fn state_read_adapter(vm: &mut Vm, _args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    if let Some(error) = state.control_error() {
        return return_json(error);
    }
    let Some(call) = state.plugin_state_call.as_ref() else {
        return return_json(state_read_failure(
            "plugin_state_unauthorized",
            "no sealed Native state call is installed",
        ));
    };
    return_json(call.snapshot())
}

fn state_write_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let state = installed_state(vm)?;
    if let Some(error) = state.control_error() {
        return return_json(error);
    }
    let expected_revision = match args.first() {
        Some(Value::Int(value)) => *value,
        _ => {
            return return_json(state_write_failure(
                "plugin_state_conflict",
                "expected revision is not an integer",
            ));
        }
    };
    let document = match args.get(1) {
        Some(Value::String(value)) => value.as_str(),
        _ => {
            return return_json(state_write_failure(
                "plugin_state_invalid_document",
                "state document is not a string",
            ));
        }
    };
    let Some(call) = state.plugin_state_call.as_ref() else {
        return return_json(state_write_failure(
            "plugin_state_unauthorized",
            "no sealed Native state call is installed",
        ));
    };
    return_json(call.write(expected_revision, document))
}

fn malformed_json_object() -> JsonValue {
    json!({
        "ok": false,
        "code": "malformed_payload",
        "message": "payload is not a JSON object",
        "value": {},
    })
}

fn parse_json_object(text: &str) -> JsonValue {
    if text.len() > PARSE_JSON_OBJECT_MAX_BYTES || !text.is_char_boundary(text.len()) {
        return malformed_json_object();
    }
    match serde_json::from_str::<JsonValue>(text) {
        Ok(JsonValue::Object(map)) => json!({
            "ok": true,
            "code": "",
            "message": "",
            "value": JsonValue::Object(map),
        }),
        _ => malformed_json_object(),
    }
}

fn tool_replay_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let metadata = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    return_json(state.capability_replay(&vm_value_to_json(&metadata)))
}

fn approval_attest_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let metadata = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    return_json(state.capability_approval_attest(&vm_value_to_json(&metadata)))
}

fn approval_storage_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let operation = match args.first() {
        Some(Value::String(value)) => value.as_str(),
        _ => "",
    };
    let payload = args.get(1).cloned().unwrap_or(Value::Null);
    validate_provider_json_resources(vm, &payload)?;
    let state = installed_state(vm)?;
    return_json(state.approval_storage(operation, &vm_value_to_json(&payload)))
}

fn tool_prepare_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let metadata = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    // The injected AfterIntent cut is a Native crash, not a tool refusal: it
    // traps the caller VM so the run fails without a tool terminal.
    let envelope = state
        .capability_prepare(&vm_value_to_json(&metadata))
        .map_err(VmError::HostError)?;
    return_json(envelope)
}

fn tool_commit_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let token = match args.first() {
        Some(Value::String(value)) => value.to_string(),
        _ => String::new(),
    };
    let result = args.get(1).cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    return_json(state.capability_commit_value(&token, &result))
}

/// The exact typed bridge request, used only to count its full encoding with a
/// bounded counting writer before any Native-owned copy or parse.
#[derive(serde::Serialize)]
struct TypedChildRequest<'a> {
    canonical_arguments: &'a str,
}

struct CountingWriter(u64);

impl std::io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buffer.len() as u64);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn count_typed_child_request(canonical: &str) -> std::result::Result<u64, String> {
    if canonical.len() > crate::config::MAX_TOOL_OUTPUT_BYTES {
        return Err("child arguments exceed the bounded request limit".into());
    }
    let mut writer = CountingWriter(0);
    serde_json::to_writer(
        &mut writer,
        &TypedChildRequest {
            canonical_arguments: canonical,
        },
    )
    .map_err(|error| error.to_string())?;
    Ok(writer.0)
}

/// A child's returned value becomes the canonical child result only through
/// the existing canonical validator; a representable error envelope is
/// accepted, anything else is unrepresentable and aborts the delegation.
fn canonical_child_result(
    value: &JsonValue,
    limit: u64,
) -> std::result::Result<crate::effects::journal::CanonicalToolResultJson, String> {
    if let Ok(result) =
        crate::effects::journal::CanonicalToolResultJson::from_value_bounded(value, limit)
    {
        return Ok(result);
    }
    if value.get("ok") == Some(&JsonValue::Bool(false))
        && let Some(error) = value.get("error")
        && error.get("code").and_then(JsonValue::as_str).is_some()
    {
        let code = error
            .get("code")
            .and_then(JsonValue::as_str)
            .unwrap_or("child_failed");
        let message = error
            .get("message")
            .and_then(JsonValue::as_str)
            .unwrap_or("delegated read failed");
        let canonical = json!({
            "ok": false,
            "content": "",
            "data": {},
            "error": { "code": code, "message": message },
            "truncated": false,
            "artifacts": [],
        });
        return crate::effects::journal::CanonicalToolResultJson::from_value_bounded(
            &canonical, limit,
        );
    }
    Err("child result is not a canonical tool result".into())
}

fn invoke_pinned_tool_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let request = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    return_json(state.invoke_pinned_tool(&vm_value_to_json(&request)))
}

fn invoke_pinned_plugin_child_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    // decode the named request directly from the borrowed VM value: the
    // canonical string is never copied before it is bounded and charged.
    let state = installed_state(vm)?;
    return_json(state.invoke_pinned_plugin_child(args.first().unwrap_or(&Value::Null)))
}

fn pinned_outcome(
    ok: bool,
    content: &str,
    kind: &str,
    code: &str,
    message: &str,
    canonical_result: &str,
) -> JsonValue {
    json!({
        "ok": ok,
        "text": content,
        "content": content,
        "kind": kind,
        "code": code,
        "message": message,
        "canonical_result": canonical_result,
    })
}

fn pinned_binding_mismatch() -> JsonValue {
    pinned_outcome(
        false,
        "",
        "",
        "pinned_binding_mismatch",
        "retained tool binding does not match this owner",
        "",
    )
}

fn pinned_call_mismatch() -> JsonValue {
    pinned_outcome(
        false,
        "",
        "",
        "pinned_call_mismatch",
        "tool call does not match the approved grant",
        "",
    )
}

fn same_workspace(left: &std::path::Path, right: &std::path::Path) -> bool {
    left == right
}

const PINNED_CANONICAL_RESULT_MAX_BYTES: usize = 1024 * 1024;

fn pinned_tool_result(value: &JsonValue) -> JsonValue {
    pinned_tool_result_with_limit(value, PINNED_CANONICAL_RESULT_MAX_BYTES)
}

fn pinned_tool_result_with_limit(value: &JsonValue, max_bytes: usize) -> JsonValue {
    let explicit_ok = value.get("ok").and_then(JsonValue::as_bool);
    let content = value
        .get("content")
        .and_then(JsonValue::as_str)
        .or_else(|| {
            value
                .get("content_block")
                .and_then(|block| block.get("content"))
                .and_then(JsonValue::as_str)
        })
        .or_else(|| value.get("text").and_then(JsonValue::as_str))
        .unwrap_or("");
    let code = value
        .get("code")
        .and_then(JsonValue::as_str)
        .or_else(|| {
            value
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(JsonValue::as_str)
        })
        .unwrap_or("");
    let message = value
        .get("message")
        .and_then(JsonValue::as_str)
        .or_else(|| {
            value
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(JsonValue::as_str)
        })
        .unwrap_or("");
    let kind = value.get("kind").and_then(JsonValue::as_str).unwrap_or("");
    let canonical = match serde_json::to_string(value) {
        Ok(encoded) if encoded.len() <= max_bytes => encoded,
        Ok(_) => {
            return pinned_outcome(
                false,
                "",
                "",
                "pinned_result_too_large",
                "pinned tool result exceeds the canonical bound",
                "",
            );
        }
        Err(_) => String::new(),
    };
    let Some(ok) = explicit_ok else {
        return pinned_outcome(
            false,
            "",
            kind,
            if code.is_empty() {
                "pinned_tool_failed"
            } else {
                code
            },
            if message.is_empty() {
                "pinned tool result omitted explicit ok"
            } else {
                message
            },
            &canonical,
        );
    };
    pinned_outcome(ok, content, kind, code, message, &canonical)
}

fn json_object_rejected(raw: &str) -> bool {
    json_has_duplicate_keys(raw).unwrap_or(true)
}

fn json_has_duplicate_keys(raw: &str) -> Result<bool, ()> {
    let mut chars = raw.chars().peekable();
    let duplicated = walk_json(&mut chars)?;
    skip_json_ws(&mut chars);
    if chars.next().is_some() {
        return Err(());
    }
    Ok(duplicated)
}

fn skip_json_ws(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
        chars.next();
    }
}

fn walk_json(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<bool, ()> {
    skip_json_ws(chars);
    match chars.peek().copied() {
        Some('{') => {
            chars.next();
            let mut keys = std::collections::BTreeSet::new();
            loop {
                skip_json_ws(chars);
                if chars.peek() == Some(&'}') {
                    chars.next();
                    return Ok(false);
                }
                let key = parse_json_string(chars)?;
                if !keys.insert(key) {
                    return Ok(true);
                }
                skip_json_ws(chars);
                if chars.next() != Some(':') {
                    return Err(());
                }
                if walk_json(chars)? {
                    return Ok(true);
                }
                skip_json_ws(chars);
                match chars.next() {
                    Some(',') => continue,
                    Some('}') => return Ok(false),
                    _ => return Err(()),
                }
            }
        }
        Some('[') => {
            chars.next();
            loop {
                skip_json_ws(chars);
                if chars.peek() == Some(&']') {
                    chars.next();
                    return Ok(false);
                }
                if walk_json(chars)? {
                    return Ok(true);
                }
                skip_json_ws(chars);
                match chars.next() {
                    Some(',') => continue,
                    Some(']') => return Ok(false),
                    _ => return Err(()),
                }
            }
        }
        Some('"') => {
            parse_json_string(chars)?;
            Ok(false)
        }
        Some(ch) if ch == '-' || ch.is_ascii_digit() => {
            chars.next();
            while chars
                .peek()
                .is_some_and(|next| matches!(next, '0'..='9' | '.' | 'e' | 'E' | '+' | '-'))
            {
                chars.next();
            }
            Ok(false)
        }
        Some('t') => expect_json_literal(chars, "true"),
        Some('f') => expect_json_literal(chars, "false"),
        Some('n') => expect_json_literal(chars, "null"),
        _ => Err(()),
    }
}

fn expect_json_literal(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    literal: &str,
) -> Result<bool, ()> {
    for expected in literal.chars() {
        if chars.next() != Some(expected) {
            return Err(());
        }
    }
    Ok(false)
}

fn parse_json_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String, ()> {
    if chars.next() != Some('"') {
        return Err(());
    }
    let mut out = String::new();
    loop {
        match chars.next() {
            Some('"') => return Ok(out),
            Some('\\') => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('b') => out.push('\u{0008}'),
                Some('f') => out.push('\u{000c}'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        hex.push(chars.next().ok_or(())?);
                    }
                    let code = u32::from_str_radix(&hex, 16).map_err(|_| ())?;
                    out.push(char::from_u32(code).ok_or(())?);
                }
                _ => return Err(()),
            },
            Some(ch) => out.push(ch),
            None => return Err(()),
        }
    }
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
    if let Some(JsonValue::Bool(close_after_initial)) = fields.get("close_after_initial") {
        limits.close_after_initial = *close_after_initial;
    } else if fields.contains_key("close_after_initial") {
        return Err(invalid_request(
            "close_after_initial must be a boolean".to_string(),
        ));
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
    "adapter_failed",
    "unsupported_parallel",
    "unsupported_task",
    "provider_step_persist_failed",
    "interrupted_provider",
    "corrupt_provider_step",
    "run_terminal",
    "missing_tool_parent",
    "plugin_graph_revoked",
    "plugin_graph_pin_required",
    "plugin_artifact_unavailable",
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

#[cfg(all(feature = "config-fixture", test))]
mod b1_json_guard_native_auth_reuse_tests {
    use super::*;
    use rustscript_vm::{
        CallOutcome, CallReturn, CompileSourceFileOptions, HostAdapterDescriptor,
        HostFunctionRegistry, SourceFlavor, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn fixture_home() -> std::path::PathBuf {
        let root = std::path::PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let home = root.join(format!(
            "b1-json-guard-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&home).expect("private fixture home");
        #[cfg(unix)]
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
            .expect("fixture home permissions");
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("fixture config");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("fixture auth")
            .replace("1788440000000", "1900003600000");
        assert!(auth.contains("1900003600000"));
        assert!(!auth.contains("1788440000000"));
        fs::write(home.join("auth.yaml"), auth).expect("fixture auth copy");
        #[cfg(unix)]
        for name in ["config.yaml", "auth.yaml"] {
            fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                .expect("fixture file permissions");
        }
        home
    }

    fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
        let Value::Map(entries) = value else {
            panic!("expected map")
        };
        entries
            .iter()
            .find_map(|(key, value)| match key {
                Value::String(key) if key.as_ref() == name => Some(value),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    fn invoke_adapter(
        vm: &mut Vm,
        adapter: HostAdapterDescriptor,
        args: &[Value],
    ) -> rustscript_vm::VmResult<CallOutcome> {
        match adapter {
            HostAdapterDescriptor::StaticStack(function)
            | HostAdapterDescriptor::StaticStackRuntimeOwned(function) => function(vm, args),
            HostAdapterDescriptor::StaticArgs(function)
            | HostAdapterDescriptor::StaticNonYieldingArgs(function) => function(args),
            _ => panic!("auth access descriptor has an unsupported adapter kind"),
        }
    }

    #[test]
    fn provider_json_guard_rejects_nested_resources_without_consuming_native_auth_resources() {
        use crate::auth::host::{AuthHost, auth_host_module};
        use crate::auth::oauth::{
            OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
            ScriptedHttpsTransport,
        };
        use std::time::Duration;

        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let transport = Arc::new(ScriptedHttpsTransport::new());
        transport.push_json(
            200,
            json!({
                "access_token": "SYNTHETIC_PRIVATE_RESPONSE_FIELD",
                "public": "accepted"
            }),
        );
        let oauth = Arc::new(OAuthHost::new(
            transport.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        ));
        let auth_host = AuthHost::new(fixture_home(), cancellation.clone())
            .expect("auth owner")
            .with_oauth_host(oauth);

        let source = r#"
use config;
use auth;
use oauth;

pub fn b1_issue_policy(home: resource<auth.host_home>) -> resource<auth.policy> {
    config::load_snapshot(&home).policy_handle
}

pub fn b1_send(
    policy: resource<auth.policy>,
    access: resource<auth.access>
) -> TransportResultEnvelope {
    let request: TransportPublicRequest = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "GET",
        path: "/oauth/token",
        public_headers: [{name: "accept", value: "application/json"}],
        public_body: ""
    };
    let usage: TransportCredentialUse = {
        kind: "access",
        access_handle: access,
        refresh_handle: null,
        code_handle: null,
        verifier_handle: null,
        device_handle: null
    };
    oauth::transport_result(&request, &usage)
}
"#;
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("rss/auth/transport_contract.rss");
        let catalog = agent_host_catalog();
        let compiled = compile_source_at_path_with_flavor_and_options(
            &path,
            source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
        )
        .expect("compile fixture RSS");
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let mut registry = HostFunctionRegistry::restricted();
        auth_host
            .register(&mut registry, catalog.as_ref())
            .expect("register auth descriptors");
        register_agent_host_functions(&mut registry, catalog.as_ref())
            .expect("register agent descriptors");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind restricted catalog");

        let provider = ScriptedProvider::new();
        vm.host_context().set_module_state(AgentHostState {
            child_call: None,
            child_read: None,
            provider: Arc::new(provider.clone()),
            cancellation: cancellation.clone(),
            sleeps: Arc::new(Mutex::new(SleepLog::default())),
            skip_sleep: true,
            metrics: None,
            lifecycle: None,
            capability_owner: None,
            filesystem: None,
            processes: None,
            artifacts: None,
            leases: Arc::new(Mutex::new(HashMap::new())),
            control_hook: None,
            pinned_tool: None,
            allow_stateless_pin: false,
            expected_call: None,
            plugin_state_call: None,
            provider_arguments: Default::default(),
        });
        let context = auth_host.bind_vm(&mut vm).expect("bind genuine auth owner");
        let home = field(&context, "host_home").clone();
        assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));

        let issue = vm
            .resolve_exported_callable("b1_issue_policy")
            .expect("policy issuer");
        let policy = vm
            .invoke_callable(issue, &[home])
            .expect("real policy issue");
        let access_descriptor = auth_host_module()
            .functions
            .iter()
            .map(|descriptor| descriptor())
            .find(|descriptor| descriptor.schema.name == "auth::access_handle")
            .expect("existing auth access descriptor");
        let access_outcome = invoke_adapter(
            &mut vm,
            access_descriptor.adapter,
            &[
                Value::string("fixture-codex"),
                Value::Int(4),
                policy.clone(),
            ],
        )
        .expect("existing auth access adapter");
        let CallOutcome::Return(CallReturn::One(access_envelope)) = access_outcome else {
            panic!("auth access adapter returned an unexpected outcome")
        };
        assert_eq!(field(&access_envelope, "ok"), &Value::Bool(true));
        let access = field(&access_envelope, "handle").clone();
        assert!(matches!(access, Value::Int(_)));

        let nested_request = Value::map(vec![(
            Value::string("messages"),
            Value::array(vec![Value::map(vec![
                (Value::string("policy"), policy.clone()),
                (
                    Value::string("parts"),
                    Value::array(vec![Value::map(vec![(
                        Value::string("credential"),
                        access.clone(),
                    )])]),
                ),
            ])]),
        )]);
        let guard_failure = provider_call_adapter(&mut vm, &[nested_request])
            .expect_err("nested resource-bearing provider JSON rejected");
        assert!(matches!(
            guard_failure,
            VmError::HostError(message) if message == "opaque_nonserializable"
        ));
        assert_eq!(provider.call_count(), 0);

        let send = vm
            .resolve_exported_callable("b1_send")
            .expect("native send");
        let envelope = vm
            .invoke_callable(send, &[policy, access])
            .expect("native transport result envelope");
        assert_eq!(field(&envelope, "ok"), &Value::Bool(true));
        let response = field(&envelope, "value");
        assert!(
            !matches!(response, Value::Null),
            "canonical transport response absent"
        );
        assert_eq!(field(response, "status"), &Value::Int(200));
        assert_eq!(
            field(response, "body_without_secret_fields"),
            &Value::string(r#"{"public":"accepted"}"#)
        );
        assert!(!format!("{response:?}").contains("SYNTHETIC_PRIVATE_RESPONSE_FIELD"));
        let sent = transport.take_sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].url, "https://auth.openai.com/oauth/token");
        assert!(
            sent[0]
                .headers
                .get("authorization")
                .is_some_and(|header| header == "Bearer SYNTHETIC_ACCESS_TOKEN")
        );
        assert_eq!(
            provider.call_count(),
            0,
            "native auth transport bypasses provider callback"
        );

        provider.push_ok(json!({}));
        let control_request =
            Value::map(vec![(Value::string("messages"), Value::array(Vec::new()))]);
        let control = provider_call_adapter(&mut vm, &[control_request])
            .expect("ordinary provider callback with resource-free JSON");
        assert!(matches!(control, CallOutcome::Return(_)));
        assert_eq!(provider.call_count(), 1);
    }
}

/// Measurement contracts for the shared output meter: the frame bounds must stay
/// coupled to the builders that produce the charged representations.
#[cfg(test)]
mod t07_measurement_tests {
    use super::*;

    fn read_value(bytes: Vec<u8>, offset: u64, truncated: bool) -> Value {
        fs_read_value(crate::capabilities::FsRead {
            hash: Some("a".repeat(64)),
            bytes,
            offset,
            truncated,
        })
    }

    fn keys_of(value: &Value) -> Vec<String> {
        let Value::Map(entries) = value else {
            panic!("the read envelope must be a map");
        };
        entries
            .iter()
            .map(|(key, _)| match key {
                Value::String(text) => text.to_string(),
                other => panic!("read envelope keys must be text: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn fs_read_frame_keys_and_widths_match_the_builder() {
        let value = read_value(Vec::new(), 0, false);
        let mut keys = keys_of(&value);
        keys.sort();
        let mut expected_keys = FS_READ_KEYS.map(str::to_string).to_vec();
        expected_keys.sort();
        assert_eq!(keys, expected_keys);
        // One-digit offset/len and no payload: the frame is exactly the key set
        // plus the fixed value widths.
        let expected = json_object_frame(&FS_READ_KEYS, 4 + 7 + 1 + 5 + 1 + 64);
        assert_eq!(vm_value_typed_bytes(&value), expected);
        assert!(expected <= FS_READ_FRAME_BOUND);
    }

    #[test]
    fn raw_bytes_are_charged_at_their_own_length() {
        let payload = vec![0xFF_u8; 256];
        let value = read_value(payload, u64::MAX, true);
        let measured = vm_value_typed_bytes(&value);
        assert!(
            measured >= 256 + 20,
            "the raw payload plus its frame must be charged: {measured}"
        );
        assert!(
            measured <= 256 + FS_READ_FRAME_BOUND,
            "the maximal frame bound must cover the real frame: {measured}"
        );
        // A lossy UTF-8 view would have expanded every byte to a replacement
        // character and then to JSON escapes.
        assert!(measured < 256 * 3);
    }

    #[test]
    fn metadata_frame_bound_covers_the_success_envelope() {
        let envelope = json!({
            "ok": true,
            "kind": "fs_metadata",
            "file_type": "directory",
            "len": u64::MAX,
        });
        let mut keys = envelope
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        let mut expected = FS_METADATA_KEYS.map(str::to_string).to_vec();
        expected.sort();
        assert_eq!(keys, expected);
        let measured = json_bytes(&envelope);
        assert!(
            measured <= FS_METADATA_FRAME_BOUND,
            "the encoded success frame must fit its precharge: {measured}"
        );
    }

    #[test]
    fn metadata_refusal_frame_is_charged_within_its_own_bound() {
        // Worst case: every text byte of the bounded code and message expands to
        // a six-byte `\u00XX` escape in the encoded frame.
        let envelope = capability_error_envelope(&crate::capabilities::CapabilityError::new(
            "\u{1}".repeat(48),
            "\u{1}".repeat(336),
        ));
        let measured = json_bytes(&envelope);
        assert!(
            measured <= FS_METADATA_ERROR_BOUND,
            "the refusal allowance must cover the widest escaped error frame: {measured}"
        );
        // The metadata preflight must reserve the whole refusal allowance
        // before IO, and the error frame is charged beyond the success frame.
        const _: () = assert!(FS_METADATA_BOUND >= FS_METADATA_ERROR_BOUND);
        const _: () = assert!(FS_METADATA_BOUND > FS_METADATA_FRAME_BOUND);
        // A real bounded refusal stays far inside the allowance, so reserving it
        // does not disturb ordinary metadata reads.
        let real = capability_error_envelope(&crate::capabilities::CapabilityError::new(
            "path_denied",
            "symlinks are not followed",
        ));
        assert!(json_bytes(&real) < FS_METADATA_ERROR_BOUND);
        let mut outer = real
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        outer.sort();
        let mut expected_outer = FS_METADATA_OUTER_KEYS.map(str::to_string).to_vec();
        expected_outer.sort();
        assert_eq!(outer, expected_outer);
        let mut inner = real["error"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        inner.sort();
        let mut expected_inner = FS_METADATA_ERROR_KEYS.map(str::to_string).to_vec();
        expected_inner.sort();
        assert_eq!(inner, expected_inner);
    }

    #[test]
    fn guest_result_measurement_matches_the_strict_json_encoding() {
        // Escaping, byte buffers, non-string map keys, non-finite floats and
        // callables are measured exactly as `guest_result_json` encodes them,
        // so the pre-allocation bound equals the canonical encoding.
        let value = Value::map(vec![
            (Value::string("text"), Value::string("a\"b\\c\n\u{1}é")),
            (Value::string("bytes"), Value::bytes(b"raw-bytes".to_vec())),
            (Value::Int(7), Value::Int(-3)),
            (Value::Float(f64::NAN), Value::Null),
            (
                Value::string("items"),
                Value::array(vec![Value::Null, Value::Bool(true), Value::Bool(false)]),
            ),
        ]);
        let json = guest_result_json(&value).unwrap();
        let exact = serde_json::to_string(&json).unwrap().len() as u64;
        assert_eq!(
            crate::effects::journal::BoundedJsonCounter::measure(&GuestResultJson(&value), exact)
                .unwrap(),
            exact
        );
        assert!(
            crate::effects::journal::BoundedJsonCounter::measure(
                &GuestResultJson(&value),
                exact - 1
            )
            .is_err()
        );
        assert_eq!(validate_guest_result(&value), Ok(()));
        // An invalid byte buffer is refused by every step of the path, so no
        // lossy replacement can reach the measurement or the JSON tree.
        let invalid = Value::bytes(vec![0xff, 0xfe]);
        assert!(validate_guest_result(&invalid).is_err());
        assert!(guest_result_json(&invalid).is_err());
        assert!(
            crate::effects::journal::BoundedJsonCounter::measure(
                &GuestResultJson(&invalid),
                u64::MAX
            )
            .is_err()
        );
        // A byte buffer used as a map key is validated the same way instead of
        // falling back to the lossy converter.
        let byte_key = Value::map(vec![(Value::bytes(vec![0xff]), Value::Int(1))]);
        assert!(guest_result_json(&byte_key).is_err());
        let text_key = Value::map(vec![(Value::bytes(b"key".to_vec()), Value::Int(1))]);
        assert_eq!(
            guest_result_json(&text_key).unwrap(),
            json!({ "\"key\"": 1 })
        );
    }

    #[test]
    fn bounded_writer_refuses_one_byte_over_before_allocating() {
        let value =
            json!({"ok": true, "content": "abcd", "data": {}, "truncated": false, "artifacts": []});
        let exact = serde_json::to_string(&value).unwrap().len() as u64;
        assert_eq!(
            crate::effects::journal::BoundedJsonCounter::measure(&value, exact).unwrap(),
            exact
        );
        assert!(crate::effects::journal::BoundedJsonCounter::measure(&value, exact - 1).is_err());
        let canonical =
            crate::effects::journal::CanonicalToolResultJson::from_value(&value).unwrap();
        let size = canonical.as_str().len() as u64;
        assert!(
            crate::effects::journal::CanonicalToolResultJson::from_value_bounded(&value, size)
                .is_ok()
        );
        assert!(
            crate::effects::journal::CanonicalToolResultJson::from_value_bounded(&value, size - 1)
                .is_err()
        );
    }
}

#[cfg(test)]
mod s2_child_state_handoff_tests {
    use super::*;
    use std::path::PathBuf;

    const S2_CALLEE_PACKAGE: &str = "org.rustscript.test.s2callee";
    const S2_ARTIFACT: &str = "artifact-s2callee";

    fn s2_test_root() -> PathBuf {
        let base = std::env::var("RUSTSCRIPT_AGENT_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::var("CARGO_TARGET_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"))
                    .join("s2-tmp")
            });
        let dir = base.join(format!("s2-handoff-{}", uuid::Uuid::new_v4().simple()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("s2 handoff scratch");
        dir
    }

    fn s2_seed_run(
        persistence: &crate::gateway::store::GatewayPersistence,
        session_id: &str,
        run_id: &str,
    ) {
        persistence
            .session_create(&json!({
                "id": session_id,
                "profile": "default",
                "platform": "s2-handoff-test",
                "account_id": session_id,
                "chat_id": session_id,
                "thread_id": "",
                "user_id": "",
                "generation": 1,
                "system_prompt": "",
                "model": "test-model",
                "provider": "test-provider",
                "toolset_hash": "test-tools",
                "metadata_json": "{}",
                "title": "",
                "end_reason": "",
                "now_ms": 10,
            }))
            .expect("seed session");
        persistence
            .run_create(&json!({
                "id": run_id,
                "session_id": session_id,
                "parent_run_id": "",
                "input_json": "{}",
                "provider": "test-provider",
                "model": "test-model",
                "script_hash": "",
                "idempotency_scope": "",
                "idempotency_key": "",
                "now_ms": 11,
            }))
            .expect("seed run");
    }

    fn s2_state_call(
        store: crate::plugins::PluginStateStore,
        run_id: &str,
        session_id: &str,
        call_id: &str,
    ) -> PluginStateCall {
        PluginStateCall {
            store,
            run_id: run_id.to_string(),
            session_id: session_id.to_string(),
            profile: "default".to_string(),
            graph_id: "graph-s2".to_string(),
            package_id: S2_CALLEE_PACKAGE.to_string(),
            artifact_id: S2_ARTIFACT.to_string(),
            scope: crate::plugins::PluginStateScope::Run,
            schema: 1,
            call_id: call_id.to_string(),
            can_read: true,
            can_write: true,
            managed_effect_commit: true,
            cancellation: RunCancellation::default(),
            staged: Arc::new(Mutex::new(None)),
        }
    }

    fn s2_root_revision(store: &crate::plugins::PluginStateStore, run_id: &str) -> u64 {
        store
            .binding(run_id)
            .expect("read binding")
            .expect("run binding")
            .binding
            .revision
    }

    #[test]
    fn s2_child_state_handoff_routes_child_publication_with_writer_lease() {
        let root = s2_test_root();
        let persistence = Arc::new(
            crate::gateway::store::GatewayPersistence::open(
                &crate::config::AgentGatewayConfig::default(),
                &root.join("gateway.sqlite"),
            )
            .expect("open persistence"),
        );
        let run_id = "run-s2-handoff";
        let session_id = "session-s2-handoff";
        s2_seed_run(&persistence, session_id, run_id);
        let store = crate::plugins::PluginStateStore::open(Arc::clone(&persistence));
        store
            .bind_run(&crate::plugins::PluginStateBindRequest {
                run_id: run_id.to_string(),
                session_id: session_id.to_string(),
                workspace_id: "workspace-s2".to_string(),
                branch_id: "branch-s2".to_string(),
                plugin_id: S2_CALLEE_PACKAGE.to_string(),
                package_id: S2_CALLEE_PACKAGE.to_string(),
                artifact_id: S2_ARTIFACT.to_string(),
                scope: crate::plugins::PluginStateScope::Run,
                graph_id: "graph-s2".to_string(),
                epoch: 1,
                schema: 1,
                checkpoint_id: String::new(),
            })
            .expect("bind callee run root");
        assert_eq!(s2_root_revision(&store, run_id), 1);

        // The caller-side clone shares the staged Arc, so the publication the
        // child staged survives the child VM exit and is visible here.
        let child = s2_state_call(store.clone(), run_id, session_id, "call-s2-child");
        let staged = child.write(1, "{\"count\":1}");
        assert_eq!(staged["ok"], json!(true), "child stages: {staged}");
        let caller_side_view = child.clone();
        let shared = caller_side_view.take_state_publication();
        assert!(
            shared
                .as_ref()
                .is_some_and(|(publication, _)| publication.plugin_id == S2_CALLEE_PACKAGE),
            "the caller-side clone must observe the child-staged publication"
        );
        drop(shared);

        // Stateless caller (no caller call) plus a staged child: the handoff
        // yields the child publication with its candidate lease and an
        // acquired writer lease, while the root stays untouched until commit.
        let staged = child.write(1, "{\"count\":1}");
        assert_eq!(staged["ok"], json!(true), "child re-stages: {staged}");
        let handoff = take_managed_state_handoff(None, Some(&child)).expect("child handoff");
        let Some(handoff) = handoff else {
            panic!("a staged child must produce a handoff");
        };
        assert_eq!(handoff.publication.plugin_id, S2_CALLEE_PACKAGE);
        assert!(!handoff.publication.ephemeral);
        assert!(
            handoff.owner.is_some(),
            "the candidate lease must travel with the publication into prepare"
        );
        assert!(
            handoff.writer.is_some(),
            "the writer lease must be acquired before prepare_result"
        );
        assert_eq!(s2_root_revision(&store, run_id), 1);
        drop(handoff);

        // Caller and child both staged: refuse, never silently drop either.
        let staged = child.write(1, "{\"count\":2}");
        assert_eq!(staged["ok"], json!(true), "child stages again: {staged}");
        let caller = s2_state_call(store.clone(), run_id, session_id, "call-s2-caller");
        let staged = caller.write(1, "{\"count\":9}");
        assert_eq!(staged["ok"], json!(true), "caller stages: {staged}");
        let refused = take_managed_state_handoff(Some(&caller), Some(&child));
        let error = match refused {
            Err(error) => error,
            Ok(_) => panic!("dual publication must be refused"),
        };
        assert_eq!(error.code, "managed_prepare_failed");
        assert_eq!(s2_root_revision(&store, run_id), 1);

        // Caller-only staging keeps the S1 path: caller publication, caller lease.
        let staged = caller.write(1, "{\"count\":9}");
        assert_eq!(staged["ok"], json!(true), "caller re-stages: {staged}");
        let handoff = take_managed_state_handoff(Some(&caller), None).expect("caller handoff");
        let Some(handoff) = handoff else {
            panic!("a staged caller must produce a handoff");
        };
        assert_eq!(handoff.publication.plugin_id, S2_CALLEE_PACKAGE);
        assert!(handoff.writer.is_some());
        assert_eq!(s2_root_revision(&store, run_id), 1);
        drop(handoff);

        // Nothing staged: no publication, S1/stateless prepare unchanged.
        assert!(
            take_managed_state_handoff(None, None)
                .expect("empty handoff")
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn s2_child_production_populates_child_state_call_from_callee_binding() {
        let root = s2_test_root();
        let persistence = Arc::new(
            crate::gateway::store::GatewayPersistence::open(
                &crate::config::AgentGatewayConfig::default(),
                &root.join("gateway.sqlite"),
            )
            .expect("open persistence"),
        );
        let run_id = "run-s2-production";
        let session_id = "session-s2-production";
        s2_seed_run(&persistence, session_id, run_id);
        let store = crate::plugins::PluginStateStore::open(Arc::clone(&persistence));
        store
            .bind_run(&crate::plugins::PluginStateBindRequest {
                run_id: run_id.to_string(),
                session_id: session_id.to_string(),
                workspace_id: "workspace-s2".to_string(),
                branch_id: "branch-s2".to_string(),
                plugin_id: S2_CALLEE_PACKAGE.to_string(),
                package_id: S2_CALLEE_PACKAGE.to_string(),
                artifact_id: S2_ARTIFACT.to_string(),
                scope: crate::plugins::PluginStateScope::Run,
                graph_id: "graph-s2".to_string(),
                epoch: 1,
                schema: 1,
                checkpoint_id: String::new(),
            })
            .expect("bind callee run root");

        let read_write_contract = crate::effects::broker::ManagedEntryContract {
            trust: crate::plugins::PackageTrust::AcceptedPublisher,
            effects: vec![
                crate::effects::broker::ManagedEffectRequirement {
                    kind: "workspace.fs.read".to_string(),
                    scope: "bound_workspace".to_string(),
                    recovery: "none".to_string(),
                },
                crate::effects::broker::ManagedEffectRequirement {
                    kind: "workspace.fs.write".to_string(),
                    scope: "bound_workspace".to_string(),
                    recovery: "none".to_string(),
                },
            ],
            topology: None,
        };
        let run_state = crate::plugins::StateDeclaration {
            scope: "run".to_string(),
            schema: 1,
            migration: None,
        };
        let cancellation = RunCancellation::default();

        // S1 stateless path stays empty: no callee declaration means no child call.
        let s1 = child_state_call_for(
            Some(&store),
            S2_CALLEE_PACKAGE,
            S2_ARTIFACT,
            None,
            None,
            run_id,
            session_id,
            "default",
            "graph-s2",
            "call-s2-parent",
            &cancellation,
        )
        .expect("s1 must not error");
        assert!(
            s1.is_none(),
            "S1 without a callee run declaration must keep child_state_call None"
        );

        // S2 production path: run scope schema 1 without migration populates
        // the child call from the callee run binding.
        let s2 = child_state_call_for(
            Some(&store),
            S2_CALLEE_PACKAGE,
            S2_ARTIFACT,
            Some(&run_state),
            Some(&read_write_contract),
            run_id,
            session_id,
            "default",
            "graph-s2",
            "call-s2-parent",
            &cancellation,
        )
        .expect("s2 construction must succeed");
        let Some(child) = s2 else {
            panic!("production path must not leave child_state_call empty for S2");
        };
        assert_eq!(child.package_id, S2_CALLEE_PACKAGE);
        assert_eq!(child.artifact_id, S2_ARTIFACT);
        assert_eq!(child.scope, crate::plugins::PluginStateScope::Run);
        assert_eq!(child.schema, 1);
        assert_eq!(child.run_id, run_id);
        assert_eq!(child.call_id, "call-s2-parent");
        assert!(child.can_read, "callee contract grants workspace.fs.read");
        assert!(child.can_write, "callee contract grants workspace.fs.write");
        assert!(
            child.managed_effect_commit,
            "S2 always has a managed parent call"
        );
        // The populated call is usable: it can stage against the bound root.
        let staged = child.write(1, "{\"count\":1}");
        assert_eq!(staged["ok"], json!(true), "child stages: {staged}");

        // Non-S2 declarations stay empty: session scope, other schemas and
        // migrations never populate the production field.
        let session_state = crate::plugins::StateDeclaration {
            scope: "session".to_string(),
            schema: 1,
            migration: None,
        };
        assert!(
            child_state_call_for(
                Some(&store),
                S2_CALLEE_PACKAGE,
                S2_ARTIFACT,
                Some(&session_state),
                Some(&read_write_contract),
                run_id,
                session_id,
                "default",
                "graph-s2",
                "call-s2-parent",
                &cancellation,
            )
            .expect("session scope must not error")
            .is_none(),
            "only run scope populates the child call"
        );
        let schema2 = crate::plugins::StateDeclaration {
            scope: "run".to_string(),
            schema: 2,
            migration: None,
        };
        assert!(
            child_state_call_for(
                Some(&store),
                S2_CALLEE_PACKAGE,
                S2_ARTIFACT,
                Some(&schema2),
                Some(&read_write_contract),
                run_id,
                session_id,
                "default",
                "graph-s2",
                "call-s2-parent",
                &cancellation,
            )
            .expect("schema 2 must not error")
            .is_none(),
            "only schema 1 populates the child call"
        );
        let migrating = crate::plugins::StateDeclaration {
            scope: "run".to_string(),
            schema: 1,
            migration: Some(crate::plugins::StateMigration {
                entry: "migrate".to_string(),
            }),
        };
        assert!(
            child_state_call_for(
                Some(&store),
                S2_CALLEE_PACKAGE,
                S2_ARTIFACT,
                Some(&migrating),
                Some(&read_write_contract),
                run_id,
                session_id,
                "default",
                "graph-s2",
                "call-s2-parent",
                &cancellation,
            )
            .expect("migration must not error")
            .is_none(),
            "a callee migration never populates the child call"
        );

        // Callee allowlist: only state::read and state::write reach the child.
        assert!(
            crate::plugins::child_program_import_allowed("state::read"),
            "callee must admit state::read"
        );
        assert!(
            crate::plugins::child_program_import_allowed("state::write"),
            "callee must admit state::write"
        );
        assert!(
            !crate::plugins::child_program_import_allowed("cap::fs_write_atomic"),
            "callee must still refuse cap::fs_write_atomic"
        );
        let child_module = retained_child_host_module();
        let descriptors = child_module.descriptors();
        let names: Vec<&str> = descriptors
            .iter()
            .map(|descriptor| descriptor.schema.name.as_str())
            .collect();
        assert!(
            names.contains(&"state::read"),
            "child module must install state::read, got {names:?}"
        );
        assert!(
            names.contains(&"state::write"),
            "child module must install state::write, got {names:?}"
        );
        assert!(
            !names.contains(&"cap::fs_write_atomic"),
            "child module must not add cap::fs_write_atomic, got {names:?}"
        );
        assert!(
            !names.contains(&"cap::fs_list"),
            "child module must not add cap::fs_list, got {names:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
