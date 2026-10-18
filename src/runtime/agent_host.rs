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
const APPROVAL_STORAGE: &str = "agent::approval_storage";
const TOOL_COMMIT: &str = "agent_runtime::tool_commit";
const INVOKE_PINNED_TOOL: &str = "agent_runtime::invoke_pinned_tool";
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
    program: Arc<rustscript_vm::Program>,
    entry: String,
    graph_id: String,
    package_id: String,
    artifact_id: String,
    export: String,
    run_id: String,
    session_id: String,
    profile: String,
    ref_id: String,
    generation: u64,
    registry_identity: String,
    workspace: std::path::PathBuf,
    registry: Result<Arc<HostFunctionRegistry>, String>,
    expects_dispatch_input: bool,
}

#[derive(Clone)]
pub(crate) struct PinnedToolCode {
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

impl PinnedToolProgram {
    pub(crate) fn seal(code: PinnedToolCode, receipt: PinnedToolReceipt) -> Self {
        Self {
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

    pub fn entry(&self) -> &str {
        &self.entry
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
    pub run_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub registry_identity: String,
    pub risk_class: String,
    pub summary: String,
    outcome: Arc<Mutex<PinnedCallOutcome>>,
}

/// Native-only evidence for one child invocation. Guest return values cannot
/// populate this witness or borrow a sibling invocation's execution token.
#[derive(Default)]
enum PinnedCallOutcome {
    #[default]
    Pending,
    Executing {
        token: String,
    },
    Complete {
        result: JsonValue,
    },
    Failed {
        error: JsonValue,
    },
}

impl PinnedCallOutcome {
    fn resolve(&self, child: &JsonValue) -> JsonValue {
        match self {
            Self::Complete { result } => {
                match crate::capabilities::lifecycle::validate_canonical_result(result) {
                    Ok(()) => pinned_tool_result(result),
                    Err(error) => {
                        pinned_tool_result(&crate::capabilities::host::error_envelope(&error))
                    }
                }
            }
            Self::Failed { error } if error.get("ok") == Some(&JsonValue::Bool(false)) => {
                pinned_tool_result(error)
            }
            Self::Pending | Self::Executing { .. }
                if child.get("ok") == Some(&JsonValue::Bool(false)) =>
            {
                pinned_tool_result(child)
            }
            Self::Pending | Self::Executing { .. } | Self::Failed { .. } => pinned_outcome(
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
    pub(crate) provider_arguments: Arc<Mutex<HashMap<(String, String), JsonValue>>>,
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
        let parsed = match parse_prepare_metadata(metadata) {
            Ok(metadata) => metadata,
            Err(error) => return crate::capabilities::host::error_envelope(&error),
        };
        if let Some(grant) = &self.expected_call
            && !grant.matches(&parsed)
        {
            return pinned_call_mismatch();
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
            return pinned_call_mismatch();
        }
        let envelope = tool_prepare(lifecycle, owner, parsed);
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
                && let Some(result) = envelope.get("result")
            {
                PinnedCallOutcome::Complete {
                    result: result.clone(),
                }
            } else {
                PinnedCallOutcome::Failed {
                    error: envelope.clone(),
                }
            };
        }
        envelope
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
        let risk_class = field("risk_class");
        let summary = field("summary");
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
        let grant = ExpectedCallGrant {
            run_id: pinned.run_id.clone(),
            call_id,
            tool_name,
            argument_digest: canonical,
            registry_identity: pinned.registry_identity.clone(),
            risk_class,
            summary,
            outcome: Arc::clone(&outcome),
        };
        if grant.call_id.is_empty() || grant.tool_name.is_empty() {
            return pinned_call_mismatch();
        }
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
        match super::rss_runner::invoke_retained_tool(
            Arc::clone(&pinned.program),
            &pinned.entry,
            host,
            json_to_vm_value(&context),
            &self.cancellation,
            &pinned.registry,
            Some(grant),
        ) {
            Ok(value) => outcome
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .resolve(&vm_value_to_json(&value)),
            Err(error) => pinned_outcome(false, "", "", "pinned_tool_failed", &error, ""),
        }
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

    fn capability_approval_attest(&self, metadata: &JsonValue) -> JsonValue {
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
        let result = parse_prepare_metadata(metadata)
            .and_then(|metadata| lifecycle.attest_approval(owner, metadata));
        match result {
            Ok(()) => json!({ "ok": true, "kind": "attested" }),
            Err(error) => crate::capabilities::host::error_envelope(&error),
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
        let envelope = tool_commit(lifecycle, owner, token, result.clone());
        if let Some(outcome) = outcome.as_deref_mut() {
            *outcome = if envelope.get("ok") == Some(&JsonValue::Bool(true))
                && envelope.get("kind").and_then(JsonValue::as_str) == Some("committed")
                && envelope.get("call_id").and_then(JsonValue::as_str)
                    == self
                        .expected_call
                        .as_ref()
                        .map(|grant| grant.call_id.as_str())
                && let Some(result) = envelope.get("result")
            {
                PinnedCallOutcome::Complete {
                    result: result.clone(),
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

fn invoke_pinned_tool_adapter(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let request = args.first().cloned().unwrap_or(Value::Null);
    let state = installed_state(vm)?;
    return_json(state.invoke_pinned_tool(&vm_value_to_json(&request)))
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
        Ok(encoded) if encoded.len() <= PINNED_CANONICAL_RESULT_MAX_BYTES => encoded,
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
