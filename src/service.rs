//! AgentService: atomic run admission, typed cancellation, the run worker
//! lifecycle, and bounded in-memory lifecycle state.
//!
//! One reservation covers capacity (a semaphore permit), session
//! resolution/creation, the run ID, and the cancellation/delivery state; any
//! failure rolls back every intermediate step, so a rejected admission leaves
//! no session or run behind. The service owns sequencing, persistence hooks,
//! and live delivery: the worker builds the canonical run context, drives the
//! exported RSS `run(context)` through the invocation item stream, delivers
//! script events durably and live, and commits exactly one typed terminal
//! transition. Stop, timeout, disconnect, and gateway halt map to typed core
//! cancellation reasons. Terminal lifecycle handles are bounded by a
//! configured TTL. A terminal commit that cannot be persisted durably is
//! retried with bounded backoff (`terminal_persist_retries`/
//! `terminal_persist_retry_delay`); if every attempt fails, the run becomes
//! observably `terminal_pending` (never a false terminal): the admission
//! permit is released immediately, and a bounded retry loop (janitor
//! cadence) commits the typed terminal when storage recovers. After the
//! retry window the durable side is left for restart recovery, so a
//! sustained outage can neither exhaust capacity nor leak handles or live
//! streams forever. Nothing is ever published before the durable commit
//! succeeds. Live subscribers observe at-least-once delivery of durable
//! events; exactly-once is not guaranteed across an unacknowledged receiver
//! crash window.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::{
    Arc, Condvar, Mutex, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::{Mutex as ParkingMutex, RwLock};
use rustscript_vm::{HttpConfig, InvocationError, Value as VmValue};

use crate::runtime::cancellation::{CancellationReason, CancellationToken};
use serde_json::{Map, Value as JsonValue, json};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::capabilities::{
    ArtifactCapability, ArtifactLimits, CancellationFlag, CapabilityLifecycle, CapabilityOwner,
    DurableStarted, DurableToolLifecycle, FilesystemCapability, FilesystemLimits,
    GuardianApprovalGate, LifecycleError, LifecycleLimits, ProcessCapability, ProcessLimits,
    SystemClock, UuidIssuer,
};
use crate::config::{
    ADMISSION_IDEMPOTENCY_SCOPE, ADMISSION_RUN_COL_ID, ADMISSION_RUN_COL_INPUT_JSON,
    ADMISSION_RUN_COL_MODEL, ADMISSION_RUN_COL_PARENT_RUN_ID, ADMISSION_RUN_COL_PROVIDER,
    ADMISSION_RUN_COL_SCRIPT_HASH, ADMISSION_RUN_COL_SESSION_ID, ADMISSION_RUN_COL_STATUS,
    ADMISSION_SESSION_PROFILE, AdmissionSqliteCellLens, AgentGatewayConfig, ClientDisconnectPolicy,
    FileToolConfig, MAX_IDEMPOTENCY_KEY_BYTES, MAX_MODEL_NAME_BYTES, MAX_PROVIDER_NAME_BYTES,
    MAX_RUN_CONTEXT_STORAGE_BYTES, MAX_TOOL_OUTPUT_BYTES, ProcessToolConfig, ProviderProfile,
    ProviderProfileError, RunLimits, RunLimitsError, estimate_admission_query_bytes,
    validate_request_hash, validate_visible_name,
};
use crate::config_file::CompactionSettings;
#[cfg(test)]
#[path = "service_preflight_tests.rs"]
mod preflight_tests;

use crate::domain::{
    LlmContentBlock, MAX_DURABLE_TEXT_CHARS, RunContext, decode_message_blocks,
    decode_message_content, durable_message_id, durable_provider_event_id, durable_tool_event_id,
    encode_message_content, json_to_vm_value, provider_pending_may_retry, timestamp,
    truncate_for_log, truncate_utf8_chars, vm_value_to_json,
};
use crate::events;
use crate::events::{DurableEventCommitter, EventCommitError};
use crate::gateway::store::{
    GatewayEvent, GatewayPersistence, GatewayStore, IdempotencyRecord, RunRecord, SessionMessage,
    SessionRecord, SessionView, WorkspaceBinding,
};
use crate::metrics::{AdmitRejectReason, Metrics, TerminalRetryOutcome, TerminalStatus};
use crate::prompt::{CodingPromptBudgets, DateSource, SystemDateSource, build_coding_prompt};
use crate::registry::{ToolRegistry, ToolRegistrySnapshot};
use crate::runtime::delivery::{
    ChannelEventSink, DeliveryContext, apply_event_locked, event_candidate, run_delivery_task,
};
use crate::runtime::rss_runner::{AgentConfig, AgentRunner, bundled_tool_registry};
use crate::tool_result::ToolResult;
use crate::{AgentHostBridges, AgentProviderHost, RunCancellation, RunError};

/// Typed outcome of bounded capability-host cleanup. Never claims success when
/// process residue could not be confirmed stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    Clean,
    Timeout,
    Failed,
}

/// Private tagged agent entry route. `File` keeps the original live-tree
/// compile/freshness behavior (fixed install path only). `Bundled` names an
/// embedded catalog key admitted by the RSS source policy; it is compiled
/// from the immutable native closed bundle and never reads the checkout
/// module tree.
#[derive(Clone)]
enum AgentEntry {
    File(PathBuf),
    Bundled(String),
}

struct CachedAgentRunner {
    source_digest: String,
    config: AgentConfig,
    runner: AgentRunner,
}

#[derive(Clone, Copy)]
struct AdmissionReplayIdentity<'a> {
    key: Option<&'a str>,
    request_hash: Option<&'a str>,
    request_selector: Option<&'a str>,
}

struct SessionMaintenanceLease {
    session_id: String,
    sessions: Arc<ParkingMutex<HashSet<String>>>,
}

impl SessionMaintenanceLease {
    fn acquire(sessions: Arc<ParkingMutex<HashSet<String>>>, session_id: &str) -> Option<Self> {
        if !sessions.lock().insert(session_id.to_string()) {
            return None;
        }
        Some(Self {
            session_id: session_id.to_string(),
            sessions,
        })
    }
}

impl Drop for SessionMaintenanceLease {
    fn drop(&mut self) {
        self.sessions.lock().remove(&self.session_id);
    }
}

fn agent_source_digest(source: &str) -> String {
    crate::capabilities::sha256_hex(source.as_bytes())
}

fn failed_payload_with_code(code: &str, error: String) -> JsonValue {
    json!({
        "status": "failed",
        "error_code": code,
        "error_message": error,
    })
}

/// Recovery action for a pending provider request after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderPendingDecision {
    Retry,
    Replay,
    Interrupted,
    /// The run is already terminal; recovery must not append `model.completed`.
    RefusedTerminal,
}

/// Canonical durable provider step returned by [`AgentService::commit_provider_step`].
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderCommit {
    pub message_id: String,
    pub envelope: JsonValue,
}

/// Inserted records a new turn. Existing returns the durable envelope and
/// never the caller's fresh payload.
#[derive(Clone, Debug, PartialEq)]
pub enum ProviderCommitOutcome {
    Inserted(ProviderCommit),
    Existing(ProviderCommit),
}

impl ProviderCommitOutcome {
    pub fn message_id(&self) -> &str {
        match self {
            Self::Inserted(commit) | Self::Existing(commit) => &commit.message_id,
        }
    }

    pub fn envelope(&self) -> &JsonValue {
        match self {
            Self::Inserted(commit) | Self::Existing(commit) => &commit.envelope,
        }
    }

    pub fn is_inserted(&self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

const PROVIDER_RETRY_BUDGET: u64 = 2;
const SECRET_PROVIDER_REQUEST_KEYS: &[&str] = &[
    "request",
    "messages",
    "prompt",
    "provider_options",
    "api_key",
    "headers",
    "body",
    "authorization",
    "system",
    "instructions",
    "content",
];

/// One run whose terminal state could not be committed durably. The worker
/// has already exited; a bounded retry loop (janitor cadence) commits the
/// typed terminal when storage recovers — durable commit first, then
/// broadcast. Live subscribers observe at-least-once delivery of durable
/// events; exactly-once is not guaranteed across an unacknowledged receiver
/// crash window. The deadline bounds the
/// retry so a sustained outage cannot exhaust admission capacity or
/// accumulate retry state forever; the durable side is repaired by restart
/// recovery once the window expires.
#[derive(Clone)]
pub struct PendingTerminal {
    pub(crate) to_status: String,
    pub(crate) session_id: Option<String>,
    pub(crate) events: Vec<GatewayEvent>,
    pub(crate) assistant_message: Option<SessionMessage>,
    pub(crate) deadline: std::time::Instant,
}

/// One admitted run's lifecycle state: typed cancellation, delivery permit,
/// bounded terminal retention, and live SSE subscriber tracking.
pub struct RunHandle {
    pub(crate) cancel: RunCancellation,
    pub(crate) terminal_at: Mutex<Option<Instant>>,
    pub(crate) permit: Mutex<Option<OwnedSemaphorePermit>>,
    pub(crate) started_at: Instant,
    /// Set when the one terminal transition is committed (mark_terminal).
    /// The subscriber drop guard never requests a client-disconnect
    /// cancellation for a run that already reached a terminal.
    terminal: AtomicBool,
    /// The typed gateway cancellation reason (stop/halt/client disconnect).
    /// The worker commits this exact reason instead of the generic core
    /// string, so `client_disconnect` survives into the persisted terminal.
    cancel_reason: Mutex<Option<&'static str>>,
    /// Live SSE subscriber bookkeeping: the active count and the
    /// exactly-once disconnect notification flag, guarded by one short
    /// critical section so attach/drop races are atomic.
    subscribers: Mutex<SubscriberState>,
    disconnect_policy: ClientDisconnectPolicy,
    /// Created at admission and cancelled by every stop/deadline/terminal path.
    tool_cancel: CancellationToken,
    /// Run-scoped capability host shared by RSS `tools::dispatch` and cleanup.
    capability_host: Mutex<CapabilityHostPhase>,
    capability_host_cv: Condvar,
    workspace_authority: Option<Arc<crate::runtime::rss_runner::WorkspaceAuthority>>,
    legacy_workspace_root: Option<PathBuf>,
    /// Frozen coding system prompt captured at admission.
    coding_system_prompt: Arc<str>,
    /// Exclusive worker occupancy. Concurrent `run_worker` tasks cannot both
    /// call the provider or advance the turn. Released on Drop (error/panic).
    occupancy: AtomicBool,
}

/// Run-scoped capability host shared by RSS dispatch and lifecycle cleanup.
struct CapabilityHostState {
    cleaned: AtomicBool,
    shutdown_entered: Option<Arc<dyn Fn() + Send + Sync>>,
    cleanup_grace: Duration,
    uncooperative: Option<Arc<AtomicBool>>,
    lifecycle: Arc<CapabilityLifecycle>,
    capability_owner: CapabilityOwner,
    filesystem: Option<Arc<FilesystemCapability>>,
    processes: Option<Arc<ProcessCapability>>,
    artifacts: Arc<ArtifactCapability>,
}

/// Two-phase capability-host slot. The handle lock is never held across
/// filesystem IO. `Closed` retains the process capability so residue stays
/// observable after the live host is released.
enum CapabilityHostPhase {
    Empty,
    Initializing,
    Ready(Arc<CapabilityHostState>),
    Closed(Option<ClosedCapabilityHost>),
}

#[derive(Clone)]
struct ClosedCapabilityHost {
    processes: Option<Arc<ProcessCapability>>,
}

/// Restores a retriable `Empty` phase if initialization panics or returns
/// `Err` before `Ready` is published. Drop never waits on IO or the condvar.
struct CapabilityHostInitGuard {
    handle: Arc<RunHandle>,
    armed: bool,
}

impl CapabilityHostInitGuard {
    fn arm(handle: &Arc<RunHandle>) -> Self {
        Self {
            handle: Arc::clone(handle),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CapabilityHostInitGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut phase = self
            .handle
            .capability_host
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*phase, CapabilityHostPhase::Initializing) {
            *phase = CapabilityHostPhase::Empty;
        }
        self.handle.capability_host_cv.notify_all();
    }
}

impl CapabilityHostState {
    fn shutdown(&self) -> CleanupOutcome {
        self.shutdown_with_grace(self.cleanup_grace)
    }

    fn shutdown_with_grace(&self, grace: Duration) -> CleanupOutcome {
        if self.cleaned.swap(true, Ordering::SeqCst) {
            return if self
                .processes
                .as_ref()
                .is_none_or(|processes| processes.table_len() == 0)
            {
                CleanupOutcome::Clean
            } else {
                CleanupOutcome::Timeout
            };
        }
        if let Some(observer) = &self.shutdown_entered {
            observer();
        }
        if let Some(release) = &self.uncooperative {
            let started = Instant::now();
            while !release.load(Ordering::SeqCst) && started.elapsed() < grace {
                thread::sleep(Duration::from_millis(10));
            }
            if !release.load(Ordering::SeqCst) {
                return CleanupOutcome::Timeout;
            }
        }
        if let Some(processes) = &self.processes {
            processes.shutdown_all();
        }
        let _ = self.lifecycle.recover_open_tokens();
        if self
            .processes
            .as_ref()
            .is_some_and(|processes| processes.table_len() > 0)
        {
            CleanupOutcome::Timeout
        } else {
            CleanupOutcome::Clean
        }
    }

    fn host_bridges(
        &self,
        cancellation: RunCancellation,
        metrics: Option<Arc<Metrics>>,
    ) -> AgentHostBridges {
        AgentHostBridges {
            provider: None,
            auth_host_factory: None,
            cancellation: Some(cancellation),
            sleeps: Default::default(),
            skip_sleep: false,
            metrics,
            lifecycle: Some(Arc::clone(&self.lifecycle)),
            capability_owner: Some(self.capability_owner.clone()),
            filesystem: self.filesystem.clone(),
            processes: self.processes.clone(),
            artifacts: Some(Arc::clone(&self.artifacts)),
            control_hook: None,
        }
    }
}

impl Drop for CapabilityHostState {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Live SSE subscriber accounting for one run handle.
struct SubscriberState {
    count: usize,
    /// True once the last-subscriber disconnect cancellation was requested.
    notified: bool,
}

impl RunHandle {
    /// True while the run has not committed a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.terminal_at.lock().expect("terminal lock").is_some()
    }

    /// Frozen coding system prompt captured at admission for this run.
    pub fn coding_system_prompt(&self) -> &str {
        &self.coding_system_prompt
    }

    /// Sole cancellation root for this run. `stop` requests it; hosts and the
    /// capability host child tokens are linked to it.
    pub fn cancellation(&self) -> &RunCancellation {
        &self.cancel
    }

    fn request_user_stop(&self) {
        *self.cancel_reason.lock().expect("cancel reason lock") = Some("requested");
        self.cancel.request(CancellationReason::Requested);
        self.cancel_run_tools();
    }

    fn cancel_run_tools(&self) {
        self.tool_cancel.cancel();
        let (lifecycle, processes) = {
            let phase = self
                .capability_host
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match &*phase {
                CapabilityHostPhase::Ready(state) => {
                    (Some(Arc::clone(&state.lifecycle)), state.processes.clone())
                }
                _ => (None, None),
            }
        };
        if let Some(processes) = processes {
            processes.cancel_all();
        }
        if let Some(lifecycle) = lifecycle {
            let _ = lifecycle.recover_open_tokens();
        }
    }

    fn capability_host_closed(&self) -> bool {
        matches!(
            *self.capability_host.lock().expect("capability host lock"),
            CapabilityHostPhase::Closed(_)
        )
    }

    fn release_capability_host(&self) -> CleanupOutcome {
        self.tool_cancel.cancel();
        if let Some(authority) = &self.workspace_authority {
            authority.revoke();
        }
        let state = {
            let mut phase = self.capability_host.lock().expect("capability host lock");
            match std::mem::replace(&mut *phase, CapabilityHostPhase::Closed(None)) {
                CapabilityHostPhase::Ready(state) => {
                    *phase = CapabilityHostPhase::Closed(Some(ClosedCapabilityHost {
                        processes: state.processes.clone(),
                    }));
                    self.capability_host_cv.notify_all();
                    Some(state)
                }
                CapabilityHostPhase::Closed(existing) => {
                    *phase = CapabilityHostPhase::Closed(existing);
                    self.capability_host_cv.notify_all();
                    None
                }
                CapabilityHostPhase::Empty | CapabilityHostPhase::Initializing => {
                    self.capability_host_cv.notify_all();
                    None
                }
            }
        };
        match state {
            Some(state) => state.shutdown(),
            None => CleanupOutcome::Clean,
        }
    }

    fn capability_host_retained(&self) -> bool {
        matches!(
            *self.capability_host.lock().expect("capability host lock"),
            CapabilityHostPhase::Ready(_)
        )
    }
}

/// Drop guard returned by [`AgentService::attach_subscriber`] and moved into
/// the SSE stream state. Dropping it (client disconnect, stream end, or the
/// body future being cancelled) decrements the run's subscriber count
/// synchronously — no async destructor, no store lock. A cancel-on-disconnect
/// run whose count reaches zero while it is still active and whose stream
/// ended without delivering a terminal (so `armed` is still true) requests
/// the typed `client_disconnect` cancellation exactly once.
pub(crate) struct SubscriberGuard {
    handle: Arc<RunHandle>,
    /// False once a terminal event was delivered to this subscriber: a
    /// normal stream end after a terminal must never request a
    /// cancellation. A stream that ends without a terminal (client abort or
    /// closed live channel) stays armed.
    armed: bool,
}

impl SubscriberGuard {
    /// Disarms the guard when the SSE stream ends because a terminal event
    /// was delivered, so the drop never requests a cancellation.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        let mut subscribers = self.handle.subscribers.lock().expect("subscriber lock");
        subscribers.count = subscribers.count.saturating_sub(1);
        if !self.armed
            || subscribers.count != 0
            || self.handle.disconnect_policy != ClientDisconnectPolicy::CancelOnDisconnect
            || self.handle.terminal.load(Ordering::Acquire)
            || subscribers.notified
        {
            return;
        }
        subscribers.notified = true;
        // The gateway's typed reason is recorded before the request so the
        // worker commits `client_disconnect` (the core VM has no dedicated
        // variant; the request maps onto the core Requested reason).
        *self
            .handle
            .cancel_reason
            .lock()
            .expect("cancel reason lock") = Some("client_disconnect");
        self.handle.cancel.request(CancellationReason::Requested);
        self.handle.cancel_run_tools();
    }
}

/// The typed gateway cancellation reason recorded on the handle, or the
/// fallback when the cancellation was requested by the worker itself
/// (deadline) or by the core (e.g. parent).
fn handle_cancel_reason(handle: &RunHandle, fallback: &'static str) -> &'static str {
    handle
        .cancel_reason
        .lock()
        .expect("cancel reason lock")
        .unwrap_or(fallback)
}

/// Admission request built by the transport from the normalized request.
#[derive(Clone, Debug, Default)]
pub struct AdmitRunRequest {
    pub input: JsonValue,
    pub session_id: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub parent_run_id: Option<String>,
    pub instructions: Option<String>,
    pub platform: String,
    pub idempotency_key: Option<String>,
    pub idempotency_hash: Option<String>,
}

/// Result of an accepted (or idempotently replayed) admission.
#[derive(Clone, Debug)]
pub struct AdmittedRun {
    pub run_id: String,
    pub session_id: String,
    pub status: String,
    pub replayed: bool,
}

/// Typed errors raised when an admitted run cannot safely resume with its
/// captured context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunContextError {
    Missing {
        run_id: String,
    },
    RegistryMismatch {
        run_id: String,
        expected: String,
        actual: String,
    },
    InvalidMetadata {
        run_id: String,
        reason: String,
    },
    Persistence(String),
}

impl std::fmt::Display for RunContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { run_id } => {
                write!(formatter, "run context is missing for run {run_id}")
            }
            Self::RegistryMismatch {
                run_id,
                expected,
                actual,
            } => write!(
                formatter,
                "run {run_id} registry snapshot mismatch: expected {expected}, current {actual}"
            ),
            Self::InvalidMetadata { run_id, reason } => {
                write!(
                    formatter,
                    "run {run_id} context metadata is invalid: {reason}"
                )
            }
            Self::Persistence(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for RunContextError {}

#[derive(Clone, Debug)]
pub struct CompactionError {
    pub http_status: u16,
    pub code: String,
    pub message: String,
    detail: String,
}

impl CompactionError {
    /// Map an internal category through the shared RSS-owned public error policy.
    pub fn from_rss(kind: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let fallback = || Self {
            http_status: 500,
            code: "compaction_failed".to_string(),
            message: "Compaction could not be completed.".to_string(),
            detail: detail.clone(),
        };
        let Ok(policy) =
            AgentRunner::from_bundled("rss/agent/compaction_error.rss", AgentConfig::default())
        else {
            return fallback();
        };
        let Ok(value) = policy.run_with_context(json_to_vm_value(&json!({ "kind": kind }))) else {
            return fallback();
        };
        let mapped = vm_value_to_json(&value);
        let Some(error) = mapped.get("error") else {
            return fallback();
        };
        let Some(http_status) = mapped
            .get("http_status")
            .and_then(JsonValue::as_u64)
            .and_then(|status| u16::try_from(status).ok())
        else {
            return fallback();
        };
        let (Some(code), Some(message)) = (
            error.get("code").and_then(JsonValue::as_str),
            error.get("message").and_then(JsonValue::as_str),
        ) else {
            return fallback();
        };
        Self {
            http_status,
            code: code.to_string(),
            message: message.to_string(),
            detail,
        }
    }

    /// Raw service detail for private diagnostics; never include this in a public response.
    #[allow(dead_code)]
    pub(crate) fn diagnostic_detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for CompactionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CompactionError {}

#[derive(Debug)]
enum CompactionFailure {
    Host(String),
    Rss { code: String, detail: String },
}

impl CompactionFailure {
    fn host(detail: impl Into<String>) -> Self {
        Self::Host(detail.into())
    }

    fn rss(code: String, detail: String) -> Self {
        Self::Rss { code, detail }
    }

    fn mapper_code(&self) -> &str {
        match self {
            Self::Host(_) => "internal",
            Self::Rss { code, .. } => code,
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Host(detail) | Self::Rss { detail, .. } => detail,
        }
    }
}

#[derive(Debug)]
pub enum AdmitError {
    RunLimitReached,
    IdempotencyConflict,
    ParentNotFound,
    SessionNotFound,
    ActiveRun,
    SessionMaintenanceBusy(CompactionError),
    Persistence(String),
    Invalid(String),
    /// The gateway is halting (SIGINT path): admission is closed before
    /// active runs are cancelled, so no new work can start after shutdown
    /// begins.
    Halting,
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RunLimitReached => formatter.write_str("maximum concurrent run limit reached"),
            Self::IdempotencyConflict => {
                formatter.write_str("idempotency key was used with a different request")
            }
            Self::ParentNotFound => formatter.write_str("parent run not found"),
            Self::SessionNotFound => formatter.write_str("session not found"),
            Self::ActiveRun => formatter.write_str("workspace cannot change while a run is active"),
            Self::SessionMaintenanceBusy(error) => formatter.write_str(&error.message),
            Self::Persistence(message) => formatter.write_str(message),
            Self::Invalid(message) => formatter.write_str(message),
            Self::Halting => formatter.write_str("gateway is halting; new runs are not admitted"),
        }
    }
}

impl std::error::Error for AdmitError {}

const RUN_CONTEXT_METADATA_VERSION: u64 = 1;
const RUN_CONTEXT_STORAGE_KEY: &str = "run_context";

#[derive(Clone)]
struct RunAdmissionSnapshot {
    registry: ToolRegistrySnapshot,
    provider_profile: ProviderProfile,
    limits: RunLimits,
}

struct ContextAdmissionInput {
    run_id: String,
    session_id: String,
    message_id: String,
    parent_run_id: Option<String>,
    platform: String,
    input: JsonValue,
    messages: Vec<SessionMessage>,
    model: String,
    provider: Option<String>,
    system_prompt: Option<String>,
}

const MAX_PENDING_APPROVAL_PREVIEWS: usize = 256;
const MAX_APPROVAL_PREVIEW_BYTES: usize = 2048;

#[derive(Clone)]
struct PendingApprovalPreview {
    session_id: String,
    tool_call_id: String,
    tool_name: String,
    risk_class: String,
    expires_at_ms: i64,
    text: String,
}

pub(crate) struct PendingApprovalPreviewBinding<'a> {
    session_id: &'a str,
    approval_id: &'a str,
    tool_call_id: &'a str,
    tool_name: &'a str,
    risk_class: &'a str,
    expires_at_ms: i64,
}

impl<'a> PendingApprovalPreviewBinding<'a> {
    pub(crate) fn new(
        session_id: &'a str,
        approval_id: &'a str,
        tool_call_id: &'a str,
        tool_name: &'a str,
        risk_class: &'a str,
        expires_at_ms: i64,
    ) -> Self {
        Self {
            session_id,
            approval_id,
            tool_call_id,
            tool_name,
            risk_class,
            expires_at_ms,
        }
    }
}

#[derive(Clone)]
pub struct AgentService {
    inner: Arc<AgentServiceInner>,
}

#[derive(Clone, Default)]
struct AuthHostFactoryPair {
    legacy_top_level: Option<crate::runtime::agent_host::AuthHostFactory>,
    provider_child: Option<crate::runtime::agent_host::AuthHostFactory>,
}

/// Only unbound bundled code for one effective configuration is retained.
struct WorkspaceRunnerTemplates {
    config: AgentConfig,
    open: Option<Arc<AgentRunner>>,
    bind: Option<Arc<AgentRunner>>,
}

#[cfg(test)]
type CompactionPolicyObserver = Arc<dyn Fn(&str) + Send + Sync>;

struct AgentServiceInner {
    config: Arc<AgentGatewayConfig>,
    compaction_settings: CompactionSettings,
    store: Arc<RwLock<GatewayStore>>,
    persistence: Option<Arc<GatewayPersistence>>,
    agent_source: Option<Arc<String>>,
    agent_entry: Mutex<Option<AgentEntry>>,
    http_config: HttpConfig,
    tool_registry: RwLock<ToolRegistry>,
    provider_profiles: RwLock<HashMap<String, ProviderProfile>>,
    run_limits: RwLock<RunLimits>,
    contexts: Mutex<HashMap<String, RunContext>>,
    approval_previews: Mutex<HashMap<(String, String), PendingApprovalPreview>>,
    context_registries: Mutex<HashMap<String, ToolRegistrySnapshot>>,
    context_cache_capacity: usize,
    capacity: Arc<Semaphore>,
    session_maintenance: Arc<ParkingMutex<HashSet<String>>>,
    runs: Mutex<HashMap<String, Arc<RunHandle>>>,
    pending: Mutex<HashMap<String, PendingTerminal>>,
    halting: AtomicBool,
    janitor_stop: Notify,
    store_generation: AtomicU64,
    metrics: Arc<Metrics>,
    file_search_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    capability_host_shutdown: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    capability_host_init_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    prompt_read_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    date_source: RwLock<Arc<dyn DateSource>>,
    /// Optional one-shot injected provider host for tests. Consumed atomically
    /// by the next `run_worker`; production uses RssAdapterProvider.
    provider_host: Mutex<Option<Arc<dyn AgentProviderHost>>>,
    /// Fault injection for compaction boundary redaction tests.
    compaction_policy_failure: Mutex<Option<String>>,
    compaction_worker_panic: Mutex<Option<String>>,
    #[cfg(test)]
    compaction_maintenance_published: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    compaction_runner_lookup_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    compaction_policy_entered: Mutex<Option<CompactionPolicyObserver>>,
    /// Legacy and provider-child auth factories are one configuration
    /// snapshot so worker admission cannot observe an interleaved pair.
    auth_host_factories: Mutex<AuthHostFactoryPair>,
    /// Workspace admission uses a separate trusted-home factory so opting
    /// into filesystem policy never opts provider RSS into OAuth authority.
    workspace_host_factory: Mutex<Option<crate::runtime::agent_host::AuthHostFactory>>,
    workspace_runners: Mutex<Option<WorkspaceRunnerTemplates>>,
    #[cfg(test)]
    workspace_runner_constructions: [AtomicUsize; 2],
    /// Explicit embedding-supplied legacy root; default RunLimits never
    /// become ambient authority for production HTTP or Telegram requests.
    trusted_legacy_workspace_root: RwLock<Option<PathBuf>>,
    /// Compiled agent source reused across workers so compile does not reset the deadline.
    runner: Mutex<Option<CachedAgentRunner>>,
    import_validation_memo: crate::runtime::module_snapshot::ImportValidationMemo,
    /// Immutable bundled compaction program reused by persisted context refreshes.
    compaction_runner: Mutex<Option<AgentRunner>>,
    #[cfg(test)]
    compaction_runner_constructions: AtomicUsize,
    /// Test seam: invoked after file-agent lookup digest and before compile.
    agent_compile_lookup_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Test seam: invoked after file-agent compile and before postcheck digest.
    agent_compile_postcheck_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// When set, the next capability host holds its serial mutex until released.
    uncooperative_dispatch: Mutex<Option<Arc<AtomicBool>>>,
    /// Serializes durable event/message commits so seq/ordinal reservation
    /// cannot interleave. Never held across GET; the GatewayStore lock is
    /// released before SQLite/worker IO.
    commit_gate: Arc<ParkingMutex<()>>,
    crash_after_provider_commit: AtomicBool,
    crash_after_provider_request: AtomicBool,
    crash_after_tool_commit: AtomicBool,
    provider_commit_crashed: AtomicBool,
}

impl Drop for AgentServiceInner {
    fn drop(&mut self) {
        let handles: Vec<Arc<RunHandle>> = self
            .runs
            .lock()
            .expect("runs lock")
            .drain()
            .map(|(_, handle)| handle)
            .collect();
        for handle in handles {
            handle.release_capability_host();
        }
    }
}

impl AgentService {
    pub(crate) fn new(
        config: Arc<AgentGatewayConfig>,
        store: Arc<RwLock<GatewayStore>>,
        persistence: Option<Arc<GatewayPersistence>>,
        agent_source: Option<Arc<String>>,
        http_config: HttpConfig,
        metrics: Arc<Metrics>,
        compaction_settings: CompactionSettings,
    ) -> Self {
        let capacity = Arc::new(Semaphore::new(config.max_concurrent_runs));
        let context_cache_capacity = config.max_concurrent_runs.saturating_mul(4).max(16);
        normalize_loaded_session_messages(&store);
        let default_registry = bundled_tool_registry().expect("RSS tool registry validates");
        let default_provider = config
            .provider
            .clone()
            .unwrap_or_else(|| "local-agent".to_string());
        let default_profile = ProviderProfile::builtin(default_provider.clone())
            .expect("built-in provider profile validates");
        let mut provider_profiles = HashMap::new();
        provider_profiles.insert(default_provider, default_profile);
        let inner = Arc::new(AgentServiceInner {
            config,
            compaction_settings,
            store,
            persistence,
            agent_source,
            agent_entry: Mutex::new(None),
            http_config,
            tool_registry: RwLock::new(default_registry),
            provider_profiles: RwLock::new(provider_profiles),
            run_limits: RwLock::new(RunLimits::default()),
            contexts: Mutex::new(HashMap::new()),
            approval_previews: Mutex::new(HashMap::new()),
            context_registries: Mutex::new(HashMap::new()),
            context_cache_capacity,
            capacity,
            session_maintenance: Arc::new(ParkingMutex::new(HashSet::new())),
            runs: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            halting: AtomicBool::new(false),
            janitor_stop: Notify::new(),
            store_generation: AtomicU64::new(0),
            metrics,
            file_search_entered: Mutex::new(None),
            capability_host_shutdown: Mutex::new(None),
            capability_host_init_entered: Mutex::new(None),
            prompt_read_entered: Mutex::new(None),
            date_source: RwLock::new(Arc::new(SystemDateSource)),
            provider_host: Mutex::new(None),
            compaction_policy_failure: Mutex::new(None),
            compaction_worker_panic: Mutex::new(None),
            #[cfg(test)]
            compaction_maintenance_published: Mutex::new(None),
            #[cfg(test)]
            compaction_runner_lookup_entered: Mutex::new(None),
            #[cfg(test)]
            compaction_policy_entered: Mutex::new(None),
            auth_host_factories: Mutex::new(AuthHostFactoryPair::default()),
            workspace_host_factory: Mutex::new(None),
            workspace_runners: Mutex::new(None),
            #[cfg(test)]
            workspace_runner_constructions: [AtomicUsize::new(0), AtomicUsize::new(0)],
            trusted_legacy_workspace_root: RwLock::new(None),
            runner: Mutex::new(None),
            import_validation_memo: Default::default(),
            compaction_runner: Mutex::new(None),
            #[cfg(test)]
            compaction_runner_constructions: AtomicUsize::new(0),
            agent_compile_lookup_entered: Mutex::new(None),
            agent_compile_postcheck_entered: Mutex::new(None),
            uncooperative_dispatch: Mutex::new(None),
            commit_gate: Arc::new(ParkingMutex::new(())),
            crash_after_provider_commit: AtomicBool::new(false),
            crash_after_provider_request: AtomicBool::new(false),
            crash_after_tool_commit: AtomicBool::new(false),
            provider_commit_crashed: AtomicBool::new(false),
        });
        spawn_lifecycle_janitor(Arc::clone(&inner));
        Self { inner }
    }

    pub fn config(&self) -> &Arc<AgentGatewayConfig> {
        &self.inner.config
    }

    pub fn agent_source(&self) -> Option<Arc<String>> {
        self.inner.agent_source.clone()
    }

    pub fn http_config(&self) -> &HttpConfig {
        &self.inner.http_config
    }

    /// Test seam: one-shot provider host consumed by the next `run_worker`.
    /// A second run without another inject uses the production adapter.
    pub fn inject_provider_host(&self, host: Arc<dyn AgentProviderHost>) {
        *self.inner.provider_host.lock().expect("provider host lock") = Some(host);
    }

    /// Test seam: inject one private RSS-policy diagnostic at compaction.
    pub fn inject_compaction_policy_failure(&self, detail: impl Into<String>) {
        *self
            .inner
            .compaction_policy_failure
            .lock()
            .expect("compaction policy failure lock") = Some(detail.into());
    }

    /// Test seam: panic once in the explicit compaction blocking worker.
    pub fn inject_compaction_worker_panic(&self, detail: impl Into<String>) {
        *self
            .inner
            .compaction_worker_panic
            .lock()
            .expect("compaction worker panic lock") = Some(detail.into());
    }

    /// Installs the native-owned factory used to construct a fresh AuthHost
    /// for each RSS VM invocation.
    pub fn set_auth_host_factory(
        &self,
        factory: Arc<
            dyn Fn(
                    crate::runtime::RunCancellation,
                ) -> std::result::Result<crate::auth::host::AuthHost, String>
                + Send
                + Sync,
        >,
    ) {
        let mut factories = self
            .inner
            .auth_host_factories
            .lock()
            .expect("auth host factory lock");
        factories.legacy_top_level = Some(Arc::clone(&factory));
        factories.provider_child = Some(factory);
    }

    /// Installs a native factory only for the default provider's child RSS
    /// invocation. Top-level RSS auth and workspace admission are unchanged.
    pub(crate) fn set_provider_auth_host_factory(
        &self,
        factory: crate::runtime::agent_host::AuthHostFactory,
    ) {
        self.inner
            .auth_host_factories
            .lock()
            .expect("auth host factory lock")
            .provider_child = Some(factory);
    }

    /// Installs only the trusted-home factory used by workspace admission.
    /// It does not install an OAuth/provider factory for ordinary agent runs.
    pub fn set_workspace_host_factory(&self, factory: crate::runtime::agent_host::AuthHostFactory) {
        *self
            .inner
            .workspace_host_factory
            .lock()
            .expect("workspace host factory lock") = Some(factory);
    }

    fn resolve_workspace_admission(
        &self,
        selector: Option<&str>,
        existing: Option<&WorkspaceBinding>,
        cancellation: &RunCancellation,
        allow_switch: bool,
    ) -> Result<
        (
            Option<WorkspaceBinding>,
            Option<Arc<crate::runtime::rss_runner::WorkspaceAuthority>>,
        ),
        AdmitError,
    > {
        let factory = self
            .inner
            .workspace_host_factory
            .lock()
            .expect("auth host factory lock")
            .clone();
        if selector.is_none() && existing.is_none() && factory.is_none() {
            return Ok((None, None));
        }
        let context = json!({
            "selector": selector.unwrap_or(""),
            "selector_present": selector.is_some(),
            "session_selector": existing.map_or("", |binding| binding.selector.as_str()),
            "session_canonical_path": existing.map_or("", |binding| binding.canonical_path.as_str()),
        });
        let entry = if allow_switch { "bind" } else { "open" };
        let runner = self
            .cached_workspace_runner(entry, self.workspace_runner_config())
            .map_err(|_| AdmitError::Invalid("workspace admission is unavailable".to_string()))?;
        let bridges = AgentHostBridges {
            auth_host_factory: factory,
            cancellation: Some(cancellation.clone()),
            ..AgentHostBridges::default()
        };
        let outcome = match runner
            .with_host(bridges)
            .with_cancellation(cancellation.clone())
            .run_workspace_admission(
                entry,
                crate::domain::json_to_vm_value(&context),
                cancellation,
            ) {
            Ok(outcome) => outcome,
            Err(_) if selector.is_none() && existing.is_none() => return Ok((None, None)),
            Err(_) => {
                return Err(AdmitError::Invalid(
                    "workspace admission was rejected".to_string(),
                ));
            }
        };
        if !outcome.ok {
            if selector.is_none() && existing.is_none() && outcome.code == "workspace_unavailable" {
                return Ok((None, None));
            }
            return Err(AdmitError::Invalid(outcome.code));
        }
        let authority = outcome.authority.ok_or_else(|| {
            AdmitError::Invalid("workspace authority was not retained".to_string())
        })?;
        let canonical_path = outcome.canonical_path.ok_or_else(|| {
            AdmitError::Invalid("workspace admission omitted its path".to_string())
        })?;
        let generation = outcome.generation.ok_or_else(|| {
            AdmitError::Invalid("workspace admission omitted its generation".to_string())
        })?;
        let effective_selector = outcome.effective_selector.ok_or_else(|| {
            AdmitError::Invalid("workspace admission omitted its effective selector".to_string())
        })?;
        let binding = WorkspaceBinding {
            selector: effective_selector,
            canonical_path,
            selected_name: outcome.selected_name,
            generation,
        };
        Ok((Some(binding), Some(authority)))
    }

    fn workspace_runner_config(&self) -> AgentConfig {
        AgentConfig {
            http: self.inner.http_config.clone(),
            sqlite: self.inner.config.sqlite.clone(),
            fuel: self.inner.config.fuel,
        }
    }

    fn cached_workspace_runner(
        &self,
        entry: &str,
        config: AgentConfig,
    ) -> Result<AgentRunner, String> {
        let index = match entry {
            "open" => 0,
            "bind" => 1,
            _ => return Err("workspace entry is unavailable".to_string()),
        };
        let template = {
            let mut cache = self
                .inner
                .workspace_runners
                .lock()
                .expect("workspace runner lock");
            if cache
                .as_ref()
                .is_none_or(|current| current.config != config)
            {
                *cache = Some(WorkspaceRunnerTemplates {
                    config: config.clone(),
                    open: None,
                    bind: None,
                });
            }
            let current = cache.as_mut().expect("workspace config installed");
            let slot = if index == 0 {
                &mut current.open
            } else {
                &mut current.bind
            };
            if slot.is_none() {
                let runner =
                    AgentRunner::from_bundled_named("rss/agent/workspace.rss", entry, config)
                        .map_err(|error| format!("compile RSS workspace policy: {error}"))?;
                #[cfg(test)]
                self.inner.workspace_runner_constructions[index].fetch_add(1, Ordering::SeqCst);
                *slot = Some(Arc::new(runner));
            }
            Arc::clone(slot.as_ref().expect("workspace template installed"))
        };
        // Clone code outside initialization synchronization. Each invocation
        // subsequently replaces default bridges and creates its own native VM.
        Ok(template.as_ref().clone())
    }

    /// Installs or replaces a provider profile used by later admissions.
    pub fn upsert_provider_profile(&self, profile: ProviderProfile) {
        self.inner
            .provider_profiles
            .write()
            .insert(profile.name.clone(), profile);
    }

    /// Holds the next capability host's serial mutex until
    /// [`Self::release_uncooperative_dispatch`].
    pub fn inject_uncooperative_dispatch(&self) {
        *self
            .inner
            .uncooperative_dispatch
            .lock()
            .expect("uncooperative dispatch lock") = Some(Arc::new(AtomicBool::new(false)));
    }

    /// Releases an injected uncooperative dispatcher lock.
    pub fn release_uncooperative_dispatch(&self) {
        if let Some(flag) = self
            .inner
            .uncooperative_dispatch
            .lock()
            .expect("uncooperative dispatch lock")
            .take()
        {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// Effective AgentConfig compiled into the cached runner, if any.
    pub fn cached_runner_config(&self) -> Option<AgentConfig> {
        self.inner
            .runner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|cached| cached.config.clone())
    }

    /// The native snapshot digest of the currently installed runner, if any.
    /// Read from the admitted runner itself (never recomputed), for bounded
    /// public health facts.
    pub(crate) fn installed_runner_snapshot_digest(&self) -> Option<String> {
        self.inner
            .runner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|cached| cached.runner.snapshot_digest().to_string())
    }

    /// Compiles or reuses the cached runner using current source + effective config.
    pub fn materialize_cached_runner(&self) -> Result<AgentConfig, String> {
        let runner = self.cached_agent_runner(
            self.inner
                .agent_source
                .as_ref()
                .map(|source| source.as_str()),
        )?;
        if self.inner.persistence.is_some() {
            self.cached_compaction_runner()
                .map_err(|error| error.detail().to_string())?;
        }
        let workspace_enabled = self
            .inner
            .workspace_host_factory
            .lock()
            .expect("workspace host factory lock")
            .is_some();
        if workspace_enabled {
            let config = self.workspace_runner_config();
            self.cached_workspace_runner("open", config.clone())?;
            self.cached_workspace_runner("bind", config)?;
        }
        Ok(runner.config().clone())
    }

    /// Test failpoint: panic after a successful provider-step commit, before
    /// the envelope is returned to RSS. The worker leaves the run started so
    /// a restart can replay the durable step.
    pub fn inject_crash_after_provider_commit(&self) {
        self.inner
            .crash_after_provider_commit
            .store(true, Ordering::SeqCst);
        self.inner
            .provider_commit_crashed
            .store(false, Ordering::SeqCst);
    }

    /// Test failpoint: panic after a durable `model.requested` boundary, before
    /// the inner provider call. Restart may retry the same logical turn.
    pub fn inject_crash_after_provider_request(&self) {
        self.inner
            .crash_after_provider_request
            .store(true, Ordering::SeqCst);
        self.inner
            .provider_commit_crashed
            .store(false, Ordering::SeqCst);
    }

    /// Test failpoint: panic after a successful durable tool completion, before
    /// the next provider response. The worker leaves the run started so a
    /// restart can replay the canonical tool result without a second effect.
    pub fn inject_crash_after_tool_commit(&self) {
        self.inner
            .crash_after_tool_commit
            .store(true, Ordering::SeqCst);
        self.inner
            .provider_commit_crashed
            .store(false, Ordering::SeqCst);
    }

    pub(crate) fn take_crash_after_provider_commit(&self) -> bool {
        self.inner
            .crash_after_provider_commit
            .swap(false, Ordering::SeqCst)
    }

    pub(crate) fn take_crash_after_provider_request(&self) -> bool {
        self.inner
            .crash_after_provider_request
            .swap(false, Ordering::SeqCst)
    }

    pub(crate) fn mark_provider_commit_crashed(&self) {
        self.inner
            .provider_commit_crashed
            .store(true, Ordering::SeqCst);
    }

    /// Returns the registry snapshot currently used for future admissions.
    pub fn tool_registry_snapshot(&self) -> ToolRegistrySnapshot {
        self.inner.tool_registry.read().snapshot()
    }

    /// Replaces the registry used by future admissions. Existing run contexts
    /// retain their own cloned snapshot and are unaffected. Empty registries
    /// are rejected and leave the active registry unchanged.
    pub fn set_tool_registry(&self, registry: ToolRegistry) -> Result<(), String> {
        if registry.snapshot().is_empty() {
            return Err("tool registry must not be empty".to_string());
        }
        *self.inner.tool_registry.write() = registry;
        Ok(())
    }

    /// Installs a validated provider profile for future admissions.
    pub fn set_provider_profile(
        &self,
        profile: ProviderProfile,
    ) -> Result<(), ProviderProfileError> {
        let profile = ProviderProfile::new(profile.name.clone(), profile.options().clone())?;
        self.inner
            .provider_profiles
            .write()
            .insert(profile.name.clone(), profile);
        Ok(())
    }

    /// Replaces the validated limits used by future admissions.
    pub fn set_run_limits(&self, limits: RunLimits) -> Result<(), RunLimitsError> {
        let limits = limits.normalized()?;
        *self.inner.trusted_legacy_workspace_root.write() = Some(limits.workspace_root.clone());
        *self.inner.run_limits.write() = limits;
        Ok(())
    }

    /// Replaces the date source used by future admissions. Existing runs keep
    /// the date captured into their frozen coding prompt.
    pub fn set_date_source(&self, source: Arc<dyn DateSource>) {
        *self.inner.date_source.write() = source;
    }

    /// Returns the immutable context captured at admission time.
    pub fn run_context(&self, run_id: &str) -> Option<RunContext> {
        if let Some(context) = self
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .get(run_id)
            .cloned()
        {
            return Some(context);
        }
        self.resume_context(run_id).ok()
    }

    pub fn run_registry_snapshot(&self, run_id: &str) -> Option<ToolRegistrySnapshot> {
        self.inner
            .context_registries
            .lock()
            .expect("context registries lock")
            .get(run_id)
            .cloned()
    }

    /// Returns a JSON view of the in-memory run events for integration tests
    /// and gateway diagnostics without exposing the storage-owned event type.
    pub fn run_events(&self, run_id: &str) -> Vec<JsonValue> {
        self.inner
            .store
            .try_read()
            .and_then(|store| {
                store.runs.get(run_id).map(|run| {
                    run.events
                        .iter()
                        .map(|event| {
                            json!({
                                "event_id": event.event_id,
                                "seq": event.seq,
                                "event": event.event,
                                "run_id": event.run_id,
                                "timestamp": event.timestamp,
                                "data": event.data,
                            })
                        })
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    /// Blocking GET of session messages. Used by tests to observe live
    /// visibility without `try_read` skipping a held write lock.
    pub fn session_messages(&self, session_id: &str) -> Vec<JsonValue> {
        self.inner
            .store
            .read()
            .sessions
            .get(session_id)
            .map(|session| {
                session
                    .messages
                    .iter()
                    .map(|message| serde_json::to_value(message).expect("session message json"))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn refresh_provider_context(
        &self,
        run_id: &str,
        context: &JsonValue,
        cancellation: &RunCancellation,
    ) -> JsonValue {
        if self.inner.persistence.is_none() {
            return json!({ "ok": true, "storage_available": false });
        }
        let session_context = self
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .get(run_id)
            .cloned();
        let Some(session_context) = session_context else {
            return compaction_error(
                "run_context_missing",
                "durable session context is unavailable",
            );
        };
        if context.get("session_id").and_then(JsonValue::as_str)
            != Some(session_context.session_id.as_str())
        {
            return compaction_error(
                "run_context_mismatch",
                "RSS session identity changed during context refresh",
            );
        }
        if cancellation.requested().is_some() || cancellation.deadline_passed() {
            return compaction_error("cancelled", "run was cancelled before context refresh");
        }
        if self
            .persist_unstarted_tool_failures(run_id, context)
            .is_err()
        {
            return compaction_error(
                "tool_failure_persist_failed",
                "tool validation failure could not be recorded",
            );
        }
        match self.refresh_session_compaction(
            &session_context.session_id,
            run_id,
            &session_context.model,
            false,
            cancellation,
        ) {
            Ok(compacted) => {
                let mut messages = context
                    .get("messages")
                    .and_then(JsonValue::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter(|message| {
                                matches!(
                                    message.get("role").and_then(JsonValue::as_str),
                                    Some("system" | "developer")
                                )
                            })
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if let Some(items) = compacted.as_array() {
                    messages.extend(items.iter().cloned());
                }
                json!({ "ok": true, "storage_available": true, "messages": messages })
            }
            Err(error) => {
                let mut result = compaction_error("context_refresh_failed", error.detail());
                result["storage_available"] = json!(true);
                result
            }
        }
    }

    /// Preserve pre-execution validation failures before durable history replaces
    /// the RSS-local transcript. This records no successful effect and issues no
    /// execution token. The committer checks parent/run and absence of started
    /// effects under the same gate as the write.
    fn persist_unstarted_tool_failures(
        &self,
        run_id: &str,
        context: &JsonValue,
    ) -> Result<(), EventCommitError> {
        let Some(messages) = context.get("messages").and_then(JsonValue::as_array) else {
            return Ok(());
        };
        for message in messages {
            if message.get("role").and_then(JsonValue::as_str) != Some("user") {
                continue;
            }
            for block in decode_message_blocks(&message["content"]) {
                if block.block_type != "tool_result" || block.is_error != Some(true) {
                    continue;
                }
                let call_id = block.tool_call_id.as_deref().unwrap_or_default();
                let error = block.error.as_ref().unwrap_or(&JsonValue::Null);
                let code = error
                    .get("code")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default();
                if call_id.is_empty() || code.is_empty() {
                    return Err(EventCommitError::Corrupt(
                        "invalid local tool failure".into(),
                    ));
                }
                // Committed results are already authoritative; do not re-account
                // them or reinterpret an interrupted effect as validation.
                let name = {
                    let store = self.inner.store.read();
                    let run = store.runs.get(run_id).ok_or(EventCommitError::Terminal)?;
                    if store.sessions.get(&run.session_id).is_some_and(|session| {
                        session
                            .messages
                            .iter()
                            .any(|message| message.tool_call_id.as_deref() == Some(call_id))
                    }) {
                        continue;
                    }
                    let (_, name) = lookup_tool_call_parent(&store, &run.session_id, call_id)
                        .ok_or(EventCommitError::MissingParent)?;
                    if block.name.as_ref().is_some_and(|claimed| claimed != &name) {
                        return Err(EventCommitError::Corrupt(
                            "tool failure name mismatch".into(),
                        ));
                    }
                    name
                };
                if self
                    .replay_durable_tool_result(run_id, call_id, &name)?
                    .is_some()
                {
                    continue;
                }
                let result = ToolResult::failure_with(
                    code,
                    error
                        .get("message")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("tool arguments rejected"),
                    block.content.as_deref().unwrap_or_default(),
                    json!({}),
                    block.truncated.unwrap_or(false),
                );
                self.commit_tool_step(
                    run_id,
                    "tool.failed",
                    json!({
                        "tool_call_id": call_id,
                        "name": block.name,
                        "ok": false,
                        "error_code": code,
                        "validation_only": true,
                    }),
                    Some(&result),
                )?;
            }
        }
        Ok(())
    }

    /// Force the same RSS compaction policy used before provider turns without
    /// issuing a provider request. A hidden service run supplies the durable
    /// lifecycle identity required by the compaction transaction.
    pub fn compact_session_explicit(&self, session_id: &str) -> Result<JsonValue, CompactionError> {
        if let Some(detail) = self
            .inner
            .compaction_worker_panic
            .lock()
            .expect("compaction worker panic lock")
            .take()
        {
            panic!("{detail}");
        }
        let persistence = self.inner.persistence.as_ref().ok_or_else(|| {
            CompactionError::from_rss("internal", "durable storage is unavailable for compaction")
        })?;
        let _admission_serial = self.inner.commit_gate.lock();
        let (model, provider) = {
            let store = self.inner.store.read();
            let session = store
                .sessions
                .get(session_id)
                .ok_or_else(|| CompactionError::from_rss("not_found", "session not found"))?;
            if store.runs.values().any(|run| {
                run.session_id == session_id
                    && matches!(
                        run.status.as_str(),
                        "queued" | "running" | "started" | "stopping"
                    )
            }) {
                return Err(CompactionError::from_rss(
                    "busy",
                    "session has an active run",
                ));
            }
            (
                session.view.model.clone(),
                session.view.provider.clone().unwrap_or_default(),
            )
        };
        let _capacity_permit =
            self.inner
                .capacity
                .clone()
                .try_acquire_owned()
                .map_err(|error| {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::RunLimitReached);
                    CompactionError::from_rss("capacity", error.to_string())
                })?;
        let _maintenance_lease = SessionMaintenanceLease::acquire(
            Arc::clone(&self.inner.session_maintenance),
            session_id,
        )
        .ok_or_else(|| {
            CompactionError::from_rss("busy", "session maintenance is already active")
        })?;
        let (generation, _, _) = load_durable_compaction_snapshot(persistence, session_id)
            .map_err(|error| CompactionError::from_rss("internal", error))?;
        let run_id = Uuid::new_v4().to_string();
        let now_ms = timestamp();
        persistence
            .run_create(&json!({
                "id": run_id,
                "session_id": session_id,
                "parent_run_id": "",
                "input_json": "{\"source\":\"session.compact\"}",
                "provider": provider,
                "model": model,
                "script_hash": "",
                "idempotency_scope": "",
                "idempotency_key": "",
                "now_ms": now_ms,
            }))
            .map_err(|error| CompactionError::from_rss("internal", error.to_string()))?;
        self.inner.store.write().runs.insert(
            run_id.clone(),
            RunRecord {
                run_id: run_id.clone(),
                session_id: session_id.to_string(),
                parent_run_id: None,
                status: "started".to_string(),
                events: Vec::new(),
                sender: None,
                cancel_requested: Arc::new(AtomicBool::new(false)),
            },
        );
        drop(_admission_serial);
        #[cfg(test)]
        if let Some(observer) = self
            .inner
            .compaction_maintenance_published
            .lock()
            .expect("compaction maintenance observer lock")
            .take()
        {
            observer();
        }
        if let Err(error) = self.transition_compaction_run(&run_id, "queued", "running") {
            self.inner.store.write().runs.remove(&run_id);
            return Err(CompactionError::from_rss("internal", error));
        }
        if let Err(error) = self.refresh_session_compaction(
            session_id,
            &run_id,
            &model,
            true,
            &RunCancellation::new(),
        ) {
            let failed = self
                .transition_compaction_run(&run_id, "running", "failed")
                .or_else(|_| self.transition_compaction_run(&run_id, "compacting", "failed"));
            if failed.is_ok()
                && let Some(run) = self.inner.store.write().runs.get_mut(&run_id)
            {
                run.status = "failed".to_string();
            }
            return Err(CompactionError::from_rss(
                error.mapper_code(),
                error.detail().to_string(),
            ));
        }
        if let Err(error) = self.complete_compaction_lifecycle_run(&run_id) {
            if self
                .transition_compaction_run(&run_id, "running", "failed")
                .is_ok()
                && let Some(run) = self.inner.store.write().runs.get_mut(&run_id)
            {
                run.status = "failed".to_string();
            }
            return Err(CompactionError::from_rss("internal", error));
        }
        let (actual_generation, _, _) =
            load_durable_compaction_snapshot(persistence, session_id)
                .map_err(|error| CompactionError::from_rss("internal", error))?;
        Ok(json!({
            "ok": true,
            "session_id": session_id,
            "run_id": run_id,
            "status": if actual_generation > generation { "committed" } else { "skipped" },
            "generation": actual_generation,
        }))
    }

    fn cached_compaction_runner(&self) -> Result<AgentRunner, CompactionFailure> {
        let mut cache = self
            .inner
            .compaction_runner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(runner) = cache.as_ref() {
            return Ok(runner.clone());
        }
        let runner = AgentRunner::from_bundled("rss/agent/compact.rss", AgentConfig::default())
            .map_err(|error| {
                CompactionFailure::host(format!("compile RSS compaction policy: {error}"))
            })?;
        #[cfg(test)]
        self.inner
            .compaction_runner_constructions
            .fetch_add(1, Ordering::Relaxed);
        *cache = Some(runner.clone());
        Ok(runner)
    }

    fn refresh_session_compaction(
        &self,
        session_id: &str,
        run_id: &str,
        model: &str,
        force: bool,
        cancellation: &RunCancellation,
    ) -> Result<JsonValue, CompactionFailure> {
        let persistence = self.inner.persistence.as_ref().ok_or_else(|| {
            CompactionFailure::host("durable storage is unavailable for compaction")
        })?;
        let (generation, history, previous_summary) =
            load_durable_compaction_snapshot(persistence, session_id)
                .map_err(CompactionFailure::host)?;
        if cancellation.requested().is_some() || cancellation.deadline_passed() {
            return Err(CompactionFailure::rss(
                "cancelled".to_string(),
                "run was cancelled before RSS compaction policy".to_string(),
            ));
        }
        if let Some(detail) = self
            .inner
            .compaction_policy_failure
            .lock()
            .expect("compaction policy failure lock")
            .take()
        {
            return Err(CompactionFailure::host(format!(
                "RSS compaction policy failed: {detail}"
            )));
        }
        let settings = self.inner.compaction_settings.clone();
        #[cfg(test)]
        if let Some(hook) = self
            .inner
            .compaction_runner_lookup_entered
            .lock()
            .expect("compaction runner lookup observer lock")
            .clone()
        {
            hook();
        }
        let decision_runner = self.cached_compaction_runner()?;
        let policy_input = json!({
            "session_id": session_id,
            "run_id": run_id,
            "generation": generation,
            "messages": history,
            "config": {
                "enabled": settings.enabled,
                "max_context_messages": settings.max_context_messages,
                "retained_tail": settings.retained_tail,
                "force": force,
                "previous_summary": previous_summary,
                "now_ms": timestamp(),
                "model": model,
                "token_estimate": 0,
            }
        });
        #[cfg(test)]
        {
            // Observe only session identity at the real invocation boundary.
            // Release the observer mutex before callbacks, including barriers.
            let observer = self
                .inner
                .compaction_policy_entered
                .lock()
                .expect("compaction policy observer lock")
                .clone();
            if let Some(observer) = observer {
                observer(session_id);
            }
        }
        let decision_value = decision_runner
            .run_with_context(json_to_vm_value(&policy_input))
            .map_err(|error| {
                CompactionFailure::host(format!("RSS compaction policy failed: {error}"))
            })?;
        let decision = vm_value_to_json(&decision_value);
        let kind = decision
            .get("kind")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        match kind {
            "compact.skip" => Ok(decision
                .get("context_messages")
                .cloned()
                .unwrap_or_else(|| json!([]))),
            "compact.plan" => {
                if cancellation.requested().is_some() || cancellation.deadline_passed() {
                    return Err(CompactionFailure::rss(
                        "cancelled".to_string(),
                        "run was cancelled before compaction transaction".to_string(),
                    ));
                }
                self.transition_compaction_run(run_id, "running", "compacting")
                    .map_err(CompactionFailure::host)?;
                let execution =
                    execute_rss_compaction(persistence, &decision_runner, &decision, cancellation);
                let restore = self.transition_compaction_run(run_id, "compacting", "running");
                execution.map_err(CompactionFailure::host)?;
                restore.map_err(CompactionFailure::host)?;
                let expected_generation = decision
                    .get("generation")
                    .and_then(JsonValue::as_i64)
                    .ok_or_else(|| {
                        CompactionFailure::host("RSS compaction plan omitted its target generation")
                    })?;
                let (actual_generation, _, _) =
                    load_durable_compaction_snapshot(persistence, session_id)
                        .map_err(CompactionFailure::host)?;
                if actual_generation != expected_generation {
                    return Err(CompactionFailure::host(format!(
                        "committed compaction generation mismatch: expected {expected_generation}, found {actual_generation}"
                    )));
                }
                Ok(decision
                    .get("context_messages")
                    .cloned()
                    .unwrap_or_else(|| json!([])))
            }
            "compact.error" => {
                let code = decision
                    .get("code")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| {
                        CompactionFailure::host("RSS compaction error omitted its code")
                    })?;
                let detail = decision
                    .get("message")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| {
                        CompactionFailure::host("RSS compaction error omitted its message")
                    })?;
                Err(CompactionFailure::rss(code.to_string(), detail.to_string()))
            }
            _ => Err(CompactionFailure::host(
                "RSS compaction policy returned an invalid decision",
            )),
        }
    }

    fn transition_compaction_run(
        &self,
        run_id: &str,
        from_status: &str,
        to_status: &str,
    ) -> Result<(), String> {
        let persistence =
            self.inner.persistence.as_ref().ok_or_else(|| {
                "durable storage is unavailable for compaction lifecycle".to_string()
            })?;
        let _serial = self.inner.commit_gate.lock();
        let now_ms = timestamp();
        let (event, max_events) = {
            let store = self.inner.store.read();
            let run = store
                .runs
                .get(run_id)
                .ok_or_else(|| "compaction run is unavailable".to_string())?;
            if run.status != "started" {
                return Err(format!(
                    "compaction run is no longer active: in-memory status is {}",
                    run.status
                ));
            }
            let seq = run
                .events
                .last()
                .map(|event| event.seq.saturating_add(1))
                .unwrap_or(1);
            (
                GatewayEvent {
                    event_id: format!(
                        "run-transition:{run_id}:{now_ms}:{from_status}:{to_status}:{seq}"
                    ),
                    seq,
                    event: "run.status_changed".to_string(),
                    run_id: run_id.to_string(),
                    timestamp: now_ms,
                    data: json!({}),
                },
                self.inner.config.max_events_per_run,
            )
        };
        persistence
            .run_transition(&json!({
                "run_id": run_id,
                "from_status": from_status,
                "to_status": to_status,
                "error_code": "",
                "error_message": "",
                "recovery_reason": "",
                "now_ms": now_ms,
            }))
            .map_err(|error| {
                format!("transition compaction run {from_status}->{to_status}: {error}")
            })?;
        let mut store = self.inner.store.write();
        let run = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| "compaction run disappeared after transition".to_string())?;
        if run.status != "started" {
            return Err("in-memory compaction run ended during transition".to_string());
        }
        apply_event_locked(run, &event, max_events);
        Ok(())
    }

    fn complete_compaction_lifecycle_run(&self, run_id: &str) -> Result<(), String> {
        let persistence =
            self.inner.persistence.as_deref().ok_or_else(|| {
                "durable storage is unavailable for compaction lifecycle".to_string()
            })?;
        let _serial = self.inner.commit_gate.lock();
        let now_ms = timestamp();
        let (session_id, mut event, max_events) = {
            let store = self.inner.store.read();
            let run = store
                .runs
                .get(run_id)
                .ok_or_else(|| "compaction run is unavailable at completion".to_string())?;
            let seq = run
                .events
                .last()
                .map(|event| event.seq.saturating_add(1))
                .unwrap_or(1);
            (
                run.session_id.clone(),
                GatewayEvent {
                    event_id: format!("{run_id}:compaction:completed"),
                    seq,
                    event: "run.completed".to_string(),
                    run_id: run_id.to_string(),
                    timestamp: now_ms,
                    data: json!({
                        "status": "completed",
                        "output": {"text": "session compaction completed"},
                        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
                    }),
                },
                self.inner.config.max_events_per_run,
            )
        };
        let committed = terminal_commit(
            Some(persistence),
            run_id,
            &session_id,
            "completed",
            std::slice::from_ref(&event),
            None,
        )
        .map_err(|error| format!("commit compaction lifecycle terminal: {error}"))?;
        event.seq = committed.first().map(|(_, seq)| *seq).ok_or_else(|| {
            "compaction lifecycle terminal returned no event sequence".to_string()
        })?;
        let mut store = self.inner.store.write();
        let run = store
            .runs
            .get_mut(run_id)
            .ok_or_else(|| "compaction run disappeared at completion".to_string())?;
        apply_event_locked(run, &event, max_events);
        run.status = "completed".to_string();
        Ok(())
    }

    /// Persist one run event without attaching a message (tests / recovery).
    pub fn persist_run_event(
        &self,
        run_id: &str,
        event_id: &str,
        event_type: &str,
        payload: JsonValue,
    ) -> Result<(), EventCommitError> {
        self.persist_provider_event(run_id, event_id, event_type, payload)
    }

    /// Persist one tool step (event + optional tool_result message).
    pub fn commit_tool_step(
        &self,
        run_id: &str,
        event_type: &str,
        data: JsonValue,
        result: Option<&ToolResult>,
    ) -> Result<(), EventCommitError> {
        ServiceEventCommitter {
            store: Arc::clone(&self.inner.store),
            persistence: self.inner.persistence.clone(),
            run_id: run_id.to_string(),
            handle: self
                .handle(run_id)
                .map(|handle| Arc::downgrade(&handle))
                .unwrap_or_default(),
            max_event_bytes: self.inner.config.max_event_bytes,
            max_events_per_run: self.inner.config.max_events_per_run,
            commit_gate: Arc::clone(&self.inner.commit_gate),
            service: Arc::downgrade(&self.inner),
        }
        .commit_step(event_type, data, result)
    }

    /// Run-scoped capability engine used by `agent_runtime::tool_prepare`
    /// and `agent_runtime::tool_commit`. Initializes capability host if needed.
    pub fn capability_lifecycle(
        &self,
        run_id: &str,
    ) -> Result<(Arc<CapabilityLifecycle>, CapabilityOwner), RunContextError> {
        let handle = self
            .handle(run_id)
            .ok_or_else(|| RunContextError::Missing {
                run_id: run_id.to_string(),
            })?;
        match self.capability_host_state(run_id, &handle)? {
            Some(state) => Ok((Arc::clone(&state.lifecycle), state.capability_owner.clone())),
            None => Err(RunContextError::InvalidMetadata {
                run_id: run_id.to_string(),
                reason: "capability host is closed".to_string(),
            }),
        }
    }

    /// Capability host bridges for a live run. Production workers attach these
    /// to `rss/agent/main.rss`; tests may attach them to an AgentRunner harness.
    pub fn capability_host_bridges(
        &self,
        run_id: &str,
    ) -> Result<Option<AgentHostBridges>, RunContextError> {
        let handle = self
            .handle(run_id)
            .ok_or_else(|| RunContextError::Missing {
                run_id: run_id.to_string(),
            })?;
        if handle.is_terminal() || handle.capability_host_closed() {
            return Ok(None);
        }
        match self.capability_host_state(run_id, &handle)? {
            Some(state) => Ok(Some(state.host_bridges(
                handle.cancel.clone(),
                Some(Arc::clone(&self.inner.metrics)),
            ))),
            None => Ok(None),
        }
    }

    /// Replay a completed/failed tool result from durable messages/events.
    /// Completed effects are never dispatched again. Interrupted effects
    /// surface as typed `interrupted_effect` failures without re-execution.
    /// Corrupt canonical state fails closed. Name must match the durable
    /// parent/result when present.
    fn replay_durable_tool_result(
        &self,
        run_id: &str,
        tool_call_id: &str,
        name: &str,
    ) -> Result<Option<ToolResult>, EventCommitError> {
        let store = self.inner.store.read();
        let Some(run) = store.runs.get(run_id) else {
            return Err(EventCommitError::Terminal);
        };
        let has_output = run.events.iter().any(|event| {
            matches!(
                event.event.as_str(),
                "tool.output" | "tool.completed" | "tool.failed"
            ) && event.data.get("tool_call_id").and_then(JsonValue::as_str) == Some(tool_call_id)
        });
        if !has_output {
            return Ok(None);
        }
        if let Some((_, stored_name)) =
            lookup_tool_call_parent(&store, &run.session_id, tool_call_id)
            && stored_name != name
        {
            return Err(EventCommitError::Corrupt(
                "tool call name does not match durable parent".to_string(),
            ));
        }
        if let Some(session) = store.sessions.get(&run.session_id) {
            for message in session.messages.iter().rev() {
                if message.tool_call_id.as_deref() != Some(tool_call_id) {
                    continue;
                }
                if let Some(stored_name) = message.name.as_deref()
                    && stored_name != name
                {
                    return Err(EventCommitError::Corrupt(
                        "tool result name does not match the requested tool".to_string(),
                    ));
                }
                for block in decode_message_blocks(&message.content) {
                    if block.block_type != "tool_result"
                        || block.tool_call_id.as_deref() != Some(tool_call_id)
                    {
                        continue;
                    }
                    if block.is_error == Some(true) {
                        let (code, message_text) = block
                            .error
                            .as_ref()
                            .map(|error| {
                                (
                                    error
                                        .get("code")
                                        .and_then(JsonValue::as_str)
                                        .unwrap_or("tool_failed")
                                        .to_string(),
                                    error
                                        .get("message")
                                        .and_then(JsonValue::as_str)
                                        .unwrap_or("tool failed")
                                        .to_string(),
                                )
                            })
                            .unwrap_or_else(|| {
                                ("tool_failed".to_string(), "tool failed".to_string())
                            });
                        return Ok(Some(ToolResult::failure(code, message_text)));
                    }
                    let mut result = ToolResult::success(
                        block.content.clone().unwrap_or_default(),
                        block.result.clone().unwrap_or(JsonValue::Null),
                    );
                    result.truncated = block.truncated.unwrap_or(false);
                    if let Some(JsonValue::Object(artifact)) = block.artifact {
                        if let Some(id) = artifact.get("id").and_then(JsonValue::as_str) {
                            result.artifacts = vec![id.to_string()];
                        }
                    } else if let Some(JsonValue::String(id)) = block.artifact {
                        result.artifacts = vec![id];
                    } else if let Some(JsonValue::Array(artifacts)) = block.artifact {
                        result.artifacts = artifacts
                            .iter()
                            .filter_map(JsonValue::as_str)
                            .map(str::to_string)
                            .collect();
                    }
                    return Ok(Some(result));
                }
            }
        }
        let interrupted = run.events.iter().any(|event| {
            event.event == "tool.failed"
                && event.data.get("error_code").and_then(JsonValue::as_str)
                    == Some("interrupted_effect")
                && event.data.get("tool_call_id").and_then(JsonValue::as_str) == Some(tool_call_id)
        });
        if interrupted {
            return Ok(Some(ToolResult::failure(
                "interrupted_effect",
                "effect interrupted by restart",
            )));
        }
        Err(EventCommitError::Corrupt(
            "durable tool output is missing a canonical result payload".to_string(),
        ))
    }

    /// Persist one provider step (assistant message + model.completed) before
    /// live visibility. Completed provider responses are replayed when a
    /// durable response already exists. The store lock is not held across
    /// SQLite/worker IO; GET sees the old snapshot until durable success.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_provider_step(
        &self,
        run_id: &str,
        turn: u64,
        blocks: &[LlmContentBlock],
        usage: Option<&crate::domain::Usage>,
        finish_reason: Option<&str>,
        provider: Option<&str>,
        model: Option<&str>,
        parent_message_id: Option<&str>,
    ) -> Result<ProviderCommitOutcome, EventCommitError> {
        self.commit_provider_step_with_meta(
            run_id,
            turn,
            blocks,
            usage,
            finish_reason,
            provider,
            model,
            parent_message_id,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_provider_step_with_meta(
        &self,
        run_id: &str,
        turn: u64,
        blocks: &[LlmContentBlock],
        usage: Option<&crate::domain::Usage>,
        finish_reason: Option<&str>,
        provider: Option<&str>,
        model: Option<&str>,
        _parent_message_id: Option<&str>,
        truncated: Option<bool>,
        reasoning: Option<&JsonValue>,
    ) -> Result<ProviderCommitOutcome, EventCommitError> {
        crate::durable_provider::validate_provider_blocks(blocks)?;
        let _serial = self.inner.commit_gate.lock();
        let event_id = durable_provider_event_id(run_id, turn, "model.completed");
        let message_id = durable_message_id(run_id, "turn", &turn.to_string());
        let content = encode_message_content(blocks);
        let encoded_blocks = decode_message_blocks(&content);
        crate::durable_provider::validate_provider_blocks(&encoded_blocks)?;
        let mut metadata = serde_json::Map::new();
        metadata.insert("turn".to_string(), json!(turn));
        if let Some(usage) = usage {
            metadata.insert(
                "usage".to_string(),
                json!({
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "total_tokens": usage.total_tokens,
                }),
            );
        }
        if let Some(provider) = provider.filter(|value| !value.is_empty()) {
            metadata.insert("provider".to_string(), json!(provider));
        }
        if let Some(model) = model.filter(|value| !value.is_empty()) {
            metadata.insert("model".to_string(), json!(model));
        }
        if let Some(truncated) = truncated {
            metadata.insert("truncated".to_string(), json!(truncated));
        }
        if let Some(reasoning) = reasoning {
            metadata.insert("reasoning".to_string(), reasoning.clone());
        }
        let metadata = JsonValue::Object(metadata);
        let reserved = {
            let store = self.inner.store.read();
            let Some(run) = store.runs.get(run_id) else {
                return Err(EventCommitError::Terminal);
            };
            if run.events.iter().any(|event| event.event_id == event_id) {
                return existing_provider_commit(&store, run, &message_id);
            }
            if run.status == "cancelled" {
                return Err(EventCommitError::Cancelled);
            }
            if run_refuses_pending_provider(run) {
                return Err(EventCommitError::Terminal);
            }
            let session_id = run.session_id.clone();
            let parent_message_id = store
                .sessions
                .get(&session_id)
                .and_then(|session| session.messages.last().map(|message| message.id.clone()));
            let mut event = event_candidate(
                run,
                "model.completed",
                json!({
                    "turn": turn,
                    "finish_reason": finish_reason.unwrap_or(""),
                    "provider": provider.unwrap_or(""),
                    "model": model.unwrap_or(""),
                }),
                self.inner.config.max_event_bytes,
            );
            event.event_id = event_id.clone();
            let ordinal = store.sessions.get(&session_id).map(next_message_ordinal);
            let message = SessionMessage {
                id: message_id.clone(),
                session_id: session_id.clone(),
                role: "assistant".to_string(),
                content: content.clone(),
                created_at: event.timestamp,
                run_id: Some(run_id.to_string()),
                finish_reason: finish_reason.map(str::to_string),
                name: None,
                tool_call_id: None,
                parent_message_id: parent_message_id.clone(),
                token_estimate: usage.map(|usage| usage.total_tokens as i64),
                metadata: metadata.clone(),
                ordinal,
            };
            let payload = json!({
                "run_id": run_id,
                "session_id": session_id,
                "event_id": event_id,
                "event_type": "model.completed",
                "payload_json": serde_json::to_string(&event.data).unwrap_or_else(|_| "{}".to_string()),
                "now_ms": event.timestamp,
                "max_events": self.inner.config.max_events_per_run,
                "message_id": message_id,
                "role": "assistant",
                "content_json": serde_json::to_string(&content).unwrap_or_else(|_| "[]".to_string()),
                "name": "",
                "tool_call_id": "",
                "parent_message_id": parent_message_id.unwrap_or_default(),
                "token_estimate": usage.map(|usage| usage.total_tokens as i64).unwrap_or(0),
                "metadata_json": serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string()),
                "finish_reason": finish_reason.unwrap_or(""),
                "seq": event.seq,
                "ordinal": ordinal.unwrap_or(0),
            });
            ReservedCommit {
                event,
                message: Some(message),
                persist_payload: payload,
                kind: PersistKind::Step,
                max_events_per_run: self.inner.config.max_events_per_run,
            }
        };
        let envelope = crate::durable_provider::reconstruct_provider_envelope(
            &content,
            &metadata,
            finish_reason,
        )?;
        persist_and_apply(
            &self.inner.store,
            self.inner.persistence.as_deref(),
            reserved,
        )?;
        Ok(ProviderCommitOutcome::Inserted(ProviderCommit {
            message_id,
            envelope,
        }))
    }

    /// Persist a sanitized provider request boundary (`model.requested`).
    ///
    /// Fresh request (no existing boundary for this turn): persist exactly one
    /// row whose `attempt` is the logical provider attempt about to run
    /// (normally 1). Same-turn retry must not call this again — reuse the
    /// existing row so request-boundary ids never conflict. Never stores
    /// request/messages/prompt/provider_options/api_key/headers/body.
    pub fn commit_provider_request(
        &self,
        run_id: &str,
        turn: u64,
        attempt: u64,
        request_is_idempotent: bool,
        request: &JsonValue,
    ) -> Result<(), EventCommitError> {
        let event_id = durable_provider_event_id(run_id, turn, "model.requested");
        let mut payload = json!({
            "turn": turn,
            "attempt": attempt,
            "request_fingerprint": crate::durable_provider::canonical_provider_request_fingerprint(request),
            "retry_safe": request_is_idempotent,
        });
        if let Some(value) = request.get("_provider_step_key") {
            let key = value
                .as_str()
                .filter(|key| {
                    !key.is_empty() && key.len() <= 512 && !key.chars().any(char::is_control)
                })
                .ok_or_else(|| {
                    EventCommitError::Corrupt("provider step identity is invalid".into())
                })?;
            payload["step_key"] = json!(key);
        }
        if let JsonValue::Object(map) = &mut payload {
            for key in SECRET_PROVIDER_REQUEST_KEYS {
                map.remove(*key);
            }
        }
        self.persist_provider_event(run_id, &event_id, "model.requested", payload)
    }

    /// Inspect durable provider-request state. Retry does not call the inner
    /// provider or synthesize an assistant step; Interrupted fail-closes.
    /// `request` is the current sanitized canonical request; its fingerprint
    /// must match the stored digest before Retry is allowed.
    pub fn recover_pending_provider(
        &self,
        run_id: &str,
        turn: u64,
        request: &JsonValue,
    ) -> Result<ProviderPendingDecision, EventCommitError> {
        let decision = self.provider_pending_decision(run_id, turn, request);
        match decision {
            ProviderPendingDecision::Replay
            | ProviderPendingDecision::RefusedTerminal
            | ProviderPendingDecision::Retry => Ok(decision),
            ProviderPendingDecision::Interrupted => {
                self.persist_interrupted_provider(run_id, turn)?;
                Ok(ProviderPendingDecision::Interrupted)
            }
        }
    }

    pub fn provider_pending_decision(
        &self,
        run_id: &str,
        turn: u64,
        request: &JsonValue,
    ) -> ProviderPendingDecision {
        let store = self.inner.store.read();
        let Some(run) = store.runs.get(run_id) else {
            return ProviderPendingDecision::Interrupted;
        };
        let requested_id = durable_provider_event_id(run_id, turn, "model.requested");
        let completed_id = durable_provider_event_id(run_id, turn, "model.completed");
        let interrupted_id = durable_provider_event_id(run_id, turn, "interrupted_provider");
        let requested = run
            .events
            .iter()
            .find(|event| event.event_id == requested_id);
        let has_completed = run
            .events
            .iter()
            .any(|event| event.event_id == completed_id);
        if has_completed {
            return ProviderPendingDecision::Replay;
        }
        let has_terminal_failure = run.events.iter().any(|event| {
            event.event_id == interrupted_id
                || (event.event == "model.failed"
                    && event.data.get("turn").and_then(JsonValue::as_u64) == Some(turn)
                    && !provider_failure_is_retryable(event))
        });
        if has_terminal_failure {
            return ProviderPendingDecision::Interrupted;
        }
        if run_refuses_pending_provider(run) {
            return ProviderPendingDecision::RefusedTerminal;
        }
        let Some(requested) = requested else {
            return ProviderPendingDecision::Interrupted;
        };
        let retry_safe = requested
            .data
            .get("retry_safe")
            .and_then(JsonValue::as_bool)
            .or_else(|| {
                requested
                    .data
                    .get("idempotent")
                    .and_then(JsonValue::as_bool)
            });
        let stored_fingerprint = requested
            .data
            .get("request_fingerprint")
            .and_then(JsonValue::as_str);
        let current_fingerprint =
            crate::durable_provider::canonical_provider_request_fingerprint(request);
        let fingerprint_ok = stored_fingerprint == Some(current_fingerprint.as_str())
            && current_fingerprint.starts_with("sha256:");
        let secret_leak = requested_payload_leaks_secrets(&requested.data);
        if retry_safe != Some(true) || !fingerprint_ok || secret_leak {
            return ProviderPendingDecision::Interrupted;
        }
        let request_seq = requested.seq;
        let has_effect = run
            .events
            .iter()
            .any(|event| event.seq > request_seq && event.event.starts_with("tool."));
        let retryable_failures = run
            .events
            .iter()
            .filter(|event| {
                event.event == "model.failed"
                    && event.data.get("turn").and_then(JsonValue::as_u64) == Some(turn)
                    && provider_failure_is_retryable(event)
            })
            .count() as u64;
        let has_durable_response = false;
        if provider_pending_may_retry(has_durable_response, true, has_effect)
            && retryable_failures <= PROVIDER_RETRY_BUDGET
        {
            ProviderPendingDecision::Retry
        } else {
            ProviderPendingDecision::Interrupted
        }
    }

    fn persist_interrupted_provider(
        &self,
        run_id: &str,
        turn: u64,
    ) -> Result<(), EventCommitError> {
        let event_id = durable_provider_event_id(run_id, turn, "interrupted_provider");
        let payload = json!({
            "turn": turn,
            "error_code": "interrupted_provider",
            "retryable": false,
        });
        self.persist_provider_event(run_id, &event_id, "model.failed", payload)
    }

    /// Locate a caller-owned logical provider step without interpreting policy.
    /// Legacy pending boundaries retain their interruption checks; completed
    /// legacy steps cannot be selected as a different scoped request.
    pub(crate) fn provider_turn_for_step(
        &self,
        run_id: &str,
        key: &str,
        positional: u64,
        request: &JsonValue,
    ) -> Result<u64, EventCommitError> {
        let store = self.inner.store.read();
        let run = store.runs.get(run_id).ok_or(EventCommitError::Terminal)?;
        let mut found = None;
        let mut max_turn = 0;
        for event in &run.events {
            if event.event.starts_with("model.") {
                max_turn = max_turn.max(
                    event
                        .data
                        .get("turn")
                        .and_then(JsonValue::as_u64)
                        .unwrap_or(0),
                );
            }
            if event.event == "model.requested" {
                let turn = event
                    .data
                    .get("turn")
                    .and_then(JsonValue::as_u64)
                    .ok_or_else(|| EventCommitError::Corrupt("provider turn is missing".into()))?;
                match event.data.get("step_key") {
                    Some(JsonValue::String(stored)) if stored == key => {
                        let current =
                            crate::durable_provider::canonical_provider_request_fingerprint(
                                request,
                            );
                        if event
                            .data
                            .get("request_fingerprint")
                            .and_then(JsonValue::as_str)
                            != Some(current.as_str())
                        {
                            return Err(EventCommitError::Corrupt(
                                "provider step request identity changed".into(),
                            ));
                        }
                        if found.replace(turn).is_some() {
                            return Err(EventCommitError::Corrupt(
                                "provider step identity is duplicated".into(),
                            ));
                        }
                    }
                    None if turn == positional => {
                        if run.events.iter().any(|item| {
                            item.event_id
                                == durable_provider_event_id(run_id, turn, "model.completed")
                        }) {
                            return Err(EventCommitError::Corrupt(
                                "legacy completed step has no caller identity".into(),
                            ));
                        }
                        return Ok(turn);
                    }
                    Some(JsonValue::String(_)) | None => {}
                    _ => {
                        return Err(EventCommitError::Corrupt(
                            "provider step identity is invalid".into(),
                        ));
                    }
                }
            }
        }
        if let Some(turn) = found {
            return Ok(turn);
        }
        if positional <= max_turn && run.events.first().is_some_and(|event| event.seq > 1) {
            return Err(EventCommitError::Corrupt(
                "provider replay identity was pruned".into(),
            ));
        }
        max_turn
            .checked_add(1)
            .ok_or_else(|| EventCommitError::Corrupt("provider turn overflow".into()))
    }

    pub(crate) fn has_provider_request(&self, run_id: &str, turn: u64) -> bool {
        let store = self.inner.store.read();
        let Some(run) = store.runs.get(run_id) else {
            return false;
        };
        let event_id = durable_provider_event_id(run_id, turn, "model.requested");
        run.events.iter().any(|event| event.event_id == event_id)
    }

    /// Next logical provider attempt for `turn`: one past the highest durable
    /// `model.failed.attempt`, or 1 when no failure has been recorded.
    pub(crate) fn next_provider_attempt(&self, run_id: &str, turn: u64) -> u64 {
        let store = self.inner.store.read();
        let Some(run) = store.runs.get(run_id) else {
            return 1;
        };
        let max_attempt = run
            .events
            .iter()
            .filter(|event| {
                event.event == "model.failed"
                    && event.data.get("turn").and_then(JsonValue::as_u64) == Some(turn)
            })
            .filter_map(|event| event.data.get("attempt").and_then(JsonValue::as_u64))
            .max()
            .unwrap_or(0);
        max_attempt.saturating_add(1)
    }

    pub(crate) fn persist_provider_failure(
        &self,
        run_id: &str,
        turn: u64,
        attempt: u64,
        code: &str,
        status: Option<u64>,
        retryable: bool,
    ) -> Result<(), EventCommitError> {
        let event_id = durable_provider_event_id(run_id, turn, &format!("model.failed:{attempt}"));
        let bounded_code = truncate_for_log(code, 64);
        let mut payload = json!({
            "turn": turn,
            "attempt": attempt,
            "error_code": bounded_code,
            "retryable": retryable,
        });
        if let Some(status) = status {
            payload["status"] = json!(status);
        }
        self.persist_provider_event(run_id, &event_id, "model.failed", payload)
    }

    pub(crate) fn replay_provider_envelope(
        &self,
        run_id: &str,
        turn: u64,
    ) -> Result<Option<JsonValue>, EventCommitError> {
        let store = self.inner.store.read();
        let Some(run) = store.runs.get(run_id) else {
            return Err(EventCommitError::Terminal);
        };
        let completed_id = durable_provider_event_id(run_id, turn, "model.completed");
        let message_id = durable_message_id(run_id, "turn", &turn.to_string());
        let completed = run
            .events
            .iter()
            .find(|event| event.event_id == completed_id);
        let message = store.sessions.get(&run.session_id).and_then(|session| {
            session
                .messages
                .iter()
                .find(|message| message.id == message_id)
        });
        match (completed, message) {
            (None, None) => Ok(None),
            (Some(event), Some(message)) if message.role == "assistant" => {
                let finish_reason = message
                    .finish_reason
                    .as_deref()
                    .or_else(|| event.data.get("finish_reason").and_then(JsonValue::as_str));
                crate::durable_provider::reconstruct_provider_envelope(
                    &message.content,
                    &message.metadata,
                    finish_reason,
                )
                .map(Some)
            }
            _ => Err(EventCommitError::Corrupt(
                "durable provider step is incomplete".to_string(),
            )),
        }
    }

    fn persist_provider_event(
        &self,
        run_id: &str,
        event_id: &str,
        event_type: &str,
        payload: JsonValue,
    ) -> Result<(), EventCommitError> {
        let _serial = self.inner.commit_gate.lock();
        let reserved = {
            let store = self.inner.store.read();
            let Some(run) = store.runs.get(run_id) else {
                return Err(EventCommitError::Terminal);
            };
            if run.events.iter().any(|event| event.event_id == event_id) {
                return Ok(());
            }
            if run.status == "cancelled" {
                return Err(EventCommitError::Cancelled);
            }
            if run_refuses_pending_provider(run) {
                return Err(EventCommitError::Terminal);
            }
            let session_id = run.session_id.clone();
            let max_event_bytes = self.inner.config.max_event_bytes;
            let max_events = self.inner.config.max_events_per_run;
            let mut event = event_candidate(run, event_type, payload, max_event_bytes);
            event.event_id = event_id.to_string();
            let persist_payload = json!({
                "run_id": run_id,
                "session_id": session_id,
                "event_id": event_id,
                "event_type": event_type,
                "payload_json": serde_json::to_string(&event.data)
                    .unwrap_or_else(|_| "{}".to_string()),
                "now_ms": event.timestamp,
                "max_events": max_events,
                "seq": event.seq,
            });
            ReservedCommit {
                event,
                message: None,
                persist_payload,
                kind: PersistKind::EventAppend,
                max_events_per_run: max_events,
            }
        };
        persist_and_apply(
            &self.inner.store,
            self.inner.persistence.as_deref(),
            reserved,
        )
    }

    fn capability_host_state(
        &self,
        run_id: &str,
        handle: &Arc<RunHandle>,
    ) -> Result<Option<Arc<CapabilityHostState>>, RunContextError> {
        loop {
            let mut phase = handle.capability_host.lock().expect("capability host lock");
            if matches!(*phase, CapabilityHostPhase::Closed(_)) {
                return Ok(None);
            }
            if let CapabilityHostPhase::Ready(state) = &*phase {
                return Ok(Some(Arc::clone(state)));
            }
            if matches!(*phase, CapabilityHostPhase::Initializing) {
                drop(
                    handle
                        .capability_host_cv
                        .wait(phase)
                        .expect("capability host condvar"),
                );
                continue;
            }
            *phase = CapabilityHostPhase::Initializing;
            break;
        }
        let mut guard = CapabilityHostInitGuard::arm(handle);
        let observer = self
            .inner
            .capability_host_init_entered
            .lock()
            .expect("capability host init observer lock")
            .clone();
        if let Some(observer) = observer {
            observer();
        }
        let built = self.build_capability_host_state(run_id, handle);
        match built {
            Ok(state) => {
                let state = Arc::new(state);
                let mut phase = handle.capability_host.lock().expect("capability host lock");
                if matches!(*phase, CapabilityHostPhase::Initializing) {
                    *phase = CapabilityHostPhase::Ready(Arc::clone(&state));
                    handle.capability_host_cv.notify_all();
                    guard.disarm();
                    Ok(Some(state))
                } else {
                    handle.capability_host_cv.notify_all();
                    guard.disarm();
                    drop(phase);
                    drop(state);
                    Ok(None)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn build_capability_host_state(
        &self,
        run_id: &str,
        handle: &Arc<RunHandle>,
    ) -> Result<CapabilityHostState, RunContextError> {
        let context = self
            .run_context(run_id)
            .ok_or_else(|| RunContextError::Missing {
                run_id: run_id.to_string(),
            })?;
        let registry = self.run_registry_snapshot(run_id).ok_or_else(|| {
            invalid_context_metadata(run_id, "admitted registry snapshot is missing")
        })?;
        let expected = context
            .metadata
            .get("registry_identity")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| invalid_context_metadata(run_id, "registry identity is missing"))?;
        if registry.identity() != expected {
            return Err(RunContextError::RegistryMismatch {
                run_id: run_id.to_string(),
                expected: expected.to_string(),
                actual: registry.identity().to_string(),
            });
        }
        let workspace_authority = handle.workspace_authority.as_ref();
        let (workspace, workspace_grant) = if let Some(authority) = workspace_authority {
            authority.check().map_err(|_| {
                invalid_context_metadata(run_id, "trusted workspace authority is revoked")
            })?;
            (
                Some(PathBuf::from(authority.canonical_path())),
                Some(authority.grant()),
            )
        } else if let Some(root) = handle.legacy_workspace_root.as_ref() {
            (Some(root.clone()), None)
        } else {
            (None, None)
        };
        let max_tool_calls = context
            .limits
            .get("max_tool_calls")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| invalid_context_metadata(run_id, "max_tool_calls is missing"))?;
        let max_tool_output_bytes = context
            .limits
            .get("max_tool_output_bytes")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| invalid_context_metadata(run_id, "max_tool_output_bytes is missing"))?
            as usize;
        let output_cap = max_tool_output_bytes.clamp(1, MAX_TOOL_OUTPUT_BYTES);
        // Limits are independent of path authority. With no admitted workspace,
        // keep only the bounded configuration values; do not open a path.
        let limits_root = workspace.clone().unwrap_or_default();
        let mut file_config = FileToolConfig::for_workspace(limits_root.clone());
        file_config.apply_admitted_output_cap(output_cap);
        let filesystem_limits = FilesystemLimits {
            max_read_bytes: file_config.max_read_bytes,
            max_write_bytes: file_config.max_write_bytes,
            max_list_entries: file_config.max_search_files.max(1),
        };
        let artifact_limits = ArtifactLimits {
            max_object_bytes: file_config.artifact_store.max_object_bytes,
            max_total_bytes: file_config.artifact_store.max_total_bytes,
            max_objects: file_config.artifact_store.max_objects.max(1),
        };
        let mut process_config = ProcessToolConfig::for_workspace(limits_root.clone());
        process_config.apply_admitted_output_cap(output_cap);
        let process_limits = ProcessLimits {
            timeout_ms: u64::try_from(process_config.max_timeout.as_millis()).unwrap_or(u64::MAX),
            stdout_limit: process_config.max_stream_bytes,
            stderr_limit: process_config.max_stream_bytes,
            total_limit: process_config.max_stream_bytes,
            stdin_limit: process_config.max_stdin_bytes,
            log_limit: process_config.max_output_bytes.max(1),
            close_after_initial: false,
        };
        let events: Arc<dyn DurableEventCommitter> = Arc::new(ServiceEventCommitter {
            store: Arc::clone(&self.inner.store),
            persistence: self.inner.persistence.clone(),
            run_id: run_id.to_string(),
            handle: Arc::downgrade(handle),
            max_event_bytes: self.inner.config.max_event_bytes,
            max_events_per_run: self.inner.config.max_events_per_run,
            commit_gate: Arc::clone(&self.inner.commit_gate),
            service: Arc::downgrade(&self.inner),
        });
        let capability_owner = CapabilityOwner::new(
            ADMISSION_SESSION_PROFILE,
            &context.session_id,
            &context.run_id,
        )
        .map_err(|error| invalid_context_metadata(run_id, &error))?;
        let now = Instant::now();
        let now_ms = timestamp();
        let deadline_ms = match handle.cancel.deadline_instant() {
            Some(deadline) if deadline > now => now_ms.saturating_add(
                u64::try_from(deadline.duration_since(now).as_millis()).unwrap_or(u64::MAX),
            ),
            Some(_) => now_ms,
            None => now_ms.saturating_add(
                u64::try_from(self.inner.config.run_timeout.as_millis()).unwrap_or(u64::MAX),
            ),
        };
        let lifecycle = CapabilityLifecycle::builder()
            .owner(capability_owner.clone())
            .registry_identity(expected.to_string())
            // CapabilityLifecycle currently requires a path-shaped token claim.
            // The empty value is an absent marker only: filesystem/process
            // capabilities are omitted below when no trusted root exists.
            .workspace(limits_root)
            .limits(LifecycleLimits {
                max_tool_calls,
                max_output_bytes: output_cap,
                max_summary_bytes: 4096,
            })
            .deadline_ms(deadline_ms)
            .clock(Arc::new(SystemClock))
            .tokens(Arc::new(UuidIssuer))
            .durable(Arc::new(ServiceDurableLifecycle {
                events: Arc::clone(&events),
            }) as Arc<dyn DurableToolLifecycle>)
            .approval(Arc::new(GuardianApprovalGate::new(
                Arc::new(SystemClock),
                1,
            )))
            .cancellation(Arc::new(HandleCancelFlag {
                cancel: handle.cancel.clone(),
            }) as Arc<dyn CancellationFlag>)
            .generation(workspace_authority.map_or(1, |authority| authority.generation()))
            .build()
            .map_err(|error| invalid_context_metadata(run_id, error.code()))?;
        let filesystem = match (workspace.as_ref(), workspace_grant.as_ref()) {
            (Some(_), Some(grant)) => Some(Arc::new(
                FilesystemCapability::new_adopted(
                    lifecycle.clone(),
                    capability_owner.clone(),
                    filesystem_limits,
                    Arc::clone(grant),
                )
                .map_err(|error| invalid_context_metadata(run_id, error.code()))?,
            )),
            (Some(_), None) => Some(Arc::new(
                FilesystemCapability::new(
                    lifecycle.clone(),
                    capability_owner.clone(),
                    filesystem_limits,
                )
                .map_err(|error| invalid_context_metadata(run_id, error.code()))?,
            )),
            (None, _) => None,
        };
        let processes = match (workspace.as_ref(), workspace_grant.as_ref()) {
            (Some(_), Some(grant)) => Some(Arc::new(
                ProcessCapability::new_adopted(
                    lifecycle.clone(),
                    capability_owner.clone(),
                    process_limits,
                    Arc::clone(grant),
                )
                .map_err(|error| invalid_context_metadata(run_id, error.code()))?,
            )),
            (Some(_), None) => Some(Arc::new(
                ProcessCapability::new(lifecycle.clone(), capability_owner.clone(), process_limits)
                    .map_err(|error| invalid_context_metadata(run_id, error.code()))?,
            )),
            (None, _) => None,
        };
        let artifacts = Arc::new(
            ArtifactCapability::new(lifecycle.clone(), capability_owner.clone(), artifact_limits)
                .map_err(|error| invalid_context_metadata(run_id, error.code()))?,
        );
        Ok(CapabilityHostState {
            cleaned: AtomicBool::new(false),
            shutdown_entered: self
                .inner
                .capability_host_shutdown
                .lock()
                .expect("capability host shutdown observer lock")
                .clone(),
            cleanup_grace: self.inner.config.cancellation_grace,
            uncooperative: self
                .inner
                .uncooperative_dispatch
                .lock()
                .expect("uncooperative dispatch lock")
                .clone(),
            lifecycle: Arc::new(lifecycle),
            capability_owner,
            filesystem,
            processes,
            artifacts,
        })
    }

    /// True when run-scoped capability host state is still retained.
    pub fn capability_host_retained(&self, run_id: &str) -> bool {
        self.handle(run_id)
            .is_some_and(|handle| handle.capability_host_retained())
    }

    /// True when capability host for `run_id` is sticky-closed.
    pub fn capability_host_closed(&self, run_id: &str) -> bool {
        self.handle(run_id)
            .is_some_and(|handle| handle.capability_host_closed())
    }

    /// Live process-owner residue for `run_id`, or 0 after cleanup/close.
    pub fn process_owner_count(&self, run_id: &str) -> usize {
        let Some(handle) = self.handle(run_id) else {
            return 0;
        };
        let Ok(phase) = handle.capability_host.lock() else {
            return 0;
        };
        match &*phase {
            CapabilityHostPhase::Ready(state) => state
                .processes
                .as_ref()
                .map_or(0, |processes| processes.table_len()),
            CapabilityHostPhase::Closed(Some(closed)) => closed
                .processes
                .as_ref()
                .map_or(0, |processes| processes.table_len()),
            CapabilityHostPhase::Empty
            | CapabilityHostPhase::Initializing
            | CapabilityHostPhase::Closed(None) => 0,
        }
    }

    /// OS PIDs retained for `run_id`, including draining residue after close.
    pub fn process_owner_pids(&self, run_id: &str) -> Vec<u32> {
        let Some(handle) = self.handle(run_id) else {
            return Vec::new();
        };
        let Ok(phase) = handle.capability_host.lock() else {
            return Vec::new();
        };
        match &*phase {
            CapabilityHostPhase::Ready(state) => state
                .processes
                .as_ref()
                .map_or_else(Vec::new, |processes| processes.live_pids()),
            CapabilityHostPhase::Closed(Some(closed)) => closed
                .processes
                .as_ref()
                .map_or_else(Vec::new, |processes| processes.live_pids()),
            CapabilityHostPhase::Empty
            | CapabilityHostPhase::Initializing
            | CapabilityHostPhase::Closed(None) => Vec::new(),
        }
    }

    fn cleanup_run_hosts(&self, handle: &RunHandle) -> CleanupOutcome {
        handle.release_capability_host()
    }

    async fn commit_cleanup_or_continue(&self, run_id: &str, handle: &RunHandle) -> bool {
        match self.cleanup_run_hosts(handle) {
            CleanupOutcome::Clean => true,
            CleanupOutcome::Timeout => {
                self.finish_failed(
                    run_id,
                    failed_payload_with_code(
                        "cleanup_timeout",
                        "capability host or process cleanup exceeded grace".into(),
                    ),
                )
                .await;
                false
            }
            CleanupOutcome::Failed => {
                self.finish_failed(
                    run_id,
                    failed_payload_with_code(
                        "cleanup_failed",
                        "capability host or process cleanup failed".into(),
                    ),
                )
                .await;
                false
            }
        }
    }

    const COMPILE_DIGEST_RETRIES: usize = 4;

    fn cached_agent_runner(&self, source: Option<&str>) -> Result<AgentRunner, String> {
        let expected = self.effective_agent_config();
        if let Some(entry) = self
            .inner
            .agent_entry
            .lock()
            .expect("agent entry lock")
            .clone()
        {
            match entry {
                AgentEntry::File(entry) => {
                    let mut last_error = "module tree changed during compile".to_string();
                    for _ in 0..Self::COMPILE_DIGEST_RETRIES {
                        if let Some(hook) = self
                            .inner
                            .agent_compile_lookup_entered
                            .lock()
                            .expect("agent compile lookup observer lock")
                            .clone()
                        {
                            hook();
                        }
                        let live_a =
                            crate::runtime::rss_runner::module_tree_digest_with_import_memo(
                                &entry,
                                &self.inner.import_validation_memo,
                            )
                            .map_err(|error| error.to_string())?;
                        {
                            let cache = self
                                .inner
                                .runner
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if let Some(cached) = cache.as_ref()
                                && cached.source_digest == live_a
                                && cached.config == expected
                                && cached.runner.snapshot_digest() == live_a
                            {
                                return Ok(cached.runner.clone());
                            }
                        }
                        let runner = AgentRunner::from_file(&entry, expected.clone())
                            .map_err(|error| error.to_string())?;
                        if let Some(hook) = self
                            .inner
                            .agent_compile_postcheck_entered
                            .lock()
                            .expect("agent compile postcheck observer lock")
                            .clone()
                        {
                            hook();
                        }
                        let compiled_b = runner.snapshot_digest().to_string();
                        let live_c =
                            crate::runtime::rss_runner::module_tree_digest_with_import_memo(
                                &entry,
                                &self.inner.import_validation_memo,
                            )
                            .map_err(|error| error.to_string())?;
                        if live_c == compiled_b {
                            let mut cache = self
                                .inner
                                .runner
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            *cache = Some(CachedAgentRunner {
                                source_digest: compiled_b,
                                config: expected,
                                runner: runner.clone(),
                            });
                            return Ok(runner);
                        }
                        last_error = "module tree changed during compile".to_string();
                    }
                    return Err(format!("RustScript compile error: {last_error}"));
                }
                AgentEntry::Bundled(key) => {
                    // Immutable embedded resource: never a file digest or
                    // checkout tree read. A cache hit is honored only when it
                    // still names this exact admitted key and carries the
                    // current effective config; otherwise the same admitted
                    // key is recompiled through the native staged pipeline.
                    {
                        let cache = self
                            .inner
                            .runner
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if let Some(cached) = cache.as_ref()
                            && cached.runner.bundled_resource_key() == Some(key.as_str())
                            && cached.config == expected
                        {
                            return Ok(cached.runner.clone());
                        }
                    }
                    let runner = AgentRunner::from_bundled(&key, expected.clone())
                        .map_err(|error| error.to_string())?;
                    let mut cache = self
                        .inner
                        .runner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if let Some(cached) = cache.as_ref()
                        && cached.runner.bundled_resource_key() == Some(key.as_str())
                        && cached.config == expected
                    {
                        return Ok(cached.runner.clone());
                    }
                    *cache = Some(CachedAgentRunner {
                        source_digest: runner.snapshot_digest().to_string(),
                        config: expected,
                        runner: runner.clone(),
                    });
                    return Ok(runner);
                }
            }
        }
        let source = source.ok_or_else(|| "RSS agent source is not configured".to_string())?;
        let digest = agent_source_digest(source);
        {
            let cache = self
                .inner
                .runner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = cache.as_ref()
                && cached.source_digest == digest
                && cached.config == expected
                && cached.runner.snapshot_digest() == digest
            {
                return Ok(cached.runner.clone());
            }
        }
        let runner = AgentRunner::from_source(source, expected.clone())
            .map_err(|error| error.to_string())?;
        let compiled_digest = runner.snapshot_digest().to_string();
        let mut cache = self
            .inner
            .runner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached) = cache.as_ref()
            && cached.source_digest == digest
            && cached.config == expected
            && cached.runner.snapshot_digest() == digest
        {
            return Ok(cached.runner.clone());
        }
        *cache = Some(CachedAgentRunner {
            source_digest: compiled_digest,
            config: expected,
            runner: runner.clone(),
        });
        Ok(runner)
    }

    fn effective_agent_config(&self) -> AgentConfig {
        AgentConfig {
            http: self.inner.http_config.clone(),
            sqlite: self.inner.config.sqlite.clone(),
            fuel: self.inner.config.fuel,
        }
    }

    /// Install a precompiled runner so workers do not recompile the agent source.
    /// The cache key is the digest the runner actually compiled, never a later
    /// live-tree digest.
    pub fn install_agent_runner(&self, runner: AgentRunner) {
        let digest = runner.snapshot_digest().to_string();
        *self
            .inner
            .runner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(CachedAgentRunner {
            source_digest: digest,
            config: runner.config().clone(),
            runner,
        });
    }

    pub fn install_agent_entry(&self, path: PathBuf) {
        *self.inner.agent_entry.lock().expect("agent entry lock") = Some(AgentEntry::File(path));
    }

    /// Installs an immutable embedded bundled agent entry named by an
    /// admitted native catalog key. The runner is compiled through the
    /// native closed-bundle API with the current effective config *before*
    /// the tagged entry is published, so a worker can never observe a
    /// `Bundled` tag without its matching admitted runner. A `Bundled` key
    /// is never resolved against the checkout module tree.
    pub(crate) fn install_bundled_agent_entry(&self, key: &str) -> Result<(), String> {
        let runner = AgentRunner::from_bundled(key, self.effective_agent_config())
            .map_err(|_| "native bundled agent source could not be compiled".to_string())?;
        self.install_agent_runner(runner);
        *self.inner.agent_entry.lock().expect("agent entry lock") =
            Some(AgentEntry::Bundled(key.to_string()));
        Ok(())
    }

    /// Drops the live handle so `run_worker` must restore cancellation from
    /// frozen context metadata (restart seam).
    pub fn evict_run_handle(&self, run_id: &str) {
        self.inner.runs.lock().expect("runs lock").remove(run_id);
    }

    /// Test seam: overwrite frozen context deadline for overflow restore tests.
    pub fn set_context_deadline_at_ms(&self, run_id: &str, deadline_at_ms: u64) {
        if let Some(context) = self
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .get_mut(run_id)
            && let Some(metadata) = context.metadata.as_object_mut()
        {
            metadata.insert(
                "deadline_at_ms".to_string(),
                JsonValue::from(deadline_at_ms.to_string()),
            );
        }
    }

    fn restore_handle_from_frozen_context(&self, run_id: &str) -> Option<Arc<RunHandle>> {
        let status = {
            let store = self.inner.store.read();
            store.runs.get(run_id)?.status.clone()
        };
        if !matches!(status.as_str(), "started" | "stopping") {
            return None;
        }
        let context = self.run_context(run_id)?;
        let deadline_at_ms = context.metadata.get("deadline_at_ms").and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })?;
        let cancel = RunCancellation::from_wall_deadline_ms(deadline_at_ms, timestamp());
        let prompt = context.coding_system_prompt.clone().unwrap_or_default();
        // A persisted limits path is never a grant. Re-open only an originally
        // admitted trusted binding through the current RSS workspace policy.
        let workspace_authority = context
            .metadata
            .get("admitted_workspace_binding")
            .and_then(|value| serde_json::from_value::<WorkspaceBinding>(value.clone()).ok())
            .and_then(|binding| {
                if status != "started" || cancel.requested().is_some() || cancel.deadline_passed() {
                    return None;
                }
                let (current, authority) = self
                    .resolve_workspace_admission(
                        Some(binding.selector.as_str()),
                        Some(&binding),
                        &cancel,
                        false,
                    )
                    .ok()?;
                let current = current?;
                if serde_json::to_value(&current).ok()? != serde_json::to_value(&binding).ok()? {
                    return None;
                }
                authority
            });
        let handle = Arc::new(RunHandle {
            tool_cancel: cancel.token(),
            cancel,
            terminal_at: Mutex::new(None),
            permit: Mutex::new(None),
            terminal: AtomicBool::new(false),
            cancel_reason: Mutex::new(None),
            subscribers: Mutex::new(SubscriberState {
                count: 0,
                notified: false,
            }),
            disconnect_policy: self.inner.config.client_disconnect_policy,
            started_at: Instant::now(),
            capability_host: Mutex::new(CapabilityHostPhase::Empty),
            capability_host_cv: Condvar::new(),
            workspace_authority,
            legacy_workspace_root: None,
            coding_system_prompt: Arc::from(prompt),
            occupancy: AtomicBool::new(false),
        });
        let registered = Arc::clone(
            self.inner
                .runs
                .lock()
                .expect("runs lock")
                .entry(run_id.to_string())
                .or_insert_with(|| Arc::clone(&handle)),
        );
        if status == "stopping" {
            registered.request_user_stop();
        }
        Some(registered)
    }

    /// Shared in-memory artifact capability for an initialized run, if any.
    pub fn native_artifact_ids(&self, run_id: &str) -> Option<Vec<String>> {
        let handle = self.handle(run_id)?;
        let phase = handle.capability_host.lock().ok()?;
        match &*phase {
            CapabilityHostPhase::Ready(state) => Some(state.artifacts.stored_ids()),
            CapabilityHostPhase::Empty
            | CapabilityHostPhase::Initializing
            | CapabilityHostPhase::Closed(_) => None,
        }
    }

    /// Test seam: later capability host construction invokes `observer` after
    /// releasing the slot lock and before FileTools/ArtifactStore IO.
    pub fn inject_capability_host_init_entered_observer(
        &self,
        observer: Arc<dyn Fn() + Send + Sync>,
    ) {
        *self
            .inner
            .capability_host_init_entered
            .lock()
            .expect("capability host init observer lock") = Some(observer);
    }

    /// Test seam: later `search_files` walks invoke `observer` when they
    /// begin, so service tests can prove stop overlaps an in-flight search.
    pub fn inject_file_search_entered_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .file_search_entered
            .lock()
            .expect("file search observer lock") = Some(observer);
    }

    /// Test seam: later capability-host shutdown invokes `observer` before
    /// process/artifact teardown, so service tests can overlap handle/stop/admit
    /// with an in-flight close.
    pub fn inject_capability_host_shutdown_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .capability_host_shutdown
            .lock()
            .expect("capability host shutdown observer lock") = Some(observer);
    }

    /// Test seam: later coding-prompt guidance reads invoke `observer` after
    /// admission has cloned prompt inputs and released the store lock, and
    /// before any `ConfinedFsRoot` filesystem IO.
    pub fn inject_prompt_read_entered_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .prompt_read_entered
            .lock()
            .expect("prompt read observer lock") = Some(observer);
    }

    /// Test seam: invoked after each file-agent lookup digest and before compile.
    pub fn inject_agent_compile_lookup_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .agent_compile_lookup_entered
            .lock()
            .expect("agent compile lookup observer lock") = Some(observer);
    }

    /// Test seam: invoked after each file-agent compile and before postcheck digest.
    pub fn inject_agent_compile_postcheck_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .agent_compile_postcheck_entered
            .lock()
            .expect("agent compile postcheck observer lock") = Some(observer);
    }

    /// Drops capability host state and cleans processes/artifacts for every
    /// run belonging to `session_id`.
    pub fn cleanup_session_capability_host(&self, session_id: &str) {
        let run_ids: Vec<String> = {
            let store = self.inner.store.read();
            let mut ids: Vec<String> = store
                .runs
                .iter()
                .filter(|(_, run)| run.session_id == session_id)
                .map(|(run_id, _)| run_id.clone())
                .collect();
            drop(store);
            if ids.is_empty() {
                ids = self
                    .inner
                    .contexts
                    .lock()
                    .expect("contexts lock")
                    .iter()
                    .filter(|(_, context)| context.session_id == session_id)
                    .map(|(run_id, _)| run_id.clone())
                    .collect();
            }
            ids
        };
        let handles: Vec<Arc<RunHandle>> = {
            let runs = self.inner.runs.lock().expect("runs lock");
            run_ids
                .into_iter()
                .filter_map(|run_id| runs.get(&run_id).cloned())
                .collect()
        };
        for handle in handles {
            handle.release_capability_host();
        }
    }

    /// Cancels and drops every retained capability host state.
    pub fn shutdown_capability_host(&self) {
        let handles: Vec<Arc<RunHandle>> = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .values()
            .cloned()
            .collect();
        for handle in handles {
            handle.release_capability_host();
        }
    }

    /// Verifies that an admitted or persisted run can execute with the
    /// currently loaded registry. A mismatch is returned before any RSS
    /// invocation is started.
    pub fn verify_run_context(&self, run_id: &str) -> Result<(), RunContextError> {
        let context = self
            .run_context(run_id)
            .map(Ok)
            .unwrap_or_else(|| self.resume_context(run_id))?;
        let current_identity = self.inner.tool_registry.read().identity().to_string();
        verify_context_registry(&context, &current_identity)?;
        if let Some(snapshot) = self
            .inner
            .context_registries
            .lock()
            .expect("context registries lock")
            .get(run_id)
        {
            let expected = context
                .metadata
                .get("registry_identity")
                .and_then(JsonValue::as_str)
                .expect("metadata validation checked registry identity");
            if snapshot.identity() != expected {
                return Err(invalid_context_metadata(
                    run_id,
                    "in-memory registry snapshot does not match metadata",
                ));
            }
        }
        Ok(())
    }

    /// Restores a context from the run's durable admission snapshot. The
    /// snapshot is authoritative for recovery; checking the currently loaded
    /// registry is deliberately left to [`Self::verify_run_context`].
    pub fn resume_context(&self, run_id: &str) -> Result<RunContext, RunContextError> {
        let context = self.load_persisted_context(run_id)?;
        let current_registry = self.inner.tool_registry.read().snapshot();
        let registry_matches = context
            .metadata
            .get("registry_identity")
            .and_then(JsonValue::as_str)
            .is_some_and(|identity| identity == current_registry.identity());
        self.cache_context(
            context.clone(),
            registry_matches.then_some(current_registry),
        );
        Ok(context)
    }

    /// Number of cached context and registry snapshots, respectively.
    pub fn context_cache_counts(&self) -> (usize, usize) {
        (
            self.inner.contexts.lock().expect("contexts lock").len(),
            self.inner
                .context_registries
                .lock()
                .expect("context registries lock")
                .len(),
        )
    }

    pub fn handle(&self, run_id: &str) -> Option<Arc<RunHandle>> {
        self.inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()
    }

    /// Number of in-memory lifecycle handles (active + retained terminal).
    pub fn handle_count(&self) -> usize {
        self.inner.runs.lock().expect("runs lock").len()
    }

    /// Stores one exact-call action preview outside durable approval storage.
    pub(crate) fn store_pending_approval_preview(
        &self,
        run_id: &str,
        binding: &PendingApprovalPreviewBinding<'_>,
        text: &str,
    ) -> Result<(), &'static str> {
        if binding.approval_id.is_empty()
            || binding.tool_call_id.is_empty()
            || binding.tool_name.is_empty()
            || binding.risk_class.is_empty()
            || binding.session_id.len() > 256
            || binding.approval_id.len() > 512
            || binding.tool_call_id.len() > 256
            || binding.tool_name.len() > 128
            || binding.risk_class.len() > 32
            || text.trim().is_empty()
            || text.len() > MAX_APPROVAL_PREVIEW_BYTES
        {
            return Err("approval_preview_invalid");
        }
        let now = i64::try_from(timestamp()).unwrap_or(i64::MAX);
        if binding.expires_at_ms <= now {
            return Err("approval_expired");
        }
        let Some(handle) = self.handle(run_id) else {
            return Err("run_not_active");
        };
        if handle.is_terminal() || handle.cancel.requested().is_some() {
            return Err("run_not_active");
        }
        let Some(context) = self
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .get(run_id)
            .cloned()
        else {
            return Err("run_not_active");
        };
        if context.session_id != binding.session_id {
            return Err("approval_owner_mismatch");
        }
        let Some(persistence) = self.persistence_handle() else {
            return Err("storage_unavailable");
        };
        let Ok(current) = persistence.approval_get(binding.approval_id) else {
            return Err("storage_unavailable");
        };
        let Some(row) = current
            .get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
        else {
            return Err("approval_not_found");
        };
        if row.first().and_then(JsonValue::as_str) != Some(binding.approval_id)
            || row.get(1).and_then(JsonValue::as_str) != Some(run_id)
            || row.get(2).and_then(JsonValue::as_str) != Some(binding.session_id)
            || row.get(3).and_then(JsonValue::as_str) != Some(binding.tool_call_id)
            || row.get(4).and_then(JsonValue::as_str) != Some(binding.tool_name)
            || row.get(5).and_then(JsonValue::as_str) != Some("{}")
            || row.get(6).and_then(JsonValue::as_str) != Some(binding.risk_class)
            || row.get(7).and_then(JsonValue::as_str) != Some("pending")
            || row.get(11).and_then(JsonValue::as_i64) != Some(binding.expires_at_ms)
        {
            return Err("approval_call_mismatch");
        }
        let key = (run_id.to_string(), binding.approval_id.to_string());
        let mut previews = self
            .inner
            .approval_previews
            .lock()
            .expect("approval previews lock");
        previews.retain(|_, preview| preview.expires_at_ms > now);
        if let Some(existing) = previews.get(&key) {
            return if existing.session_id == binding.session_id
                && existing.tool_call_id == binding.tool_call_id
                && existing.tool_name == binding.tool_name
                && existing.risk_class == binding.risk_class
                && existing.expires_at_ms == binding.expires_at_ms
                && existing.text == text
            {
                Ok(())
            } else {
                Err("approval_preview_conflict")
            };
        }
        if previews
            .keys()
            .any(|(owner_run_id, _)| owner_run_id == run_id)
        {
            return Err("approval_preview_conflict");
        }
        let capacity = self
            .inner
            .config
            .max_concurrent_runs
            .clamp(1, MAX_PENDING_APPROVAL_PREVIEWS);
        if previews.len() >= capacity {
            return Err("approval_preview_capacity");
        }
        previews.insert(
            key,
            PendingApprovalPreview {
                session_id: binding.session_id.to_string(),
                tool_call_id: binding.tool_call_id.to_string(),
                tool_name: binding.tool_name.to_string(),
                risk_class: binding.risk_class.to_string(),
                expires_at_ms: binding.expires_at_ms,
                text: text.to_string(),
            },
        );
        Ok(())
    }

    pub(crate) fn clear_pending_approval_preview(&self, run_id: &str, approval_id: &str) {
        self.inner
            .approval_previews
            .lock()
            .expect("approval previews lock")
            .remove(&(run_id.to_string(), approval_id.to_string()));
    }

    fn clear_run_approval_previews(&self, run_id: &str) {
        self.inner
            .approval_previews
            .lock()
            .expect("approval previews lock")
            .retain(|(owner_run_id, _), _| owner_run_id != run_id);
    }

    fn matching_pending_approval_preview(
        &self,
        run_id: &str,
        binding: &PendingApprovalPreviewBinding<'_>,
        now_ms: i64,
    ) -> Option<String> {
        let previews = self
            .inner
            .approval_previews
            .lock()
            .expect("approval previews lock");
        let preview = previews.get(&(run_id.to_string(), binding.approval_id.to_string()))?;
        if preview.session_id != binding.session_id
            || preview.tool_call_id != binding.tool_call_id
            || preview.tool_name != binding.tool_name
            || preview.risk_class != binding.risk_class
            || preview.expires_at_ms != binding.expires_at_ms
            || preview.expires_at_ms <= now_ms
            || preview.text.len() > MAX_APPROVAL_PREVIEW_BYTES
        {
            return None;
        }
        Some(preview.text.clone())
    }

    /// Lists bounded pending approval previews for the exact live run owner.
    pub fn pending_approvals(
        &self,
        run_id: &str,
        expected_session_id: Option<&str>,
    ) -> Result<Vec<JsonValue>, &'static str> {
        self.pending_approvals_for_owner(run_id, expected_session_id, None)
    }

    /// Telegram preview reads also bind the actor to the persisted session owner.
    pub fn pending_approvals_for_actor(
        &self,
        run_id: &str,
        expected_session_id: &str,
        expected_actor_id: &str,
    ) -> Result<Vec<JsonValue>, &'static str> {
        self.pending_approvals_for_owner(run_id, Some(expected_session_id), Some(expected_actor_id))
    }

    fn pending_approvals_for_owner(
        &self,
        run_id: &str,
        expected_session_id: Option<&str>,
        expected_actor_id: Option<&str>,
    ) -> Result<Vec<JsonValue>, &'static str> {
        let handle = self.handle(run_id).ok_or("run_not_active")?;
        if handle.is_terminal() || handle.cancel.requested().is_some() {
            return Err("run_not_active");
        }
        let context = self
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .get(run_id)
            .cloned()
            .ok_or("run_not_active")?;
        if expected_session_id.is_some_and(|session| context.session_id != session) {
            return Err("approval_owner_mismatch");
        }
        let persistence = self.persistence_handle().ok_or("storage_unavailable")?;
        if let Some(actor_id) = expected_actor_id {
            let session = persistence
                .session_get(&context.session_id)
                .map_err(|_| "storage_unavailable")?;
            let owner_id = session
                .get("rows")
                .and_then(JsonValue::as_array)
                .and_then(|rows| rows.first())
                .and_then(JsonValue::as_array)
                .and_then(|row| row.get(6))
                .and_then(JsonValue::as_str);
            if owner_id != Some(actor_id) {
                return Err("approval_owner_mismatch");
            }
        }
        let data = persistence
            .approval_list(run_id, &context.session_id)
            .map_err(|_| "storage_unavailable")?;
        let now = i64::try_from(timestamp()).unwrap_or(i64::MAX);
        let rows = data
            .get("rows")
            .and_then(JsonValue::as_array)
            .ok_or("storage_unavailable")?;
        let mut approvals = Vec::new();
        for row in rows.iter().filter_map(JsonValue::as_array) {
            if row.get(7).and_then(JsonValue::as_str) != Some("pending") {
                continue;
            }
            let approval_id = row
                .first()
                .and_then(JsonValue::as_str)
                .ok_or("storage_unavailable")?;
            let expires_at_ms = row
                .get(11)
                .and_then(JsonValue::as_i64)
                .ok_or("storage_unavailable")?;
            if expires_at_ms <= now {
                self.clear_pending_approval_preview(run_id, approval_id);
                continue;
            }
            let tool_call_id = row
                .get(3)
                .and_then(JsonValue::as_str)
                .ok_or("storage_unavailable")?;
            let tool_name = row
                .get(4)
                .and_then(JsonValue::as_str)
                .ok_or("storage_unavailable")?;
            let risk_class = row
                .get(6)
                .and_then(JsonValue::as_str)
                .ok_or("storage_unavailable")?;
            let binding = PendingApprovalPreviewBinding::new(
                &context.session_id,
                approval_id,
                tool_call_id,
                tool_name,
                risk_class,
                expires_at_ms,
            );
            let Some(preview) = self.matching_pending_approval_preview(run_id, &binding, now)
            else {
                continue;
            };
            approvals.push(json!({
                "approval_id": approval_id,
                "run_id": run_id,
                "session_id": context.session_id,
                "tool_name": tool_name,
                "risk_class": risk_class,
                "state": "pending",
                "expires_at_ms": expires_at_ms,
                "preview": preview,
            }));
        }
        Ok(approvals)
    }

    /// Resolves one durable, pending approval only while its owning run is
    /// live. The caller supplies a trusted transport identity and, for
    /// Telegram, the session selected from the allowlisted chat.
    pub fn resolve_pending_approval(
        &self,
        run_id: &str,
        approval_id: &str,
        decision: &str,
        resolver: &str,
        expected_session_id: Option<&str>,
    ) -> Result<(), &'static str> {
        if !matches!(decision, "approved" | "denied") {
            return Err("decision_invalid");
        }
        let resolver_valid = resolver == "http-bearer"
            || resolver
                .strip_prefix("telegram:")
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()));
        if !resolver_valid {
            return Err("resolver_invalid");
        }
        let handle = self.handle(run_id).ok_or("run_not_active")?;
        if handle.is_terminal() || handle.cancel.requested().is_some() {
            return Err("run_not_active");
        }
        let context = self
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .get(run_id)
            .cloned()
            .ok_or("run_not_active")?;
        let persistence = self.persistence_handle().ok_or("storage_unavailable")?;
        let current = persistence
            .approval_get(approval_id)
            .map_err(|_| "storage_unavailable")?;
        let row = current
            .get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .ok_or("approval_not_found")?;
        if row.first().and_then(JsonValue::as_str) != Some(approval_id)
            || row.get(1).and_then(JsonValue::as_str) != Some(run_id)
            || row.get(2).and_then(JsonValue::as_str) != Some(context.session_id.as_str())
            || expected_session_id.is_some_and(|session| {
                row.get(2).and_then(JsonValue::as_str) != Some(session)
                    || context.session_id != session
            })
        {
            return Err("approval_owner_mismatch");
        }
        if let Some(actor_id) = resolver.strip_prefix("telegram:") {
            let session = persistence
                .session_get(&context.session_id)
                .map_err(|_| "storage_unavailable")?;
            let session_owner = session
                .get("rows")
                .and_then(JsonValue::as_array)
                .and_then(|rows| rows.first())
                .and_then(JsonValue::as_array)
                .and_then(|row| row.get(6))
                .and_then(JsonValue::as_str);
            if session_owner != Some(actor_id) {
                return Err("approval_owner_mismatch");
            }
        }
        if row.get(7).and_then(JsonValue::as_str) != Some("pending") {
            return Err("approval_not_pending");
        }
        let now = i64::try_from(timestamp()).unwrap_or(i64::MAX);
        if row
            .get(11)
            .and_then(JsonValue::as_i64)
            .is_some_and(|expiry| expiry > 0 && expiry <= now)
        {
            return Err("approval_expired");
        }
        if decision == "approved" {
            let tool_call_id = row
                .get(3)
                .and_then(JsonValue::as_str)
                .ok_or("approval_not_found")?;
            let tool_name = row
                .get(4)
                .and_then(JsonValue::as_str)
                .ok_or("approval_not_found")?;
            let risk_class = row
                .get(6)
                .and_then(JsonValue::as_str)
                .ok_or("approval_not_found")?;
            let expires_at_ms = row
                .get(11)
                .and_then(JsonValue::as_i64)
                .ok_or("approval_not_found")?;
            let binding = PendingApprovalPreviewBinding::new(
                &context.session_id,
                approval_id,
                tool_call_id,
                tool_name,
                risk_class,
                expires_at_ms,
            );
            self.matching_pending_approval_preview(run_id, &binding, now)
                .ok_or("approval_preview_unavailable")?;
        }
        let resolution = persistence
            .approval_resolve(&json!({
                "id": approval_id,
                "run_id": run_id,
                "state": decision,
                "resolver": resolver,
                "decision_reason": "user_decision",
                "resolved_at_ms": now,
            }))
            .map_err(|_| "storage_unavailable")?;
        if resolution.get("rows_affected").and_then(JsonValue::as_i64) != Some(1) {
            return Err("approval_not_pending");
        }
        let resolved = persistence
            .approval_get(approval_id)
            .map_err(|_| "storage_unavailable")?;
        let resolved_row = resolved
            .get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .ok_or("storage_unavailable")?;
        if resolved_row.first().and_then(JsonValue::as_str) != Some(approval_id)
            || resolved_row.get(1).and_then(JsonValue::as_str) != Some(run_id)
            || resolved_row.get(7).and_then(JsonValue::as_str) != Some(decision)
            || resolved_row.get(13).and_then(JsonValue::as_str) != Some(resolver)
        {
            return Err("storage_unavailable");
        }
        self.clear_pending_approval_preview(run_id, approval_id);
        Ok(())
    }

    /// The persistence handle for typed repository commands; `None` when no
    /// SQLite path is configured (in-memory only mode).
    pub(crate) fn persistence_handle(&self) -> Option<Arc<GatewayPersistence>> {
        self.inner.persistence.clone()
    }

    /// Resolves and durably changes a session workspace through the shared RSS
    /// selection entry and the atomic storage session command.
    pub(crate) async fn bind_session_workspace(
        &self,
        session_id: &str,
        selector: String,
    ) -> Result<SessionView, AdmitError> {
        if self.inner.halting.load(Ordering::Acquire) {
            return Err(AdmitError::Halting);
        }
        let service = self.clone();
        let session_id = session_id.to_string();
        tokio::task::spawn_blocking(move || {
            service.bind_session_workspace_blocking(&session_id, &selector)
        })
        .await
        .map_err(|error| {
            AdmitError::Persistence(format!("workspace binding worker failed: {error}"))
        })?
    }

    fn bind_session_workspace_blocking(
        &self,
        session_id: &str,
        selector: &str,
    ) -> Result<SessionView, AdmitError> {
        let _admission_serial = self.inner.commit_gate.lock();
        if self.inner.halting.load(Ordering::Acquire) {
            return Err(AdmitError::Halting);
        }
        let existing = {
            let store = self.inner.store.read();
            let Some(session) = store.sessions.get(session_id) else {
                return Err(AdmitError::SessionNotFound);
            };
            if store.runs.values().any(|run| {
                run.session_id == session_id
                    && matches!(
                        run.status.as_str(),
                        "queued" | "running" | "started" | "stopping"
                    )
            }) {
                return Err(AdmitError::ActiveRun);
            }
            session.view.workspace.clone()
        };
        let cancellation = RunCancellation::with_timeout(self.inner.config.run_timeout);
        let (binding, authority) = self.resolve_workspace_admission(
            Some(selector),
            existing.as_ref(),
            &cancellation,
            true,
        )?;
        let binding = binding.ok_or_else(|| {
            AdmitError::Invalid("workspace selection was not admitted".to_string())
        })?;
        let authority = authority.ok_or_else(|| {
            AdmitError::Invalid("workspace authority was not retained".to_string())
        })?;
        authority.check().map_err(|_| {
            AdmitError::Invalid(
                "workspace authority was revoked before session binding".to_string(),
            )
        })?;
        let workspace_value = serde_json::to_value(&binding)
            .map_err(|error| AdmitError::Invalid(error.to_string()))?;
        let durable = match self.inner.persistence.as_ref() {
            Some(persistence) => persistence
                .session_workspace_bind(session_id, &workspace_value)
                .map(|_| ())
                .map_err(|error| match error.code.as_str() {
                    "active_run" => AdmitError::ActiveRun,
                    "session_not_found" => AdmitError::SessionNotFound,
                    _ => {
                        AdmitError::Persistence(format!("session workspace update failed: {error}"))
                    }
                }),
            None => Ok(()),
        };
        authority.revoke();
        durable?;

        let mut store = self.inner.store.write();
        let session = store
            .sessions
            .get_mut(session_id)
            .ok_or(AdmitError::SessionNotFound)?;
        session.view.workspace = Some(binding);
        session.view.updated_at = timestamp();
        Ok(session.view.clone())
    }

    /// Atomically admits one run: capacity permit, idempotency, parent check,
    /// session resolution/creation, run ID, cancellation/delivery state, and
    /// one transactional durable admission command. The whole critical
    /// section (store write lock plus the blocking storage worker round-trip)
    /// runs on a blocking thread so Tokio request threads are never occupied
    /// by storage stalls.
    ///
    /// All read-only admission checks (idempotency conflict, idempotent
    /// replay, parent existence) run before any session or run state is
    /// created, so a rejected or replayed admission leaves nothing behind and
    /// a replay performs no durable write. In-memory state is applied only
    /// after the durable commit succeeded, so a failed admission leaves
    /// nothing behind — in memory or on disk.
    pub async fn admit(&self, request: AdmitRunRequest) -> Result<AdmittedRun, AdmitError> {
        self.admit_with_workspace_options(request, None, true).await
    }

    /// Admits a run with an optional raw workspace selector. RSS interprets the
    /// token against the trusted native policy before the durable transaction.
    pub async fn admit_with_workspace_selector(
        &self,
        request: AdmitRunRequest,
        workspace_selector: Option<String>,
    ) -> Result<AdmittedRun, AdmitError> {
        self.admit_with_workspace_options(request, workspace_selector, true)
            .await
    }

    /// Admits an external HTTP/Telegram request. These transport callers may
    /// use only a trusted workspace binding, never an embedding's legacy root.
    pub async fn admit_external_with_workspace_selector(
        &self,
        request: AdmitRunRequest,
        workspace_selector: Option<String>,
    ) -> Result<AdmittedRun, AdmitError> {
        self.admit_with_workspace_options(request, workspace_selector, false)
            .await
    }

    async fn admit_with_workspace_options(
        &self,
        request: AdmitRunRequest,
        workspace_selector: Option<String>,
        allow_legacy_workspace_root: bool,
    ) -> Result<AdmittedRun, AdmitError> {
        // The halting gate is checked before any capacity permit or storage
        // work: once shutdown begins (SIGINT path), new admissions answer
        // the typed Halting rejection and never consume capacity.
        if self.inner.halting.load(Ordering::Acquire) {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::Halting);
            return Err(AdmitError::Halting);
        }
        if let Err(message) = validate_idempotency_pair(
            request.idempotency_key.as_deref(),
            request.idempotency_hash.as_deref(),
        ) {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::Invalid);
            return Err(AdmitError::Invalid(message));
        }
        if let Some(model) = request.model.as_deref()
            && let Err(message) = validate_visible_name(model, "model", MAX_MODEL_NAME_BYTES)
        {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::Invalid);
            return Err(AdmitError::Invalid(message));
        }
        if let Some(provider) = request
            .provider
            .as_deref()
            .filter(|value| !value.is_empty())
            && let Err(message) =
                validate_visible_name(provider, "provider", MAX_PROVIDER_NAME_BYTES)
        {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::Invalid);
            return Err(AdmitError::Invalid(message));
        }
        let capacity_permit = self
            .inner
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::RunLimitReached);
                AdmitError::RunLimitReached
            })?;
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            service.admit_blocking(
                request,
                workspace_selector,
                allow_legacy_workspace_root,
                capacity_permit,
            )
        })
        .await
        .map_err(|error| {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::Persistence);
            AdmitError::Persistence(format!("admission worker failed: {error}"))
        })?
    }

    /// Observed original-deadline/cancellation state before any durable or
    /// memory linearization. The rejection follows the existing workspace-RSS
    /// taxonomy: generic `Invalid`, never `Persistence`, never with
    /// credential/input details.
    fn admission_cancelled_before_commit(cancellation: &RunCancellation) -> bool {
        cancellation.requested().is_some() || cancellation.deadline_passed()
    }

    /// Exactly one generic invalid rejection for an admission whose original
    /// absolute deadline/cancellation was observed before linearization.
    fn admission_deadline_rejection(&self) -> AdmitError {
        self.inner
            .metrics
            .admission_rejected(AdmitRejectReason::Invalid);
        AdmitError::Invalid("admission cancelled before commit".to_string())
    }

    fn admit_blocking(
        &self,
        request: AdmitRunRequest,
        workspace_selector: Option<String>,
        allow_legacy_workspace_root: bool,
        capacity_permit: OwnedSemaphorePermit,
    ) -> Result<AdmittedRun, AdmitError> {
        // Optimistic two-phase admission: slow preparation (store snapshot
        // reads, RSS workspace admission, prompt observer + filesystem IO)
        // runs outside `commit_gate` so an unrelated admission, store writer,
        // or terminal event never waits on prompt IO. Only the fresh
        // revalidation + durable commit + in-memory publication holds the
        // gate. ONE capacity permit and ONE original absolute
        // cancellation/deadline are reused across re-preparation attempts;
        // clocks are never reset and budgets never refreshed.
        let cancellation = RunCancellation::with_timeout(self.inner.config.run_timeout);
        let run_id = Uuid::new_v4().to_string();
        let now = timestamp();
        let message_id = Uuid::new_v4().to_string();
        let event_id = Uuid::new_v4().to_string();
        let mut permit_opt = Some(capacity_permit);
        // Re-preparation loops under the ONE original absolute
        // cancellation/deadline above: the clock is never reset and the
        // budget never refreshed. Only observed expiry ends the loop without
        // a commit; relevant-input drift reprepares within the budget.
        loop {
            if Self::admission_cancelled_before_commit(&cancellation) {
                return Err(self.admission_deadline_rejection());
            }
            let registry = self.inner.tool_registry.read().snapshot();
            if registry.is_empty() {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Invalid);
                return Err(AdmitError::Invalid(
                    "tool registry must not be empty".to_string(),
                ));
            }
            let run_limits = self.inner.run_limits.read().clone();
            run_limits
                .validate()
                .map_err(|error| AdmitError::Invalid(format!("invalid run limits: {error}")))?;
            // Fresh per-attempt base snapshot; the global generation alone never
            // invalidates (only relevant prepared inputs trigger a reprepare).
            let base_limits = run_limits.clone();
            let store = self.inner.store.read();

            // Session resolution: reuse an existing session or prepare a new one
            // (applied in memory only after the durable commit).
            let replay_session_id = request
                .idempotency_key
                .as_deref()
                .and_then(|key| store.idempotency.get(key))
                .and_then(|record| store.runs.get(&record.run_id))
                .map(|run| run.session_id.clone());
            let has_idempotency_replay = replay_session_id.is_some();
            let session_id = match request.session_id.clone().or(replay_session_id) {
                Some(session_id) => {
                    if !store.sessions.contains_key(&session_id) {
                        self.inner
                            .metrics
                            .admission_rejected(AdmitRejectReason::SessionNotFound);
                        return Err(AdmitError::SessionNotFound);
                    }
                    session_id
                }
                None => Uuid::new_v4().to_string(),
            };
            let session_new = !store.sessions.contains_key(&session_id);
            let existing_workspace_binding = store
                .sessions
                .get(&session_id)
                .and_then(|session| session.view.workspace.clone());
            let (effective_model, effective_provider, effective_system_prompt) = if session_new {
                (
                    request
                        .model
                        .clone()
                        .unwrap_or_else(|| self.inner.config.model.clone()),
                    request
                        .provider
                        .clone()
                        .or_else(|| self.inner.config.provider.clone()),
                    request.instructions.clone(),
                )
            } else {
                let session = store
                    .sessions
                    .get(&session_id)
                    .expect("existing admission session should be present");
                (
                    request
                        .model
                        .clone()
                        .unwrap_or_else(|| session.view.model.clone()),
                    request
                        .provider
                        .clone()
                        .or_else(|| session.view.provider.clone()),
                    request
                        .instructions
                        .clone()
                        .or_else(|| session.view.system_prompt.clone()),
                )
            };
            if let Err(message) =
                validate_visible_name(&effective_model, "model", MAX_MODEL_NAME_BYTES)
            {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Invalid);
                return Err(AdmitError::Invalid(message));
            }
            if let Some(provider) = effective_provider
                .as_deref()
                .filter(|value| !value.is_empty())
                && let Err(message) =
                    validate_visible_name(provider, "provider", MAX_PROVIDER_NAME_BYTES)
            {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Invalid);
                return Err(AdmitError::Invalid(message));
            }
            let mut new_session_view = if session_new {
                let view = SessionView {
                    id: session_id.clone(),
                    object: "hermes.session".to_string(),
                    title: None,
                    model: effective_model.clone(),
                    provider: effective_provider.clone(),
                    source: request.platform.clone(),
                    system_prompt: effective_system_prompt.clone(),
                    workspace: None,
                    created_at: now,
                    updated_at: now,
                    message_count: 0,
                    end_reason: None,
                };
                Some(view)
            } else {
                None
            };
            if let Some(parent_run_id) = request.parent_run_id.as_deref()
                && !store.runs.contains_key(parent_run_id)
            {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::ParentNotFound);
                return Err(AdmitError::ParentNotFound);
            }
            let provider_profile = self
                .resolve_provider_profile(effective_provider.as_deref())
                .map_err(|error| {
                    AdmitError::Invalid(format!("invalid provider profile: {error}"))
                })?;
            let mut snapshot = RunAdmissionSnapshot {
                registry,
                provider_profile,
                limits: run_limits,
            };
            let context_message = SessionMessage {
                id: message_id.clone(),
                session_id: session_id.clone(),
                role: "user".to_string(),
                content: decode_message_content(&request.input),
                created_at: now,
                run_id: Some(run_id.clone()),
                finish_reason: None,
                name: None,
                tool_call_id: None,
                parent_message_id: None,
                token_estimate: None,
                metadata: JsonValue::Null,
                ordinal: None,
            };
            let mut context_messages = store
                .sessions
                .get(&session_id)
                .map(|session| session.messages.clone())
                .unwrap_or_default();
            context_messages.push(context_message.clone());
            let context_input = ContextAdmissionInput {
                run_id: run_id.clone(),
                session_id: session_id.clone(),
                message_id: message_id.clone(),
                parent_run_id: request.parent_run_id.clone(),
                platform: request.platform.clone(),
                input: request.input.clone(),
                messages: context_messages,
                model: effective_model.clone(),
                provider: effective_provider.clone(),
                system_prompt: effective_system_prompt.clone(),
            };
            drop(store);

            let replay_identity = AdmissionReplayIdentity {
                key: request.idempotency_key.as_deref(),
                request_hash: request.idempotency_hash.as_deref(),
                request_selector: workspace_selector.as_deref(),
            };
            if let Some(replayed) =
                self.replay_existing_admission(replay_identity, &cancellation)?
            {
                return Ok(replayed);
            }

            if self.inner.session_maintenance.lock().contains(&session_id) {
                return Err(AdmitError::SessionMaintenanceBusy(
                    CompactionError::from_rss("busy", "session maintenance is in progress"),
                ));
            }

            let (workspace_binding, workspace_authority) = self.resolve_workspace_admission(
                workspace_selector.as_deref(),
                existing_workspace_binding.as_ref(),
                &cancellation,
                has_idempotency_replay,
            )?;

            let legacy_workspace_root =
                if workspace_binding.is_none() && allow_legacy_workspace_root {
                    self.inner.trusted_legacy_workspace_root.read().clone()
                } else {
                    None
                };
            let effective_request_hash = request.idempotency_hash.clone();
            let workspace_identity_json = workspace_identity_json(
                workspace_binding.as_ref(),
                legacy_workspace_root.as_deref(),
                workspace_selector.as_deref(),
            )?;
            if let Some(binding) = &workspace_binding {
                snapshot.limits.workspace_root = PathBuf::from(&binding.canonical_path);
            } else if let Some(root) = &legacy_workspace_root {
                snapshot.limits.workspace_root = root.clone();
            }
            if let Some(view) = new_session_view.as_mut() {
                view.workspace = workspace_binding.clone();
            }
            let session_metadata_json = match &workspace_binding {
                Some(binding) => serde_json::to_string(&json!({"workspace": binding}))
                    .map_err(|error| AdmitError::Invalid(error.to_string()))?,
                None => "{}".to_string(),
            };
            let date = self.inner.date_source.read().current_date();
            let platform = std::env::consts::OS.to_string();
            let arch = std::env::consts::ARCH.to_string();
            let workspace_root = snapshot.limits.workspace_root.clone();
            let tool_descriptors = snapshot.registry.descriptors().to_vec();
            let run_limits = snapshot.limits.clone();

            let prompt_read_observer = self
                .inner
                .prompt_read_entered
                .lock()
                .expect("prompt read observer lock")
                .clone();
            if let Some(observer) = prompt_read_observer {
                observer();
            }

            let coding_system_prompt = build_coding_prompt(
                &workspace_root,
                &tool_descriptors,
                &run_limits,
                &date,
                &platform,
                &arch,
                CodingPromptBudgets::default(),
            )
            .map_err(|error| {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Invalid);
                AdmitError::Invalid(error.to_string())
            })?;
            let mut context =
                self.make_admitted_context(&context_input, &snapshot, coding_system_prompt.clone());
            if let Some(binding) = workspace_binding.as_ref() {
                context.metadata["admitted_workspace_binding"] = serde_json::to_value(binding)
                    .map_err(|error| AdmitError::Invalid(error.to_string()))?;
            }
            let persisted_input = persisted_run_context_json(&context)?;
            let provider = effective_provider.clone().unwrap_or_default();
            let idempotency_key = request.idempotency_key.clone().unwrap_or_default();
            let estimate = estimate_admission_query_bytes(AdmissionSqliteCellLens {
                run_id: run_id.len(),
                session_id: session_id.len(),
                parent_run_id: request.parent_run_id.as_deref().unwrap_or("").len(),
                input_json: persisted_input.len(),
                provider: provider.len(),
                model: effective_model.len(),
                script_hash: snapshot.registry.identity().len(),
                idempotency_scope: ADMISSION_IDEMPOTENCY_SCOPE.len(),
                idempotency_key: idempotency_key.len(),
                platform: request.platform.len(),
                profile: ADMISSION_SESSION_PROFILE.len(),
                system_prompt: effective_system_prompt.as_deref().unwrap_or("").len(),
                message_id: message_id.len(),
                // The existing lens also budgets identity bytes stored in the durable response.
                request_hash: request
                    .idempotency_hash
                    .as_deref()
                    .unwrap_or("")
                    .len()
                    .saturating_add(workspace_identity_json.as_deref().map_or(0, str::len)),
                has_idempotency: !idempotency_key.is_empty(),
            })
            .map_err(|error| {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Invalid);
                AdmitError::Invalid(error.to_string())
            })?;
            estimate.ensure_fits().map_err(|error| {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Invalid);
                AdmitError::Invalid(error.to_string())
            })?;

            let payload = json!({
                "session_id": session_id,
                "session_new": if session_new { 1 } else { 0 },
                "profile": ADMISSION_SESSION_PROFILE,
                "platform": request.platform.clone(),
                "account_id": session_id,
                "model": effective_model.clone(),
                "provider": effective_provider.clone().unwrap_or_default(),
                "system_prompt": effective_system_prompt.clone().unwrap_or_default(),
                "session_metadata_json": session_metadata_json,
                "run_id": run_id,
                "parent_run_id": request.parent_run_id.clone().unwrap_or_default(),
                "input_json": persisted_input,
                "message_id": message_id,
                "message_run_id": run_id,
                "script_hash": snapshot.registry.identity(),
                "idempotency_scope": ADMISSION_IDEMPOTENCY_SCOPE,
                "idempotency_key": request.idempotency_key.clone().unwrap_or_default(),
                "request_hash": effective_request_hash.clone().unwrap_or_default(),
                "workspace_identity_json": workspace_identity_json.clone().unwrap_or_default(),
                "event_id": event_id,
                "now_ms": now,
                "expires_at_ms": 0,
            });

            // Commit phase: fresh revalidation then atomic durable + in-memory
            // publication while holding the gate. Unrelated global generation
            // drift alone never invalidates; only relevant prepared inputs
            // trigger a reprepare outside the gate within the original budget.
            {
                let _admission_serial = self.inner.commit_gate.lock();
                if self.inner.halting.load(Ordering::Acquire) {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::Halting);
                    return Err(AdmitError::Halting);
                }
                // Halting keeps priority above. The original absolute
                // deadline/cancellation is enforced next, still before any
                // durable write or memory publication.
                if Self::admission_cancelled_before_commit(&cancellation) {
                    return Err(self.admission_deadline_rejection());
                }
                let (
                    cur_exists,
                    cur_view,
                    cur_messages_len,
                    cur_message_ids,
                    cur_parent_ok,
                    cur_maintenance,
                    cur_idem,
                    cur_run_exists,
                ) = {
                    let store = self.inner.store.read();
                    let cur_exists = store.sessions.contains_key(&session_id);
                    let cur_view = store.sessions.get(&session_id).map(|s| s.view.clone());
                    let (cur_len, cur_ids) = store
                        .sessions
                        .get(&session_id)
                        .map(|s| {
                            (
                                s.messages.len(),
                                s.messages.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
                            )
                        })
                        .unwrap_or_default();
                    let cur_parent_ok = match request.parent_run_id.as_deref() {
                        None => true,
                        Some(parent) => store.runs.contains_key(parent),
                    };
                    let cur_maintenance =
                        self.inner.session_maintenance.lock().contains(&session_id);
                    let cur_idem = request
                        .idempotency_key
                        .as_deref()
                        .and_then(|k| store.idempotency.get(k).cloned());
                    let cur_run_exists = store.runs.contains_key(&run_id);
                    (
                        cur_exists,
                        cur_view,
                        cur_len,
                        cur_ids,
                        cur_parent_ok,
                        cur_maintenance,
                        cur_idem,
                        cur_run_exists,
                    )
                };
                if session_new && cur_exists {
                    continue;
                }
                if !session_new && !cur_exists {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::SessionNotFound);
                    return Err(AdmitError::SessionNotFound);
                }
                if !cur_parent_ok {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::ParentNotFound);
                    return Err(AdmitError::ParentNotFound);
                }
                if cur_maintenance {
                    return Err(AdmitError::SessionMaintenanceBusy(
                        CompactionError::from_rss("busy", "session maintenance is in progress"),
                    ));
                }
                if let Some(authority) = workspace_authority.as_ref()
                    && authority.check().is_err()
                {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::Invalid);
                    return Err(AdmitError::Invalid(
                        "workspace authority was revoked before admission commit".to_string(),
                    ));
                }
                if let Some(cur) = cur_view.as_ref() {
                    if cur.workspace != existing_workspace_binding {
                        continue;
                    }
                    if !session_new {
                        let cur_eff_model =
                            request.model.clone().unwrap_or_else(|| cur.model.clone());
                        let cur_eff_provider =
                            request.provider.clone().or_else(|| cur.provider.clone());
                        let cur_eff_prompt = request
                            .instructions
                            .clone()
                            .or_else(|| cur.system_prompt.clone());
                        if cur_eff_model != effective_model
                            || cur_eff_provider != effective_provider
                            || cur_eff_prompt != effective_system_prompt
                        {
                            continue;
                        }
                        let prepared_base_len = context_input.messages.len().saturating_sub(1);
                        if cur_messages_len != prepared_base_len {
                            continue;
                        }
                        let base_match = context_input
                            .messages
                            .iter()
                            .take(prepared_base_len)
                            .enumerate()
                            .all(|(i, m)| cur_message_ids.get(i).is_some_and(|id| id == &m.id));
                        if !base_match {
                            continue;
                        }
                    }
                } else if !session_new {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::SessionNotFound);
                    return Err(AdmitError::SessionNotFound);
                }
                {
                    let cur_registry_id = self.inner.tool_registry.read().identity().to_string();
                    if cur_registry_id != snapshot.registry.identity() {
                        continue;
                    }
                    let cur_base = self.inner.run_limits.read().clone();
                    if cur_base.max_turns != base_limits.max_turns
                        || cur_base.max_tool_calls != base_limits.max_tool_calls
                        || cur_base.max_tool_output_bytes != base_limits.max_tool_output_bytes
                    {
                        continue;
                    }
                    if workspace_binding.is_none()
                        && legacy_workspace_root.is_none()
                        && cur_base.workspace_root != base_limits.workspace_root
                    {
                        continue;
                    }
                    if workspace_binding.is_none() && allow_legacy_workspace_root {
                        let cur_legacy = self.inner.trusted_legacy_workspace_root.read().clone();
                        if cur_legacy != legacy_workspace_root {
                            continue;
                        }
                    }
                    let cur_profile = self
                        .resolve_provider_profile(effective_provider.as_deref())
                        .map_err(|error| {
                            AdmitError::Invalid(format!("invalid provider profile: {error}"))
                        })?;
                    if cur_profile.to_json() != snapshot.provider_profile.to_json() {
                        continue;
                    }
                    let cur_date = self.inner.date_source.read().current_date();
                    if cur_date != date {
                        continue;
                    }
                }
                if let (Some(_key), Some(hash)) = (
                    request.idempotency_key.as_deref(),
                    effective_request_hash.as_deref(),
                ) && let Some(existing) = cur_idem
                {
                    if !self.workspace_replay_identity_matches(
                        &existing,
                        hash,
                        replay_identity.request_selector,
                        &cancellation,
                    )? {
                        self.inner
                            .metrics
                            .admission_rejected(AdmitRejectReason::IdempotencyConflict);
                        return Err(AdmitError::IdempotencyConflict);
                    }
                    let store = self.inner.store.read();
                    let (sid, status) = store
                        .runs
                        .get(&existing.run_id)
                        .map(|r| (r.session_id.clone(), r.status.clone()))
                        .unwrap_or_else(|| (String::new(), "unknown".to_string()));
                    return Ok(AdmittedRun {
                        run_id: existing.run_id.clone(),
                        session_id: sid,
                        status,
                        replayed: true,
                    });
                }
                if cur_run_exists {
                    let store = self.inner.store.read();
                    if let Some(existing) = store.runs.get(&run_id) {
                        return Ok(AdmittedRun {
                            run_id: run_id.clone(),
                            session_id: existing.session_id.clone(),
                            status: existing.status.clone(),
                            replayed: true,
                        });
                    }
                }
                // Pre-linearization check: deadline/cancel rejection is
                // BEFORE linearization. After a successful durable commit the
                // in-memory publication below completes unconditionally (no
                // post-durable rejection may orphan rows); the
                // non-persistent path is likewise covered here before its
                // memory linearization.
                if Self::admission_cancelled_before_commit(&cancellation) {
                    return Err(self.admission_deadline_rejection());
                }
                let durable = match self.inner.persistence.as_ref() {
                    Some(persistence) => persistence.admission_create(&payload).map_err(|error| {
                        self.inner
                            .metrics
                            .admission_rejected(AdmitRejectReason::Persistence);
                        match error.code.as_str() {
                            "idempotency_key_conflict" => AdmitError::IdempotencyConflict,
                            _ => AdmitError::Persistence(format!(
                                "run admission could not be durably committed: {error}"
                            )),
                        }
                    }),
                    None => Ok(JsonValue::Null),
                };
                let data = durable?;
                if data.get("replayed") == Some(&JsonValue::Bool(true)) {
                    return self.finish_durable_replay(&data);
                }
                let mut store = self.inner.store.write();
                if store.runs.contains_key(&run_id)
                    && let Some(existing) = store.runs.get(&run_id)
                {
                    return Ok(AdmittedRun {
                        run_id: run_id.clone(),
                        session_id: existing.session_id.clone(),
                        status: existing.status.clone(),
                        replayed: true,
                    });
                }
                if let (Some(key), Some(hash)) = (
                    request.idempotency_key.as_deref(),
                    effective_request_hash.as_deref(),
                ) && let Some(existing) = store.idempotency.get(key)
                {
                    if !self.workspace_replay_identity_matches(
                        existing,
                        hash,
                        replay_identity.request_selector,
                        &cancellation,
                    )? {
                        self.inner
                            .metrics
                            .admission_rejected(AdmitRejectReason::IdempotencyConflict);
                        return Err(AdmitError::IdempotencyConflict);
                    }
                    let (sid, status) = store
                        .runs
                        .get(&existing.run_id)
                        .map(|r| (r.session_id.clone(), r.status.clone()))
                        .unwrap_or_else(|| (String::new(), "unknown".to_string()));
                    return Ok(AdmittedRun {
                        run_id: existing.run_id.clone(),
                        session_id: sid,
                        status,
                        replayed: true,
                    });
                }
                if !session_new && !store.sessions.contains_key(&session_id) {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::SessionNotFound);
                    return Err(AdmitError::SessionNotFound);
                }
                if let Some(parent_run_id) = request.parent_run_id.as_deref()
                    && !store.runs.contains_key(parent_run_id)
                {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::ParentNotFound);
                    return Err(AdmitError::ParentNotFound);
                }
                self.inner.store_generation.fetch_add(1, Ordering::Release);
                if session_new {
                    store.sessions.insert(
                        session_id.clone(),
                        SessionRecord {
                            view: new_session_view.expect("new session view was prepared"),
                            messages: Vec::new(),
                        },
                    );
                }
                let session = store
                    .sessions
                    .get_mut(&session_id)
                    .expect("admission session exists after commit");
                if let Some(model) = request.model.clone() {
                    session.view.model = model;
                }
                if request.provider.is_some() {
                    session.view.provider = request.provider.clone();
                }
                if request.instructions.is_some() {
                    session.view.system_prompt = request.instructions.clone();
                }
                if let Some(binding) = workspace_binding.clone() {
                    session.view.workspace = Some(binding);
                }
                session.messages.push(context_message);
                session.view.message_count = session.messages.len();
                session.view.updated_at = now;

                let (sender, _) =
                    tokio::sync::broadcast::channel(self.inner.config.broadcast_capacity);
                let started_event = GatewayEvent {
                    event_id: event_id.clone(),
                    seq: 1,
                    event: "run.started".to_string(),
                    run_id: run_id.clone(),
                    timestamp: now,
                    data: json!({"status": "running", "session_id": session_id}),
                };
                let run = RunRecord {
                    run_id: run_id.clone(),
                    session_id: session_id.clone(),
                    parent_run_id: request.parent_run_id.clone(),
                    status: "started".to_string(),
                    events: vec![started_event],
                    sender: Some(sender),
                    cancel_requested: Arc::new(AtomicBool::new(false)),
                };
                store.runs.insert(run_id.clone(), run);
                if let (Some(key), Some(hash)) = (
                    request.idempotency_key.as_deref(),
                    effective_request_hash.as_deref(),
                ) {
                    store.idempotency.insert(
                        key.to_string(),
                        IdempotencyRecord {
                            request_hash: hash.to_string(),
                            run_id: run_id.clone(),
                            workspace_identity_json: workspace_identity_json.clone(),
                        },
                    );
                }

                let permit = permit_opt
                    .take()
                    .expect("admission capacity permit retained until commit");
                let handle = Arc::new(RunHandle {
                    tool_cancel: cancellation.token(),
                    cancel: cancellation.clone(),
                    terminal_at: Mutex::new(None),
                    permit: Mutex::new(Some(permit)),
                    terminal: AtomicBool::new(false),
                    cancel_reason: Mutex::new(None),
                    subscribers: Mutex::new(SubscriberState {
                        count: 0,
                        notified: false,
                    }),
                    disconnect_policy: self.inner.config.client_disconnect_policy,
                    started_at: Instant::now(),
                    capability_host: Mutex::new(CapabilityHostPhase::Empty),
                    capability_host_cv: Condvar::new(),
                    workspace_authority,
                    legacy_workspace_root,
                    coding_system_prompt: Arc::from(coding_system_prompt),
                    occupancy: AtomicBool::new(false),
                });
                self.inner
                    .runs
                    .lock()
                    .expect("runs lock")
                    .insert(run_id.clone(), handle);
                self.cache_context(context, Some(snapshot.registry));
                self.inner.metrics.admission_accepted();
                self.inner.metrics.active_runs_inc();
                return Ok(AdmittedRun {
                    run_id: run_id.clone(),
                    session_id,
                    status: "started".to_string(),
                    replayed: false,
                });
            }
        }
        // Unreachable: the loop only exits via commit, replay, or a typed
        // rejection; drift reprepares while the original deadline holds.
    }

    fn replay_existing_admission(
        &self,
        replay: AdmissionReplayIdentity<'_>,
        cancellation: &RunCancellation,
    ) -> Result<Option<AdmittedRun>, AdmitError> {
        let (Some(key), Some(hash)) = (replay.key, replay.request_hash) else {
            return Ok(None);
        };
        let (existing, run_info) = {
            let store = self.inner.store.read();
            let Some(existing) = store.idempotency.get(key).cloned() else {
                drop(store);
                return self.replay_durable_admission(key, hash, replay.request_selector);
            };
            let run_info = store
                .runs
                .get(&existing.run_id)
                .map(|run| (run.session_id.clone(), run.status.clone()));
            (existing, run_info)
        };
        if !self.workspace_replay_identity_matches(
            &existing,
            hash,
            replay.request_selector,
            cancellation,
        )? {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::IdempotencyConflict);
            return Err(AdmitError::IdempotencyConflict);
        }
        let store = self.inner.store.write();
        let Some(current) = store.idempotency.get(key) else {
            return Ok(None);
        };
        if !self.workspace_replay_identity_matches(
            current,
            hash,
            replay.request_selector,
            cancellation,
        )? {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::IdempotencyConflict);
            return Err(AdmitError::IdempotencyConflict);
        }
        let (session_id, status) = store
            .runs
            .get(&current.run_id)
            .map(|run| (run.session_id.clone(), run.status.clone()))
            .or(run_info)
            .unwrap_or_else(|| (String::new(), "unknown".to_string()));
        Ok(Some(AdmittedRun {
            run_id: current.run_id.clone(),
            session_id,
            status,
            replayed: true,
        }))
    }

    fn replay_durable_admission(
        &self,
        key: &str,
        request_hash: &str,
        request_selector: Option<&str>,
    ) -> Result<Option<AdmittedRun>, AdmitError> {
        let Some(persistence) = self.inner.persistence.as_ref() else {
            return Ok(None);
        };
        let data = persistence
            .admission_replay(
                ADMISSION_IDEMPOTENCY_SCOPE,
                key,
                request_hash,
                request_selector,
            )
            .map_err(|error| {
                if error.code == "idempotency_key_conflict" {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::IdempotencyConflict);
                    AdmitError::IdempotencyConflict
                } else {
                    self.inner
                        .metrics
                        .admission_rejected(AdmitRejectReason::Persistence);
                    AdmitError::Persistence(format!("durable admission replay failed: {error}"))
                }
            })?;
        match data.get("replayed") {
            Some(JsonValue::Bool(true)) => self.finish_durable_replay(&data).map(Some),
            Some(JsonValue::Bool(false)) => Ok(None),
            _ => {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Persistence);
                Err(AdmitError::Persistence(
                    "durable admission replay omitted its replay status".to_string(),
                ))
            }
        }
    }

    fn workspace_replay_identity_matches(
        &self,
        stored: &IdempotencyRecord,
        request_hash: &str,
        request_selector: Option<&str>,
        cancellation: &RunCancellation,
    ) -> Result<bool, AdmitError> {
        let stored_workspace_identity = stored
            .workspace_identity_json
            .as_deref()
            .map(serde_json::from_str::<JsonValue>)
            .transpose()
            .map_err(|error| {
                AdmitError::Persistence(format!(
                    "stored workspace replay identity is invalid: {error}"
                ))
            })?;
        let matches = AgentRunner::workspace_replay_identity_matches(
            crate::domain::json_to_vm_value(&json!({
                "stored_request_hash": stored.request_hash,
                "request_hash": request_hash,
                "stored_workspace_identity_present": stored_workspace_identity.is_some(),
                "stored_workspace_identity": stored_workspace_identity.unwrap_or(JsonValue::Null),
                "incoming_workspace_selector_present": request_selector.is_some(),
                "incoming_workspace_selector": request_selector.unwrap_or_default(),
            })),
            AgentConfig {
                http: self.inner.http_config.clone(),
                sqlite: self.inner.config.sqlite.clone(),
                fuel: self.inner.config.fuel,
            },
            cancellation,
        );

        matches.map_err(|error| {
            AdmitError::Invalid(format!("workspace replay comparison failed: {error}"))
        })
    }

    fn finish_durable_replay(&self, data: &JsonValue) -> Result<AdmittedRun, AdmitError> {
        let run_row = crate::sqlite_storage_rows::sqlite_storage_first_row(
            data.get("run").unwrap_or(&JsonValue::Null),
        )
        .ok_or_else(|| {
            AdmitError::Persistence("replayed admission omitted the existing run".to_string())
        })?;
        let replayed_run_id = admission_run_str(&run_row, ADMISSION_RUN_COL_ID)
            .unwrap_or_default()
            .to_string();
        let replayed_session = admission_run_str(&run_row, ADMISSION_RUN_COL_SESSION_ID)
            .unwrap_or_default()
            .to_string();
        let replayed_status = admission_run_str(&run_row, ADMISSION_RUN_COL_STATUS)
            .unwrap_or("unknown")
            .to_string();
        let store = self.inner.store.write();
        if let Some(run) = store.runs.get(&replayed_run_id) {
            return Ok(AdmittedRun {
                run_id: replayed_run_id,
                session_id: run.session_id.clone(),
                status: run.status.clone(),
                replayed: true,
            });
        }
        Ok(AdmittedRun {
            run_id: replayed_run_id,
            session_id: replayed_session,
            status: replayed_status,
            replayed: true,
        })
    }

    // Admission linearization is validated before the durable write in
    // `admit_blocking`; no post-commit generation log can replace the full
    // pre-commit revalidation above.
    fn reconstruct_admitted_messages(
        &self,
        context: &RunContext,
    ) -> Result<JsonValue, RunContextError> {
        let message_id = context
            .metadata
            .get("message_id")
            .and_then(JsonValue::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_context_metadata(&context.run_id, "message id is missing"))?;
        let store = self.inner.store.read();
        let session = store.sessions.get(&context.session_id).ok_or_else(|| {
            invalid_context_metadata(&context.run_id, "session messages are missing")
        })?;
        let cutoff = session
            .messages
            .iter()
            .position(|message| message.id == message_id)
            .ok_or_else(|| {
                invalid_context_metadata(&context.run_id, "admitted message is missing")
            })?;
        let mut messages = serde_json::to_value(&session.messages[..=cutoff]).map_err(|error| {
            invalid_context_metadata(
                &context.run_id,
                &format!("session messages could not be reconstructed: {error}"),
            )
        })?;
        if let Some(items) = messages.as_array_mut() {
            for item in items {
                if let Some(object) = item.as_object_mut() {
                    object.remove("ordinal");
                }
            }
        }
        Ok(messages)
    }

    /// Registers one live SSE subscriber against an active run's handle and
    /// returns the drop guard that tracks it. Returns `None` when the run's
    /// handle is already released (terminal beyond TTL): a terminal run can
    /// never be cancelled by a disconnect, so no guard is needed.
    pub(crate) fn attach_subscriber(&self, run_id: &str) -> Option<SubscriberGuard> {
        let handle = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()?;
        handle.subscribers.lock().expect("subscriber lock").count += 1;
        Some(SubscriberGuard {
            handle,
            armed: true,
        })
    }

    /// Requests a typed stop for an active run. Idempotent: the first request
    /// wins; later requests see the current status. A run whose worker has
    /// already exited with a pending terminal cannot be stopped: the outcome
    /// is decided, so stop() returns the current durable status without
    /// mutating it (and never hangs).
    pub fn stop(&self, run_id: &str) -> Option<String> {
        let handle = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()?;
        let mut store = self.inner.store.write();
        let status = store
            .runs
            .get_mut(run_id)
            .map(|run| run.status.clone())
            .unwrap_or_default();
        if status == "started" {
            if let Some(run) = store.runs.get_mut(run_id) {
                run.status = "stopping".to_string();
            }
            // The typed reason is recorded before the request so any worker
            // observing the cancellation commits exactly this reason.
            *handle.cancel_reason.lock().expect("cancel reason lock") = Some("requested");
            handle.cancel.request(CancellationReason::Requested);
            drop(store);
            handle.cancel_run_tools();
            tracing::debug!(
                run_id,
                reason = "requested",
                "typed cancellation requested for the run"
            );
            Some("stopping".to_string())
        } else {
            Some(status)
        }
    }

    /// Cancels every active run with the typed resource-closed reason and
    /// marks the service as halting; workers exit within their configured
    /// bounds and commit their typed terminal transitions.
    pub fn halt(&self) {
        self.stop_admission();
        let handles = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        tracing::info!(
            runs = handles.len(),
            reason = "resource_closed",
            "halting the gateway: cancelling every active run"
        );
        for handle in handles {
            *handle.cancel_reason.lock().expect("cancel reason lock") = Some("resource_closed");
            handle.cancel.request(CancellationReason::ResourceClosed);
            handle.cancel_run_tools();
        }
    }

    /// Stops new admissions without touching active runs: every later
    /// `admit()` answers the typed [`AdmitError::Halting`] rejection. The
    /// gateway's SIGINT path calls this first (no new work can start after
    /// shutdown begins), then stops the Telegram adapter, then cancels
    /// active runs via [`Self::halt`]. Idempotent.
    pub fn stop_admission(&self) {
        self.inner.halting.store(true, Ordering::Release);
        // Wake the idle janitor now: its interval must not retain the last
        // service/storage owner after the embedding stops admission.
        self.inner.janitor_stop.notify_one();
    }

    /// Marks a run terminal: records the terminal time for TTL retention,
    /// releases the capacity permit, and sets the atomic terminal flag the
    /// subscriber drop guard consults before any client-disconnect
    /// cancellation. The first call also releases the active gauge and
    /// records the run duration into the fixed histogram buckets; a
    /// repeated call for the same run (the bounded durable retry path can
    /// re-enter) must never double-decrement the gauge. Called by the
    /// worker (or the bounded terminal retry loop) after the one terminal
    /// commit.
    pub fn mark_terminal(&self, run_id: &str) {
        let Some(handle) = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()
        else {
            return;
        };
        handle.terminal.store(true, Ordering::Release);
        let now = Instant::now();
        let mut terminal_at = handle.terminal_at.lock().expect("terminal lock");
        if terminal_at.is_none() {
            self.inner
                .metrics
                .record_run_duration(handle.started_at.elapsed().as_secs_f64());
            // The gauge release belongs to the same first-call guard:
            // the run transitions out of the active gauge exactly once.
            self.inner.metrics.active_runs_dec();
        }
        *terminal_at = Some(now);
        drop(terminal_at);
        handle.permit.lock().expect("permit lock").take();
        handle.release_capability_host();
        self.clear_run_approval_previews(run_id);
        if let Some(persistence) = self.persistence_handle() {
            let now_ms = i64::try_from(timestamp()).unwrap_or(i64::MAX);
            if let Err(error) = persistence.approval_expire(&json!({
                "now_ms": now_ms,
                "run_id": run_id,
                "force": 1,
            })) {
                tracing::warn!(run_id, error = %error, "failed to expire pending approvals after terminal run");
            }
        }
    }

    /// Records one run's terminal state for the bounded durable-first retry
    /// loop. The worker already rolled the in-memory terminal mutation back;
    /// this marks the run observably `terminal_pending` (never a false
    /// terminal) and hands the prebuilt typed terminal to the retry loop.
    /// Lock order: store write lock, then the pending map.
    pub(crate) fn register_pending_terminal(&self, run_id: &str, pending: PendingTerminal) {
        let mut store = self.inner.store.write();
        if let Some(run) = store.runs.get_mut(run_id) {
            run.status = "terminal_pending".to_string();
        }
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .insert(run_id.to_string(), pending);
        self.inner.metrics.runs_terminal_pending_inc();
        tracing::warn!(
            run_id,
            "run terminal parked as pending for the bounded durable retry"
        );
    }

    /// Snapshot for the commit-gate-serialized retry. Keep the entry observable
    /// throughout storage IO, including a failed attempt.
    fn pending_terminal(&self, run_id: &str) -> Option<PendingTerminal> {
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .get(run_id)
            .cloned()
    }

    /// Remove only when retry has a final outcome, not while it is in flight.
    fn clear_pending_terminal(&self, run_id: &str) {
        if self
            .inner
            .pending
            .lock()
            .expect("pending lock")
            .remove(run_id)
            .is_some()
        {
            self.inner.metrics.runs_terminal_pending_dec();
        }
    }

    /// Number of runs awaiting a durable terminal commit retry (observable
    /// health state; bounded by the retry window).
    pub fn pending_terminal_count(&self) -> usize {
        self.inner.pending.lock().expect("pending lock").len()
    }

    /// Remaining admission capacity (observable; used by health and tests to
    /// prove terminal-pending runs never hold permits).
    pub fn available_capacity(&self) -> usize {
        self.inner.capacity.available_permits()
    }

    /// The bounded metrics registry shared by the service, delivery, storage
    /// worker, and API handlers.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.inner.metrics)
    }

    /// Drives one admitted run to its single terminal transition.
    ///
    /// The worker builds the canonical run context, runs the exported RSS
    /// `run(context)` through the invocation item stream with one bounded
    /// delivery path, and commits exactly one typed terminal: `run.completed`
    /// from the `Complete` value, `run.cancelled` from a typed cancellation,
    /// or `run.failed` from any other typed error. Nothing is published after
    /// the terminal commit.
    pub async fn run_worker(self: Arc<Self>, run_id: String, _input: String) {
        tokio::task::yield_now().await;
        let Some(handle) = self
            .handle(&run_id)
            .or_else(|| self.restore_handle_from_frozen_context(&run_id))
        else {
            return;
        };
        if handle.cancel.has_deadline_overflow() {
            if self.commit_cleanup_or_continue(&run_id, &handle).await {
                self.finish_failed(
                    &run_id,
                    failed_payload_with_code(
                        "invalid_deadline",
                        "persisted run deadline overflowed Instant arithmetic".into(),
                    ),
                )
                .await;
            }
            return;
        }
        let Some(_occupancy) = try_occupy_run(&handle) else {
            return;
        };
        let session_id = {
            let store = self.inner.store.read();
            let Some(run) = store.runs.get(&run_id) else {
                return;
            };
            run.session_id.clone()
        };
        let cancellation = handle.cancel.clone();

        if let Some(reason) = cancellation.requested() {
            if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                return;
            }
            self.finish_cancelled(&run_id, handle_cancel_reason(&handle, reason.as_str()))
                .await;
            return;
        }
        if cancellation.deadline_passed()
            || cancellation
                .remaining_deadline()
                .is_some_and(|remaining| remaining.is_zero())
        {
            cancellation.request(CancellationReason::Deadline);
            if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                return;
            }
            self.finish_cancelled(&run_id, handle_cancel_reason(&handle, "deadline"))
                .await;
            return;
        }

        if let Err(error) = self.verify_run_context(&run_id) {
            tracing::error!(
                run_id = %run_id,
                error = %error,
                "run context verification failed before RSS execution"
            );
            if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                return;
            }
            self.finish_failed(
                &run_id,
                json!({
                    "status": "failed",
                    "error_code": "run_context_mismatch",
                    "error_message": "the admitted run context no longer matches the loaded registry",
                }),
            )
            .await;
            return;
        }

        let output_text = if self.inner.agent_source.is_some()
            || self
                .inner
                .agent_entry
                .lock()
                .expect("agent entry lock")
                .is_some()
        {
            let source = self.inner.agent_source.clone();
            let context = self.build_run_context(&run_id);
            let (lifecycle, capability_owner, filesystem, processes, artifacts) =
                match self.capability_host_state(&run_id, &handle) {
                    Ok(Some(state)) => (
                        Some(Arc::clone(&state.lifecycle)),
                        Some(state.capability_owner.clone()),
                        state.filesystem.clone(),
                        state.processes.clone(),
                        Some(Arc::clone(&state.artifacts)),
                    ),
                    Ok(None) => (None, None, None, None, None),
                    Err(error) => {
                        if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                            return;
                        }
                        self.finish_failed(&run_id, failed_payload(error.to_string()))
                            .await;
                        return;
                    }
                };
            let provider_override = self
                .inner
                .provider_host
                .lock()
                .expect("provider host lock")
                .take();
            let auth_host_factories = self
                .inner
                .auth_host_factories
                .lock()
                .expect("auth host factory lock")
                .clone();
            let raw_provider = provider_override.unwrap_or_else(|| {
                if let Some(factory) = auth_host_factories.provider_child.clone() {
                    crate::runtime::rss_runner::default_agent_provider_host_with_auth_factory(Some(
                        factory,
                    ))
                } else {
                    crate::runtime::rss_runner::default_agent_provider_host()
                }
            });
            let accounted = Arc::new(crate::durable_provider::AccountingProvider::new(
                raw_provider,
                Arc::clone(&self.inner.metrics),
            ));
            let provider = Some(Arc::new(crate::durable_provider::DurableProviderHost::new(
                AgentService::clone(self.as_ref()),
                run_id.clone(),
                accounted,
                Arc::clone(&self.inner.metrics),
            )) as Arc<dyn AgentProviderHost>);
            let host = AgentHostBridges {
                provider,
                auth_host_factory: auth_host_factories.legacy_top_level,
                cancellation: Some(cancellation.clone()),
                sleeps: Default::default(),
                skip_sleep: false,
                metrics: Some(Arc::clone(&self.inner.metrics)),
                lifecycle,
                capability_owner,
                filesystem,
                processes,
                artifacts,
                control_hook: None,
            };
            // One bounded delivery path: the worker blocks on this channel
            // when the delivery task is busy, which pauses invocation polling
            // (backpressure). The delivery task validates, sequences, appends
            // durably, and only then publishes to live subscribers.
            let (sender, receiver) =
                tokio::sync::mpsc::channel(self.inner.config.event_channel_capacity);
            let delivery = tokio::spawn(run_delivery_task(
                DeliveryContext {
                    store: Arc::clone(&self.inner.store),
                    persistence: self.inner.persistence.clone(),
                    config: Arc::clone(&self.inner.config),
                    metrics: Arc::clone(&self.inner.metrics),
                    commit_gate: Arc::clone(&self.inner.commit_gate),
                },
                run_id.clone(),
                receiver,
            ));
            let mut sink = ChannelEventSink(sender);
            let run_cancellation = cancellation.clone();
            let runner = match self.cached_agent_runner(source.as_ref().map(|value| value.as_str()))
            {
                Ok(runner) => runner,
                Err(error) => {
                    if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                        return;
                    }
                    self.finish_failed(
                        &run_id,
                        failed_payload(format!("compile RSS run source: {error}")),
                    )
                    .await;
                    return;
                }
            };
            let mut worker = tokio::task::spawn_blocking(move || {
                runner.with_host(host).run_with_context_and_events(
                    context,
                    &mut sink,
                    &run_cancellation,
                )
            });
            let remaining = cancellation
                .remaining_deadline()
                .unwrap_or(Duration::from_millis(1));
            let outcome = match tokio::time::timeout(remaining, &mut worker).await {
                Ok(Ok(Ok(value))) => WorkerOutcome::Completed(value),
                Ok(Ok(Err(error))) => WorkerOutcome::from_run_error(error),
                Ok(Err(error)) => WorkerOutcome::Failed(format!("RSS worker join failed: {error}")),
                Err(_) => {
                    tracing::warn!(
                        run_id,
                        reason = "deadline",
                        "run timeout reached; cancelling with the typed deadline reason"
                    );
                    cancellation.request(CancellationReason::Deadline);
                    let _ = tokio::time::timeout(self.inner.config.cancellation_grace, &mut worker)
                        .await;
                    WorkerOutcome::Cancelled("deadline")
                }
            };
            // The worker dropped the channel sender when it returned; the
            // delivery task drains the remaining events and then exits. Wait
            // only the configured cancellation grace for the drain so the
            // terminal commit always follows the last durably delivered
            // script event.
            let delivery_outcome =
                tokio::time::timeout(self.inner.config.cancellation_grace, delivery)
                    .await
                    .ok()
                    .and_then(|result| result.ok())
                    .unwrap_or_default();
            if self
                .inner
                .provider_commit_crashed
                .swap(false, Ordering::SeqCst)
            {
                self.cleanup_run_hosts(&handle);
                return;
            }
            match outcome {
                WorkerOutcome::Completed(value) => {
                    if let Some(reason) = delivery_outcome.schema_violation {
                        if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                            return;
                        }
                        self.finish_failed(&run_id, events::schema_violation_error(&reason))
                            .await;
                        return;
                    }
                    if delivery_outcome.persist_failed {
                        if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                            return;
                        }
                        self.finish_failed(
                            &run_id,
                            json!({
                                "status": "failed",
                                "error_code": "persistence_unavailable",
                                "error_message": "a run event could not be appended durably",
                            }),
                        )
                        .await;
                        return;
                    }
                    match interpret_loop_decision(&value, &cancellation) {
                        WorkerOutcome::Completed(value) => completed_output_text(&value),
                        WorkerOutcome::Cancelled(core_reason) => {
                            if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                                return;
                            }
                            self.finish_cancelled(
                                &run_id,
                                handle_cancel_reason(&handle, core_reason),
                            )
                            .await;
                            return;
                        }
                        WorkerOutcome::Failed(error) => {
                            if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                                return;
                            }
                            self.finish_failed(&run_id, failed_payload(error)).await;
                            return;
                        }
                    }
                }
                WorkerOutcome::Cancelled(core_reason) => {
                    if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                        return;
                    }
                    self.finish_cancelled(&run_id, handle_cancel_reason(&handle, core_reason))
                        .await;
                    return;
                }
                WorkerOutcome::Failed(error) => {
                    if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                        return;
                    }
                    self.finish_failed(&run_id, failed_payload(error)).await;
                    return;
                }
            }
        } else {
            self.inner
                .contexts
                .lock()
                .expect("contexts lock")
                .get(&run_id)
                .map(|context| context.input.to_string())
                .expect("run context was verified before completion")
        };

        if cancellation.requested().is_some() {
            if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                return;
            }
            self.finish_cancelled(&run_id, handle_cancel_reason(&handle, "requested"))
                .await;
            return;
        }

        if !self.commit_cleanup_or_continue(&run_id, &handle).await {
            return;
        }
        self.finish_completed(&run_id, &session_id, &output_text)
            .await;
    }

    /// Durably commits the completed terminal. The assistant message,
    /// `message.delta`, and `run.completed` form one atomic delta: the whole
    /// delta is persisted through the typed `run.terminal` transaction under
    /// the store lock and published only after the durable commit succeeds.
    /// On a persist failure the delta is rolled back, nothing is published,
    /// and the worker retries with bounded backoff
    /// (`terminal_persist_retries`/`terminal_persist_retry_delay`); if every
    /// attempt fails, the run becomes observably `terminal_pending` and the
    /// bounded retry loop commits the exact same terminal once storage
    /// recovers.
    async fn finish_completed(&self, run_id: &str, session_id: &str, output_text: &str) {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        for attempt in 0..attempts {
            match self
                .commit_completed_once(run_id, session_id, output_text)
                .await
            {
                TerminalOutcome::Committed => {
                    self.inner.metrics.runs_terminal(TerminalStatus::Completed);
                    self.mark_terminal(run_id);
                    return;
                }
                TerminalOutcome::NotActive => {
                    // A stop landed between the worker check and this
                    // commit; the typed cancellation path wins, keeping the
                    // exact reason recorded on the handle.
                    let reason = self
                        .inner
                        .runs
                        .lock()
                        .expect("runs lock")
                        .get(run_id)
                        .map(|handle| handle_cancel_reason(handle, "requested"))
                        .unwrap_or("requested");
                    self.finish_cancelled(run_id, reason).await;
                    return;
                }
                TerminalOutcome::SessionMissing => {
                    self.finish_failed(run_id, failed_payload("session not found".to_string()))
                        .await;
                    return;
                }
                TerminalOutcome::TerminalPersistFailed { error, pending } => {
                    if attempt + 1 < attempts {
                        self.inner.metrics.terminal_persist_backoff();
                        tokio::time::sleep(self.inner.config.terminal_persist_retry_delay).await;
                    } else {
                        tracing::error!(
                            run_id,
                            error = %truncate_for_log(&error, 256),
                            "completed terminal could not be persisted after bounded retries; \
                             parked as pending"
                        );
                        self.inner.metrics.runs_terminal(TerminalStatus::Completed);
                        self.register_pending_terminal(run_id, *pending);
                        self.mark_terminal(run_id);
                        self.spawn_terminal_retry(run_id.to_string());
                        return;
                    }
                }
            }
        }
    }

    /// One durable attempt of the completed terminal delta. The started/
    /// stopping race guard runs under the store lock: a stop that landed
    /// before this commit wins (the typed cancellation path commits instead).
    async fn commit_completed_once(
        &self,
        run_id: &str,
        session_id: &str,
        output_text: &str,
    ) -> TerminalOutcome {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let session_id_for_commit = session_id.to_string();
        let output_text_for_commit = output_text.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let _serial = service.inner.commit_gate.lock();
            let persistence = service.persistence_handle();
            let terminal_timestamp = timestamp();
            let reserved = {
                let store = service.inner.store.read();
                let Some(run) = store.runs.get(&run_id_for_commit) else {
                    return TerminalOutcome::NotActive;
                };
                if run.status != "started" {
                    return TerminalOutcome::NotActive;
                }
                let Some(session) = store.sessions.get(&session_id_for_commit) else {
                    return TerminalOutcome::SessionMissing;
                };
                let provider_step_present = run
                    .events
                    .iter()
                    .any(|event| event.event == "model.completed");
                if provider_step_present {
                    let mut completed_event = event_candidate(
                        run,
                        "run.completed",
                        json!({
                            "status": "completed",
                            "output": {"text": output_text_for_commit},
                            "usage": {
                                "input_tokens": 0,
                                "output_tokens": 0,
                                "total_tokens": 0
                            }
                        }),
                        max_event_bytes,
                    );
                    completed_event.timestamp = terminal_timestamp;
                    (None, vec![completed_event])
                } else {
                    let ordinal = next_message_ordinal(session);
                    let message = SessionMessage {
                        id: uuid::Uuid::new_v4().to_string(),
                        session_id: session_id_for_commit.clone(),
                        role: "assistant".to_string(),
                        content: decode_message_content(&JsonValue::String(
                            output_text_for_commit.clone(),
                        )),
                        created_at: timestamp(),
                        run_id: Some(run_id_for_commit.clone()),
                        finish_reason: Some("stop".to_string()),
                        name: None,
                        tool_call_id: None,
                        parent_message_id: None,
                        token_estimate: None,
                        metadata: JsonValue::Null,
                        ordinal: Some(ordinal),
                    };
                    let mut delta_event = event_candidate(
                        run,
                        "message.delta",
                        json!({
                            "message_id": message.id,
                            "delta": output_text_for_commit,
                            "role": "assistant"
                        }),
                        max_event_bytes,
                    );
                    delta_event.timestamp = terminal_timestamp;
                    let mut completed_event = event_candidate(
                        run,
                        "run.completed",
                        json!({
                            "status": "completed",
                            "output": {"message": message},
                            "usage": {
                                "input_tokens": 0,
                                "output_tokens": 0,
                                "total_tokens": 0
                            }
                        }),
                        max_event_bytes,
                    );
                    completed_event.timestamp = terminal_timestamp;
                    completed_event.seq = delta_event.seq + 1;
                    (Some(message), vec![delta_event, completed_event])
                }
            };
            let (assistant_message, events) = reserved;
            match terminal_commit(
                persistence.as_deref(),
                &run_id_for_commit,
                &session_id_for_commit,
                "completed",
                &events,
                assistant_message.as_ref(),
            ) {
                Ok(seqs) => {
                    let mut store = service.inner.store.write();
                    apply_terminal(
                        &mut store,
                        &run_id_for_commit,
                        "completed",
                        &events,
                        &seqs,
                        assistant_message.as_ref(),
                        max_events_per_run,
                    );
                    let sender = store
                        .runs
                        .get(&run_id_for_commit)
                        .and_then(|run| run.sender.clone());
                    drop(store);
                    if let Some(sender) = sender {
                        for event in events {
                            let _ = sender.send(event);
                        }
                    }
                    TerminalOutcome::Committed
                }
                Err(error) => TerminalOutcome::TerminalPersistFailed {
                    error: error.to_string(),
                    pending: Box::new(PendingTerminal {
                        to_status: "completed".to_string(),
                        session_id: Some(session_id_for_commit),
                        events,
                        assistant_message,
                        deadline: std::time::Instant::now() + retry_window,
                    }),
                },
            }
        })
        .await
        .expect("terminal commit task must complete")
    }

    /// Cancels a run with the typed reason through a durable-first terminal
    /// commit: `run.terminal` commits the cancellation event and the status
    /// change in one transaction, and only then is the event published. The
    /// commit is retried with bounded backoff; on final failure the
    /// cancellation is handed to the bounded retry loop (`terminal_pending`),
    /// which commits it durably then broadcasts when storage recovers.
    pub(crate) async fn finish_cancelled(&self, run_id: &str, reason: &str) {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        for attempt in 0..attempts {
            match self.commit_cancelled_once(run_id, reason).await {
                TerminalOutcome::Committed => {
                    self.inner.metrics.runs_terminal(TerminalStatus::Cancelled);
                    tracing::info!(run_id, reason, "cancelled terminal committed durably");
                    self.mark_terminal(run_id);
                    return;
                }
                TerminalOutcome::TerminalPersistFailed { error, pending } => {
                    if attempt + 1 < attempts {
                        self.inner.metrics.terminal_persist_backoff();
                        tokio::time::sleep(self.inner.config.terminal_persist_retry_delay).await;
                    } else {
                        tracing::error!(
                            run_id,
                            reason,
                            error = %truncate_for_log(&error, 256),
                            "failed to commit cancellation durably after bounded retries; \
                             retrying within the bounded window"
                        );
                        self.inner.metrics.runs_terminal(TerminalStatus::Cancelled);
                        self.register_pending_terminal(run_id, *pending);
                        self.mark_terminal(run_id);
                        self.spawn_terminal_retry(run_id.to_string());
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    /// One durable attempt of the `run.cancelled` transition.
    async fn commit_cancelled_once(&self, run_id: &str, reason: &str) -> TerminalOutcome {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let reason_for_commit = reason.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let _serial = service.inner.commit_gate.lock();
            let persistence = service.persistence_handle();
            let event = {
                let store = service.inner.store.read();
                let Some(run) = store.runs.get(&run_id_for_commit) else {
                    return TerminalOutcome::NotActive;
                };
                if run_is_terminal(&run.status) {
                    return TerminalOutcome::NotActive;
                }
                event_candidate(
                    run,
                    "run.cancelled",
                    json!({"status":"cancelled", "reason":reason_for_commit}),
                    max_event_bytes,
                )
            };
            let events = vec![event.clone()];
            match terminal_commit(
                persistence.as_deref(),
                &run_id_for_commit,
                "",
                "cancelled",
                &events,
                None,
            ) {
                Ok(seqs) => {
                    let mut store = service.inner.store.write();
                    apply_terminal(
                        &mut store,
                        &run_id_for_commit,
                        "cancelled",
                        &events,
                        &seqs,
                        None,
                        max_events_per_run,
                    );
                    let sender = store
                        .runs
                        .get(&run_id_for_commit)
                        .and_then(|run| run.sender.clone());
                    drop(store);
                    if let Some(sender) = sender {
                        let _ = sender.send(event);
                    }
                    TerminalOutcome::Committed
                }
                Err(error) => TerminalOutcome::TerminalPersistFailed {
                    error: error.to_string(),
                    pending: Box::new(PendingTerminal {
                        to_status: "cancelled".to_string(),
                        session_id: None,
                        events: vec![event],
                        assistant_message: None,
                        deadline: std::time::Instant::now() + retry_window,
                    }),
                },
            }
        })
        .await
        .expect("terminal commit task must complete")
    }

    /// Fails a run through a durable-first terminal commit: `run.terminal`
    /// commits the failure event and the status change in one transaction,
    /// and only then is the event published. The commit is retried with
    /// bounded backoff; on final failure the failure is handed to the bounded
    /// retry loop (`terminal_pending`), which commits it durably then
    /// broadcasts when storage recovers.
    pub(crate) async fn finish_failed(&self, run_id: &str, data: JsonValue) {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        for attempt in 0..attempts {
            match self.commit_failed_once(run_id, data.clone()).await {
                TerminalOutcome::Committed => {
                    self.inner.metrics.runs_terminal(TerminalStatus::Failed);
                    self.mark_terminal(run_id);
                    return;
                }
                TerminalOutcome::TerminalPersistFailed { error, pending } => {
                    if attempt + 1 < attempts {
                        self.inner.metrics.terminal_persist_backoff();
                        tokio::time::sleep(self.inner.config.terminal_persist_retry_delay).await;
                    } else {
                        tracing::error!(
                            run_id,
                            error = %truncate_for_log(&error, 256),
                            "failed to commit failure durably after bounded retries; \
                             retrying within the bounded window"
                        );
                        self.inner.metrics.runs_terminal(TerminalStatus::Failed);
                        self.register_pending_terminal(run_id, *pending);
                        self.mark_terminal(run_id);
                        self.spawn_terminal_retry(run_id.to_string());
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    /// One durable attempt of the `run.failed` transition.
    async fn commit_failed_once(&self, run_id: &str, data: JsonValue) -> TerminalOutcome {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let _serial = service.inner.commit_gate.lock();
            let persistence = service.persistence_handle();
            let event = {
                let store = service.inner.store.read();
                let Some(run) = store.runs.get(&run_id_for_commit) else {
                    return TerminalOutcome::NotActive;
                };
                if run_is_terminal(&run.status) {
                    return TerminalOutcome::NotActive;
                }
                event_candidate(run, "run.failed", data, max_event_bytes)
            };
            let events = vec![event.clone()];
            match terminal_commit(
                persistence.as_deref(),
                &run_id_for_commit,
                "",
                "failed",
                &events,
                None,
            ) {
                Ok(seqs) => {
                    let mut store = service.inner.store.write();
                    apply_terminal(
                        &mut store,
                        &run_id_for_commit,
                        "failed",
                        &events,
                        &seqs,
                        None,
                        max_events_per_run,
                    );
                    let sender = store
                        .runs
                        .get(&run_id_for_commit)
                        .and_then(|run| run.sender.clone());
                    drop(store);
                    if let Some(sender) = sender {
                        let _ = sender.send(event);
                    }
                    TerminalOutcome::Committed
                }
                Err(error) => TerminalOutcome::TerminalPersistFailed {
                    error: error.to_string(),
                    pending: Box::new(PendingTerminal {
                        to_status: "failed".to_string(),
                        session_id: None,
                        events: vec![event],
                        assistant_message: None,
                        deadline: std::time::Instant::now() + retry_window,
                    }),
                },
            }
        })
        .await
        .expect("terminal commit task must complete")
    }

    fn resolve_provider_profile(
        &self,
        provider: Option<&str>,
    ) -> Result<ProviderProfile, ProviderProfileError> {
        let provider = provider.unwrap_or("local-agent");
        if let Some(profile) = self.inner.provider_profiles.read().get(provider).cloned() {
            return Ok(profile);
        }
        ProviderProfile::builtin(provider.to_string())
    }

    fn make_admitted_context(
        &self,
        admission: &ContextAdmissionInput,
        snapshot: &RunAdmissionSnapshot,
        coding_system_prompt: String,
    ) -> RunContext {
        let provider_options = snapshot.provider_profile.options().clone();
        let tool_schemas = snapshot.registry.schemas();
        let limits = effective_limits_json(&snapshot.limits, &self.inner.config);
        let mut metadata = Map::new();
        metadata.insert(
            "schema_version".to_string(),
            JsonValue::from(RUN_CONTEXT_METADATA_VERSION),
        );
        metadata.insert(
            "run_id".to_string(),
            JsonValue::String(admission.run_id.clone()),
        );
        metadata.insert(
            "session_id".to_string(),
            JsonValue::String(admission.session_id.clone()),
        );
        metadata.insert(
            "registry_identity".to_string(),
            JsonValue::String(snapshot.registry.identity().to_string()),
        );
        metadata.insert(
            "toolset_hash".to_string(),
            JsonValue::String(snapshot.registry.identity().to_string()),
        );
        metadata.insert(
            "approval_settings".to_string(),
            serde_json::to_value(&self.inner.config.approvals)
                .expect("approval settings must be serializable"),
        );
        metadata.insert(
            "provider_profile".to_string(),
            JsonValue::String(snapshot.provider_profile.name.clone()),
        );
        metadata.insert(
            "message_id".to_string(),
            JsonValue::String(admission.message_id.clone()),
        );
        let created_at_ms = timestamp();
        let timeout_ms =
            u64::try_from(self.inner.config.run_timeout.as_millis()).unwrap_or(u64::MAX);
        metadata.insert("created_at_ms".to_string(), JsonValue::from(created_at_ms));
        metadata.insert(
            "deadline_at_ms".to_string(),
            JsonValue::from(created_at_ms.saturating_add(timeout_ms)),
        );
        RunContext {
            run_id: admission.run_id.clone(),
            session_id: admission.session_id.clone(),
            parent_run_id: admission.parent_run_id.clone(),
            platform: admission.platform.clone(),
            input: admission.input.clone(),
            messages: serde_json::to_value(&admission.messages)
                .expect("admitted session messages must be serializable"),
            system_prompt: admission.system_prompt.clone(),
            model: admission.model.clone(),
            provider: admission.provider.clone(),
            provider_options,
            tool_schemas,
            limits,
            metadata: JsonValue::Object(metadata),
            coding_system_prompt: Some(coding_system_prompt),
        }
    }

    fn cache_context(&self, context: RunContext, registry: Option<ToolRegistrySnapshot>) {
        let active_ids: HashSet<String> = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .iter()
            .filter_map(|(run_id, handle)| (!handle.is_terminal()).then_some(run_id.clone()))
            .collect();
        let cache_capacity = self.inner.context_cache_capacity;
        let mut evicted = None;
        {
            let mut contexts = self.inner.contexts.lock().expect("contexts lock");
            if !contexts.contains_key(&context.run_id) && contexts.len() >= cache_capacity {
                evicted = contexts
                    .keys()
                    .find(|run_id| !active_ids.contains(*run_id))
                    .cloned();
                if let Some(run_id) = &evicted {
                    contexts.remove(run_id);
                }
            }
            contexts.insert(context.run_id.clone(), context.clone());
        }
        let mut registries = self
            .inner
            .context_registries
            .lock()
            .expect("context registries lock");
        if let Some(run_id) = evicted {
            registries.remove(&run_id);
        }
        if let Some(registry) = registry {
            if !registries.contains_key(&context.run_id)
                && registries.len() >= cache_capacity
                && let Some(run_id) = registries
                    .keys()
                    .find(|run_id| !active_ids.contains(*run_id))
                    .cloned()
            {
                registries.remove(&run_id);
            }
            registries.insert(context.run_id, registry);
        } else {
            registries.remove(&context.run_id);
        }
    }

    fn load_persisted_context(&self, run_id: &str) -> Result<RunContext, RunContextError> {
        let Some(persistence) = &self.inner.persistence else {
            return Err(RunContextError::Missing {
                run_id: run_id.to_string(),
            });
        };
        let run_data = persistence
            .run_get(run_id)
            .map_err(|error| RunContextError::Persistence(format!("read run context: {error}")))?;
        let run_row =
            crate::sqlite_storage_rows::sqlite_storage_first_row(&run_data).ok_or_else(|| {
                RunContextError::Missing {
                    run_id: run_id.to_string(),
                }
            })?;
        if admission_run_str(&run_row, ADMISSION_RUN_COL_ID) != Some(run_id) {
            return Err(invalid_context_metadata(
                run_id,
                "run record id does not match the requested run",
            ));
        }
        let persisted_input = admission_run_str(&run_row, ADMISSION_RUN_COL_INPUT_JSON)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_context_metadata(run_id, "run context snapshot is missing"))?;
        let envelope: JsonValue = serde_json::from_str(persisted_input).map_err(|error| {
            invalid_context_metadata(run_id, &format!("run context snapshot is invalid: {error}"))
        })?;
        if envelope.get("schema_version").and_then(JsonValue::as_u64)
            != Some(RUN_CONTEXT_METADATA_VERSION)
        {
            return Err(invalid_context_metadata(
                run_id,
                "unsupported run context snapshot schema version",
            ));
        }
        let context_value = envelope
            .get(RUN_CONTEXT_STORAGE_KEY)
            .cloned()
            .ok_or_else(|| invalid_context_metadata(run_id, "run context snapshot is missing"))?;
        let mut context: RunContext = serde_json::from_value(context_value).map_err(|error| {
            invalid_context_metadata(
                run_id,
                &format!("run context snapshot is incomplete: {error}"),
            )
        })?;
        context.messages = self.reconstruct_admitted_messages(&context)?;
        verify_context_metadata(&context)?;
        if context.run_id != run_id {
            return Err(invalid_context_metadata(
                run_id,
                "run id does not match the persisted context",
            ));
        }
        let row_session_id = admission_run_str(&run_row, ADMISSION_RUN_COL_SESSION_ID)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_context_metadata(run_id, "run session id is missing"))?;
        if context.session_id != row_session_id {
            return Err(invalid_context_metadata(
                run_id,
                "session id does not match the run record",
            ));
        }
        if context.parent_run_id != optional_string(run_row.get(ADMISSION_RUN_COL_PARENT_RUN_ID)) {
            return Err(invalid_context_metadata(
                run_id,
                "parent run id does not match the run record",
            ));
        }
        if context.provider != optional_string(run_row.get(ADMISSION_RUN_COL_PROVIDER)) {
            return Err(invalid_context_metadata(
                run_id,
                "provider does not match the run record",
            ));
        }
        if admission_run_str(&run_row, ADMISSION_RUN_COL_MODEL) != Some(context.model.as_str()) {
            return Err(invalid_context_metadata(
                run_id,
                "model does not match the run record",
            ));
        }
        let registry_identity = context
            .metadata
            .get("registry_identity")
            .and_then(JsonValue::as_str)
            .expect("context metadata validation checked registry identity");
        if admission_run_str(&run_row, ADMISSION_RUN_COL_SCRIPT_HASH) != Some(registry_identity) {
            return Err(invalid_context_metadata(
                run_id,
                "registry identity does not match the run record",
            ));
        }
        Ok(context)
    }

    /// Builds the canonical structured run context (gateway-api plan 4.2)
    /// that is passed as the sole argument to the exported `run(context)`
    /// callable.
    fn build_run_context(&self, run_id: &str) -> VmValue {
        let context = self
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .get(run_id)
            .cloned()
            .expect("run context was verified before execution");
        context.to_vm_value()
    }
}

fn workspace_identity_json(
    binding: Option<&WorkspaceBinding>,
    legacy_root: Option<&std::path::Path>,
    request_selector: Option<&str>,
) -> Result<Option<String>, AdmitError> {
    if binding.is_none() && legacy_root.is_none() && request_selector.is_none() {
        return Ok(None);
    }

    let mut identity = binding
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| {
            AdmitError::Invalid(format!("workspace identity serialization failed: {error}"))
        })?
        .unwrap_or_else(|| json!({}));
    let object = identity.as_object_mut().ok_or_else(|| {
        AdmitError::Invalid("workspace identity serialization returned a non-object".to_string())
    })?;
    object.insert(
        "request_selector_present".to_string(),
        JsonValue::Bool(request_selector.is_some()),
    );
    object.insert(
        "request_selector".to_string(),
        JsonValue::String(request_selector.unwrap_or_default().to_string()),
    );
    if let Some(root) = legacy_root {
        object.insert(
            "legacy_root".to_string(),
            JsonValue::String(root.to_string_lossy().into_owned()),
        );
    }
    serde_json::to_string(&identity).map(Some).map_err(|error| {
        AdmitError::Invalid(format!("workspace identity serialization failed: {error}"))
    })
}

/// Validates the service-owned idempotency-key grammar before any admission
/// storage command runs. A Rust `&str` is already valid UTF-8; its byte length
/// is used deliberately so multibyte keys consume their actual serialized
/// budget. The accepted grammar is one or more visible Unicode scalar values:
/// whitespace and control characters are rejected.
fn validate_idempotency_key(key: Option<&str>) -> Result<(), String> {
    let Some(key) = key else {
        return Ok(());
    };
    validate_visible_name(key, "idempotency key", MAX_IDEMPOTENCY_KEY_BYTES)
}

fn validate_idempotency_pair(key: Option<&str>, hash: Option<&str>) -> Result<(), String> {
    validate_idempotency_key(key)?;
    match (key, hash) {
        (None, None | Some("")) => Ok(()),
        (None, Some(_)) => Err("idempotency hash requires an idempotency key".to_string()),
        (Some(_), None | Some("")) => {
            Err("idempotency hash is required when an idempotency key is present".to_string())
        }
        (Some(_), Some(hash)) => validate_request_hash(hash),
    }
}

fn admission_run_str(row: &[JsonValue], index: usize) -> Option<&str> {
    row.get(index).and_then(JsonValue::as_str)
}

fn persisted_run_context_json(context: &RunContext) -> Result<String, AdmitError> {
    verify_context_metadata(context).map_err(admit_context_error)?;
    let mut snapshot = context.clone();
    snapshot.messages = JsonValue::Array(Vec::new());
    let envelope = canonicalize_json_value(&json!({
        "schema_version": RUN_CONTEXT_METADATA_VERSION,
        RUN_CONTEXT_STORAGE_KEY: snapshot,
    }));
    let serialized = serde_json::to_string(&envelope).map_err(|error| {
        AdmitError::Invalid(format!("run context serialization failed: {error}"))
    })?;
    if serialized.len() > MAX_RUN_CONTEXT_STORAGE_BYTES {
        return Err(AdmitError::Invalid(
            "run context snapshot exceeds the size limit".to_string(),
        ));
    }
    Ok(serialized)
}

fn compaction_error(code: &str, message: &str) -> JsonValue {
    json!({
        "ok": false,
        "error": { "code": code, "message": message },
    })
}

fn load_durable_compaction_snapshot(
    persistence: &GatewayPersistence,
    session_id: &str,
) -> Result<(i64, Vec<JsonValue>, String), String> {
    let session_data = persistence
        .session_get(session_id)
        .map_err(|error| format!("read compaction session: {error}"))?;
    let session_row = crate::sqlite_storage_rows::sqlite_storage_first_row(&session_data)
        .ok_or_else(|| "compaction session row is missing".to_string())?;
    let generation = session_row
        .get(7)
        .and_then(JsonValue::as_i64)
        .ok_or_else(|| "compaction session generation is missing".to_string())?;

    let mut history = Vec::new();
    let mut after_ordinal = 0_i64;
    loop {
        let page = persistence
            .message_list(session_id, after_ordinal)
            .map_err(|error| format!("read compaction message page: {error}"))?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&page)?;
        if rows.is_empty() {
            break;
        }
        let page_len = rows.len();
        for row in rows {
            if row.len() < 14 {
                return Err("compaction message row is incomplete".to_string());
            }
            let ordinal = row[2]
                .as_i64()
                .ok_or_else(|| "compaction message ordinal is invalid".to_string())?;
            let role = row[3]
                .as_str()
                .ok_or_else(|| "compaction message role is invalid".to_string())?;
            let content_json = row[4]
                .as_str()
                .ok_or_else(|| "compaction message content is invalid".to_string())?;
            let content_value: JsonValue = serde_json::from_str(content_json)
                .map_err(|error| format!("decode compaction message content: {error}"))?;
            let mut message = json!({
                "id": row[0],
                "session_id": row[1],
                "ordinal": ordinal,
                "role": role,
                "content": decode_message_content(&content_value),
                "compacted": row[9].as_i64().unwrap_or_default(),
            });
            if let Some(object) = message.as_object_mut() {
                for (column, field) in [(5, "name"), (6, "tool_call_id"), (7, "parent_message_id")]
                {
                    if let Some(value) = row
                        .get(column)
                        .and_then(JsonValue::as_str)
                        .filter(|v| !v.is_empty())
                    {
                        object.insert(field.to_string(), JsonValue::String(value.to_string()));
                    }
                }
            }
            history.push(message);
            after_ordinal = ordinal;
        }
        if page_len < 128 {
            break;
        }
    }

    let mut previous_summary = String::new();
    let latest = persistence
        .compaction_latest(session_id)
        .map_err(|error| format!("read previous compaction summary: {error}"))?;
    if let Ok(rows) = crate::sqlite_storage_rows::sqlite_storage_rows(&latest) {
        for row in rows {
            if row.get(10).and_then(JsonValue::as_str) != Some("committed") {
                continue;
            }
            if let Some(summary_json) = row.get(7).and_then(JsonValue::as_str)
                && let Ok(summary) = serde_json::from_str::<JsonValue>(summary_json)
            {
                previous_summary = summary
                    .get("text")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
            }
            break;
        }
    }
    Ok((generation, history, previous_summary))
}

fn execute_rss_compaction(
    persistence: &GatewayPersistence,
    decision_runner: &AgentRunner,
    decision: &JsonValue,
    cancellation: &RunCancellation,
) -> Result<(), String> {
    let commands = decision
        .get("commands")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "RSS compaction plan omitted storage commands".to_string())?;
    if commands.len() != 3 {
        return Err(
            "RSS compaction plan did not emit the start/compact/commit sequence".to_string(),
        );
    }
    let compaction_id = commands[0]
        .get("payload")
        .and_then(|payload| payload.get("id"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "RSS compaction start omitted its identifier".to_string())?;
    let mut started = false;
    for command in commands {
        if cancellation.requested().is_some() || cancellation.deadline_passed() {
            if started {
                fail_rss_compaction(
                    persistence,
                    decision_runner,
                    compaction_id,
                    "compaction cancelled",
                )?;
            }
            return Err("run was cancelled during compaction".to_string());
        }
        let op = command
            .get("op")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "RSS compaction command omitted its operation".to_string())?;
        let payload = command
            .get("payload")
            .ok_or_else(|| "RSS compaction command omitted its payload".to_string())?;
        let result = match op {
            "compaction.start" => persistence.compaction_start(payload),
            "message.compact" => persistence.message_compact(payload),
            "compaction.commit" => persistence.compaction_commit(payload),
            _ => {
                return Err(format!(
                    "RSS compaction emitted unsupported storage operation {op}"
                ));
            }
        };
        match result {
            Ok(data) => {
                if op == "compaction.start" {
                    let rows = data.get("rows").and_then(JsonValue::as_array);
                    if rows.is_none_or(Vec::is_empty) {
                        return Err("compaction.start returned no pending durable row".to_string());
                    }
                    started = true;
                }
                if op == "compaction.commit" {
                    started = false;
                }
            }
            Err(error) => {
                if started {
                    fail_rss_compaction(
                        persistence,
                        decision_runner,
                        compaction_id,
                        &error.to_string(),
                    )?;
                }
                return Err(format!("execute RSS storage command {op}: {error}"));
            }
        }
    }
    Ok(())
}

fn fail_rss_compaction(
    persistence: &GatewayPersistence,
    decision_runner: &AgentRunner,
    compaction_id: &str,
    error_message: &str,
) -> Result<(), String> {
    let decision = decision_runner
        .run_with_context(json_to_vm_value(&json!({
            "command": "fail",
            "compaction_id": compaction_id,
            "error_message": truncate_utf8_chars(error_message, 1024).0,
            "completed_at_ms": timestamp(),
        })))
        .map_err(|error| format!("RSS compaction failure decision failed: {error}"))?;
    let failure = vm_value_to_json(&decision);
    let payload = failure
        .get("payload")
        .ok_or_else(|| "RSS compaction failure omitted its storage payload".to_string())?;
    persistence
        .compaction_fail(payload)
        .map(|_| ())
        .map_err(|error| format!("persist RSS compaction failure: {error}"))
}

fn normalize_loaded_session_messages(store: &Arc<RwLock<GatewayStore>>) {
    let mut store = store.write();
    for session in store.sessions.values_mut() {
        for message in &mut session.messages {
            if let Some(input) = admission_input_from_message_content(&message.content) {
                message.content = decode_message_content(&input);
            }
        }
    }
}

fn admission_input_from_message_content(content: &JsonValue) -> Option<JsonValue> {
    if let Some(input) = envelope_run_input(content) {
        return Some(input);
    }
    let text = content
        .as_array()
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(JsonValue::as_str)?;
    let parsed: JsonValue = serde_json::from_str(text).ok()?;
    envelope_run_input(&parsed)
}

fn envelope_run_input(value: &JsonValue) -> Option<JsonValue> {
    let envelope = value.as_object()?;
    if envelope.get("schema_version").and_then(JsonValue::as_u64)
        != Some(RUN_CONTEXT_METADATA_VERSION)
    {
        return None;
    }
    envelope
        .get(RUN_CONTEXT_STORAGE_KEY)
        .and_then(JsonValue::as_object)
        .and_then(|context| context.get("input"))
        .cloned()
}

fn admit_context_error(error: RunContextError) -> AdmitError {
    match error {
        RunContextError::Persistence(message) => AdmitError::Persistence(message),
        other => AdmitError::Invalid(other.to_string()),
    }
}

struct HandleCancelFlag {
    cancel: RunCancellation,
}

impl CancellationFlag for HandleCancelFlag {
    fn is_cancelled(&self) -> bool {
        self.cancel.requested().is_some()
    }
}

struct ServiceDurableLifecycle {
    events: Arc<dyn DurableEventCommitter>,
}

impl DurableToolLifecycle for ServiceDurableLifecycle {
    fn assert_active_run(&self, _run_id: &str) -> Result<(), LifecycleError> {
        if self.events.is_terminal() {
            Err(LifecycleError::InactiveRun)
        } else {
            Ok(())
        }
    }

    fn prepare_parent(
        &self,
        _run_id: &str,
        call_id: &str,
        tool_name: &str,
    ) -> Result<(), LifecycleError> {
        self.events
            .prepare_tool_parent(call_id, tool_name)
            .map(|_| ())
            .map_err(map_event_commit_error)
    }

    fn replay_result(
        &self,
        _run_id: &str,
        call_id: &str,
        tool_name: &str,
    ) -> Result<Option<serde_json::Value>, LifecycleError> {
        match self.events.replay_durable_tool_result(call_id, tool_name) {
            Ok(Some(result)) => Ok(Some(
                serde_json::to_value(&result).unwrap_or_else(|_| json!({})),
            )),
            Ok(None) => Ok(None),
            Err(error) => Err(map_event_commit_error(error)),
        }
    }

    fn commit_started(&self, record: &DurableStarted) -> Result<(), LifecycleError> {
        let data = json!({
            "tool_call_id": record.call_id,
            "name": record.tool_name,
            "argument_digest": record.argument_digest,
            "registry_identity": record.registry_identity,
            "risk_class": record.risk_class.as_str(),
            "generation": record.generation,
        });
        self.events
            .commit_pair(("tool.requested", data.clone()), ("tool.started", data))
            .map_err(|error| match error {
                EventCommitError::PersistFailed(message) => {
                    LifecycleError::StartedCommitFailed(message)
                }
                other => map_event_commit_error(other),
            })
    }

    fn commit_result(
        &self,
        call_id: &str,
        result: &serde_json::Value,
    ) -> Result<serde_json::Value, LifecycleError> {
        let tool_result = canonical_tool_result(result)?;
        let event_type = if tool_result.ok {
            "tool.completed"
        } else {
            "tool.failed"
        };
        let mut data = json!({
            "tool_call_id": call_id,
            "ok": tool_result.ok,
            "truncated": tool_result.truncated,
        });
        if let Some(error) = &tool_result.error {
            data["error_code"] = json!(error.code);
        }
        if !tool_result.artifacts.is_empty() {
            data["artifacts"] = json!(tool_result.artifacts);
        }
        self.events
            .commit_step("tool.output", data.clone(), Some(&tool_result))
            .map_err(|error| match error {
                EventCommitError::PersistFailed(message) => {
                    LifecycleError::ResultCommitFailed(message)
                }
                other => map_event_commit_error(other),
            })?;
        self.events
            .commit_step(event_type, data, Some(&tool_result))
            .map_err(|error| match error {
                EventCommitError::PersistFailed(message) => {
                    LifecycleError::ResultCommitFailed(message)
                }
                other => map_event_commit_error(other),
            })?;
        Ok(result.clone())
    }

    fn interrupt(&self, call_id: &str) -> Result<(), LifecycleError> {
        let tool_result =
            ToolResult::failure("interrupted_effect", "effect interrupted by restart");
        self.events
            .commit_step(
                "tool.failed",
                json!({
                    "tool_call_id": call_id,
                    "error_code": "interrupted_effect",
                    "ok": false,
                }),
                Some(&tool_result),
            )
            .map_err(map_event_commit_error)
    }
}

fn map_event_commit_error(error: EventCommitError) -> LifecycleError {
    match error {
        EventCommitError::Terminal => LifecycleError::InactiveRun,
        EventCommitError::Cancelled => LifecycleError::Cancelled,
        EventCommitError::MissingParent => LifecycleError::MissingParent,
        EventCommitError::PersistFailed(message) => LifecycleError::ResultCommitFailed(message),
        EventCommitError::Corrupt(message) => LifecycleError::ResultCommitFailed(message),
    }
}

fn canonical_tool_result(result: &JsonValue) -> Result<ToolResult, LifecycleError> {
    let ok = match result.get("ok") {
        Some(JsonValue::Bool(ok)) => *ok,
        _ => {
            return Err(LifecycleError::InvalidMetadata(
                "`ok` is required".to_string(),
            ));
        }
    };
    if ok {
        let content = result
            .get("content")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                LifecycleError::InvalidMetadata(
                    "success result requires string `content`".to_string(),
                )
            })?;
        let mut tool_result = ToolResult::success(
            content.to_string(),
            result.get("data").cloned().unwrap_or_else(|| json!({})),
        );
        tool_result.truncated = result
            .get("truncated")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        if let Some(artifacts) = result.get("artifacts").and_then(JsonValue::as_array) {
            tool_result.artifacts = artifacts
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect();
        }
        Ok(tool_result)
    } else {
        let error = result.get("error");
        let code = error
            .and_then(|value| value.get("code"))
            .and_then(JsonValue::as_str)
            .filter(|code| !code.is_empty())
            .ok_or_else(|| {
                LifecycleError::InvalidMetadata(
                    "failure result requires string `error.code`".to_string(),
                )
            })?;
        let message = error
            .and_then(|value| value.get("message"))
            .and_then(JsonValue::as_str)
            .unwrap_or("tool failed");
        let content = result
            .get("content")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let data = result.get("data").cloned().unwrap_or_else(|| json!({}));
        let truncated = result
            .get("truncated")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        let mut tool_result = ToolResult::failure_with(code, message, content, data, truncated);
        if let Some(artifacts) = result.get("artifacts").and_then(JsonValue::as_array) {
            tool_result.artifacts = artifacts
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect();
        }
        Ok(tool_result)
    }
}

struct ServiceEventCommitter {
    store: Arc<RwLock<GatewayStore>>,
    persistence: Option<Arc<GatewayPersistence>>,
    run_id: String,
    handle: Weak<RunHandle>,
    max_event_bytes: usize,
    max_events_per_run: usize,
    commit_gate: Arc<ParkingMutex<()>>,
    service: Weak<AgentServiceInner>,
}

impl DurableEventCommitter for ServiceEventCommitter {
    fn is_terminal(&self) -> bool {
        self.handle
            .upgrade()
            .map(|handle| handle.is_terminal())
            .unwrap_or(true)
    }

    fn stop_requested(&self) -> bool {
        self.handle
            .upgrade()
            .map(|handle| handle.cancel.requested().is_some())
            .unwrap_or(true)
    }

    fn commit(&self, event_type: &str, data: JsonValue) -> Result<(), EventCommitError> {
        self.commit_step(event_type, data, None)
    }

    fn prepare_tool_parent(
        &self,
        tool_call_id: &str,
        name: &str,
    ) -> Result<(String, String), EventCommitError> {
        let store = self.store.read();
        let Some(run) = store.runs.get(&self.run_id) else {
            return Err(EventCommitError::Terminal);
        };
        if run_is_terminal(&run.status) {
            return Err(EventCommitError::Terminal);
        }
        match lookup_tool_call_parent(&store, &run.session_id, tool_call_id) {
            Some((parent_id, stored_name)) if stored_name == name => Ok((parent_id, stored_name)),
            _ => Err(EventCommitError::MissingParent),
        }
    }

    fn replay_durable_tool_result(
        &self,
        tool_call_id: &str,
        name: &str,
    ) -> Result<Option<ToolResult>, EventCommitError> {
        let Some(inner) = self.service.upgrade() else {
            return Err(EventCommitError::Terminal);
        };
        let _serial = self.commit_gate.lock();
        AgentService { inner }.replay_durable_tool_result(&self.run_id, tool_call_id, name)
    }

    fn commit_step(
        &self,
        event_type: &str,
        data: JsonValue,
        result: Option<&ToolResult>,
    ) -> Result<(), EventCommitError> {
        if self.is_terminal() {
            return Err(EventCommitError::Terminal);
        }
        let _serial = self.commit_gate.lock();
        let tool_call_id = data
            .get("tool_call_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let event_id = if tool_call_id.is_empty() {
            String::new()
        } else {
            durable_tool_event_id(&self.run_id, &tool_call_id, event_type)
        };
        let attach_message = result.is_some()
            && !tool_call_id.is_empty()
            && matches!(event_type, "tool.output" | "tool.completed" | "tool.failed");
        let message_id = if attach_message {
            durable_message_id(&self.run_id, "result", &tool_call_id)
        } else {
            String::new()
        };
        let content = result
            .filter(|_| attach_message)
            .map(|result| tool_result_content_json(&tool_call_id, result));
        let reserved = {
            let store = self.store.read();
            let Some(run) = store.runs.get(&self.run_id) else {
                return Err(EventCommitError::Terminal);
            };
            if run_is_terminal(&run.status) {
                return Err(EventCommitError::Terminal);
            }
            if !event_id.is_empty() && run.events.iter().any(|event| event.event_id == event_id) {
                return Ok(());
            }
            let session_id = run.session_id.clone();
            let (parent_message_id, tool_name) = if attach_message {
                match lookup_tool_call_parent(&store, &session_id, &tool_call_id) {
                    Some(pair) => pair,
                    None => return Err(EventCommitError::MissingParent),
                }
            } else {
                (String::new(), String::new())
            };
            if data.get("validation_only").and_then(JsonValue::as_bool) == Some(true) {
                if self.stop_requested() {
                    return Err(EventCommitError::Cancelled);
                }
                let parent = store
                    .sessions
                    .get(&session_id)
                    .and_then(|session| {
                        session
                            .messages
                            .iter()
                            .find(|message| message.id == parent_message_id)
                    })
                    .ok_or(EventCommitError::MissingParent)?;
                if event_type != "tool.failed"
                    || result.is_none_or(|result| result.ok)
                    || parent.run_id.as_deref() != Some(self.run_id.as_str())
                    || data
                        .get("name")
                        .and_then(JsonValue::as_str)
                        .is_some_and(|name| name != tool_name)
                    || run.events.iter().any(|event| {
                        event.event == "tool.started"
                            && event.data.get("tool_call_id").and_then(JsonValue::as_str)
                                == Some(tool_call_id.as_str())
                    })
                {
                    return Err(EventCommitError::Corrupt(
                        "invalid unstarted tool failure".into(),
                    ));
                }
            }
            let mut event = event_candidate(run, event_type, data, self.max_event_bytes);
            if !event_id.is_empty() {
                event.event_id = event_id.clone();
            }
            let ordinal = if attach_message {
                store.sessions.get(&session_id).map(next_message_ordinal)
            } else {
                None
            };
            let message = if attach_message {
                Some(SessionMessage {
                    id: message_id.clone(),
                    session_id: session_id.clone(),
                    role: "user".to_string(),
                    content: content.clone().unwrap_or(JsonValue::Array(Vec::new())),
                    created_at: timestamp(),
                    run_id: Some(self.run_id.clone()),
                    finish_reason: None,
                    name: if tool_name.is_empty() {
                        None
                    } else {
                        Some(tool_name.clone())
                    },
                    tool_call_id: Some(tool_call_id.clone()),
                    parent_message_id: if parent_message_id.is_empty() {
                        None
                    } else {
                        Some(parent_message_id.clone())
                    },
                    token_estimate: None,
                    metadata: JsonValue::Null,
                    ordinal,
                })
            } else {
                None
            };
            let payload_json =
                serde_json::to_string(&event.data).unwrap_or_else(|_| "{}".to_string());
            let persist_payload = if attach_message {
                json!({
                    "run_id": self.run_id,
                    "session_id": session_id,
                    "event_id": event.event_id,
                    "event_type": event.event,
                    "payload_json": payload_json,
                    "now_ms": timestamp(),
                    "max_events": self.max_events_per_run,
                    "message_id": message_id,
                    "role": "user",
                    "content_json": serde_json::to_string(
                        content.as_ref().unwrap_or(&JsonValue::Array(Vec::new()))
                    )
                    .unwrap_or_else(|_| "[]".to_string()),
                    "name": tool_name,
                    "tool_call_id": tool_call_id,
                    "parent_message_id": parent_message_id,
                    "token_estimate": 0,
                    "metadata_json": "{}",
                    "finish_reason": "",
                    "seq": event.seq,
                    "ordinal": ordinal.unwrap_or(0),
                })
            } else {
                json!({
                    "run_id": self.run_id,
                    "event_id": event.event_id,
                    "event_type": event.event,
                    "payload_json": payload_json,
                    "now_ms": timestamp(),
                    "max_events": self.max_events_per_run,
                    "seq": event.seq,
                })
            };
            ReservedCommit {
                event,
                message,
                persist_payload,
                kind: if attach_message {
                    PersistKind::Step
                } else {
                    PersistKind::EventAppend
                },
                max_events_per_run: self.max_events_per_run,
            }
        };
        let persist = persist_and_apply(&self.store, self.persistence.as_deref(), reserved);
        if persist.is_ok()
            && matches!(event_type, "tool.completed" | "tool.failed")
            && let Some(inner) = self.service.upgrade()
        {
            let failed =
                event_type == "tool.failed" || result.map(|tool| !tool.ok).unwrap_or(false);
            let truncated = result.map(|tool| tool.truncated).unwrap_or(false);
            inner.metrics.account_tool_attempt(failed, truncated);
            if inner.crash_after_tool_commit.swap(false, Ordering::SeqCst) {
                inner.provider_commit_crashed.store(true, Ordering::SeqCst);
                panic!("tool_commit_crash");
            }
        }
        persist
    }

    fn commit_pair(
        &self,
        first: (&str, JsonValue),
        second: (&str, JsonValue),
    ) -> Result<(), EventCommitError> {
        if self.is_terminal() {
            return Err(EventCommitError::Terminal);
        }
        let _serial = self.commit_gate.lock();
        let first_call_id = first
            .1
            .get("tool_call_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let second_call_id = second
            .1
            .get("tool_call_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let first_event_id = if first_call_id.is_empty() {
            String::new()
        } else {
            durable_tool_event_id(&self.run_id, &first_call_id, first.0)
        };
        let second_event_id = if second_call_id.is_empty() {
            String::new()
        } else {
            durable_tool_event_id(&self.run_id, &second_call_id, second.0)
        };
        enum PairAction {
            BothPresent,
            MissingFirst(ReservedCommit),
            MissingSecond(ReservedCommit),
            Pair(ReservedPair),
        }
        let action = {
            let store = self.store.read();
            let Some(run) = store.runs.get(&self.run_id) else {
                return Err(EventCommitError::Terminal);
            };
            if run_is_terminal(&run.status) {
                return Err(EventCommitError::Terminal);
            }
            let first_present = !first_event_id.is_empty()
                && run
                    .events
                    .iter()
                    .any(|event| event.event_id == first_event_id);
            let second_present = !second_event_id.is_empty()
                && run
                    .events
                    .iter()
                    .any(|event| event.event_id == second_event_id);
            match (first_present, second_present) {
                (true, true) => PairAction::BothPresent,
                (false, true) => {
                    let mut event =
                        event_candidate(run, first.0, first.1.clone(), self.max_event_bytes);
                    if !first_event_id.is_empty() {
                        event.event_id = first_event_id.clone();
                    }
                    let payload_json =
                        serde_json::to_string(&event.data).unwrap_or_else(|_| "{}".to_string());
                    let persist_payload = json!({
                        "run_id": self.run_id,
                        "event_id": event.event_id,
                        "event_type": event.event,
                        "payload_json": payload_json,
                        "now_ms": timestamp(),
                        "max_events": self.max_events_per_run,
                        "seq": event.seq,
                    });
                    PairAction::MissingFirst(ReservedCommit {
                        event,
                        message: None,
                        persist_payload,
                        kind: PersistKind::EventAppend,
                        max_events_per_run: self.max_events_per_run,
                    })
                }
                (true, false) => {
                    let mut event =
                        event_candidate(run, second.0, second.1.clone(), self.max_event_bytes);
                    if !second_event_id.is_empty() {
                        event.event_id = second_event_id.clone();
                    }
                    let payload_json =
                        serde_json::to_string(&event.data).unwrap_or_else(|_| "{}".to_string());
                    let persist_payload = json!({
                        "run_id": self.run_id,
                        "event_id": event.event_id,
                        "event_type": event.event,
                        "payload_json": payload_json,
                        "now_ms": timestamp(),
                        "max_events": self.max_events_per_run,
                        "seq": event.seq,
                    });
                    PairAction::MissingSecond(ReservedCommit {
                        event,
                        message: None,
                        persist_payload,
                        kind: PersistKind::EventAppend,
                        max_events_per_run: self.max_events_per_run,
                    })
                }
                (false, false) => {
                    let mut first_event =
                        event_candidate(run, first.0, first.1.clone(), self.max_event_bytes);
                    if !first_event_id.is_empty() {
                        first_event.event_id = first_event_id.clone();
                    }
                    let mut second_event =
                        event_candidate(run, second.0, second.1.clone(), self.max_event_bytes);
                    if !second_event_id.is_empty() {
                        second_event.event_id = second_event_id.clone();
                    }
                    second_event.seq = first_event.seq + 1;
                    let payload_json_a = serde_json::to_string(&first_event.data)
                        .unwrap_or_else(|_| "{}".to_string());
                    let payload_json_b = serde_json::to_string(&second_event.data)
                        .unwrap_or_else(|_| "{}".to_string());
                    let persist_payload = json!({
                        "run_id": self.run_id,
                        "event_id_a": first_event.event_id,
                        "event_type_a": first_event.event,
                        "payload_json_a": payload_json_a,
                        "event_id_b": second_event.event_id,
                        "event_type_b": second_event.event,
                        "payload_json_b": payload_json_b,
                        "now_ms": timestamp(),
                        "max_events": self.max_events_per_run,
                        "seq_a": first_event.seq,
                        "seq_b": second_event.seq,
                    });
                    PairAction::Pair(ReservedPair {
                        first: first_event,
                        second: second_event,
                        persist_payload,
                        max_events_per_run: self.max_events_per_run,
                    })
                }
            }
        };
        match action {
            PairAction::BothPresent => Ok(()),
            PairAction::MissingFirst(reserved) | PairAction::MissingSecond(reserved) => {
                persist_and_apply(&self.store, self.persistence.as_deref(), reserved)
            }
            PairAction::Pair(reserved) => {
                persist_and_apply_pair(&self.store, self.persistence.as_deref(), reserved)
            }
        }
    }
}

fn lookup_tool_call_parent(
    store: &GatewayStore,
    session_id: &str,
    tool_call_id: &str,
) -> Option<(String, String)> {
    let session = store.sessions.get(session_id)?;
    for message in &session.messages {
        if message.role != "assistant" {
            continue;
        }
        for block in decode_message_blocks(&message.content) {
            if block.block_type == "tool_call"
                && block.tool_call_id.as_deref() == Some(tool_call_id)
            {
                return Some((message.id.clone(), block.name.unwrap_or_default()));
            }
        }
    }
    None
}

fn run_is_terminal(status: &str) -> bool {
    matches!(
        status,
        "completed" | "failed" | "cancelled" | "terminal_pending"
    )
}

/// Worker-committed terminals must not grow a pending `model.completed`.
/// Restart recovery fails leftover active runs with `gateway_restart`; those
/// still retry or interrupt a pending provider request.
fn run_refuses_pending_provider(run: &RunRecord) -> bool {
    match run.status.as_str() {
        "completed" | "cancelled" | "terminal_pending" => true,
        "failed" => !run.events.iter().any(|event| {
            event.event == "run.failed"
                && event.data.get("error_code").and_then(JsonValue::as_str)
                    == Some("gateway_restart")
        }),
        _ => false,
    }
}

fn next_message_ordinal(session: &SessionRecord) -> i64 {
    let max_ordinal = session
        .messages
        .iter()
        .filter_map(|message| message.ordinal)
        .max()
        .unwrap_or(0);
    max_ordinal.max(session.messages.len() as i64) + 1
}

struct RunOccupancyGuard {
    handle: Arc<RunHandle>,
}

impl Drop for RunOccupancyGuard {
    fn drop(&mut self) {
        self.handle.occupancy.store(false, Ordering::SeqCst);
    }
}

fn try_occupy_run(handle: &Arc<RunHandle>) -> Option<RunOccupancyGuard> {
    handle
        .occupancy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .ok()
        .map(|_| RunOccupancyGuard {
            handle: Arc::clone(handle),
        })
}

fn existing_provider_commit(
    store: &GatewayStore,
    run: &RunRecord,
    message_id: &str,
) -> Result<ProviderCommitOutcome, EventCommitError> {
    let Some(session) = store.sessions.get(&run.session_id) else {
        return Err(EventCommitError::Corrupt(
            "durable provider step is incomplete".to_string(),
        ));
    };
    let Some(message) = session
        .messages
        .iter()
        .find(|message| message.id == message_id)
    else {
        return Err(EventCommitError::Corrupt(
            "durable provider step is incomplete".to_string(),
        ));
    };
    if message.role != "assistant" {
        return Err(EventCommitError::Corrupt(
            "durable provider step is incomplete".to_string(),
        ));
    }
    let envelope = crate::durable_provider::reconstruct_provider_envelope(
        &message.content,
        &message.metadata,
        message.finish_reason.as_deref(),
    )?;
    Ok(ProviderCommitOutcome::Existing(ProviderCommit {
        message_id: message_id.to_string(),
        envelope,
    }))
}

fn provider_failure_is_retryable(event: &GatewayEvent) -> bool {
    event.data.get("retryable").and_then(JsonValue::as_bool) == Some(true)
}

fn requested_payload_leaks_secrets(data: &JsonValue) -> bool {
    match data {
        JsonValue::Object(map) => map.iter().any(|(key, value)| {
            SECRET_PROVIDER_REQUEST_KEYS.contains(&key.as_str())
                || requested_payload_leaks_secrets(value)
        }),
        JsonValue::Array(items) => items.iter().any(requested_payload_leaks_secrets),
        _ => false,
    }
}

enum PersistKind {
    Step,
    EventAppend,
}

struct ReservedCommit {
    event: GatewayEvent,
    message: Option<SessionMessage>,
    persist_payload: JsonValue,
    kind: PersistKind,
    max_events_per_run: usize,
}

struct ReservedPair {
    first: GatewayEvent,
    second: GatewayEvent,
    persist_payload: JsonValue,
    max_events_per_run: usize,
}

fn persist_and_apply(
    store: &RwLock<GatewayStore>,
    persistence: Option<&GatewayPersistence>,
    reserved: ReservedCommit,
) -> Result<(), EventCommitError> {
    let durable = match persistence {
        Some(persistence) => match reserved.kind {
            PersistKind::Step => persistence
                .step_commit(&reserved.persist_payload)
                .map(|_| ()),
            PersistKind::EventAppend => persistence
                .event_append(&reserved.persist_payload)
                .map(|_| ()),
        },
        None => Ok(()),
    };
    match durable {
        Ok(()) => {
            let mut store = store.write();
            apply_reserved(&mut store, &reserved);
            let sender = store
                .runs
                .get(&reserved.event.run_id)
                .and_then(|run| run.sender.clone());
            drop(store);
            if let Some(sender) = sender {
                let _ = sender.send(reserved.event);
            }
            Ok(())
        }
        Err(error) => Err(EventCommitError::PersistFailed(error.to_string())),
    }
}

fn apply_reserved(store: &mut GatewayStore, reserved: &ReservedCommit) {
    if let Some(run) = store.runs.get_mut(&reserved.event.run_id) {
        apply_event_locked(run, &reserved.event, reserved.max_events_per_run);
    }
    if let Some(message) = &reserved.message
        && let Some(session) = store.sessions.get_mut(&message.session_id)
        && !session
            .messages
            .iter()
            .any(|existing| existing.id == message.id)
    {
        session.messages.push(message.clone());
        session.view.message_count = session.messages.len();
        session.view.updated_at = timestamp();
    }
}

fn persist_and_apply_pair(
    store: &RwLock<GatewayStore>,
    persistence: Option<&GatewayPersistence>,
    reserved: ReservedPair,
) -> Result<(), EventCommitError> {
    let durable = match persistence {
        Some(persistence) => persistence
            .event_append_pair(&reserved.persist_payload)
            .map(|_| ()),
        None => Ok(()),
    };
    match durable {
        Ok(()) => {
            let mut store = store.write();
            apply_reserved_pair(&mut store, &reserved);
            let sender = store
                .runs
                .get(&reserved.first.run_id)
                .and_then(|run| run.sender.clone());
            drop(store);
            if let Some(sender) = sender {
                let _ = sender.send(reserved.first);
                let _ = sender.send(reserved.second);
            }
            Ok(())
        }
        Err(error) => Err(EventCommitError::PersistFailed(error.to_string())),
    }
}

fn apply_reserved_pair(store: &mut GatewayStore, reserved: &ReservedPair) {
    if let Some(run) = store.runs.get_mut(&reserved.first.run_id) {
        apply_event_locked(run, &reserved.first, reserved.max_events_per_run);
        apply_event_locked(run, &reserved.second, reserved.max_events_per_run);
    }
}

fn apply_terminal(
    store: &mut GatewayStore,
    run_id: &str,
    to_status: &str,
    events: &[GatewayEvent],
    seqs: &[(String, u64)],
    message: Option<&SessionMessage>,
    max_events_per_run: usize,
) {
    if let Some(run) = store.runs.get_mut(run_id) {
        for event in events {
            let mut event = event.clone();
            if let Some((_, seq)) = seqs
                .iter()
                .find(|(event_id, _)| event_id == &event.event_id)
            {
                event.seq = *seq;
            }
            apply_event_locked(run, &event, max_events_per_run);
        }
        run.status = to_status.to_string();
    }
    if let Some(message) = message
        && let Some(session) = store.sessions.get_mut(&message.session_id)
        && !session
            .messages
            .iter()
            .any(|existing| existing.id == message.id)
    {
        session.messages.push(message.clone());
        session.view.message_count = session.messages.len();
        session.view.updated_at = timestamp();
    }
}

fn tool_result_content_json(tool_call_id: &str, result: &ToolResult) -> JsonValue {
    let (content, cut) = truncate_utf8_chars(&result.content, MAX_DURABLE_TEXT_CHARS);
    let truncated = result.truncated || cut;
    let error = result.error.as_ref().map(|error| {
        json!({
            "code": error.code,
            "message": error.message,
        })
    });
    let artifact = result
        .artifacts
        .first()
        .cloned()
        .map(|id| json!({"id": id}));
    encode_message_content(&[LlmContentBlock {
        block_type: "tool_result".to_string(),
        tool_call_id: Some(tool_call_id.to_string()),
        content: Some(content),
        is_error: Some(!result.ok),
        result: if result.ok {
            Some(result.data.clone())
        } else {
            None
        },
        error,
        artifact,
        truncated: truncated.then_some(true),
        ..LlmContentBlock::default()
    }])
}

fn invalid_context_metadata(run_id: &str, reason: &str) -> RunContextError {
    RunContextError::InvalidMetadata {
        run_id: run_id.to_string(),
        reason: reason.to_string(),
    }
}

fn optional_string(value: Option<&JsonValue>) -> Option<String> {
    value
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn effective_limits_json(limits: &RunLimits, config: &AgentGatewayConfig) -> JsonValue {
    let mut object = match limits.to_json() {
        JsonValue::Object(object) => object,
        _ => Map::new(),
    };
    object.insert(
        "max_events".to_string(),
        JsonValue::from(config.max_events_per_run),
    );
    object.insert(
        "max_event_bytes".to_string(),
        JsonValue::from(config.max_event_bytes),
    );
    object.insert(
        "timeout_ms".to_string(),
        JsonValue::from(u64::try_from(config.run_timeout.as_millis()).unwrap_or(u64::MAX)),
    );
    JsonValue::Object(object)
}

fn canonicalize_json_value(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Array(values) => JsonValue::Array(
            values
                .iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        JsonValue::Object(entries) => {
            let mut keys = entries.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut object = Map::new();
            for key in keys {
                object.insert(
                    key.clone(),
                    canonicalize_json_value(entries.get(key).expect("key came from object")),
                );
            }
            JsonValue::Object(object)
        }
        _ => value.clone(),
    }
}

fn verify_context_metadata(context: &RunContext) -> Result<(), RunContextError> {
    let run_id = &context.run_id;
    let metadata = context
        .metadata
        .as_object()
        .ok_or_else(|| invalid_context_metadata(run_id, "context metadata is not an object"))?;
    if metadata.get("schema_version").and_then(JsonValue::as_u64)
        != Some(RUN_CONTEXT_METADATA_VERSION)
    {
        return Err(invalid_context_metadata(
            run_id,
            "unsupported metadata schema version",
        ));
    }
    if metadata.get("run_id").and_then(JsonValue::as_str) != Some(run_id) {
        return Err(invalid_context_metadata(
            run_id,
            "run id does not match metadata",
        ));
    }
    if metadata.get("session_id").and_then(JsonValue::as_str) != Some(context.session_id.as_str()) {
        return Err(invalid_context_metadata(
            run_id,
            "session id does not match metadata",
        ));
    }
    let registry_identity = metadata
        .get("registry_identity")
        .and_then(JsonValue::as_str)
        .filter(|identity| identity.starts_with("sha256:") && identity.len() == 71)
        .ok_or_else(|| invalid_context_metadata(run_id, "registry identity is invalid"))?;
    if metadata.get("toolset_hash").and_then(JsonValue::as_str) != Some(registry_identity) {
        return Err(invalid_context_metadata(
            run_id,
            "toolset hash does not match registry identity",
        ));
    }
    let message_id = metadata
        .get("message_id")
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_context_metadata(run_id, "message id is missing"))?;
    let _ = message_id;
    for bulky in ["provider_options", "tool_schemas", "limits", "input"] {
        if metadata.contains_key(bulky) {
            return Err(invalid_context_metadata(
                run_id,
                "context metadata must not duplicate run payload fields",
            ));
        }
    }
    let tool_schemas = context
        .tool_schemas
        .as_array()
        .filter(|schemas| !schemas.is_empty())
        .ok_or_else(|| {
            invalid_context_metadata(run_id, "tool schema snapshot must be non-empty")
        })?;
    let _ = tool_schemas;
    let messages = context
        .messages
        .as_array()
        .filter(|messages| !messages.is_empty())
        .ok_or_else(|| invalid_context_metadata(run_id, "message baseline must be non-empty"))?;
    if messages.iter().any(JsonValue::is_null) {
        return Err(invalid_context_metadata(
            run_id,
            "message baseline contains a null entry",
        ));
    }
    let provider_profile_name = metadata
        .get("provider_profile")
        .and_then(JsonValue::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_context_metadata(run_id, "provider profile is missing"))?;
    ProviderProfile::new(provider_profile_name, context.provider_options.clone())
        .map_err(|error| invalid_context_metadata(run_id, &error.to_string()))?;
    RunLimits::from_json(&context.limits)
        .map_err(|error| invalid_context_metadata(run_id, &error.to_string()))?;
    Ok(())
}

fn verify_context_registry(
    context: &RunContext,
    current_identity: &str,
) -> Result<(), RunContextError> {
    verify_context_metadata(context)?;
    let expected = context
        .metadata
        .get("registry_identity")
        .and_then(JsonValue::as_str)
        .expect("metadata validation checked registry identity");
    if expected != current_identity {
        return Err(RunContextError::RegistryMismatch {
            run_id: context.run_id.clone(),
            expected: expected.to_string(),
            actual: current_identity.to_string(),
        });
    }
    Ok(())
}

impl AgentService {
    /// Retries one run's pending terminal commit. Runs on a blocking thread.
    /// The GatewayStore lock is not held across SQLite/worker IO. On success
    /// the durable terminal is applied then broadcast; on a typed transition
    /// conflict the pending terminal is dropped without broadcasting (never a
    /// fabricated terminal). Live subscribers observe at-least-once delivery
    /// of durable events; exactly-once is not guaranteed across an
    /// unacknowledged receiver crash window.
    async fn retry_pending_terminal(&self, run_id: &str) -> PendingRetryOutcome {
        let service = self.clone();
        let run_id_for_block = run_id.to_string();
        tokio::task::spawn_blocking(move || {
            let _serial = service.inner.commit_gate.lock();
            let persistence = service.persistence_handle();
            let Some(pending) = service.pending_terminal(&run_id_for_block) else {
                return PendingRetryOutcome::Gone;
            };
            {
                let store = service.inner.store.read();
                let Some(run) = store.runs.get(&run_id_for_block) else {
                    service.clear_pending_terminal(&run_id_for_block);
                    return PendingRetryOutcome::Gone;
                };
                if run.status != "terminal_pending" {
                    service.clear_pending_terminal(&run_id_for_block);
                    return PendingRetryOutcome::Gone;
                }
            }
            if std::time::Instant::now() >= pending.deadline {
                service.clear_pending_terminal(&run_id_for_block);
                let mut store = service.inner.store.write();
                if let Some(run) = store.runs.get_mut(&run_id_for_block) {
                    close_run_stream(run);
                }
                service
                    .inner
                    .metrics
                    .terminal_retry(TerminalRetryOutcome::Expired);
                tracing::warn!(
                    run_id = %run_id_for_block,
                    "terminal retry window expired; durable side left for restart recovery"
                );
                return PendingRetryOutcome::Expired;
            }
            let durable = terminal_commit(
                persistence.as_deref(),
                &run_id_for_block,
                pending.session_id.as_deref().unwrap_or(""),
                &pending.to_status,
                &pending.events,
                pending.assistant_message.as_ref(),
            );
            match durable {
                Ok(seqs) => {
                    let mut store = service.inner.store.write();
                    apply_terminal(
                        &mut store,
                        &run_id_for_block,
                        &pending.to_status,
                        &pending.events,
                        &seqs,
                        pending.assistant_message.as_ref(),
                        service.inner.config.max_events_per_run,
                    );
                    service.clear_pending_terminal(&run_id_for_block);
                    let sender = store
                        .runs
                        .get(&run_id_for_block)
                        .and_then(|run| run.sender.clone());
                    drop(store);
                    if let Some(sender) = sender {
                        for event in &pending.events {
                            let mut published = event.clone();
                            if let Some((_, seq)) = seqs
                                .iter()
                                .find(|(event_id, _)| event_id == &event.event_id)
                            {
                                published.seq = *seq;
                            }
                            let _ = sender.send(published);
                        }
                    }
                    service
                        .inner
                        .metrics
                        .terminal_retry(TerminalRetryOutcome::Committed);
                    tracing::info!(
                        run_id = %run_id_for_block,
                        status = %pending.to_status,
                        "pending terminal committed durably by the bounded retry"
                    );
                    PendingRetryOutcome::Committed
                }
                Err(error) if error.code == "transition_conflict" => {
                    service.clear_pending_terminal(&run_id_for_block);
                    let mut store = service.inner.store.write();
                    if let Some(run) = store.runs.get_mut(&run_id_for_block) {
                        close_run_stream(run);
                    }
                    service
                        .inner
                        .metrics
                        .terminal_retry(TerminalRetryOutcome::Conflict);
                    tracing::warn!(
                        run_id = %run_id_for_block,
                        "pending terminal dropped on a durable transition conflict \
                         (no fabricated terminal)"
                    );
                    PendingRetryOutcome::Conflict
                }
                Err(error) => {
                    tracing::error!(
                        run_id = %run_id_for_block,
                        error = %truncate_for_log(&error.message, 256),
                        "terminal retry failed; will retry on the next janitor tick"
                    );
                    service
                        .inner
                        .metrics
                        .terminal_retry(TerminalRetryOutcome::RetryFailed);
                    PendingRetryOutcome::RetryFailed
                }
            }
        })
        .await
        .expect("terminal retry task must complete")
    }

    /// Spawns the bounded retry loop for one run's pending terminal. The
    /// loop retries on the janitor cadence until the terminal commits durably
    /// (then publishes and releases the permit), the run disappears, the
    /// durable side reports a terminal conflict, or the retry window expires.
    fn spawn_terminal_retry(&self, run_id: String) {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(service.inner.config.janitor_interval);
            loop {
                interval.tick().await;
                match service.retry_pending_terminal(&run_id).await {
                    PendingRetryOutcome::Committed
                    | PendingRetryOutcome::Gone
                    | PendingRetryOutcome::Conflict
                    | PendingRetryOutcome::Expired => return,
                    PendingRetryOutcome::RetryFailed => continue,
                }
            }
        });
    }
}

/// Outcome of the RSS worker: a completed value, a typed cancellation, or a
/// failure string. No string matching drives control flow; the variants are
/// decided from typed run outcomes.
enum WorkerOutcome {
    Completed(VmValue),
    Cancelled(&'static str),
    Failed(String),
}

impl WorkerOutcome {
    /// Maps a typed runner error to the terminal outcome without string
    /// matching: cancellation/deadline/fuel/capability categories are decided
    /// from the typed variants.
    fn from_run_error(error: RunError) -> Self {
        match error {
            RunError::Invocation(InvocationError::Cancelled(reason)) => {
                WorkerOutcome::Cancelled(reason.as_str())
            }
            RunError::Invocation(InvocationError::DeadlineReached { .. }) => {
                WorkerOutcome::Cancelled("deadline")
            }
            RunError::Invocation(InvocationError::OutOfFuel { .. }) => {
                WorkerOutcome::Failed("out_of_fuel".to_string())
            }
            RunError::Invocation(InvocationError::Capability(error)) => {
                WorkerOutcome::Failed(format!("capability_{}", error.code().as_str()))
            }
            RunError::Invocation(InvocationError::Host { message }) => {
                WorkerOutcome::Failed(message)
            }
            RunError::Invocation(InvocationError::Vm(error)) => {
                WorkerOutcome::Failed(format!("{error}"))
            }
            RunError::EarlyEnd => {
                WorkerOutcome::Failed("invocation stream ended without a terminal item".to_string())
            }
            RunError::DeliveryClosed => {
                WorkerOutcome::Failed("event delivery closed before the run completed".to_string())
            }
            RunError::DeliveryRejected { message, .. } => WorkerOutcome::Failed(message),
            RunError::NoEntry => {
                WorkerOutcome::Failed("agent script does not export run(context)".to_string())
            }
            RunError::EntryArity { expected, got } => WorkerOutcome::Failed(format!(
                "exported run takes {got} parameter(s); expected exactly {expected}"
            )),
            RunError::Setup(error) | RunError::Vm(error) => {
                WorkerOutcome::Failed(format!("{error}"))
            }
        }
    }
}

fn interpret_loop_decision(value: &VmValue, cancellation: &RunCancellation) -> WorkerOutcome {
    if let Some(reason) = cancellation.requested() {
        return WorkerOutcome::Cancelled(reason.as_str());
    }
    if cancellation.deadline_passed() {
        return WorkerOutcome::Cancelled("deadline");
    }
    let json = vm_value_to_json(value);
    match json.get("kind").and_then(JsonValue::as_str) {
        Some("run.failed") => {
            let code = json
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(JsonValue::as_str)
                .unwrap_or("failed");
            match code {
                "cancelled" => WorkerOutcome::Cancelled("requested"),
                "deadline_elapsed" => WorkerOutcome::Cancelled("deadline"),
                other => {
                    let message = json
                        .get("error")
                        .and_then(|error| error.get("message"))
                        .and_then(JsonValue::as_str)
                        .unwrap_or(other)
                        .to_string();
                    WorkerOutcome::Failed(message)
                }
            }
        }
        _ => WorkerOutcome::Completed(value.clone()),
    }
}

fn completed_output_text(value: &VmValue) -> String {
    let json = vm_value_to_json(value);
    if json.get("kind").and_then(JsonValue::as_str) == Some("run.completed") {
        match json.get("answer") {
            Some(JsonValue::String(answer)) => return answer.clone(),
            Some(answer) => return answer.to_string(),
            None => {}
        }
    }
    json.to_string()
}

/// Outcome of one durable terminal commit attempt.
enum TerminalOutcome {
    /// The terminal state was committed durably and published.
    Committed,
    /// The run is no longer active (a terminal was committed elsewhere).
    NotActive,
    /// The run's session vanished before the commit.
    SessionMissing,
    /// The durable commit failed; the in-memory terminal state was rolled
    /// back and the prebuilt typed terminal is handed to the bounded retry
    /// loop (`register_pending_terminal`), never a false terminal.
    TerminalPersistFailed {
        error: String,
        pending: Box<PendingTerminal>,
    },
}

/// A typed failure of one `run.terminal` commit attempt. The `code` lets
/// the bounded retry loop distinguish a durable terminal conflict (the run
/// already reached a terminal state durably) from an unavailable-storage
/// failure that should be retried.
#[derive(Debug)]
struct TerminalCommitError {
    code: String,
    message: String,
}

impl std::fmt::Display for TerminalCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

/// Commits one run's terminal state through the typed `run.terminal`
/// transaction (status change + terminal events + optional assistant
/// message in one durable commit). The GatewayStore lock is not held
/// across SQLite/worker IO. Sequences returned by the command are applied
/// after persist so live and reopened history stay adjacent. Callers
/// broadcast only after this returns `Ok`.
fn terminal_commit(
    persistence: Option<&GatewayPersistence>,
    run_id: &str,
    session_id: &str,
    to_status: &str,
    events: &[GatewayEvent],
    assistant_message: Option<&SessionMessage>,
) -> Result<Vec<(String, u64)>, TerminalCommitError> {
    let Some(persistence) = persistence else {
        return Ok(events
            .iter()
            .map(|event| (event.event_id.clone(), event.seq))
            .collect());
    };
    let event = |index: usize| -> &GatewayEvent {
        events.get(index).expect("terminal event index in range")
    };
    let event_count = events.len();
    let payload = json!({
        "run_id": run_id,
        "to_status": to_status,
        "error_code": "",
        "error_message": "",
        "event_1_id": if event_count >= 1 { event(0).event_id.clone() } else { String::new() },
        "event_1_type": if event_count >= 1 { event(0).event.clone() } else { String::new() },
        "event_1_payload": if event_count >= 1 {
            serde_json::to_string(&event(0).data).unwrap_or_else(|_| "{}".to_string())
        } else { "{}".to_string() },
        "event_2_id": if event_count >= 2 { event(1).event_id.clone() } else { String::new() },
        "event_2_type": if event_count >= 2 { event(1).event.clone() } else { String::new() },
        "event_2_payload": if event_count >= 2 {
            serde_json::to_string(&event(1).data).unwrap_or_else(|_| "{}".to_string())
        } else { "{}".to_string() },
        "event_count": event_count,
        "message_id": assistant_message.map(|message| message.id.clone()).unwrap_or_default(),
        "message_session_id": assistant_message.map(|_| session_id.to_string()).unwrap_or_default(),
        "message_role": assistant_message.map(|message| message.role.clone()).unwrap_or_default(),
        "message_content_json": assistant_message
            .map(|message| serde_json::to_string(&message.content).unwrap_or_else(|_| "null".to_string()))
            .unwrap_or_default(),
        "message_run_id": assistant_message
            .and_then(|message| message.run_id.clone())
            .unwrap_or_default(),
        "message_finish_reason": assistant_message
            .and_then(|message| message.finish_reason.clone())
            .unwrap_or_default(),
        "message_ordinal": assistant_message.and_then(|message| message.ordinal).unwrap_or(0),
        "now_ms": events
            .first()
            .map(|event| event.timestamp)
            .unwrap_or_else(timestamp),
    });
    let data = persistence
        .run_terminal(&payload)
        .map_err(|error| TerminalCommitError {
            code: error.code.clone(),
            message: error.message.clone(),
        })?;
    let rows = crate::sqlite_storage_rows::sqlite_storage_rows(
        data.get("events").unwrap_or(&JsonValue::Null),
    )
    .map_err(|message| TerminalCommitError {
        code: "terminal_commit_invalid".to_string(),
        message,
    })?;
    if rows.len() < event_count {
        return Err(TerminalCommitError {
            code: "terminal_commit_invalid".to_string(),
            message: format!(
                "run.terminal appended {} events, expected at least {event_count}",
                rows.len()
            ),
        });
    }
    let offset = rows.len() - event_count;
    let mut seqs = Vec::with_capacity(event_count);
    for (index, event) in events.iter().enumerate() {
        let row = rows
            .get(offset + index)
            .ok_or_else(|| TerminalCommitError {
                code: "terminal_commit_invalid".to_string(),
                message: "run.terminal returned a malformed event row".to_string(),
            })?;
        let seq = row
            .first()
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| TerminalCommitError {
                code: "terminal_commit_invalid".to_string(),
                message: "run.terminal returned a malformed event sequence".to_string(),
            })?;
        seqs.push((event.event_id.clone(), seq));
    }
    Ok(seqs)
}

/// Outcome of one bounded terminal retry attempt.
enum PendingRetryOutcome {
    /// The terminal was committed durably and then broadcast. Live
    /// subscribers observe at-least-once delivery; exactly-once is not
    /// guaranteed across an unacknowledged receiver crash window.
    Committed,
    /// The run or its pending entry no longer exists; nothing to do.
    Gone,
    /// The durable side already holds a different terminal (for example
    /// restart recovery); the pending terminal must not be published.
    Conflict,
    /// The bounded retry window expired; the retry loop stops, the live
    /// stream is closed, and the durable side is left for restart recovery.
    Expired,
    /// Storage is still unavailable; retry again on the next tick.
    RetryFailed,
}

/// Closes a run's live delivery stream: existing subscribers observe
/// `Closed` and the SSE stream ends instead of hanging forever, and new
/// subscribers replay history and then end.
fn close_run_stream(run: &mut RunRecord) {
    run.sender = None;
}

/// Canonical run.failed payload from a plain failure message.
pub(crate) fn failed_payload(error: String) -> JsonValue {
    json!({
        "status": "failed",
        "error_code": "agent_failed",
        "error_message": error,
    })
}

/// Removes terminal lifecycle handles after the configured TTL. The durable
/// store keeps the run record (replay handoff); only the in-memory
/// cancellation/delivery state is released. The bounded durable-first retry
/// of `terminal_pending` runs is owned by the per-run retry loops spawned by
/// [`AgentService::spawn_terminal_retry`], so exactly one janitor system
/// exists.
fn spawn_lifecycle_janitor(inner: Arc<AgentServiceInner>) {
    let interval_duration = inner.config.janitor_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = inner.janitor_stop.notified() => {},
            }
            if inner.halting.load(Ordering::Acquire) {
                return;
            }
            let ttl = inner.config.terminal_run_ttl;
            let now = Instant::now();
            let mut expired_handles = Vec::new();
            let expired_run_ids: HashSet<String> = {
                let mut runs = inner.runs.lock().expect("runs lock");
                let mut expired = HashSet::new();
                runs.retain(|run_id, handle| {
                    let keep = handle
                        .terminal_at
                        .lock()
                        .expect("terminal lock")
                        .is_none_or(|terminal_at| terminal_at + ttl > now);
                    if !keep {
                        expired_handles.push(Arc::clone(handle));
                        expired.insert(run_id.clone());
                    }
                    keep
                });
                expired
            };
            for handle in expired_handles {
                handle.release_capability_host();
            }
            if !expired_run_ids.is_empty() {
                inner
                    .contexts
                    .lock()
                    .expect("contexts lock")
                    .retain(|run_id, _| !expired_run_ids.contains(run_id));
                inner
                    .context_registries
                    .lock()
                    .expect("context registries lock")
                    .retain(|run_id, _| !expired_run_ids.contains(run_id));
            }
        }
    });
}

#[cfg(test)]
mod teardown_tests {
    use super::*;
    use crate::gateway::AgentGatewayState;

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn stopped_admission_releases_idle_janitor_owner_within_cleanup_budget() {
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        let (sender, finished) = tokio::sync::oneshot::channel();
        let signal = DropSignal(Some(sender));
        service.inject_capability_host_shutdown_observer(Arc::new(move || {
            let _ = &signal;
        }));
        tokio::task::yield_now().await;
        service.stop_admission();
        drop(service);
        drop(state);
        tokio::time::timeout(Duration::from_secs(2), finished)
            .await
            .expect("idle janitor must release its owner within the cleanup budget")
            .expect("service owner retirement acknowledgement");
    }
}

#[cfg(test)]
mod import_validation_memo_tests {
    use super::*;
    use crate::gateway::AgentGatewayState;
    use crate::runtime::module_snapshot::import_validation_counts;
    use std::fs;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = PathBuf::from(std::env::var_os("TEST_TMPDIR").unwrap())
                .join(format!("service-import-memo-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&root).unwrap();
            fs::write(
                root.join("main.rss"),
                "pub fn run(input: map) -> string { \"old\"; }\n",
            )
            .unwrap();
            Self(root)
        }

        fn entry(&self) -> PathBuf {
            self.0.join("main.rss")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[tokio::test]
    async fn warm_current_file_lookup_reuses_import_validation_but_captures_again() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        service.install_agent_entry(fixture.entry());
        service.cached_agent_runner(None).unwrap();
        let before = import_validation_counts();
        for _ in 0..3 {
            service.cached_agent_runner(None).unwrap();
        }
        let after = import_validation_counts();
        assert_eq!(after.0 - before.0, 3, "each lookup captures current files");
        assert_eq!(
            after.1 - before.1,
            0,
            "warm identical files need no additional full import parse"
        );
    }

    #[tokio::test]
    async fn separate_services_validate_independently_and_current_config_rebuilds() {
        let fixture = Fixture::new();
        let first_state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let second_state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let first = first_state.service();
        let second = second_state.service();
        first.install_agent_entry(fixture.entry());
        second.install_agent_entry(fixture.entry());
        first.cached_agent_runner(None).unwrap();
        let before = import_validation_counts();
        second.cached_agent_runner(None).unwrap();
        assert!(
            import_validation_counts().1 > before.1,
            "another service has its own positive slot"
        );
        let mut different = first.effective_agent_config();
        different.fuel = Some(different.fuel.unwrap_or(1_000_000).saturating_add(1));
        first.install_agent_runner(AgentRunner::from_file(fixture.entry(), different).unwrap());
        let before = import_validation_counts();
        let rebuilt = first.cached_agent_runner(None).unwrap();
        assert_eq!(rebuilt.config(), &first.effective_agent_config());
        assert!(
            import_validation_counts().0 - before.0 >= 3,
            "live A, compile B and live C remain"
        );
        assert!(
            import_validation_counts().1 > before.1,
            "compile retains original non-memo capture"
        );
    }

    #[tokio::test]
    async fn warm_current_file_mutation_compiles_new_bytes() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        service.install_agent_entry(fixture.entry());
        let old = service.cached_agent_runner(None).unwrap();
        let mtime = fs::metadata(fixture.entry()).unwrap().modified().unwrap();
        fs::write(
            fixture.entry(),
            "pub fn run(input: map) -> string { \"new\"; }\n",
        )
        .unwrap();
        fs::File::options()
            .write(true)
            .open(fixture.entry())
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        let current = service.cached_agent_runner(None).unwrap();
        assert_ne!(old.snapshot_digest(), current.snapshot_digest());
        assert_eq!(
            current
                .run_with_context(crate::domain::json_to_vm_value(&json!({})))
                .unwrap(),
            crate::domain::json_to_vm_value(&json!("new"))
        );
    }

    #[tokio::test]
    async fn warm_postcheck_mutation_retries_then_rejects_continuous_changes() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        service.install_agent_entry(fixture.entry());
        service.cached_agent_runner(None).unwrap();
        let path = fixture.entry();
        let once = AtomicBool::new(false);
        service.inject_agent_compile_postcheck_observer(Arc::new(move || {
            if !once.swap(true, Ordering::SeqCst) {
                fs::write(&path, "pub fn run(input: map) -> string { \"end\"; }\n").unwrap();
            }
        }));
        fs::write(
            fixture.entry(),
            "pub fn run(input: map) -> string { \"new\"; }\n",
        )
        .unwrap();
        let current = service.cached_agent_runner(None).unwrap();
        assert_eq!(
            current
                .run_with_context(crate::domain::json_to_vm_value(&json!({})))
                .unwrap(),
            crate::domain::json_to_vm_value(&json!("end"))
        );
        let path = fixture.entry();
        service.inject_agent_compile_lookup_observer(Arc::new(move || {
            fs::write(&path, "pub fn run(input: map) -> string { \"new\"; }\n").unwrap();
        }));
        let path = fixture.entry();
        service.inject_agent_compile_postcheck_observer(Arc::new(move || {
            fs::write(&path, "pub fn run(input: map) -> string { \"end\"; }\n").unwrap();
        }));
        let error = service.cached_agent_runner(None).err().unwrap();
        assert_eq!(
            error,
            "RustScript compile error: module tree changed during compile"
        );
    }

    #[tokio::test]
    async fn current_production_tree_miss_hit_lookup_phase_measurements() {
        let state = AgentGatewayState::with_agent_file(
            AgentGatewayConfig::default(),
            crate::runtime::rss_runner::bundled_agent_main_path(),
        )
        .unwrap();
        let service = state.service();
        for label in ["miss", "hit"] {
            let before = import_validation_counts();
            let started = Instant::now();
            service.cached_agent_runner(None).unwrap();
            let lookup_ns = started.elapsed().as_nanos();
            let after = import_validation_counts();
            let (capture_ns, validation_ns, pure_validation_ns) =
                crate::runtime::module_snapshot::import_validation_timings();
            eprintln!(
                "IMPORT_MEMO_PHASE label={label} capture_ns={capture_ns} validation_including_memo_ns={validation_ns} pure_validation_ns={pure_validation_ns} lookup_ns={lookup_ns} capture_count={} import_scan_count={}",
                after.0 - before.0,
                after.1 - before.1
            );
            assert_eq!(after.0 - before.0, 1);
            if label == "hit" {
                assert_eq!(after.1 - before.1, 0);
            } else {
                assert!(after.1 > before.1);
            }
        }
    }
}

#[cfg(test)]
mod workspace_template_tests {
    use super::*;
    use crate::gateway::AgentGatewayState;
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, Instant};

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        first: PathBuf,
        second: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR").unwrap())
                .join(format!("workspace-template-{}", uuid::Uuid::new_v4()));
            let fixture = Self {
                home: root.join("home"),
                first: root.join("first"),
                second: root.join("second"),
                root,
            };
            for path in [&fixture.home, &fixture.first, &fixture.second] {
                fs::create_dir_all(path).unwrap();
            }
            fixture.write_policy(&fixture.first);
            fixture
        }

        fn write_policy(&self, default: &Path) {
            let text = format!(
                "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n    - '{}'\n  default: '{}'\n  named:\n    first: '{}'\n    second: '{}'\n",
                self.first.display(),
                self.second.display(),
                default.display(),
                self.first.display(),
                self.second.display()
            );
            crate::config_file::ConfigFile::from_str(&text).unwrap();
            fs::write(self.home.join("config.yaml"), text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.home, fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(
                    self.home.join("config.yaml"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
        }

        fn install(&self, service: &AgentService, calls: Arc<AtomicUsize>) {
            let home = self.home.clone();
            service.set_workspace_host_factory(Arc::new(move |cancellation| {
                calls.fetch_add(1, Ordering::SeqCst);
                crate::auth::host::AuthHost::new(home.clone(), cancellation)
            }));
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("private workspace fixture cleanup");
        }
    }

    fn resolve(
        service: &AgentService,
        selector: &str,
        existing: Option<&WorkspaceBinding>,
        bind: bool,
    ) -> (
        WorkspaceBinding,
        Arc<crate::runtime::rss_runner::WorkspaceAuthority>,
    ) {
        let root = RunCancellation::with_timeout(Duration::from_secs(10));
        let started = Instant::now();
        let (binding, authority) = service
            .resolve_workspace_admission(Some(selector), existing, &root, bind)
            .unwrap();
        let authority = authority.unwrap();
        authority.check().unwrap();
        eprintln!(
            "workspace_resolution_success entry={} elapsed_ns={} generation={} grant_path={}",
            if bind { "bind" } else { "open" },
            started.elapsed().as_nanos(),
            authority.generation(),
            authority.canonical_path()
        );
        (binding.unwrap(), authority)
    }

    fn counts(service: &AgentService) -> [usize; 2] {
        std::array::from_fn(|index| {
            service.inner.workspace_runner_constructions[index].load(Ordering::SeqCst)
        })
    }

    #[tokio::test]
    async fn materialize_prepares_both_entries_only_with_factory_without_authority() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        service.materialize_cached_runner().unwrap();
        assert_eq!(counts(&service), [0, 0]);
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.install(&service, calls.clone());
        for _ in 0..2 {
            service.materialize_cached_runner().unwrap();
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "preparation cannot invoke native factory"
        );
        assert_eq!(counts(&service), [1, 1]);
        let (first, owner1) = resolve(&service, "name:first", None, false);
        let (second, owner2) = resolve(&service, "name:second", Some(&first), true);
        assert_ne!(first.canonical_path, second.canonical_path);
        owner1.revoke();
        owner2.check().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(counts(&service), [1, 1]);
    }

    #[tokio::test]
    async fn exact_config_replacement_retains_at_most_two_entry_templates() {
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        let base = service.workspace_runner_config();
        let mut configs = vec![base.clone()];
        let mut http = base.clone();
        http.http.max_redirects += 1;
        configs.push(http);
        let mut sqlite = base.clone();
        sqlite.sqlite.limits.max_rows += 1;
        configs.push(sqlite);
        let mut sqlite_root = base.clone();
        sqlite_root.sqlite.database_root = Some("/synthetic/code-only".to_string());
        configs.push(sqlite_root);
        let mut unsafe_sql = base.clone();
        unsafe_sql.sqlite.allow_unsafe_sql = true;
        configs.push(unsafe_sql);
        let mut fuel = base.clone();
        fuel.fuel = Some(base.fuel.unwrap() - 1);
        configs.push(fuel);
        configs.push(base);
        for (position, config) in configs.into_iter().enumerate() {
            for entry in ["open", "bind"] {
                for _ in 0..2 {
                    let runner = service
                        .cached_workspace_runner(entry, config.clone())
                        .unwrap();
                    assert_eq!(runner.config(), &config);
                }
            }
            let cache = service.inner.workspace_runners.lock().unwrap();
            let current = cache.as_ref().unwrap();
            assert_eq!(current.config, config);
            assert_eq!(
                usize::from(current.open.is_some()) + usize::from(current.bind.is_some()),
                2
            );
            assert_eq!(counts(&service), [position + 1, position + 1]);
        }
        let before = counts(&service);
        assert!(
            service
                .cached_workspace_runner(
                    "replay_identity_matches",
                    service.workspace_runner_config()
                )
                .is_err()
        );
        assert_eq!(counts(&service), before);
    }

    #[tokio::test]
    async fn warm_resolution_uses_current_factory_policy_generation_and_held_directory() {
        let fixture = Fixture::new();
        let replacement = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.install(&service, calls.clone());
        service.materialize_cached_runner().unwrap();
        let (first, owner1) = resolve(&service, "name:first", None, false);
        fixture.write_policy(&fixture.second);
        let home = fixture.home.clone();
        let generation_calls = calls.clone();
        service.set_workspace_host_factory(Arc::new(move |root| {
            generation_calls.fetch_add(1, Ordering::SeqCst);
            let host = crate::auth::host::AuthHost::new(home.clone(), root)?;
            assert_eq!(host.reload()?, 2);
            Ok(host)
        }));
        let root = RunCancellation::with_timeout(Duration::from_secs(10));
        let (binding, authority) = service
            .resolve_workspace_admission(None, None, &root, false)
            .unwrap();
        let current = binding.unwrap();
        let owner2 = authority.unwrap();
        assert_eq!(first.generation, 1);
        assert_eq!(current.generation, 2);
        assert_eq!(current.canonical_path, fixture.second.to_str().unwrap());
        assert_eq!(owner2.generation(), 2);
        owner2.check().unwrap();
        // Held directory facts are current; renaming one admitted root cannot
        // revoke an independent directory admitted by a different native owner.
        fs::rename(&fixture.second, fixture.root.join("moved-second")).unwrap();
        assert!(owner2.check().is_err());
        owner1.check().unwrap();
        replacement.install(&service, calls.clone());
        let (third, owner3) = resolve(&service, "name:first", None, false);
        assert_eq!(third.canonical_path, replacement.first.to_str().unwrap());
        assert_eq!(third.generation, 1);
        owner1.revoke();
        owner3.check().unwrap();
        assert_eq!(counts(&service), [1, 1]);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn warmed_denied_expired_cancelled_and_optional_paths_do_not_reuse_authority() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.install(&service, calls.clone());
        service.materialize_cached_runner().unwrap();
        let (binding, owner) = resolve(&service, "name:first", None, false);
        let fresh = RunCancellation::with_timeout(Duration::from_secs(10));
        let denied = service.resolve_workspace_admission(
            Some(fixture.root.to_str().unwrap()),
            None,
            &fresh,
            false,
        );
        assert!(matches!(denied, Err(AdmitError::Invalid(ref code)) if code == "workspace_denied"));
        let switching =
            service.resolve_workspace_admission(Some("name:second"), Some(&binding), &fresh, false);
        assert!(
            matches!(switching, Err(AdmitError::Invalid(ref code)) if code == "workspace_conflict")
        );
        let cancelled = RunCancellation::with_timeout(Duration::from_secs(10));
        cancelled.request(CancellationReason::Requested);
        for root in [RunCancellation::with_deadline(Instant::now()), cancelled] {
            assert!(
                service
                    .resolve_workspace_admission(Some("name:first"), Some(&binding), &root, false)
                    .is_err()
            );
            let optional = service
                .resolve_workspace_admission(None, None, &root, false)
                .unwrap();
            assert!(optional.0.is_none() && optional.1.is_none());
        }
        owner.check().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fixture.home, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(
                service
                    .resolve_workspace_admission(Some("name:first"), None, &fresh, false)
                    .is_err()
            );
            fs::set_permissions(&fixture.home, fs::Permissions::from_mode(0o700)).unwrap();
        }
        *service.inner.workspace_host_factory.lock().unwrap() = None;
        assert!(
            service
                .resolve_workspace_admission(Some("name:first"), None, &fresh, false)
                .is_err()
        );
        let optional = service
            .resolve_workspace_admission(None, None, &fresh, false)
            .unwrap();
        assert!(optional.0.is_none() && optional.1.is_none());
        assert_eq!(counts(&service), [1, 1]);
    }

    #[tokio::test]
    async fn parallel_native_factories_run_outside_template_initialization_lock() {
        use std::sync::mpsc;
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        fixture.install(&service, Arc::new(AtomicUsize::new(0)));
        service.materialize_cached_runner().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release1_tx, release1_rx) = mpsc::channel();
        let (release2_tx, release2_rx) = mpsc::channel();
        let releases = [Mutex::new(release1_rx), Mutex::new(release2_rx)];
        let call = AtomicUsize::new(0);
        let home = fixture.home.clone();
        service.set_workspace_host_factory(Arc::new(move |root| {
            let index = call.fetch_add(1, Ordering::SeqCst);
            entered_tx.send(index).unwrap();
            releases[index]
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "bounded release expired".to_string())?;
            crate::auth::host::AuthHost::new(home.clone(), root)
        }));
        let threads: Vec<_> = ["name:first", "name:second"]
            .into_iter()
            .map(|selector| {
                let service = service.clone();
                std::thread::spawn(move || resolve(&service, selector, None, false))
            })
            .collect();
        let entered1 = entered_rx.recv_timeout(Duration::from_secs(5));
        let entered2 = entered_rx.recv_timeout(Duration::from_secs(5));
        // Both factories are now held past cache lookup. A callback-local
        // try_lock could race another lookup or even the other test probe.
        let (cache_available, owned_lock_control) = if entered1.is_ok() && entered2.is_ok() {
            match service.inner.workspace_runners.try_lock() {
                Ok(guard) => {
                    let rejected = matches!(
                        service.inner.workspace_runners.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    );
                    drop(guard);
                    (true, rejected)
                }
                Err(_) => (false, false),
            }
        } else {
            (false, false)
        };
        // Always release and join both owned workers before any assertion.
        let _ = release1_tx.send(());
        let _ = release2_tx.send(());
        let outcomes: Vec<_> = threads.into_iter().map(|worker| worker.join()).collect();
        assert!(
            entered1.is_ok() && entered2.is_ok(),
            "both native factories must enter before release"
        );
        assert!(
            cache_available,
            "initialization lock must be free while both factories are held"
        );
        assert!(
            owned_lock_control,
            "an actually owned cache lock must reject the probe"
        );
        let mut owners = Vec::new();
        for outcome in outcomes {
            owners.push(outcome.unwrap().1);
        }
        assert!(!Arc::ptr_eq(&owners[0].grant(), &owners[1].grant()));
        owners[0].revoke();
        owners[1].check().unwrap();
        assert_eq!(counts(&service), [1, 1]);
    }

    #[tokio::test]
    async fn warm_template_clone_and_successful_native_adoption_measurements() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.install(&service, calls.clone());
        service.materialize_cached_runner().unwrap();
        let config = service.workspace_runner_config();
        let started = Instant::now();
        let runner = service.cached_workspace_runner("open", config).unwrap();
        let clone_ns = started.elapsed().as_nanos();
        let root = RunCancellation::with_timeout(Duration::from_secs(10));
        let factory = service.inner.workspace_host_factory.lock().unwrap().clone();
        let runner = runner
            .with_host(AgentHostBridges {
                auth_host_factory: factory,
                cancellation: Some(root.clone()),
                ..AgentHostBridges::default()
            })
            .with_cancellation(root.clone());
        let started = Instant::now();
        let outcome = runner.run_workspace_admission("open", crate::domain::json_to_vm_value(&json!({"selector":"name:first", "selector_present":true, "session_selector":"", "session_canonical_path":""})), &root).unwrap();
        let native_ns = started.elapsed().as_nanos();
        assert!(outcome.ok);
        let owner = outcome.authority.unwrap();
        owner.check().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(counts(&service), [1, 1]);
        eprintln!(
            "workspace_measured template_hit_clone_ns={clone_ns} successful_native_vm_policy_grant_adoption_ns={native_ns} generation={} path={}",
            owner.generation(),
            owner.canonical_path()
        );
    }

    #[tokio::test]
    async fn two_sessions_retain_independent_current_native_grants() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.install(&service, calls.clone());
        service.materialize_cached_runner().unwrap();
        let mut runs = Vec::new();
        for selector in ["name:first", "name:second"] {
            runs.push(
                service
                    .admit_external_with_workspace_selector(
                        AdmitRunRequest {
                            input: json!("synthetic session ownership"),
                            platform: "http".to_string(),
                            ..AdmitRunRequest::default()
                        },
                        Some(selector.to_string()),
                    )
                    .await
                    .unwrap(),
            );
        }
        assert_ne!(runs[0].session_id, runs[1].session_id);
        let owner1 = service
            .handle(&runs[0].run_id)
            .unwrap()
            .workspace_authority
            .clone()
            .unwrap();
        let owner2 = service
            .handle(&runs[1].run_id)
            .unwrap()
            .workspace_authority
            .clone()
            .unwrap();
        assert!(!Arc::ptr_eq(&owner1.grant(), &owner2.grant()));
        assert_eq!(owner1.canonical_path(), fixture.first.to_str().unwrap());
        assert_eq!(owner2.canonical_path(), fixture.second.to_str().unwrap());
        service.stop(&runs[0].run_id);
        assert!(owner1.check().is_err());
        owner2.check().unwrap();
        service.stop(&runs[1].run_id);
        assert!(owner2.check().is_err());
        assert_eq!(counts(&service), [1, 1]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn repeated_open_resolution_constructs_one_template_with_fresh_grants() {
        let fixture = Fixture::new();
        let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
        let service = state.service();
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.install(&service, calls.clone());
        let (first, owner1) = resolve(&service, "name:first", None, false);
        let (second, owner2) = resolve(&service, "name:second", None, false);
        assert_ne!(first.canonical_path, second.canonical_path);
        assert!(!Arc::ptr_eq(&owner1.grant(), &owner2.grant()));
        owner1.revoke();
        assert!(owner1.check().is_err());
        owner2.check().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            service.inner.workspace_runner_constructions[0].load(Ordering::SeqCst),
            1
        );
    }
}

#[cfg(test)]
mod f3_session_maintenance_tests {
    use super::{AdmitError, AdmitRunRequest};
    use crate::config::AgentGatewayConfig;
    use crate::gateway::AgentGatewayState;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};
    use tower::ServiceExt;

    struct MaintenanceBarrierRelease(Option<mpsc::Sender<()>>);

    impl MaintenanceBarrierRelease {
        fn release(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    impl Drop for MaintenanceBarrierRelease {
        fn drop(&mut self) {
            self.release();
        }
    }

    struct CompactionTimingProvider {
        inner: crate::runtime::agent_host::ScriptedProvider,
        lookup_at: Arc<Mutex<Option<Instant>>>,
        elapsed_us: Arc<Mutex<Option<u128>>>,
        first_call: AtomicBool,
    }

    impl crate::AgentProviderHost for CompactionTimingProvider {
        fn call(&self, request: &Value, cancellation: &crate::RunCancellation) -> Value {
            if !self.first_call.swap(true, Ordering::SeqCst)
                && let Some(lookup_at) = *self.lookup_at.lock().expect("lookup timestamp lock")
            {
                *self.elapsed_us.lock().expect("provider timestamp lock") =
                    Some(lookup_at.elapsed().as_micros());
            }
            self.inner.call(request, cancellation)
        }
    }

    fn private_root() -> PathBuf {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
                .expect("assigned lifecycle-test directory"),
        )
        .join(format!("f3-maintenance-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("private maintenance fixture directory");
        root
    }

    fn seed_session(
        persistence: &crate::gateway::store::GatewayPersistence,
        session_id: &str,
        now_ms: i64,
    ) {
        persistence
            .session_create(&json!({
                "id": session_id,
                "profile": "default",
                "platform": "f3-maintenance-test",
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
                "now_ms": now_ms,
            }))
            .expect("create private persisted session");
        for ordinal in 1..=40_i64 {
            let message_id = format!("{session_id}-history-{ordinal}");
            persistence
                .message_append(&json!({
                    "id": message_id,
                    "session_id": session_id,
                    "role": if ordinal % 2 == 0 { "assistant" } else { "user" },
                    "content_json": json!([{"type":"text", "text":format!("{session_id} fact {ordinal}")}]).to_string(),
                    "name": "",
                    "tool_call_id": "",
                    "parent_message_id": "",
                    "token_estimate": 1,
                    "metadata_json": "{}",
                    "run_id": "",
                    "finish_reason": "",
                    "now_ms": now_ms + ordinal,
                }))
                .expect("append private production history");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn durable_worker_measures_compaction_lookup_to_first_provider() {
        const SESSION_ID: &str = "compaction-cache-measure-session";

        let root = private_root();
        let db_path = root.join("gateway.db");
        let setup = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &db_path)
            .expect("open private durable measurement fixture");
        let persistence = setup.persistence().expect("private persistence");
        seed_session(&persistence, SESSION_ID, 10);
        drop(persistence);
        drop(setup);

        let state = AgentGatewayState::with_agent_file_and_sqlite(
            AgentGatewayConfig::default(),
            crate::runtime::rss_runner::bundled_agent_main_path(),
            &db_path,
        )
        .expect("reload durable measurement fixture with production service");
        let service = state.service();
        let scripted = crate::runtime::agent_host::ScriptedProvider::new();
        scripted.push_ok(json!({
            "text": "measurement answer",
            "tool_calls": [],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "reasoning": "",
            "stop_reason": "stop"
        }));
        let lookup_at = Arc::new(Mutex::new(None));
        let elapsed_us = Arc::new(Mutex::new(None));
        *service
            .inner
            .compaction_runner_lookup_entered
            .lock()
            .expect("compaction runner lookup observer lock") = Some(Arc::new({
            let lookup_at = Arc::clone(&lookup_at);
            move || {
                let mut started = lookup_at.lock().expect("lookup timestamp lock");
                if started.is_none() {
                    *started = Some(Instant::now());
                }
            }
        }));
        service.inject_provider_host(Arc::new(CompactionTimingProvider {
            inner: scripted.clone(),
            lookup_at: Arc::clone(&lookup_at),
            elapsed_us: Arc::clone(&elapsed_us),
            first_call: AtomicBool::new(false),
        }));

        let admitted = service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"measure durable compaction refresh"}),
                session_id: Some(SESSION_ID.to_string()),
                platform: "compaction-cache-measurement".to_string(),
                ..AdmitRunRequest::default()
            })
            .await
            .expect("admit durable measurement run");
        tokio::time::timeout(
            Duration::from_secs(20),
            service
                .clone()
                .run_worker(admitted.run_id.clone(), "ignored".to_string()),
        )
        .await
        .expect("durable measurement worker should complete");

        let measured_us = *elapsed_us.lock().expect("provider timestamp lock");
        let constructions = service
            .inner
            .compaction_runner_constructions
            .load(Ordering::Relaxed);
        let provider_calls = scripted.call_count();
        let completed = service
            .run_events(&admitted.run_id)
            .iter()
            .any(|event| event["event"] == "run.completed");

        drop(service);
        drop(state);
        fs::remove_dir_all(root).expect("private durable measurement cleanup");
        assert!(
            measured_us.is_some(),
            "first provider call must follow compaction lookup"
        );
        assert_eq!(
            constructions, 1,
            "one service should build one immutable Runner"
        );
        assert_eq!(provider_calls, 1, "one provider call is expected");
        assert!(completed, "durable production worker should complete");
        eprintln!(
            "COMPACTION_CACHE_METRIC label=durable_lookup_to_first_provider elapsed_us={} runner_constructions={} provider_calls={} persisted_history_messages=40",
            measured_us.expect("measured provider boundary"),
            constructions,
            provider_calls
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn explicit_maintenance_blocks_only_new_same_session_admission_until_release() {
        let root = private_root();
        let db_path = root.join("gateway.db");
        let config = AgentGatewayConfig {
            max_concurrent_runs: 4,
            ..AgentGatewayConfig::default()
        };
        let setup = AgentGatewayState::with_sqlite_path(config.clone(), &db_path)
            .expect("open private production SQLite fixture");
        let persistence = setup.persistence().expect("private persistence");
        seed_session(&persistence, "maintenance-session-1", 10);
        seed_session(&persistence, "maintenance-session-2", 100);
        drop(persistence);
        drop(setup);

        let state = AgentGatewayState::with_sqlite_path(config, &db_path)
            .expect("reload private production SQLite fixture");
        let service = state.service();
        let persistence = state.persistence().expect("private persistence");
        let replay_request = AdmitRunRequest {
            input: json!({"prompt":"durable maintenance replay"}),
            session_id: Some("maintenance-session-1".to_string()),
            platform: "f3-maintenance-replay".to_string(),
            idempotency_key: Some("f3-maintenance-replay-key".to_string()),
            idempotency_hash: Some("fnv64:0123456789abcdef".to_string()),
            ..AdmitRunRequest::default()
        };
        let original = service
            .admit(replay_request.clone())
            .await
            .expect("create durable replay fixture through service admission");
        service
            .finish_failed(&original.run_id, json!({"error":"fixture completed"}))
            .await;
        let app = crate::gateway::build_agent_gateway_app(state.clone());
        let http_request = Request::builder()
            .method(Method::POST)
            .uri("/v1/runs")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "input":"HTTP admission during explicit maintenance",
                    "session_id":"maintenance-session-1"
                })
                .to_string(),
            ))
            .expect("HTTP admission request");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        *service
            .inner
            .compaction_maintenance_published
            .lock()
            .expect("compaction maintenance observer lock") = Some(Arc::new(move || {
            entered_tx
                .send(())
                .expect("publish explicit maintenance phase");
            release_rx
                .lock()
                .expect("maintenance phase barrier lock")
                .recv()
                .expect("release explicit maintenance phase");
        }));
        let explicit = tokio::task::spawn_blocking({
            let service = Arc::clone(&service);
            move || service.compact_session_explicit("maintenance-session-1")
        });
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .expect("maintenance observer task")
            .expect("explicit maintenance reached post-publication phase");

        let before_memory = {
            let store = service.inner.store.read();
            (
                store
                    .runs
                    .values()
                    .filter(|run| run.session_id == "maintenance-session-1")
                    .count(),
                store.sessions["maintenance-session-1"].messages.len(),
            )
        };
        let durable_before = persistence
            .session_get("maintenance-session-1")
            .expect("read durable history before admission attempts");
        let before = (
            before_memory.0,
            before_memory.1,
            durable_before["rows"][0][14].clone(),
        );
        let same_session = service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"must not race maintenance"}),
                session_id: Some("maintenance-session-1".to_string()),
                platform: "f3-maintenance-new".to_string(),
                ..AdmitRunRequest::default()
            })
            .await;
        let http_response = app.oneshot(http_request).await;
        let replay = service.admit(replay_request).await;
        let other_session = service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"independent session remains available"}),
                session_id: Some("maintenance-session-2".to_string()),
                platform: "f3-maintenance-independent".to_string(),
                ..AdmitRunRequest::default()
            })
            .await;
        let after_memory = {
            let store = service.inner.store.read();
            (
                store
                    .runs
                    .values()
                    .filter(|run| run.session_id == "maintenance-session-1")
                    .count(),
                store.sessions["maintenance-session-1"].messages.len(),
            )
        };
        let durable_after = persistence
            .session_get("maintenance-session-1")
            .expect("read durable history after admission attempts");
        let after = (
            after_memory.0,
            after_memory.1,
            durable_after["rows"][0][14].clone(),
        );
        release_tx
            .send(())
            .expect("release explicit maintenance barrier");
        let compacted = explicit
            .await
            .expect("explicit service task should finish")
            .expect("real RSS/SQLite explicit compaction should complete");
        let fresh = service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"same session after release"}),
                session_id: Some("maintenance-session-1".to_string()),
                platform: "f3-maintenance-after-release".to_string(),
                ..AdmitRunRequest::default()
            })
            .await;

        let busy = match same_session {
            Err(AdmitError::SessionMaintenanceBusy(error)) => error,
            result => panic!("new same-session admission must be excluded, got {result:?}"),
        };
        let http_response = http_response.expect("HTTP admission handler should respond");
        let http_status = http_response.status();
        let http_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(http_response.into_body(), usize::MAX)
                .await
                .expect("HTTP admission body"),
        )
        .expect("HTTP admission JSON");
        assert_eq!(http_status, StatusCode::CONFLICT);
        assert_eq!(http_body["error"]["code"], "session_busy");
        assert_eq!(busy.code, "session_busy");
        assert_eq!(busy.http_status, 409);
        assert_eq!(
            before, after,
            "rejection must leave session runs/history unchanged"
        );
        assert!(
            replay
                .expect("cached/durable replay should retain priority")
                .replayed
        );
        let independent_run_id = other_session
            .expect("spare global capacity should admit an independent session")
            .run_id;
        assert!(!independent_run_id.is_empty());
        assert_eq!(compacted["status"], Value::String("committed".to_string()));
        assert!(
            fresh.is_ok(),
            "same-session admission should resume after release"
        );

        let fresh_run_id = fresh
            .as_ref()
            .expect("fresh same-session admission")
            .run_id
            .clone();
        service
            .finish_failed(&fresh_run_id, json!({"error":"release fixture capacity"}))
            .await;
        service
            .finish_failed(
                &independent_run_id,
                json!({"error":"release independent fixture capacity"}),
            )
            .await;
        service.inject_compaction_policy_failure("F3_POLICY_SENTINEL");
        let failed_compaction = tokio::task::spawn_blocking({
            let service = Arc::clone(&service);
            move || service.compact_session_explicit("maintenance-session-2")
        })
        .await
        .expect("error cleanup task should finish");
        assert!(failed_compaction.is_err(), "injected RSS path should fail");
        assert!(
            !service
                .inner
                .session_maintenance
                .lock()
                .contains("maintenance-session-2"),
            "error return must RAII-release its session lease"
        );

        let error_recovery = service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"after error cleanup"}),
                session_id: Some("maintenance-session-2".to_string()),
                platform: "f3-maintenance-error-recovery".to_string(),
                ..AdmitRunRequest::default()
            })
            .await
            .expect("same-session admission should resume after compaction error");
        service
            .finish_failed(
                &error_recovery.run_id,
                json!({"error":"release error-recovery fixture capacity"}),
            )
            .await;

        *service
            .inner
            .compaction_maintenance_published
            .lock()
            .expect("compaction maintenance observer lock") = Some(Arc::new(|| {
            panic!("synthetic unwind after maintenance publication")
        }));
        let unwind = tokio::task::spawn_blocking({
            let service = Arc::clone(&service);
            move || service.compact_session_explicit("maintenance-session-2")
        })
        .await
        .expect_err("phase observer should unwind the explicit operation");
        assert!(unwind.is_panic());
        assert!(
            !service
                .inner
                .session_maintenance
                .lock()
                .contains("maintenance-session-2"),
            "unwind must RAII-release its session lease"
        );
        assert!(
            service
                .admit(AdmitRunRequest {
                    input: json!({"prompt":"after unwind cleanup"}),
                    session_id: Some("maintenance-session-2".to_string()),
                    platform: "f3-maintenance-unwind-recovery".to_string(),
                    ..AdmitRunRequest::default()
                })
                .await
                .is_ok(),
            "ordinary admission should resume after unwind releases the lease"
        );

        drop(service);
        drop(state);
        fs::remove_dir_all(root).expect("private maintenance fixture cleanup");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn materialize_prepares_compaction_runner_only_for_persisted_services() {
        let root = private_root();
        let state = AgentGatewayState::with_sqlite_path(
            AgentGatewayConfig::default(),
            root.join("gateway.db"),
        )
        .expect("open private persisted preparation fixture");
        let service = state.service();
        service
            .materialize_cached_runner()
            .expect("materialize the existing bundled agent runner");
        let persisted_constructions = service
            .inner
            .compaction_runner_constructions
            .load(Ordering::Relaxed);
        drop(service);
        drop(state);
        fs::remove_dir_all(&root).expect("private preparation fixture cleanup");
        assert_eq!(
            persisted_constructions, 1,
            "persistence-enabled preparation should warm one compaction Runner"
        );

        let memory_state = AgentGatewayState::with_agent_file(
            AgentGatewayConfig::default(),
            crate::runtime::rss_runner::bundled_agent_main_path(),
        )
        .expect("open in-memory preparation service");
        let memory_service = memory_state.service();
        memory_service
            .materialize_cached_runner()
            .expect("materialize the in-memory agent runner");
        assert_eq!(
            memory_service
                .inner
                .compaction_runner_constructions
                .load(Ordering::Relaxed),
            0,
            "in-memory preparation should not compile the unused compaction Runner"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persisted_context_refreshes_reuse_one_compaction_runner() {
        const SESSION_ID: &str = "compaction-cache-session";
        const RUN_ID: &str = "compaction-cache-run";

        let root = private_root();
        let db_path = root.join("gateway.db");
        let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &db_path)
            .expect("open private persisted compaction fixture");
        let persistence = state.persistence().expect("private persistence");
        seed_session(&persistence, SESSION_ID, 10);
        let service = state.service();
        service
            .inner
            .contexts
            .lock()
            .expect("contexts lock")
            .insert(
                RUN_ID.to_string(),
                crate::domain::RunContext {
                    run_id: RUN_ID.to_string(),
                    session_id: SESSION_ID.to_string(),
                    parent_run_id: None,
                    platform: "compaction-cache-test".to_string(),
                    input: json!({}),
                    messages: json!([]),
                    system_prompt: None,
                    model: "test-model".to_string(),
                    provider: Some("test-provider".to_string()),
                    provider_options: json!({}),
                    tool_schemas: json!([]),
                    limits: json!({}),
                    metadata: json!({}),
                    coding_system_prompt: None,
                },
            );
        let context = json!({ "session_id": SESSION_ID, "messages": [] });

        let first =
            service.refresh_provider_context(RUN_ID, &context, &super::RunCancellation::new());
        assert_eq!(
            first["ok"],
            json!(true),
            "first durable refresh must succeed"
        );
        assert_eq!(
            first["messages"].as_array().expect("first messages").len(),
            40
        );

        persistence
            .message_append(&json!({
                "id": format!("{SESSION_ID}-history-41"),
                "session_id": SESSION_ID,
                "role": "user",
                "content_json": json!([{"type":"text", "text":"new durable fact"}]).to_string(),
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 1,
                "metadata_json": "{}",
                "run_id": "",
                "finish_reason": "",
                "now_ms": 51,
            }))
            .expect("append current durable history through persistence API");
        let second =
            service.refresh_provider_context(RUN_ID, &context, &super::RunCancellation::new());
        assert_eq!(
            second["ok"],
            json!(true),
            "second durable refresh must succeed"
        );
        assert_eq!(
            second["messages"]
                .as_array()
                .expect("second messages")
                .len(),
            41,
            "refresh must reload current persisted history"
        );
        let constructions = service
            .inner
            .compaction_runner_constructions
            .load(Ordering::Relaxed);

        drop(service);
        drop(persistence);
        drop(state);
        fs::remove_dir_all(root).expect("private compaction fixture cleanup");
        assert_eq!(
            constructions, 1,
            "one service should construct its fixed compaction Runner once"
        );
    }

    // Coverage-only fixtures: real native storage and the unchanged bundled policy.
    struct CacheCoverageRoot(PathBuf);

    impl Drop for CacheCoverageRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct CacheCoverageFixture {
        service: Arc<super::AgentService>,
        _state: AgentGatewayState,
        persistence: Arc<crate::gateway::store::GatewayPersistence>,
        _root: CacheCoverageRoot,
    }

    fn coverage_summary(
        persistence: &crate::gateway::store::GatewayPersistence,
        session: &str,
        generation: i64,
        ordinal: i64,
        text: &str,
    ) {
        let run = format!("{session}-summary-run-{generation}");
        let id = format!("{session}-summary-{generation}");
        let now = super::timestamp() as i64 + generation;
        persistence
            .run_create(&json!({
                "id":run, "session_id":session, "parent_run_id":"", "input_json":"{}",
                "provider":"test-provider", "model":"test-model", "script_hash":"",
                "idempotency_scope":"", "idempotency_key":"", "now_ms":now
            }))
            .expect("create native summary run");
        for (from, to) in [("queued", "running"), ("running", "compacting")] {
            persistence
                .run_transition(&json!({
                    "run_id":run, "from_status":from, "to_status":to,
                    "error_code":"", "error_message":"", "recovery_reason":"", "now_ms":now
                }))
                .expect("transition native summary run");
        }
        persistence
            .compaction_start(&json!({
                "id":id, "session_id":session, "run_id":run, "generation":generation,
                "source_start_ordinal":ordinal, "source_end_ordinal":ordinal,
                "retained_tail_ordinal":ordinal, "summary_json":json!({"text":text}).to_string(),
                "token_estimate":1, "model":"test-model", "now_ms":now
            }))
            .expect("start native summary transaction");
        persistence
            .compaction_commit(&json!({
                "id":id, "session_id":session, "start_ordinal":ordinal, "end_ordinal":ordinal,
                "generation":generation, "completed_at_ms":now
            }))
            .expect("commit native summary transaction");
        persistence
            .run_transition(&json!({
                "run_id":run, "from_status":"compacting", "to_status":"completed",
                "error_code":"", "error_message":"", "recovery_reason":"", "now_ms":now
            }))
            .expect("complete native summary run");
        assert_eq!(
            super::load_durable_compaction_snapshot(persistence, session)
                .expect("read committed summary")
                .0,
            generation
        );
    }

    fn coverage_fixture() -> CacheCoverageFixture {
        let root = CacheCoverageRoot(private_root());
        let path = root.0.join("gateway.db");
        let setup = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
            .expect("open coverage fixture");
        let persistence = setup.persistence().expect("native fixture persistence");
        seed_session(&persistence, "cache-coverage-a", 10);
        seed_session(&persistence, "cache-coverage-b", 100);
        coverage_summary(
            &persistence,
            "cache-coverage-a",
            2,
            1,
            "alpha summary generation two",
        );
        coverage_summary(
            &persistence,
            "cache-coverage-b",
            2,
            1,
            "beta summary generation two",
        );
        coverage_summary(
            &persistence,
            "cache-coverage-b",
            3,
            2,
            "beta summary generation three",
        );
        drop(persistence);
        drop(setup);
        let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
            .expect("reload native coverage fixture");
        let service = state.service();
        let persistence = state.persistence().expect("reloaded persistence");
        service
            .materialize_cached_runner()
            .expect("warm real preparation path");
        assert_eq!(
            service
                .inner
                .compaction_runner_constructions
                .load(Ordering::Relaxed),
            1
        );
        CacheCoverageFixture {
            service,
            _state: state,
            persistence,
            _root: root,
        }
    }

    fn coverage_expected(session: &str, summary: &str, start: i64) -> Value {
        let mut messages =
            vec![json!({"role":"user", "content":[{"type":"text", "text":summary}]})];
        for ordinal in start..=40 {
            messages.push(json!({
                "id":format!("{session}-history-{ordinal}"), "session_id":session,
                "ordinal":ordinal, "role":if ordinal % 2 == 0 { "assistant" } else { "user" },
                "content":[{"type":"text", "text":format!("{session} fact {ordinal}")}],
                "compacted":0
            }));
        }
        json!(messages)
    }

    fn coverage_refresh(service: &super::AgentService, session: &str) -> Value {
        service
            .refresh_session_compaction(
                session,
                "coverage-skip-run",
                "test-model",
                false,
                &crate::RunCancellation::new(),
            )
            .expect("real RSS coverage refresh")
    }

    fn coverage_count(service: &super::AgentService) {
        assert_eq!(
            service
                .inner
                .compaction_runner_constructions
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn warmed_cache_keeps_two_durable_snapshots_current_and_isolated() {
        let f = coverage_fixture();
        let a = coverage_refresh(&f.service, "cache-coverage-a");
        let b = coverage_refresh(&f.service, "cache-coverage-b");
        assert_eq!(
            a,
            coverage_expected("cache-coverage-a", "alpha summary generation two", 2)
        );
        assert_eq!(
            b,
            coverage_expected("cache-coverage-b", "beta summary generation three", 3)
        );
        coverage_summary(
            &f.persistence,
            "cache-coverage-a",
            3,
            2,
            "alpha replacement generation three",
        );
        let changed_a = coverage_refresh(&f.service, "cache-coverage-a");
        assert_eq!(
            changed_a,
            coverage_expected("cache-coverage-a", "alpha replacement generation three", 3)
        );
        assert_ne!(changed_a, a);
        assert_eq!(coverage_refresh(&f.service, "cache-coverage-b"), b);
        assert_eq!(
            super::load_durable_compaction_snapshot(&f.persistence, "cache-coverage-a")
                .unwrap()
                .0,
            3
        );
        assert_eq!(
            super::load_durable_compaction_snapshot(&f.persistence, "cache-coverage-b")
                .unwrap()
                .0,
            3
        );
        coverage_count(&f.service);
    }

    // All test-owned threads are joined on success and unwind; the first barrier
    // is released before joining. Its own receive is bounded even if setup fails.
    struct CoverageThreads {
        release: Option<mpsc::Sender<()>>,
        threads: Vec<std::thread::JoinHandle<Value>>,
    }

    impl Drop for CoverageThreads {
        fn drop(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn warmed_cache_allows_overlapping_real_policy_contexts() {
        let f = coverage_fixture();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let invocations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *f.service.inner.compaction_policy_entered.lock().unwrap() = Some(Arc::new({
            let invocations = Arc::clone(&invocations);
            move |session| {
                invocations.fetch_add(1, Ordering::SeqCst);
                if session == "cache-coverage-a" {
                    entered_tx.send(()).expect("publish first policy boundary");
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .expect("bounded policy release");
                }
            }
        }));
        let mut owned = CoverageThreads {
            release: Some(release_tx),
            threads: Vec::new(),
        };
        owned.threads.push(std::thread::spawn({
            let service = Arc::clone(&f.service);
            move || coverage_refresh(&service, "cache-coverage-a")
        }));
        let first_entered = entered_rx.recv_timeout(Duration::from_secs(5));
        let (done_tx, done_rx) = mpsc::channel();
        if first_entered.is_ok() {
            owned.threads.push(std::thread::spawn({
                let service = Arc::clone(&f.service);
                move || {
                    let result = coverage_refresh(&service, "cache-coverage-b");
                    let _ = done_tx.send(());
                    result
                }
            }));
        }
        let second_completed_while_first_paused = done_rx.recv_timeout(Duration::from_secs(5));
        if let Some(release) = owned.release.take() {
            let _ = release.send(());
        }
        let joined = owned
            .threads
            .drain(..)
            .map(|thread| thread.join())
            .collect::<Vec<_>>();
        *f.service.inner.compaction_policy_entered.lock().unwrap() = None;
        assert!(
            first_entered.is_ok(),
            "first invocation must reach the policy boundary"
        );
        assert!(
            second_completed_while_first_paused.is_ok(),
            "other cache acquisition and actual RSS evaluation must complete before first release"
        );
        assert_eq!(joined.len(), 2);
        let mut outputs = joined
            .into_iter()
            .map(|result| result.expect("owned policy thread joined"));
        assert_eq!(
            outputs.next().unwrap(),
            coverage_expected("cache-coverage-a", "alpha summary generation two", 2)
        );
        assert_eq!(
            outputs.next().unwrap(),
            coverage_expected("cache-coverage-b", "beta summary generation three", 3)
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 2);
        coverage_count(&f.service);
    }

    fn coverage_event_count(
        persistence: &crate::gateway::store::GatewayPersistence,
        run: &str,
        name: &str,
    ) -> usize {
        let page = persistence
            .event_replay(
                &json!({"run_id":run, "after_seq":0, "max_events":256, "max_bytes":65536}),
            )
            .expect("read actual durable event boundary");
        let columns = page["columns"].as_array().expect("durable event columns");
        let event_type = columns
            .iter()
            .position(|value| value == "event_type")
            .expect("event type column");
        page["rows"]
            .as_array()
            .expect("durable events")
            .iter()
            .filter(|row| row[event_type] == name)
            .count()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn warmed_cache_failures_cancel_deadline_reload_without_request_effects() {
        let f = coverage_fixture();
        use crate::AgentProviderHost;
        let admitted = f
            .service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"coverage failure"}),
                session_id: Some("cache-coverage-a".to_string()),
                platform: "cache-coverage".to_string(),
                ..AdmitRunRequest::default()
            })
            .await
            .expect("admit real failure context");
        let raw = crate::runtime::agent_host::ScriptedProvider::new();
        let host = crate::durable_provider::DurableProviderHost::new(
            super::AgentService::clone(f.service.as_ref()),
            admitted.run_id.clone(),
            Arc::new(raw.clone()),
            Arc::clone(&f.service.inner.metrics),
        );
        let context = json!({"session_id":"cache-coverage-a", "messages":[]});
        assert_eq!(
            host.refresh_context(&context, &crate::RunCancellation::new())
                .unwrap()["ok"],
            true
        );
        coverage_count(&f.service);
        f.service
            .inject_compaction_policy_failure("CACHE_COVERAGE_POLICY_FAILURE");
        let policy = host
            .refresh_context(&context, &crate::RunCancellation::new())
            .unwrap();
        assert_eq!(policy["ok"], false);
        assert_eq!(policy["error"]["code"], "context_refresh_failed");
        let cancelled = crate::RunCancellation::new();
        cancelled.request(super::CancellationReason::Requested);
        let expired = crate::RunCancellation::with_deadline(Instant::now());
        for cancellation in [&cancelled, &expired] {
            let failure = host.refresh_context(&context, cancellation).unwrap();
            assert_eq!(failure["ok"], false);
            assert_eq!(failure["error"]["code"], "cancelled");
        }
        assert_eq!(raw.call_count(), 0);
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "model.requested"),
            0
        );
        // Exercise the production main RSS refresh -> control -> provider path,
        // not only the provider bridge. Await the owned worker to completion;
        // no diagnostic timeout drops a worker future.
        f.service.inject_provider_host(Arc::new(raw.clone()));
        f.service
            .inject_compaction_policy_failure("CACHE_COVERAGE_WORKER_FAILURE");
        Arc::clone(&f.service)
            .run_worker(admitted.run_id.clone(), "ignored".to_string())
            .await;
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "run.failed"),
            1
        );
        assert_eq!(raw.call_count(), 0);
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "model.requested"),
            0
        );
        coverage_summary(
            &f.persistence,
            "cache-coverage-a",
            3,
            2,
            "alpha after failure generation three",
        );
        let current = host
            .refresh_context(&context, &crate::RunCancellation::new())
            .unwrap();
        assert_eq!(current["ok"], true);
        assert_eq!(
            current["messages"][0],
            json!({"role":"user", "content":[{"type":"text", "text":"alpha after failure generation three"}]})
        );
        assert_eq!(
            current["messages"][1]["content"],
            json!([{"type":"text", "text":"cache-coverage-a fact 3"}])
        );
        assert_eq!(
            super::load_durable_compaction_snapshot(&f.persistence, "cache-coverage-a")
                .unwrap()
                .0,
            3
        );
        assert_eq!(raw.call_count(), 0);
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "model.requested"),
            0
        );
        coverage_count(&f.service);
        f.service
            .finish_failed(
                &admitted.run_id,
                json!({"error":"coverage fixture completed"}),
            )
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn warmed_cache_rejects_real_native_generation_conflict_then_refreshes() {
        let f = coverage_fixture();
        assert_eq!(
            coverage_refresh(&f.service, "cache-coverage-a"),
            coverage_expected("cache-coverage-a", "alpha summary generation two", 2)
        );
        let once = Arc::new(AtomicBool::new(false));
        *f.service.inner.compaction_policy_entered.lock().unwrap() = Some(Arc::new({
            let persistence = Arc::clone(&f.persistence);
            move |session| {
                if session == "cache-coverage-a" && !once.swap(true, Ordering::SeqCst) {
                    // Snapshot was loaded at generation 2. A real competing native
                    // transaction commits generation 3 before the RSS plan executes.
                    coverage_summary(
                        &persistence,
                        session,
                        3,
                        2,
                        "alpha competing generation three",
                    );
                }
            }
        }));
        let stale = f.service.compact_session_explicit("cache-coverage-a");
        *f.service.inner.compaction_policy_entered.lock().unwrap() = None;
        let stale = stale.expect_err("stale generation plan must fail closed");
        assert_eq!(stale.code, "compaction_failed");
        assert!(
            stale
                .diagnostic_detail()
                .contains("compaction_already_committed"),
            "native typed conflict must propagate"
        );
        assert_eq!(
            super::load_durable_compaction_snapshot(&f.persistence, "cache-coverage-a")
                .unwrap()
                .0,
            3
        );
        assert_eq!(
            coverage_refresh(&f.service, "cache-coverage-a"),
            coverage_expected("cache-coverage-a", "alpha competing generation three", 3)
        );
        let valid = f
            .service
            .compact_session_explicit("cache-coverage-a")
            .expect("fresh generation plan commits");
        assert_eq!(valid["generation"], 4);
        assert_eq!(valid["status"], "committed");
        assert_eq!(
            super::load_durable_compaction_snapshot(&f.persistence, "cache-coverage-a")
                .unwrap()
                .0,
            4
        );
        coverage_count(&f.service);
    }

    struct CoverageOrderedProvider {
        persistence: Arc<crate::gateway::store::GatewayPersistence>,
        run: String,
        inner: crate::runtime::agent_host::ScriptedProvider,
        committed_entries: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::AgentProviderHost for CoverageOrderedProvider {
        fn call(&self, request: &Value, cancellation: &crate::RunCancellation) -> Value {
            assert_eq!(
                coverage_event_count(&self.persistence, &self.run, "model.requested"),
                1,
                "raw provider entry requires the durable request commit"
            );
            self.committed_entries.fetch_add(1, Ordering::SeqCst);
            self.inner.call(request, cancellation)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn warmed_cache_durable_request_commit_precedes_raw_call_and_replay() {
        use crate::AgentProviderHost;
        let f = coverage_fixture();
        let admitted = f
            .service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"coverage durable ordering"}),
                session_id: Some("cache-coverage-a".to_string()),
                platform: "cache-coverage".to_string(),
                ..AdmitRunRequest::default()
            })
            .await
            .expect("admit actual durable provider run");
        let raw = crate::runtime::agent_host::ScriptedProvider::new();
        raw.push_ok(json!({"text":"coverage answer", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
        let committed_entries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ordered: Arc<dyn crate::AgentProviderHost> = Arc::new(CoverageOrderedProvider {
            persistence: Arc::clone(&f.persistence),
            run: admitted.run_id.clone(),
            inner: raw.clone(),
            committed_entries: Arc::clone(&committed_entries),
        });
        let make_host = || {
            crate::durable_provider::DurableProviderHost::new(
                super::AgentService::clone(f.service.as_ref()),
                admitted.run_id.clone(),
                Arc::clone(&ordered),
                Arc::clone(&f.service.inner.metrics),
            )
        };
        let host = make_host();
        let context = json!({"session_id":"cache-coverage-a", "messages":[]});
        assert_eq!(
            host.refresh_context(&context, &crate::RunCancellation::new())
                .unwrap()["ok"],
            true
        );
        coverage_count(&f.service);
        let request = json!({"model":"test-model", "provider":"test-provider"});
        f.persistence.inject_fail_model_requested_append();
        let failed = host.call(&request, &crate::RunCancellation::new());
        assert_eq!(failed["error"]["code"], "provider_step_persist_failed");
        assert_eq!(raw.call_count(), 0);
        assert_eq!(committed_entries.load(Ordering::SeqCst), 0);
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "model.requested"),
            0
        );
        f.service.inject_crash_after_provider_request();
        let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host.call(&request, &crate::RunCancellation::new())
        }));
        assert!(crash.is_err());
        assert_eq!(raw.call_count(), 0);
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "model.requested"),
            1
        );
        let redrive = make_host();
        assert_eq!(
            redrive
                .refresh_context(&context, &crate::RunCancellation::new())
                .unwrap()["ok"],
            true
        );
        let success = redrive.call(&request, &crate::RunCancellation::new());
        assert_eq!(success["ok"], true);
        assert_eq!(raw.call_count(), 1);
        assert_eq!(committed_entries.load(Ordering::SeqCst), 1);
        let replay = make_host();
        assert_eq!(
            replay
                .refresh_context(&context, &crate::RunCancellation::new())
                .unwrap()["ok"],
            true
        );
        let replayed = replay.call(&request, &crate::RunCancellation::new());
        assert_eq!(replayed, success);
        assert_eq!(raw.call_count(), 1);
        assert_eq!(committed_entries.load(Ordering::SeqCst), 1);
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "model.requested"),
            1
        );
        assert_eq!(
            coverage_event_count(&f.persistence, &admitted.run_id, "model.completed"),
            1
        );
        assert_eq!(
            f.service
                .session_messages("cache-coverage-a")
                .iter()
                .filter(|message| message["content"]
                    == json!([{"type":"text", "text":"coverage answer"}]))
                .count(),
            1
        );
        coverage_count(&f.service);
        f.service
            .finish_failed(
                &admitted.run_id,
                json!({"error":"coverage fixture completed"}),
            )
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn durable_only_replay_precedes_session_maintenance_rejection() {
        const SESSION_ID: &str = "maintenance-durable-only-session";
        const OTHER_SESSION_ID: &str = "maintenance-durable-only-other";
        const REPLAY_KEY: &str = "f3-durable-only-replay-key";
        const CACHED_KEY: &str = "f3-maintenance-cached-replay-key";

        let root = private_root();
        let db_path = root.join("gateway.db");
        let config = AgentGatewayConfig {
            max_concurrent_runs: 4,
            ..AgentGatewayConfig::default()
        };
        let setup = AgentGatewayState::with_sqlite_path(config.clone(), &db_path)
            .expect("open private production SQLite fixture");
        let persistence = setup.persistence().expect("private persistence");
        seed_session(&persistence, SESSION_ID, 10);
        seed_session(&persistence, OTHER_SESSION_ID, 100);
        drop(persistence);
        drop(setup);

        let state = AgentGatewayState::with_sqlite_path(config, &db_path)
            .expect("reload private production SQLite fixture");
        let service = state.service();
        let persistence = state.persistence().expect("private persistence");
        let replay_request = AdmitRunRequest {
            input: json!({"prompt":"durable-only maintenance replay"}),
            session_id: Some(SESSION_ID.to_string()),
            platform: "f3-durable-only-replay".to_string(),
            idempotency_key: Some(REPLAY_KEY.to_string()),
            idempotency_hash: Some("fnv64:fedcba9876543210".to_string()),
            ..AdmitRunRequest::default()
        };
        let original = service
            .admit(replay_request.clone())
            .await
            .expect("create durable replay fixture through service admission");
        service
            .finish_failed(
                &original.run_id,
                json!({"error":"durable replay fixture completed"}),
            )
            .await;
        let cached_request = AdmitRunRequest {
            input: json!({"prompt":"cached replay remains available"}),
            session_id: Some(SESSION_ID.to_string()),
            platform: "f3-cached-replay".to_string(),
            idempotency_key: Some(CACHED_KEY.to_string()),
            idempotency_hash: Some("fnv64:0011223344556677".to_string()),
            ..AdmitRunRequest::default()
        };
        let cached_original = service
            .admit(cached_request.clone())
            .await
            .expect("create independent cached replay fixture");
        service
            .finish_failed(
                &cached_original.run_id,
                json!({"error":"cached replay fixture completed"}),
            )
            .await;

        let durable_identity = persistence
            .admission_replay(
                super::ADMISSION_IDEMPOTENCY_SCOPE,
                REPLAY_KEY,
                replay_request
                    .idempotency_hash
                    .as_deref()
                    .expect("fixture hash"),
                None,
            )
            .expect("read persisted idempotency record before cache eviction");
        assert_eq!(durable_identity["replayed"], Value::Bool(true));
        let durable_identity_run =
            crate::sqlite_storage_rows::sqlite_storage_first_row(&durable_identity["run"])
                .expect("durable replay exposes the stored run row");
        assert_eq!(durable_identity_run[0], original.run_id);
        let durable_original = persistence
            .run_get(&original.run_id)
            .expect("read durable original run before cache eviction");
        let durable_run_columns = durable_original["columns"]
            .as_array()
            .expect("durable run columns");
        let idempotency_key_column = durable_run_columns
            .iter()
            .position(|column| column == "idempotency_key")
            .expect("durable run carries its idempotency key");
        let status_column = durable_run_columns
            .iter()
            .position(|column| column == "status")
            .expect("durable run carries its current status");
        let durable_run_status = durable_original["rows"][0][status_column]
            .as_str()
            .expect("durable run status")
            .to_string();
        assert_eq!(
            durable_original["rows"][0][idempotency_key_column], REPLAY_KEY,
            "the admission transaction durably committed the keyed run"
        );
        let durable_session_before = persistence
            .session_get(SESSION_ID)
            .expect("read durable session before maintenance");
        let durable_events_before = persistence
            .event_replay(&json!({
                "run_id": original.run_id,
                "after_seq": 0,
                "max_events": 256,
                "max_bytes": 65536,
            }))
            .expect("read durable admission events before maintenance");
        service
            .inner
            .store
            .write()
            .idempotency
            .remove(REPLAY_KEY)
            .expect("remove only the target in-memory idempotency entry");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        *service
            .inner
            .compaction_maintenance_published
            .lock()
            .expect("compaction maintenance observer lock") = Some(Arc::new(move || {
            entered_tx
                .send(())
                .expect("publish explicit maintenance phase");
            release_rx
                .lock()
                .expect("maintenance phase barrier lock")
                .recv()
                .expect("release explicit maintenance phase");
        }));
        let explicit = tokio::task::spawn_blocking({
            let service = Arc::clone(&service);
            move || service.compact_session_explicit(SESSION_ID)
        });
        let mut release = MaintenanceBarrierRelease(Some(release_tx));
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .expect("maintenance observer task")
            .expect("explicit maintenance reached post-publication phase");

        let memory_before = {
            let store = service.inner.store.read();
            let session = &store.sessions[SESSION_ID];
            (
                store
                    .runs
                    .values()
                    .filter(|run| run.session_id == SESSION_ID)
                    .count(),
                session.messages.len(),
                session.view.updated_at,
                store.idempotency.get(CACHED_KEY).map(|record| {
                    (
                        record.request_hash.clone(),
                        record.run_id.clone(),
                        record.workspace_identity_json.clone(),
                    )
                }),
            )
        };
        let fresh_unmatched = service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"fresh key remains blocked"}),
                session_id: Some(SESSION_ID.to_string()),
                platform: "f3-fresh-unmatched".to_string(),
                idempotency_key: Some("f3-fresh-unmatched-key".to_string()),
                idempotency_hash: Some("fnv64:abcdef0123456789".to_string()),
                ..AdmitRunRequest::default()
            })
            .await;
        let matching_retry = service.admit(replay_request.clone()).await;
        let hash_conflict = service
            .admit(AdmitRunRequest {
                idempotency_hash: Some("fnv64:0000000000000000".to_string()),
                ..replay_request.clone()
            })
            .await;
        let selector_conflict = service
            .admit_with_workspace_selector(
                replay_request.clone(),
                Some("f3-selector-that-is-not-configured".to_string()),
            )
            .await;
        let cached_replay = service.admit(cached_request).await;
        let independent_session = service
            .admit(AdmitRunRequest {
                input: json!({"prompt":"independent session has spare capacity"}),
                session_id: Some(OTHER_SESSION_ID.to_string()),
                platform: "f3-independent-session".to_string(),
                ..AdmitRunRequest::default()
            })
            .await;
        let memory_after = {
            let store = service.inner.store.read();
            let session = &store.sessions[SESSION_ID];
            (
                store
                    .runs
                    .values()
                    .filter(|run| run.session_id == SESSION_ID)
                    .count(),
                session.messages.len(),
                session.view.updated_at,
                store.idempotency.get(CACHED_KEY).map(|record| {
                    (
                        record.request_hash.clone(),
                        record.run_id.clone(),
                        record.workspace_identity_json.clone(),
                    )
                }),
            )
        };
        let durable_session_after = persistence
            .session_get(SESSION_ID)
            .expect("read durable session during maintenance");
        let durable_run_after = persistence
            .run_get(&original.run_id)
            .expect("read durable original run during maintenance");
        let durable_events_after = persistence
            .event_replay(&json!({
                "run_id": original.run_id,
                "after_seq": 0,
                "max_events": 256,
                "max_bytes": 65536,
            }))
            .expect("read durable admission events during maintenance");

        release.release();
        let compacted = explicit
            .await
            .expect("explicit service task should finish")
            .expect("real RSS/SQLite explicit compaction should complete");

        let replayed =
            matching_retry.expect("durable-only matching retry must precede maintenance rejection");
        assert_eq!(replayed.run_id, original.run_id);
        assert_eq!(replayed.session_id, SESSION_ID);
        assert_eq!(replayed.status, durable_run_status);
        assert!(replayed.replayed);
        assert!(matches!(
            hash_conflict,
            Err(AdmitError::IdempotencyConflict)
        ));
        assert!(matches!(
            selector_conflict,
            Err(AdmitError::IdempotencyConflict)
        ));
        assert!(matches!(
            fresh_unmatched,
            Err(AdmitError::SessionMaintenanceBusy(_))
        ));
        let cached_replay = cached_replay.expect("cached replay remains available");
        assert_eq!(cached_replay.run_id, cached_original.run_id);
        assert!(cached_replay.replayed);
        let independent = independent_session.expect("spare capacity admits another session");
        assert_eq!(independent.session_id, OTHER_SESSION_ID);
        assert_eq!(memory_before, memory_after);
        assert_eq!(durable_session_before, durable_session_after);
        assert_eq!(durable_original, durable_run_after);
        assert_eq!(durable_events_before, durable_events_after);
        assert_eq!(compacted["status"], Value::String("committed".to_string()));

        service
            .finish_failed(
                &independent.run_id,
                json!({"error":"release independent fixture capacity"}),
            )
            .await;
        drop(service);
        drop(state);
        fs::remove_dir_all(root).expect("private maintenance fixture cleanup");
    }
}

#[cfg(test)]
mod external_legacy_admission_tests {
    use super::*;
    use crate::gateway::AgentGatewayState;

    const INLINE_SOURCE: &str = "pub fn run(input: map) -> string { \"ok\"; }";

    fn short_config() -> AgentGatewayConfig {
        AgentGatewayConfig {
            run_timeout: Duration::from_secs(2),
            ..AgentGatewayConfig::default()
        }
    }

    fn private_root(tag: &str) -> PathBuf {
        let base = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
            .or_else(|| std::env::var_os("TEST_TMPDIR"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = base.join(format!("external-legacy-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("private external-legacy fixture directory");
        root
    }

    fn external_request() -> AdmitRunRequest {
        AdmitRunRequest {
            input: json!({"message": "external legacy eligibility probe"}),
            platform: "external-legacy-test".to_string(),
            ..AdmitRunRequest::default()
        }
    }

    async fn assert_external_without_legacy_root(
        service: &AgentService,
        trusted: &std::path::Path,
    ) {
        let admitted = service
            .admit_external_with_workspace_selector(external_request(), None)
            .await
            .expect("external selector-None admission must start without the legacy root");
        assert_eq!(admitted.status, "started");
        let handle = service
            .handle(&admitted.run_id)
            .expect("admitted external run handle exists");
        assert!(
            handle.workspace_authority.is_none(),
            "external admission must not adopt workspace authority"
        );
        assert!(
            handle.legacy_workspace_root.is_none(),
            "external admission must not capture the legacy root"
        );
        let binding = service
            .inner
            .store
            .read()
            .sessions
            .get(&admitted.session_id)
            .and_then(|session| session.view.workspace.clone());
        assert!(
            binding.is_none(),
            "external admission must leave the session unbound"
        );
        let internal = service
            .admit(external_request())
            .await
            .expect("ordinary legacy-enabled admission must still start");
        assert_eq!(internal.status, "started");
        let internal_handle = service
            .handle(&internal.run_id)
            .expect("admitted internal run handle exists");
        assert!(
            internal_handle.workspace_authority.is_none(),
            "selector-None internal admission adopts no authority without a factory"
        );
        assert_eq!(
            internal_handle.legacy_workspace_root.as_deref(),
            Some(trusted),
            "ordinary legacy-enabled admission still captures the normalized trusted root"
        );
        service.stop(&admitted.run_id);
        service.stop(&internal.run_id);
    }

    #[tokio::test]
    async fn external_selector_none_admits_without_legacy_root_memory() {
        let root = private_root("memory");
        let guard = root.join("legacy-workspace");
        std::fs::create_dir_all(&guard).expect("private legacy workspace guard");
        let state = AgentGatewayState::with_agent_source(short_config(), INLINE_SOURCE)
            .expect("inline RSS source should compile");
        let service = state.service();
        let limits = RunLimits::new(64, 128, 1024 * 1024, &guard)
            .expect("legacy workspace guard should validate");
        service
            .set_run_limits(limits.clone())
            .expect("trusted legacy root should install");
        assert_external_without_legacy_root(&service, &limits.workspace_root).await;
        drop(service);
        drop(state);
        std::fs::remove_dir_all(&root).expect("private external-legacy fixture cleanup");
    }

    #[tokio::test]
    async fn external_selector_none_admits_without_legacy_root_sqlite() {
        let root = private_root("sqlite");
        let guard = root.join("legacy-workspace");
        std::fs::create_dir_all(&guard).expect("private legacy workspace guard");
        let db_path = root.join("gateway.db");
        let state = AgentGatewayState::with_agent_source_and_sqlite(
            short_config(),
            INLINE_SOURCE,
            &db_path,
        )
        .expect("SQLite state should open");
        let service = state.service();
        let limits = RunLimits::new(64, 128, 1024 * 1024, &guard)
            .expect("legacy workspace guard should validate");
        service
            .set_run_limits(limits.clone())
            .expect("trusted legacy root should install");
        assert_external_without_legacy_root(&service, &limits.workspace_root).await;
        drop(service);
        drop(state);
        std::fs::remove_dir_all(&root).expect("private external-legacy fixture cleanup");
    }
}
