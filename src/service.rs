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
use std::sync::{
    Arc, Condvar, Mutex, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::{Mutex as ParkingMutex, RwLock};
use rustscript_vm::{
    CancellationReason, CancellationToken, HttpConfig, InvocationError, Value as VmValue,
};
use serde_json::{Map, Value as JsonValue, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::capabilities::{
    AllowAllApproval, CancellationFlag, CapabilityLifecycle, CapabilityOwner, DurableStarted,
    DurableToolLifecycle, LifecycleError, LifecycleLimits, SystemClock, UuidIssuer,
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
use crate::domain::{
    LlmContentBlock, MAX_DURABLE_TEXT_CHARS, RunContext, ToolCall, decode_message_blocks,
    decode_message_content, durable_message_id, durable_provider_event_id, durable_tool_event_id,
    encode_message_content, provider_pending_may_retry, timestamp, truncate_for_log,
    truncate_utf8_chars, vm_value_to_json,
};
use crate::events;
use crate::gateway::store::{
    GatewayEvent, GatewayPersistence, GatewayStore, IdempotencyRecord, RunRecord, SessionMessage,
    SessionRecord, SessionView,
};
use crate::metrics::{AdmitRejectReason, Metrics, TerminalRetryOutcome, TerminalStatus};
use crate::prompt::{CodingPromptBudgets, DateSource, SystemDateSource, build_coding_prompt};
use crate::runtime::delivery::{
    ChannelEventSink, DeliveryContext, apply_event_locked, event_candidate, run_delivery_task,
};
use crate::runtime::rss_runner::{AgentConfig, AgentRunner};
use crate::tools::artifacts::ArtifactStorePool;
use crate::tools::{
    ArtifactError, ArtifactOwner, ArtifactStore, DispatchContext, DispatchLimits,
    DurableEventCommitter, EventCommitError, FileTools, NativeExecutionDeps, ProcessArtifactSink,
    ProcessExecutor, ProcessOwner, ProcessTable, TerminalExecutor, ToolOwner, ToolRegistry,
    ToolRegistrySnapshot, ToolResult,
};
use crate::{AgentHostBridges, AgentProviderHost, RunCancellation, RunError};

/// Typed outcome of bounded native-host cleanup. Never claims success when
/// dispatcher or process residue could not be confirmed stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    Clean,
    Timeout,
    Failed,
}

struct CachedAgentRunner {
    source_digest: u64,
    config: AgentConfig,
    runner: AgentRunner,
}

fn agent_source_digest(source: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    source.hash(&mut hasher);
    hasher.finish()
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
    /// Run-scoped native dispatch state shared by every `dispatch_tools` call.
    native_dispatch: Mutex<NativeDispatchPhase>,
    native_dispatch_cv: Condvar,
    /// Frozen coding system prompt captured at admission.
    coding_system_prompt: Arc<str>,
    /// Exclusive worker occupancy. Concurrent `run_worker` tasks cannot both
    /// call the provider or advance the turn. Released on Drop (error/panic).
    occupancy: AtomicBool,
}

/// Shared native dispatch machinery for one admitted run.
struct NativeDispatchState {
    dispatcher: DispatchContext,
    files: FileTools,
    table: Arc<ProcessTable>,
    cleaned: AtomicBool,
    shutdown_entered: Option<Arc<dyn Fn() + Send + Sync>>,
    cleanup_grace: Duration,
    lifecycle: Arc<CapabilityLifecycle>,
    capability_owner: CapabilityOwner,
}

/// Two-phase native dispatch slot. The handle lock is never held across
/// FileTools/ArtifactStore filesystem IO. `Closed` retains the process table so
/// residue stays observable after FileTools are released.
enum NativeDispatchPhase {
    Empty,
    Initializing,
    Ready(Arc<NativeDispatchState>),
    Closed(Option<ClosedDispatch>),
}

#[derive(Clone)]
struct ClosedDispatch {
    table: Arc<ProcessTable>,
    owner: ProcessOwner,
}

/// Restores a retriable `Empty` phase if initialization panics or returns
/// `Err` before `Ready` is published. Drop never waits on IO or the condvar.
struct NativeDispatchInitGuard {
    handle: Arc<RunHandle>,
    armed: bool,
}

impl NativeDispatchInitGuard {
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

impl Drop for NativeDispatchInitGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut phase = self
            .handle
            .native_dispatch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*phase, NativeDispatchPhase::Initializing) {
            *phase = NativeDispatchPhase::Empty;
        }
        self.handle.native_dispatch_cv.notify_all();
    }
}

impl NativeDispatchState {
    fn owner(&self) -> ProcessOwner {
        ProcessOwner::from(self.dispatcher.owner().clone())
    }

    fn shutdown(&self) -> CleanupOutcome {
        self.shutdown_with_grace(self.cleanup_grace)
    }

    fn shutdown_with_grace(&self, grace: Duration) -> CleanupOutcome {
        if self.cleaned.swap(true, Ordering::SeqCst) {
            return if self.table.owner_count(&self.owner()) == 0 {
                CleanupOutcome::Clean
            } else {
                CleanupOutcome::Timeout
            };
        }
        if let Some(observer) = &self.shutdown_entered {
            observer();
        }
        let _ = self.lifecycle.recover_open_tokens();
        self.dispatcher.close();
        let quiesced = self.dispatcher.try_quiesce(grace);
        let owner = self.owner();
        let _ = self.table.cleanup_owner(&owner);
        let _ = self
            .files
            .artifact_store_arc()
            .cleanup_owner(&ArtifactOwner::from(self.dispatcher.owner().clone()));
        if !quiesced || self.table.owner_count(&owner) > 0 {
            CleanupOutcome::Timeout
        } else {
            CleanupOutcome::Clean
        }
    }
}

impl Drop for NativeDispatchState {
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
    /// native dispatcher child tokens are linked to it.
    pub fn cancellation(&self) -> &RunCancellation {
        &self.cancel
    }

    fn request_user_stop(&self) {
        *self.cancel_reason.lock().expect("cancel reason lock") = Some("requested");
        self.cancel.request(CancellationReason::Requested);
        self.cancel_native_tools();
    }

    fn cancel_native_tools(&self) {
        self.tool_cancel.cancel();
        let lifecycle = {
            let phase = self
                .native_dispatch
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match &*phase {
                NativeDispatchPhase::Ready(state) => Some(Arc::clone(&state.lifecycle)),
                _ => None,
            }
        };
        if let Some(lifecycle) = lifecycle {
            let _ = lifecycle.recover_open_tokens();
        }
    }

    fn native_dispatch_closed(&self) -> bool {
        matches!(
            *self.native_dispatch.lock().expect("native dispatch lock"),
            NativeDispatchPhase::Closed(_)
        )
    }

    fn release_native_dispatch(&self) -> CleanupOutcome {
        self.tool_cancel.cancel();
        let state = {
            let mut phase = self.native_dispatch.lock().expect("native dispatch lock");
            match std::mem::replace(&mut *phase, NativeDispatchPhase::Closed(None)) {
                NativeDispatchPhase::Ready(state) => {
                    *phase = NativeDispatchPhase::Closed(Some(ClosedDispatch {
                        table: Arc::clone(&state.table),
                        owner: state.owner(),
                    }));
                    self.native_dispatch_cv.notify_all();
                    Some(state)
                }
                NativeDispatchPhase::Closed(existing) => {
                    *phase = NativeDispatchPhase::Closed(existing);
                    self.native_dispatch_cv.notify_all();
                    None
                }
                NativeDispatchPhase::Empty | NativeDispatchPhase::Initializing => {
                    self.native_dispatch_cv.notify_all();
                    None
                }
            }
        };
        match state {
            Some(state) => state.shutdown(),
            None => CleanupOutcome::Clean,
        }
    }

    fn native_dispatch_retained(&self) -> bool {
        matches!(
            *self.native_dispatch.lock().expect("native dispatch lock"),
            NativeDispatchPhase::Ready(_)
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
        self.handle.cancel_native_tools();
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

fn cancelled_dispatch_results(calls: &[ToolCall], terminal: bool) -> Vec<ToolResult> {
    let message = if terminal {
        "run already committed a terminal state"
    } else {
        "native dispatch is closed"
    };
    calls
        .iter()
        .map(|_| ToolResult::failure("cancelled", message))
        .collect()
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

#[derive(Debug)]
pub enum AdmitError {
    RunLimitReached,
    IdempotencyConflict,
    ParentNotFound,
    SessionNotFound,
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

#[derive(Clone)]
pub struct AgentService {
    inner: Arc<AgentServiceInner>,
}

struct AgentServiceInner {
    config: Arc<AgentGatewayConfig>,
    store: Arc<RwLock<GatewayStore>>,
    persistence: Option<Arc<GatewayPersistence>>,
    agent_source: Option<Arc<String>>,
    http_config: HttpConfig,
    tool_registry: RwLock<ToolRegistry>,
    provider_profiles: RwLock<HashMap<String, ProviderProfile>>,
    run_limits: RwLock<RunLimits>,
    contexts: Mutex<HashMap<String, RunContext>>,
    context_registries: Mutex<HashMap<String, ToolRegistrySnapshot>>,
    context_cache_capacity: usize,
    capacity: Arc<Semaphore>,
    runs: Mutex<HashMap<String, Arc<RunHandle>>>,
    pending: Mutex<HashMap<String, PendingTerminal>>,
    halting: AtomicBool,
    store_generation: AtomicU64,
    metrics: Arc<Metrics>,
    file_search_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    native_dispatch_shutdown: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    native_dispatch_init_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    prompt_read_entered: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    artifact_stores: ArtifactStorePool,
    date_source: RwLock<Arc<dyn DateSource>>,
    /// Optional one-shot injected provider host for tests. Consumed atomically
    /// by the next `run_worker`; production uses RssAdapterProvider.
    provider_host: Mutex<Option<Arc<dyn AgentProviderHost>>>,
    /// Compiled agent source reused across workers so compile does not reset the deadline.
    runner: Mutex<Option<CachedAgentRunner>>,
    /// When set, the next native dispatcher holds its serial mutex until released.
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
            handle.release_native_dispatch();
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
    ) -> Self {
        let capacity = Arc::new(Semaphore::new(config.max_concurrent_runs));
        let context_cache_capacity = config.max_concurrent_runs.saturating_mul(4).max(16);
        normalize_loaded_session_messages(&store);
        let default_registry = ToolRegistry::builtin().expect("built-in tool registry validates");
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
            store,
            persistence,
            agent_source,
            http_config,
            tool_registry: RwLock::new(default_registry),
            provider_profiles: RwLock::new(provider_profiles),
            run_limits: RwLock::new(RunLimits::default()),
            contexts: Mutex::new(HashMap::new()),
            context_registries: Mutex::new(HashMap::new()),
            context_cache_capacity,
            capacity,
            runs: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            halting: AtomicBool::new(false),
            store_generation: AtomicU64::new(0),
            metrics,
            file_search_entered: Mutex::new(None),
            native_dispatch_shutdown: Mutex::new(None),
            native_dispatch_init_entered: Mutex::new(None),
            prompt_read_entered: Mutex::new(None),
            artifact_stores: ArtifactStorePool::default(),
            date_source: RwLock::new(Arc::new(SystemDateSource)),
            provider_host: Mutex::new(None),
            runner: Mutex::new(None),
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

    /// Installs or replaces a provider profile used by later admissions.
    pub fn upsert_provider_profile(&self, profile: ProviderProfile) {
        self.inner
            .provider_profiles
            .write()
            .insert(profile.name.clone(), profile);
    }

    /// Holds the next native dispatcher's serial mutex until
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
            .expect("runner cache lock")
            .as_ref()
            .map(|cached| cached.config.clone())
    }

    /// Compiles or reuses the cached runner using current source + effective config.
    pub fn materialize_cached_runner(&self) -> Result<AgentConfig, String> {
        let source = self
            .inner
            .agent_source
            .as_ref()
            .ok_or_else(|| "agent source is missing".to_string())?;
        Ok(self.cached_agent_runner(source)?.config().clone())
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
    /// and `agent_runtime::tool_commit`. Initializes native dispatch if needed.
    pub fn capability_lifecycle(
        &self,
        run_id: &str,
    ) -> Result<(Arc<CapabilityLifecycle>, CapabilityOwner), RunContextError> {
        let handle = self
            .handle(run_id)
            .ok_or_else(|| RunContextError::Missing {
                run_id: run_id.to_string(),
            })?;
        match self.native_dispatch_state(run_id, &handle)? {
            Some(state) => Ok((Arc::clone(&state.lifecycle), state.capability_owner.clone())),
            None => Err(RunContextError::InvalidMetadata {
                run_id: run_id.to_string(),
                reason: "native dispatch is closed".to_string(),
            }),
        }
    }

    /// Serial, validated native dispatch against the admitted registry snapshot.
    ///
    /// The live registry is not consulted. Durable event append uses the same
    /// store/persist/publish path as script delivery.
    pub fn dispatch_tools(
        &self,
        run_id: &str,
        calls: &[ToolCall],
    ) -> Result<Vec<ToolResult>, RunContextError> {
        let handle = self
            .handle(run_id)
            .ok_or_else(|| RunContextError::Missing {
                run_id: run_id.to_string(),
            })?;
        if handle.is_terminal() || handle.native_dispatch_closed() {
            return Ok(cancelled_dispatch_results(calls, handle.is_terminal()));
        }
        match self.native_dispatch_state(run_id, &handle)? {
            Some(state) => {
                let mut results = Vec::with_capacity(calls.len());
                let mut pending = Vec::new();
                let mut pending_idx = Vec::new();
                for (index, call) in calls.iter().enumerate() {
                    match self.replay_durable_tool_result(run_id, &call.id, &call.name) {
                        Ok(Some(replayed)) => results.push(Some(replayed)),
                        Ok(None) => {
                            results.push(None);
                            pending.push(call.clone());
                            pending_idx.push(index);
                        }
                        Err(error) => results.push(Some(replay_commit_failure(error))),
                    }
                }
                if !pending.is_empty() {
                    let dispatched = state.dispatcher.dispatch(&pending);
                    for (slot, result) in pending_idx.into_iter().zip(dispatched) {
                        if !result.replayed {
                            self.inner
                                .metrics
                                .account_tool_attempt(!result.ok, result.truncated);
                        }
                        results[slot] = Some(result);
                    }
                }
                Ok(results
                    .into_iter()
                    .map(|result| result.expect("dispatch slot filled"))
                    .collect())
            }
            None => Ok(cancelled_dispatch_results(calls, handle.is_terminal())),
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
                created_at: timestamp(),
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
                "now_ms": timestamp(),
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
                "now_ms": timestamp(),
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

    fn native_dispatch_state(
        &self,
        run_id: &str,
        handle: &Arc<RunHandle>,
    ) -> Result<Option<Arc<NativeDispatchState>>, RunContextError> {
        loop {
            let mut phase = handle.native_dispatch.lock().expect("native dispatch lock");
            if matches!(*phase, NativeDispatchPhase::Closed(_)) {
                return Ok(None);
            }
            if let NativeDispatchPhase::Ready(state) = &*phase {
                return Ok(Some(Arc::clone(state)));
            }
            if matches!(*phase, NativeDispatchPhase::Initializing) {
                drop(
                    handle
                        .native_dispatch_cv
                        .wait(phase)
                        .expect("native dispatch condvar"),
                );
                continue;
            }
            *phase = NativeDispatchPhase::Initializing;
            break;
        }
        let mut guard = NativeDispatchInitGuard::arm(handle);
        let observer = self
            .inner
            .native_dispatch_init_entered
            .lock()
            .expect("native dispatch init observer lock")
            .clone();
        if let Some(observer) = observer {
            observer();
        }
        let built = self.build_native_dispatch_state(run_id, handle);
        match built {
            Ok(state) => {
                let state = Arc::new(state);
                let mut phase = handle.native_dispatch.lock().expect("native dispatch lock");
                if matches!(*phase, NativeDispatchPhase::Initializing) {
                    *phase = NativeDispatchPhase::Ready(Arc::clone(&state));
                    handle.native_dispatch_cv.notify_all();
                    guard.disarm();
                    Ok(Some(state))
                } else {
                    handle.native_dispatch_cv.notify_all();
                    guard.disarm();
                    drop(phase);
                    drop(state);
                    Ok(None)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn build_native_dispatch_state(
        &self,
        run_id: &str,
        handle: &Arc<RunHandle>,
    ) -> Result<NativeDispatchState, RunContextError> {
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
        let toolset_hash = context
            .metadata
            .get("toolset_hash")
            .and_then(JsonValue::as_str)
            .unwrap_or(expected)
            .to_string();
        let owner = ToolOwner::new(
            ADMISSION_SESSION_PROFILE,
            &context.session_id,
            &context.run_id,
        )
        .map_err(|error| invalid_context_metadata(run_id, &error))?;
        let workspace = context
            .limits
            .get("workspace_root")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| invalid_context_metadata(run_id, "workspace_root is missing"))?;
        let workspace = PathBuf::from(workspace);
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
        let mut file_config = FileToolConfig::for_workspace(&workspace);
        file_config.apply_admitted_output_cap(output_cap);
        let mut process_config = ProcessToolConfig::for_workspace(&workspace);
        process_config.apply_admitted_output_cap(output_cap);
        let artifacts = self
            .inner
            .artifact_stores
            .get_or_open(file_config.artifact_store.clone())
            .map_err(|error| artifact_init_error(run_id, &error))?;
        let mut files = FileTools::with_artifact_store(file_config, artifacts)
            .map_err(|error| invalid_context_metadata(run_id, &error))?
            .with_owner(ArtifactOwner::from(owner.clone()));
        if let Some(observer) = self
            .inner
            .file_search_entered
            .lock()
            .expect("file search observer lock")
            .clone()
        {
            files = files.with_search_entered_observer(observer);
        }
        let table = Arc::new(
            ProcessTable::new(process_config.clone())
                .map_err(|error| invalid_context_metadata(run_id, &error))?,
        );
        let sink: Arc<dyn ProcessArtifactSink> = files.artifact_store_arc();
        let terminal = TerminalExecutor::new(
            process_config.clone(),
            Arc::clone(&table),
            ProcessOwner::from(owner.clone()),
        )
        .map_err(|error| invalid_context_metadata(run_id, &error))?
        .with_artifact_sink(Arc::clone(&sink));
        let process = ProcessExecutor::new(
            process_config,
            Arc::clone(&table),
            ProcessOwner::from(owner.clone()),
        )
        .map_err(|error| invalid_context_metadata(run_id, &error))?
        .with_artifact_sink(sink);
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
            .workspace(workspace.clone())
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
            .approval(Arc::new(AllowAllApproval))
            .cancellation(Arc::new(HandleCancelFlag {
                cancel: handle.cancel.clone(),
            }) as Arc<dyn CancellationFlag>)
            .generation(1)
            .build()
            .map_err(|error| invalid_context_metadata(run_id, error.code()))?;
        let dispatcher = DispatchContext::new(
            owner,
            workspace.clone(),
            handle.cancel.token(),
            handle.cancel.deadline_instant().unwrap_or_else(|| {
                Instant::now()
                    .checked_add(self.inner.config.run_timeout)
                    .unwrap_or_else(Instant::now)
            }),
            registry,
            expected.to_string(),
            toolset_hash,
            DispatchLimits {
                max_tool_calls,
                max_tool_output_bytes: output_cap,
                max_event_bytes: self.inner.config.max_event_bytes,
            },
            Arc::clone(&events),
            Arc::new(NativeExecutionDeps {
                files: files.clone(),
                terminal,
                process,
            }),
        )
        .map_err(|error| invalid_context_metadata(run_id, &error))?;
        if let Some(release) = self
            .inner
            .uncooperative_dispatch
            .lock()
            .expect("uncooperative dispatch lock")
            .clone()
        {
            let holder = dispatcher.clone();
            thread::spawn(move || {
                let _guard = holder.lock_serial();
                while !release.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(10));
                }
            });
            thread::sleep(Duration::from_millis(5));
        }
        Ok(NativeDispatchState {
            dispatcher,
            files,
            table,
            cleaned: AtomicBool::new(false),
            shutdown_entered: self
                .inner
                .native_dispatch_shutdown
                .lock()
                .expect("native dispatch shutdown observer lock")
                .clone(),
            cleanup_grace: self.inner.config.cancellation_grace,
            lifecycle: Arc::new(lifecycle),
            capability_owner,
        })
    }

    /// True when run-scoped native dispatch state is still retained.
    pub fn native_dispatch_retained(&self, run_id: &str) -> bool {
        self.handle(run_id)
            .is_some_and(|handle| handle.native_dispatch_retained())
    }

    /// True when native dispatch for `run_id` is sticky-closed.
    pub fn native_dispatch_closed(&self, run_id: &str) -> bool {
        self.handle(run_id)
            .is_some_and(|handle| handle.native_dispatch_closed())
    }

    /// Live process-owner residue for `run_id`, or 0 after cleanup/close.
    pub fn process_owner_count(&self, run_id: &str) -> usize {
        let Some(handle) = self.handle(run_id) else {
            return 0;
        };
        let Ok(phase) = handle.native_dispatch.lock() else {
            return 0;
        };
        match &*phase {
            NativeDispatchPhase::Ready(state) => {
                let owner = ProcessOwner::from(state.dispatcher.owner().clone());
                state.table.owner_count(&owner)
            }
            NativeDispatchPhase::Closed(Some(closed)) => closed.table.owner_count(&closed.owner),
            NativeDispatchPhase::Empty
            | NativeDispatchPhase::Initializing
            | NativeDispatchPhase::Closed(None) => 0,
        }
    }

    /// OS PIDs retained for `run_id`, including draining residue after close.
    pub fn process_owner_pids(&self, run_id: &str) -> Vec<u32> {
        let Some(handle) = self.handle(run_id) else {
            return Vec::new();
        };
        let Ok(phase) = handle.native_dispatch.lock() else {
            return Vec::new();
        };
        match &*phase {
            NativeDispatchPhase::Ready(state) => {
                let owner = ProcessOwner::from(state.dispatcher.owner().clone());
                state.table.owner_pids(&owner)
            }
            NativeDispatchPhase::Closed(Some(closed)) => closed.table.owner_pids(&closed.owner),
            NativeDispatchPhase::Empty
            | NativeDispatchPhase::Initializing
            | NativeDispatchPhase::Closed(None) => Vec::new(),
        }
    }

    fn cleanup_run_hosts(&self, handle: &RunHandle) -> CleanupOutcome {
        handle.release_native_dispatch()
    }

    async fn commit_cleanup_or_continue(&self, run_id: &str, handle: &RunHandle) -> bool {
        match self.cleanup_run_hosts(handle) {
            CleanupOutcome::Clean => true,
            CleanupOutcome::Timeout => {
                self.finish_failed(
                    run_id,
                    failed_payload_with_code(
                        "cleanup_timeout",
                        "native dispatcher or process cleanup exceeded grace".into(),
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
                        "native dispatcher or process cleanup failed".into(),
                    ),
                )
                .await;
                false
            }
        }
    }

    fn cached_agent_runner(&self, source: &str) -> Result<AgentRunner, String> {
        let expected = self.effective_agent_config();
        let digest = agent_source_digest(source);
        let mut cache = self.inner.runner.lock().expect("runner cache lock");
        if let Some(cached) = cache.as_ref()
            && cached.source_digest == digest
            && cached.config == expected
        {
            return Ok(cached.runner.clone());
        }
        let runner = AgentRunner::from_source(source, expected.clone())
            .map_err(|error| error.to_string())?;
        *cache = Some(CachedAgentRunner {
            source_digest: digest,
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
    pub fn install_agent_runner(&self, runner: AgentRunner) {
        let digest = self
            .inner
            .agent_source
            .as_ref()
            .map(|source| agent_source_digest(source))
            .unwrap_or(0);
        *self.inner.runner.lock().expect("runner cache lock") = Some(CachedAgentRunner {
            source_digest: digest,
            config: runner.config().clone(),
            runner,
        });
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
            native_dispatch: Mutex::new(NativeDispatchPhase::Empty),
            native_dispatch_cv: Condvar::new(),
            coding_system_prompt: Arc::from(prompt),
            occupancy: AtomicBool::new(false),
        });
        self.inner
            .runs
            .lock()
            .expect("runs lock")
            .insert(run_id.to_string(), Arc::clone(&handle));
        if status == "stopping" {
            handle.request_user_stop();
        }
        Some(handle)
    }

    /// Shared owner-scoped artifact store for an initialized run, if any.
    pub fn native_artifact_store(&self, run_id: &str) -> Option<Arc<ArtifactStore>> {
        let handle = self.handle(run_id)?;
        let phase = handle.native_dispatch.lock().ok()?;
        match &*phase {
            NativeDispatchPhase::Ready(state) => Some(state.files.artifact_store_arc()),
            NativeDispatchPhase::Empty
            | NativeDispatchPhase::Initializing
            | NativeDispatchPhase::Closed(_) => None,
        }
    }

    /// Test seam: later native dispatch construction invokes `observer` after
    /// releasing the slot lock and before FileTools/ArtifactStore IO.
    pub fn inject_native_dispatch_init_entered_observer(
        &self,
        observer: Arc<dyn Fn() + Send + Sync>,
    ) {
        *self
            .inner
            .native_dispatch_init_entered
            .lock()
            .expect("native dispatch init observer lock") = Some(observer);
    }

    /// Test seam: later native `search_files` walks invoke `observer` when they
    /// begin, so service tests can prove stop overlaps an in-flight search.
    pub fn inject_file_search_entered_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .file_search_entered
            .lock()
            .expect("file search observer lock") = Some(observer);
    }

    /// Test seam: later native-dispatch shutdown invokes `observer` before
    /// process/artifact teardown, so service tests can overlap handle/stop/admit
    /// with an in-flight close.
    pub fn inject_native_dispatch_shutdown_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .native_dispatch_shutdown
            .lock()
            .expect("native dispatch shutdown observer lock") = Some(observer);
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

    /// Drops native dispatch state and cleans processes/artifacts for every
    /// run belonging to `session_id`.
    pub fn cleanup_session_native_dispatch(&self, session_id: &str) {
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
            handle.release_native_dispatch();
        }
    }

    /// Cancels and drops every retained native dispatch state.
    pub fn shutdown_native_dispatch(&self) {
        let handles: Vec<Arc<RunHandle>> = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .values()
            .cloned()
            .collect();
        for handle in handles {
            handle.release_native_dispatch();
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

    /// The persistence handle for typed repository commands; `None` when no
    /// SQLite path is configured (in-memory only mode).
    pub(crate) fn persistence_handle(&self) -> Option<Arc<GatewayPersistence>> {
        self.inner.persistence.clone()
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
        tokio::task::spawn_blocking(move || service.admit_blocking(request, capacity_permit))
            .await
            .map_err(|error| {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Persistence);
                AdmitError::Persistence(format!("admission worker failed: {error}"))
            })?
    }

    fn admit_blocking(
        &self,
        request: AdmitRunRequest,
        capacity_permit: OwnedSemaphorePermit,
    ) -> Result<AdmittedRun, AdmitError> {
        let run_id = Uuid::new_v4().to_string();
        let now = timestamp();
        let message_id = Uuid::new_v4().to_string();
        let event_id = Uuid::new_v4().to_string();
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
        if let Some(replayed) = self.replay_existing_admission(
            request.idempotency_key.as_deref(),
            request.idempotency_hash.as_deref(),
        )? {
            return Ok(replayed);
        }

        let generation = self.inner.store_generation.load(Ordering::Acquire);
        let store = self.inner.store.read();

        // Session resolution: reuse an existing session or prepare a new one
        // (applied in memory only after the durable commit).
        let session_id = match request.session_id.clone() {
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
        if let Err(message) = validate_visible_name(&effective_model, "model", MAX_MODEL_NAME_BYTES)
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
        let new_session_view = if session_new {
            let view = SessionView {
                id: session_id.clone(),
                object: "hermes.session".to_string(),
                title: None,
                model: effective_model.clone(),
                provider: effective_provider.clone(),
                source: request.platform.clone(),
                system_prompt: effective_system_prompt.clone(),
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
            .map_err(|error| AdmitError::Invalid(format!("invalid provider profile: {error}")))?;
        let snapshot = RunAdmissionSnapshot {
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
        let date = self.inner.date_source.read().current_date();
        let platform = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let workspace_root = snapshot.limits.workspace_root.clone();
        let tool_descriptors = snapshot.registry.descriptors().to_vec();
        let run_limits = snapshot.limits.clone();
        drop(store);

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
        let context =
            self.make_admitted_context(&context_input, &snapshot, coding_system_prompt.clone());
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
            request_hash: request.idempotency_hash.as_deref().unwrap_or("").len(),
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
            "run_id": run_id,
            "parent_run_id": request.parent_run_id.clone().unwrap_or_default(),
            "input_json": persisted_input,
            "message_id": message_id,
            "message_run_id": run_id,
            "script_hash": snapshot.registry.identity(),
            "idempotency_scope": ADMISSION_IDEMPOTENCY_SCOPE,
            "idempotency_key": request.idempotency_key.clone().unwrap_or_default(),
            "request_hash": request.idempotency_hash.clone().unwrap_or_default(),
            "event_id": event_id,
            "now_ms": now,
            "expires_at_ms": 0,
        });

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
        // The transactional admission may have replayed an existing key (a
        // restart race the in-memory fast path cannot see).
        if data.get("replayed") == Some(&JsonValue::Bool(true)) {
            return self.finish_durable_replay(&data);
        }

        // Durable commit succeeded: apply the matching in-memory state under
        // the write lock with a generation recheck so concurrent admits cannot
        // duplicate runs after the storage roundtrip.
        let mut store = self.inner.store.write();
        if let Some(replayed) = self.recheck_admission_after_commit(
            &store,
            generation,
            request.idempotency_key.as_deref(),
            request.idempotency_hash.as_deref(),
            &run_id,
        )? {
            return Ok(replayed);
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
        session.messages.push(context_message);
        session.view.message_count = session.messages.len();
        session.view.updated_at = now;

        let (sender, _) = tokio::sync::broadcast::channel(self.inner.config.broadcast_capacity);
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
            request.idempotency_hash.as_deref(),
        ) {
            store.idempotency.insert(
                key.to_string(),
                IdempotencyRecord {
                    request_hash: hash.to_string(),
                    run_id: run_id.clone(),
                },
            );
        }

        let cancel = RunCancellation::with_timeout(self.inner.config.run_timeout);
        let handle = Arc::new(RunHandle {
            tool_cancel: cancel.token(),
            cancel,
            terminal_at: Mutex::new(None),
            permit: Mutex::new(Some(capacity_permit)),
            terminal: AtomicBool::new(false),
            cancel_reason: Mutex::new(None),
            subscribers: Mutex::new(SubscriberState {
                count: 0,
                notified: false,
            }),
            disconnect_policy: self.inner.config.client_disconnect_policy,
            started_at: Instant::now(),
            native_dispatch: Mutex::new(NativeDispatchPhase::Empty),
            native_dispatch_cv: Condvar::new(),
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
        Ok(AdmittedRun {
            run_id: run_id.clone(),
            session_id,
            status: "started".to_string(),
            replayed: false,
        })
    }

    fn replay_existing_admission(
        &self,
        key: Option<&str>,
        hash: Option<&str>,
    ) -> Result<Option<AdmittedRun>, AdmitError> {
        let (Some(key), Some(hash)) = (key, hash) else {
            return Ok(None);
        };
        let peeked = {
            let store = self.inner.store.read();
            store.idempotency.get(key).cloned().map(|existing| {
                let run = store.runs.get(&existing.run_id);
                (
                    existing,
                    run.map(|run| (run.session_id.clone(), run.status.clone())),
                )
            })
        };
        let Some((existing, run_info)) = peeked else {
            return Ok(None);
        };
        if existing.request_hash != hash {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::IdempotencyConflict);
            return Err(AdmitError::IdempotencyConflict);
        }
        let store = self.inner.store.write();
        let Some(current) = store.idempotency.get(key) else {
            return Ok(None);
        };
        if current.request_hash != hash {
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

    fn finish_durable_replay(&self, data: &JsonValue) -> Result<AdmittedRun, AdmitError> {
        let run_row = data
            .get("run")
            .and_then(|run| run.get("rows"))
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .cloned()
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

    fn recheck_admission_after_commit(
        &self,
        store: &GatewayStore,
        generation: u64,
        key: Option<&str>,
        hash: Option<&str>,
        run_id: &str,
    ) -> Result<Option<AdmittedRun>, AdmitError> {
        let current_generation = self.inner.store_generation.load(Ordering::Acquire);
        if current_generation != generation {
            tracing::debug!(
                current_generation,
                generation,
                "admission store generation changed during durable commit"
            );
        }
        if let Some(existing) = store.runs.get(run_id) {
            return Ok(Some(AdmittedRun {
                run_id: run_id.to_string(),
                session_id: existing.session_id.clone(),
                status: existing.status.clone(),
                replayed: true,
            }));
        }
        if let (Some(key), Some(hash)) = (key, hash)
            && let Some(existing) = store.idempotency.get(key)
        {
            if existing.request_hash != hash {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::IdempotencyConflict);
                return Err(AdmitError::IdempotencyConflict);
            }
            let (session_id, status) = store
                .runs
                .get(&existing.run_id)
                .map(|run| (run.session_id.clone(), run.status.clone()))
                .unwrap_or_else(|| (String::new(), "unknown".to_string()));
            return Ok(Some(AdmittedRun {
                run_id: existing.run_id.clone(),
                session_id,
                status,
                replayed: true,
            }));
        }
        Ok(None)
    }

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
            handle.cancel_native_tools();
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
            handle.cancel_native_tools();
        }
    }

    /// Stops new admissions without touching active runs: every later
    /// `admit()` answers the typed [`AdmitError::Halting`] rejection. The
    /// gateway's SIGINT path calls this first (no new work can start after
    /// shutdown begins), then stops the Telegram adapter, then cancels
    /// active runs via [`Self::halt`]. Idempotent.
    pub fn stop_admission(&self) {
        self.inner.halting.store(true, Ordering::Release);
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
        handle.release_native_dispatch();
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

    /// Removes and returns one pending terminal entry (the retry loop owns
    /// the entry while it attempts the durable commit).
    pub(crate) fn take_pending_terminal(&self, run_id: &str) -> Option<PendingTerminal> {
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .remove(run_id)
    }

    /// Re-inserts a pending terminal entry whose retry attempt failed (the
    /// storage outage is still ongoing).
    pub(crate) fn put_pending_terminal(&self, run_id: &str, pending: PendingTerminal) {
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .insert(run_id.to_string(), pending);
        self.inner.metrics.runs_terminal_pending_inc();
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

        let output_text = if let Some(source) = self.inner.agent_source.clone() {
            let context = self.build_run_context(&run_id);
            let (dispatcher, lifecycle, capability_owner) =
                match self.native_dispatch_state(&run_id, &handle) {
                    Ok(Some(state)) => (
                        Some(Arc::new(state.dispatcher.clone())),
                        Some(Arc::clone(&state.lifecycle)),
                        Some(state.capability_owner.clone()),
                    ),
                    Ok(None) => (None, None, None),
                    Err(error) => {
                        if !self.commit_cleanup_or_continue(&run_id, &handle).await {
                            return;
                        }
                        self.finish_failed(&run_id, failed_payload(error.to_string()))
                            .await;
                        return;
                    }
                };
            let raw_provider = self
                .inner
                .provider_host
                .lock()
                .expect("provider host lock")
                .take()
                .unwrap_or_else(crate::runtime::rss_runner::default_agent_provider_host);
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
                dispatcher,
                cancellation: Some(cancellation.clone()),
                sleeps: Default::default(),
                skip_sleep: false,
                metrics: Some(Arc::clone(&self.inner.metrics)),
                lifecycle,
                capability_owner,
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
            let runner = match self.cached_agent_runner(source.as_ref()) {
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
                    let completed_event = event_candidate(
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
                    let delta_event = event_candidate(
                        run,
                        "message.delta",
                        json!({
                            "message_id": message.id,
                            "delta": output_text_for_commit,
                            "role": "assistant"
                        }),
                        max_event_bytes,
                    );
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
        let run_row = run_data
            .get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .ok_or_else(|| RunContextError::Missing {
                run_id: run_id.to_string(),
            })?;
        if admission_run_str(run_row, ADMISSION_RUN_COL_ID) != Some(run_id) {
            return Err(invalid_context_metadata(
                run_id,
                "run record id does not match the requested run",
            ));
        }
        let persisted_input = admission_run_str(run_row, ADMISSION_RUN_COL_INPUT_JSON)
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
        let row_session_id = admission_run_str(run_row, ADMISSION_RUN_COL_SESSION_ID)
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
        if admission_run_str(run_row, ADMISSION_RUN_COL_MODEL) != Some(context.model.as_str()) {
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
        if admission_run_str(run_row, ADMISSION_RUN_COL_SCRIPT_HASH) != Some(registry_identity) {
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
        self.events
            .commit(
                "tool.started",
                json!({
                    "tool_call_id": record.call_id,
                    "name": record.tool_name,
                    "argument_digest": record.argument_digest,
                    "registry_identity": record.registry_identity,
                    "risk_class": record.risk_class.as_str(),
                    "generation": record.generation,
                }),
            )
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
        });
        if let Some(error) = &tool_result.error {
            data["error_code"] = json!(error.code);
        }
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
        let result = persist_and_apply(&self.store, self.persistence.as_deref(), reserved);
        if result.is_ok()
            && matches!(event_type, "tool.completed" | "tool.failed")
            && let Some(inner) = self.service.upgrade()
            && inner.crash_after_tool_commit.swap(false, Ordering::SeqCst)
        {
            inner.provider_commit_crashed.store(true, Ordering::SeqCst);
            panic!("tool_commit_crash");
        }
        result
    }
}

fn replay_commit_failure(error: EventCommitError) -> ToolResult {
    match error {
        EventCommitError::Corrupt(_) => ToolResult::failure(
            "corrupt_tool_result",
            "durable tool output is missing a canonical result payload",
        ),
        EventCommitError::MissingParent => ToolResult::failure(
            "missing_tool_parent",
            "tool result parent tool_call is missing",
        ),
        EventCommitError::Cancelled => ToolResult::failure("cancelled", "run was cancelled"),
        EventCommitError::Terminal => ToolResult::failure("run_terminal", "run is terminal"),
        EventCommitError::PersistFailed(_) => {
            ToolResult::failure("persist_failed", "durable event persist failed")
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

fn artifact_init_error(run_id: &str, error: &ArtifactError) -> RunContextError {
    invalid_context_metadata(run_id, &format!("{}: {}", error.code(), error.message()))
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
            let Some(pending) = service.take_pending_terminal(&run_id_for_block) else {
                return PendingRetryOutcome::Gone;
            };
            service.inner.metrics.runs_terminal_pending_dec();
            {
                let store = service.inner.store.read();
                let Some(run) = store.runs.get(&run_id_for_block) else {
                    return PendingRetryOutcome::Gone;
                };
                if run.status != "terminal_pending" {
                    return PendingRetryOutcome::Gone;
                }
            }
            if std::time::Instant::now() >= pending.deadline {
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
                    service.put_pending_terminal(&run_id_for_block, pending);
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
        "now_ms": timestamp(),
    });
    let data = persistence
        .run_terminal(&payload)
        .map_err(|error| TerminalCommitError {
            code: error.code.clone(),
            message: error.message.clone(),
        })?;
    let rows = data
        .get("events")
        .and_then(|events| events.get("rows"))
        .and_then(JsonValue::as_array)
        .ok_or_else(|| TerminalCommitError {
            code: "terminal_commit_invalid".to_string(),
            message: "run.terminal result omitted events".to_string(),
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
            .and_then(JsonValue::as_array)
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
            interval.tick().await;
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
                handle.release_native_dispatch();
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
