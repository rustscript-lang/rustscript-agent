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
//! cadence) commits the typed terminal exactly once when storage recovers.
//! After the retry window the durable side is left for restart recovery, so
//! a sustained outage can neither exhaust capacity nor leak handles or live
//! streams forever. Nothing is ever published before the durable commit
//! succeeds.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, atomic::AtomicBool, atomic::Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rustscript_vm::{CancellationReason, HttpConfig, InvocationError, Value as VmValue};
use serde_json::{Value as JsonValue, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::config::AgentGatewayConfig;
use crate::config::ClientDisconnectPolicy;
use crate::domain::{RunContext, timestamp, truncate_for_log, vm_value_to_json};
use crate::events;
use crate::gateway::store::{
    GatewayEvent, GatewayPersistence, GatewayStore, IdempotencyRecord, RunRecord, SessionMessage,
    SessionRecord, SessionView, append_message,
};
use crate::metrics::{AdmitRejectReason, Metrics, TerminalRetryOutcome, TerminalStatus};
use crate::runtime::approval_bridge::{
    ApprovalBridge, NativeDenyPolicy, PendingApproval, Resolution, RiskClass,
};
use crate::runtime::delivery::{
    ChannelEventSink, DeliveryContext, DeliveryOutcome, append_event_locked, run_delivery_task,
};
use crate::runtime::rss_runner::execute_rss_source;
use crate::{AgentConfig, AgentRunner, RunCancellation, RunError};

/// One run whose terminal state could not be committed durably. The worker
/// has already exited; a bounded retry loop (janitor cadence) commits the
/// typed terminal exactly once when storage recovers — durable commit
/// first, publish and permit release only after. The deadline bounds the
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

#[derive(Clone)]
pub struct AgentService {
    inner: Arc<AgentServiceInner>,
}

struct AgentServiceInner {
    config: Arc<AgentGatewayConfig>,
    store: Arc<RwLock<GatewayStore>>,
    persistence: Option<Arc<GatewayPersistence>>,
    agent_source: Option<Arc<String>>,
    /// The production serial loop program (`rss/agent/main.rss`); when
    /// present, the worker drives the RSS-owned loop instead of the legacy
    /// single-shot source.
    agent_program: Option<Arc<AgentRunner>>,
    /// The durable approval bridge over the A2 storage program; `None` in
    /// in-memory-only mode (approval.wait then fails the run typed).
    approval: Option<Arc<ApprovalBridge>>,
    /// Runs parked on a durable pending approval: run_id -> the approval id
    /// and the loop state needed to resume exactly once.
    parked: Mutex<HashMap<String, ParkedRun>>,
    http_config: HttpConfig,
    capacity: Arc<Semaphore>,
    runs: Mutex<HashMap<String, Arc<RunHandle>>>,
    pending: Mutex<HashMap<String, PendingTerminal>>,
    halting: AtomicBool,
    metrics: Arc<Metrics>,
}

/// The production A2 storage program path. The default resolves relative to
/// the crate's manifest directory; `RUSTSCRIPT_STORAGE_PROGRAM` overrides it
/// (deployment without the source tree, and the no-source-tree tests). The
/// loader is fallible, so a missing program is a typed error, never a panic.
fn storage_program_path() -> std::path::PathBuf {
    match std::env::var_os("RUSTSCRIPT_STORAGE_PROGRAM") {
        Some(path) => std::path::PathBuf::from(path),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rss")
            .join("storage")
            .join("main.rss"),
    }
}

/// One run parked on a durable pending approval. The resume re-invokes the
/// loop with `phase: "approval.resume"` and the exact loop state from the
/// `approval.wait` decision (durable sequencing; restart recovery fails
/// interrupted runs and their approvals, so the in-memory park is bounded by
/// admission capacity). The ORIGINAL run deadline rides along: the park time
/// counts against the run's wall clock and a resume never resets it.
///
/// Once the bridge has durably resolved the row, the OUTCOME is recorded on
/// the park: a resume that fails to transition the run back to `running`
/// restores the park WITH the recorded decision, so a retry never re-resolves
/// the durable row and never downgrades an approve to a deny.
#[derive(Clone)]
struct ParkedRun {
    approval_id: String,
    base_context: JsonValue,
    state: JsonValue,
    deadline: std::time::Instant,
    /// The durable bridge outcome when the row was resolved but the run
    /// transition failed (`None` while the row is still pending).
    resolution: Option<ParkedResolution>,
}

/// One recorded durable bridge outcome: `resolved` (the loop dispatches the
/// call when true), the typed `outcome` (`approved` | `denied` | `expired`),
/// and the terminal reason.
#[derive(Clone)]
struct ParkedResolution {
    resolved: bool,
    outcome: String,
    reason: String,
}

impl AgentService {
    pub(crate) fn new(
        config: Arc<AgentGatewayConfig>,
        store: Arc<RwLock<GatewayStore>>,
        persistence: Option<Arc<GatewayPersistence>>,
        agent_source: Option<Arc<String>>,
        http_config: HttpConfig,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        Self::build(
            config,
            store,
            persistence,
            agent_source,
            None,
            http_config,
            metrics,
        )
    }

    /// Constructs the service with the production serial loop program (the
    /// RSS-owned loop the worker drives) plus the durable approval bridge.
    pub(crate) fn with_program(
        config: Arc<AgentGatewayConfig>,
        store: Arc<RwLock<GatewayStore>>,
        persistence: Option<Arc<GatewayPersistence>>,
        program: AgentRunner,
        http_config: HttpConfig,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        Self::build(
            config,
            store,
            persistence,
            None,
            Some(program),
            http_config,
            metrics,
        )
    }

    fn build(
        config: Arc<AgentGatewayConfig>,
        store: Arc<RwLock<GatewayStore>>,
        persistence: Option<Arc<GatewayPersistence>>,
        agent_source: Option<Arc<String>>,
        agent_program: Option<AgentRunner>,
        http_config: HttpConfig,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        let capacity = Arc::new(Semaphore::new(config.max_concurrent_runs));
        // The durable approval bridge composes the production A2 storage
        // program. Construction is fallible: a deployment without the source
        // tree answers a typed error instead of panicking (the gateway
        // constructors propagate it), so a missing program can never take
        // the process down.
        let approval = match persistence.as_ref() {
            Some(persistence) => {
                let root = storage_program_path();
                let mut agent_config = AgentConfig {
                    http: http_config.clone(),
                    sqlite: config.sqlite.clone(),
                    io: config.io.clone(),
                    fuel: config.fuel,
                };
                if let Some(parent) = persistence.db_root() {
                    agent_config = agent_config.with_sqlite_root(parent);
                }
                let storage = AgentRunner::from_file(&root, agent_config)
                    .map_err(|error| format!("compile the built-in storage program: {error}"))?;
                Some(Arc::new(ApprovalBridge::new(
                    storage,
                    persistence.db_file_name().to_string(),
                    NativeDenyPolicy::new(),
                )))
            }
            None => None,
        };
        let inner = Arc::new(AgentServiceInner {
            config,
            store,
            persistence,
            agent_source,
            agent_program: agent_program.map(Arc::new),
            approval,
            parked: Mutex::new(HashMap::new()),
            http_config,
            capacity,
            runs: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            halting: AtomicBool::new(false),
            metrics,
        });
        spawn_lifecycle_janitor(Arc::clone(&inner));
        Ok(Self { inner })
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
        let mut store = self.inner.store.write();

        // Idempotent replay fast path (authoritative under the write lock):
        // an admitted key returns the existing run without creating anything.
        if let (Some(key), Some(hash)) = (
            request.idempotency_key.as_deref(),
            request.idempotency_hash.as_deref(),
        ) && let Some(existing) = store.idempotency.get(key)
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
                .unwrap_or((String::new(), "unknown".to_string()));
            return Ok(AdmittedRun {
                run_id: existing.run_id.clone(),
                session_id,
                status,
                replayed: true,
            });
        }

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
        let new_session_view = if session_new {
            let view = SessionView {
                id: session_id.clone(),
                object: "hermes.session".to_string(),
                title: None,
                model: request
                    .model
                    .clone()
                    .unwrap_or_else(|| self.inner.config.model.clone()),
                provider: request
                    .provider
                    .clone()
                    .or_else(|| self.inner.config.provider.clone()),
                source: request.platform.clone(),
                system_prompt: request.instructions.clone(),
                created_at: now,
                updated_at: now,
                message_count: 0,
                generation: 1,
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

        let payload = json!({
            "session_id": session_id,
            "session_new": if session_new { 1 } else { 0 },
            "profile": "gateway",
            "platform": request.platform,
            "account_id": session_id,
            "model": request.model.clone().unwrap_or_default(),
            "provider": request.provider.clone().unwrap_or_default(),
            "system_prompt": request.instructions.clone().unwrap_or_default(),
            "run_id": run_id,
            "parent_run_id": request.parent_run_id.clone().unwrap_or_default(),
            "input_json": serde_json::to_string(&request.input)
                .unwrap_or_else(|_| "null".to_string()),
            "message_id": message_id,
            "message_run_id": run_id,
            "script_hash": "",
            "idempotency_scope": "api:chat",
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
            let run_row = data
                .get("run")
                .and_then(|run| run.get("rows"))
                .and_then(JsonValue::as_array)
                .and_then(|rows| rows.first())
                .and_then(JsonValue::as_array)
                .cloned()
                .ok_or_else(|| {
                    AdmitError::Persistence(
                        "replayed admission omitted the existing run".to_string(),
                    )
                })?;
            let replayed_run_id = run_row
                .first()
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string();
            let replayed_session = run_row
                .get(1)
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string();
            let replayed_status = run_row
                .get(3)
                .and_then(JsonValue::as_str)
                .unwrap_or("unknown")
                .to_string();
            return Ok(AdmittedRun {
                run_id: replayed_run_id,
                session_id: replayed_session,
                status: replayed_status,
                replayed: true,
            });
        }

        // Durable commit succeeded: apply the matching in-memory state.
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
        session.messages.push(SessionMessage {
            id: message_id.clone(),
            session_id: session_id.clone(),
            role: "user".to_string(),
            tool_call_id: String::new(),
            content: request.input.clone(),
            created_at: now,
            run_id: Some(run_id.clone()),
            finish_reason: None,
            compacted: false,
        });
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
            platform: request.platform.clone(),
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

        let handle = Arc::new(RunHandle {
            cancel: RunCancellation::with_timeout(self.inner.config.run_timeout),
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
        });
        self.inner
            .runs
            .lock()
            .expect("runs lock")
            .insert(run_id.clone(), handle);
        self.inner.metrics.admission_accepted();
        self.inner.metrics.active_runs_inc();
        Ok(AdmittedRun {
            run_id: run_id.clone(),
            session_id,
            status: "started".to_string(),
            replayed: false,
        })
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
            tracing::debug!(
                run_id,
                reason = "requested",
                "typed cancellation requested for the run"
            );
            // A run parked on a pending approval has no worker to observe the
            // cancellation: transition it back to `running` durably and
            // commit the typed cancellation now.
            if self
                .inner
                .parked
                .lock()
                .expect("parked lock")
                .remove(run_id)
                .is_some()
            {
                let service = self.clone();
                let run_id = run_id.to_string();
                tokio::spawn(async move {
                    service
                        .transition_run(&run_id, "waiting_approval", "running")
                        .await;
                    service.finish_cancelled(&run_id, "requested").await;
                });
            }
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
        if let Some(handle) = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()
        {
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
    pub async fn run_worker(self: Arc<Self>, run_id: String, input: String) {
        tokio::task::yield_now().await;
        let Some(handle) = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(&run_id)
            .cloned()
        else {
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

        if cancellation.requested().is_some() {
            self.finish_cancelled(&run_id, handle_cancel_reason(&handle, "requested"))
                .await;
            return;
        }

        // The production serial loop: the RSS-owned loop program is driven
        // here (lifecycle, capability composition, durable sequencing); the
        // legacy single-shot source path remains for inline sources.
        if let Some(program) = self.inner.agent_program.clone() {
            let base_context = self.build_production_loop_context(&run_id, &session_id);
            self.drive_production_loop(
                program,
                &run_id,
                &session_id,
                base_context,
                "start",
                JsonValue::Object(Default::default()),
                Instant::now() + self.inner.config.run_timeout,
            )
            .await;
            return;
        }

        let output_text = if let Some(source) = self.inner.agent_source.clone() {
            let http_config = self.inner.http_config.clone();
            let sqlite_policy = self.inner.config.sqlite.clone();
            let run_timeout = self.inner.config.run_timeout;
            let context = self.build_run_context(&run_id, &session_id, &input);
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
                },
                run_id.clone(),
                receiver,
            ));
            let mut sink = ChannelEventSink(sender);
            let run_cancellation = cancellation.clone();
            let mut worker = tokio::task::spawn_blocking(move || {
                execute_rss_source(
                    &source,
                    http_config,
                    sqlite_policy,
                    context,
                    &mut sink,
                    &run_cancellation,
                )
            });
            let outcome = match tokio::time::timeout(run_timeout, &mut worker).await {
                Ok(Ok(Ok(value))) => WorkerOutcome::Completed(value),
                Ok(Ok(Err(error))) => WorkerOutcome::from_run_error(error),
                Ok(Err(error)) => WorkerOutcome::Failed(format!("RSS worker join failed: {error}")),
                Err(_) => {
                    // The timeout is authoritative: cancel with the typed
                    // deadline reason and wait only the configured grace for
                    // worker exit.
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
            // script event. When the drain cannot finish within the grace,
            // the tail is NOT silently dropped: the typed `run.truncated`
            // marker is durably appended BEFORE the terminal (a marker
            // failure is the typed persistence_unavailable terminal).
            let (delivery_outcome, truncation_reason) =
                match tokio::time::timeout(self.inner.config.cancellation_grace, delivery).await {
                    Ok(Ok(outcome)) => (outcome, None),
                    Ok(Err(_)) => (DeliveryOutcome::default(), Some("delivery_task_failed")),
                    Err(_) => (DeliveryOutcome::default(), Some("delivery_drain_timeout")),
                };
            if let Some(reason) = truncation_reason
                && let Err(error) = self.append_truncation_marker(&run_id, reason).await
            {
                tracing::error!(
                    run_id,
                    error = %truncate_for_log(&error, 256),
                    "the truncation marker could not be persisted; the run fails typed"
                );
                // A stop that raced the drain keeps its typed cancellation
                // (never downgraded to a failure); otherwise the run fails
                // with the typed persistence contract — never a silent tail
                // drop.
                if self.run_is_stopping(&run_id) {
                    self.finish_cancelled(&run_id, handle_cancel_reason(&handle, "requested"))
                        .await;
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
            match outcome {
                WorkerOutcome::Completed(value) => {
                    if let Some(reason) = delivery_outcome.schema_violation {
                        self.finish_failed(&run_id, events::schema_violation_error(&reason))
                            .await;
                        return;
                    }
                    if delivery_outcome.persist_failed {
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
                    vm_value_to_json(&value).to_string()
                }
                WorkerOutcome::Cancelled(core_reason) => {
                    // Prefer the typed gateway reason recorded on the handle
                    // (stop/halt/client disconnect); the core-derived string
                    // is the fallback for worker-requested cancellations.
                    self.finish_cancelled(&run_id, handle_cancel_reason(&handle, core_reason))
                        .await;
                    return;
                }
                WorkerOutcome::Failed(error) => {
                    self.finish_failed(&run_id, failed_payload(error)).await;
                    return;
                }
            }
        } else {
            input.clone()
        };

        if cancellation.requested().is_some() {
            self.finish_cancelled(&run_id, handle_cancel_reason(&handle, "requested"))
                .await;
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
            let mut store = service.inner.store.write();
            let persistence = service.persistence_handle();
            let run_active = store
                .runs
                .get(&run_id_for_commit)
                .is_some_and(|run| run.status == "started");
            if !run_active {
                return TerminalOutcome::NotActive;
            }
            let Some(session) = store.sessions.get_mut(&session_id_for_commit) else {
                return TerminalOutcome::SessionMissing;
            };
            let previous_session_updated = session.view.updated_at;
            let message = append_message(
                &mut session.view,
                &mut session.messages,
                "assistant",
                JsonValue::String(output_text_for_commit.clone()),
                Some(run_id_for_commit.clone()),
                Some("stop".to_string()),
                false,
                "",
            );
            let run = store
                .runs
                .get_mut(&run_id_for_commit)
                .expect("run was checked above");
            let previous_status = run.status.clone();
            let previous_events = run.events.len();
            let delta_event = append_event_locked(
                run,
                "message.delta",
                json!({"message_id":message.id, "delta":output_text_for_commit, "role":"assistant"}),
                max_event_bytes,
                max_events_per_run,
            );
            let completed_event = append_event_locked(
                run,
                "run.completed",
                json!({"status":"completed", "output":{"message":message}, "usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}),
                max_event_bytes,
                max_events_per_run,
            );
            run.status = "completed".to_string();
            let durable = terminal_commit(
                persistence.as_deref(),
                run,
                &session_id_for_commit,
                "completed",
                &[&delta_event, &completed_event],
                Some(&message),
            );
            match durable {
                Ok(()) => {
                    if let Some(sender) = &run.sender {
                        let _ = sender.send(delta_event);
                        let _ = sender.send(completed_event);
                    }
                    TerminalOutcome::Committed
                }
                Err(error) => {
                    // Roll the in-memory terminal state back: the run becomes
                    // observably terminal-pending and the retry loop owns the
                    // exact same terminal (events, message, status).
                    run.status = previous_status;
                    run.events.truncate(previous_events);
                    let session = store
                        .sessions
                        .get_mut(&session_id_for_commit)
                        .expect("session was checked above");
                    session.messages.pop();
                    session.view.message_count = session.messages.len();
                    session.view.updated_at = previous_session_updated;
                    TerminalOutcome::TerminalPersistFailed {
                        error: error.to_string(),
                        pending: Box::new(PendingTerminal {
                            to_status: "completed".to_string(),
                            session_id: Some(session_id_for_commit),
                            events: vec![delta_event, completed_event],
                            assistant_message: Some(message),
                            deadline: std::time::Instant::now() + retry_window,
                        }),
                    }
                }
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
    /// which commits and publishes it exactly once when storage recovers.
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
            let mut store = service.inner.store.write();
            let persistence = service.persistence_handle();
            let Some(run) = store.runs.get_mut(&run_id_for_commit) else {
                return TerminalOutcome::NotActive;
            };
            if matches!(
                run.status.as_str(),
                "completed" | "failed" | "cancelled" | "terminal_pending"
            ) {
                return TerminalOutcome::NotActive;
            }
            let previous_status = run.status.clone();
            let previous_events = run.events.len();
            let event = append_event_locked(
                run,
                "run.cancelled",
                json!({"status":"cancelled", "reason":reason_for_commit}),
                max_event_bytes,
                max_events_per_run,
            );
            run.status = "cancelled".to_string();
            match terminal_commit(
                persistence.as_deref(),
                run,
                "",
                "cancelled",
                &[&event],
                None,
            ) {
                Ok(()) => {
                    if let Some(sender) = &run.sender {
                        let _ = sender.send(event);
                    }
                    TerminalOutcome::Committed
                }
                Err(error) => {
                    run.status = previous_status;
                    run.events.truncate(previous_events);
                    TerminalOutcome::TerminalPersistFailed {
                        error: error.to_string(),
                        pending: Box::new(PendingTerminal {
                            to_status: "cancelled".to_string(),
                            session_id: None,
                            events: vec![event],
                            assistant_message: None,
                            deadline: std::time::Instant::now() + retry_window,
                        }),
                    }
                }
            }
        })
        .await
        .expect("terminal commit task must complete")
    }

    /// Fails a run through a durable-first terminal commit: `run.terminal`
    /// commits the failure event and the status change in one transaction,
    /// and only then is the event published. The commit is retried with
    /// bounded backoff; on final failure the failure is handed to the bounded
    /// retry loop (`terminal_pending`), which commits and publishes it
    /// exactly once when storage recovers.
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
            let mut store = service.inner.store.write();
            let persistence = service.persistence_handle();
            let Some(run) = store.runs.get_mut(&run_id_for_commit) else {
                return TerminalOutcome::NotActive;
            };
            if matches!(
                run.status.as_str(),
                "completed" | "failed" | "cancelled" | "terminal_pending"
            ) {
                return TerminalOutcome::NotActive;
            }
            let previous_status = run.status.clone();
            let previous_events = run.events.len();
            let event =
                append_event_locked(run, "run.failed", data, max_event_bytes, max_events_per_run);
            run.status = "failed".to_string();
            match terminal_commit(persistence.as_deref(), run, "", "failed", &[&event], None) {
                Ok(()) => {
                    if let Some(sender) = &run.sender {
                        let _ = sender.send(event);
                    }
                    TerminalOutcome::Committed
                }
                Err(error) => {
                    run.status = previous_status;
                    run.events.truncate(previous_events);
                    TerminalOutcome::TerminalPersistFailed {
                        error: error.to_string(),
                        pending: Box::new(PendingTerminal {
                            to_status: "failed".to_string(),
                            session_id: None,
                            events: vec![event],
                            assistant_message: None,
                            deadline: std::time::Instant::now() + retry_window,
                        }),
                    }
                }
            }
        })
        .await
        .expect("terminal commit task must complete")
    }

    /// Builds the canonical structured run context (gateway-api plan 4.2)
    /// that is passed as the sole argument to the exported `run(context)`
    /// callable.
    fn build_run_context(&self, run_id: &str, session_id: &str, input: &str) -> VmValue {
        let store = self.inner.store.read();
        let session = store.sessions.get(session_id);
        let run = store.runs.get(run_id);
        let messages = session
            .map(|session| serde_json::to_value(&session.messages).unwrap_or(JsonValue::Null))
            .unwrap_or(JsonValue::Null);
        let system_prompt = session.and_then(|session| session.view.system_prompt.clone());
        let model = session
            .map(|session| session.view.model.clone())
            .unwrap_or_else(|| self.inner.config.model.clone());
        let provider = session
            .and_then(|session| session.view.provider.clone())
            .or_else(|| self.inner.config.provider.clone());
        let parent_run_id = run.and_then(|run| run.parent_run_id.clone());
        let platform = run
            .map(|run| run.platform.clone())
            .unwrap_or_else(|| "api_server".to_string());
        let context = RunContext {
            run_id: run_id.to_string(),
            session_id: session_id.to_string(),
            parent_run_id,
            platform,
            input: JsonValue::String(input.to_string()),
            messages,
            system_prompt,
            model,
            provider,
            // Provider options and tool schemas arrive with the provider and
            // tool milestones; the canonical shape is present from the start.
            provider_options: self.inner.config.provider_options.clone(),
            tool_schemas: JsonValue::Array(Vec::new()),
            limits: json!({
                "max_events": self.inner.config.max_events_per_run,
                "max_event_bytes": self.inner.config.max_event_bytes,
                "timeout_ms": self.inner.config.run_timeout.as_millis(),
                "max_turns": self.inner.config.max_turns,
                "max_retries": self.inner.config.max_retries,
                "base_retry_delay_ms": self.inner.config.base_retry_delay_ms,
                "max_retry_delay_ms": self.inner.config.max_retry_delay_ms,
                "approval_mode": self.inner.config.approval_mode,
                "max_context_messages": self.inner.config.max_context_messages,
                "retained_tail": self.inner.config.retained_tail,
                "stream": self.inner.config.stream,
                "parallel": self.inner.config.parallel,
                "task": self.inner.config.task,
            }),
            metadata: JsonValue::Object(Default::default()),
        };
        context.to_vm_value()
    }

    /// Builds the canonical PRODUCTION serial loop context (A5 plan section
    /// 4): the flat typed fields the loop reads (`turn`, `retry_count`,
    /// `max_turns`, `max_retries`, `model`, `provider`, `provider_options`,
    /// `system_prompt`, `messages`, `last_text`) plus the nested `config` map
    /// (`base_retry_delay_ms`, `max_retry_delay_ms`, `max_context_messages`,
    /// `retained_tail`, `approval_mode`, `native_hard_deny`, `stream`,
    /// `parallel`, `task`, `max_output_tokens`, `now_ms`, `generation`,
    /// `message_count`, `compaction_id`). The session messages are
    /// normalized to canonical `{ordinal, role, tool_call_id, content}`
    /// entries whose ordinals mirror the durable per-session message
    /// ordinals (insertion order), so the loop's compaction plan references
    /// real rows; `tool_call_id` mirrors the durable messages.tool_call_id
    /// column (pair preservation across reloads) and content is normalized
    /// to the canonical content-part array.
    fn build_production_loop_context(&self, run_id: &str, session_id: &str) -> VmValue {
        let config = &self.inner.config;
        let store = self.inner.store.read();
        let session = store.sessions.get(session_id);
        let run = store.runs.get(run_id);
        // The provider-facing history EXCLUDES compacted rows (a committed
        // compaction covered them), even when the durable count is within the
        // window. Ordinals keep mirroring the durable rows (position + 1), so
        // a later compaction plan still references real rows.
        let messages: Vec<JsonValue> = session
            .map(|session| {
                session
                    .messages
                    .iter()
                    .enumerate()
                    .filter(|(_, message)| !message.compacted)
                    .map(|(index, message)| {
                        json!({
                            "ordinal": index + 1,
                            "role": message.role,
                            // The message-level pair id mirrors the durable
                            // messages.tool_call_id column: compaction plans
                            // pair assistant tool-call messages with their
                            // tool results across reloads.
                            "tool_call_id": message.tool_call_id,
                            "content": canonical_message_content(&message.content),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let system_prompt = session
            .and_then(|session| session.view.system_prompt.clone())
            .unwrap_or_default();
        let model = session
            .map(|session| session.view.model.clone())
            .unwrap_or_else(|| config.model.clone());
        let provider = session
            .and_then(|session| session.view.provider.clone())
            .or_else(|| config.provider.clone())
            .unwrap_or_default();
        let generation = session.map(|session| session.view.generation).unwrap_or(1);
        let message_count = session.map(|session| session.messages.len()).unwrap_or(0);
        let platform = run
            .map(|run| run.platform.clone())
            .or_else(|| session.map(|session| session.view.source.clone()))
            .unwrap_or_default();
        let context = json!({
            "run_id": run_id,
            "session_id": session_id,
            "platform": platform,
            "turn": 0,
            "retry_count": 0,
            "max_turns": config.max_turns,
            "max_retries": config.max_retries,
            "model": model,
            "provider": provider,
            "provider_options": config.provider_options.clone(),
            "system_prompt": system_prompt,
            "messages": messages,
            "last_text": "",
            "config": {
                "base_retry_delay_ms": config.base_retry_delay_ms,
                "max_retry_delay_ms": config.max_retry_delay_ms,
                "max_context_messages": config.max_context_messages,
                "retained_tail": config.retained_tail,
                "approval_mode": config.approval_mode.clone(),
                "native_hard_deny": false,
                "stream": config.stream,
                "parallel": config.parallel,
                "task": config.task,
                "max_output_tokens": 1024,
                "now_ms": timestamp(),
                "generation": generation,
                "message_count": message_count,
                "compaction_id": format!("compact:{session_id}:{}", generation + 1),
            }
        });
        json_to_vm_value(&context)
    }

    // -----------------------------------------------------------------------
    // Production serial loop driver (RSS-owned loop, service-owned lifecycle)
    // -----------------------------------------------------------------------

    /// Drives the RSS-owned production loop: one invocation per step, typed
    /// decisions executed here (retry sleep, approval park, compaction, typed
    /// terminals), re-invocation with the carried state. The whole run is
    /// bounded by `deadline` — the ORIGINAL run deadline (a resume after a
    /// park passes the parked deadline, so park time counts against the run
    /// wall clock); cancellation is typed.
    #[allow(clippy::too_many_arguments)]
    async fn drive_production_loop(
        &self,
        program: Arc<AgentRunner>,
        run_id: &str,
        session_id: &str,
        base_context: VmValue,
        initial_phase: &str,
        initial_state: JsonValue,
        deadline: Instant,
    ) {
        let mut base_json = vm_value_to_json(&base_context);
        let mut phase = initial_phase.to_string();
        let mut state = initial_state;
        // The durable message watermark: every in-run message whose ordinal
        // exceeds it is persisted durably before the loop continues (the
        // loop's assistant tool-call / tool-result appends are durable-first).
        let mut durable_ordinal = base_json["config"]["message_count"].as_i64().unwrap_or(0);
        loop {
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
            if handle.cancel.requested().is_some() {
                self.finish_cancelled(run_id, handle_cancel_reason(&handle, "requested"))
                    .await;
                return;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                handle.cancel.request(CancellationReason::Deadline);
                // The typed reason on the handle wins (a stop that raced the
                // deadline keeps its own reason).
                self.finish_cancelled(run_id, handle_cancel_reason(&handle, "deadline"))
                    .await;
                return;
            }
            let context = self.loop_step_context(&base_json, &phase, &state);
            let outcome = self
                .invoke_loop_step(Arc::clone(&program), run_id, context, remaining)
                .await;
            let decision = match outcome {
                LoopStepOutcome::Decision(decision) => decision,
                LoopStepOutcome::Cancelled => return,
            };
            // Durable-first message sync: the loop's in-run appends (assistant
            // tool-call and tool-result messages) must be persisted before the
            // next step, a park, or the terminal commit.
            match self
                .sync_durable_messages(run_id, session_id, &decision, durable_ordinal)
                .await
            {
                Ok(new_ordinal) => {
                    durable_ordinal = new_ordinal;
                    // The compaction gate plans over the CURRENT durable
                    // count, so the refreshed watermark feeds the next step's
                    // context.
                    base_json["config"]["message_count"] = json!(durable_ordinal);
                }
                Err(error) => {
                    self.finish_failed(
                        run_id,
                        json!({
                            "status": "failed",
                            "error_code": "persistence_unavailable",
                            "error_message": format!(
                                "a tool-cycle message could not be appended durably: {error}"
                            ),
                        }),
                    )
                    .await;
                    return;
                }
            }
            // The loop's continuation decisions carry the CURRENT config
            // (generation/message_count advance across internal turns and
            // compactions); merge it back so a park/resume or the next
            // invocation plans with the fresh durable state. The compaction
            // id is canonicalized from the generation (the pinned core has
            // no int-to-string conversion).
            if let Some(config) = decision["config"].as_object() {
                for (key, value) in config {
                    base_json["config"][key] = value.clone();
                }
                if let Some(generation) = base_json["config"]["generation"].as_i64() {
                    base_json["config"]["compaction_id"] =
                        json!(format!("compact:{session_id}:{}", generation + 1));
                }
            }
            match decision["kind"].as_str().unwrap_or("") {
                "run.completed" => {
                    let text = decision["text"].as_str().unwrap_or("").to_string();
                    self.finish_completed(run_id, session_id, &text).await;
                    return;
                }
                "run.failed" => {
                    self.finish_failed(run_id, self.failed_decision_payload(&decision))
                        .await;
                    return;
                }
                "retry" => {
                    let delay_ms = decision["delay_ms"].as_i64().unwrap_or(0).max(0) as u64;
                    tokio::time::sleep(Duration::from_millis(delay_ms).min(remaining)).await;
                    phase = "start".to_string();
                    state = decision_state(&decision);
                }
                "approval.wait" => {
                    match self
                        .park_for_approval(run_id, &base_json, &decision, deadline)
                        .await
                    {
                        ParkOutcome::Parked => return,
                        ParkOutcome::Cancelled => {
                            // A stop (or the deadline) landed before the park
                            // could be durably created: commit the typed
                            // cancellation now — no pending approval row and
                            // no park were created after the stop.
                            if deadline.saturating_duration_since(Instant::now()).is_zero() {
                                handle.cancel.request(CancellationReason::Deadline);
                            }
                            self.finish_cancelled(
                                run_id,
                                handle_cancel_reason(&handle, "deadline"),
                            )
                            .await;
                            return;
                        }
                        ParkOutcome::Failed => {
                            self.finish_failed(
                                run_id,
                                json!({
                                    "status": "failed",
                                    "error_code": "approval_unavailable",
                                    "error_message": "a durable approval could not be persisted for the pending tool call",
                                }),
                            )
                            .await;
                            return;
                        }
                    }
                }
                "compact" => {
                    let (ok, error) = self.execute_compaction(run_id, &decision).await;
                    phase = "compact.result".to_string();
                    let mut next = decision_state(&decision);
                    next["compact_ok"] = json!(ok);
                    next["compact_error"] = json!(error);
                    state = next;
                    if ok {
                        // The commit advanced the session generation: refresh
                        // the base config so a SECOND compaction in the same
                        // run plans the next generation with a fresh
                        // compaction id (never a stale-generation conflict).
                        if let Some(generation) = decision["plan"]["generation"].as_i64() {
                            base_json["config"]["generation"] = json!(generation);
                            base_json["config"]["compaction_id"] =
                                json!(format!("compact:{session_id}:{}", generation + 1));
                        }
                    }
                }
                "parallel.handoff" | "subagent.handoff" => {
                    let code = if decision["kind"] == "parallel.handoff" {
                        "parallel_execution_unavailable"
                    } else {
                        "task_execution_unavailable"
                    };
                    let message = decision["message"]
                        .as_str()
                        .unwrap_or("parallel/subagent execution is not available")
                        .to_string();
                    self.finish_failed(
                        run_id,
                        json!({
                            "status": "failed",
                            "error_code": code,
                            "error_message": message,
                            "blocked_reason": decision["blocked_reason"],
                        }),
                    )
                    .await;
                    return;
                }
                other => {
                    self.finish_failed(
                        run_id,
                        json!({
                            "status": "failed",
                            "error_code": "invalid_loop_decision",
                            "error_message": format!("the serial loop produced an unknown decision kind: {other}"),
                        }),
                    )
                    .await;
                    return;
                }
            }
        }
    }

    /// True while the run must not create new durable approval/compaction
    /// state: a typed cancellation was requested or the in-memory status is
    /// `stopping`. The checks run before every durable side effect.
    fn run_is_stopping(&self, run_id: &str) -> bool {
        let Some(handle) = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()
        else {
            return true;
        };
        if handle.cancel.requested().is_some() {
            return true;
        }
        self.inner
            .store
            .read()
            .runs
            .get(run_id)
            .is_some_and(|run| run.status == "stopping")
    }

    /// One loop invocation with its own bounded delivery path (events are
    /// durably appended before publish by the delivery task). Bounded by the
    /// remaining run deadline; a timeout cancels with the typed deadline
    /// reason.
    async fn invoke_loop_step(
        &self,
        program: Arc<AgentRunner>,
        run_id: &str,
        context: JsonValue,
        remaining: Duration,
    ) -> LoopStepOutcome {
        let Some(handle) = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()
        else {
            return LoopStepOutcome::Cancelled;
        };
        let cancellation = handle.cancel.clone();
        let (sender, receiver) =
            tokio::sync::mpsc::channel(self.inner.config.event_channel_capacity);
        let delivery = tokio::spawn(run_delivery_task(
            DeliveryContext {
                store: Arc::clone(&self.inner.store),
                persistence: self.inner.persistence.clone(),
                config: Arc::clone(&self.inner.config),
                metrics: Arc::clone(&self.inner.metrics),
            },
            run_id.to_string(),
            receiver,
        ));
        let mut sink = ChannelEventSink(sender);
        let context_vm = json_to_vm_value(&context);
        let cancellation_for_worker = cancellation.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            program.run_with_context_and_events(context_vm, &mut sink, &cancellation_for_worker)
        });
        // The terminal action each non-decision branch must commit AFTER the
        // delivery drain (never before).
        enum TerminalAction {
            Cancel(&'static str),
            Fail(JsonValue),
        }
        let (outcome, terminal) = match tokio::time::timeout(remaining, &mut worker).await {
            Ok(Ok(Ok(value))) => (LoopStepOutcome::Decision(vm_value_to_json(&value)), None),
            Ok(Ok(Err(error))) => match error {
                // A typed invocation failure fails the run (never a
                // fabricated terminal).
                RunError::Invocation(rustscript_vm::InvocationError::Cancelled(reason)) => (
                    LoopStepOutcome::Cancelled,
                    Some(TerminalAction::Cancel(handle_cancel_reason(
                        &handle,
                        reason.as_str(),
                    ))),
                ),
                other => (
                    LoopStepOutcome::Cancelled,
                    Some(TerminalAction::Fail(failed_payload(other.to_string()))),
                ),
            },
            Ok(Err(error)) => (
                LoopStepOutcome::Cancelled,
                Some(TerminalAction::Fail(failed_payload(format!(
                    "RSS worker join failed: {error}"
                )))),
            ),
            Err(_) => {
                // The step deadline is authoritative: cancel with the typed
                // deadline reason and wait only the configured grace. A stop
                // that raced the deadline keeps its own typed reason.
                cancellation.request(CancellationReason::Deadline);
                let _ =
                    tokio::time::timeout(self.inner.config.cancellation_grace, &mut worker).await;
                (
                    LoopStepOutcome::Cancelled,
                    Some(TerminalAction::Cancel(handle_cancel_reason(
                        &handle, "deadline",
                    ))),
                )
            }
        };
        // Drain the delivery path (bounded) so the terminal commit ALWAYS
        // follows the last durably delivered script event — including the
        // cancel/error/join/timeout branches, whose tail events would
        // otherwise race (or be dropped by) the terminal commit. When the
        // drain cannot finish within the cancellation grace (a runaway
        // worker keeps the bounded channel fed while the delivery task is
        // stalled), the tail is NOT silently dropped: the typed
        // `run.truncated` marker is durably appended BEFORE the terminal so
        // a replay always sees the truncation boundary; if even the marker
        // cannot be persisted, the run fails with the typed
        // persistence_unavailable contract.
        let (delivery_outcome, truncation_reason) =
            match tokio::time::timeout(self.inner.config.cancellation_grace, delivery).await {
                Ok(Ok(outcome)) => (outcome, None),
                Ok(Err(_)) => (DeliveryOutcome::default(), Some("delivery_task_failed")),
                Err(_) => (DeliveryOutcome::default(), Some("delivery_drain_timeout")),
            };
        if let Some(reason) = truncation_reason
            && let Err(error) = self.append_truncation_marker(run_id, reason).await
        {
            tracing::error!(
                run_id,
                error = %truncate_for_log(&error, 256),
                "the truncation marker could not be persisted; the run fails typed"
            );
            // A stop that raced the drain keeps its typed cancellation
            // (never downgraded to a failure); otherwise the run fails with
            // the typed persistence contract — never a silent tail drop.
            if self.run_is_stopping(run_id) {
                self.finish_cancelled(run_id, handle_cancel_reason(&handle, "requested"))
                    .await;
                return LoopStepOutcome::Cancelled;
            }
            self.finish_failed(
                run_id,
                json!({
                    "status": "failed",
                    "error_code": "persistence_unavailable",
                    "error_message": "a run event could not be appended durably",
                }),
            )
            .await;
            return LoopStepOutcome::Cancelled;
        }
        if let Some(reason) = delivery_outcome.schema_violation {
            self.finish_failed(run_id, events::schema_violation_error(&reason))
                .await;
            return LoopStepOutcome::Cancelled;
        }
        if delivery_outcome.persist_failed {
            self.finish_failed(
                run_id,
                json!({
                    "status": "failed",
                    "error_code": "persistence_unavailable",
                    "error_message": "a run event could not be appended durably",
                }),
            )
            .await;
            return LoopStepOutcome::Cancelled;
        }
        match terminal {
            Some(TerminalAction::Cancel(reason)) => {
                self.finish_cancelled(run_id, reason).await;
            }
            Some(TerminalAction::Fail(payload)) => {
                self.finish_failed(run_id, payload).await;
            }
            None => {}
        }
        outcome
    }

    /// Merges the loop's base context with the current phase and the carried
    /// loop state into one typed context map.
    fn loop_step_context(&self, base: &JsonValue, phase: &str, state: &JsonValue) -> JsonValue {
        let mut context = base.clone();
        if let (JsonValue::Object(fields), JsonValue::Object(state_fields)) = (&mut context, state)
        {
            fields.insert("phase".to_string(), JsonValue::String(phase.to_string()));
            for (key, value) in state_fields {
                fields.insert(key.clone(), value.clone());
            }
        }
        context
    }

    /// Persists a durable pending approval (bridge), emits the
    /// `approval.required` event with the REAL bridge id, transitions the run
    /// to `waiting_approval`, and parks the exact loop state for an
    /// exactly-once resume. A stop/cancel that lands before the durable write
    /// (or during the storage round trip) cancels the park instead: no
    /// pending approval row is created after a stop, and the run can never be
    /// wedged by a park racing a stop.
    async fn park_for_approval(
        &self,
        run_id: &str,
        base_context: &JsonValue,
        decision: &JsonValue,
        deadline: Instant,
    ) -> ParkOutcome {
        let Some(bridge) = self.inner.approval.clone() else {
            return ParkOutcome::Failed;
        };
        // B: no durable approval write may start after a stop/cancel, and a
        // parked run whose deadline already passed must not be created (the
        // deadline keeps counting while we park).
        if self.run_is_stopping(run_id) {
            return ParkOutcome::Cancelled;
        }
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return ParkOutcome::Cancelled;
        }
        let approval = &decision["approval"];
        let session_id = self
            .inner
            .store
            .read()
            .runs
            .get(run_id)
            .map(|run| run.session_id.clone())
            .unwrap_or_default();
        let tool_call_id = approval["tool_call_id"].as_str().unwrap_or("").to_string();
        let tool_name = approval["tool_name"].as_str().unwrap_or("").to_string();
        let arguments_json =
            serde_json::to_string(&approval["arguments"]).unwrap_or_else(|_| "{}".to_string());
        let risk = match approval["risk_class"].as_str() {
            Some("read") => RiskClass::Read,
            Some("write") => RiskClass::Write,
            Some("execute") => RiskClass::Execute,
            _ => RiskClass::Privileged,
        };
        let now = timestamp() as i64;
        let request = PendingApproval {
            run_id: run_id.to_string(),
            session_id,
            tool_call_id: tool_call_id.clone(),
            tool_name: tool_name.clone(),
            arguments_json,
            risk,
            requested_at_ms: now,
            expires_at_ms: now + self.inner.config.approval_timeout.as_millis() as i64,
        };
        // P2-5: the durable approval request runs on a BLOCKING thread (never
        // a Tokio worker — SQLite/VM stalls must not occupy the request
        // runtime), bounded by the run's remaining deadline so a stuck
        // bridge cannot wedge the run (the typed deadline cancellation path
        // stays reachable).
        //
        // Final P2 (deadline orphan): the approval id is generated BEFORE
        // the request starts and passed idempotently (the storage layer
        // INSERT OR IGNOREs by id — a retry can never duplicate the row),
        // and the JoinHandle is KEPT. When the deadline fires first, the
        // background request still completes — and if its insert wins the
        // lock race, a pending row exists with NO park and NO
        // `approval.required` event. The compensation watcher awaits the
        // join and durably cancels THAT SPECIFIC row the moment the request
        // completes, so no park-less orphan can wait out the 600s
        // approval_timeout sweep.
        let remaining_deadline = deadline.saturating_duration_since(Instant::now());
        let approval_id = Uuid::new_v4().to_string();
        let bridge_for_block = bridge.clone();
        let request_for_block = request;
        let id_for_block = approval_id.clone();
        let mut join = tokio::task::spawn_blocking(move || {
            bridge_for_block.request_pending(&request_for_block, &id_for_block)
        });
        let approval_id = match tokio::time::timeout(remaining_deadline, &mut join).await {
            Ok(Ok(Ok(approval_id))) => approval_id,
            Ok(Ok(Err(error))) => {
                tracing::error!(
                    run_id,
                    error = %truncate_for_log(&error.to_string(), 256),
                    "durable approval request failed; the run fails typed"
                );
                // The request may still have persisted the row before the
                // typed failure (a storage command can fail mid-way):
                // compensate that specific id the moment the worker returns.
                let service_for_comp = self.clone();
                let run_id_for_comp = run_id.to_string();
                let id_for_comp = approval_id.clone();
                tokio::spawn(async move {
                    let _ = join.await;
                    let _ = service_for_comp
                        .cancel_abandoned_approval(&run_id_for_comp, &id_for_comp)
                        .await;
                });
                return ParkOutcome::Failed;
            }
            Ok(Err(error)) => {
                tracing::error!(
                    run_id,
                    error = %truncate_for_log(&error.to_string(), 256),
                    "durable approval request worker failed; the run fails typed"
                );
                let service_for_comp = self.clone();
                let run_id_for_comp = run_id.to_string();
                let id_for_comp = approval_id.clone();
                tokio::spawn(async move {
                    let _ = join.await;
                    let _ = service_for_comp
                        .cancel_abandoned_approval(&run_id_for_comp, &id_for_comp)
                        .await;
                });
                return ParkOutcome::Failed;
            }
            Err(_) => {
                // The run's remaining deadline passed while the durable
                // request was in flight: cancel typed (the request itself
                // completes in the background; no park exists yet). The
                // compensation below expires the specific row if — and the
                // moment — the late request actually persisted it.
                tracing::warn!(
                    run_id,
                    "durable approval request outlived the run deadline; cancelling typed"
                );
                let service_for_comp = self.clone();
                let run_id_for_comp = run_id.to_string();
                let id_for_comp = approval_id.clone();
                tokio::spawn(async move {
                    // The join resolves only AFTER the blocking storage
                    // command returned, so an Ok(id) result means the row
                    // exists (durably): cancel it immediately. An Err result
                    // means no row was created — the guarded cancel is still
                    // attempted as a typed no-op.
                    let _ = join.await;
                    let _ = service_for_comp
                        .cancel_abandoned_approval(&run_id_for_comp, &id_for_comp)
                        .await;
                });
                return ParkOutcome::Cancelled;
            }
        };
        // B: re-check after the blocking storage round trip — a stop that
        // landed meanwhile must not see a new park.
        if self.run_is_stopping(run_id) {
            return ParkOutcome::Cancelled;
        }
        if !self
            .transition_run(run_id, "running", "waiting_approval")
            .await
        {
            if self.run_is_stopping(run_id) {
                return ParkOutcome::Cancelled;
            }
            return ParkOutcome::Failed;
        }
        // The park is inserted BEFORE the notification event: the run is
        // observable as parked the moment the durable transition lands, so a
        // resolution that races the event append still finds the park.
        self.inner.parked.lock().expect("parked lock").insert(
            run_id.to_string(),
            ParkedRun {
                approval_id: approval_id.clone(),
                base_context: base_context.clone(),
                state: decision_state(decision),
                // C: the ORIGINAL run deadline rides along; a resume passes
                // it back so the park time counts against the wall clock.
                deadline,
                // The row is still pending; the durable outcome is recorded
                // only once the bridge resolves it (see ParkedRun docs).
                resolution: None,
            },
        );
        // P2-4: re-check atomically AFTER the park insert — a stop/cancel
        // that landed during the durable transition must not see a new park
        // or a post-stop approval.required event (the run would otherwise sit
        // parked until the approval_timeout expiry sweep — the default 600s).
        if self.run_is_stopping(run_id) {
            self.inner
                .parked
                .lock()
                .expect("parked lock")
                .remove(run_id);
            // The park transition may have committed durably while the stop
            // landed: move the durable status back to `running` so the typed
            // terminal can commit (the A2 run.terminal contract requires a
            // `running` source state).
            let _ = self
                .transition_run(run_id, "waiting_approval", "running")
                .await;
            return ParkOutcome::Cancelled;
        }
        // H: the approval.required event is emitted HERE with the real
        // bridge-generated id, durably appended before publish, exactly once
        // per park (the loop no longer emits a placeholder with an empty id).
        let turn = decision["turn"].as_i64().unwrap_or(0);
        if let Err(error) = self
            .append_approval_required_event(
                run_id,
                &approval_id,
                &tool_call_id,
                &tool_name,
                risk.as_str(),
                turn,
            )
            .await
        {
            tracing::error!(
                run_id,
                error = %truncate_for_log(&error, 256),
                "approval.required could not be appended durably; the run fails typed"
            );
            // Un-wedge: remove the park (a stop may have already removed it)
            // so the run can never be stuck parked.
            self.inner
                .parked
                .lock()
                .expect("parked lock")
                .remove(run_id);
            if self.run_is_stopping(run_id) {
                // The append was rejected because a stop landed: cancel typed
                // (the durable status is still waiting_approval; move it back
                // to running so the typed terminal can commit).
                let _ = self
                    .transition_run(run_id, "waiting_approval", "running")
                    .await;
                return ParkOutcome::Cancelled;
            }
            let _ = self
                .transition_run(run_id, "waiting_approval", "running")
                .await;
            return ParkOutcome::Failed;
        }
        tracing::info!(run_id, "run parked on a pending approval");
        ParkOutcome::Parked
    }

    /// Final-P2 compensation for an approval whose blocking `approval.request`
    /// outlived the run deadline (or failed mid-way): the moment the
    /// background request completes, durably cancel (expire) THAT SPECIFIC
    /// row. Targeted by id and pending-only — a legitimate park's row (a
    /// different id) is never touched, and a missing row is a typed no-op.
    /// One bounded storage round trip on a blocking thread; a failure is
    /// logged (the restart-recovery orphan sweep and the janitor expiry
    /// sweep remain as the durable backstops).
    async fn cancel_abandoned_approval(
        &self,
        run_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        let Some(bridge) = self.inner.approval.clone() else {
            return Ok(());
        };
        let run_id_for_block = run_id.to_string();
        let approval_id_for_block = approval_id.to_string();
        let resolver = "deadline-compensation".to_string();
        tokio::task::spawn_blocking(move || {
            let now = timestamp() as i64;
            match bridge.cancel(&approval_id_for_block, &resolver, now) {
                Ok(affected) => {
                    if affected > 0 {
                        tracing::info!(
                            run_id = %run_id_for_block,
                            approval_id = %approval_id_for_block,
                            "abandoned approval durably cancelled after the run deadline"
                        );
                    }
                    Ok(())
                }
                Err(error) => Err(format!("approval.cancel failed: {error}")),
            }
        })
        .await
        .map_err(|error| format!("approval cancel worker failed: {error}"))?
    }

    /// Durably appends the typed `run.truncated` marker (reason + drain
    /// bounds only — never event payloads, tool arguments, or any other
    /// sensitive run data) BEFORE the terminal of a step whose bounded
    /// delivery drain exceeded the cancellation grace. Mirrors the
    /// approval.required append path: store lock + durable `event.append`,
    /// in-memory rollback on failure.
    async fn append_truncation_marker(&self, run_id: &str, reason: &str) -> Result<(), String> {
        let service = self.clone();
        let run_id_for_block = run_id.to_string();
        let reason_for_block = reason.to_string();
        let grace_ms = self.inner.config.cancellation_grace.as_millis() as i64;
        let channel_capacity = self.inner.config.event_channel_capacity as i64;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let mut store = service.inner.store.write();
            let Some(run) = store.runs.get_mut(&run_id_for_block) else {
                return Err("the run is gone".to_string());
            };
            if matches!(
                run.status.as_str(),
                "completed" | "failed" | "cancelled" | "terminal_pending" | "stopping"
            ) {
                return Err("the run already reached a terminal or is stopping".to_string());
            }
            let event = append_event_locked(
                run,
                "run.truncated",
                events::truncation_marker(&reason_for_block, grace_ms, channel_capacity),
                max_event_bytes,
                max_events,
            );
            let payload = json!({
                "run_id": run_id_for_block,
                "event_id": event.event_id,
                "event_type": event.event,
                "payload_json": serde_json::to_string(&event.data)
                    .unwrap_or_else(|_| "{}".to_string()),
                "now_ms": timestamp(),
                "max_events": max_events,
            });
            let durable = match service.persistence_handle() {
                Some(persistence) => persistence.event_append(&payload).map(|_| ()),
                None => Ok(()),
            };
            match durable {
                Ok(()) => {
                    if let Some(sender) = &run.sender {
                        let _ = sender.send(event);
                    }
                    Ok(())
                }
                Err(error) => {
                    run.events
                        .retain(|existing| existing.event_id != event.event_id);
                    Err(format!("run.truncated event append failed: {error}"))
                }
            }
        })
        .await
        .map_err(|error| format!("truncation marker worker failed: {error}"))?
    }

    /// Durably appends and publishes the `approval.required` event carrying
    /// the bridge-generated approval id (the loop's placeholder emission was
    /// removed; this is the single exact-once emission per park).
    async fn append_approval_required_event(
        &self,
        run_id: &str,
        approval_id: &str,
        tool_call_id: &str,
        tool_name: &str,
        risk_class: &str,
        turn: i64,
    ) -> Result<(), String> {
        let service = self.clone();
        let run_id_for_block = run_id.to_string();
        let approval_id_for_block = approval_id.to_string();
        let tool_call_id_for_block = tool_call_id.to_string();
        let tool_name_for_block = tool_name.to_string();
        let risk_class_for_block = risk_class.to_string();
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let mut store = service.inner.store.write();
            let Some(run) = store.runs.get_mut(&run_id_for_block) else {
                return Err("the run is gone".to_string());
            };
            if matches!(
                run.status.as_str(),
                "completed" | "failed" | "cancelled" | "terminal_pending" | "stopping"
            ) {
                // P2-4: a stop that landed before this closure ran (the
                // park-insert re-check is the primary guard; this status
                // check closes the last microsecond of the race) must never
                // see a post-stop approval.required event.
                return Err("the run already reached a terminal or is stopping".to_string());
            }
            let event = append_event_locked(
                run,
                "approval.required",
                json!({
                    "approval_id": approval_id_for_block,
                    "tool_call_id": tool_call_id_for_block,
                    "tool_name": tool_name_for_block,
                    "risk_class": risk_class_for_block,
                    "turn": turn,
                }),
                max_event_bytes,
                max_events,
            );
            let payload = json!({
                "run_id": run_id_for_block,
                "event_id": event.event_id,
                "event_type": event.event,
                "payload_json": serde_json::to_string(&event.data)
                    .unwrap_or_else(|_| "{}".to_string()),
                "now_ms": timestamp(),
                "max_events": max_events,
            });
            let durable = match service.persistence_handle() {
                Some(persistence) => persistence.event_append(&payload).map(|_| ()),
                None => Ok(()),
            };
            match durable {
                Ok(()) => {
                    if let Some(sender) = &run.sender {
                        let _ = sender.send(event);
                    }
                    Ok(())
                }
                Err(error) => {
                    run.events
                        .retain(|existing| existing.event_id != event.event_id);
                    Err(format!("approval.required event append failed: {error}"))
                }
            }
        })
        .await
        .map_err(|error| format!("approval event worker failed: {error}"))?
    }

    /// Persists every in-run message whose ordinal exceeds the durable
    /// watermark (the loop appends assistant tool-call and tool-result
    /// messages inline; they must be durably committed before the loop
    /// continues, parks, or commits a terminal). Returns the new watermark.
    /// Durable-first: any failure fails the run typed — the loop never
    /// continues on unpersisted history. In-memory-only mode mirrors the
    /// same messages into the session (a second run on the same session
    /// must never silently lose the first run's tool cycle).
    async fn sync_durable_messages(
        &self,
        run_id: &str,
        session_id: &str,
        decision: &JsonValue,
        durable_ordinal: i64,
    ) -> Result<i64, String> {
        let Some(messages) = decision["messages"].as_array() else {
            return Ok(durable_ordinal);
        };
        let mut watermark = durable_ordinal;
        for message in messages {
            let ordinal = message["ordinal"].as_i64().unwrap_or(0);
            if ordinal <= watermark {
                continue;
            }
            let content = message["content"].clone();
            // The message-level pair id (the loop's canonical shape) mirrors
            // the durable messages.tool_call_id column; the content-part
            // scan is the fallback for history shapes without the
            // message-level field.
            let tool_call_id = message["tool_call_id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| first_tool_result_call_id(&content));
            let payload = json!({
                "id": Uuid::new_v4().to_string(),
                "session_id": session_id,
                "role": message["role"].as_str().unwrap_or("").to_string(),
                "content_json": serde_json::to_string(&content)
                    .unwrap_or_else(|_| "[]".to_string()),
                "name": "",
                "tool_call_id": tool_call_id,
                "parent_message_id": "",
                "token_estimate": 0,
                "metadata_json": "{}",
                "run_id": run_id,
                "finish_reason": "",
                "now_ms": timestamp(),
            });
            let service = self.clone();
            let run_id_for_block = run_id.to_string();
            let session_id_for_block = session_id.to_string();
            tokio::task::spawn_blocking(move || {
                service.persist_loop_message(&run_id_for_block, &session_id_for_block, &payload)
            })
            .await
            .map_err(|error| format!("durable message worker failed: {error}"))??;
            watermark = ordinal;
        }
        Ok(watermark)
    }

    /// One message append: the durable append (when durable storage is
    /// configured) plus the matching in-memory session mirror (durable
    /// first; the in-memory row is applied only after the commit succeeded).
    /// The in-memory mirror ALWAYS runs, so an in-memory-only gateway keeps
    /// the session history complete across runs in the same session.
    fn persist_loop_message(
        &self,
        run_id: &str,
        session_id: &str,
        payload: &JsonValue,
    ) -> Result<(), String> {
        if let Some(persistence) = self.inner.persistence.clone() {
            persistence
                .message_append(payload)
                .map_err(|error| format!("durable message append failed: {error}"))?;
        }
        let mut store = self.inner.store.write();
        let Some(session) = store.sessions.get_mut(session_id) else {
            return Ok(());
        };
        session.messages.push(SessionMessage {
            id: payload["id"].as_str().unwrap_or("").to_string(),
            session_id: session_id.to_string(),
            role: payload["role"].as_str().unwrap_or("").to_string(),
            // The message-level pair id mirrors the durable column so a
            // reload (or a later compaction in this run) still pairs the
            // assistant tool-call with its tool result.
            tool_call_id: payload["tool_call_id"].as_str().unwrap_or("").to_string(),
            content: payload["content_json"]
                .as_str()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or(JsonValue::Null),
            created_at: payload["now_ms"].as_u64().unwrap_or(0),
            run_id: Some(run_id.to_string()),
            finish_reason: None,
            compacted: false,
        });
        session.view.message_count = session.messages.len();
        session.view.updated_at = timestamp();
        Ok(())
    }

    /// Executes the RSS-planned compaction commands (`compaction.start` ->
    /// `message.compact` -> `compaction.commit`) while the run is durably
    /// `compacting`, then transitions back to `running`. On a step failure a
    /// pending row is durably failed; the loop resumes with the typed result
    /// and the full history (recoverable).
    async fn execute_compaction(&self, run_id: &str, decision: &JsonValue) -> (bool, String) {
        let Some(persistence) = self.inner.persistence.clone() else {
            return (false, "no durable storage is configured".to_string());
        };
        // B: no durable compaction work may start after a stop/cancel.
        if self.run_is_stopping(run_id) {
            return (
                false,
                "the run was stopped before the compaction started".to_string(),
            );
        }
        if !self.transition_run(run_id, "running", "compacting").await {
            return (
                false,
                "the run could not transition to compacting".to_string(),
            );
        }
        let plan = decision["plan"].clone();
        let mut commands: Vec<(String, JsonValue)> = plan["commands"]
            .as_array()
            .map(|commands| {
                commands
                    .iter()
                    .filter_map(|command| {
                        let op = command["op"].as_str()?.to_string();
                        Some((op, command["payload"].clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let start_ordinal = plan["source_start_ordinal"].as_i64().unwrap_or(0);
        let end_ordinal = plan["source_end_ordinal"].as_i64().unwrap_or(0);
        let generation = plan["generation"].as_i64().unwrap_or(0);
        let session_id = commands
            .first()
            .and_then(|(_, payload)| payload["session_id"].as_str())
            .unwrap_or("")
            .to_string();
        // The canonical compaction id is service-owned (`compact:{session}:{generation}`):
        // the loop's carried config may trail after an internal compaction
        // (the pinned core has no int-to-string conversion), so the plan's
        // command ids are canonicalized before execution — the A2 storage's
        // per-(session, generation) identity and the idempotent-resume path
        // both key on this exact id.
        for (_, payload) in &mut commands {
            if payload.get("id").is_some() {
                payload["id"] = json!(format!("compact:{session_id}:{generation}"));
            }
        }
        let service = self.clone();
        let run_id_for_block = run_id.to_string();
        let session_id_for_block = session_id;
        let result = tokio::task::spawn_blocking(move || {
            // B: re-check inside the blocking worker, immediately before any
            // durable write — a stop that landed during the transition must
            // not create a compaction row.
            if service.run_is_stopping(&run_id_for_block) {
                let _ = persistence.run_transition(&json!({
                    "run_id": run_id_for_block,
                    "from_status": "compacting",
                    "to_status": "running",
                    "error_code": "",
                    "error_message": "",
                    "recovery_reason": "",
                    "now_ms": timestamp(),
                }));
                return Some("the run was stopped during the compaction".to_string());
            }
            let mut error = None;
            let mut start_ok = false;
            for (op, payload) in &commands {
                let step = match op.as_str() {
                    "compaction.start" => persistence.compaction_start(payload),
                    "message.compact" => persistence.message_compact(payload),
                    "compaction.commit" => persistence.compaction_commit(payload),
                    // E: an unknown compaction command is a typed failure, never
                    // a silent continue (the plan may drift from the storage
                    // contract).
                    other => {
                        error = Some(format!("{other}: unknown compaction command in the plan"));
                        break;
                    }
                };
                match step {
                    Ok(value) if compaction_command_ok(op, &value) => {
                        if op == "compaction.start" {
                            start_ok = true;
                        }
                        continue;
                    }
                    Ok(value) => {
                        let code = value
                            .get("code")
                            .and_then(JsonValue::as_str)
                            .unwrap_or("storage_error")
                            .to_string();
                        let message = value
                            .get("message")
                            .and_then(JsonValue::as_str)
                            .unwrap_or("")
                            .to_string();
                        error = Some(format!("{op} failed: {code} {message}"));
                        break;
                    }
                    Err(e) => {
                        error = Some(format!("{op} failed: {e}"));
                        break;
                    }
                }
            }
            // A pending row that never committed is durably failed (the A2
            // fail command; a rejected start fabricated no row).
            if let Some(error) = error.as_ref()
                && start_ok
                && let Some(payload) = commands.first().map(|(_, payload)| payload)
            {
                let _ = persistence.compaction_fail(&json!({
                    "id": payload["id"],
                    "error_message": error,
                    "completed_at_ms": timestamp(),
                }));
            }
            // The run returns to `running` either way (terminals require it).
            let _ = persistence.run_transition(&json!({
                "run_id": run_id_for_block,
                "from_status": "compacting",
                "to_status": "running",
                "error_code": "",
                "error_message": "",
                "recovery_reason": "",
                "now_ms": timestamp(),
            }));
            if error.is_none() {
                // E/G: mirror the committed compaction in memory: mark the
                // covered range compacted and advance the session generation
                // (new runs filter the compacted rows; the next plan in this
                // run targets the refreshed generation).
                let mut store = service.inner.store.write();
                if let Some(session) = store.sessions.get_mut(&session_id_for_block) {
                    for (index, message) in session.messages.iter_mut().enumerate() {
                        let ordinal = (index + 1) as i64;
                        if ordinal >= start_ordinal && ordinal <= end_ordinal {
                            message.compacted = true;
                        }
                    }
                    session.view.generation = generation as u64;
                }
            }
            error
        })
        .await
        .unwrap_or_else(|error| Some(format!("compaction worker failed: {error}")));
        match result {
            None => (true, String::new()),
            Some(error) => (false, error),
        }
    }

    /// Durable run status transition through the A2 storage program. The
    /// typed `run.transition` data is `{results: [{rows_affected, ...}]}`;
    /// the transition matched exactly when the first result row reports at
    /// least one affected row.
    async fn transition_run(&self, run_id: &str, from_status: &str, to_status: &str) -> bool {
        let Some(persistence) = self.inner.persistence.clone() else {
            // In-memory-only mode has no durable status to transition.
            return true;
        };
        let run_id = run_id.to_string();
        let from_status = from_status.to_string();
        let to_status = to_status.to_string();
        tokio::task::spawn_blocking(move || {
            persistence
                .run_transition(&json!({
                    "run_id": run_id,
                    "from_status": from_status,
                    "to_status": to_status,
                    "error_code": "",
                    "error_message": "",
                    "recovery_reason": "",
                    "now_ms": timestamp(),
                }))
                .map(|value| run_transition_matched(&value))
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }

    /// The typed run.failed payload for a `run.failed` decision.
    fn failed_decision_payload(&self, decision: &JsonValue) -> JsonValue {
        let error = &decision["error"];
        json!({
            "status": "failed",
            "error_code": error["code"].as_str().unwrap_or("provider_error"),
            "error_message": error["message"].as_str().unwrap_or("provider request failed"),
            "provider_error": {
                "status": error["status"],
                "type": error["type"],
                "code": error["code"],
                "message": error["message"],
                "param": error["param"],
                "request_id": error["request_id"],
            },
            "reason": decision["reason"],
        })
    }

    /// Resolves a parked run's approval exactly once and resumes the loop:
    /// `Resumed` resumes with `resolved: true`; a deny/expire terminal
    /// resumes with `resolved: false` plus the typed outcome (`denied` |
    /// `expired`) so the loop folds the typed `approval_denied` /
    /// `approval_expired` tool result into the conversation; `AlreadyResolved`
    /// is a strict typed no-op — it never resumes with `resolved:false`.
    ///
    /// Once the bridge durably resolves the row, the OUTCOME is recorded on
    /// the park: a transition failure restores the park WITH the recorded
    /// decision, so a retry never re-resolves the durable row (and never
    /// downgrades an approve to a deny). A bridge or transition failure NEVER
    /// drops the park while the run is still active: the park is restored so
    /// a retry (or the expiry sweep, or a stop) stays reachable — a failed
    /// resolution can never wedge the run.
    pub fn resolve_run_approval(&self, run_id: &str, approve: bool) -> Result<(), String> {
        let parked = self
            .inner
            .parked
            .lock()
            .expect("parked lock")
            .remove(run_id)
            .ok_or_else(|| "no pending approval is parked for this run".to_string())?;
        let Some(bridge) = self.inner.approval.clone() else {
            self.restore_park_if_active(run_id, &parked);
            return Err("the durable approval bridge is not available".to_string());
        };
        let now = timestamp() as i64;
        // The durable outcome (resolved, typed outcome, reason). A park that
        // already records the bridge outcome skips the resolve entirely: the
        // durable row is terminal and a second resolve could only downgrade
        // the recorded decision (an approve re-resolved after the row moved
        // to `approved` surfaces as AlreadyResolved and would read as a
        // deny).
        let (resolved, outcome, reason) = match &parked.resolution {
            Some(recorded) => (
                recorded.resolved,
                recorded.outcome.clone(),
                recorded.reason.clone(),
            ),
            None => {
                let resolution = match bridge.resolve(&parked.approval_id, approve, "gateway", now)
                {
                    Ok(resolution) => resolution,
                    Err(error) => {
                        // A storage failure must not consume the park:
                        // restore it so the caller (or the sweep) can
                        // retry.
                        self.restore_park_if_active(run_id, &parked);
                        return Err(error.to_string());
                    }
                };
                match resolution {
                    Resolution::Resumed { .. } => (true, "approved".to_string(), String::new()),
                    Resolution::Terminal { reason, code, .. } => {
                        (false, code.clone(), reason.clone())
                    }
                    Resolution::AlreadyResolved => {
                        // Strict no-op: the durable row is already terminal
                        // (a foreign expire/resolve landed first). The park
                        // is restored so the expiry resume path (the sweep's
                        // own resolve) can still pick it up — but this call
                        // never resumes the run with `resolved:false` and
                        // never re-resolves the row.
                        self.restore_park_if_active(run_id, &parked);
                        return Err("approval already resolved".to_string());
                    }
                }
            }
        };
        if !self.transition_run_blocking(run_id, "waiting_approval", "running") {
            // The run may have moved (a stop or a concurrent terminal): only
            // restore the park while the run is still an active, un-cancelled
            // candidate — otherwise the run is on its way to a terminal and
            // re-parking would wedge it. The restored park CARRIES the
            // durable outcome so a retry resumes with the same decision.
            let mut restored = parked.clone();
            restored.resolution = Some(ParkedResolution {
                resolved,
                outcome: outcome.clone(),
                reason: reason.clone(),
            });
            if !self.restore_park_if_active(run_id, &restored) {
                tracing::warn!(
                    run_id,
                    approval_id = %parked.approval_id,
                    "parked run could not transition back to running and is no longer active"
                );
            }
            return Err("the run could not transition back to running".to_string());
        }
        let service = self.clone();
        let run_id = run_id.to_string();
        let session_id = service
            .inner
            .store
            .read()
            .runs
            .get(&run_id)
            .map(|run| run.session_id.clone())
            .unwrap_or_default();
        let program = match service.inner.agent_program.clone() {
            Some(program) => program,
            None => return Err("the production loop program is not available".to_string()),
        };
        let base_context = json_to_vm_value(&parked.base_context);
        let deadline = parked.deadline;
        tokio::spawn(async move {
            let mut state = parked.state;
            let approval = state.get("approval").cloned().unwrap_or_else(|| json!({}));
            state["approval"] = json!({
                "approval_id": parked.approval_id,
                "tool_call_id": approval["tool_call_id"],
                "tool_name": approval["tool_name"],
                "arguments": approval["arguments"],
                "risk_class": approval["risk_class"],
                "resolved": resolved,
                "outcome": outcome,
                "reason": reason,
            });
            service
                .drive_production_loop(
                    program,
                    &run_id,
                    &session_id,
                    base_context,
                    "approval.resume",
                    state,
                    // C: the ORIGINAL run deadline — the resume must not
                    // reset the wall clock.
                    deadline,
                )
                .await;
        });
        Ok(())
    }

    /// Re-inserts one taken park when the run is still an active,
    /// un-cancelled candidate (never re-park a stopped/terminal run).
    /// Returns whether the park was restored.
    fn restore_park_if_active(&self, run_id: &str, parked: &ParkedRun) -> bool {
        let active = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .is_some_and(|handle| handle.cancel.requested().is_none());
        if active {
            self.inner
                .parked
                .lock()
                .expect("parked lock")
                .insert(run_id.to_string(), parked.clone());
        }
        active
    }

    /// Blocking variant of the run transition (resolution path).
    fn transition_run_blocking(&self, run_id: &str, from_status: &str, to_status: &str) -> bool {
        let Some(persistence) = self.inner.persistence.clone() else {
            return true;
        };
        persistence
            .run_transition(&json!({
                "run_id": run_id,
                "from_status": from_status,
                "to_status": to_status,
                "error_code": "",
                "error_message": "",
                "recovery_reason": "",
                "now_ms": timestamp(),
            }))
            .map(|value| run_transition_matched(&value))
            .unwrap_or(false)
    }

    /// Expires every parked approval whose durable row has passed its
    /// deadline and resumes the affected runs with the typed expired tool
    /// result. Called on the janitor cadence; bounded by admission capacity.
    /// The whole sweep (the typed `approval.expire` command plus the per-run
    /// storage reads) runs on a blocking worker so Tokio threads are never
    /// occupied by storage stalls.
    fn expire_parked_approvals(&self) {
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.expire_parked_approvals_blocking());
    }

    fn expire_parked_approvals_blocking(&self) {
        // D: the typed approval.expire sweep marks every pending row at or
        // before now as durably `expired`.
        if let Some(bridge) = self.inner.approval.clone() {
            let now = timestamp() as i64;
            if let Err(error) = bridge.expire(now) {
                tracing::warn!(
                    error = %truncate_for_log(&error.to_string(), 256),
                    "approval expire sweep failed; parked runs will retry on the next tick"
                );
            }
        }
        let candidates: Vec<(String, String)> = self
            .inner
            .parked
            .lock()
            .expect("parked lock")
            .iter()
            .map(|(run_id, parked)| (run_id.clone(), parked.approval_id.clone()))
            .collect();
        for (run_id, approval_id) in candidates {
            let Some(persistence) = self.inner.persistence.clone() else {
                continue;
            };
            // One bounded storage round-trip per parked run on the janitor
            // cadence (parked runs are bounded by admission capacity).
            let expired = persistence
                .approval_get(&approval_id)
                .ok()
                .and_then(|value| {
                    value
                        .get("rows")
                        .and_then(JsonValue::as_array)
                        .and_then(|rows| rows.first())
                        .and_then(JsonValue::as_array)
                        .and_then(|row| row.get(7))
                        .and_then(JsonValue::as_str)
                        .map(|state| state == "expired")
                })
                .unwrap_or(false);
            if expired && let Err(error) = self.resolve_run_approval(&run_id, false) {
                tracing::warn!(run_id, approval_id, error = %error, "expired approval sweep failed");
            }
        }
    }
}

/// One invocation outcome of a production loop step.
enum LoopStepOutcome {
    /// The loop produced a typed decision map.
    Decision(JsonValue),
    /// The step ended with a typed terminal (already committed).
    Cancelled,
}

/// Outcome of one durable approval park attempt.
enum ParkOutcome {
    /// The approval row, the `approval.required` event, and the park are all
    /// durable; the run waits for a resolution.
    Parked,
    /// A stop/cancel (or the run deadline) landed before the park could be
    /// created: no durable approval row and no park exist; the drive loop
    /// commits the typed cancellation.
    Cancelled,
    /// The durable bridge or event append failed; the run fails typed.
    Failed,
}

/// The `tool_call_id` of the first `tool_result` content part of one
/// canonical message (the durable messages.tool_call_id column mirror).
fn first_tool_result_call_id(content: &JsonValue) -> String {
    content
        .as_array()
        .into_iter()
        .flatten()
        .find(|part| part["type"] == "tool_result")
        .and_then(|part| part["tool_call_id"].as_str())
        .unwrap_or("")
        .to_string()
}

/// The loop state carried by a decision (everything except the `kind`
/// discriminator).
fn decision_state(decision: &JsonValue) -> JsonValue {
    let mut state = decision.clone();
    if let JsonValue::Object(fields) = &mut state {
        fields.remove("kind");
    }
    state
}

/// Converts one JSON value into a VM value (the service-side mirror of the
/// renderer).
fn json_to_vm_value(value: &JsonValue) -> VmValue {
    crate::domain::json_to_vm_value(value)
}

/// Normalizes one stored message content to the canonical content-part array
/// the serial loop and the provider adapters consume: a plain string becomes
/// a single text part, an array passes through, anything else is empty.
fn canonical_message_content(content: &JsonValue) -> JsonValue {
    match content {
        JsonValue::String(text) => json!([{"type": "text", "text": text}]),
        JsonValue::Array(_) => content.clone(),
        _ => JsonValue::Array(Vec::new()),
    }
}

/// True when a typed compaction command's DATA payload reports success:
/// `compaction.start` returns the inserted row query (non-empty `rows`);
/// `message.compact` is the guarded no-op before the commit (the A2
/// contract: it returns a successful envelope with zero affected rows, and
/// the commit itself marks the range); `compaction.commit` returns the
/// transition `{results: [...]}` array and must match the pending row.
fn compaction_command_ok(op: &str, data: &JsonValue) -> bool {
    match op {
        "compaction.start" => data
            .get("rows")
            .and_then(JsonValue::as_array)
            .map(|rows| !rows.is_empty())
            .unwrap_or(false),
        "message.compact" => true,
        "compaction.commit" => run_transition_matched(data),
        _ => true,
    }
}

/// True when a typed `run.transition` data payload (`{results:
/// [{rows_affected, ...}]}`) matched exactly one run row.
fn run_transition_matched(data: &JsonValue) -> bool {
    data.get("results")
        .and_then(JsonValue::as_array)
        .and_then(|results| results.first())
        .and_then(JsonValue::as_object)
        .and_then(|first| first.get("rows_affected"))
        .and_then(JsonValue::as_i64)
        .unwrap_or(0)
        >= 1
}

impl AgentService {
    /// Retries one run's pending terminal commit. Runs on a blocking thread
    /// with the store write lock held (durable-before-visible). On success
    /// the terminal events are published exactly once and the run record
    /// reaches its true terminal state; on a typed transition conflict the
    /// pending terminal is dropped without publishing (never a fabricated
    /// terminal).
    async fn retry_pending_terminal(&self, run_id: &str) -> PendingRetryOutcome {
        let service = self.clone();
        let run_id_for_block = run_id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut store = service.inner.store.write();
            let persistence = service.persistence_handle();
            // The retry owns the pending entry while it attempts the commit.
            let Some(pending) = service.take_pending_terminal(&run_id_for_block) else {
                return PendingRetryOutcome::Gone;
            };
            service.inner.metrics.runs_terminal_pending_dec();
            let Some(run) = store.runs.get_mut(&run_id_for_block) else {
                return PendingRetryOutcome::Gone;
            };
            if run.status != "terminal_pending" {
                return PendingRetryOutcome::Gone;
            }
            if std::time::Instant::now() >= pending.deadline {
                // Bounded: after the window no more events can ever be
                // published for this run in this process. Close the live
                // stream so SSE subscribers are not held forever; the handle
                // is released via its TTL and the durable side is repaired by
                // restart recovery.
                close_run_stream(run);
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
            let previous_status = run.status.clone();
            let previous_events = run.events.len();
            // Rebuild the terminal's assistant message under the same lock
            // (durable-before-visible: it is appended in memory only after
            // the durable commit succeeds).
            let message = pending.assistant_message.clone();
            let mut previous_session_updated = None;
            if let Some(message) = &message {
                let Some(session_id) = pending.session_id.as_deref() else {
                    return PendingRetryOutcome::Gone;
                };
                let Some(session) = store.sessions.get_mut(session_id) else {
                    return PendingRetryOutcome::Gone;
                };
                previous_session_updated = Some(session.view.updated_at);
                session.messages.push(message.clone());
                session.view.message_count = session.messages.len();
                session.view.updated_at = timestamp();
            }
            let events = pending.events.iter().collect::<Vec<_>>();
            let durable = {
                let run = store
                    .runs
                    .get_mut(&run_id_for_block)
                    .expect("run presence was checked above");
                for event in &pending.events {
                    run.events.push(event.clone());
                }
                let max_events = service.inner.config.max_events_per_run;
                if run.events.len() > max_events {
                    let excess = run.events.len() - max_events;
                    run.events.drain(0..excess);
                }
                run.status = pending.to_status.clone();
                terminal_commit(
                    persistence.as_deref(),
                    run,
                    pending.session_id.as_deref().unwrap_or(""),
                    &pending.to_status,
                    &events,
                    message.as_ref(),
                )
            };
            match durable {
                Ok(()) => {
                    let run = store
                        .runs
                        .get_mut(&run_id_for_block)
                        .expect("run presence was checked above");
                    // Publish the reconciled copies (sequences were updated in
                    // place by the commit), exactly once per event.
                    for event in &pending.events {
                        if let Some(reconciled) = run
                            .events
                            .iter()
                            .find(|candidate| candidate.event_id == event.event_id)
                            && let Some(sender) = &run.sender
                        {
                            let _ = sender.send(reconciled.clone());
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
                    // The durable side already reached a different terminal
                    // (e.g. restart recovery); publishing ours would fabricate
                    // a terminal that never happened durably.
                    rollback_pending_retry(
                        &mut store,
                        &run_id_for_block,
                        &pending,
                        previous_status,
                        previous_events,
                        previous_session_updated,
                    );
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
                    rollback_pending_retry(
                        &mut store,
                        &run_id_for_block,
                        &pending,
                        previous_status,
                        previous_events,
                        previous_session_updated,
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
/// message in one durable commit). The caller holds the store write lock on
/// a blocking thread. The in-memory events' sequences are reconciled with
/// the transactionally allocated sequences returned by the command, so
/// reload adjacency validation can never diverge from the durable side.
/// Callers publish the terminal events only after this returns `Ok`.
fn terminal_commit(
    persistence: Option<&GatewayPersistence>,
    run: &mut RunRecord,
    session_id: &str,
    to_status: &str,
    events: &[&GatewayEvent],
    assistant_message: Option<&SessionMessage>,
) -> Result<(), TerminalCommitError> {
    let Some(persistence) = persistence else {
        return Ok(());
    };
    let event = |index: usize| -> &GatewayEvent {
        events.get(index).expect("terminal event index in range")
    };
    let event_count = events.len();
    let payload = json!({
        "run_id": run.run_id,
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
        "now_ms": timestamp(),
    });
    let data = persistence
        .run_terminal(&payload)
        .map_err(|error| TerminalCommitError {
            code: error.code.clone(),
            message: error.message.clone(),
        })?;
    // Reconcile the in-memory terminal event sequences with the
    // transactionally allocated durable sequences.
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
        if let Some(in_memory) = run
            .events
            .iter_mut()
            .find(|candidate| candidate.event_id == event.event_id)
        {
            in_memory.seq = seq;
        }
    }
    Ok(())
}

/// Outcome of one bounded terminal retry attempt.
enum PendingRetryOutcome {
    /// The terminal was committed durably and published (exactly once).
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

/// Rolls one failed retry attempt back to the observable terminal-pending
/// state (or the durable-terminal-elsewhere state), mirroring the worker's
/// rollback so no unpersisted terminal is ever visible.
#[allow(clippy::too_many_arguments)]
fn rollback_pending_retry(
    store: &mut GatewayStore,
    run_id: &str,
    pending: &PendingTerminal,
    previous_status: String,
    previous_events: usize,
    previous_session_updated: Option<u64>,
) {
    if let Some(run) = store.runs.get_mut(run_id) {
        run.status = previous_status;
        run.events.truncate(previous_events);
    }
    if let (Some(session_id), Some(updated_at)) =
        (pending.session_id.as_deref(), previous_session_updated)
        && let Some(session) = store.sessions.get_mut(session_id)
    {
        session.messages.pop();
        session.view.message_count = session.messages.len();
        session.view.updated_at = updated_at;
    }
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
            let mut runs = inner.runs.lock().expect("runs lock");
            runs.retain(|_run_id, handle| {
                handle
                    .terminal_at
                    .lock()
                    .expect("terminal lock")
                    .is_none_or(|terminal_at| terminal_at + ttl > now)
            });
            drop(runs);
            // The bounded approval expiry sweep: parked runs whose durable
            // approval passed its deadline resume with a typed expired tool
            // result (the loop folds it and continues).
            let service = AgentService {
                inner: Arc::clone(&inner),
            };
            service.expire_parked_approvals();
        }
    });
}
