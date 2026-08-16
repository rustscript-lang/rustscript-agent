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

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, atomic::AtomicBool, atomic::Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rustscript_vm::{CancellationReason, HttpConfig, InvocationError, Value as VmValue};
use serde_json::{Value as JsonValue, json};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::config::AgentGatewayConfig;
use crate::config::ClientDisconnectPolicy;
use crate::domain::{RunContext, timestamp, truncate_for_log, vm_value_to_json};
use crate::events;
use crate::gateway::store::{
    ChildLinkRecord, GatewayEvent, GatewayPersistence, GatewayStore, IdempotencyRecord, RunRecord,
    SessionMessage, SessionRecord, SessionView, append_message_with_id,
};
use crate::metrics::{AdmitRejectReason, Metrics, TerminalRetryOutcome, TerminalStatus};
use crate::runtime::approval_bridge::{
    ApprovalBridge, NativeDenyPolicy, PendingApproval, Resolution, RiskClass,
};
use crate::runtime::delivery::{
    ChannelEventSink, DeliveryContext, DeliveryOutcome, append_event_locked,
    append_event_locked_with_id, restore_events_after_failed_append, run_delivery_task,
};
use crate::runtime::rss_runner::execute_rss_source;
use crate::runtime::subagent_supervisor::{
    ChildExecutor, ChildOutcome, ChildSpec, SupervisionMode, SupervisorCancel,
    supervise_batch_bounded,
};
use crate::{AgentConfig, AgentRunner, RunCancellation, RunError};

const MAX_DURABLE_ASSISTANT_BYTES: usize = 1_048_576;

// One in-flight approval cancellation per durable approval id. The cell
// deduplicates stop/deadline compensation races without issuing duplicate
// storage writes.
type ApprovalCancellation = Arc<OnceCell<Result<(), String>>>;

/// Capacity bound for the pending child-link-terminal retry set. Each pending
/// entry is a child link whose durable terminal advance is being retried by
/// the lifecycle-managed janitor; a full set defers to restart recovery
/// (which reconciles `pending`/`active` links from the child's real terminal)
/// so the map can never grow without bound.
const MAX_PENDING_LINK_TERMINALS: usize = 4096;

/// One run whose terminal state could not be committed durably. The worker
/// has already exited; the original terminal gets a bounded retry window,
/// then converts to a typed terminal-expiry marker that remains recoverable
/// until durable storage accepts it. Live delivery waits for that commit;
/// the admission permit is released immediately, so outages cannot exhaust
/// capacity.
#[derive(Clone)]
pub struct PendingTerminal {
    pub(crate) to_status: String,
    pub(crate) session_id: Option<String>,
    pub(crate) events: Vec<GatewayEvent>,
    pub(crate) assistant_message: Option<SessionMessage>,
    pub(crate) deadline: std::time::Instant,
    pub(crate) expired_fallback: bool,
    pub(crate) kind: PendingTerminalKind,
}

/// What one pending terminal commits durably. The A5 admitted-run terminal
/// commits through the `run.terminal` transaction (from `running`); a
/// maintenance run's terminal commits through `run.transition` +
/// `event.append` + best-effort `compaction.fail`, because the A2
/// maintenance lifecycle is `queued -> running -> compacting -> terminal`
/// and `run.terminal` only accepts `running` runs.
#[derive(Clone)]
pub(crate) enum PendingTerminalKind {
    /// An admitted run's terminal: `run.terminal` with the prebuilt events
    /// and optional assistant message.
    RunTerminal,
    /// A maintenance run's terminal (manual session compaction): the
    /// durable-first compensation writes that had not landed when the run
    /// was parked.
    Maintenance {
        /// The durable status at park time (the `run.transition`
        /// from-status; no other actor mutates the maintenance run, so it
        /// cannot drift between attempts).
        from_status: String,
        error_code: String,
        error_message: String,
        /// The pending `compaction.fail` payload, cleared once it landed
        /// (best-effort by the A2 contract).
        fail_payload: Option<JsonValue>,
        /// The terminal transition already landed (a previous attempt
        /// committed it before the event append failed).
        transition_landed: bool,
        /// The `compact.completed` event already landed (exact-once).
        event_landed: bool,
    },
}

/// One maintenance run's durable terminal writes (the A2 maintenance
/// lifecycle: `run.transition` to the terminal status, the exact-once
/// `compact.completed` event, and the best-effort `compaction.fail`).
#[derive(Clone)]
pub(crate) struct MaintenanceTerminalWrites {
    pub(crate) run_id: String,
    /// The durable status the terminal transition starts from (no other
    /// actor mutates the maintenance run, so it cannot drift).
    pub(crate) from_status: String,
    /// `failed` or `completed`.
    pub(crate) to_status: String,
    pub(crate) error_code: String,
    pub(crate) error_message: String,
    /// The `compact.completed` event to append durably (exact-once).
    pub(crate) completed_event: Option<GatewayEvent>,
    /// The best-effort `compaction.fail` payload (pending row only).
    pub(crate) fail_payload: Option<JsonValue>,
    /// The terminal transition already landed durably.
    pub(crate) transition_landed: bool,
    /// The `compact.completed` event already landed durably.
    pub(crate) event_landed: bool,
}

impl MaintenanceTerminalWrites {
    /// One terminal write set; nothing has landed yet.
    fn new(
        run_id: String,
        from_status: String,
        to_status: String,
        error_code: String,
        error_message: String,
        completed_event: Option<GatewayEvent>,
        fail_payload: Option<JsonValue>,
    ) -> Self {
        Self {
            run_id,
            from_status,
            to_status,
            error_code,
            error_message,
            completed_event,
            fail_payload,
            transition_landed: false,
            event_landed: false,
        }
    }

    /// True when every required write has landed.
    fn done(&self) -> bool {
        self.transition_landed && (self.event_landed || self.completed_event.is_none())
    }
}

/// Outcome of one bounded durable terminal attempt for a maintenance run.
pub(crate) enum MaintenanceTerminalOutcome {
    /// Every terminal write landed durably.
    Committed,
    /// Storage is still down after the bounded retries: the caller mirrors
    /// the run observably `terminal_pending` and parks this pending
    /// terminal for the bounded retry loop.
    Parked(Box<PendingTerminal>),
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

/// One canonical pre-appended session message drafted by a transport (the
/// OpenAI route's normalized conversation history). The admission persists
/// these messages in the SAME transaction as the session and the run, so a
/// failed admission leaves no partial session and a replayed idempotency
/// key never creates a new one.
#[derive(Clone, Debug)]
pub struct SessionMessageDraft {
    pub role: String,
    /// The canonical content-part array (`text`/`tool_call`/`tool_result`).
    pub content: JsonValue,
    /// The message-level pair id (tool messages only).
    pub tool_call_id: String,
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
    /// The durable per-run origin actor (for example `telegram:<user_id>`
    /// for the Telegram adapter). Persisted onto the run's storage row at
    /// `None`/empty for transports that do not carry an origin
    /// (API-server admissions). Telegram `/approve`/`deny` resolution is
    /// gated on this durable actor, so the binding survives restarts and is
    /// never an in-memory-only map.
    pub origin_actor: Option<String>,
    /// The typed per-request overrides rendered into the canonical run
    /// context `request` map (OpenAI route: `tools`, `tool_choice`,
    /// `sampling`, `max_output_tokens`, `stream`, `metadata`). The loop
    /// reads exactly these typed fields; provider credentials/base_url are
    /// NEVER part of this map (they stay gateway-config-owned). In-memory
    /// only: an interrupted run is failed by restart recovery, so the
    /// overrides never need to survive a restart.
    pub request_overrides: JsonValue,
    /// The transport's canonical pre-appended conversation history
    /// (OpenAI route). Persisted durably inside the admission transaction
    /// and mirrored in memory after the commit; empty for transports that
    /// append their own messages.
    pub session_messages: Vec<SessionMessageDraft>,
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
    /// A child admission was rejected because the parent run is terminal or
    /// stopping: no child/link/event is ever inserted under a finished parent.
    ParentNotActive,
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
            Self::ParentNotActive => {
                formatter.write_str("parent run is terminal or stopping; no child can be admitted")
            }
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
    /// The A6 native-supervisor policy programs: `parallel.rss` and
    /// `subagents.rss` are the VERIFIED-plan sources. The native supervisor
    /// runs them with the real parent/child context and executes exactly
    /// what they plan — it never implements agent policy itself.
    policies: Option<Arc<AgentPolicies>>,
    /// approval bridge over the A2 storage program; `None` in
    /// in-memory-only mode (approval.wait then fails the run typed).
    approval: Option<Arc<ApprovalBridge>>,
    /// The precompiled manual-compaction policy (`rss/agent/compact.rss`).
    /// The service never re-implements the pair-preserving prefix in Rust:
    /// it renders the canonical history, invokes this exported `run`
    /// callable, and executes the returned typed A2 command sequence
    /// through the storage worker. `None` when no durable storage is
    /// configured (manual compaction then answers a typed error).
    compact: Option<Arc<AgentRunner>>,
    /// Sessions with a manual compaction in flight (the in-process race
    /// guard; the durable pending-row contract is the cross-process guard).
    compacting_sessions: Mutex<HashSet<String>>,
    /// Native deny policy is independent from durable approval persistence;
    /// the same policy therefore applies in in-memory-only mode.
    native_deny: NativeDenyPolicy,
    /// Runs parked on a durable pending approval: run_id -> the approval id
    /// and the loop state needed to resume exactly once.
    parked: Mutex<HashMap<String, ParkedRun>>,
    http_config: HttpConfig,
    capacity: Arc<Semaphore>,
    runs: Mutex<HashMap<String, Arc<RunHandle>>>,
    pending: Mutex<HashMap<String, PendingTerminal>>,
    halting: AtomicBool,
    /// The live pre-admission compensation watchers, deduplicated by their
    /// deterministic admission idempotency key: at most ONE watcher per key,
    /// so a re-dropped slot never spawns a second watcher. The count is
    /// bounded by the admission/concurrency upper bound — every waiting
    /// watcher corresponds to a dropped admission that still holds a
    /// capacity permit, and in-flight admissions are capped by
    /// `max_concurrent_runs`.
    compensation_watchers: Mutex<HashSet<String>>,
    /// Bounded set of child links whose DURABLE terminal advance could not be
    /// persisted within the inline retry budget of
    /// `update_child_link_state_native`. A lifecycle-managed janitor
    /// (`link_terminal_retry_loop`, at most ONE live task) retries each entry —
    /// deriving the terminal from the child's real observed durable state and
    /// writing DURABLY before the mirror — until storage recovers, so a
    /// terminal link never stays permanently non-terminal in the current
    /// process. Keyed by `(parent_run_id, child_run_id)` (deduplicated) and
    /// capped at [`MAX_PENDING_LINK_TERMINALS`]; an entry whose parent reaches
    /// a real terminal is dropped (restart recovery reconciles it on the next
    /// open, since the durable `run.link_state` write cannot succeed under a
    /// terminal parent).
    pending_link_terminal: Mutex<HashMap<(String, String), ()>>,
    /// True while a link-terminal retry janitor task is running (or about to
    /// exit). Guarded by the `swap` below so at most one janitor exists.
    link_retry_running: AtomicBool,
    /// One shared async cell per approval id. Every stop/deadline/park
    /// compensation path awaits the same cell, so a single approval.request
    /// success has exactly one approval.cancel invocation even when all race
    /// branches fire concurrently.
    approval_cancellations: Mutex<HashMap<String, ApprovalCancellation>>,
    metrics: Arc<Metrics>,
}

/// The A6 native-supervisor policy programs (compiled once with the
/// gateway's capability policy, exactly like the production loop program).
/// Both are pure DECISION policies: they never execute a child and never
/// fabricate a lifecycle artifact; the native supervisor consumes their
/// typed plans (`parallel.plan` / `subagent.admit` / `subagent.cancel` /
/// `parallel.rejected` / `subagent.rejected`) and drives the real child
/// runs.
struct AgentPolicies {
    parallel: AgentRunner,
    subagent: AgentRunner,
}

/// One A6 handoff execution result: the typed outcome to backfill into the
/// loop state, a cancellation that landed during execution (typed terminal
/// wins), or a typed supervisor unavailability.
enum HandoffExec {
    Outcome(JsonValue),
    Cancelled,
    Unavailable(String),
}

/// The REAL child executor bound to [`AgentService`]: one supervised slot is
/// one genuine child run admitted with `parent_run_id` (isolated session,
/// capacity permit, tokio worker ACTUALLY spawned), durably linked, awaited
/// to its durable terminal, and reported as a typed outcome.
/// `subagent.started` is emitted only AFTER the admission + worker spawn;
/// `subagent.completed` only AFTER the durable terminal. A refused
/// admission or a failed link is a typed failure and never emits started.
/// This is the single executor the native supervisor engine drives — no
/// second executor exists.
#[derive(Clone)]
struct ServiceChildExecutor {
    service: AgentService,
    parent_run_id: String,
    relation: String,
    /// slot -> real admitted child run id (filled after a real admission).
    admitted: Arc<Mutex<HashMap<usize, String>>>,
    /// slot -> real admitted child session id.
    sessions: Arc<Mutex<HashMap<usize, String>>>,
}

impl ServiceChildExecutor {
    fn new(service: AgentService, parent_run_id: &str, relation: &str) -> Self {
        Self {
            service,
            parent_run_id: parent_run_id.to_string(),
            relation: relation.to_string(),
            admitted: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn admitted_slot_ids(&self) -> HashMap<usize, String> {
        self.admitted.lock().expect("admitted lock").clone()
    }

    fn admitted_sessions(&self) -> HashMap<usize, String> {
        self.sessions.lock().expect("sessions lock").clone()
    }

    /// The parent's current session model/provider (the child inherits the
    /// parent's model and provider).
    fn parent_model_provider(&self) -> (String, Option<String>) {
        let store = self.service.inner.store.read();
        let Some(run) = store.runs.get(&self.parent_run_id) else {
            return (String::new(), None);
        };
        let model = store
            .sessions
            .get(&run.session_id)
            .map(|session| session.view.model.clone())
            .unwrap_or_default();
        let provider = store
            .sessions
            .get(&run.session_id)
            .and_then(|session| session.view.provider.clone());
        (model, provider)
    }

    /// Awaits the child's durable terminal: polls the in-memory run record
    /// (the durable commit precedes the in-memory terminal), observes the
    /// shared supervision cancel (propagating it to the child's
    /// `RunCancellation`), and reports a typed outcome — never a fabricated
    /// success.
    async fn await_child_terminal(
        &self,
        service: &AgentService,
        child_run_id: &str,
        cancel: &SupervisorCancel,
    ) -> ChildOutcome {
        loop {
            if cancel.is_requested()
                && let Some(handle) = service.handle(child_run_id)
            {
                // Propagate the REAL cancellation reason (deadline vs parent
                // stop) to the child so its terminal is typed accurately.
                // The deadline-bounded batch requests the shared cancel with
                // reason "deadline"; the parent-stop watcher uses
                // "parent_cancelled"/the parent's typed reason.
                let reason = if cancel.reason() == "deadline" {
                    CancellationReason::Deadline
                } else {
                    CancellationReason::Requested
                };
                handle.cancel.request(reason);
            }
            let terminal = {
                let store = service.inner.store.read();
                store.runs.get(child_run_id).map(|run| run.status.clone())
            };
            match terminal.as_deref() {
                Some("completed") => {
                    return ChildOutcome::Completed(JsonValue::String(child_output_text(
                        service,
                        child_run_id,
                    )));
                }
                Some("cancelled") => {
                    return ChildOutcome::Cancelled(child_terminal_reason(
                        service,
                        child_run_id,
                        "cancelled",
                    ));
                }
                Some("failed") => {
                    return ChildOutcome::Failed(child_terminal_reason(
                        service,
                        child_run_id,
                        "failed",
                    ));
                }
                Some("terminal_pending") => {
                    // A parent stop cannot turn this intermediate state into a
                    // cancelled child. Keep waiting for durable terminal state;
                    // the retry janitor terminates it canonically as `failed`
                    // (typed `error_code=terminal_retry_expired`) if the
                    // bounded window is exhausted.
                }
                Some(_) | None => {}
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl ChildExecutor for ServiceChildExecutor {
    fn execute_child(
        &self,
        child: &ChildSpec,
        cancel: &SupervisorCancel,
    ) -> Pin<Box<dyn Future<Output = ChildOutcome> + Send + '_>> {
        let executor = self.clone();
        let child_spec = child.clone();
        let cancel_for_child = cancel.clone();
        Box::pin(async move {
            if cancel_for_child.is_requested() {
                return ChildOutcome::Cancelled(cancel_for_child.reason());
            }
            let service = executor.service.clone();
            let parent_run_id = executor.parent_run_id.clone();
            let (parent_model, parent_provider) = executor.parent_model_provider();
            let model = parent_model;
            let input = child_spec.input.clone();
            // The child admission carries a DETERMINISTIC idempotency key:
            // the same slot always maps to the same key, so an admission
            // whose future was dropped mid-flight (the grace-drop window)
            // can be located and durably compensated.
            let idempotency_key = format!(
                "child:{parent_run_id}:{}:{}",
                executor.relation, child_spec.slot
            );
            let idempotency_hash = fnv1a64(&format!(
                "{idempotency_key}:{}:{model}",
                serde_json::to_string(&input).unwrap_or_default()
            ));
            let request = AdmitRunRequest {
                input,
                session_id: None,
                model: Some(model),
                provider: parent_provider,
                parent_run_id: Some(parent_run_id.clone()),
                instructions: None,
                platform: "agent:child".to_string(),
                idempotency_key: Some(idempotency_key.clone()),
                idempotency_hash: Some(idempotency_hash),
                origin_actor: None,
                request_overrides: JsonValue::Object(Default::default()),
                session_messages: Vec::new(),
            };
            // The pre-admit re-check: a stop that landed while this slot
            // was queued (or during the policy VM) prevents the admission
            // entirely — no child work starts after a stop.
            if cancel_for_child.is_requested() || service.run_is_stopping(&parent_run_id) {
                return ChildOutcome::Cancelled(cancel_for_child.reason());
            }
            // The PRE-admission RAII guard is created BEFORE the admission
            // await: a drop while the admission is still in flight (the
            // grace-drop window) is compensated deterministically — the
            // guard's bounded watcher polls the deterministic admission key
            // and, the moment the detached admission completes, immediately
            // cancels the child, commits its durable terminal, and releases
            // the permit/handle/link. After the admission returns, the
            // guard is updated with the real run id.
            let mut guard = AdmittedChildGuard {
                service: service.clone(),
                parent_run_id: parent_run_id.clone(),
                child_run_id: String::new(),
                idempotency_key: idempotency_key.clone(),
                resolved: false,
                disarmed: false,
            };
            let admitted = match service.admit(request).await {
                Ok(admitted) => admitted,
                Err(error) => {
                    // A refused admission never starts and never emits
                    // subagent.started: typed failure in the slot. Nothing
                    // was admitted, so no compensation is needed.
                    guard.disarmed = true;
                    return ChildOutcome::Failed(format!(
                        "admission_refused:{}",
                        describe_admit_error(&error)
                    ));
                }
            };
            guard.resolved = true;
            guard.child_run_id = admitted.run_id.clone();
            let child_run_id = admitted.run_id.clone();
            let child_session_id = admitted.session_id.clone();
            executor
                .admitted
                .lock()
                .expect("admitted lock")
                .insert(child_spec.slot, child_run_id.clone());
            executor
                .sessions
                .lock()
                .expect("sessions lock")
                .insert(child_spec.slot, child_session_id.clone());
            // A REPLAYED admission (the deterministic slot key already
            // admitted — for example a re-executed handoff): the child's
            // lifecycle was already produced by the ORIGINAL admission.
            // NEVER spawn a second worker (a terminal child would be
            // re-driven), never re-emit subagent.started/completed, never
            // re-link. Await the EXISTING run's terminal — an active replay
            // awaits the original worker, a terminal replay returns its
            // durable terminal immediately — and advance the link state to
            // the observed outcome (never a regression to active).
            if admitted.replayed {
                let outcome = executor
                    .await_child_terminal(&service, &child_run_id, &cancel_for_child)
                    .await;
                service
                    .update_child_link_state_native(
                        &parent_run_id,
                        &child_run_id,
                        child_outcome_status(&outcome),
                    )
                    .await;
                guard.disarmed = true;
                return outcome;
            }
            // The worker receives the exact structured admission input. The
            // canonical context parser below restores object/array shape
            // instead of collapsing it to an empty or string-only value.
            let worker_input =
                serde_json::to_string(&child_spec.input).unwrap_or_else(|_| "null".to_string());
            tokio::task::spawn(
                Arc::new(service.clone()).run_worker(child_run_id.clone(), worker_input),
            );
            // Durable parent link (the A2 `run.link_child` contract) with
            // the in-memory mirror; a failed link fails the slot typed and
            // cancels the child (never a claim that the link exists).
            let link_ok = {
                let service = service.clone();
                let parent = parent_run_id.clone();
                let child_id = child_run_id.clone();
                let relation = executor.relation.clone();
                tokio::task::spawn_blocking(move || {
                    service.link_child_native(&parent, &child_id, child_spec.slot as i64, &relation)
                })
                .await
                .unwrap_or(false)
            };
            if !link_ok {
                if let Some(handle) = service.handle(&child_run_id) {
                    handle.cancel.request(CancellationReason::Requested);
                }
                return ChildOutcome::Failed(
                    "link_failed: the child could not be linked durably".to_string(),
                );
            }
            // The pre-started re-check: a stop that landed during the
            // admission/link window must never produce a `subagent.started`
            // after the stop — the child is cancelled instead.
            if service.run_is_stopping(&parent_run_id) {
                if let Some(handle) = service.handle(&child_run_id) {
                    handle.cancel.request(CancellationReason::Requested);
                }
                return ChildOutcome::Cancelled(cancel_for_child.reason());
            }
            match service
                .emit_native_event(
                    &parent_run_id,
                    "subagent.started",
                    json!({
                        "child_run_id": child_run_id,
                        "parent_run_id": parent_run_id,
                        "session_id": child_session_id,
                        "ordinal": child_spec.slot,
                        "relation": executor.relation,
                        "turn": 0,
                    }),
                )
                .await
            {
                NativeEventEmit::Emitted => {}
                NativeEventEmit::ParentTerminal => {
                    // The parent went terminal while the child was being
                    // linked: no post-terminal side effects; the child is
                    // cancelled.
                    if let Some(handle) = service.handle(&child_run_id) {
                        handle.cancel.request(CancellationReason::Requested);
                    }
                    return ChildOutcome::Cancelled(cancel_for_child.reason());
                }
                NativeEventEmit::AppendFailed => {
                    // The durable append of `subagent.started` failed (a
                    // storage fault): fail closed with the TYPED reason —
                    // never a fabricated started event and never a
                    // mislabeled parent cancellation.
                    if let Some(handle) = service.handle(&child_run_id) {
                        handle.cancel.request(CancellationReason::Requested);
                    }
                    return ChildOutcome::Cancelled("event_append_failed".to_string());
                }
            }
            let outcome = executor
                .await_child_terminal(&service, &child_run_id, &cancel_for_child)
                .await;
            // The link state advances to the child's observed terminal —
            // durably (the storage `run.link_state` command) AND in the
            // in-memory mirror.
            service
                .update_child_link_state_native(
                    &parent_run_id,
                    &child_run_id,
                    child_outcome_status(&outcome),
                )
                .await;
            // The canonical `subagent.completed` event is appended durably
            // (bounded retry inside emit_native_event) BEFORE the child's
            // outcome is returned: a failed append is promoted to a TYPED
            // parent failure — the child's outcome (and its output text)
            // must never reach the parent's history before (or without) the
            // durable event.
            match service
                .emit_native_event(
                    &parent_run_id,
                    "subagent.completed",
                    json!({
                        "child_run_id": child_run_id,
                        "parent_run_id": parent_run_id,
                        "status": child_outcome_status(&outcome),
                        "turn": 0,
                    }),
                )
                .await
            {
                NativeEventEmit::Emitted => {}
                NativeEventEmit::ParentTerminal => {
                    // The parent went terminal while the child reached its
                    // durable terminal: no post-terminal side effects — the
                    // event is intentionally not appended, and nothing folds
                    // the outcome once the parent is terminal.
                }
                NativeEventEmit::AppendFailed => {
                    guard.disarmed = true;
                    return ChildOutcome::Failed(
                        "completed_event_append_failed: the durable \
                         subagent.completed event could not be appended \
                         after bounded retries"
                            .to_string(),
                    );
                }
            }
            guard.disarmed = true;
            outcome
        })
    }

    /// The slot's child's REAL durable terminal (when it has reached one),
    /// folded to a typed outcome — used by the `supervise_batch_bounded`
    /// grace-drop fallback so a child that already durably completed (
    /// including one whose `subagent.completed` event was appended but whose
    /// outcome had not yet been folded into the shared buffer) is reported as
    /// its real terminal, never as a spurious cancellation. `None` while the
    /// child is not (yet) durably terminal.
    fn observed_terminal_outcome(&self, slot: usize) -> Option<ChildOutcome> {
        let child_run_id = self
            .admitted
            .lock()
            .expect("admitted lock")
            .get(&slot)
            .cloned()?;
        // NON-BLOCKING status read: this helper runs on the grace-drop
        // fallback inside `supervise_batch_bounded`, on a tokio worker thread.
        // parking_lot's `read()` parks behind a queued writer, which would
        // stall the batch drop and delay compensation watchers. `try_read()`
        // returns immediately on write contention; if we cannot read the
        // child's status now, the in-flight child is compensated by its RAII
        // guard and we fall back to the typed cancel reason.
        let status = self
            .service
            .inner
            .store
            .try_read()?
            .runs
            .get(&child_run_id)?
            .status
            .clone();
        match status.as_str() {
            "completed" => Some(ChildOutcome::Completed(JsonValue::String(
                child_output_text(&self.service, &child_run_id),
            ))),
            "cancelled" => Some(ChildOutcome::Cancelled(child_terminal_reason(
                &self.service,
                &child_run_id,
                "cancelled",
            ))),
            "failed" => Some(ChildOutcome::Failed(child_terminal_reason(
                &self.service,
                &child_run_id,
                "failed",
            ))),
            _ => None,
        }
    }
}

/// RAII compensation for one child slot. The guard is created BEFORE the
/// admission await and updated after it returns. If the slot future is
/// dropped between the guard creation and the outcome (the
/// `supervise_batch_bounded` grace-drop window), the child run would
/// otherwise be orphaned: a drop DURING the admission leaves a permit held
/// and a run nobody ever drives once the detached admission completes; a
/// drop while awaiting the terminal leaves nobody to propagate the
/// cancellation. Drop therefore starts a compensation watcher whose
/// lifecycle is bounded ONLY by service shutdown (it has no wall-clock
/// give-up — see [`AdmittedChildGuard`] drop): for the in-flight-admission
/// window it polls the deterministic admission key and, the moment the
/// detached run appears, immediately cancels it, durably terminates it
/// (`finish_cancelled` is idempotent against the worker's own terminal),
/// and advances the link state — the permit and handle are always released.
/// The watcher count is bounded by the admission/concurrency upper bound
/// (one deduplicated watcher per deterministic key; every waiting watcher
/// corresponds to an in-flight admission that still holds a capacity
/// permit).
struct AdmittedChildGuard {
    service: AgentService,
    parent_run_id: String,
    /// The real admitted run id once the admission returned; empty while
    /// the admission is still in flight (the drop-during-admission window).
    child_run_id: String,
    /// The deterministic admission idempotency key (locating the run if the
    /// drop happened while the admission was still in flight).
    idempotency_key: String,
    /// True once the admission returned (the real run id is known).
    resolved: bool,
    /// True on the normal path right before the outcome is returned.
    disarmed: bool,
}

impl Drop for AdmittedChildGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let service = self.service.clone();
        let parent_run_id = self.parent_run_id.clone();
        let child_run_id = self.child_run_id.clone();
        let idempotency_key = self.idempotency_key.clone();
        if let Some(handle) = service.handle(&child_run_id) {
            handle.cancel.request(CancellationReason::Requested);
        }
        let resolved = self.resolved;
        // At most ONE watcher per deterministic admission key (the key is
        // `child:{parent}:{relation}:{slot}`): a re-dropped slot — a
        // re-executed handoff of the same plan — registers the same key and
        // is a no-op. The number of live watchers is therefore bounded by
        // the number of in-flight admissions: every waiting watcher
        // corresponds to a dropped admission whose `spawn_blocking` still
        // HOLDS its capacity permit, and in-flight admissions are capped by
        // `max_concurrent_runs` (the admission/concurrency upper bound).
        let mut watchers = service
            .inner
            .compensation_watchers
            .lock()
            .expect("compensation watchers lock");
        if !watchers.insert(idempotency_key.clone()) {
            return;
        }
        drop(watchers);
        // Compensation runs on the shared runtime (Drop cannot await). The
        // watcher has NO wall-clock give-up: it polls until the detached
        // admission's run appears (then compensates it durably) or the
        // service shuts down (the SIGINT path) — the ONLY termination
        // besides process death. An admission that never completed has no
        // durable row (the admission commit is transactional), so restart
        // recovery has nothing to repair; a row that lands in the shutdown
        // race window is durably failed by the restart-recovery orphan
        // sweep, exactly like any other terminal persist left for restart.
        tokio::spawn(async move {
            // The registration is removed on EVERY exit path of the watcher.
            let _registration = WatcherRegistration {
                service: service.clone(),
                key: idempotency_key.clone(),
            };
            let mut found: Option<String> = if resolved {
                Some(child_run_id.clone())
            } else {
                None
            };
            if found.is_none() {
                // A drop DURING the admission (the grace-drop window): the
                // spawn_blocking admission may still complete AFTER this
                // future is gone. Poll the deterministic key until the run
                // appears; the moment it does, immediately cancel it, commit
                // the durable terminal, and release the permit/handle/link.
                // The lookup is NON-BLOCKING (try_read): a stalled admission
                // that holds (or waits for) the store write lock must never
                // park this watcher behind it — the watcher always reaches
                // the shutdown check between polls.
                loop {
                    if let Some(Some(found_id)) =
                        service.try_find_run_by_idempotency(&idempotency_key)
                    {
                        found = Some(found_id);
                        break;
                    }
                    if service.inner.halting.load(Ordering::Acquire) {
                        // Service shutdown: one final lookup (the admission
                        // may have completed while this poll was in flight)
                        // — an admission found here is still compensated —
                        // then the watcher ends with the process.
                        if let Some(Some(found_id)) =
                            service.try_find_run_by_idempotency(&idempotency_key)
                        {
                            found = Some(found_id);
                        }
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            let Some(found_id) = found else {
                // The admission never completed: nothing was durably created
                // (the transactional admission never committed), so there is
                // nothing to compensate and restart recovery has nothing to
                // repair. The in-flight admission dies with the process.
                return;
            };
            if let Some(handle) = service.handle(&found_id) {
                handle.cancel.request(CancellationReason::Requested);
            }
            // Durable terminal first: the child really reaches a terminal
            // (the worker — when spawned — observes the cancellation; the
            // commit is idempotent against the worker's own terminal) and
            // the permit/handle are released by mark_terminal.
            service
                .finish_cancelled(&found_id, "supervisor_abandoned")
                .await;
            // The link advances to the child's OBSERVED terminal (never a
            // terminal->terminal regression when the compensation races a
            // child that really completed). NEVER write the terminal link
            // before the child reaches a real durable terminal: if the child
            // is still observably `terminal_pending` (its durable terminal
            // commit is pending recovery), keep waiting/retrying instead of
            // claiming a terminal the durable side may not carry yet.
            loop {
                match observed_link_state(&service, &found_id) {
                    Some(state) => {
                        service
                            .update_child_link_state_native(&parent_run_id, &found_id, &state)
                            .await;
                        break;
                    }
                    None => {
                        if service.inner.halting.load(Ordering::Acquire) {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }
}

/// Removes one compensation-watcher registration when its watcher task
/// exits (found-and-compensated, or service shutdown) — the registry can
/// never leak an entry for a watcher that is no longer running.
struct WatcherRegistration {
    service: AgentService,
    key: String,
}

impl Drop for WatcherRegistration {
    fn drop(&mut self) {
        self.service
            .inner
            .compensation_watchers
            .lock()
            .expect("compensation watchers lock")
            .remove(&self.key);
    }
}

/// The child's durable terminal status for a link-state advance: its real
/// durable status when it has reached a REAL terminal
/// (`completed`/`failed`/`cancelled`), or `None` while the child is still
/// durable-active/pending (including `terminal_pending`, whose durable
/// terminal commit is pending recovery — a link must NEVER advance to a
/// terminal the durable side does not yet carry). This lets the compensation
/// watcher wait for a real durable terminal instead of writing a premature
/// terminal link.
fn observed_link_state(service: &AgentService, child_run_id: &str) -> Option<String> {
    let status = service
        .inner
        .store
        .read()
        .runs
        .get(child_run_id)
        .map(|run| run.status.clone())
        .unwrap_or_default();
    match status.as_str() {
        "completed" | "failed" | "cancelled" => Some(status),
        _ => None,
    }
}

/// Deterministic FNV-1a 64-bit hash used to derive the child admission
/// idempotency hash: the same slot/input/model always produces the same
/// hash, so an abandoned admission can be located and compensated.
fn fnv1a64(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn canonical_input_value(input: &str) -> JsonValue {
    serde_json::from_str(input).unwrap_or_else(|_| JsonValue::String(input.to_string()))
}

/// Stable identifiers for result slots that were never admitted. These are
/// intentionally derived only from the parent, relation, and ordinal so
/// race/fail-fast continuation can still carry a non-empty correlation id.
fn stable_slot_id(parent_run_id: &str, relation: &str, slot: usize) -> String {
    format!("slot:{}:{}:{}", fnv1a64(parent_run_id), relation, slot)
}

fn stable_tool_call_id(parent_run_id: &str, relation: &str, slot: usize) -> String {
    format!("toolcall:{}:{}:{}", fnv1a64(parent_run_id), relation, slot)
}

fn is_terminal_status(status: &str) -> bool {
    matches!(
        status,
        "completed" | "failed" | "cancelled" | "terminal_pending"
    )
}

/// The REAL child terminal statuses that validly advance a child link's state.
/// Unlike the run-terminal `is_terminal_status`, this excludes `terminal_pending`
/// — a child still pending its durable terminal commit must NEVER be written
/// as a terminal link.
fn is_terminal_link_status(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

/// The typed status string of one child outcome.
fn child_outcome_status(outcome: &ChildOutcome) -> &'static str {
    match outcome {
        ChildOutcome::Completed(_) => "completed",
        ChildOutcome::Cancelled(_) => "cancelled",
        ChildOutcome::Failed(_) => "failed",
    }
}

/// The child's final assistant text (its terminal output): the last
/// assistant message's text parts in the child's own session.
fn child_output_text(service: &AgentService, child_run_id: &str) -> String {
    let store = service.inner.store.read();
    let Some(run) = store.runs.get(child_run_id) else {
        return String::new();
    };
    let Some(session) = store.sessions.get(&run.session_id) else {
        return String::new();
    };
    session
        .messages
        .iter()
        .rev()
        .find(|message| message.role == "assistant")
        .map(|message| content_text(&message.content))
        .unwrap_or_default()
}

/// The child's typed terminal reason from its terminal event (fallback when
/// no terminal event is retained).
fn child_terminal_reason(service: &AgentService, child_run_id: &str, fallback: &str) -> String {
    let store = service.inner.store.read();
    let Some(run) = store.runs.get(child_run_id) else {
        return fallback.to_string();
    };
    run.events
        .iter()
        .rev()
        .find(|event| event.event == "run.cancelled" || event.event == "run.failed")
        .and_then(|event| {
            event
                .data
                .get("reason")
                .and_then(JsonValue::as_str)
                .or_else(|| event.data.get("error_code").and_then(JsonValue::as_str))
                .map(str::to_string)
        })
        .unwrap_or_else(|| fallback.to_string())
}

/// The text of one canonical content value (a plain string or text parts).
fn content_text(content: &JsonValue) -> String {
    match content {
        JsonValue::String(text) => text.clone(),
        JsonValue::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                if part.get("type").and_then(JsonValue::as_str) == Some("text") {
                    part.get("text")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The typed admission refusal code for the slot outcome.
fn describe_admit_error(error: &AdmitError) -> &'static str {
    match error {
        AdmitError::RunLimitReached => "run_limit_reached",
        AdmitError::IdempotencyConflict => "idempotency_conflict",
        AdmitError::ParentNotFound => "parent_not_found",
        AdmitError::ParentNotActive => "parent_not_active",
        AdmitError::SessionNotFound => "session_not_found",
        AdmitError::Persistence(_) => "persistence_failed",
        AdmitError::Invalid(_) => "invalid_request",
        AdmitError::Halting => "halting",
    }
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

/// Compiles the A6 native-supervisor policy programs (`parallel.rss` /
/// `subagents.rss`) with the gateway's capability policy — the same seam
/// the production loop program uses. Fallible: a deployment without the
/// source tree answers a typed error at construction (handoffs then fail
/// typed), never a panic.
fn compile_agent_policies(
    http_config: &HttpConfig,
    config: &AgentGatewayConfig,
) -> Option<Result<AgentPolicies, String>> {
    let agent_config = AgentConfig {
        http: http_config.clone(),
        sqlite: config.sqlite.clone(),
        io: config.io.clone(),
        fuel: config.fuel,
    };
    let agent_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("rss")
        .join("agent");
    let parallel =
        match AgentRunner::from_file(agent_root.join("parallel.rss"), agent_config.clone()) {
            Ok(runner) => runner,
            Err(error) => {
                return Some(Err(format!(
                    "compile the built-in parallel policy: {error}"
                )));
            }
        };
    let subagent = match AgentRunner::from_file(agent_root.join("subagents.rss"), agent_config) {
        Ok(runner) => runner,
        Err(error) => {
            return Some(Err(format!(
                "compile the built-in subagent policy: {error}"
            )));
        }
    };
    Some(Ok(AgentPolicies { parallel, subagent }))
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

/// Typed outcome of one API approval resolution ([`AgentService::resolve_run_approval_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalResolveOutcome {
    /// The durable row transitioned and the run resumed with the decision
    /// (`approved` for an approve, `denied` for a fresh deny).
    Resumed { approved: bool },
    /// A deny (or the expiry sweep) landed on an already-terminal row: the
    /// run resumes with the typed terminal code (`expired`).
    Terminal { code: String },
}

/// Typed failure of one API approval resolution. The variants map directly
/// to the HTTP error envelope codes (no string matching in the gateway).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalResolveError {
    /// The run exists but is not parked on a pending approval.
    NoPendingApproval,
    /// The run is parked on a DIFFERENT approval id than the caller
    /// addressed (the park is untouched).
    ApprovalIdMismatch,
    /// The durable row is already terminal (a foreign resolve/expire landed
    /// first): strict no-op, the park is restored.
    AlreadyResolved,
    /// The run could not transition back to `running` (a stop or a terminal
    /// raced the resolution).
    RunNotActive,
    /// No durable approval bridge (in-memory-only mode).
    BridgeUnavailable,
    /// No production loop program to resume with.
    ProgramUnavailable,
    /// A durable storage failure (the park is restored, retryable).
    Storage(String),
}

impl ApprovalResolveError {
    /// The legacy `String` message of the original
    /// [`AgentService::resolve_run_approval`] surface (the expiry sweep and
    /// the A5 fixtures depend on these exact texts).
    fn legacy_message(&self) -> String {
        match self {
            Self::NoPendingApproval => "no pending approval is parked for this run".to_string(),
            Self::ApprovalIdMismatch => "approval id mismatch".to_string(),
            Self::AlreadyResolved => "approval already resolved".to_string(),
            Self::RunNotActive => "the run could not transition back to running".to_string(),
            Self::BridgeUnavailable => "the durable approval bridge is not available".to_string(),
            Self::ProgramUnavailable => "the production loop program is not available".to_string(),
            Self::Storage(message) => message.clone(),
        }
    }
}

impl std::fmt::Display for ApprovalResolveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.legacy_message())
    }
}

/// Typed outcome of one manual session compaction
/// ([`AgentService::compact_session`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactSessionOutcome {
    /// The RSS-planned compaction committed durably: the real compaction id,
    /// the maintenance run that executed it, the advanced generation, and
    /// the covered range.
    Committed {
        compaction_id: String,
        run_id: String,
        generation: u64,
        source_start_ordinal: i64,
        source_end_ordinal: i64,
        retained_tail_ordinal: i64,
    },
    /// The RSS policy decided nothing to do (`compact.skip`); no durable
    /// state was created.
    Skipped { reason: String },
    /// The manual compact was refused: an active/waiting/compacting run
    /// owns the session, or another compaction is already in flight.
    Conflict {
        kind: CompactConflict,
        run_id: Option<String>,
        status: Option<String>,
    },
}

/// Why a manual compaction was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactConflict {
    /// A run for the session is durably queued/running/waiting_approval/
    /// compacting: compaction is loop-managed while a run is active.
    ActiveRun,
    /// Another manual compaction is in flight (in-process race guard or the
    /// durable pending-row contract of a concurrent process).
    CompactionInProgress,
}

/// Typed failure of one manual session compaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactSessionError {
    SessionNotFound,
    /// No durable SQLite state is configured (in-memory-only mode).
    NoDurableStorage,
    /// The gateway is halting; no new durable work may start.
    Halting,
    /// The RSS policy could not be compiled or produced an invalid decision.
    Plan(String),
    /// A durable storage failure (the maintenance run was durably failed and
    /// any pending row failed; retry is safe).
    Storage(String),
}

/// Maps a storage worker error onto the typed compaction error.
fn storage_error(error: crate::gateway::store::StorageError) -> CompactSessionError {
    CompactSessionError::Storage(error.to_string())
}

impl std::fmt::Display for CompactSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => formatter.write_str("session not found"),
            Self::NoDurableStorage => formatter.write_str("no durable storage is configured"),
            Self::Halting => formatter.write_str("the gateway is halting"),
            Self::Plan(message) => formatter.write_str(message),
            Self::Storage(message) => formatter.write_str(message),
        }
    }
}

/// The typed outcome of a native lifecycle event emission: the failure
/// modes are DISTINCT — a parent terminal (no post-terminal side effects;
/// the child is cancelled as `parent_cancelled`) vs a failed durable append
/// (storage fault; the child is cancelled with the typed
/// `event_append_failed` reason) vs a successful emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeEventEmit {
    Emitted,
    ParentTerminal,
    AppendFailed,
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
        let mut deny = NativeDenyPolicy::new();
        if config.native_hard_deny {
            deny = deny.hard_deny();
        }
        for tool in &config.native_deny_tools {
            deny = deny.deny_tool(tool.clone());
        }
        for risk in &config.native_deny_risks {
            deny = deny.deny_risk(match risk.as_str() {
                "read" => RiskClass::Read,
                "write" => RiskClass::Write,
                "execute" => RiskClass::Execute,
                _ => RiskClass::Privileged,
            });
        }
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
                // The native deny policy is configurable: tool names and risk
                // classes denied regardless of the RSS approval mode.
                Some(Arc::new(ApprovalBridge::new(
                    storage,
                    persistence.db_file_name().to_string(),
                    deny.clone(),
                )))
            }
            None => None,
        };
        // The manual-compaction policy is compiled with the same capability
        // policy as the storage program (it is a pure decision policy and
        // never touches SQLite, but it must exist wherever durable storage
        // does). A missing or uncompilable policy is a TYPED construction
        // error — the gateway fails to start with a clear message, never a
        // panic and never a silent fallback. The typed
        // `compaction_policy_unavailable` answer is reserved for
        // configurations without durable storage and for runtime policy
        // failures.
        let compact = match persistence.as_ref() {
            Some(persistence) => {
                let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("rss")
                    .join("agent")
                    .join("compact.rss");
                let mut agent_config = AgentConfig {
                    http: http_config.clone(),
                    sqlite: config.sqlite.clone(),
                    io: config.io.clone(),
                    fuel: config.fuel,
                };
                if let Some(parent) = persistence.db_root() {
                    agent_config = agent_config.with_sqlite_root(parent);
                }
                let compact = AgentRunner::from_file(&root, agent_config)
                    .map_err(|error| format!("compile the built-in compact policy: {error}"))?;
                Some(Arc::new(compact))
            }
            None => None,
        };
        let policies = compile_agent_policies(&http_config, config.as_ref())
            .transpose()?
            .map(Arc::new);
        let inner = Arc::new(AgentServiceInner {
            config,
            store,
            persistence,
            agent_source,
            agent_program: agent_program.map(Arc::new),
            policies,
            approval,
            compact,
            compacting_sessions: Mutex::new(HashSet::new()),
            native_deny: deny,
            parked: Mutex::new(HashMap::new()),
            http_config,
            capacity,
            runs: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            halting: AtomicBool::new(false),
            compensation_watchers: Mutex::new(HashSet::new()),
            pending_link_terminal: Mutex::new(HashMap::new()),
            link_retry_running: AtomicBool::new(false),
            approval_cancellations: Mutex::new(HashMap::new()),
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

    /// Number of live pre-admission compensation watchers. Deduplicated per
    /// deterministic admission key and bounded by the admission/concurrency
    /// upper bound (each waiting watcher corresponds to a dropped admission
    /// that still holds a capacity permit). Observable for the durability
    /// suites.
    pub fn compensation_watcher_count(&self) -> usize {
        self.inner
            .compensation_watchers
            .lock()
            .expect("compensation watchers lock")
            .len()
    }

    /// The persistence handle for typed repository commands; `None` when no
    /// SQLite path is configured (in-memory only mode).
    pub(crate) fn persistence_handle(&self) -> Option<Arc<GatewayPersistence>> {
        self.inner.persistence.clone()
    }

    // -----------------------------------------------------------------------
    // Manual session compaction (single composition; RSS-owned policy)
    // -----------------------------------------------------------------------

    /// Compacts one session on demand. The pair-preserving prefix comes from
    /// the RSS policy (`rss/agent/compact.rss`); native code only orchestrates
    /// generic storage commands. With no active run the service creates a
    /// bounded auditable maintenance run and executes
    /// `compaction.start → message.compact → compaction.commit` (or the typed
    /// failure path) with generation advance and exact-once events/terminal;
    /// with an active/waiting/compacting run it answers a typed conflict
    /// (never a concurrent double compact). Idempotent retry and restart
    /// recovery are safe by the unchanged A2 storage contract.
    pub async fn compact_session(
        &self,
        session_id: &str,
        actor: &str,
    ) -> Result<CompactSessionOutcome, CompactSessionError> {
        if self.inner.halting.load(Ordering::Acquire) {
            return Err(CompactSessionError::Halting);
        }
        {
            let store = self.inner.store.read();
            if !store.sessions.contains_key(session_id) {
                return Err(CompactSessionError::SessionNotFound);
            }
        }
        // In-process race guard: one manual compaction per session at a
        // time. The durable pending-row contract is the cross-process guard.
        {
            let mut compacting = self
                .inner
                .compacting_sessions
                .lock()
                .expect("compacting sessions lock");
            if !compacting.insert(session_id.to_string()) {
                return Ok(CompactSessionOutcome::Conflict {
                    kind: CompactConflict::CompactionInProgress,
                    run_id: None,
                    status: None,
                });
            }
        }
        let service = self.clone();
        let session_id = session_id.to_string();
        let actor = actor.to_string();
        let guard_key = session_id.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            service.compact_session_blocking(&session_id, &actor)
        })
        .await
        .unwrap_or_else(|error| {
            Err(CompactSessionError::Storage(format!(
                "compaction worker failed: {error}"
            )))
        });
        self.inner
            .compacting_sessions
            .lock()
            .expect("compacting sessions lock")
            .remove(&guard_key);
        outcome
    }

    /// The blocking composition (storage worker round-trips never occupy
    /// Tokio threads). See [`Self::compact_session`] for the contract.
    fn compact_session_blocking(
        &self,
        session_id: &str,
        actor: &str,
    ) -> Result<CompactSessionOutcome, CompactSessionError> {
        let Some(persistence) = self.inner.persistence.clone() else {
            return Err(CompactSessionError::NoDurableStorage);
        };
        let Some(compact) = self.inner.compact.clone() else {
            return Err(CompactSessionError::Plan(
                "the compact.rss policy is not available".to_string(),
            ));
        };
        // Authoritative durable active-run gate (restart-safe): any
        // non-terminal run for the session refuses the manual compact.
        {
            let data = persistence
                .run_list(session_id, "")
                .map_err(storage_error)?;
            if let Some((run_id, status)) = data
                .get("rows")
                .and_then(JsonValue::as_array)
                .into_iter()
                .flatten()
                .filter_map(JsonValue::as_array)
                .find(|row| {
                    row.get(3)
                        .and_then(JsonValue::as_str)
                        .is_some_and(|status| {
                            matches!(
                                status,
                                "queued" | "running" | "waiting_approval" | "compacting"
                            )
                        })
                })
                .map(|row| {
                    (
                        row.first()
                            .and_then(JsonValue::as_str)
                            .unwrap_or("")
                            .to_string(),
                        row.get(3)
                            .and_then(JsonValue::as_str)
                            .unwrap_or("")
                            .to_string(),
                    )
                })
            {
                return Ok(CompactSessionOutcome::Conflict {
                    kind: CompactConflict::ActiveRun,
                    run_id: Some(run_id),
                    status: Some(status),
                });
            }
        }

        // Canonical history from the mirror (the same shape the production
        // loop plans over: ordinals mirror durable rows, message-level pair
        // ids, canonical content parts).
        let (messages, generation, model) = {
            let store = self.inner.store.read();
            let session = store.sessions.get(session_id);
            let messages = session
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
                                // The message-level pair id mirrors the
                                // durable messages.tool_call_id column, and
                                // content is canonicalized to the parts
                                // array exactly like the production loop
                                // context (string content -> one text part),
                                // so the policy contract holds for any
                                // persisted shape.
                                "tool_call_id": message.tool_call_id,
                                "content": canonical_message_content(&message.content),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let generation = session.map(|session| session.view.generation).unwrap_or(1);
            let model = session
                .map(|session| session.view.model.clone())
                .unwrap_or_else(|| self.inner.config.model.clone());
            (messages, generation, model)
        };

        // The RSS policy decides: skip (typed no-op, no durable writes) or
        // plan (the exact A2 command sequence to execute).
        let maintenance_run_id = format!(
            "compact-run:{session_id}:{}:{}",
            generation + 1,
            &Uuid::new_v4().to_string()[..8]
        );
        let config = &self.inner.config;
        let context = json!({
            "session_id": session_id,
            "run_id": maintenance_run_id,
            "compaction_id": format!("compact:{session_id}:{}", generation + 1),
            "generation": generation,
            "messages": messages,
            "config": {
                "max_context_messages": config.max_context_messages,
                "retained_tail": config.retained_tail,
                "now_ms": timestamp(),
                "model": model,
                "token_estimate": 0,
            },
        });
        let decision = compact
            .run_with_context(json_to_vm_value(&context))
            .map_err(|error| CompactSessionError::Plan(format!("compact.rss failed: {error}")))
            .map(|decision| vm_value_to_json(&decision))?;
        let kind = decision["kind"].as_str().unwrap_or("").to_string();
        if kind == "compact.skip" {
            let reason = decision["reason"]
                .as_str()
                .unwrap_or("history_within_window")
                .to_string();
            return Ok(CompactSessionOutcome::Skipped { reason });
        }
        if kind != "compact.plan" {
            return Err(CompactSessionError::Plan(format!(
                "compact.rss produced an unknown decision kind: {kind}"
            )));
        }
        // The policy's decision is FLAT (the loop wraps it under `plan`
        // only when it yields the `compact` decision; the policy itself
        // returns kind/generation/range/commands at the top level).
        let plan = decision.clone();
        let plan_generation = plan["generation"].as_i64().unwrap_or(0);
        let start_ordinal = plan["source_start_ordinal"].as_i64().unwrap_or(0);
        let end_ordinal = plan["source_end_ordinal"].as_i64().unwrap_or(0);
        let tail_ordinal = plan["retained_tail_ordinal"].as_i64().unwrap_or(0);
        let compaction_id = format!("compact:{session_id}:{plan_generation}");
        let now = timestamp() as i64;
        let max_events = config.max_events_per_run as i64;

        // The bounded auditable maintenance run: created durably, stepped
        // queued -> running -> compacting (the A2 start/commit guards require
        // `compacting`). Any failure durably fails the run — no orphan
        // non-terminal run is ever left behind.
        let audit_input = json!({
            "kind": "session_compaction",
            "actor": actor,
            "session_id": session_id,
            "target_generation": plan_generation,
        });
        persistence
            .run_create(&json!({
                "id": maintenance_run_id,
                "session_id": session_id,
                "parent_run_id": "",
                "input_json": audit_input.to_string(),
                "provider": "",
                "model": model,
                "script_hash": "compact",
                "idempotency_scope": "",
                "idempotency_key": "",
                "now_ms": now,
            }))
            .map_err(storage_error)?;
        for (from, to) in [("queued", "running"), ("running", "compacting")] {
            let matched = persistence
                .run_transition(&json!({
                    "run_id": maintenance_run_id,
                    "from_status": from,
                    "to_status": to,
                    "error_code": "",
                    "error_message": "",
                    "recovery_reason": "",
                    "now_ms": now,
                }))
                .map(|value| run_transition_matched(&value))
                .unwrap_or(false);
            if !matched {
                // Durable-first compensation: the maintenance run can never
                // reach compacting — fail it durably with bounded retries,
                // and if storage is still down park it observably
                // `terminal_pending` for the bounded retry loop (never a
                // silent `let _ =` that strands the run durably
                // queued/running without an owned retry).
                let message = format!("the maintenance run could not transition {from} -> {to}");
                let writes = MaintenanceTerminalWrites::new(
                    maintenance_run_id.clone(),
                    from.to_string(),
                    "failed".to_string(),
                    "maintenance_run_failed".to_string(),
                    message.clone(),
                    None,
                    None,
                );
                let outcome = self.commit_maintenance_terminal(&persistence, writes.clone());
                self.mirror_maintenance_terminal(session_id, &writes, outcome, None);
                return Err(CompactSessionError::Storage(message));
            }
        }

        // Exact-once durable event trail: compact.started before the first
        // command, compact.completed after (ok or error). The started event
        // must be durable before any command runs: a persistent failure
        // aborts the compaction and fails the maintenance run durably.
        let started_event = GatewayEvent {
            event_id: Uuid::new_v4().to_string(),
            seq: 1,
            event: "compact.started".to_string(),
            run_id: maintenance_run_id.clone(),
            timestamp: now as u64,
            data: json!({
                "compaction_id": compaction_id,
                "generation": plan_generation,
                "source_start_ordinal": start_ordinal,
                "source_end_ordinal": end_ordinal,
                "retained_tail_ordinal": tail_ordinal,
            }),
        };
        if !self.append_maintenance_event_bounded(&persistence, &started_event, now, max_events) {
            let message =
                "compact.started could not be persisted durably; the compaction was aborted"
                    .to_string();
            let writes = MaintenanceTerminalWrites::new(
                maintenance_run_id.clone(),
                "compacting".to_string(),
                "failed".to_string(),
                "compaction_failed".to_string(),
                message.clone(),
                None,
                None,
            );
            let outcome = self.commit_maintenance_terminal(&persistence, writes.clone());
            self.mirror_maintenance_terminal(session_id, &writes, outcome, None);
            return Err(CompactSessionError::Storage(message));
        }

        // The plan's command sequence, with the canonical service-owned
        // compaction id (the storage layer's per-(session, generation)
        // identity and the idempotent-resume path key on this exact id).
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
        for (_, payload) in &mut commands {
            if payload.get("id").is_some() {
                payload["id"] = json!(compaction_id);
            }
        }

        let mut error: Option<String> = None;
        let mut start_ok = false;
        let mut conflict: Option<CompactConflict> = None;
        let mut already_committed: Option<JsonValue> = None;
        for (op, payload) in &commands {
            let step = match op.as_str() {
                "compaction.start" => persistence.compaction_start(payload),
                "message.compact" => persistence.message_compact(payload),
                "compaction.commit" => persistence.compaction_commit(payload),
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
                }
                Ok(value) => {
                    // An ok:true envelope whose data reports no match (a
                    // guarded step that matched no row) is a typed step
                    // failure; the storage layer reports every typed
                    // conflict as an ERR (see the Err arm below).
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
                Err(storage_error) => {
                    // The typed storage layer reports guard conflicts as
                    // `Err(StorageError { code })`, never as an ok envelope.
                    match storage_error.code.as_str() {
                        // Cross-process double compact: the other process's
                        // pending/failed row owns the target generation.
                        "compaction_pending_conflict" | "compaction_failed_conflict" => {
                            conflict = Some(CompactConflict::CompactionInProgress);
                            break;
                        }
                        // The other process already committed this exact
                        // (session, generation): the idempotent answer comes
                        // from the committed durable row. A failed or empty
                        // read is a TYPED storage failure — never a
                        // fall-through to the success path, which would
                        // fabricate a completed attribution and run
                        // ownership the durable side never recorded.
                        "compaction_already_committed" => {
                            let row = persistence
                                .compaction_get(&compaction_id)
                                .map_err(|error| {
                                    format!(
                                        "{op} reported {}, but the committed row could \
                                         not be read: {error}",
                                        storage_error.code
                                    )
                                })
                                .and_then(|data| {
                                    data.get("rows")
                                        .and_then(JsonValue::as_array)
                                        .and_then(|rows| rows.first())
                                        .cloned()
                                        .ok_or_else(|| {
                                            format!(
                                                "{op} reported {}, but the committed \
                                                 row is missing",
                                                storage_error.code
                                            )
                                        })
                                })
                                .and_then(|row| {
                                    if row.get(10).and_then(JsonValue::as_str) == Some("committed")
                                    {
                                        Ok(row)
                                    } else {
                                        Err(format!(
                                            "{op} reported {}, but the committed row \
                                             is not in the committed state",
                                            storage_error.code
                                        ))
                                    }
                                });
                            match row {
                                Ok(row) => already_committed = Some(row),
                                Err(message) => error = Some(message),
                            }
                            break;
                        }
                        _ => {
                            error = Some(format!("{op} failed: {storage_error}"));
                            break;
                        }
                    }
                }
            }
        }

        let completed_event_id = Uuid::new_v4().to_string();
        if let Some(conflict) = conflict {
            // The maintenance run is durably failed (exact-once terminal for
            // the losing request) and the event trail closes — durable-first
            // with bounded retries; a persistent outage parks the terminal
            // observably `terminal_pending` for the bounded retry loop.
            let completed_event = GatewayEvent {
                event_id: completed_event_id,
                seq: 2,
                event: "compact.completed".to_string(),
                run_id: maintenance_run_id.clone(),
                timestamp: now as u64,
                data: json!({
                    "ok": false,
                    "error": "compaction_conflict",
                    "compaction_id": compaction_id,
                    "generation": plan_generation,
                }),
            };
            let message =
                "a compaction for this session+generation is already in flight".to_string();
            let writes = MaintenanceTerminalWrites::new(
                maintenance_run_id.clone(),
                "compacting".to_string(),
                "failed".to_string(),
                "compaction_conflict".to_string(),
                message,
                Some(completed_event),
                None,
            );
            let outcome = self.commit_maintenance_terminal(&persistence, writes.clone());
            self.mirror_maintenance_terminal(session_id, &writes, outcome, Some(&started_event));
            return Ok(CompactSessionOutcome::Conflict {
                kind: conflict,
                run_id: None,
                status: None,
            });
        }
        if let Some(row) = already_committed {
            // Idempotent answer from the committed durable row: the other
            // process owns the committed truth, so the response carries its
            // real values and the mirror is REFRESHED from the same row
            // (later plans and message views never see stale state).
            let committed_compaction_id = row
                .get(0)
                .and_then(JsonValue::as_str)
                .unwrap_or(&compaction_id)
                .to_string();
            let committed_run_id = row
                .get(2)
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string();
            let committed_generation = row.get(3).and_then(JsonValue::as_u64).unwrap_or(0);
            let committed_start = row.get(4).and_then(JsonValue::as_i64).unwrap_or(0);
            let committed_end = row.get(5).and_then(JsonValue::as_i64).unwrap_or(0);
            let committed_tail = row.get(6).and_then(JsonValue::as_i64).unwrap_or(0);
            let completed_event = GatewayEvent {
                event_id: completed_event_id,
                seq: 2,
                event: "compact.completed".to_string(),
                run_id: maintenance_run_id.clone(),
                timestamp: now as u64,
                data: json!({
                    "ok": false,
                    "error": "compaction_already_committed",
                    "compaction_id": compaction_id,
                    "generation": plan_generation,
                }),
            };
            let writes = MaintenanceTerminalWrites::new(
                maintenance_run_id.clone(),
                "compacting".to_string(),
                "failed".to_string(),
                "compaction_already_committed".to_string(),
                "a compaction for this session+generation was already committed".to_string(),
                Some(completed_event),
                None,
            );
            let outcome = self.commit_maintenance_terminal(&persistence, writes.clone());
            // Refresh the mirror session state from the committed durable
            // row (durable truth) regardless of the terminal outcome.
            {
                let mut store = self.inner.store.write();
                if let Some(session) = store.sessions.get_mut(session_id) {
                    for (index, message) in session.messages.iter_mut().enumerate() {
                        let ordinal = (index + 1) as i64;
                        if ordinal >= committed_start && ordinal <= committed_end {
                            message.compacted = true;
                        }
                    }
                    session.view.generation = session.view.generation.max(committed_generation);
                    session.view.updated_at = timestamp();
                }
            }
            self.mirror_maintenance_terminal(session_id, &writes, outcome, Some(&started_event));
            return Ok(CompactSessionOutcome::Committed {
                compaction_id: committed_compaction_id,
                run_id: committed_run_id,
                generation: committed_generation,
                source_start_ordinal: committed_start,
                source_end_ordinal: committed_end,
                retained_tail_ordinal: committed_tail,
            });
        }
        if let Some(error) = error {
            // A pending row that never committed is durably failed; the
            // maintenance run is terminal-failed; the history stays fully
            // recoverable (A2 contract). All terminal writes are
            // durable-first (bounded retries + parked terminal), never
            // silent `let _ =`.
            let completed_event = GatewayEvent {
                event_id: completed_event_id,
                seq: 2,
                event: "compact.completed".to_string(),
                run_id: maintenance_run_id.clone(),
                timestamp: now as u64,
                data: json!({
                    "ok": false,
                    "error": error,
                    "compaction_id": compaction_id,
                    "generation": plan_generation,
                }),
            };
            let writes = MaintenanceTerminalWrites::new(
                maintenance_run_id.clone(),
                "compacting".to_string(),
                "failed".to_string(),
                "compaction_failed".to_string(),
                error.clone(),
                Some(completed_event),
                if start_ok {
                    Some(json!({
                        "id": compaction_id,
                        "error_message": error,
                        "completed_at_ms": now,
                    }))
                } else {
                    None
                },
            );
            let outcome = self.commit_maintenance_terminal(&persistence, writes.clone());
            self.mirror_maintenance_terminal(session_id, &writes, outcome, Some(&started_event));
            return Err(CompactSessionError::Storage(error));
        }

        // Success: the compaction is durably committed (generation
        // advanced). Mirror the committed session state (durable truth),
        // then close the event trail and the maintenance run's terminal
        // exactly once — durable-first, parked observably if storage is
        // still down (the run terminal lands via the bounded retry loop,
        // never left durably compacting).
        {
            let mut store = self.inner.store.write();
            if let Some(session) = store.sessions.get_mut(session_id) {
                for (index, message) in session.messages.iter_mut().enumerate() {
                    let ordinal = (index + 1) as i64;
                    if ordinal >= start_ordinal && ordinal <= end_ordinal {
                        message.compacted = true;
                    }
                }
                session.view.generation = plan_generation as u64;
                session.view.updated_at = timestamp();
            }
        }
        let completed_event = GatewayEvent {
            event_id: completed_event_id,
            seq: 2,
            event: "compact.completed".to_string(),
            run_id: maintenance_run_id.clone(),
            timestamp: now as u64,
            data: json!({
                "ok": true,
                "error": "",
                "compaction_id": compaction_id,
                "generation": plan_generation,
            }),
        };
        let writes = MaintenanceTerminalWrites::new(
            maintenance_run_id.clone(),
            "compacting".to_string(),
            "completed".to_string(),
            String::new(),
            String::new(),
            Some(completed_event),
            None,
        );
        let outcome = self.commit_maintenance_terminal(&persistence, writes.clone());
        self.mirror_maintenance_terminal(session_id, &writes, outcome, Some(&started_event));
        Ok(CompactSessionOutcome::Committed {
            compaction_id,
            run_id: maintenance_run_id,
            generation: plan_generation as u64,
            source_start_ordinal: start_ordinal,
            source_end_ordinal: end_ordinal,
            retained_tail_ordinal: tail_ordinal,
        })
    }

    /// Mirrors a failed/terminal maintenance run into the store so run views
    /// and session-active checks never see a fabricated or stale state.
    fn mirror_maintenance_run(
        &self,
        session_id: &str,
        maintenance_run_id: &str,
        status: &str,
        events: Vec<GatewayEvent>,
    ) {
        let mut store = self.inner.store.write();
        store.runs.insert(
            maintenance_run_id.to_string(),
            RunRecord {
                run_id: maintenance_run_id.to_string(),
                request_overrides: JsonValue::Object(Default::default()),
                session_id: session_id.to_string(),
                parent_run_id: None,
                platform: "maintenance".to_string(),
                input: JsonValue::Null,
                status: status.to_string(),
                events,
                sender: None,
                cancel_requested: Arc::new(AtomicBool::new(false)),
            },
        );
    }

    /// Appends one maintenance-run event with bounded in-process retries
    /// (the A5 `terminal_persist_retries` / `terminal_persist_retry_delay`
    /// knobs; the blocking compaction worker owns its thread, so sleeping
    /// there never stalls Tokio). Returns false when the bounded retries
    /// are exhausted.
    fn append_maintenance_event_bounded(
        &self,
        persistence: &GatewayPersistence,
        event: &GatewayEvent,
        now_ms: i64,
        max_events: i64,
    ) -> bool {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        for attempt in 0..attempts {
            let appended = persistence
                .event_append(&json!({
                    "run_id": event.run_id,
                    "event_id": event.event_id,
                    "event_type": event.event,
                    "payload_json": serde_json::to_string(&event.data)
                        .unwrap_or_else(|_| "{}".to_string()),
                    "now_ms": now_ms,
                    "max_events": max_events,
                }))
                .is_ok();
            if appended {
                return true;
            }
            if attempt + 1 < attempts {
                std::thread::sleep(self.inner.config.terminal_persist_retry_delay);
            }
        }
        false
    }

    /// One attempt of the maintenance-run terminal writes; `Ok` when every
    /// write landed, `Err` while any remains. The best-effort
    /// `compaction.fail` never blocks the terminal (the A2 contract; a
    /// leftover pending row is swept by restart recovery).
    fn maintenance_terminal_once(
        &self,
        persistence: &GatewayPersistence,
        writes: &mut MaintenanceTerminalWrites,
    ) -> Result<(), ()> {
        if let Some(payload) = writes.fail_payload.as_ref()
            && persistence.compaction_fail(payload).is_ok()
        {
            writes.fail_payload = None;
        }
        if !writes.transition_landed {
            match persistence.run_transition(&json!({
                "run_id": writes.run_id,
                "from_status": writes.from_status,
                "to_status": writes.to_status,
                "error_code": writes.error_code,
                "error_message": writes.error_message,
                "recovery_reason": "",
                "now_ms": timestamp(),
            })) {
                Ok(data) if run_transition_matched(&data) => {
                    writes.transition_landed = true;
                }
                Ok(_) => {
                    // Not matched: the run may already be terminal durably
                    // (an earlier attempt landed, or restart recovery ran).
                    // A terminal status settles the transition either way —
                    // the event trail still closes exactly once.
                    let durable_status = persistence
                        .run_get(&writes.run_id)
                        .ok()
                        .and_then(|data| {
                            data.get("rows")
                                .and_then(JsonValue::as_array)
                                .and_then(|rows| rows.first())
                                .and_then(|row| row.get(3))
                                .and_then(JsonValue::as_str)
                                .map(|status| status.to_string())
                        })
                        .unwrap_or_default();
                    if matches!(
                        durable_status.as_str(),
                        "completed" | "failed" | "cancelled"
                    ) {
                        writes.transition_landed = true;
                    }
                }
                Err(_) => {}
            }
        }
        if !writes.event_landed
            && let Some(event) = writes.completed_event.as_ref()
            && persistence
                .event_append(&json!({
                    "run_id": event.run_id,
                    "event_id": event.event_id,
                    "event_type": event.event,
                    "payload_json": serde_json::to_string(&event.data)
                        .unwrap_or_else(|_| "{}".to_string()),
                    "now_ms": timestamp(),
                    "max_events": self.inner.config.max_events_per_run,
                }))
                .is_ok()
        {
            writes.event_landed = true;
        }
        if writes.done() { Ok(()) } else { Err(()) }
    }

    /// Durably commits one maintenance run's terminal with bounded
    /// in-process retries (the A5 terminal retry knobs). On final failure
    /// the terminal is parked observably `terminal_pending` and handed to
    /// the bounded retry loop, so a maintenance run is never left durably
    /// `compacting` (or queued/running) without an owned retry: the same
    /// process commits the exact terminal once storage recovers. The
    /// caller mirrors the run (`mirror_maintenance_terminal`) and returns
    /// its typed outcome.
    fn commit_maintenance_terminal(
        &self,
        persistence: &GatewayPersistence,
        mut writes: MaintenanceTerminalWrites,
    ) -> MaintenanceTerminalOutcome {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        for attempt in 0..attempts {
            if self
                .maintenance_terminal_once(persistence, &mut writes)
                .is_ok()
            {
                return MaintenanceTerminalOutcome::Committed;
            }
            if attempt + 1 < attempts {
                std::thread::sleep(self.inner.config.terminal_persist_retry_delay);
            }
        }
        let pending = PendingTerminal {
            to_status: writes.to_status.clone(),
            session_id: None,
            events: writes.completed_event.clone().into_iter().collect(),
            assistant_message: None,
            deadline: std::time::Instant::now() + self.inner.config.terminal_commit_retry_window,
            expired_fallback: false,
            kind: PendingTerminalKind::Maintenance {
                from_status: writes.from_status.clone(),
                error_code: writes.error_code.clone(),
                error_message: writes.error_message.clone(),
                fail_payload: writes.fail_payload.clone(),
                transition_landed: writes.transition_landed,
                event_landed: writes.event_landed,
            },
        };
        MaintenanceTerminalOutcome::Parked(Box::new(pending))
    }

    /// Mirrors one maintenance run's terminal after the durable-first
    /// attempt and hands a parked terminal to the bounded retry loop:
    /// `Committed` -> the terminal status with the full event trail;
    /// `Parked` -> observably `terminal_pending` with only the durably
    /// appended events, and the bounded retry loop commits the terminal and
    /// completes the mirror exactly once when storage recovers.
    fn mirror_maintenance_terminal(
        &self,
        session_id: &str,
        writes: &MaintenanceTerminalWrites,
        outcome: MaintenanceTerminalOutcome,
        started_event: Option<&GatewayEvent>,
    ) {
        let mut events = Vec::new();
        if let Some(started) = started_event {
            events.push(started.clone());
        }
        match outcome {
            MaintenanceTerminalOutcome::Committed => {
                if let Some(completed) = &writes.completed_event {
                    events.push(completed.clone());
                }
                self.mirror_maintenance_run(session_id, &writes.run_id, &writes.to_status, events);
            }
            MaintenanceTerminalOutcome::Parked(pending) => {
                self.mirror_maintenance_run(session_id, &writes.run_id, "terminal_pending", events);
                self.register_pending_terminal(&writes.run_id, *pending);
                self.spawn_terminal_retry(writes.run_id.clone());
            }
        }
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
        if let (Some(key), Some(hash)) = (
            request.idempotency_key.as_deref(),
            request.idempotency_hash.as_deref(),
        ) {
            let store = self.inner.store.read();
            if let Some(existing) = store.idempotency.get(key) {
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

    /// Rehydrates the live replay mirror from durable rows. The durable store
    /// is authoritative after restart or a race with another gateway process;
    /// an in-memory idempotency hit must never return a parent with stale
    /// fanout links.
    fn refresh_replay_mirror(
        &self,
        store: &mut GatewayStore,
        run_id: &str,
    ) -> Result<(String, String), AdmitError> {
        let Some(persistence) = self.inner.persistence.as_ref() else {
            let run = store.runs.get(run_id).ok_or_else(|| {
                AdmitError::Persistence("replayed run is missing from the mirror".to_string())
            })?;
            return Ok((run.session_id.clone(), run.status.clone()));
        };
        let run_data = persistence.run_get(run_id).map_err(|error| {
            AdmitError::Persistence(format!("replayed run lookup failed: {error}"))
        })?;
        let run_row = run_data
            .get("rows")
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .ok_or_else(|| {
                AdmitError::Persistence("replayed run lookup omitted the run".to_string())
            })?;
        let durable_run_id = run_row
            .first()
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        let session_id = run_row
            .get(1)
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string();
        let durable_status = run_row
            .get(3)
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        if durable_run_id != run_id || session_id.is_empty() {
            return Err(AdmitError::Persistence(
                "replayed run row is malformed".to_string(),
            ));
        }
        let mapped_status = match durable_status {
            "completed" => "completed",
            "failed" => "failed",
            "cancelled" => "cancelled",
            "terminal_pending" => "terminal_pending",
            // A legacy durable `terminal_retry_expired` row unifies to the
            // canonical `failed` terminal (the typed reason is carried by the
            // terminal event's `error_code`), never a second canonical state.
            "terminal_retry_expired" => "failed",
            _ => "started",
        };
        if let Some(run) = store.runs.get_mut(run_id) {
            // The durable row is authoritative, including intermediate and
            // retry-expired terminal states.
            run.status = mapped_status.to_string();
        }

        let mut links = Vec::new();
        let mut after_ordinal = -1_i64;
        let mut after_child_id = String::new();
        loop {
            let children_data = persistence
                .list_children_page(run_id, after_ordinal, &after_child_id)
                .map_err(|error| {
                    AdmitError::Persistence(format!("replayed child-link lookup failed: {error}"))
                })?;
            let rows = children_data
                .get("rows")
                .and_then(JsonValue::as_array)
                .ok_or_else(|| {
                    AdmitError::Persistence("replayed child-link lookup omitted rows".to_string())
                })?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let cells = row.as_array().ok_or_else(|| {
                    AdmitError::Persistence("replayed child-link row is malformed".to_string())
                })?;
                if cells.len() < 5 || cells.first().and_then(JsonValue::as_str) != Some(run_id) {
                    return Err(AdmitError::Persistence(
                        "replayed child-link row is malformed".to_string(),
                    ));
                }
                let child_run_id = cells
                    .get(1)
                    .and_then(JsonValue::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        AdmitError::Persistence("replayed child-link has no child id".to_string())
                    })?;
                let ordinal = cells.get(2).and_then(JsonValue::as_i64).ok_or_else(|| {
                    AdmitError::Persistence("replayed child-link has no ordinal".to_string())
                })?;
                let relation = cells
                    .get(3)
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                let state = cells
                    .get(4)
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                links.push(ChildLinkRecord {
                    child_run_id: child_run_id.to_string(),
                    ordinal,
                    relation,
                    state,
                });
            }
            let last = rows.last().and_then(JsonValue::as_array).ok_or_else(|| {
                AdmitError::Persistence("replayed child-link row is malformed".to_string())
            })?;
            after_ordinal = last.get(2).and_then(JsonValue::as_i64).ok_or_else(|| {
                AdmitError::Persistence("replayed child-link has no ordinal".to_string())
            })?;
            after_child_id = last
                .get(1)
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string();
            let truncated = children_data
                .get("truncated")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false);
            if !truncated && rows.len() < 512 {
                break;
            }
        }
        links.sort_by_key(|link| (link.ordinal, link.child_run_id.clone()));
        store.child_links.insert(run_id.to_string(), links);
        Ok((session_id, mapped_status.to_string()))
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
            let existing_run_id = existing.run_id.clone();
            let (session_id, status) =
                match self.refresh_replay_mirror(&mut store, &existing_run_id) {
                    Ok(value) => value,
                    Err(AdmitError::Persistence(message))
                        if message.contains("storage_unavailable") =>
                    {
                        // An in-memory idempotency replay is read-only. If the
                        // durable worker is unavailable, preserve that original
                        // response without pretending the fanout mirror was
                        // refreshed; every successful durable read still takes
                        // the authoritative paginated path above.
                        let run = store.runs.get(&existing_run_id).ok_or_else(|| {
                            AdmitError::Persistence(
                                "replayed run is missing from the mirror".to_string(),
                            )
                        })?;
                        (run.session_id.clone(), run.status.clone())
                    }
                    Err(error) => return Err(error),
                };
            return Ok(AdmittedRun {
                run_id: existing_run_id,
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
        // A child may only be admitted under an ACTIVE parent: the durable
        // admission transaction rejects a terminal/stopping parent (RSS
        // `run_active` predicate), and the in-memory mirror enforces the same
        // guard so no child/link/event is ever inserted beneath a finished
        // parent in either store.
        if let Some(parent_run_id) = request.parent_run_id.as_deref()
            && let Some(parent) = store.runs.get(parent_run_id)
            && is_terminal_status(parent.status.as_str())
        {
            self.inner
                .metrics
                .admission_rejected(AdmitRejectReason::ParentNotActive);
            return Err(AdmitError::ParentNotActive);
        }

        // The transport's canonical pre-appended conversation (OpenAI
        // route): persisted in the SAME admission transaction as the
        // session and the run, so a failed admission leaves no partial
        // session and a replayed key never creates a new one. The ids are
        // generated here so the in-memory mirror matches the durable rows
        // exactly.
        let mut conversation_rows = Vec::new();
        let mut conversation_messages = Vec::new();
        for draft in &request.session_messages {
            let draft_message_id = Uuid::new_v4().to_string();
            conversation_rows.push(json!({
                "id": draft_message_id,
                "role": draft.role,
                "content_json": serde_json::to_string(&draft.content)
                    .unwrap_or_else(|_| "[]".to_string()),
                "tool_call_id": draft.tool_call_id,
            }));
            conversation_messages.push(SessionMessage {
                id: draft_message_id,
                session_id: session_id.clone(),
                role: draft.role.clone(),
                tool_call_id: draft.tool_call_id.clone(),
                content: draft.content.clone(),
                created_at: now,
                run_id: None,
                finish_reason: None,
                compacted: false,
            });
        }
        let conversation_json =
            serde_json::to_string(&conversation_rows).unwrap_or_else(|_| "[]".to_string());

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
            "origin_actor": request.origin_actor.clone().unwrap_or_default(),
            "event_id": event_id,
            "now_ms": now,
            "expires_at_ms": 0,
            "conversation_json": conversation_json,
        });

        let durable = match self.inner.persistence.as_ref() {
            Some(persistence) => persistence.admission_create(&payload).map_err(|error| {
                self.inner
                    .metrics
                    .admission_rejected(AdmitRejectReason::Persistence);
                match error.code.as_str() {
                    "idempotency_key_conflict" => AdmitError::IdempotencyConflict,
                    "parent_not_found" => AdmitError::ParentNotFound,
                    // The durable admission transaction rejects a child under
                    // a terminal/stopping parent (`run_active` predicate):
                    // no child/link/event is inserted and the rejection is
                    // typed, never a generic persistence failure.
                    "parent_not_active" => AdmitError::ParentNotActive,
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
            let (replayed_session, replayed_status) =
                self.refresh_replay_mirror(&mut store, &replayed_run_id)?;
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
        // The transport's pre-appended conversation mirrors the durable
        // rows exactly (same ids, same order); the run's user message
        // follows, matching the durable ordinal order.
        session.messages.extend(conversation_messages);
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
            request_overrides: request.request_overrides.clone(),
            platform: request.platform.clone(),
            input: request.input.clone(),
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
        if matches!(status.as_str(), "started" | "waiting_approval") {
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
            // commit the typed cancellation now. The consumed park's durable
            // approval row is cancelled via the A5 `approval.cancel` op in
            // the SAME task: the row transitions pending -> expired promptly
            // (never left for the default TTL sweep). The storage update is
            // pending-only, so a resolve that already landed before the stop
            // is never downgraded — stop/resolve stay exactly-once.
            if let Some(parked) = self
                .inner
                .parked
                .lock()
                .expect("parked lock")
                .remove(run_id)
            {
                let service = self.clone();
                let run_id = run_id.to_string();
                let approval_id = parked.approval_id;
                tokio::spawn(async move {
                    let _ = service
                        .cancel_abandoned_approval(&run_id, &approval_id)
                        .await;
                    service
                        .transition_run(&run_id, "waiting_approval", "running")
                        .await;
                    service.finish_cancelled(&run_id, "requested").await;
                });
            } else if status == "waiting_approval" {
                // Close the micro-window after the durable status transition
                // but before the park map insert. The worker may still return
                // from park_for_approval, yet a direct stop must never leave
                // a park-less waiting run stuck in `stopping`.
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

    #[doc(hidden)]
    pub fn fail_next_link_states(&self, n: usize) {
        if let Some(persistence) = &self.inner.persistence {
            persistence.fail_next_link_states(n);
        }
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
            // The authoritative active-status check (every run_worker entry
            // runs it BEFORE any provider/message/event side effect): a run
            // that already reached a terminal — for example a REPLAYED child
            // admission whose lifecycle was already produced — is never
            // re-driven, never executes a provider round, and never appends
            // messages or events.
            if is_terminal_status(run.status.as_str()) {
                return;
            }
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

        self.finish_completed(
            &run_id,
            &session_id,
            &output_text,
            &empty_usage_json(),
            "stop",
        )
        .await;
    }

    /// Durably commits the completed terminal. The assistant message,
    /// `message.delta`, and `run.completed` form one atomic delta: the whole
    /// delta is persisted through the typed `run.terminal` transaction under
    /// the store lock and published only after the durable commit succeeds.
    /// The canonical `usage` (the production loop carries the FINAL provider
    /// round's usage through its `run.completed` decision; transports
    /// without usage information pass the canonical zero shape) and the
    /// `finish_reason` (the provider's typed stop reason, `stop` default)
    /// are persisted into the terminal event and the assistant message row.
    /// On a persist failure the delta is rolled back, nothing is published,
    /// and the worker retries with bounded backoff
    /// (`terminal_persist_retries`/`terminal_persist_retry_delay`); if every
    /// attempt fails, the run becomes observably `terminal_pending` and the
    /// bounded retry loop commits the exact same terminal once storage
    /// recovers.
    async fn finish_completed(
        &self,
        run_id: &str,
        session_id: &str,
        output_text: &str,
        usage: &JsonValue,
        finish_reason: &str,
    ) {
        if output_text.len() > MAX_DURABLE_ASSISTANT_BYTES {
            self.finish_failed(
                run_id,
                json!({
                    "code": "output_too_large",
                    "message": format!(
                        "assistant output exceeds the {MAX_DURABLE_ASSISTANT_BYTES} UTF-8 byte durable bound"
                    )
                }),
            )
            .await;
            return;
        }
        let finish_reason = if finish_reason.is_empty() {
            "stop"
        } else {
            finish_reason
        };
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        // IDs belong to the logical terminal transition, not to an attempt.
        // Reusing them makes a retry safe after an ambiguous durable response.
        let message_id = Uuid::new_v4().to_string();
        let delta_event_id = Uuid::new_v4().to_string();
        let completed_event_id = Uuid::new_v4().to_string();
        for attempt in 0..attempts {
            match self
                .commit_completed_once(
                    run_id,
                    session_id,
                    output_text,
                    usage,
                    finish_reason,
                    &message_id,
                    &delta_event_id,
                    &completed_event_id,
                )
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
    #[allow(clippy::too_many_arguments)]
    async fn commit_completed_once(
        &self,
        run_id: &str,
        session_id: &str,
        output_text: &str,
        usage: &JsonValue,
        finish_reason: &str,
        message_id: &str,
        delta_event_id: &str,
        completed_event_id: &str,
    ) -> TerminalOutcome {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let session_id_for_commit = session_id.to_string();
        let output_text_for_commit = output_text.to_string();
        let usage_for_commit = canonical_usage_json(usage);
        let finish_reason_for_commit = finish_reason.to_string();
        let message_id_for_commit = message_id.to_string();
        let delta_event_id_for_commit = delta_event_id.to_string();
        let completed_event_id_for_commit = completed_event_id.to_string();
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
            let message = append_message_with_id(
                &mut session.view,
                &mut session.messages,
                message_id_for_commit.clone(),
                "assistant",
                JsonValue::String(output_text_for_commit.clone()),
                Some(run_id_for_commit.clone()),
                Some(finish_reason_for_commit.clone()),
                false,
                "",
            );
            let run = store
                .runs
                .get_mut(&run_id_for_commit)
                .expect("run was checked above");
            let previous_status = run.status.clone();
            let previous_events = run.events.clone();
let delta_event = append_event_locked_with_id(
                run,
                delta_event_id_for_commit.clone(),
                "message.delta",
                json!({"message_id":message.id, "delta":output_text_for_commit, "role":"assistant"}),
                max_event_bytes,
                max_events_per_run,
            );
            // The terminal event is a bounded index into RSS-owned durable
            // storage.  Keep the complete message inline only when it fits
            // the configured event envelope; long output never reaches the
            // 32 KiB event cap and is recovered by `message_id` at render
            // time.  A message reference is present in both forms so a
            // replay never has to infer which payload was truncated.
            let inline_completed = json!({
                "status":"completed",
                "session_id":session_id_for_commit,
                "message_id":message.id,
                "output":{"message":message.clone()},
                "usage":usage_for_commit,
                "finish_reason":finish_reason_for_commit,
            });
            let completed_data = if serde_json::to_vec(&inline_completed)
                .map(|bytes| bytes.len() <= max_event_bytes)
                .unwrap_or(false)
            {
                inline_completed
            } else {
                json!({
                    "status":"completed",
                    "session_id":session_id_for_commit,
                    "message_id":message.id,
                    "usage":usage_for_commit,
                    "finish_reason":finish_reason_for_commit,
                })
            };
            let completed_event = append_event_locked_with_id(
                run,
                completed_event_id_for_commit.clone(),
                "run.completed",
                completed_data,
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
                Ok(durable_events) => {
                    if let Some(sender) = &run.sender {
                        for event in durable_events {
                            let _ = sender.send(event);
                        }
                    }
                    // The terminal is committed and published: close the
                    // broadcast sender so existing subscribers observe
                    // Closed and new subscribers replay history and end,
                    // instead of lingering until the janitor TTL.
                    close_run_stream(run);
                    TerminalOutcome::Committed
                }
                Err(error) => {
                    // Roll the in-memory terminal state back: the run becomes
                    // observably terminal-pending and the retry loop owns the
                    // exact same terminal (events, message, status).
                    run.status = previous_status;
                    restore_events_after_failed_append(&mut run.events, previous_events);
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
                            expired_fallback: false,
                            kind: PendingTerminalKind::RunTerminal,
                        }),
                    }
                }
            }
        })
        .await
                    .unwrap_or_else(|error| terminal_commit_task_cancelled(run_id, retry_window, error.to_string()))
    }

    /// Cancels a run with the typed reason through a durable-first terminal
    /// commit: `run.terminal` commits the cancellation event and the status
    /// change in one transaction, and only then is the event published. The
    /// commit is retried with bounded backoff; on final failure the
    /// cancellation is handed to the bounded retry loop (`terminal_pending`),
    /// which commits and publishes it exactly once when storage recovers.
    pub(crate) async fn finish_cancelled(&self, run_id: &str, reason: &str) {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        let event_id = Uuid::new_v4().to_string();
        for attempt in 0..attempts {
            match self.commit_cancelled_once(run_id, reason, &event_id).await {
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
    async fn commit_cancelled_once(
        &self,
        run_id: &str,
        reason: &str,
        event_id: &str,
    ) -> TerminalOutcome {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let reason_for_commit = reason.to_string();
        let event_id_for_commit = event_id.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let mut store = service.inner.store.write();
            let persistence = service.persistence_handle();
            let Some(run) = store.runs.get_mut(&run_id_for_commit) else {
                return TerminalOutcome::NotActive;
            };
            if is_terminal_status(run.status.as_str()) {
                return TerminalOutcome::NotActive;
            }
            let previous_status = run.status.clone();
            let previous_events = run.events.clone();
            let event = append_event_locked_with_id(
                run,
                event_id_for_commit.clone(),
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
                Ok(durable_events) => {
                    if let Some(sender) = &run.sender {
                        for event in durable_events {
                            let _ = sender.send(event);
                        }
                    }
                    // The terminal is committed and published: close the
                    // broadcast sender so subscribers observe Closed and
                    // new subscribers replay history and end.
                    close_run_stream(run);
                    TerminalOutcome::Committed
                }
                Err(error) => {
                    run.status = previous_status;
                    restore_events_after_failed_append(&mut run.events, previous_events);
                    TerminalOutcome::TerminalPersistFailed {
                        error: error.to_string(),
                        pending: Box::new(PendingTerminal {
                            to_status: "cancelled".to_string(),
                            session_id: None,
                            events: vec![event],
                            assistant_message: None,
                            deadline: std::time::Instant::now() + retry_window,
                            expired_fallback: false,
                            kind: PendingTerminalKind::RunTerminal,
                        }),
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|error| {
            terminal_commit_task_cancelled(run_id, retry_window, error.to_string())
        })
    }

    /// Fails a run through a durable-first terminal commit: `run.terminal`
    /// commits the failure event and the status change in one transaction,
    /// and only then is the event published. The commit is retried with
    /// bounded backoff; on final failure the failure is handed to the bounded
    /// retry loop (`terminal_pending`), which commits and publishes it
    /// exactly once when storage recovers.
    pub(crate) async fn finish_failed(&self, run_id: &str, data: JsonValue) {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        let event_id = Uuid::new_v4().to_string();
        for attempt in 0..attempts {
            match self
                .commit_failed_once(run_id, data.clone(), &event_id)
                .await
            {
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
    async fn commit_failed_once(
        &self,
        run_id: &str,
        data: JsonValue,
        event_id: &str,
    ) -> TerminalOutcome {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let event_id_for_commit = event_id.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let mut store = service.inner.store.write();
            let persistence = service.persistence_handle();
            let Some(run) = store.runs.get_mut(&run_id_for_commit) else {
                return TerminalOutcome::NotActive;
            };
            if is_terminal_status(run.status.as_str()) {
                return TerminalOutcome::NotActive;
            }
            let previous_status = run.status.clone();
            let previous_events = run.events.clone();
            let event = append_event_locked_with_id(
                run,
                event_id_for_commit.clone(),
                "run.failed",
                data,
                max_event_bytes,
                max_events_per_run,
            );
            run.status = "failed".to_string();
            match terminal_commit(persistence.as_deref(), run, "", "failed", &[&event], None) {
                Ok(durable_events) => {
                    if let Some(sender) = &run.sender {
                        for event in durable_events {
                            let _ = sender.send(event);
                        }
                    }
                    // The terminal is committed and published: close the
                    // broadcast sender so subscribers observe Closed and
                    // new subscribers replay history and end.
                    close_run_stream(run);
                    TerminalOutcome::Committed
                }
                Err(error) => {
                    run.status = previous_status;
                    restore_events_after_failed_append(&mut run.events, previous_events);
                    TerminalOutcome::TerminalPersistFailed {
                        error: error.to_string(),
                        pending: Box::new(PendingTerminal {
                            to_status: "failed".to_string(),
                            session_id: None,
                            events: vec![event],
                            assistant_message: None,
                            deadline: std::time::Instant::now() + retry_window,
                            expired_fallback: false,
                            kind: PendingTerminalKind::RunTerminal,
                        }),
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|error| {
            terminal_commit_task_cancelled(run_id, retry_window, error.to_string())
        })
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
            input: canonical_input_value(input),
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
        // The typed per-request overrides (OpenAI route): an empty map when
        // the transport did not carry any. The loop's `build_request` reads
        // the `request` context map for tools/tool_choice/sampling/
        // max_output_tokens/stream with documented fallbacks; credentials
        // never travel through it.
        let request_overrides = run
            .map(|run| run.request_overrides.clone())
            .unwrap_or_else(|| JsonValue::Object(Default::default()));
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
        // The structured admission input: the loop carries it so delegation
        // requests (the parallel batch / the subagent child descriptor)
        // reach the serial loop without a separate lookup.
        let input = run.map(|run| run.input.clone()).unwrap_or(JsonValue::Null);
        // A CHILD run (admitted with a parent link) never re-delegates: the
        // delegation capability flags are forced off so a supervised child
        // reasons normally instead of recursing into another handoff.
        let is_child = run.is_some_and(|run| run.parent_run_id.is_some());
        let parallel = if is_child { false } else { config.parallel };
        let task = if is_child { false } else { config.task };
        let mut context = json!({
            "run_id": run_id,
            "session_id": session_id,
            "platform": platform,
            "input": input,
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
                "native_hard_deny": config.native_hard_deny,
                "stream": config.stream,
                "parallel": parallel,
                "task": task,
                "max_output_tokens": 1024,
                "max_event_bytes": config.max_event_bytes,
                "now_ms": timestamp(),
                "generation": generation,
                "message_count": message_count,
                "compaction_id": format!("compact:{session_id}:{}", generation + 1),
            }
        });
        context["request"] = request_overrides;
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
                    // The typed usage/stop_reason carried by the loop's
                    // terminal decision (the FINAL provider round's canonical
                    // usage) are persisted into the durable terminal event
                    // and the assistant message row.
                    let usage = decision
                        .get("usage")
                        .cloned()
                        .unwrap_or_else(empty_usage_json);
                    let stop_reason = decision["stop_reason"].as_str().unwrap_or("stop");
                    self.finish_completed(run_id, session_id, &text, &usage, stop_reason)
                        .await;
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
                    // A natively-denied delegation NEVER parks: the typed
                    // rejection is folded and the loop continues — no
                    // durable approval row is created for a tool the native
                    // policy denies (the park would otherwise wait for an
                    // approval that can never execute).
                    let pending_tool = decision["approval"]["tool_name"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    if (pending_tool == "parallel.run" || pending_tool == "subagent.run")
                        && let Some(rejection) = self.native_deny_rejection(&pending_tool)
                    {
                        let is_parallel = pending_tool == "parallel.run";
                        phase = if is_parallel {
                            "parallel.result"
                        } else {
                            "subagent.result"
                        }
                        .to_string();
                        state = decision_state(&decision);
                        if is_parallel {
                            state["parallel_outcome"] = rejection;
                        } else {
                            state["subagent_outcome"] = rejection;
                        }
                        continue;
                    }
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
                    let is_parallel = decision["kind"] == "parallel.handoff";
                    let delegation_tool = if is_parallel {
                        "parallel.run"
                    } else {
                        "subagent.run"
                    };
                    // The NATIVE deny policy is authoritative BEFORE any
                    // child work: a natively-denied delegation folds the
                    // typed rejection (approval_denied) and the loop
                    // continues reasoning — no admission, no park, no
                    // child, no subagent.started.
                    if let Some(rejection) = self.native_deny_rejection(delegation_tool) {
                        phase = if is_parallel {
                            "parallel.result"
                        } else {
                            "subagent.result"
                        }
                        .to_string();
                        state = decision_state(&decision);
                        if is_parallel {
                            state["parallel_outcome"] = rejection;
                        } else {
                            state["subagent_outcome"] = rejection;
                        }
                        continue;
                    }
                    // A6 native supervisor execution: a stop that landed
                    // before the handoff is a typed cancellation (no child
                    // work starts after a stop).
                    if self.run_is_stopping(run_id) {
                        self.finish_cancelled(run_id, handle_cancel_reason(&handle, "requested"))
                            .await;
                        return;
                    }
                    let executed = if is_parallel {
                        self.execute_parallel_handoff(run_id, &decision, deadline)
                            .await
                    } else {
                        self.execute_subagent_handoff(run_id, &decision, deadline)
                            .await
                    };
                    phase = if is_parallel {
                        "parallel.result"
                    } else {
                        "subagent.result"
                    }
                    .to_string();
                    state = decision_state(&decision);
                    match executed {
                        HandoffExec::Outcome(outcome) => {
                            // Backfill the ordered typed results / child
                            // outcome into the loop state; the loop folds
                            // them and continues reasoning.
                            if is_parallel {
                                state["parallel_outcome"] = outcome;
                            } else {
                                state["subagent_outcome"] = outcome;
                            }
                        }
                        HandoffExec::Cancelled => {
                            // A stop/cancel landed during the handoff
                            // execution: the typed cancellation path wins
                            // (children were cancelled by the propagated
                            // supervision cancel).
                            self.finish_cancelled(
                                run_id,
                                handle_cancel_reason(&handle, "requested"),
                            )
                            .await;
                            return;
                        }
                        HandoffExec::Unavailable(message) => {
                            // The native supervisor could not run (policy
                            // programs unavailable): typed failure, never a
                            // fabricated outcome.
                            self.finish_failed(
                                run_id,
                                json!({
                                    "status": "failed",
                                    "error_code": "supervisor_unavailable",
                                    "error_message": message,
                                }),
                            )
                            .await;
                            return;
                        }
                    }
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

    // -----------------------------------------------------------------------
    // A6 native supervisor execution (real child runs through AgentService)
    // -----------------------------------------------------------------------

    /// Runs one RSS policy program (`parallel.rss` / `subagents.rss`) with
    /// the real context on a blocking thread (VM execution must never occupy
    /// a Tokio worker). Returns the typed decision map, or `None` when the
    /// program cannot run.
    async fn run_policy(runner: &AgentRunner, context: &JsonValue) -> Option<JsonValue> {
        let runner = runner.clone();
        let context = context.clone();
        tokio::task::spawn_blocking(move || {
            let value = runner.run_with_context(json_to_vm_value(&context)).ok()?;
            Some(vm_value_to_json(&value))
        })
        .await
        .ok()
        .flatten()
    }

    /// Appends one native lifecycle event (`subagent.started` /
    /// `subagent.completed`) to the parent run's durable event stream and
    /// publishes it — the same durable-first critical section as script
    /// event delivery. A failed durable append is retried with the bounded
    /// retry (`terminal_persist_retries` immediate attempts with
    /// `terminal_persist_retry_delay` backoff); only when storage stays
    /// down past the bound does the typed [`NativeEventEmit::AppendFailed`]
    /// reach the caller, which must fail the slot typed — never fold an
    /// outcome whose canonical event is not durable. No duplicate can arise:
    /// each failed attempt rolls the in-memory event back and the storage
    /// worker either commits (returning Ok) or fails without committing; a
    /// worker that dies mid-command fails every later attempt too, so the
    /// retry path can never append the same event twice.
    async fn emit_native_event(
        &self,
        run_id: &str,
        event_type: &str,
        data: JsonValue,
    ) -> NativeEventEmit {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        let event_id = Uuid::new_v4().to_string();
        let mut last = NativeEventEmit::AppendFailed;
        for attempt in 0..attempts {
            last = self
                .emit_native_event_once(run_id, event_id.as_str(), event_type, data.clone())
                .await;
            match last {
                // A parent terminal is final (no post-terminal side
                // effects): retrying cannot help and must not append after
                // the terminal.
                NativeEventEmit::Emitted | NativeEventEmit::ParentTerminal => return last,
                NativeEventEmit::AppendFailed => {
                    if attempt + 1 < attempts {
                        tokio::time::sleep(self.inner.config.terminal_persist_retry_delay).await;
                    }
                }
            }
        }
        last
    }

    /// One durable attempt of a native lifecycle event append, under the
    /// store write lock: append in memory, commit through the typed
    /// `event.append` transaction, publish only after the durable commit,
    /// and roll the in-memory event back on failure.
    async fn emit_native_event_once(
        &self,
        run_id: &str,
        event_id: &str,
        event_type: &str,
        data: JsonValue,
    ) -> NativeEventEmit {
        let service = self.clone();
        let run_id_for_block = run_id.to_string();
        let event_id_for_block = event_id.to_string();
        let event_type_for_block = event_type.to_string();
        let data_for_block = data.clone();
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let mut store = service.inner.store.write();
            let Some(run) = store.runs.get_mut(&run_id_for_block) else {
                return NativeEventEmit::ParentTerminal;
            };
            if is_terminal_status(run.status.as_str()) {
                return NativeEventEmit::ParentTerminal;
            }
            let previous_events = run.events.clone();
            let event = append_event_locked_with_id(
                run,
                event_id_for_block,
                &event_type_for_block,
                data_for_block,
                max_event_bytes,
                max_events_per_run,
            );
            let persistence = service.persistence_handle();
            let durable = match persistence.as_ref() {
                Some(persistence) => persistence
                    .event_append(&json!({
                        "run_id": run_id_for_block,
                        "event_id": event.event_id,
                        "event_type": event.event,
                        "payload_json": serde_json::to_string(&event.data)
                            .unwrap_or_else(|_| "{}".to_string()),
                        "now_ms": timestamp(),
                        "max_events": max_events_per_run,
                    }))
                    .map(|_| ()),
                None => Ok(()),
            };
            match durable {
                Ok(()) => {
                    if let Some(sender) = &run.sender {
                        let _ = sender.send(event);
                    }
                    NativeEventEmit::Emitted
                }
                Err(_) => {
                    run.events = previous_events;
                    NativeEventEmit::AppendFailed
                }
            }
        })
        .await
        .unwrap_or(NativeEventEmit::AppendFailed)
    }

    /// Durable parent/child link after a REAL child admission (the A2
    /// `run.link_child` command through the RSS storage program) plus the
    /// in-memory mirror for the live parent's policy context. A failed
    /// durable link reports false — the slot fails typed (never a claim
    /// that the link exists). The mirror is DEDUPLICATED by child id and
    /// never regresses a terminal state back to active (matching the
    /// durable UPSERT guard).
    fn link_child_native(
        &self,
        parent_run_id: &str,
        child_run_id: &str,
        ordinal: i64,
        relation: &str,
    ) -> bool {
        let durable_ok = match self.inner.persistence.as_ref() {
            Some(persistence) => persistence
                .link_child(&json!({
                    "parent_run_id": parent_run_id,
                    "child_run_id": child_run_id,
                    "ordinal": ordinal,
                    "relation": relation,
                    "state": "active",
                    "now_ms": timestamp(),
                }))
                .is_ok(),
            None => true,
        };
        if durable_ok {
            let mut store = self.inner.store.write();
            let links = store
                .child_links
                .entry(parent_run_id.to_string())
                .or_default();
            match links
                .iter_mut()
                .find(|link| link.child_run_id == child_run_id)
            {
                // Re-linking an existing pair is idempotent in the mirror:
                // pending/active advance to active, a terminal state is
                // never moved back.
                Some(existing) => {
                    if existing.state == "pending" || existing.state == "active" {
                        existing.state = "active".to_string();
                    }
                }
                None => links.push(ChildLinkRecord {
                    child_run_id: child_run_id.to_string(),
                    ordinal,
                    relation: relation.to_string(),
                    state: "active".to_string(),
                }),
            }
        }
        durable_ok
    }

    /// The live in-memory child links of one parent (the durable rows are
    /// authoritative for restart recovery; this mirror feeds the subagent
    /// policy context during the parent's own execution). The mirror is the
    /// AUTHORITATIVE live fanout count: it accumulates every child admitted
    /// under the parent across ALL batches of the run, so cumulative
    /// fanout can never be understated by a caller-declared count.
    fn child_links_native(&self, parent_run_id: &str) -> Vec<ChildLinkRecord> {
        self.inner
            .store
            .read()
            .child_links
            .get(parent_run_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Reserves `count` parent-global ordinals for a `(parent_run_id,
    /// namespace)` pair and returns the base of the reserved range (A6
    /// sparse-parallel fix).
    ///
    /// With durable storage the full range is reserved ATOMICALLY by the
    /// storage program BEFORE any child of the batch starts, so refused or
    /// cancelled-before-start slots — which consume an ordinal identity but
    /// create no `child_run_links` row — still occupy durable high-water:
    /// a later batch of the same run (or another gateway process, or a
    /// restart) never reuses them. A durable allocation failure is a typed
    /// error: the batch must fail rather than proceed with an ordinal space
    /// that diverges from the durable source of truth. Without durable
    /// storage the base is the MAX live mirror ordinal + 1 (never the sparse
    /// link count) — the strongest invariant available offline.
    async fn allocate_parent_ordinals(
        &self,
        parent_run_id: &str,
        namespace: &str,
        count: usize,
    ) -> Result<i64, String> {
        if let Some(persistence) = self.inner.persistence.clone() {
            let parent = parent_run_id.to_string();
            let ns = namespace.to_string();
            let base = tokio::task::spawn_blocking(move || {
                persistence.allocate_ordinals(&parent, &ns, count)
            })
            .await
            .map_err(|error| format!("ordinal allocator task failed: {error}"))?
            .map_err(|error| error.to_string())?;
            return Ok(base);
        }
        let max_ordinal = self
            .child_links_native(parent_run_id)
            .iter()
            .map(|link| link.ordinal)
            .max()
            .unwrap_or(-1);
        Ok((max_ordinal + 1).max(0))
    }

    /// Non-blocking lookup of the run id recorded under an idempotency key
    /// (the in-memory admission record), for the grace-drop compensation
    /// watcher: returns `None` while the store lock is unavailable (a
    /// writer — a stalled admission holding or awaiting the write lock — is
    /// queued), so the watcher NEVER parks behind a stalled writer and can
    /// always observe service shutdown between polls.
    fn try_find_run_by_idempotency(&self, key: &str) -> Option<Option<String>> {
        self.inner.store.try_read().map(|store| {
            store
                .idempotency
                .get(key)
                .map(|record| record.run_id.clone())
        })
    }

    /// Advances one link's state to the child's observed terminal status —
    /// DURABLY (the storage `run.link_state` command: the durable row
    /// really progresses pending -> active -> terminal) AND in the
    /// in-memory mirror. The mirror is updated only after the durable
    /// command succeeded, so the live state never claims a terminal the
    /// durable side does not carry.
    ///
    /// When the inline retry budget is exhausted writing a REAL child
    /// terminal while the parent is still live, the advance is handed to the
    /// capacity-bounded, lifecycle-managed `link_terminal_retry_loop` janitor
    /// (deriving the terminal from the child's real observed durable state)
    /// instead of silently leaving the durable link — and the mirror — at a
    /// permanent non-terminal state. A child still `terminal_pending` is
    /// NEVER written as a terminal link (the janitor reads the observed
    /// status, which is `None` until a real durable terminal).
    async fn update_child_link_state_native(
        &self,
        parent_run_id: &str,
        child_run_id: &str,
        state: &str,
    ) {
        let max_attempts = 1 + self.inner.config.terminal_persist_retries.max(2);
        for attempt in 0..max_attempts {
            if self
                .write_link_state_durable(parent_run_id, child_run_id, state)
                .await
            {
                self.update_link_mirror_link(parent_run_id, child_run_id, state);
                return;
            }
            if attempt + 1 < max_attempts {
                tokio::time::sleep(Duration::from_millis(5 * (attempt as u64 + 1))).await;
            }
        }
        tracing::error!(
            parent_run_id,
            child_run_id,
            state,
            "child link state durable retry budget exhausted"
        );
        // P2 restart: an exhausted terminal advance must eventually converge
        // in THIS process (not just at the next open). If the desired state is
        // a real child terminal and the parent is still live, enqueue a
        // bounded pending reconciliation retried by the janitor until storage
        // recovers (the mirror stays non-terminal until the durable write
        // really lands; a `terminal_pending` child is never prematurely
        // advanced because the janitor derives the status from the child's
        // observed durable terminal).
        if is_terminal_link_status(state) && !self.parent_reached_real_terminal(parent_run_id) {
            self.enqueue_pending_link_terminal(parent_run_id, child_run_id);
        }
    }

    /// Durable `run.link_state` write. `true` when the durable row advanced
    /// (or there is no durable store to advance); `false` on any storage
    /// failure (including a fault-injected one and a terminal parent).
    async fn write_link_state_durable(
        &self,
        parent_run_id: &str,
        child_run_id: &str,
        state: &str,
    ) -> bool {
        let Some(persistence) = self.inner.persistence.clone() else {
            return true;
        };
        let parent = parent_run_id.to_string();
        let child = child_run_id.to_string();
        let state = state.to_string();
        tokio::task::spawn_blocking(move || {
            persistence
                .link_state(&json!({
                    "parent_run_id": parent,
                    "child_run_id": child,
                    "ordinal": 0,
                    "relation": "",
                    "state": state,
                    "now_ms": timestamp(),
                }))
                .is_ok()
        })
        .await
        .unwrap_or(false)
    }

    /// Advances one child link in the in-memory mirror (after the durable
    /// write succeeded).
    fn update_link_mirror_link(&self, parent_run_id: &str, child_run_id: &str, state: &str) {
        let mut store = self.inner.store.write();
        if let Some(links) = store.child_links.get_mut(parent_run_id) {
            for link in links.iter_mut() {
                if link.child_run_id == child_run_id {
                    link.state = state.to_string();
                }
            }
        }
    }

    /// True once the parent has reached a REAL durable terminal (mirror
    /// status `completed`/`failed`/`cancelled`): the durable `run.link_state`
    /// write can never succeed under a terminal parent (`parent_not_active`).
    fn parent_reached_real_terminal(&self, parent_run_id: &str) -> bool {
        let status = self
            .inner
            .store
            .read()
            .runs
            .get(parent_run_id)
            .map(|run| run.status.clone())
            .unwrap_or_default();
        matches!(status.as_str(), "completed" | "failed" | "cancelled")
    }

    /// The child's REAL (durable-authoritative) terminal status for the link
    /// janitor: reads the child run's DURABLE row via `run.get` when durable
    /// storage is present (so a child whose durable terminal committed — even
    /// if the in-memory mirror has not caught up — advances the link), falling
    /// back to the in-memory mirror only in in-memory-only mode. Never yields
    /// while the child is still `pending`/`running`/`terminal_pending` (a
    /// `terminal_pending` child stays `None`, so the janitor never writes a
    /// premature terminal link).
    async fn observed_link_terminal(&self, child_run_id: &str) -> Option<String> {
        if let Some(persistence) = self.inner.persistence.clone() {
            let child = child_run_id.to_string();
            let durable_status = tokio::task::spawn_blocking(move || {
                persistence
                    .run_get(&child)
                    .ok()
                    .and_then(|data| data["rows"].as_array().cloned())
                    .and_then(|rows| rows.first().cloned())
                    .and_then(|row| row.get(3).cloned())
                    .and_then(|status| status.as_str().map(str::to_string))
            })
            .await
            .unwrap_or(None);
            if let Some(status) = durable_status
                && matches!(status.as_str(), "completed" | "failed" | "cancelled")
            {
                return Some(status);
            }
        }
        observed_link_state(self, child_run_id)
    }

    /// Number of child links currently awaiting the link-terminal retry
    /// janitor (live + bounded by [`MAX_PENDING_LINK_TERMINALS`]).
    pub fn pending_link_terminal_count(&self) -> usize {
        self.inner
            .pending_link_terminal
            .lock()
            .expect("pending link terminal lock")
            .len()
    }

    /// Records a child link whose durable terminal advance failed past the
    /// inline budget for live reconciliation, and starts (at most one) janitor
    /// task if none is running.
    fn enqueue_pending_link_terminal(&self, parent_run_id: &str, child_run_id: &str) {
        let mut pending = self
            .inner
            .pending_link_terminal
            .lock()
            .expect("pending link terminal lock");
        if pending.len() >= MAX_PENDING_LINK_TERMINALS {
            // Capacity-bound: a full set defers the remaining link to restart
            // recovery, which reconciles `pending`/`active` links from the
            // child's real terminal on the next open.
            tracing::error!(
                parent_run_id,
                child_run_id,
                "pending link terminal set at capacity; link terminal deferred to restart recovery"
            );
            return;
        }
        pending.insert((parent_run_id.to_string(), child_run_id.to_string()), ());
        drop(pending);
        if !self.inner.link_retry_running.swap(true, Ordering::AcqRel) {
            let service = self.clone();
            tokio::spawn(async move {
                service.link_terminal_retry_loop().await;
            });
        }
    }

    /// The lifecycle-managed link-terminal retry janitor. Runs while there is
    /// at least one pending entry and the service is not halting; it exits
    /// (clearing the running flag) when the pending set empties so a later
    /// enqueue starts a fresh task — at most ONE janitor ever runs. Each pass
    /// derives the terminal from the child's REAL observed durable status and
    /// writes DURABLY before updating the mirror. Entries whose parent reached
    /// a real terminal are dropped (their durable write can never succeed and
    /// restart recovery reconciles them).
    async fn link_terminal_retry_loop(&self) {
        loop {
            let pending: Vec<(String, String)> = {
                let map = self
                    .inner
                    .pending_link_terminal
                    .lock()
                    .expect("pending link terminal lock");
                map.keys().cloned().collect()
            };
            if pending.is_empty() {
                self.inner
                    .link_retry_running
                    .store(false, Ordering::Release);
                return;
            }
            for (parent_run_id, child_run_id) in &pending {
                if self.parent_reached_real_terminal(parent_run_id) {
                    // The parent is terminal: this live process cannot
                    // complete the link terminal (durable write rejects a
                    // terminal parent); drop the entry and let restart
                    // recovery reconcile it.
                    self.inner
                        .pending_link_terminal
                        .lock()
                        .expect("pending link terminal lock")
                        .remove(&(parent_run_id.clone(), child_run_id.clone()));
                    continue;
                }
                // Only advance once the child really carries a terminal —
                // NEVER write a terminal the child does not yet hold (a
                // `terminal_pending` child stays None and keeps waiting). The
                // DURABLE child run row is authoritative; the in-memory mirror
                // is only a fallback for in-memory-only mode.
                let Some(observed) = self.observed_link_terminal(child_run_id).await else {
                    continue;
                };
                if self
                    .write_link_state_durable(parent_run_id, child_run_id, &observed)
                    .await
                {
                    self.update_link_mirror_link(parent_run_id, child_run_id, &observed);
                    self.inner
                        .pending_link_terminal
                        .lock()
                        .expect("pending link terminal lock")
                        .remove(&(parent_run_id.clone(), child_run_id.clone()));
                }
            }
            if self.inner.halting.load(Ordering::Acquire) {
                // Service shutdown: the remaining entries are repaired by
                // restart recovery on the next open.
                self.inner
                    .link_retry_running
                    .store(false, Ordering::Release);
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[doc(hidden)]
    pub async fn update_child_link_state_for_test(
        &self,
        parent_run_id: &str,
        child_run_id: &str,
        state: &str,
    ) {
        self.update_child_link_state_native(parent_run_id, child_run_id, state)
            .await;
    }

    /// The parent status the subagent policy decides over: terminal statuses
    /// pass through, an in-flight cancellation is "cancelling", anything
    /// else is "active".
    fn parent_policy_status(&self, run_id: &str) -> String {
        let cancel_requested = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .is_some_and(|handle| handle.cancel.requested().is_some());
        let status = self
            .inner
            .store
            .read()
            .runs
            .get(run_id)
            .map(|run| run.status.clone())
            .unwrap_or_default();
        match status.as_str() {
            "completed" | "cancelled" | "failed" | "terminal_pending" => status,
            _ if cancel_requested => "cancelling".to_string(),
            _ => "active".to_string(),
        }
    }

    /// Spawns the parent-cancellation watcher: while the parent's
    /// `RunCancellation` is requested, the shared supervision cancel fires
    /// and every in-flight child's executor propagates it to the child's own
    /// cancellation. The watcher exits once `done` is set (the batch
    /// finished) or the parent cancels, so no per-handoff task leaks.
    fn spawn_parent_cancel_watcher(
        &self,
        run_id: &str,
        supervisor_cancel: &SupervisorCancel,
    ) -> (Arc<AtomicBool>, Option<tokio::task::JoinHandle<()>>) {
        let done = Arc::new(AtomicBool::new(false));
        let Some(parent_cancel) = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .map(|handle| handle.cancel.clone())
        else {
            return (done, None);
        };
        let watcher_cancel = supervisor_cancel.clone();
        let watcher_done = Arc::clone(&done);
        let watcher = tokio::spawn(async move {
            loop {
                if parent_cancel.requested().is_some() {
                    watcher_cancel.request();
                    return;
                }
                if watcher_done.load(Ordering::Acquire) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        (done, Some(watcher))
    }

    /// Executes a `parallel.handoff`: the parallel policy plans over the
    /// REAL parent/child context (windows, ordered slots, supervision
    /// mode), and the native supervisor drives N real child runs with
    /// bounded concurrency, ordered result slots, race/fail-fast sibling
    /// cancellation, parent-cancel propagation, and the remaining run
    /// deadline as the batch bound. The ordered typed results (or the
    /// policy's typed rejection — no child ever starts) become the
    /// `parallel_outcome` the loop folds.
    async fn execute_parallel_handoff(
        &self,
        run_id: &str,
        decision: &JsonValue,
        deadline: Instant,
    ) -> HandoffExec {
        if self.run_is_stopping(run_id) {
            return HandoffExec::Cancelled;
        }
        let Some(policies) = self.inner.policies.clone() else {
            return HandoffExec::Unavailable(
                "the A6 parallel policy program is not available".to_string(),
            );
        };
        // The parent-cancellation watcher is established BEFORE the policy
        // VM runs: a stop that lands during the policy evaluation requests
        // the shared supervision cancel, so no slot ever starts after it
        // (the batch engine checks the cancel before each child admission).
        let supervisor_cancel = SupervisorCancel::default();
        let (watcher_done, _watcher) = self.spawn_parent_cancel_watcher(run_id, &supervisor_cancel);
        // The cumulative fanout is the AUTHORITATIVE live child count under
        // this parent (the mirror accumulates across ALL batches of the
        // run), never the caller-declared `current_fanout`: multiple
        // parallel batches in one run cannot bypass max_fanout.
        let current_fanout = self.child_links_native(run_id).len() as i64;
        let context = json!({
            "parent_run_id": run_id,
            "batch": decision["batch"].clone(),
            "mode": decision["mode"].as_str().unwrap_or("all"),
            "max_concurrency": decision["max_concurrency"].as_i64().unwrap_or(1),
            "max_fanout": decision["max_fanout"].as_i64().unwrap_or(0),
            "current_fanout": current_fanout,
            "depth": decision["depth"].as_i64().unwrap_or(0),
            "max_depth": decision["max_depth"].as_i64().unwrap_or(0),
        });
        let Some(plan) = Self::run_policy(&policies.parallel, &context).await else {
            watcher_done.store(true, Ordering::Release);
            return HandoffExec::Unavailable(
                "the parallel policy could not be executed".to_string(),
            );
        };
        if plan["kind"] != "parallel.plan" {
            // The policy's typed rejection is folded back into the loop
            // state; nothing was ever admitted or started.
            watcher_done.store(true, Ordering::Release);
            return HandoffExec::Outcome(json!({
                "kind": "rejected",
                "code": plan["code"].as_str().unwrap_or("rejected"),
                "message": plan["message"].as_str().unwrap_or("the parallel batch was rejected"),
            }));
        }
        let cancel_rule = plan["supervision"]["cancel_rule"]
            .as_str()
            .unwrap_or("none");
        let mode = SupervisionMode::from_plan(Some(cancel_rule));
        let max_concurrency = plan["supervision"]["max_concurrency"]
            .as_i64()
            .unwrap_or(1)
            .max(1) as usize;
        let batch = decision["batch"].as_array().cloned().unwrap_or_default();
        let slots = plan["ordered_slots"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if slots.is_empty() {
            watcher_done.store(true, Ordering::Release);
            return HandoffExec::Outcome(json!({
                "kind": "executed",
                "results": [],
            }));
        }
        // Item 2 — parent-global batch identity: the per-batch slot index
        // must NEVER be reused across multiple parallel batches of the same
        // run as a child/slot/tool_call/idempotency identity.
        //
        // The parent-global ordinal base is NOT the live child-link COUNT
        // (`links.len()`): consumed ordinals are SPARSE — a slot that is
        // refused admission or cancelled before it starts still consumes its
        // ordinal (as its slot / tool_call / idempotency identity) but
        // creates NO `child_run_links` row, so the link count understates
        // the ordinals actually consumed. The base therefore comes from the
        // DURABLE parent-level ordinal allocator, which reserves this
        // batch's full range (`slots.len()`) atomically before any child
        // starts — the refused/cancelled slots' ordinals are durable
        // high-water and a later batch (or another gateway process, or a
        // restart) never reuses them. Without durable storage the base
        // falls back to the MAX ordinals of every live mirror link + 1
        // (never the count), the strongest invariant available offline.
        let ordinal_base = match self
            .allocate_parent_ordinals(run_id, "parallel", slots.len())
            .await
        {
            Ok(base) => base,
            Err(error) => {
                watcher_done.store(true, Ordering::Release);
                return HandoffExec::Unavailable(format!(
                    "parallel ordinal allocation failed: {error}"
                ));
            }
        };
        let mut specs = Vec::new();
        for slot in &slots {
            let index = slot["index"].as_i64().unwrap_or(0).max(0) as usize;
            let global_ordinal = (ordinal_base + index as i64).max(0) as usize;
            let item = batch.get(index).cloned().unwrap_or(JsonValue::Null);
            let proposed_id = item
                .get("id")
                .and_then(JsonValue::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| stable_slot_id(run_id, "parallel", global_ordinal));
            let input = item.get("input").cloned().unwrap_or(item);
            specs.push(ChildSpec {
                slot: global_ordinal,
                child_run_id: proposed_id,
                input,
            });
        }
        let executor = ServiceChildExecutor::new(self.clone(), run_id, "parallel");
        let (outcomes, _timed_out) = supervise_batch_bounded(
            &executor,
            &specs,
            mode,
            max_concurrency,
            &supervisor_cancel,
            deadline,
            self.inner.config.cancellation_grace,
        )
        .await;
        watcher_done.store(true, Ordering::Release);
        let admitted = executor.admitted_slot_ids();
        let results: Vec<JsonValue> = outcomes
            .iter()
            .enumerate()
            .map(|(local_index, outcome)| {
                // The result's identity uses the PARENT-GLOBAL ordinal (the
                // ChildSpec slot), never the local batch index: a later batch
                // never reuses a slot/tool_call/child identity.
                let slot = specs[local_index].slot;
                let real_id = admitted
                    .get(&slot)
                    .cloned()
                    .unwrap_or_else(|| specs[local_index].child_run_id.clone());
                let slot_id = stable_slot_id(run_id, "parallel", slot);
                let tool_call_id = stable_tool_call_id(run_id, "parallel", slot);
                match outcome {
                    ChildOutcome::Completed(output) => json!({
                        "slot": slot,
                        "slot_id": slot_id,
                        "tool_call_id": tool_call_id,
                        "child_run_id": real_id,
                        "status": "completed",
                        "output": output,
                    }),
                    ChildOutcome::Cancelled(reason) => json!({
                        "slot": slot,
                        "slot_id": slot_id,
                        "tool_call_id": tool_call_id,
                        "child_run_id": real_id,
                        "status": "cancelled",
                        "reason": reason,
                    }),
                    ChildOutcome::Failed(error) => json!({
                        "slot": slot,
                        "slot_id": slot_id,
                        "tool_call_id": tool_call_id,
                        "child_run_id": real_id,
                        "status": "failed",
                        "code": "child_run_failed",
                        "error": error,
                    }),
                }
            })
            .collect();
        HandoffExec::Outcome(json!({
            "kind": "executed",
            "results": results,
        }))
    }

    /// Executes a `subagent.handoff`: the subagent policy decides admission
    /// over the REAL parent state (parent link count, children, depth/fanout
    /// budgets, parent status). An admission becomes a real child run
    /// through AgentService (parent link, isolated session, worker actually
    /// spawned before `subagent.started`), awaited to its durable terminal
    /// (`subagent.completed`), and the typed child outcome is folded back.
    /// A refused/rejected admission never starts anything; a parent
    /// cancellation propagates to the listed children.
    async fn execute_subagent_handoff(
        &self,
        run_id: &str,
        decision: &JsonValue,
        deadline: Instant,
    ) -> HandoffExec {
        if self.run_is_stopping(run_id) {
            return HandoffExec::Cancelled;
        }
        let Some(policies) = self.inner.policies.clone() else {
            return HandoffExec::Unavailable(
                "the A6 subagent policy program is not available".to_string(),
            );
        };
        // The parent-cancellation watcher is established BEFORE the policy
        // VM runs (a stop during the policy evaluation must already be
        // observed by the shared supervision cancel — no admission starts
        // after a stop).
        let supervisor_cancel = SupervisorCancel::default();
        let (watcher_done, _watcher) = self.spawn_parent_cancel_watcher(run_id, &supervisor_cancel);
        let links = self.child_links_native(run_id);
        let children: Vec<JsonValue> = links
            .iter()
            .map(|link| json!({"child_run_id": link.child_run_id, "state": link.state}))
            .collect();
        let context = json!({
            "parent_run_id": run_id,
            "child": decision["child"].clone(),
            "depth": decision["depth"].as_i64().unwrap_or(0),
            "max_depth": decision["max_depth"].as_i64().unwrap_or(0),
            "current_fanout": links.len() as i64,
            "max_fanout": decision["max_fanout"].as_i64().unwrap_or(0),
            "parent_status": self.parent_policy_status(run_id),
            "children": children,
        });
        let Some(policy_decision) = Self::run_policy(&policies.subagent, &context).await else {
            watcher_done.store(true, Ordering::Release);
            return HandoffExec::Unavailable(
                "the subagent policy could not be executed".to_string(),
            );
        };
        match policy_decision["kind"].as_str() {
            Some("subagent.rejected") => {
                watcher_done.store(true, Ordering::Release);
                HandoffExec::Outcome(json!({
                    "kind": "rejected",
                    "code": policy_decision["code"].as_str().unwrap_or("rejected"),
                    "message": policy_decision["message"].as_str().unwrap_or("the child admission was rejected"),
                }))
            }
            Some("subagent.cancel") => {
                // Parent-cancellation propagation decided by the policy: the
                // listed pending/active children are cancelled (terminal
                // children are never listed).
                if let Some(ids) = policy_decision["child_run_ids"].as_array() {
                    for id in ids {
                        if let Some(child_id) = id.as_str()
                            && let Some(handle) = self.handle(child_id)
                        {
                            handle.cancel.request(CancellationReason::Requested);
                        }
                    }
                }
                watcher_done.store(true, Ordering::Release);
                HandoffExec::Outcome(json!({
                    "kind": "cancelled",
                    "child_run_ids": policy_decision["child_run_ids"].clone(),
                    "reason": policy_decision["reason"].as_str().unwrap_or("parent_cancelled"),
                }))
            }
            Some("subagent.admit") => {
                let ordinal = policy_decision["ordinal"]
                    .as_i64()
                    .unwrap_or(links.len() as i64);
                let proposed_id = policy_decision["child_run_id"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| stable_slot_id(run_id, "subagent", ordinal.max(0) as usize));
                let child = decision["child"].clone();
                let input = child.get("input").cloned().unwrap_or(child);
                let spec = ChildSpec {
                    slot: ordinal.max(0) as usize,
                    child_run_id: proposed_id,
                    input,
                };
                let executor = ServiceChildExecutor::new(self.clone(), run_id, "subagent");
                let (outcomes, _timed_out) = supervise_batch_bounded(
                    &executor,
                    std::slice::from_ref(&spec),
                    SupervisionMode::All,
                    1,
                    &supervisor_cancel,
                    deadline,
                    self.inner.config.cancellation_grace,
                )
                .await;
                watcher_done.store(true, Ordering::Release);
                let admitted = executor.admitted_slot_ids();
                let slot = ordinal.max(0) as usize;
                let real_id = admitted
                    .get(&slot)
                    .cloned()
                    .unwrap_or_else(|| spec.child_run_id.clone());
                let child_session_id = executor
                    .admitted_sessions()
                    .get(&slot)
                    .cloned()
                    .unwrap_or_default();
                let slot_id = stable_slot_id(run_id, "subagent", slot);
                let tool_call_id = stable_tool_call_id(run_id, "subagent", slot);
                let outcome = match outcomes
                    .into_iter()
                    .next()
                    .unwrap_or(ChildOutcome::Cancelled("batch_terminated".to_string()))
                {
                    ChildOutcome::Completed(output) => json!({
                        "kind": "executed",
                        "slot_id": slot_id,
                        "tool_call_id": tool_call_id,
                        "child_run_id": real_id,
                        "session_id": child_session_id,
                        "status": "completed",
                        "output": output,
                    }),
                    ChildOutcome::Cancelled(reason) => json!({
                        "kind": "executed",
                        "slot_id": slot_id,
                        "tool_call_id": tool_call_id,
                        "child_run_id": real_id,
                        "session_id": child_session_id,
                        "status": "cancelled",
                        "reason": reason,
                    }),
                    ChildOutcome::Failed(error) => json!({
                        "kind": "executed",
                        "slot_id": slot_id,
                        "tool_call_id": tool_call_id,
                        "child_run_id": real_id,
                        "session_id": child_session_id,
                        "status": "failed",
                        "code": "child_run_failed",
                        "error": error,
                    }),
                };
                HandoffExec::Outcome(outcome)
            }
            _ => {
                watcher_done.store(true, Ordering::Release);
                HandoffExec::Unavailable(
                    "the subagent policy returned an unrecognized decision".to_string(),
                )
            }
        }
    }

    /// The typed rejection outcome for a natively-denied delegation, or
    /// `None` when the native policy allows it. `ApprovalBridge::decide` is
    /// the native authority: a `Denied { native: true }` cannot be relaxed
    /// by any RSS approval mode. The RSS approval policy only ever saw the
    /// config bool; the bridge's tool/risk deny policy is consulted HERE at
    /// the native execution boundary (delegation is risk class `execute`).
    fn native_deny_rejection(&self, tool_name: &str) -> Option<JsonValue> {
        if self
            .inner
            .native_deny
            .denies_all(tool_name, RiskClass::Execute)
        {
            Some(json!({
                "kind": "rejected",
                "code": "approval_denied",
                "message": format!("native policy denies {} ({})", tool_name, RiskClass::Execute.as_str()),
            }))
        } else {
            None
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

    /// Selects the durable resolver for an abandoned approval. An explicit
    /// gateway cancellation reason wins over the generic cancellation token:
    /// the latter is also used for deadline cancellation and must not be
    /// mislabeled as a gateway stop.
    fn approval_cancel_resolver(&self, run_id: &str) -> &'static str {
        let has_gateway_reason = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .is_some_and(|handle| {
                handle
                    .cancel_reason
                    .lock()
                    .expect("cancel reason lock")
                    .is_some()
            });
        if has_gateway_reason
            || self
                .inner
                .store
                .read()
                .runs
                .get(run_id)
                .is_some_and(|run| run.status == "stopping")
        {
            "gateway-stop"
        } else {
            "deadline-compensation"
        }
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
    #[doc(hidden)]
    pub async fn park_for_approval_for_test(
        &self,
        run_id: &str,
        decision: &JsonValue,
        deadline: Instant,
    ) -> &'static str {
        match self
            .park_for_approval(run_id, &JsonValue::Null, decision, deadline)
            .await
        {
            ParkOutcome::Parked => "parked",
            ParkOutcome::Cancelled => "cancelled",
            ParkOutcome::Failed => "failed",
        }
    }

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
        // The request succeeded, so every exit from this point owns exactly
        // one compensation. Deadline and stop are checked together after the
        // blocking round trip; either race must cancel the durable row before
        // returning without a park.
        if self.run_is_stopping(run_id)
            || deadline.saturating_duration_since(Instant::now()).is_zero()
        {
            let _ = self.cancel_abandoned_approval(run_id, &approval_id).await;
            return ParkOutcome::Cancelled;
        }
        if !self
            .transition_run(run_id, "running", "waiting_approval")
            .await
        {
            let _ = self.cancel_abandoned_approval(run_id, &approval_id).await;
            return if self.run_is_stopping(run_id) {
                ParkOutcome::Cancelled
            } else {
                ParkOutcome::Failed
            };
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
            let _ = self.cancel_abandoned_approval(run_id, &approval_id).await;
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
            let stopping = self.run_is_stopping(run_id);
            let _ = self
                .transition_run(run_id, "waiting_approval", "running")
                .await;
            let _ = self.cancel_abandoned_approval(run_id, &approval_id).await;
            return if stopping {
                ParkOutcome::Cancelled
            } else {
                ParkOutcome::Failed
            };
        }
        if self.run_is_stopping(run_id)
            || deadline.saturating_duration_since(Instant::now()).is_zero()
        {
            self.inner
                .parked
                .lock()
                .expect("parked lock")
                .remove(run_id);
            let _ = self
                .transition_run(run_id, "waiting_approval", "running")
                .await;
            let _ = self.cancel_abandoned_approval(run_id, &approval_id).await;
            return ParkOutcome::Cancelled;
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
        let cell = {
            let mut cancellations = self
                .inner
                .approval_cancellations
                .lock()
                .expect("approval cancellation lock");
            cancellations
                .entry(approval_id.to_string())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };
        let run_id = run_id.to_string();
        let approval_id = approval_id.to_string();
        // The key is cloned for the completion-removal below (the closure
        // consumes its own copy).
        let completion_key = approval_id.clone();
        let result = cell
            .get_or_init(|| async move {
                let run_id_for_block = run_id;
                let approval_id_for_block = approval_id;
                // A cancellation racing the park can enter this shared
                // once-cell from either the gateway stop path or the
                // deadline/failed-request compensation path. Resolve the
                // reason from the live run state at the point the
                // cancellation is committed so a stop is never recorded as
                // deadline compensation merely because the callers raced.
                let service_for_reason = self.clone();
                let resolver = service_for_reason.approval_cancel_resolver(&run_id_for_block);
                tokio::task::spawn_blocking(move || {
                    let now = timestamp() as i64;
                    match bridge.cancel(&approval_id_for_block, resolver, now) {
                        Ok(affected) => {
                            if affected > 0 {
                                tracing::info!(
                                    run_id = %run_id_for_block,
                                    approval_id = %approval_id_for_block,
                                    "abandoned approval durably cancelled"
                                );
                            }
                            Ok(())
                        }
                        Err(error) => Err(format!("approval.cancel failed: {error}")),
                    }
                })
                .await
                .map_err(|error| format!("approval cancel worker failed: {error}"))?
            })
            .await;
        // The once-cell de-duplicates concurrent stop/deadline compensation
        // races. Once the attempt completes, the entry is REMOVED so (a) a
        // FAILED cancellation is NOT permanently cached — the next retry (the
        // janitor sweep, a re-entered stop path) genuinely re-attempts the
        // durable cancel instead of re-reading the stale error — and (b) the
        // map stays bounded by in-flight cancellations, never leaking one
        // entry per abandoned approval forever. Removing an entry while a
        // concurrent caller still holds the cloned cell is safe: the caller
        // observes this attempt's result, and a later caller starts fresh.
        self.inner
            .approval_cancellations
            .lock()
            .expect("approval cancellation lock")
            .remove(&completion_key);
        result.clone()
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
            if is_terminal_status(run.status.as_str()) || run.status == "stopping" {
                return Err("the run already reached a terminal or is stopping".to_string());
            }
            let previous_events = run.events.clone();
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
                    run.events = previous_events;
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
            if is_terminal_status(run.status.as_str()) || run.status == "stopping" {
                // P2-4: a stop that landed before this closure ran (the
                // park-insert re-check is the primary guard; this status
                // check closes the last microsecond of the race) must never
                // see a post-stop approval.required event.
                return Err("the run already reached a terminal or is stopping".to_string());
            }
            let previous_events = run.events.clone();
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
                    run.events = previous_events;
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
    ///
    /// Legacy service surface (the expiry sweep and the A5 fixtures): the
    /// resolution outcome is mapped to `Ok(())` / a legacy `String` error.
    /// The API surface uses [`Self::resolve_run_approval_for`], which carries
    /// the run + approval id, actor/reason, and the typed outcome/error; the
    /// Telegram surface uses [`Self::resolve_run_approval_as`] with the
    /// sending user as the actor and the source message as the reason. All
    /// three surfaces share the exact-once core [`Self::resolve_parked_approval`].
    pub fn resolve_run_approval(&self, run_id: &str, approve: bool) -> Result<(), String> {
        self.resolve_run_approval_as(run_id, approve, "gateway", "")
    }

    /// The API approval surface: resolves the parked run's approval by run +
    /// approval id (a mismatch is a typed error and never consumes the park),
    /// records the caller's `actor`/`reason` on the durable row, and returns
    /// the typed outcome so the HTTP layer can surface exact-once /
    /// AlreadyResolved / expired states without string matching. See
    /// [`Self::resolve_run_approval`] for the exact-once and park-restore
    /// semantics (shared implementation).
    pub fn resolve_run_approval_for(
        &self,
        run_id: &str,
        approval_id: &str,
        approve: bool,
        actor: &str,
        reason: &str,
    ) -> Result<ApprovalResolveOutcome, ApprovalResolveError> {
        self.resolve_parked_approval(run_id, Some(approval_id), approve, actor, reason)
    }

    /// The Telegram approval surface: resolves the parked run's approval
    /// with the sending user as the durable actor and the source message as
    /// the reason (an empty reason keeps the default resolver text). The
    /// typed outcome is mapped to the legacy `String` surface so the
    /// Telegram matchers see the same "already resolved" / "no pending
    /// approval is parked" / "bridge is not available" texts.
    pub fn resolve_run_approval_as(
        &self,
        run_id: &str,
        approve: bool,
        actor: &str,
        reason: &str,
    ) -> Result<(), String> {
        match self.resolve_parked_approval(run_id, None, approve, actor, reason) {
            Ok(_) => Ok(()),
            Err(error) => Err(error.legacy_message()),
        }
    }

    /// The shared exact-once resolution core. `expected_approval_id` is the
    /// API's id check (the legacy and Telegram surfaces pass `None`);
    /// `resolver` / `reason` are recorded on the durable row (the legacy
    /// surface passes `"gateway"` / `""`, byte-identical to the previous
    /// payloads).
    fn resolve_parked_approval(
        &self,
        run_id: &str,
        expected_approval_id: Option<&str>,
        approve: bool,
        resolver: &str,
        reason: &str,
    ) -> Result<ApprovalResolveOutcome, ApprovalResolveError> {
        // A run that is not parked must report NoPendingApproval regardless of
        // program availability (the 404/409 contract). Peek first.
        let pending_absent = self
            .inner
            .parked
            .lock()
            .expect("parked lock")
            .get(run_id)
            .is_none();
        if pending_absent {
            return Err(ApprovalResolveError::NoPendingApproval);
        }
        // Program availability is checked BEFORE the park is consumed. A
        // resolution must never eat the park (and leave the run durably
        // `running` with no worker) merely because the resume program is
        // missing; the park is restored so a later resume stays reachable.
        let program = match self.inner.agent_program.clone() {
            Some(program) => program,
            None => return Err(ApprovalResolveError::ProgramUnavailable),
        };
        let parked = self
            .inner
            .parked
            .lock()
            .expect("parked lock")
            .remove(run_id)
            .ok_or(ApprovalResolveError::NoPendingApproval)?;
        if let Some(expected) = expected_approval_id
            && parked.approval_id != expected
        {
            // The caller addressed a different approval than the one this run
            // is parked on: restore the park untouched (a mismatch must never
            // consume or resolve anything).
            self.restore_park_if_active(run_id, &parked);
            return Err(ApprovalResolveError::ApprovalIdMismatch);
        }
        let Some(bridge) = self.inner.approval.clone() else {
            self.restore_park_if_active(run_id, &parked);
            return Err(ApprovalResolveError::BridgeUnavailable);
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
                let resolution = match bridge.resolve_with_reason(
                    &parked.approval_id,
                    approve,
                    resolver,
                    reason,
                    now,
                ) {
                    Ok(resolution) => resolution,
                    Err(error) => {
                        // A storage failure must not consume the park:
                        // restore it so the caller (or the sweep) can
                        // retry.
                        self.restore_park_if_active(run_id, &parked);
                        return Err(ApprovalResolveError::Storage(error.to_string()));
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
                        return Err(ApprovalResolveError::AlreadyResolved);
                    }
                }
            }
        };
        // The run must transition durably back to `running` before the
        // resume. An AMBIGUOUS failure of that transition — a park that has
        // ALREADY recorded a durable resolution (a prior attempt resolved the
        // bridge, then lost) whose durable status is already `running` — is a
        // resolved resume: recover from the durable current state instead of
        // repeatedly re-trying `waiting_approval -> running` and never drop
        // the park while the run is actually running. A fresh attempt with no
        // recorded resolution and an externally-moved `running` status stays
        // a typed error (legacy exact semantics): only the ambiguous-retry
        // path recovers.
        let transitioned = self.transition_run_blocking(run_id, "waiting_approval", "running")
            || (parked.resolution.is_some()
                && self.durable_run_status(run_id).as_deref() == Some("running"));
        if !transitioned {
            // The run may have moved to a terminal (a stop or a concurrent
            // terminal): only restore the park while the run is still an
            // active, un-cancelled candidate — otherwise the run is on its
            // way to a terminal and re-parking would wedge it. The restored
            // park CARRIES the durable outcome so a retry resumes with the
            // same decision.
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
            return Err(ApprovalResolveError::RunNotActive);
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
        let base_context = json_to_vm_value(&parked.base_context);
        let deadline = parked.deadline;
        // The typed outcome is computed BEFORE the resume spawn (the spawn
        // consumes the loop-facing state strings).
        let outcome_enum = if resolved {
            ApprovalResolveOutcome::Resumed {
                approved: outcome == "approved",
            }
        } else if outcome == "denied" {
            // A fresh deny transitioned the row and the run resumes with the
            // typed denied outcome.
            ApprovalResolveOutcome::Resumed { approved: false }
        } else {
            // A deny (or the sweep) landed on an already-terminal row: the
            // run resumes with the typed terminal code (`expired`).
            ApprovalResolveOutcome::Terminal {
                code: outcome.clone(),
            }
        };
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
        Ok(outcome_enum)
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

    /// Reads the DURABLE current status of one run (`run.get`), so an
    /// ambiguous lifecycle transition can be recovered from the authoritative
    /// on-disk state instead of the command's ambiguous success indicator.
    /// `None` when there is no durable store (in-memory mode) or the read
    /// fails (the caller then conservatively treats the transition as not
    /// having landed).
    fn durable_run_status(&self, run_id: &str) -> Option<String> {
        let persistence = self.inner.persistence.as_ref()?;
        let value = persistence.run_get(run_id).ok()?;
        let row = value.get("rows")?.as_array()?.first()?.as_array()?;
        row.get(3).and_then(JsonValue::as_str).map(str::to_string)
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

    /// Bounded durable retention sweep for TERMINAL runs: deletes terminal
    /// runs (completed/failed/cancelled) whose durable `updated_at_ms` is
    /// older than the configured [`AgentGatewayConfig::durable_run_retention`]
    /// window, through the typed `runs.prune_terminal` RSS command. Active,
    /// pending, and `terminal_pending` runs are never matched, so restart
    /// replay and the terminal retry loop stay intact. Runs on a blocking
    /// worker so Tokio threads are never occupied by storage stalls.
    fn prune_durable_terminal_runs(&self) {
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            let Some(persistence) = service.inner.persistence.clone() else {
                return;
            };
            let now = timestamp() as i64;
            let older_than_ms = now - service.inner.config.durable_run_retention.as_millis() as i64;
            let pending_nonempty = !service
                .inner
                .pending
                .lock()
                .expect("pending lock")
                .is_empty();
            if pending_nonempty {
                // A pending/terminal_pending run may still have a durable
                // terminal row after a crash-window race. Defer the sweep
                // while any such entry exists; this keeps the SQL candidate
                // set from deleting an ambiguous run.
                return;
            }
            let result = match persistence.runs_prune_terminal(older_than_ms, 64) {
                Ok(result) => result,
                Err(error) => {
                    tracing::warn!(
                        error = %truncate_for_log(&error.to_string(), 256),
                        "durable terminal retention sweep failed; runs will be reclaimed on the next tick"
                    );
                    return;
                }
            };
            // The storage command returns the exact ordered candidate set it
            // deleted.  Mirror that set under the store lock so a retained
            // terminal can never remain addressable in memory after durable
            // GC.  Pending terminals are protected even if a future storage
            // migration represents their state as a terminal row.
            let ids = result
                .get("rows")
                .and_then(JsonValue::as_array)
                .into_iter()
                .flatten()
                .filter_map(|row| row.as_array())
                .filter_map(|row| row.first().and_then(JsonValue::as_str))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if ids.is_empty() {
                return;
            }
            let mut store = service.inner.store.write();
            let mut removable = Vec::new();
            for run_id in ids {
                if service
                    .inner
                    .pending
                    .lock()
                    .expect("pending lock")
                    .contains_key(&run_id)
                {
                    continue;
                }
                if let Some(mut run) = store.runs.remove(&run_id) {
                    // Explicitly close the sender before dropping the record;
                    // existing subscribers observe Closed instead of waiting
                    // on an orphaned channel.
                    run.sender = None;
                    removable.push(run_id);
                } else {
                    removable.push(run_id);
                }
            }
            if !removable.is_empty() {
                store
                    .idempotency
                    .retain(|_, record| !removable.iter().any(|id| id == &record.run_id));
            }
            drop(store);
            let mut handles = service.inner.runs.lock().expect("runs lock");
            for run_id in removable {
                handles.remove(&run_id);
            }
        });
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

/// The canonical zero usage shape: transports without provider-reported
/// usage (the legacy single-shot path) commit exactly this shape — never a
/// fabricated nonzero number.
fn empty_usage_json() -> JsonValue {
    json!({"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})
}

/// Normalizes one canonical usage map (`{input_tokens, output_tokens,
/// total_tokens}` from the loop's provider round) into the durable terminal
/// shape; missing/unknown entries fall back to zero.
fn canonical_usage_json(usage: &JsonValue) -> JsonValue {
    json!({
        "input_tokens": usage["input_tokens"].as_u64().unwrap_or(0),
        "output_tokens": usage["output_tokens"].as_u64().unwrap_or(0),
        "total_tokens": usage["total_tokens"].as_u64().unwrap_or(0),
    })
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
            if std::time::Instant::now() >= pending.deadline && !pending.expired_fallback {
                // The original terminal retry budget is exhausted. Convert it
                // into a durable failure marker and keep retrying that marker
                // until storage recovers; closing the sender here would leave
                // the durable run running with no typed SSE outcome.
                let next_seq = run.events.last().map_or(1, |event| event.seq + 1);
                let expired_event = GatewayEvent {
                    event_id: Uuid::new_v4().to_string(),
                    seq: next_seq,
                    event: "run.failed".to_string(),
                    run_id: run.run_id.clone(),
                    timestamp: timestamp(),
                    data: json!({
                        "status": "failed",
                        "error_code": "terminal_retry_expired",
                        "error_message": "durable terminal retry window expired"
                    }),
                };
                let expired_pending = PendingTerminal {
                    to_status: "failed".to_string(),
                    session_id: None,
                    events: vec![expired_event],
                    assistant_message: None,
                    deadline: std::time::Instant::now(),
                    expired_fallback: true,
                    kind: PendingTerminalKind::RunTerminal,
                };
                service.put_pending_terminal(&run_id_for_block, expired_pending);
                service
                    .inner
                    .metrics
                    .terminal_retry(TerminalRetryOutcome::Expired);
                tracing::warn!(
                    run_id = %run_id_for_block,
                    "terminal retry window expired; durable terminal-expiry marker will be retried"
                );
                return PendingRetryOutcome::RetryFailed;
            }
            // Maintenance-run terminals commit through the durable-first
            // compensation (run.transition + event.append + best-effort
            // compaction.fail), not the `run.terminal` transaction: the A2
            // maintenance lifecycle is queued/running/compacting and
            // `run.terminal` only accepts `running` runs.
            if matches!(pending.kind, PendingTerminalKind::Maintenance { .. }) {
                let deadline = pending.deadline;
                let PendingTerminalKind::Maintenance {
                    from_status,
                    error_code,
                    error_message,
                    fail_payload,
                    transition_landed,
                    event_landed,
                } = pending.kind
                else {
                    unreachable!("kind was checked above");
                };
                let mut writes = MaintenanceTerminalWrites {
                    run_id: run_id_for_block.clone(),
                    from_status,
                    error_code,
                    error_message,
                    completed_event: pending.events.first().cloned(),
                    fail_payload,
                    transition_landed,
                    event_landed,
                    to_status: pending.to_status.clone(),
                };
                let landed = persistence.as_deref().is_some_and(|persistence| {
                    service
                        .maintenance_terminal_once(persistence, &mut writes)
                        .is_ok()
                });
                if landed {
                    // Mirror the terminal: the status plus the completed
                    // event exactly once (durable-before-visible).
                    if let Some(run) = store.runs.get_mut(&run_id_for_block) {
                        run.status = writes.to_status.clone();
                        if let Some(event) = &writes.completed_event
                            && !run
                                .events
                                .iter()
                                .any(|candidate| candidate.event_id == event.event_id)
                        {
                            run.events.push(GatewayEvent {
                                seq: (run.events.len() + 1) as u64,
                                ..event.clone()
                            });
                        }
                    }
                    service
                        .inner
                        .metrics
                        .terminal_retry(TerminalRetryOutcome::Committed);
                    tracing::info!(
                        run_id = %run_id_for_block,
                        status = %writes.to_status,
                        "maintenance run terminal committed durably by the bounded retry"
                    );
                    return PendingRetryOutcome::Committed;
                }
                // Storage is still down: reflect the writes that landed and
                // retry on the next janitor tick (the original deadline
                // bounds the window).
                service.put_pending_terminal(
                    &run_id_for_block,
                    PendingTerminal {
                        to_status: writes.to_status,
                        session_id: None,
                        events: writes.completed_event.into_iter().collect(),
                        assistant_message: None,
                        deadline,
                        expired_fallback: false,
                        kind: PendingTerminalKind::Maintenance {
                            from_status: writes.from_status,
                            error_code: writes.error_code,
                            error_message: writes.error_message,
                            fail_payload: writes.fail_payload,
                            transition_landed: writes.transition_landed,
                            event_landed: writes.event_landed,
                        },
                    },
                );
                service
                    .inner
                    .metrics
                    .terminal_retry(TerminalRetryOutcome::RetryFailed);
                return PendingRetryOutcome::RetryFailed;
            }
            let previous_status = run.status.clone();
            let previous_events = run.events.clone();
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
                Ok(durable_events) => {
                    let run = store
                        .runs
                        .get_mut(&run_id_for_block)
                        .expect("run presence was checked above");
                    // Publish only the rows returned by durable storage; the
                    // prebuilt in-memory events are never used as evidence of
                    // a successful terminal.
                    if let Some(sender) = &run.sender {
                        for event in durable_events {
                            let _ = sender.send(event);
                        }
                    }
                    // The terminal is committed and published: close the
                    // broadcast sender so subscribers observe Closed and
                    // new subscribers replay history and end.
                    close_run_stream(run);
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
                    | PendingRetryOutcome::Conflict => return,
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

fn terminal_commit_task_cancelled(
    run_id: &str,
    retry_window: std::time::Duration,
    error: String,
) -> TerminalOutcome {
    let event = GatewayEvent {
        event_id: Uuid::new_v4().to_string(),
        seq: 0,
        event: "run.failed".to_string(),
        run_id: run_id.to_string(),
        timestamp: timestamp(),
        data: json!({
            "status": "failed",
            "error_code": "terminal_commit_task_cancelled",
            "error_message": error,
        }),
    };
    TerminalOutcome::TerminalPersistFailed {
        error: "terminal commit task was cancelled".to_string(),
        pending: Box::new(PendingTerminal {
            to_status: "failed".to_string(),
            session_id: None,
            events: vec![event],
            assistant_message: None,
            deadline: std::time::Instant::now() + retry_window,
            expired_fallback: false,
            kind: PendingTerminalKind::RunTerminal,
        }),
    }
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
) -> Result<Vec<GatewayEvent>, TerminalCommitError> {
    let Some(persistence) = persistence else {
        return Ok(events.iter().map(|event| (*event).clone()).collect());
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
    // transactionally allocated durable sequences returned by the command.
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
    let mut durable_events = Vec::with_capacity(event_count);
    for (index, expected) in events.iter().enumerate() {
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
        let durable_run_id = row.get(1).and_then(JsonValue::as_str).unwrap_or("");
        let durable_event_id = row.get(2).and_then(JsonValue::as_str).unwrap_or("");
        let durable_event_type = row.get(3).and_then(JsonValue::as_str).unwrap_or("");
        if durable_run_id != run.run_id
            || durable_event_id != expected.event_id
            || durable_event_type != expected.event
        {
            return Err(TerminalCommitError {
                code: "terminal_commit_invalid".to_string(),
                message: format!(
                    "durable event row disagreed with the pre-generated terminal id/type: run={durable_run_id} id={durable_event_id} type={durable_event_type}"
                ),
            });
        }
        let payload = row
            .get(4)
            .and_then(JsonValue::as_str)
            .and_then(|payload| serde_json::from_str::<JsonValue>(payload).ok())
            .ok_or_else(|| TerminalCommitError {
                code: "terminal_commit_invalid".to_string(),
                message: "run.terminal returned a malformed event payload".to_string(),
            })?;
        let created_at = row.get(5).and_then(JsonValue::as_u64).unwrap_or_default();
        durable_events.push(GatewayEvent {
            event_id: durable_event_id.to_string(),
            seq,
            run_id: run.run_id.clone(),
            event: durable_event_type.to_string(),
            data: payload,
            timestamp: created_at,
        });
    }
    if let Some(expected_message) = assistant_message {
        let message_row = data
            .get("message")
            .and_then(|message| message.get("rows"))
            .and_then(JsonValue::as_array)
            .and_then(|rows| rows.first())
            .and_then(JsonValue::as_array)
            .ok_or_else(|| TerminalCommitError {
                code: "terminal_commit_invalid".to_string(),
                message: "run.terminal result omitted the assistant message row".to_string(),
            })?;
        let durable_message_id = message_row
            .first()
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let durable_session_id = message_row.get(1).and_then(JsonValue::as_str).unwrap_or("");
        let durable_message_run_id = message_row
            .get(11)
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if durable_message_id != expected_message.id
            || durable_session_id != session_id
            || durable_message_run_id != run.run_id
        {
            return Err(TerminalCommitError {
                code: "terminal_commit_invalid".to_string(),
                message:
                    "durable assistant message row disagreed with the pre-generated ownership tuple"
                        .to_string(),
            });
        }
    }
    for durable in &durable_events {
        if let Some(in_memory) = run
            .events
            .iter_mut()
            .find(|candidate| candidate.event_id == durable.event_id)
        {
            *in_memory = durable.clone();
        }
    }
    Ok(durable_events)
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
    previous_events: Vec<GatewayEvent>,
    previous_session_updated: Option<u64>,
) {
    if let Some(run) = store.runs.get_mut(run_id) {
        run.status = previous_status;
        run.events = previous_events;
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
            let mut expired_pending_runs = Vec::new();
            let mut runs = inner.runs.lock().expect("runs lock");
            runs.retain(|run_id, handle| {
                let keep = handle
                    .terminal_at
                    .lock()
                    .expect("terminal lock")
                    .is_none_or(|terminal_at| terminal_at + ttl > now);
                if !keep && handle.subscribers.lock().expect("subscriber lock").count == 0 {
                    expired_pending_runs.push(run_id.clone());
                    false
                } else {
                    true
                }
            });
            drop(runs);
            if !expired_pending_runs.is_empty() {
                let mut store = inner.store.write();
                for run_id in expired_pending_runs {
                    if let Some(run) = store.runs.get_mut(&run_id)
                        && run.status == "terminal_pending"
                    {
                        // No live subscriber remains. Close this stale
                        // sender so a later replay request cannot hang while
                        // the durable expiry fallback keeps retrying.
                        run.sender = None;
                    }
                }
            }
            // The bounded durable retention sweep: terminal runs older
            // than the configured window are deleted durably (active and
            // pending runs are never matched).
            let service = AgentService {
                inner: Arc::clone(&inner),
            };
            service.prune_durable_terminal_runs();
            // The bounded approval expiry sweep: parked runs whose durable
            // approval passed its deadline resume with a typed expired tool
            // result (the loop folds it and continues).
            service.expire_parked_approvals();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::store::RunView;

    #[test]
    fn canonical_child_input_preserves_json_shapes() {
        assert_eq!(
            canonical_input_value(r#"{"opaque":{"n":7}}"#),
            json!({"opaque":{"n":7}})
        );
        assert_eq!(canonical_input_value(r#"[1,{"n":7}]"#), json!([1,{"n":7}]));
        assert_eq!(
            canonical_input_value("plain user text"),
            json!("plain user text")
        );
    }

    #[test]
    fn missing_child_slot_ids_are_stable_and_non_empty() {
        let first = stable_slot_id("parent", "parallel", 3);
        let second = stable_slot_id("parent", "parallel", 3);
        assert!(!first.is_empty());
        assert_eq!(first, second);
        assert!(!stable_tool_call_id("parent", "parallel", 3).is_empty());
    }

    /// Item 2 — parallel multi-batch identity: distinct parent-global slot
    /// ordinals (base + batch index) must never collide across batches of
    /// the same run, so child/slot/tool_call/idempotency identities are
    /// never reused.
    #[test]
    fn parallel_slot_identities_are_distinct_across_batches() {
        let parent = "run-1";
        // Batch 1 (base 0): slots 0..1. Batch 2 (base 2): slots 2..3.
        let mut seen = std::collections::HashSet::new();
        for base in [0_i64, 2_i64] {
            for index in 0..2_usize {
                let ordinal = (base + index as i64) as usize;
                let slot_id = stable_slot_id(parent, "parallel", ordinal);
                let tool_call_id = stable_tool_call_id(parent, "parallel", ordinal);
                assert!(
                    seen.insert(slot_id.clone()),
                    "slot id must never be reused across batches: {slot_id}"
                );
                assert!(
                    seen.insert(tool_call_id.clone()),
                    "tool_call id must never be reused across batches: {tool_call_id}"
                );
            }
        }
        // The parent-global ordering is monotonic within and across batches.
        assert_ne!(
            stable_slot_id(parent, "parallel", 1),
            stable_slot_id(parent, "parallel", 2),
            "global ordinal must be distinct across the batch boundary"
        );
    }

    /// Item 4 — compensation link ordering: the observed link state for a
    /// child still `terminal_pending` (durable terminal not yet committed)
    /// must be None, so the compensation watcher keeps waiting instead of
    /// writing a terminal link before the child's durable terminal.
    fn observed_link_state_for_mirror(mirror: &GatewayStore, child_run_id: &str) -> Option<String> {
        let status = mirror
            .runs
            .get(child_run_id)
            .map(|run| run.status.clone())
            .unwrap_or_default();
        match status.as_str() {
            "completed" | "failed" | "cancelled" => Some(status),
            _ => None,
        }
    }

    #[test]
    fn observed_link_state_is_none_until_real_durable_terminal() {
        let mut store = GatewayStore::default();
        store.runs.insert(
            "child".to_string(),
            RunRecord {
                run_id: "child".to_string(),
                session_id: "s".to_string(),
                parent_run_id: None,
                request_overrides: JsonValue::Object(Default::default()),
                platform: "test".to_string(),
                input: JsonValue::Null,
                status: "terminal_pending".to_string(),
                events: Vec::new(),
                sender: None,
                cancel_requested: Arc::new(AtomicBool::new(false)),
            },
        );
        assert_eq!(
            observed_link_state_for_mirror(&store, "child"),
            None,
            "terminal_pending must never advance the link to a terminal"
        );
        store.runs.get_mut("child").expect("child").status = "completed".to_string();
        assert_eq!(
            observed_link_state_for_mirror(&store, "child"),
            Some("completed".to_string())
        );
    }

    #[test]
    fn pending_retry_rollback_restores_events_removed_by_retention() {
        let mut store = GatewayStore::default();
        store.runs.insert(
            "run-1".to_string(),
            RunRecord {
                run_id: "run-1".to_string(),
                session_id: "session-1".to_string(),
                parent_run_id: None,
                request_overrides: JsonValue::Object(Default::default()),
                platform: "test".to_string(),
                input: JsonValue::Null,
                status: "terminal_pending".to_string(),
                events: vec![GatewayEvent {
                    event_id: "old-event".to_string(),
                    seq: 1,
                    event: "model.delta".to_string(),
                    run_id: "run-1".to_string(),
                    timestamp: 1,
                    data: json!({"text":"old"}),
                }],
                sender: None,
                cancel_requested: Arc::new(AtomicBool::new(false)),
            },
        );
        let pending = PendingTerminal {
            to_status: "completed".to_string(),
            session_id: None,
            events: vec![GatewayEvent {
                event_id: "terminal-event".to_string(),
                seq: 2,
                event: "run.completed".to_string(),
                run_id: "run-1".to_string(),
                timestamp: 2,
                data: json!({"status":"completed"}),
            }],
            assistant_message: None,
            deadline: Instant::now() + Duration::from_secs(1),
            expired_fallback: false,
            kind: PendingTerminalKind::RunTerminal,
        };

        // A failed append can prune the old event before the durable command
        // reports an error. Rollback must restore the exact retained snapshot,
        // not merely truncate the new tail by length.
        let previous_events = store.runs["run-1"].events.clone();
        store.runs.get_mut("run-1").expect("run").events = pending.events.clone();
        rollback_pending_retry(
            &mut store,
            "run-1",
            &pending,
            "terminal_pending".to_string(),
            previous_events,
            None,
        );
        let events = &store.runs["run-1"].events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "old-event");
    }

    #[test]
    fn terminal_retry_expired_is_canonical_failed_with_typed_reason() {
        // A terminal-retry-expired run is canonically `failed` (mirror and
        // durable), with the typed reason carried by the terminal event's
        // `error_code` — never a second `terminal_retry_expired` status that
        // would fork memory from the durable `failed` row.
        let run = RunRecord {
            run_id: "run-1".to_string(),
            session_id: "session-1".to_string(),
            parent_run_id: None,
            request_overrides: JsonValue::Object(Default::default()),
            platform: "test".to_string(),
            input: JsonValue::Null,
            status: "failed".to_string(),
            events: vec![GatewayEvent {
                event_id: "terminal-expired:run-1".to_string(),
                seq: 1,
                event: "run.failed".to_string(),
                run_id: "run-1".to_string(),
                timestamp: 42,
                data: json!({
                    "status": "failed",
                    "error_code": "terminal_retry_expired",
                    "error_message": "durable terminal retry window expired",
                }),
            }],
            sender: None,
            cancel_requested: Arc::new(AtomicBool::new(false)),
        };
        let view = RunView::from_mirror(&run);
        assert_eq!(
            view.status, "failed",
            "canonical mirror terminal must be failed"
        );
        assert_eq!(
            view.error_code, "terminal_retry_expired",
            "the typed retry-expired reason must survive in the terminal event"
        );
        assert_eq!(view.finished_at, 42);
        assert_eq!(
            observed_link_state_for_mirror(
                &GatewayStore {
                    runs: std::collections::HashMap::from([("run-1".to_string(), run.clone())]),
                    ..GatewayStore::default()
                },
                "run-1",
            ),
            Some("failed".to_string()),
            "the canonical failed terminal advances the child link to failed"
        );
    }
}
