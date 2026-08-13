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
//! configured TTL. A terminal commit that fails while storage is down
//! registers the run as observably `terminal_pending` (never a false
//! terminal): the admission permit is released immediately, and a bounded
//! retry loop commits the typed terminal exactly once when storage recovers.
//! After the retry window the durable side is left for restart recovery, so
//! a sustained outage can neither exhaust capacity nor leak handles or live
//! streams forever.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, atomic::AtomicBool, atomic::Ordering};
use std::time::Instant;

use parking_lot::RwLock;
use rustscript_vm::{CancellationReason, HttpConfig, InvocationError, Value as VmValue};
use serde_json::{Value as JsonValue, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::config::AgentGatewayConfig;
use crate::domain::{RunContext, timestamp, vm_value_to_json};
use crate::events;
use crate::gateway::store::{
    GatewayEvent, GatewayPersistence, GatewayStore, IdempotencyRecord, RunRecord, SessionMessage,
    SessionRecord, SessionView, append_message,
};
use crate::runtime::delivery::{
    ChannelEventSink, DeliveryContext, append_event_locked, run_delivery_task,
};
use crate::runtime::rss_runner::execute_rss_source;
use crate::{RunCancellation, RunError};

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
/// and bounded terminal retention.
pub struct RunHandle {
    pub(crate) cancel: RunCancellation,
    pub(crate) terminal_at: Mutex<Option<Instant>>,
    pub(crate) permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl RunHandle {
    /// True while the run has not committed a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.terminal_at.lock().expect("terminal lock").is_some()
    }
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
    http_config: HttpConfig,
    capacity: Arc<Semaphore>,
    runs: Mutex<HashMap<String, Arc<RunHandle>>>,
    pending: Mutex<HashMap<String, PendingTerminal>>,
    halting: AtomicBool,
}

impl AgentService {
    pub(crate) fn new(
        config: Arc<AgentGatewayConfig>,
        store: Arc<RwLock<GatewayStore>>,
        persistence: Option<Arc<GatewayPersistence>>,
        agent_source: Option<Arc<String>>,
        http_config: HttpConfig,
    ) -> Self {
        let capacity = Arc::new(Semaphore::new(config.max_concurrent_runs));
        let inner = Arc::new(AgentServiceInner {
            config,
            store,
            persistence,
            agent_source,
            http_config,
            capacity,
            runs: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            halting: AtomicBool::new(false),
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
        let capacity_permit = self
            .inner
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmitError::RunLimitReached)?;
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.admit_blocking(request, capacity_permit))
            .await
            .map_err(|error| AdmitError::Persistence(format!("admission worker failed: {error}")))?
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
                end_reason: None,
            };
            Some(view)
        } else {
            None
        };
        if let Some(parent_run_id) = request.parent_run_id.as_deref()
            && !store.runs.contains_key(parent_run_id)
        {
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

        let durable =
            match self.inner.persistence.as_ref() {
                Some(persistence) => persistence.admission_create(&payload).map_err(|error| {
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
            content: request.input.clone(),
            created_at: now,
            run_id: Some(run_id.clone()),
            finish_reason: None,
        });
        session.view.message_count = session.messages.len();
        session.view.updated_at = now;

        let (sender, _) = tokio::sync::broadcast::channel(32);
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

        let handle = Arc::new(RunHandle {
            cancel: RunCancellation::with_timeout(self.inner.config.run_timeout),
            terminal_at: Mutex::new(None),
            permit: Mutex::new(Some(capacity_permit)),
        });
        self.inner
            .runs
            .lock()
            .expect("runs lock")
            .insert(run_id.clone(), handle);
        Ok(AdmittedRun {
            run_id: run_id.clone(),
            session_id,
            status: "started".to_string(),
            replayed: false,
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
            handle.cancel.request(CancellationReason::Requested);
            Some("stopping".to_string())
        } else {
            Some(status)
        }
    }

    /// Cancels every active run with the typed resource-closed reason and
    /// marks the service as halting; workers exit within their configured
    /// bounds and commit their typed terminal transitions.
    pub fn halt(&self) {
        self.inner.halting.store(true, Ordering::Release);
        let handles = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            handle.cancel.request(CancellationReason::ResourceClosed);
        }
    }

    /// Marks a run terminal: releases the capacity permit and records the
    /// terminal time for TTL retention. Called by the worker (or the bounded
    /// terminal retry loop) after the one terminal commit.
    pub fn mark_terminal(&self, run_id: &str) {
        if let Some(handle) = self
            .inner
            .runs
            .lock()
            .expect("runs lock")
            .get(run_id)
            .cloned()
        {
            *handle.terminal_at.lock().expect("terminal lock") = Some(Instant::now());
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
            self.finish_cancelled(&run_id, "requested").await;
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
                WorkerOutcome::Cancelled(reason) => {
                    self.finish_cancelled(&run_id, reason).await;
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
            self.finish_cancelled(&run_id, "requested").await;
            return;
        }

        self.finish_completed(&run_id, &session_id, &output_text).await;
    }

    /// Durably commits the completed terminal. The assistant message,
    /// `message.delta`, and `run.completed` form one atomic delta: the whole
    /// delta is persisted through the typed `run.terminal` transaction under
    /// the store lock and published only after the durable commit succeeds.
    /// On a persist failure the delta is rolled back, nothing is published,
    /// and the run becomes observably `terminal_pending`; the bounded retry
    /// loop commits the exact same terminal once storage recovers.
    async fn finish_completed(&self, run_id: &str, session_id: &str, output_text: &str) {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let session_id_for_commit = session_id.to_string();
        let output_text_for_commit = output_text.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        let outcome = tokio::task::spawn_blocking(move || {
            let mut store = service.inner.store.write();
            let persistence = service.persistence_handle();
            // The started/stopping race guard: a stop that landed before this
            // commit wins (the typed cancellation path commits instead).
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
        .expect("terminal commit task must complete");
        match outcome {
            TerminalOutcome::Committed => self.mark_terminal(run_id),
            TerminalOutcome::NotActive => {
                self.finish_cancelled(run_id, "requested").await;
            }
            TerminalOutcome::SessionMissing => {
                self.finish_failed(run_id, failed_payload("session not found".to_string()))
                    .await;
            }
            TerminalOutcome::TerminalPersistFailed { error, pending } => {
                tracing::error!(
                    "failed to commit terminal state durably for {run_id}: {error}; \
                     retrying within the bounded window"
                );
                self.register_pending_terminal(run_id, *pending);
                self.mark_terminal(run_id);
                self.spawn_terminal_retry(run_id.to_string());
            }
        }
    }

    /// Cancels a run with the typed reason through a durable-first terminal
    /// commit: `run.terminal` commits the cancellation event and the status
    /// change in one transaction, and only then is the event published. A
    /// failed commit rolls the in-memory state back and hands the
    /// cancellation to the bounded retry loop (`terminal_pending`), which
    /// commits and publishes it exactly once when storage recovers.
    pub(crate) async fn finish_cancelled(&self, run_id: &str, reason: &str) {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let reason_for_commit = reason.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        let outcome = tokio::task::spawn_blocking(move || {
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
            match terminal_commit(persistence.as_deref(), run, "", "cancelled", &[&event], None) {
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
        .expect("terminal commit task must complete");
        match outcome {
            TerminalOutcome::Committed => self.mark_terminal(run_id),
            TerminalOutcome::TerminalPersistFailed { error, pending } => {
                tracing::error!(
                    "failed to commit cancellation durably for {run_id}: {error}; \
                     retrying within the bounded window"
                );
                self.register_pending_terminal(run_id, *pending);
                self.mark_terminal(run_id);
                self.spawn_terminal_retry(run_id.to_string());
            }
            _ => {}
        }
    }

    /// Fails a run through a durable-first terminal commit: `run.terminal`
    /// commits the failure event and the status change in one transaction,
    /// and only then is the event published. A failed commit rolls the
    /// in-memory state back and hands the failure to the bounded retry loop
    /// (`terminal_pending`), which commits and publishes it exactly once when
    /// storage recovers.
    pub(crate) async fn finish_failed(&self, run_id: &str, data: JsonValue) {
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        let outcome = tokio::task::spawn_blocking(move || {
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
                "run.failed",
                data,
                max_event_bytes,
                max_events_per_run,
            );
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
        .expect("terminal commit task must complete");
        match outcome {
            TerminalOutcome::Committed => self.mark_terminal(run_id),
            TerminalOutcome::TerminalPersistFailed { error, pending } => {
                tracing::error!(
                    "failed to commit failure durably for {run_id}: {error}; \
                     retrying within the bounded window"
                );
                self.register_pending_terminal(run_id, *pending);
                self.mark_terminal(run_id);
                self.spawn_terminal_retry(run_id.to_string());
            }
            _ => {}
        }
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
        let context = RunContext {
            run_id: run_id.to_string(),
            session_id: session_id.to_string(),
            parent_run_id,
            platform: "api_server".to_string(),
            input: JsonValue::String(input.to_string()),
            messages,
            system_prompt,
            model,
            provider,
            // Provider options and tool schemas arrive with the provider and
            // tool milestones; the canonical shape is present from the start.
            provider_options: JsonValue::Object(Default::default()),
            tool_schemas: JsonValue::Array(Vec::new()),
            limits: json!({
                "max_events": self.inner.config.max_events_per_run,
                "max_event_bytes": self.inner.config.max_event_bytes,
                "timeout_ms": self.inner.config.run_timeout.as_millis(),
            }),
            metadata: JsonValue::Object(Default::default()),
        };
        context.to_vm_value()
    }

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
                    PendingRetryOutcome::Conflict
                }
                Err(error) => {
                    tracing::error!(
                        "terminal retry for {run_id_for_block} failed: {error}; \
                         will retry on the next janitor tick"
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
        }
    });
}
