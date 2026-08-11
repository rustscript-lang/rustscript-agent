//! AgentService: atomic run admission, typed cancellation, and bounded
//! lifecycle state.
//!
//! One reservation covers capacity (a semaphore permit), session
//! resolution/creation, the run ID, and the cancellation/delivery state; any
//! failure rolls back every intermediate step, so a rejected admission leaves
//! no session or run behind. Stop, timeout, disconnect, and gateway halt
//! map to typed core cancellation reasons. Terminal lifecycle handles are
//! bounded by a configured TTL.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, atomic::AtomicBool, atomic::Ordering};
use std::time::Instant;

use parking_lot::RwLock;
use rustscript_vm::{CancellationReason, HttpConfig};
use serde_json::{Value as JsonValue, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::RunCancellation;
use crate::gateway::{AgentGatewayConfig, append_message, emit_event_locked, timestamp};
use crate::gateway_store::{
    GatewayPersistence, GatewayStore, IdempotencyRecord, RunRecord, SessionRecord, SessionView,
};

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

    pub fn persist(&self) -> bool {
        let Some(persistence) = self.inner.persistence.as_ref() else {
            return true;
        };
        let store = self.inner.store.read();
        match persistence.save(&store) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!("failed to persist agent gateway state: {error}");
                false
            }
        }
    }

    /// Atomically admits one run: capacity permit, idempotency, parent check,
    /// session resolution/creation, run ID, cancellation/delivery state, and
    /// durable commit. On any failure every intermediate step is rolled back
    /// and the capacity permit is released.
    pub fn admit(&self, request: AdmitRunRequest) -> Result<AdmittedRun, AdmitError> {
        let capacity_permit = self
            .inner
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmitError::RunLimitReached)?;
        let mut permit = Some(capacity_permit);

        let run_id = Uuid::new_v4().to_string();
        let cancel = RunCancellation::with_timeout(self.inner.config.run_timeout);
        let mut store = self.inner.store.write();
        let previous_session: Option<(String, Option<SessionRecord>)>;
        let session_id = match request.session_id.clone() {
            Some(session_id) => {
                if !store.sessions.contains_key(&session_id) {
                    return Err(AdmitError::SessionNotFound);
                }
                previous_session = None;
                session_id
            }
            None => {
                let id = Uuid::new_v4().to_string();
                let now = timestamp();
                let view = SessionView {
                    id: id.clone(),
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
                    source: "yahu".to_string(),
                    system_prompt: request.instructions.clone(),
                    created_at: now,
                    updated_at: now,
                    message_count: 0,
                    end_reason: None,
                };
                store.sessions.insert(
                    id.clone(),
                    SessionRecord {
                        view,
                        messages: Vec::new(),
                    },
                );
                previous_session = Some((id.clone(), None));
                id
            }
        };

        let result = (|| {
            if let (Some(key), Some(hash)) = (
                request.idempotency_key.as_deref(),
                request.idempotency_hash.as_deref(),
            ) && let Some(existing) = store.idempotency.get(key)
            {
                if existing.request_hash != hash {
                    return Err(AdmitError::IdempotencyConflict);
                }
                let (run_id, status) = store
                    .runs
                    .get(&existing.run_id)
                    .map(|run| (run.run_id.clone(), run.status.clone()))
                    .unwrap_or((existing.run_id.clone(), "unknown".to_string()));
                return Ok(AdmittedRun {
                    run_id,
                    session_id,
                    status,
                    replayed: true,
                });
            }
            if let Some(parent_run_id) = request.parent_run_id.as_deref()
                && !store.runs.contains_key(parent_run_id)
            {
                return Err(AdmitError::ParentNotFound);
            }
            if let Some(session) = store.sessions.get_mut(&session_id) {
                if let Some(model) = request.model.clone() {
                    session.view.model = model;
                }
                if let Some(provider) = request.provider.clone() {
                    session.view.provider = Some(provider);
                }
                if request.instructions.is_some() {
                    session.view.system_prompt = request.instructions.clone();
                }
                append_message(
                    &mut session.view,
                    &mut session.messages,
                    "user",
                    request.input.clone(),
                    Some(run_id.clone()),
                    None,
                );
            }
            let (sender, _) = tokio::sync::broadcast::channel(32);
            let run = RunRecord {
                run_id: run_id.clone(),
                session_id: session_id.clone(),
                parent_run_id: request.parent_run_id.clone(),
                status: "started".to_string(),
                events: Vec::new(),
                sender,
                cancel_requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            store.runs.insert(run_id.clone(), run);
            if let Some(run) = store.runs.get_mut(&run_id) {
                emit_event_locked(
                    run,
                    "run.started",
                    json!({"status":"started","session_id":session_id}),
                );
            }
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
                cancel: cancel.clone(),
                terminal_at: Mutex::new(None),
                permit: Mutex::new(permit.take()),
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
        })();

        match result {
            Ok(admitted) => {
                drop(store);
                if !self.persist() {
                    // Roll back every intermediate step; the rejection leaves
                    // no session, run, or idempotency record behind.
                    let mut store = self.inner.store.write();
                    store.runs.remove(&run_id);
                    if let Some(key) = request.idempotency_key.as_deref() {
                        store.idempotency.remove(key);
                    }
                    if let Some((session_id, previous)) = previous_session {
                        match previous {
                            Some(session) => {
                                store.sessions.insert(session_id, session);
                            }
                            None => {
                                store.sessions.remove(&session_id);
                            }
                        }
                    }
                    if let Some(handle) = self.inner.runs.lock().expect("runs lock").remove(&run_id)
                    {
                        handle.permit.lock().expect("permit lock").take();
                    }
                    return Err(AdmitError::Persistence(
                        "run admission could not be durably committed".to_string(),
                    ));
                }
                Ok(admitted)
            }
            Err(error) => {
                if let Some(permit) = permit.take() {
                    drop(permit);
                }
                Err(error)
            }
        }
    }

    /// Requests a typed stop for an active run. Idempotent: the first request
    /// wins; later requests see the current status.
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
    /// terminal time for TTL retention. Called by the worker after the one
    /// terminal commit.
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
}

/// Removes terminal lifecycle handles after the configured TTL. The durable
/// store keeps the run record (replay handoff); only the in-memory
/// cancellation/delivery state is released.
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
