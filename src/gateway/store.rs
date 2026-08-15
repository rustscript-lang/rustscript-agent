//! Gateway durable state: a dedicated storage worker thread executes every
//! RSS storage command off the Tokio request threads against the normalized
//! typed schema (`rss/storage/main.rss`), never the legacy blob adapter
//! (`rss/storage/gateway.rss`, retained only as an explicit migration
//! fixture).
//!
//! The worker owns the compiled `main.rss` program and serializes all
//! SQLite access through one connection per command. Callers submit a
//! request and block on the bounded response; the worker performs the RSS
//! invocation. `load()` migrates, runs transactional restart recovery in
//! bounded batches, then reconstructs the in-memory store from a
//! cursor-paginated dump — a load larger than any single page or byte limit
//! is drained completely, never silently truncated.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::AtomicBool,
    mpsc::{self, Receiver, RecvTimeoutError, Sender},
};
use std::time::Duration;

use rustscript_vm::Value as VmValue;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::AgentGatewayConfig;
use crate::domain::{timestamp, vm_value_to_json};
use crate::{AgentConfig, AgentRunner};

/// Response timeout for one storage command; the worker is dedicated and
/// every RSS op is bounded, so this only guards against a wedged worker.
const STORAGE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// One recovery batch processes at most this many interrupted runs; the
/// gateway loops until a batch reports zero recovered.
const RECOVERY_BATCH: i64 = 512;

/// Page size used by the cursor-paginated `load.all` dump.
const LOAD_PAGE_ROWS: i64 = 512;

/// Per-page byte budget of the cursor-paginated `load.all` dump.
const LOAD_PAGE_BYTES: i64 = 2 * 1024 * 1024;

/// Hard total-row cap of the `load.all` dump: a state larger than this is
/// a typed `load_too_large` error, never a silent truncation.
const LOAD_CAP_ROWS: i64 = 1_000_000;

/// Column orders of the `load.all` rows (part of the command contract; see
/// `rss/storage/load.rss`).
/// sessions:   id, profile, platform, account_id, chat_id, thread_id,
///             user_id, generation, status, system_prompt, model, provider,
///             toolset_hash, metadata_json, last_message_seq, created_at_ms,
///             updated_at_ms, title, end_reason
/// messages:   ordinal, id, session_id, role, content_json, name,
///             tool_call_id, parent_message_id, token_estimate, compacted,
///             metadata_json, run_id, finish_reason, created_at_ms
/// runs:       id, session_id, parent_run_id, status, input_json, provider,
///             model, script_hash, idempotency_scope, idempotency_key,
///             turn_count, input_tokens, output_tokens, error_code,
///             error_message, recovery_reason, created_at_ms, started_at_ms,
///             finished_at_ms, updated_at_ms
/// events:     seq, run_id, event_id, event_type, payload_json, created_at_ms
/// jobs:       id, name, schedule_json, prompt, deliver_json, skills_json,
///             repeat_count, enabled, output_json, created_at_ms,
///             updated_at_ms, last_run_at_ms
/// idempotency: scope, key, request_hash, resource_type, resource_id, state,
///              response_json, created_at_ms, expires_at_ms, completed_at_ms
///
/// A typed storage command failure carrying the RSS error code.
#[derive(Debug, Clone)]
pub struct StorageError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for StorageError {}

pub struct GatewayPersistence {
    worker: StorageWorker,
    max_events: i64,
    broadcast_capacity: usize,
    metrics: Arc<crate::metrics::Metrics>,
}

/// One serialized storage request for the dedicated worker thread.
struct StorageRequest {
    op: String,
    payload: Value,
    respond: Sender<Result<Value, String>>,
}

/// The dedicated storage worker: owns the compiled RSS program and executes
/// every command on its own thread.
struct StorageWorker {
    sender: Sender<StorageRequest>,
    shutdown: Sender<()>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    closed: std::sync::atomic::AtomicBool,
}

struct StorageRunner {
    runner: AgentRunner,
    db_path: String,
    max_events: i64,
}

impl StorageRunner {
    fn open(config: &AgentGatewayConfig, path: &Path) -> Result<Self, String> {
        let root = path.parent().unwrap_or_else(|| Path::new("."));
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            io: config.io.clone(),
            fuel: config.fuel,
        }
        .with_sqlite_root(root);
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("rss")
            .join("storage")
            .join("main.rss");
        let runner = AgentRunner::from_file(source, agent_config)
            .map_err(|error| format!("compile RSS storage program: {error}"))?;
        let db_path = path
            .file_name()
            .ok_or_else(|| "gateway SQLite state path must name a file".to_string())?
            .to_string_lossy()
            .into_owned();
        Ok(Self {
            runner,
            db_path,
            max_events: config.max_events_per_run as i64,
        })
    }

    fn command(&self, op: &str, payload: &Value) -> Result<Value, String> {
        let input = VmValue::map(vec![
            (VmValue::string("op"), VmValue::string(op)),
            (
                VmValue::string("request_id"),
                VmValue::string(Uuid::new_v4().to_string()),
            ),
            (
                VmValue::string("db_path"),
                VmValue::string(self.db_path.clone()),
            ),
            (
                VmValue::string("db_mode"),
                VmValue::string("read_write_create"),
            ),
            (VmValue::string("busy_timeout_ms"), VmValue::Int(5_000)),
            (VmValue::string("max_rows"), VmValue::Int(LOAD_PAGE_ROWS)),
            (VmValue::string("max_bytes"), VmValue::Int(LOAD_PAGE_BYTES)),
            (VmValue::string("max_events"), VmValue::Int(self.max_events)),
            (VmValue::string("max_messages"), VmValue::Int(128)),
            (VmValue::string("now_ms"), VmValue::Int(timestamp() as i64)),
            (
                VmValue::string("payload_json"),
                VmValue::string(payload.to_string()),
            ),
        ]);
        let result = self
            .runner
            .run_with_context(input)
            .map_err(|error| format!("run RSS storage operation {op}: {error}"))?;
        let VmValue::Map(result) = result else {
            return Err(format!(
                "RSS storage operation {op} returned a non-map result"
            ));
        };
        Ok(vm_value_to_json(&VmValue::Map(result)))
    }
}

/// Runs the worker loop: execute one request at a time on this dedicated
/// thread, then answer. A dropped sender (or shutdown signal) ends the loop.
fn storage_worker_loop(
    runner: StorageRunner,
    requests: Receiver<StorageRequest>,
    shutdown: Receiver<()>,
) {
    loop {
        match requests.recv_timeout(Duration::from_millis(200)) {
            Ok(request) => {
                let result = runner.command(&request.op, &request.payload);
                let _ = request.respond.send(result);
            }
            Err(RecvTimeoutError::Timeout) => {
                if shutdown.try_recv().is_ok() {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

impl GatewayPersistence {
    /// Opens the normalized typed storage repository: compiles `main.rss`
    /// and spawns the dedicated worker thread. Typed repository commands
    /// (admission, sessions, messages, runs, events, jobs, approvals,
    /// compactions) block on the worker's bounded response and are meant to
    /// be called from blocking threads (`spawn_blocking`), never directly
    /// from Tokio request threads.
    pub fn open(config: &crate::config::AgentGatewayConfig, path: &Path) -> Result<Self, String> {
        Self::open_with_metrics(config, path, Arc::new(crate::metrics::Metrics::default()))
    }

    /// Like [`Self::open`], but shares the caller's bounded metrics registry
    /// so every storage command is observable.
    pub fn open_with_metrics(
        config: &crate::config::AgentGatewayConfig,
        path: &Path,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Result<Self, String> {
        let runner = StorageRunner::open(config, path)?;
        let (sender, requests) = mpsc::channel::<StorageRequest>();
        let (shutdown_sender, shutdown) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("gateway-storage-worker".to_string())
            .spawn(move || storage_worker_loop(runner, requests, shutdown))
            .map_err(|error| format!("spawn gateway storage worker: {error}"))?;
        Ok(Self {
            worker: StorageWorker {
                sender,
                shutdown: shutdown_sender,
                thread: std::sync::Mutex::new(Some(thread)),
                closed: std::sync::atomic::AtomicBool::new(false),
            },
            max_events: config.max_events_per_run as i64,
            broadcast_capacity: config.broadcast_capacity,
            metrics,
        })
    }

    /// Closes the storage worker deterministically: signals it to exit,
    /// joins the thread, and marks it closed so every later command fails
    /// fast with a typed error instead of hanging. Idempotent; concurrent
    /// calls and `Drop` are safe. Queued-but-unstarted requests observe a
    /// disconnected response channel (typed `storage_unavailable`).
    pub fn shutdown(&self) {
        self.worker.shutdown();
    }

    /// Runs one command on the dedicated storage worker and blocks (bounded)
    /// for the response. The worker thread executes the RSS program; caller
    /// threads never run storage code themselves.
    fn command(&self, op: &str, payload: &Value) -> Result<Value, String> {
        let result = if self
            .worker
            .closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Err("gateway storage worker is not running".to_string())
        } else {
            let (respond, response) = mpsc::channel();
            let sent = self.worker.sender.send(StorageRequest {
                op: op.to_string(),
                payload: payload.clone(),
                respond,
            });
            match sent {
                Ok(()) => response
                    .recv_timeout(STORAGE_COMMAND_TIMEOUT)
                    .map_err(|error| match error {
                        RecvTimeoutError::Timeout => "gateway storage worker timed out".to_string(),
                        RecvTimeoutError::Disconnected => {
                            "gateway storage worker exited unexpectedly".to_string()
                        }
                    })?,
                Err(_) => Err("gateway storage worker is not running".to_string()),
            }
        };
        self.metrics
            .storage_op(crate::metrics::StorageOp::from_command(op), result.is_ok());
        result
    }

    /// Runs one typed command and returns its `data` payload, or a typed
    /// [`StorageError`] carrying the RSS error code.
    fn command_data(&self, op: &str, payload: &Value) -> Result<Value, StorageError> {
        let result = self.command(op, payload).map_err(|message| StorageError {
            code: "storage_unavailable".to_string(),
            message,
        })?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(StorageError {
                code: result
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("storage_error")
                    .to_string(),
                message: result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("storage command failed")
                    .to_string(),
            });
        }
        Ok(result.get("data").cloned().unwrap_or(Value::Null))
    }

    // ------------------------------------------------------------------
    // Typed repository commands (production read/write path).
    // ------------------------------------------------------------------

    /// One atomic admission: session (created or touched), first user
    /// message, run, child link, idempotency record, run.started event, and
    /// retention floor commit in a single transaction. The returned data
    /// carries `replayed`, `run`, `session`, `message`, and `idempotency`.
    pub fn admission_create(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("admission.create", payload)
    }

    pub fn session_create(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("session.create", payload)
    }

    pub fn session_touch(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("session.touch", payload)
    }

    /// Cascades one session (messages, runs, events, links, approvals,
    /// compactions, delivery cursors, idempotency) in one transaction.
    pub fn session_delete(&self, session_id: &str) -> Result<Value, StorageError> {
        self.command_data("session.delete", &json!({ "session_id": session_id }))
    }

    pub fn message_append(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("message.append", payload)
    }

    /// Appends one run event with transactional sequence allocation and
    /// retention pruning.
    pub fn event_append(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("event.append", payload)
    }

    /// One atomic terminal commit: run status transition plus terminal
    /// events (and optional assistant message) in a single transaction.
    /// The returned data carries the run row and the run's event rows.
    pub fn run_terminal(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("run.terminal", payload)
    }

    /// A guarded typed run status transition (0 rows is a typed
    /// `transition_conflict`).
    pub fn run_transition(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("run.transition", payload)
    }

    pub fn run_get(&self, run_id: &str) -> Result<Value, StorageError> {
        self.command_data("run.get", &json!({ "run_id": run_id }))
    }

    pub fn session_get(&self, session_id: &str) -> Result<Value, StorageError> {
        self.command_data("session.get", &json!({ "session_id": session_id }))
    }

    /// Reads one delivery cursor row (`session_id`, `consumer`,
    /// `last_event_seq`, `updated_at_ms`); an empty `rows` array means no
    /// cursor was ever persisted for the consumer.
    pub fn delivery_get(&self, session_id: &str, consumer: &str) -> Result<Value, StorageError> {
        self.command_data(
            "delivery.get",
            &json!({ "session_id": session_id, "consumer": consumer }),
        )
    }

    /// Monotonic validated cursor advance for run-event delivery: the value
    /// must not exceed the session's high-water event sequence.
    pub fn delivery_advance(
        &self,
        session_id: &str,
        consumer: &str,
        event_seq: i64,
    ) -> Result<Value, StorageError> {
        self.command_data(
            "delivery.advance",
            &json!({
                "session_id": session_id,
                "consumer": consumer,
                "event_seq": event_seq,
                "now_ms": timestamp() as i64,
            }),
        )
    }

    /// Monotonic unvalidated cursor upsert for transport-level values (for
    /// example the Telegram getUpdates offset) that are unrelated to run
    /// event sequences.
    pub fn delivery_set(
        &self,
        session_id: &str,
        consumer: &str,
        value: i64,
    ) -> Result<Value, StorageError> {
        self.command_data(
            "delivery.set",
            &json!({
                "session_id": session_id,
                "consumer": consumer,
                "event_seq": value,
                "now_ms": timestamp() as i64,
            }),
        )
    }

    /// Replays one run's retained events with precise
    /// oldest/high-water cursors (`cursor_too_old` below the floor).
    pub fn event_replay(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("event.replay", payload)
    }

    pub fn job_create(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("job.create", payload)
    }

    pub fn job_update(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("job.update", payload)
    }

    pub fn job_delete(&self, job_id: &str) -> Result<Value, StorageError> {
        self.command_data("job.delete", &json!({ "job_id": job_id }))
    }

    pub fn approval_request(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("approval.request", payload)
    }

    pub fn approval_get(&self, approval_id: &str) -> Result<Value, StorageError> {
        self.command_data("approval.get", &json!({ "approval_id": approval_id }))
    }

    pub fn approval_resolve(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("approval.resolve", payload)
    }

    pub fn approval_expire(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("approval.expire", payload)
    }

    pub fn compaction_start(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("compaction.start", payload)
    }

    pub fn compaction_get(&self, compaction_id: &str) -> Result<Value, StorageError> {
        self.command_data("compaction.get", &json!({ "compaction_id": compaction_id }))
    }

    pub fn compaction_latest(&self, session_id: &str) -> Result<Value, StorageError> {
        self.command_data("compaction.latest", &json!({ "session_id": session_id }))
    }

    pub fn compaction_commit(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("compaction.commit", payload)
    }

    pub fn compaction_fail(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("compaction.fail", payload)
    }

    /// Restart recovery: migrates the schema, recovers every interrupted
    /// active run to the documented terminal restart state in transactional
    /// bounded batches (exactly once per run, guarded by
    /// `recovery_records`), and rebuilds the in-memory store from the
    /// cursor-paginated normalized dump.
    pub fn load(&self) -> Result<GatewayStore, String> {
        let migrated = self
            .command_data("migrate", &json!({}))
            .map_err(|error| format!("migrate gateway state: {error}"))?;
        if migrated.get("schema_version") != Some(&json!(4)) {
            return Err(format!(
                "gateway schema migrated to an unexpected version: {migrated}"
            ));
        }
        let mut recovered = 1i64;
        let mut rounds = 0u32;
        while recovered > 0 {
            let result = self
                .command_data(
                    "recovery.recover_active",
                    &json!({
                        "reason": "gateway_restart",
                        "details_json": "{}",
                        "now_ms": timestamp(),
                        "max_rows": RECOVERY_BATCH,
                        "max_bytes": LOAD_PAGE_BYTES,
                        "max_events": self.max_events,
                    }),
                )
                .map_err(|error| format!("recover interrupted runs: {error}"))?;
            recovered = result.get("recovered").and_then(Value::as_i64).unwrap_or(0);
            rounds += 1;
            if rounds > 10_000 {
                return Err("restart recovery did not converge".to_string());
            }
        }
        let data = self
            .command_data(
                "load.all",
                &json!({
                    "max_rows": LOAD_PAGE_ROWS,
                    "max_bytes": LOAD_PAGE_BYTES,
                    "load_cap": LOAD_CAP_ROWS,
                }),
            )
            .map_err(|error| format!("load gateway state: {error}"))?;
        GatewayStore::from_load(&data, self.broadcast_capacity)
    }
}

impl StorageWorker {
    /// Signals the worker to exit and joins it, exactly once (idempotent
    /// under concurrent calls and `Drop`).
    fn shutdown(&self) {
        if self.closed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        let _ = self.shutdown.send(());
        if let Some(thread) = self.thread.lock().expect("storage thread lock").take() {
            let _ = thread.join();
        }
    }
}

impl Drop for GatewayPersistence {
    /// Signals the worker to exit and joins it so no storage thread outlives
    /// the persistence handle.
    fn drop(&mut self) {
        self.worker.shutdown();
    }
}

#[derive(Default)]
pub struct GatewayStore {
    pub(crate) sessions: BTreeMap<String, SessionRecord>,
    pub(crate) runs: HashMap<String, RunRecord>,
    pub(crate) jobs: BTreeMap<String, JobRecord>,
    pub(crate) idempotency: HashMap<String, IdempotencyRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct IdempotencyRecord {
    pub(crate) request_hash: String,
    pub(crate) run_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) view: SessionView,
    pub(crate) messages: Vec<SessionMessage>,
}

#[derive(Clone)]
pub(crate) struct RunRecord {
    pub(crate) run_id: String,
    pub(crate) session_id: String,
    pub(crate) parent_run_id: Option<String>,
    pub(crate) status: String,
    pub(crate) events: Vec<GatewayEvent>,
    /// Live delivery channel; `None` once the run's stream was closed (the
    /// bounded terminal retry expired) so SSE subscribers are never held
    /// forever without a terminal event.
    pub(crate) sender: Option<broadcast::Sender<GatewayEvent>>,
    /// Legacy boolean stop flag kept for in-memory compatibility; the
    /// authoritative typed cancellation lives in the service RunHandle.
    #[allow(dead_code)]
    pub(crate) cancel_requested: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct JobRecord {
    pub(crate) view: JobView,
    pub(crate) output: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct JobView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) schedule: Value,
    pub(crate) prompt: String,
    pub(crate) deliver: Value,
    pub(crate) skills: Vec<String>,
    pub(crate) repeat: Option<i64>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) last_run_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionView {
    pub(crate) id: String,
    pub(crate) object: String,
    pub(crate) title: Option<String>,
    pub(crate) model: String,
    pub(crate) provider: Option<String>,
    pub(crate) source: String,
    pub(crate) system_prompt: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) message_count: usize,
    pub(crate) end_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionMessage {
    pub(crate) id: String,
    pub(crate) session_id: String,
    pub(crate) role: String,
    pub(crate) content: Value,
    pub(crate) created_at: u64,
    pub(crate) run_id: Option<String>,
    pub(crate) finish_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GatewayEvent {
    pub(crate) event_id: String,
    pub(crate) seq: u64,
    pub(crate) event: String,
    pub(crate) run_id: String,
    pub(crate) timestamp: u64,
    pub(crate) data: Value,
}

impl GatewayEvent {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(
            self.event.as_str(),
            "run.completed" | "run.cancelled" | "run.failed"
        )
    }

    pub(crate) fn into_sse(self) -> axum::response::sse::Event {
        let event_name = self.event.clone();
        let mut payload = serde_json::Map::new();
        payload.insert("event_id".to_string(), Value::String(self.event_id.clone()));
        payload.insert("seq".to_string(), json!(self.seq));
        payload.insert("event".to_string(), Value::String(self.event));
        payload.insert("run_id".to_string(), Value::String(self.run_id));
        payload.insert("timestamp".to_string(), json!(self.timestamp));
        match self.data {
            Value::Object(fields) => payload.extend(fields),
            data => {
                payload.insert("data".to_string(), data);
            }
        }
        let data =
            serde_json::to_string(&Value::Object(payload)).unwrap_or_else(|_| "{}".to_string());
        axum::response::sse::Event::default()
            .event(event_name)
            .data(data)
    }
}

/// Maps a normalized run status back to the gateway's in-memory status
/// vocabulary. The DB persists only `running` for active runs (a gateway
/// `stopping` state is in-memory only); restart recovery converts every
/// non-terminal DB status to `failed` before load, so any leftover active
/// status maps defensively to `started`.
fn memory_status(db_status: &str) -> &'static str {
    match db_status {
        "completed" => "completed",
        "failed" => "failed",
        "cancelled" => "cancelled",
        _ => "started",
    }
}

impl GatewayStore {
    /// Rebuilds the in-memory store from the normalized `load.all` dump.
    /// Validation is explicit and hard-failing: duplicate ids, unknown
    /// session/message references, unknown parent runs, and event sequence
    /// gaps are all rejected (agent correctness never depends on SQLite
    /// foreign-key enforcement, which the core host does not enable).
    fn from_load(data: &Value, broadcast_capacity: usize) -> Result<Self, String> {
        let session_rows = load_rows(data, "sessions")?;
        let message_rows = load_rows(data, "messages")?;
        let run_rows = load_rows(data, "runs")?;
        let event_rows = load_rows(data, "events")?;
        let job_rows = load_rows(data, "jobs")?;
        let idempotency_rows = load_rows(data, "idempotency")?;

        let mut sessions = BTreeMap::new();
        for row in session_rows {
            let id = string_cell(&row, 0, "session id")?;
            let view = SessionView {
                id: id.clone(),
                object: "hermes.session".to_string(),
                title: optional_string(&row, 17),
                model: string_cell(&row, 10, "session model")?,
                provider: optional_string(&row, 11),
                source: string_cell(&row, 2, "session platform")?,
                system_prompt: optional_string(&row, 9),
                created_at: int_cell(&row, 15, "session created_at")? as u64,
                updated_at: int_cell(&row, 16, "session updated_at")? as u64,
                message_count: 0,
                end_reason: optional_string(&row, 18),
            };
            if sessions
                .insert(
                    id.clone(),
                    SessionRecord {
                        view,
                        messages: Vec::new(),
                    },
                )
                .is_some()
            {
                return Err(format!("duplicate session row: {id}"));
            }
        }
        let mut messages_by_session: HashMap<String, Vec<SessionMessage>> = HashMap::new();
        for row in message_rows {
            let session_id = string_cell(&row, 2, "message session id")?;
            if !sessions.contains_key(&session_id) {
                return Err(format!("message references unknown session: {session_id}"));
            }
            let message = SessionMessage {
                id: string_cell(&row, 1, "message id")?,
                session_id: session_id.clone(),
                role: string_cell(&row, 3, "message role")?,
                content: json_cell(&row, 4, "message content")?,
                created_at: int_cell(&row, 13, "message created_at")? as u64,
                run_id: optional_string(&row, 11),
                finish_reason: optional_string(&row, 12),
            };
            messages_by_session
                .entry(session_id)
                .or_default()
                .push(message);
        }
        for (session_id, mut messages) in messages_by_session {
            messages.sort_by_key(|message| message.created_at);
            let session = sessions
                .get_mut(&session_id)
                .expect("session presence was validated above");
            session.messages = messages;
            session.view.message_count = session.messages.len();
        }

        let mut runs = HashMap::new();
        for row in run_rows {
            let run_id = string_cell(&row, 0, "run id")?;
            let session_id = string_cell(&row, 1, "run session id")?;
            if !sessions.contains_key(&session_id) {
                return Err(format!("run references unknown session: {session_id}"));
            }
            let (sender, _) = broadcast::channel(broadcast_capacity);
            let run = RunRecord {
                run_id: run_id.clone(),
                session_id,
                parent_run_id: optional_string(&row, 2),
                status: memory_status(&string_cell(&row, 3, "run status")?).to_string(),
                events: Vec::new(),
                sender: Some(sender),
                cancel_requested: Arc::new(AtomicBool::new(false)),
            };
            if runs.insert(run_id.clone(), run).is_some() {
                return Err(format!("duplicate run row: {run_id}"));
            }
        }
        // Parent references must exist (the RSS layer enforces this on
        // write; load re-validates so correctness never depends on FK).
        for run in runs.values() {
            if let Some(parent) = run.parent_run_id.as_deref()
                && !runs.contains_key(parent)
            {
                return Err(format!("run references unknown parent run: {parent}"));
            }
        }
        let mut events_by_run: HashMap<String, Vec<GatewayEvent>> = HashMap::new();
        for row in event_rows {
            let run_id = string_cell(&row, 1, "event run id")?;
            if !runs.contains_key(&run_id) {
                return Err(format!("event references unknown run: {run_id}"));
            }
            let event = GatewayEvent {
                event_id: string_cell(&row, 2, "event id")?,
                seq: int_cell(&row, 0, "event seq")? as u64,
                event: string_cell(&row, 3, "event type")?,
                run_id: run_id.clone(),
                timestamp: int_cell(&row, 5, "event created_at")? as u64,
                data: json_cell(&row, 4, "event payload")?,
            };
            events_by_run.entry(run_id).or_default().push(event);
        }
        for (run_id, mut events) in events_by_run {
            events.sort_by_key(|event| event.seq);
            let mut seen = HashSet::new();
            let first_seq = events.first().map(|event| event.seq).unwrap_or(1);
            for (index, event) in events.iter().enumerate() {
                let expected_seq = first_seq + index as u64;
                if event.seq != expected_seq || !seen.insert(event.event_id.clone()) {
                    return Err(format!(
                        "event sequence gap or duplicate for run {run_id}: expected {expected_seq}, got {}",
                        event.seq
                    ));
                }
            }
            runs.get_mut(&run_id)
                .expect("run presence was validated above")
                .events = events;
        }

        let mut jobs = BTreeMap::new();
        for row in job_rows {
            let id = string_cell(&row, 0, "job id")?;
            let repeat = int_cell(&row, 6, "job repeat")?;
            let job = JobRecord {
                view: JobView {
                    id: id.clone(),
                    name: string_cell(&row, 1, "job name")?,
                    schedule: json_cell(&row, 2, "job schedule")?,
                    prompt: string_cell(&row, 3, "job prompt")?,
                    deliver: json_cell(&row, 4, "job deliver")?,
                    skills: json_array_strings(&row, 5, "job skills")?,
                    repeat: (repeat > 0).then_some(repeat),
                    enabled: int_cell(&row, 7, "job enabled")? != 0,
                    created_at: int_cell(&row, 9, "job created_at")? as u64,
                    updated_at: int_cell(&row, 10, "job updated_at")? as u64,
                    last_run_at: {
                        let value = int_cell(&row, 11, "job last_run_at")?;
                        (value > 0).then_some(value as u64)
                    },
                },
                output: json_optional_cell(&row, 8, "job output")?,
            };
            if jobs.insert(id.clone(), job).is_some() {
                return Err(format!("duplicate job row: {id}"));
            }
        }

        let mut idempotency = HashMap::new();
        for row in idempotency_rows {
            let key = string_cell(&row, 1, "idempotency key")?;
            let state = string_cell(&row, 5, "idempotency state")?;
            if state == "completed" {
                let record = IdempotencyRecord {
                    request_hash: string_cell(&row, 2, "idempotency request hash")?,
                    run_id: string_cell(&row, 4, "idempotency resource id")?,
                };
                if idempotency.insert(key.clone(), record).is_some() {
                    return Err(format!("duplicate idempotency row: {key}"));
                }
            }
        }

        Ok(Self {
            sessions,
            runs,
            jobs,
            idempotency,
        })
    }
}

fn load_rows(data: &Value, key: &str) -> Result<Vec<Vec<Value>>, String> {
    data.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("load.all result omitted {key} rows"))?
        .iter()
        .map(|row| {
            row.as_array()
                .cloned()
                .ok_or_else(|| format!("load.all {key} row is not an array"))
        })
        .collect()
}

fn string_cell(row: &[Value], index: usize, label: &str) -> Result<String, String> {
    row.get(index)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("load.all row missing {label}"))
}

fn optional_string(row: &[Value], index: usize) -> Option<String> {
    row.get(index)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn int_cell(row: &[Value], index: usize, label: &str) -> Result<i64, String> {
    row.get(index)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("load.all row missing {label}"))
}

fn json_cell(row: &[Value], index: usize, label: &str) -> Result<Value, String> {
    let text = string_cell(row, index, label)?;
    serde_json::from_str(&text).map_err(|error| format!("decode {label}: {error}"))
}

fn json_optional_cell(row: &[Value], index: usize, label: &str) -> Result<Option<Value>, String> {
    match row.get(index).and_then(Value::as_str) {
        Some("") | None => Ok(None),
        Some(text) => serde_json::from_str(text)
            .map(Some)
            .map_err(|error| format!("decode {label}: {error}")),
    }
}

fn json_array_strings(row: &[Value], index: usize, label: &str) -> Result<Vec<String>, String> {
    let value = json_cell(row, index, label)?;
    value
        .as_array()
        .ok_or_else(|| format!("{label} is not an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{label} contains a non-string"))
        })
        .collect()
}

/// Appends one session message and updates the session view counters.
pub(crate) fn append_message(
    view: &mut SessionView,
    messages: &mut Vec<SessionMessage>,
    role: &str,
    content: Value,
    run_id: Option<String>,
    finish_reason: Option<String>,
) -> SessionMessage {
    let message = SessionMessage {
        id: Uuid::new_v4().to_string(),
        session_id: view.id.clone(),
        role: role.to_string(),
        content,
        created_at: timestamp(),
        run_id,
        finish_reason,
    };
    messages.push(message.clone());
    view.message_count = messages.len();
    view.updated_at = timestamp();
    message
}
