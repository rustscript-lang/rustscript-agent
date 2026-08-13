//! Gateway durable state: a dedicated storage worker thread executes every
//! RSS storage command off the Tokio request threads, and mutations are
//! committed one typed command at a time (never a delete-all + insert-snapshot
//! replacement).
//!
//! The worker owns the compiled `gateway.rss` program and serializes all
//! SQLite access through one connection per command. Callers submit a
//! request and block on the bounded response; the worker performs the RSS
//! invocation. `load()` reconstructs the in-memory store from the durable
//! tables and re-normalizes it with per-record upserts.

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

use axum::response::sse::Event;

use crate::gateway::{timestamp, vm_value_to_json};
use crate::{AgentConfig, AgentRunner};

/// Response timeout for one storage command; the worker is dedicated and
/// every RSS op is bounded, so this only guards against a wedged worker.
const STORAGE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct GatewayPersistence {
    worker: StorageWorker,
}

/// One serialized storage request for the dedicated worker thread.
struct StorageRequest {
    op: String,
    kind: String,
    record_id: String,
    payload: Value,
    respond: Sender<Result<Value, String>>,
}

/// The dedicated storage worker: owns the compiled RSS program and executes
/// every command on its own thread.
struct StorageWorker {
    sender: Sender<StorageRequest>,
    shutdown: Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct StorageRunner {
    runner: AgentRunner,
    db_path: String,
    max_events: i64,
}

impl StorageRunner {
    fn open(config: &crate::gateway::AgentGatewayConfig, path: &Path) -> Result<Self, String> {
        let root = path.parent().unwrap_or_else(|| Path::new("."));
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            fuel: config.fuel,
        }
        .with_sqlite_root(root);
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("rss")
            .join("storage")
            .join("gateway.rss");
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

    fn command(
        &self,
        op: &str,
        kind: &str,
        record_id: &str,
        payload: &Value,
    ) -> Result<Value, String> {
        let input = VmValue::map(vec![
            (VmValue::string("op"), VmValue::string(op)),
            (VmValue::string("kind"), VmValue::string(kind)),
            (VmValue::string("record_id"), VmValue::string(record_id)),
            (
                VmValue::string("request_id"),
                VmValue::string(uuid::Uuid::new_v4().to_string()),
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
            (VmValue::string("max_rows"), VmValue::Int(10_000)),
            (VmValue::string("max_bytes"), VmValue::Int(4 * 1024 * 1024)),
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
            .run_with_input(input)
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
                let result = runner.command(
                    &request.op,
                    &request.kind,
                    &request.record_id,
                    &request.payload,
                );
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
    pub(crate) fn open(
        config: &crate::gateway::AgentGatewayConfig,
        path: &Path,
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
                thread: Some(thread),
            },
        })
    }

    /// Runs one command on the dedicated storage worker and blocks (bounded)
    /// for the response. The worker thread executes the RSS program; request
    /// threads never run storage code themselves.
    fn command(
        &self,
        op: &str,
        kind: &str,
        record_id: &str,
        payload: &Value,
    ) -> Result<Value, String> {
        let (respond, response) = mpsc::channel();
        self.worker
            .sender
            .send(StorageRequest {
                op: op.to_string(),
                kind: kind.to_string(),
                record_id: record_id.to_string(),
                payload: payload.clone(),
                respond,
            })
            .map_err(|_| "gateway storage worker is not running".to_string())?;
        response
            .recv_timeout(STORAGE_COMMAND_TIMEOUT)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => "gateway storage worker timed out".to_string(),
                RecvTimeoutError::Disconnected => {
                    "gateway storage worker exited unexpectedly".to_string()
                }
            })?
    }

    /// Upserts one record through the typed per-record command.
    pub(crate) fn put(&self, kind: &str, record_id: &str, payload: &Value) -> Result<(), String> {
        let result = self.command("put", kind, record_id, payload)?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(format!("put {kind}/{record_id} failed: {result}"));
        }
        Ok(())
    }

    /// Deletes one record (events delete by run prefix) through the typed
    /// per-record command.
    pub(crate) fn delete(&self, kind: &str, record_id: &str) -> Result<(), String> {
        let result = self.command("delete", kind, record_id, &Value::Null)?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(format!("delete {kind}/{record_id} failed: {result}"));
        }
        Ok(())
    }

    pub(crate) fn load(&self) -> Result<GatewayStore, String> {
        let result = self.command("load", "", "", &json!({}))?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(format!("load gateway state failed: {result}"));
        }
        let data = result
            .get("data")
            .cloned()
            .ok_or_else(|| "gateway state result omitted data".to_string())?;
        let mut snapshot = PersistedState {
            sessions: BTreeMap::new(),
            runs: HashMap::new(),
            jobs: BTreeMap::new(),
            idempotency: HashMap::new(),
        };
        let mut events_by_run: HashMap<String, Vec<GatewayEvent>> = HashMap::new();
        let mut seen_sessions = HashSet::new();
        let mut seen_runs = HashSet::new();
        let mut seen_jobs = HashSet::new();
        let mut seen_idempotency = HashSet::new();
        let mut seen_event_ids = HashSet::new();
        let rows = data
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| "gateway state result omitted rows".to_string())?;
        for row in rows {
            let Some(row) = row.as_array() else { continue };
            let (Some(kind), Some(record_id), Some(payload)) = (
                row.first().and_then(Value::as_str),
                row.get(1).and_then(Value::as_str),
                row.get(2).and_then(Value::as_str),
            ) else {
                continue;
            };
            match kind {
                "session" => {
                    let session: SessionRecord = serde_json::from_str(payload)
                        .map_err(|error| format!("decode session: {error}"))?;
                    if session.view.id != record_id || !seen_sessions.insert(record_id) {
                        return Err(format!("invalid or duplicate session row: {record_id}"));
                    }
                    snapshot.sessions.insert(record_id.to_string(), session);
                }
                "run" => {
                    let run: PersistedRun = serde_json::from_str(payload)
                        .map_err(|error| format!("decode run: {error}"))?;
                    if run.run_id != record_id || !seen_runs.insert(record_id) {
                        return Err(format!("invalid or duplicate run row: {record_id}"));
                    }
                    snapshot.runs.insert(record_id.to_string(), run);
                }
                "job" => {
                    let job: JobRecord = serde_json::from_str(payload)
                        .map_err(|error| format!("decode job: {error}"))?;
                    if job.view.id != record_id || !seen_jobs.insert(record_id) {
                        return Err(format!("invalid or duplicate job row: {record_id}"));
                    }
                    snapshot.jobs.insert(record_id.to_string(), job);
                }
                "event" => {
                    let event: GatewayEvent = serde_json::from_str(payload)
                        .map_err(|error| format!("decode event: {error}"))?;
                    let run_id = record_id
                        .split_once(':')
                        .map(|(run_id, _)| run_id)
                        .unwrap_or(record_id);
                    if event.run_id != run_id || !seen_event_ids.insert(event.event_id.clone()) {
                        return Err(format!("invalid or duplicate event row: {record_id}"));
                    }
                    events_by_run
                        .entry(run_id.to_string())
                        .or_default()
                        .push(event);
                }
                "idempotency" => {
                    let idempotency: IdempotencyRecord = serde_json::from_str(payload)
                        .map_err(|error| format!("decode idempotency record: {error}"))?;
                    if !seen_idempotency.insert(record_id) {
                        return Err(format!("duplicate idempotency row: {record_id}"));
                    }
                    snapshot
                        .idempotency
                        .insert(record_id.to_string(), idempotency);
                }
                _ => {}
            }
        }
        for (run_id, mut events) in events_by_run {
            events.sort_by_key(|event| event.seq);
            // Retained history may begin at first_seq > 1 (retention floor);
            // only adjacency must hold.
            let first_seq = events.first().map(|event| event.seq).unwrap_or(1);
            for (index, event) in events.iter().enumerate() {
                let expected_seq = first_seq + index as u64;
                if event.seq != expected_seq {
                    return Err(format!(
                        "event sequence gap for run {run_id}: expected {expected_seq}, got {}",
                        event.seq
                    ));
                }
            }
            let session_id = snapshot
                .runs
                .get(&run_id)
                .ok_or_else(|| format!("event references unknown run: {run_id}"))?
                .session_id
                .clone();
            if !snapshot.sessions.contains_key(&session_id) {
                return Err(format!("run references unknown session: {session_id}"));
            }
            snapshot
                .runs
                .get_mut(&run_id)
                .expect("run was validated above")
                .events = events;
        }
        let store = GatewayStore::from_snapshot(snapshot);
        // Re-normalize durably with per-record upserts (sequence fixes and
        // restart terminal transitions), never a full snapshot replacement.
        self.normalize(&store)?;
        Ok(store)
    }

    /// Writes the normalized store back one record at a time. Ordering
    /// matters for reload validation: sessions, then runs, then events, then
    /// idempotency records.
    fn normalize(&self, store: &GatewayStore) -> Result<(), String> {
        for (id, session) in &store.sessions {
            self.put(
                "session",
                id,
                &serde_json::to_value(session)
                    .map_err(|error| format!("encode session {id}: {error}"))?,
            )?;
        }
        for run in store.runs.values() {
            self.put(
                "run",
                &run.run_id,
                &persisted_run_value(run)
                    .map_err(|error| format!("encode run {}: {error}", run.run_id))?,
            )?;
            for event in &run.events {
                self.put(
                    "event",
                    &event_record_id(&run.run_id, event.seq),
                    &serde_json::to_value(event)
                        .map_err(|error| format!("encode event {}: {error}", event.event_id))?,
                )?;
            }
        }
        for (id, job) in &store.jobs {
            self.put(
                "job",
                id,
                &serde_json::to_value(job).map_err(|error| format!("encode job {id}: {error}"))?,
            )?;
        }
        for (id, record) in &store.idempotency {
            self.put(
                "idempotency",
                id,
                &serde_json::to_value(record)
                    .map_err(|error| format!("encode idempotency record {id}: {error}"))?,
            )?;
        }
        Ok(())
    }
}

impl Drop for GatewayPersistence {
    /// Signals the worker to exit and joins it so no storage thread outlives
    /// the persistence handle.
    fn drop(&mut self) {
        let _ = self.worker.shutdown.send(());
        if let Some(thread) = self.worker.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serializes one run record without its event rows (events are separate
/// records); the `events` field deserializes as empty on reload.
pub(crate) fn persisted_run_value(run: &RunRecord) -> Result<Value, String> {
    serde_json::to_value(PersistedRun {
        run_id: run.run_id.clone(),
        session_id: run.session_id.clone(),
        parent_run_id: run.parent_run_id.clone(),
        status: run.status.clone(),
        events: Vec::new(),
    })
    .map_err(|error| format!("encode run {}: {error}", run.run_id))
}

/// Durable record id for one event row: zero-padded sequence keeps the load
/// dump ordered by run and sequence.
pub(crate) fn event_record_id(run_id: &str, seq: u64) -> String {
    format!("{run_id}:{seq:020}")
}

#[derive(Default)]
pub(crate) struct GatewayStore {
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

#[derive(Serialize, Deserialize)]
struct PersistedState {
    sessions: BTreeMap<String, SessionRecord>,
    #[serde(default)]
    runs: HashMap<String, PersistedRun>,
    jobs: BTreeMap<String, JobRecord>,
    #[serde(default)]
    idempotency: HashMap<String, IdempotencyRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedRun {
    run_id: String,
    session_id: String,
    parent_run_id: Option<String>,
    status: String,
    #[serde(default)]
    events: Vec<GatewayEvent>,
}

impl GatewayStore {
    fn from_snapshot(snapshot: PersistedState) -> Self {
        let runs = snapshot
            .runs
            .into_iter()
            .map(|(run_id, persisted)| {
                let (sender, _) = broadcast::channel(64);
                let mut status = persisted.status;
                let mut events = persisted.events;
                for (index, event) in events.iter_mut().enumerate() {
                    if event.seq == 0 {
                        event.seq = (index + 1) as u64;
                    }
                    if event.event_id.is_empty() {
                        event.event_id = format!("{}-{}", persisted.run_id, event.seq);
                    }
                }
                if matches!(status.as_str(), "started" | "stopping")
                    && !events.iter().any(GatewayEvent::is_terminal)
                {
                    status = "failed".to_string();
                    events.push(GatewayEvent {
                        event_id: format!("{}-{}", persisted.run_id, events.len() + 1),
                        seq: events.len() as u64 + 1,
                        event: "run.failed".to_string(),
                        run_id: persisted.run_id.clone(),
                        timestamp: timestamp(),
                        data: json!({
                            "status": "failed",
                            "error_code": "gateway_restart",
                            "error_message": "run interrupted during gateway restart"
                        }),
                    });
                }
                (
                    run_id,
                    RunRecord {
                        run_id: persisted.run_id,
                        session_id: persisted.session_id,
                        parent_run_id: persisted.parent_run_id,
                        status,
                        events,
                        sender,
                        cancel_requested: Arc::new(AtomicBool::new(false)),
                    },
                )
            })
            .collect();
        Self {
            sessions: snapshot.sessions,
            runs,
            jobs: snapshot.jobs,
            idempotency: snapshot.idempotency,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) view: SessionView,
    pub(crate) messages: Vec<SessionMessage>,
}

pub(crate) struct RunRecord {
    pub(crate) run_id: String,
    pub(crate) session_id: String,
    pub(crate) parent_run_id: Option<String>,
    pub(crate) status: String,
    pub(crate) events: Vec<GatewayEvent>,
    pub(crate) sender: broadcast::Sender<GatewayEvent>,
    /// Legacy boolean stop flag kept for persisted-state compatibility; the
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

    pub(crate) fn into_sse(self) -> Event {
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
        Event::default().event(event_name).data(data)
    }
}
