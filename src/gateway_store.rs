use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::AtomicBool},
};

use axum::response::sse::Event;
use rustscript_vm::Value as VmValue;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::gateway::{timestamp, vm_value_to_json};
use crate::{AgentConfig, AgentRunner};

pub(crate) struct GatewayPersistence {
    storage: Mutex<StorageRunner>,
}

struct StorageRunner {
    runner: AgentRunner,
    db_path: String,
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
        Ok(Self { runner, db_path })
    }

    fn command(
        &self,
        op: &str,
        kind: &str,
        record_id: &str,
        payload: Value,
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
            (VmValue::string("max_events"), VmValue::Int(128)),
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

impl GatewayPersistence {
    pub(crate) fn open(
        config: &crate::gateway::AgentGatewayConfig,
        path: &Path,
    ) -> Result<Self, String> {
        Ok(Self {
            storage: Mutex::new(StorageRunner::open(config, path)?),
        })
    }

    pub(crate) fn load(&self) -> Result<GatewayStore, String> {
        let storage = self
            .storage
            .lock()
            .map_err(|_| "gateway storage mutex poisoned".to_string())?;
        let result = storage.command("load", "", "", json!({}))?;
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
        if rows.len() >= 100_000 {
            return Err(
                "gateway state row limit reached; refusing possibly truncated replay".to_string(),
            );
        }
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
            for (index, event) in events.iter().enumerate() {
                let expected_seq = index as u64 + 1;
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
        drop(storage);
        self.save(&store)?;
        Ok(store)
    }

    pub(crate) fn save(&self, store: &GatewayStore) -> Result<(), String> {
        let storage = self
            .storage
            .lock()
            .map_err(|_| "gateway storage mutex poisoned".to_string())?;
        let snapshot = store.snapshot();
        let mut sessions = Vec::with_capacity(snapshot.sessions.len());
        for (id, session) in snapshot.sessions {
            sessions.push(json!({
                "record_id": id,
                "payload_json": serde_json::to_string(&session)
                    .map_err(|error| format!("encode session: {error}"))?,
            }));
        }
        let mut runs = Vec::with_capacity(snapshot.runs.len());
        let mut events = Vec::new();
        for (id, mut run) in snapshot.runs {
            let run_events = std::mem::take(&mut run.events);
            runs.push(json!({
                "record_id": id,
                "payload_json": serde_json::to_string(&run)
                    .map_err(|error| format!("encode run: {error}"))?,
            }));
            for event in run_events {
                events.push(json!({
                    "record_id": format!("{}:{:020}", run.run_id, event.seq),
                            "payload_json": serde_json::to_string(&event)
                        .map_err(|error| format!("encode event: {error}"))?,
                }));
            }
        }
        let mut jobs = Vec::with_capacity(snapshot.jobs.len());
        for (id, job) in snapshot.jobs {
            jobs.push(json!({
                "record_id": id,
                "payload_json": serde_json::to_string(&job)
                    .map_err(|error| format!("encode job: {error}"))?,
            }));
        }
        let mut idempotency = Vec::with_capacity(snapshot.idempotency.len());
        for (id, record) in snapshot.idempotency {
            idempotency.push(json!({
                "record_id": id,
                "payload_json": serde_json::to_string(&record)
                    .map_err(|error| format!("encode idempotency record: {error}"))?,
            }));
        }
        let record_count =
            sessions.len() + runs.len() + jobs.len() + events.len() + idempotency.len();
        if record_count + 5 > 1024 {
            return Err(format!(
                "gateway state has {record_count} records; atomic storage transaction limit is 1019"
            ));
        }
        storage.command(
            "replace",
            "",
            "",
            json!({
                "sessions": sessions,
                "runs": runs,
                "jobs": jobs,
                "events": events,
                "idempotency": idempotency,
            }),
        )?;
        Ok(())
    }
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
    events: Vec<GatewayEvent>,
}

impl GatewayStore {
    fn snapshot(&self) -> PersistedState {
        PersistedState {
            sessions: self.sessions.clone(),
            runs: self
                .runs
                .values()
                .map(|run| {
                    (
                        run.run_id.clone(),
                        PersistedRun {
                            run_id: run.run_id.clone(),
                            session_id: run.session_id.clone(),
                            parent_run_id: run.parent_run_id.clone(),
                            status: run.status.clone(),
                            events: run.events.clone(),
                        },
                    )
                })
                .collect(),
            jobs: self.jobs.clone(),
            idempotency: self.idempotency.clone(),
        }
    }

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
