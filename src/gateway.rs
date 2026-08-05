use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    path::Path as FsPath,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::stream::{self, Stream};
use parking_lot::RwLock;
use rusqlite::{Connection, OptionalExtension, params};
use rustscript_vm::{HostFunctionRegistry, HttpConfig, Value as VmValue, Vm, VmStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AgentGatewayConfig {
    pub model: String,
    pub provider: Option<String>,
    pub agent_name: String,
    pub bearer_token: Option<String>,
    pub max_body_bytes: usize,
    pub max_concurrent_runs: usize,
    pub run_timeout: Duration,
    pub http: HttpConfig,
}

impl Default for AgentGatewayConfig {
    fn default() -> Self {
        Self {
            model: "local-agent".to_string(),
            provider: Some("pd-edge".to_string()),
            agent_name: "local-rss-agent".to_string(),
            bearer_token: None,
            max_body_bytes: 4 * 1024 * 1024,
            max_concurrent_runs: 8,
            run_timeout: Duration::from_secs(900),
            http: HttpConfig::default(),
        }
    }
}

#[derive(Clone)]
pub struct AgentGatewayState {
    config: Arc<AgentGatewayConfig>,
    store: Arc<RwLock<GatewayStore>>,
    persistence: Option<Arc<GatewayPersistence>>,
    agent_source: Option<Arc<String>>,
    http_config: HttpConfig,
}

impl AgentGatewayState {
    pub fn new(config: AgentGatewayConfig) -> Self {
        let http_config = config.http.clone();
        Self {
            config: Arc::new(config),
            store: Arc::new(RwLock::new(GatewayStore::default())),
            persistence: None,
            agent_source: None,
            http_config,
        }
    }

    pub fn with_agent_source(
        config: AgentGatewayConfig,
        source: impl Into<String>,
    ) -> Result<Self, String> {
        let source = source.into();
        let validation_source = format!("let input = \"probe\";\n{source}");
        rustscript_vm::compile_source(&validation_source)
            .map_err(|error| format!("compile RSS agent source: {error}"))?;
        let mut state = Self::new(config);
        state.agent_source = Some(Arc::new(source));
        Ok(state)
    }

    pub fn with_agent_source_and_sqlite(
        config: AgentGatewayConfig,
        source: impl Into<String>,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        let mut state = Self::with_agent_source(config, source)?;
        let persistence = Arc::new(
            GatewayPersistence::open(path.as_ref())
                .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        state.store = Arc::new(RwLock::new(store));
        state.persistence = Some(persistence);
        Ok(state)
    }

    pub fn with_sqlite_path(
        config: AgentGatewayConfig,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        let http_config = config.http.clone();
        let persistence = Arc::new(
            GatewayPersistence::open(path.as_ref())
                .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        Ok(Self {
            config: Arc::new(config),
            store: Arc::new(RwLock::new(store)),
            persistence: Some(persistence),
            agent_source: None,
            http_config,
        })
    }

    fn persist(&self) -> bool {
        let Some(persistence) = self.persistence.as_ref() else {
            return true;
        };
        if let Err(error) = persistence.save(&self.store.read()) {
            tracing::error!("failed to persist agent gateway state: {error}");
            return false;
        }
        true
    }
}

struct GatewayPersistence {
    connection: std::sync::Mutex<Connection>,
}

impl GatewayPersistence {
    fn open(path: &FsPath) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS gateway_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload TEXT NOT NULL
            )",
        )?;
        Ok(Self {
            connection: std::sync::Mutex::new(connection),
        })
    }

    fn load(&self) -> rusqlite::Result<GatewayStore> {
        let connection = self.connection.lock().expect("gateway SQLite mutex");
        let payload = connection
            .query_row(
                "SELECT payload FROM gateway_state WHERE id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(payload) = payload else {
            return Ok(GatewayStore::default());
        };
        let snapshot = serde_json::from_str::<PersistedState>(&payload).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
        Ok(GatewayStore::from_snapshot(snapshot))
    }

    fn save(&self, store: &GatewayStore) -> rusqlite::Result<()> {
        let payload = serde_json::to_string(&store.snapshot())
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let connection = self.connection.lock().expect("gateway SQLite mutex");
        connection.execute(
            "INSERT INTO gateway_state (id, payload) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET payload = excluded.payload",
            params![payload],
        )?;
        Ok(())
    }
}

#[derive(Default)]
struct GatewayStore {
    sessions: BTreeMap<String, SessionRecord>,
    runs: HashMap<String, RunRecord>,
    jobs: BTreeMap<String, JobRecord>,
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    sessions: BTreeMap<String, SessionRecord>,
    jobs: BTreeMap<String, JobRecord>,
}

impl GatewayStore {
    fn snapshot(&self) -> PersistedState {
        PersistedState {
            sessions: self.sessions.clone(),
            jobs: self.jobs.clone(),
        }
    }

    fn from_snapshot(snapshot: PersistedState) -> Self {
        Self {
            sessions: snapshot.sessions,
            runs: HashMap::new(),
            jobs: snapshot.jobs,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionRecord {
    view: SessionView,
    messages: Vec<SessionMessage>,
}

struct RunRecord {
    run_id: String,
    session_id: String,
    status: String,
    events: Vec<GatewayEvent>,
    sender: broadcast::Sender<GatewayEvent>,
    cancel_requested: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobRecord {
    view: JobView,
    output: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobView {
    id: String,
    name: String,
    schedule: Value,
    prompt: String,
    deliver: Value,
    skills: Vec<String>,
    repeat: Option<i64>,
    enabled: bool,
    created_at: u64,
    updated_at: u64,
    last_run_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionView {
    id: String,
    object: String,
    title: Option<String>,
    model: String,
    provider: Option<String>,
    source: String,
    system_prompt: Option<String>,
    created_at: u64,
    updated_at: u64,
    message_count: usize,
    end_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionMessage {
    id: String,
    session_id: String,
    role: String,
    content: Value,
    created_at: u64,
    run_id: Option<String>,
    finish_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GatewayEvent {
    event: String,
    run_id: String,
    timestamp: u64,
    data: Value,
}

impl GatewayEvent {
    fn is_terminal(&self) -> bool {
        matches!(
            self.event.as_str(),
            "run.completed" | "run.cancelled" | "run.failed"
        )
    }

    fn into_sse(self) -> Event {
        let event_name = self.event.clone();
        let mut payload = serde_json::Map::new();
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

#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    id: Option<String>,
    session_id: Option<String>,
    source: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    system_prompt: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SessionListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    source: Option<String>,
    q: Option<String>,
    exclude_sources: Option<String>,
    #[serde(default)]
    include_children: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateSessionRequest {
    title: Option<String>,
    end_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateRunRequest {
    input: Option<Value>,
    session_id: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    instructions: Option<String>,
    #[serde(rename = "conversation_history")]
    _conversation_history: Option<Value>,
    #[serde(flatten)]
    _extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ChatRequest {
    input: Option<Value>,
    model: Option<String>,
    provider: Option<String>,
    instructions: Option<String>,
    #[serde(flatten)]
    _extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct JobRequest {
    id: Option<String>,
    job_id: Option<String>,
    name: Option<String>,
    schedule: Option<Value>,
    prompt: Option<String>,
    deliver: Option<Value>,
    skills: Option<Vec<String>>,
    repeat: Option<i64>,
    enabled: Option<bool>,
    #[serde(flatten)]
    _extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct JobListQuery {
    include_disabled: Option<bool>,
}

pub fn build_agent_gateway_app(state: AgentGatewayState) -> Router {
    Router::new()
        .route("/health/detailed", get(health_detailed_handler))
        .route("/v1/models", get(models_handler))
        .route(
            "/api/sessions",
            get(list_sessions_handler).post(create_session_handler),
        )
        .route(
            "/api/sessions/{session_id}",
            get(get_session_handler)
                .patch(update_session_handler)
                .delete(delete_session_handler),
        )
        .route(
            "/api/sessions/{session_id}/messages",
            get(session_messages_handler),
        )
        .route(
            "/api/sessions/{session_id}/chat",
            post(session_chat_handler),
        )
        .route("/v1/runs", post(create_run_handler))
        .route("/v1/runs/{run_id}/events", get(run_events_handler))
        .route("/v1/runs/{run_id}/stop", post(stop_run_handler))
        .route("/api/jobs", get(list_jobs_handler).post(create_job_handler))
        .route(
            "/api/jobs/{job_id}",
            get(get_job_handler)
                .patch(update_job_handler)
                .delete(delete_job_handler),
        )
        .route(
            "/api/jobs/{job_id}/output/latest",
            get(latest_job_output_handler),
        )
        .route("/api/jobs/{job_id}/pause", post(pause_job_handler))
        .route("/api/jobs/{job_id}/resume", post(resume_job_handler))
        .route("/api/jobs/{job_id}/run", post(run_job_handler))
        .route(
            "/api/subagents/{subagent_id}/interrupt",
            post(interrupt_subagent_handler),
        )
        .layer(DefaultBodyLimit::max(state.config.max_body_bytes))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            persist_gateway_state,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ))
        .with_state(state)
}

async fn persist_gateway_state(
    State(state): State<AgentGatewayState>,
    request: Request,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    if state.persist() {
        response
    } else {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_failed",
            "gateway state could not be persisted",
        )
    }
}

async fn bearer_auth_middleware(
    State(state): State<AgentGatewayState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.config.bearer_token.as_deref() else {
        return next.run(request).await;
    };
    let authorized = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value == expected);
    if !authorized {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
        );
    }
    next.run(request).await
}

async fn health_detailed_handler(State(state): State<AgentGatewayState>) -> impl IntoResponse {
    let active_agents = state
        .store
        .read()
        .runs
        .values()
        .filter(|run| matches!(run.status.as_str(), "started" | "stopping"))
        .count();
    Json(json!({
        "status": "ok",
        "active_agents": active_agents,
        "agent": state.config.agent_name,
    }))
}

async fn models_handler(State(state): State<AgentGatewayState>) -> impl IntoResponse {
    Json(json!({
        "object": "list",
        "data": [{
            "id": state.config.model,
            "object": "model",
            "owned_by": state.config.provider.clone().unwrap_or_else(|| "pd-edge".to_string()),
            "root": state.config.model,
        }]
    }))
}

async fn create_session_handler(
    State(state): State<AgentGatewayState>,
    Json(request): Json<CreateSessionRequest>,
) -> Response {
    let id = request
        .session_id
        .or(request.id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let now = timestamp();
    let view = SessionView {
        id: id.clone(),
        object: "hermes.session".to_string(),
        title: request.title,
        model: request.model.unwrap_or_else(|| state.config.model.clone()),
        provider: request.provider.or_else(|| state.config.provider.clone()),
        source: request.source.unwrap_or_else(|| "yahu".to_string()),
        system_prompt: request.system_prompt,
        created_at: now,
        updated_at: now,
        message_count: 0,
        end_reason: None,
    };
    let mut store = state.store.write();
    if store.sessions.contains_key(&id) {
        return json_error(
            StatusCode::CONFLICT,
            "session_exists",
            "session already exists",
        );
    }
    store.sessions.insert(
        id,
        SessionRecord {
            view: view.clone(),
            messages: Vec::new(),
        },
    );
    drop(store);
    state.persist();
    json_response(
        StatusCode::CREATED,
        json!({"object":"hermes.session", "session":view, "data":view}),
    )
}

async fn list_sessions_handler(
    State(state): State<AgentGatewayState>,
    Query(query): Query<SessionListQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    let excluded = query
        .exclude_sources
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let search = query.q.as_deref().map(str::to_ascii_lowercase);
    let store = state.store.read();
    let filtered = store
        .sessions
        .values()
        .filter(|session| {
            query
                .source
                .as_deref()
                .is_none_or(|source| source == session.view.source)
        })
        .filter(|session| !excluded.contains(&session.view.source.as_str()))
        .filter(|session| {
            search.as_deref().is_none_or(|needle| {
                session
                    .view
                    .title
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(needle)
                    || session.view.id.to_ascii_lowercase().contains(needle)
            })
        })
        .filter(|session| query.include_children || session.view.source != "subagent")
        .map(|session| session.view.clone())
        .collect::<Vec<_>>();
    let has_more = offset.saturating_add(limit) < filtered.len();
    let data = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    Json(json!({
        "object": "list",
        "data": data,
        "limit": limit,
        "offset": offset,
        "has_more": has_more,
    }))
}

async fn get_session_handler(
    State(state): State<AgentGatewayState>,
    Path(session_id): Path<String>,
) -> Response {
    let store = state.store.read();
    let Some(session) = store.sessions.get(&session_id) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        );
    };
    json_response(
        StatusCode::OK,
        json!({"object":"hermes.session", "session":session.view, "data":session.view}),
    )
}

async fn update_session_handler(
    State(state): State<AgentGatewayState>,
    Path(session_id): Path<String>,
    Json(request): Json<UpdateSessionRequest>,
) -> Response {
    if request.title.as_deref().is_some_and(str::is_empty) {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_title",
            "title is empty",
        );
    }
    let mut store = state.store.write();
    let Some(session) = store.sessions.get_mut(&session_id) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        );
    };
    if let Some(title) = request.title {
        session.view.title = Some(title);
    }
    if request.end_reason.is_some() {
        session.view.end_reason = request.end_reason;
    }
    session.view.updated_at = timestamp();
    let view = session.view.clone();
    drop(store);
    state.persist();
    json_response(
        StatusCode::OK,
        json!({"object":"hermes.session", "session":view, "data":view}),
    )
}

async fn delete_session_handler(
    State(state): State<AgentGatewayState>,
    Path(session_id): Path<String>,
) -> Response {
    let mut store = state.store.write();
    if store.sessions.remove(&session_id).is_none() {
        return json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        );
    }
    drop(store);
    state.persist();
    json_response(
        StatusCode::OK,
        json!({"object":"hermes.session.deleted", "id":session_id, "deleted":true}),
    )
}

async fn session_messages_handler(
    State(state): State<AgentGatewayState>,
    Path(session_id): Path<String>,
) -> Response {
    let store = state.store.read();
    let Some(session) = store.sessions.get(&session_id) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        );
    };
    json_response(
        StatusCode::OK,
        json!({"object":"list", "session_id":session_id, "data":session.messages}),
    )
}

async fn session_chat_handler(
    State(state): State<AgentGatewayState>,
    Path(session_id): Path<String>,
    Json(request): Json<ChatRequest>,
) -> Response {
    let Some(source) = state.agent_source.clone() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "agent_source_not_configured",
            "session chat requires PD_EDGE_AGENT_SCRIPT",
        );
    };
    if !state.store.read().sessions.contains_key(&session_id) {
        return json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        );
    }

    let input = request.input.unwrap_or(Value::Null);
    let input_text = input_text(&input);
    let cancellation = Arc::new(AtomicBool::new(false));
    let http_config = state.http_config.clone();
    let worker_input = input_text.clone();
    let worker = tokio::task::spawn_blocking(move || {
        execute_rss_source(&source, http_config, worker_input, cancellation)
    });
    let output = match tokio::time::timeout(state.config.run_timeout, worker).await {
        Ok(Ok(Ok(value))) => vm_value_to_json(&value),
        Ok(Ok(Err(error))) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "agent_failed", &error);
        }
        Ok(Err(error)) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent_worker_failed",
                &format!("agent worker join failed: {error}"),
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::GATEWAY_TIMEOUT,
                "agent_timeout",
                "agent execution timed out",
            );
        }
    };

    let mut store = state.store.write();
    let Some(session) = store.sessions.get_mut(&session_id) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        );
    };
    if let Some(model) = request.model {
        session.view.model = model;
    }
    if request.provider.is_some() {
        session.view.provider = request.provider;
    }
    if request.instructions.is_some() {
        session.view.system_prompt = request.instructions;
    }
    append_message(
        &mut session.view,
        &mut session.messages,
        "user",
        input,
        None,
        None,
    );
    let message = append_message(
        &mut session.view,
        &mut session.messages,
        "assistant",
        output,
        None,
        Some("stop".to_string()),
    );
    drop(store);
    state.persist();
    json_response(
        StatusCode::OK,
        json!({
            "object":"hermes.session.chat.completion",
            "session_id":session_id,
            "message":message,
            "usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0},
        }),
    )
}

async fn create_run_handler(
    State(state): State<AgentGatewayState>,
    Json(request): Json<CreateRunRequest>,
) -> Response {
    let input = request.input.unwrap_or(Value::Null);
    let text = input_text(&input);
    let session_id = match request.session_id {
        Some(session_id) => session_id,
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
                    .unwrap_or_else(|| state.config.model.clone()),
                provider: request
                    .provider
                    .clone()
                    .or_else(|| state.config.provider.clone()),
                source: "yahu".to_string(),
                system_prompt: request.instructions.clone(),
                created_at: now,
                updated_at: now,
                message_count: 0,
                end_reason: None,
            };
            state.store.write().sessions.insert(
                id.clone(),
                SessionRecord {
                    view,
                    messages: Vec::new(),
                },
            );
            id
        }
    };
    if state
        .store
        .read()
        .runs
        .values()
        .filter(|run| matches!(run.status.as_str(), "started" | "stopping"))
        .count()
        >= state.config.max_concurrent_runs
    {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "run_limit_reached",
            "maximum concurrent run limit reached",
        );
    }
    let run_id = Uuid::new_v4().to_string();
    let cancel_requested = Arc::new(AtomicBool::new(false));
    let (sender, _) = broadcast::channel(32);
    {
        let mut store = state.store.write();
        let Some(session) = store.sessions.get_mut(&session_id) else {
            return json_error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            );
        };
        if let Some(model) = request.model.clone() {
            session.view.model = model;
        }
        if request.provider.is_some() {
            session.view.provider = request.provider.clone();
        }
        if request.instructions.is_some() {
            session.view.system_prompt = request.instructions.clone();
        }
        append_message(
            &mut session.view,
            &mut session.messages,
            "user",
            input,
            Some(run_id.clone()),
            None,
        );
        store.runs.insert(
            run_id.clone(),
            RunRecord {
                run_id: run_id.clone(),
                session_id: session_id.clone(),
                status: "started".to_string(),
                events: Vec::new(),
                sender,
                cancel_requested: cancel_requested.clone(),
            },
        );
    }
    state.persist();
    let worker_state = state.clone();
    let worker_run_id = run_id.clone();
    tokio::spawn(async move {
        run_local_agent(worker_state, worker_run_id, text).await;
    });
    json_response(
        StatusCode::ACCEPTED,
        json!({"run_id":run_id, "status":"started"}),
    )
}

async fn run_events_handler(
    State(state): State<AgentGatewayState>,
    Path(run_id): Path<String>,
) -> Response {
    let (history, receiver) = {
        let store = state.store.read();
        let Some(run) = store.runs.get(&run_id) else {
            return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
        };
        (run.events.clone(), run.sender.subscribe())
    };
    let stream = event_stream(history, receiver);
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("keepalive"),
        )
        .into_response()
}

async fn stop_run_handler(
    State(state): State<AgentGatewayState>,
    Path(run_id): Path<String>,
) -> Response {
    let mut store = state.store.write();
    let Some(run) = store.runs.get_mut(&run_id) else {
        return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
    };
    if run.status == "started" {
        run.status = "stopping".to_string();
        run.cancel_requested.store(true, Ordering::Release);
    }
    drop(store);
    state.persist();
    json_response(
        StatusCode::OK,
        json!({"run_id":run_id, "status":"stopping"}),
    )
}

async fn create_job_handler(
    State(state): State<AgentGatewayState>,
    Json(request): Json<JobRequest>,
) -> Response {
    let id = request
        .job_id
        .or(request.id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let now = timestamp();
    let view = JobView {
        id: id.clone(),
        name: request
            .name
            .unwrap_or_else(|| "rustscript-agent".to_string()),
        schedule: request.schedule.unwrap_or(Value::Null),
        prompt: request.prompt.unwrap_or_default(),
        deliver: request.deliver.unwrap_or(Value::Null),
        skills: request.skills.unwrap_or_default(),
        repeat: request.repeat,
        enabled: request.enabled.unwrap_or(true),
        created_at: now,
        updated_at: now,
        last_run_at: None,
    };
    let mut store = state.store.write();
    if store.jobs.contains_key(&id) {
        return json_error(StatusCode::CONFLICT, "job_exists", "job already exists");
    }
    store.jobs.insert(
        id,
        JobRecord {
            view: view.clone(),
            output: None,
        },
    );
    json_response(StatusCode::CREATED, json!({"job":view}))
}

async fn list_jobs_handler(
    State(state): State<AgentGatewayState>,
    Query(query): Query<JobListQuery>,
) -> impl IntoResponse {
    let include_disabled = query.include_disabled.unwrap_or(false);
    let jobs = state
        .store
        .read()
        .jobs
        .values()
        .filter(|job| include_disabled || job.view.enabled)
        .map(|job| job.view.clone())
        .collect::<Vec<_>>();
    Json(json!({"jobs":jobs}))
}

async fn get_job_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
) -> Response {
    let store = state.store.read();
    let Some(job) = store.jobs.get(&job_id) else {
        return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
    };
    json_response(StatusCode::OK, json!({"job":job.view}))
}

async fn update_job_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
    Json(request): Json<JobRequest>,
) -> Response {
    let mut store = state.store.write();
    let Some(job) = store.jobs.get_mut(&job_id) else {
        return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
    };
    if let Some(name) = request.name {
        job.view.name = name;
    }
    if let Some(schedule) = request.schedule {
        job.view.schedule = schedule;
    }
    if let Some(prompt) = request.prompt {
        job.view.prompt = prompt;
    }
    if let Some(deliver) = request.deliver {
        job.view.deliver = deliver;
    }
    if let Some(skills) = request.skills {
        job.view.skills = skills;
    }
    if request.repeat.is_some() {
        job.view.repeat = request.repeat;
    }
    if let Some(enabled) = request.enabled {
        job.view.enabled = enabled;
    }
    job.view.updated_at = timestamp();
    let view = job.view.clone();
    json_response(StatusCode::OK, json!({"job":view}))
}

async fn delete_job_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
) -> Response {
    if state.store.write().jobs.remove(&job_id).is_none() {
        return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
    }
    json_response(StatusCode::OK, json!({"ok":true}))
}

async fn latest_job_output_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
) -> Response {
    let store = state.store.read();
    let Some(job) = store.jobs.get(&job_id) else {
        return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
    };
    json_response(StatusCode::OK, json!({"output":job.output}))
}

async fn pause_job_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
) -> Response {
    set_job_enabled(&state, &job_id, false)
}

async fn resume_job_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
) -> Response {
    set_job_enabled(&state, &job_id, true)
}

async fn run_job_handler(
    State(_state): State<AgentGatewayState>,
    Path(_job_id): Path<String>,
) -> Response {
    json_error(
        StatusCode::NOT_IMPLEMENTED,
        "job_execution_unavailable",
        "scheduled job execution is not wired to the agent runner",
    )
}

async fn interrupt_subagent_handler(
    State(state): State<AgentGatewayState>,
    Path(subagent_id): Path<String>,
) -> Response {
    let mut store = state.store.write();
    let Some(run) = store.runs.get_mut(&subagent_id) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "subagent_not_found",
            "subagent not found",
        );
    };
    if run.status == "started" {
        run.status = "stopping".to_string();
        run.cancel_requested.store(true, Ordering::Release);
    }
    drop(store);
    state.persist();
    json_response(
        StatusCode::ACCEPTED,
        json!({
            "object":"hermes.subagent.interrupt",
            "subagent_id":subagent_id,
            "status":"interrupt_requested"
        }),
    )
}

fn set_job_enabled(state: &AgentGatewayState, job_id: &str, enabled: bool) -> Response {
    let mut store = state.store.write();
    let Some(job) = store.jobs.get_mut(job_id) else {
        return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
    };
    job.view.enabled = enabled;
    job.view.updated_at = timestamp();
    let view = job.view.clone();
    json_response(StatusCode::OK, json!({"job":view}))
}

async fn run_local_agent(state: AgentGatewayState, run_id: String, text: String) {
    tokio::task::yield_now().await;
    let (session_id, cancel_requested) = {
        let store = state.store.read();
        let Some(run) = store.runs.get(&run_id) else {
            return;
        };
        (run.session_id.clone(), run.cancel_requested.clone())
    };

    if cancel_requested.load(Ordering::Acquire) {
        finish_cancelled(&state, &run_id, "client_stop");
        return;
    }

    let output_text = if let Some(source) = state.agent_source.clone() {
        let http_config = state.http_config.clone();
        let input = text.clone();
        let cancellation = cancel_requested.clone();
        let worker = tokio::task::spawn_blocking(move || {
            execute_rss_source(&source, http_config, input, cancellation)
        });
        match tokio::time::timeout(state.config.run_timeout, worker).await {
            Ok(Ok(Ok(value))) => vm_value_to_json(&value).to_string(),
            Ok(Ok(Err(error)))
                if cancel_requested.load(Ordering::Acquire) || error == "cancelled" =>
            {
                finish_cancelled(&state, &run_id, "client_stop");
                return;
            }
            Ok(Ok(Err(error))) => {
                finish_failed(&state, &run_id, error);
                return;
            }
            Ok(Err(error)) => {
                finish_failed(&state, &run_id, format!("RSS worker join failed: {error}"));
                return;
            }
            Err(_) => {
                cancel_requested.store(true, Ordering::Release);
                finish_cancelled(&state, &run_id, "run_timeout");
                return;
            }
        }
    } else {
        text.clone()
    };

    if cancel_requested.load(Ordering::Acquire) {
        finish_cancelled(&state, &run_id, "client_stop");
        return;
    }

    let mut store = state.store.write();
    let run_active = store.runs.get(&run_id).is_some_and(|run| {
        run.status == "started" && !run.cancel_requested.load(Ordering::Acquire)
    });
    if !run_active {
        drop(store);
        finish_cancelled(&state, &run_id, "client_stop");
        return;
    }
    if !store.sessions.contains_key(&session_id) {
        drop(store);
        finish_failed(&state, &run_id, "session not found".to_string());
        return;
    }

    let message = {
        let session = store
            .sessions
            .get_mut(&session_id)
            .expect("session was checked above");
        append_message(
            &mut session.view,
            &mut session.messages,
            "assistant",
            Value::String(output_text.clone()),
            Some(run_id.clone()),
            Some("stop".to_string()),
        )
    };
    let run = store.runs.get_mut(&run_id).expect("run was checked above");
    emit_event_locked(
        run,
        "message.delta",
        json!({"message_id":message.id, "delta":output_text, "role":"assistant"}),
    );
    emit_event_locked(
        run,
        "run.completed",
        json!({"status":"completed", "output":{"message":message}, "usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}),
    );
    run.status = "completed".to_string();
    drop(store);
    state.persist();
}

fn finish_cancelled(state: &AgentGatewayState, run_id: &str, reason: &str) {
    let mut store = state.store.write();
    if let Some(run) = store.runs.get_mut(run_id) {
        if matches!(run.status.as_str(), "completed" | "failed" | "cancelled") {
            drop(store);
            return;
        }
        emit_event_locked(
            run,
            "run.cancelled",
            json!({"status":"cancelled", "reason":reason}),
        );
        run.status = "cancelled".to_string();
    }
    drop(store);
    state.persist();
}

fn finish_failed(state: &AgentGatewayState, run_id: &str, error: String) {
    let mut store = state.store.write();
    if let Some(run) = store.runs.get_mut(run_id) {
        if matches!(run.status.as_str(), "completed" | "failed" | "cancelled") {
            drop(store);
            return;
        }
        emit_event_locked(run, "run.failed", json!({"error":error}));
        run.status = "failed".to_string();
    }
    drop(store);
    state.persist();
}

fn execute_rss_source(
    source: &str,
    http_config: HttpConfig,
    input: String,
    cancel_requested: Arc<AtomicBool>,
) -> Result<VmValue, String> {
    if cancel_requested.load(Ordering::Acquire) {
        return Err("cancelled".to_string());
    }
    let input_literal =
        serde_json::to_string(&input).map_err(|error| format!("encode RSS input: {error}"))?;
    let wrapped_source = format!("let input = {input_literal};\n{source}");
    let program = rustscript_vm::compile_source(&wrapped_source)
        .map_err(|error| format!("compile RSS run source: {error}"))?
        .program;
    let mut vm = Vm::new(program);
    vm.configure_http(http_config);
    HostFunctionRegistry::new()
        .bind_vm_cached(&mut vm)
        .map_err(|error| format!("bind RSS host functions: {error}"))?;
    loop {
        if cancel_requested.load(Ordering::Acquire) {
            vm.cancel_waiting_host_op();
            return Err("cancelled".to_string());
        }
        match vm
            .run()
            .map_err(|error| format!("run RSS source: {error}"))?
        {
            VmStatus::Halted => {
                return vm
                    .stack()
                    .last()
                    .cloned()
                    .ok_or_else(|| "RSS source halted without a result".to_string());
            }
            VmStatus::Waiting(_) => vm
                .wait_for_host_op_blocking_with_cancel(|| cancel_requested.load(Ordering::Acquire))
                .map_err(|error| {
                    if cancel_requested.load(Ordering::Acquire) {
                        "cancelled".to_string()
                    } else {
                        format!("resume RSS host operation: {error}")
                    }
                })?,
            VmStatus::Yielded => continue,
        }
    }
}

fn vm_value_to_json(value: &VmValue) -> Value {
    match value {
        VmValue::Null => Value::Null,
        VmValue::Int(value) => json!(value),
        VmValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        VmValue::Bool(value) => json!(value),
        VmValue::String(value) => Value::String(value.to_string()),
        VmValue::Bytes(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        VmValue::Array(values) => Value::Array(values.iter().map(vm_value_to_json).collect()),
        VmValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        VmValue::Callable(_) => Value::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &VmValue) -> String {
    match value {
        VmValue::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

fn event_stream(
    history: Vec<GatewayEvent>,
    receiver: broadcast::Receiver<GatewayEvent>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(
        (history.into_iter(), receiver, false),
        |(mut history, mut receiver, mut done)| async move {
            if let Some(event) = history.next() {
                done |= event.is_terminal();
                return Some((Ok(event.into_sse()), (history, receiver, done)));
            }
            if done {
                return None;
            }
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        done |= event.is_terminal();
                        return Some((Ok(event.into_sse()), (history, receiver, done)));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    )
}

fn emit_event_locked(run: &mut RunRecord, event: &str, data: Value) {
    let event = GatewayEvent {
        event: event.to_string(),
        run_id: run.run_id.clone(),
        timestamp: timestamp(),
        data,
    };
    run.events.push(event.clone());
    let _ = run.sender.send(event);
}

fn append_message(
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

fn input_text(input: &Value) -> String {
    match input {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, json!({"error":{"code":code,"message":message}}))
}
