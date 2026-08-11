use std::{
    collections::HashMap,
    convert::Infallible,
    hash::{Hash, Hasher},
    path::Path as FsPath,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::stream::{self, Stream};
use parking_lot::RwLock;
use rustscript_vm::{CancellationReason, HttpConfig, SqlitePolicy, Value as VmValue};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{AgentConfig, AgentRunner, RunCancellation, RunDeliveryError, RunEventSink};

#[path = "gateway_store.rs"]
mod gateway_store;
use gateway_store::{
    GatewayEvent, GatewayPersistence, GatewayStore, IdempotencyRecord, JobRecord, JobView,
    RunRecord, SessionMessage, SessionRecord, SessionView,
};

#[derive(Debug, Default, Deserialize)]
struct EventQuery {
    after_seq: Option<u64>,
}

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
    pub sqlite: SqlitePolicy,
    pub fuel: Option<u64>,
}

impl Default for AgentGatewayConfig {
    fn default() -> Self {
        let mut sqlite = SqlitePolicy::default();
        sqlite.limits.max_statements = 1024;
        Self {
            model: "local-agent".to_string(),
            provider: Some("local-agent".to_string()),
            agent_name: "local-rss-agent".to_string(),
            bearer_token: None,
            max_body_bytes: 4 * 1024 * 1024,
            max_concurrent_runs: 8,
            run_timeout: Duration::from_secs(900),
            http: HttpConfig::default(),
            sqlite,
            fuel: Some(10_000_000),
        }
    }
}

#[derive(Clone)]
struct AgentService {
    persistence: Option<Arc<GatewayPersistence>>,
}

impl AgentService {
    fn persist(&self, store: &GatewayStore) -> bool {
        let Some(persistence) = self.persistence.as_ref() else {
            return true;
        };
        if let Err(error) = persistence.save(store) {
            tracing::error!("failed to persist agent gateway state: {error}");
            return false;
        }
        true
    }
}

#[derive(Clone)]
pub struct AgentGatewayState {
    config: Arc<AgentGatewayConfig>,
    store: Arc<RwLock<GatewayStore>>,
    service: AgentService,
    agent_source: Option<Arc<String>>,
    http_config: HttpConfig,
}

impl AgentGatewayState {
    pub fn new(config: AgentGatewayConfig) -> Self {
        let http_config = config.http.clone();
        Self {
            config: Arc::new(config),
            store: Arc::new(RwLock::new(GatewayStore::default())),
            service: AgentService { persistence: None },
            agent_source: None,
            http_config,
        }
    }

    pub fn with_agent_source(
        config: AgentGatewayConfig,
        source: impl Into<String>,
    ) -> Result<Self, String> {
        let source = source.into();
        if source.len() > crate::MAX_AGENT_SOURCE_BYTES {
            return Err(format!(
                "RSS source exceeds {} bytes",
                crate::MAX_AGENT_SOURCE_BYTES
            ));
        }
        rustscript_vm::compile_source(&source)
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
        let mut state = Self::with_agent_source(config.clone(), source)?;
        let persistence = Arc::new(
            GatewayPersistence::open(&config, path.as_ref())
                .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        state.store = Arc::new(RwLock::new(store));
        state.service = AgentService {
            persistence: Some(persistence),
        };
        Ok(state)
    }

    pub fn with_sqlite_path(
        config: AgentGatewayConfig,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        let http_config = config.http.clone();
        let persistence = Arc::new(
            GatewayPersistence::open(&config, path.as_ref())
                .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        Ok(Self {
            config: Arc::new(config),
            store: Arc::new(RwLock::new(store)),
            service: AgentService {
                persistence: Some(persistence),
            },
            agent_source: None,
            http_config,
        })
    }

    fn persist(&self) -> bool {
        self.service.persist(&self.store.read())
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
    parent_run_id: Option<String>,
    instructions: Option<String>,
    #[serde(rename = "conversation_history")]
    conversation_history: Option<Value>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = (left.len() ^ right.len()) as u8;
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |=
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0);
    }
    difference == 0
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
        .is_some_and(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()));
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
            "owned_by": state.config.provider.clone().unwrap_or_else(|| "local-agent".to_string()),
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
    if !state.persist() {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence_unavailable",
            "failed to persist session",
        );
    }
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
            "session chat requires RUSTSCRIPT_AGENT_SCRIPT",
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
    let worker_cancellation = Arc::clone(&cancellation);
    let http_config = state.http_config.clone();
    let sqlite_policy = state.config.sqlite.clone();
    let worker_input = input_text.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        execute_rss_source(
            &source,
            http_config,
            sqlite_policy,
            worker_input,
            worker_cancellation,
        )
    });
    let output = match tokio::time::timeout(state.config.run_timeout, &mut worker).await {
        Ok(Ok(Ok((value, _events)))) => vm_value_to_json(&value),
        Ok(Ok(Err((error, _events)))) => {
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
            cancellation.store(true, Ordering::Release);
            let _ = worker.await;
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
    headers: HeaderMap,
    Json(request): Json<CreateRunRequest>,
) -> Response {
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let request_hash = idempotency_key.as_ref().map(|_| {
        let canonical = serde_json::to_string(&json!({
            "input": request.input.clone(),
            "session_id": request.session_id.clone(),
            "model": request.model.clone(),
            "provider": request.provider.clone(),
            "parent_run_id": request.parent_run_id.clone(),
            "instructions": request.instructions.clone(),
            "conversation_history": request.conversation_history.clone(),
            "extra": request.extra.clone(),
        }))
        .unwrap_or_default();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        canonical.hash(&mut hasher);
        format!("fnv64:{:016x}", hasher.finish())
    });
    let input = request.input.clone().unwrap_or(Value::Null);
    let text = input_text(&input);
    let agent_input = if request.conversation_history.is_none() && request.extra.is_empty() {
        text.clone()
    } else {
        serde_json::to_string(&json!({
            "input": input.clone(),
            "conversation_history": request.conversation_history.clone(),
            "options": request.extra.clone(),
        }))
        .map_err(|error| error.to_string())
        .unwrap_or_else(|_| text.clone())
    };
    let run_id = Uuid::new_v4().to_string();
    let cancel_requested = Arc::new(AtomicBool::new(false));
    let (sender, _) = broadcast::channel(32);
    let previous_session: Option<(String, Option<SessionRecord>)>;
    {
        let mut store = state.store.write();
        if let (Some(key), Some(hash)) = (idempotency_key.as_ref(), request_hash.as_ref())
            && let Some(existing) = store.idempotency.get(key)
        {
            if existing.request_hash != *hash {
                return json_error(
                    StatusCode::CONFLICT,
                    "idempotency_key_reused",
                    "idempotency key was used with a different request",
                );
            }
            let status = store
                .runs
                .get(&existing.run_id)
                .map(|run| run.status.clone())
                .unwrap_or_else(|| "unknown".to_string());
            return json_response(
                StatusCode::ACCEPTED,
                json!({"run_id": existing.run_id, "status": status}),
            );
        }
        if store
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
        if let Some(parent_run_id) = request.parent_run_id.as_ref()
            && !store.runs.contains_key(parent_run_id)
        {
            return json_error(
                StatusCode::NOT_FOUND,
                "parent_run_not_found",
                "parent run not found",
            );
        }
        let session_id = match request.session_id.clone() {
            Some(session_id) => {
                previous_session =
                    Some((session_id.clone(), store.sessions.get(&session_id).cloned()));
                session_id
            }
            None => {
                let id = Uuid::new_v4().to_string();
                previous_session = Some((id.clone(), None));
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
                store.sessions.insert(
                    id.clone(),
                    SessionRecord {
                        view,
                        messages: Vec::new(),
                    },
                );
                id
            }
        };
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
                parent_run_id: request.parent_run_id.clone(),
                status: "started".to_string(),
                events: Vec::new(),
                sender,
                cancel_requested: cancel_requested.clone(),
            },
        );
        if let Some(run) = store.runs.get_mut(&run_id) {
            emit_event_locked(
                run,
                "run.started",
                json!({"status":"started","session_id":session_id}),
            );
        }
        if let (Some(key), Some(hash)) = (idempotency_key.as_ref(), request_hash.as_ref()) {
            store.idempotency.insert(
                key.clone(),
                IdempotencyRecord {
                    request_hash: hash.clone(),
                    run_id: run_id.clone(),
                },
            );
        }
    }
    if !state.persist() {
        let mut store = state.store.write();
        store.runs.remove(&run_id);
        if let Some(key) = idempotency_key.as_ref() {
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
        drop(store);
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence_unavailable",
            "run admission could not be durably committed",
        );
    }
    let worker_state = state.clone();
    let worker_run_id = run_id.clone();
    tokio::spawn(async move {
        run_local_agent(worker_state, worker_run_id, agent_input).await;
    });
    json_response(
        StatusCode::ACCEPTED,
        json!({"run_id":run_id, "status":"started"}),
    )
}

async fn run_events_handler(
    State(state): State<AgentGatewayState>,
    Path(run_id): Path<String>,
    Query(query): Query<EventQuery>,
) -> Response {
    let (history, receiver) = {
        let store = state.store.read();
        let Some(run) = store.runs.get(&run_id) else {
            return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
        };
        if let Some(cursor) = query.after_seq
            && let Some(earliest) = run.events.first().map(|event| event.seq)
            && cursor + 1 < earliest
        {
            return json_error(
                StatusCode::CONFLICT,
                "event_cursor_too_old",
                &format!("event cursor is older than retained history; earliest_seq={earliest}"),
            );
        }
        (
            run.events
                .iter()
                .filter(|event| query.after_seq.is_none_or(|cursor| event.seq > cursor))
                .cloned()
                .collect(),
            run.sender.subscribe(),
        )
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
    json_response(
        StatusCode::NOT_IMPLEMENTED,
        json!({
            "experimental": true,
            "error": {
                "code": "job_execution_unavailable",
                "message": "scheduled job execution is not wired to the agent runner"
            }
        }),
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

fn append_runtime_events(state: &AgentGatewayState, run_id: &str, runtime_events: &[VmValue]) {
    if runtime_events.is_empty() {
        return;
    }
    let mut store = state.store.write();
    if let Some(run) = store.runs.get_mut(run_id) {
        for event in runtime_events {
            emit_event_locked(
                run,
                "runtime.emit",
                json!({"value": vm_value_to_json(event)}),
            );
        }
    }
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
        let sqlite_policy = state.config.sqlite.clone();
        let run_timeout = state.config.run_timeout;
        let input = text.clone();
        let cancellation = cancel_requested.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            execute_rss_source(&source, http_config, sqlite_policy, input, cancellation)
        });
        match tokio::time::timeout(run_timeout, &mut worker).await {
            Ok(Ok(Ok((value, runtime_events)))) => {
                append_runtime_events(&state, &run_id, &runtime_events);
                vm_value_to_json(&value).to_string()
            }
            Ok(Ok(Err((error, runtime_events))))
                if cancel_requested.load(Ordering::Acquire) || error == "cancelled" =>
            {
                append_runtime_events(&state, &run_id, &runtime_events);
                finish_cancelled(&state, &run_id, "client_stop");
                return;
            }
            Ok(Ok(Err((error, runtime_events)))) => {
                append_runtime_events(&state, &run_id, &runtime_events);
                finish_failed(&state, &run_id, error);
                return;
            }
            Ok(Err(error)) => {
                finish_failed(&state, &run_id, format!("RSS worker join failed: {error}"));
                return;
            }
            Err(_) => {
                cancel_requested.store(true, Ordering::Release);
                if let Ok(result) = worker.await {
                    match result {
                        Ok((_, runtime_events)) | Err((_, runtime_events)) => {
                            append_runtime_events(&state, &run_id, &runtime_events);
                        }
                    }
                }
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
    sqlite_policy: SqlitePolicy,
    input: String,
    cancel_requested: Arc<AtomicBool>,
) -> Result<(VmValue, Vec<VmValue>), (String, Vec<VmValue>)> {
    if cancel_requested.load(Ordering::Acquire) {
        return Err(("cancelled".to_string(), Vec::new()));
    }
    if source.len() > crate::MAX_AGENT_SOURCE_BYTES {
        return Err((
            format!("RSS source exceeds {} bytes", crate::MAX_AGENT_SOURCE_BYTES),
            Vec::new(),
        ));
    }
    let runner = AgentRunner::from_source(
        source,
        AgentConfig {
            http: http_config,
            sqlite: sqlite_policy,
            fuel: None,
        },
    )
    .map_err(|error| (format!("compile RSS run source: {error}"), Vec::new()))?;

    let events = Arc::new(Mutex::new(Vec::<VmValue>::new()));
    let mut sink = GatewayEventSink {
        events: Arc::clone(&events),
        max_events: 128,
    };

    // Bridge the legacy boolean stop flag into the typed cancellation handle.
    let cancellation = RunCancellation::new();
    let bridge_cancellation = cancellation.clone();
    let bridge_stop = Arc::new(AtomicBool::new(false));
    let bridge_cancel_flag = Arc::clone(&cancel_requested);
    let bridge_stop_flag = Arc::clone(&bridge_stop);
    let bridge = thread::spawn(move || {
        while !bridge_stop_flag.load(Ordering::Acquire) {
            if bridge_cancel_flag.load(Ordering::Acquire) {
                bridge_cancellation.request(CancellationReason::Requested);
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    let result =
        runner.run_with_context_and_events(VmValue::string(input), &mut sink, &cancellation);
    bridge_stop.store(true, Ordering::Release);
    let _ = bridge.join();

    let event_snapshot = events
        .lock()
        .map(|events| events.clone())
        .unwrap_or_default();
    match result {
        Ok(value) => Ok((value, event_snapshot)),
        Err(error) => Err((error.to_string(), event_snapshot)),
    }
}

/// Collects script-visible `stream::emit` values with a bounded cap.
struct GatewayEventSink {
    events: Arc<Mutex<Vec<VmValue>>>,
    max_events: usize,
}

impl RunEventSink for GatewayEventSink {
    fn deliver(&mut self, value: VmValue) -> Result<(), RunDeliveryError> {
        let mut events = self.events.lock().map_err(|_| RunDeliveryError::Rejected {
            code: "sink_lock",
            message: "event sink lock poisoned".to_string(),
        })?;
        if events.len() >= self.max_events {
            return Err(RunDeliveryError::Rejected {
                code: "event_limit",
                message: format!("runtime event limit of {} exceeded", self.max_events),
            });
        }
        events.push(value);
        Ok(())
    }
}

pub(crate) fn vm_value_to_json(value: &VmValue) -> Value {
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
            match receiver.recv().await {
                Ok(event) => {
                    done |= event.is_terminal();
                    Some((Ok(event.into_sse()), (history, receiver, done)))
                }
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    done = true;
                    let event = Event::default()
                        .event("error")
                        .data(json!({"code":"event_lagged","dropped":dropped}).to_string());
                    Some((Ok(event), (history, receiver, done)))
                }
                Err(broadcast::error::RecvError::Closed) => None,
            }
        },
    )
}

fn emit_event_locked(run: &mut RunRecord, event: &str, mut data: Value) {
    const MAX_EVENT_BYTES: usize = 32 * 1024;
    const MAX_EVENTS_PER_RUN: usize = 240;
    if serde_json::to_vec(&data)
        .map(|payload| payload.len() > MAX_EVENT_BYTES)
        .unwrap_or(true)
    {
        data = json!({"truncated":true,"original_bytes":"over_limit"});
    }
    let seq = run.events.last().map(|event| event.seq + 1).unwrap_or(1);
    let event = GatewayEvent {
        event_id: Uuid::new_v4().to_string(),
        seq,
        event: event.to_string(),
        run_id: run.run_id.clone(),
        timestamp: timestamp(),
        data,
    };
    run.events.push(event.clone());
    if run.events.len() > MAX_EVENTS_PER_RUN {
        let excess = run.events.len() - MAX_EVENTS_PER_RUN;
        run.events.drain(0..excess);
    }
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

pub(crate) fn timestamp() -> u64 {
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
