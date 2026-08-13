use std::{
    collections::HashMap,
    convert::Infallible,
    hash::{Hash, Hasher},
    path::Path as FsPath,
    sync::Arc,
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

use crate::service::PendingTerminal;
use crate::{AgentConfig, AgentRunner, RunCancellation, RunDeliveryError, RunEventSink, events};

use crate::gateway_store::{
    GatewayEvent, GatewayPersistence, GatewayStore, JobRecord, JobView, RunRecord, SessionMessage,
    SessionRecord, SessionView,
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
    pub event_channel_capacity: usize,
    pub max_events_per_run: usize,
    pub max_event_bytes: usize,
    pub terminal_run_ttl: Duration,
    pub cancellation_grace: Duration,
    pub janitor_interval: Duration,
    /// Bounded window during which a terminal commit that failed while
    /// storage was down is retried (janitor cadence). After the window the
    /// run's permit/handle/stream are released and the durable side is left
    /// for restart recovery, so a sustained outage cannot exhaust capacity.
    pub terminal_commit_retry_window: Duration,
    pub http: HttpConfig,
    pub sqlite: SqlitePolicy,
    pub fuel: Option<u64>,
}

impl AgentGatewayConfig {
    /// Validates that every lifecycle bound is positive.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_concurrent_runs == 0 {
            return Err("max_concurrent_runs must be positive".to_string());
        }
        if self.run_timeout.is_zero() {
            return Err("run_timeout must be positive".to_string());
        }
        if self.event_channel_capacity == 0 {
            return Err("event_channel_capacity must be positive".to_string());
        }
        if self.max_events_per_run == 0 {
            return Err("max_events_per_run must be positive".to_string());
        }
        if self.max_event_bytes == 0 {
            return Err("max_event_bytes must be positive".to_string());
        }
        if self.terminal_run_ttl.is_zero() {
            return Err("terminal_run_ttl must be positive".to_string());
        }
        if self.cancellation_grace.is_zero() {
            return Err("cancellation_grace must be positive".to_string());
        }
        if self.janitor_interval.is_zero() {
            return Err("janitor_interval must be positive".to_string());
        }
        if self.terminal_commit_retry_window.is_zero() {
            return Err("terminal_commit_retry_window must be positive".to_string());
        }
        Ok(())
    }
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
            event_channel_capacity: 64,
            max_events_per_run: 240,
            max_event_bytes: 32 * 1024,
            terminal_run_ttl: Duration::from_secs(60),
            cancellation_grace: Duration::from_secs(5),
            janitor_interval: Duration::from_secs(5),
            terminal_commit_retry_window: Duration::from_secs(300),
            http: HttpConfig::default(),
            sqlite,
            fuel: Some(10_000_000),
        }
    }
}

#[derive(Clone)]
pub struct AgentGatewayState {
    config: Arc<AgentGatewayConfig>,
    store: Arc<RwLock<GatewayStore>>,
    service: Arc<crate::service::AgentService>,
    agent_source: Option<Arc<String>>,
    http_config: HttpConfig,
}

impl AgentGatewayState {
    pub fn new(config: AgentGatewayConfig) -> Self {
        let http_config = config.http.clone();
        config
            .validate()
            .expect("gateway configuration must validate");
        let store = Arc::new(RwLock::new(GatewayStore::default()));
        let service = Arc::new(crate::service::AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            None,
            None,
            http_config.clone(),
        ));
        Self {
            config: Arc::clone(service.config()),
            store,
            service,
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
        let source = source.into();
        if source.len() > crate::MAX_AGENT_SOURCE_BYTES {
            return Err(format!(
                "RSS source exceeds {} bytes",
                crate::MAX_AGENT_SOURCE_BYTES
            ));
        }
        rustscript_vm::compile_source(&source)
            .map_err(|error| format!("compile RSS agent source: {error}"))?;
        let http_config = config.http.clone();
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let persistence = Arc::new(
            GatewayPersistence::open(&config, path.as_ref())
                .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        let store = Arc::new(RwLock::new(store));
        let agent_source = Some(Arc::new(source));
        let service = Arc::new(crate::service::AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            Some(persistence),
            agent_source.clone(),
            http_config.clone(),
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source,
            http_config,
        })
    }

    pub fn with_sqlite_path(
        config: AgentGatewayConfig,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        let http_config = config.http.clone();
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let persistence = Arc::new(
            GatewayPersistence::open(&config, path.as_ref())
                .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        let store = Arc::new(RwLock::new(store));
        let service = Arc::new(crate::service::AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            Some(persistence),
            None,
            http_config.clone(),
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
        })
    }

    pub fn service(&self) -> Arc<crate::service::AgentService> {
        Arc::clone(&self.service)
    }

    /// The typed storage repository handle (normalized schema), or `None`
    /// when no SQLite path is configured (in-memory only mode).
    pub fn persistence(&self) -> Option<Arc<GatewayPersistence>> {
        self.service.persistence_handle()
    }
}

/// Runs one store mutation on a blocking thread with the store write lock
/// held, so the blocking storage worker round-trip never occupies a Tokio
/// runtime thread (request runtimes stay responsive during storage stalls)
/// and durable-before-visible ordering is preserved. The closure receives
/// the write lock guard and the optional repository handle.
async fn store_mutation<T: Send + 'static>(
    state: AgentGatewayState,
    mutation: impl FnOnce(&mut GatewayStore, Option<&GatewayPersistence>) -> T + Send + 'static,
) -> T {
    tokio::task::spawn_blocking(move || {
        let mut store = state.store.write();
        let persistence = state.service.persistence_handle();
        mutation(&mut store, persistence.as_deref())
    })
    .await
    .expect("store mutation task must complete")
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
            bearer_auth_middleware,
        ))
        .with_state(state)
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
        // Runs whose terminal commit is awaiting the bounded durable retry
        // (observable instead of a silent leak).
        "terminal_pending": state.service.pending_terminal_count(),
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
    store_mutation(state.clone(), move |store, persistence| {
        let id = request
            .session_id
            .or(request.id)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = timestamp();
        let view = SessionView {
            id: id.clone(),
            object: "hermes.session".to_string(),
            title: request.title.clone(),
            model: request
                .model
                .clone()
                .unwrap_or_else(|| state.config.model.clone()),
            provider: request
                .provider
                .clone()
                .or_else(|| state.config.provider.clone()),
            source: request.source.clone().unwrap_or_else(|| "yahu".to_string()),
            system_prompt: request.system_prompt.clone(),
            created_at: now,
            updated_at: now,
            message_count: 0,
            end_reason: None,
        };
        if store.sessions.contains_key(&id) {
            return json_error(
                StatusCode::CONFLICT,
                "session_exists",
                "session already exists",
            );
        }
        // Durable before visible: the normalized session row is committed
        // through the typed `session.create` command while the write lock is
        // held; a failed commit leaves no in-memory session behind.
        if let Some(persistence) = persistence {
            let payload = json!({
                "id": id,
                "profile": "gateway",
                "platform": view.source,
                "account_id": id,
                "chat_id": "",
                "thread_id": "",
                "user_id": "",
                "generation": 1,
                "system_prompt": view.system_prompt.clone().unwrap_or_default(),
                "model": view.model,
                "provider": view.provider.clone().unwrap_or_default(),
                "toolset_hash": "",
                "metadata_json": "{}",
                "title": view.title.clone().unwrap_or_default(),
                "end_reason": view.end_reason.clone().unwrap_or_default(),
                "now_ms": now,
            });
            if let Err(error) = persistence.session_create(&payload) {
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "persistence_unavailable",
                    &format!("failed to persist session: {error}"),
                );
            }
        }
        let session = SessionRecord {
            view: view.clone(),
            messages: Vec::new(),
        };
        store.sessions.insert(id, session);
        json_response(
            StatusCode::CREATED,
            json!({"object":"hermes.session", "session":view, "data":view}),
        )
    })
    .await
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
    store_mutation(state.clone(), move |store, persistence| {
        if request.title.as_deref().is_some_and(str::is_empty) {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_title",
                "title is empty",
            );
        }
        let Some(session) = store.sessions.get_mut(&session_id) else {
            return json_error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            );
        };
        let previous = session.clone();
        if let Some(title) = request.title.clone() {
            session.view.title = Some(title);
        }
        if let Some(end_reason) = request.end_reason.clone() {
            session.view.end_reason = Some(end_reason);
        }
        session.view.updated_at = timestamp();
        let view = session.view.clone();
        // Durable before visible: `session.touch` commits the update; a
        // failed commit restores the previous in-memory session.
        if let Some(persistence) = persistence {
            let payload = json!({
                "session_id": session_id,
                "status": "active",
                "generation": 1,
                "system_prompt": view.system_prompt.clone().unwrap_or_default(),
                "model": view.model,
                "provider": view.provider.clone().unwrap_or_default(),
                "toolset_hash": "",
                "metadata_json": "{}",
                "title": view.title.clone().unwrap_or_default(),
                "end_reason": view.end_reason.clone().unwrap_or_default(),
                "now_ms": timestamp(),
            });
            if let Err(error) = persistence.session_touch(&payload) {
                *session = previous;
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "persistence_unavailable",
                    &format!("failed to persist session: {error}"),
                );
            }
        }
        json_response(
            StatusCode::OK,
            json!({"object":"hermes.session", "session":view, "data":view}),
        )
    })
    .await
}

async fn delete_session_handler(
    State(state): State<AgentGatewayState>,
    Path(session_id): Path<String>,
) -> Response {
    store_mutation(state.clone(), move |store, persistence| {
        let Some(session) = store.sessions.remove(&session_id) else {
            return json_error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            );
        };
        // Cascade: the session's runs and their retained events must not
        // dangle (reload validates every run's session reference), in
        // memory and durably. The typed `session.delete` removes every
        // dependent row in one transaction.
        let removed_runs: HashMap<String, RunRecord> = store
            .runs
            .iter()
            .filter(|(_, run)| run.session_id == session_id)
            .map(|(run_id, run)| (run_id.clone(), run.clone()))
            .collect();
        for run_id in removed_runs.keys() {
            store.runs.remove(run_id);
        }
        let durable = match persistence {
            Some(persistence) => persistence.session_delete(&session_id).map(|_| ()),
            None => Ok(()),
        };
        if let Err(error) = durable {
            store.sessions.insert(session_id.clone(), session);
            for (run_id, run) in removed_runs {
                store.runs.insert(run_id, run);
            }
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persistence_unavailable",
                &format!("failed to persist session deletion: {error}"),
            );
        }
        json_response(
            StatusCode::OK,
            json!({"object":"hermes.session.deleted", "id":session_id, "deleted":true}),
        )
    })
    .await
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
    let cancellation = RunCancellation::new();
    let http_config = state.http_config.clone();
    let sqlite_policy = state.config.sqlite.clone();
    let worker_input = input_text.clone();
    // The legacy chat completion path has no run record to deliver events to;
    // script events are validated and then discarded here. Run delivery is
    // the AgentService path (POST /v1/runs).
    let mut sink = DiscardingSink;
    let run_cancellation = cancellation.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let context = VmValue::map(vec![(
            VmValue::string("input"),
            VmValue::string(worker_input),
        )]);
        execute_rss_source(
            &source,
            http_config,
            sqlite_policy,
            context,
            &mut sink,
            &run_cancellation,
        )
    });
    let output = match tokio::time::timeout(state.config.run_timeout, &mut worker).await {
        Ok(Ok(Ok(value))) => vm_value_to_json(&value),
        Ok(Ok(Err(error))) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent_failed",
                &error.to_string(),
            );
        }
        Ok(Err(error)) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent_worker_failed",
                &format!("agent worker join failed: {error}"),
            );
        }
        Err(_) => {
            cancellation.request(rustscript_vm::CancellationReason::Deadline);
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut worker).await;
            return json_error(
                StatusCode::GATEWAY_TIMEOUT,
                "agent_timeout",
                "agent execution timed out",
            );
        }
    };

    // The legacy chat path appends both messages through the normalized
    // typed commands (session touch, then the two message rows); a failure
    // restores the previous in-memory session.
    store_mutation(state.clone(), move |store, persistence| {
        let Some(session) = store.sessions.get_mut(&session_id) else {
            return json_error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            );
        };
        let previous = session.clone();
        if let Some(model) = request.model.clone() {
            session.view.model = model;
        }
        if request.provider.is_some() {
            session.view.provider = request.provider.clone();
        }
        if request.instructions.is_some() {
            session.view.system_prompt = request.instructions.clone();
        }
        let user_message = append_message(
            &mut session.view,
            &mut session.messages,
            "user",
            input,
            None,
            None,
        );
        let assistant_message = append_message(
            &mut session.view,
            &mut session.messages,
            "assistant",
            output,
            None,
            Some("stop".to_string()),
        );
        let durable = (|| -> Result<(), String> {
            let Some(persistence) = persistence else {
                return Ok(());
            };
            let view = session.view.clone();
            let touch = json!({
                "session_id": session_id,
                "status": "active",
                "generation": 1,
                "system_prompt": view.system_prompt.clone().unwrap_or_default(),
                "model": view.model,
                "provider": view.provider.clone().unwrap_or_default(),
                "toolset_hash": "",
                "metadata_json": "{}",
                "title": view.title.clone().unwrap_or_default(),
                "end_reason": view.end_reason.clone().unwrap_or_default(),
                "now_ms": timestamp(),
            });
            persistence
                .session_touch(&touch)
                .map_err(|error| error.to_string())?;
            for (message, role) in [(&user_message, "user"), (&assistant_message, "assistant")] {
                let payload = json!({
                    "id": message.id,
                    "session_id": session_id,
                    "role": role,
                    "content_json": serde_json::to_string(&message.content)
                        .unwrap_or_else(|_| "null".to_string()),
                    "name": "",
                    "tool_call_id": "",
                    "parent_message_id": "",
                    "token_estimate": 0,
                    "metadata_json": "{}",
                    "run_id": message.run_id.clone().unwrap_or_default(),
                    "finish_reason": message.finish_reason.clone().unwrap_or_default(),
                    "now_ms": timestamp(),
                });
                persistence
                    .message_append(&payload)
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        })();
        if let Err(error) = durable {
            *session = previous;
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persistence_unavailable",
                &format!("failed to persist session: {error}"),
            );
        }
        json_response(
            StatusCode::OK,
            json!({
                "object":"hermes.session.chat.completion",
                "session_id":session_id,
                "message":assistant_message,
                "usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0},
            }),
        )
    })
    .await
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

    // Atomic admission: one reservation covers capacity, session, run ID,
    // cancellation and delivery state; rejection leaves nothing behind.
    let admitted = match state
        .service
        .admit(crate::service::AdmitRunRequest {
            input,
            session_id: request.session_id.clone(),
            model: request.model.clone(),
            provider: request.provider.clone(),
            parent_run_id: request.parent_run_id.clone(),
            instructions: request.instructions.clone(),
            platform: "api_server".to_string(),
            idempotency_key,
            idempotency_hash: request_hash,
        })
        .await
    {
        Ok(admitted) => admitted,
        Err(crate::service::AdmitError::RunLimitReached) => {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "run_limit_reached",
                "maximum concurrent run limit reached",
            );
        }
        Err(crate::service::AdmitError::IdempotencyConflict) => {
            return json_error(
                StatusCode::CONFLICT,
                "idempotency_key_reused",
                "idempotency key was used with a different request",
            );
        }
        Err(crate::service::AdmitError::ParentNotFound) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "parent_run_not_found",
                "parent run not found",
            );
        }
        Err(crate::service::AdmitError::SessionNotFound) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            );
        }
        Err(crate::service::AdmitError::Persistence(message)) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persistence_unavailable",
                &message,
            );
        }
        Err(crate::service::AdmitError::Invalid(message)) => {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_admission",
                &message,
            );
        }
    };
    if admitted.replayed {
        return json_response(
            StatusCode::ACCEPTED,
            json!({"run_id": admitted.run_id, "status": admitted.status}),
        );
    }
    let worker_state = state.clone();
    let worker_run_id = admitted.run_id.clone();
    tokio::spawn(async move {
        // A worker that exits without committing a terminal (for example a
        // panic) must fail the run rather than leave it started forever; the
        // terminal guard inside the commit functions makes this idempotent.
        let outcome = tokio::task::spawn(run_local_agent(
            worker_state.clone(),
            worker_run_id.clone(),
            agent_input,
        ))
        .await;
        if outcome.is_err() {
            finish_failed(
                worker_state,
                worker_run_id,
                failed_payload("agent worker exited without a terminal outcome".to_string()),
            )
            .await;
        }
    });
    json_response(
        StatusCode::ACCEPTED,
        json!({"run_id": admitted.run_id, "status": "started"}),
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
            run.sender.as_ref().map(|sender| sender.subscribe()),
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
    // The stop takes the store write lock; run it on a blocking thread so a
    // storage-stalled mutation never occupies a Tokio request thread.
    let state_for_block = state.clone();
    let run_id_for_block = run_id.clone();
    let status =
        tokio::task::spawn_blocking(move || state_for_block.service.stop(&run_id_for_block))
            .await
            .expect("stop task must not panic");
    let Some(status) = status else {
        return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
    };
    // `stopping` is an in-memory cancel state; the normalized schema keeps
    // the run `running` until the one terminal commit, so there is nothing
    // to persist here. A gateway crash mid-stop is repaired by restart
    // recovery exactly once.
    json_response(StatusCode::OK, json!({"run_id":run_id, "status":status}))
}

async fn create_job_handler(
    State(state): State<AgentGatewayState>,
    Json(request): Json<JobRequest>,
) -> Response {
    store_mutation(state.clone(), move |store, persistence| {
        let id = request
            .job_id
            .or(request.id)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = timestamp();
        let view = JobView {
            id: id.clone(),
            name: request
                .name
                .clone()
                .unwrap_or_else(|| "rustscript-agent".to_string()),
            schedule: request.schedule.clone().unwrap_or(Value::Null),
            prompt: request.prompt.clone().unwrap_or_default(),
            deliver: request.deliver.clone().unwrap_or(Value::Null),
            skills: request.skills.clone().unwrap_or_default(),
            repeat: request.repeat,
            enabled: request.enabled.unwrap_or(true),
            created_at: now,
            updated_at: now,
            last_run_at: None,
        };
        if store.jobs.contains_key(&id) {
            return json_error(StatusCode::CONFLICT, "job_exists", "job already exists");
        }
        let job = JobRecord {
            view: view.clone(),
            output: None,
        };
        // Durable before visible: the normalized job row is committed
        // through the typed `job.create` command.
        if let Some(persistence) = persistence {
            let payload = job_payload(&view, now);
            if let Err(error) = persistence.job_create(&payload) {
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "persistence_unavailable",
                    &format!("failed to persist job: {error}"),
                );
            }
        }
        store.jobs.insert(id, job);
        json_response(StatusCode::CREATED, json!({"job":view}))
    })
    .await
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
    store_mutation(state.clone(), move |store, persistence| {
        let Some(job) = store.jobs.get_mut(&job_id) else {
            return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
        };
        if let Some(name) = request.name.clone() {
            job.view.name = name;
        }
        if let Some(schedule) = request.schedule.clone() {
            job.view.schedule = schedule;
        }
        if let Some(prompt) = request.prompt.clone() {
            job.view.prompt = prompt;
        }
        if let Some(deliver) = request.deliver.clone() {
            job.view.deliver = deliver;
        }
        if let Some(skills) = request.skills.clone() {
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
        let previous = job.clone();
        if let Some(persistence) = persistence {
            let payload = job_payload(&view, view.updated_at);
            if let Err(error) = persistence.job_update(&payload) {
                *job = previous;
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "persistence_unavailable",
                    &format!("failed to persist job: {error}"),
                );
            }
        }
        json_response(StatusCode::OK, json!({"job":view}))
    })
    .await
}

async fn delete_job_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
) -> Response {
    store_mutation(state.clone(), move |store, persistence| {
        let Some(job) = store.jobs.remove(&job_id) else {
            return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
        };
        // Durable first: the typed `job.delete` reports the real
        // `rows_affected`. Zero rows means the durable side never had the
        // job (a divergence), so the in-memory removal is rolled back and
        // the caller gets the honest not-found response.
        let durable = match persistence {
            Some(persistence) => persistence.job_delete(&job_id),
            None => Ok(json!({"rows_affected": 1})),
        };
        match durable {
            Ok(data) => {
                let affected = data
                    .get("rows_affected")
                    .and_then(Value::as_i64)
                    .unwrap_or(1);
                if affected == 0 {
                    store.jobs.insert(job_id.clone(), job);
                    return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
                }
                json_response(
                    StatusCode::OK,
                    json!({"ok": true, "deleted": true, "rows_affected": affected}),
                )
            }
            Err(error) => {
                store.jobs.insert(job_id, job);
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "persistence_unavailable",
                    &format!("failed to persist job deletion: {error}"),
                )
            }
        }
    })
    .await
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
    set_job_enabled(state, job_id, false).await
}

async fn resume_job_handler(
    State(state): State<AgentGatewayState>,
    Path(job_id): Path<String>,
) -> Response {
    set_job_enabled(state, job_id, true).await
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
    // Same blocking-thread rule as stop: the interrupt takes the store
    // write lock and must never occupy a Tokio request thread.
    let state_for_block = state.clone();
    let subagent_id_for_block = subagent_id.clone();
    let found = tokio::task::spawn_blocking(move || {
        state_for_block
            .service
            .stop(&subagent_id_for_block)
            .is_some()
    })
    .await
    .expect("interrupt task must not panic");
    if !found {
        return json_error(
            StatusCode::NOT_FOUND,
            "subagent_not_found",
            "subagent not found",
        );
    }
    json_response(
        StatusCode::ACCEPTED,
        json!({
            "object":"hermes.subagent.interrupt",
            "subagent_id":subagent_id,
            "status":"interrupt_requested"
        }),
    )
}

async fn set_job_enabled(state: AgentGatewayState, job_id: String, enabled: bool) -> Response {
    store_mutation(state.clone(), move |store, persistence| {
        let Some(job) = store.jobs.get_mut(&job_id) else {
            return json_error(StatusCode::NOT_FOUND, "job_not_found", "job not found");
        };
        let previous = job.clone();
        job.view.enabled = enabled;
        job.view.updated_at = timestamp();
        let view = job.view.clone();
        if let Some(persistence) = persistence {
            let payload = job_payload(&view, view.updated_at);
            if let Err(error) = persistence.job_update(&payload) {
                *job = previous;
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "persistence_unavailable",
                    &format!("failed to persist job: {error}"),
                );
            }
        }
        json_response(StatusCode::OK, json!({"job":view}))
    })
    .await
}

/// Serializes one job view into the normalized `job.create`/`job.update`
/// command payload (schedules and deliveries are JSON-encoded text).
fn job_payload(view: &JobView, now: u64) -> Value {
    json!({
        "id": view.id,
        "name": view.name,
        "schedule_json": serde_json::to_string(&view.schedule).unwrap_or_else(|_| "{}".to_string()),
        "prompt": view.prompt,
        "deliver_json": serde_json::to_string(&view.deliver).unwrap_or_else(|_| "{}".to_string()),
        "skills_json": serde_json::to_string(&view.skills).unwrap_or_else(|_| "[]".to_string()),
        "repeat_count": view.repeat.unwrap_or(0),
        "enabled": if view.enabled { 1 } else { 0 },
        "now_ms": now,
    })
}

/// Outcome of the RSS worker: a completed value, a typed cancellation, or a
/// failure string. No string matching drives control flow; the variants are
/// decided from typed run outcomes.
enum WorkerOutcome {
    Completed(VmValue),
    Cancelled(&'static str),
    Failed(String),
}

async fn run_local_agent(state: AgentGatewayState, run_id: String, text: String) {
    tokio::task::yield_now().await;
    let Some(handle) = state.service.handle(&run_id) else {
        return;
    };
    let session_id = {
        let store = state.store.read();
        let Some(run) = store.runs.get(&run_id) else {
            return;
        };
        run.session_id.clone()
    };
    let cancellation = handle.cancel.clone();

    if cancellation.requested().is_some() {
        finish_cancelled(state.clone(), run_id.clone(), "requested".to_string()).await;
        return;
    }

    let output_text = if let Some(source) = state.agent_source.clone() {
        let http_config = state.http_config.clone();
        let sqlite_policy = state.config.sqlite.clone();
        let run_timeout = state.config.run_timeout;
        let input = text.clone();
        let context = build_run_context(&state, &run_id, &session_id, &input);
        // One bounded delivery path: the worker blocks on this channel when
        // the delivery task is busy, which pauses invocation polling
        // (backpressure). The delivery task validates, sequences, appends
        // durably, and only then publishes to live subscribers.
        let (sender, receiver) = tokio::sync::mpsc::channel(state.config.event_channel_capacity);
        let delivery = tokio::spawn(run_delivery_task(state.clone(), run_id.clone(), receiver));
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
                // The timeout is authoritative: cancel with the typed deadline
                // reason and wait only the configured grace for worker exit.
                cancellation.request(CancellationReason::Deadline);
                let _ = tokio::time::timeout(state.config.cancellation_grace, &mut worker).await;
                WorkerOutcome::Cancelled("deadline")
            }
        };
        // The worker dropped the channel sender when it returned; the delivery
        // task drains the remaining events and then exits. Wait only a bounded
        // grace for the drain so the terminal commit always follows the last
        // durably delivered script event.
        let delivery_outcome = tokio::time::timeout(Duration::from_secs(5), delivery)
            .await
            .ok()
            .and_then(|result| result.ok())
            .unwrap_or_default();
        match outcome {
            WorkerOutcome::Completed(value) => {
                if let Some(reason) = delivery_outcome.schema_violation {
                    finish_failed(
                        state.clone(),
                        run_id.clone(),
                        events::schema_violation_error(&reason),
                    )
                    .await;
                    return;
                }
                if delivery_outcome.persist_failed {
                    finish_failed(
                        state.clone(),
                        run_id.clone(),
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
                finish_cancelled(state.clone(), run_id.clone(), reason.to_string()).await;
                return;
            }
            WorkerOutcome::Failed(error) => {
                finish_failed(state.clone(), run_id.clone(), failed_payload(error)).await;
                return;
            }
        }
    } else {
        text.clone()
    };

    if cancellation.requested().is_some() {
        finish_cancelled(state.clone(), run_id.clone(), "requested".to_string()).await;
        return;
    }

    // Durable-before-visible terminal commit: the assistant message, the
    // two terminal events, and the run status change are committed in ONE
    // transaction (`run.terminal`) while the store write lock is held on a
    // blocking thread; only after the durable commit succeeds are the
    // terminal events published to live subscribers. A failed commit rolls
    // the in-memory mutation back and hands the prebuilt terminal to the
    // bounded retry loop (`terminal_pending`), which commits it exactly once
    // when storage recovers — the run is never left "started" forever and
    // no false terminal is ever published.
    let run_id_for_commit = run_id.clone();
    let retry_window = state.config.terminal_commit_retry_window;
    let max_event_bytes = state.config.max_event_bytes;
    let max_events_per_run = state.config.max_events_per_run;
    let outcome = store_mutation(state.clone(), move |store, persistence| {
        let run_active = store
            .runs
            .get(&run_id_for_commit)
            .is_some_and(|run| run.status == "started");
        if !run_active {
            return TerminalOutcome::NotActive;
        }
        let Some(session) = store.sessions.get_mut(&session_id) else {
            return TerminalOutcome::SessionMissing;
        };
        let previous_session_updated = session.view.updated_at;
        let message = append_message(
            &mut session.view,
            &mut session.messages,
            "assistant",
            Value::String(output_text.clone()),
            Some(run_id_for_commit.clone()),
            Some("stop".to_string()),
        );
        let run = store
            .runs
            .get_mut(&run_id_for_commit)
            .expect("run was checked above");
        let previous_status = run.status.clone();
        let previous_events = run.events.len();
        let delta_event = make_event_locked(
            run,
            "message.delta",
            json!({"message_id":message.id, "delta":output_text, "role":"assistant"}),
            max_event_bytes,
            max_events_per_run,
        );
        let completed_event = make_event_locked(
            run,
            "run.completed",
            json!({"status":"completed", "output":{"message":message}, "usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}),
            max_event_bytes,
            max_events_per_run,
        );
        run.status = "completed".to_string();
        let durable = terminal_commit(
            persistence,
            run,
            &session_id,
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
                // observably terminal-pending and the retry loop below owns
                // the exact same terminal (events, message, status).
                run.status = previous_status;
                run.events.truncate(previous_events);
                let session = store
                    .sessions
                    .get_mut(&session_id)
                    .expect("session was checked above");
                session.messages.pop();
                session.view.message_count = session.messages.len();
                session.view.updated_at = previous_session_updated;
                TerminalOutcome::TerminalPersistFailed {
                    error: error.to_string(),
                    pending: Box::new(PendingTerminal {
                        to_status: "completed".to_string(),
                        session_id: Some(session_id),
                        events: vec![delta_event, completed_event],
                        assistant_message: Some(message),
                        deadline: std::time::Instant::now() + retry_window,
                    }),
                }
            }
        }
    })
    .await;
    match outcome {
        TerminalOutcome::Committed => state.service.mark_terminal(&run_id),
        TerminalOutcome::NotActive => {
            finish_cancelled(state.clone(), run_id.clone(), "requested".to_string()).await;
        }
        TerminalOutcome::SessionMissing => {
            finish_failed(
                state.clone(),
                run_id.clone(),
                failed_payload("session not found".to_string()),
            )
            .await;
        }
        TerminalOutcome::TerminalPersistFailed { error, pending } => {
            tracing::error!(
                "failed to commit terminal state durably for {run_id}: {error}; \
                 retrying within the bounded window"
            );
            state.service.register_pending_terminal(&run_id, *pending);
            state.service.mark_terminal(&run_id);
            spawn_terminal_retry(state, run_id);
        }
    }
}

impl WorkerOutcome {
    /// Maps a typed runner error to the terminal outcome without string
    /// matching: cancellation/deadline/fuel/capability categories are decided
    /// from the typed variants.
    fn from_run_error(error: crate::RunError) -> Self {
        use crate::RunError;
        match error {
            RunError::Invocation(rustscript_vm::InvocationError::Cancelled(reason)) => {
                WorkerOutcome::Cancelled(reason.as_str())
            }
            RunError::Invocation(rustscript_vm::InvocationError::DeadlineReached { .. }) => {
                WorkerOutcome::Cancelled("deadline")
            }
            RunError::Invocation(rustscript_vm::InvocationError::OutOfFuel { .. }) => {
                WorkerOutcome::Failed("out_of_fuel".to_string())
            }
            RunError::Invocation(rustscript_vm::InvocationError::Capability(error)) => {
                WorkerOutcome::Failed(format!("capability_{}", error.code().as_str()))
            }
            RunError::Invocation(rustscript_vm::InvocationError::Host { message }) => {
                WorkerOutcome::Failed(message)
            }
            RunError::Invocation(rustscript_vm::InvocationError::Vm(error)) => {
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

/// Cancels a run with the typed reason through a durable-first terminal
/// commit: `run.terminal` commits the cancellation event and the status
/// change in one transaction, and only then is the event published. A
/// failed commit rolls the in-memory state back and hands the cancellation
/// to the bounded retry loop (`terminal_pending`), which commits and
/// publishes it exactly once when storage recovers.
async fn finish_cancelled(state: AgentGatewayState, run_id: String, reason: String) {
    let run_id_for_commit = run_id.clone();
    let retry_window = state.config.terminal_commit_retry_window;
    let max_event_bytes = state.config.max_event_bytes;
    let max_events_per_run = state.config.max_events_per_run;
    let outcome = store_mutation(state.clone(), move |store, persistence| {
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
        let event = make_event_locked(
            run,
            "run.cancelled",
            json!({"status":"cancelled", "reason":reason}),
            max_event_bytes,
            max_events_per_run,
        );
        run.status = "cancelled".to_string();
        match terminal_commit(persistence, run, "", "cancelled", &[&event], None) {
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
    .await;
    match outcome {
        TerminalOutcome::Committed => state.service.mark_terminal(&run_id),
        TerminalOutcome::TerminalPersistFailed { error, pending } => {
            tracing::error!(
                "failed to commit cancellation durably for {run_id}: {error}; \
                 retrying within the bounded window"
            );
            state.service.register_pending_terminal(&run_id, *pending);
            state.service.mark_terminal(&run_id);
            spawn_terminal_retry(state, run_id);
        }
        _ => {}
    }
}

/// Canonical run.failed payload from a plain failure message.
fn failed_payload(error: String) -> Value {
    json!({
        "status": "failed",
        "error_code": "agent_failed",
        "error_message": error,
    })
}

/// Fails a run through a durable-first terminal commit: `run.terminal`
/// commits the failure event and the status change in one transaction, and
/// only then is the event published. A failed commit rolls the in-memory
/// state back and hands the failure to the bounded retry loop
/// (`terminal_pending`), which commits and publishes it exactly once when
/// storage recovers.
async fn finish_failed(state: AgentGatewayState, run_id: String, data: Value) {
    let run_id_for_commit = run_id.clone();
    let retry_window = state.config.terminal_commit_retry_window;
    let max_event_bytes = state.config.max_event_bytes;
    let max_events_per_run = state.config.max_events_per_run;
    let outcome = store_mutation(state.clone(), move |store, persistence| {
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
        let event = make_event_locked(run, "run.failed", data, max_event_bytes, max_events_per_run);
        run.status = "failed".to_string();
        match terminal_commit(persistence, run, "", "failed", &[&event], None) {
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
    .await;
    match outcome {
        TerminalOutcome::Committed => state.service.mark_terminal(&run_id),
        TerminalOutcome::TerminalPersistFailed { error, pending } => {
            tracing::error!(
                "failed to commit failure durably for {run_id}: {error}; \
                 retrying within the bounded window"
            );
            state.service.register_pending_terminal(&run_id, *pending);
            state.service.mark_terminal(&run_id);
            spawn_terminal_retry(state, run_id);
        }
        _ => {}
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
        .and_then(Value::as_array)
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
            .and_then(Value::as_array)
            .ok_or_else(|| TerminalCommitError {
                code: "terminal_commit_invalid".to_string(),
                message: "run.terminal returned a malformed event row".to_string(),
            })?;
        let seq = row
            .first()
            .and_then(Value::as_u64)
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

/// Retries one run's pending terminal commit. Runs on a blocking thread
/// with the store write lock held (durable-before-visible). On success the
/// terminal events are published exactly once and the run record reaches
/// its true terminal state; on a typed transition conflict the pending
/// terminal is dropped without publishing (never a fabricated terminal).
async fn retry_pending_terminal(state: AgentGatewayState, run_id: &str) -> PendingRetryOutcome {
    let run_id_for_block = run_id.to_string();
    store_mutation(state.clone(), move |store, persistence| {
        // The retry owns the pending entry while it attempts the commit.
        let Some(pending) = state.service.take_pending_terminal(&run_id_for_block) else {
            return PendingRetryOutcome::Gone;
        };
        let Some(run) = store.runs.get_mut(&run_id_for_block) else {
            return PendingRetryOutcome::Gone;
        };
        if run.status != "terminal_pending" {
            return PendingRetryOutcome::Gone;
        }
        if std::time::Instant::now() >= pending.deadline {
            // Bounded: after the window no more events can ever be published
            // for this run in this process. Close the live stream so SSE
            // subscribers are not held forever; the handle is released via
            // its TTL and the durable side is repaired by restart recovery.
            close_run_stream(run);
            return PendingRetryOutcome::Expired;
        }
        let previous_status = run.status.clone();
        let previous_events = run.events.len();
        // Rebuild the terminal's assistant message under the same lock
        // (durable-before-visible: it is appended in memory only after the
        // durable commit succeeds).
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
            let max_events = state.config.max_events_per_run;
            if run.events.len() > max_events {
                let excess = run.events.len() - max_events;
                run.events.drain(0..excess);
            }
            run.status = pending.to_status.clone();
            terminal_commit(
                persistence,
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
                    store,
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
                    store,
                    &run_id_for_block,
                    &pending,
                    previous_status,
                    previous_events,
                    previous_session_updated,
                );
                state
                    .service
                    .put_pending_terminal(&run_id_for_block, pending);
                PendingRetryOutcome::RetryFailed
            }
        }
    })
    .await
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

/// Spawns the bounded retry loop for one run's pending terminal. The loop
/// retries on the janitor cadence until the terminal commits durably (then
/// publishes and releases the permit), the run disappears, the durable side
/// reports a terminal conflict, or the retry window expires.
fn spawn_terminal_retry(state: AgentGatewayState, run_id: String) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(state.config.janitor_interval);
        loop {
            interval.tick().await;
            match retry_pending_terminal(state.clone(), &run_id).await {
                PendingRetryOutcome::Committed
                | PendingRetryOutcome::Gone
                | PendingRetryOutcome::Conflict
                | PendingRetryOutcome::Expired => return,
                PendingRetryOutcome::RetryFailed => continue,
            }
        }
    });
}

/// Appends one service-owned event to the run's retained history and
/// returns it WITHOUT publishing: callers publish only after the durable
/// commit succeeds (durable-before-visible). Retention and byte bounds come
/// from the validated configuration.
fn make_event_locked(
    run: &mut RunRecord,
    event: &str,
    mut data: Value,
    max_event_bytes: usize,
    max_events_per_run: usize,
) -> GatewayEvent {
    if serde_json::to_vec(&data)
        .map(|payload| payload.len() > max_event_bytes)
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
    if run.events.len() > max_events_per_run {
        let excess = run.events.len() - max_events_per_run;
        run.events.drain(0..excess);
    }
    event
}

fn execute_rss_source(
    source: &str,
    http_config: HttpConfig,
    sqlite_policy: SqlitePolicy,
    context: VmValue,
    sink: &mut dyn RunEventSink,
    cancellation: &RunCancellation,
) -> std::result::Result<VmValue, crate::RunError> {
    if source.len() > crate::MAX_AGENT_SOURCE_BYTES {
        return Err(crate::RunError::Setup(rustscript_vm::VmError::HostError(
            format!("RSS source exceeds {} bytes", crate::MAX_AGENT_SOURCE_BYTES),
        )));
    }
    let runner = AgentRunner::from_source(
        source,
        AgentConfig {
            http: http_config,
            sqlite: sqlite_policy,
            fuel: None,
        },
    )
    .map_err(|error| {
        crate::RunError::Vm(rustscript_vm::VmError::HostError(format!(
            "compile RSS run source: {error}"
        )))
    })?;
    runner.run_with_context_and_events(context, sink, cancellation)
}

/// Bounded channel delivery sink: `blocking_send` pauses the worker (and
/// therefore invocation polling) while the delivery task is busy, and fails
/// once the receiver is gone.
struct ChannelEventSink(tokio::sync::mpsc::Sender<VmValue>);

impl RunEventSink for ChannelEventSink {
    fn deliver(&mut self, value: VmValue) -> std::result::Result<(), RunDeliveryError> {
        self.0
            .blocking_send(value)
            .map_err(|_| RunDeliveryError::Closed)
    }
}

/// Discards script events (used by the legacy chat completion path, which has
/// no run record for live delivery).
struct DiscardingSink;

impl RunEventSink for DiscardingSink {
    fn deliver(&mut self, _value: VmValue) -> std::result::Result<(), RunDeliveryError> {
        Ok(())
    }
}

/// Durable live delivery for one run.
///
/// For every script event: validate against the agent event schema, assign the
/// monotonic per-run sequence, append durably (persist) and only then publish
/// to live subscribers. Nothing is published after the run commits a terminal
/// state, and a failed append is rolled back so no unpersisted event is ever
/// visible.
/// Outcome of one delivery critical section: the event was durably appended
/// and may be published, the run ended (stop the stream), or the durable
/// append failed (roll back in memory, report persist failure).
enum DeliverOutcome {
    Published(GatewayEvent, broadcast::Sender<GatewayEvent>),
    RunEnded,
    PersistFailed(String),
}

async fn run_delivery_task(
    state: AgentGatewayState,
    run_id: String,
    mut receiver: tokio::sync::mpsc::Receiver<VmValue>,
) -> events::DeliveryOutcome {
    let mut outcome = events::DeliveryOutcome::default();
    while let Some(value) = receiver.recv().await {
        let event_type = match events::validate_script_event(&value) {
            Ok(event_type) => event_type.to_string(),
            Err(reason) => {
                if outcome.schema_violation.is_none() {
                    outcome.schema_violation = Some(reason.to_string());
                }
                continue;
            }
        };
        let data = events::script_event_data(&value);
        // The critical section (store write lock plus the blocking storage
        // worker round-trip) runs on a blocking thread so the request
        // runtime is never occupied by a storage stall.
        let state_for_block = state.clone();
        let run_id_for_block = run_id.clone();
        let event_type_for_block = event_type.clone();
        let data_for_block = data.clone();
        let delivered = tokio::task::spawn_blocking(move || {
            let mut store = state_for_block.store.write();
            let Some(run) = store.runs.get_mut(&run_id_for_block) else {
                return DeliverOutcome::RunEnded;
            };
            if matches!(
                run.status.as_str(),
                "completed" | "failed" | "cancelled" | "terminal_pending"
            ) {
                return DeliverOutcome::RunEnded;
            }
            let event = append_script_event_locked(
                run,
                &event_type_for_block,
                data_for_block,
                state_for_block.config.max_event_bytes,
                state_for_block.config.max_events_per_run,
            );
            // Durable before visible: the event row is committed through the
            // typed `event.append` transaction while the write lock is held;
            // on failure the in-memory append is rolled back so no
            // unpersisted event is ever visible.
            let durable = match state_for_block.persistence() {
                Some(persistence) => {
                    let payload = json!({
                        "run_id": run_id_for_block,
                        "event_id": event.event_id,
                        "event_type": event.event,
                        "payload_json": serde_json::to_string(&event.data)
                            .unwrap_or_else(|_| "{}".to_string()),
                        "now_ms": timestamp(),
                        "max_events": state_for_block.config.max_events_per_run,
                    });
                    persistence.event_append(&payload).map(|_| ())
                }
                None => Ok(()),
            };
            match durable {
                Ok(()) => DeliverOutcome::Published(
                    event,
                    run.sender
                        .as_ref()
                        .cloned()
                        .expect("the delivery channel exists while the run is active"),
                ),
                Err(error) => {
                    run.events
                        .retain(|existing| existing.event_id != event.event_id);
                    DeliverOutcome::PersistFailed(error.to_string())
                }
            }
        })
        .await
        .expect("delivery task must complete");
        match delivered {
            DeliverOutcome::Published(event, sender) => {
                outcome.delivered += 1;
                let _ = sender.send(event);
            }
            DeliverOutcome::RunEnded => break,
            DeliverOutcome::PersistFailed(error) => {
                tracing::error!("failed to append run event durably: {error}");
                outcome.persist_failed = true;
            }
        }
    }
    outcome
}

/// Appends one script event to the run's retained history and returns it with
/// the live delivery sender. Sequence and timestamps are AgentService-owned.
fn append_script_event_locked(
    run: &mut RunRecord,
    event_type: &str,
    mut data: Value,
    max_event_bytes: usize,
    max_events_per_run: usize,
) -> GatewayEvent {
    if serde_json::to_vec(&data)
        .map(|payload| payload.len() > max_event_bytes)
        .unwrap_or(true)
    {
        data = json!({"truncated":true,"original_bytes":"over_limit"});
    }
    let seq = run.events.last().map(|event| event.seq + 1).unwrap_or(1);
    let event = GatewayEvent {
        event_id: Uuid::new_v4().to_string(),
        seq,
        event: event_type.to_string(),
        run_id: run.run_id.clone(),
        timestamp: timestamp(),
        data,
    };
    run.events.push(event.clone());
    if run.events.len() > max_events_per_run {
        let excess = run.events.len() - max_events_per_run;
        run.events.drain(0..excess);
    }
    event
}

/// Builds the canonical structured run context (gateway-api plan 4.2) that is
/// passed as the sole argument to the exported `run(context)` callable.
fn build_run_context(
    state: &AgentGatewayState,
    run_id: &str,
    session_id: &str,
    input: &str,
) -> VmValue {
    let store = state.store.read();
    let session = store.sessions.get(session_id);
    let run = store.runs.get(run_id);
    let messages = session
        .map(|session| {
            json_to_vm_value(&serde_json::to_value(&session.messages).unwrap_or(Value::Null))
        })
        .unwrap_or(VmValue::array(vec![]));
    let system_prompt = session
        .and_then(|session| session.view.system_prompt.clone())
        .map(VmValue::string)
        .unwrap_or(VmValue::Null);
    let model = session
        .map(|session| session.view.model.clone())
        .unwrap_or_else(|| state.config.model.clone());
    let provider = session
        .and_then(|session| session.view.provider.clone())
        .or_else(|| state.config.provider.clone());
    let parent_run_id = run
        .and_then(|run| run.parent_run_id.clone())
        .map(VmValue::string)
        .unwrap_or(VmValue::Null);
    VmValue::map(vec![
        (VmValue::string("run_id"), VmValue::string(run_id)),
        (VmValue::string("session_id"), VmValue::string(session_id)),
        (VmValue::string("parent_run_id"), parent_run_id),
        (VmValue::string("platform"), VmValue::string("api_server")),
        (VmValue::string("input"), VmValue::string(input)),
        (VmValue::string("messages"), messages),
        (VmValue::string("system_prompt"), system_prompt),
        (VmValue::string("model"), VmValue::string(&model)),
        (
            VmValue::string("provider"),
            provider.map(VmValue::string).unwrap_or(VmValue::Null),
        ),
    ])
}

/// Converts one JSON value into a VM value (mirror of `vm_value_to_json`).
fn json_to_vm_value(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::Null,
        Value::Bool(value) => VmValue::Bool(*value),
        Value::Number(value) => value
            .as_i64()
            .map(VmValue::Int)
            .or_else(|| value.as_f64().map(VmValue::Float))
            .unwrap_or(VmValue::Null),
        Value::String(value) => VmValue::string(value),
        Value::Array(values) => VmValue::array(values.iter().map(json_to_vm_value).collect()),
        Value::Object(fields) => VmValue::map(
            fields
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm_value(value)))
                .collect(),
        ),
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
    receiver: Option<broadcast::Receiver<GatewayEvent>>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(
        (history.into_iter(), receiver, false),
        |(mut history, receiver, mut done)| async move {
            if let Some(event) = history.next() {
                done |= event.is_terminal();
                return Some((Ok(event.into_sse()), (history, receiver, done)));
            }
            if done {
                return None;
            }
            // A run whose live stream was closed (bounded terminal retry
            // expiry) ends the SSE after its retained history.
            let mut receiver = receiver?;
            match receiver.recv().await {
                Ok(event) => {
                    done |= event.is_terminal();
                    Some((Ok(event.into_sse()), (history, Some(receiver), done)))
                }
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    done = true;
                    let event = Event::default()
                        .event("error")
                        .data(json!({"code":"event_lagged","dropped":dropped}).to_string());
                    Some((Ok(event), (history, Some(receiver), done)))
                }
                Err(broadcast::error::RecvError::Closed) => None,
            }
        },
    )
}

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
