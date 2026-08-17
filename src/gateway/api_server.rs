//! API Server: the Axum router, handlers, auth/persistence middleware, and
//! SSE event streaming.
//!
//! Handlers normalize inbound platform data into canonical requests and
//! render canonical events; all run lifecycle decisions live in AgentService.
//! No provider parser, agent loop, private host function, or SQL statement
//! exists here.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, RETRY_AFTER},
    },
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::stream::{self, Stream};
use parking_lot::Mutex;
use rustscript_vm::CancellationReason;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::{AgentGatewayConfig, RateLimitConfig};
use crate::domain::{fnv1a64, input_text, timestamp, vm_value_to_json};
use crate::gateway::api_openai::openai_chat_completions_handler;
use crate::runtime::delivery::DiscardingSink;
use crate::runtime::rss_runner::execute_rss_source;
use crate::service::{
    AdmitError, ApprovalResolveError, ApprovalResolveOutcome, CompactConflict, CompactSessionError,
    CompactSessionOutcome, SubscriberGuard, failed_payload,
};
use crate::{
    AgentGatewayState, RunCancellation,
    gateway::store::{
        GatewayEvent, GatewayPersistence, GatewayStore, JobRecord, JobView, RunRecord, RunView,
        SessionRecord, SessionView, append_message,
    },
};

/// The durable `run.list` window cap (the storage program's bounded row
/// page; see `LOAD_PAGE_ROWS` in `src/gateway/store.rs`). Offset + limit
/// beyond this cannot be answered honestly from the durable store, so the
/// list rejects the window instead of silently truncating.
const DURABLE_RUN_LIST_CAP: usize = 512;

#[derive(Debug, Default, Deserialize)]
struct EventQuery {
    after_seq: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct RunListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    session_id: Option<String>,
    status: Option<String>,
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
    let rate_limiter = Arc::new(RateLimiter::new(state.config.rate_limit));
    let guard_config = Arc::clone(&state.config);
    Router::new()
        .route("/health/detailed", get(health_detailed_handler))
        .route("/metrics", get(metrics_handler))
        .route("/v1/models", get(models_handler))
        .route(
            "/v1/chat/completions",
            post(openai_chat_completions_handler),
        )
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
        .route(
            "/api/sessions/{session_id}/compact",
            post(session_compact_handler),
        )
        .route("/v1/runs", get(list_runs_handler).post(create_run_handler))
        .route("/v1/runs/{run_id}", get(get_run_handler))
        .route("/v1/runs/{run_id}/events", get(run_events_handler))
        .route("/v1/runs/{run_id}/stop", post(stop_run_handler))
        .route(
            "/v1/runs/{run_id}/approvals/{approval_id}/approve",
            post(approve_approval_handler),
        )
        .route(
            "/v1/runs/{run_id}/approvals/{approval_id}/deny",
            post(deny_approval_handler),
        )
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
        .route(
            "/api/subagents/{subagent_id}/interrupt",
            post(interrupt_subagent_handler),
        )
        .layer(DefaultBodyLimit::max(state.config.max_body_bytes))
        // Outermost guard: per-IP rate limiting (all requests), bearer
        // authentication, then per-account rate limiting (verified requests
        // only). Auth failures are rejected before any account token is
        // consumed, and the two rate-limit dimensions are keyed separately.
        .layer(middleware::from_fn(move |request, next| {
            gateway_guard_middleware(
                request,
                next,
                Arc::clone(&rate_limiter),
                Arc::clone(&guard_config),
            )
        }))
        .with_state(state)
}

/// Bounded, non-blocking in-memory token-bucket rate limiter keyed by
/// arbitrary identity strings (peer IP or bearer account).
///
/// Each bucket holds up to `burst` tokens and refills `burst` tokens per
/// `window`; one `check` consumes one token when available. The critical
/// section is a single short Mutex with no I/O, so request runtimes never
/// block on the limiter. Memory is bounded by `max_buckets`: stale buckets
/// (idle for a full window, i.e. fully refilled and therefore semantically
/// lossless to drop) are swept on access, and at the bound the stalest
/// bucket is evicted, so the table can never grow without limit.
struct RateLimiter {
    inner: Mutex<RateLimiterInner>,
    window: Duration,
    max_buckets: usize,
    sweep_interval: Duration,
}

struct RateLimiterInner {
    buckets: HashMap<String, Bucket>,
    last_sweep: Instant,
}

struct Bucket {
    tokens: f64,
    refilled_at: Instant,
}

enum RateLimitOutcome {
    Allowed,
    Denied { retry_after: Duration },
}

impl RateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            window: config.window,
            max_buckets: config.max_buckets,
            // Sweep at most once per window: an idle bucket is fully
            // refilled after one window, so dropping it is lossless.
            sweep_interval: config.window,
        }
    }

    /// Consumes one token from `key`'s bucket, refilling by elapsed time
    /// first. On denial, returns the seconds until at least one token
    /// refills (for the `Retry-After` header).
    fn check(&self, key: &str, burst: f64) -> RateLimitOutcome {
        let mut inner = self.inner.lock();
        let now = Instant::now();
        if now.duration_since(inner.last_sweep) >= self.sweep_interval {
            inner
                .buckets
                .retain(|_, bucket| now.duration_since(bucket.refilled_at) < self.window);
            inner.last_sweep = now;
        }
        if !inner.buckets.contains_key(key)
            && inner.buckets.len() >= self.max_buckets
            && let Some(stalest) = inner
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.refilled_at)
                .map(|(key, _)| key.clone())
        {
            // Evict only to make room for a new identity; an existing key
            // always keeps its bucket (evicting the caller's own bucket
            // would silently reset its limit).
            inner.buckets.remove(&stalest);
        }
        let bucket = inner.buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: burst,
            refilled_at: now,
        });
        let rate = burst / self.window.as_secs_f64();
        let elapsed = now.duration_since(bucket.refilled_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.refilled_at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitOutcome::Allowed
        } else {
            RateLimitOutcome::Denied {
                retry_after: self.retry_after(bucket.tokens, rate),
            }
        }
    }

    /// Seconds until the bucket refills at least one token, at least 1.
    fn retry_after(&self, tokens: f64, rate: f64) -> Duration {
        let seconds = ((1.0 - tokens) / rate).ceil().max(1.0) as u64;
        Duration::from_secs(seconds)
    }

    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.inner.lock().buckets.len()
    }
}

async fn gateway_guard_middleware(
    request: Request,
    next: Next,
    rate_limiter: Arc<RateLimiter>,
    config: Arc<AgentGatewayConfig>,
) -> Response {
    let request_id = gateway_request_id(request.headers());
    let mut request = request;
    let has_request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .is_some_and(|value| value == request_id);
    if !has_request_id && let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), value);
    }
    let is_openai_chat = request.uri().path() == "/v1/chat/completions";
    if config.rate_limit.enabled {
        // Peer-IP dimension: every request charges its IP bucket, including
        // auth failures (that is the anti-brute-force point). Without
        // ConnectInfo (router oneshot) the key falls back to a single
        // shared bucket, which only matters for in-process tests.
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect_info| connect_info.0.ip().to_string())
            .unwrap_or_else(|| "no-peer".to_string());
        if let RateLimitOutcome::Denied { retry_after } =
            rate_limiter.check(&format!("ip:{peer}"), f64::from(config.rate_limit.ip_burst))
        {
            return rate_limited_response(retry_after, &request_id, is_openai_chat);
        }
    }
    let Some(expected) = config.bearer_token.as_deref() else {
        return next.run(request).await;
    };
    let authorized = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| bearer_value_matches(value, expected));
    if !authorized {
        if is_openai_chat {
            return openai_guard_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or invalid bearer token",
                &request_id,
            );
        }
        return json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
        );
    }
    if config.rate_limit.enabled {
        // Account dimension: charged only after the bearer token verifies,
        // keyed by a hash of the verified identity. Failed authentication
        // can never pollute an authenticated account's budget.
        let account_key = format!("account:fnv64:{:016x}", fnv1a64(expected.as_bytes()));
        if let RateLimitOutcome::Denied { retry_after } =
            rate_limiter.check(&account_key, f64::from(config.rate_limit.account_burst))
        {
            return rate_limited_response(retry_after, &request_id, is_openai_chat);
        }
    }
    next.run(request).await
}

/// RFC 7235 treats the authentication scheme as case-insensitive.  Keep the
/// credential comparison constant-time while accepting `bearer`, `BEARER`,
/// and mixed-case spellings with exactly one credential token.
fn bearer_value_matches(value: &str, expected: &str) -> bool {
    let mut parts = value.split_ascii_whitespace();
    let Some(scheme) = parts.next() else {
        return false;
    };
    let Some(token) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && scheme.eq_ignore_ascii_case("bearer")
        && constant_time_eq(token.as_bytes(), expected.as_bytes())
}

/// Request identifiers used by middleware must follow the same bounded,
/// header-safe contract as the OpenAI handler's identifiers.
fn gateway_request_id(headers: &HeaderMap) -> String {
    let inbound = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value.chars().count() <= 128
                && value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        });
    inbound
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("req-{}", Uuid::new_v4()))
}

fn openai_guard_error(status: StatusCode, code: &str, message: &str, request_id: &str) -> Response {
    (
        status,
        [("x-request-id", request_id.to_string())],
        Json(json!({
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "code": code,
                "request_id": request_id,
            }
        })),
    )
        .into_response()
}

/// HTTP 429 with the seconds until at least one token refills.
fn rate_limited_response(retry_after: Duration, request_id: &str, openai: bool) -> Response {
    let seconds = retry_after.as_secs().max(1);
    if openai {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (RETRY_AFTER, seconds.to_string()),
                (
                    HeaderName::from_static("x-request-id"),
                    request_id.to_string(),
                ),
            ],
            Json(json!({
                "error": {
                    "message": "rate limit exceeded",
                    "type": "rate_limit_error",
                    "code": "rate_limited",
                    "request_id": request_id,
                }
            })),
        )
            .into_response();
    }
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(RETRY_AFTER, seconds.to_string())],
        Json(json!({
            "error": {
                "code": "rate_limited",
                "message": "rate limit exceeded",
            }
        })),
    )
        .into_response()
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

async fn health_detailed_handler(State(state): State<AgentGatewayState>) -> impl IntoResponse {
    // Both values come from the same atomic gauge snapshot the /metrics
    // scrape renders, so health and metrics can never disagree (one source
    // of truth) and neither endpoint ever touches the store.
    let snapshot = state.metrics.snapshot();
    Json(json!({
        "status": "ok",
        "active_agents": snapshot.active_runs.max(0),
        // Runs whose terminal commit is awaiting the bounded durable retry
        // (observable instead of a silent leak).
        "terminal_pending": snapshot.runs_terminal_pending.max(0),
        "agent": state.config.agent_name,
    }))
}

/// Prometheus text exposition of the bounded registry. Reads atomics only;
/// the scrape never blocks on the store or the storage worker.
async fn metrics_handler(State(state): State<AgentGatewayState>) -> Response {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render_prometheus(),
    )
        .into_response()
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
            generation: 1,
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
        let context = rustscript_vm::Value::map(vec![(
            rustscript_vm::Value::string("input"),
            rustscript_vm::Value::string(worker_input),
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
            cancellation.request(CancellationReason::Deadline);
            let _ = tokio::time::timeout(state.config.cancellation_grace, &mut worker).await;
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
            false,
            "",
        );
        let assistant_message = append_message(
            &mut session.view,
            &mut session.messages,
            "assistant",
            output,
            None,
            Some("stop".to_string()),
            false,
            "",
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

/// One run's mirror metadata (never the status source for the API): the
/// platform (the session's source) and the retained event mirror.
struct RunMirrorMeta {
    platform: String,
    event_count: usize,
    last_event_seq: u64,
}

fn run_mirror_meta(store: &GatewayStore, run_id: &str) -> Option<RunMirrorMeta> {
    let run = store.runs.get(run_id)?;
    Some(RunMirrorMeta {
        platform: run.platform.clone(),
        event_count: run.events.len(),
        last_event_seq: run.events.last().map(|event| event.seq).unwrap_or(0),
    })
}

/// Renders the canonical `hermes.run` envelope. The `error` object appears
/// only for the durable `failed` status (the durable error columns); a
/// zero `started_at`/`finished_at` renders as `null` (never a fabricated
/// timestamp).
fn run_view_json(view: &RunView) -> Value {
    let error = if view.status == "failed" {
        json!({"code": view.error_code, "message": view.error_message})
    } else {
        Value::Null
    };
    json!({
        "object": view.object,
        "run_id": view.run_id,
        "session_id": view.session_id,
        "parent_run_id": view.parent_run_id,
        "platform": view.platform,
        "status": view.status,
        "event_count": view.event_count,
        "last_event_seq": view.last_event_seq,
        "created_at": view.created_at,
        "started_at": (view.started_at > 0).then_some(view.started_at),
        "finished_at": (view.finished_at > 0).then_some(view.finished_at),
        "updated_at": view.updated_at,
        "error": error,
    })
}

/// GET /v1/runs/{run_id}: the run's status comes from the DURABLE run row
/// (`run.get`), never from the in-memory mirror (which keeps the legacy
/// `started` placeholder for active runs) — a run that never started can
/// never be reported as started. The storage read runs on a blocking
/// thread so a storage stall never occupies a Tokio request thread.
async fn get_run_handler(
    State(state): State<AgentGatewayState>,
    Path(run_id): Path<String>,
) -> Response {
    let meta = {
        let store = state.store.read();
        let Some(meta) = run_mirror_meta(&store, &run_id) else {
            return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
        };
        meta
    };
    let view = match state.service.persistence_handle() {
        Some(persistence) => {
            let result = tokio::task::spawn_blocking(move || persistence.run_get(&run_id))
                .await
                .expect("run.get task must complete");
            match result {
                Ok(data) => {
                    let row = data
                        .get("rows")
                        .and_then(Value::as_array)
                        .and_then(|rows| rows.first())
                        .and_then(Value::as_array)
                        .cloned();
                    let Some(mut view) = row.and_then(|row| RunView::from_durable_row(&row)) else {
                        return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
                    };
                    view.platform = meta.platform;
                    view.event_count = meta.event_count;
                    view.last_event_seq = meta.last_event_seq;
                    view
                }
                Err(error) => {
                    return json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "persistence_unavailable",
                        &format!("durable run lookup failed: {error}"),
                    );
                }
            }
        }
        // In-memory-only mode has no durable store; the mirror is the only
        // authoritative state (the status is the honest mirror status).
        None => {
            let store = state.store.read();
            let Some(run) = store.runs.get(&run_id) else {
                return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
            };
            RunView::from_mirror(run)
        }
    };
    json_response(StatusCode::OK, run_view_json(&view))
}

/// GET /v1/runs: the durable run list (newest first) with optional exact
/// `session_id` / `status` filters and bounded pagination. The window is
/// bounded by the storage program's row page; an offset + limit beyond it
/// is rejected typed instead of silently truncated.
async fn list_runs_handler(
    State(state): State<AgentGatewayState>,
    Query(query): Query<RunListQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    if offset.saturating_add(limit) > DURABLE_RUN_LIST_CAP {
        return json_error(
            StatusCode::BAD_REQUEST,
            "list_window_too_large",
            &format!(
                "the durable run list window (offset + limit) is bounded to \
                 {DURABLE_RUN_LIST_CAP} rows"
            ),
        );
    }
    let session_id = query.session_id.clone().unwrap_or_default();
    let status = query.status.clone().unwrap_or_default();
    let mirror = {
        let store = state.store.read();
        store
            .runs
            .iter()
            .map(|(run_id, run)| {
                (
                    run_id.clone(),
                    RunMirrorMeta {
                        platform: run.platform.clone(),
                        event_count: run.events.len(),
                        last_event_seq: run.events.last().map(|event| event.seq).unwrap_or(0),
                    },
                )
            })
            .collect::<HashMap<_, _>>()
    };
    let views = match state.service.persistence_handle() {
        Some(persistence) => {
            let result =
                tokio::task::spawn_blocking(move || persistence.run_list(&session_id, &status))
                    .await
                    .expect("run.list task must complete");
            match result {
                Ok(data) => data
                    .get("rows")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|row| {
                        let mut view = RunView::from_durable_row(row.as_array()?)?;
                        if let Some(meta) = mirror.get(&view.run_id) {
                            view.platform = meta.platform.clone();
                            view.event_count = meta.event_count;
                            view.last_event_seq = meta.last_event_seq;
                        }
                        Some(view)
                    })
                    .collect::<Vec<_>>(),
                Err(error) => {
                    return json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "persistence_unavailable",
                        &format!("durable run list failed: {error}"),
                    );
                }
            }
        }
        // In-memory-only fallback: the mirror, newest first by last event.
        None => {
            let store = state.store.read();
            let mut runs = store
                .runs
                .values()
                .filter(|run| session_id.is_empty() || run.session_id == session_id)
                .filter(|run| status.is_empty() || run.status == status)
                .collect::<Vec<_>>();
            runs.sort_by_key(|run| {
                std::cmp::Reverse(run.events.last().map(|event| event.timestamp).unwrap_or(0))
            });
            runs.into_iter().map(RunView::from_mirror).collect()
        }
    };
    let has_more = offset.saturating_add(limit) < views.len();
    let data = views
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|view| run_view_json(&view))
        .collect::<Vec<_>>();
    json_response(
        StatusCode::OK,
        json!({
            "object": "list",
            "data": data,
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
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
        format!("fnv64:{:016x}", fnv1a64(canonical.as_bytes()))
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
            origin_actor: None,
            request_overrides: Value::Object(Default::default()),
            session_messages: Vec::new(),
        })
        .await
    {
        Ok(admitted) => admitted,
        Err(AdmitError::RunLimitReached) => {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "run_limit_reached",
                "maximum concurrent run limit reached",
            );
        }
        Err(AdmitError::IdempotencyConflict) => {
            return json_error(
                StatusCode::CONFLICT,
                "idempotency_key_reused",
                "idempotency key was used with a different request",
            );
        }
        Err(AdmitError::ParentNotFound) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "parent_run_not_found",
                "parent run not found",
            );
        }
        Err(AdmitError::SessionNotFound) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            );
        }
        Err(AdmitError::Persistence(message)) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persistence_unavailable",
                &message,
            );
        }
        Err(AdmitError::Invalid(message)) => {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_admission",
                &message,
            );
        }
        Err(AdmitError::Halting) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway_halting",
                "gateway is halting; new runs are not admitted",
            );
        }
    };
    if admitted.replayed {
        return json_response(
            StatusCode::ACCEPTED,
            json!({"run_id": admitted.run_id, "status": admitted.status}),
        );
    }
    let service = state.service();
    let worker_run_id = admitted.run_id.clone();
    tokio::spawn(async move {
        // A worker that exits without committing a terminal (for example a
        // panic) must fail the run rather than leave it started forever; the
        // terminal guard inside the commit functions makes this idempotent.
        let outcome = tokio::task::spawn(
            service
                .clone()
                .run_worker(worker_run_id.clone(), agent_input),
        )
        .await;
        if outcome.is_err() {
            service
                .finish_failed(
                    &worker_run_id,
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
    let (history, receiver, subscriber_guard) = {
        let store = state.store.read();
        let Some(run) = store.runs.get(&run_id) else {
            return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
        };
        if let Some(cursor) = query.after_seq
            && let Some(earliest) = run.events.first().map(|event| event.seq)
            // Saturating: a u64::MAX cursor means "everything after the
            // maximum sequence" (an empty replay), never an overflow panic
            // or a wrapped cursor that looks older than retained history.
            && cursor.saturating_add(1) < earliest
        {
            return json_error(
                StatusCode::CONFLICT,
                "event_cursor_too_old",
                &format!("event cursor is older than retained history; earliest_seq={earliest}"),
            );
        }
        let receiver = run.sender.as_ref().map(|sender| sender.subscribe());
        let subscriber_guard = receiver.as_ref().map(|_| state.metrics.subscriber_guard());
        (
            run.events
                .iter()
                .filter(|event| query.after_seq.is_none_or(|cursor| event.seq > cursor))
                .cloned()
                .collect(),
            receiver,
            subscriber_guard,
        )
    };
    // Track this SSE connection as a live subscriber for the duration of
    // the stream; the drop guard (moved into the stream state) decides the
    // client-disconnect policy when the connection ends. The metrics guard
    // (RAII connection gauge + lag recording) rides the same stream state
    // and drops together with the service guard.
    let guard = state.service.attach_subscriber(&run_id);
    let stream = event_stream(history, receiver, guard, subscriber_guard);
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(state.config.sse_keepalive_interval)
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

/// The approval resolution body: actor/reason are optional (defaults:
/// `api_server` / empty). The durable bridge resolution runs on a blocking
/// thread (storage round-trip) and returns the typed outcome; the error
/// envelope carries the exact-once / AlreadyResolved / expired states
/// without string matching.
#[derive(Debug, Default, Deserialize)]
struct ApprovalResolutionRequest {
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

async fn approve_approval_handler(
    State(state): State<AgentGatewayState>,
    Path((run_id, approval_id)): Path<(String, String)>,
    Json(request): Json<ApprovalResolutionRequest>,
) -> Response {
    resolve_approval(state, run_id, approval_id, true, request).await
}

async fn deny_approval_handler(
    State(state): State<AgentGatewayState>,
    Path((run_id, approval_id)): Path<(String, String)>,
    Json(request): Json<ApprovalResolutionRequest>,
) -> Response {
    resolve_approval(state, run_id, approval_id, false, request).await
}

async fn resolve_approval(
    state: AgentGatewayState,
    run_id: String,
    approval_id: String,
    approve: bool,
    request: ApprovalResolutionRequest,
) -> Response {
    // Existence fast path under the read lock; a run that never started can
    // never be resolved (404 typed).
    if !state.store.read().runs.contains_key(&run_id) {
        return json_error(StatusCode::NOT_FOUND, "run_not_found", "run not found");
    }
    let actor = request.actor.unwrap_or_else(|| "api_server".to_string());
    let reason = request.reason.unwrap_or_default();
    let state_for_block = state.clone();
    let run_id_for_block = run_id.clone();
    let approval_id_for_block = approval_id.clone();
    let actor_for_block = actor.clone();
    let reason_for_block = reason.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        state_for_block.service().resolve_run_approval_for(
            &run_id_for_block,
            &approval_id_for_block,
            approve,
            &actor_for_block,
            &reason_for_block,
        )
    })
    .await
    .expect("approval resolution task must not panic");
    match &outcome {
        Ok(ApprovalResolveOutcome::Resumed { approved }) => approval_envelope(
            &run_id,
            &approval_id,
            &actor,
            &reason,
            if *approved { "approved" } else { "denied" },
        ),
        Ok(ApprovalResolveOutcome::Terminal { code }) => {
            approval_envelope(&run_id, &approval_id, &actor, &reason, code)
        }
        Err(ApprovalResolveError::NoPendingApproval) => json_error(
            StatusCode::CONFLICT,
            "no_pending_approval",
            "the run has no pending approval parked",
        ),
        Err(ApprovalResolveError::ApprovalIdMismatch) => json_error(
            StatusCode::CONFLICT,
            "approval_id_mismatch",
            "the run is parked on a different approval id",
        ),
        Err(ApprovalResolveError::AlreadyResolved) => json_error(
            StatusCode::CONFLICT,
            "already_resolved",
            "the approval was already resolved",
        ),
        Err(ApprovalResolveError::RunNotActive) => json_error(
            StatusCode::CONFLICT,
            "run_no_longer_waiting",
            "the run could not transition back to running",
        ),
        Err(ApprovalResolveError::BridgeUnavailable) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "approval_bridge_unavailable",
            "the durable approval bridge is not available",
        ),
        Err(ApprovalResolveError::ProgramUnavailable) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent_program_unavailable",
            "the production loop program is not available",
        ),
        Err(ApprovalResolveError::Storage(message)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence_unavailable",
            &format!("approval resolution failed: {message}"),
        ),
    }
}

/// The canonical `hermes.approval` resolution envelope.
fn approval_envelope(
    run_id: &str,
    approval_id: &str,
    actor: &str,
    reason: &str,
    status: &str,
) -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "object": "hermes.approval",
            "run_id": run_id,
            "approval_id": approval_id,
            "status": status,
            "actor": actor,
            "reason": reason,
        }),
    )
}

/// POST /api/sessions/{session_id}/compact: real manual session compaction.
///
/// The whole composition lives in `AgentService::compact_session`: the RSS
/// `compact.rss` policy decides the pair-preserving prefix, the service
/// creates a bounded auditable maintenance run (only when no
/// active/waiting/compacting run exists) and executes the planned A2 storage
/// commands through the typed worker. This handler only renders the typed
/// outcome — real compaction id/generation/range/status, a typed skip, a
/// typed 409 for active runs / in-flight compactions, and typed errors.
async fn session_compact_handler(
    State(state): State<AgentGatewayState>,
    Path(session_id): Path<String>,
) -> Response {
    if !state.store.read().sessions.contains_key(&session_id) {
        return json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        );
    }
    match state
        .service()
        .compact_session(&session_id, "api_server")
        .await
    {
        Ok(CompactSessionOutcome::Committed {
            compaction_id,
            run_id,
            generation,
            source_start_ordinal,
            source_end_ordinal,
            retained_tail_ordinal,
        }) => json_response(
            StatusCode::OK,
            json!({
                "object": "hermes.compaction",
                "compaction_id": compaction_id,
                "run_id": run_id,
                "session_id": session_id,
                "generation": generation,
                "source_start_ordinal": source_start_ordinal,
                "source_end_ordinal": source_end_ordinal,
                "retained_tail_ordinal": retained_tail_ordinal,
                "status": "committed",
            }),
        ),
        Ok(CompactSessionOutcome::Skipped { reason }) => json_response(
            StatusCode::OK,
            json!({
                "object": "hermes.compaction",
                "session_id": session_id,
                "status": "skipped",
                "reason": reason,
            }),
        ),
        Ok(CompactSessionOutcome::Conflict {
            kind: CompactConflict::ActiveRun,
            run_id: _,
            status,
        }) => json_error(
            StatusCode::CONFLICT,
            "run_active_conflict",
            &format!(
                "an agent run{} is active for this session; manual compaction is refused \
                 while a run is active",
                status
                    .as_deref()
                    .map(|status| format!(" ({status})"))
                    .unwrap_or_default()
            ),
        ),
        Ok(CompactSessionOutcome::Conflict {
            kind: CompactConflict::CompactionInProgress,
            ..
        }) => json_error(
            StatusCode::CONFLICT,
            "compaction_in_progress",
            "a compaction is already in progress for this session",
        ),
        Err(CompactSessionError::SessionNotFound) => json_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        ),
        Err(CompactSessionError::NoDurableStorage) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence_unavailable",
            "no durable storage is configured; compaction is unavailable",
        ),
        Err(CompactSessionError::Halting) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_halting",
            "the gateway is halting; no new compaction may start",
        ),
        Err(CompactSessionError::Plan(message)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "compaction_policy_unavailable",
            &message,
        ),
        Err(CompactSessionError::Storage(message)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence_unavailable",
            &format!("session compaction failed: {message}"),
        ),
    }
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

/// FNV-1a 64-bit hash of the canonical idempotency payload. The `fnv64:`
/// label matches the algorithm exactly, so persisted hashes stay
/// unambiguous regardless of the platform's `DefaultHasher`. Shared with the
/// Telegram adapter through `crate::domain::fnv1a64`.
fn event_stream(
    history: Vec<GatewayEvent>,
    receiver: Option<broadcast::Receiver<GatewayEvent>>,
    guard: Option<SubscriberGuard>,
    subscriber_guard: Option<crate::metrics::SubscriberGuard>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(
        (
            history.into_iter(),
            receiver,
            guard,
            subscriber_guard,
            false,
        ),
        |(mut history, receiver, mut guard, subscriber_guard, mut done)| async move {
            if let Some(event) = history.next() {
                done |= event.is_terminal();
                // A stream that ends because a terminal was delivered must
                // never request a client-disconnect cancellation.
                if event.is_terminal()
                    && let Some(guard) = guard.as_mut()
                {
                    guard.disarm();
                }
                return Some((
                    Ok(event.into_sse()),
                    (history, receiver, guard, subscriber_guard, done),
                ));
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
                    if event.is_terminal()
                        && let Some(guard) = guard.as_mut()
                    {
                        guard.disarm();
                    }
                    Some((
                        Ok(event.into_sse()),
                        (history, Some(receiver), guard, subscriber_guard, done),
                    ))
                }
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    // The subscriber fell behind the bounded broadcast
                    // buffer; the dropped count is observable, the stream
                    // ends instead of presenting a gap as if nothing
                    // happened, and the client reconnects for a full replay.
                    // The service guard stays armed: without a delivered
                    // terminal, a cancel-on-disconnect run treats this as a
                    // disconnect.
                    if let Some(guard) = &subscriber_guard {
                        guard.record_lag(dropped);
                    }
                    done = true;
                    let event = Event::default()
                        .event("error")
                        .data(json!({"code":"event_lagged","dropped":dropped}).to_string());
                    Some((
                        Ok(event),
                        (history, Some(receiver), guard, subscriber_guard, done),
                    ))
                }
                Err(broadcast::error::RecvError::Closed) => None,
            }
        },
    )
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, json!({"error":{"code":code,"message":message}}))
}

#[cfg(test)]
mod rate_limiter_tests {
    use super::*;

    fn limiter(window: Duration, max_buckets: usize) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            enabled: true,
            ip_burst: 1,
            account_burst: 1,
            window,
            max_buckets,
        })
    }

    #[test]
    fn burst_is_allowed_then_denied_with_retry_after() {
        let limiter = limiter(Duration::from_secs(60), 16);
        for _ in 0..3 {
            assert!(matches!(
                limiter.check("ip:a", 3.0),
                RateLimitOutcome::Allowed
            ));
        }
        let denied = limiter.check("ip:a", 3.0);
        let RateLimitOutcome::Denied { retry_after } = denied else {
            panic!("the burst-exceeding check must be denied");
        };
        assert!(
            retry_after >= Duration::from_secs(1),
            "Retry-After must advertise at least one second"
        );
    }

    #[test]
    fn keys_are_isolated() {
        let limiter = limiter(Duration::from_secs(60), 16);
        assert!(matches!(
            limiter.check("ip:1", 1.0),
            RateLimitOutcome::Allowed
        ));
        assert!(matches!(
            limiter.check("ip:2", 1.0),
            RateLimitOutcome::Allowed
        ));
        assert!(matches!(
            limiter.check("ip:1", 1.0),
            RateLimitOutcome::Denied { .. }
        ));
        assert!(matches!(
            limiter.check("account:2", 1.0),
            RateLimitOutcome::Allowed
        ));
    }

    #[test]
    fn bucket_refills_after_the_window() {
        let limiter = limiter(Duration::from_millis(100), 16);
        assert!(matches!(
            limiter.check("ip:a", 1.0),
            RateLimitOutcome::Allowed
        ));
        assert!(matches!(
            limiter.check("ip:a", 1.0),
            RateLimitOutcome::Denied { .. }
        ));
        std::thread::sleep(Duration::from_millis(200));
        assert!(matches!(
            limiter.check("ip:a", 1.0),
            RateLimitOutcome::Allowed
        ));
    }

    #[test]
    fn stale_buckets_are_swept() {
        let limiter = limiter(Duration::from_millis(100), 16);
        let _ = limiter.check("ip:a", 1.0);
        let _ = limiter.check("ip:b", 1.0);
        assert_eq!(limiter.bucket_count(), 2);
        std::thread::sleep(Duration::from_millis(250));
        let _ = limiter.check("ip:c", 1.0);
        assert_eq!(
            limiter.bucket_count(),
            1,
            "buckets idle for a full window must be swept on access"
        );
    }

    #[test]
    fn bucket_table_is_bounded_by_eviction() {
        let limiter = limiter(Duration::from_secs(60), 2);
        let _ = limiter.check("ip:a", 1.0);
        std::thread::sleep(Duration::from_millis(10));
        let _ = limiter.check("ip:b", 1.0);
        std::thread::sleep(Duration::from_millis(10));
        let _ = limiter.check("ip:c", 1.0);
        assert_eq!(
            limiter.bucket_count(),
            2,
            "the stalest bucket must be evicted at the bound"
        );
    }

    #[test]
    fn existing_key_never_evicts_its_own_bucket() {
        // A single identity at the bucket bound must still be limited (its
        // own bucket is never evicted to make room for itself).
        let limiter = limiter(Duration::from_secs(60), 1);
        assert!(matches!(
            limiter.check("ip:a", 2.0),
            RateLimitOutcome::Allowed
        ));
        assert!(matches!(
            limiter.check("ip:a", 2.0),
            RateLimitOutcome::Allowed
        ));
        assert!(matches!(
            limiter.check("ip:a", 2.0),
            RateLimitOutcome::Denied { .. }
        ));
    }
}
