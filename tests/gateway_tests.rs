use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

async fn json_request(
    app: &axum::Router,
    method: axum::http::Method,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

#[tokio::test]
async fn health_models_and_sessions_follow_hermes_envelopes() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default());
    let app = build_agent_gateway_app(state);

    let (health_status, health) = json_request(
        &app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
    )
    .await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health["status"], "ok");
    assert!(health["active_agents"].is_number());

    let (models_status, models) =
        json_request(&app, axum::http::Method::GET, "/v1/models", Value::Null).await;
    assert_eq!(models_status, StatusCode::OK);
    assert_eq!(models["object"], "list");
    assert!(
        models["data"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let (create_status, created) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"source":"yahu", "model":"local-agent", "title":"Test"}),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    assert_eq!(created["object"], "hermes.session");
    let session_id = created["session"]["id"].as_str().expect("session id");

    let (list_status, sessions) = json_request(
        &app,
        axum::http::Method::GET,
        "/api/sessions?limit=10&offset=0",
        Value::Null,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(sessions["object"], "list");
    assert_eq!(sessions["data"][0]["id"], session_id);
}

#[tokio::test]
async fn run_returns_202_and_sse_contains_terminal_events() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default());
    let app = build_agent_gateway_app(state);

    let (session_status, session) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"source":"yahu", "model":"local-agent"}),
    )
    .await;
    assert_eq!(session_status, StatusCode::CREATED);
    let session_id = session["session"]["id"].as_str().expect("session id");

    let (run_status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"session_id":session_id, "input":"hello from yahu"}),
    )
    .await;
    assert_eq!(run_status, StatusCode::ACCEPTED);
    assert_eq!(run["status"], "started");
    let run_id = run["run_id"].as_str().expect("run id");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri(format!("/v1/runs/{run_id}/events"))
                .header("accept", "text/event-stream")
                .body(Body::empty())
                .expect("SSE request should build"),
        )
        .await
        .expect("SSE route should respond");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8");
    assert!(text.contains("message.delta"));
    assert!(text.contains("run.completed"));
    assert!(text.contains(run_id));
}

#[tokio::test]
async fn bearer_auth_is_enforced_when_configured() {
    let state = AgentGatewayState::new(AgentGatewayConfig {
        bearer_token: Some("test-token".to_string()),
        ..AgentGatewayConfig::default()
    });
    let app = build_agent_gateway_app(state);

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri("/health/detailed")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri("/health/detailed")
                .header("authorization", "Bearer test-token")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(authorized.status(), StatusCode::OK);
}

#[tokio::test]
async fn jobs_and_subagent_interrupt_follow_hermes_shapes() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default());
    let app = build_agent_gateway_app(state);

    let (create_status, created) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/jobs",
        json!({
            "name":"nightly",
            "schedule":"0 9 * * *",
            "prompt":"run local rss agent",
            "deliver":"telegram",
            "skills":["demo"],
            "repeat":2,
            "script":"ignored-for-hermes-compat"
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let job_id = created["job"]["id"].as_str().expect("job id");
    assert_eq!(created["job"]["schedule"], "0 9 * * *");

    let (list_status, list) =
        json_request(&app, axum::http::Method::GET, "/api/jobs", Value::Null).await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list["jobs"][0]["id"], job_id);

    let (pause_status, paused) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/api/jobs/{job_id}/pause"),
        Value::Null,
    )
    .await;
    assert_eq!(pause_status, StatusCode::OK);
    assert_eq!(paused["job"]["enabled"], false);

    let (hidden_status, hidden) =
        json_request(&app, axum::http::Method::GET, "/api/jobs", Value::Null).await;
    assert_eq!(hidden_status, StatusCode::OK);
    assert!(hidden["jobs"].as_array().is_some_and(Vec::is_empty));

    let (resume_status, resumed) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/api/jobs/{job_id}/resume"),
        Value::Null,
    )
    .await;
    assert_eq!(resume_status, StatusCode::OK);
    assert_eq!(resumed["job"]["enabled"], true);

    let (run_status, run) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/api/jobs/{job_id}/run"),
        Value::Null,
    )
    .await;
    assert_eq!(run_status, StatusCode::OK);
    assert_eq!(run["job"]["id"], job_id);

    let (output_status, output) = json_request(
        &app,
        axum::http::Method::GET,
        &format!("/api/jobs/{job_id}/output/latest"),
        Value::Null,
    )
    .await;
    assert_eq!(output_status, StatusCode::OK);
    assert!(output["output"].is_object());

    let (interrupt_status, interrupt) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/subagents/unknown/interrupt",
        Value::Null,
    )
    .await;
    assert_eq!(interrupt_status, StatusCode::NOT_FOUND);
    assert_eq!(interrupt["error"]["code"], "subagent_not_found");

    let (delete_status, deleted) = json_request(
        &app,
        axum::http::Method::DELETE,
        &format!("/api/jobs/{job_id}"),
        Value::Null,
    )
    .await;
    assert_eq!(delete_status, StatusCode::OK);
    assert_eq!(deleted["ok"], true);
}

#[tokio::test]
async fn sessions_and_jobs_reload_from_sqlite_state() {
    let path = std::env::temp_dir().join(format!("pd-edge-gateway-{}.db", Uuid::new_v4()));
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);

    let (session_status, session) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"id":"durable-session", "title":"durable"}),
    )
    .await;
    assert_eq!(session_status, StatusCode::CREATED);
    assert_eq!(session["session"]["id"], "durable-session");

    let (job_status, job) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/jobs",
        json!({"id":"durable-job", "name":"durable", "schedule":"manual"}),
    )
    .await;
    assert_eq!(job_status, StatusCode::CREATED);
    assert_eq!(job["job"]["id"], "durable-job");
    drop(app);

    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let (sessions_status, sessions) = json_request(
        &restored_app,
        axum::http::Method::GET,
        "/api/sessions",
        Value::Null,
    )
    .await;
    assert_eq!(sessions_status, StatusCode::OK);
    assert_eq!(sessions["data"][0]["id"], "durable-session");
    let (jobs_status, jobs) = json_request(
        &restored_app,
        axum::http::Method::GET,
        "/api/jobs",
        Value::Null,
    )
    .await;
    assert_eq!(jobs_status, StatusCode::OK);
    assert_eq!(jobs["jobs"][0]["id"], "durable-job");
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn configured_rss_source_runs_inside_the_vm() {
    let state = AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), "input;")
        .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (session_status, session) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"id":"rss-session"}),
    )
    .await;
    assert_eq!(session_status, StatusCode::CREATED);
    let session_id = session["session"]["id"].as_str().expect("session id");
    let (run_status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"session_id":session_id, "input":"from-rss"}),
    )
    .await;
    assert_eq!(run_status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let response = app
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri(format!("/v1/runs/{run_id}/events"))
                .body(Body::empty())
                .expect("SSE request should build"),
        )
        .await
        .expect("SSE route should respond");
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8");
    assert!(text.contains("from-rss"));
}

#[tokio::test]
async fn active_run_can_be_interrupted_as_a_subagent() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default());
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"interrupt-me"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let (status, body) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/api/subagents/{run_id}/interrupt"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["object"], "hermes.subagent.interrupt");
    assert_eq!(body["status"], "interrupt_requested");
}
