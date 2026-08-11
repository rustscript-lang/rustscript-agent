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
    assert!(text.contains("\"delta\""));
    assert!(text.contains("\"output\""));
    assert!(text.contains("\"usage\""));
    assert!(!text.contains("\"data\":{\"delta\""));
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
    assert_eq!(run_status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(run["error"]["code"], "job_execution_unavailable");

    let (output_status, output) = json_request(
        &app,
        axum::http::Method::GET,
        &format!("/api/jobs/{job_id}/output/latest"),
        Value::Null,
    )
    .await;
    assert_eq!(output_status, StatusCode::OK);
    assert!(output["output"].is_null());

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
    let path = std::env::temp_dir().join(format!("rustscript-agent-gateway-{}.db", Uuid::new_v4()));
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
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { let text: string = input[\"input\"]; text; }",
    )
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

/// Reads one run's full SSE body.
async fn read_run_events(app: &axum::Router, run_id: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri(format!("/v1/runs/{run_id}/events"))
                .body(Body::empty())
                .expect("SSE request should build"),
        )
        .await
        .expect("SSE route should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8")
}

#[tokio::test]
async fn script_events_stream_in_order_before_the_terminal() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "model.started", "model": "local"});
            stream::emit({"type": "model.delta", "delta": "hello"});
            "done";
        }
        "#,
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"emit-order"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    let started = text.find("model.started").expect("model.started event");
    let delta = text.find("model.delta").expect("model.delta event");
    let completed = text.find("run.completed").expect("terminal event");
    assert!(
        started < delta && delta < completed,
        "script events must stream before the terminal event"
    );
    assert!(
        text.contains("\"seq\":1") && text.contains("\"seq\":2"),
        "AgentService must assign monotonic per-run sequence numbers"
    );
    assert!(
        text.contains("\"event\":\"model.started\"") && text.contains("\"event\":\"model.delta\""),
        "script events must be delivered live with their canonical names"
    );
}

#[tokio::test]
async fn invalid_script_event_fails_the_run_with_a_typed_code() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "not_a_canonical_event"});
            "done";
        }
        "#,
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"schema-violation"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    assert!(
        text.contains("run.failed") && text.contains("invalid_event_schema"),
        "a schema-violating event must fail the run with the typed code"
    );
    assert!(
        !text.contains("run.completed"),
        "no success terminal may be committed after a schema violation"
    );
}

#[tokio::test]
async fn script_events_are_appended_durably_before_live_publish() {
    let path = std::env::temp_dir().join(format!("rustscript-agent-events-{}.db", Uuid::new_v4()));
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "model.started", "model": "local"});
            "durable";
        }
        "#,
        &path,
    )
    .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"durable"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    assert!(
        text.contains("model.started") && text.contains("run.completed"),
        "the live stream must publish the event and the terminal"
    );
    drop(app);

    // A fresh gateway reloads only what was persisted: the script event must
    // have been appended durably before it was ever published live.
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let restored_text = read_run_events(&restored_app, run_id).await;
    assert!(
        restored_text.contains("model.started")
            && restored_text.contains("\"seq\":1")
            && restored_text.contains("run.completed"),
        "the script event must be replayed from durable storage after restart"
    );
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn atomic_admission_admits_exactly_the_configured_count() {
    // A pure CPU loop keeps admitted runs active so capacity is exercised.
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            max_concurrent_runs: 2,
            ..AgentGatewayConfig::default()
        },
        r#"
        pub fn run(input: map) -> string {
            while true {
                1;
            }
            "unreachable";
        }
        "#,
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);

    let requests = (0..4).map(|index| {
        let app = app.clone();
        async move {
            let (status, body) = json_request(
                &app,
                axum::http::Method::POST,
                "/v1/runs",
                json!({"input": format!("concurrent-{index}")}),
            )
            .await;
            (status, body)
        }
    });
    let responses = futures_util::future::join_all(requests).await;
    let accepted = responses
        .iter()
        .filter(|(status, _)| *status == StatusCode::ACCEPTED)
        .count();
    let rejected = responses
        .iter()
        .filter(|(status, _)| *status == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!(
        accepted, 2,
        "exactly the configured capacity must be admitted"
    );
    assert_eq!(rejected, 2, "overflow admissions must be rejected");

    // Rejected admission leaves no empty session/run behind: only the two
    // accepted runs created sessions.
    let (_, sessions) = json_request(
        &app,
        axum::http::Method::GET,
        "/api/sessions?limit=50&offset=0",
        Value::Null,
    )
    .await;
    assert_eq!(
        sessions["data"].as_array().map(Vec::len),
        Some(2),
        "rejected admissions must not leave empty sessions behind"
    );

    // Stop both admitted runs; each must reach a typed cancellation within a
    // bounded worker exit.
    for (_, body) in responses
        .iter()
        .filter(|(status, _)| *status == StatusCode::ACCEPTED)
    {
        let run_id = body["run_id"].as_str().expect("run id");
        let (stop_status, _) = json_request(
            &app,
            axum::http::Method::POST,
            &format!("/v1/runs/{run_id}/stop"),
            Value::Null,
        )
        .await;
        assert_eq!(stop_status, StatusCode::OK);
        let text = read_run_events(&app, run_id).await;
        assert!(
            text.contains("run.cancelled"),
            "a stopped run must commit one typed cancellation"
        );
    }
}

#[tokio::test]
async fn stop_and_timeout_finish_within_bounded_worker_exit() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            run_timeout: std::time::Duration::from_millis(300),
            ..AgentGatewayConfig::default()
        },
        r#"
        pub fn run(input: map) -> string {
            while true {
                1;
            }
            "unreachable";
        }
        "#,
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);

    // Timeout: the pure CPU loop must reach terminal cancellation within the
    // configured bound.
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"timeout-me"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let started = std::time::Instant::now();
    let text = read_run_events(&app, run_id).await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "timeout must finish within the bounded worker exit"
    );
    assert!(
        text.contains("run.cancelled"),
        "a timed-out run must commit a typed cancellation"
    );

    // Stop: bounded exit as well.
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"stop-me"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let (stop_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    assert_eq!(stop_status, StatusCode::OK);
    let started = std::time::Instant::now();
    let text = read_run_events(&app, run_id).await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "stop must finish within the bounded worker exit"
    );
    assert!(text.contains("run.cancelled"));
}

#[tokio::test]
async fn terminal_commit_is_single_and_late_stop_is_idempotent() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"done\"; }",
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"single-terminal"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    assert_eq!(
        text.matches("event: run.completed").count(),
        1,
        "exactly one terminal commit is allowed"
    );

    // A late stop must not produce a second terminal.
    let (stop_status, stop_body) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    assert_eq!(stop_status, StatusCode::OK);
    assert_eq!(stop_body["status"], "completed");
    let after = read_run_events(&app, run_id).await;
    assert_eq!(
        after.matches("event: run.completed").count(),
        1,
        "a late stop must not add a second terminal commit"
    );
}

#[tokio::test]
async fn terminal_handles_are_released_after_the_configured_ttl() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            terminal_run_ttl: std::time::Duration::from_millis(300),
            janitor_interval: std::time::Duration::from_millis(100),
            ..AgentGatewayConfig::default()
        },
        "pub fn run(input: map) -> string { \"ttl\"; }",
    )
    .expect("RSS source should compile");
    let service = state.service();
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"ttl"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let _ = read_run_events(&app, run_id).await;
    // The terminal handle is retained for replay handoff right after the run...
    assert_eq!(service.handle_count(), 1);
    // ...and released by the janitor after the TTL.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    assert_eq!(
        service.handle_count(),
        0,
        "terminal lifecycle handles must be released after the TTL"
    );
}

#[tokio::test]
async fn typed_capability_failure_marks_the_run_failed() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        r#"
        use http;
        pub fn run(input: map) -> map {
            http::client::request({ method: "GET", url: "http://127.0.0.1:1/" });
        }
        "#,
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"capability"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    assert!(
        text.contains("run.failed") && text.contains("capability_"),
        "a typed capability failure must mark the run failed, got: {text}"
    );
}

#[tokio::test]
async fn stop_racing_completion_commits_exactly_one_terminal() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"raced\"; }",
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"race"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    // Stop immediately; the run may complete or cancel, but never both.
    let _ = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    let text = read_run_events(&app, run_id).await;
    let terminals = text.matches("event: run.completed").count()
        + text.matches("event: run.cancelled").count()
        + text.matches("event: run.failed").count();
    assert_eq!(
        terminals, 1,
        "a stop racing completion must commit exactly one terminal, got: {text}"
    );
}

#[tokio::test]
async fn no_events_are_published_after_the_terminal_commit() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "model.delta", "delta": "before"});
            while true {
                1;
            }
            "unreachable";
        }
        "#,
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"no-after-terminal"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let (stop_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    assert_eq!(stop_status, StatusCode::OK);
    let text = read_run_events(&app, run_id).await;
    if let Some(delta) = text.find("model.delta") {
        assert!(
            delta < text.find("run.cancelled").expect("terminal event"),
            "an event delivered before the stop must be published before the terminal"
        );
    }
    let last_event = text
        .lines()
        .rev()
        .find(|line| line.starts_with("event:"))
        .expect("at least one event");
    assert_eq!(
        last_event.trim(),
        "event: run.cancelled",
        "nothing may be published after the terminal commit; last event was {last_event}"
    );
}

#[tokio::test]
async fn event_retention_respects_the_configured_per_run_limit() {
    let path =
        std::env::temp_dir().join(format!("rustscript-agent-retention-{}.db", Uuid::new_v4()));
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig {
            max_events_per_run: 3,
            ..AgentGatewayConfig::default()
        },
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "model.delta", "delta": "1"});
            stream::emit({"type": "model.delta", "delta": "2"});
            stream::emit({"type": "model.delta", "delta": "3"});
            stream::emit({"type": "model.delta", "delta": "4"});
            stream::emit({"type": "model.delta", "delta": "5"});
            "done";
        }
        "#,
        &path,
    )
    .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"retention"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    assert!(text.contains("run.completed"));
    drop(app);

    // The retained replay history obeys max_events_per_run.
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let replayed = read_run_events(&restored_app, run_id).await;
    assert!(
        replayed.matches("event: model.delta").count() <= 3,
        "retained history must obey max_events_per_run, got: {replayed}"
    );
    assert!(replayed.contains("run.completed"));
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}
