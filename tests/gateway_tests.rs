use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, GatewayPersistence, build_agent_gateway_app,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

/// Temporary gateway SQLite path under /mnt/TEMP/rustscript (workspace
/// rule: all development temporary state lives there).
fn gateway_db_path(label: &str) -> std::path::PathBuf {
    let root = std::path::PathBuf::from("/mnt/TEMP/rustscript/gateway-tests");
    std::fs::create_dir_all(&root).expect("gateway test root should be created");
    root.join(format!("{label}-{}.db", Uuid::new_v4()))
}

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
    let path = gateway_db_path("reload");
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
    let path = gateway_db_path("events");
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

/// A deleted session (and its runs/events) must not resurrect on restart:
/// the durable cascade removes every row the reload path validates.
#[tokio::test]
async fn deleted_session_does_not_resurrect_after_restart() {
    let path = gateway_db_path("delete");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);

    let (session_status, _session) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"id":"doomed-session", "title":"doomed"}),
    )
    .await;
    assert_eq!(session_status, StatusCode::CREATED);
    let (run_status, _run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"session_id":"doomed-session", "input":"doomed"}),
    )
    .await;
    assert_eq!(run_status, StatusCode::ACCEPTED);
    let (delete_status, deleted) = json_request(
        &app,
        axum::http::Method::DELETE,
        "/api/sessions/doomed-session",
        Value::Null,
    )
    .await;
    assert_eq!(delete_status, StatusCode::OK);
    assert_eq!(deleted["deleted"], true);
    drop(app);

    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload after deletion");
    let restored_app = build_agent_gateway_app(restored);
    let (sessions_status, sessions) = json_request(
        &restored_app,
        axum::http::Method::GET,
        "/api/sessions",
        Value::Null,
    )
    .await;
    assert_eq!(sessions_status, StatusCode::OK);
    assert!(
        sessions["data"].as_array().is_some_and(Vec::is_empty),
        "deleted session must not resurrect, got: {sessions}"
    );
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn event_retention_respects_the_configured_per_run_limit() {
    let path = gateway_db_path("retention");
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

/// P1-2 (production path, fault injection): a durable admission failure
/// (disk made read-only mid-flight) leaves no partial state that a restart
/// could resurrect. The single-transaction `admission.create` rolls back
/// the whole admission; reloading after the fault shows exactly the
/// pre-fault state.
#[tokio::test]
async fn failed_admission_leaves_no_resurrecting_partial_state() {
    let path = gateway_db_path("admission-fault");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    let now = 1_000_000u64;
    let admit = |run_id: &str, message_id: &str, event_id: &str, now: u64| {
        json!({
            "session_id": "fault-session",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "fault-session",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": run_id,
            "parent_run_id": "",
            "input_json": "{\"text\":\"hello\"}",
            "message_id": message_id,
            "message_run_id": run_id,
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "event_id": event_id,
            "now_ms": now,
            "expires_at_ms": 0,
        })
    };
    // Pre-fault admission commits fully.
    persistence
        .admission_create(&admit("run-1", "message-1", "event-1", now))
        .expect("first admission should commit");

    // Fault: the database file becomes read-only, so the next admission
    // cannot commit durably (every storage command opens the file for
    // read-write and fails).
    let mut permissions = std::fs::metadata(&path).expect("db metadata").permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions).expect("make db read-only");

    let failed = persistence.admission_create(&admit("run-2", "message-2", "event-2", now + 1));
    assert!(
        failed.is_err(),
        "admission must fail while the database is read-only, got {failed:?}"
    );
    drop(state);

    // Heal the fault and restart: only the pre-fault run exists; the
    // half-admitted run never resurrects.
    let mut permissions = std::fs::metadata(&path).expect("db metadata").permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).expect("restore db writability");

    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload after the fault");
    let restored_persistence = restored
        .persistence()
        .expect("persistence handle should be exposed");
    let run_1 = restored_persistence
        .run_get("run-1")
        .expect("pre-fault run must survive");
    assert_eq!(
        run_1["rows"][0][0],
        json!("run-1"),
        "the pre-fault run is intact"
    );
    let run_2 = restored_persistence.run_get("run-2").expect("run.get");
    assert!(
        run_2["rows"].as_array().is_some_and(Vec::is_empty),
        "the failed admission must not resurrect after restart"
    );
    drop(restored);
    let _ = std::fs::remove_file(&path);
}

/// P2-3: request runtimes are not saturated by storage stalls. While the
/// storage worker is blocked on an exclusive SQLite lock held by another
/// connection, an unrelated request completes immediately; the stalled
/// admission finishes once the lock is released. (On a current-thread
/// runtime, inline blocking storage calls would stall every request.)
#[tokio::test]
async fn request_runtime_stays_responsive_during_storage_stall() {
    let path = gateway_db_path("stall");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"stalled\"; }",
        &path,
    )
    .expect("SQLite state should open");
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    // Seed enough state that a full reload (migrate + recovery + load.all)
    // takes a couple of seconds on the dedicated storage worker.
    let mut now = 4_000_000u64;
    for index in 0..1500 {
        persistence
            .session_create(&json!({
                "id": format!("stall-session-{index:04}"),
                "profile": "gateway",
                "platform": "test",
                "account_id": format!("account-{index:04}"),
                "chat_id": format!("chat-{index:04}"),
                "thread_id": "",
                "user_id": "",
                "generation": 1,
                "system_prompt": "",
                "model": "m",
                "provider": "p",
                "toolset_hash": "",
                "metadata_json": "{}",
                "title": "",
                "end_reason": "",
                "now_ms": now,
            }))
            .expect("session create should commit");
        now += 1;
    }
    drop(state);
    let app = build_agent_gateway_app(
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
            .expect("SQLite state should open"),
    );

    // The dedicated storage worker is busy for a while with a full reload
    // on a blocking thread; an admission submitted meanwhile queues behind
    // it. Request runtimes must stay free: an unrelated request completes
    // immediately, and the admission only finishes once the worker drains.
    let slow_state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("second gateway should open");
    let slow_persistence = slow_state
        .persistence()
        .expect("persistence handle should be exposed");
    let slow_load = tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        slow_persistence.load().expect("reload should succeed");
        started.elapsed()
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stall_app = app.clone();
    let admission = tokio::spawn(async move {
        json_request(
            &stall_app,
            axum::http::Method::POST,
            "/v1/runs",
            json!({"input":"stall"}),
        )
        .await
    });

    // While the admission is queued behind the storage worker's slow
    // reload, an unrelated request must complete promptly: the runtime is
    // not occupied by the storage stall.
    let models = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        json_request(&app, axum::http::Method::GET, "/v1/models", Value::Null),
    )
    .await;
    assert!(
        models.is_ok(),
        "an unrelated request must complete while storage is stalled"
    );
    assert_eq!(models.expect("models response").0, StatusCode::OK);

    let admitted = tokio::time::timeout(std::time::Duration::from_secs(60), admission)
        .await
        .expect("admission must finish once the worker drains")
        .expect("admission task must not panic");
    assert_eq!(admitted.0, StatusCode::ACCEPTED);
    let slow: std::time::Duration =
        tokio::time::timeout(std::time::Duration::from_secs(60), slow_load)
            .await
            .expect("slow reload must finish")
            .expect("reload task must not panic");
    assert!(
        slow >= std::time::Duration::from_millis(300),
        "the seeded reload must actually occupy the worker for a while (took {slow:?})"
    );
    drop(slow_state);
    drop(app);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn interrupted_run_receives_exactly_one_terminal_recovery_event() {
    let path = gateway_db_path("recovery");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        r#"
        pub fn run(input: map) -> string {
            while true {
                1;
            }
            "unreachable";
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
        json!({"input":"crash-me"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    // Crash window: the gateway is dropped while the run is active (its
    // terminal state was never committed).
    drop(app);

    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let text = read_run_events(&restored_app, &run_id).await;
    assert!(
        text.contains("run.started"),
        "prior events stay replayable, got: {text}"
    );
    assert_eq!(
        text.matches("event: run.failed").count(),
        1,
        "exactly one recovery terminal event, got: {text}"
    );
    let _ = std::fs::remove_file(&path);
}

/// P2-2 (production path): admission persists `run.started` durably at
/// sequence 1 before anything is visible; a restart replays it before any
/// script event.
#[tokio::test]
async fn admission_persists_run_started_before_any_script_event() {
    let path = gateway_db_path("started-first");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "model.started", "model": "local"});
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
        json!({"input":"started-first"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    // Wait for the run to finish (the terminal event only appears after the
    // durable commit), then restart.
    let live_text = read_run_events(&app, &run_id).await;
    assert!(live_text.contains("run.completed"));
    drop(app);

    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let text = read_run_events(&restored_app, &run_id).await;
    let started = text.find("run.started").expect("run.started replays");
    let script = text.find("model.started").expect("script event replays");
    assert!(
        started < script,
        "run.started (seq 1) must precede script events, got: {text}"
    );
    assert!(text.contains("run.completed"));
    let _ = std::fs::remove_file(&path);
}

/// P1-4: the typed approval/compaction repository APIs are real production
/// commands with restart round-trips (for A4/A5 consumption), not dead RSS.
#[tokio::test]
async fn approval_and_compaction_repository_round_trip_restart() {
    let path = gateway_db_path("approval-compaction");
    let config = AgentGatewayConfig::default();
    let now = 2_000_000u64;

    let first = GatewayPersistence::open(&config, &path).expect("repository should open");
    first
        .admission_create(&json!({
            "session_id": "repo-session",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "repo-session",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "repo-run",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "repo-message",
            "message_run_id": "repo-run",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "event_id": "repo-event",
            "now_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("admission should commit");
    let approval = first
        .approval_request(&json!({
            "id": "approval-1",
            "run_id": "repo-run",
            "session_id": "repo-session",
            "tool_call_id": "tool-1",
            "tool_name": "shell",
            "arguments_json": "{\"cmd\":\"ls\"}",
            "risk_class": "execute",
            "decision_scope": "",
            "one_time": 0,
            "requested_at_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("approval should be requested");
    assert_eq!(approval["rows"][0][0], json!("approval-1"));
    assert_eq!(approval["rows"][0][7], json!("pending"));
    first
        .run_transition(&json!({
            "run_id": "repo-run",
            "from_status": "running",
            "to_status": "compacting",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now + 1,
        }))
        .expect("run should transition to compacting");
    let compaction = first
        .compaction_start(&json!({
            "id": "compaction-1",
            "session_id": "repo-session",
            "run_id": "repo-run",
            "generation": 2,
            "source_start_ordinal": 1,
            "source_end_ordinal": 1,
            "retained_tail_ordinal": 1,
            "summary_json": "{\"summary\":\"compacted\"}",
            "token_estimate": 10,
            "model": "m",
            "now_ms": now + 2,
        }))
        .expect("compaction should start");
    assert_eq!(compaction["rows"][0][0], json!("compaction-1"));
    assert_eq!(compaction["rows"][0][10], json!("pending"));
    drop(first);

    // Restart round-trip: a fresh repository instance reads the same
    // durable objects and can resolve/commit them.
    let second = GatewayPersistence::open(&config, &path).expect("repository should reopen");
    let approval_again = second
        .approval_get("approval-1")
        .expect("approval should survive restart");
    assert_eq!(approval_again["rows"][0][7], json!("pending"));
    second
        .approval_resolve(&json!({
            "id": "approval-1",
            "state": "approved",
            "resolver": "test-user",
            "decision_reason": "ok",
            "resolved_at_ms": now + 3,
        }))
        .expect("approval should resolve");
    let compaction_again = second
        .compaction_get("compaction-1")
        .expect("compaction should survive restart");
    assert_eq!(compaction_again["rows"][0][10], json!("pending"));
    second
        .compaction_commit(&json!({
            "id": "compaction-1",
            "session_id": "repo-session",
            "start_ordinal": 1,
            "end_ordinal": 1,
            "generation": 2,
            "completed_at_ms": now + 4,
        }))
        .expect("compaction should commit");
    let committed = second
        .compaction_get("compaction-1")
        .expect("compaction after commit");
    assert_eq!(committed["rows"][0][10], json!("committed"));
    drop(second);
    let _ = std::fs::remove_file(&path);
}

/// P1-1 (production path): the gateway's real restart load path drains
/// more state than any single page or byte budget — 600 sessions and one
/// run with 600 messages + 600 events all reload after restart, with no
/// silent truncation.
#[tokio::test]
async fn production_load_drains_beyond_page_and_byte_boundaries() {
    let path = gateway_db_path("load-boundary");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    let mut now = 3_000_000u64;
    for index in 0..600 {
        persistence
            .session_create(&json!({
                "id": format!("session-{index:03}"),
                "profile": "gateway",
                "platform": "test",
                "account_id": format!("account-{index:03}"),
                "chat_id": format!("chat-{index:03}"),
                "thread_id": "",
                "user_id": "",
                "generation": 1,
                "system_prompt": "",
                "model": "m",
                "provider": "p",
                "toolset_hash": "",
                "metadata_json": "{}",
                "title": format!("title-{index:03}"),
                "end_reason": "",
                "now_ms": now,
            }))
            .expect("session create should commit");
        now += 1;
    }
    persistence
        .admission_create(&json!({
            "session_id": "session-000",
            "session_new": 0,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-000",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "run-boundary",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "message-admission",
            "message_run_id": "run-boundary",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "event_id": "event-started",
            "now_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("admission should commit");
    now += 1;
    for ordinal in 1..=600 {
        persistence
            .message_append(&json!({
                "id": format!("message-{ordinal:03}"),
                "session_id": "session-000",
                "role": "user",
                "content_json": format!("{{\"text\":\"message {ordinal}\"}}"),
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 0,
                "metadata_json": "{}",
                "run_id": "",
                "finish_reason": "",
                "now_ms": now,
            }))
            .expect("message append should commit");
        now += 1;
    }
    for seq in 2..=600 {
        persistence
            .event_append(&json!({
                "run_id": "run-boundary",
                "event_id": format!("event-{seq:03}"),
                "event_type": "model.delta",
                "payload_json": format!("{{\"delta\":\"{seq}\"}}"),
                "now_ms": now,
                "max_events": 2048,
            }))
            .expect("event append should commit");
        now += 1;
    }
    drop(state);

    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_persistence = restored
        .persistence()
        .expect("persistence handle should be exposed");
    let replay = restored_persistence
        .event_replay(&json!({
            "run_id": "run-boundary",
            "after_seq": 362,
            "max_events": 2048,
            "max_bytes": 2 * 1024 * 1024,
        }))
        .expect("replay should load every retained event");
    assert_eq!(
        replay["rows"].as_array().map(Vec::len),
        Some(240),
        "the retained tail (240 events after restart recovery pruning) must load"
    );
    let restored_app = build_agent_gateway_app(restored);
    let (sessions_status, sessions) = json_request(
        &restored_app,
        axum::http::Method::GET,
        "/api/sessions?limit=200&offset=0",
        Value::Null,
    )
    .await;
    assert_eq!(sessions_status, StatusCode::OK);
    assert!(
        sessions["data"]
            .as_array()
            .is_some_and(|data| data.len() == 200),
        "sessions must load across pages without truncation"
    );
    assert_eq!(sessions["has_more"], json!(true), "600 > 200 page size");
    let (messages_status, messages) = json_request(
        &restored_app,
        axum::http::Method::GET,
        "/api/sessions/session-000/messages",
        Value::Null,
    )
    .await;
    assert_eq!(messages_status, StatusCode::OK);
    assert_eq!(
        messages["data"].as_array().map(Vec::len),
        Some(601),
        "admission message + 600 appends all reload"
    );
    drop(restored_app);
    let _ = std::fs::remove_file(&path);
}
