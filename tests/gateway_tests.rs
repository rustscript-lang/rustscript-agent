use std::io::{Read, Write};
use std::net::TcpListener;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rustscript_agent::metrics::{StorageOp, TerminalRetryOutcome, TerminalStatus};
use rustscript_agent::{
    AdmitError, AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, AgentService,
    GatewayPersistence, build_agent_gateway_app,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

/// Temporary gateway SQLite path. Honors `RUSTSCRIPT_AGENT_TEST_TMP` (CI
/// sets it to a runner-local directory); the default keeps local
/// development state under /mnt/TEMP/rustscript (workspace rule).
fn gateway_db_path(label: &str) -> std::path::PathBuf {
    let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/mnt/TEMP/rustscript/gateway-tests"));
    std::fs::create_dir_all(&root).expect("gateway test root should be created");
    root.join(format!("{label}-{}.db", Uuid::new_v4()))
}

/// Accepts one HTTP request and holds the response until the test releases
/// it, so a scripted run can be parked deterministically before its terminal
/// commit. The arrival signal is a Tokio oneshot so the test can await it
/// without blocking the current-thread runtime (which must keep polling the
/// worker task).
fn spawn_holding_fixture() -> (
    u16,
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read fixture request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = arrived_tx.send(());
        release_rx.recv().expect("wait for release");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nX-Agent: fixture\r\n\r\nagent-ok")
            .expect("write fixture response");
    });
    (port, arrived_rx, release_tx, handle)
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

/// Sends one request and returns only the status code. Needed for routes
/// that are intentionally absent: the default 404 body is empty and is not
/// JSON, so `json_request` cannot be used.
async fn raw_status(app: &axum::Router, method: axum::http::Method, uri: &str) -> StatusCode {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    response.status()
}

#[tokio::test]
async fn health_models_and_sessions_follow_hermes_envelopes() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
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
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
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
    })
    .expect("gateway config must validate");
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
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
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

    // Durable scheduled job execution is explicitly out of scope, so the
    // run route is intentionally absent: the path answers a plain 404
    // instead of advertising a not-implemented placeholder.
    let run_status = raw_status(
        &app,
        axum::http::Method::POST,
        &format!("/api/jobs/{job_id}/run"),
    )
    .await;
    assert_eq!(run_status, StatusCode::NOT_FOUND);

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
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
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

/// Admission request used to probe the service capacity permit directly,
/// bypassing the HTTP persist middleware (which fail-closes every request
/// with 500 while the durable store is down).
async fn probe_admit(
    service: &AgentService,
    input: &str,
) -> Result<rustscript_agent::AdmittedRun, AdmitError> {
    service
        .admit(AdmitRunRequest {
            input: json!({"probe": input}),
            platform: "probe".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
}

/// Spawns the holding fixture and builds the config/source pair that parks a
/// worker inside an HTTP call before its terminal commit.
fn spawn_holding_run_env(
    config_overrides: impl FnOnce(AgentGatewayConfig) -> AgentGatewayConfig,
) -> (
    u16,
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
    AgentGatewayConfig,
    String,
) {
    let (port, arrived_rx, release_tx, fixture) = spawn_holding_fixture();
    let http = rustscript_vm::HttpConfig {
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_schemes: vec!["http".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
    let source = format!(
        r#"
        use http;
        pub fn run(input: map) -> string {{
            http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
            "done";
        }}
        "#
    );
    let config = config_overrides(AgentGatewayConfig {
        http,
        ..AgentGatewayConfig::default()
    });
    (port, arrived_rx, release_tx, fixture, config, source)
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
    // The terminal handle is retained for replay handoff right after the run
    // completes...
    assert_eq!(service.handle_count(), 1);
    // ...and released by the janitor after the TTL (bounded polling, not a
    // fixed sleep).
    assert!(
        wait_until(std::time::Duration::from_secs(5), || service.handle_count()
            == 0)
        .await,
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
            "origin_actor": "",
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
            "origin_actor": "",
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
            "origin_actor": "",
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

/// Polls a condition until it holds or the timeout expires.
async fn wait_until(timeout: std::time::Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// P2: a terminal commit that fails while storage is down must not leak the
/// run's handle/SSE/permit. The run enters an observable terminal-pending
/// state, its admission permit is released as soon as it stops executing,
/// and a bounded retry commits the terminal exactly once once storage
/// recovers (durable commit first, publish only after).
#[tokio::test]
async fn terminal_commit_is_retried_after_storage_recovers_exactly_once() {
    let path = gateway_db_path("terminal-retry");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig {
            janitor_interval: std::time::Duration::from_millis(100),
            terminal_commit_retry_window: std::time::Duration::from_secs(10),
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
        &path,
    )
    .expect("SQLite state should open");
    let service = state.service();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "retry-me"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();

    // Storage goes down: replace the SQLite file with a directory so every
    // storage command fails (the worker opens the DB per command).
    let broken = path.with_extension("db.broken");
    std::fs::rename(&path, &broken).expect("move the db aside");
    std::fs::create_dir(&path).expect("break storage with a directory");

    // Stop the active run; its terminal commit (cancelled) cannot be
    // persisted, so the run must enter the observable terminal-pending state
    // instead of silently staying "started" forever.
    let (stop_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    assert_eq!(stop_status, StatusCode::OK);

    let pending = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 1
    })
    .await;
    assert!(
        pending,
        "the run must enter the terminal-pending retry state"
    );

    // The admission permit is released as soon as the run stops executing,
    // so a sustained storage outage can never permanently exhaust capacity.
    assert_eq!(
        service.available_capacity(),
        AgentGatewayConfig::default().max_concurrent_runs,
        "a terminal-pending run must not hold the admission permit"
    );

    // Storage recovers; the bounded retry commits the terminal durably and
    // only then publishes it (exactly once).
    std::fs::remove_dir(&path).expect("restore storage");
    std::fs::rename(&broken, &path).expect("restore the db file");

    let text = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        read_run_events(&app, &run_id),
    )
    .await
    .expect("the terminal retry must publish within the bounded window");
    assert_eq!(
        text.matches("event: run.cancelled").count(),
        1,
        "exactly one terminal commit after recovery, got: {text}"
    );
    assert_eq!(
        text.matches("event: run.completed").count() + text.matches("event: run.failed").count(),
        0,
        "no other terminal may be published, got: {text}"
    );

    let resolved = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 0
    })
    .await;
    assert!(resolved, "the retry must remove the pending terminal entry");

    // Restart round trip: the durable side also holds exactly one terminal
    // (no duplicate, no recovery event for an already-terminal run).
    drop(app);
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let text = read_run_events(&restored_app, &run_id).await;
    assert_eq!(
        text.matches("event: run.cancelled").count(),
        1,
        "restart must not duplicate or recover the terminal, got: {text}"
    );
    let _ = std::fs::remove_file(&path);
}

/// P2: when storage stays down for the whole retry window, the run must
/// not leak anything: the retry stops (bounded), the admission permit stays
/// released, the SSE stream ends without a fabricated terminal, the handle
/// is released via its TTL, and the durable side is repaired exactly once
/// by restart recovery.
#[tokio::test]
async fn terminal_commit_window_expiry_releases_capacity_and_restart_recovery_repairs() {
    let path = gateway_db_path("terminal-expiry");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig {
            janitor_interval: std::time::Duration::from_millis(100),
            terminal_commit_retry_window: std::time::Duration::from_millis(400),
            terminal_run_ttl: std::time::Duration::from_millis(500),
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
        &path,
    )
    .expect("SQLite state should open");
    let service = state.service();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "expire-me"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();

    // Storage goes down before the terminal commit.
    let broken = path.with_extension("db.broken");
    std::fs::rename(&path, &broken).expect("move the db aside");
    std::fs::create_dir(&path).expect("break storage with a directory");
    let (stop_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    assert_eq!(stop_status, StatusCode::OK);

    let pending = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 1
    })
    .await;
    assert!(
        pending,
        "the run must enter the terminal-pending retry state"
    );

    // The pending terminal is observable through the health endpoint.
    let (health_status, health) = json_request(
        &app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
    )
    .await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health["terminal_pending"], json!(1));

    // The window expires while storage is still down: the retry stops and
    // the live stream ends without ever fabricating a terminal event.
    let expired = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 0
    })
    .await;
    assert!(expired, "the bounded retry window must expire");
    let text = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_run_events(&app, &run_id),
    )
    .await
    .expect("the SSE stream must end once the retry window expires");
    assert!(
        !text.contains("event: run.cancelled")
            && !text.contains("event: run.completed")
            && !text.contains("event: run.failed"),
        "no terminal event may be published after expiry, got: {text}"
    );

    // Capacity is never exhausted and the handle is TTL-released.
    assert_eq!(
        service.available_capacity(),
        AgentGatewayConfig::default().max_concurrent_runs
    );
    let released = wait_until(std::time::Duration::from_secs(10), || {
        service.handle_count() == 0
    })
    .await;
    assert!(released, "the terminal-pending handle must be TTL-released");

    // Storage recovers; restart recovery fails the interrupted run exactly
    // once, so the durable side reaches a real terminal state.
    std::fs::remove_dir(&path).expect("restore storage");
    std::fs::rename(&broken, &path).expect("restore the db file");
    drop(app);
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let text = read_run_events(&restored_app, &run_id).await;
    assert_eq!(
        text.matches("event: run.failed").count(),
        1,
        "restart recovery must fail the interrupted run exactly once, got: {text}"
    );
    let _ = std::fs::remove_file(&path);
}

/// Gated HTTP fixture: accepts one connection, reads the request headers,
/// then blocks until released so the test can break storage while the
/// worker is mid-flight.
fn spawn_gated_fixture() -> (
    u16,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{BufRead as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("fixture accept");
        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line).expect("read request head");
            if read == 0 || line == "\r\n" {
                break;
            }
        }
        drop(reader);
        release_rx.recv().expect("fixture release");
        let mut stream = stream;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .expect("write fixture response");
    });
    (port, release_tx, handle)
}

/// P2: the completed terminal (assistant message + delta + completed
/// events) is rebuilt and committed exactly once by the bounded retry after
/// storage recovers; the durable reload sees one terminal and the assistant
/// message.
#[tokio::test]
async fn completed_terminal_with_message_is_retried_after_storage_recovers() {
    let (port, release, fixture) = spawn_gated_fixture();
    let http = rustscript_vm::HttpConfig {
        allowed_schemes: vec!["http".to_string()],
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };

    let path = gateway_db_path("terminal-retry-completed");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig {
            janitor_interval: std::time::Duration::from_millis(100),
            terminal_commit_retry_window: std::time::Duration::from_secs(10),
            http,
            ..AgentGatewayConfig::default()
        },
        format!(
            r#"
            use http;
            pub fn run(input: map) -> map {{
                http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
            }}
            "#
        ),
        &path,
    )
    .expect("SQLite state should open");
    let service = state.service();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "completed-retry"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    // The admission auto-created a session; fetch its id for message checks.
    let (sessions_status, sessions) = json_request(
        &app,
        axum::http::Method::GET,
        "/api/sessions?limit=10&offset=0",
        Value::Null,
    )
    .await;
    assert_eq!(sessions_status, StatusCode::OK);
    let session_id = sessions["data"][0]["id"]
        .as_str()
        .expect("admission session id")
        .to_string();

    // The worker is blocked inside the HTTP call: break storage now, then
    // release the fixture so the completed terminal commit fails durably.
    let broken = path.with_extension("db.broken");
    std::fs::rename(&path, &broken).expect("move the db aside");
    std::fs::create_dir(&path).expect("break storage with a directory");
    release.send(()).expect("release the fixture");

    let pending = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 1
    })
    .await;
    assert!(
        pending,
        "the completed run must enter the terminal-pending retry state"
    );
    assert_eq!(
        service.available_capacity(),
        AgentGatewayConfig::default().max_concurrent_runs,
        "a terminal-pending run must not hold the admission permit"
    );

    // Storage recovers; the retry re-appends the assistant message and both
    // terminal events, commits them durably, then publishes exactly once.
    std::fs::remove_dir(&path).expect("restore storage");
    std::fs::rename(&broken, &path).expect("restore the db file");
    let text = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        read_run_events(&app, &run_id),
    )
    .await
    .expect("the completed terminal retry must publish within the bounded window");
    assert_eq!(
        text.matches("event: run.completed").count(),
        1,
        "exactly one completed terminal after recovery, got: {text}"
    );
    assert_eq!(
        text.matches("event: message.delta").count(),
        1,
        "the terminal delta replays once, got: {text}"
    );

    let resolved = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 0
    })
    .await;
    assert!(resolved, "the retry must remove the pending terminal entry");

    // In-memory session now holds the user message plus the assistant reply.
    let (messages_status, messages) = json_request(
        &app,
        axum::http::Method::GET,
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    assert_eq!(messages_status, StatusCode::OK);
    assert_eq!(
        messages["data"].as_array().map(Vec::len),
        Some(2),
        "the retried terminal must restore the assistant message"
    );

    // Restart round trip: the durable side holds the same single terminal
    // and both messages.
    drop(app);
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let text = read_run_events(&restored_app, &run_id).await;
    assert_eq!(
        text.matches("event: run.completed").count(),
        1,
        "restart must not duplicate the completed terminal, got: {text}"
    );
    let (messages_status, messages) = json_request(
        &restored_app,
        axum::http::Method::GET,
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    assert_eq!(messages_status, StatusCode::OK);
    assert_eq!(
        messages["data"].as_array().map(Vec::len),
        Some(2),
        "the durable reload must keep both messages"
    );
    fixture.join().expect("fixture thread");
    let _ = std::fs::remove_file(&path);
}

/// P2: when the durable side already reached a different terminal (restart
/// recovery ran while the retry was pending), the retry must not publish a
/// fabricated terminal: it drops the pending entry, closes the stream, and
/// the durable recovery terminal stays the single source of truth.
#[tokio::test]
async fn terminal_retry_conflict_never_publishes_a_fabricated_terminal() {
    let path = gateway_db_path("terminal-retry-conflict");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig {
            janitor_interval: std::time::Duration::from_secs(2),
            terminal_commit_retry_window: std::time::Duration::from_secs(30),
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
        &path,
    )
    .expect("SQLite state should open");
    let service = state.service();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "conflict-me"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();

    let broken = path.with_extension("db.broken");
    std::fs::rename(&path, &broken).expect("move the db aside");
    std::fs::create_dir(&path).expect("break storage with a directory");
    let (stop_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    assert_eq!(stop_status, StatusCode::OK);
    let pending = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 1
    })
    .await;
    assert!(
        pending,
        "the run must enter the terminal-pending retry state"
    );

    // Storage recovers, but a restart recovery runs first (a second gateway
    // loads the same state and durably fails the interrupted run). The next
    // retry tick then hits the typed transition conflict.
    std::fs::remove_dir(&path).expect("restore storage");
    std::fs::rename(&broken, &path).expect("restore the db file");
    let recovered = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload and recover");
    let recovered_app = build_agent_gateway_app(recovered);
    let recovered_text = read_run_events(&recovered_app, &run_id).await;
    assert_eq!(
        recovered_text.matches("event: run.failed").count(),
        1,
        "restart recovery fails the interrupted run exactly once"
    );
    drop(recovered_app);

    // The retry sees the durable conflict: the pending entry is dropped and
    // the live stream ends without publishing any terminal.
    let resolved = wait_until(std::time::Duration::from_secs(15), || {
        service.pending_terminal_count() == 0
    })
    .await;
    assert!(
        resolved,
        "the conflicting retry must drop the pending terminal entry"
    );
    let text = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_run_events(&app, &run_id),
    )
    .await
    .expect("the SSE stream must end after the conflict");
    assert!(
        !text.contains("event: run.cancelled")
            && !text.contains("event: run.completed")
            && !text.contains("event: run.failed"),
        "no fabricated terminal may be published, got: {text}"
    );
    assert_eq!(
        service.available_capacity(),
        AgentGatewayConfig::default().max_concurrent_runs
    );
    let _ = std::fs::remove_file(&path);
}

/// P3: the service-owned terminal events (`message.delta` +
/// `run.completed`) must honor the configured per-run retention and byte
/// bounds, not hardcoded constants.
#[tokio::test]
async fn terminal_events_respect_the_configured_per_run_bounds() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            max_events_per_run: 4,
            max_event_bytes: 64,
            ..AgentGatewayConfig::default()
        },
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "model.delta", "delta": "d1"});
            stream::emit({"type": "model.delta", "delta": "d2"});
            stream::emit({"type": "model.delta", "delta": "d3"});
            stream::emit({"type": "model.delta", "delta": "d4"});
            stream::emit({"type": "model.delta", "delta": "d5"});
            stream::emit({"type": "model.delta", "delta": "d6"});
            "done";
        }
        "#,
    )
    .expect("RSS source should compile");
    let service = state.service();
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "bounded"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    // Wait until the run is no longer active, then subscribe: the SSE body
    // is then exactly the retained history (no live events).
    let finished = wait_until(std::time::Duration::from_secs(10), || {
        service.available_capacity() == AgentGatewayConfig::default().max_concurrent_runs
    })
    .await;
    assert!(finished, "the run must finish");
    let text = read_run_events(&app, run_id).await;
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("event: "))
            .count(),
        4,
        "retained history must honor the configured per-run bound, got: {text}"
    );
    assert_eq!(
        text.lines().rev().find(|line| line.starts_with("event: ")),
        Some("event: run.completed"),
        "the terminal commit must stay the last retained event, got: {text}"
    );
    assert!(
        text.contains("truncated"),
        "the terminal events must honor the configured byte bound, got: {text}"
    );
    let _ = state;
}

/// P3: `stop` must not occupy a Tokio request thread while the store write
/// lock is held by a storage-stalled mutation: it runs on a blocking
/// thread, so an unrelated request completes while the stop is pending
/// (single-threaded runtime: a blocking stop would stall everything).
#[tokio::test(flavor = "current_thread")]
async fn stop_waits_on_a_blocking_thread_during_a_storage_stall() {
    let path = gateway_db_path("stop-stall");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"done\"; }",
        &path,
    )
    .expect("SQLite state should open");
    let service = state.service();
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    let app = build_agent_gateway_app(state);

    // Admit and finish a run while storage is healthy.
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "stop-stall"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    let finished = wait_until(std::time::Duration::from_secs(10), || {
        service.available_capacity() == AgentGatewayConfig::default().max_concurrent_runs
    })
    .await;
    assert!(finished, "the run must finish before the stall");

    // Seed enough state that a full reload occupies the storage worker for
    // a while, then stall the worker with that reload. Large session
    // prompts make the reload byte-bound (one row per page), so a handful
    // of commands produce a multi-second reload.
    let big_prompt = "x".repeat(900_000);
    let mut now = 5_000_000u64;
    for index in 0..250 {
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
                "system_prompt": big_prompt,
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
    let slow_persistence = persistence.clone();
    let slow_load = tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        slow_persistence.load().expect("reload should succeed");
        started.elapsed()
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Hold the store write lock behind the stalled worker with a session
    // create, then request a stop: the stop must wait on a blocking thread.
    let stall_app = app.clone();
    let session_hold = tokio::spawn(async move {
        json_request(
            &stall_app,
            axum::http::Method::POST,
            "/api/sessions",
            json!({"id": "lock-holder", "source": "test"}),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // The stop request: while it is pending, an unrelated request spawned
    // alongside it must still complete within a strict budget. On a
    // single-threaded runtime a stop that occupies the request thread would
    // starve the probe until the stall drains; a blocking-thread stop lets
    // it through. The probe's brief sleep makes the ordering of the two
    // tasks irrelevant: whichever runs first, the probe cannot finish
    // before the stall drains if the stop occupies the request thread.
    let stop_app = app.clone();
    let stop = tokio::spawn(async move {
        json_request(
            &stop_app,
            axum::http::Method::POST,
            &format!("/v1/runs/{run_id}/stop"),
            Value::Null,
        )
        .await
    });
    let probe_app = app.clone();
    let probe = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        json_request(
            &probe_app,
            axum::http::Method::GET,
            "/v1/models",
            Value::Null,
        )
        .await
    });
    let models = tokio::time::timeout(std::time::Duration::from_millis(600), probe).await;
    assert!(
        models.is_ok(),
        "the request runtime must stay responsive while stop waits"
    );
    assert_eq!(
        models
            .expect("models response")
            .expect("probe task must not panic")
            .0,
        StatusCode::OK
    );

    let slow: std::time::Duration =
        tokio::time::timeout(std::time::Duration::from_secs(120), slow_load)
            .await
            .expect("the reload must finish")
            .expect("reload task must not panic");
    assert!(
        slow >= std::time::Duration::from_millis(1200),
        "the seeded reload must actually occupy the worker for a while (took {slow:?})"
    );

    let (stop_status, stop_body) = tokio::time::timeout(std::time::Duration::from_secs(60), stop)
        .await
        .expect("the stop must finish once the stall drains")
        .expect("stop task must not panic");
    assert_eq!(stop_status, StatusCode::OK);
    assert_eq!(stop_body["status"], "completed");

    let _ = tokio::time::timeout(std::time::Duration::from_secs(60), session_hold)
        .await
        .expect("the session create must finish once the stall drains")
        .expect("session create task must not panic");
    let _ = std::fs::remove_file(&path);
}

/// P3: the gateway job delete reports the real durable `rows_affected`
/// instead of a hardcoded success, and a missing job stays a typed 404.
#[tokio::test]
async fn job_delete_reports_the_real_durable_rows_affected() {
    let path = gateway_db_path("job-delete");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);

    let (create_status, job) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/jobs",
        json!({"name": "nightly", "prompt": "run"}),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let job_id = job["job"]["id"].as_str().expect("job id").to_string();

    let (delete_status, deleted) = json_request(
        &app,
        axum::http::Method::DELETE,
        &format!("/api/jobs/{job_id}"),
        Value::Null,
    )
    .await;
    assert_eq!(delete_status, StatusCode::OK);
    assert_eq!(deleted["deleted"], json!(true));
    assert_eq!(
        deleted["rows_affected"],
        json!(1),
        "the delete must report the real durable row count, got: {deleted}"
    );

    let (list_status, jobs) =
        json_request(&app, axum::http::Method::GET, "/api/jobs", Value::Null).await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(jobs["jobs"].as_array().map(Vec::len), Some(0));

    let (missing_status, _) = json_request(
        &app,
        axum::http::Method::DELETE,
        &format!("/api/jobs/{job_id}"),
        Value::Null,
    )
    .await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_file(&path);
}

/// P3: run idempotency currently uses the single `api:chat` scope; the
/// replay contract is tested explicitly — same key + same request replays
/// the same run (also after a restart, proving the durable scope), same key
/// + different request is a typed conflict.
#[tokio::test]
async fn idempotent_run_replay_uses_the_single_api_chat_scope() {
    let path = gateway_db_path("idempotency");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"done\"; }",
        &path,
    )
    .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);

    let body = json!({"input": "idempotent"});
    let request = |payload: Value| {
        app.clone().oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/runs")
                .header("idempotency-key", "chat-key-1")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
    };
    let read = |response: axum::response::Response| async move {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body should be readable");
        (
            status,
            serde_json::from_slice::<Value>(&bytes).expect("response should be JSON"),
        )
    };

    let (first_status, first) =
        read(request(body.clone()).await.expect("router should respond")).await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    let run_id = first["run_id"].as_str().expect("run id").to_string();

    // Same key + same request: the same run is replayed, never re-admitted.
    let (replay_status, replay) =
        read(request(body.clone()).await.expect("router should respond")).await;
    assert_eq!(replay_status, StatusCode::ACCEPTED);
    assert_eq!(
        replay["run_id"],
        json!(run_id),
        "the idempotency scope must replay the same run"
    );

    // Same key + different request: a typed conflict.
    let (conflict_status, conflict) = read(
        request(json!({"input": "different"}))
            .await
            .expect("router should respond"),
    )
    .await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_eq!(conflict["error"]["code"], "idempotency_key_reused");

    // The durable idempotency record lives under the single `api:chat`
    // scope, so the replay also works after a restart.
    drop(app);
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let replay = restored_app
        .clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/runs")
                .header("idempotency-key", "chat-key-1")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("restored router should respond");
    let replay_status = replay.status();
    let bytes = to_bytes(replay.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    let replay: Value = serde_json::from_slice(&bytes).expect("response should be JSON");
    assert_eq!(replay_status, StatusCode::ACCEPTED);
    assert_eq!(
        replay["run_id"],
        json!(run_id),
        "the durable api:chat scope must replay the same run after restart"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn live_run_context_carries_the_full_canonical_shape() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> map { input; }",
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input":"shape"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    assert!(
        text.contains("run.completed"),
        "the run must complete and echo its context, got: {text}"
    );
    for key in [
        "run_id",
        "session_id",
        "parent_run_id",
        "platform",
        "input",
        "messages",
        "system_prompt",
        "model",
        "provider",
        "provider_options",
        "tool_schemas",
        "limits",
        "metadata",
    ] {
        assert!(
            text.contains(key),
            "the live run context must carry the canonical {key} field"
        );
    }
}

#[tokio::test]
async fn service_owned_terminal_events_emitted_by_scripts_are_rejected() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "run.completed", "output": "spoofed"});
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
        json!({"input":"spoof"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");
    let text = read_run_events(&app, run_id).await;
    assert!(
        text.contains("run.failed") && text.contains("invalid_event_schema"),
        "a script-emitted service-owned terminal must fail the run with the typed code, got: {text}"
    );
    assert!(
        !text.contains("event: run.completed"),
        "no script-owned terminal may be committed, got: {text}"
    );
}

async fn json_request_with_key(app: &axum::Router, body: Value, key: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/runs")
                .header("content-type", "application/json")
                .header("idempotency-key", key)
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

async fn session_count(app: &axum::Router) -> usize {
    let (_, sessions) = json_request(
        app,
        axum::http::Method::GET,
        "/api/sessions?limit=50&offset=0",
        Value::Null,
    )
    .await;
    sessions["data"].as_array().map(Vec::len).unwrap_or(0)
}

#[test]
fn invalid_config_is_rejected_by_the_constructor() {
    let config = AgentGatewayConfig {
        max_body_bytes: 0,
        ..AgentGatewayConfig::default()
    };
    assert!(
        AgentGatewayState::new(config).is_err(),
        "an invalid configuration must be rejected, not panic"
    );
}

#[tokio::test]
async fn idempotency_conflict_creates_no_session() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
    let app = build_agent_gateway_app(state);

    let (first_status, _) =
        json_request_with_key(&app, json!({"input": "conflict-original"}), "conflict-key").await;
    assert_eq!(first_status, StatusCode::ACCEPTED);

    let (second_status, second) =
        json_request_with_key(&app, json!({"input": "conflict-different"}), "conflict-key").await;
    assert_eq!(second_status, StatusCode::CONFLICT);
    assert_eq!(second["error"]["code"], "idempotency_key_reused");

    assert_eq!(
        session_count(&app).await,
        1,
        "an idempotency conflict must not create a new empty session"
    );
}

#[tokio::test]
async fn idempotent_replay_returns_the_original_run_and_creates_no_session() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
    let app = build_agent_gateway_app(state);

    let (first_status, first) =
        json_request_with_key(&app, json!({"input": "replay-original"}), "replay-key").await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    let run_id = first["run_id"].as_str().expect("run id").to_string();

    let (second_status, second) =
        json_request_with_key(&app, json!({"input": "replay-original"}), "replay-key").await;
    assert_eq!(second_status, StatusCode::ACCEPTED);
    assert_eq!(
        second["run_id"], run_id,
        "an idempotent replay must return the original run"
    );

    assert_eq!(
        session_count(&app).await,
        1,
        "an idempotent replay must not create a new empty session"
    );
}

#[tokio::test]
async fn missing_parent_rejects_without_creating_a_session() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
    let app = build_agent_gateway_app(state);

    let (status, body) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "child", "parent_run_id": "missing-run"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "parent_run_not_found");
    assert_eq!(
        session_count(&app).await,
        0,
        "a missing parent must reject admission without creating a session"
    );
}

#[tokio::test]
async fn failed_replay_persist_keeps_the_original_idempotency_record() {
    let path = std::env::temp_dir().join(format!("rustscript-agent-idem-{}.db", Uuid::new_v4()));
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);

    // The first admission durably commits the idempotency record.
    let (first_status, first) =
        json_request_with_key(&app, json!({"input": "replay-durable"}), "durable-key").await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    let run_id = first["run_id"].as_str().expect("run id").to_string();
    // Wait for the run's terminal commit so the SQLite file is quiescent.
    let _ = read_run_events(&app, &run_id).await;

    // Break persistence: SQLite cannot open a directory.
    let backup = path.with_extension("db.bak");
    std::fs::copy(&path, &backup).expect("backup SQLite state");
    std::fs::remove_file(&path).expect("remove SQLite state");
    std::fs::create_dir(&path).expect("replace SQLite state with a directory");

    // A replay is read-only: the in-memory fast path returns the original
    // run without any durable write, so it succeeds even while persistence
    // is down and leaves the durable idempotency record untouched.
    let (down_status, down_replay) =
        json_request_with_key(&app, json!({"input": "replay-durable"}), "durable-key").await;
    assert_eq!(down_status, StatusCode::ACCEPTED);
    assert_eq!(
        down_replay["run_id"], run_id,
        "a read-only replay must return the original run while persistence is down"
    );

    // Restore the durable store in the same process: the original
    // idempotency record must still be present (the replay performed no
    // durable write), so the next identical request replays the original
    // run instead of admitting a new one.
    std::fs::remove_dir(&path).expect("remove SQLite directory");
    std::fs::copy(&backup, &path).expect("restore SQLite state");
    let (restored_status, restored_replay) =
        json_request_with_key(&app, json!({"input": "replay-durable"}), "durable-key").await;
    assert_eq!(restored_status, StatusCode::ACCEPTED);
    assert_eq!(
        restored_replay["run_id"], run_id,
        "the original idempotency record must survive a failed replay persist"
    );
    assert_eq!(
        session_count(&app).await,
        1,
        "a failed replay persist must not leave a new session behind"
    );

    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
    std::fs::remove_file(backup).expect("temporary SQLite backup should be removed");
}

#[tokio::test]
async fn failed_terminal_persist_parks_a_pending_terminal_without_publishing() {
    let (_, arrived_rx, release_tx, fixture, config, source) =
        spawn_holding_run_env(|config| AgentGatewayConfig {
            terminal_persist_retries: 2,
            terminal_persist_retry_delay: std::time::Duration::from_millis(5),
            janitor_interval: std::time::Duration::from_millis(50),
            ..config
        });
    let path =
        std::env::temp_dir().join(format!("rustscript-agent-terminal-{}.db", Uuid::new_v4()));
    let backup = path.with_extension("db.bak");
    let state = AgentGatewayState::with_agent_source_and_sqlite(config, source, &path)
        .expect("SQLite state should open");
    let service = state.service();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "hold-terminal"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();

    // Subscribe to the live SSE stream BEFORE storage breaks (while the
    // gateway persist middleware still succeeds), so the stream stays open
    // and can observe what is (and is not) published during the outage.
    let sse_app = app.clone();
    let sse_run_id = run_id.clone();
    let mut sse_task = tokio::spawn(async move { read_run_events(&sse_app, &sse_run_id).await });

    // The worker is now parked inside the scripted HTTP call, before its
    // terminal commit. Awaiting (instead of blocking) keeps the current-thread
    // runtime polling the worker task.
    tokio::time::timeout(std::time::Duration::from_secs(15), arrived_rx)
        .await
        .expect("the worker must reach the held HTTP call")
        .expect("fixture arrival signal");

    // Break the durable store: SQLite cannot open a directory.
    std::fs::copy(&path, &backup).expect("backup SQLite state");
    std::fs::remove_file(&path).expect("remove SQLite state");
    std::fs::create_dir(&path).expect("replace SQLite state with a directory");

    // Release the script: every bounded commit attempt fails, so the worker
    // parks the decided terminal as pending instead of leaving the run
    // active forever with a leaked permit and a hanging SSE stream.
    release_tx.send(()).expect("release the held HTTP call");
    assert!(
        wait_until(std::time::Duration::from_secs(10), || service
            .pending_terminal_count()
            == 1)
        .await,
        "the worker must park the pending terminal after bounded retries"
    );
    assert_eq!(
        service.stop(&run_id).as_deref(),
        Some("terminal_pending"),
        "a pending terminal is observable, not a committed terminal"
    );

    // stop() must not hang while the terminal is pending, and must not flip
    // the status: the worker has exited and the outcome is decided.
    assert_eq!(
        service.stop(&run_id).as_deref(),
        Some("terminal_pending"),
        "a stop during the pending window must not mutate the run status"
    );
    assert_eq!(
        service.stop(&run_id).as_deref(),
        Some("terminal_pending"),
        "stop() must stay idempotent while the terminal is pending"
    );

    // Nothing may be published while the durable store is down: the live
    // stream stays open without a terminal event.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), &mut sse_task)
            .await
            .is_err(),
        "no terminal may be published while the durable store is down"
    );

    // Restore the durable store: the janitor commits the parked terminal,
    // publishes it exactly once, and the live stream closes on it.
    std::fs::remove_dir(&path).expect("remove SQLite directory");
    std::fs::copy(&backup, &path).expect("restore SQLite state");
    assert!(
        wait_until(std::time::Duration::from_secs(15), || service
            .stop(&run_id)
            .as_deref()
            == Some("completed"))
        .await,
        "the janitor must commit the parked terminal after storage recovery"
    );
    let text = tokio::time::timeout(std::time::Duration::from_secs(15), sse_task)
        .await
        .expect("the live stream must close after the recovered terminal")
        .expect("SSE read task");
    assert_eq!(
        text.matches("event: run.completed").count(),
        1,
        "the recovered terminal must be published exactly once"
    );

    fixture.join().expect("fixture thread");
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
    std::fs::remove_file(backup).expect("temporary SQLite backup should be removed");
}

#[tokio::test]
async fn recovered_storage_commits_the_parked_terminal_once_and_releases_the_permit() {
    let (_, arrived_rx, release_tx, fixture, config, source) =
        spawn_holding_run_env(|config| AgentGatewayConfig {
            max_concurrent_runs: 1,
            terminal_persist_retries: 2,
            terminal_persist_retry_delay: std::time::Duration::from_millis(5),
            janitor_interval: std::time::Duration::from_millis(50),
            ..config
        });
    let path = std::env::temp_dir().join(format!("rustscript-agent-recover-{}.db", Uuid::new_v4()));
    let backup = path.with_extension("db.bak");
    let state = AgentGatewayState::with_agent_source_and_sqlite(config, source, &path)
        .expect("SQLite state should open");
    let service = state.service();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "hold-terminal"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    tokio::time::timeout(std::time::Duration::from_secs(15), arrived_rx)
        .await
        .expect("the worker must reach the held HTTP call")
        .expect("fixture arrival signal");

    std::fs::copy(&path, &backup).expect("backup SQLite state");
    std::fs::remove_file(&path).expect("remove SQLite state");
    std::fs::create_dir(&path).expect("replace SQLite state with a directory");

    release_tx.send(()).expect("release the held HTTP call");
    assert!(
        wait_until(std::time::Duration::from_secs(10), || service
            .pending_terminal_count()
            == 1)
        .await,
        "the worker must park the pending terminal"
    );

    // The admission permit is released as soon as the terminal is registered
    // as pending (never held during a storage outage): capacity 1 admits
    // again immediately (probed directly, because the HTTP persist
    // middleware fail-closes every request while storage is down). The probe
    // admission itself can only fail on the unavailable durable store, never
    // on capacity.
    let second = probe_admit(&service, "second").await;
    assert!(
        !matches!(second, Err(AdmitError::RunLimitReached)),
        "a pending terminal must never hold its capacity permit, got: {second:?}"
    );

    // Restore the durable store: the janitor must commit the parked
    // terminal, publish it exactly once, and release the permit.
    std::fs::remove_dir(&path).expect("remove SQLite directory");
    std::fs::copy(&backup, &path).expect("restore SQLite state");
    assert!(
        wait_until(std::time::Duration::from_secs(15), || service
            .stop(&run_id)
            .as_deref()
            == Some("completed"))
        .await,
        "the janitor must commit the parked terminal after storage recovery"
    );
    assert_eq!(
        service.pending_terminal_count(),
        0,
        "a committed terminal must clear the pending registry"
    );
    assert_eq!(
        service.stop(&run_id).as_deref(),
        Some("completed"),
        "the run record must reach its committed terminal status"
    );

    // The permit is released: capacity 1 admits again.
    let (third_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "third"}),
    )
    .await;
    assert_eq!(
        third_status,
        StatusCode::ACCEPTED,
        "the terminal commit must release the capacity permit"
    );

    // The terminal was published exactly once.
    let text = read_run_events(&app, &run_id).await;
    assert_eq!(
        text.matches("event: run.completed").count(),
        1,
        "the recovered terminal must be published exactly once"
    );

    // ... and it is durably persisted: a fresh gateway replays it once.
    drop(app);
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_app = build_agent_gateway_app(restored);
    let restored_text = read_run_events(&restored_app, &run_id).await;
    assert_eq!(
        restored_text.matches("event: run.completed").count(),
        1,
        "the recovered terminal must be persisted durably"
    );

    fixture.join().expect("fixture thread");
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
    std::fs::remove_file(backup).expect("temporary SQLite backup should be removed");
}

#[tokio::test]
async fn sustained_persistence_failure_never_permanently_exhausts_capacity() {
    let (_, arrived_rx, release_tx, fixture, config, source) =
        spawn_holding_run_env(|config| AgentGatewayConfig {
            max_concurrent_runs: 1,
            terminal_persist_retries: 2,
            terminal_persist_retry_delay: std::time::Duration::from_millis(5),
            janitor_interval: std::time::Duration::from_millis(50),
            ..config
        });
    let path =
        std::env::temp_dir().join(format!("rustscript-agent-capacity-{}.db", Uuid::new_v4()));
    let state = AgentGatewayState::with_agent_source_and_sqlite(config, source, &path)
        .expect("SQLite state should open");
    let service = state.service();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "hold-terminal"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    tokio::time::timeout(std::time::Duration::from_secs(15), arrived_rx)
        .await
        .expect("the worker must reach the held HTTP call")
        .expect("fixture arrival signal");

    // Break the durable store for the rest of the test: every terminal
    // commit attempt keeps failing.
    std::fs::remove_file(&path).expect("remove SQLite state");
    std::fs::create_dir(&path).expect("replace SQLite state with a directory");

    release_tx.send(()).expect("release the held HTTP call");
    assert!(
        wait_until(std::time::Duration::from_secs(10), || service
            .pending_terminal_count()
            == 1)
        .await,
        "the worker must park the pending terminal"
    );

    // The permit is released as soon as the terminal is registered as
    // pending, so a sustained outage can never permanently exhaust
    // admission: capacity 1 admits again immediately (probed directly; the
    // HTTP persist middleware fail-closes every request while storage is
    // down). The probe admission can only fail on the unavailable durable
    // store, never on capacity.
    let boundary = probe_admit(&service, "boundary").await;
    assert!(
        !matches!(boundary, Err(AdmitError::RunLimitReached)),
        "the pending run must never hold its permit, got: {boundary:?}"
    );
    let retry = probe_admit(&service, "retry").await;
    assert!(
        !matches!(retry, Err(AdmitError::RunLimitReached)),
        "admission must stay available while the terminal is pending, got: {retry:?}"
    );
    // The permit is free: admission proceeds (and honestly fails on the
    // unavailable durable store, which is not a capacity error).
    assert_eq!(
        service.pending_terminal_count(),
        1,
        "the pending state must stay observable after the permit is released"
    );
    assert_eq!(
        service.stop(&run_id).as_deref(),
        Some("terminal_pending"),
        "no terminal may be committed while storage is down; the status must stay observable"
    );

    fixture.join().expect("fixture thread");
    std::fs::remove_dir(&path).expect("remove SQLite directory");
}

#[tokio::test]
async fn failed_admission_persist_rolls_back_an_existing_sessions_message() {
    let path =
        std::env::temp_dir().join(format!("rustscript-agent-rollback-{}.db", Uuid::new_v4()));
    let backup = path.with_extension("db.bak");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"ok\"; }",
        &path,
    )
    .expect("SQLite state should open");
    let app = build_agent_gateway_app(state);

    let (create_status, created) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"source": "yahu"}),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let session_id = created["session"]["id"]
        .as_str()
        .expect("session id")
        .to_string();
    let (_, before) = json_request(
        &app,
        axum::http::Method::GET,
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    assert_eq!(
        before["data"].as_array().map(Vec::len).unwrap_or(0),
        0,
        "the existing session must start empty"
    );

    std::fs::copy(&path, &backup).expect("backup SQLite state");
    std::fs::remove_file(&path).expect("remove SQLite state");
    std::fs::create_dir(&path).expect("replace SQLite state with a directory");

    // Admission against the existing session appends a user message, then
    // fails to persist; the whole admission must roll back, including the
    // message appended to the pre-existing session.
    let (admit_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "rollback-me", "session_id": session_id}),
    )
    .await;
    assert_ne!(
        admit_status,
        StatusCode::ACCEPTED,
        "admission must fail while persistence is down"
    );

    // Restore storage and verify the existing session is unchanged: no user
    // message leaked from the failed admission.
    std::fs::remove_dir(&path).expect("remove SQLite directory");
    std::fs::copy(&backup, &path).expect("restore SQLite state");
    let (_, after) = json_request(
        &app,
        axum::http::Method::GET,
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    assert_eq!(
        after["data"].as_array().map(Vec::len).unwrap_or(0),
        0,
        "a failed admission must roll back the message appended to the existing session"
    );

    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
    std::fs::remove_file(backup).expect("temporary SQLite backup should be removed");
}

#[tokio::test]
async fn legacy_chat_timeout_is_bounded_while_the_worker_is_blocked() {
    let (_, _arrived_rx, release_tx, fixture, config, source) =
        spawn_holding_run_env(|config| AgentGatewayConfig {
            run_timeout: std::time::Duration::from_millis(200),
            cancellation_grace: std::time::Duration::from_millis(50),
            ..config
        });
    let state =
        AgentGatewayState::with_agent_source(config, source).expect("RSS source should compile");
    let app = build_agent_gateway_app(state);

    let (create_status, created) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"source": "yahu"}),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let session_id = created["session"]["id"]
        .as_str()
        .expect("session id")
        .to_string();

    // The legacy chat completion path must bound the worker exit: even with
    // the worker blocked inside the held HTTP call, the run_timeout fires
    // and the response arrives well within run_timeout + cancellation_grace
    // (a hardcoded 5s grace would blow this bound).
    let chat_uri = format!("/api/sessions/{session_id}/chat");
    let chat = json_request(
        &app,
        axum::http::Method::POST,
        &chat_uri,
        json!({"input": "hang"}),
    );
    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(3), chat)
        .await
        .expect("legacy chat must finish within run_timeout + cancellation_grace");
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body["error"]["code"], "agent_timeout");

    // Unblock the abandoned worker so the fixture thread can exit.
    release_tx.send(()).expect("release the held HTTP call");
    fixture.join().expect("fixture thread");
}

/// P1 (production path): the gateway's real restart load path fails the
/// pending compaction of an interrupted run, so the session is never stuck:
/// after reopen, a fresh compaction starts (the failed row is reset) and
/// commits with exactly-once generation.
#[tokio::test]
async fn gateway_restart_recovery_fails_pending_compaction_and_allows_retry() {
    let path = gateway_db_path("compaction-crash-window");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    let now = 2_000_000u64;
    persistence
        .admission_create(&json!({
            "session_id": "crash-session",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "crash-session",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "crash-run",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "crash-message",
            "message_run_id": "crash-run",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "crash-run",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "crash-event",
            "now_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("admission should commit");
    for (message_id, content) in [
        ("crash-message-2", r#"[{"type":"text","text":"more"}]"#),
        ("crash-message-3", r#"[{"type":"text","text":"done"}]"#),
    ] {
        persistence
            .message_append(&json!({
                "id": message_id,
                "session_id": "crash-session",
                "role": "user",
                "content_json": content,
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 1,
                "metadata_json": "{}",
                "run_id": "",
                "finish_reason": "",
                "now_ms": now + 1,
            }))
            .expect("message should append");
    }
    // Admission leaves the run `running`; move it to compacting.
    persistence
        .run_transition(&json!({
            "run_id": "crash-run",
            "from_status": "running",
            "to_status": "compacting",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now + 3,
        }))
        .expect("run should transition to compacting");
    let compaction = persistence
        .compaction_start(&json!({
            "id": "compaction-1",
            "session_id": "crash-session",
            "run_id": "crash-run",
            "generation": 2,
            "source_start_ordinal": 1,
            "source_end_ordinal": 3,
            "retained_tail_ordinal": 3,
            "summary_json": "{\"summary\":\"compacted\"}",
            "token_estimate": 10,
            "model": "m",
            "now_ms": now + 4,
        }))
        .expect("compaction should start");
    assert_eq!(compaction["rows"][0][0], json!("compaction-1"));
    assert_eq!(compaction["rows"][0][10], json!("pending"));
    drop(state);

    // Production reopen: the restart load path fails the interrupted run
    // AND its pending compaction.
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload");
    let restored_persistence = restored
        .persistence()
        .expect("persistence handle should be exposed");
    let failed = restored_persistence
        .compaction_get("compaction-1")
        .expect("compaction should be observable after restart");
    assert_eq!(
        failed["rows"][0][10],
        json!("failed"),
        "restart recovery must fail the pending compaction of the interrupted run"
    );
    let run = restored_persistence
        .run_get("crash-run")
        .expect("run should be observable after restart");
    assert_eq!(run["rows"][0][3], json!("failed"));

    // The session is not stuck: a fresh run enters compacting and the SAME
    // compaction id is retried (the failed row is reset to pending and
    // commits; the single row keeps its audit identity).
    restored_persistence
        .admission_create(&json!({
            "session_id": "crash-session",
            "session_new": 0,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "crash-session",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "crash-run-2",
            "parent_run_id": "",
            "input_json": "{\"text\":\"retry\"}",
            "message_id": "crash-message-retry",
            "message_run_id": "crash-run-2",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "crash-run-2",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "crash-event-retry",
            "now_ms": now + 5,
            "expires_at_ms": 0,
        }))
        .expect("retry admission should commit");
    // Admission leaves the run `running`; move it to compacting.
    restored_persistence
        .run_transition(&json!({
            "run_id": "crash-run-2",
            "from_status": "running",
            "to_status": "compacting",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now + 7,
        }))
        .expect("retry run should transition to compacting");
    let restarted = restored_persistence
        .compaction_start(&json!({
            "id": "compaction-1",
            "session_id": "crash-session",
            "run_id": "crash-run-2",
            "generation": 2,
            "source_start_ordinal": 1,
            "source_end_ordinal": 3,
            "retained_tail_ordinal": 3,
            "summary_json": "{\"summary\":\"compacted\"}",
            "token_estimate": 10,
            "model": "m",
            "now_ms": now + 8,
        }))
        .expect("a fresh compaction should start after recovery");
    assert_eq!(restarted["rows"][0][0], json!("compaction-1"));
    assert_eq!(restarted["rows"][0][10], json!("pending"));
    let committed = restored_persistence
        .compaction_commit(&json!({
            "id": "compaction-1",
            "session_id": "crash-session",
            "start_ordinal": 1,
            "end_ordinal": 3,
            "generation": 2,
            "completed_at_ms": now + 9,
        }))
        .expect("the retry compaction should commit");
    assert_eq!(committed["results"][0]["rows_affected"], json!(1));
    let committed_row = restored_persistence
        .compaction_get("compaction-1")
        .expect("compaction after commit");
    assert_eq!(committed_row["rows"][0][10], json!("committed"));
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// A7: bounded rate limiting and the client-disconnect policy, exercised over
// a real Axum HTTP/SSE server (not router oneshot) with fixture RSS.
// ---------------------------------------------------------------------------

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use rustscript_agent::config::{ClientDisconnectPolicy, RateLimitConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Real Axum server bound to the dual-stack IPv6 wildcard so tests can
/// reach one listener from two distinct peer IPs (127.0.0.1 and ::1).
struct GatewayServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    _task: tokio::task::JoinHandle<()>,
}

async fn spawn_gateway_server(state: AgentGatewayState) -> GatewayServer {
    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0))
        .await
        .expect("bind dual-stack gateway listener");
    let addr = listener.local_addr().expect("gateway listener address");
    let app = build_agent_gateway_app(state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .expect("gateway server must run");
    });
    GatewayServer {
        addr,
        _shutdown: shutdown_tx,
        _task: task,
    }
}

/// Minimal raw HTTP/1.1 client over tokio TCP (no extra dependencies), with
/// an incremental SSE reader that strips chunked framing so marker scans
/// see the event stream exactly as the server wrote it. Dropping the client
/// aborts the connection (the server notices on the next write).
struct RawHttp {
    stream: tokio::net::TcpStream,
    /// Raw bytes received but not yet consumed (head or chunk framing).
    buffer: Vec<u8>,
    /// De-chunked SSE body bytes.
    sse: Vec<u8>,
    /// True once the final chunk (`0\r\n\r\n`) or EOF was seen.
    sse_done: bool,
}

impl RawHttp {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to gateway");
        Self {
            stream,
            buffer: Vec::new(),
            sse: Vec::new(),
            sse_done: false,
        }
    }

    async fn read_some(&mut self) -> usize {
        let mut chunk = [0_u8; 8192];
        let read = self
            .stream
            .read(&mut chunk)
            .await
            .expect("read gateway response");
        self.buffer.extend_from_slice(&chunk[..read]);
        read
    }

    fn sse_contains(&self, marker: &str) -> bool {
        self.sse
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }

    /// One complete request/response exchange (Content-Length bodies).
    async fn exchange(&mut self, head: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        self.stream
            .write_all(head.as_bytes())
            .await
            .expect("write request");
        let (status, headers) = self.read_head().await;
        let length = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(0);
        while self.buffer.len() < length && self.read_some().await > 0 {}
        let body = self.buffer.drain(..length.min(self.buffer.len())).collect();
        (status, headers, body)
    }

    /// Sends a request and reads only the response head; the SSE body stays
    /// in the buffer for incremental `read_until` scanning.
    async fn open(&mut self, head: &str) -> (u16, Vec<(String, String)>) {
        self.stream
            .write_all(head.as_bytes())
            .await
            .expect("write request");
        self.read_head().await
    }

    async fn read_head(&mut self) -> (u16, Vec<(String, String)>) {
        loop {
            if let Some(end) = self
                .buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                let head = String::from_utf8_lossy(&self.buffer[..end]).into_owned();
                self.buffer.drain(..end + 4);
                let mut lines = head.split("\r\n");
                let status_line = lines.next().unwrap_or_default();
                let status = status_line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let headers = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| {
                        (name.trim().to_ascii_lowercase(), value.trim().to_string())
                    })
                    .collect();
                return (status, headers);
            }
            if self.read_some().await == 0 {
                panic!("gateway closed the connection before the response head");
            }
        }
    }

    /// Blocks until `marker` appears in the de-chunked SSE body, the stream
    /// ends, or `timeout` elapses.
    async fn read_until(&mut self, marker: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let (consumed, finished) = decode_chunked(&self.buffer, &mut self.sse);
            if consumed > 0 {
                self.buffer.drain(..consumed);
            }
            if finished {
                self.sse_done = true;
            }
            if self.sse_contains(marker) {
                return true;
            }
            if self.sse_done {
                return false;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, self.read_some()).await {
                Ok(0) => {
                    let (_, finished) = decode_chunked(&self.buffer, &mut self.sse);
                    if finished {
                        self.sse_done = true;
                    }
                    return self.sse_contains(marker);
                }
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }

    /// Reads until the SSE stream ends (final chunk or EOF), bounded.
    async fn drain_sse(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.sse_done {
            let (consumed, finished) = decode_chunked(&self.buffer, &mut self.sse);
            if consumed > 0 {
                self.buffer.drain(..consumed);
            }
            if finished {
                self.sse_done = true;
                return;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            match tokio::time::timeout(remaining, self.read_some()).await {
                Ok(0) => self.sse_done = true,
                Ok(_) => {}
                Err(_) => return,
            }
        }
    }

    fn sse_text(&self) -> String {
        String::from_utf8_lossy(&self.sse).into_owned()
    }
}

/// Strips HTTP/1.1 chunked framing from `raw`, appending decoded bytes to
/// `out`. Returns how many raw bytes were consumed and whether the final
/// chunk was reached. Incomplete trailing frames are left in `raw` for the
/// next read.
fn decode_chunked(raw: &[u8], out: &mut Vec<u8>) -> (usize, bool) {
    let mut pos = 0;
    loop {
        let Some(relative_end) = raw[pos..].windows(2).position(|window| window == b"\r\n") else {
            return (pos, false);
        };
        let size_line = &raw[pos..pos + relative_end];
        let Some(size) = std::str::from_utf8(size_line)
            .ok()
            .and_then(|line| usize::from_str_radix(line.trim(), 16).ok())
        else {
            return (pos, false);
        };
        pos += relative_end + 2;
        if size == 0 {
            if raw.len() < pos + 2 || &raw[pos..pos + 2] != b"\r\n" {
                return (pos, false);
            }
            pos += 2;
            return (pos, true);
        }
        if raw.len() < pos + size + 2 {
            return (pos, false);
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size + 2;
    }
}

fn http_head(method: &str, path: &str, body: Option<&str>, extra: &[(&str, &str)]) -> String {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: gateway.test\r\n");
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    match body {
        Some(body) => head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )),
        None => head.push_str("Content-Length: 0\r\n\r\n"),
    }
    head
}

/// One JSON request over a fresh real HTTP connection.
async fn raw_json(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Value,
    extra: &[(&str, &str)],
) -> (u16, Vec<(String, String)>, Value) {
    let mut client = RawHttp::connect(addr).await;
    let (status, headers, bytes) = client
        .exchange(&http_head(method, path, Some(&body.to_string()), extra))
        .await;
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

/// Polls `/health/detailed` until `active_agents` reaches `expected`.
async fn wait_for_active_agents(addr: SocketAddr, expected: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mut client = RawHttp::connect(addr).await;
        let (status, _, bytes) = client
            .exchange(&http_head("GET", "/health/detailed", None, &[]))
            .await;
        assert_eq!(status, 200, "health endpoint must respond");
        let health: Value = serde_json::from_slice(&bytes).expect("health JSON");
        let active = health["active_agents"].as_u64().unwrap_or(0) as usize;
        if active == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "active_agents never reached {expected} (last={active})"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn rate_limit_rejects_with_429_retry_after_and_recovers_after_window() {
    let state = AgentGatewayState::new(AgentGatewayConfig {
        rate_limit: RateLimitConfig {
            enabled: true,
            ip_burst: 2,
            account_burst: 2,
            window: Duration::from_millis(200),
            max_buckets: 64,
        },
        ..AgentGatewayConfig::default()
    })
    .expect("gateway config must validate");
    let server = spawn_gateway_server(state).await;

    let mut client = RawHttp::connect(server.addr).await;
    let health = http_head("GET", "/health/detailed", None, &[]);
    for _ in 0..2 {
        let (status, _, _) = client.exchange(&health).await;
        assert_eq!(status, 200, "requests inside the burst must pass");
    }
    let (status, headers, bytes) = client.exchange(&health).await;
    assert_eq!(
        status, 429,
        "the burst-exceeding request must be rate limited"
    );
    let retry_after = headers
        .iter()
        .find(|(name, _)| name == "retry-after")
        .expect("429 must carry a Retry-After header");
    assert!(
        retry_after.1.parse::<u64>().unwrap_or(0) >= 1,
        "Retry-After must be at least 1 second"
    );
    let body: Value = serde_json::from_slice(&bytes).expect("429 body JSON");
    assert_eq!(body["error"]["code"], "rate_limited");

    // After the window the bucket refills (or the stale bucket is swept,
    // which is semantically identical: a fresh bucket starts full).
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (status, _, _) = client.exchange(&health).await;
    assert_eq!(status, 200, "the bucket must recover after the window");
}

#[tokio::test]
async fn rate_limit_isolates_accounts_from_ips_and_auth_failures_never_charge_accounts() {
    let state = AgentGatewayState::new(AgentGatewayConfig {
        bearer_token: Some("a7-secret".to_string()),
        rate_limit: RateLimitConfig {
            enabled: true,
            // The IP dimension has headroom: any 429 below must come from
            // the account dimension, and a 401 proves auth failure ordering.
            ip_burst: 100,
            account_burst: 2,
            window: Duration::from_millis(200),
            max_buckets: 64,
        },
        ..AgentGatewayConfig::default()
    })
    .expect("gateway config must validate");
    let server = spawn_gateway_server(state).await;
    let authorized = [("authorization", "Bearer a7-secret")];

    // 1) An authenticated request consumes one account token.
    let (status, _, _) = raw_json(
        server.addr,
        "GET",
        "/health/detailed",
        Value::Null,
        &authorized,
    )
    .await;
    assert_eq!(status, 200);

    // 2) An auth failure is 401 and must not consume the account bucket.
    let (status, _, _) = raw_json(
        server.addr,
        "GET",
        "/health/detailed",
        Value::Null,
        &[("authorization", "Bearer wrong")],
    )
    .await;
    assert_eq!(
        status, 401,
        "auth failures must be rejected as unauthorized, never rate limited"
    );

    // 3) The account still has its last token: this request must pass.
    let (status, _, _) = raw_json(
        server.addr,
        "GET",
        "/health/detailed",
        Value::Null,
        &authorized,
    )
    .await;
    assert_eq!(
        status, 200,
        "the failed auth must not have consumed the account bucket"
    );

    // 4) The account bucket is now exhausted while the IP bucket has
    //    headroom: the 429 must come from the account dimension.
    let (status, _, body) = raw_json(
        server.addr,
        "GET",
        "/health/detailed",
        Value::Null,
        &authorized,
    )
    .await;
    assert_eq!(
        status, 429,
        "the account bucket must be exhausted independently of the IP bucket"
    );
    assert_eq!(body["error"]["code"], "rate_limited");

    // Window recovery restores the account dimension.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (status, _, _) = raw_json(
        server.addr,
        "GET",
        "/health/detailed",
        Value::Null,
        &authorized,
    )
    .await;
    assert_eq!(
        status, 200,
        "the account bucket must recover after the window"
    );
}

#[tokio::test]
async fn rate_limit_isolates_peer_ips_on_one_listener() {
    let state = AgentGatewayState::new(AgentGatewayConfig {
        rate_limit: RateLimitConfig {
            enabled: true,
            ip_burst: 2,
            account_burst: 100,
            window: Duration::from_secs(60),
            max_buckets: 64,
        },
        ..AgentGatewayConfig::default()
    })
    .expect("gateway config must validate");
    let server = spawn_gateway_server(state).await;
    let health = http_head("GET", "/health/detailed", None, &[]);

    // One dual-stack listener, two distinct peer addresses.
    let ipv4_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server.addr.port());
    let ipv6_peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), server.addr.port());

    let mut ipv4 = RawHttp::connect(ipv4_peer).await;
    let (status, _, _) = ipv4.exchange(&health).await;
    assert_eq!(status, 200, "first request from the IPv4 peer must pass");

    let mut ipv6 = RawHttp::connect(ipv6_peer).await;
    let (status, _, _) = ipv6.exchange(&health).await;
    assert_eq!(status, 200, "a different peer IP must have its own bucket");

    let (status, _, _) = ipv4.exchange(&health).await;
    assert_eq!(status, 200, "the IPv4 burst is not yet exhausted");
    let (status, _, _) = ipv4.exchange(&health).await;
    assert_eq!(status, 429, "the exhausted IPv4 bucket must be rejected");
    let (status, _, _) = ipv6.exchange(&health).await;
    assert_eq!(
        status, 200,
        "the IPv6 bucket must be unaffected by IPv4 exhaustion"
    );
}

#[tokio::test]
async fn keep_running_default_survives_disconnect_and_events_replay_by_cursor() {
    let (_, arrived_rx, release_tx, fixture, config, source) =
        spawn_holding_run_env(|config| AgentGatewayConfig {
            sse_keepalive_interval: Duration::from_millis(100),
            ..config
        });
    let state =
        AgentGatewayState::with_agent_source(config, source).expect("RSS source should compile");
    let server = spawn_gateway_server(state).await;

    let (status, _, session) = raw_json(
        server.addr,
        "POST",
        "/api/sessions",
        json!({"source": "a7"}),
        &[],
    )
    .await;
    assert_eq!(status, 201);
    let session_id = session["session"]["id"].as_str().expect("session id");
    let (status, _, run) = raw_json(
        server.addr,
        "POST",
        "/v1/runs",
        json!({"session_id": session_id, "input": "hold"}),
        &[],
    )
    .await;
    assert_eq!(status, 202);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    arrived_rx
        .await
        .expect("the run must reach the holding fixture");

    // Subscribe over real SSE, then disconnect while the run is active.
    let sse_path = format!("/v1/runs/{run_id}/events");
    let mut subscriber = RawHttp::connect(server.addr).await;
    let (status, _) = subscriber
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        subscriber
            .read_until("event: run.started", Duration::from_secs(3))
            .await,
        "started event must stream"
    );
    drop(subscriber); // client disconnect

    // Default policy keep-running: the run must still be active well past
    // the disconnect-detection bound (one keep-alive interval).
    tokio::time::sleep(Duration::from_millis(400)).await;
    wait_for_active_agents(server.addr, 1, Duration::from_secs(2)).await;

    // Release the held HTTP call: the run completes on its own.
    release_tx.send(()).expect("release the held HTTP call");
    wait_for_active_agents(server.addr, 0, Duration::from_secs(5)).await;
    fixture.join().expect("fixture thread");

    // Cursor replay: after_seq=1 returns everything after run.started,
    // including the terminal. No cancellation was requested.
    let replay_path = format!("/v1/runs/{run_id}/events?after_seq=1");
    let mut replay = RawHttp::connect(server.addr).await;
    let (status, _) = replay
        .open(&http_head(
            "GET",
            &replay_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        replay
            .read_until("event: run.completed", Duration::from_secs(5))
            .await,
        "replayed terminal event"
    );
    replay.drain_sse(Duration::from_secs(2)).await;
    let text = replay.sse_text();
    assert!(
        text.contains("event: run.completed"),
        "the terminal must be replayable"
    );
    assert!(
        !text.contains("event: run.started"),
        "after_seq=1 must skip the started event"
    );
    assert!(
        !text.contains("event: run.cancelled"),
        "keep-running must not cancel on disconnect"
    );
    assert_eq!(
        text.matches("event: run.completed").count(),
        1,
        "exactly one terminal"
    );
}

/// P3: an `after_seq` of u64::MAX must not overflow the retained-history
/// check: the cursor is saturated, so the request answers with the empty
/// replay (no event can follow the maximum sequence) instead of panicking
/// or wrapping into a bogus `event_cursor_too_old` conflict. The SSE stream
/// stays open after the empty replay (live subscription semantics — clients
/// never wait for EOF), so the body is read with a bounded window.
#[tokio::test]
async fn max_u64_event_cursor_is_rejected_without_overflow() {
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
        json!({"input": "cursor-max"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id");

    // Wait for the terminal so retained history exists (earliest seq 1)
    // and the terminal event is replayable.
    let text = read_run_events(&app, run_id).await;
    assert!(text.contains("event: run.completed"));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri(format!(
                    "/v1/runs/{run_id}/events?after_seq=18446744073709551615"
                ))
                .body(Body::empty())
                .expect("SSE request should build"),
        )
        .await
        .expect("the router must answer the saturated cursor, not panic");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a saturated cursor must answer 200, not panic or wrap"
    );
    // Nothing can be replayed after u64::MAX: whatever arrives within the
    // bounded window must not contain any event.
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024);
    let body = tokio::time::timeout(std::time::Duration::from_millis(1500), body).await;
    let text = match body {
        Ok(Ok(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
        Ok(Err(error)) => panic!("SSE body should be readable: {error}"),
        Err(_) => String::new(),
    };
    assert!(
        !text.contains("event: run.completed"),
        "no retained event can follow u64::MAX, got: {text:?}"
    );
    assert!(!text.contains("event: run.started"));
}

#[tokio::test]
async fn cancel_on_disconnect_cancels_when_last_subscriber_disconnects() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            client_disconnect_policy: ClientDisconnectPolicy::CancelOnDisconnect,
            sse_keepalive_interval: Duration::from_millis(100),
            ..AgentGatewayConfig::default()
        },
        include_str!("fixtures/gateway/cpu_loop.rss"),
    )
    .expect("RSS source should compile");
    let server = spawn_gateway_server(state).await;

    let (status, _, run) = raw_json(
        server.addr,
        "POST",
        "/v1/runs",
        json!({"input": "spin"}),
        &[],
    )
    .await;
    assert_eq!(status, 202);
    let run_id = run["run_id"].as_str().expect("run id").to_string();

    let sse_path = format!("/v1/runs/{run_id}/events");
    let mut subscriber = RawHttp::connect(server.addr).await;
    let (status, _) = subscriber
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        subscriber
            .read_until("event: run.started", Duration::from_secs(3))
            .await,
        "started event must stream"
    );
    drop(subscriber);

    // The last subscriber disconnected while the run was active: the typed
    // client_disconnect cancellation must commit a terminal.
    wait_for_active_agents(server.addr, 0, Duration::from_secs(5)).await;

    let mut replay = RawHttp::connect(server.addr).await;
    let (status, _) = replay
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        replay
            .read_until("\"reason\":\"client_disconnect\"", Duration::from_secs(5))
            .await,
        "the persisted cancellation must carry the typed client_disconnect reason"
    );
    replay.drain_sse(Duration::from_secs(2)).await;
    let text = replay.sse_text();
    assert_eq!(
        text.matches("event: run.cancelled").count(),
        1,
        "exactly one terminal"
    );
    assert!(
        !text.contains("event: run.completed"),
        "a disconnected run must not complete"
    );
    assert!(
        text.contains("event: run.started"),
        "full history must replay"
    );
}

#[tokio::test]
async fn multi_subscriber_and_reconnect_races_never_cancel_while_a_subscriber_remains() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            client_disconnect_policy: ClientDisconnectPolicy::CancelOnDisconnect,
            sse_keepalive_interval: Duration::from_millis(100),
            ..AgentGatewayConfig::default()
        },
        include_str!("fixtures/gateway/cpu_loop.rss"),
    )
    .expect("RSS source should compile");
    let server = spawn_gateway_server(state).await;

    let (status, _, run) = raw_json(
        server.addr,
        "POST",
        "/v1/runs",
        json!({"input": "spin"}),
        &[],
    )
    .await;
    assert_eq!(status, 202);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    let sse_path = format!("/v1/runs/{run_id}/events");

    let mut first = RawHttp::connect(server.addr).await;
    let (status, _) = first
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        first
            .read_until("event: run.started", Duration::from_secs(3))
            .await
    );

    let mut second = RawHttp::connect(server.addr).await;
    let (status, _) = second
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        second
            .read_until("event: run.started", Duration::from_secs(3))
            .await
    );

    // One of two subscribers drops: the run must survive well past the
    // disconnect-detection bound.
    drop(first);
    tokio::time::sleep(Duration::from_millis(500)).await;
    wait_for_active_agents(server.addr, 1, Duration::from_secs(2)).await;

    // A reconnecting subscriber joins before the second one drops: still no
    // cancellation.
    let mut third = RawHttp::connect(server.addr).await;
    let (status, _) = third
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        third
            .read_until("event: run.started", Duration::from_secs(3))
            .await
    );
    drop(second);
    tokio::time::sleep(Duration::from_millis(500)).await;
    wait_for_active_agents(server.addr, 1, Duration::from_secs(2)).await;

    // The last subscriber leaves: the typed cancellation commits.
    drop(third);
    wait_for_active_agents(server.addr, 0, Duration::from_secs(5)).await;

    let mut replay = RawHttp::connect(server.addr).await;
    let (status, _) = replay
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        replay
            .read_until("\"reason\":\"client_disconnect\"", Duration::from_secs(5))
            .await,
        "the last disconnect must commit the typed client_disconnect cancellation"
    );
    replay.drain_sse(Duration::from_secs(2)).await;
    let text = replay.sse_text();
    assert_eq!(
        text.matches("event: run.cancelled").count(),
        1,
        "exactly one terminal"
    );
    assert!(!text.contains("event: run.completed"));
}

#[tokio::test]
async fn normal_terminal_end_never_requests_client_disconnect_cancellation() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            client_disconnect_policy: ClientDisconnectPolicy::CancelOnDisconnect,
            sse_keepalive_interval: Duration::from_millis(100),
            ..AgentGatewayConfig::default()
        },
        include_str!("fixtures/gateway/complete_fast.rss"),
    )
    .expect("RSS source should compile");
    let server = spawn_gateway_server(state).await;

    let (status, _, run) = raw_json(
        server.addr,
        "POST",
        "/v1/runs",
        json!({"input": "fast"}),
        &[],
    )
    .await;
    assert_eq!(status, 202);
    let run_id = run["run_id"].as_str().expect("run id").to_string();

    // Subscribe and read through the terminal; the stream ends on its own.
    let sse_path = format!("/v1/runs/{run_id}/events");
    let mut subscriber = RawHttp::connect(server.addr).await;
    let (status, _) = subscriber
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        subscriber
            .read_until("event: run.completed", Duration::from_secs(5))
            .await,
        "the fast run must complete"
    );
    subscriber.drain_sse(Duration::from_secs(2)).await;
    let text = subscriber.sse_text();
    assert_eq!(
        text.matches("event: run.completed").count(),
        1,
        "exactly one terminal"
    );
    assert!(
        !text.contains("event: run.cancelled"),
        "a normal terminal end must never request a cancellation"
    );

    // Replaying the same terminal (subscriber attaches after completion)
    // must not request anything either.
    wait_for_active_agents(server.addr, 0, Duration::from_secs(5)).await;
    let mut replay = RawHttp::connect(server.addr).await;
    let (status, _) = replay
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        replay
            .read_until("event: run.completed", Duration::from_secs(5))
            .await
    );
    replay.drain_sse(Duration::from_secs(2)).await;
    let replayed = replay.sse_text();
    assert_eq!(replayed.matches("event: run.completed").count(), 1);
    assert!(!replayed.contains("event: run.cancelled"));
    assert!(!replayed.contains("client_disconnect"));
}
/// A9: two concurrent stop requests racing the same active run must both
/// succeed (the typed cancellation is idempotent) and the run must commit
/// exactly one terminal — never two.
#[tokio::test]
async fn concurrent_stops_commit_exactly_one_terminal() {
    let (port, arrived, release, fixture) = spawn_holding_fixture();
    let http = rustscript_vm::HttpConfig {
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_schemes: vec!["http".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            http,
            ..AgentGatewayConfig::default()
        },
        format!(
            r#"
            use http;
            pub fn run(input: map) -> string {{
                http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
                "done";
            }}
            "#
        ),
    )
    .expect("RSS source should compile");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "race"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    arrived.await.expect("the run must reach the fixture");

    let stop_uri = format!("/v1/runs/{run_id}/stop");
    let (first, second) = tokio::join!(
        json_request(&app, axum::http::Method::POST, &stop_uri, Value::Null,),
        json_request(&app, axum::http::Method::POST, &stop_uri, Value::Null,),
    );
    assert_eq!(first.0, StatusCode::OK, "the first stop must succeed");
    assert_eq!(second.0, StatusCode::OK, "the second stop must succeed");

    release.send(()).expect("release the fixture");
    fixture.join().expect("fixture thread");
    let text = read_run_events(&app, &run_id).await;
    let terminals = text.matches("event: run.completed").count()
        + text.matches("event: run.cancelled").count()
        + text.matches("event: run.failed").count();
    assert_eq!(
        terminals, 1,
        "two concurrent stops must still commit exactly one terminal, got: {text}"
    );
}

/// A9: a stop that lands while the worker is inside the bounded terminal
/// persist-retry loop (storage down, attempts failing) must never produce
/// two terminals: the retry either commits its typed terminal or the typed
/// cancellation path wins — exactly one terminal, counted exactly once.
#[tokio::test]
async fn stop_during_terminal_persist_retry_commits_exactly_one_terminal() {
    let path = gateway_db_path("stop-during-retry");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig {
            janitor_interval: std::time::Duration::from_millis(50),
            terminal_commit_retry_window: std::time::Duration::from_secs(30),
            terminal_persist_retries: 10,
            terminal_persist_retry_delay: std::time::Duration::from_millis(50),
            ..AgentGatewayConfig::default()
        },
        "pub fn run(input: map) -> string { \"done\"; }",
        &path,
    )
    .expect("SQLite state should open");
    let metrics = state.metrics();
    let service = state.service();
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "retry"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();

    // Break storage so the completed terminal cannot be persisted.
    let broken = path.with_extension("db.broken");
    std::fs::rename(&path, &broken).expect("move the db aside");
    std::fs::create_dir(&path).expect("break storage with a directory");

    // Deterministic signal: the first failed run.terminal attempt means the
    // worker is inside the bounded persist-retry loop (no sleeps).
    let in_retry = wait_until(std::time::Duration::from_secs(10), || {
        metrics
            .snapshot()
            .storage_op_failures(StorageOp::RunTerminal)
            >= 1
    })
    .await;
    assert!(
        in_retry,
        "the worker must enter the terminal persist retry loop"
    );

    let (stop_status, _) = json_request(
        &app,
        axum::http::Method::POST,
        &format!("/v1/runs/{run_id}/stop"),
        Value::Null,
    )
    .await;
    assert_eq!(stop_status, StatusCode::OK);

    // Recover storage; whichever side wins (the retry's terminal or the
    // typed cancellation), exactly one terminal is committed and counted.
    std::fs::remove_dir(&path).expect("restore storage");
    std::fs::rename(&broken, &path).expect("restore the db file");
    let text = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        read_run_events(&app, &run_id),
    )
    .await
    .expect("the run must reach exactly one terminal");
    let terminals = text.matches("event: run.completed").count()
        + text.matches("event: run.cancelled").count()
        + text.matches("event: run.failed").count();
    assert_eq!(
        terminals, 1,
        "a stop landing inside the terminal persist retry must never produce two terminals, got: {text}"
    );
    // The SSE body completes at publish time, inside the terminal commit;
    // the permit/gauge release happens a scheduling step later. Wait for
    // the observable terminal (bounded polling, not a fixed sleep).
    let settled = wait_until(std::time::Duration::from_secs(10), || {
        service.available_capacity() == AgentGatewayConfig::default().max_concurrent_runs
    })
    .await;
    assert!(
        settled,
        "the permit must be released after the terminal resolves"
    );
    assert_eq!(
        service.pending_terminal_count(),
        0,
        "the pending terminal must resolve after recovery"
    );
    let snapshot = metrics.snapshot();
    let terminal_total = snapshot.runs_terminal_by(TerminalStatus::Completed)
        + snapshot.runs_terminal_by(TerminalStatus::Cancelled)
        + snapshot.runs_terminal_by(TerminalStatus::Failed);
    assert_eq!(
        terminal_total, 1,
        "the registry must count exactly one terminal for the raced run"
    );
    let _ = std::fs::remove_file(&path);
}

/// A9: an SSE subscriber that falls behind the bounded broadcast buffer
/// receives a typed lagged error (with the dropped count) and its stream
/// ends — no silent gap, no fabricated terminal — and a fresh subscription
/// replays the complete ordered history.
#[tokio::test]
async fn sse_subscriber_lag_emits_typed_error_and_replay_recovers() {
    let (port, arrived, release, fixture) = spawn_holding_fixture();
    let http = rustscript_vm::HttpConfig {
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_schemes: vec!["http".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            broadcast_capacity: 2,
            http,
            ..AgentGatewayConfig::default()
        },
        format!(
            r#"
            use http;
            use stream;
            pub fn run(input: map) -> string {{
                http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
                stream::emit({{"type": "model.delta", "delta": "a"}});
                stream::emit({{"type": "model.delta", "delta": "b"}});
                stream::emit({{"type": "model.delta", "delta": "c"}});
                "done";
            }}
            "#
        ),
    )
    .expect("RSS source should compile");
    let metrics = state.metrics();
    let service = state.service();
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "lag"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    // The script is parked inside the HTTP call before any event is emitted.
    arrived.await.expect("the run must reach the fixture");

    // Subscribe while the run is live, then hold the response unread.
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

    // Release the script: three deltas and the two terminal events are
    // broadcast into a capacity-2 channel while the subscriber is not
    // reading — a deterministic lag (no sleeps).
    release.send(()).expect("release the fixture");
    let terminal = wait_until(std::time::Duration::from_secs(10), || {
        service.available_capacity() == AgentGatewayConfig::default().max_concurrent_runs
    })
    .await;
    assert!(terminal, "the run must reach its terminal");
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8");
    // 5 broadcasts (a, b, c, message.delta, run.completed) with capacity 2:
    // the subscriber missed 3 and must observe a typed lagged error, then
    // the stream ends instead of presenting a gap.
    assert!(
        text.contains("event: error") && text.contains("event_lagged"),
        "a lagging subscriber must get a typed lagged error, got: {text}"
    );
    assert!(
        text.contains("\"dropped\":3"),
        "the lagged error must carry the exact dropped count, got: {text}"
    );
    assert!(
        !text.contains("event: model.delta") && !text.contains("event: run.completed"),
        "no skipped event may be silently presented, got: {text}"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.events_lagged, 3);
    assert_eq!(snapshot.events_emitted, 3);

    // A fresh subscription replays the complete ordered history: started,
    // the three deltas, then the terminal events.
    let replay = read_run_events(&app, &run_id).await;
    assert_eq!(replay.matches("event: run.started").count(), 1);
    assert_eq!(replay.matches("event: model.delta").count(), 3);
    assert_eq!(replay.matches("event: run.completed").count(), 1);
    let event_lines = replay
        .lines()
        .filter(|line| line.starts_with("event: "))
        .collect::<Vec<_>>();
    assert_eq!(event_lines.first(), Some(&"event: run.started"));
    assert_eq!(
        event_lines.last(),
        Some(&"event: run.completed"),
        "the replayed terminal must stay last, got: {replay}"
    );
    fixture.join().expect("fixture thread");
}

/// A9: closing the storage worker while a run is mid-flight must not hang
/// or leak: delivery drops the unpersistable event (observable), the run
/// parks as terminal_pending, the bounded retry fails fast and expires,
/// the handle is released via its TTL, no terminal is fabricated, and
/// restart recovery repairs the durable side exactly once.
#[tokio::test]
async fn storage_worker_shutdown_mid_run_parks_terminal_and_restart_recovers() {
    let (port, arrived, release, fixture) = spawn_holding_fixture();
    let http = rustscript_vm::HttpConfig {
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_schemes: vec!["http".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
    let path = gateway_db_path("worker-closure");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig {
            janitor_interval: std::time::Duration::from_millis(50),
            terminal_commit_retry_window: std::time::Duration::from_millis(300),
            terminal_run_ttl: std::time::Duration::from_millis(500),
            http,
            ..AgentGatewayConfig::default()
        },
        format!(
            r#"
            use http;
            use stream;
            pub fn run(input: map) -> string {{
                stream::emit({{"type": "model.delta", "delta": "e1"}});
                http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
                stream::emit({{"type": "model.delta", "delta": "e2"}});
                "done";
            }}
            "#
        ),
        &path,
    )
    .expect("SQLite state should open");
    let metrics = state.metrics();
    let service = state.service();
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "closure"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    // The script emitted e1 and is parked inside the HTTP call.
    arrived.await.expect("the run must reach the fixture");

    // Close the storage worker while the run is live (deterministic
    // closure; every later command fails fast with a typed error).
    persistence.shutdown();
    release.send(()).expect("release the fixture");

    // e2 cannot be appended durably and the terminal cannot be persisted:
    // the run parks as terminal_pending (never a false terminal).
    let parked = wait_until(std::time::Duration::from_secs(10), || {
        service.pending_terminal_count() == 1
    })
    .await;
    assert!(
        parked,
        "the run must enter the terminal-pending retry state"
    );
    assert_eq!(
        metrics.snapshot().runs_terminal_pending,
        1,
        "the pending gauge must match the pending map"
    );
    assert!(
        metrics.snapshot().events_dropped >= 1,
        "the unpersistable event must be counted as dropped"
    );
    assert!(
        metrics
            .snapshot()
            .storage_op_failures(StorageOp::EventAppend)
            >= 1,
        "the failed event append must be counted as a storage error"
    );
    assert_eq!(
        service.available_capacity(),
        AgentGatewayConfig::default().max_concurrent_runs,
        "a terminal-pending run must not hold the admission permit"
    );

    // The bounded retry fails fast against the closed worker and then
    // expires: the entry is dropped and the handle is released via its TTL.
    let released = wait_until(std::time::Duration::from_secs(10), || {
        service.handle_count() == 0
    })
    .await;
    assert!(released, "the handle must be released via its TTL");
    assert_eq!(
        service.pending_terminal_count(),
        0,
        "the expired retry must stop"
    );
    assert!(
        metrics
            .snapshot()
            .terminal_retries_by(TerminalRetryOutcome::RetryFailed)
            >= 1,
        "the closed-worker retries must be observable"
    );

    // No terminal was ever published by the old service.
    let text = read_run_events(&app, &run_id).await;
    assert!(
        !text.contains("event: run.completed")
            && !text.contains("event: run.cancelled")
            && !text.contains("event: run.failed"),
        "no fabricated terminal may be published, got: {text}"
    );

    // Restart recovery repairs the durable side exactly once.
    drop(app);
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reload and recover");
    let restored_app = build_agent_gateway_app(restored);
    let text = read_run_events(&restored_app, &run_id).await;
    assert_eq!(
        text.matches("event: run.failed").count(),
        1,
        "restart recovery must fail the interrupted run exactly once, got: {text}"
    );
    fixture.join().expect("fixture thread");
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn telegram_storage_ops_classify_precisely_and_never_collapse_to_unknown() {
    // A8's Telegram adapter drives delivery.get/advance/set and session.get
    // through the shared storage worker; every one of those commands must
    // classify as its typed storage op, never as `unknown`.
    let path = gateway_db_path("telegram-storage-ops");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let metrics = state.metrics();
    let persistence = state.persistence().expect("persistence handle");

    // One real session so the raw delivery cursor commands succeed (the
    // cursor table has a foreign key to sessions).
    persistence
        .session_create(&json!({
            "id": "telegram-session",
            "profile": "telegram",
            "platform": "telegram",
            "account_id": "telegram",
            "chat_id": "",
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
            "now_ms": 1_000,
        }))
        .expect("session create should commit");
    // session.get / delivery.get / delivery.set are raw commands: they
    // count as successes under their typed ops.
    persistence
        .session_get("telegram-session")
        .expect("raw session read must succeed");
    persistence
        .delivery_get("telegram-session", "telegram:offset")
        .expect("raw cursor read must succeed");
    persistence
        .delivery_set("telegram-session", "telegram:offset", 7)
        .expect("raw cursor upsert must succeed");
    // A delivery.set for an unknown session violates the cursor foreign key
    // — a typed storage failure still classified as delivery.set.
    assert!(
        persistence
            .delivery_set("missing-session", "telegram:offset", 7)
            .is_err(),
        "delivery.set on an unknown session must fail the foreign key guard"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.storage_op_successes(StorageOp::SessionGet), 1);
    assert_eq!(snapshot.storage_op_successes(StorageOp::DeliveryGet), 1);
    assert_eq!(snapshot.storage_op_successes(StorageOp::DeliverySet), 1);
    assert_eq!(snapshot.storage_op_failures(StorageOp::DeliverySet), 1);
    assert_eq!(
        snapshot.storage_op_failures(StorageOp::Unknown),
        0,
        "no telegram storage op may collapse to unknown"
    );

    // Storage failures (worker unavailable) classify under their typed ops
    // — the registry's error counters are the source of truth for
    // at-least-once delivery advance failures.
    persistence.shutdown();
    assert!(
        persistence
            .delivery_advance("missing-session", "telegram:offset", 5)
            .is_err(),
        "commands after shutdown must fail fast"
    );
    assert!(
        persistence.session_get("missing-session").is_err(),
        "commands after shutdown must fail fast"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.storage_op_failures(StorageOp::DeliveryAdvance), 1);
    assert_eq!(snapshot.storage_op_failures(StorageOp::SessionGet), 1);
    assert_eq!(
        snapshot.storage_op_failures(StorageOp::Unknown),
        0,
        "a shutdown delivery/session command must still classify as its typed op"
    );

    drop(state);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn halt_gates_admission_and_shutdown_makes_commands_fail_fast() {
    // SIGINT ordering (A7+A8): admission is closed first with a typed
    // rejection, then active runs are cancelled, then the storage worker is
    // shut down deterministically — later commands fail fast instead of
    // hanging, and nothing leaks a second chance to start work.
    let path = gateway_db_path("halt-shutdown");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let service = state.service();
    let persistence = state.persistence().expect("persistence handle");

    // Admission is open before the halt.
    let first = service
        .admit(AdmitRunRequest {
            input: json!({"text": "hi"}),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "api_server".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
        })
        .await
        .expect("admission must be open before the halt");
    assert_eq!(first.status, "started");

    // stop_admission closes the gate with the typed Halting rejection and
    // never touches active runs.
    service.stop_admission();
    let rejected = service
        .admit(AdmitRunRequest {
            input: json!({"text": "later"}),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "api_server".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
        })
        .await;
    assert!(
        matches!(rejected, Err(AdmitError::Halting)),
        "admission after stop_admission must answer the typed Halting rejection, got {rejected:?}"
    );
    assert_eq!(
        state
            .metrics()
            .snapshot()
            .admissions_rejected_by(rustscript_agent::metrics::AdmitRejectReason::Halting),
        1,
        "the halting rejection must be observable in the bounded metrics"
    );

    // The HTTP surface answers 503 gateway_halting for new runs.
    let app = build_agent_gateway_app(state.clone());
    let (status, body) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "x"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "gateway_halting");

    // halt() is idempotent with stop_admission and cancels active runs.
    service.halt();
    service.halt();

    // Deterministic storage shutdown: every later command fails fast with a
    // typed error instead of hanging; shutdown is idempotent.
    persistence.shutdown();
    persistence.shutdown();
    let error = persistence
        .session_get("whatever")
        .expect_err("commands after shutdown must fail fast");
    assert_eq!(error.code, "storage_unavailable");

    drop(state);
    let _ = std::fs::remove_file(&path);
}

/// P3 (production path): restart recovery fails EVERY pending compaction,
/// including one whose run is already terminal when the gateway reopens
/// (the crash window between the run terminal commit and
/// `compaction.fail`), so no session is ever stuck with an orphaned
/// pending row.
#[tokio::test]
async fn gateway_reopen_fails_orphan_pending_compaction_even_when_run_is_terminal() {
    let path = gateway_db_path("compaction-orphan-crash-window");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    let now = 2_000_000u64;
    persistence
        .admission_create(&json!({
            "session_id": "orphan-session",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "orphan-session",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "orphan-run",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "orphan-message",
            "message_run_id": "orphan-run",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "orphan-run",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "orphan-event",
            "now_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("admission should commit");
    for (message_id, content) in [
        ("orphan-message-2", r#"[{"type":"text","text":"more"}]"#),
        ("orphan-message-3", r#"[{"type":"text","text":"done"}]"#),
    ] {
        persistence
            .message_append(&json!({
                "id": message_id,
                "session_id": "orphan-session",
                "role": "user",
                "content_json": content,
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 1,
                "metadata_json": "{}",
                "run_id": "",
                "finish_reason": "",
                "now_ms": now + 1,
            }))
            .expect("message should append");
    }
    persistence
        .run_transition(&json!({
            "run_id": "orphan-run",
            "from_status": "running",
            "to_status": "compacting",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now + 3,
        }))
        .expect("run should transition to compacting");
    persistence
        .compaction_start(&json!({
            "id": "orphan-compaction",
            "session_id": "orphan-session",
            "run_id": "orphan-run",
            "generation": 2,
            "source_start_ordinal": 1,
            "source_end_ordinal": 3,
            "retained_tail_ordinal": 3,
            "summary_json": "{\"summary\":\"compacted\"}",
            "token_estimate": 10,
            "model": "m",
            "now_ms": now + 4,
        }))
        .expect("compaction should start");
    // The run leaves compacting with a terminal transition BEFORE any
    // compaction.fail is committed — the crash window.
    persistence
        .run_transition(&json!({
            "run_id": "orphan-run",
            "from_status": "compacting",
            "to_status": "failed",
            "error_code": "gateway_restart",
            "error_message": "",
            "recovery_reason": "gateway_restart",
            "now_ms": now + 5,
        }))
        .expect("run should transition to failed");
    drop(state);

    // Production reopen: the restart load path fails the orphaned pending
    // compaction even though its run is already terminal (no run is
    // recovered).
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reopen");
    let restored_persistence = restored
        .persistence()
        .expect("persistence handle should be exposed");
    let recovered = restored_persistence
        .compaction_get("orphan-compaction")
        .expect("compaction after reopen");
    let row = recovered["rows"][0].clone();
    assert_eq!(row[10], json!("failed"));
    assert_eq!(
        row[11],
        json!("run interrupted during gateway restart"),
        "the typed recovery failure reason must be recorded"
    );
    let run = restored_persistence
        .run_get("orphan-run")
        .expect("run after reopen");
    assert_eq!(
        run["rows"][0][3],
        json!("failed"),
        "the terminal run must stay terminal"
    );
    drop(restored);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn gateway_reopen_expires_orphan_pending_approval_even_when_run_is_terminal() {
    // A pending approval whose run is ALREADY terminal at restart is by
    // definition an orphan: the park sequence never runs after a terminal
    // commit, so such a row can only be a leftover of the crash window (or
    // of the P2 deadline race where the blocking approval.request outlived
    // the run deadline). The restart recovery must expire it durably —
    // never leave it pending until the approval_timeout sweep.
    let path = gateway_db_path("approval-orphan-crash-window");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should open");
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    let now = 2_000_000u64;
    persistence
        .admission_create(&json!({
            "session_id": "orphan-approval-session",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "orphan-approval-session",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "orphan-approval-run",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "orphan-approval-message",
            "message_run_id": "orphan-approval-run",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "orphan-approval-run",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "orphan-approval-event",
            "now_ms": now,
            "expires_at_ms": 0,
        }))
        .expect("admission should commit");
    // The durable pending approval commits while the run is still running
    // (the deadline race: the request's insert wins the lock race).
    persistence
        .approval_request(&json!({
            "id": "orphan-approval",
            "run_id": "orphan-approval-run",
            "session_id": "orphan-approval-session",
            "tool_call_id": "call-1",
            "tool_name": "file.write",
            "arguments_json": "{}",
            "risk_class": "write",
            "decision_scope": "",
            "one_time": 1,
            "requested_at_ms": now + 1,
            "expires_at_ms": now + 600_000,
        }))
        .expect("approval should persist");
    // The run reaches its terminal BEFORE the compensation can cancel the
    // row (the crash window: the gateway dies between the insert and the
    // cancel).
    persistence
        .run_transition(&json!({
            "run_id": "orphan-approval-run",
            "from_status": "running",
            "to_status": "cancelled",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now + 2,
        }))
        .expect("run should transition to cancelled");
    drop(state);

    // Production reopen: the restart load path expires the orphaned pending
    // approval even though its run is already terminal (no run is
    // recovered).
    let restored = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &path)
        .expect("SQLite state should reopen");
    let restored_persistence = restored
        .persistence()
        .expect("persistence handle should be exposed");
    let approval = restored_persistence
        .approval_get("orphan-approval")
        .expect("approval after reopen");
    let row = approval["rows"][0].clone();
    assert_eq!(
        row[7],
        json!("expired"),
        "an orphaned pending approval on a terminal run must be expired by restart recovery"
    );
    let run = restored_persistence
        .run_get("orphan-approval-run")
        .expect("run after reopen");
    assert_eq!(
        run["rows"][0][3],
        json!("cancelled"),
        "the terminal run must stay terminal"
    );
    drop(restored);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn combined_guards_gauge_lag_disconnect_and_replay_agree_exactly() {
    // A7 service guard + A9 metrics guard coexist on every SSE stream: the
    // subscriber gauge tracks the exact live-stream count across
    // multi-subscriber attach/drop, a lagging stream emits the typed error
    // and releases its gauge slot, the last-subscriber disconnect cancels
    // the run (typed client_disconnect), and a reconnect replays the exact
    // terminal. No drift between the two guards on any path.
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            client_disconnect_policy: ClientDisconnectPolicy::CancelOnDisconnect,
            sse_keepalive_interval: Duration::from_millis(100),
            broadcast_capacity: 2,
            ..AgentGatewayConfig::default()
        },
        include_str!("fixtures/gateway/cpu_loop.rss"),
    )
    .expect("RSS source should compile");
    let metrics = state.metrics();
    let server = spawn_gateway_server(state).await;

    // --- Run 1: multi-subscriber, disconnect, gauge, cancel, replay ---
    let (status, _, run) = raw_json(
        server.addr,
        "POST",
        "/v1/runs",
        json!({"input": "spin"}),
        &[],
    )
    .await;
    assert_eq!(status, 202);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    let sse_path = format!("/v1/runs/{run_id}/events");

    let mut first = RawHttp::connect(server.addr).await;
    let (status, _) = first
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    let mut second = RawHttp::connect(server.addr).await;
    let (status, _) = second
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    let subscribed = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 2
    })
    .await;
    assert!(
        subscribed,
        "two open SSE streams must be counted by the gauge"
    );

    // One subscriber disconnects while the other remains: no cancellation
    // (cancel-on-disconnect only fires for the LAST subscriber) and the
    // gauge drops to exactly 1.
    drop(first);
    let released = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 1
    })
    .await;
    assert!(released, "the dropped stream must release its gauge slot");
    // The run must stay active while one subscriber remains (the helper
    // itself asserts the observed count).
    wait_for_active_agents(server.addr, 1, Duration::from_secs(2)).await;

    // The last subscriber disconnects while the run is active: the service
    // guard cancels the run with the typed reason; the metrics guard drops
    // the gauge to exactly 0.
    drop(second);
    let drained = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 0
    })
    .await;
    assert!(drained, "the last dropped stream must release the gauge");
    wait_for_active_agents(server.addr, 0, Duration::from_secs(5)).await;

    // Terminal replay: exactly one run.cancelled with the typed
    // client_disconnect reason and the full replayed history.
    let mut replay = RawHttp::connect(server.addr).await;
    let (status, _) = replay
        .open(&http_head(
            "GET",
            &sse_path,
            None,
            &[("accept", "text/event-stream")],
        ))
        .await;
    assert_eq!(status, 200);
    assert!(
        replay
            .read_until("event: run.cancelled", Duration::from_secs(5))
            .await,
        "the persisted cancellation must replay"
    );
    replay.drain_sse(Duration::from_secs(2)).await;
    let text = replay.sse_text();
    assert_eq!(text.matches("event: run.cancelled").count(), 1);
    assert!(
        text.contains("client_disconnect"),
        "the replayed terminal must carry the typed reason, got: {text}"
    );
    assert!(
        text.contains("event: run.started"),
        "full history must replay"
    );

    // --- Run 2: a lagging stream emits the typed error, releases its
    // gauge slot, and the registry counts the lag. The subscriber body is
    // held unread (router oneshot), so the bounded broadcast channel fills
    // deterministically before the stream is polled.
    let (port, arrived, release, fixture) = spawn_holding_fixture();
    let http = rustscript_vm::HttpConfig {
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_schemes: vec!["http".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            client_disconnect_policy: ClientDisconnectPolicy::CancelOnDisconnect,
            sse_keepalive_interval: Duration::from_millis(100),
            broadcast_capacity: 2,
            http,
            ..AgentGatewayConfig::default()
        },
        format!(
            r#"
            use http;
            use stream;
            pub fn run(input: map) -> string {{
                http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
                stream::emit({{"type": "model.delta", "delta": "a"}});
                stream::emit({{"type": "model.delta", "delta": "b"}});
                stream::emit({{"type": "model.delta", "delta": "c"}});
                "done";
            }}
            "#
        ),
    )
    .expect("RSS source should compile");
    let metrics = state.metrics();
    let app = build_agent_gateway_app(state.clone());
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "lag"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    arrived.await.expect("the run must reach the fixture");

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
        .await;
    let response = response.expect("SSE route should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let counted = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 1
    })
    .await;
    assert!(counted, "the lagging stream must be counted by the gauge");

    // Release the script: five broadcasts into a capacity-2 channel while
    // the subscriber is not reading — a deterministic lag.
    release.send(()).expect("release the fixture");
    let terminal = wait_until(std::time::Duration::from_secs(10), || {
        metrics.snapshot().active_runs == 0
    })
    .await;
    assert!(terminal, "the run must reach its terminal");
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    let text = String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8");
    assert!(
        text.contains("event_lagged"),
        "the lagging subscriber must observe the typed lagged error, got: {text}"
    );
    let released = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 0
    })
    .await;
    assert!(
        released,
        "the lagged stream must release its gauge slot exactly once"
    );
    assert!(
        metrics.snapshot().events_lagged >= 3,
        "the registry must count the dropped broadcasts"
    );
    fixture.join().expect("fixture thread");
}

#[tokio::test]
async fn legacy_run_context_carries_the_inbound_platform() {
    let db = gateway_db_path("legacy-platform");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { let platform: string = input[\"platform\"]; platform; }",
        &db,
    )
    .expect("RSS source should compile");
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("ping"),
            session_id: None,
            model: None,
            provider: None,
            parent_run_id: None,
            instructions: None,
            platform: "telegram".to_string(),
            idempotency_key: None,
            idempotency_hash: None,
            origin_actor: None,
        })
        .await
        .expect("admission should succeed");
    tokio::spawn(
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ping".to_string()),
    );
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(15) {
        if let Some(handle) = service.handle(&admitted.run_id)
            && handle.is_terminal()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .event_replay(&json!({
            "run_id": admitted.run_id,
            "after_seq": 1,
            "max_events": 64,
            "max_bytes": 65536,
        }))
        .expect("event replay");
    let mut terminal_content = None;
    if let Some(rows) = data.get("rows").and_then(Value::as_array) {
        for row in rows {
            if let Some(row) = row.as_array()
                && row.get(3).and_then(Value::as_str) == Some("run.completed")
            {
                terminal_content = row.get(4).and_then(Value::as_str).and_then(|text| {
                    serde_json::from_str::<Value>(text)
                        .ok()
                        .and_then(|payload| {
                            payload["output"]["message"]["content"]
                                .as_str()
                                .map(String::from)
                        })
                });
            }
        }
    }
    let content = terminal_content.unwrap_or_default();
    assert_eq!(
        content.trim_matches('"'),
        "telegram",
        "the legacy run context must carry the inbound platform (the legacy \
         path persists the JSON-encoded output text)"
    );
}
