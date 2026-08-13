//! A9 observability: the bounded metrics registry, Prometheus text rendering,
//! gauge parity with `/health/detailed`, and auth parity for `/metrics`.
//!
//! Every label must come from a finite enum; no run/session/token/model
//! original value may ever appear as a label. The metrics scrape must never
//! block on the store.

use std::sync::{Arc, Mutex};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rustscript_agent::metrics::{
    AdmitRejectReason, Metrics, StorageOp, TerminalRetryOutcome, TerminalStatus,
};
use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app,
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

async fn json_request_with_headers(
    app: &axum::Router,
    method: axum::http::Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        String::from_utf8(body.to_vec()).expect("response should be UTF-8"),
    )
}

async fn wait_until(timeout: std::time::Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// Every label value the registry may emit, across all label names.
fn bounded_label_values() -> Vec<&'static str> {
    let mut values = vec![
        "accepted", "rejected", "ok", "error", "+Inf", "0.001", "0.01", "0.1", "0.5", "1", "5",
        "15", "60", "300", "900",
    ];
    values.extend(AdmitRejectReason::ALL.iter().map(|reason| reason.label()));
    values.extend(TerminalStatus::ALL.iter().map(|status| status.label()));
    values.extend(
        TerminalRetryOutcome::ALL
            .iter()
            .map(|outcome| outcome.label()),
    );
    values.extend(StorageOp::ALL.iter().map(|op| op.label()));
    values
}

/// Parses every `{...}` label block from rendered Prometheus text.
fn label_blocks(render: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    for line in render.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some(open) = line.find('{') else {
            continue;
        };
        let Some(close) = line[open..].find('}') else {
            continue;
        };
        blocks.push(line[open + 1..open + close].to_string());
    }
    blocks
}

#[test]
fn registry_tracks_every_metric_and_renders_exact_prometheus_text() {
    let metrics = Metrics::default();
    metrics.admission_accepted();
    metrics.admission_accepted();
    metrics.admission_rejected(AdmitRejectReason::RunLimitReached);
    metrics.admission_rejected(AdmitRejectReason::IdempotencyConflict);
    metrics.active_runs_inc();
    metrics.active_runs_inc();
    metrics.active_runs_inc();
    metrics.active_runs_dec();
    metrics.runs_terminal_pending_inc();
    metrics.runs_terminal_pending_dec();
    metrics.runs_terminal(TerminalStatus::Completed);
    metrics.runs_terminal(TerminalStatus::Completed);
    metrics.runs_terminal(TerminalStatus::Failed);
    metrics.events_emitted();
    metrics.events_emitted();
    metrics.events_emitted();
    metrics.events_emitted();
    metrics.events_emitted();
    metrics.events_dropped();
    metrics.events_lagged(3);
    metrics.storage_op(StorageOp::EventAppend, true);
    metrics.storage_op(StorageOp::EventAppend, false);
    metrics.storage_op(StorageOp::Unknown, true);
    metrics.terminal_retry(TerminalRetryOutcome::Committed);
    metrics.terminal_retry(TerminalRetryOutcome::RetryFailed);
    metrics.terminal_persist_backoff();
    metrics.sse_subscriber_inc();
    metrics.sse_subscriber_inc();
    metrics.sse_subscriber_dec();
    metrics.record_run_duration(0.05);
    metrics.record_run_duration(2.5);
    metrics.record_run_duration(500.0);
    metrics.record_run_duration(0.001);
    metrics.record_run_duration(10_000.0);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.admissions_accepted, 2);
    assert_eq!(
        snapshot.admissions_rejected_by(AdmitRejectReason::RunLimitReached),
        1
    );
    assert_eq!(
        snapshot.admissions_rejected_by(AdmitRejectReason::IdempotencyConflict),
        1
    );
    assert_eq!(
        snapshot.admissions_rejected_by(AdmitRejectReason::ParentNotFound),
        0
    );
    assert_eq!(snapshot.active_runs, 2);
    assert_eq!(snapshot.runs_terminal_pending, 0);
    assert_eq!(snapshot.runs_terminal_by(TerminalStatus::Completed), 2);
    assert_eq!(snapshot.runs_terminal_by(TerminalStatus::Failed), 1);
    assert_eq!(snapshot.runs_terminal_by(TerminalStatus::Cancelled), 0);
    assert_eq!(snapshot.events_emitted, 5);
    assert_eq!(snapshot.events_dropped, 1);
    assert_eq!(snapshot.events_lagged, 3);
    assert_eq!(snapshot.storage_op_successes(StorageOp::EventAppend), 1);
    assert_eq!(snapshot.storage_op_failures(StorageOp::EventAppend), 1);
    assert_eq!(snapshot.storage_op_successes(StorageOp::Unknown), 1);
    assert_eq!(
        snapshot.terminal_retries_by(TerminalRetryOutcome::Committed),
        1
    );
    assert_eq!(
        snapshot.terminal_retries_by(TerminalRetryOutcome::RetryFailed),
        1
    );
    assert_eq!(snapshot.terminal_persist_backoffs, 1);
    assert_eq!(snapshot.sse_subscribers, 1);

    // Fixed histogram buckets: [0.001, 0.01, 0.1, 0.5, 1, 5, 15, 60, 300, 900, +Inf].
    // The snapshot keeps raw per-bucket counts; rendering accumulates them.
    assert_eq!(snapshot.run_duration.count, 5);
    assert_eq!(snapshot.run_duration.sum_micros, 10_502_551_000);
    assert_eq!(
        snapshot.run_duration.buckets,
        [1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1],
        "each duration lands in exactly one fixed bucket"
    );

    let render = metrics.render_prometheus();
    assert!(render.contains("# TYPE agent_admissions_total counter"));
    assert!(render.contains("agent_admissions_total{outcome=\"accepted\"} 2"));
    assert!(render.contains(
        "agent_admissions_total{outcome=\"rejected\",reason=\"idempotency_conflict\"} 1"
    ));
    assert!(
        render.contains(
            "agent_admissions_total{outcome=\"rejected\",reason=\"run_limit_reached\"} 1"
        )
    );
    assert!(render.contains("agent_active_runs 2"));
    assert!(render.contains("agent_runs_terminal_total{status=\"completed\"} 2"));
    assert!(render.contains("agent_events_lagged_total 3"));
    assert!(render.contains("agent_storage_ops_total{op=\"event.append\",outcome=\"error\"} 1"));
    assert!(render.contains("agent_terminal_retries_total{outcome=\"retry_failed\"} 1"));
    assert!(render.contains("agent_sse_subscribers 1"));
    assert!(render.contains("agent_run_duration_seconds_bucket{le=\"0.001\"} 1"));
    assert!(render.contains("agent_run_duration_seconds_bucket{le=\"+Inf\"} 5"));
    assert!(render.contains("agent_run_duration_seconds_sum 10502.551"));
    assert!(render.contains("agent_run_duration_seconds_count 5"));

    // Bounded labels: every label value in the rendered text belongs to the
    // finite constant sets; no run/session/token/model value can appear.
    let allowed = bounded_label_values();
    for block in label_blocks(&render) {
        for assignment in block.split(',') {
            let Some((name, value)) = assignment.split_once('=') else {
                panic!("malformed label assignment: {assignment:?}");
            };
            assert!(
                ["outcome", "reason", "status", "op", "le"].contains(&name),
                "unexpected label name {name:?} in {assignment:?}"
            );
            let value = value.trim_matches('"');
            assert!(
                allowed.contains(&value),
                "label value {value:?} is not from the bounded constant sets"
            );
        }
    }
}

#[test]
fn storage_op_label_mapping_is_a_finite_closed_set() {
    let known = [
        ("admission.create", StorageOp::AdmissionCreate),
        ("session.create", StorageOp::SessionCreate),
        ("session.touch", StorageOp::SessionTouch),
        ("session.delete", StorageOp::SessionDelete),
        ("message.append", StorageOp::MessageAppend),
        ("event.append", StorageOp::EventAppend),
        ("run.terminal", StorageOp::RunTerminal),
        ("run.transition", StorageOp::RunTransition),
        ("run.get", StorageOp::RunGet),
        ("event.replay", StorageOp::EventReplay),
        ("job.create", StorageOp::JobCreate),
        ("job.update", StorageOp::JobUpdate),
        ("job.delete", StorageOp::JobDelete),
        ("approval.request", StorageOp::ApprovalRequest),
        ("approval.get", StorageOp::ApprovalGet),
        ("approval.resolve", StorageOp::ApprovalResolve),
        ("approval.expire", StorageOp::ApprovalExpire),
        ("compaction.start", StorageOp::CompactionStart),
        ("compaction.get", StorageOp::CompactionGet),
        ("compaction.latest", StorageOp::CompactionLatest),
        ("compaction.commit", StorageOp::CompactionCommit),
        ("compaction.fail", StorageOp::CompactionFail),
        ("migrate", StorageOp::Migrate),
        ("recovery.recover_active", StorageOp::RecoveryRecoverActive),
        ("load.all", StorageOp::LoadAll),
    ];
    for (command, expected) in known {
        assert_eq!(
            StorageOp::from_command(command),
            expected,
            "{command} must map to its typed storage op"
        );
        assert_eq!(expected.label(), command, "labels must round-trip");
    }
    assert_eq!(StorageOp::from_command("unknown.op"), StorageOp::Unknown);
    for op in StorageOp::ALL {
        assert_eq!(
            StorageOp::from_command(op.label()),
            op,
            "every declared op must map back to itself"
        );
    }
}

#[test]
fn histogram_records_edge_durations_into_the_fixed_buckets() {
    let metrics = Metrics::default();
    metrics.record_run_duration(0.0001);
    metrics.record_run_duration(0.001);
    metrics.record_run_duration(10_000.0);
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.run_duration.buckets[0], 2,
        "below/at 0.001 lands in the first bucket"
    );
    assert_eq!(
        snapshot.run_duration.buckets[10], 1,
        "values above the largest bound land in the +Inf bucket"
    );
    assert_eq!(snapshot.run_duration.count, 3);
    assert!(
        metrics
            .render_prometheus()
            .contains("agent_run_duration_seconds_bucket{le=\"+Inf\"} 3"),
        "rendered buckets accumulate to the total count"
    );
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
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
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
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .expect("write fixture response");
    });
    (port, arrived_rx, release_tx, handle)
}

/// The source used by admission/hold scenarios: an HTTP call parks the run
/// deterministically until the fixture is released.
fn holding_source(port: u16) -> String {
    format!(
        r#"
        use http;
        pub fn run(input: map) -> string {{
            http::client::request({{ method: "GET", url: "http://127.0.0.1:{port}/" }});
            "done";
        }}
        "#
    )
}

/// Accepts two HTTP requests and holds both responses until the test
/// releases them, so two concurrent runs can be parked deterministically.
fn spawn_holding_fixture_pair() -> (
    u16,
    [tokio::sync::oneshot::Receiver<()>; 2],
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel();
    let (arrived_tx_2, arrived_rx_2) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().expect("accept first fixture request");
        let _ = arrived_tx.send(());
        let (mut second, _) = listener.accept().expect("accept second fixture request");
        let _ = arrived_tx_2.send(());
        release_rx.recv().expect("wait for release");
        for stream in [&mut first, &mut second] {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .expect("write fixture response");
        }
    });
    (port, [arrived_rx, arrived_rx_2], release_tx, handle)
}

fn http_config(port: u16) -> rustscript_vm::HttpConfig {
    rustscript_vm::HttpConfig {
        allowed_schemes: vec!["http".to_string()],
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_ports: vec![port],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    }
}

/// Issues one SSE request and returns the response without reading the body,
/// so the subscriber gauge stays live until the test drops the response.
async fn sse_response(app: &axum::Router, run_id: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::GET)
                .uri(format!("/v1/runs/{run_id}/events"))
                .body(Body::empty())
                .expect("SSE request should build"),
        )
        .await
        .expect("SSE route should respond")
}

/// Reads one run's full SSE body.
async fn read_run_events(app: &axum::Router, run_id: &str) -> String {
    let response = sse_response(app, run_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8")
}

#[tokio::test]
async fn admission_accepted_and_typed_rejections_are_counted() {
    let (port, arrived, release, fixture) = spawn_holding_fixture_pair();
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            max_concurrent_runs: 2,
            http: http_config(port),
            ..AgentGatewayConfig::default()
        },
        holding_source(port),
    )
    .expect("RSS source should compile");
    let metrics = state.metrics();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request_with_headers(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "keyed"}),
        &[("idempotency-key", "admission-K")],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let first_run = serde_json::from_str::<Value>(&run).expect("run json");

    // Same key, different body: typed idempotency conflict.
    let (status, _) = json_request_with_headers(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "different-body"}),
        &[("idempotency-key", "admission-K")],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "orphan", "parent_run_id": "missing-parent"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "ghost", "session_id": "missing-session"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, second) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "second"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(second["run_id"].is_string());

    // Capacity 2 is exhausted by the two held runs.
    let (status, _) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "third"}),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Both runs must actually be parked on the fixture before asserting the
    // active gauge (deterministic barrier, no sleeps).
    for arrived in arrived {
        arrived.await.expect("both runs must reach the fixture");
    }
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.admissions_accepted, 2);
    assert_eq!(
        snapshot.admissions_rejected_by(AdmitRejectReason::IdempotencyConflict),
        1
    );
    assert_eq!(
        snapshot.admissions_rejected_by(AdmitRejectReason::ParentNotFound),
        1
    );
    assert_eq!(
        snapshot.admissions_rejected_by(AdmitRejectReason::SessionNotFound),
        1
    );
    assert_eq!(
        snapshot.admissions_rejected_by(AdmitRejectReason::RunLimitReached),
        1
    );
    assert_eq!(snapshot.active_runs, 2);

    release.send(()).expect("release the fixture");
    fixture.join().expect("fixture thread");
    let run_id = first_run["run_id"].as_str().expect("run id").to_string();
    let _ = run_id;
}

#[tokio::test]
async fn health_detailed_and_metrics_share_one_gauge_snapshot() {
    let (port, arrived, release, fixture) = spawn_holding_fixture_pair();
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            max_concurrent_runs: 2,
            http: http_config(port),
            ..AgentGatewayConfig::default()
        },
        holding_source(port),
    )
    .expect("RSS source should compile");
    let metrics = state.metrics();
    let app = build_agent_gateway_app(state);

    let (status, first) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "one"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, second) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "two"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    for arrived in arrived {
        arrived.await.expect("both runs must reach the fixture");
    }

    // While both runs are active, health and the registry report the same
    // gauge value (one source of truth).
    let (health_status, health) = json_request(
        &app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
    )
    .await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health["active_agents"], 2);
    assert_eq!(health["terminal_pending"], 0);
    assert_eq!(metrics.snapshot().active_runs, 2);
    assert!(metrics.render_prometheus().contains("agent_active_runs 2"));

    // Stop both runs; each commits exactly one cancelled terminal.
    for run in [&first, &second] {
        let run_id = run["run_id"].as_str().expect("run id");
        let (stop_status, stop) = json_request(
            &app,
            axum::http::Method::POST,
            &format!("/v1/runs/{run_id}/stop"),
            Value::Null,
        )
        .await;
        assert_eq!(stop_status, StatusCode::OK);
        assert_eq!(stop["status"], "stopping");
    }
    release.send(()).expect("release the fixture");
    fixture.join().expect("fixture thread");
    let finished = wait_until(std::time::Duration::from_secs(10), || {
        metrics.snapshot().active_runs == 0
    })
    .await;
    assert!(finished, "both runs must commit their terminals");

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.runs_terminal_by(TerminalStatus::Cancelled), 2);
    assert_eq!(snapshot.runs_terminal_by(TerminalStatus::Completed), 0);
    let (health_status, health) = json_request(
        &app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
    )
    .await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health["active_agents"], 0);
    assert_eq!(health["terminal_pending"], 0);
    assert!(
        metrics
            .render_prometheus()
            .contains("agent_runs_terminal_total{status=\"cancelled\"} 2")
    );
}

#[tokio::test]
async fn runs_terminal_by_status_and_run_duration_histogram() {
    // Completed run.
    let completed_state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"done\"; }",
    )
    .expect("RSS source should compile");
    let completed_metrics = completed_state.metrics();
    let completed_app = build_agent_gateway_app(completed_state);
    let (status, run) = json_request(
        &completed_app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "complete"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    let text = read_run_events(&completed_app, &run_id).await;
    assert_eq!(text.matches("event: run.completed").count(), 1);
    // The SSE body completes at publish time, inside the terminal commit;
    // the gauge/histogram release happens a scheduling step later. Wait for
    // the observable terminal (bounded polling, not a fixed sleep).
    let finished = wait_until(std::time::Duration::from_secs(5), || {
        completed_metrics.snapshot().active_runs == 0
    })
    .await;
    assert!(finished, "the completed run must release the active gauge");
    let snapshot = completed_metrics.snapshot();
    assert_eq!(snapshot.runs_terminal_by(TerminalStatus::Completed), 1);
    assert_eq!(snapshot.runs_terminal_by(TerminalStatus::Failed), 0);
    assert_eq!(snapshot.run_duration.count, 1);
    assert!(snapshot.run_duration.sum_micros > 0);

    // Failed run via a typed capability rejection.
    let failed_state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        r#"
        use http;
        pub fn run(input: map) -> map {
            http::client::request({ method: "GET", url: "http://127.0.0.1:1/" });
        }
        "#,
    )
    .expect("RSS source should compile");
    let failed_metrics = failed_state.metrics();
    let failed_app = build_agent_gateway_app(failed_state);
    let (status, run) = json_request(
        &failed_app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "fail"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    let text = read_run_events(&failed_app, &run_id).await;
    assert!(text.contains("event: run.failed"));
    let finished = wait_until(std::time::Duration::from_secs(5), || {
        failed_metrics.snapshot().active_runs == 0
    })
    .await;
    assert!(finished, "the failed run must release the active gauge");
    assert_eq!(
        failed_metrics
            .snapshot()
            .runs_terminal_by(TerminalStatus::Failed),
        1
    );
}

#[tokio::test]
async fn events_emitted_and_dropped_are_counted() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit({"type": "model.delta", "delta": "ok-1"});
            stream::emit({"type": "model.delta", "delta": "ok-2"});
            stream::emit({"type": "not_a_canonical_event", "delta": "bad"});
            "done";
        }
        "#,
    )
    .expect("RSS source should compile");
    let metrics = state.metrics();
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "events"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    let text = read_run_events(&app, &run_id).await;
    assert_eq!(text.matches("event: model.delta").count(), 2);
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.events_emitted, 2,
        "valid events are counted as emitted"
    );
    assert_eq!(
        snapshot.events_dropped, 1,
        "schema violations are counted as dropped"
    );
}

#[tokio::test]
async fn sse_subscriber_gauge_tracks_live_streams() {
    let (port, arrived, release, fixture) = spawn_holding_fixture();
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            http: http_config(port),
            ..AgentGatewayConfig::default()
        },
        holding_source(port),
    )
    .expect("RSS source should compile");
    let metrics = state.metrics();
    let app = build_agent_gateway_app(state);
    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "sse"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    arrived.await.expect("the run must reach the fixture");

    let first = sse_response(&app, &run_id).await;
    assert_eq!(first.status(), StatusCode::OK);
    let subscribed = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 1
    })
    .await;
    assert!(subscribed, "one open SSE stream must be counted");

    let second = sse_response(&app, &run_id).await;
    assert_eq!(second.status(), StatusCode::OK);
    let subscribed = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 2
    })
    .await;
    assert!(subscribed, "a second open SSE stream must be counted");

    drop(first);
    drop(second);
    let released = wait_until(std::time::Duration::from_secs(5), || {
        metrics.snapshot().sse_subscribers == 0
    })
    .await;
    assert!(
        released,
        "dropped streams must release the subscriber gauge"
    );

    release.send(()).expect("release the fixture");
    fixture.join().expect("fixture thread");
}

#[tokio::test]
async fn metrics_requires_the_same_auth_as_health() {
    // With a bearer token configured, both endpoints reject anonymous
    // requests and accept the same token.
    let secured = AgentGatewayState::with_agent_source(
        AgentGatewayConfig {
            bearer_token: Some("metrics-secret".to_string()),
            ..AgentGatewayConfig::default()
        },
        "pub fn run(input: map) -> string { \"auth\"; }",
    )
    .expect("RSS source should compile");
    let secured_app = build_agent_gateway_app(secured);

    let (status, _) = json_request_with_headers(
        &secured_app,
        axum::http::Method::GET,
        "/metrics",
        Value::Null,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = json_request_with_headers(
        &secured_app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (metrics_status, metrics_body) = json_request_with_headers(
        &secured_app,
        axum::http::Method::GET,
        "/metrics",
        Value::Null,
        &[("authorization", "Bearer metrics-secret")],
    )
    .await;
    assert_eq!(metrics_status, StatusCode::OK);
    assert!(metrics_body.contains("agent_admissions_total"));
    assert!(metrics_body.contains("# TYPE agent_active_runs gauge"));
    let (health_status, health_body) = json_request_with_headers(
        &secured_app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
        &[("authorization", "Bearer metrics-secret")],
    )
    .await;
    assert_eq!(health_status, StatusCode::OK);
    assert!(health_body.contains("\"status\":\"ok\""));

    // Without a bearer token both endpoints are open, like every route.
    let open = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
    let open_app = build_agent_gateway_app(open);
    let (metrics_status, metrics_body) = json_request_with_headers(
        &open_app,
        axum::http::Method::GET,
        "/metrics",
        Value::Null,
        &[],
    )
    .await;
    assert_eq!(metrics_status, StatusCode::OK);
    assert!(metrics_body.contains("# TYPE agent_admissions_total counter"));
    let (health_status, _) = json_request_with_headers(
        &open_app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
        &[],
    )
    .await;
    assert_eq!(health_status, StatusCode::OK);
}

#[tokio::test(flavor = "current_thread")]
async fn metrics_scrape_does_not_block_on_the_store() {
    let path = gateway_db_path("metrics-scrape");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"scrape\"; }",
        &path,
    )
    .expect("SQLite state should open");
    let persistence = state
        .persistence()
        .expect("persistence handle should be exposed");
    // Seed enough state that a full reload takes a couple of seconds on the
    // dedicated storage worker (same mechanism as the storage-stall test).
    let mut now = 4_000_000u64;
    for index in 0..1500 {
        persistence
            .session_create(&json!({
                "id": format!("scrape-session-{index:04}"),
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
    let metrics = state.metrics();
    let app = build_agent_gateway_app(state);

    // A full reload on the app's own storage worker, on a blocking thread.
    let reload_persistence = persistence;
    let slow_reload = tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        reload_persistence.load().expect("reload should succeed");
        started.elapsed()
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // While the worker is busy, a session create blocks on the store write
    // lock; both scrape endpoints must still complete promptly because they
    // only read the atomic registry.
    let stall_app = app.clone();
    let mutation = tokio::spawn(async move {
        json_request(
            &stall_app,
            axum::http::Method::POST,
            "/api/sessions",
            json!({"source": "yahu"}),
        )
        .await
    });

    let metrics_scrape = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        json_request_with_headers(&app, axum::http::Method::GET, "/metrics", Value::Null, &[]),
    )
    .await;
    assert!(
        metrics_scrape.is_ok(),
        "the metrics scrape must not block on the store"
    );
    assert_eq!(metrics_scrape.expect("metrics response").0, StatusCode::OK);

    let health_scrape = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        json_request_with_headers(
            &app,
            axum::http::Method::GET,
            "/health/detailed",
            Value::Null,
            &[],
        ),
    )
    .await;
    assert!(
        health_scrape.is_ok(),
        "health must read the gauge snapshot, not the store"
    );
    let health_value: Value =
        serde_json::from_str(&health_scrape.expect("health response").1).expect("health json");
    assert_eq!(health_value["active_agents"], 0);

    let mutation_status = tokio::time::timeout(std::time::Duration::from_secs(60), mutation)
        .await
        .expect("the blocked mutation must finish once the worker drains")
        .expect("mutation task must not panic");
    assert_eq!(mutation_status.0, StatusCode::CREATED);
    let slow: std::time::Duration =
        tokio::time::timeout(std::time::Duration::from_secs(60), slow_reload)
            .await
            .expect("slow reload must finish")
            .expect("reload task must not panic");
    assert!(
        slow >= std::time::Duration::from_millis(300),
        "the seeded reload must actually occupy the worker for a while (took {slow:?})"
    );
    assert!(
        metrics.snapshot().storage_op_successes(StorageOp::LoadAll) >= 2,
        "construction and the reload both count load.all successes"
    );
    drop(app);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn storage_ops_successes_and_failures_are_counted() {
    let path = gateway_db_path("metrics-storage-ops");
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        "pub fn run(input: map) -> string { \"storage-ops\"; }",
        &path,
    )
    .expect("SQLite state should open");
    let metrics = state.metrics();
    let app = build_agent_gateway_app(state);

    let (status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({"input": "counted"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    let text = read_run_events(&app, &run_id).await;
    assert_eq!(text.matches("event: run.completed").count(), 1);
    let snapshot = metrics.snapshot();
    assert!(
        snapshot.storage_op_successes(StorageOp::AdmissionCreate) >= 1,
        "admission must count a successful admission.create"
    );
    assert!(
        snapshot.storage_op_successes(StorageOp::RunTerminal) >= 1,
        "the terminal commit must count a successful run.terminal"
    );
    assert!(
        snapshot.storage_op_failures(StorageOp::RunTerminal) == 0,
        "no terminal failures on the happy path"
    );

    // Break storage: the next mutation fails durably and is counted.
    let broken = path.with_extension("db.broken");
    std::fs::rename(&path, &broken).expect("move the db aside");
    std::fs::create_dir(&path).expect("break storage with a directory");
    let (status, _) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({"source": "yahu"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        metrics
            .snapshot()
            .storage_op_failures(StorageOp::SessionCreate)
            >= 1,
        "a failed session.create must be counted as a storage error"
    );

    std::fs::remove_dir(&path).expect("restore storage");
    std::fs::rename(&broken, &path).expect("restore the db file");
    let _ = std::fs::remove_file(&path);
}

/// A minimal tracing subscriber that records every event's structured
/// fields, so tests can verify typed reasons are logged as fields (log
/// verification is kept to the synchronous, maintainable surface).
#[derive(Clone)]
struct CapturingSubscriber {
    events: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Vec::new();
        event.record(&mut FieldCollector {
            fields: &mut fields,
        });
        self.events
            .lock()
            .expect("events lock")
            .push(format!("{}: {fields:?}", event.metadata().target()));
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct FieldCollector<'a> {
    fields: &'a mut Vec<(String, String)>,
}

impl tracing::field::Visit for FieldCollector<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }
}

#[tokio::test]
async fn stop_and_halt_log_structured_typed_reasons() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway config must validate");
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!("log-me"),
            platform: "test".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admission should succeed");
    let run_id = admitted.run_id.clone();

    let events = Arc::new(Mutex::new(Vec::new()));
    {
        let subscriber = CapturingSubscriber {
            events: Arc::clone(&events),
        };
        tracing::subscriber::with_default(subscriber, || {
            let status = service.stop(&run_id);
            assert_eq!(status.as_deref(), Some("stopping"));
        });
    }
    let captured = events.lock().expect("events lock");
    assert!(
        captured
            .iter()
            .any(|entry| entry.contains("reason") && entry.contains("requested")),
        "stop must log the typed cancellation reason as a structured field, got: {captured:?}"
    );
    drop(captured);

    events.lock().expect("events lock").clear();
    {
        let subscriber = CapturingSubscriber {
            events: Arc::clone(&events),
        };
        tracing::subscriber::with_default(subscriber, || service.halt());
    }
    let captured = events.lock().expect("events lock");
    assert!(
        captured
            .iter()
            .any(|entry| entry.contains("reason") && entry.contains("resource_closed")),
        "halt must log the typed resource-closed reason as a structured field, got: {captured:?}"
    );
}
