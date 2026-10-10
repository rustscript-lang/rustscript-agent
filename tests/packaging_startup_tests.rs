//! Gateway RSS source-selection consumption through the real generated source
//! policy, the bundled coding entry as a real gateway run, and the packaged
//! binary's startup / health / pre-listen behavior.
//!
//! Three layers live here:
//! * the generated `rss/agent/source_policy.rss` executed through the real
//!   standalone runner (the decision layer),
//! * `with_agent_selection` driving real gateway runs (the consumption layer),
//! * the actual gateway binary started over real loopback and observed for
//!   health facts and pre-listen failure (the packaged-binary layer).

#[cfg(unix)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rustscript_agent::{
    AdmitRunRequest, AgentConfig, AgentGatewayConfig, AgentGatewayState, AgentRunner,
    ScriptedProvider, build_agent_gateway_app, bundled_rss_sources,
};
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

fn temp_root() -> PathBuf {
    let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("rustscript-agent-gateway-source-tests"));
    std::fs::create_dir_all(&root).expect("gateway source test root should be created");
    root
}

// ---------------------------------------------------------------------------
// Decision layer: the generated catalog's source policy through the real
// runner.
// ---------------------------------------------------------------------------

fn json_to_vm(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::Null,
        Value::Bool(value) => VmValue::Bool(*value),
        Value::Number(value) => value
            .as_i64()
            .map(VmValue::Int)
            .or_else(|| value.as_f64().map(VmValue::Float))
            .unwrap_or(VmValue::Null),
        Value::String(value) => VmValue::string(value),
        Value::Array(values) => {
            VmValue::Array(values.iter().map(json_to_vm).collect::<Vec<_>>().into())
        }
        Value::Object(entries) => VmValue::map(
            entries
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm(value)))
                .collect(),
        ),
    }
}

fn vm_to_json(value: &VmValue) -> Value {
    match value {
        VmValue::Null => Value::Null,
        VmValue::Bool(value) => json!(value),
        VmValue::Int(value) => json!(value),
        VmValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        VmValue::String(value) => Value::String(value.to_string()),
        VmValue::Bytes(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        VmValue::Array(values) => Value::Array(values.iter().map(vm_to_json).collect::<Vec<_>>()),
        VmValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    let key = match key {
                        VmValue::String(key) => key.to_string(),
                        other => vm_to_json(other).to_string(),
                    };
                    (key, vm_to_json(value))
                })
                .collect(),
        ),
        VmValue::Callable(_) => Value::String("<callable>".to_string()),
    }
}

/// Compiles the generated catalog's `rss/agent/source_policy.rss` bytes and
/// runs its exported `run(context)` entry, returning the decision envelope.
fn decide_policy(context: Value) -> Value {
    let source = bundled_rss_sources()
        .iter()
        .find(|(key, _)| *key == "rss/agent/source_policy.rss")
        .map(|(_, source)| *source)
        .expect("generated catalog must embed rss/agent/source_policy.rss");
    let runner = AgentRunner::from_source(source, AgentConfig::default())
        .expect("generated source policy must compile");
    let decision = runner
        .run_with_context(json_to_vm(&context))
        .expect("generated source policy must run");
    vm_to_json(&decision)
}

fn policy_bundled_success() -> Value {
    json!({
        "ok": true,
        "source": "bundled:coding",
        "descriptor": {"kind": "bundled", "resource": "coding"},
        "deprecated_override": false
    })
}

fn policy_file_success(source: &str, path: &str, deprecated_override: bool) -> Value {
    json!({
        "ok": true,
        "source": source,
        "descriptor": {"kind": "file", "path": path},
        "deprecated_override": deprecated_override
    })
}

fn policy_failure(code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "deprecated_override": false,
        "error": {"code": code, "message": message}
    })
}

#[test]
fn generated_policy_default_and_explicit_file_select_expected_descriptors() {
    assert_eq!(decide_policy(json!({})), policy_bundled_success());
    let path = "/srv/エージェント dir/my agent.rss";
    assert_eq!(
        decide_policy(json!({ "source": format!("file:{path}") })),
        policy_file_success(&format!("file:{path}"), path, false)
    );
}

#[test]
fn generated_policy_precedence_and_migration_are_rss_owned() {
    // A configured source beats a valid legacy value.
    assert_eq!(
        decide_policy(json!({ "source": "bundled:coding", "legacy_script": "/legacy/agent.rss" })),
        policy_bundled_success()
    );
    // A legacy absolute path migrates to a file source with the indicator set.
    let raw = "/legacy/エージェント dir/agent.rss";
    assert_eq!(
        decide_policy(json!({ "legacy_script": raw })),
        policy_file_success(&format!("file:{raw}"), raw, true)
    );
    // A null configured source falls back to a valid legacy value.
    assert_eq!(
        decide_policy(json!({ "source": null, "legacy_script": "/legacy/agent.rss" })),
        policy_file_success("file:/legacy/agent.rss", "/legacy/agent.rss", true)
    );
}

#[test]
fn generated_policy_invalid_and_unsupported_sources_are_static_without_fallback() {
    assert_eq!(
        decide_policy(json!({ "source": 12, "legacy_script": "/legacy/agent.rss" })),
        policy_failure("invalid_agent_source", "agent source is invalid")
    );
    assert_eq!(
        decide_policy(json!({ "source": "other:thing", "legacy_script": "/legacy/agent.rss" })),
        policy_failure("unsupported_agent_source", "agent source is unsupported")
    );
}

#[test]
fn generated_policy_failure_never_echoes_hostile_input() {
    let hostile = "<script>alert(1)</script>?source=\u{0}evil";
    let result = decide_policy(json!({ "source": hostile }));
    assert_eq!(
        result,
        policy_failure("invalid_agent_source", "agent source is invalid")
    );
    let encoded = result.to_string();
    assert!(!encoded.contains(hostile));
    assert!(!encoded.contains("script"));
    assert!(!encoded.contains("evil"));
}

// ---------------------------------------------------------------------------
// Consumption layer: `with_agent_selection` drives real gateway runs.
// ---------------------------------------------------------------------------

/// Writes one self-contained RSS entry that returns a fixed marker string, so
/// a run's SSE output proves which source actually executed. Each entry lives
/// under its own `rss/` directory so the module snapshot's allowed root is
/// that isolated directory, never the shared test temp dir.
fn write_marker_source(label: &str, marker: &str) -> PathBuf {
    let dir = temp_root()
        .join(format!("selected-{label}-{}", Uuid::new_v4()))
        .join("rss");
    std::fs::create_dir_all(&dir).expect("selected agent source directory should be created");
    let path = dir.join("agent.rss");
    let body = format!("pub fn run(context: map) -> string {{ {marker:?}; }}\n");
    std::fs::write(&path, body).expect("selected agent source should be written");
    path
}

fn file_selection(path: &Path) -> Value {
    json!({ "source": format!("file:{}", path.display()) })
}

fn text_response(text: &str) -> Value {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

fn admit_request() -> AdmitRunRequest {
    AdmitRunRequest {
        input: json!({"message": "hello"}),
        platform: "packaging_startup_tests".to_string(),
        ..AdmitRunRequest::default()
    }
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

async fn run_selected_events(state: AgentGatewayState, session_id: &str) -> String {
    let app = build_agent_gateway_app(state);
    let (session_status, session) = json_request(
        &app,
        axum::http::Method::POST,
        "/api/sessions",
        json!({ "id": session_id }),
    )
    .await;
    assert_eq!(session_status, StatusCode::CREATED);
    let session_id = session["session"]["id"]
        .as_str()
        .expect("session id")
        .to_string();
    let (run_status, run) = json_request(
        &app,
        axum::http::Method::POST,
        "/v1/runs",
        json!({ "session_id": session_id, "input": "select" }),
    )
    .await;
    assert_eq!(run_status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8")
}

/// Control: the legacy constructors keep starting the bundled coding entry, so
/// the harness itself is not a blanket failure.
#[tokio::test]
async fn legacy_default_constructors_still_start_bundled() {
    AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("bundled default must start through the legacy constructor");
}

/// An empty selection makes the generated policy choose the bundled coding
/// entry. Before the native bundled arm is wired the constructor cannot admit
/// the resource and fails (genuine startup RED); once the embedded catalog
/// entry compiles and is installed through the tagged bundled route, a real
/// service run completes with the injected provider's answer.
#[tokio::test(flavor = "multi_thread")]
async fn empty_selection_runs_bundled_coding_with_provider_answer() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("bundled-selected-answer"));
    let state =
        AgentGatewayState::with_agent_selection(AgentGatewayConfig::default(), json!({}), None)
            .expect("an empty selection must select the bundled coding entry");
    state
        .service()
        .inject_provider_host(std::sync::Arc::new(provider.clone()));
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events = service.run_events(&admitted.run_id);
    let completed = events
        .iter()
        .find(|event| event["event"] == "run.completed")
        .unwrap_or_else(|| panic!("the bundled coding entry must complete the run: {events:?}"));
    assert!(
        completed.to_string().contains("bundled-selected-answer"),
        "the bundled coding entry must run with the injected provider: {completed}"
    );
    assert_eq!(
        provider.call_count(),
        1,
        "the bundled coding loop calls the provider exactly once"
    );
}

async fn assert_bundled_run_rebuilds_replaced_cache(key: &str, wrong_config: bool) {
    let state =
        AgentGatewayState::with_agent_selection(AgentGatewayConfig::default(), json!({}), None)
            .expect("bundled selection must start");
    let service = state.service();
    let expected = service
        .cached_runner_config()
        .expect("the bundled selection installs its admitted runner");
    let mut replacement_config = expected.clone();
    if wrong_config {
        replacement_config.http.allowed_hosts = vec!["cache-policy.invalid".to_string()];
    }
    let replacement = AgentRunner::from_bundled(key, replacement_config)
        .expect("the replacement is an admitted native bundled runner");
    service.install_agent_runner(replacement);
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("cache-rebuilt-bundled-answer"));
    service.inject_provider_host(std::sync::Arc::new(provider.clone()));
    let admitted = service.admit(admit_request()).await.expect("admission");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let events = service.run_events(&admitted.run_id);
    let completed = events
        .iter()
        .find(|event| event["event"] == "run.completed")
        .unwrap_or_else(|| panic!("the admitted coding entry must complete: {events:?}"));
    assert!(
        completed
            .to_string()
            .contains("cache-rebuilt-bundled-answer")
    );
    assert_eq!(provider.call_count(), 1);
    assert_eq!(service.cached_runner_config(), Some(expected));
}

#[tokio::test(flavor = "multi_thread")]
async fn bundled_cache_rebuilds_same_key_with_wrong_effective_config() {
    assert_bundled_run_rebuilds_replaced_cache("rss/agent/main.rss", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bundled_cache_rejects_another_admitted_resource_key() {
    assert_bundled_run_rebuilds_replaced_cache("rss/storage/main.rss", false).await;
}

/// The explicit file selection must execute the selected source, not the
/// default bundled entry.
#[tokio::test]
async fn selected_file_source_overrides_bundled_default() {
    let path = write_marker_source("override", "SELECTED_FILE_MARKER_OVERRIDE");
    let state = AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        file_selection(&path),
        None,
    )
    .expect("a valid file selection must start");
    let text = run_selected_events(state, "selected-file").await;
    assert!(
        text.contains("SELECTED_FILE_MARKER_OVERRIDE"),
        "the selected file source must execute, got: {text}"
    );
}

/// A configured source beats a valid legacy value even when the configured
/// value names a different file.
#[tokio::test]
async fn selected_file_source_beats_valid_legacy() {
    let chosen = write_marker_source("chosen", "SELECTED_FILE_MARKER_CHOSEN");
    let legacy = write_marker_source("legacy", "SELECTED_FILE_MARKER_LEGACY");
    let state = AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        json!({
            "source": format!("file:{}", chosen.display()),
            "legacy_script": legacy.display().to_string(),
        }),
        None,
    )
    .expect("a valid configured file selection must start");
    let text = run_selected_events(state, "selected-beats-legacy").await;
    assert!(
        text.contains("SELECTED_FILE_MARKER_CHOSEN"),
        "the configured file source must win, got: {text}"
    );
    assert!(
        !text.contains("SELECTED_FILE_MARKER_LEGACY"),
        "the legacy file must not run when a configured source wins, got: {text}"
    );
}

/// A legacy absolute path migrates to a file source and the migrated file
/// executes.
#[tokio::test]
async fn selected_legacy_absolute_path_migrates_to_file() {
    let legacy = write_marker_source("migrated", "SELECTED_FILE_MARKER_MIGRATED");
    let state = AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        json!({ "legacy_script": legacy.display().to_string() }),
        None,
    )
    .expect("an absolute legacy path must migrate");
    let text = run_selected_events(state, "selected-migrated").await;
    assert!(
        text.contains("SELECTED_FILE_MARKER_MIGRATED"),
        "the migrated legacy file must execute, got: {text}"
    );
}

/// A null configured source falls back to a valid legacy value.
#[tokio::test]
async fn selected_null_source_falls_back_to_valid_legacy() {
    let legacy = write_marker_source("nullfallback", "SELECTED_FILE_MARKER_NULL_FALLBACK");
    let state = AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        json!({
            "source": Value::Null,
            "legacy_script": legacy.display().to_string(),
        }),
        None,
    )
    .expect("a null source must fall back to a valid legacy value");
    let text = run_selected_events(state, "selected-null").await;
    assert!(
        text.contains("SELECTED_FILE_MARKER_NULL_FALLBACK"),
        "the legacy fallback file must execute, got: {text}"
    );
}

/// An unsupported configured source is a static policy error: no bundled or
/// legacy fallback, and no hostile input echoed.
#[tokio::test]
async fn selected_unsupported_source_fails_static_error() {
    let legacy = "/legacy/agent.rss";
    let error = match AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        json!({ "source": "other:thing", "legacy_script": legacy }),
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("an unsupported configured source must fail"),
    };
    assert!(
        error.contains("unsupported agent source") || error.contains("unsupported_agent_source"),
        "the static unsupported-source error must be returned, got: {error}"
    );
    assert!(
        !error.contains(legacy),
        "the policy error must not echo the legacy path, got: {error}"
    );
}

/// A non-string configured source is a static invalid-source error without
/// fallback to the valid legacy value.
#[tokio::test]
async fn selected_non_string_source_is_invalid_without_fallback() {
    let error = match AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        json!({ "source": 12, "legacy_script": "/legacy/agent.rss" }),
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("a non-string configured source must fail"),
    };
    assert!(
        error.contains("agent source is invalid") || error.contains("invalid_agent_source"),
        "the static invalid-source error must be returned, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// Health metadata: bounded public source facts, never a raw selected path.
// ---------------------------------------------------------------------------

async fn health_json(app: &axum::Router) -> Value {
    let (status, health) = json_request(
        app,
        axum::http::Method::GET,
        "/health/detailed",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    health
}

#[tokio::test]
async fn health_reports_bounded_file_source_metadata_without_raw_path() {
    let path = write_marker_source("health", "SELECTED_FILE_MARKER_HEALTH");
    let state = AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        file_selection(&path),
        None,
    )
    .expect("a valid file selection must start");
    let app = build_agent_gateway_app(state);
    let health = health_json(&app).await;

    assert_eq!(health["source"]["kind"], "file");
    let hash = health["source"]["hash"]
        .as_str()
        .expect("source hash must be a string");
    assert_eq!(hash.len(), 64, "the native snapshot digest is 64 hex chars");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "the source hash must be hex, got: {hash}"
    );
    assert_eq!(health["source"]["deprecated_override"], false);

    // The raw selected path must never appear in the public health body.
    let body = health.to_string();
    let rendered = path.to_string_lossy();
    assert!(
        !body.contains(rendered.as_ref()),
        "health must not echo the raw selected path, got: {body}"
    );
}

#[tokio::test]
async fn health_reports_deprecated_override_for_migrated_legacy_source() {
    let legacy = write_marker_source("healthlegacy", "SELECTED_FILE_MARKER_HEALTH_LEGACY");
    let state = AgentGatewayState::with_agent_selection(
        AgentGatewayConfig::default(),
        json!({ "legacy_script": legacy.display().to_string() }),
        None,
    )
    .expect("an absolute legacy path must migrate");
    let app = build_agent_gateway_app(state);
    let health = health_json(&app).await;
    assert_eq!(health["source"]["kind"], "file");
    assert_eq!(health["source"]["deprecated_override"], true);
}

#[tokio::test]
async fn health_omits_source_metadata_for_legacy_constructors() {
    // `new` is selection-driven now and publishes bounded bundled facts; the
    // *legacy* constructors that carry no RSS selection must not.
    let state = AgentGatewayState::with_agent_file(
        AgentGatewayConfig::default(),
        rustscript_agent::bundled_agent_main_path(),
    )
    .expect("bundled file entry must start");
    let app = build_agent_gateway_app(state);
    let health = health_json(&app).await;
    assert_eq!(health["status"], "ok");
    assert!(
        health.get("source").is_none(),
        "a legacy constructor must not publish source metadata, got: {health}"
    );
}

// ---------------------------------------------------------------------------
// Packaged-binary layer: the actual gateway binary over real loopback.
// ---------------------------------------------------------------------------

fn binary_root(label: &str) -> PathBuf {
    let root = temp_root().join(format!("bin-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("binary test root should be created");
    root
}

/// One raw HTTP GET over a plain TCP stream (no HTTP client dependency).
async fn http_get(host_port: &str, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(host_port)
        .await
        .expect("connect to the gateway");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

/// Polls the child's stderr file for the listening line and returns the bound
/// address, or `None` if the child exited first or the bound elapsed.
async fn wait_for_listening(
    child: &mut tokio::process::Child,
    stderr_path: &Path,
    timeout: Duration,
) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = std::fs::read_to_string(stderr_path)
            && let Some(position) = text.find("listening on http://")
        {
            let rest = &text[position + "listening on http://".len()..];
            let address = rest.lines().next().unwrap_or("").trim().to_string();
            if !address.is_empty() {
                return Some(address);
            }
        }
        if let Ok(Some(_)) = child.try_wait() {
            return None;
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn stop_child(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else {
        return;
    };
    let _ = std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status();
    let _ = tokio::time::timeout(Duration::from_secs(15), child.wait()).await;
}

/// An invalid authoritative source with a valid legacy fallback present must
/// fail startup *before* the listener binds: no listening line, non-zero exit,
/// and the static error never echoes the legacy path.
#[tokio::test]
async fn binary_invalid_authoritative_source_fails_before_listen() {
    let root = binary_root("invalid-source");
    let legacy = write_marker_source("binlegacy", "BINARY_LEGACY_MARKER");
    let db = root.join("state.db");
    let stderr_path = root.join("stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("stderr file");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"))
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .env("RUSTSCRIPT_AGENT_SOURCE", "other:thing")
        .env("RUSTSCRIPT_AGENT_SCRIPT", &legacy)
        .env("RUSTSCRIPT_AGENT_STATE_DB", &db)
        .env("HOME", &root)
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("gateway binary should spawn");

    let listening = wait_for_listening(&mut child, &stderr_path, Duration::from_secs(25)).await;
    if let Some(address) = listening {
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        stop_child(&mut child).await;
        panic!(
            "an invalid authoritative source must fail before bind, but it listened on {address}: {stderr}"
        );
    }
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("the gateway must exit")
        .expect("child wait");
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        !status.success(),
        "an invalid authoritative source must exit non-zero: {stderr}"
    );
    assert!(
        !stderr.contains("listening on http://"),
        "the gateway must not listen with an invalid source: {stderr}"
    );
    assert!(
        !stderr.contains(legacy.to_string_lossy().as_ref()),
        "the static startup error must not echo the legacy path: {stderr}"
    );
}

/// The default packaged binary starts from an empty source environment,
/// selects the bundled coding entry, binds a real loopback port, and publishes
/// bounded native source facts on `/health/detailed`.
#[tokio::test]
async fn binary_default_starts_and_health_reports_bundled_source() {
    let root = binary_root("default-health");
    let stderr_path = root.join("stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("stderr file");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"))
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .env("HOME", &root)
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("gateway binary should spawn");

    let address = match wait_for_listening(&mut child, &stderr_path, Duration::from_secs(30)).await
    {
        Some(address) => address,
        None => {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("the default gateway must bind and listen: {stderr}");
        }
    };

    let health = http_get(&address, "/health/detailed").await;
    assert!(
        health.contains("200 OK"),
        "health must answer 200: {health}"
    );
    let body = health.split("\r\n\r\n").nth(1).unwrap_or("");
    let json: Value = serde_json::from_str(body).expect("health body must be JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(
        json["source"]["kind"], "bundled",
        "the default entry's source facts must name the bundled coding kind: {json}"
    );
    let hash = json["source"]["hash"]
        .as_str()
        .expect("bundled source hash must be a string");
    assert_eq!(hash.len(), 64, "the native snapshot digest is 64 hex chars");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "the bundled source hash must be hex, got: {hash}"
    );
    assert_eq!(json["source"]["deprecated_override"], false);
    assert!(
        !health.contains(env!("CARGO_MANIFEST_DIR")),
        "health must not leak any checkout path: {health}"
    );

    stop_child(&mut child).await;
}

// ---------------------------------------------------------------------------
// Native OS encoding admission: a present non-UTF8 token for the two selected
// source fields must be classified by the RSS source policy, never decoded in
// Rust. These cases spawn the actual packaged binary with a synthetic opaque
// OS environment value (never a credential) and assert the RSS-level outcome.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn os_string_from_bytes(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes.to_vec())
}

/// A present non-UTF8 authoritative `SOURCE` must reach the RSS policy as a
/// present non-string token, so the policy returns its canonical
/// `invalid_agent_source` static error before the listener binds. The raw OS
/// bytes must never be surfaced (no `NotUnicode`, no marker) and the valid
/// legacy script must never be selected.
#[cfg(unix)]
#[tokio::test]
async fn binary_non_utf8_authoritative_source_is_static_invalid_without_leak() {
    let root = binary_root("non-utf8-source");
    let legacy = write_marker_source("nonutf8src", "NON_UTF8_SOURCE_LEGACY_MARKER");
    let db = root.join("state.db");
    let stderr_path = root.join("stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("stderr file");
    let marker = "PRIVATE_SOURCE_ENCODING_SENTINEL";
    let opaque_source = os_string_from_bytes(b"\xFFPRIVATE_SOURCE_ENCODING_SENTINEL");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"))
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .env("RUSTSCRIPT_AGENT_SOURCE", opaque_source)
        .env("RUSTSCRIPT_AGENT_SCRIPT", &legacy)
        .env("RUSTSCRIPT_AGENT_STATE_DB", &db)
        .env("HOME", &root)
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("gateway binary should spawn");

    let listening = wait_for_listening(&mut child, &stderr_path, Duration::from_secs(25)).await;
    if let Some(address) = listening {
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        stop_child(&mut child).await;
        panic!(
            "a present non-UTF8 authoritative source must not bind/listen on {address}: {stderr}"
        );
    }
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("the gateway must exit")
        .expect("child wait");
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        !status.success(),
        "a present non-UTF8 authoritative source must exit non-zero: {stderr}"
    );
    assert!(
        !stderr.contains("listening on http://"),
        "the gateway must not listen with an invalid source: {stderr}"
    );
    assert!(
        !stderr.contains("NotUnicode") && !stderr.contains(marker),
        "the RSS static error must never expose the raw OS bytes: {stderr}"
    );
    assert!(
        !stderr.contains(legacy.to_string_lossy().as_ref()),
        "the invalid authoritative source must not fall back to the legacy script: {stderr}"
    );
    assert!(
        stderr.contains("invalid_agent_source") || stderr.contains("agent source is invalid"),
        "the RSS policy's canonical invalid-source error must be returned: {stderr}"
    );
}

/// A valid authoritative bundled selection plus a present non-UTF8 legacy
/// script must still start: the RSS policy selects the bundled entry and never
/// reads the unused invalid legacy token. The collector must not throw an OS
/// decoding error before the policy can select.
#[cfg(unix)]
#[tokio::test]
async fn binary_valid_source_with_non_utf8_legacy_starts_bundled() {
    let root = binary_root("valid-src-non-utf8-legacy");
    let stderr_path = root.join("stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("stderr file");
    let opaque_legacy = os_string_from_bytes(b"\xFFPRIVATE_LEGACY_ENCODING_SENTINEL");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"))
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .env("RUSTSCRIPT_AGENT_SOURCE", "bundled:coding")
        .env("RUSTSCRIPT_AGENT_SCRIPT", opaque_legacy)
        .env("HOME", &root)
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("gateway binary should spawn");

    let address = match wait_for_listening(&mut child, &stderr_path, Duration::from_secs(30)).await
    {
        Some(address) => address,
        None => {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("a valid bundled source with an unused non-UTF8 legacy must start: {stderr}");
        }
    };
    let health = http_get(&address, "/health/detailed").await;
    stop_child(&mut child).await;
    assert!(
        health.contains("200 OK"),
        "health must answer 200: {health}"
    );
    let body = health.split("\r\n\r\n").nth(1).unwrap_or("");
    let json: Value = serde_json::from_str(body).expect("health body must be JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(
        json["source"]["kind"], "bundled",
        "the valid authoritative source must select bundled:coding: {json}"
    );
    assert_eq!(json["source"]["deprecated_override"], false);
}
