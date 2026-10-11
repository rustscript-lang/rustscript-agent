use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use rustscript_agent::service::AgentService;
use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, ScriptedProvider, build_agent_gateway_app,
};
use rustscript_vm::{
    CompileSourceFileOptions, SourceFlavor, compile_source_at_path_with_flavor_and_options,
};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn private_test_root(prefix: &str) -> PathBuf {
    let base = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
        .map(PathBuf::from)
        .expect("RUSTSCRIPT_AGENT_TEST_TMPDIR must point into the assigned private TEMP");
    base.join(format!("{prefix}-{}", uuid::Uuid::new_v4()))
}

async fn gateway_sessions(app: &axum::Router) -> Vec<serde_json::Value> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/sessions")
                .body(Body::empty())
                .expect("session-list request"),
        )
        .await
        .expect("session-list response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("session-list body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("session-list JSON");
    body["data"].as_array().cloned().unwrap_or_default()
}

fn scripted_tool_response(tool_calls: Value) -> Value {
    json!({
        "text": "",
        "tool_calls": tool_calls,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    })
}

fn scripted_text_response(text: &str) -> Value {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

async fn post_http_run(app: &axum::Router, payload: Value) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/runs")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("run request"),
        )
        .await
        .expect("run response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("run response body");
    let body: Value = serde_json::from_slice(&bytes).expect("run response JSON");
    assert_eq!(status, StatusCode::ACCEPTED, "run response: {body}");
    body
}

async fn wait_for_terminal(service: &AgentService, run_id: &str) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let events = service.run_events(run_id);
        if events.iter().any(|event| {
            matches!(
                event.get("event").and_then(Value::as_str),
                Some("run.completed" | "run.failed" | "run.cancelled")
            )
        }) {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "run did not terminate: {events:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn provider_tool_result(provider: &ScriptedProvider, call_id: &str) -> Value {
    for request in provider.requests() {
        if let Some(messages) = request.get("messages").and_then(Value::as_array) {
            for message in messages {
                if let Some(blocks) = message.get("content").and_then(Value::as_array) {
                    for block in blocks {
                        if block.get("type").and_then(Value::as_str) == Some("tool_result")
                            && block.get("tool_call_id").and_then(Value::as_str) == Some(call_id)
                        {
                            return block.clone();
                        }
                    }
                }
            }
        }
    }
    panic!("provider never received tool result for {call_id}");
}

#[tokio::test]
async fn explicit_http_compaction_uses_rss_and_is_generation_idempotent() {
    let root = private_test_root("http-compaction");
    fs::create_dir_all(&root).expect("private test root");
    let db_path = root.join("gateway.db");
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig::default(),
        rustscript_agent::bundled_agent_main_path(),
        &db_path,
    )
    .expect("gateway should open private SQLite fixture");
    let app = build_agent_gateway_app(state.clone());
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/sessions")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"id":"http-compaction-session", "model":"test-model", "provider":"test-provider"}).to_string(),
                ))
                .expect("create-session request"),
        )
        .await
        .expect("create-session response");
    assert!(
        create.status().is_success(),
        "session create: {}",
        create.status()
    );
    let persistence = state.persistence().expect("durable repository");
    for ordinal in 1..=40_i64 {
        persistence
            .message_append(&json!({
                "id": format!("http-compaction-message-{ordinal}"),
                "session_id": "http-compaction-session",
                "role": if ordinal % 2 == 0 { "assistant" } else { "user" },
                "content_json": json!([{"type":"text", "text":format!("http fact {ordinal}")}]).to_string(),
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 1,
                "metadata_json": "{}",
                "run_id": "",
                "finish_reason": "",
                "now_ms": ordinal + 100,
            }))
            .expect("append synthetic history through production RSS storage");
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions/http-compaction-session/compact")
                .body(Body::empty())
                .expect("explicit compaction request"),
        )
        .await
        .expect("explicit compaction response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("explicit compaction body");
    let first: Value = serde_json::from_slice(&bytes).expect("explicit compaction JSON");
    assert_eq!(first["status"], "committed", "{first}");
    assert_eq!(first["generation"], 2, "{first}");

    let replay = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions/http-compaction-session/compact")
                .body(Body::empty())
                .expect("replayed compaction request"),
        )
        .await
        .expect("replayed compaction response");
    assert_eq!(replay.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(replay.into_body(), usize::MAX)
        .await
        .expect("replayed compaction body");
    let second: Value = serde_json::from_slice(&bytes).expect("replayed compaction JSON");
    assert_eq!(second["status"], "skipped", "{second}");
    assert_eq!(second["generation"], 2, "{second}");
    drop(persistence);
    drop(state);
    fs::remove_dir_all(root).expect("private HTTP compaction fixture cleanup");
}

#[tokio::test]
async fn explicit_http_compaction_redacts_private_storage_error_details() {
    let root = private_test_root("http-compaction-error-redaction");
    fs::create_dir_all(&root).expect("private test root");
    let db_path = root.join("gateway.db");
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig::default(),
        rustscript_agent::bundled_agent_main_path(),
        &db_path,
    )
    .expect("gateway should open private SQLite fixture");
    let app = build_agent_gateway_app(state.clone());
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/sessions")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"id":"http-compaction-error-session", "model":"test-model", "provider":"test-provider"}).to_string(),
                ))
                .expect("create-session request"),
        )
        .await
        .expect("create-session response");
    assert!(create.status().is_success());
    let persistence = state.persistence().expect("durable repository");
    for ordinal in 1..=40_i64 {
        persistence
            .message_append(&json!({
                "id": format!("http-compaction-error-message-{ordinal}"),
                "session_id": "http-compaction-error-session",
                "role": if ordinal % 2 == 0 { "assistant" } else { "user" },
                "content_json": json!([{"type":"text", "text":format!("http error fact {ordinal}")}]).to_string(),
                "name": "",
                "tool_call_id": "",
                "parent_message_id": "",
                "token_estimate": 1,
                "metadata_json": "{}",
                "run_id": "",
                "finish_reason": "",
                "now_ms": ordinal + 100,
            }))
            .expect("append synthetic history through production RSS storage");
    }
    let script = r#"import sqlite3,sys
connection=sqlite3.connect(sys.argv[1])
connection.execute("CREATE TRIGGER f4_private_compaction_failure BEFORE INSERT ON compactions BEGIN SELECT RAISE(ABORT, 'F4_PRIVATE_STORAGE_SENTINEL'); END")
connection.commit()
connection.close()"#;
    let injected = std::process::Command::new("python3")
        .args([
            "-c",
            script,
            db_path.to_str().expect("fixture database path"),
        ])
        .output()
        .expect("python3 should inject the private SQLite failure");
    assert!(
        injected.status.success(),
        "failure trigger setup: {}",
        String::from_utf8_lossy(&injected.stderr)
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions/http-compaction-error-session/compact")
                .body(Body::empty())
                .expect("explicit compaction request"),
        )
        .await
        .expect("explicit compaction response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("explicit compaction body");
    let body: Value = serde_json::from_slice(&bytes).expect("explicit compaction JSON");
    assert_eq!(body["error"]["code"], "compaction_failed");
    assert!(!body.to_string().contains("F4_PRIVATE_STORAGE_SENTINEL"));

    let service = state.service();
    service.inject_compaction_policy_failure("F4_PRIVATE_VM_SENTINEL");
    let vm_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions/http-compaction-error-session/compact")
                .body(Body::empty())
                .expect("VM failure compaction request"),
        )
        .await
        .expect("VM failure compaction response");
    assert_eq!(vm_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let vm_body: Value = serde_json::from_slice(
        &axum::body::to_bytes(vm_response.into_body(), usize::MAX)
            .await
            .expect("VM failure body"),
    )
    .expect("VM failure JSON");
    assert_eq!(vm_body["error"]["code"], "compaction_failed");
    assert!(!vm_body.to_string().contains("F4_PRIVATE_VM_SENTINEL"));

    service.inject_compaction_worker_panic("F4_PRIVATE_WORKER_SENTINEL");
    let worker_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions/http-compaction-error-session/compact")
                .body(Body::empty())
                .expect("worker failure compaction request"),
        )
        .await
        .expect("worker failure compaction response");
    assert_eq!(worker_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let worker_body: Value = serde_json::from_slice(
        &axum::body::to_bytes(worker_response.into_body(), usize::MAX)
            .await
            .expect("worker failure body"),
    )
    .expect("worker failure JSON");
    assert_eq!(worker_body["error"]["code"], "compaction_failed");
    assert!(
        !worker_body
            .to_string()
            .contains("F4_PRIVATE_WORKER_SENTINEL")
    );
    drop(persistence);
    drop(state);
    fs::remove_dir_all(root).expect("private HTTP compaction fixture cleanup");
}

#[tokio::test]
async fn workspace_selector_errors_leave_no_session_and_default_resolves() {
    use rustscript_agent::service::{AdmitError, AdmitRunRequest};

    let root = private_test_root("workspace-selector-policy");
    let home = root.join("workspace-home");
    let allowed = root.join("allowed");
    let outside = root.join("outside");
    fs::create_dir_all(&home).expect("private workspace home");
    fs::create_dir_all(&allowed).expect("allowed workspace");
    fs::create_dir_all(&outside).expect("outside workspace");
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n",
        allowed.display(),
        allowed.display(),
        allowed.display()
    );
    rustscript_agent::config_file::ConfigFile::from_str(&config)
        .expect("workspace policy fixture config");
    fs::write(home.join("config.yaml"), config).expect("workspace policy config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("config mode");
    }
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("gateway state")
        .with_workspace_home(home);
    let service = state.service();
    let app = build_agent_gateway_app(state.clone());
    let invalid = [
        (String::new(), "workspace_selector_blank"),
        ("../outside".to_string(), "workspace_selector_relative"),
        (outside.display().to_string(), "workspace_denied"),
        ("name:missing".to_string(), "workspace_name_unknown"),
        ("x".repeat(4097), "workspace_selector_too_long"),
    ];
    for (selector, expected) in invalid {
        let result = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!("selector validation fixture"),
                    platform: "http".to_string(),
                    ..AdmitRunRequest::default()
                },
                Some(selector),
            )
            .await;
        assert!(
            matches!(&result, Err(AdmitError::Invalid(code)) if code == expected),
            "selector should fail with {expected}: {result:?}"
        );
        assert!(
            gateway_sessions(&app).await.is_empty(),
            "invalid selector left a session"
        );
    }

    let defaulted = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("resolve the configured default"),
                platform: "http".to_string(),
                ..AdmitRunRequest::default()
            },
            None,
        )
        .await
        .expect("missing selector resolves configured default");
    let sessions = gateway_sessions(&app).await;
    let session = sessions
        .iter()
        .find(|session| session["id"] == defaulted.session_id)
        .expect("default-workspace session");
    assert_eq!(
        session["workspace"]["canonical_path"],
        allowed.display().to_string()
    );
    service.stop(&defaulted.run_id);
    drop(app);
    drop(service);
    drop(state);
    fs::remove_dir_all(root).expect("remove private selector fixture");
}

#[tokio::test]
async fn http_run_rejects_workspace_selector_without_trusted_workspace_home() {
    use rustscript_agent::service::AdmitRunRequest;

    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("default gateway config must validate");
    let app = build_agent_gateway_app(state.clone());
    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health/detailed")
                .body(Body::empty())
                .expect("health request"),
        )
        .await
        .expect("health response");
    assert_eq!(health.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/runs")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"input":"inspect files","workspace":"name:missing"}).to_string(),
                ))
                .expect("request must build"),
        )
        .await
        .expect("gateway must respond");

    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "explicit workspace admission must fail before creating a run when no trusted workspace home is installed"
    );
    let service = state.service();
    let admitted = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("normal prompt needs no workspace home"),
                platform: "http".to_string(),
                ..AdmitRunRequest::default()
            },
            None,
        )
        .await
        .expect("workspace authority is optional for ordinary admissions");
    let session = gateway_sessions(&app)
        .await
        .into_iter()
        .find(|session| session["id"] == admitted.session_id)
        .expect("ordinary no-workspace session");
    assert!(session["workspace"].is_null());
    service.stop(&admitted.run_id);
    drop(service);
    drop(state);
}

#[tokio::test(flavor = "multi_thread")]
async fn http_main_runs_without_workspace_and_persists_typed_effect_denials() {
    let root = private_test_root("workspace-unavailable-run");
    fs::create_dir_all(&root).expect("private run root");
    let database = root.join("gateway.sqlite3");
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig::default(),
        rustscript_agent::bundled_agent_main_path(),
        &database,
    )
    .expect("production bundled Main with durable store");
    let provider = ScriptedProvider::new();
    provider.push_ok(scripted_tool_response(json!([
        {
            "id": "no-workspace-read",
            "name": "read_file",
            "arguments": {"path": "Cargo.toml"}
        },
        {
            "id": "no-workspace-process",
            "name": "terminal",
            "arguments": {"argv": ["/bin/pwd"], "timeout_ms": 2000}
        }
    ])));
    provider.push_ok(scripted_text_response("ordinary Main run completed"));
    let service = state.service();
    service.inject_provider_host(Arc::new(provider.clone()));
    let app = build_agent_gateway_app(state.clone());

    let response = post_http_run(&app, json!({"input": "Summarize the current project."})).await;
    let run_id = response["run_id"].as_str().expect("accepted run id");
    let events = wait_for_terminal(&service, run_id).await;
    assert!(
        events.iter().any(|event| event["event"] == "run.completed"),
        "ordinary Main must complete after denied effects: {events:?}"
    );
    assert!(!events.iter().any(|event| event["event"] == "run.failed"));
    for call_id in ["no-workspace-read", "no-workspace-process"] {
        let denied = events
            .iter()
            .find(|event| {
                event["event"] == "tool.failed" && event["data"]["tool_call_id"] == call_id
            })
            .unwrap_or_else(|| panic!("missing durable denial for {call_id}: {events:?}"));
        assert_eq!(denied["data"]["error_code"], "workspace_unavailable");
        let result = provider_tool_result(&provider, call_id);
        assert_eq!(result["is_error"], true);
        assert_eq!(result["error"]["code"], "workspace_unavailable");
    }
    assert_eq!(provider.call_count(), 2, "denials must not abort RSS");
    assert!(service.capability_host_closed(run_id));
    assert!(!service.capability_host_retained(run_id));
    assert_eq!(service.process_owner_count(run_id), 0);

    let session_id = events
        .iter()
        .find(|event| event["event"] == "run.started")
        .and_then(|event| event.pointer("/data/session_id"))
        .and_then(Value::as_str)
        .expect("durable session id");
    let stored = service.session_messages(session_id);
    let stored = serde_json::to_string(&stored).expect("durable tool results serialize");
    assert!(stored.contains("workspace_unavailable"));

    drop(app);
    drop(service);
    drop(state);
    fs::remove_dir_all(root).expect("remove no-workspace run fixture");
}

#[tokio::test(flavor = "multi_thread")]
async fn http_named_workspace_runs_production_rss_file_and_process_effects() {
    let root = private_test_root("workspace-native-effects");
    let home = root.join("auth-home");
    let workspace = root.join("project");
    fs::create_dir_all(&home).expect("private auth home");
    fs::create_dir_all(&workspace).expect("private workspace");
    fs::write(workspace.join("readme.txt"), "WORKSPACE_READ_SENTINEL")
        .expect("workspace read fixture");
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    rustscript_agent::config_file::ConfigFile::from_str(&config)
        .expect("synthetic native workspace policy");
    fs::write(home.join("config.yaml"), config).expect("workspace policy file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("config mode");
    }
    let database = root.join("gateway.sqlite3");
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig::default(),
        rustscript_agent::bundled_agent_main_path(),
        &database,
    )
    .expect("production bundled Main with durable store")
    .with_workspace_home(home.clone());
    let provider = ScriptedProvider::new();
    provider.push_ok(scripted_tool_response(json!([
        {
            "id": "workspace-read",
            "name": "read_file",
            "arguments": {"path": "readme.txt"}
        },
        {
            "id": "workspace-write",
            "name": "write_file",
            "arguments": {"path": "written.txt", "content": "WORKSPACE_WRITE_SENTINEL"}
        },
        {
            "id": "workspace-cwd",
            "name": "terminal",
            "arguments": {"argv": ["/bin/pwd"], "timeout_ms": 3000}
        }
    ])));
    provider.push_ok(scripted_text_response("workspace RSS run completed"));
    let service = state.service();
    service.inject_provider_host(Arc::new(provider.clone()));
    let app = build_agent_gateway_app(state.clone());

    let response = post_http_run(
        &app,
        json!({
            "input": "Read the workspace note, write a note, and report the process working directory.",
            "workspace": "name:project"
        }),
    )
    .await;
    let run_id = response["run_id"].as_str().expect("accepted run id");
    let events = wait_for_terminal(&service, run_id).await;
    assert!(
        events.iter().any(|event| event["event"] == "run.completed"),
        "production Main should complete after workspace effects: {events:?}"
    );
    for call_id in ["workspace-read", "workspace-write", "workspace-cwd"] {
        assert!(
            events.iter().any(|event| {
                event["event"] == "tool.completed" && event["data"]["tool_call_id"] == call_id
            }),
            "missing successful tool event for {call_id}: {events:?}"
        );
    }
    assert_eq!(
        fs::read_to_string(workspace.join("written.txt")).expect("native workspace write"),
        "WORKSPACE_WRITE_SENTINEL"
    );
    let read_result = provider_tool_result(&provider, "workspace-read");
    assert!(
        read_result.to_string().contains("WORKSPACE_READ_SENTINEL"),
        "RSS read result should include the real workspace bytes: {read_result}"
    );
    let cwd_result = provider_tool_result(&provider, "workspace-cwd");
    assert!(
        cwd_result
            .to_string()
            .contains(&workspace.display().to_string()),
        "process must run with the held workspace as cwd: {cwd_result}"
    );
    assert_eq!(provider.call_count(), 2);
    assert!(service.capability_host_closed(run_id));
    assert!(!service.capability_host_retained(run_id));
    assert_eq!(service.process_owner_count(run_id), 0);

    let session_id = events
        .iter()
        .find(|event| event["event"] == "run.started")
        .and_then(|event| event.pointer("/data/session_id"))
        .and_then(Value::as_str)
        .expect("durable session id");
    let session = gateway_sessions(&app)
        .await
        .into_iter()
        .find(|session| session["id"] == session_id)
        .expect("persisted named-workspace session");
    assert_eq!(
        session["workspace"]["canonical_path"],
        workspace.display().to_string()
    );
    assert_eq!(session["workspace"]["selector"], "name:project");

    drop(app);
    drop(service);
    drop(state);
    fs::remove_dir_all(root).expect("remove workspace effect fixture");
}

#[tokio::test]
async fn trusted_named_workspace_binds_session_replays_once_and_rejects_switch() {
    use rustscript_agent::service::{AdmitError, AdmitRunRequest};

    let root = private_test_root("workspace-session-binding");
    let home = root.join("auth-home");
    let first_workspace = root.join("workspace-one");
    let second_workspace = root.join("workspace-two");
    fs::create_dir_all(&home).expect("private auth home");
    fs::create_dir_all(&first_workspace).expect("first workspace");
    fs::create_dir_all(&second_workspace).expect("second workspace");
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n    alias: '{}'\n    alternate: '{}'\n",
        first_workspace.display(),
        second_workspace.display(),
        first_workspace.display(),
        first_workspace.display(),
        first_workspace.display(),
        second_workspace.display(),
    );
    rustscript_agent::config_file::ConfigFile::from_str(&config)
        .expect("synthetic workspace config schema");
    fs::write(home.join("config.yaml"), config).expect("synthetic native config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("config mode");
    }

    let database = root.join("gateway.sqlite3");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &database)
        .expect("gateway config")
        .with_workspace_home(PathBuf::from(&home));
    let service = state.service();
    let app = build_agent_gateway_app(state.clone());
    let request =
        |key: &str, hash: &str, input: &str, session_id: Option<String>| AdmitRunRequest {
            input: json!(input),
            platform: "http".to_string(),
            session_id,
            idempotency_key: Some(key.to_string()),
            idempotency_hash: Some(hash.to_string()),
            ..AdmitRunRequest::default()
        };

    let first = service
        .admit_with_workspace_selector(
            request(
                "idem-first",
                "fnv64:0000000000000001",
                "open first file",
                None,
            ),
            Some("name:project".to_string()),
        )
        .await
        .expect("trusted named workspace admitted");
    let replay = service
        .admit_with_workspace_selector(
            request(
                "idem-first",
                "fnv64:0000000000000001",
                "open first file",
                None,
            ),
            Some("name:project".to_string()),
        )
        .await
        .expect("idempotent replay");
    assert_eq!(replay.run_id, first.run_id);
    assert!(replay.replayed);
    assert_eq!(service.session_messages(&first.session_id).len(), 1);
    let cross_workspace_replay = service
        .admit_with_workspace_selector(
            request(
                "idem-first",
                "fnv64:0000000000000001",
                "open first file",
                None,
            ),
            Some("name:alternate".to_string()),
        )
        .await;
    assert!(
        matches!(cross_workspace_replay, Err(AdmitError::IdempotencyConflict)),
        "same payload hash must conflict across effective workspace roots: {cross_workspace_replay:?}"
    );
    assert_eq!(service.session_messages(&first.session_id).len(), 1);

    let alias_conflict = service
        .admit_with_workspace_selector(
            request(
                "idem-alias",
                "fnv64:0000000000000004",
                "use same canonical path through another selector",
                Some(first.session_id.clone()),
            ),
            Some("name:alias".to_string()),
        )
        .await;
    assert!(
        matches!(&alias_conflict, Err(AdmitError::Invalid(message)) if message == "workspace_conflict"),
        "a different selector for the same canonical root must conflict: {alias_conflict:?}"
    );
    assert_eq!(service.session_messages(&first.session_id).len(), 1);
    let stored_session = state
        .persistence()
        .expect("production persistence")
        .session_get(&first.session_id)
        .expect("read bound session after selector conflict");
    let stored_metadata: serde_json::Value = serde_json::from_str(
        stored_session["rows"][0][13]
            .as_str()
            .expect("session metadata JSON"),
    )
    .expect("session metadata object");
    assert_eq!(stored_metadata["workspace"]["selector"], "name:project");
    assert_eq!(
        stored_metadata["workspace"]["canonical_path"],
        first_workspace.display().to_string()
    );

    let defaulted = service
        .admit_with_workspace_selector(
            request(
                "idem-default",
                "fnv64:0000000000000002",
                "use the bound workspace",
                Some(first.session_id.clone()),
            ),
            None,
        )
        .await
        .expect("session workspace reopens from the trusted config");
    assert_eq!(service.session_messages(&first.session_id).len(), 2);

    let switch = service
        .admit_with_workspace_selector(
            request(
                "idem-switch",
                "fnv64:0000000000000003",
                "switch workspace",
                Some(first.session_id.clone()),
            ),
            Some("name:alternate".to_string()),
        )
        .await;
    assert!(matches!(switch, Err(AdmitError::Invalid(message)) if message == "workspace_conflict"));
    assert_eq!(service.session_messages(&first.session_id).len(), 2);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/sessions")
                .body(Body::empty())
                .expect("session request"),
        )
        .await
        .expect("gateway must respond");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("session response body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("session JSON");
    let session = body["data"]
        .as_array()
        .and_then(|data| {
            data.iter()
                .find(|session| session["id"] == first.session_id)
        })
        .expect("bound session response");
    assert_eq!(
        session["workspace"]["canonical_path"],
        first_workspace.display().to_string()
    );
    assert_eq!(session["workspace"]["selector"], "name:project");

    service.stop(&first.run_id);
    service.stop(&defaulted.run_id);
    drop(service);
    drop(state);
    fs::remove_dir_all(root).expect("remove private test fixture");
}

#[tokio::test]
async fn http_session_workspace_route_binds_an_idle_session() {
    use rustscript_agent::service::{AdmitError, AdmitRunRequest};

    let root = private_test_root("workspace-session-route");
    let home = root.join("auth-home");
    let first = root.join("workspace-one");
    let second = root.join("workspace-two");
    fs::create_dir_all(&home).expect("private auth home");
    fs::create_dir_all(&first).expect("first workspace");
    fs::create_dir_all(&second).expect("second workspace");
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n    alias: '{}'\n    alternate: '{}'\n",
        first.display(),
        second.display(),
        first.display(),
        first.display(),
        first.display(),
        second.display()
    );
    fs::write(home.join("config.yaml"), config).expect("trusted workspace config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("config mode");
    }

    let database = root.join("gateway.sqlite3");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &database)
        .expect("gateway SQLite state")
        .with_workspace_home(home.clone());
    let service = state.service();
    let app = build_agent_gateway_app(state.clone());
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/sessions")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("create-session request"),
        )
        .await
        .expect("create-session response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(created.into_body(), usize::MAX)
        .await
        .expect("created-session body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("created-session JSON");
    let session_id = body["session"]["id"].as_str().expect("created session id");
    state
        .persistence()
        .expect("production SQLite persistence")
        .session_touch(&json!({
            "session_id": session_id,
            "status": "active",
            "generation": 0,
            "system_prompt": "",
            "model": "synthetic",
            "provider": "local-test",
            "toolset_hash": "",
            "metadata_json": "{\"unrelated\":\"preserved\"}",
            "title": "",
            "end_reason": "",
            "now_ms": 1
        }))
        .expect("seed unrelated persisted session metadata");
    let persistence = state.persistence().expect("production SQLite persistence");
    persistence.inject_persist_failure();
    let failed_bind = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/sessions/{session_id}/workspace"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workspace":"name:project"}"#))
                .expect("failed workspace-bind request"),
        )
        .await
        .expect("failed workspace-bind response");
    assert_eq!(failed_bind.status(), StatusCode::SERVICE_UNAVAILABLE);
    let unchanged = persistence
        .session_get(session_id)
        .expect("session after failed atomic bind");
    let unchanged_metadata: serde_json::Value = serde_json::from_str(
        unchanged["rows"][0][13]
            .as_str()
            .expect("metadata after failed bind"),
    )
    .expect("metadata JSON after failed bind");
    assert_eq!(unchanged_metadata["unrelated"], "preserved");
    assert!(unchanged_metadata.get("workspace").is_none());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/sessions/{session_id}/workspace"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workspace":"name:project"}"#))
                .expect("workspace-bind request"),
        )
        .await
        .expect("workspace-bind response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("workspace-bind body");
    assert_eq!(
        status,
        StatusCode::OK,
        "workspace-bind response: {}",
        String::from_utf8_lossy(&bytes)
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("workspace-bind JSON");
    assert_eq!(body["session"]["workspace"]["selector"], "name:project");

    let alias_conflict = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("first run through a changed selector"),
                platform: "http".to_string(),
                session_id: Some(session_id.to_string()),
                idempotency_key: Some("orphan-idempotency-key".to_string()),
                idempotency_hash: Some("fnv64:0123456789abcdef".to_string()),
                ..AdmitRunRequest::default()
            },
            Some("name:alias".to_string()),
        )
        .await;
    assert!(
        matches!(&alias_conflict, Err(AdmitError::Invalid(message)) if message == "workspace_conflict"),
        "same-canonical selector changes must be rejected before durable admission: {alias_conflict:?}"
    );
    assert!(service.session_messages(session_id).is_empty());

    let provider = ScriptedProvider::new();
    provider.push_ok(scripted_tool_response(json!([
        {
            "id": "bound-http-write",
            "name": "write_file",
            "arguments": {"path": "bound-http-write.txt", "content": "HTTP_BOUND_WORKSPACE_WRITE"}
        },
        {
            "id": "bound-http-process",
            "name": "terminal",
            "arguments": {"argv": ["/bin/touch", "bound-http-process.txt"], "timeout_ms": 3000}
        }
    ])));
    provider.push_ok(scripted_text_response(
        "bound session native effects completed",
    ));
    service.inject_provider_host(Arc::new(provider.clone()));
    let ordinary_http_run = post_http_run(
        &app,
        json!({
            "session_id": session_id,
            "input": "Write the file and create a process-side workspace marker."
        }),
    )
    .await;
    let ordinary_run_id = ordinary_http_run["run_id"]
        .as_str()
        .expect("ordinary same-session HTTP run id");
    let ordinary_events = wait_for_terminal(&service, ordinary_run_id).await;
    assert!(
        ordinary_events
            .iter()
            .any(|event| event["event"] == "run.completed")
    );
    assert!(ordinary_events.iter().any(|event| {
        event["event"] == "run.started" && event["data"]["session_id"] == session_id
    }));
    assert_eq!(
        fs::read_to_string(first.join("bound-http-write.txt")).expect("bound HTTP file effect"),
        "HTTP_BOUND_WORKSPACE_WRITE"
    );
    assert!(first.join("bound-http-process.txt").is_file());
    assert_eq!(provider.call_count(), 2);

    let active_created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/sessions")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("create active session request"),
        )
        .await
        .expect("create active session response");
    assert_eq!(active_created.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(active_created.into_body(), usize::MAX)
        .await
        .expect("active session body");
    let active_session: serde_json::Value =
        serde_json::from_slice(&bytes).expect("active session JSON");
    let active_session_id = active_session["session"]["id"]
        .as_str()
        .expect("active session id");
    persistence
        .session_touch(&json!({
            "session_id": active_session_id,
            "status": "active",
            "generation": 0,
            "system_prompt": "",
            "model": "synthetic",
            "provider": "local-test",
            "toolset_hash": "",
            "metadata_json": "{\"admission_sentinel\":\"preserved\"}",
            "title": "",
            "end_reason": "",
            "now_ms": 1
        }))
        .expect("seed metadata before admission");
    let active_bind = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/sessions/{active_session_id}/workspace"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workspace":"name:project"}"#))
                .expect("bind active session workspace request"),
        )
        .await
        .expect("bind active session workspace response");
    assert_eq!(active_bind.status(), StatusCode::OK);
    service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("hold an active run"),
                platform: "http".to_string(),
                session_id: Some(active_session_id.to_string()),
                ..AdmitRunRequest::default()
            },
            None,
        )
        .await
        .expect("create durable active run");
    let active_switch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/sessions/{active_session_id}/workspace"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workspace":"name:alternate"}"#))
                .expect("active switch request"),
        )
        .await
        .expect("active switch response");
    assert_eq!(active_switch.status(), StatusCode::CONFLICT);
    let active_metadata = persistence
        .session_get(active_session_id)
        .expect("read metadata after admission");
    let active_row = &active_metadata["rows"][0];
    let active_metadata_raw = active_row
        .as_array()
        .and_then(|values| values.get(13))
        .and_then(serde_json::Value::as_str)
        .expect("active metadata JSON");
    let active_metadata: serde_json::Value =
        serde_json::from_str(active_metadata_raw).expect("active metadata object");
    assert_eq!(active_metadata["admission_sentinel"], "preserved");
    assert_eq!(
        active_metadata["workspace"]["canonical_path"],
        first.display().to_string()
    );

    drop(app);
    drop(service);
    drop(state);

    let reopened_state =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &database)
            .expect("reopen production SQLite state")
            .with_workspace_home(home.clone());
    let persisted = reopened_state
        .persistence()
        .expect("reopened SQLite persistence")
        .session_get(session_id)
        .expect("read reopened session");
    let row = &persisted["rows"][0];
    let metadata_raw = row
        .as_array()
        .and_then(|values| values.get(13))
        .and_then(serde_json::Value::as_str)
        .expect("persisted session metadata");
    let metadata: serde_json::Value =
        serde_json::from_str(metadata_raw).expect("persisted metadata JSON");
    assert_eq!(metadata["unrelated"], "preserved");
    assert_eq!(
        metadata["workspace"]["canonical_path"],
        first.display().to_string()
    );

    let reopened_app = build_agent_gateway_app(reopened_state.clone());
    let idle_switch = reopened_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/sessions/{session_id}/workspace"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workspace":"name:alternate"}"#))
                .expect("idle switch request"),
        )
        .await
        .expect("idle switch response");
    assert_eq!(idle_switch.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(idle_switch.into_body(), usize::MAX)
        .await
        .expect("idle switch body");
    let switched: serde_json::Value = serde_json::from_slice(&bytes).expect("idle switch JSON");
    assert_eq!(
        switched["session"]["workspace"]["canonical_path"],
        second.display().to_string()
    );

    let changed_config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n    alternate: '{}'\n",
        first.display(),
        first.display(),
        first.display(),
        first.display()
    );
    rustscript_agent::config_file::ConfigFile::from_str(&changed_config)
        .expect("changed workspace roots remain valid config");
    fs::write(home.join("config.yaml"), changed_config).expect("change configured workspace roots");
    drop(reopened_app);
    drop(reopened_state);

    let changed_state =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &database)
            .expect("reopen changed workspace policy")
            .with_workspace_home(home.clone());
    let service_after_policy_change = changed_state.service();
    let messages_before = service_after_policy_change
        .session_messages(session_id)
        .len();
    let denied = service_after_policy_change
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("must not bind to a changed root"),
                platform: "http".to_string(),
                session_id: Some(session_id.to_string()),
                ..AdmitRunRequest::default()
            },
            None,
        )
        .await
        .expect_err("changed and now disallowed prior root must not be reused");
    assert!(
        matches!(&denied, AdmitError::Invalid(code) if code == "workspace_conflict"),
        "stale disallowed workspace binding must fail closed: {denied:?}"
    );
    assert_eq!(
        service_after_policy_change
            .session_messages(session_id)
            .len(),
        messages_before
    );
    drop(service_after_policy_change);
    drop(changed_state);
    fs::remove_dir_all(root).expect("remove private test fixture");
}

#[tokio::test]
async fn workspace_idempotency_replay_is_pure_cached_and_durable() {
    use rustscript_agent::service::{AdmitError, AdmitRunRequest};

    let root = private_test_root("workspace-pure-replay");
    let home = root.join("auth-home");
    let workspace = root.join("project");
    let replacement_default = root.join("replacement-default");
    let database = root.join("gateway.sqlite3");
    fs::create_dir_all(&home).expect("private auth home");
    fs::create_dir_all(&workspace).expect("workspace root");
    fs::create_dir_all(&replacement_default).expect("replacement default workspace");
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n    alias: '{}'\n",
        workspace.display(),
        replacement_default.display(),
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    rustscript_agent::config_file::ConfigFile::from_str(&config)
        .expect("synthetic workspace policy");
    fs::write(home.join("config.yaml"), config).expect("workspace policy file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("config mode");
    }

    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &database)
        .expect("durable gateway state")
        .with_workspace_home(home.clone());
    let service = state.service();

    let original = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-pure-replay".to_string()),
                idempotency_hash: Some("fnv64:0123456789abcdef".to_string()),
                ..AdmitRunRequest::default()
            },
            Some("name:project".to_string()),
        )
        .await
        .expect("original workspace admission");
    let original_messages = service.session_messages(&original.session_id);
    let original_events = service.run_events(&original.run_id);
    assert_eq!(original_messages.len(), 1);
    assert_eq!(original_events.len(), 1);

    let default_original = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original default logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-default-replay".to_string()),
                idempotency_hash: Some("fnv64:0000000000000010".to_string()),
                ..AdmitRunRequest::default()
            },
            None,
        )
        .await
        .expect("original default-workspace admission");
    let default_messages = service.session_messages(&default_original.session_id);
    let default_events = service.run_events(&default_original.run_id);
    let default_cached = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original default logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-default-replay".to_string()),
                idempotency_hash: Some("fnv64:0000000000000010".to_string()),
                ..AdmitRunRequest::default()
            },
            None,
        )
        .await
        .expect("matching cached default replay");
    assert!(default_cached.replayed);
    assert_eq!(default_cached.run_id, default_original.run_id);
    assert_eq!(
        service.session_messages(&default_original.session_id),
        default_messages
    );
    assert_eq!(service.run_events(&default_original.run_id), default_events);

    fs::remove_dir_all(&workspace).expect("make the original root unavailable");
    let changed_default_config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n    alias: '{}'\n",
        workspace.display(),
        replacement_default.display(),
        replacement_default.display(),
        workspace.display(),
        workspace.display()
    );
    rustscript_agent::config_file::ConfigFile::from_str(&changed_default_config)
        .expect("changed synthetic workspace policy");
    fs::write(home.join("config.yaml"), changed_default_config)
        .expect("change the current default workspace");

    let cached = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-pure-replay".to_string()),
                idempotency_hash: Some("fnv64:0123456789abcdef".to_string()),
                ..AdmitRunRequest::default()
            },
            Some("name:project".to_string()),
        )
        .await
        .expect("matching cached replay must not reopen the removed root");
    assert!(cached.replayed);
    assert_eq!(cached.run_id, original.run_id);
    assert_eq!(
        service.session_messages(&original.session_id),
        original_messages
    );
    assert_eq!(service.run_events(&original.run_id), original_events);

    drop(service);
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &database)
        .expect("reopen durable gateway state")
        .with_workspace_home(home.clone());
    let reopened_service = reopened.service();
    let durable_messages_before = reopened_service.session_messages(&original.session_id);
    let durable_events_before = reopened_service.run_events(&original.run_id);
    assert_eq!(durable_messages_before.len(), original_messages.len());
    assert_eq!(durable_messages_before[0]["id"], original_messages[0]["id"]);
    let durable = reopened_service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-pure-replay".to_string()),
                idempotency_hash: Some("fnv64:0123456789abcdef".to_string()),
                ..AdmitRunRequest::default()
            },
            Some("name:project".to_string()),
        )
        .await
        .expect("matching durable replay must not reopen the removed root");
    assert!(durable.replayed);
    assert_eq!(durable.run_id, original.run_id);
    assert_eq!(
        reopened_service.session_messages(&original.session_id),
        durable_messages_before
    );
    assert_eq!(
        reopened_service.run_events(&original.run_id),
        durable_events_before
    );

    let default_durable_messages_before =
        reopened_service.session_messages(&default_original.session_id);
    let default_durable_events_before = reopened_service.run_events(&default_original.run_id);
    let default_durable = reopened_service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original default logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-default-replay".to_string()),
                idempotency_hash: Some("fnv64:0000000000000010".to_string()),
                ..AdmitRunRequest::default()
            },
            None,
        )
        .await
        .expect("missing selector retains the original default meaning after restart");
    assert!(default_durable.replayed);
    assert_eq!(default_durable.run_id, default_original.run_id);
    assert_eq!(
        reopened_service.session_messages(&default_original.session_id),
        default_durable_messages_before
    );
    assert_eq!(
        reopened_service.run_events(&default_original.run_id),
        default_durable_events_before
    );

    let changed_selector_same_hash = reopened_service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-pure-replay".to_string()),
                idempotency_hash: Some("fnv64:0123456789abcdef".to_string()),
                ..AdmitRunRequest::default()
            },
            Some("name:alias".to_string()),
        )
        .await;
    assert!(
        matches!(
            changed_selector_same_hash,
            Err(AdmitError::IdempotencyConflict)
        ),
        "the original hash with a changed selector must conflict before opening the removed root: {changed_selector_same_hash:?}"
    );

    let changed_selector = reopened_service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("original logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-pure-replay".to_string()),
                idempotency_hash: Some("fnv64:fedcba9876543210".to_string()),
                ..AdmitRunRequest::default()
            },
            Some("name:alias".to_string()),
        )
        .await;
    assert!(
        matches!(changed_selector, Err(AdmitError::IdempotencyConflict)),
        "changed raw selector must conflict before trying the removed root: {changed_selector:?}"
    );
    let changed_payload = reopened_service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!("changed logical request"),
                platform: "http".to_string(),
                idempotency_key: Some("workspace-pure-replay".to_string()),
                idempotency_hash: Some("fnv64:fedcba9876543210".to_string()),
                ..AdmitRunRequest::default()
            },
            Some("name:project".to_string()),
        )
        .await;
    assert!(
        matches!(changed_payload, Err(AdmitError::IdempotencyConflict)),
        "changed logical payload must conflict before trying the removed root: {changed_payload:?}"
    );
    assert_eq!(
        reopened_service.session_messages(&original.session_id),
        durable_messages_before
    );
    assert_eq!(
        reopened_service.run_events(&original.run_id),
        durable_events_before
    );
    drop(reopened_service);
    drop(reopened);
    fs::remove_dir_all(root).expect("remove private replay fixture");
}

#[test]
fn workspace_and_storage_rss_compile_against_production_host_catalog() {
    for relative in [
        "rss/agent/workspace.rss",
        "rss/storage/admission.rss",
        "rss/storage/sessions.rss",
        "rss/storage/main.rss",
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
        let source = fs::read_to_string(&path).expect("RSS source");
        let result = compile_source_at_path_with_flavor_and_options(
            &path,
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default()
                .with_host_api_catalog(rustscript_agent::runtime::agent_host_catalog()),
        );
        if let Err(error) = result {
            panic!("{relative} production compilation failed: {error:?}");
        }
    }
}
