//! Task 9: real service worker, unified cancellation/deadline, zero-residue cleanup.

use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustscript_agent::config::{ProviderProfile, RunLimits};
use rustscript_agent::{
    AdmitRunRequest, AgentConfig, AgentGatewayConfig, AgentGatewayState, AgentRunner, AgentService,
    LlmContentBlock, ScriptedProvider, ToolCall,
};
use serde_json::{Value as JsonValue, json};

fn agent_loop_source() -> String {
    fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"))
        .expect("bundled rss/agent/main.rss should be readable")
}

fn text_response(text: &str) -> JsonValue {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

fn tool_response(text: &str, tool_calls: JsonValue) -> JsonValue {
    json!({
        "text": text,
        "tool_calls": tool_calls,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    })
}

fn background_sleep_call() -> JsonValue {
    json!([{
        "id": "call-sleep",
        "name": "terminal",
        "arguments": {
            "argv": ["/bin/sleep", "30"],
            "background": true,
            "timeout_ms": 5000
        }
    }])
}

fn admit_request() -> AdmitRunRequest {
    AdmitRunRequest {
        input: json!({"message": "hello"}),
        platform: "run_lifecycle_tests".to_string(),
        ..AdmitRunRequest::default()
    }
}

fn short_config(run_timeout: Duration) -> AgentGatewayConfig {
    AgentGatewayConfig {
        run_timeout,
        cancellation_grace: Duration::from_millis(80),
        ..AgentGatewayConfig::default()
    }
}

fn terminal_events(service: &AgentService, run_id: &str) -> Vec<String> {
    service
        .run_events(run_id)
        .into_iter()
        .filter_map(|event| {
            let name = event.get("event")?.as_str()?;
            matches!(name, "run.completed" | "run.cancelled" | "run.failed")
                .then(|| name.to_string())
        })
        .collect()
}

fn cancel_reason(service: &AgentService, run_id: &str) -> String {
    service
        .run_events(run_id)
        .into_iter()
        .find(|event| event["event"] == "run.cancelled")
        .and_then(|event| {
            event
                .pointer("/data/reason")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default()
}

async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

fn pid_alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let Some(close) = stat.rfind(')') else {
                return true;
            };
            let state = stat[close + 1..].split_whitespace().next().unwrap_or("");
            state != "Z"
        }
        Err(_) => false,
    }
}

fn failed_error_code(service: &AgentService, run_id: &str) -> String {
    service
        .run_events(run_id)
        .into_iter()
        .rev()
        .find_map(|event| {
            (event.get("event").and_then(JsonValue::as_str) == Some("run.failed"))
                .then(|| {
                    event
                        .pointer("/data/error_code")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string)
                })
                .flatten()
        })
        .unwrap_or_default()
}

fn loop_service(config: AgentGatewayConfig, provider: &ScriptedProvider) -> AgentGatewayState {
    let state = AgentGatewayState::with_agent_source(config, agent_loop_source())
        .expect("bundled agent loop should compile");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
}

fn temporary_db_path() -> PathBuf {
    let root = std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(
                "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-tools-agent-integration-c77be280",
            )
        });
    fs::create_dir_all(&root).expect("test database directory should exist");
    root.join(format!("{}.db", uuid::Uuid::new_v4()))
}

fn loop_service_sqlite(
    config: AgentGatewayConfig,
    provider: &ScriptedProvider,
    path: &std::path::Path,
) -> AgentGatewayState {
    let state = AgentGatewayState::with_agent_source_and_sqlite(config, agent_loop_source(), path)
        .expect("bundled agent loop should compile against sqlite");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
}

fn assistant_messages(service: &AgentService, session_id: &str) -> Vec<JsonValue> {
    service
        .session_messages(session_id)
        .into_iter()
        .filter(|message| message["role"] == "assistant")
        .collect()
}

fn event_names(service: &AgentService, run_id: &str) -> Vec<String> {
    service
        .run_events(run_id)
        .into_iter()
        .filter_map(|event| {
            event
                .get("event")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn tool_event_count(service: &AgentService, run_id: &str) -> usize {
    event_names(service, run_id)
        .into_iter()
        .filter(|name| name.starts_with("tool."))
        .count()
}

fn retryable_provider_error() -> JsonValue {
    json!({
        "status": 503,
        "type": "server_error",
        "code": "unavailable",
        "message": "down",
        "param": "",
        "request_id": "",
        "retryable": true
    })
}

fn activity_values(service: &AgentService) -> [u64; 5] {
    let snapshot = service.metrics().snapshot();
    [
        snapshot.model_calls,
        snapshot.tool_calls,
        snapshot.tool_failures,
        snapshot.turns,
        snapshot.truncations,
    ]
}

fn prometheus_counter(render: &str, name: &str) -> u64 {
    let prefix = format!("{name} ");
    let mut values = Vec::new();
    for line in render.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            if rest.starts_with('{') {
                continue;
            }
            values.push(
                rest.split_whitespace()
                    .next()
                    .expect("prometheus sample value")
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("{name} should be a u64, got {rest:?}")),
            );
        }
    }
    assert_eq!(
        values.len(),
        1,
        "{name} must have exactly one unlabelled sample, got {values:?} in:\n{render}"
    );
    values[0]
}

fn assert_prometheus_matches_snapshot(service: &AgentService) {
    let snapshot = service.metrics().snapshot();
    let render = service.metrics().render_prometheus();
    assert_eq!(
        prometheus_counter(&render, "agent_model_calls_total"),
        snapshot.model_calls
    );
    assert_eq!(
        prometheus_counter(&render, "agent_tool_calls_total"),
        snapshot.tool_calls
    );
    assert_eq!(
        prometheus_counter(&render, "agent_tool_failures_total"),
        snapshot.tool_failures
    );
    assert_eq!(
        prometheus_counter(&render, "agent_turns_total"),
        snapshot.turns
    );
    assert_eq!(
        prometheus_counter(&render, "agent_truncations_total"),
        snapshot.truncations
    );
}

fn assert_frozen_prompt_exactly_once(
    service: &AgentService,
    run_id: &str,
    provider: &ScriptedProvider,
) {
    let prompt = service
        .run_context(run_id)
        .expect("frozen context")
        .coding_system_prompt
        .expect("admission must freeze a coding system prompt");
    assert!(!prompt.is_empty(), "frozen coding prompt must be non-empty");
    let requests = provider.requests();
    assert!(
        !requests.is_empty(),
        "provider must observe at least one request"
    );
    for request in &requests {
        let messages = request["messages"]
            .as_array()
            .expect("provider request messages");
        let system: Vec<_> = messages
            .iter()
            .filter(|message| message["role"] == "system")
            .collect();
        assert_eq!(
            system.len(),
            1,
            "frozen prompt must appear as exactly one system message: {request}"
        );
        assert_eq!(messages[0]["role"], json!("system"));
        let text = messages[0]["content"][0]["text"]
            .as_str()
            .expect("system text");
        assert_eq!(text, prompt);
        for later in messages.iter().skip(1) {
            assert_ne!(
                later["content"][0]["text"].as_str(),
                Some(prompt.as_str()),
                "frozen prompt must not be duplicated into later messages"
            );
        }
    }
}

fn has_tool_result_event(service: &AgentService, run_id: &str, tool_call_id: &str) -> bool {
    service.run_events(run_id).into_iter().any(|event| {
        matches!(
            event.get("event").and_then(JsonValue::as_str),
            Some("tool.output" | "tool.completed" | "tool.failed")
        ) && event
            .pointer("/data/tool_call_id")
            .and_then(JsonValue::as_str)
            == Some(tool_call_id)
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn scripted_real_worker_completes_with_provider_answer() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("loop-ok"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let terminals = terminal_events(&service, &admitted.run_id);
    assert_eq!(
        terminals,
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let payload = service
        .run_events(&admitted.run_id)
        .into_iter()
        .find(|event| event["event"] == "run.completed")
        .expect("completed terminal");
    let rendered = payload.to_string();
    assert!(
        rendered.contains("loop-ok"),
        "completed output should carry the scripted answer: {rendered}"
    );
    assert_eq!(provider.call_count(), 1);
    assert!(!service.native_dispatch_retained(&admitted.run_id));
    assert!(service.native_dispatch_closed(&admitted.run_id));
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_hanging_provider_cancels_once() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(5), || provider.call_count() >= 1).await,
        "provider should enter the hanging call"
    );
    assert_eq!(service.stop(&admitted.run_id).as_deref(), Some("stopping"));
    worker.await.expect("worker join");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert!(service.native_dispatch_closed(&admitted.run_id));
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_terminates_child_process_without_residue() {
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response("", background_sleep_call()));
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    let spawned = wait_until(Duration::from_secs(8), || {
        service.process_owner_count(&admitted.run_id) > 0
    })
    .await;
    assert!(spawned, "child process should be owned before stop");
    let pids = service.process_owner_pids(&admitted.run_id);
    assert!(!pids.is_empty());
    for pid in &pids {
        assert!(
            pid_alive(*pid),
            "owned PID {pid} should be live before stop"
        );
    }
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    for pid in pids {
        assert!(!pid_alive(pid), "PID {pid} should be dead after cleanup");
    }
    assert!(service.native_dispatch_closed(&admitted.run_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_terminates_child_process_without_residue() {
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response("", background_sleep_call()));
    provider.push_hang();
    let state = loop_service(short_config(Duration::from_millis(250)), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let started = Instant::now();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let elapsed = started.elapsed();

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "deadline");
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert!(service.native_dispatch_closed(&admitted.run_id));
    assert!(
        elapsed < Duration::from_secs(2),
        "deadline should not wait for the child sleep: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_is_cumulative_from_admission() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let timeout = Duration::from_millis(400);
    let state = loop_service(short_config(timeout), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let remaining = service
        .handle(&admitted.run_id)
        .expect("live handle")
        .cancellation()
        .remaining_deadline()
        .expect("deadline");
    assert!(
        remaining < timeout,
        "remaining deadline {remaining:?} must be less than the original {timeout:?}"
    );
    assert!(remaining > Duration::from_millis(20));
    let started = Instant::now();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let elapsed = started.elapsed();

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "deadline");
    assert!(
        elapsed < timeout,
        "worker should observe remaining deadline, not a fresh {timeout:?}: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn race_stop_and_completion_commits_exactly_one_terminal() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("race-ok"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");

    let terminals = terminal_events(&service, &admitted.run_id);
    assert_eq!(terminals.len(), 1, "{terminals:?}");
    assert!(
        terminals[0] == "run.completed" || terminals[0] == "run.cancelled",
        "race must commit exactly one terminal: {terminals:?}"
    );
    assert!(service.native_dispatch_closed(&admitted.run_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn persisted_restart_fails_typed_when_wall_deadline_expired() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(short_config(Duration::from_millis(80)), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let context = service
        .run_context(&admitted.run_id)
        .expect("frozen context");
    assert!(
        context
            .metadata
            .get("created_at_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "admission must freeze created_at_ms"
    );
    assert!(
        context
            .metadata
            .get("deadline_at_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "admission must freeze deadline_at_ms"
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    service.evict_run_handle(&admitted.run_id);

    let started = Instant::now();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let elapsed = started.elapsed();

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "deadline");
    assert_eq!(provider.call_count(), 0);
    assert!(
        elapsed < Duration::from_millis(400),
        "expired restart must not grant a fresh timeout: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_success_multi_turn_and_prometheus_matches_snapshot() {
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-read".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("done"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(activity_values(&service), [2, 1, 0, 2, 0]);
    assert_prometheus_matches_snapshot(&service);
    assert_frozen_prompt_exactly_once(&service, &admitted.run_id, &provider);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert!(service.native_dispatch_closed(&admitted.run_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_retryable_failure_then_success_without_turn_on_retry() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_ok(text_response("recovered"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 2);
    assert_eq!(activity_values(&service), [2, 0, 0, 1, 0]);
    assert_prometheus_matches_snapshot(&service);
    assert_frozen_prompt_exactly_once(&service, &admitted.run_id, &provider);
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_retry_exhaustion_without_turns() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_error(retryable_provider_error());
    provider.push_error(retryable_provider_error());
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 3);
    assert_eq!(activity_values(&service), [3, 0, 0, 0, 0]);
    assert_prometheus_matches_snapshot(&service);
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_truncated_tool_result_once() {
    let root = PathBuf::from(
        "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-tools-agent-integration-c77be280",
    )
    .join(format!("trunc-{}", std::process::id()));
    fs::create_dir_all(&root).expect("truncation workspace");
    fs::write(root.join("big.txt"), "x".repeat(4096)).expect("truncated fixture");
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-trunc".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "big.txt"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("after-trunc"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    service
        .set_run_limits(RunLimits::new(8, 8, 512, &root).expect("limits"))
        .expect("set run limits");
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let snapshot = service.metrics().snapshot();
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(snapshot.model_calls, 2);
    assert_eq!(snapshot.turns, 2);
    assert_eq!(snapshot.tool_calls, 1);
    assert_eq!(snapshot.truncations, 1);
    assert_prometheus_matches_snapshot(&service);
    let _ = fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_tool_replay_does_not_increment_activity() {
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-replay".to_string(),
        name: "not_a_real_tool".to_string(),
        arguments: json!({"path": "a.txt"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    let worker = {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        tokio::spawn(async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        })
    };
    assert!(
        wait_until(Duration::from_secs(2), || {
            has_tool_result_event(&service, &admitted.run_id, &call.id)
        })
        .await,
        "worker should commit the first tool result: {:?}",
        service.run_events(&admitted.run_id)
    );
    let before = activity_values(&service);
    assert_eq!(before, [1, 1, 1, 1, 0]);
    let replayed = service
        .dispatch_tools(&admitted.run_id, std::slice::from_ref(&call))
        .expect("durable replay");
    assert_eq!(replayed.len(), 1);
    assert!(!replayed[0].ok);
    assert_eq!(activity_values(&service), before);
    assert_prometheus_matches_snapshot(&service);

    service.stop(&admitted.run_id);
    worker.await.expect("worker join");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uncooperative_dispatcher_cleanup_is_bounded_and_fail_closed() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("ok"));
    let mut config = short_config(Duration::from_secs(8));
    config.cancellation_grace = Duration::from_millis(80);
    let state = loop_service(config, &provider);
    let service = state.service();
    service.inject_uncooperative_dispatch();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let started = Instant::now();
    let finished = tokio::time::timeout(
        Duration::from_secs(3),
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string()),
    )
    .await;
    let elapsed = started.elapsed();
    service.release_uncooperative_dispatch();
    assert!(
        finished.is_ok(),
        "uncooperative dispatcher must not block cleanup indefinitely: {elapsed:?}"
    );
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        failed_error_code(&service, &admitted.run_id),
        "cleanup_timeout"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "uncooperative dispatcher must not block cleanup indefinitely: {elapsed:?}"
    );
    assert!(service.native_dispatch_closed(&admitted.run_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_stopping_requests_cancel_before_provider() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    assert_eq!(service.stop(&admitted.run_id).as_deref(), Some("stopping"));
    service.evict_run_handle(&admitted.run_id);
    tokio::time::timeout(
        Duration::from_secs(4),
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("restore stopping must stay bounded");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert_eq!(provider.call_count(), 0);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_runner_uses_http_sqlite_and_fuel_and_rejects_stale_cache() {
    let mut config = AgentGatewayConfig::default();
    config.http.allowed_hosts = vec!["example.test".to_string()];
    config.sqlite.database_root = Some("/tmp/agent-sqlite-task9".to_string());
    config.fuel = Some(12_345);
    let state = AgentGatewayState::with_agent_source(config, agent_loop_source())
        .expect("compile gateway agent");
    let service = state.service();
    let installed = service
        .cached_runner_config()
        .expect("gateway should install a runner");
    assert_eq!(installed.http.allowed_hosts, ["example.test"]);
    assert_eq!(
        installed.sqlite.database_root.as_deref(),
        Some("/tmp/agent-sqlite-task9")
    );
    assert_eq!(installed.fuel, Some(12_345));

    let stale = AgentRunner::from_source(&agent_loop_source(), AgentConfig::default())
        .expect("compile default runner");
    service.install_agent_runner(stale);
    assert_ne!(
        service.cached_runner_config().expect("stale cache").fuel,
        Some(12_345)
    );
    let refreshed = service
        .materialize_cached_runner()
        .expect("rebuild stale runner");
    assert_eq!(refreshed.http.allowed_hosts, ["example.test"]);
    assert_eq!(refreshed.fuel, Some(12_345));
}

#[tokio::test(flavor = "multi_thread")]
async fn huge_persisted_deadline_restore_fails_typed_without_panic() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service.set_context_deadline_at_ms(&admitted.run_id, u64::MAX);
    service.evict_run_handle(&admitted.run_id);
    tokio::time::timeout(
        Duration::from_secs(4),
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("huge deadline restore must not hang");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()]
    );
    assert_eq!(
        failed_error_code(&service, &admitted.run_id),
        "invalid_deadline"
    );
    assert_eq!(provider.call_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn injected_provider_is_one_shot_and_second_run_uses_default() {
    let hang = ScriptedProvider::new();
    hang.push_hang();
    let ok = ScriptedProvider::new();
    ok.push_ok(text_response("second-ok"));
    let state =
        AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), agent_loop_source())
            .expect("compile");
    let service = state.service();
    service.inject_provider_host(Arc::new(hang.clone()));
    service.inject_provider_host(Arc::new(ok.clone()));
    let first = service.admit(admit_request()).await.expect("admit first");
    tokio::time::timeout(
        Duration::from_secs(8),
        service
            .clone()
            .run_worker(first.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("first injected run");
    assert_eq!(
        terminal_events(&service, &first.run_id),
        vec!["run.completed".to_string()]
    );
    assert_eq!(ok.call_count(), 1);
    assert_eq!(hang.call_count(), 0);

    let second = service.admit(admit_request()).await.expect("admit second");
    tokio::time::timeout(
        Duration::from_secs(8),
        service
            .clone()
            .run_worker(second.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("second run without inject must not hang on the consumed host");
    assert_eq!(
        ok.call_count(),
        1,
        "one-shot inject must not leak to the second run"
    );
    assert_eq!(hang.call_count(), 0);
    assert_eq!(
        terminal_events(&service, &second.run_id).len(),
        1,
        "second run must still commit a terminal without the injected host: {:?}",
        service.run_events(&second.run_id)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_backoff_sleep_is_interrupted_by_stop() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(4), || provider.call_count() >= 1).await,
        "first retryable provider error should land"
    );
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_expired_restart_keeps_remaining_deadline() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let timeout = Duration::from_secs(5);
    let state = loop_service(short_config(timeout), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    tokio::time::sleep(Duration::from_millis(400)).await;
    service.evict_run_handle(&admitted.run_id);
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(4), || provider.call_count() >= 1).await,
        "restored worker should reach the hang"
    );
    let remaining = service
        .handle(&admitted.run_id)
        .expect("restored handle")
        .cancellation()
        .remaining_deadline()
        .expect("deadline");
    assert!(
        remaining < timeout - Duration::from_millis(200),
        "restart must keep the remaining deadline, not a fresh {timeout:?}: {remaining:?}"
    );
    assert!(remaining > Duration::from_millis(100));
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");
}

#[tokio::test(flavor = "multi_thread")]
async fn hanging_http_adapter_stop_cancels() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind hang server");
    let port = listener.local_addr().expect("local addr").port();
    let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepted_flag = Arc::clone(&accepted);
    let server = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            accepted_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            thread::sleep(Duration::from_secs(30));
            drop(stream);
        }
    });
    let mut config = short_config(Duration::from_secs(8));
    config.http.allowed_hosts = vec!["127.0.0.1".to_string()];
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_ports = vec![port];
    config.http.allow_private_ips = true;
    let state = AgentGatewayState::with_agent_source(config, agent_loop_source())
        .expect("compile adapter run");
    let service = state.service();
    service.upsert_provider_profile(
        ProviderProfile::new(
            "local-agent",
            json!({ "base_url": format!("http://127.0.0.1:{port}") }),
        )
        .expect("profile"),
    );
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(4), || {
            accepted.load(std::sync::atomic::Ordering::SeqCst)
        })
        .await,
        "RssAdapterProvider should connect to the hanging HTTP server"
    );
    let _ = service.stop(&admitted.run_id);
    tokio::time::timeout(Duration::from_secs(6), worker)
        .await
        .expect("hanging HTTP stop must stay bounded")
        .expect("worker join");
    let terminals = terminal_events(&service, &admitted.run_id);
    assert_eq!(
        terminals.len(),
        1,
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert!(
        terminals[0] == "run.cancelled" || terminals[0] == "run.failed",
        "stop must commit a typed terminal, got {terminals:?}"
    );
    drop(server);
}

#[tokio::test(flavor = "multi_thread")]
async fn first_tool_effect_succeeds_with_parent_already_durable() {
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-parent".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("after-tool"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let names = event_names(&service, &admitted.run_id);
    let completed = names
        .iter()
        .position(|name| name == "model.completed")
        .expect("provider step must be durable before tools");
    let tool_started = names
        .iter()
        .position(|name| name.starts_with("tool."))
        .expect("tool effect must run");
    assert!(
        completed < tool_started,
        "durable provider parent must precede tool events: {names:?}"
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    let parent = assistants
        .iter()
        .find(|message| {
            message["content"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|block| {
                    block["type"] == "tool_call" && block["tool_call_id"] == json!(call.id)
                })
        })
        .expect("assistant tool_call parent");
    let parent_id = parent["id"].as_str().expect("parent id");
    let tool_messages: Vec<_> = service
        .session_messages(&admitted.session_id)
        .into_iter()
        .filter(|message| message["tool_call_id"] == json!(call.id))
        .collect();
    assert!(
        !tool_messages.is_empty(),
        "tool result message should exist"
    );
    assert!(
        tool_messages
            .iter()
            .all(|message| message["parent_message_id"] == json!(parent_id)),
        "tool result parent_message_id must point at the durable assistant: {tool_messages:?}"
    );
    assert_eq!(provider.call_count(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn persist_failpoint_leaves_executor_count_zero() {
    let path = temporary_db_path();
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-persist-fail".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("should-not-run"));
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &path);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    state
        .persistence()
        .expect("sqlite persistence")
        .inject_fail_after_partial_write();

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let failed = service
        .run_events(&admitted.run_id)
        .into_iter()
        .find(|event| event["event"] == "run.failed")
        .expect("failed terminal");
    let rendered = failed.to_string();
    assert!(
        rendered.contains("provider_step_persist_failed")
            || rendered.contains("failed to persist provider step"),
        "persist failure must be typed: {rendered}"
    );
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert_eq!(provider.call_count(), 1);
    drop(state);
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread")]
async fn post_commit_crash_restart_replays_provider_and_runs_tool_once() {
    let path = temporary_db_path();
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-crash".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("after-restart"));
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &path);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service.inject_crash_after_provider_commit();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert!(
        terminal_events(&service, &admitted.run_id).is_empty(),
        "crash after commit must leave the run started: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 1);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    // Process restart of leftover running runs is `gateway_restart`. This
    // seam is a worker crash after the provider step is durable: evict the
    // live handle and resume the same started run so replay, not a second
    // inner call, drives tool dispatch.
    service.evict_run_handle(&admitted.run_id);
    service.inject_provider_host(Arc::new(provider.clone()));
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        provider.call_count(),
        2,
        "restart must replay the committed provider step without a second inner call"
    );
    assert_eq!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        2
    );
    assert!(has_tool_result_event(&service, &admitted.run_id, &call.id));
    drop(state);
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread")]
async fn final_text_commits_one_assistant_row() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("only-once"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()]
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    assert_eq!(
        assistants.len(),
        1,
        "provider step already stored the assistant text: {assistants:?}"
    );
    let rendered = assistants[0].to_string();
    assert!(
        rendered.contains("only-once"),
        "assistant row must keep the provider text: {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tool_call_and_text_combined_are_preserved() {
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-combined".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "thinking",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("done"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    let combined = assistants
        .iter()
        .find(|message| {
            let blocks = message["content"].as_array().cloned().unwrap_or_default();
            blocks
                .iter()
                .any(|block| block["type"] == "text" && block["text"] == "thinking")
                && blocks.iter().any(|block| {
                    block["type"] == "tool_call" && block["tool_call_id"] == json!(call.id)
                })
        })
        .expect("combined text+tool_call assistant");
    assert!(
        combined["content"]
            .as_array()
            .expect("blocks")
            .iter()
            .any(|block| block["arguments_json"].as_str()
                == Some(call.arguments.to_string().as_str())
                || block["arguments"] == call.arguments),
        "tool_call arguments must be preserved: {combined}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_and_retry_provider_ordinals_are_stable() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_ok(text_response("stable"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()]
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    assert_eq!(
        assistants.len(),
        1,
        "retryable failure must not create an assistant row: {assistants:?}"
    );
    let _ordinal = assistants[0]["ordinal"].as_u64();
    assert!(
        _ordinal.is_some(),
        "committed assistant must have an ordinal"
    );

    let fresh = loop_service(AgentGatewayConfig::default(), &ScriptedProvider::new());
    let service = fresh.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("fresh admit should succeed");
    let run_id = admitted.run_id.clone();
    let blocks = [LlmContentBlock {
        block_type: "text".to_string(),
        text: Some("stable".to_string()),
        ..LlmContentBlock::default()
    }];
    let left = {
        let service = service.clone();
        let run_id = run_id.clone();
        let blocks = blocks.clone();
        thread::spawn(move || {
            service.commit_provider_step(&run_id, 1, &blocks, None, Some("stop"), None, None, None)
        })
    };
    let right = {
        let service = service.clone();
        let run_id = run_id.clone();
        let blocks = blocks.clone();
        thread::spawn(move || {
            service.commit_provider_step(&run_id, 1, &blocks, None, Some("stop"), None, None, None)
        })
    };
    let left_commit = left.join().expect("left join").expect("left commit");
    let right_commit = right.join().expect("right join").expect("right commit");
    assert_eq!(left_commit.message_id(), right_commit.message_id());
    assert_eq!(left_commit.envelope(), right_commit.envelope());
    let after = assistant_messages(&service, &admitted.session_id);
    assert_eq!(
        after.len(),
        1,
        "concurrent replay must not duplicate ordinals"
    );
    assert_eq!(after[0]["id"].as_str(), Some(left_commit.message_id()));
    let concurrent_ordinals: Vec<_> = after
        .iter()
        .filter_map(|message| message["ordinal"].as_u64())
        .collect();
    assert_eq!(concurrent_ordinals.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_workers_occupy_run_once() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service.admit(admit_request()).await.expect("admit");
    let worker1 = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(2), || provider.call_count() == 1).await,
        "first worker should occupy the provider call"
    );
    let worker2 = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    tokio::time::timeout(Duration::from_millis(400), worker2)
        .await
        .expect("second worker must return while first occupies")
        .expect("second worker join");
    assert_eq!(provider.call_count(), 1);
    service.stop(&admitted.run_id);
    worker1.await.expect("first worker");
    assert_eq!(provider.call_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_ok_envelope_does_not_commit_durable_success() {
    let provider = ScriptedProvider::new();
    provider.push_envelope(json!({
        "ok": true,
        "response": "not-an-object",
        "error": {}
    }));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service.admit(admit_request()).await.expect("admit");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        event_names(&service, &admitted.run_id)
            .into_iter()
            .filter(|name| name == "model.completed")
            .count(),
        0,
        "malformed envelope must not persist model.completed: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert!(
        assistant_messages(&service, &admitted.session_id).is_empty(),
        "malformed envelope must not persist an assistant step"
    );
    assert_ne!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()]
    );
}
