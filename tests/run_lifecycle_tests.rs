//! Task 9: real service worker, unified cancellation/deadline, zero-residue cleanup.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustscript_agent::config::RunLimits;
use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, AgentService, LlmContentBlock,
    ScriptedProvider, ToolCall,
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

fn seed_sleep_tool_parent(service: &AgentService, run_id: &str) {
    service
        .commit_provider_step(
            run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some("call-sleep".to_string()),
                name: Some("terminal".to_string()),
                arguments_json: Some(
                    json!({
                        "argv": ["/bin/sleep", "30"],
                        "background": true,
                        "timeout_ms": 5000
                    })
                    .to_string(),
                ),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect("durable tool-call parent");
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

fn loop_service(config: AgentGatewayConfig, provider: &ScriptedProvider) -> AgentGatewayState {
    let state = AgentGatewayState::with_agent_source(config, agent_loop_source())
        .expect("bundled agent loop should compile");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
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

fn seed_tool_parent(service: &AgentService, run_id: &str, call: &ToolCall) {
    service
        .commit_provider_step(
            run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some(call.id.clone()),
                name: Some(call.name.clone()),
                arguments_json: Some(call.arguments.to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect("durable tool-call parent");
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
    seed_sleep_tool_parent(&service, &admitted.run_id);
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
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");
    assert!(spawned, "child process should be owned before stop");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
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
    seed_sleep_tool_parent(&service, &admitted.run_id);
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
        elapsed < Duration::from_millis(350),
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
    seed_tool_parent(&service, &admitted.run_id, &call);

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
    seed_tool_parent(&service, &admitted.run_id, &call);

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
    seed_tool_parent(&service, &admitted.run_id, &call);

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
