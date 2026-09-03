//! Task 9: real service worker, unified cancellation/deadline, zero-residue cleanup.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, AgentService, LlmContentBlock,
    ScriptedProvider,
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
