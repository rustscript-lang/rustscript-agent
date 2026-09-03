//! Task 10 edge E2E: stop-during-terminal and output-limit through production
//! AgentService + bundled RSS + native tools with ScriptedProvider.
//!
//! Helpers are localized. The current service committer still requires a
//! durable assistant `tool_call` parent (`MissingParent`); `seed_tool_parent`
//! is idempotent if a later Task 9 cleanup starts committing that parent
//! itself.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::config::{ADMISSION_SESSION_PROFILE, FileToolConfig, RunLimits};
use rustscript_agent::tools::{ArtifactOwner, ArtifactStore};
use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, AgentProviderHost, AgentService,
    LlmContentBlock, RunCancellation, ScriptedProvider, ToolCall,
};
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;

const LEASE_TMP: &str = "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-t10-edge-e2e-485ce928";
const PYTHON: &str = "/usr/bin/python3";
const OUTPUT_CAP: u64 = 800;
const OVERFLOW_BYTES: usize = 4096;
const WAIT_BUDGET: Duration = Duration::from_secs(15);
const WORKER_BUDGET: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(5);

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    parent: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let parent = temp_root().join(format!(
            "{label}-{}-{}-{}",
            std::process::id(),
            sequence,
            Uuid::new_v4()
        ));
        let workspace = parent.join("workspace");
        fs::create_dir_all(&workspace).expect("edge e2e workspace");
        let workspace = fs::canonicalize(&workspace).expect("canonical workspace");
        Self { parent, workspace }
    }

    fn db_path(&self) -> PathBuf {
        self.parent.join("state.db")
    }

    fn artifact_root(&self) -> PathBuf {
        FileToolConfig::for_workspace(&self.workspace)
            .artifact_store
            .root
    }

    fn write_script(&self, name: &str, source: &str) {
        fs::write(self.workspace.join(name), source).expect("write workspace script");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

fn temp_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("TEST_TMPDIR") {
        let root = PathBuf::from(dir);
        fs::create_dir_all(&root).expect("TEST_TMPDIR");
        return root;
    }
    let root = PathBuf::from(LEASE_TMP);
    fs::create_dir_all(&root).expect("lease tmp");
    root
}

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

fn admit_request() -> AdmitRunRequest {
    AdmitRunRequest {
        input: json!({"message": "edge-e2e"}),
        platform: "coding_agent_edge_e2e_tests".to_string(),
        ..AdmitRunRequest::default()
    }
}

fn loop_service(config: AgentGatewayConfig, provider: &ScriptedProvider) -> AgentGatewayState {
    let state = AgentGatewayState::with_agent_source(config, agent_loop_source())
        .expect("bundled agent loop should compile");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
}

fn loop_service_sqlite(
    config: AgentGatewayConfig,
    provider: &ScriptedProvider,
    db: &Path,
) -> AgentGatewayState {
    let state = AgentGatewayState::with_agent_source_and_sqlite(config, agent_loop_source(), db)
        .expect("bundled agent loop with sqlite should compile");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
}

/// Holds the second provider call so artifact retrieval can happen before owner cleanup.
#[derive(Clone)]
struct SecondCallGate {
    provider: ScriptedProvider,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl SecondCallGate {
    fn new(provider: ScriptedProvider) -> Self {
        Self {
            provider,
            release: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    fn release(&self) {
        let (flag, cv) = &*self.release;
        *flag.lock().expect("gate flag") = true;
        cv.notify_all();
    }
}

impl AgentProviderHost for SecondCallGate {
    fn call(&self, request: &JsonValue, cancellation: &RunCancellation) -> JsonValue {
        let outcome = self.provider.call(request, cancellation);
        if self.provider.call_count() < 2 {
            return outcome;
        }
        let (flag, cv) = &*self.release;
        let mut ready = flag.lock().expect("gate flag");
        let deadline = Instant::now() + WAIT_BUDGET;
        while !*ready {
            if cancellation.requested().is_some() || cancellation.deadline_passed() {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (guard, _) = cv
                .wait_timeout(ready, deadline.saturating_duration_since(now))
                .expect("gate wait");
            ready = guard;
        }
        outcome
    }
}

fn apply_workspace_limits(service: &AgentService, workspace: &Path, max_tool_output_bytes: u64) {
    service
        .set_run_limits(RunLimits::new(8, 8, max_tool_output_bytes, workspace).expect("run limits"))
        .expect("set run limits");
}

/// Localized durable parent seed. Idempotent with `commit_provider_step`.
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

fn event_names(service: &AgentService, run_id: &str) -> Vec<String> {
    service
        .run_events(run_id)
        .into_iter()
        .filter_map(|event| event.get("event")?.as_str().map(str::to_string))
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

fn first_event_index(names: &[String], needle: &str) -> Option<usize> {
    names.iter().position(|name| name == needle)
}

async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    pred()
}

fn pid_alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let state = stat.split_whitespace().nth(2).unwrap_or("");
            state != "Z" && state != "X"
        }
        Err(_) => false,
    }
}

async fn wait_until_dead(pid: u32, timeout: Duration) -> bool {
    wait_until(timeout, || !pid_alive(pid)).await
}

fn parse_pid_file(path: &Path) -> Option<u32> {
    fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 1)
}

fn tool_result_blocks(request: &JsonValue) -> Vec<&JsonValue> {
    request
        .get("messages")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter(|message| message.get("role") == Some(&json!("user")))
        .flat_map(|message| {
            message
                .get("content")
                .and_then(JsonValue::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|block| block.get("type") == Some(&json!("tool_result")))
        .collect()
}

fn json_contains_path(value: &JsonValue, path: &Path) -> bool {
    let rendered = value.to_string();
    let candidates = [
        path.to_string_lossy().into_owned(),
        path.display().to_string(),
    ];
    candidates
        .iter()
        .any(|candidate| !candidate.is_empty() && rendered.contains(candidate))
}

fn durable_tool_result_messages(service: &AgentService, session_id: &str) -> Vec<JsonValue> {
    service
        .session_messages(session_id)
        .into_iter()
        .filter(|message| {
            message.get("role") == Some(&json!("user")) && message.get("tool_call_id").is_some()
        })
        .collect()
}

fn encoded_len(value: &JsonValue) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn u64_field(value: &JsonValue, key: &str) -> Option<u64> {
    value.get(key).and_then(JsonValue::as_u64)
}

fn sleeper_source() -> &'static str {
    r#"import os
import sys
import time

path = sys.argv[1]
with open(path, "w", encoding="utf-8") as handle:
    handle.write(str(os.getpid()))
    handle.flush()
    os.fsync(handle.fileno())
time.sleep(120)
"#
}

fn overflow_source() -> &'static str {
    r#"import sys

count = int(sys.argv[1])
sys.stdout.write("O" * count)
sys.stderr.write("E" * count)
sys.stdout.flush()
sys.stderr.flush()
"#
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_during_terminal_cancels_child_without_residue() {
    let fixture = Fixture::new("stop-terminal");
    fixture.write_script("sleeper.py", sleeper_source());
    let pid_name = "child.pid";
    let call = ToolCall {
        id: "call-stop-terminal".to_string(),
        name: "terminal".to_string(),
        arguments: json!({
            "argv": [PYTHON, "sleeper.py", pid_name],
            "timeout_ms": 120_000
        }),
    };
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("should-not-run"));

    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    apply_workspace_limits(&service, &fixture.workspace, 64 * 1024);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    seed_tool_parent(&service, &admitted.run_id, &call);

    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });

    let pid_path = fixture.workspace.join(pid_name);
    let started = wait_until(WAIT_BUDGET, || {
        service
            .run_events(&admitted.run_id)
            .iter()
            .any(|event| event.get("event") == Some(&json!("tool.started")))
            && service.process_owner_count(&admitted.run_id) > 0
            && parse_pid_file(&pid_path).is_some_and(pid_alive)
    })
    .await;
    assert!(
        started,
        "child PID/started event should be observed before stop: events={:?} owner={} pid={:?}",
        event_names(&service, &admitted.run_id),
        service.process_owner_count(&admitted.run_id),
        parse_pid_file(&pid_path)
    );
    let pid = parse_pid_file(&pid_path).expect("pid file");
    assert!(pid_alive(pid), "child {pid} should be live at stop");
    let live_store = service.native_artifact_store(&admitted.run_id);

    assert_eq!(service.stop(&admitted.run_id).as_deref(), Some("stopping"));
    tokio::time::timeout(WORKER_BUDGET, worker)
        .await
        .expect("worker should finish within the bounded wait")
        .expect("worker join");

    let terminals = terminal_events(&service, &admitted.run_id);
    assert_eq!(
        terminals,
        vec!["run.cancelled".to_string()],
        "exactly one durable terminal: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert_eq!(
        provider.call_count(),
        1,
        "stop during the live terminal must cancel the RSS loop before the next provider call"
    );

    let names = event_names(&service, &admitted.run_id);
    let requested = first_event_index(&names, "tool.requested").expect("tool.requested");
    let started_at = first_event_index(&names, "tool.started").expect("tool.started");
    let cancelled_at = first_event_index(&names, "run.cancelled").expect("run.cancelled");
    assert!(
        requested < started_at && started_at < cancelled_at,
        "lifecycle order tool.requested < tool.started < run.cancelled: {names:?}"
    );
    assert!(
        names.iter().filter(|name| *name == "run.cancelled").count() == 1
            && names
                .iter()
                .all(|name| name != "run.completed" && name != "run.failed"),
        "no extra terminal events: {names:?}"
    );

    assert!(
        wait_until_dead(pid, WAIT_BUDGET).await,
        "unix pid {pid} must be dead after stop"
    );
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert!(service.native_dispatch_closed(&admitted.run_id));
    assert!(!service.native_dispatch_retained(&admitted.run_id));
    let leftover = live_store
        .as_ref()
        .map(|store| store.object_count())
        .or_else(|| {
            ArtifactStore::with_config(
                FileToolConfig::for_workspace(&fixture.workspace).artifact_store,
            )
            .ok()
            .map(|store| store.object_count())
        })
        .unwrap_or(0);
    assert_eq!(
        leftover, 0,
        "stop-during-terminal must not leave artifact residue"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn output_limit_bounds_envelope_artifact_and_next_provider_request() {
    let fixture = Fixture::new("output-limit");
    fixture.write_script("overflow.py", overflow_source());
    let call = ToolCall {
        id: "call-output-limit".to_string(),
        name: "terminal".to_string(),
        arguments: json!({
            "argv": [PYTHON, "overflow.py", OVERFLOW_BYTES.to_string()],
            "timeout_ms": 10_000
        }),
    };
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("bounded-summary"));
    let gate = SecondCallGate::new(provider.clone());

    let state =
        AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), agent_loop_source())
            .expect("bundled agent loop should compile");
    let service = state.service();
    service.inject_provider_host(Arc::new(gate.clone()));
    apply_workspace_limits(&service, &fixture.workspace, OUTPUT_CAP);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    seed_tool_parent(&service, &admitted.run_id, &call);

    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(WAIT_BUDGET, || provider.call_count() >= 2).await,
        "second provider request should see the bounded tool_result: events={:?}",
        event_names(&service, &admitted.run_id)
    );
    let live_store = service
        .native_artifact_store(&admitted.run_id)
        .expect("artifact store stays live until owner cleanup");

    let requests = provider.requests();
    let second = &requests[1];
    let blocks = tool_result_blocks(second);
    assert_eq!(
        blocks.len(),
        1,
        "next provider request must see one tool_result: {second}"
    );
    let block = blocks[0];
    assert_eq!(block["tool_call_id"], json!(call.id));
    assert_eq!(block["truncated"], json!(true));
    let result = block.get("result").cloned().unwrap_or_else(|| json!({}));
    assert_eq!(result.get("truncated"), Some(&json!(true)));
    let envelope_len = encoded_len(&result);
    assert!(
        envelope_len <= OUTPUT_CAP as usize,
        "ToolResult envelope {envelope_len} exceeds cap {OUTPUT_CAP}: {result}"
    );
    let data = result
        .get("data")
        .cloned()
        .unwrap_or_else(|| result.clone());
    assert!(
        data.get("stdout_gap").is_some() && data.get("stderr_gap").is_some(),
        "gap fields must be present: {result}"
    );
    let omitted_stdout = u64_field(&data, "overflow_stdout_bytes").unwrap_or(0);
    let omitted_stderr = u64_field(&data, "overflow_stderr_bytes").unwrap_or(0);
    assert_eq!(
        omitted_stdout, OVERFLOW_BYTES as u64,
        "omitted stdout count: {result}"
    );
    assert_eq!(
        omitted_stderr, OVERFLOW_BYTES as u64,
        "omitted stderr count: {result}"
    );
    assert_eq!(
        u64_field(&data, "stdout_next_offset"),
        Some(OVERFLOW_BYTES as u64)
    );
    assert_eq!(
        u64_field(&data, "stderr_next_offset"),
        Some(OVERFLOW_BYTES as u64)
    );

    let artifact_ids = result
        .get("artifacts")
        .and_then(JsonValue::as_array)
        .cloned()
        .or_else(|| block.get("artifact").and_then(JsonValue::as_array).cloned())
        .unwrap_or_default();
    let artifact_id = artifact_ids
        .iter()
        .filter_map(JsonValue::as_str)
        .next()
        .map(str::to_string)
        .or_else(|| {
            block
                .get("artifact")
                .and_then(|value| value.get("id"))
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .expect("artifact ref");
    assert!(!artifact_id.is_empty(), "artifact id must be non-empty");
    assert!(
        !artifact_id.contains('/') && !artifact_id.contains('\\'),
        "artifact id must not look like a path: {artifact_id}"
    );

    let owner = ArtifactOwner::new(
        ADMISSION_SESSION_PROFILE,
        &admitted.session_id,
        &admitted.run_id,
    )
    .expect("artifact owner");
    let payload = live_store
        .retrieve(&owner, &artifact_id)
        .expect("owner can retrieve overflow artifact while the run is live");
    let text = String::from_utf8_lossy(&payload);
    assert!(
        text.contains("stdout:") && text.contains("stderr:"),
        "overflow artifact should keep labeled stdout/stderr: {text}"
    );
    assert!(
        text.contains('O') && text.contains('E'),
        "overflow artifact should retain truncated stream bytes: {text}"
    );
    assert_eq!(
        live_store.object_count(),
        1,
        "one overflow artifact retained while live"
    );

    let artifact_root = fixture.artifact_root();
    for value in [
        second,
        block,
        &result,
        &JsonValue::Array(service.run_events(&admitted.run_id)),
        &JsonValue::Array(durable_tool_result_messages(&service, &admitted.session_id)),
    ] {
        assert!(
            !json_contains_path(value, &artifact_root),
            "artifact path must not leak: {} in {value}",
            artifact_root.display()
        );
    }

    for message in durable_tool_result_messages(&service, &admitted.session_id) {
        assert!(
            encoded_len(&message) <= 64 * 1024,
            "durable tool_result message must stay bounded: {message}"
        );
        let content = message.get("content").cloned().unwrap_or(json!(null));
        assert!(
            content.to_string().contains("truncated")
                || content.to_string().contains(artifact_id.as_str()),
            "durable message should retain truncation/artifact metadata: {message}"
        );
    }
    for event in service.run_events(&admitted.run_id) {
        if matches!(
            event.get("event").and_then(JsonValue::as_str),
            Some("tool.output" | "tool.completed" | "tool.failed")
        ) {
            assert!(
                encoded_len(&event) <= 32 * 1024,
                "durable tool event must stay bounded: {event}"
            );
            assert!(
                event.pointer("/data/truncated") == Some(&json!(true))
                    || event
                        .pointer("/data/artifacts")
                        .and_then(JsonValue::as_array)
                        .is_some_and(|items| !items.is_empty()),
                "tool event should carry truncation or artifact metadata: {event}"
            );
        }
    }

    gate.release();
    tokio::time::timeout(WORKER_BUDGET, worker)
        .await
        .expect("output-limit worker should finish")
        .expect("worker join");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 2);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert!(service.native_dispatch_closed(&admitted.run_id));
    assert!(
        live_store.retrieve(&owner, &artifact_id).is_err(),
        "run-scoped artifact must be cleaned up with native dispatch"
    );
    assert_eq!(live_store.object_count(), 0);

    let completed = service
        .run_events(&admitted.run_id)
        .into_iter()
        .find(|event| event["event"] == "run.completed")
        .expect("completed terminal");
    assert!(
        completed.to_string().contains("bounded-summary"),
        "final summary should complete: {completed}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn completed_run_restart_does_not_reexecute_tools_or_double_metrics() {
    let fixture = Fixture::new("restart-replay");
    let call = ToolCall {
        id: "call-restart".to_string(),
        name: "terminal".to_string(),
        arguments: json!({
            "argv": ["/usr/bin/printf", "%s", "hello-edge"],
            "timeout_ms": 5_000
        }),
    };
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("restart-summary"));

    let db = fixture.db_path();
    let first = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &db);
    let service = first.service();
    apply_workspace_limits(&service, &fixture.workspace, 64 * 1024);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    seed_tool_parent(&service, &admitted.run_id, &call);
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("first worker should finish");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let before = service.metrics().snapshot();
    assert_eq!(before.tool_calls, 1);
    assert_eq!(before.turns, 2);
    assert_eq!(provider.call_count(), 2);
    let run_id = admitted.run_id.clone();
    drop(first);

    let resumed_provider = ScriptedProvider::new();
    resumed_provider.push_ok(text_response("must-not-run"));
    let resumed = loop_service_sqlite(AgentGatewayConfig::default(), &resumed_provider, &db);
    let resumed_service = resumed.service();
    tokio::time::timeout(WORKER_BUDGET, {
        let service = resumed_service.clone();
        let run_id = run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("restart worker should finish without hanging");

    assert_eq!(
        terminal_events(&resumed_service, &run_id),
        vec!["run.completed".to_string()],
        "reopen must not add another terminal: {:?}",
        resumed_service.run_events(&run_id)
    );
    assert_eq!(
        resumed_provider.call_count(),
        0,
        "completed restart must not call the provider again"
    );
    let after = resumed_service.metrics().snapshot();
    assert_eq!(after.tool_calls, 0, "metrics must not double-count tools");
    assert_eq!(after.model_calls, 0, "metrics must not double-count models");
    assert_eq!(after.turns, 0);
    assert_eq!(resumed_service.process_owner_count(&run_id), 0);
}
