//! Task 10 edge E2E: stop-during-terminal, output-limit, and durable provider
//! recovery through production AgentService + bundled RSS + native tools.
//!
//! `ScriptedProvider` is injected as the inner model transport. Production
//! `DurableProviderHost` commits provider steps, replays completed turns, and
//! fail-closes unsafe pending requests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::config::{FileToolConfig, RunLimits};

use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, AgentProviderHost, AgentService,
    RunCancellation, ScriptedProvider, ToolCall, decode_message_blocks,
};
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;

const OUTPUT_CAP: u64 = 800;
const OVERFLOW_BYTES: usize = 4096;
const WAIT_BUDGET: Duration = Duration::from_secs(15);
const WORKER_BUDGET: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(5);

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn test_temp_root() -> PathBuf {
    std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn lookup_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn locate_sh() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        for candidate in ["/bin/sh", "/usr/bin/sh"] {
            let path = PathBuf::from(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
        lookup_in_path("sh")
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn require_sh() -> PathBuf {
    locate_sh().unwrap_or_else(|| {
        #[cfg(unix)]
        panic!("unix coding edge e2e requires sh at /bin/sh, /usr/bin/sh, or PATH");
        #[cfg(not(unix))]
        panic!("coding edge e2e requires POSIX sh")
    })
}

struct Fixture {
    parent: PathBuf,
    workspace: PathBuf,
    cleaned: bool,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let parent = test_temp_root().join(format!(
            "{label}-{}-{}-{}",
            std::process::id(),
            sequence,
            Uuid::new_v4()
        ));
        if parent.exists() {
            fs::remove_dir_all(&parent).expect("stale edge fixture");
        }
        let workspace = parent.join("workspace");
        fs::create_dir_all(&workspace).expect("edge e2e workspace");
        let workspace = fs::canonicalize(&workspace).expect("canonical workspace");
        Self {
            parent,
            workspace,
            cleaned: false,
        }
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

    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        if self.parent.exists() {
            fs::remove_dir_all(&self.parent).unwrap_or_else(|error| {
                panic!("edge fixture cleanup {}: {error}", self.parent.display())
            });
        }
        assert!(
            !self.parent.exists(),
            "edge fixture root must be removed: {}",
            self.parent.display()
        );
        self.cleaned = true;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.cleaned && self.parent.exists() {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }
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

fn event_name_count(service: &AgentService, run_id: &str, name: &str) -> usize {
    event_names(service, run_id)
        .into_iter()
        .filter(|event| event == name)
        .count()
}

fn tool_event_count(service: &AgentService, run_id: &str) -> usize {
    event_names(service, run_id)
        .into_iter()
        .filter(|event| event.starts_with("tool."))
        .count()
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

fn json_opt_str<'a>(value: &'a JsonValue, key: &str) -> Option<&'a str> {
    value.get(key).and_then(JsonValue::as_str)
}

fn message_id(message: &JsonValue) -> &str {
    json_opt_str(message, "id").unwrap_or_else(|| panic!("message id: {message}"))
}

fn run_messages<'a>(messages: &'a [JsonValue], run_id: &str) -> Vec<&'a JsonValue> {
    messages
        .iter()
        .filter(|message| message.get("run_id").and_then(JsonValue::as_str) == Some(run_id))
        .collect()
}

fn assistant_tool_call<'a>(messages: &'a [&'a JsonValue], call_id: &str) -> &'a JsonValue {
    messages
        .iter()
        .copied()
        .find(|message| {
            json_opt_str(message, "role") == Some("assistant")
                && decode_message_blocks(&message["content"])
                    .iter()
                    .any(|block| {
                        block.block_type == "tool_call"
                            && block.tool_call_id.as_deref() == Some(call_id)
                    })
        })
        .unwrap_or_else(|| panic!("assistant tool_call {call_id}"))
}

fn user_tool_result<'a>(messages: &'a [&'a JsonValue], call_id: &str) -> &'a JsonValue {
    messages
        .iter()
        .copied()
        .find(|message| {
            json_opt_str(message, "role") == Some("user")
                && json_opt_str(message, "tool_call_id") == Some(call_id)
        })
        .unwrap_or_else(|| panic!("user tool_result {call_id}"))
}

fn assert_exact_parent_name_ordinal(
    result: &JsonValue,
    parent: &JsonValue,
    name: &str,
    ordinal: i64,
) {
    assert_eq!(
        json_opt_str(result, "parent_message_id"),
        Some(message_id(parent)),
        "tool_result parent must be the assistant tool_call: result={result} parent={parent}"
    );
    assert_eq!(
        json_opt_str(result, "name"),
        Some(name),
        "tool_result name: {result}"
    );
    assert_eq!(
        result.get("ordinal").and_then(JsonValue::as_i64),
        Some(ordinal),
        "tool_result ordinal: {result}"
    );
    assert_eq!(
        parent.get("ordinal").and_then(JsonValue::as_i64),
        Some(ordinal - 1),
        "assistant tool_call ordinal: {parent}"
    );
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

#[cfg(target_os = "linux")]
fn pid_alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let state = stat.split_whitespace().nth(2).unwrap_or("");
            state != "Z" && state != "X"
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
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

fn sleeper_source() -> String {
    "printf '%s\\n' \"$$\" > \"$1\"\nsleep 120\n".to_string()
}

fn overflow_source(count: usize) -> String {
    format!(
        "printf '%s' '{stdout}'\nprintf '%s' '{stderr}' >&2\n",
        stdout = "O".repeat(count),
        stderr = "E".repeat(count)
    )
}

fn hello_source() -> &'static str {
    "printf '%s\\n' 'hello-edge'\n"
}

fn once_source() -> &'static str {
    "printf x >> counter.txt\n"
}

fn sh_arg(sh: &Path) -> String {
    sh.to_str().expect("sh path should be utf-8").to_string()
}

fn assert_stop_lifecycle(names: &[String]) {
    let requested = first_event_index(names, "tool.requested").expect("tool.requested");
    let started_at = first_event_index(names, "tool.started").expect("tool.started");
    let tool_end = first_event_index(names, "tool.failed")
        .or_else(|| first_event_index(names, "tool.cancelled"))
        .expect("tool.failed or tool.cancelled");
    let cancelled_at = first_event_index(names, "run.cancelled").expect("run.cancelled");
    assert!(
        requested < started_at && started_at < tool_end && tool_end < cancelled_at,
        "lifecycle order tool.requested < tool.started < tool.failed/cancelled < run.cancelled: {names:?}"
    );
    assert!(
        names.iter().filter(|name| *name == "run.cancelled").count() == 1
            && names
                .iter()
                .all(|name| name != "run.completed" && name != "run.failed"),
        "no extra terminal events: {names:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_during_terminal_cancels_child_without_residue() {
    let Some(_) = locate_sh() else {
        #[cfg(unix)]
        panic!("unix coding edge e2e requires sh at /bin/sh, /usr/bin/sh, or PATH");
        #[cfg(not(unix))]
        {
            eprintln!("skipping stop-during-terminal without POSIX sh");
            return;
        }
    };
    let sh = require_sh();
    let mut fixture = Fixture::new("stop-terminal");
    fixture.write_script("sleeper.sh", &sleeper_source());
    let pid_name = "child.pid";
    let call = ToolCall {
        id: "call-stop-terminal".to_string(),
        name: "terminal".to_string(),
        arguments: json!({
            "argv": [sh_arg(&sh), "sleeper.sh", pid_name],
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

    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });

    let pid_path = fixture.workspace.join(pid_name);
    let started = wait_until(WAIT_BUDGET, || {
        let started_event = service
            .run_events(&admitted.run_id)
            .iter()
            .any(|event| event.get("event") == Some(&json!("tool.started")));
        let owned = service.process_owner_count(&admitted.run_id) > 0;
        if !started_event || !owned {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            parse_pid_file(&pid_path).is_some_and(pid_alive)
        }
        #[cfg(not(target_os = "linux"))]
        {
            true
        }
    })
    .await;
    assert!(
        started,
        "child PID/started event should be observed before stop: events={:?} owner={} pid={:?}",
        event_names(&service, &admitted.run_id),
        service.process_owner_count(&admitted.run_id),
        parse_pid_file(&pid_path)
    );
    #[cfg(target_os = "linux")]
    {
        let pid = parse_pid_file(&pid_path).expect("pid file");
        assert!(pid_alive(pid), "child {pid} should be live at stop");
    }
    let live_ids = service.native_artifact_ids(&admitted.run_id);

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
    assert_stop_lifecycle(&names);

    let messages = service.session_messages(&admitted.session_id);
    let chain = run_messages(&messages, &admitted.run_id);
    let parent = assistant_tool_call(&chain, &call.id);
    let result = user_tool_result(&chain, &call.id);
    assert_eq!(
        json_opt_str(parent, "parent_message_id"),
        Some(message_id(chain[0])),
        "assistant tool_call parent is the durable user admission message"
    );
    assert_exact_parent_name_ordinal(result, parent, "terminal", 3);
    let result_blocks = decode_message_blocks(&result["content"]);
    let result_block = result_blocks
        .iter()
        .find(|block| block.block_type == "tool_result")
        .expect("tool_result block");
    assert_eq!(result_block.tool_call_id.as_deref(), Some(call.id.as_str()));
    assert_eq!(result_block.name.as_deref(), None);
    assert_eq!(result_block.is_error, Some(true));

    #[cfg(target_os = "linux")]
    {
        let pid = parse_pid_file(&pid_path).expect("pid file");
        assert!(
            wait_until_dead(pid, WAIT_BUDGET).await,
            "linux pid {pid} must be dead after stop"
        );
    }
    assert_eq!(
        service.process_owner_count(&admitted.run_id),
        0,
        "ProcessTable owner count is the portable PID fallback"
    );
    assert!(service.native_dispatch_closed(&admitted.run_id));
    assert!(!service.native_dispatch_retained(&admitted.run_id));
    let leftover = live_ids.map(|ids| ids.len()).unwrap_or(0);
    assert_eq!(
        leftover, 0,
        "stop-during-terminal must not leave artifact residue"
    );
    fixture.cleanup();
}

#[tokio::test(flavor = "multi_thread")]
async fn output_limit_bounds_envelope_artifact_and_next_provider_request() {
    let Some(_) = locate_sh() else {
        #[cfg(unix)]
        panic!("unix coding edge e2e requires sh at /bin/sh, /usr/bin/sh, or PATH");
        #[cfg(not(unix))]
        {
            eprintln!("skipping output-limit without POSIX sh");
            return;
        }
    };
    let sh = require_sh();
    let mut fixture = Fixture::new("output-limit");
    fixture.write_script("overflow.sh", &overflow_source(OVERFLOW_BYTES));
    let call = ToolCall {
        id: "call-output-limit".to_string(),
        name: "terminal".to_string(),
        arguments: json!({
            "argv": [sh_arg(&sh), "overflow.sh"],
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
    let live_ids = service
        .native_artifact_ids(&admitted.run_id)
        .unwrap_or_default();

    let requests = provider.requests();
    assert_eq!(
        requests.len(),
        2,
        "provider follow-up must be bounded to one tool_result request plus the original: {requests:?}"
    );
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
    assert_eq!(
        data.get("stdout_gap"),
        Some(&json!(false)),
        "stdout captured from offset 0: {result}"
    );
    assert_eq!(
        data.get("stderr_gap"),
        Some(&json!(false)),
        "stderr captured from offset 0: {result}"
    );
    assert_eq!(
        u64_field(&data, "overflow_stdout_bytes"),
        Some(OVERFLOW_BYTES as u64),
        "omitted stdout count: {result}"
    );
    assert_eq!(
        u64_field(&data, "overflow_stderr_bytes"),
        Some(OVERFLOW_BYTES as u64),
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

    assert!(
        live_ids.iter().any(|id| id == &artifact_id),
        "overflow artifact {artifact_id} should be live: {live_ids:?}"
    );
    assert_eq!(
        live_ids.len(),
        1,
        "one overflow artifact retained while live"
    );

    let messages = service.session_messages(&admitted.session_id);
    let chain = run_messages(&messages, &admitted.run_id);
    let parent = assistant_tool_call(&chain, &call.id);
    let durable_result = user_tool_result(&chain, &call.id);
    assert_eq!(
        json_opt_str(parent, "parent_message_id"),
        Some(message_id(chain[0])),
        "assistant tool_call parent is the durable user admission message"
    );
    assert_exact_parent_name_ordinal(durable_result, parent, "terminal", 3);

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
            assert_eq!(
                event.pointer("/data/truncated"),
                Some(&json!(true)),
                "tool event truncation=true: {event}"
            );
            assert!(
                event
                    .pointer("/data/artifacts")
                    .and_then(JsonValue::as_array)
                    .is_some_and(|items| !items.is_empty()),
                "tool event should carry artifact metadata: {event}"
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
    assert_eq!(
        service
            .native_artifact_ids(&admitted.run_id)
            .unwrap_or_default()
            .len(),
        0,
        "run-scoped artifacts must be cleaned up with capability host"
    );

    let completed = service
        .run_events(&admitted.run_id)
        .into_iter()
        .find(|event| event["event"] == "run.completed")
        .expect("completed terminal");
    assert!(
        completed.to_string().contains("bounded-summary"),
        "final summary should complete: {completed}"
    );
    fixture.cleanup();
}

/// Reopening a completed run is a no-op: no provider call, no extra terminal,
/// and metrics do not double-count. Pending-turn recovery is covered by the
/// restart tests below.
#[tokio::test(flavor = "multi_thread")]
async fn completed_run_reopen_is_noop() {
    let Some(_) = locate_sh() else {
        #[cfg(unix)]
        panic!("unix coding edge e2e requires sh at /bin/sh, /usr/bin/sh, or PATH");
        #[cfg(not(unix))]
        {
            eprintln!("skipping completed reopen without POSIX sh");
            return;
        }
    };
    let sh = require_sh();
    let mut fixture = Fixture::new("reopen-noop");
    fixture.write_script("hello.sh", hello_source());
    let call = ToolCall {
        id: "call-restart".to_string(),
        name: "terminal".to_string(),
        arguments: json!({
            "argv": [sh_arg(&sh), "hello.sh"],
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
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &db);
    let service = state.service();
    apply_workspace_limits(&service, &fixture.workspace, 64 * 1024);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
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
    drop(state);

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
        "completed reopen must not call the provider again"
    );
    let after = resumed_service.metrics().snapshot();
    assert_eq!(after.tool_calls, 0, "metrics must not double-count tools");
    assert_eq!(after.model_calls, 0, "metrics must not double-count models");
    assert_eq!(after.turns, 0);
    assert_eq!(resumed_service.process_owner_count(&run_id), 0);
    fixture.cleanup();
}

fn require_posix_sh() -> Option<PathBuf> {
    let Some(_) = locate_sh() else {
        #[cfg(unix)]
        panic!("unix coding edge e2e requires sh at /bin/sh, /usr/bin/sh, or PATH");
        #[cfg(not(unix))]
        {
            eprintln!("skipping durable provider recovery without POSIX sh");
            return None;
        }
    };
    Some(require_sh())
}

fn once_tool_call(sh: &Path, id: &str) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        name: "terminal".to_string(),
        arguments: json!({
            "argv": [sh_arg(sh), "once.sh"],
            "timeout_ms": 5_000
        }),
    }
}

fn rich_tool_response(call: &ToolCall) -> JsonValue {
    json!({
        "text": "need-once",
        "tool_calls": [{"id": call.id, "name": call.name, "arguments": call.arguments}],
        "usage": {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18},
        "reasoning": {"summary": "append once"},
        "stop_reason": "tool_calls",
        "truncated": false,
        "model": "scripted-model",
        "provider": "scripted-provider",
    })
}

fn assert_tool_parent_chain(
    service: &AgentService,
    session_id: &str,
    run_id: &str,
    call: &ToolCall,
) {
    let messages = service.session_messages(session_id);
    let chain = run_messages(&messages, run_id);
    let parent = assistant_tool_call(&chain, &call.id);
    let result = user_tool_result(&chain, &call.id);
    assert_eq!(
        json_opt_str(parent, "parent_message_id"),
        Some(message_id(chain[0])),
        "assistant tool_call parent is the durable user admission message"
    );
    assert_exact_parent_name_ordinal(result, parent, "terminal", 3);
}

/// Crash after the durable `model.requested` boundary: reopen retries the same
/// logical turn, runs the tool once, and does not double-count completed metrics.
#[tokio::test(flavor = "multi_thread")]
async fn pending_provider_request_restart_retries_without_duplicate_tool() {
    let Some(sh) = require_posix_sh() else {
        return;
    };
    let mut fixture = Fixture::new("pending-request-retry");
    fixture.write_script("once.sh", once_source());
    let counter = fixture.workspace.join("counter.txt");
    let call = once_tool_call(&sh, "call-pending-retry");
    let provider = ScriptedProvider::new();
    provider.push_ok(rich_tool_response(&call));
    provider.push_ok(text_response("after-retry"));

    let db = fixture.db_path();
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &db);
    let service = state.service();
    apply_workspace_limits(&service, &fixture.workspace, 64 * 1024);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service.inject_crash_after_provider_request();
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("crash worker should finish");

    assert!(
        terminal_events(&service, &admitted.run_id).is_empty(),
        "pending request crash must not commit a terminal: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "model.requested"),
        1
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "model.completed"),
        0
    );
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert_eq!(
        provider.call_count(),
        0,
        "inner provider must not run before the requested crash"
    );
    assert!(!counter.exists(), "tool must not run before recovery");
    service.evict_run_handle(&admitted.run_id);
    service.inject_provider_host(Arc::new(provider.clone()));
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("recovery worker should finish");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 2);
    assert_eq!(
        fs::read(&counter).expect("counter after retry"),
        b"x",
        "retry-safe pending request must execute the tool exactly once"
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "tool.started"),
        1
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "model.completed"),
        2
    );
    assert_tool_parent_chain(&service, &admitted.session_id, &admitted.run_id, &call);
    let messages = service.session_messages(&admitted.session_id);
    let chain = run_messages(&messages, &admitted.run_id);
    let parent = assistant_tool_call(&chain, &call.id);
    assert_eq!(parent["metadata"]["usage"]["total_tokens"], json!(18));
    assert_eq!(parent["metadata"]["provider"], json!("scripted-provider"));
    assert_eq!(parent["metadata"]["model"], json!("scripted-model"));
    assert_eq!(parent["metadata"]["truncated"], json!(false));
    assert_eq!(
        parent["metadata"]["reasoning"],
        json!({"summary": "append once"})
    );
    assert_eq!(parent["finish_reason"], json!("tool_calls"));
    let metrics = service.metrics().snapshot();
    assert_eq!(metrics.model_calls, 2);
    assert_eq!(metrics.tool_calls, 1);
    assert_eq!(metrics.turns, 2);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    drop(state);
    fixture.cleanup();
}

/// Crash after a durable completed provider step: reopen replays the envelope
/// without a second inner call or duplicate tool effect, preserving metadata.
#[tokio::test(flavor = "multi_thread")]
async fn completed_provider_step_restart_replays_without_duplicate_tool() {
    let Some(sh) = require_posix_sh() else {
        return;
    };
    let mut fixture = Fixture::new("completed-step-replay");
    fixture.write_script("once.sh", once_source());
    let counter = fixture.workspace.join("counter.txt");
    let call = once_tool_call(&sh, "call-completed-replay");
    let provider = ScriptedProvider::new();
    provider.push_ok(rich_tool_response(&call));
    provider.push_ok(text_response("after-replay"));

    let db = fixture.db_path();
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &db);
    let service = state.service();
    apply_workspace_limits(&service, &fixture.workspace, 64 * 1024);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service.inject_crash_after_provider_commit();
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("commit-crash worker should finish");

    assert!(
        terminal_events(&service, &admitted.run_id).is_empty(),
        "post-commit crash must not commit a terminal: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "model.requested"),
        1
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "model.completed"),
        1
    );
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert_eq!(provider.call_count(), 1);
    assert!(!counter.exists(), "tool must not run before replay");
    let messages = service.session_messages(&admitted.session_id);
    let chain = run_messages(&messages, &admitted.run_id);
    let parent = assistant_tool_call(&chain, &call.id);
    let committed_id = message_id(parent).to_string();
    let committed_metadata = parent["metadata"].clone();
    let committed_finish = parent["finish_reason"].clone();
    assert_eq!(committed_metadata["usage"]["input_tokens"], json!(11));
    assert_eq!(committed_metadata["usage"]["output_tokens"], json!(7));
    assert_eq!(committed_metadata["usage"]["total_tokens"], json!(18));
    assert_eq!(committed_metadata["provider"], json!("scripted-provider"));
    assert_eq!(committed_metadata["model"], json!("scripted-model"));
    assert_eq!(committed_metadata["truncated"], json!(false));
    assert_eq!(
        committed_metadata["reasoning"],
        json!({"summary": "append once"})
    );
    assert_eq!(committed_finish, json!("tool_calls"));
    let first_metrics = service.metrics().snapshot();
    assert_eq!(first_metrics.model_calls, 1);
    assert_eq!(first_metrics.turns, 1);
    assert_eq!(first_metrics.tool_calls, 0);
    service.evict_run_handle(&admitted.run_id);
    service.inject_provider_host(Arc::new(provider.clone()));
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("replay worker should finish");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        provider.call_count(),
        2,
        "replayed completed step must not call the inner provider again for turn 1"
    );
    assert_eq!(
        fs::read(&counter).expect("counter after replay"),
        b"x",
        "completed durable replay must execute the tool exactly once"
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "tool.started"),
        1
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "model.completed"),
        2
    );
    assert_tool_parent_chain(&service, &admitted.session_id, &admitted.run_id, &call);
    let messages = service.session_messages(&admitted.session_id);
    let chain = run_messages(&messages, &admitted.run_id);
    let replayed = assistant_tool_call(&chain, &call.id);
    assert_eq!(message_id(replayed), committed_id);
    assert_eq!(replayed["metadata"], committed_metadata);
    assert_eq!(replayed["finish_reason"], committed_finish);
    let metrics = service.metrics().snapshot();
    assert_eq!(
        metrics.model_calls,
        first_metrics.model_calls + 1,
        "replayed turn must not count a second model call"
    );
    assert_eq!(metrics.tool_calls, 1);
    assert_eq!(
        metrics.turns,
        first_metrics.turns + 1,
        "replayed completed step must not double-count turns"
    );
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    drop(state);
    fixture.cleanup();
}

/// Crash after durable tool completion, before the next provider response:
/// evict/re-drive replays the same tool_call without a second native effect.
#[tokio::test(flavor = "multi_thread")]
async fn completed_tool_step_restart_replays_without_duplicate_effect() {
    let Some(sh) = require_posix_sh() else {
        return;
    };
    let mut fixture = Fixture::new("completed-tool-replay");
    fixture.write_script("once.sh", once_source());
    let counter = fixture.workspace.join("counter.txt");
    let call = once_tool_call(&sh, "call-tool-replay");
    let provider = ScriptedProvider::new();
    provider.push_ok(rich_tool_response(&call));
    provider.push_ok(text_response("after-tool-replay"));

    let db = fixture.db_path();
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &db);
    let service = state.service();
    apply_workspace_limits(&service, &fixture.workspace, 64 * 1024);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service.inject_crash_after_tool_commit();
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("tool-commit-crash worker should finish");

    assert!(
        terminal_events(&service, &admitted.run_id).is_empty(),
        "post-tool-commit crash must not commit a terminal: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "tool.completed"),
        1
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "tool.started"),
        1
    );
    assert_eq!(
        durable_tool_result_messages(&service, &admitted.session_id).len(),
        1
    );
    assert_eq!(
        fs::read(&counter).expect("counter after first drive"),
        b"x",
        "first drive must execute the tool once"
    );
    assert_eq!(provider.call_count(), 1);
    let first_metrics = service.metrics().snapshot();
    assert_eq!(first_metrics.tool_failures, 0);
    service.evict_run_handle(&admitted.run_id);
    service.inject_provider_host(Arc::new(provider.clone()));
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("replay worker should finish");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        provider.call_count(),
        2,
        "replayed tool must not call the inner provider again for turn 1"
    );
    assert_eq!(
        fs::read(&counter).expect("counter after replay"),
        b"x",
        "durable tool replay must execute the tool exactly once"
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "tool.started"),
        1
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "tool.completed"),
        1
    );
    assert_eq!(
        event_name_count(&service, &admitted.run_id, "tool.requested"),
        1
    );
    assert_eq!(
        durable_tool_result_messages(&service, &admitted.session_id).len(),
        1
    );
    assert_tool_parent_chain(&service, &admitted.session_id, &admitted.run_id, &call);
    let metrics = service.metrics().snapshot();
    assert_eq!(
        metrics.tool_calls, first_metrics.tool_calls,
        "replayed tool must not increment tool_calls"
    );
    assert_eq!(metrics.tool_failures, 0);
    assert!(
        metrics.tool_calls <= 1,
        "tool_calls must not double-count: {}",
        metrics.tool_calls
    );
    assert_eq!(
        metrics.model_calls,
        first_metrics.model_calls + 1,
        "replayed tool must not double-count the first model call"
    );
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    drop(state);
    fixture.cleanup();
}

/// An unsafe pending request fail-closes: no inner provider call and no tool effect.
#[tokio::test(flavor = "multi_thread")]
async fn unsafe_pending_provider_request_fails_closed_without_tool() {
    let Some(sh) = require_posix_sh() else {
        return;
    };
    let mut fixture = Fixture::new("unsafe-pending");
    fixture.write_script("once.sh", once_source());
    let counter = fixture.workspace.join("counter.txt");
    let call = once_tool_call(&sh, "call-unsafe-pending");
    let provider = ScriptedProvider::new();
    provider.push_ok(rich_tool_response(&call));
    provider.push_ok(text_response("must-not-run"));

    let db = fixture.db_path();
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &db);
    let service = state.service();
    apply_workspace_limits(&service, &fixture.workspace, 64 * 1024);
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service
        .commit_provider_request(
            &admitted.run_id,
            1,
            1,
            false,
            &json!({"model": "local-agent"}),
        )
        .expect("unsafe pending request boundary");
    tokio::time::timeout(WORKER_BUDGET, {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    })
    .await
    .expect("unsafe pending worker should finish");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert!(
        service.run_events(&admitted.run_id).iter().any(|event| {
            event["event"] == "model.failed"
                && event["data"]["error_code"] == "interrupted_provider"
        }),
        "unsafe pending must fail closed as interrupted_provider: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 0);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert!(!counter.exists(), "unsafe pending must not run the tool");
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    drop(state);
    fixture.cleanup();
}

#[test]
fn docs_name_both_coding_e2e_commands() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let commands = [
        "cargo test --test coding_agent_e2e_tests",
        "cargo test --test coding_agent_edge_e2e_tests",
    ];
    for relative in ["README.md", "docs/configuration.md"] {
        let text = fs::read_to_string(root.join(relative)).expect(relative);
        for command in commands {
            assert!(text.contains(command), "{relative} must document {command}");
        }
        assert!(
            !text.contains("does not cover stop-during-output"),
            "{relative} must not claim stop-during-output is uncovered"
        );
    }
}
