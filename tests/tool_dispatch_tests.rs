use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rustscript_agent::config::{ArtifactStoreConfig, FileToolConfig, ProcessToolConfig, RunLimits};
use rustscript_agent::service::RunContextError;
use rustscript_agent::tools::{
    ArtifactOwner, ArtifactStore, DispatchContext, DispatchLimits, DurableEventCommitter,
    EventCommitError, FileTools, NativeExecutionDeps, NativeToolExecutor, ProcessArtifactSink,
    ProcessExecutor, ProcessOwner, ProcessTable, TerminalExecutor, TerminalRequest,
    ToolExecutorBoundary, ToolOwner, ToolRegistry, ToolRegistryEntry, ToolRegistrySnapshot,
    ToolResult,
};
use rustscript_agent::{
    AdmitRunRequest, AdmittedRun, AgentGatewayConfig, AgentGatewayState, AgentService,
    LlmContentBlock, ToolCall, ToolDescriptor, Toolset,
};
use rustscript_vm::CancellationToken;
use serde_json::{Value, json};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const TEMP_ROOT: &str = "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-t7-address-spec-148adf54";
const SECRET_NEEDLE: &str = "NEONSECRET_t5_9f3a2c";
const PATH_NEEDLE: &str = "/tmp/t5-redact-path-zzq91";
const STDIN_NEEDLE: &str = "STDIN_t5_kettledrum";
const OUTPUT_NEEDLE: &str = "STDOUT_t5_umbraflare";
const ENV_NEEDLE: &str = "ENV_t5_willowbank=1";
const PATCH_NEEDLE: &str = "PATCHBODY_t5_oldnew";

struct Fixture {
    root: PathBuf,
    parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let parent = Path::new(TEMP_ROOT).join(format!(
            "dispatch-{}-{}-{}",
            std::process::id(),
            sequence,
            std::thread::current().name().unwrap_or("test")
        ));
        let root = parent.join("workspace");
        fs::create_dir_all(&root).expect("create dispatch fixture root");
        Self { root, parent }
    }

    fn file_config(&self) -> FileToolConfig {
        let mut config = FileToolConfig::for_workspace(&self.root);
        config.artifact_store.root = self.parent.join("artifacts");
        config
    }

    fn process_config(&self) -> ProcessToolConfig {
        ProcessToolConfig::for_workspace(&self.root)
    }

    fn native_deps(&self, owner: ToolOwner) -> NativeExecutionDeps {
        let files = FileTools::new(self.file_config())
            .expect("file tools")
            .with_owner(ArtifactOwner::from(owner.clone()));
        let table = Arc::new(ProcessTable::new(self.process_config()).expect("process table"));
        let sink: Arc<dyn ProcessArtifactSink> = files.artifact_store_arc();
        let terminal = TerminalExecutor::new(
            self.process_config(),
            Arc::clone(&table),
            ProcessOwner::from(owner.clone()),
        )
        .expect("terminal")
        .with_artifact_sink(Arc::clone(&sink));
        let process = ProcessExecutor::new(self.process_config(), table, ProcessOwner::from(owner))
            .expect("process")
            .with_artifact_sink(sink);
        NativeExecutionDeps {
            files,
            terminal,
            process,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

fn tool_owner() -> ToolOwner {
    ToolOwner::new("profile-test", "session-test", "run-test").expect("tool owner")
}

fn other_owner() -> ToolOwner {
    ToolOwner::new("other-profile", "other-session", "other-run").expect("other owner")
}

fn builtin_snapshot() -> rustscript_agent::tools::ToolRegistrySnapshot {
    ToolRegistry::builtin()
        .expect("builtin registry")
        .snapshot()
}

fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn default_limits() -> DispatchLimits {
    DispatchLimits {
        max_tool_calls: 128,
        max_tool_output_bytes: 64 * 1024,
        max_event_bytes: 32 * 1024,
    }
}

fn call(id: &str, name: &str, arguments: Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        name: name.to_string(),
        arguments,
    }
}

fn error_code(result: &ToolResult) -> &str {
    result
        .error
        .as_ref()
        .expect("tool result should contain an error")
        .code
        .as_str()
}

fn assert_replayed_canonical(result: &ToolResult, canonical: &ToolResult) {
    assert_eq!(result.ok, canonical.ok);
    assert_eq!(result.content, canonical.content);
    assert_eq!(result.data, canonical.data);
    assert_eq!(result.error, canonical.error);
    assert_eq!(result.truncated, canonical.truncated);
    assert_eq!(result.artifacts, canonical.artifacts);
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

fn wait_until_dead(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while pid_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "process {pid} still alive after cleanup"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn hostile_ignore_term_args(marker: &Path) -> serde_json::Value {
    json!({
        "argv": [
            "/bin/sh",
            "-c",
            "trap \"\" TERM INT HUP QUIT; echo $$ > \"$1\"; while :; do sleep 1; done",
            "hostile",
            marker.to_string_lossy()
        ],
        "background": true,
        "timeout_ms": 30_000
    })
}

fn wait_for_file(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(path)
            && !text.trim().is_empty()
        {
            return text;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {}", path.display());
}

fn assert_cancelled_bounded(result: &ToolResult) {
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(result), "cancelled");
    let encoded = serde_json::to_string(result).expect("encode tool result");
    assert!(
        encoded.len() < 32 * 1024,
        "cancelled result exceeded the bound: {} bytes",
        encoded.len()
    );
}

async fn admit_dispatch_service(fixture: &Fixture) -> (AgentGatewayState, Arc<AgentService>) {
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    let limits = RunLimits::new(8, 8, 64 * 1024, &fixture.root).expect("run limits");
    service.set_run_limits(limits).expect("set limits");
    (state, service)
}

async fn admit_run(service: &Arc<AgentService>) -> AdmittedRun {
    service
        .admit(AdmitRunRequest {
            input: json!({"message": "dispatch"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit")
}

fn commit_tool_parents(service: &AgentService, run_id: &str, turn: u64, calls: &[ToolCall]) {
    let blocks: Vec<LlmContentBlock> = calls
        .iter()
        .map(|call| LlmContentBlock {
            block_type: "tool_call".to_string(),
            tool_call_id: Some(call.id.clone()),
            name: Some(call.name.clone()),
            arguments_json: Some(call.arguments.to_string()),
            ..LlmContentBlock::default()
        })
        .collect();
    service
        .commit_provider_step(
            run_id,
            turn,
            &blocks,
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect("tool-call parent");
}

fn event_history(events: &MemoryEvents) -> String {
    serde_json::to_string(&*events.events.lock()).expect("serialize event history")
}

fn assert_no_needles(history: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !history.contains(needle),
            "serialized event history leaked {needle}: {history}"
        );
    }
}

fn redact_needles() -> [&'static str; 6] {
    [
        SECRET_NEEDLE,
        PATH_NEEDLE,
        STDIN_NEEDLE,
        OUTPUT_NEEDLE,
        ENV_NEEDLE,
        PATCH_NEEDLE,
    ]
}

struct MemoryEvents {
    events: Mutex<Vec<(String, Value)>>,
    terminal: AtomicBool,
    fail_on: Mutex<Option<String>>,
    fail_once: AtomicBool,
    stop: AtomicBool,
}

impl MemoryEvents {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            terminal: AtomicBool::new(false),
            fail_on: Mutex::new(None),
            fail_once: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        })
    }

    fn fail_on_type(self: &Arc<Self>, event_type: &str) {
        *self.fail_on.lock() = Some(event_type.to_string());
        self.fail_once.store(true, Ordering::SeqCst);
    }

    fn mark_terminal(&self) {
        self.terminal.store(true, Ordering::SeqCst);
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn types(&self) -> Vec<String> {
        self.events
            .lock()
            .iter()
            .map(|(event_type, _)| event_type.clone())
            .collect()
    }
}

impl DurableEventCommitter for MemoryEvents {
    fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::SeqCst)
    }

    fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn commit(&self, event_type: &str, data: Value) -> Result<(), EventCommitError> {
        if self.is_terminal() {
            return Err(EventCommitError::Terminal);
        }
        let should_fail = {
            let fail_on = self.fail_on.lock();
            fail_on.as_deref() == Some(event_type) && self.fail_once.swap(false, Ordering::SeqCst)
        };
        if should_fail {
            return Err(EventCommitError::PersistFailed(
                "injected durable failure".to_string(),
            ));
        }
        self.events.lock().push((event_type.to_string(), data));
        Ok(())
    }
}

struct ReplayEvents {
    inner: Arc<MemoryEvents>,
    replay: Mutex<Result<Option<ToolResult>, EventCommitError>>,
}

impl ReplayEvents {
    fn new(replay: Result<Option<ToolResult>, EventCommitError>) -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryEvents::new(),
            replay: Mutex::new(replay),
        })
    }
}

impl DurableEventCommitter for ReplayEvents {
    fn is_terminal(&self) -> bool {
        self.inner.is_terminal()
    }

    fn stop_requested(&self) -> bool {
        self.inner.stop_requested()
    }

    fn commit(&self, event_type: &str, data: Value) -> Result<(), EventCommitError> {
        self.inner.commit(event_type, data)
    }

    fn replay_durable_tool_result(
        &self,
        tool_call_id: &str,
        name: &str,
    ) -> Result<Option<ToolResult>, EventCommitError> {
        assert_eq!(tool_call_id, "c-replay");
        assert_eq!(name, "read_file");
        self.replay.lock().clone()
    }
}

struct CountingExecutor {
    count: AtomicU64,
    names: Mutex<Vec<String>>,
    result: Mutex<Option<ToolResult>>,
}

impl CountingExecutor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU64::new(0),
            names: Mutex::new(Vec::new()),
            result: Mutex::new(None),
        })
    }

    fn with_result(result: ToolResult) -> Arc<Self> {
        let executor = Self::new();
        *executor.result.lock() = Some(result);
        executor
    }
}

impl ToolExecutorBoundary for CountingExecutor {
    fn execute(
        &self,
        executor: &NativeToolExecutor,
        _arguments: &Value,
        _cancellation: &CancellationToken,
        _deadline: Instant,
    ) -> ToolResult {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.names.lock().push(executor.tool_name().to_string());
        self.result
            .lock()
            .clone()
            .unwrap_or_else(|| ToolResult::success("counted", json!({"ok": true})))
    }
}

struct PanicExecutor {
    count: AtomicU64,
}

impl PanicExecutor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU64::new(0),
        })
    }
}

impl ToolExecutorBoundary for PanicExecutor {
    fn execute(
        &self,
        _executor: &NativeToolExecutor,
        _arguments: &Value,
        _cancellation: &CancellationToken,
        _deadline: Instant,
    ) -> ToolResult {
        self.count.fetch_add(1, Ordering::SeqCst);
        panic!("injected executor panic");
    }
}

struct BlockingExecutor {
    started: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
    count: AtomicU64,
}

impl BlockingExecutor {
    fn pair() -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let executor = Arc::new(Self {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(Some(release_rx)),
            count: AtomicU64::new(0),
        });
        (executor, started_rx, release_tx)
    }
}

impl ToolExecutorBoundary for BlockingExecutor {
    fn execute(
        &self,
        _executor: &NativeToolExecutor,
        _arguments: &Value,
        _cancellation: &CancellationToken,
        _deadline: Instant,
    ) -> ToolResult {
        self.count.fetch_add(1, Ordering::SeqCst);
        if let Some(started) = self.started.lock().take() {
            let _ = started.send(());
        }
        if let Some(release) = self.release.lock().as_ref() {
            let _ = release.recv();
        }
        ToolResult::success("unblocked", json!({}))
    }
}

struct CancelWatchExecutor {
    started: Mutex<Option<mpsc::Sender<()>>>,
    saw_cancel: AtomicBool,
    received_cancelled: AtomicBool,
}

impl CancelWatchExecutor {
    fn pair() -> (Arc<Self>, mpsc::Receiver<()>) {
        let (started_tx, started_rx) = mpsc::channel();
        let executor = Arc::new(Self {
            started: Mutex::new(Some(started_tx)),
            saw_cancel: AtomicBool::new(false),
            received_cancelled: AtomicBool::new(false),
        });
        (executor, started_rx)
    }
}

impl ToolExecutorBoundary for CancelWatchExecutor {
    fn execute(
        &self,
        _executor: &NativeToolExecutor,
        _arguments: &Value,
        cancellation: &CancellationToken,
        _deadline: Instant,
    ) -> ToolResult {
        self.received_cancelled
            .store(cancellation.is_cancelled(), Ordering::SeqCst);
        if let Some(started) = self.started.lock().take() {
            let _ = started.send(());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if cancellation.is_cancelled() {
                self.saw_cancel.store(true, Ordering::SeqCst);
                return ToolResult::failure("cancelled", "tool execution was cancelled");
            }
            thread::sleep(Duration::from_millis(5));
        }
        ToolResult::failure("deadline_elapsed", "cancel watcher timed out")
    }
}

fn context_with(
    owner: ToolOwner,
    workspace: PathBuf,
    events: Arc<dyn DurableEventCommitter>,
    executor: Arc<dyn ToolExecutorBoundary>,
    limits: DispatchLimits,
) -> DispatchContext {
    let registry = builtin_snapshot();
    let identity = registry.identity().to_string();
    DispatchContext::new(
        owner,
        workspace,
        CancellationToken::new(),
        far_deadline(),
        registry,
        identity.clone(),
        identity,
        limits,
        events,
        executor,
    )
    .expect("dispatch context")
}

#[test]
fn unknown_tool_returns_typed_result_without_executor() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call("c1", "not_a_tool", json!({"path": "x"})));
    assert!(!result.ok);
    assert_eq!(error_code(&result), "unknown_tool");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert_eq!(events.types(), ["tool.requested", "tool.failed"]);
}

#[test]
fn invalid_arguments_return_typed_result_without_executor() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"offset": 1})));
    assert!(!result.ok);
    assert_eq!(error_code(&result), "invalid_arguments");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert_eq!(events.types(), ["tool.requested", "tool.failed"]);
}

#[test]
fn extra_properties_are_invalid_arguments() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call(
        "c1",
        "read_file",
        json!({"path": "a.txt", "extra": true}),
    ));
    assert_eq!(error_code(&result), "invalid_arguments");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
}

#[test]
fn successful_dispatch_persists_requested_started_output_completed() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert!(result.ok, "{result:?}");
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.types(),
        [
            "tool.requested",
            "tool.started",
            "tool.output",
            "tool.completed"
        ]
    );
}

#[test]
fn durable_failure_before_started_prevents_effect() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    events.fail_on_type("tool.started");
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert!(!result.ok);
    assert_eq!(error_code(&result), "event_persist_failed");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert_eq!(events.types(), ["tool.requested"]);
    assert!(!events.types().iter().any(|event| event == "tool.started"));
}

#[test]
fn unknown_multibyte_tool_name_over_64_bytes_returns_typed_result_without_panic() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );
    let name = "测".repeat(30);
    assert!(name.len() > 64);

    let result = dispatcher.dispatch_one(&call("c1", &name, json!({})));
    assert!(!result.ok);
    assert_eq!(error_code(&result), "unknown_tool");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    let history = event_history(&events);
    assert!(!history.contains(&name));
}

#[test]
fn durable_requested_failure_blocks_executor_and_emits_no_later_event() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    events.fail_on_type("tool.requested");
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert_eq!(error_code(&result), "event_persist_failed");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.types().is_empty());
}

#[test]
fn durable_output_failure_after_effect_stops_publication_and_preserves_started() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    events.fail_on_type("tool.output");
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert_eq!(error_code(&result), "event_persist_failed");
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);
    assert_eq!(events.types(), ["tool.requested", "tool.started"]);
    assert!(!events.types().iter().any(|event| event == "tool.output"
        || event == "tool.completed"
        || event == "tool.failed"));
}

#[test]
fn durable_events_redact_secrets_on_success() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::with_result(ToolResult::success(
        OUTPUT_NEEDLE,
        json!({
            "stdout": OUTPUT_NEEDLE,
            "stderr": OUTPUT_NEEDLE,
            "path": PATH_NEEDLE
        }),
    ));
    let mut limits = default_limits();
    limits.max_event_bytes = 256;
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        executor,
        limits,
    );

    let result = dispatcher.dispatch_one(&call(
        "c1",
        "write_file",
        json!({
            "path": PATH_NEEDLE,
            "content": SECRET_NEEDLE
        }),
    ));
    assert!(result.ok, "{result:?}");
    assert!(result.content.contains(OUTPUT_NEEDLE));

    let terminal = dispatcher.dispatch_one(&call(
        "c2",
        "terminal",
        json!({
            "argv": ["/bin/true", PATH_NEEDLE, ENV_NEEDLE],
            "cwd": PATH_NEEDLE,
            "stdin": format!("{STDIN_NEEDLE}{ENV_NEEDLE}")
        }),
    ));
    assert!(terminal.ok, "{terminal:?}");

    let patched = dispatcher.dispatch_one(&call(
        "c3",
        "patch",
        json!({
            "path": PATH_NEEDLE,
            "old_string": PATCH_NEEDLE,
            "new_string": SECRET_NEEDLE
        }),
    ));
    assert!(patched.ok, "{patched:?}");

    let history = event_history(&events);
    assert_no_needles(&history, &redact_needles());
    for (event_type, data) in events.events.lock().iter() {
        let payload = serde_json::to_vec(data).expect("serialize event");
        assert!(
            payload.len() <= 256,
            "{event_type} event {} exceeds event cap after redaction",
            payload.len()
        );
        assert!(
            data.get("output").is_none(),
            "{event_type} persisted output"
        );
        assert!(
            data.pointer("/tool_call/arguments").is_none(),
            "{event_type} persisted arguments"
        );
        assert!(
            data.pointer("/error/message").is_none(),
            "{event_type} persisted error message"
        );
    }
}

#[test]
fn durable_events_redact_secrets_on_failure() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::with_result(ToolResult::failure(
        "io_error",
        format!("failed to read {PATH_NEEDLE}: {OUTPUT_NEEDLE} {SECRET_NEEDLE}"),
    ));
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        executor,
        default_limits(),
    );

    let failed = dispatcher.dispatch_one(&call(
        "c1",
        "terminal",
        json!({
            "argv": ["/bin/false", PATH_NEEDLE],
            "cwd": PATH_NEEDLE,
            "stdin": format!("{STDIN_NEEDLE}{ENV_NEEDLE}{SECRET_NEEDLE}")
        }),
    ));
    assert!(!failed.ok);
    assert!(
        failed
            .error
            .as_ref()
            .is_some_and(|error| error.message.contains(PATH_NEEDLE))
    );

    let invalid = dispatcher.dispatch_one(&call(
        "c2",
        "read_file",
        json!({
            "path": PATH_NEEDLE,
            "instance": SECRET_NEEDLE,
            "stdin": STDIN_NEEDLE
        }),
    ));
    assert_eq!(error_code(&invalid), "invalid_arguments");

    let history = event_history(&events);
    assert_no_needles(&history, &redact_needles());
    for (event_type, data) in events.events.lock().iter() {
        assert!(
            data.pointer("/error/message").is_none(),
            "{event_type} persisted executor/schema error text"
        );
        assert!(
            data.get("output").is_none(),
            "{event_type} persisted output"
        );
        assert!(
            data.pointer("/tool_call/arguments").is_none(),
            "{event_type} persisted arguments"
        );
    }
}

#[test]
fn cancel_before_validation_publishes_nothing() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let registry = builtin_snapshot();
    let identity = registry.identity().to_string();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let dispatcher = DispatchContext::new(
        tool_owner(),
        fixture.root.clone(),
        cancellation,
        far_deadline(),
        registry,
        identity.clone(),
        identity,
        default_limits(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
    )
    .expect("dispatch context");

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert_eq!(error_code(&result), "cancelled");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.types().is_empty());
}

#[test]
fn deadline_before_validation_publishes_nothing() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let registry = builtin_snapshot();
    let identity = registry.identity().to_string();
    let dispatcher = DispatchContext::new(
        tool_owner(),
        fixture.root.clone(),
        CancellationToken::new(),
        Instant::now() - Duration::from_secs(1),
        registry,
        identity.clone(),
        identity,
        default_limits(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
    )
    .expect("dispatch context");

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert_eq!(error_code(&result), "deadline_elapsed");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.types().is_empty());
}

fn dispatcher_with_cancel(
    owner: ToolOwner,
    workspace: PathBuf,
    cancellation: CancellationToken,
    events: Arc<dyn DurableEventCommitter>,
    executor: Arc<dyn ToolExecutorBoundary>,
) -> DispatchContext {
    let registry = builtin_snapshot();
    let identity = registry.identity().to_string();
    DispatchContext::new(
        owner,
        workspace,
        cancellation,
        far_deadline(),
        registry,
        identity.clone(),
        identity,
        default_limits(),
        events,
        executor,
    )
    .expect("dispatch context")
}

fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pred() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    pred()
}

#[test]
fn cancel_during_terminal_call_propagates_to_per_call_token() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let (executor, started_rx) = CancelWatchExecutor::pair();
    let cancellation = CancellationToken::new();
    let dispatcher = Arc::new(dispatcher_with_cancel(
        tool_owner(),
        fixture.root.clone(),
        cancellation.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
    ));

    let worker = {
        let dispatcher = Arc::clone(&dispatcher);
        thread::spawn(move || {
            dispatcher.dispatch_one(&call(
                "c1",
                "terminal",
                json!({"argv": ["/bin/sleep", "30"]}),
            ))
        })
    };
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal effect started");
    assert!(!executor.received_cancelled.load(Ordering::SeqCst));
    cancellation.cancel();
    let result = worker.join().expect("join terminal dispatch");
    assert_eq!(error_code(&result), "cancelled");
    assert!(executor.saw_cancel.load(Ordering::SeqCst));
}

#[test]
fn stop_requested_during_terminal_call_cancels_per_call_token() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let (executor, started_rx) = CancelWatchExecutor::pair();
    let cancellation = CancellationToken::new();
    let dispatcher = Arc::new(dispatcher_with_cancel(
        tool_owner(),
        fixture.root.clone(),
        cancellation.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
    ));

    let worker = {
        let dispatcher = Arc::clone(&dispatcher);
        thread::spawn(move || {
            dispatcher.dispatch_one(&call(
                "c1",
                "process",
                json!({"action": "poll", "process_id": "p1"}),
            ))
        })
    };
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("process effect started");
    events.request_stop();
    let result = worker.join().expect("join process dispatch");
    assert_eq!(error_code(&result), "cancelled");
    assert!(executor.saw_cancel.load(Ordering::SeqCst));
    assert!(!cancellation.is_cancelled());
}

#[test]
fn cancel_during_file_call_uses_parent_token() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let (executor, started_rx) = CancelWatchExecutor::pair();
    let cancellation = CancellationToken::new();
    let dispatcher = Arc::new(dispatcher_with_cancel(
        tool_owner(),
        fixture.root.clone(),
        cancellation.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
    ));

    let worker = {
        let dispatcher = Arc::clone(&dispatcher);
        thread::spawn(move || {
            dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})))
        })
    };
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("file effect started");
    cancellation.cancel();
    let result = worker.join().expect("join file dispatch");
    assert_eq!(error_code(&result), "cancelled");
    assert!(executor.saw_cancel.load(Ordering::SeqCst));
}

#[test]
fn no_events_after_terminal_ownership() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    events.mark_terminal();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert_eq!(error_code(&result), "cancelled");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.types().is_empty());
}

#[test]
fn terminal_after_requested_prevents_started_and_effect() {
    let fixture = Fixture::new();
    let executor = CountingExecutor::new();

    struct FlipOnRequested {
        inner: Arc<MemoryEvents>,
    }
    impl DurableEventCommitter for FlipOnRequested {
        fn is_terminal(&self) -> bool {
            self.inner.is_terminal()
        }
        fn stop_requested(&self) -> bool {
            false
        }
        fn commit(&self, event_type: &str, data: Value) -> Result<(), EventCommitError> {
            let result = self.inner.commit(event_type, data);
            if event_type == "tool.requested" {
                self.inner.mark_terminal();
            }
            result
        }
    }

    let events = MemoryEvents::new();
    let flipping = Arc::new(FlipOnRequested {
        inner: Arc::clone(&events),
    });
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        flipping,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );
    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert!(!result.ok);
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert_eq!(events.types(), ["tool.requested"]);
}

fn replay_dispatcher(
    fixture: &Fixture,
    events: Arc<ReplayEvents>,
    executor: Arc<CountingExecutor>,
) -> DispatchContext {
    context_with(
        tool_owner(),
        fixture.root.clone(),
        events,
        executor,
        default_limits(),
    )
}

fn replay_call() -> ToolCall {
    call("c-replay", "read_file", json!({"path": "a.txt"}))
}

#[test]
fn completed_durable_replay_skips_native_effect_and_lifecycle() {
    let fixture = Fixture::new();
    let canonical = ToolResult::success("cached-output", json!({"from": "durable"}));
    let events = ReplayEvents::new(Ok(Some(canonical.clone())));
    let executor = CountingExecutor::new();
    let dispatcher = replay_dispatcher(&fixture, Arc::clone(&events), Arc::clone(&executor));

    let result = dispatcher.dispatch_one(&replay_call());
    assert_replayed_canonical(&result, &canonical);
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.inner.types().is_empty());
}

#[test]
fn failed_durable_replay_skips_native_effect_and_lifecycle() {
    let fixture = Fixture::new();
    let canonical = ToolResult::failure("tool_failed", "cached failure");
    let events = ReplayEvents::new(Ok(Some(canonical.clone())));
    let executor = CountingExecutor::new();
    let dispatcher = replay_dispatcher(&fixture, Arc::clone(&events), Arc::clone(&executor));

    let result = dispatcher.dispatch_one(&replay_call());
    assert_replayed_canonical(&result, &canonical);
    assert_eq!(error_code(&result), "tool_failed");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.inner.types().is_empty());
}

#[test]
fn interrupted_durable_replay_skips_native_effect_and_lifecycle() {
    let fixture = Fixture::new();
    let canonical = ToolResult::failure("interrupted_effect", "effect interrupted by restart");
    let events = ReplayEvents::new(Ok(Some(canonical.clone())));
    let executor = CountingExecutor::new();
    let dispatcher = replay_dispatcher(&fixture, Arc::clone(&events), Arc::clone(&executor));

    let result = dispatcher.dispatch_one(&replay_call());
    assert_replayed_canonical(&result, &canonical);
    assert_eq!(error_code(&result), "interrupted_effect");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.inner.types().is_empty());
}

#[test]
fn corrupt_durable_replay_fails_closed_without_native_effect() {
    let fixture = Fixture::new();
    let events = ReplayEvents::new(Err(EventCommitError::Corrupt(
        "durable tool output is missing a canonical result payload".to_string(),
    )));
    let executor = CountingExecutor::new();
    let dispatcher = replay_dispatcher(&fixture, Arc::clone(&events), Arc::clone(&executor));

    let result = dispatcher.dispatch_one(&replay_call());
    assert_eq!(error_code(&result), "corrupt_tool_result");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.inner.types().is_empty());
}

#[test]
fn max_tool_calls_enforced_atomically() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let mut limits = default_limits();
    limits.max_tool_calls = 1;
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        limits,
    );

    let results = dispatcher.dispatch(&[
        call("c1", "read_file", json!({"path": "a.txt"})),
        call("c2", "read_file", json!({"path": "b.txt"})),
    ]);
    assert!(results[0].ok);
    assert_eq!(error_code(&results[1]), "max_tool_calls");
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);
    assert_eq!(executor.names.lock().as_slice(), ["read_file"]);
}

#[test]
fn concurrent_dispatch_serializes_effects_and_call_budget() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let (executor, started_rx, release_tx) = BlockingExecutor::pair();
    let mut limits = default_limits();
    limits.max_tool_calls = 1;
    let dispatcher = Arc::new(context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        limits,
    ));

    let first = {
        let dispatcher = Arc::clone(&dispatcher);
        thread::spawn(move || {
            dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})))
        })
    };
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first effect started");

    let (second_started_tx, second_started_rx) = mpsc::channel();
    let second = {
        let dispatcher = Arc::clone(&dispatcher);
        thread::spawn(move || {
            let _ = second_started_tx.send(());
            dispatcher.dispatch_one(&call("c2", "read_file", json!({"path": "b.txt"})))
        })
    };
    second_started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second caller entered");
    // The second caller must be blocked on the serial lock, not executing.
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);
    release_tx.send(()).expect("release first effect");

    let first_result = first.join().expect("first join");
    let second_result = second.join().expect("second join");
    assert!(first_result.ok);
    assert_eq!(error_code(&second_result), "max_tool_calls");
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);
}

#[test]
fn registry_mismatch_returns_typed_result_without_executor() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let registry = builtin_snapshot();
    let dispatcher = DispatchContext::new(
        tool_owner(),
        fixture.root.clone(),
        CancellationToken::new(),
        far_deadline(),
        registry,
        "sha256:not-the-admitted-identity".to_string(),
        "sha256:not-the-admitted-identity".to_string(),
        default_limits(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
    )
    .expect("dispatch context");

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert_eq!(error_code(&result), "registry_mismatch");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
    assert!(events.types().is_empty());
}

#[test]
fn panic_at_executor_boundary_is_typed_failure_and_does_not_poison() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = PanicExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let panicked = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    assert!(!panicked.ok);
    assert_eq!(error_code(&panicked), "executor_panic");
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);

    let after = dispatcher.dispatch_one(&call(
        "c2",
        "write_file",
        json!({"path": "a.txt", "content": "x"}),
    ));
    assert!(!after.ok);
    assert_eq!(error_code(&after), "executor_panic");
    assert_eq!(executor.count.load(Ordering::SeqCst), 2);
}

#[test]
fn output_and_event_byte_caps_are_enforced() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let huge = "x".repeat(8 * 1024);
    let executor = CountingExecutor::with_result(ToolResult::success(huge, json!({})));
    let mut limits = default_limits();
    limits.max_tool_output_bytes = 256;
    limits.max_event_bytes = 256;
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        executor,
        limits,
    );

    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "a.txt"})));
    let encoded = serde_json::to_vec(&result).expect("serialize result");
    assert!(
        encoded.len() <= 256,
        "result {} exceeds output cap",
        encoded.len()
    );
    assert!(
        result.truncated
            || result
                .error
                .as_ref()
                .is_some_and(|error| error.code == "output_truncated")
            || !result.ok
    );
    for (event_type, data) in events.events.lock().iter() {
        let payload = serde_json::to_vec(data).expect("serialize event");
        assert!(
            payload.len() <= 256,
            "{event_type} event {} exceeds event cap",
            payload.len()
        );
    }
}

#[test]
fn ordered_multi_call_preserves_call_order() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );

    let results = dispatcher.dispatch(&[
        call("c1", "read_file", json!({"path": "a.txt"})),
        call(
            "c2",
            "write_file",
            json!({"path": "a.txt", "content": "hi"}),
        ),
        call("c3", "search_files", json!({"pattern": "hi"})),
    ]);
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|result| result.ok));
    assert_eq!(
        executor.names.lock().as_slice(),
        ["read_file", "write_file", "search_files"]
    );
    let requested_names: Vec<_> = events
        .events
        .lock()
        .iter()
        .filter(|(event_type, _)| event_type == "tool.requested")
        .map(|(_, data)| data["tool_call"]["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(requested_names, ["read_file", "write_file", "search_files"]);
}

#[test]
fn real_file_terminal_and_process_paths_run_through_one_dispatcher() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("note.txt"), "hello dispatch\n").expect("write note");
    let events = MemoryEvents::new();
    let owner = tool_owner();
    let deps = fixture.native_deps(owner.clone());
    let spawn_terminal = deps.terminal.clone();
    let dispatcher = context_with(
        owner,
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::new(deps),
        default_limits(),
    );

    let read = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "note.txt"})));
    assert!(read.ok, "{read:?}");
    assert!(read.content.contains("hello dispatch"));

    let written = dispatcher.dispatch_one(&call(
        "c2",
        "write_file",
        json!({"path": "note.txt", "content": "patched-start\nhello dispatch\n"}),
    ));
    assert!(written.ok, "{written:?}");

    let patched = dispatcher.dispatch_one(&call(
        "c3",
        "patch",
        json!({
            "path": "note.txt",
            "old_string": "patched-start",
            "new_string": "patched-done"
        }),
    ));
    assert!(patched.ok, "{patched:?}");

    let searched = dispatcher.dispatch_one(&call(
        "c4",
        "search_files",
        json!({"pattern": "patched-done"}),
    ));
    assert!(searched.ok, "{searched:?}");

    let terminal = dispatcher.dispatch_one(&call(
        "c5",
        "terminal",
        json!({"argv": ["/usr/bin/printf", "ok-term"]}),
    ));
    assert!(terminal.ok, "{terminal:?}");
    assert!(
        terminal.content.contains("ok-term") || terminal.data["stdout"].as_str() == Some("ok-term")
    );

    let spawned = spawn_terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"]
        .as_str()
        .expect("background process id")
        .to_string();
    let polled = dispatcher.dispatch_one(&call(
        "c6",
        "process",
        json!({"action": "poll", "process_id": process_id}),
    ));
    assert!(polled.ok, "{polled:?}");
    spawn_terminal.table().shutdown();
}

#[test]
fn native_terminal_drop_does_not_cancel_run_token() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let owner = tool_owner();
    let deps = fixture.native_deps(owner.clone());
    let shutdown = deps.terminal.clone();
    let cancellation = CancellationToken::new();
    let dispatcher = dispatcher_with_cancel(
        owner,
        fixture.root.clone(),
        cancellation.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::new(deps),
    );

    let terminal = dispatcher.dispatch_one(&call(
        "c1",
        "terminal",
        json!({"argv": ["/usr/bin/printf", "ok-term"]}),
    ));
    assert!(terminal.ok, "{terminal:?}");
    assert!(!cancellation.is_cancelled());
    assert_eq!(
        events.types(),
        [
            "tool.requested",
            "tool.started",
            "tool.output",
            "tool.completed"
        ]
    );
    shutdown.table().shutdown();
}

#[test]
fn cancel_during_native_terminal_call_stops_process() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let owner = tool_owner();
    let deps = fixture.native_deps(owner.clone());
    let shutdown = deps.terminal.clone();
    let cancellation = CancellationToken::new();
    let dispatcher = Arc::new(dispatcher_with_cancel(
        owner,
        fixture.root.clone(),
        cancellation.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::new(deps),
    ));

    let worker = {
        let dispatcher = Arc::clone(&dispatcher);
        thread::spawn(move || {
            dispatcher.dispatch_one(&call(
                "c1",
                "terminal",
                json!({"argv": ["/bin/sleep", "30"], "timeout_ms": 10_000}),
            ))
        })
    };
    assert!(
        wait_until(Duration::from_secs(3), || {
            events.types().iter().any(|event| event == "tool.started")
        }),
        "native terminal never started: {:?}",
        events.types()
    );
    cancellation.cancel();
    let result = worker.join().expect("join native terminal");
    assert_eq!(error_code(&result), "cancelled");
    assert!(
        events
            .types()
            .iter()
            .any(|event| event == "tool.failed" || event == "tool.completed"),
        "expected terminal event after cancel: {:?}",
        events.types()
    );
    shutdown.table().shutdown();
}

#[test]
fn owner_denial_rejects_foreign_process_records() {
    let fixture = Fixture::new();
    let table = Arc::new(ProcessTable::new(fixture.process_config()).expect("table"));
    let owner = tool_owner();
    let other = other_owner();
    let files = FileTools::new(fixture.file_config()).expect("files");
    let sink: Arc<dyn ProcessArtifactSink> = files.artifact_store_arc();
    let terminal = TerminalExecutor::new(
        fixture.process_config(),
        Arc::clone(&table),
        ProcessOwner::from(owner.clone()),
    )
    .expect("terminal")
    .with_artifact_sink(Arc::clone(&sink));
    let spawned = terminal.run(TerminalRequest {
        argv: vec!["/bin/sleep".to_string(), "30".to_string()],
        background: true,
        timeout_ms: Some(5_000),
        ..TerminalRequest::default()
    });
    assert!(spawned.ok, "{spawned:?}");
    let process_id = spawned.data["process_id"].as_str().unwrap().to_string();

    let foreign_files = files.with_owner(ArtifactOwner::from(other.clone()));
    let foreign_terminal = TerminalExecutor::new(
        fixture.process_config(),
        Arc::clone(&table),
        ProcessOwner::from(other.clone()),
    )
    .expect("foreign terminal")
    .with_artifact_sink(foreign_files.artifact_store_arc());
    let foreign_process = ProcessExecutor::new(
        fixture.process_config(),
        Arc::clone(&table),
        ProcessOwner::from(other.clone()),
    )
    .expect("foreign process")
    .with_artifact_sink(foreign_files.artifact_store_arc());
    let events = MemoryEvents::new();
    let dispatcher = context_with(
        other,
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::new(NativeExecutionDeps {
            files: foreign_files,
            terminal: foreign_terminal,
            process: foreign_process,
        }),
        default_limits(),
    );
    let denied = dispatcher.dispatch_one(&call(
        "c1",
        "process",
        json!({"action": "poll", "process_id": process_id}),
    ));
    assert!(!denied.ok);
    assert_eq!(error_code(&denied), "process_not_found");
    table.shutdown();
}

#[tokio::test]
async fn service_dispatch_uses_admitted_snapshot_not_live_registry() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("admitted.txt"), "from-admitted\n").expect("write admitted file");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    let limits = RunLimits::new(8, 16, 64 * 1024, &fixture.root).expect("run limits");
    service.set_run_limits(limits).expect("set limits");
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "dispatch"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit");

    let live = {
        let mut entry = rustscript_agent::builtin_entries()
            .into_iter()
            .next()
            .expect("read_file");
        entry.descriptor = ToolDescriptor::new(
            "read_file",
            "A drifted live registry",
            Toolset::CODING,
            "read",
            entry.descriptor.schema,
        );
        ToolRegistry::new([entry]).expect("live registry")
    };
    service
        .set_tool_registry(live)
        .expect("replace live registry");

    let results_calls = [call("c1", "read_file", json!({"path": "admitted.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &results_calls);
    let results = service
        .dispatch_tools(&admitted.run_id, &results_calls)
        .expect("service dispatch");
    assert_eq!(results.len(), 1);
    assert!(results[0].ok, "{:?}", results[0]);
    assert!(results[0].content.contains("from-admitted"));

    let unknown_calls = [call("c2", "not_in_admitted_registry", json!({}))];
    commit_tool_parents(&service, &admitted.run_id, 2, &unknown_calls);
    let unknown = service
        .dispatch_tools(&admitted.run_id, &unknown_calls)
        .expect("unknown dispatch");
    assert_eq!(error_code(&unknown[0]), "unknown_tool");

    let event_types: Vec<String> = service
        .run_events(&admitted.run_id)
        .into_iter()
        .map(|event| event["event"].as_str().unwrap().to_string())
        .collect();
    assert!(event_types.contains(&"tool.requested".to_string()));
    assert!(
        event_types.contains(&"tool.completed".to_string())
            || event_types.contains(&"tool.failed".to_string())
    );
}

fn prefix_items_registry() -> ToolRegistry {
    ToolRegistry::new([ToolRegistryEntry::new(
        ToolDescriptor::new(
            "tuple_tool",
            "2020-12 prefixItems tool",
            Toolset::CODING,
            "read",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "array",
                "prefixItems": [
                    {"type": "string"},
                    {"type": "integer"}
                ],
                "items": false
            }),
        ),
        NativeToolExecutor::Placeholder("tuple_tool".to_string()),
    )])
    .expect("prefix items registry")
}

fn dispatcher_with_registry(
    owner: ToolOwner,
    workspace: PathBuf,
    events: Arc<dyn DurableEventCommitter>,
    executor: Arc<dyn ToolExecutorBoundary>,
    registry: ToolRegistrySnapshot,
    limits: DispatchLimits,
) -> DispatchContext {
    let identity = registry.identity().to_string();
    DispatchContext::new(
        owner,
        workspace,
        CancellationToken::new(),
        far_deadline(),
        registry,
        identity.clone(),
        identity,
        limits,
        events,
        executor,
    )
    .expect("dispatch context")
}

#[test]
fn durable_completed_failure_after_output_returns_persist_failed() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let events = MemoryEvents::new();
    events.fail_on_type("tool.completed");
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::new(fixture.native_deps(tool_owner())),
        default_limits(),
    );
    let result = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "ok.txt"})));
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "event_persist_failed");
    assert_eq!(
        events.types(),
        vec![
            "tool.requested".to_string(),
            "tool.started".to_string(),
            "tool.output".to_string(),
        ]
    );
    assert_no_needles(&event_history(&events), &redact_needles());
}

#[test]
fn max_tool_calls_emits_requested_and_failed_without_effect() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let mut limits = default_limits();
    limits.max_tool_calls = 1;
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        limits,
    );
    let first = dispatcher.dispatch_one(&call("c1", "read_file", json!({"path": "x"})));
    assert!(first.ok, "{first:?}");
    let second = dispatcher.dispatch_one(&call("c2", "read_file", json!({"path": SECRET_NEEDLE})));
    assert!(!second.ok);
    assert_eq!(error_code(&second), "max_tool_calls");
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.types(),
        vec![
            "tool.requested".to_string(),
            "tool.started".to_string(),
            "tool.output".to_string(),
            "tool.completed".to_string(),
            "tool.requested".to_string(),
            "tool.failed".to_string(),
        ]
    );
    let history = event_history(&events);
    assert_no_needles(&history, &redact_needles());
    assert!(history.len() < 32 * 1024);
}

#[test]
fn linked_cancellation_spawn_failure_is_fail_closed_before_effect() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let dispatcher = context_with(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        default_limits(),
    );
    dispatcher.inject_linked_spawn_failure();
    let result = dispatcher.dispatch_one(&call("c1", "terminal", json!({"argv": ["/bin/true"]})));
    assert!(!result.ok, "{result:?}");
    assert_eq!(error_code(&result), "cancellation_unavailable");
    assert_eq!(executor.count.load(Ordering::SeqCst), 0);
}

#[test]
fn draft_2020_12_prefix_items_is_enforced_at_runtime() {
    let fixture = Fixture::new();
    let events = MemoryEvents::new();
    let executor = CountingExecutor::new();
    let registry = prefix_items_registry();
    let snap = registry.snapshot();
    let reused = registry.snapshot();
    let first = snap
        .frozen_argument_validator("tuple_tool")
        .expect("frozen validator");
    let second = reused
        .frozen_argument_validator("tuple_tool")
        .expect("cloned frozen validator");
    assert!(
        std::ptr::eq(first, second),
        "snapshots must reuse the compiled validator"
    );

    let dispatcher = dispatcher_with_registry(
        tool_owner(),
        fixture.root.clone(),
        Arc::clone(&events) as Arc<_>,
        Arc::clone(&executor) as Arc<_>,
        snap,
        default_limits(),
    );
    let valid = dispatcher.dispatch_one(&call("c1", "tuple_tool", json!(["ok", 1])));
    assert!(valid.ok, "{valid:?}");
    let invalid = dispatcher.dispatch_one(&call("c2", "tuple_tool", json!(["ok", "nope"])));
    assert!(!invalid.ok);
    assert_eq!(error_code(&invalid), "invalid_arguments");
    let extra = dispatcher.dispatch_one(&call("c3", "tuple_tool", json!(["ok", 1, true])));
    assert!(!extra.ok);
    assert_eq!(error_code(&extra), "invalid_arguments");
    assert_eq!(executor.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn service_cumulative_budget_and_serial_dispatch_share_run_state() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("a.txt"), "a\n").expect("write a");
    fs::write(fixture.root.join("b.txt"), "b\n").expect("write b");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    let limits = RunLimits::new(8, 1, 64 * 1024, &fixture.root).expect("run limits");
    service.set_run_limits(limits).expect("set limits");
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "dispatch"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit");

    let first_calls = [call("c1", "read_file", json!({"path": "a.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &first_calls);
    let first = service
        .dispatch_tools(&admitted.run_id, &first_calls)
        .expect("first dispatch");
    assert!(first[0].ok, "{:?}", first[0]);
    assert!(service.native_dispatch_retained(&admitted.run_id));

    let second_calls = [call("c2", "read_file", json!({"path": SECRET_NEEDLE}))];
    commit_tool_parents(&service, &admitted.run_id, 2, &second_calls);
    let second = service
        .dispatch_tools(&admitted.run_id, &second_calls)
        .expect("second dispatch");
    assert_eq!(error_code(&second[0]), "max_tool_calls");

    let events: Vec<String> = service
        .run_events(&admitted.run_id)
        .into_iter()
        .filter_map(|event| {
            let name = event["event"].as_str()?;
            name.starts_with("tool.").then(|| name.to_string())
        })
        .collect();
    assert_eq!(
        events,
        vec![
            "tool.requested".to_string(),
            "tool.started".to_string(),
            "tool.output".to_string(),
            "tool.completed".to_string(),
            "tool.requested".to_string(),
            "tool.failed".to_string(),
        ]
    );
    let history = serde_json::to_string(&service.run_events(&admitted.run_id)).expect("history");
    assert_no_needles(&history, &redact_needles());
}

#[tokio::test]
async fn service_concurrent_dispatch_is_serialized_for_one_run() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("a.txt"), "a\n").expect("write a");
    fs::write(fixture.root.join("b.txt"), "b\n").expect("write b");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    let limits = RunLimits::new(8, 8, 64 * 1024, &fixture.root).expect("run limits");
    service.set_run_limits(limits).expect("set limits");
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "dispatch"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit");
    let run_id = admitted.run_id.clone();
    let left = service.clone();
    let right = service.clone();
    let left_id = run_id.clone();
    let right_id = run_id.clone();
    let left_calls = [call("c1", "read_file", json!({"path": "a.txt"}))];
    let right_calls = [call("c2", "read_file", json!({"path": "b.txt"}))];
    commit_tool_parents(&service, &run_id, 1, &left_calls);
    commit_tool_parents(&service, &run_id, 2, &right_calls);
    let left_thread = thread::spawn(move || left.dispatch_tools(&left_id, &left_calls));
    let right_thread = thread::spawn(move || right.dispatch_tools(&right_id, &right_calls));
    let left_result = left_thread
        .join()
        .expect("left join")
        .expect("left dispatch");
    let right_result = right_thread
        .join()
        .expect("right join")
        .expect("right dispatch");
    assert!(left_result[0].ok, "{:?}", left_result[0]);
    assert!(right_result[0].ok, "{:?}", right_result[0]);
    let events: Vec<String> = service
        .run_events(&run_id)
        .into_iter()
        .filter_map(|event| {
            let name = event["event"].as_str()?;
            name.starts_with("tool.").then(|| name.to_string())
        })
        .collect();
    assert_eq!(events.len(), 8);
    for chunk in events.chunks(4) {
        assert_eq!(
            chunk,
            [
                "tool.requested".to_string(),
                "tool.started".to_string(),
                "tool.output".to_string(),
                "tool.completed".to_string()
            ]
        );
    }
}

#[tokio::test]
async fn service_background_process_survives_across_dispatch_calls() {
    let fixture = Fixture::new();
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    let limits = RunLimits::new(8, 8, 64 * 1024, &fixture.root).expect("run limits");
    service.set_run_limits(limits).expect("set limits");
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "dispatch"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit");
    let spawn_calls = [call(
        "c1",
        "terminal",
        json!({"argv": ["/bin/sleep", "30"], "background": true, "timeout_ms": 5000}),
    )];
    commit_tool_parents(&service, &admitted.run_id, 1, &spawn_calls);
    let spawned = service
        .dispatch_tools(&admitted.run_id, &spawn_calls)
        .expect("spawn");
    assert!(spawned[0].ok, "{:?}", spawned[0]);
    let process_id = spawned[0].data["process_id"]
        .as_str()
        .expect("process_id")
        .to_string();
    let poll_calls = [call(
        "c2",
        "process",
        json!({"action": "poll", "process_id": process_id}),
    )];
    commit_tool_parents(&service, &admitted.run_id, 2, &poll_calls);
    let polled = service
        .dispatch_tools(&admitted.run_id, &poll_calls)
        .expect("poll");
    assert!(polled[0].ok, "{:?}", polled[0]);
}

#[tokio::test]
async fn service_live_stop_cancels_blocking_terminal_and_file_search() {
    let fixture = Fixture::new();
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let admitted = admit_run(&service).await;
    let run_id = admitted.run_id.clone();
    let worker = service.clone();
    let worker_id = run_id.clone();
    let worker_calls = [call(
        "c1",
        "terminal",
        json!({"argv": ["/bin/sleep", "30"], "timeout_ms": 30_000}),
    )];
    commit_tool_parents(&service, &run_id, 1, &worker_calls);
    let handle = thread::spawn(move || worker.dispatch_tools(&worker_id, &worker_calls));
    let started = Instant::now();
    loop {
        let events = service.run_events(&run_id);
        if events.iter().any(|event| event["event"] == "tool.started") {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for tool.started"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let status = service.stop(&run_id).expect("stop");
    assert_eq!(status, "stopping");
    let results = handle.join().expect("join").expect("dispatch");
    assert_eq!(error_code(&results[0]), "cancelled");

    let search_fixture = Fixture::new();
    fs::write(search_fixture.root.join("needle.txt"), "needle\n").expect("write search file");
    let (_search_state, search_service) = admit_dispatch_service(&search_fixture).await;
    let admitted_search = admit_run(&search_service).await;
    let entered = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let observer_entered = Arc::clone(&entered);
    let observer_barrier = Arc::clone(&barrier);
    search_service.inject_file_search_entered_observer(Arc::new(move || {
        observer_entered.store(true, Ordering::SeqCst);
        observer_barrier.wait();
    }));
    let searcher = search_service.clone();
    let search_id = admitted_search.run_id.clone();
    let search_calls = [call(
        "c2",
        "search_files",
        json!({"pattern": "needle", "path": "."}),
    )];
    commit_tool_parents(&search_service, &search_id, 1, &search_calls);
    let search_started = Instant::now();
    let search = thread::spawn(move || searcher.dispatch_tools(&search_id, &search_calls));
    let entered_deadline = Instant::now();
    while !entered.load(Ordering::SeqCst) {
        if search.is_finished() {
            let finished = search
                .join()
                .expect("search join")
                .expect("search dispatch");
            panic!("search finished before entering walk: {finished:?}");
        }
        assert!(
            entered_deadline.elapsed() < Duration::from_secs(5),
            "search effect did not enter walk"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let search_status = search_service
        .stop(&admitted_search.run_id)
        .expect("stop search");
    assert_eq!(search_status, "stopping");
    barrier.wait();
    let search_results = search
        .join()
        .expect("search join")
        .expect("search dispatch");
    assert_cancelled_bounded(&search_results[0]);
    assert!(
        search_started.elapsed() < Duration::from_secs(5),
        "search stop did not complete promptly: {:?}",
        search_started.elapsed()
    );
    let search_events: Vec<String> = search_service
        .run_events(&admitted_search.run_id)
        .into_iter()
        .filter_map(|event| {
            let name = event["event"].as_str()?;
            name.starts_with("tool.").then(|| name.to_string())
        })
        .collect();
    assert!(
        search_events.iter().any(|name| name == "tool.started"),
        "expected tool.started before stop, got {search_events:?}"
    );
    assert!(
        search_events.iter().any(|name| name == "tool.failed"),
        "expected cancelled search to complete the prompt with tool.failed, got {search_events:?}"
    );
}

#[tokio::test]
async fn service_cleanup_drops_dispatch_state_on_terminal_session_and_shutdown() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    let limits = RunLimits::new(8, 8, 64 * 1024, &fixture.root).expect("run limits");
    service.set_run_limits(limits).expect("set limits");
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "dispatch"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit");
    let first_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &first_calls);
    service
        .dispatch_tools(&admitted.run_id, &first_calls)
        .expect("dispatch");
    assert!(service.native_dispatch_retained(&admitted.run_id));
    service.mark_terminal(&admitted.run_id);
    assert!(!service.native_dispatch_retained(&admitted.run_id));

    let admitted_session = service
        .admit(AdmitRunRequest {
            input: json!({"message": "session"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit session");
    let session_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted_session.run_id, 1, &session_calls);
    service
        .dispatch_tools(&admitted_session.run_id, &session_calls)
        .expect("session dispatch");
    assert!(service.native_dispatch_retained(&admitted_session.run_id));
    service.cleanup_session_native_dispatch(&admitted_session.session_id);
    assert!(!service.native_dispatch_retained(&admitted_session.run_id));

    let admitted_shutdown = service
        .admit(AdmitRunRequest {
            input: json!({"message": "shutdown"}),
            platform: "dispatch_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit shutdown");
    let shutdown_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted_shutdown.run_id, 1, &shutdown_calls);
    service
        .dispatch_tools(&admitted_shutdown.run_id, &shutdown_calls)
        .expect("shutdown dispatch");
    assert!(service.native_dispatch_retained(&admitted_shutdown.run_id));
    service.shutdown_native_dispatch();
    assert!(!service.native_dispatch_retained(&admitted_shutdown.run_id));
}

#[tokio::test]
async fn service_cleanup_does_not_refill_native_dispatch_or_leave_processes() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let marker = fixture.root.join("hostile.pid");
    let (_state, service) = admit_dispatch_service(&fixture).await;

    let admitted_session = admit_run(&service).await;
    let spawn_calls = [call("c1", "terminal", hostile_ignore_term_args(&marker))];
    commit_tool_parents(&service, &admitted_session.run_id, 1, &spawn_calls);
    let spawned = service
        .dispatch_tools(&admitted_session.run_id, &spawn_calls)
        .expect("spawn hostile");
    assert!(spawned[0].ok, "{:?}", spawned[0]);
    let pid: u32 = wait_for_file(&marker).trim().parse().expect("pid");
    service.cleanup_session_native_dispatch(&admitted_session.session_id);
    assert!(!service.native_dispatch_retained(&admitted_session.run_id));
    let after_cleanup_calls = [call("c2", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted_session.run_id, 2, &after_cleanup_calls);
    let after_cleanup = service
        .dispatch_tools(&admitted_session.run_id, &after_cleanup_calls)
        .expect("dispatch after session cleanup");
    assert_cancelled_bounded(&after_cleanup[0]);
    assert!(!service.native_dispatch_retained(&admitted_session.run_id));
    wait_until_dead(pid);

    let admitted_terminal = admit_run(&service).await;
    service.mark_terminal(&admitted_terminal.run_id);
    let after_terminal = service
        .dispatch_tools(
            &admitted_terminal.run_id,
            &[call("c1", "read_file", json!({"path": "ok.txt"}))],
        )
        .expect("dispatch after terminal");
    assert_cancelled_bounded(&after_terminal[0]);
    assert!(!service.native_dispatch_retained(&admitted_terminal.run_id));

    let admitted_shutdown = admit_run(&service).await;
    service.shutdown_native_dispatch();
    let after_shutdown = service
        .dispatch_tools(
            &admitted_shutdown.run_id,
            &[call("c1", "read_file", json!({"path": "ok.txt"}))],
        )
        .expect("dispatch after shutdown");
    assert_cancelled_bounded(&after_shutdown[0]);
    assert!(!service.native_dispatch_retained(&admitted_shutdown.run_id));
}

#[tokio::test]
async fn concurrent_mark_terminal_versus_first_dispatch_leaves_no_retained_state() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    for _ in 0..32 {
        let admitted = admit_run(&service).await;
        let run_id = admitted.run_id.clone();
        let dispatcher = service.clone();
        let closer = service.clone();
        let dispatch_id = run_id.clone();
        let close_id = run_id.clone();
        let dispatch_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
        commit_tool_parents(&service, &run_id, 1, &dispatch_calls);
        let dispatch =
            thread::spawn(move || dispatcher.dispatch_tools(&dispatch_id, &dispatch_calls));
        let close = thread::spawn(move || closer.mark_terminal(&close_id));
        let results = dispatch.join().expect("dispatch join").expect("dispatch");
        close.join().expect("close join");
        assert!(!service.native_dispatch_retained(&run_id));
        if !results[0].ok {
            assert_eq!(error_code(&results[0]), "cancelled");
        }
    }
}

#[tokio::test]
async fn session_cleanup_does_not_block_handle_stop_or_admission_during_hostile_teardown() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let marker = fixture.root.join("lock-hostile.pid");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let entered = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let observer_entered = Arc::clone(&entered);
    let observer_barrier = Arc::clone(&barrier);
    service.inject_native_dispatch_shutdown_observer(Arc::new(move || {
        observer_entered.store(true, Ordering::SeqCst);
        observer_barrier.wait();
    }));

    let admitted_hostile = admit_run(&service).await;
    let admitted_other = admit_run(&service).await;
    let spawn_calls = [call("c1", "terminal", hostile_ignore_term_args(&marker))];
    commit_tool_parents(&service, &admitted_hostile.run_id, 1, &spawn_calls);
    let spawned = service
        .dispatch_tools(&admitted_hostile.run_id, &spawn_calls)
        .expect("spawn hostile");
    assert!(spawned[0].ok, "{:?}", spawned[0]);
    let pid: u32 = wait_for_file(&marker).trim().parse().expect("pid");

    let cleanup_service = service.clone();
    let session_id = admitted_hostile.session_id.clone();
    let cleanup = thread::spawn(move || {
        cleanup_service.cleanup_session_native_dispatch(&session_id);
    });
    let wait_start = Instant::now();
    while !entered.load(Ordering::SeqCst) {
        assert!(
            wait_start.elapsed() < Duration::from_secs(2),
            "cleanup did not enter native dispatch shutdown"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        pid_alive(pid),
        "hostile process should still be running during teardown"
    );
    let started = Instant::now();
    assert!(service.handle(&admitted_other.run_id).is_some());
    assert_eq!(
        service.stop(&admitted_other.run_id).expect("stop other"),
        "stopping"
    );
    let admitted_during = admit_run(&service).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "handle/stop/admission blocked for {elapsed:?} during hostile cleanup"
    );
    assert!(service.handle(&admitted_during.run_id).is_some());
    barrier.wait();
    cleanup.join().expect("cleanup join");
    wait_until_dead(pid);
    assert!(!service.native_dispatch_retained(&admitted_hostile.run_id));
}

fn derived_artifact_root(workspace: &Path) -> PathBuf {
    let name = workspace
        .file_name()
        .map(|component| component.to_string_lossy().into_owned())
        .unwrap_or_else(|| "workspace".to_string());
    workspace
        .parent()
        .expect("workspace parent")
        .join(format!(".rustscript-agent-state-{name}"))
}

#[tokio::test]
async fn same_workspace_two_runs_share_one_artifact_store() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let first = admit_run(&service).await;
    let second = admit_run(&service).await;
    let first_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    let second_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &first.run_id, 1, &first_calls);
    commit_tool_parents(&service, &second.run_id, 1, &second_calls);
    let first_result = service
        .dispatch_tools(&first.run_id, &first_calls)
        .expect("first dispatch");
    let second_result = service
        .dispatch_tools(&second.run_id, &second_calls)
        .expect("second dispatch");
    assert!(first_result[0].ok, "{:?}", first_result[0]);
    assert!(second_result[0].ok, "{:?}", second_result[0]);
    let store_a = service
        .native_artifact_store(&first.run_id)
        .expect("first store");
    let store_b = service
        .native_artifact_store(&second.run_id)
        .expect("second store");
    assert!(
        Arc::ptr_eq(&store_a, &store_b),
        "concurrent runs in one workspace must share one ArtifactStore"
    );
}

#[tokio::test]
async fn concurrent_same_workspace_first_inits_share_one_store() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let first = admit_run(&service).await;
    let second = admit_run(&service).await;
    let left = service.clone();
    let right = service.clone();
    let left_id = first.run_id.clone();
    let right_id = second.run_id.clone();
    let left_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    let right_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &first.run_id, 1, &left_calls);
    commit_tool_parents(&service, &second.run_id, 1, &right_calls);
    let left_thread = thread::spawn(move || left.dispatch_tools(&left_id, &left_calls));
    let right_thread = thread::spawn(move || right.dispatch_tools(&right_id, &right_calls));
    let left_result = left_thread
        .join()
        .expect("left join")
        .expect("left dispatch");
    let right_result = right_thread
        .join()
        .expect("right join")
        .expect("right dispatch");
    assert!(left_result[0].ok, "{:?}", left_result[0]);
    assert!(right_result[0].ok, "{:?}", right_result[0]);
    let store_a = service
        .native_artifact_store(&first.run_id)
        .expect("first store");
    let store_b = service
        .native_artifact_store(&second.run_id)
        .expect("second store");
    assert!(Arc::ptr_eq(&store_a, &store_b));
}

#[tokio::test]
async fn different_workspace_artifact_stores_stay_isolated() {
    let left_fixture = Fixture::new();
    let right_fixture = Fixture::new();
    fs::write(left_fixture.root.join("ok.txt"), "left\n").expect("write left");
    fs::write(right_fixture.root.join("ok.txt"), "right\n").expect("write right");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    service
        .set_run_limits(RunLimits::new(8, 8, 64 * 1024, &left_fixture.root).expect("left limits"))
        .expect("set left");
    let left_run = admit_run(&service).await;
    service
        .set_run_limits(RunLimits::new(8, 8, 64 * 1024, &right_fixture.root).expect("right limits"))
        .expect("set right");
    let right_run = admit_run(&service).await;
    let left_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    let right_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &left_run.run_id, 1, &left_calls);
    commit_tool_parents(&service, &right_run.run_id, 1, &right_calls);
    let left_result = service
        .dispatch_tools(&left_run.run_id, &left_calls)
        .expect("left dispatch");
    let right_result = service
        .dispatch_tools(&right_run.run_id, &right_calls)
        .expect("right dispatch");
    assert!(left_result[0].ok, "{:?}", left_result[0]);
    assert!(right_result[0].ok, "{:?}", right_result[0]);
    let store_a = service
        .native_artifact_store(&left_run.run_id)
        .expect("left store");
    let store_b = service
        .native_artifact_store(&right_run.run_id)
        .expect("right store");
    assert!(!Arc::ptr_eq(&store_a, &store_b));
}

#[tokio::test]
async fn artifact_store_pool_drops_dead_stores_so_root_can_reopen() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let admitted = admit_run(&service).await;
    let pool_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &pool_calls);
    service
        .dispatch_tools(&admitted.run_id, &pool_calls)
        .expect("dispatch");
    service.mark_terminal(&admitted.run_id);
    assert!(!service.native_dispatch_retained(&admitted.run_id));
    let config = ArtifactStoreConfig::for_root(derived_artifact_root(&fixture.root));
    ArtifactStore::with_config(config).expect("dead pool entry must release the exclusive flock");
}

#[tokio::test]
async fn native_dispatch_init_preserves_artifact_store_error_code() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let artifact_root = derived_artifact_root(&fixture.root);
    fs::write(&artifact_root, b"not-a-directory").expect("block artifact root with a file");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let admitted = admit_run(&service).await;
    let init_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &init_calls);
    let error = service
        .dispatch_tools(&admitted.run_id, &init_calls)
        .expect_err("blocked artifact root must fail native init");
    match error {
        RunContextError::InvalidMetadata { reason, .. } => {
            assert!(
                reason.contains("invalid_config"),
                "typed ArtifactStoreError code must survive native init: {reason}"
            );
        }
        other => panic!("expected InvalidMetadata, got {other:?}"),
    }
}

#[tokio::test]
async fn admitted_32kib_cap_artifacts_at_executor_layer() {
    let fixture = Fixture::new();
    let payload = "0123456789abcdef".repeat(40 * 1024 / 16);
    fs::write(fixture.root.join("mid.txt"), &payload).expect("write mid file");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    service
        .set_run_limits(RunLimits::new(8, 8, 32 * 1024, &fixture.root).expect("32KiB limits"))
        .expect("set limits");
    let admitted = admit_run(&service).await;
    let mid_calls = [call("c1", "read_file", json!({"path": "mid.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &mid_calls);
    let result = service
        .dispatch_tools(&admitted.run_id, &mid_calls)
        .expect("dispatch");
    assert!(
        result[0].truncated || !result[0].artifacts.is_empty(),
        "32KiB admitted cap must artifact at the executor: {:?}",
        result[0]
    );
    let encoded = serde_json::to_vec(&result[0]).expect("encode");
    assert!(
        encoded.len() <= 32 * 1024,
        "serialized cap is defense-in-depth: {}",
        encoded.len()
    );
}

#[tokio::test]
async fn admitted_1mib_cap_keeps_over_64kib_inline() {
    let fixture = Fixture::new();
    let payload = "0123456789abcdef".repeat(80 * 1024 / 16);
    fs::write(fixture.root.join("large.txt"), &payload).expect("write large file");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    service
        .set_run_limits(RunLimits::new(8, 8, 1024 * 1024, &fixture.root).expect("1MiB limits"))
        .expect("set limits");
    let admitted = admit_run(&service).await;
    let large_calls = [call("c1", "read_file", json!({"path": "large.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &large_calls);
    let result = service
        .dispatch_tools(&admitted.run_id, &large_calls)
        .expect("dispatch");
    assert!(result[0].ok, "{:?}", result[0]);
    assert!(
        result[0].artifacts.is_empty(),
        "80KiB payload must stay inline under the 1MiB admitted cap: {:?}",
        result[0]
    );
    assert!(result[0].content.contains("0123456789abcdef"));
    let encoded = serde_json::to_vec(&result[0]).expect("encode");
    assert!(encoded.len() <= 1024 * 1024, "{}", encoded.len());
    assert!(
        encoded.len() > 64 * 1024,
        "payload should exceed the old 64KiB executor default"
    );
}

#[tokio::test]
async fn first_init_close_does_not_wait_for_init_io() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let entered = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let observer_entered = Arc::clone(&entered);
    let observer_barrier = Arc::clone(&barrier);
    service.inject_native_dispatch_init_entered_observer(Arc::new(move || {
        observer_entered.store(true, Ordering::SeqCst);
        observer_barrier.wait();
    }));
    let admitted = admit_run(&service).await;
    let run_id = admitted.run_id.clone();
    let dispatcher = service.clone();
    let dispatch_id = run_id.clone();
    let init_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &run_id, 1, &init_calls);
    let dispatch = thread::spawn(move || dispatcher.dispatch_tools(&dispatch_id, &init_calls));
    let wait_start = Instant::now();
    while !entered.load(Ordering::SeqCst) {
        assert!(
            wait_start.elapsed() < Duration::from_secs(2),
            "native dispatch init did not start"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let closer = service.clone();
    let close_id = run_id.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        closer.mark_terminal(&close_id);
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_millis(500))
        .expect("mark_terminal must not wait for init IO");
    barrier.wait();
    let results = dispatch.join().expect("dispatch join").expect("dispatch");
    assert!(!service.native_dispatch_retained(&run_id));
    if !results[0].ok {
        assert_eq!(error_code(&results[0]), "cancelled");
    }
}

#[tokio::test]
async fn blocked_put_then_cleanup_leaves_no_object_reservation_or_bytes() {
    let fixture = Fixture::new();
    let payload = "0123456789abcdef".repeat(8 * 1024);
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write small");
    fs::write(fixture.root.join("large.txt"), &payload).expect("write large");
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("gateway state");
    let service = state.service();
    service
        .set_run_limits(RunLimits::new(8, 8, 32 * 1024, &fixture.root).expect("32KiB limits"))
        .expect("set limits");
    let admitted = admit_run(&service).await;
    let prime_calls = [call("c0", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &prime_calls);
    service
        .dispatch_tools(&admitted.run_id, &prime_calls)
        .expect("prime dispatch");
    let store = service
        .native_artifact_store(&admitted.run_id)
        .expect("store after init");
    let entered = Arc::new(AtomicBool::new(false));
    let hold = Arc::new(Barrier::new(2));
    let observer_entered = Arc::clone(&entered);
    let observer_hold = Arc::clone(&hold);
    store.inject_put_entered_observer(Arc::new(move || {
        observer_entered.store(true, Ordering::SeqCst);
        observer_hold.wait();
    }));
    let dispatcher = service.clone();
    let dispatch_id = admitted.run_id.clone();
    let overflow_calls = [call("c1", "read_file", json!({"path": "large.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 2, &overflow_calls);
    let dispatch = thread::spawn(move || dispatcher.dispatch_tools(&dispatch_id, &overflow_calls));
    let wait_start = Instant::now();
    while !entered.load(Ordering::SeqCst) {
        assert!(
            wait_start.elapsed() < Duration::from_secs(2),
            "overflow put did not start"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let cleanup_service = service.clone();
    let session_id = admitted.session_id.clone();
    let cleanup = thread::spawn(move || {
        cleanup_service.cleanup_session_native_dispatch(&session_id);
    });
    let closed_start = Instant::now();
    while !service.native_dispatch_closed(&admitted.run_id) {
        assert!(
            closed_start.elapsed() < Duration::from_secs(2),
            "cleanup did not close native dispatch"
        );
        thread::sleep(Duration::from_millis(5));
    }
    hold.wait();
    dispatch.join().expect("dispatch join").expect("dispatch");
    cleanup.join().expect("cleanup join");
    assert_eq!(store.object_count(), 0);
    assert_eq!(store.total_bytes(), 0);
    assert_eq!(store.reserved_count(), 0);
    assert_eq!(store.reserved_bytes(), 0);
    assert!(
        store
            .confined_object_names()
            .expect("confined names")
            .is_empty()
    );
    let after_calls = [call("c2", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 3, &after_calls);
    let after = service
        .dispatch_tools(&admitted.run_id, &after_calls)
        .expect("sticky closed dispatch");
    assert_cancelled_bounded(&after[0]);
}

#[tokio::test]
async fn native_dispatch_init_panic_wakes_waiters_and_allows_retry() {
    // Empty restore: the init guard returns the slot to Empty, waiters wake,
    // and a later dispatch can initialize Ready. Closed-vs-panic is covered by
    // `native_dispatch_init_panic_does_not_overwrite_closed_and_redrive_cancels_once`.
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let admitted = admit_run(&service).await;
    let run_id = admitted.run_id.clone();

    let entered = Arc::new(Barrier::new(2));
    let panic_gate = Arc::new(Barrier::new(2));
    let panic_once = Arc::new(AtomicBool::new(true));
    let observer_entered = Arc::clone(&entered);
    let observer_gate = Arc::clone(&panic_gate);
    let observer_panic = Arc::clone(&panic_once);
    service.inject_native_dispatch_init_entered_observer(Arc::new(move || {
        if observer_panic.swap(false, Ordering::SeqCst) {
            observer_entered.wait();
            observer_gate.wait();
            panic!("injected native dispatch init panic");
        }
    }));

    let init_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &run_id, 1, &init_calls);
    let initiator = {
        let dispatcher = service.clone();
        let dispatch_id = run_id.clone();
        thread::spawn(move || dispatcher.dispatch_tools(&dispatch_id, &init_calls))
    };
    entered.wait();

    let waiter_calls = [call("c2", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &run_id, 2, &waiter_calls);
    let (waiter_tx, waiter_rx) = mpsc::sync_channel(1);
    let waiter = {
        let dispatcher = service.clone();
        let dispatch_id = run_id.clone();
        thread::spawn(move || {
            let result = dispatcher.dispatch_tools(&dispatch_id, &waiter_calls);
            let _ = waiter_tx.send(result);
        })
    };

    panic_gate.wait();
    assert!(
        initiator.join().is_err(),
        "init thread must propagate the injected panic"
    );
    let waiter_result = waiter_rx
        .recv_timeout(Duration::from_secs(8))
        .expect("concurrent waiter must complete after init panic recovery");
    waiter.join().expect("waiter join");
    let waiter_results = waiter_result.expect("waiter dispatch after recovered init");
    assert!(
        waiter_results[0].ok,
        "recovered waiter must initialize successfully: {:?}",
        waiter_results[0]
    );

    let retry_calls = [call("c3", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &run_id, 3, &retry_calls);
    let retry = service
        .dispatch_tools(&run_id, &retry_calls)
        .expect("retry after init panic");
    assert!(retry[0].ok, "{:?}", retry[0]);
    assert!(service.native_dispatch_retained(&run_id));
    assert!(!service.native_dispatch_closed(&run_id));
    assert_eq!(service.process_owner_count(&run_id), 0);
}

#[tokio::test]
async fn native_dispatch_init_error_can_retry_after_fixing_artifact_root() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("ok.txt"), "ok\n").expect("write");
    let artifact_root = derived_artifact_root(&fixture.root);
    fs::write(&artifact_root, b"not-a-directory").expect("block artifact root with a file");
    let (_state, service) = admit_dispatch_service(&fixture).await;
    let admitted = admit_run(&service).await;
    let init_calls = [call("c1", "read_file", json!({"path": "ok.txt"}))];
    commit_tool_parents(&service, &admitted.run_id, 1, &init_calls);
    service
        .dispatch_tools(&admitted.run_id, &init_calls)
        .expect_err("blocked artifact root must fail native init");
    assert!(!service.native_dispatch_retained(&admitted.run_id));
    assert!(!service.native_dispatch_closed(&admitted.run_id));
    fs::remove_file(&artifact_root).expect("unblock artifact root");
    let retry = service
        .dispatch_tools(&admitted.run_id, &init_calls)
        .expect("retry after init error");
    assert!(retry[0].ok, "{:?}", retry[0]);
    assert!(service.native_dispatch_retained(&admitted.run_id));
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
}
