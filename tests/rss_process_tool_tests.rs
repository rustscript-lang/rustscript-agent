//! Native-equivalence tests for RSS `terminal` and `process`.
//!
//! RSS modules own argument validation, poll loops, and canonical envelopes.
//! Native `TerminalExecutor` / `ProcessExecutor` are the oracle. Opaque handle
//! IDs and artifact IDs are projected before exact envelope comparison.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::capabilities::{
    ApprovalGate, ArtifactCapability, ArtifactLimits, CancellationFlag, CapabilityLifecycle,
    CapabilityOwner, CapabilityRisk, DurableStarted, DurableToolLifecycle, LifecycleClock,
    LifecycleError, LifecycleLimits, NeverCancelled, PrepareMetadata, PrepareOutcome,
    ProcessCapability, ProcessLimits, SystemClock, TokenIssuer, UuidIssuer,
};
use rustscript_agent::config::ProcessToolConfig;
use rustscript_agent::tools::{
    ProcessArtifactSink, ProcessExecutor, ProcessOwner, ProcessTable, TerminalExecutor, ToolResult,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, ToolRegistry};
use rustscript_vm::{CancellationToken, Value as VmValue};
use serde_json::{Value, json};
use uuid::Uuid;

fn json_to_vm_value(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::Null,
        Value::Bool(value) => VmValue::Bool(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                VmValue::Int(value)
            } else {
                VmValue::Float(value.as_f64().expect("finite json number"))
            }
        }
        Value::String(value) => VmValue::string(value),
        Value::Array(values) => VmValue::Array(std::sync::Arc::new(
            values.iter().map(json_to_vm_value).collect::<Vec<_>>(),
        )),
        Value::Object(entries) => VmValue::map(
            entries
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

fn vm_value_to_json(value: &VmValue) -> Value {
    match value {
        VmValue::Null => Value::Null,
        VmValue::Int(value) => json!(value),
        VmValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        VmValue::Bool(value) => json!(value),
        VmValue::String(value) => Value::String(value.to_string()),
        VmValue::Bytes(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        VmValue::Array(values) => Value::Array(values.iter().map(vm_value_to_json).collect()),
        VmValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        VmValue::Callable(_) => Value::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &VmValue) -> String {
    match value {
        VmValue::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

const REGISTRY_IDENTITY: &str = "rss-process-tool-equivalence";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn unique_temp_parent(label: &str) -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "rss-proc-{}-{}-{}-{}",
        label.replace('/', "-"),
        std::process::id(),
        sequence,
        Uuid::new_v4().simple()
    ))
}

struct Fixture {
    root: PathBuf,
    parent: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let mut last_error = None;
        for _ in 0..8 {
            let parent = unique_temp_parent(label);
            if parent.exists() {
                continue;
            }
            let root = parent.join("workspace");
            match fs::create_dir_all(&root) {
                Ok(()) => return Self { root, parent },
                Err(error) => last_error = Some((parent, error)),
            }
        }
        let (parent, error) = last_error.expect("fixture create attempts");
        panic!("create rss process fixture {}: {error}", parent.display());
    }

    fn config(&self) -> ProcessToolConfig {
        ProcessToolConfig::for_workspace(&self.root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

struct MemoryDurable {
    started: Mutex<Vec<DurableStarted>>,
    results: Mutex<std::collections::HashMap<String, Value>>,
    interrupted: Mutex<Vec<String>>,
    parent_ok: Mutex<bool>,
    active: Mutex<bool>,
    fail_next_commit: AtomicBool,
    commit_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl MemoryDurable {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Mutex::new(Vec::new()),
            results: Mutex::new(std::collections::HashMap::new()),
            interrupted: Mutex::new(Vec::new()),
            parent_ok: Mutex::new(true),
            active: Mutex::new(true),
            fail_next_commit: AtomicBool::new(false),
            commit_hook: Mutex::new(None),
        })
    }

    fn started_len(&self) -> usize {
        self.started.lock().expect("started").len()
    }

    #[allow(dead_code)]
    fn started_call_ids(&self) -> Vec<String> {
        self.started
            .lock()
            .expect("started")
            .iter()
            .map(|record| record.call_id.clone())
            .collect()
    }

    fn stored_result(&self, call_id: &str) -> Option<Value> {
        self.results.lock().expect("results").get(call_id).cloned()
    }

    fn fail_next_commit(&self) {
        self.fail_next_commit.store(true, Ordering::SeqCst);
    }

    fn on_commit(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.commit_hook.lock().expect("commit hook") = Some(Arc::new(hook));
    }
}

impl DurableToolLifecycle for MemoryDurable {
    fn assert_active_run(&self, _run_id: &str) -> Result<(), LifecycleError> {
        if *self.active.lock().expect("active") {
            Ok(())
        } else {
            Err(LifecycleError::InactiveRun)
        }
    }

    fn prepare_parent(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), LifecycleError> {
        if *self.parent_ok.lock().expect("parent") {
            Ok(())
        } else {
            Err(LifecycleError::MissingParent)
        }
    }

    fn replay_result(
        &self,
        _run_id: &str,
        call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        Ok(self.results.lock().expect("results").get(call_id).cloned())
    }

    fn commit_started(&self, record: &DurableStarted) -> Result<(), LifecycleError> {
        self.started.lock().expect("started").push(record.clone());
        Ok(())
    }

    fn commit_result(&self, call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
        if let Some(hook) = self.commit_hook.lock().expect("commit hook").clone() {
            hook();
        }
        if self.fail_next_commit.load(Ordering::SeqCst) {
            return Err(LifecycleError::ResultCommitFailed(
                "injected result failure".to_string(),
            ));
        }
        self.results
            .lock()
            .expect("results")
            .insert(call_id.to_string(), result.clone());
        Ok(json!({
            "ok": true,
            "kind": "committed",
            "call_id": call_id,
            "result": result,
        }))
    }

    fn interrupt(&self, call_id: &str) -> Result<(), LifecycleError> {
        self.interrupted
            .lock()
            .expect("interrupted")
            .push(call_id.to_string());
        Ok(())
    }
}

struct AllowAll;

impl ApprovalGate for AllowAll {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Ok(metadata.risk_class)
    }
}

struct DenyAll;

impl ApprovalGate for DenyAll {
    fn authorize(&self, _metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Err(LifecycleError::ApprovalDenied {
            reason: "execute tools are not approved".to_string(),
        })
    }
}

struct FlagCancel {
    cancelled: AtomicBool,
}

impl FlagCancel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
        })
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl CancellationFlag for FlagCancel {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

fn rss_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rss/tools")
        .join(name)
}

fn compile_rss(name: &str) -> AgentRunner {
    compile_rss_with_fuel(name, AgentConfig::default().fuel)
}

fn compile_rss_with_fuel(name: &str, fuel: Option<u64>) -> AgentRunner {
    AgentRunner::from_file(
        rss_path(name),
        AgentConfig {
            fuel,
            ..AgentConfig::default()
        },
    )
    .unwrap_or_else(|error| {
        panic!("compile {name}: {error}");
    })
}

fn rss_config_json(config: &ProcessToolConfig) -> Value {
    json!({
        "default_timeout_ms": u64::try_from(config.default_timeout.as_millis()).unwrap_or(u64::MAX),
        "max_timeout_ms": u64::try_from(config.max_timeout.as_millis()).unwrap_or(u64::MAX),
        "max_output_bytes": config.max_output_bytes,
        "max_stream_bytes": config.max_stream_bytes,
        "max_stdin_bytes": config.max_stdin_bytes,
    })
}

fn process_limits(config: &ProcessToolConfig) -> ProcessLimits {
    ProcessLimits {
        timeout_ms: u64::try_from(config.max_timeout.as_millis()).unwrap_or(u64::MAX),
        stdout_limit: config.max_stream_bytes,
        stderr_limit: config.max_stream_bytes,
        total_limit: config.max_stream_bytes,
        stdin_limit: config.max_stdin_bytes,
        log_limit: config.max_stream_bytes,
    }
}

fn owner() -> CapabilityOwner {
    CapabilityOwner::new("profile-test", "session-test", "run-test").expect("owner")
}

fn process_owner() -> ProcessOwner {
    ProcessOwner::new("profile-test", "session-test", "run-test").expect("owner")
}

fn build_lifecycle(
    workspace: &Path,
    durable: Arc<MemoryDurable>,
    approval: Arc<dyn ApprovalGate>,
    cancellation: Arc<dyn CancellationFlag>,
    clock: Arc<dyn LifecycleClock>,
    deadline_ms: u64,
) -> CapabilityLifecycle {
    CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity(REGISTRY_IDENTITY)
        .workspace(workspace)
        .limits(LifecycleLimits {
            max_tool_calls: 64,
            max_output_bytes: 1024 * 1024,
            max_summary_bytes: 256,
        })
        .deadline_ms(deadline_ms)
        .clock(clock)
        .tokens(Arc::new(UuidIssuer) as Arc<dyn TokenIssuer>)
        .durable(durable)
        .approval(approval)
        .cancellation(cancellation)
        .build()
        .expect("lifecycle")
}

struct NativePair {
    terminal: TerminalExecutor,
    process: ProcessExecutor,
    table: Arc<ProcessTable>,
}

impl NativePair {
    fn new(config: ProcessToolConfig) -> Self {
        let table = Arc::new(ProcessTable::new(config.clone()).expect("process table"));
        let terminal = TerminalExecutor::new(config.clone(), Arc::clone(&table), process_owner())
            .expect("terminal");
        let process =
            ProcessExecutor::new(config, Arc::clone(&table), process_owner()).expect("process");
        Self {
            terminal,
            process,
            table,
        }
    }

    fn with_artifact_sink(config: ProcessToolConfig, sink: Arc<dyn ProcessArtifactSink>) -> Self {
        let pair = Self::new(config);
        Self {
            terminal: pair.terminal.with_artifact_sink(Arc::clone(&sink)),
            process: pair.process.with_artifact_sink(sink),
            table: pair.table,
        }
    }
}

#[allow(dead_code)]
struct RssRun {
    result: Value,
    started: usize,
    durable: Arc<MemoryDurable>,
    call_id: String,
    processes: Arc<ProcessCapability>,
    lifecycle: Arc<CapabilityLifecycle>,
    artifacts: Option<Arc<ArtifactCapability>>,
}

struct RssExec {
    module: &'static str,
    tool_name: &'static str,
    arguments: Value,
    durable: Arc<MemoryDurable>,
    approval: Arc<dyn ApprovalGate>,
    cancellation: Arc<dyn CancellationFlag>,
    clock: Arc<dyn LifecycleClock>,
    deadline_ms: u64,
    call_id: String,
    unlimited_fuel: bool,
    shared_lifecycle: Option<Arc<CapabilityLifecycle>>,
    shared_processes: Option<Arc<ProcessCapability>>,
    artifact_limits: ArtifactLimits,
    enable_artifacts: bool,
}

fn default_artifact_limits() -> ArtifactLimits {
    ArtifactLimits {
        max_object_bytes: 8 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        max_objects: 64,
    }
}

fn run_rss_exec(fixture: &Fixture, config: &ProcessToolConfig, exec: RssExec) -> RssRun {
    let lifecycle = match exec.shared_lifecycle.clone() {
        Some(lifecycle) => lifecycle,
        None => Arc::new(build_lifecycle(
            &fixture.root,
            Arc::clone(&exec.durable),
            Arc::clone(&exec.approval),
            Arc::clone(&exec.cancellation),
            Arc::clone(&exec.clock),
            exec.deadline_ms,
        )),
    };
    let processes = match exec.shared_processes.clone() {
        Some(processes) => processes,
        None => Arc::new(
            ProcessCapability::new(lifecycle.as_ref().clone(), owner(), process_limits(config))
                .expect("process capability"),
        ),
    };
    let artifacts = if exec.enable_artifacts {
        Some(Arc::new(
            ArtifactCapability::new(lifecycle.as_ref().clone(), owner(), exec.artifact_limits)
                .expect("artifacts"),
        ))
    } else {
        None
    };
    let host = AgentHostBridges {
        lifecycle: Some(Arc::clone(&lifecycle)),
        capability_owner: Some(owner()),
        processes: Some(Arc::clone(&processes)),
        artifacts: artifacts.clone(),
        ..AgentHostBridges::default()
    };
    let context = json!({
        "kind": "execute",
        "arguments": exec.arguments,
        "prepare": {
            "run_id": "run-test",
            "call_id": exec.call_id,
            "name": exec.tool_name,
            "argument_digest": "digest",
            "registry_identity": REGISTRY_IDENTITY,
            "risk_class": "execute",
            "summary": exec.tool_name,
        },
        "config": rss_config_json(config),
    });
    let runner = if exec.unlimited_fuel {
        compile_rss_with_fuel(exec.module, None)
    } else {
        compile_rss(exec.module)
    };
    let output = runner
        .with_host(host)
        .run_with_context(json_to_vm_value(&context))
        .unwrap_or_else(|error| panic!("rss {} run failed: {error}", exec.module));
    RssRun {
        result: unwrap_committed(vm_value_to_json(&output)),
        started: exec.durable.started_len(),
        durable: Arc::clone(&exec.durable),
        call_id: exec.call_id.clone(),
        processes,
        lifecycle,
        artifacts,
    }
}

fn default_exec(module: &'static str, tool_name: &'static str, arguments: Value) -> RssExec {
    let clock = Arc::new(SystemClock);
    let deadline_ms = clock.now_ms() + 60_000;
    RssExec {
        module,
        tool_name,
        arguments,
        durable: MemoryDurable::new(),
        approval: Arc::new(AllowAll),
        cancellation: Arc::new(NeverCancelled),
        clock,
        deadline_ms,
        call_id: format!("call-{}", NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)),
        unlimited_fuel: false,
        shared_lifecycle: None,
        shared_processes: None,
        artifact_limits: default_artifact_limits(),
        enable_artifacts: true,
    }
}

fn unwrap_committed(value: Value) -> Value {
    if value.get("kind").and_then(Value::as_str) == Some("committed") {
        value.get("result").cloned().unwrap_or(value)
    } else {
        value
    }
}

fn native_descriptor(name: &str) -> Value {
    ToolRegistry::builtin()
        .expect("builtin registry")
        .snapshot()
        .schemas()
        .as_array()
        .expect("descriptor array")
        .iter()
        .find(|value| value["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("missing native descriptor {name}"))
}

fn native_envelope(result: &ToolResult) -> Value {
    serde_json::to_value(result).expect("serialize native tool result")
}

fn canonical_envelope(value: &Value) -> Value {
    let parsed: ToolResult =
        serde_json::from_value(value.clone()).expect("canonical tool result schema");
    serde_json::to_value(parsed).expect("serialize canonical tool result")
}

fn project_opaque_ids(value: &Value) -> Value {
    let mut projected = project_artifact_ids(value);
    if let Some(id) = projected
        .pointer_mut("/data/process_id")
        .filter(|value| value.as_str().is_some())
    {
        *id = json!("<handle>");
    }
    projected
}

fn project_artifact_ids(value: &Value) -> Value {
    let ids: Vec<String> = value
        .get("artifacts")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut projected = value.clone();
    if let Some(entries) = projected.get_mut("artifacts").and_then(Value::as_array_mut) {
        for (index, slot) in entries.iter_mut().enumerate() {
            *slot = json!(format!("artifact-{index}"));
        }
    }
    if let Some(content) = projected
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        let mut rewritten = content;
        for (index, id) in ids.iter().enumerate() {
            rewritten = rewritten.replace(id, &format!("artifact-{index}"));
        }
        projected["content"] = json!(rewritten);
    }
    projected
}

fn assert_exact_envelope(native: &ToolResult, rss: &Value) {
    let native_json = native_envelope(native);
    let rss_json = canonical_envelope(rss);
    assert_eq!(
        project_opaque_ids(&native_json),
        project_opaque_ids(&rss_json),
        "exact canonical envelopes must match\nnative={native_json}\nrss={rss_json}"
    );
    let encoded = serde_json::to_string(rss).expect("encode rss");
    assert!(
        !encoded.contains("/proc/"),
        "rss envelope leaked proc path: {encoded}"
    );
}

fn assert_terminal_eq(fixture: &Fixture, arguments: Value) {
    let config = fixture.config();
    let native = NativePair::new(config.clone()).terminal.execute(&arguments);
    let rss = run_rss_exec(
        fixture,
        &config,
        default_exec("terminal.rss", "terminal", arguments),
    );
    assert_exact_envelope(&native, &rss.result);
    if !native.ok
        && native.error.as_ref().is_some_and(|error| {
            matches!(
                error.code.as_str(),
                "invalid_argv" | "invalid_timeout" | "invalid_stdin" | "invalid_output_limit"
            )
        })
    {
        assert_eq!(rss.started, 0, "invalid args must not prepare");
    }
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
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("pid {pid} is still alive");
}

fn proc_children(pid: u32) -> Vec<u32> {
    fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|value| value.parse().ok())
        .collect()
}

fn collect_tree(pid: u32) -> Vec<u32> {
    let mut out = vec![pid];
    let mut stack = vec![pid];
    while let Some(current) = stack.pop() {
        for child in proc_children(current) {
            if !out.contains(&child) {
                out.push(child);
                stack.push(child);
            }
        }
    }
    out
}

fn error_code(value: &Value) -> &str {
    value
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

#[test]
fn rss_terminal_and_process_modules_compile() {
    let _ = compile_rss("terminal.rss");
    let _ = compile_rss("process.rss");
}

#[test]
fn rss_terminal_and_process_descriptors_match_native() {
    for (module, name) in [("terminal.rss", "terminal"), ("process.rss", "process")] {
        let runner = compile_rss(module);
        let output = runner
            .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
            .expect("descriptor run");
        let rss = vm_value_to_json(&output);
        assert_eq!(rss, native_descriptor(name));
        assert_eq!(rss["toolset"], json!("process"));
        assert_eq!(rss["risk_class"], json!("execute"));
    }
}

#[test]
fn foreground_echo_stdout_stderr_exit_empty_multibyte_and_nul_match_native() {
    let fixture = Fixture::new("echo");
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/echo", "hello-rss-process"]}),
    );
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/echo", "-n"]}));
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/sh", "-c", "printf '你好\\n'"]}),
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/sh", "-c", "printf 'a\\0b'"]}),
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/sh", "-c", "printf 'err' 1>&2; exit 3"]}),
    );
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/true"]}));
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/false"]}));
}

#[test]
fn invalid_argument_types_extra_fields_and_bounds_match_native_without_prepare() {
    let fixture = Fixture::new("invalid");
    let cases = [
        json!({}),
        json!({"argv": []}),
        json!({"argv": "/bin/echo"}),
        json!({"argv": [1, 2]}),
        json!({"argv": ["/bin/echo"], "timeout_ms": 0}),
        json!({"argv": ["/bin/echo"], "timeout_ms": "1"}),
        json!({"argv": ["/bin/echo"], "timeout_ms": -1}),
        json!({"argv": ["/bin/echo"], "timeout_ms": 3_600_001}),
        json!({"argv": ["/bin/echo"], "max_output_bytes": 0}),
        json!({"argv": ["/bin/echo"], "max_output_bytes": "8"}),
        json!({"argv": ["/bin/echo"], "stdin": 12}),
        json!({"argv": ["/bin/echo"], "extra": true}),
        json!({"argv": ["/bin/echo"], "cwd": 1}),
        json!({"argv": ["/bin/echo"], "background": "yes"}),
    ];
    for arguments in cases {
        assert_terminal_eq(&fixture, arguments);
    }
}

#[test]
fn cwd_missing_file_symlink_traversal_and_absolute_match_native() {
    let fixture = Fixture::new("cwd");
    fs::create_dir(fixture.root.join("sub")).unwrap();
    fs::write(fixture.root.join("file.txt"), "x").unwrap();
    symlink(fixture.root.join("sub"), fixture.root.join("link-dir")).unwrap();
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/pwd"], "cwd": "sub"}));
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "missing-dir"}),
    );
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/pwd"], "cwd": "file.txt"}));
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/pwd"], "cwd": "link-dir"}));
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/pwd"], "cwd": "../"}));
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/pwd"], "cwd": "/"}));
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/pwd"], "cwd": "/etc"}));
}

#[test]
fn host_environment_secrets_are_not_inherited() {
    let fixture = Fixture::new("env");
    unsafe {
        std::env::set_var("RUSTSCRIPT_AGENT_SHOULD_NOT_LEAK", "secret-host-env");
    }
    assert_terminal_eq(&fixture, json!({"argv": ["/usr/bin/env"]}));
    unsafe {
        std::env::remove_var("RUSTSCRIPT_AGENT_SHOULD_NOT_LEAK");
    }
}

#[test]
fn foreground_stdin_is_written_and_closed() {
    let fixture = Fixture::new("stdin");
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/cat"], "stdin": "from-stdin\n"}),
    );
}

#[test]
fn foreground_timeout_kills_child_and_grandchild() {
    let fixture = Fixture::new("timeout");
    let marker = fixture.root.join("timeout.pid");
    let grand = fixture.root.join("grand.pid");
    let config = fixture.config();
    let arguments = json!({
        "argv": [
            "/bin/sh",
            "-c",
            "echo $$ > \"$1\"; /bin/sleep 60 & echo $! > \"$2\"; wait",
            "timeout-child",
            marker.to_string_lossy(),
            grand.to_string_lossy()
        ],
        "timeout_ms": 120
    });
    let started = Instant::now();
    let native = NativePair::new(config.clone()).terminal.execute(&arguments);
    let native_elapsed = started.elapsed();
    let started = Instant::now();
    let rss = run_rss_exec(
        &fixture,
        &config,
        default_exec("terminal.rss", "terminal", arguments),
    );
    assert!(!native.ok);
    assert_eq!(native.error.as_ref().unwrap().code, "deadline_elapsed");
    assert_exact_envelope(&native, &rss.result);
    assert!(native_elapsed < Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(2));
    let pid: u32 = fs::read_to_string(&marker)
        .expect("pid marker")
        .trim()
        .parse()
        .expect("pid");
    wait_until_dead(pid);
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !grand.exists() {
        std::thread::sleep(Duration::from_millis(20));
    }
    let grand_pid: u32 = fs::read_to_string(&grand)
        .expect("grand pid marker")
        .trim()
        .parse()
        .expect("grand pid");
    wait_until_dead(grand_pid);
}

#[test]
fn background_spawn_poll_log_write_close_wait_and_kill_match_native() {
    let fixture = Fixture::new("bg");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    let spawn_args = json!({
        "argv": ["/bin/sh", "-c", "read line; printf 'got-%s\\n' \"$line\"; sleep 0.2"],
        "background": true
    });
    let native_spawn = native.terminal.execute(&spawn_args);
    let rss_spawn = run_rss_exec(
        &fixture,
        &config,
        default_exec("terminal.rss", "terminal", spawn_args),
    );
    assert_exact_envelope(&native_spawn, &rss_spawn.result);
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .expect("native handle")
        .to_string();
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .expect("rss handle")
        .to_string();
    assert!(native_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(rss_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(rss_id.len() >= 32);

    let write_args = json!({"action": "write", "process_id": native_id, "data": "payload"});
    let native_write = native.process.execute(&write_args);
    let rss_write = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&rss_spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&rss_spawn.processes)),
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "write", "process_id": rss_id, "data": "payload"}),
            )
        },
    );
    assert_exact_envelope(&native_write, &rss_write.result);

    let close_args = json!({"action": "close", "process_id": native_id});
    let native_close = native.process.execute(&close_args);
    let rss_close = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&rss_spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&rss_spawn.processes)),
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "close", "process_id": rss_id}),
            )
        },
    );
    assert_exact_envelope(&native_close, &rss_close.result);

    let wait_args = json!({"action": "wait", "process_id": native_id, "timeout_ms": 2000});
    let native_wait = native.process.execute(&wait_args);
    let rss_wait = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&rss_spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&rss_spawn.processes)),
            unlimited_fuel: true,
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "wait", "process_id": rss_id, "timeout_ms": 2000}),
            )
        },
    );
    assert_exact_envelope(&native_wait, &rss_wait.result);

    let log_args = json!({"action": "log", "process_id": native_id, "offset": 0});
    let native_log = native.process.execute(&log_args);
    let rss_log = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&rss_spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&rss_spawn.processes)),
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "log", "process_id": rss_id, "offset": 0}),
            )
        },
    );
    assert_exact_envelope(&native_log, &rss_log.result);

    let poll_args = json!({"action": "poll", "process_id": native_id});
    let native_poll = native.process.execute(&poll_args);
    let rss_poll = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&rss_spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&rss_spawn.processes)),
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "poll", "process_id": rss_id}),
            )
        },
    );
    assert_exact_envelope(&native_poll, &rss_poll.result);

    let kill_args = json!({"action": "kill", "process_id": native_id});
    let native_kill = native.process.execute(&kill_args);
    let rss_kill = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&rss_spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&rss_spawn.processes)),
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "kill", "process_id": rss_id}),
            )
        },
    );
    assert_exact_envelope(&native_kill, &rss_kill.result);
    let _ = native.table;
}

#[test]
fn process_action_validation_forged_handle_and_cursor_semantics_match_native() {
    let fixture = Fixture::new("actions");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    for arguments in [
        json!({}),
        json!({"action": 1}),
        json!({"action": "list"}),
        json!({"action": "submit", "process_id": "abc"}),
        json!({"action": "poll", "process_id": "deadbeefdeadbeefdeadbeefdeadbeef"}),
        json!({"action": "wait", "process_id": "x", "timeout_ms": 0}),
        json!({"action": "wait", "process_id": "x", "timeout_ms": "1"}),
        json!({"action": "log", "process_id": "x", "offset": -1}),
        json!({"action": "log", "process_id": "x", "limit": 0}),
        json!({"action": "write", "process_id": "x", "data": 1}),
    ] {
        let native_result = native.process.execute(&arguments);
        let rss = run_rss_exec(
            &fixture,
            &config,
            default_exec("process.rss", "process", arguments),
        );
        assert_exact_envelope(&native_result, &rss.result);
        if native_result
            .error
            .as_ref()
            .is_some_and(|error| error.code.starts_with("invalid_"))
        {
            assert_eq!(rss.started, 0, "invalid process args must not prepare");
        }
    }
}

#[test]
fn durable_replay_does_not_repeat_spawn_and_invalid_args_leave_no_process() {
    let fixture = Fixture::new("replay");
    let config = fixture.config();
    let durable = MemoryDurable::new();
    let first = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            durable: Arc::clone(&durable),
            call_id: "call-replay".into(),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/echo", "once"], "background": true}),
            )
        },
    );
    assert_eq!(first.result["ok"], json!(true));
    let handle = first.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let replay = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            durable: Arc::clone(&durable),
            call_id: "call-replay".into(),
            shared_lifecycle: None,
            shared_processes: Some(Arc::clone(&first.processes)),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/echo", "twice"], "background": true}),
            )
        },
    );
    assert_eq!(replay.result["data"]["process_id"], json!(handle));
    let _ = first.processes;

    let invalid = run_rss_exec(
        &fixture,
        &config,
        default_exec("terminal.rss", "terminal", json!({"argv": []})),
    );
    assert_eq!(error_code(&invalid.result), "invalid_argv");
    assert_eq!(invalid.started, 0);
}

#[test]
fn commit_failure_does_not_report_completed() {
    let fixture = Fixture::new("commit-fail");
    let config = fixture.config();
    let durable = MemoryDurable::new();
    durable.fail_next_commit();
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            durable: Arc::clone(&durable),
            call_id: "call-commit-fail".into(),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/echo", "x"]}),
            )
        },
    );
    assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
    assert_ne!(rss.result["ok"], json!(true));
    assert_eq!(durable.stored_result("call-commit-fail"), None);
}

#[test]
fn approval_denied_happens_before_spawn() {
    let fixture = Fixture::new("deny");
    let config = fixture.config();
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            approval: Arc::new(DenyAll),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/echo", "nope"]}),
            )
        },
    );
    assert_eq!(rss.result["ok"], json!(false));
    assert_eq!(error_code(&rss.result), "approval_denied");
}

#[test]
fn cancellation_during_foreground_wait_is_typed() {
    let fixture = Fixture::new("cancel");
    let config = fixture.config();
    let flag = FlagCancel::new();
    flag.cancel();
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            cancellation: flag,
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/sleep", "2"]}),
            )
        },
    );
    assert_eq!(rss.result["ok"], json!(false));
    assert_eq!(error_code(&rss.result), "cancelled");
    assert_eq!(
        rss.result["error"]["message"].as_str(),
        Some("process was cancelled")
    );
}

#[test]
fn output_truncation_and_overflow_artifact_match_native() {
    let fixture = Fixture::new("overflow");
    let mut config = fixture.config();
    config.max_stream_bytes = 64;
    config.max_output_bytes = 800;
    let arguments = json!({
        "argv": ["/bin/sh", "-c", "i=0; while [ $i -lt 4000 ]; do printf o; i=$((i+1)); done"]
    });
    let native = NativePair::new(config.clone()).terminal.execute(&arguments);
    let rss = run_rss_exec(
        &fixture,
        &config,
        default_exec("terminal.rss", "terminal", arguments),
    );
    assert_exact_envelope(&native, &rss.result);
    assert!(native.truncated);
}

fn error_message(value: &Value) -> &str {
    value
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn rss_process(
    fixture: &Fixture,
    config: &ProcessToolConfig,
    previous: &RssRun,
    arguments: Value,
) -> RssRun {
    run_rss_exec(
        fixture,
        config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&previous.lifecycle)),
            shared_processes: Some(Arc::clone(&previous.processes)),
            unlimited_fuel: true,
            ..default_exec("process.rss", "process", arguments)
        },
    )
}

fn rss_terminal(fixture: &Fixture, config: &ProcessToolConfig, arguments: Value) -> RssRun {
    run_rss_exec(
        fixture,
        config,
        default_exec("terminal.rss", "terminal", arguments),
    )
}

fn artifact_bytes(run: &RssRun, id: &str) -> Vec<u8> {
    let artifacts = run.artifacts.as_ref().expect("artifacts store");
    let prepared = run
        .lifecycle
        .prepare(
            &owner(),
            PrepareMetadata {
                run_id: "run-test".to_string(),
                call_id: format!(
                    "artifact-read-{}",
                    NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
                ),
                tool_name: "process".to_string(),
                argument_digest: "digest".to_string(),
                registry_identity: REGISTRY_IDENTITY.to_string(),
                risk_class: CapabilityRisk::Execute,
                summary: "artifact-read".to_string(),
            },
        )
        .expect("prepare artifact token");
    let PrepareOutcome::Execute {
        execution_token, ..
    } = prepared
    else {
        panic!("expected execute token for artifact read, got {prepared:?}");
    };
    artifacts.get(&execution_token, id).expect("artifact bytes")
}

#[derive(Default)]
struct MemorySink {
    stored: Mutex<Vec<(String, Vec<u8>)>>,
}

impl ProcessArtifactSink for MemorySink {
    fn store(&self, _owner: &ProcessOwner, bytes: &[u8]) -> Result<String, String> {
        let id = format!("artifact-{:02}", self.stored.lock().unwrap().len() + 1);
        self.stored
            .lock()
            .unwrap()
            .push((id.clone(), bytes.to_vec()));
        Ok(id)
    }
}

#[test]
fn process_log_limit_sequence_matches_native_envelopes() {
    let fixture = Fixture::new("log-limit");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    let spawn_args = json!({
        "argv": ["/usr/bin/printf", "%s", "0123456789ABCDEF"],
        "background": true
    });
    let native_spawn = native.terminal.execute(&spawn_args);
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    assert_exact_envelope(&native_spawn, &rss_spawn.result);
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let wait_native = json!({"action": "wait", "process_id": native_id, "timeout_ms": 2000});
    let wait_rss = json!({"action": "wait", "process_id": rss_id, "timeout_ms": 2000});
    assert_exact_envelope(
        &native.process.execute(&wait_native),
        &rss_process(&fixture, &config, &rss_spawn, wait_rss).result,
    );
    let first_native = native.process.execute(&json!({
        "action": "log",
        "process_id": native_id,
        "offset": 0,
        "limit": 4
    }));
    let first_rss = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "log", "process_id": rss_id, "offset": 0, "limit": 4}),
    );
    assert_exact_envelope(&first_native, &first_rss.result);
    assert_eq!(first_native.data["stdout"].as_str().unwrap(), "0123");
    let next = first_native.data["stdout_next_offset"].as_u64().unwrap();
    let second_native = native.process.execute(&json!({
        "action": "log",
        "process_id": native_id,
        "offset": next,
        "limit": 4
    }));
    let second_rss = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "log", "process_id": rss_id, "offset": next, "limit": 4}),
    );
    assert_exact_envelope(&second_native, &second_rss.result);
    assert_eq!(second_native.data["stdout"].as_str().unwrap(), "4567");
    native
        .table
        .cleanup_owner(&process_owner())
        .expect("cleanup");
}

#[test]
fn process_write_timeout_on_full_pipe_matches_native_deadline_elapsed() {
    let fixture = Fixture::new("write-timeout");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    let spawn_args = json!({
        "argv": ["/bin/sleep", "30"],
        "background": true,
        "timeout_ms": 5000
    });
    let native_spawn = native.terminal.execute(&spawn_args);
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    assert_exact_envelope(&native_spawn, &rss_spawn.result);
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let payload = "x".repeat(1024 * 1024);
    let started = Instant::now();
    let native_write = native.process.execute(&json!({
        "action": "write",
        "process_id": native_id,
        "data": payload,
        "timeout_ms": 80
    }));
    let native_elapsed = started.elapsed();
    let started = Instant::now();
    let rss_write = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({
            "action": "write",
            "process_id": rss_id,
            "data": payload,
            "timeout_ms": 80
        }),
    );
    let rss_elapsed = started.elapsed();
    assert_exact_envelope(&native_write, &rss_write.result);
    assert_eq!(error_code(&rss_write.result), "deadline_elapsed");
    assert!(
        native_elapsed < Duration::from_millis(800),
        "{native_elapsed:?}"
    );
    assert!(rss_elapsed < Duration::from_secs(2), "{rss_elapsed:?}");
    let rss_pid = rss_spawn.result["data"]["pid"].as_u64().unwrap_or(0) as u32;
    let _ = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    native
        .table
        .cleanup_owner(&process_owner())
        .expect("cleanup");
    if rss_pid > 0 {
        wait_until_dead(rss_pid);
    }
}

#[test]
fn process_write_cancel_during_full_pipe_uses_exact_cancelled_envelope() {
    let fixture = Fixture::new("write-cancel");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    let spawn_args = json!({"argv": ["/bin/sleep", "30"], "background": true, "timeout_ms": 5000});
    let native_spawn = native.terminal.execute(&spawn_args);
    let flag = FlagCancel::new();
    let spawn = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            cancellation: flag.clone(),
            ..default_exec("terminal.rss", "terminal", spawn_args)
        },
    );
    assert_eq!(spawn.result["ok"], json!(true));
    let rss_id = spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let pid = spawn
        .processes
        .live_pids()
        .first()
        .copied()
        .expect("spawn pid");
    flag.cancel();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let write_args = json!({
        "action": "write",
        "process_id": native_id,
        "data": "x".repeat(1024 * 1024),
        "timeout_ms": 2000
    });
    let native_write = native.process.execute_with_controls(
        &write_args,
        &cancelled,
        Instant::now() + Duration::from_secs(5),
    );
    let written = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            cancellation: flag.clone(),
            shared_lifecycle: Some(Arc::clone(&spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&spawn.processes)),
            ..default_exec(
                "process.rss",
                "process",
                json!({
                    "action": "write",
                    "process_id": rss_id,
                    "data": "x".repeat(1024 * 1024),
                    "timeout_ms": 2000
                }),
            )
        },
    );
    assert_exact_envelope(&native_write, &written.result);
    assert_eq!(error_code(&written.result), "cancelled");
    assert_eq!(error_message(&written.result), "process was cancelled");
    assert_eq!(spawn.processes.table_len(), 1);
    assert!(pid_alive(pid), "cancel must not kill the child");
    spawn.processes.cancel_all();
    wait_until_dead(pid);
    native
        .table
        .cleanup_owner(&process_owner())
        .expect("cleanup");
}

#[test]
fn cancelled_envelopes_are_process_was_cancelled_for_pre_spawn_and_wait() {
    let fixture = Fixture::new("cancel-envelope");
    let config = fixture.config();
    let flag = FlagCancel::new();
    flag.cancel();
    let pre_spawn = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            cancellation: Arc::clone(&flag) as Arc<dyn CancellationFlag>,
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/sleep", "2"]}),
            )
        },
    );
    assert_eq!(error_code(&pre_spawn.result), "cancelled");
    assert_eq!(error_message(&pre_spawn.result), "process was cancelled");
    let native = NativePair::new(config.clone());
    let cancelled = rustscript_vm::CancellationToken::new();
    cancelled.cancel();
    let native_pre = native.terminal.execute_with_controls(
        &json!({"argv": ["/bin/sleep", "2"]}),
        &cancelled,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(native_pre.error.as_ref().unwrap().code, "cancelled");
    assert_eq!(
        native_pre.error.as_ref().unwrap().message,
        "process was cancelled"
    );
}

#[test]
fn overflow_artifact_bytes_and_no_sink_match_native() {
    let fixture = Fixture::new("overflow-bytes");
    let mut config = fixture.config();
    config.max_stream_bytes = 256;
    config.max_output_bytes = 180;
    let arguments = json!({
        "argv": ["/usr/bin/printf", "%s", "o".repeat(200)]
    });
    let sink = Arc::new(MemorySink::default());
    let native = NativePair::with_artifact_sink(
        config.clone(),
        Arc::clone(&sink) as Arc<dyn ProcessArtifactSink>,
    )
    .terminal
    .execute(&arguments);
    let rss = rss_terminal(&fixture, &config, arguments.clone());
    assert_exact_envelope(&native, &rss.result);
    if let Some(id) = rss
        .result
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(Value::as_str)
    {
        let rss_bytes = artifact_bytes(&rss, id);
        let native_bytes = sink.stored.lock().unwrap()[0].1.clone();
        assert_eq!(rss_bytes, native_bytes);
    }
    let native_no_sink = NativePair::new(config.clone()).terminal.execute(&arguments);
    let rss_no_sink = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            enable_artifacts: false,
            ..default_exec("terminal.rss", "terminal", arguments)
        },
    );
    assert_exact_envelope(&native_no_sink, &rss_no_sink.result);
}

#[test]
fn overflow_tiny_threshold_matches_native() {
    let fixture = Fixture::new("overflow-tiny");
    let mut config = fixture.config();
    config.max_stream_bytes = 32;
    config.max_output_bytes = 48;
    let arguments = json!({"argv": ["/bin/echo", "tiny-overflow"]});
    let native = NativePair::new(config.clone()).terminal.execute(&arguments);
    let rss = rss_terminal(&fixture, &config, arguments);
    assert_exact_envelope(&native, &rss.result);
}

fn first_artifact_id(value: &Value) -> Option<&str> {
    value
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(Value::as_str)
}

fn assert_overflow_payload_shape(label: &str, payload: &[u8], stdout_has_trailing_newline: bool) {
    let text = String::from_utf8_lossy(payload);
    assert!(
        text.starts_with("stdout:\n"),
        "{label} payload must start with stdout label: {text:?}"
    );
    if stdout_has_trailing_newline {
        assert!(
            !text.contains("\n\nstderr:\n"),
            "{label} must not insert an extra newline before stderr: {text:?}"
        );
    }
}

fn assert_terminal_overflow_payload(
    label: &str,
    arguments: Value,
    max_stream_bytes: usize,
    stdout_has_trailing_newline: bool,
) {
    let fixture = Fixture::new(label);
    let mut config = fixture.config();
    config.max_stream_bytes = max_stream_bytes;
    config.max_output_bytes = 600;
    let sink = Arc::new(MemorySink::default());
    let native = NativePair::with_artifact_sink(
        config.clone(),
        Arc::clone(&sink) as Arc<dyn ProcessArtifactSink>,
    )
    .terminal
    .execute(&arguments);
    let rss = rss_terminal(&fixture, &config, arguments);
    assert_exact_envelope(&native, &rss.result);
    let rss_id = first_artifact_id(&rss.result)
        .unwrap_or_else(|| panic!("{label} rss overflow artifact id: {}", rss.result));
    let rss_bytes = artifact_bytes(&rss, rss_id);
    let stored = sink.stored.lock().unwrap();
    assert_eq!(stored.len(), 1, "{label} native overflow sink");
    assert_eq!(rss_bytes, stored[0].1, "{label} overflow artifact bytes");
    assert_overflow_payload_shape(label, &rss_bytes, stdout_has_trailing_newline);
}

fn assert_process_wait_overflow_payload(
    label: &str,
    spawn_args: Value,
    max_stream_bytes: usize,
    stdout_has_trailing_newline: bool,
) {
    let fixture = Fixture::new(label);
    let mut config = fixture.config();
    config.max_stream_bytes = max_stream_bytes;
    config.max_output_bytes = 600;
    let sink = Arc::new(MemorySink::default());
    let native = NativePair::with_artifact_sink(
        config.clone(),
        Arc::clone(&sink) as Arc<dyn ProcessArtifactSink>,
    );
    let native_spawn = native.terminal.execute(&spawn_args);
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .expect("native process id")
        .to_string();
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .expect("rss process id")
        .to_string();
    let native_wait = native.process.execute(&json!({
        "action": "wait",
        "process_id": native_id,
        "timeout_ms": 2000
    }));
    let rss_wait = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "wait", "process_id": rss_id, "timeout_ms": 2000}),
    );
    assert_exact_envelope(&native_wait, &rss_wait.result);
    let rss_artifact = first_artifact_id(&rss_wait.result)
        .unwrap_or_else(|| panic!("{label} rss wait overflow artifact id: {}", rss_wait.result));
    let rss_bytes = artifact_bytes(&rss_wait, rss_artifact);
    let stored = sink.stored.lock().unwrap();
    assert_eq!(stored.len(), 1, "{label} native wait overflow sink");
    assert_eq!(
        rss_bytes, stored[0].1,
        "{label} process overflow artifact bytes"
    );
    assert_overflow_payload_shape(label, &rss_bytes, stdout_has_trailing_newline);
    native
        .table
        .cleanup_owner(&process_owner())
        .expect("cleanup overflow wait");
}

#[test]
fn overflow_echo_and_printf_artifact_bytes_match_native_at_exact_cap_and_one_over() {
    let exact_echo = "x".repeat(299); // 299 bytes + echo newline = 300
    let one_over_echo = "x".repeat(300); // 300 bytes + echo newline = 301
    assert_terminal_overflow_payload(
        "overflow-echo-nl-exact",
        json!({"argv": ["/bin/echo", exact_echo]}),
        300,
        true,
    );
    assert_terminal_overflow_payload(
        "overflow-echo-nl-one-over",
        json!({"argv": ["/bin/echo", one_over_echo]}),
        300,
        true,
    );
    assert_terminal_overflow_payload(
        "overflow-printf-none-exact",
        json!({"argv": ["/usr/bin/printf", "%s", "x".repeat(300)]}),
        300,
        false,
    );
    assert_terminal_overflow_payload(
        "overflow-printf-none-one-over",
        json!({"argv": ["/usr/bin/printf", "%s", "x".repeat(301)]}),
        300,
        false,
    );
    assert_terminal_overflow_payload(
        "overflow-empty-stdout",
        json!({"argv": ["/bin/sh", "-c", format!("printf '%s' '{}' >&2", "E".repeat(400))]}),
        8192,
        true,
    );
    assert_terminal_overflow_payload(
        "overflow-stderr-binary",
        json!({"argv": ["/bin/sh", "-c", format!("printf '{}'; printf '\\200\\377' >&2", "B".repeat(300))]}),
        8192,
        false,
    );
}

#[test]
fn overflow_process_wait_echo_and_printf_artifact_bytes_match_native() {
    assert_process_wait_overflow_payload(
        "overflow-wait-echo-nl",
        json!({"argv": ["/bin/echo", "x".repeat(299)], "background": true}),
        300,
        true,
    );
    assert_process_wait_overflow_payload(
        "overflow-wait-printf-none",
        json!({"argv": ["/usr/bin/printf", "%s", "x".repeat(300)], "background": true}),
        300,
        false,
    );
}

#[test]
fn process_fixture_roots_live_under_std_temp_dir() {
    let fixture = Fixture::new("portable-root");
    assert!(
        fixture.parent.starts_with(std::env::temp_dir()),
        "fixture parent {:?} must be under {:?}",
        fixture.parent,
        std::env::temp_dir()
    );
}

#[test]
fn foreground_stdin_empty_multibyte_large_and_child_exit_match_native() {
    let fixture = Fixture::new("stdin-matrix");
    assert_terminal_eq(&fixture, json!({"argv": ["/bin/cat"], "stdin": ""}));
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/cat"], "stdin": "多字节\u{1F980}\n"}),
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/cat"], "stdin": "x".repeat(8 * 1024)}),
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/true"], "stdin": "unused-stdin\n"}),
    );
    let spawn_fail = rss_terminal(
        &fixture,
        &fixture.config(),
        json!({"argv": ["/no/such/rss-process-binary"]}),
    );
    assert_eq!(spawn_fail.result["ok"], json!(false));
}

#[test]
fn process_timeout_bound_uses_config_max_timeout_ms() {
    let fixture = Fixture::new("timeout-bound");
    let mut config = fixture.config();
    config.default_timeout = Duration::from_millis(400);
    config.max_timeout = Duration::from_millis(400);
    let native = NativePair::new(config.clone());
    for arguments in [
        json!({"argv": ["/bin/true"], "timeout_ms": 400}),
        json!({"argv": ["/bin/true"], "timeout_ms": 401}),
        json!({"argv": ["/bin/true"], "timeout_ms": 0}),
        json!({"argv": ["/bin/true"], "timeout_ms": -1}),
        json!({"argv": ["/bin/true"], "timeout_ms": "nope"}),
        json!({"argv": ["/bin/true"], "timeout_ms": u64::MAX}),
    ] {
        let native_result = native.terminal.execute(&arguments);
        let rss = rss_terminal(&fixture, &config, arguments);
        assert_exact_envelope(&native_result, &rss.result);
    }
}

#[test]
fn wait_timeout_while_running_matches_native_success_envelope() {
    let fixture = Fixture::new("wait-running");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    let spawn_args = json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000});
    let native_spawn = native.terminal.execute(&spawn_args);
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    assert_exact_envelope(&native_spawn, &rss_spawn.result);
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let native_wait = native.process.execute(&json!({
        "action": "wait",
        "process_id": native_id,
        "timeout_ms": 80
    }));
    let rss_wait = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "wait", "process_id": rss_id, "timeout_ms": 80}),
    );
    assert_exact_envelope(&native_wait, &rss_wait.result);
    assert!(native_wait.ok);
    assert_eq!(native_wait.data["status"].as_str(), Some("running"));
    let _ = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    native
        .table
        .cleanup_owner(&process_owner())
        .expect("cleanup");
}

#[test]
fn repeated_close_kill_forged_stale_and_signal_exits_match_native() {
    let fixture = Fixture::new("oracle-matrix");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    let spawn_args = json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000});
    let native_spawn = native.terminal.execute(&spawn_args);
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    for action in ["close", "close"] {
        let native_result = native
            .process
            .execute(&json!({"action": action, "process_id": native_id}));
        let rss_result = rss_process(
            &fixture,
            &config,
            &rss_spawn,
            json!({"action": action, "process_id": rss_id}),
        );
        assert_exact_envelope(&native_result, &rss_result.result);
    }
    let native_kill = native
        .process
        .execute(&json!({"action": "kill", "process_id": native_id}));
    let rss_kill = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    assert_eq!(
        native_kill.data.get("status").and_then(Value::as_str),
        rss_kill.result["data"]
            .get("status")
            .and_then(Value::as_str)
    );
    let native_kill2 = native
        .process
        .execute(&json!({"action": "kill", "process_id": native_id}));
    let rss_kill2 = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    assert_eq!(
        native_kill2.data.get("status").and_then(Value::as_str),
        rss_kill2.result["data"]
            .get("status")
            .and_then(Value::as_str)
    );
    let forged = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "poll", "process_id": "forged-handle"}),
    );
    let native_forged = native
        .process
        .execute(&json!({"action": "poll", "process_id": "forged-handle"}));
    assert_exact_envelope(&native_forged, &forged.result);
    let stale = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "poll", "process_id": rss_id}),
    );
    let native_stale = native
        .process
        .execute(&json!({"action": "poll", "process_id": native_id}));
    assert_exact_envelope(&native_stale, &stale.result);
}

#[test]
fn commit_failure_after_background_spawn_leaves_no_process_residue() {
    let fixture = Fixture::new("commit-residue");
    let config = fixture.config();
    let clock = Arc::new(SystemClock);
    let deadline_ms = clock.now_ms() + 60_000;
    let durable = MemoryDurable::new();
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        Arc::clone(&clock) as Arc<dyn LifecycleClock>,
        deadline_ms,
    ));
    let processes = Arc::new(
        ProcessCapability::new(lifecycle.as_ref().clone(), owner(), process_limits(&config))
            .expect("process capability"),
    );
    let captured = Arc::new(Mutex::new(Vec::<u32>::new()));
    {
        let captured = Arc::clone(&captured);
        let processes = Arc::clone(&processes);
        durable.on_commit(move || {
            let mut tree = Vec::new();
            for pid in processes.live_pids() {
                tree.extend(collect_tree(pid));
            }
            *captured.lock().expect("captured pids") = tree;
        });
    }
    durable.fail_next_commit();
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            durable: Arc::clone(&durable),
            call_id: "call-commit-fail".into(),
            shared_lifecycle: Some(Arc::clone(&lifecycle)),
            shared_processes: Some(Arc::clone(&processes)),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({
                    "argv": ["/bin/sh", "-c", "sleep 60 & exec sleep 60"],
                    "background": true,
                    "timeout_ms": 5000
                }),
            )
        },
    );
    assert_eq!(rss.result["ok"], json!(false));
    assert_eq!(error_code(&rss.result), "result_commit_failed");
    assert_eq!(durable.stored_result("call-commit-fail"), None);
    let pids = captured.lock().expect("captured pids").clone();
    assert!(
        !pids.is_empty(),
        "commit must observe a live child from the process table"
    );
    for pid in &pids {
        wait_until_dead(*pid);
    }
    assert_eq!(processes.table_len(), 0);
    let replay = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            durable: Arc::clone(&durable),
            call_id: "call-commit-fail".into(),
            shared_lifecycle: Some(lifecycle),
            shared_processes: Some(Arc::clone(&processes)),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({
                    "argv": ["/bin/sh", "-c", "sleep 60 & exec sleep 60"],
                    "background": true,
                    "timeout_ms": 5000
                }),
            )
        },
    );
    assert_eq!(error_code(&replay.result), "unresolved_call");
    assert_eq!(processes.table_len(), 0);
}

#[test]
fn durable_replay_does_not_repeat_spawn_write_or_kill() {
    let fixture = Fixture::new("replay-matrix");
    let config = fixture.config();
    let durable = MemoryDurable::new();
    let first = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            durable: Arc::clone(&durable),
            call_id: "replay-spawn".to_string(),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000}),
            )
        },
    );
    assert_eq!(first.result["ok"], json!(true));
    let handle = first.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let replay_spawn = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            durable: Arc::clone(&durable),
            call_id: "replay-spawn".to_string(),
            shared_lifecycle: Some(Arc::clone(&first.lifecycle)),
            shared_processes: Some(Arc::clone(&first.processes)),
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000}),
            )
        },
    );
    assert_eq!(replay_spawn.result, first.result);
    let write = rss_process(
        &fixture,
        &config,
        &first,
        json!({"action": "write", "process_id": handle, "data": "x"}),
    );
    assert_eq!(write.result["ok"], json!(true));
    assert_eq!(write.result["data"]["wrote_bytes"], json!(1));
    let kill = rss_process(
        &fixture,
        &config,
        &first,
        json!({"action": "kill", "process_id": handle}),
    );
    assert_eq!(kill.result["ok"], json!(true));
}

#[test]
fn mid_loop_cancel_wait_envelope_is_process_was_cancelled() {
    let fixture = Fixture::new("mid-cancel");
    let config = fixture.config();
    let native = NativePair::new(config.clone());
    let spawn_args = json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000});
    let native_spawn = native.terminal.execute(&spawn_args);
    let flag = FlagCancel::new();
    let spawn = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            cancellation: flag.clone(),
            ..default_exec("terminal.rss", "terminal", spawn_args)
        },
    );
    let handle = spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let native_id = native_spawn.data["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let pid = spawn
        .processes
        .live_pids()
        .first()
        .copied()
        .expect("spawn pid");
    flag.cancel();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let native_wait = native.process.execute_with_controls(
        &json!({"action": "wait", "process_id": native_id, "timeout_ms": 2000}),
        &cancelled,
        Instant::now() + Duration::from_secs(5),
    );
    let waited = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            cancellation: flag.clone(),
            shared_lifecycle: Some(Arc::clone(&spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&spawn.processes)),
            unlimited_fuel: true,
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "wait", "process_id": handle, "timeout_ms": 2000}),
            )
        },
    );
    assert_exact_envelope(&native_wait, &waited.result);
    assert_eq!(error_code(&waited.result), "cancelled");
    assert_eq!(error_message(&waited.result), "process was cancelled");
    assert_eq!(spawn.processes.table_len(), 1);
    assert!(pid_alive(pid), "wait cancel must not kill the child");
    spawn.processes.cancel_all();
    wait_until_dead(pid);
    native
        .table
        .cleanup_owner(&process_owner())
        .expect("cleanup");
}

#[test]
fn initial_stdin_epipe_from_fast_child_does_not_fail_terminal_spawn() {
    let fixture = Fixture::new("stdin-epipe");
    let config = fixture.config();
    for i in 0..24 {
        let arguments = json!({
            "argv": ["/bin/true"],
            "stdin": format!("epipe-{i}\n"),
        });
        let rss = rss_terminal(&fixture, &config, arguments);
        assert_eq!(
            rss.result["ok"],
            json!(true),
            "iteration {i} rss={}",
            rss.result
        );
        assert_ne!(error_code(&rss.result), "process_failed");
        assert_ne!(error_code(&rss.result), "spawn_failed");
        let pid = rss
            .processes
            .live_pids()
            .first()
            .copied()
            .expect("table pid");
        wait_until_dead(pid);
    }
}

#[test]
fn overflow_invalid_utf8_and_boundary_cap_match_native_memory_sink() {
    assert_terminal_overflow_payload(
        "overflow-utf8-stdout",
        json!({
            "argv": [
                "/bin/sh",
                "-c",
                format!("printf '\\200\\377{}'", "A".repeat(300))
            ]
        }),
        8192,
        false,
    );
    assert_terminal_overflow_payload(
        "overflow-utf8-stderr",
        json!({
            "argv": [
                "/bin/sh",
                "-c",
                format!("printf '{}'; printf '\\200\\377' >&2", "B".repeat(300))
            ]
        }),
        8192,
        false,
    );
    assert_terminal_overflow_payload(
        "overflow-utf8-boundary",
        json!({
            "argv": ["/usr/bin/printf", "%s", "x".repeat(301)]
        }),
        300,
        false,
    );
}
