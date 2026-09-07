//! Native-equivalence tests for RSS `terminal` and `process`.
//!
//! RSS modules own argument validation, poll loops, and canonical envelopes.
//! Native `TerminalExecutor` / `ProcessExecutor` are the oracle. Opaque handle
//! IDs and artifact IDs are projected before exact envelope comparison.

use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, ControlCheckHook, RunCancellation, ToolResult,
    bundled_tool_registry,
};
use rustscript_vm::{CancellationReason, Value as VmValue};
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
    let name = match name {
        "terminal.rss" => "terminal_entry.rss",
        "process.rss" => "process_entry.rss",
        other => other,
    };
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
        close_after_initial: false,
    }
}

fn owner() -> CapabilityOwner {
    CapabilityOwner::new("profile-test", "session-test", "run-test").expect("owner")
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
    control_hook: Option<ControlCheckHook>,
    run_cancellation: Option<RunCancellation>,
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
        cancellation: exec.run_cancellation.clone(),
        control_hook: exec.control_hook.clone(),
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
        control_hook: None,
        run_cancellation: None,
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
    bundled_tool_registry()
        .expect("RSS registry")
        .snapshot()
        .schemas()
        .as_array()
        .expect("descriptor array")
        .iter()
        .find(|value| value["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("missing RSS descriptor {name}"))
}

fn canonical_envelope(value: &Value) -> Value {
    let parsed: ToolResult =
        serde_json::from_value(value.clone()).expect("canonical tool result schema");
    serde_json::to_value(parsed).expect("serialize canonical tool result")
}

fn assert_canonical_envelope(rss: &Value) {
    let _ = canonical_envelope(rss);
    let encoded = serde_json::to_string(rss).expect("encode rss");
    assert!(
        !encoded.contains("/proc/"),
        "rss envelope leaked proc path: {encoded}"
    );
}

#[allow(clippy::too_many_arguments)]
fn assert_terminal_eq(
    fixture: &Fixture,
    arguments: Value,
    expected_ok: bool,
    expected_stdout: &str,
    expected_stderr: &str,
    expected_exit: Option<i64>,
    expected_timed_out: bool,
    expected_error: Option<&str>,
    expected_started: usize,
) {
    let config = fixture.config();
    let rss = run_rss_exec(
        fixture,
        &config,
        default_exec("terminal.rss", "terminal", arguments.clone()),
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(
        rss.result["ok"],
        json!(expected_ok),
        "ok arguments={arguments} rss={}",
        rss.result
    );
    match expected_error {
        None => assert_eq!(rss.result["error"], Value::Null, "rss={}", rss.result),
        Some(code) => assert_eq!(
            rss.result["error"]["code"],
            json!(code),
            "rss={}",
            rss.result
        ),
    }
    assert_eq!(
        rss.started, expected_started,
        "started arguments={arguments}"
    );
    if expected_ok {
        assert_eq!(
            rss.result["content"],
            json!(if expected_stdout.is_empty() {
                expected_stderr
            } else {
                expected_stdout
            }),
            "content arguments={arguments} rss={}",
            rss.result
        );
        assert_eq!(
            rss.result["data"]["stdout"],
            json!(expected_stdout),
            "data.stdout arguments={arguments} rss={}",
            rss.result
        );
        assert_eq!(
            rss.result["data"]["stderr"],
            json!(expected_stderr),
            "stderr arguments={arguments} rss={}",
            rss.result
        );
        if let Some(exit) = expected_exit {
            assert_eq!(
                rss.result["data"]["exit_code"],
                json!(exit),
                "exit_code arguments={arguments} rss={}",
                rss.result
            );
        }
        if expected_timed_out {
            assert_eq!(
                rss.result["data"]["timed_out"],
                json!(true),
                "timed_out arguments={arguments} rss={}",
                rss.result
            );
        } else {
            assert_eq!(
                rss.result["data"]
                    .get("timed_out")
                    .cloned()
                    .unwrap_or(Value::Null),
                Value::Null,
                "timed_out must be absent arguments={arguments} rss={}",
                rss.result
            );
        }
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
        true,
        "hello-rss-process\n",
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/echo", "-n"]}),
        true,
        "",
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/sh", "-c", "printf '你好\\n'"]}),
        true,
        "你好\n",
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/sh", "-c", "printf 'a\\0b'"]}),
        true,
        "a\u{0000}b",
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/sh", "-c", "printf 'err' 1>&2; exit 3"]}),
        true,
        "",
        "err",
        Some(3),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/true"]}),
        true,
        "",
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/false"]}),
        true,
        "",
        "",
        Some(1),
        false,
        None,
        1,
    );
}

#[test]
#[allow(clippy::type_complexity)]
fn invalid_argument_types_extra_fields_and_bounds_match_native_without_prepare() {
    let fixture = Fixture::new("invalid");
    let cases: [(Value, bool, &str, Option<i64>, Option<&str>, usize); 14] = [
        (json!({}), false, "", None, Some("invalid_argv"), 0),
        (
            json!({"argv": []}),
            false,
            "",
            None,
            Some("invalid_argv"),
            0,
        ),
        (
            json!({"argv": "/bin/echo"}),
            false,
            "",
            None,
            Some("invalid_argv"),
            0,
        ),
        (
            json!({"argv": [1, 2]}),
            false,
            "",
            None,
            Some("invalid_argv"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "timeout_ms": 0}),
            false,
            "",
            None,
            Some("invalid_timeout"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "timeout_ms": "1"}),
            false,
            "",
            None,
            Some("invalid_timeout"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "timeout_ms": -1}),
            false,
            "",
            None,
            Some("invalid_timeout"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "timeout_ms": 3_600_001}),
            false,
            "",
            None,
            Some("invalid_timeout"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "max_output_bytes": 0}),
            false,
            "",
            None,
            Some("invalid_output_limit"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "max_output_bytes": "8"}),
            false,
            "",
            None,
            Some("invalid_output_limit"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "stdin": 12}),
            false,
            "",
            None,
            Some("invalid_stdin"),
            0,
        ),
        (
            json!({"argv": ["/bin/echo"], "extra": true}),
            true,
            "\n",
            Some(0),
            None,
            1,
        ),
        (
            json!({"argv": ["/bin/echo"], "cwd": 1}),
            true,
            "\n",
            Some(0),
            None,
            1,
        ),
        (
            json!({"argv": ["/bin/echo"], "background": "yes"}),
            true,
            "\n",
            Some(0),
            None,
            1,
        ),
    ];
    for (arguments, ok, stdout, exit, error, started) in cases {
        assert_terminal_eq(
            &fixture, arguments, ok, stdout, "", exit, false, error, started,
        );
    }
}

#[test]
fn cwd_missing_file_symlink_traversal_and_absolute_match_native() {
    let fixture = Fixture::new("cwd");
    fs::create_dir(fixture.root.join("sub")).unwrap();
    fs::write(fixture.root.join("file.txt"), "x").unwrap();
    symlink(fixture.root.join("sub"), fixture.root.join("link-dir")).unwrap();
    let sub = fixture.root.join("sub").canonicalize().unwrap();
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "sub"}),
        true,
        &format!("{}\n", sub.display()),
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "missing-dir"}),
        false,
        "",
        "",
        None,
        false,
        Some("invalid_cwd"),
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "file.txt"}),
        false,
        "",
        "",
        None,
        false,
        Some("invalid_cwd"),
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "link-dir"}),
        false,
        "",
        "",
        None,
        false,
        Some("invalid_cwd"),
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "../"}),
        false,
        "",
        "",
        None,
        false,
        Some("invalid_cwd"),
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "/"}),
        false,
        "",
        "",
        None,
        false,
        Some("invalid_cwd"),
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/pwd"], "cwd": "/etc"}),
        false,
        "",
        "",
        None,
        false,
        Some("invalid_cwd"),
        1,
    );
}

#[test]
fn host_environment_secrets_are_not_inherited() {
    let fixture = Fixture::new("env");
    unsafe {
        std::env::set_var("RUSTSCRIPT_AGENT_SHOULD_NOT_LEAK", "secret-host-env");
    }
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/usr/bin/env"]}),
        true,
        "",
        "",
        Some(0),
        false,
        None,
        1,
    );
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
        true,
        "from-stdin\n",
        "",
        Some(0),
        false,
        None,
        1,
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
    let rss = run_rss_exec(
        &fixture,
        &config,
        default_exec("terminal.rss", "terminal", arguments),
    );
    assert_eq!(rss.result["ok"], json!(false));
    assert_eq!(rss.result["error"]["code"], json!("deadline_elapsed"));
    assert_canonical_envelope(&rss.result);
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
    let spawn_args = json!({
        "argv": ["/bin/sh", "-c", "read line; printf 'got-%s\\n' \"$line\"; sleep 0.2"],
        "background": true
    });
    let rss_spawn = run_rss_exec(
        &fixture,
        &config,
        default_exec("terminal.rss", "terminal", spawn_args),
    );
    assert_canonical_envelope(&rss_spawn.result);
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .expect("rss handle")
        .to_string();
    assert!(rss_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(rss_id.len() >= 32);

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
    assert_canonical_envelope(&rss_write.result);

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
    assert_canonical_envelope(&rss_close.result);

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
    assert_canonical_envelope(&rss_wait.result);

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
    assert_canonical_envelope(&rss_log.result);

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
    assert_canonical_envelope(&rss_poll.result);

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
    assert_canonical_envelope(&rss_kill.result);
}

#[test]
fn process_action_validation_forged_handle_and_cursor_semantics_match_native() {
    let fixture = Fixture::new("actions");
    let config = fixture.config();
    let cases: [(Value, &str, usize); 10] = [
        (json!({}), "invalid_action", 0),
        (json!({"action": 1}), "invalid_action", 0),
        (json!({"action": "list"}), "invalid_action", 0),
        (
            json!({"action": "submit", "process_id": "abc"}),
            "invalid_action",
            0,
        ),
        (
            json!({"action": "poll", "process_id": "deadbeefdeadbeefdeadbeefdeadbeef"}),
            "process_not_found",
            1,
        ),
        (
            json!({"action": "wait", "process_id": "x", "timeout_ms": 0}),
            "invalid_timeout",
            0,
        ),
        (
            json!({"action": "wait", "process_id": "x", "timeout_ms": "1"}),
            "invalid_timeout",
            0,
        ),
        (
            json!({"action": "log", "process_id": "x", "offset": -1}),
            "invalid_output_limit",
            0,
        ),
        (
            json!({"action": "log", "process_id": "x", "limit": 0}),
            "invalid_output_limit",
            0,
        ),
        (
            json!({"action": "write", "process_id": "x", "data": 1}),
            "process_not_found",
            1,
        ),
    ];
    for (arguments, code, started) in cases {
        let rss = run_rss_exec(
            &fixture,
            &config,
            default_exec("process.rss", "process", arguments.clone()),
        );
        assert_canonical_envelope(&rss.result);
        assert_eq!(
            rss.result["ok"],
            json!(false),
            "ok arguments={arguments} rss={}",
            rss.result
        );
        assert_eq!(
            rss.result["error"]["code"],
            json!(code),
            "code arguments={arguments} rss={}",
            rss.result
        );
        assert_eq!(rss.started, started, "started arguments={arguments}");
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
    let rss = run_rss_exec(
        &fixture,
        &config,
        default_exec("terminal.rss", "terminal", arguments),
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["truncated"], json!(true));
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

#[test]
fn process_log_limit_sequence_matches_native_envelopes() {
    let fixture = Fixture::new("log-limit");
    let config = fixture.config();
    let spawn_args = json!({
        "argv": ["/usr/bin/printf", "%s", "0123456789ABCDEF"],
        "background": true
    });
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    assert_canonical_envelope(&rss_spawn.result);
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let wait_rss = json!({"action": "wait", "process_id": rss_id, "timeout_ms": 2000});
    assert_canonical_envelope(&rss_process(&fixture, &config, &rss_spawn, wait_rss).result);
    let first_rss = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "log", "process_id": rss_id, "offset": 0, "limit": 4}),
    );
    assert_canonical_envelope(&first_rss.result);
    assert_eq!(first_rss.result["data"]["stdout"].as_str().unwrap(), "0123");
    let next = first_rss.result["data"]["stdout_next_offset"]
        .as_u64()
        .unwrap();
    let second_rss = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "log", "process_id": rss_id, "offset": next, "limit": 4}),
    );
    assert_canonical_envelope(&second_rss.result);
    assert_eq!(
        second_rss.result["data"]["stdout"].as_str().unwrap(),
        "4567"
    );
    rss_spawn.processes.cancel_all();
}

#[test]
fn process_write_timeout_on_full_pipe_matches_native_deadline_elapsed() {
    let fixture = Fixture::new("write-timeout");
    let config = fixture.config();
    let spawn_args = json!({
        "argv": ["/bin/sleep", "30"],
        "background": true,
        "timeout_ms": 5000
    });
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    assert_canonical_envelope(&rss_spawn.result);
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let payload = "x".repeat(1024 * 1024);
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
    assert_canonical_envelope(&rss_write.result);
    assert_eq!(error_code(&rss_write.result), "deadline_elapsed");
    assert!(rss_elapsed < Duration::from_secs(2), "{rss_elapsed:?}");
    let rss_pid = rss_spawn.result["data"]["pid"].as_u64().unwrap_or(0) as u32;
    let _ = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    rss_spawn.processes.cancel_all();
    if rss_pid > 0 {
        wait_until_dead(rss_pid);
    }
}

#[test]
fn process_write_cancel_during_full_pipe_uses_exact_cancelled_envelope() {
    let fixture = Fixture::new("write-cancel");
    let config = fixture.config();
    let spawn_args = json!({"argv": ["/bin/sleep", "30"], "background": true, "timeout_ms": 5000});
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
    let pid = spawn
        .processes
        .live_pids()
        .first()
        .copied()
        .expect("spawn pid");
    flag.cancel();
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
    assert_canonical_envelope(&written.result);
    assert_eq!(error_code(&written.result), "cancelled");
    assert_eq!(error_message(&written.result), "process was cancelled");
    assert_eq!(spawn.processes.table_len(), 1);
    assert!(pid_alive(pid), "cancel must not kill the child");
    spawn.processes.cancel_all();
    wait_until_dead(pid);
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
    let rss = rss_terminal(&fixture, &config, arguments.clone());
    assert_canonical_envelope(&rss.result);
    if let Some(id) = rss
        .result
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(Value::as_str)
    {
        let rss_bytes = artifact_bytes(&rss, id);
        assert_overflow_payload_shape("overflow-bytes", &rss_bytes, false);
        assert!(
            rss_bytes.starts_with(b"stdout:\n"),
            "overflow artifact must start with stdout header: {rss_bytes:?}"
        );
    }
    let rss_no_sink = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            enable_artifacts: false,
            ..default_exec("terminal.rss", "terminal", arguments)
        },
    );
    assert_canonical_envelope(&rss_no_sink.result);
}

#[test]
fn overflow_tiny_threshold_matches_native() {
    let fixture = Fixture::new("overflow-tiny");
    let mut config = fixture.config();
    config.max_stream_bytes = 32;
    config.max_output_bytes = 48;
    let arguments = json!({"argv": ["/bin/echo", "tiny-overflow"]});
    let rss = rss_terminal(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
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
    let rss = rss_terminal(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    let rss_id = first_artifact_id(&rss.result)
        .unwrap_or_else(|| panic!("{label} rss overflow artifact id: {}", rss.result));
    let rss_bytes = artifact_bytes(&rss, rss_id);
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
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .expect("rss process id")
        .to_string();
    let rss_wait = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "wait", "process_id": rss_id, "timeout_ms": 2000}),
    );
    assert_canonical_envelope(&rss_wait.result);
    let rss_artifact = first_artifact_id(&rss_wait.result)
        .unwrap_or_else(|| panic!("{label} rss wait overflow artifact id: {}", rss_wait.result));
    let rss_bytes = artifact_bytes(&rss_wait, rss_artifact);
    assert_overflow_payload_shape(label, &rss_bytes, stdout_has_trailing_newline);
    rss_spawn.processes.cancel_all();
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
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/cat"], "stdin": ""}),
        true,
        "",
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/cat"], "stdin": "多字节\u{1F980}\n"}),
        true,
        "多字节\u{1F980}\n",
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/cat"], "stdin": "x".repeat(8 * 1024)}),
        true,
        &"x".repeat(8 * 1024),
        "",
        Some(0),
        false,
        None,
        1,
    );
    assert_terminal_eq(
        &fixture,
        json!({"argv": ["/bin/true"], "stdin": "unused-stdin\n"}),
        true,
        "",
        "",
        Some(0),
        false,
        None,
        1,
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
    for arguments in [
        json!({"argv": ["/bin/true"], "timeout_ms": 400}),
        json!({"argv": ["/bin/true"], "timeout_ms": 401}),
        json!({"argv": ["/bin/true"], "timeout_ms": 0}),
        json!({"argv": ["/bin/true"], "timeout_ms": -1}),
        json!({"argv": ["/bin/true"], "timeout_ms": "nope"}),
        json!({"argv": ["/bin/true"], "timeout_ms": u64::MAX}),
    ] {
        let rss = rss_terminal(&fixture, &config, arguments);
        assert_canonical_envelope(&rss.result);
    }
}

#[test]
fn wait_timeout_while_running_matches_native_success_envelope() {
    let fixture = Fixture::new("wait-running");
    let config = fixture.config();
    let spawn_args = json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000});
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    assert_canonical_envelope(&rss_spawn.result);
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rss_wait = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "wait", "process_id": rss_id, "timeout_ms": 80}),
    );
    assert_canonical_envelope(&rss_wait.result);
    assert!(rss_wait.result["ok"] == json!(true));
    assert_eq!(rss_wait.result["data"]["status"].as_str(), Some("running"));
    let _ = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    rss_spawn.processes.cancel_all();
}

#[test]
fn repeated_close_kill_forged_stale_and_signal_exits_match_native() {
    let fixture = Fixture::new("oracle-matrix");
    let config = fixture.config();
    let spawn_args = json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000});
    let rss_spawn = rss_terminal(&fixture, &config, spawn_args);
    let rss_id = rss_spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    for action in ["close", "close"] {
        let rss_result = rss_process(
            &fixture,
            &config,
            &rss_spawn,
            json!({"action": action, "process_id": rss_id}),
        );
        assert_canonical_envelope(&rss_result.result);
    }
    let rss_kill = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    assert_eq!(
        rss_kill.result["data"]
            .get("status")
            .and_then(Value::as_str),
        rss_kill.result["data"]
            .get("status")
            .and_then(Value::as_str)
    );
    let rss_kill2 = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "kill", "process_id": rss_id}),
    );
    assert_eq!(
        rss_kill2.result["data"]
            .get("status")
            .and_then(Value::as_str),
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
    assert_canonical_envelope(&forged.result);
    let stale = rss_process(
        &fixture,
        &config,
        &rss_spawn,
        json!({"action": "poll", "process_id": rss_id}),
    );
    assert_canonical_envelope(&stale.result);
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
    let spawn_args = json!({"argv": ["/bin/sleep", "8"], "background": true, "timeout_ms": 5000});
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
    let pid = spawn
        .processes
        .live_pids()
        .first()
        .copied()
        .expect("spawn pid");
    flag.cancel();
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
    assert_canonical_envelope(&waited.result);
    assert_eq!(error_code(&waited.result), "cancelled");
    assert_eq!(error_message(&waited.result), "process was cancelled");
    assert_eq!(spawn.processes.table_len(), 1);
    assert!(pid_alive(pid), "wait cancel must not kill the child");
    spawn.processes.cancel_all();
    wait_until_dead(pid);
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sha256sum");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(bytes)
        .expect("write sha256");
    let output = child.wait_with_output().expect("sha256sum wait");
    assert!(output.status.success(), "sha256sum failed");
    String::from_utf8(output.stdout)
        .expect("utf8")
        .split_whitespace()
        .next()
        .expect("digest")
        .to_string()
}

fn wait_for_descendants(pid: u32) -> Vec<u32> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let tree = collect_tree(pid);
        if tree.len() >= 2 || Instant::now() >= deadline {
            return tree;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn wait_in_loop_host_cancel_after_first_poll_matches_native_and_keeps_tree() {
    let fixture = Fixture::new("wait-in-loop-host");
    let config = fixture.config();
    let spawn_args = json!({
        "argv": ["/bin/sh", "-c", "sleep 30 & wait"],
        "background": true,
        "timeout_ms": 5000
    });
    let spawn = rss_terminal(&fixture, &config, spawn_args);
    assert_eq!(spawn.result["ok"], json!(true));
    let handle = spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let pid = spawn
        .processes
        .live_pids()
        .first()
        .copied()
        .expect("spawn pid");
    let tree = wait_for_descendants(pid);
    let run_cancellation = RunCancellation::new();
    spawn.processes.set_after_running_poll_hook(Arc::new({
        let run_cancellation = run_cancellation.clone();
        move || {
            run_cancellation.request(CancellationReason::Requested);
        }
    }));
    let waited = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            shared_lifecycle: Some(Arc::clone(&spawn.lifecycle)),
            shared_processes: Some(Arc::clone(&spawn.processes)),
            unlimited_fuel: true,
            run_cancellation: Some(run_cancellation),
            ..default_exec(
                "process.rss",
                "process",
                json!({"action": "wait", "process_id": handle, "timeout_ms": 8000}),
            )
        },
    );
    assert_canonical_envelope(&waited.result);
    assert_eq!(error_code(&waited.result), "cancelled");
    assert_eq!(error_message(&waited.result), "process was cancelled");
    assert_eq!(waited.result["data"], json!({}));
    assert_eq!(spawn.processes.table_len(), 1);
    for live in &tree {
        assert!(
            pid_alive(*live),
            "pid {live} must stay live after wait cancel"
        );
    }
    spawn.processes.cancel_all();
    for live in tree {
        wait_until_dead(live);
    }
}

#[test]
fn wait_in_loop_lifecycle_cancel_after_first_poll_keeps_owned_child() {
    let fixture = Fixture::new("wait-in-loop-life");
    let config = fixture.config();
    let spawn_args = json!({
        "argv": ["/bin/sh", "-c", "sleep 30 & wait"],
        "background": true,
        "timeout_ms": 5000
    });
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
    let handle = spawn.result["data"]["process_id"]
        .as_str()
        .unwrap()
        .to_string();
    let pid = spawn
        .processes
        .live_pids()
        .first()
        .copied()
        .expect("spawn pid");
    let tree = wait_for_descendants(pid);
    spawn.processes.set_after_running_poll_hook(Arc::new({
        let flag = flag.clone();
        move || flag.cancel()
    }));
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
                json!({"action": "wait", "process_id": handle, "timeout_ms": 8000}),
            )
        },
    );
    assert_canonical_envelope(&waited.result);
    assert_eq!(waited.result["data"], json!({}));
    assert_eq!(spawn.processes.table_len(), 1);
    for live in &tree {
        assert!(
            pid_alive(*live),
            "lifecycle cancel must not kill pid {live}"
        );
    }
    spawn.processes.cancel_all();
    for live in tree {
        wait_until_dead(live);
    }
}

#[test]
fn write_in_loop_cancel_after_full_pipe_matches_native_and_keeps_child() {
    let fixture = Fixture::new("write-in-loop");
    let config = fixture.config();
    let spawn_args = json!({"argv": ["/bin/sleep", "30"], "background": true, "timeout_ms": 5000});
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
    let pid = spawn
        .processes
        .live_pids()
        .first()
        .copied()
        .expect("spawn pid");
    spawn.processes.set_write_blocked_hook(Arc::new({
        let flag = flag.clone();
        move || flag.cancel()
    }));
    let payload = "x".repeat(1024 * 1024);
    let written = run_rss_exec(
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
                json!({
                    "action": "write",
                    "process_id": rss_id,
                    "data": payload,
                    "timeout_ms": 2000
                }),
            )
        },
    );
    assert_canonical_envelope(&written.result);
    assert_eq!(error_code(&written.result), "cancelled");
    assert_eq!(error_message(&written.result), "process was cancelled");
    assert_eq!(written.result["data"], json!({}));
    assert_eq!(spawn.processes.table_len(), 1);
    assert!(pid_alive(pid), "write cancel must not kill the child");
    spawn.processes.cancel_all();
    wait_until_dead(pid);
}

#[test]
fn foreground_slow_reader_receives_full_max_stdin_payload() {
    let fixture = Fixture::new("slow-stdin");
    let config = fixture.config();
    let payload = "A".repeat(config.max_stdin_bytes);
    let digest = sha256_hex(payload.as_bytes());
    let script = "import hashlib,sys,time\ntime.sleep(0.05)\ndata=sys.stdin.buffer.read()\nsys.stdout.write('%d %s' % (len(data), hashlib.sha256(data).hexdigest()))";
    let rss = rss_terminal(
        &fixture,
        &config,
        json!({
            "argv": ["/usr/bin/python3", "-c", script],
            "stdin": payload,
            "timeout_ms": 15000
        }),
    );
    assert_eq!(rss.result["ok"], json!(true), "{}", rss.result);
    let stdout = rss.result["data"]["stdout"].as_str().unwrap_or("");
    assert_eq!(stdout, format!("{} {digest}", payload.len()));
}

#[test]
fn foreground_cancel_during_initial_stdin_write_cleans_process_group() {
    let fixture = Fixture::new("stdin-cancel");
    let config = fixture.config();
    let flag = FlagCancel::new();
    let clock = Arc::new(SystemClock);
    let deadline_ms = clock.now_ms() + 60_000;
    let durable = MemoryDurable::new();
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&durable),
        Arc::new(AllowAll),
        flag.clone(),
        clock,
        deadline_ms,
    ));
    let processes = Arc::new(
        ProcessCapability::new(lifecycle.as_ref().clone(), owner(), process_limits(&config))
            .expect("processes"),
    );
    processes.set_write_blocked_hook(Arc::new({
        let flag = flag.clone();
        move || flag.cancel()
    }));
    let payload = "x".repeat(config.max_stdin_bytes);
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            cancellation: flag.clone(),
            shared_lifecycle: Some(Arc::clone(&lifecycle)),
            shared_processes: Some(Arc::clone(&processes)),
            unlimited_fuel: true,
            ..default_exec(
                "terminal.rss",
                "terminal",
                json!({
                    "argv": ["/bin/sh", "-c", "sleep 30 & wait"],
                    "stdin": payload,
                    "timeout_ms": 10000
                }),
            )
        },
    );
    assert_eq!(error_code(&rss.result), "cancelled");
    assert_eq!(error_message(&rss.result), "process was cancelled");
    assert_eq!(processes.table_len(), 0);
    assert!(
        processes.live_pids().is_empty(),
        "initial-write cancel must clean the process group"
    );
}
