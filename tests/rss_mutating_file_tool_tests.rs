//! Native-equivalence tests for RSS `write_file` and `patch`.
//!
//! These tests compile the real RSS modules and run them through the RSS VM
//! with generic capability host functions. Native `FileTools` is the oracle.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustscript_agent::capabilities::{
    ApprovalGate, ArtifactCapability, ArtifactLimits, CancellationFlag, CapabilityError,
    CapabilityLifecycle, CapabilityOwner, CapabilityRisk, DurableStarted, DurableToolLifecycle,
    FilesystemCapability, FilesystemLimits, LifecycleClock, LifecycleError, LifecycleLimits,
    NeverCancelled, PrepareMetadata, SystemClock, TokenIssuer, UuidIssuer, positive_duration_ms,
};
use rustscript_agent::config::FileToolConfig;
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, ControlCheckHook, RunCancellation, ToolResult,
    bundled_tool_registry,
};
use rustscript_vm::{CancellationReason, Value as VmValue};
use serde_json::{Value, json};

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

const REGISTRY_IDENTITY: &str = "rss-mutating-file-tool-equivalence";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn unique_temp_parent(label: &str) -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(
        "/mnt/TEMP/workspace/rustscript-agent/tmp/prod-agent-task-0f-rss-dispatch-fdee5b8a",
    )
    .join(format!(
        "rss-mut-{}-{}-{}",
        label.replace('/', "-"),
        std::process::id(),
        sequence
    ))
}

struct Fixture {
    root: PathBuf,
    parent: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let parent = unique_temp_parent(label);
        let root = parent.join("workspace");
        fs::create_dir_all(&root).expect("create rss mutating fixture");
        Self { root, parent }
    }

    fn config(&self) -> FileToolConfig {
        FileToolConfig::for_workspace(&self.root)
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
        })
    }

    fn started_len(&self) -> usize {
        self.started.lock().expect("started").len()
    }

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

    #[allow(dead_code)]
    fn interrupted_call_ids(&self) -> Vec<String> {
        self.interrupted.lock().expect("interrupted").clone()
    }

    fn fail_next_commit(&self) {
        self.fail_next_commit.store(true, Ordering::SeqCst);
    }

    fn seed_result(&self, call_id: &str, result: Value) {
        self.results
            .lock()
            .expect("results")
            .insert(call_id.to_string(), result);
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
            reason: "write tools are not approved".to_string(),
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

struct SequenceIssuer {
    next: Mutex<u64>,
}

impl SequenceIssuer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: Mutex::new(1),
        })
    }
}

impl TokenIssuer for SequenceIssuer {
    fn issue(&self) -> String {
        let mut next = self.next.lock().expect("issuer");
        let id = *next;
        *next += 1;
        format!("tok-{id}")
    }
}

fn rss_path(name: &str) -> PathBuf {
    let tools = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/tools");
    let stem = name.trim_end_matches(".rss");
    let entry = tools.join(format!("{stem}_entry.rss"));
    if entry.is_file() {
        entry
    } else {
        tools.join(name)
    }
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

fn rss_config_json(config: &FileToolConfig) -> Value {
    json!({
        "max_read_bytes": config.max_read_bytes,
        "max_read_lines": config.max_read_lines,
        "max_write_bytes": config.max_write_bytes,
        "max_patch_bytes": config.max_patch_bytes,
        "max_patch_preview_bytes": config.max_patch_preview_bytes,
        "max_search_files": config.max_search_files,
        "max_search_scanned_bytes": config.max_search_scanned_bytes,
        "max_search_depth": config.max_search_depth,
        "max_search_matches": config.max_search_matches,
        "max_search_output_bytes": config.max_search_output_bytes,
        "max_search_wall_time_ms": positive_duration_ms(config.max_search_wall_time),
        "max_tool_output_bytes": config.max_output_bytes,
    })
}

fn filesystem_limits(config: &FileToolConfig) -> FilesystemLimits {
    FilesystemLimits {
        max_read_bytes: config.max_read_bytes,
        max_write_bytes: config.max_write_bytes,
        max_list_entries: config.max_search_files.max(1),
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
            max_tool_calls: 32,
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

struct JumpClock {
    base: u64,
    jump_after: u64,
    jump_to: u64,
    wall_calls: AtomicU64,
    mono_calls: AtomicU64,
    instant: Instant,
}

impl JumpClock {
    fn new(base: u64, jump_after: u64, jump_to: u64) -> Arc<Self> {
        Arc::new(Self {
            base,
            jump_after,
            jump_to,
            wall_calls: AtomicU64::new(0),
            mono_calls: AtomicU64::new(0),
            instant: Instant::now(),
        })
    }
}

impl LifecycleClock for JumpClock {
    fn now_ms(&self) -> u64 {
        let seen = self.wall_calls.fetch_add(1, Ordering::SeqCst);
        if seen >= self.jump_after {
            self.jump_to
        } else {
            self.base
        }
    }

    fn now(&self) -> Instant {
        self.instant
    }

    fn monotonic_ms(&self) -> Option<u64> {
        let seen = self.mono_calls.fetch_add(1, Ordering::SeqCst);
        Some(if seen >= self.jump_after {
            self.jump_to
        } else {
            self.base
        })
    }
}

struct CancelAfter {
    checks: AtomicU64,
    cancel_at: u64,
}

impl CancelAfter {
    fn after_checks(cancel_at: u64) -> Arc<Self> {
        Arc::new(Self {
            checks: AtomicU64::new(0),
            cancel_at,
        })
    }
}

impl CancellationFlag for CancelAfter {
    fn is_cancelled(&self) -> bool {
        let seen = self.checks.fetch_add(1, Ordering::SeqCst);
        seen >= self.cancel_at
    }
}

struct RssRun {
    result: Value,
    started: usize,
    artifacts: Option<Arc<ArtifactCapability>>,
    durable: Arc<MemoryDurable>,
    call_id: String,
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
    install_artifacts: bool,
    artifact_limits: ArtifactLimits,
    call_id: String,
    unlimited_fuel: bool,
    run_cancellation: Option<RunCancellation>,
    control_hook: Option<ControlCheckHook>,
    shared_lifecycle: Option<Arc<CapabilityLifecycle>>,
    shared_filesystem: Option<Arc<FilesystemCapability>>,
}

fn default_artifact_limits() -> ArtifactLimits {
    ArtifactLimits {
        max_object_bytes: 8 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        max_objects: 64,
    }
}

fn run_rss_exec(fixture: &Fixture, config: &FileToolConfig, exec: RssExec) -> RssRun {
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
    let fs_cap = match exec.shared_filesystem.clone() {
        Some(fs_cap) => fs_cap,
        None => Arc::new(
            FilesystemCapability::new(
                lifecycle.as_ref().clone(),
                owner(),
                filesystem_limits(config),
            )
            .expect("filesystem capability"),
        ),
    };
    let artifacts = if exec.install_artifacts {
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
        filesystem: Some(fs_cap),
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
            "risk_class": "write",
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
        artifacts,
        durable: Arc::clone(&exec.durable),
        call_id: exec.call_id.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_rss_tool(
    module: &'static str,
    fixture: &Fixture,
    config: &FileToolConfig,
    tool_name: &'static str,
    arguments: Value,
    durable: Arc<MemoryDurable>,
    approval: Arc<dyn ApprovalGate>,
    cancellation: Arc<dyn CancellationFlag>,
    install_artifacts: bool,
) -> RssRun {
    let clock = Arc::new(SystemClock);
    let deadline_ms = clock.now_ms() + 60_000;
    run_rss_exec(
        fixture,
        config,
        RssExec {
            module,
            tool_name,
            arguments,
            durable,
            approval,
            cancellation,
            clock,
            deadline_ms,
            install_artifacts,
            artifact_limits: default_artifact_limits(),
            call_id: format!("call-{}", NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)),
            unlimited_fuel: false,
            run_cancellation: None,
            control_hook: None,
            shared_lifecycle: None,
            shared_filesystem: None,
        },
    )
}

fn mutation_exec(
    module: &'static str,
    tool_name: &'static str,
    arguments: Value,
    durable: Arc<MemoryDurable>,
    call_id: impl Into<String>,
) -> RssExec {
    let clock = Arc::new(SystemClock);
    let deadline_ms = clock.now_ms() + 60_000;
    RssExec {
        module,
        tool_name,
        arguments,
        durable,
        approval: Arc::new(AllowAll),
        cancellation: Arc::new(NeverCancelled),
        clock,
        deadline_ms,
        install_artifacts: false,
        artifact_limits: default_artifact_limits(),
        call_id: call_id.into(),
        unlimited_fuel: false,
        run_cancellation: None,
        control_hook: None,
        shared_lifecycle: None,
        shared_filesystem: None,
    }
}

fn unwrap_committed(value: Value) -> Value {
    if value.get("kind").and_then(Value::as_str) == Some("committed") {
        value.get("result").cloned().unwrap_or(value)
    } else {
        value
    }
}

fn assert_canonical_envelope(rss: &Value) {
    let _parsed: ToolResult =
        serde_json::from_value(rss.clone()).expect("canonical tool result schema");
    if let Some(message) = rss
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
    {
        assert!(
            !message_leaks_temp_root(message),
            "rss error leaked temp root: {message}"
        );
    }
}

fn message_leaks_temp_root(message: &str) -> bool {
    std::env::temp_dir()
        .to_str()
        .is_some_and(|tmp| message.contains(tmp))
        || message.contains("/mnt/TEMP/workspace/rustscript-agent/tmp")
}

fn leftover_temps(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".rustscript-agent-tmp-") || name.starts_with(".rustscript-tmp") {
                out.push(name);
            } else if entry.path().is_dir() {
                walk(&entry.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

fn run_rss_write(fixture: &Fixture, config: &FileToolConfig, arguments: Value) -> RssRun {
    run_rss_tool(
        "write_file_entry.rss",
        fixture,
        config,
        "write_file",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    )
}

fn run_rss_patch(fixture: &Fixture, config: &FileToolConfig, arguments: Value) -> RssRun {
    run_rss_tool(
        "patch_entry.rss",
        fixture,
        config,
        "patch",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    )
}

fn assert_write_eq(
    fixture: &Fixture,
    setup: impl Fn(),
    arguments: Value,
    expected_ok: bool,
    expected_error: Option<&str>,
    expected_file: Option<&str>,
    expected_started: usize,
) {
    let config = fixture.config();
    let path = arguments["path"].as_str().unwrap_or("").to_string();
    setup();
    let rss = run_rss_write(fixture, &config, arguments.clone());
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
    if let Some(expected) = expected_file {
        let actual = fs::read(fixture.root.join(&path)).unwrap_or_default();
        assert_eq!(
            actual,
            expected.as_bytes(),
            "file bytes path={path} rss={}",
            rss.result
        );
        if expected_ok {
            assert_eq!(
                rss.result["data"]["bytes"],
                json!(expected.len()),
                "bytes rss={}",
                rss.result
            );
        }
    }
    assert!(
        leftover_temps(&fixture.root).is_empty(),
        "write must not leave temps: {:?}",
        leftover_temps(&fixture.root)
    );
}

fn assert_patch_eq(
    fixture: &Fixture,
    setup: impl Fn(),
    arguments: Value,
    expected_ok: bool,
    expected_error: Option<&str>,
    expected_file: Option<&str>,
    expected_started: usize,
) {
    let config = fixture.config();
    let path = arguments["path"].as_str().unwrap_or("").to_string();
    setup();
    let rss = run_rss_patch(fixture, &config, arguments.clone());
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
    if let Some(expected) = expected_file {
        let actual = fs::read(fixture.root.join(&path)).unwrap_or_default();
        assert_eq!(
            actual,
            expected.as_bytes(),
            "file bytes path={path} rss={}",
            rss.result
        );
    }
    assert!(
        leftover_temps(&fixture.root).is_empty(),
        "patch must not leave temps: {:?}",
        leftover_temps(&fixture.root)
    );
}

fn rss_descriptor(name: &str) -> Value {
    bundled_tool_registry()
        .expect("RSS registry")
        .snapshot()
        .schemas()
        .as_array()
        .expect("descriptor array")
        .iter()
        .find(|value| value["name"] == name)
        .cloned()
        .expect("descriptor")
}

#[test]
fn rss_write_file_descriptor_matches_native() {
    let runner = compile_rss("write_file_entry.rss");
    let output = runner
        .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
        .expect("descriptor run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss, rss_descriptor("write_file"));
}

#[test]
fn rss_patch_descriptor_matches_native() {
    let runner = compile_rss("patch_entry.rss");
    let output = runner
        .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
        .expect("descriptor run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss, rss_descriptor("patch"));
}

#[test]
fn write_new_existing_empty_and_multibyte_match_native() {
    let fixture = Fixture::new("write-basic");
    let root = fixture.root.clone();
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("new.txt"));
        },
        json!({"path": "new.txt", "content": "hello\n"}),
        true,
        None,
        Some("hello\n"),
        1,
    );
    assert_write_eq(
        &fixture,
        || {
            fs::write(root.join("old.txt"), "old\n").unwrap();
        },
        json!({"path": "old.txt", "content": "new\n"}),
        true,
        None,
        Some("new\n"),
        1,
    );
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("empty.txt"));
        },
        json!({"path": "empty.txt", "content": ""}),
        true,
        None,
        Some(""),
        1,
    );
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("utf8.txt"));
        },
        json!({"path": "utf8.txt", "content": "你好🦀\n"}),
        true,
        None,
        Some("你好🦀\n"),
        1,
    );
}

#[test]
fn write_nested_parent_and_missing_parent_match_native() {
    let fixture = Fixture::new("write-nested");
    let root = fixture.root.clone();
    fs::create_dir_all(root.join("nested/dir")).unwrap();
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("nested/dir/leaf.txt"));
        },
        json!({"path": "nested/dir/leaf.txt", "content": "nested-bytes\n"}),
        true,
        None,
        Some("nested-bytes\n"),
        1,
    );
    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "missing/dir/leaf.txt", "content": "nope\n"}),
        false,
        Some("not_found"),
        None,
        1,
    );
}

#[test]
fn write_max_and_one_byte_over_bounds_match_native() {
    let fixture = Fixture::new("write-bounds");
    let mut config = fixture.config();
    config.max_write_bytes = 8;
    config.artifact_store.root = fixture.parent.join("artifacts-bounds");
    let root = fixture.root.clone();
    let exact = "12345678";
    let over = "123456789";
    fs::write(root.join("cap.txt"), "keep\n").unwrap();
    fs::write(root.join("cap.txt"), "keep\n").unwrap();
    let rss = run_rss_write(
        &fixture,
        &config,
        json!({"path": "cap.txt", "content": exact}),
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(fs::read_to_string(root.join("cap.txt")).unwrap(), exact);

    fs::write(root.join("cap.txt"), "keep\n").unwrap();
    fs::write(root.join("cap.txt"), "keep\n").unwrap();
    let rss = run_rss_write(
        &fixture,
        &config,
        json!({"path": "cap.txt", "content": over}),
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(fs::read_to_string(root.join("cap.txt")).unwrap(), "keep\n");
    assert_eq!(rss.result["error"]["code"], json!("write_too_large"));
}

#[test]
fn write_preserves_native_mode_contract() {
    let fixture = Fixture::new("write-mode");
    let path = fixture.root.join("mode.txt");
    fs::write(&path, "old\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let root = fixture.root.clone();
    assert_write_eq(
        &fixture,
        || {
            fs::write(root.join("mode.txt"), "old\n").unwrap();
            fs::set_permissions(root.join("mode.txt"), fs::Permissions::from_mode(0o640)).unwrap();
        },
        json!({"path": "mode.txt", "content": "new\n"}),
        true,
        None,
        None,
        1,
    );
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("fresh.txt"));
        },
        json!({"path": "fresh.txt", "content": "fresh\n"}),
        true,
        None,
        None,
        1,
    );
}

#[test]
fn write_denied_paths_match_native_and_do_not_prepare() {
    let fixture = Fixture::new("write-denied");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let outside = fixture.parent.join("outside.txt");
    fs::write(&outside, "outside-secret\n").unwrap();
    for (path, content) in [
        ("../outside.txt", "nope\n"),
        ("/tmp/outside.txt", "nope\n"),
        ("", "nope\n"),
        ("bad\0name", "nope\n"),
        ("colon:name", "nope\n"),
        ("back\\slash", "nope\n"),
        (&"a".repeat(4097), "nope\n"),
        (&format!("{}/leaf.txt", "c".repeat(256)), "nope\n"),
    ] {
        let durable = MemoryDurable::new();
        let rss = run_rss_tool(
            "write_file_entry.rss",
            &fixture,
            &fixture.config(),
            "write_file",
            json!({"path": path, "content": content}),
            Arc::clone(&durable),
            Arc::new(AllowAll),
            Arc::new(NeverCancelled),
            false,
        );
        assert_canonical_envelope(&rss.result);
        assert_eq!(rss.started, 0, "invalid path {path:?} must not prepare");
        assert_eq!(fs::read_to_string(&outside).unwrap(), "outside-secret\n");
        assert_eq!(
            fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
            "keep\n"
        );
    }
}

#[test]
fn malformed_write_args_do_not_prepare() {
    let fixture = Fixture::new("write-malformed");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    for arguments in [
        json!({}),
        json!({"content": "x"}),
        json!({"path": "keep.txt"}),
        json!({"path": 1, "content": "x"}),
        json!({"path": "keep.txt", "content": 1}),
    ] {
        let durable = MemoryDurable::new();
        let rss = run_rss_tool(
            "write_file_entry.rss",
            &fixture,
            &fixture.config(),
            "write_file",
            arguments.clone(),
            Arc::clone(&durable),
            Arc::new(AllowAll),
            Arc::new(NeverCancelled),
            false,
        );
        assert_canonical_envelope(&rss.result);
        assert_eq!(rss.started, 0);
        assert_eq!(
            fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
            "keep\n"
        );
    }
}

#[cfg(unix)]
#[test]
fn write_symlink_hardlink_and_directory_match_native() {
    let fixture = Fixture::new("write-special");
    let outside = fixture.parent.join("secret.txt");
    fs::write(&outside, "outside-secret\n").unwrap();
    fs::write(fixture.root.join("target.txt"), "inside\n").unwrap();
    symlink(&outside, fixture.root.join("leaf-link")).unwrap();
    fs::create_dir(fixture.root.join("nested")).unwrap();
    symlink(fixture.root.join("nested"), fixture.root.join("dir-link")).unwrap();
    fs::write(fixture.root.join("nested/inner.txt"), "inner\n").unwrap();
    fs::create_dir(fixture.root.join("dir")).unwrap();
    fs::write(fixture.root.join("hard.txt"), "hard\n").unwrap();
    fs::hard_link(
        fixture.root.join("hard.txt"),
        fixture.root.join("hard-link"),
    )
    .unwrap();
    let root = fixture.root.clone();

    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "leaf-link", "content": "changed\n"}),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert_eq!(fs::read_to_string(&outside).unwrap(), "outside-secret\n");
    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "dir-link/inner.txt", "content": "changed\n"}),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "dir", "content": "changed\n"}),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert_write_eq(
        &fixture,
        || {
            fs::write(root.join("hard.txt"), "hard\n").unwrap();
            let _ = fs::remove_file(root.join("hard-link"));
            fs::hard_link(root.join("hard.txt"), root.join("hard-link")).unwrap();
        },
        json!({"path": "hard-link", "content": "changed\n"}),
        false,
        Some("path_denied"),
        Some("hard\n"),
        1,
    );
    assert_eq!(fs::read_to_string(root.join("hard.txt")).unwrap(), "hard\n");
}

#[cfg(unix)]
#[test]
fn patch_leaf_and_intermediate_symlink_match_native_without_touching_outside() {
    let fixture = Fixture::new("patch-symlink");
    let outside = fixture.parent.join("secret.txt");
    fs::write(&outside, "outside-secret\n").unwrap();
    fs::write(fixture.root.join("target.txt"), "inside-needle\n").unwrap();
    symlink(&outside, fixture.root.join("leaf-link")).unwrap();
    fs::create_dir(fixture.root.join("nested")).unwrap();
    symlink(fixture.root.join("nested"), fixture.root.join("dir-link")).unwrap();
    fs::write(fixture.root.join("nested/inner.txt"), "inner-needle\n").unwrap();
    fs::create_dir(fixture.root.join("dir")).unwrap();

    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "leaf-link", "old_string": "outside-secret", "new_string": "changed", "replace_all": false}),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert!(
        fixture
            .root
            .join("leaf-link")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "leaf symlink must remain a symlink"
    );
    assert_eq!(fs::read_to_string(&outside).unwrap(), "outside-secret\n");

    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "dir-link/inner.txt", "old_string": "inner-needle", "new_string": "changed", "replace_all": false}),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("nested/inner.txt")).unwrap(),
        "inner-needle\n"
    );
    assert_eq!(fs::read_to_string(&outside).unwrap(), "outside-secret\n");

    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "dir", "old_string": "x", "new_string": "y", "replace_all": false}),
        false,
        Some("path_denied"),
        None,
        1,
    );
}

#[test]
fn patch_zero_one_multiple_and_replace_all_match_native() {
    let fixture = Fixture::new("patch-basic");
    let root = fixture.root.clone();
    let setup = || {
        fs::write(root.join("patch.txt"), "a\nb\na\n").unwrap();
    };
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "missing", "new_string": "x", "replace_all": false}),
        false,
        Some("patch_no_match"),
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "b", "new_string": "x", "replace_all": false}),
        true,
        None,
        Some("a\nx\na\n"),
        1,
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "a", "new_string": "x", "replace_all": false}),
        false,
        Some("patch_multiple_matches"),
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "a", "new_string": "x", "replace_all": true}),
        true,
        None,
        Some("x\nb\nx\n"),
        1,
    );
}

#[test]
fn patch_overlapping_replacement_containing_search_and_newlines_match_native() {
    let fixture = Fixture::new("patch-alg");
    let root = fixture.root.clone();
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("aaa.txt"), "aaaa").unwrap(),
        json!({"path": "aaa.txt", "old_string": "aa", "new_string": "b", "replace_all": true}),
        true,
        None,
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("loop.txt"), "a").unwrap(),
        json!({"path": "loop.txt", "old_string": "a", "new_string": "aa", "replace_all": false}),
        true,
        None,
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("nl.txt"), "keep\nneedle\nkeep\n").unwrap(),
        json!({"path": "nl.txt", "old_string": "needle", "new_string": "replaced", "replace_all": false}),
        true,
        None,
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("nonew.txt"), "keep needle keep").unwrap(),
        json!({"path": "nonew.txt", "old_string": "needle", "new_string": "replaced", "replace_all": false}),
        true,
        None,
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("cjk.txt"), "keep\n旧文字行\nkeep\n").unwrap(),
        json!({"path": "cjk.txt", "old_string": "旧文字行", "new_string": "新文字行", "replace_all": false}),
        true,
        None,
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("del.txt"), "keep needle keep").unwrap(),
        json!({"path": "del.txt", "old_string": "needle", "new_string": "", "replace_all": false}),
        true,
        None,
        None,
        1,
    );
}

#[test]
fn patch_high_match_count_stays_in_budget_and_matches_native() {
    let fixture = Fixture::new("patch-high-match");
    let source = "a".repeat(2048);
    let root = fixture.root.clone();
    let source_for_setup = source.clone();
    assert_patch_eq(
        &fixture,
        move || fs::write(root.join("many.txt"), &source_for_setup).unwrap(),
        json!({
            "path": "many.txt",
            "old_string": "a",
            "new_string": "b",
            "replace_all": true
        }),
        true,
        None,
        None,
        1,
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("many.txt")).unwrap(),
        "b".repeat(2048)
    );
    assert!(leftover_temps(&fixture.root).is_empty());
}

#[test]
fn patch_binary_nul_invalid_utf8_and_empty_old_match_native() {
    let fixture = Fixture::new("patch-errors");
    fs::write(fixture.root.join("invalid.txt"), [0xff, 0xfe, 0xfd]).unwrap();
    fs::write(fixture.root.join("binary.bin"), [b'a', 0, b'b']).unwrap();
    fs::write(fixture.root.join("ok.txt"), "needle\n").unwrap();
    let root = fixture.root.clone();
    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "invalid.txt", "old_string": "a", "new_string": "b"}),
        false,
        Some("invalid_utf8"),
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "binary.bin", "old_string": "a", "new_string": "b"}),
        false,
        Some("binary_file"),
        None,
        1,
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("ok.txt"), "needle\n").unwrap(),
        json!({"path": "ok.txt", "old_string": "", "new_string": "x"}),
        false,
        Some("invalid_arguments"),
        None,
        0,
    );
    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "missing.txt", "old_string": "a", "new_string": "b"}),
        false,
        Some("not_found"),
        None,
        1,
    );
}

#[test]
fn patch_growth_cap_and_preview_truncation_match_native() {
    let fixture = Fixture::new("patch-caps");
    fs::write(fixture.root.join("patch.txt"), "needle\n").unwrap();
    let mut config = fixture.config();
    config.max_patch_bytes = 16;
    config.artifact_store.root = fixture.parent.join("artifacts-growth");
    let rss = run_rss_patch(
        &fixture,
        &config,
        json!({"path": "patch.txt", "old_string": "needle", "new_string": "x".repeat(64)}),
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(
        fs::read_to_string(fixture.root.join("patch.txt")).unwrap(),
        "needle\n"
    );

    let path = "café/🦀.txt";
    fs::create_dir_all(fixture.root.join("café")).unwrap();
    fs::write(fixture.root.join(path), "keep\n旧文字行\nkeep\n").unwrap();
    let mut preview_config = fixture.config();
    preview_config.max_patch_preview_bytes = 24;
    preview_config.artifact_store.root = fixture.parent.join("artifacts-preview");
    fs::write(fixture.root.join(path), "keep\n旧文字行\nkeep\n").unwrap();
    fs::write(fixture.root.join(path), "keep\n旧文字行\nkeep\n").unwrap();
    let rss = run_rss_patch(
        &fixture,
        &preview_config,
        json!({"path": path, "old_string": "旧文字行", "new_string": "新文字行"}),
    );
    assert_canonical_envelope(&rss.result);
}

#[test]
fn patch_replace_all_non_bool_defaults_like_native() {
    let fixture = Fixture::new("patch-types");
    let root = fixture.root.clone();
    let setup = || fs::write(root.join("patch.txt"), "a\nb\na\n").unwrap();
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "a", "new_string": "x", "replace_all": 1}),
        false,
        Some("patch_multiple_matches"),
        Some("a\nb\na\n"),
        1,
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "a", "new_string": "x"}),
        false,
        Some("patch_multiple_matches"),
        Some("a\nb\na\n"),
        1,
    );
}

#[test]
fn malformed_patch_args_do_not_prepare() {
    let fixture = Fixture::new("patch-malformed");
    fs::write(fixture.root.join("ok.txt"), "needle\n").unwrap();
    for arguments in [
        json!({}),
        json!({"old_string": "a", "new_string": "b"}),
        json!({"path": "ok.txt", "new_string": "b"}),
        json!({"path": "ok.txt", "old_string": "a"}),
        json!({"path": 1, "old_string": "a", "new_string": "b"}),
    ] {
        let durable = MemoryDurable::new();
        let rss = run_rss_tool(
            "patch_entry.rss",
            &fixture,
            &fixture.config(),
            "patch",
            arguments.clone(),
            Arc::clone(&durable),
            Arc::new(AllowAll),
            Arc::new(NeverCancelled),
            false,
        );
        assert_canonical_envelope(&rss.result);
        assert_eq!(rss.started, 0);
        assert_eq!(
            fs::read_to_string(fixture.root.join("ok.txt")).unwrap(),
            "needle\n"
        );
    }
}

#[test]
fn cancelled_and_risk_failures_do_not_prepare_or_write() {
    let fixture = Fixture::new("write-cancel");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let cancel = FlagCancel::new();
    cancel.cancel();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "write_file_entry.rss",
        &fixture,
        &fixture.config(),
        "write_file",
        json!({"path": "keep.txt", "content": "changed\n"}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        cancel,
        false,
    );
    assert_eq!(rss.result["error"]["code"], "cancelled");
    assert_eq!(rss.started, 0);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );

    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "patch_entry.rss",
        &fixture,
        &fixture.config(),
        "patch",
        json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
        Arc::clone(&durable),
        Arc::new(DenyAll),
        Arc::new(NeverCancelled),
        false,
    );
    assert_eq!(rss.result["error"]["code"], "approval_denied");
    assert_eq!(rss.started, 0);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn cancellation_during_write_and_patch_has_no_later_effects() {
    let fixture = Fixture::new("mid-cancel");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "write_file_entry.rss",
        &fixture,
        &fixture.config(),
        "write_file",
        json!({"path": "keep.txt", "content": "changed\n"}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        CancelAfter::after_checks(1),
        false,
    );
    assert_eq!(
        rss.result["error"]["code"], "cancelled",
        "rss={}",
        rss.result
    );
    assert_eq!(rss.started, 1);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
    assert!(leftover_temps(&fixture.root).is_empty());

    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "patch_entry.rss",
        &fixture,
        &fixture.config(),
        "patch",
        json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        CancelAfter::after_checks(1),
        false,
    );
    assert_eq!(
        rss.result["error"]["code"], "cancelled",
        "rss={}",
        rss.result
    );
    assert_eq!(rss.started, 1);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn deadline_during_write_and_patch_has_no_later_effects() {
    let fixture = Fixture::new("mid-deadline");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_exec(
        &fixture,
        &fixture.config(),
        RssExec {
            module: "write_file_entry.rss",
            tool_name: "write_file",
            arguments: json!({"path": "keep.txt", "content": "changed\n"}),
            durable: Arc::clone(&durable),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: JumpClock::new(1_000, 2, 5_000),
            deadline_ms: 5_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-deadline-write".to_string(),
            unlimited_fuel: false,
            run_cancellation: None,
            control_hook: None,
            shared_lifecycle: None,
            shared_filesystem: None,
        },
    );
    assert_eq!(
        rss.result["error"]["code"], "deadline_elapsed",
        "rss={}",
        rss.result
    );
    assert_eq!(rss.started, 1);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );

    let durable = MemoryDurable::new();
    let rss = run_rss_exec(
        &fixture,
        &fixture.config(),
        RssExec {
            module: "patch_entry.rss",
            tool_name: "patch",
            arguments: json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
            durable: Arc::clone(&durable),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: JumpClock::new(1_000, 2, 5_000),
            deadline_ms: 5_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-deadline-patch".to_string(),
            unlimited_fuel: false,
            run_cancellation: None,
            control_hook: None,
            shared_lifecycle: None,
            shared_filesystem: None,
        },
    );
    assert_eq!(
        rss.result["error"]["code"], "deadline_elapsed",
        "rss={}",
        rss.result
    );
    assert_eq!(rss.started, 1);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn durable_replay_skips_write_effects() {
    let fixture = Fixture::new("replay");
    fs::write(fixture.root.join("keep.txt"), "first\n").unwrap();
    let stored = json!({
        "ok": true,
        "content": "wrote 8 bytes",
        "data": {
            "publication": "published",
            "durable": true,
            "staging_cleaned": true,
            "bytes": 8
        },
        "error": null,
        "truncated": false,
        "artifacts": []
    });
    let durable = MemoryDurable::new();
    durable.seed_result("call-replay", stored.clone());
    let rss = run_rss_exec(
        &fixture,
        &fixture.config(),
        RssExec {
            module: "write_file_entry.rss",
            tool_name: "write_file",
            arguments: json!({"path": "keep.txt", "content": "changed\n"}),
            durable: Arc::clone(&durable),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: Arc::new(SystemClock),
            deadline_ms: SystemClock.now_ms() + 60_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-replay".to_string(),
            unlimited_fuel: false,
            run_cancellation: None,
            control_hook: None,
            shared_lifecycle: None,
            shared_filesystem: None,
        },
    );
    assert_eq!(rss.result, stored);
    assert_eq!(rss.started, 0);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "first\n"
    );
}

#[test]
fn commit_failure_after_write_does_not_publish_false_completed_result() {
    let fixture = Fixture::new("commit-fail");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let durable = MemoryDurable::new();
    durable.fail_next_commit();
    let mut first = mutation_exec(
        "write_file_entry.rss",
        "write_file",
        json!({"path": "keep.txt", "content": "changed\n"}),
        Arc::clone(&durable),
        "call-commit-fail",
    );
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&durable),
        first.approval.clone(),
        first.cancellation.clone(),
        first.clock.clone(),
        first.deadline_ms,
    ));
    first.shared_lifecycle = Some(Arc::clone(&lifecycle));
    let rss = run_rss_exec(&fixture, &fixture.config(), first);
    assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["error"]["code"], json!("result_commit_failed"));
    assert!(rss.started > 0);
    assert!(
        rss.durable.started_call_ids().contains(&rss.call_id),
        "started={:?}",
        rss.durable.started_call_ids()
    );
    assert_eq!(
        rss.durable.stored_result(&rss.call_id),
        None,
        "commit failure must not store a completed result"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "changed\n",
        "published write effect remains after commit failure"
    );
    assert_ne!(rss.result["ok"], json!(true));
    let mut second = mutation_exec(
        "write_file_entry.rss",
        "write_file",
        json!({"path": "keep.txt", "content": "again\n"}),
        Arc::clone(&durable),
        "call-commit-fail",
    );
    second.shared_lifecycle = Some(lifecycle);
    let replay = run_rss_exec(&fixture, &fixture.config(), second);
    assert_eq!(
        replay.result["ok"],
        json!(false),
        "replay={}",
        replay.result
    );
    assert_eq!(replay.result["error"]["code"], json!("unresolved_call"));
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "changed\n",
        "same call_id must not rewrite after commit failure"
    );
}

#[test]
fn oversized_patch_preview_artifact_publication_matches_native_with_owner() {
    let fixture = Fixture::new("artifact-parity");
    fs::write(
        fixture.root.join("wide.txt"),
        format!("needle {}\n", "x".repeat(4000)),
    )
    .unwrap();
    let mut config = fixture.config();
    config.max_output_bytes = 1024;
    config.max_search_output_bytes = 1024;
    config.max_patch_preview_bytes = 8192;
    config.artifact_store.max_object_bytes = config.max_read_bytes;
    config.artifact_store.max_total_bytes = config.max_read_bytes.saturating_mul(2);
    let rss = run_rss_patch(
        &fixture,
        &config,
        json!({
            "path": "wide.txt",
            "old_string": "needle",
            "new_string": "replaced"
        }),
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["ok"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["artifacts"], json!([]), "rss={}", rss.result);
    assert_eq!(rss.result["error"], json!(null));
    assert_eq!(rss.result["data"]["publication"], json!("published"));
    assert_eq!(rss.result["data"]["replacements"], json!(1));
    assert_eq!(rss.result["data"]["bytes"], json!(4010));
    assert_eq!(rss.result["data"]["durable"], json!(true));
    assert_eq!(rss.result["data"]["staging_cleaned"], json!(true));
    let content = rss.result["content"].as_str().expect("content");
    assert_eq!(
        &content[..std::cmp::min(content.len(), 33)],
        "diff --git a/wide.txt b/wide.txt\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("wide.txt")).unwrap(),
        format!("replaced {}\n", "x".repeat(4000))
    );
}

#[test]
fn write_deadline_before_prepare_has_no_started_record() {
    let fixture = Fixture::new("write-deadline");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let durable = MemoryDurable::new();
    let clock = Arc::new(SystemClock);
    let lifecycle = Arc::new(
        CapabilityLifecycle::builder()
            .owner(owner())
            .registry_identity(REGISTRY_IDENTITY)
            .workspace(&fixture.root)
            .limits(LifecycleLimits {
                max_tool_calls: 32,
                max_output_bytes: 1024 * 1024,
                max_summary_bytes: 256,
            })
            .deadline_ms(1)
            .clock(Arc::clone(&clock) as Arc<dyn LifecycleClock>)
            .tokens(SequenceIssuer::new())
            .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
            .approval(Arc::new(AllowAll))
            .cancellation(Arc::new(NeverCancelled))
            .build()
            .expect("lifecycle"),
    );
    let fs_cap = FilesystemCapability::new(
        lifecycle.as_ref().clone(),
        owner(),
        filesystem_limits(&fixture.config()),
    )
    .expect("filesystem");
    let host = AgentHostBridges {
        lifecycle: Some(Arc::clone(&lifecycle)),
        capability_owner: Some(owner()),
        filesystem: Some(Arc::new(fs_cap)),
        ..AgentHostBridges::default()
    };
    std::thread::sleep(Duration::from_millis(2));
    let context = json!({
        "kind": "execute",
        "arguments": {"path": "keep.txt", "content": "changed\n"},
        "prepare": {
            "run_id": "run-test",
            "call_id": "call-deadline-before",
            "name": "write_file",
            "argument_digest": "digest",
            "registry_identity": REGISTRY_IDENTITY,
            "risk_class": "write",
            "summary": "write_file",
        },
        "config": rss_config_json(&fixture.config()),
    });
    let output = compile_rss("write_file_entry.rss")
        .with_host(host)
        .run_with_context(json_to_vm_value(&context))
        .expect("run");
    let result = unwrap_committed(vm_value_to_json(&output));
    assert_eq!(result["error"]["code"], "deadline_elapsed");
    assert_eq!(durable.started_len(), 0);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn patch_default_write_budget_boundary_matches_native_envelope() {
    let fixture = Fixture::new("patch-default-write-budget");
    let mut config = fixture.config();
    let max_write = config.max_write_bytes;
    let max_patch = config.max_patch_bytes;
    assert!(
        max_write < max_patch,
        "default write budget must sit below the patch budget"
    );
    // Keep default write/patch byte bounds. Shrink only the preview budget so
    // RSS bounded_diff does not walk a 1MiB string character-by-character.
    config.max_patch_preview_bytes = 32;

    let old = "needle";
    let exact = format!("{old}{}", "x".repeat(max_write - old.len()));
    assert_eq!(exact.len(), max_write);
    let over_new = format!("{exact}Y");
    assert_eq!(over_new.len(), max_write + 1);
    assert!(over_new.len() <= max_patch);

    fs::write(fixture.root.join("cap.txt"), old).unwrap();
    let exact_args = json!({
        "path": "cap.txt",
        "old_string": old,
        "new_string": exact,
        "replace_all": false
    });
    fs::write(fixture.root.join("cap.txt"), old).unwrap();
    let rss_exact = {
        let mut exec = mutation_exec(
            "patch_entry.rss",
            "patch",
            exact_args.clone(),
            MemoryDurable::new(),
            "call-budget-exact",
        );
        exec.unlimited_fuel = true;
        run_rss_exec(&fixture, &config, exec)
    };
    assert_canonical_envelope(&rss_exact.result);
    assert_eq!(
        fs::read(fixture.root.join("cap.txt")).unwrap().len(),
        max_write
    );

    fs::write(fixture.root.join("cap.txt"), old).unwrap();
    let over_args = json!({
        "path": "cap.txt",
        "old_string": old,
        "new_string": over_new,
        "replace_all": false
    });
    fs::write(fixture.root.join("cap.txt"), old).unwrap();
    let rss_over = {
        let mut exec = mutation_exec(
            "patch_entry.rss",
            "patch",
            over_args.clone(),
            MemoryDurable::new(),
            "call-budget-over",
        );
        exec.unlimited_fuel = true;
        run_rss_exec(&fixture, &config, exec)
    };
    assert_canonical_envelope(&rss_over.result);
    assert_eq!(rss_over.result["error"]["code"], json!("budget_exceeded"));
    assert_eq!(
        rss_over.result["error"]["message"],
        json!("write budget exceeded")
    );
    assert_eq!(
        rss_over.result["data"]["publication"],
        json!("not_published")
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("cap.txt")).unwrap(),
        old
    );
    assert!(leftover_temps(&fixture.root).is_empty());
}

fn native_like_artifact_summary(id: &str, bytes: usize, cap: usize) -> String {
    let full = format!("artifact {id} ({bytes} bytes)");
    if full.len() <= cap {
        return full;
    }
    let short = format!("artifact {id}");
    if short.len() <= cap {
        return short;
    }
    if "artifact".len() <= cap {
        return "artifact".to_string();
    }
    "artifact".chars().take(cap).collect()
}

fn cancel_on_nth(
    n: u64,
    reason: CancellationReason,
) -> (RunCancellation, ControlCheckHook, Arc<AtomicU64>) {
    let seen = Arc::new(AtomicU64::new(0));
    let seen_hook = Arc::clone(&seen);
    let hook = Arc::new(move |cancellation: &RunCancellation| {
        let count = seen_hook.fetch_add(1, Ordering::SeqCst) + 1;
        if count == n {
            cancellation.request(reason);
        }
    });
    (RunCancellation::new(), hook, seen)
}

fn with_output_cap(mut config: FileToolConfig, cap: usize) -> FileToolConfig {
    config.max_output_bytes = cap;
    config.max_search_output_bytes = cap.min(config.max_search_output_bytes);
    config.artifact_store.max_object_bytes = config.max_read_bytes.max(cap);
    config.artifact_store.max_total_bytes =
        config.artifact_store.max_object_bytes.saturating_mul(2);
    config
}

fn write_artifact_thresholds(bytes: usize) -> Vec<usize> {
    let id = "0".repeat(36);
    let full = native_like_artifact_summary(&id, bytes, usize::MAX);
    let short = format!("artifact {id}");
    vec![
        1024,
        full.len(),
        full.len() - 1,
        short.len(),
        short.len() - 1,
        8,
        7,
    ]
}

#[test]
fn write_file_artifact_summary_forms_match_native_at_content_thresholds() {
    let fixture = Fixture::new("write-summary-forms");
    let content = format!("lead{}", "你".repeat(500));
    let bytes = content.len();
    let arguments = json!({"path": "wide.txt", "content": content.clone()});
    for cap in write_artifact_thresholds(bytes) {
        let config = with_output_cap(fixture.config(), cap);
        fs::write(fixture.root.join("wide.txt"), "").unwrap();
        let mut exec = mutation_exec(
            "write_file_entry.rss",
            "write_file",
            arguments.clone(),
            MemoryDurable::new(),
            "call-write-summary",
        );
        exec.install_artifacts = true;
        let rss = run_rss_exec(&fixture, &config, exec);
        assert_canonical_envelope(&rss.result);
        if rss.result["ok"] == json!(true) {
            assert_eq!(
                fs::read_to_string(fixture.root.join("wide.txt")).unwrap(),
                content,
                "cap={cap}"
            );
        }
        assert_summary_cap_parity(cap, bytes, &rss);
    }
}

#[test]
fn patch_artifact_summary_forms_match_native_at_content_thresholds() {
    let fixture = Fixture::new("patch-summary-forms");
    let source = format!("needle {}", "你".repeat(500));
    let arguments = json!({
        "path": "wide.txt",
        "old_string": "needle",
        "new_string": "replaced",
        "replace_all": false
    });
    fs::write(fixture.root.join("wide.txt"), &source).unwrap();
    let config = {
        let mut config = with_output_cap(fixture.config(), 1024);
        config.max_patch_preview_bytes = 8192;
        config
    };
    let mut exec = mutation_exec(
        "patch_entry.rss",
        "patch",
        arguments,
        MemoryDurable::new(),
        "call-summary",
    );
    exec.install_artifacts = true;
    let rss = run_rss_exec(&fixture, &config, exec);
    assert_canonical_envelope(&rss.result);
}

fn assert_summary_cap_parity(cap: usize, bytes: usize, rss: &RssRun) {
    assert_canonical_envelope(&rss.result);
    if rss.result["ok"] == json!(true) {
        let artifacts = rss
            .result
            .get("artifacts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let content = rss.result["content"].as_str().expect("content");
        if artifacts.is_empty() {
            assert_eq!(
                content,
                format!("wrote {bytes} bytes"),
                "cap={cap} rss={}",
                rss.result
            );
        } else {
            let id = artifacts[0].as_str().expect("rss artifact id");
            assert_eq!(
                content,
                native_like_artifact_summary(id, bytes, cap),
                "cap={cap} rss={}",
                rss.result
            );
            let (stored, meta) = rss
                .artifacts
                .as_ref()
                .expect("rss artifact store")
                .stored(id)
                .expect("stored artifact");
            assert!(!stored.is_empty(), "cap={cap} id={id}");
            assert_eq!(meta["run"], json!("run-test"), "cap={cap} id={id}");
        }
    } else {
        assert_eq!(
            rss.result["error"]["code"],
            json!("output_truncated"),
            "cap={cap} rss={}",
            rss.result
        );
    }
}

#[test]
fn run_cancellation_is_observed_by_control_check_before_publish() {
    let fixture = Fixture::new("run-cancel-control");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    for (module, tool_name, arguments, nth, reason, code, message) in [
        (
            "write_file_entry.rss",
            "write_file",
            json!({"path": "keep.txt", "content": "changed\n"}),
            2_u64,
            CancellationReason::Requested,
            "cancelled",
            "tool execution was cancelled",
        ),
        (
            "patch_entry.rss",
            "patch",
            json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
            2_u64,
            CancellationReason::Requested,
            "cancelled",
            "tool execution was cancelled",
        ),
        (
            "patch_entry.rss",
            "patch",
            json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
            2_u64,
            CancellationReason::Deadline,
            "deadline_elapsed",
            "tool deadline elapsed",
        ),
    ] {
        let (cancel, hook, seen) = cancel_on_nth(nth, reason);
        let mut exec = mutation_exec(
            module,
            tool_name,
            arguments,
            MemoryDurable::new(),
            format!("call-control-{tool_name}-{code}"),
        );
        exec.run_cancellation = Some(cancel);
        exec.control_hook = Some(hook);
        let rss = run_rss_exec(&fixture, &fixture.config(), exec);
        assert!(
            seen.load(Ordering::SeqCst) >= nth,
            "{tool_name} control_check was not observed"
        );
        assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
        assert_eq!(rss.result["error"]["code"], json!(code));
        assert_eq!(rss.result["error"]["message"], json!(message));
        assert_eq!(rss.result["data"]["publication"], json!("not_published"));
        assert_eq!(
            fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
            "keep\n"
        );
        assert!(leftover_temps(&fixture.root).is_empty());
    }
}

#[test]
fn patch_mid_replace_cancellation_leaves_target_and_temps_clean() {
    let fixture = Fixture::new("patch-mid-replace-cancel");
    let source = "a".repeat(256);
    fs::write(fixture.root.join("keep.txt"), &source).unwrap();
    // execute start (1) + count_matches cadences for 256 scans (4) = 5 checks
    // without replace-loop checks. The 7th check exists only once replace_text
    // itself observes control at cadence; otherwise the write would succeed.
    let nth = 7_u64;
    let (cancel, hook, seen) = cancel_on_nth(nth, CancellationReason::Requested);
    let mut exec = mutation_exec(
        "patch_entry.rss",
        "patch",
        json!({
            "path": "keep.txt",
            "old_string": "a",
            "new_string": "b",
            "replace_all": true
        }),
        MemoryDurable::new(),
        "call-mid-replace-cancel",
    );
    exec.run_cancellation = Some(cancel);
    exec.control_hook = Some(hook);
    exec.unlimited_fuel = true;
    let rss = run_rss_exec(&fixture, &fixture.config(), exec);
    assert!(
        seen.load(Ordering::SeqCst) >= nth,
        "replace_text control_check was not observed"
    );
    assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["error"]["code"], json!("cancelled"));
    assert_eq!(
        rss.result["error"]["message"],
        json!("tool execution was cancelled")
    );
    assert_eq!(rss.result["data"]["publication"], json!("not_published"));
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        source
    );
    assert!(leftover_temps(&fixture.root).is_empty());
}

#[test]
fn patch_pre_publish_hook_cancel_and_deadline_leave_target_and_temps_clean() {
    let fixture = Fixture::new("patch-pre-publish-hook");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let durable = MemoryDurable::new();
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        Arc::new(SystemClock),
        SystemClock.now_ms() + 60_000,
    ));
    let fs_cap = Arc::new(
        FilesystemCapability::new(
            lifecycle.as_ref().clone(),
            owner(),
            filesystem_limits(&fixture.config()),
        )
        .expect("fs"),
    );
    let entered = Arc::new(AtomicU64::new(0));
    let entered_hook = Arc::clone(&entered);
    fs_cap.inject_before_write(Arc::new(move |_, _| {
        entered_hook.fetch_add(1, Ordering::SeqCst);
        Err(CapabilityError::new("cancelled", "run was cancelled"))
    }));
    let mut exec = mutation_exec(
        "patch_entry.rss",
        "patch",
        json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
        Arc::clone(&durable),
        "call-pre-publish-cancel",
    );
    exec.shared_lifecycle = Some(Arc::clone(&lifecycle));
    exec.shared_filesystem = Some(Arc::clone(&fs_cap));
    let rss = run_rss_exec(&fixture, &fixture.config(), exec);
    assert_eq!(
        entered.load(Ordering::SeqCst),
        1,
        "hook must run after transform"
    );
    assert_eq!(rss.result["error"]["code"], json!("cancelled"));
    assert_eq!(
        rss.result["error"]["message"],
        json!("tool execution was cancelled")
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
    assert!(leftover_temps(&fixture.root).is_empty());

    fs_cap.inject_before_write(Arc::new(|_, _| {
        Err(CapabilityError::new(
            "deadline_elapsed",
            "run deadline elapsed",
        ))
    }));
    let mut exec = mutation_exec(
        "patch_entry.rss",
        "patch",
        json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
        MemoryDurable::new(),
        "call-pre-publish-deadline",
    );
    exec.shared_lifecycle = Some(lifecycle);
    exec.shared_filesystem = Some(fs_cap);
    let rss = run_rss_exec(&fixture, &fixture.config(), exec);
    assert_eq!(rss.result["error"]["code"], json!("deadline_elapsed"));
    assert_eq!(
        rss.result["error"]["message"],
        json!("tool deadline elapsed")
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
    assert!(leftover_temps(&fixture.root).is_empty());
}

#[test]
fn publication_indeterminate_after_publish_maps_real_host_envelope() {
    let fixture = Fixture::new("pub-indeterminate");
    let durable = MemoryDurable::new();
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        Arc::new(SystemClock),
        SystemClock.now_ms() + 60_000,
    ));
    let fs_cap = Arc::new(
        FilesystemCapability::new(
            lifecycle.as_ref().clone(),
            owner(),
            filesystem_limits(&fixture.config()),
        )
        .expect("fs"),
    );
    let published = Arc::new(AtomicU64::new(0));
    let published_hook = Arc::clone(&published);
    fs_cap.inject_after_publish(Arc::new(move |_, _| {
        published_hook.fetch_add(1, Ordering::SeqCst);
        true
    }));
    for (module, tool_name, arguments, call_id) in [
        (
            "write_file_entry.rss",
            "write_file",
            json!({"path": "keep.txt", "content": "changed\n"}),
            "call-pub-write",
        ),
        (
            "patch_entry.rss",
            "patch",
            json!({"path": "keep.txt", "old_string": "keep", "new_string": "changed"}),
            "call-pub-patch",
        ),
    ] {
        fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
        let mut exec = mutation_exec(module, tool_name, arguments, Arc::clone(&durable), call_id);
        exec.shared_lifecycle = Some(Arc::clone(&lifecycle));
        exec.shared_filesystem = Some(Arc::clone(&fs_cap));
        let rss = run_rss_exec(&fixture, &fixture.config(), exec);
        assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
        assert_eq!(
            rss.result["error"]["code"],
            json!("publication_indeterminate")
        );
        assert_eq!(
            rss.result["error"]["message"],
            json!("write publication could not be classified")
        );
        assert_eq!(rss.result["data"]["publication"], json!("indeterminate"));
        assert!(
            rss.result["data"].get("durable").is_none(),
            "indeterminate must not claim durable success: {}",
            rss.result
        );
        assert!(
            rss.result["data"].get("staging_cleaned").is_none(),
            "indeterminate must not claim staging cleanup success: {}",
            rss.result
        );
        assert_eq!(
            fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
            "changed\n",
            "{tool_name} target may contain published bytes"
        );
        assert!(leftover_temps(&fixture.root).is_empty());
        assert!(
            rss.started > 0,
            "{tool_name} lifecycle started before indeterminate"
        );
        let stored = durable
            .stored_result(call_id)
            .expect("committed failure result");
        assert_eq!(stored["ok"], json!(false), "stored={stored}");
        assert_eq!(
            stored["error"]["code"],
            json!("publication_indeterminate"),
            "lifecycle must not falsely complete"
        );
    }
    assert_eq!(
        published.load(Ordering::SeqCst),
        2,
        "after-publish seam must run for write_file and patch"
    );
}

#[test]
fn interrupted_reopen_durable_replay_does_not_rewrite() {
    let fixture = Fixture::new("interrupt-reopen");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let durable = MemoryDurable::new();
    let (cancel, hook, seen) = cancel_on_nth(2, CancellationReason::Requested);
    let mut first = mutation_exec(
        "write_file_entry.rss",
        "write_file",
        json!({"path": "keep.txt", "content": "changed\n"}),
        Arc::clone(&durable),
        "call-interrupt-reopen",
    );
    first.run_cancellation = Some(cancel);
    first.control_hook = Some(hook);
    let first_run = run_rss_exec(&fixture, &fixture.config(), first);
    assert!(seen.load(Ordering::SeqCst) >= 2);
    assert_eq!(first_run.result["error"]["code"], json!("cancelled"));
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
    let stored = durable
        .stored_result("call-interrupt-reopen")
        .expect("cancelled result must be committed for replay");
    assert_eq!(stored["ok"], json!(false));

    let second = mutation_exec(
        "write_file_entry.rss",
        "write_file",
        json!({"path": "keep.txt", "content": "second\n"}),
        Arc::clone(&durable),
        "call-interrupt-reopen",
    );
    let replay = run_rss_exec(&fixture, &fixture.config(), second);
    assert_eq!(replay.result, stored);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn completed_call_reopen_replays_without_rewriting() {
    let fixture = Fixture::new("reopen-completed");
    fs::write(fixture.root.join("keep.txt"), "keep\n").unwrap();
    let durable = MemoryDurable::new();
    let first = mutation_exec(
        "write_file_entry.rss",
        "write_file",
        json!({"path": "keep.txt", "content": "first\n"}),
        Arc::clone(&durable),
        "call-completed-reopen",
    );
    let first_run = run_rss_exec(&fixture, &fixture.config(), first);
    assert_eq!(first_run.result["ok"], json!(true));
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "first\n"
    );
    let second = mutation_exec(
        "write_file_entry.rss",
        "write_file",
        json!({"path": "keep.txt", "content": "second\n"}),
        durable,
        "call-completed-reopen",
    );
    let replay = run_rss_exec(&fixture, &fixture.config(), second);
    assert_eq!(replay.result, first_run.result);
    assert_eq!(
        fs::read_to_string(fixture.root.join("keep.txt")).unwrap(),
        "first\n"
    );
}

#[test]
fn concurrent_patch_cas_has_one_winner_and_no_torn_content() {
    let fixture = Fixture::new("concurrent-cas");
    fs::write(fixture.root.join("race.txt"), "alpha\n").unwrap();
    let durable = MemoryDurable::new();
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        Arc::new(SystemClock),
        SystemClock.now_ms() + 60_000,
    ));
    let fs_cap = Arc::new(
        FilesystemCapability::new(
            lifecycle.as_ref().clone(),
            owner(),
            filesystem_limits(&fixture.config()),
        )
        .expect("fs"),
    );
    let barrier = Arc::new(Barrier::new(2));
    let hook_barrier = Arc::clone(&barrier);
    let control_hook: ControlCheckHook = Arc::new(move |_: &RunCancellation| {
        hook_barrier.wait();
    });
    let config = fixture.config();
    let make_exec = |new_string: &'static str, call_id: &'static str| {
        let mut exec = mutation_exec(
            "patch_entry.rss",
            "patch",
            json!({
                "path": "race.txt",
                "old_string": "alpha",
                "new_string": new_string,
                "replace_all": false
            }),
            Arc::clone(&durable),
            call_id,
        );
        exec.shared_lifecycle = Some(Arc::clone(&lifecycle));
        exec.shared_filesystem = Some(Arc::clone(&fs_cap));
        exec.control_hook = Some(Arc::clone(&control_hook));
        exec
    };
    let left = make_exec("beta", "call-cas-left");
    let right = make_exec("gamma", "call-cas-right");
    let (left_run, right_run) = thread::scope(|scope| {
        let left_handle = scope.spawn(|| run_rss_exec(&fixture, &config, left));
        let right_handle = scope.spawn(|| run_rss_exec(&fixture, &config, right));
        (
            left_handle.join().expect("left thread"),
            right_handle.join().expect("right thread"),
        )
    });
    let outcomes = [&left_run.result, &right_run.result];
    let wins = outcomes
        .iter()
        .filter(|result| result["ok"] == json!(true))
        .count();
    let conflicts = outcomes
        .iter()
        .filter(|result| result["error"]["code"] == json!("cas_mismatch"))
        .count();
    assert_eq!(
        wins, 1,
        "left={} right={}",
        left_run.result, right_run.result
    );
    assert_eq!(
        conflicts, 1,
        "left={} right={}",
        left_run.result, right_run.result
    );
    let body = fs::read_to_string(fixture.root.join("race.txt")).unwrap();
    assert!(
        body == "beta\n" || body == "gamma\n",
        "torn content: {body:?}"
    );
    assert!(leftover_temps(&fixture.root).is_empty());
}

#[cfg(unix)]
#[test]
fn nested_and_swapped_parent_symlink_race_does_not_touch_outside_secret() {
    let fixture = Fixture::new("nested-symlink-race");
    let outside_dir = fixture.parent.join("nested-outside-dir");
    fs::create_dir_all(&outside_dir).unwrap();
    fs::write(outside_dir.join("secret.txt"), "outside-secret\n").unwrap();
    fs::create_dir_all(fixture.root.join("nested/real")).unwrap();
    fs::write(fixture.root.join("nested/real/leaf.txt"), "inside\n").unwrap();
    symlink(&outside_dir, fixture.root.join("nested/swapped")).unwrap();
    symlink(
        outside_dir.join("secret.txt"),
        fixture.root.join("nested/real/link.txt"),
    )
    .unwrap();

    // Patch the live leaf symlink before any write can replace the link.
    assert_patch_eq(
        &fixture,
        || {},
        json!({
            "path": "nested/real/link.txt",
            "old_string": "outside-secret",
            "new_string": "changed",
            "replace_all": false
        }),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert!(
        fixture
            .root
            .join("nested/real/link.txt")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "leaf symlink must remain a symlink after patch"
    );
    assert_eq!(
        fs::read_to_string(outside_dir.join("secret.txt")).unwrap(),
        "outside-secret\n"
    );

    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "nested/swapped/secret.txt", "content": "changed\n"}),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "nested/real/link.txt", "content": "changed\n"}),
        false,
        Some("path_denied"),
        None,
        1,
    );
    assert_eq!(
        fs::read_to_string(outside_dir.join("secret.txt")).unwrap(),
        "outside-secret\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("nested/real/leaf.txt")).unwrap(),
        "inside\n"
    );
}
