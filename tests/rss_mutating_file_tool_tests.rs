//! Native-equivalence tests for RSS `write_file` and `patch`.
//!
//! These tests compile the real RSS modules and run them through the RSS VM
//! with generic capability host functions. Native `FileTools` is the oracle.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::capabilities::{
    ApprovalGate, ArtifactCapability, ArtifactLimits, CancellationFlag, CapabilityLifecycle,
    CapabilityOwner, CapabilityRisk, DurableStarted, DurableToolLifecycle, FilesystemCapability,
    FilesystemLimits, LifecycleClock, LifecycleError, LifecycleLimits, NeverCancelled,
    PrepareMetadata, SystemClock, TokenIssuer, UuidIssuer, positive_duration_ms,
};
use rustscript_agent::config::FileToolConfig;
use rustscript_agent::tools::{ArtifactOwner, FileTools, NativeToolExecutor, ToolResult};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, ToolRegistry};
use rustscript_vm::Value as VmValue;
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
        "/mnt/TEMP/workspace/rustscript-agent/tmp/prod-agent-task-0d-rss-mutation-c115da2b",
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

    fn tools(&self) -> FileTools {
        FileTools::new(self.config()).expect("native file tools")
    }

    fn tools_with_config(&self, mut config: FileToolConfig) -> FileTools {
        config.workspace_root = self.root.clone();
        config.artifact_store.root = self.parent.join(format!(
            "artifacts-{}",
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        FileTools::new(config).expect("configured native file tools")
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
    parent_ok: Mutex<bool>,
    active: Mutex<bool>,
    fail_next_commit: AtomicBool,
}

impl MemoryDurable {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Mutex::new(Vec::new()),
            results: Mutex::new(std::collections::HashMap::new()),
            parent_ok: Mutex::new(true),
            active: Mutex::new(true),
            fail_next_commit: AtomicBool::new(false),
        })
    }

    fn started_len(&self) -> usize {
        self.started.lock().expect("started").len()
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

    fn interrupt(&self, _call_id: &str) -> Result<(), LifecycleError> {
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rss/tools")
        .join(name)
}

fn compile_rss(name: &str) -> AgentRunner {
    AgentRunner::from_file(rss_path(name), AgentConfig::default()).unwrap_or_else(|error| {
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
    #[allow(dead_code)]
    durable: Arc<MemoryDurable>,
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
}

fn default_artifact_limits() -> ArtifactLimits {
    ArtifactLimits {
        max_object_bytes: 8 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        max_objects: 64,
    }
}

fn run_rss_exec(fixture: &Fixture, config: &FileToolConfig, exec: RssExec) -> RssRun {
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&exec.durable),
        exec.approval,
        exec.cancellation,
        exec.clock,
        exec.deadline_ms,
    ));
    let fs_cap = FilesystemCapability::new(
        lifecycle.as_ref().clone(),
        owner(),
        filesystem_limits(config),
    )
    .expect("filesystem capability");
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
        filesystem: Some(Arc::new(fs_cap)),
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
            "risk_class": "write",
            "summary": exec.tool_name,
        },
        "config": rss_config_json(config),
    });
    let runner = compile_rss(exec.module);
    let output = runner
        .with_host(host)
        .run_with_context(json_to_vm_value(&context))
        .unwrap_or_else(|error| panic!("rss {} run failed: {error}", exec.module));
    RssRun {
        result: unwrap_committed(vm_value_to_json(&output)),
        started: exec.durable.started_len(),
        artifacts,
        durable: exec.durable,
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
        },
    )
}

fn unwrap_committed(value: Value) -> Value {
    if value.get("kind").and_then(Value::as_str) == Some("committed") {
        value.get("result").cloned().unwrap_or(value)
    } else {
        value
    }
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

fn native_execute(
    tools: &FileTools,
    executor: NativeToolExecutor,
    arguments: &Value,
) -> ToolResult {
    tools.execute(&executor, arguments)
}

fn native_envelope(result: &ToolResult) -> Value {
    serde_json::to_value(result).expect("serialize native tool result")
}

fn canonical_envelope(value: &Value) -> Value {
    let parsed: ToolResult =
        serde_json::from_value(value.clone()).expect("canonical tool result schema");
    serde_json::to_value(parsed).expect("serialize canonical tool result")
}

fn assert_exact_envelope(native: &ToolResult, rss: &Value) {
    let native_json = native_envelope(native);
    let rss_json = canonical_envelope(rss);
    assert_eq!(
        project_artifact_ids(&native_json),
        project_artifact_ids(&rss_json),
        "exact canonical envelopes must match\nnative={native_json}\nrss={rss_json}"
    );
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

fn file_bytes(root: &Path, rel: &str) -> Option<Vec<u8>> {
    fs::read(root.join(rel)).ok()
}

fn file_mode(root: &Path, rel: &str) -> Option<u32> {
    fs::metadata(root.join(rel))
        .ok()
        .map(|meta| meta.permissions().mode() & 0o777)
}

fn run_rss_write(fixture: &Fixture, config: &FileToolConfig, arguments: Value) -> RssRun {
    run_rss_tool(
        "write_file.rss",
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
        "patch.rss",
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

fn assert_write_eq(fixture: &Fixture, setup: impl Fn(), arguments: Value) {
    let config = fixture.config();
    let path = arguments["path"].as_str().unwrap_or("").to_string();
    setup();
    let native = native_execute(&fixture.tools(), NativeToolExecutor::WriteFile, &arguments);
    let native_bytes = file_bytes(&fixture.root, &path);
    let native_mode = file_mode(&fixture.root, &path);
    setup();
    let rss = run_rss_write(fixture, &config, arguments);
    assert_exact_envelope(&native, &rss.result);
    assert_eq!(
        file_bytes(&fixture.root, &path),
        native_bytes,
        "write published bytes must match native"
    );
    assert_eq!(
        file_mode(&fixture.root, &path),
        native_mode,
        "write published mode must match native"
    );
    assert!(
        leftover_temps(&fixture.root).is_empty(),
        "write must not leave temps: {:?}",
        leftover_temps(&fixture.root)
    );
    if native.ok {
        assert!(rss.started > 0, "successful write must prepare");
    }
}

fn assert_patch_eq(fixture: &Fixture, setup: impl Fn(), arguments: Value) {
    let config = fixture.config();
    let path = arguments["path"].as_str().unwrap_or("").to_string();
    setup();
    let native = native_execute(&fixture.tools(), NativeToolExecutor::Patch, &arguments);
    let native_bytes = file_bytes(&fixture.root, &path);
    let native_mode = file_mode(&fixture.root, &path);
    setup();
    let rss = run_rss_patch(fixture, &config, arguments);
    assert_exact_envelope(&native, &rss.result);
    assert_eq!(
        file_bytes(&fixture.root, &path),
        native_bytes,
        "patch published bytes must match native"
    );
    assert_eq!(
        file_mode(&fixture.root, &path),
        native_mode,
        "patch published mode must match native"
    );
    assert!(
        leftover_temps(&fixture.root).is_empty(),
        "patch must not leave temps: {:?}",
        leftover_temps(&fixture.root)
    );
    if native.ok {
        assert!(rss.started > 0, "successful patch must prepare");
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

fn artifact_owner() -> ArtifactOwner {
    ArtifactOwner::new("profile-test", "session-test", "run-test").expect("artifact owner")
}

#[test]
fn rss_write_file_descriptor_matches_native() {
    let runner = compile_rss("write_file.rss");
    let output = runner
        .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
        .expect("descriptor run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss, native_descriptor("write_file"));
}

#[test]
fn rss_patch_descriptor_matches_native() {
    let runner = compile_rss("patch.rss");
    let output = runner
        .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
        .expect("descriptor run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss, native_descriptor("patch"));
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
    );
    assert_write_eq(
        &fixture,
        || {
            fs::write(root.join("old.txt"), "old\n").unwrap();
        },
        json!({"path": "old.txt", "content": "new\n"}),
    );
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("empty.txt"));
        },
        json!({"path": "empty.txt", "content": ""}),
    );
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("utf8.txt"));
        },
        json!({"path": "utf8.txt", "content": "你好🦀\n"}),
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
    );
    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "missing/dir/leaf.txt", "content": "nope\n"}),
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
    let native = native_execute(
        &fixture.tools_with_config(config.clone()),
        NativeToolExecutor::WriteFile,
        &json!({"path": "cap.txt", "content": exact}),
    );
    fs::write(root.join("cap.txt"), "keep\n").unwrap();
    let rss = run_rss_write(
        &fixture,
        &config,
        json!({"path": "cap.txt", "content": exact}),
    );
    assert_exact_envelope(&native, &rss.result);
    assert_eq!(fs::read_to_string(root.join("cap.txt")).unwrap(), exact);

    fs::write(root.join("cap.txt"), "keep\n").unwrap();
    let native = native_execute(
        &fixture.tools_with_config(config.clone()),
        NativeToolExecutor::WriteFile,
        &json!({"path": "cap.txt", "content": over}),
    );
    fs::write(root.join("cap.txt"), "keep\n").unwrap();
    let rss = run_rss_write(
        &fixture,
        &config,
        json!({"path": "cap.txt", "content": over}),
    );
    assert_exact_envelope(&native, &rss.result);
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
    );
    assert_write_eq(
        &fixture,
        || {
            let _ = fs::remove_file(root.join("fresh.txt"));
        },
        json!({"path": "fresh.txt", "content": "fresh\n"}),
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
            "write_file.rss",
            &fixture,
            &fixture.config(),
            "write_file",
            json!({"path": path, "content": content}),
            Arc::clone(&durable),
            Arc::new(AllowAll),
            Arc::new(NeverCancelled),
            false,
        );
        let native = native_execute(
            &fixture.tools(),
            NativeToolExecutor::WriteFile,
            &json!({"path": path, "content": content}),
        );
        assert_exact_envelope(&native, &rss.result);
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
            "write_file.rss",
            &fixture,
            &fixture.config(),
            "write_file",
            arguments.clone(),
            Arc::clone(&durable),
            Arc::new(AllowAll),
            Arc::new(NeverCancelled),
            false,
        );
        let native = native_execute(&fixture.tools(), NativeToolExecutor::WriteFile, &arguments);
        assert_exact_envelope(&native, &rss.result);
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
    );
    assert_eq!(fs::read_to_string(&outside).unwrap(), "outside-secret\n");
    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "dir-link/inner.txt", "content": "changed\n"}),
    );
    assert_write_eq(
        &fixture,
        || {},
        json!({"path": "dir", "content": "changed\n"}),
    );
    assert_write_eq(
        &fixture,
        || {
            fs::write(root.join("hard.txt"), "hard\n").unwrap();
            let _ = fs::remove_file(root.join("hard-link"));
            fs::hard_link(root.join("hard.txt"), root.join("hard-link")).unwrap();
        },
        json!({"path": "hard-link", "content": "changed\n"}),
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
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "b", "new_string": "x", "replace_all": false}),
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "a", "new_string": "x", "replace_all": false}),
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "a", "new_string": "x", "replace_all": true}),
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
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("loop.txt"), "a").unwrap(),
        json!({"path": "loop.txt", "old_string": "a", "new_string": "aa", "replace_all": false}),
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("nl.txt"), "keep\nneedle\nkeep\n").unwrap(),
        json!({"path": "nl.txt", "old_string": "needle", "new_string": "replaced", "replace_all": false}),
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("nonew.txt"), "keep needle keep").unwrap(),
        json!({"path": "nonew.txt", "old_string": "needle", "new_string": "replaced", "replace_all": false}),
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("cjk.txt"), "keep\n旧文字行\nkeep\n").unwrap(),
        json!({"path": "cjk.txt", "old_string": "旧文字行", "new_string": "新文字行", "replace_all": false}),
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("del.txt"), "keep needle keep").unwrap(),
        json!({"path": "del.txt", "old_string": "needle", "new_string": "", "replace_all": false}),
    );
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
    );
    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "binary.bin", "old_string": "a", "new_string": "b"}),
    );
    assert_patch_eq(
        &fixture,
        || fs::write(root.join("ok.txt"), "needle\n").unwrap(),
        json!({"path": "ok.txt", "old_string": "", "new_string": "x"}),
    );
    assert_patch_eq(
        &fixture,
        || {},
        json!({"path": "missing.txt", "old_string": "a", "new_string": "b"}),
    );
}

#[test]
fn patch_growth_cap_and_preview_truncation_match_native() {
    let fixture = Fixture::new("patch-caps");
    fs::write(fixture.root.join("patch.txt"), "needle\n").unwrap();
    let mut config = fixture.config();
    config.max_patch_bytes = 16;
    config.artifact_store.root = fixture.parent.join("artifacts-growth");
    let native = native_execute(
        &fixture.tools_with_config(config.clone()),
        NativeToolExecutor::Patch,
        &json!({"path": "patch.txt", "old_string": "needle", "new_string": "x".repeat(64)}),
    );
    let rss = run_rss_patch(
        &fixture,
        &config,
        json!({"path": "patch.txt", "old_string": "needle", "new_string": "x".repeat(64)}),
    );
    assert_exact_envelope(&native, &rss.result);
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
    let native = native_execute(
        &fixture.tools_with_config(preview_config.clone()),
        NativeToolExecutor::Patch,
        &json!({"path": path, "old_string": "旧文字行", "new_string": "新文字行"}),
    );
    fs::write(fixture.root.join(path), "keep\n旧文字行\nkeep\n").unwrap();
    let rss = run_rss_patch(
        &fixture,
        &preview_config,
        json!({"path": path, "old_string": "旧文字行", "new_string": "新文字行"}),
    );
    assert_exact_envelope(&native, &rss.result);
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
    );
    assert_patch_eq(
        &fixture,
        setup,
        json!({"path": "patch.txt", "old_string": "a", "new_string": "x"}),
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
            "patch.rss",
            &fixture,
            &fixture.config(),
            "patch",
            arguments.clone(),
            Arc::clone(&durable),
            Arc::new(AllowAll),
            Arc::new(NeverCancelled),
            false,
        );
        let native = native_execute(&fixture.tools(), NativeToolExecutor::Patch, &arguments);
        assert_exact_envelope(&native, &rss.result);
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
        "write_file.rss",
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
        "patch.rss",
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
        "write_file.rss",
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
        "patch.rss",
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
            module: "write_file.rss",
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
            module: "patch.rss",
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
            module: "write_file.rss",
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
    let rss = run_rss_tool(
        "write_file.rss",
        &fixture,
        &fixture.config(),
        "write_file",
        json!({"path": "keep.txt", "content": "changed\n"}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    );
    assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["error"]["code"], json!("result_commit_failed"));
    assert!(rss.started > 0);
    assert_eq!(durable.results.lock().expect("results").get("unused"), None);
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
    // Keep the cap large enough that both serde_json and RSS json::encode keep
    // the full `artifact {id} ({bytes} bytes)` summary. A 256-byte cap is
    // encoder-sensitive and truncates native content mid-summary.
    config.max_output_bytes = 1024;
    config.max_search_output_bytes = 1024;
    config.max_patch_preview_bytes = 8192;
    config.artifact_store.max_object_bytes = config.max_read_bytes;
    config.artifact_store.max_total_bytes = config.max_read_bytes.saturating_mul(2);
    let native_tools = fixture
        .tools_with_config(config.clone())
        .with_owner(artifact_owner());
    let arguments = json!({
        "path": "wide.txt",
        "old_string": "needle",
        "new_string": "replaced"
    });
    fs::write(
        fixture.root.join("wide.txt"),
        format!("needle {}\n", "x".repeat(4000)),
    )
    .unwrap();
    let native = native_execute(&native_tools, NativeToolExecutor::Patch, &arguments);
    fs::write(
        fixture.root.join("wide.txt"),
        format!("needle {}\n", "x".repeat(4000)),
    )
    .unwrap();
    let rss = run_rss_tool(
        "patch.rss",
        &fixture,
        &config,
        "patch",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        true,
    );
    assert_exact_envelope(&native, &rss.result);
    if !native.artifacts.is_empty() {
        let native_id = native.artifacts.first().expect("native artifact");
        let rss_id = rss.result["artifacts"][0].as_str().expect("rss artifact");
        let native_bytes = native_tools
            .artifact_store()
            .retrieve(&artifact_owner(), native_id)
            .expect("native bytes");
        let (rss_bytes, rss_meta) = rss
            .artifacts
            .as_ref()
            .expect("rss store")
            .stored(rss_id)
            .expect("rss stored");
        assert_eq!(native_bytes, rss_bytes);
        assert_eq!(rss_meta["run"], json!("run-test"));
    }
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
    let output = compile_rss("write_file.rss")
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
