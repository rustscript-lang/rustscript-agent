//! RSS `read_file` and `search_files` behavioral tests.
//!
//! These tests compile the real RSS modules and run them through the RSS VM
//! with generic capability host functions.

use std::fs;
use std::os::unix::fs::symlink;
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
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, ToolResult, bundled_tool_registry,
};
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

const REGISTRY_IDENTITY: &str = "rss-file-tool-equivalence";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn unique_temp_parent(label: &str) -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "rss-file-{}-{}-{}",
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
        fs::create_dir_all(&root).expect("create rss file fixture");
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
            reason: "read tools are not approved".to_string(),
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
            "risk_class": "read",
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

fn assert_canonical_envelope(rss: &Value) {
    let parsed: ToolResult =
        serde_json::from_value(rss.clone()).expect("canonical tool result schema");
    let _ = serde_json::to_value(parsed).expect("serialize canonical tool result");
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
}

fn run_rss_read(fixture: &Fixture, config: &FileToolConfig, arguments: Value) -> RssRun {
    run_rss_tool(
        "read_file_entry.rss",
        fixture,
        config,
        "read_file",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    )
}

fn run_rss_search(fixture: &Fixture, config: &FileToolConfig, arguments: Value) -> RssRun {
    run_rss_tool(
        "search_files_entry.rss",
        fixture,
        config,
        "search_files",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    )
}

fn assert_read_eq(fixture: &Fixture, arguments: Value) {
    let config = fixture.config();
    let rss = run_rss_read(fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    if rss.result.get("ok") == Some(&json!(true)) {
        assert!(rss.started > 0, "successful read must prepare");
    }
}

fn assert_search_eq(fixture: &Fixture, arguments: Value) {
    let config = fixture.config();
    let rss = run_rss_search(fixture, &config, arguments.clone());
    assert_canonical_envelope(&rss.result);
    if rss.result.get("ok") == Some(&json!(true)) {
        assert!(rss.started > 0, "successful search must prepare");
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
        .unwrap_or_else(|| panic!("missing native descriptor {name}"))
}

#[test]
fn rss_read_file_descriptor_matches_native() {
    let runner = compile_rss("read_file_entry.rss");
    let output = runner
        .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
        .expect("descriptor run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss, native_descriptor("read_file"));
}

#[test]
fn rss_search_files_descriptor_matches_native() {
    let runner = compile_rss("search_files_entry.rss");
    let output = runner
        .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
        .expect("descriptor run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss, native_descriptor("search_files"));
}

#[test]
fn read_defaults_offset_limit_empty_eof_and_multibyte_match_native() {
    let fixture = Fixture::new("read-basic");
    fs::write(fixture.root.join("notes.txt"), "alpha\nbeta\ngamma\n").unwrap();
    fs::write(fixture.root.join("empty.txt"), "").unwrap();
    fs::write(fixture.root.join("utf8.txt"), "你好\n世界\n").unwrap();
    fs::write(fixture.root.join("no-nl.txt"), "tail").unwrap();

    assert_read_eq(&fixture, json!({"path": "notes.txt"}));
    assert_read_eq(
        &fixture,
        json!({"path": "notes.txt", "offset": 2, "limit": 1}),
    );
    assert_read_eq(
        &fixture,
        json!({"path": "notes.txt", "offset": 4, "limit": 10}),
    );
    assert_read_eq(&fixture, json!({"path": "empty.txt"}));
    assert_read_eq(&fixture, json!({"path": "utf8.txt"}));
    assert_read_eq(&fixture, json!({"path": "no-nl.txt"}));
}

#[test]
fn read_invalid_utf8_binary_missing_and_denied_paths_match_native() {
    let fixture = Fixture::new("read-errors");
    fs::write(fixture.root.join("notes.txt"), "ok\n").unwrap();
    fs::write(fixture.root.join("bad.bin"), [0xff, 0xfe, 0xfd]).unwrap();
    fs::write(fixture.root.join("nul.bin"), [b'a', 0, b'b']).unwrap();
    fs::create_dir(fixture.root.join("dir")).unwrap();

    assert_read_eq(&fixture, json!({"path": "bad.bin"}));
    assert_read_eq(&fixture, json!({"path": "nul.bin"}));
    assert_read_eq(&fixture, json!({"path": "missing.txt"}));
    assert_read_eq(&fixture, json!({"path": "dir"}));
    assert_read_eq(&fixture, json!({"path": "../outside.txt"}));
    assert_read_eq(&fixture, json!({"path": "/tmp/outside.txt"}));
    assert_read_eq(&fixture, json!({"path": ""}));
}

#[test]
fn read_symlink_leaf_and_intermediate_match_native() {
    let fixture = Fixture::new("read-symlink");
    fs::write(fixture.root.join("target.txt"), "secret\n").unwrap();
    fs::create_dir(fixture.root.join("nested")).unwrap();
    symlink(
        fixture.root.join("target.txt"),
        fixture.root.join("leaf-link"),
    )
    .unwrap();
    symlink(fixture.root.join("nested"), fixture.root.join("dir-link")).unwrap();
    fs::write(fixture.root.join("nested/inner.txt"), "inner\n").unwrap();

    assert_read_eq(&fixture, json!({"path": "leaf-link"}));
    assert_read_eq(&fixture, json!({"path": "dir-link/inner.txt"}));
}

#[test]
fn read_large_file_and_output_cap_match_native() {
    let fixture = Fixture::new("read-caps");
    fs::write(fixture.root.join("big.txt"), "x".repeat(64)).unwrap();
    let mut config = fixture.config();
    config.max_read_bytes = 16;
    config.artifact_store.root = fixture.parent.join("artifacts-big");
    let rss = run_rss_read(&fixture, &config, json!({"path": "big.txt"}));
    assert_canonical_envelope(&rss.result);

    let mut output_config = fixture.config();
    output_config.max_output_bytes = 32;
    output_config.max_search_output_bytes = 32;
    output_config.artifact_store.root = fixture.parent.join("artifacts-out");
    fs::write(
        fixture.root.join("wide.txt"),
        format!("{}\n", "w".repeat(80)),
    )
    .unwrap();
    let rss = run_rss_read(&fixture, &output_config, json!({"path": "wide.txt"}));
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["error"]["code"], "output_truncated");
}

#[test]
fn malformed_read_args_do_not_prepare_or_touch_fs() {
    let fixture = Fixture::new("read-malformed");
    fs::write(fixture.root.join("notes.txt"), "alpha\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &fixture.config(),
        "read_file",
        json!({}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    );
    assert_eq!(rss.result["error"]["code"], "invalid_arguments");
    assert_eq!(rss.started, 0);

    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &fixture.config(),
        "read_file",
        json!({"path": "notes.txt", "offset": 0}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    );
    assert_eq!(rss.result["error"]["code"], "invalid_offset");
    assert_eq!(rss.started, 0);
}

#[test]
fn cancelled_and_risk_failures_do_not_prepare_read() {
    let fixture = Fixture::new("read-cancel");
    fs::write(fixture.root.join("notes.txt"), "alpha\n").unwrap();
    let cancel = FlagCancel::new();
    cancel.cancel();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &fixture.config(),
        "read_file",
        json!({"path": "notes.txt"}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        cancel,
        false,
    );
    assert_eq!(rss.result["error"]["code"], "cancelled");
    assert_eq!(rss.started, 0);

    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &fixture.config(),
        "read_file",
        json!({"path": "notes.txt"}),
        Arc::clone(&durable),
        Arc::new(DenyAll),
        Arc::new(NeverCancelled),
        false,
    );
    assert_eq!(rss.result["error"]["code"], "approval_denied");
    assert_eq!(rss.started, 0);
}

#[test]
fn search_content_glob_filename_hidden_and_order_match_native() {
    let fixture = Fixture::new("search-basic");
    fs::create_dir_all(fixture.root.join("src")).unwrap();
    fs::create_dir_all(fixture.root.join(".hidden")).unwrap();
    fs::write(
        fixture.root.join("src/a.rs"),
        "fn alpha() {}\nfn beta() {}\n",
    )
    .unwrap();
    fs::write(fixture.root.join("src/b.rs"), "fn gamma() {}\n").unwrap();
    fs::write(fixture.root.join("src/c.txt"), "alpha text\n").unwrap();
    fs::write(fixture.root.join(".hidden/secret.rs"), "fn alpha() {}\n").unwrap();
    fs::write(fixture.root.join("z.md"), "alpha doc\n").unwrap();

    assert_search_eq(&fixture, json!({"pattern": "alpha"}));
    assert_search_eq(&fixture, json!({"pattern": "fn ", "file_glob": "*.rs"}));
    assert_search_eq(&fixture, json!({"pattern": "*.rs", "target": "files"}));
    assert_search_eq(
        &fixture,
        json!({"pattern": "alpha", "path": "src", "limit": 1, "offset": 1}),
    );
    // Frozen quirk: native content search is substring, not regex.
    assert_search_eq(&fixture, json!({"pattern": "a.rs"}));
    assert_search_eq(&fixture, json!({"pattern": "a.c"}));
}

#[test]
fn search_caps_invalid_paths_and_symlinks_match_native() {
    let fixture = Fixture::new("search-errors");
    fs::create_dir_all(fixture.root.join("src")).unwrap();
    fs::write(fixture.root.join("src/a.rs"), "fn alpha() {}\n").unwrap();
    fs::write(fixture.root.join("src/b.rs"), "fn alpha() {}\n").unwrap();
    fs::write(fixture.root.join("target.txt"), "fn alpha() {}\n").unwrap();
    symlink(
        fixture.root.join("target.txt"),
        fixture.root.join("leaf-link"),
    )
    .unwrap();

    assert_search_eq(&fixture, json!({"pattern": ""}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "path": "../outside"}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "path": "/tmp"}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "path": "missing"}));

    let leaf_link_arguments = json!({"pattern": "alpha", "path": "leaf-link"});
    let rss_leaf_link = run_rss_search(&fixture, &fixture.config(), leaf_link_arguments);
    assert_canonical_envelope(&rss_leaf_link.result);

    let mut config = fixture.config();
    config.max_search_matches = 1;
    config.artifact_store.root = fixture.parent.join("artifacts-search");
    let arguments = json!({"pattern": "alpha"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
}

#[test]
fn malformed_search_args_do_not_prepare() {
    let fixture = Fixture::new("search-malformed");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "search_files_entry.rss",
        &fixture,
        &fixture.config(),
        "search_files",
        json!({}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    );
    assert_eq!(rss.result["error"]["code"], "invalid_arguments");
    assert_eq!(rss.started, 0);
}

#[test]
fn search_deadline_before_prepare_has_no_started_record() {
    let fixture = Fixture::new("search-deadline");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
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
    let context = json!({
        "kind": "execute",
        "arguments": {"pattern": "alpha"},
        "prepare": {
            "run_id": "run-test",
            "call_id": "call-deadline",
            "name": "search_files",
            "argument_digest": "digest",
            "registry_identity": REGISTRY_IDENTITY,
            "risk_class": "read",
            "summary": "search_files",
        },
        "config": rss_config_json(&fixture.config()),
    });
    let output = compile_rss("search_files_entry.rss")
        .with_host(host)
        .run_with_context(json_to_vm_value(&context))
        .expect("run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss["error"]["code"], "deadline_elapsed");
    assert_eq!(durable.started_len(), 0);
}

#[test]
fn search_regex_metacharacters_are_literal_substrings() {
    let fixture = Fixture::new("search-regex-literal");
    fs::write(fixture.root.join("plain.txt"), "alpha\nabc\naaa\n").unwrap();
    fs::write(
        fixture.root.join("meta.txt"),
        "^alpha\na.c\n[ab]\na+\n(?P\n",
    )
    .unwrap();

    // Frozen quirk: native content search is substring, not regex.
    assert_search_eq(&fixture, json!({"pattern": "^alpha"}));
    assert_search_eq(&fixture, json!({"pattern": "alpha$"}));
    assert_search_eq(&fixture, json!({"pattern": "a.c"}));
    assert_search_eq(&fixture, json!({"pattern": "a.*"}));
    assert_search_eq(&fixture, json!({"pattern": "[ab]"}));
    assert_search_eq(&fixture, json!({"pattern": "a+"}));
    assert_search_eq(&fixture, json!({"pattern": "(?P"}));
}

#[test]
fn search_glob_question_path_empty_and_filename_file_glob_match_native() {
    let fixture = Fixture::new("search-glob");
    fs::create_dir_all(fixture.root.join("src")).unwrap();
    fs::write(fixture.root.join("src/a.rs"), "fn alpha() {}\n").unwrap();
    fs::write(fixture.root.join("src/b.rs"), "fn beta() {}\n").unwrap();
    fs::write(fixture.root.join("src/c.txt"), "alpha text\n").unwrap();
    fs::write(fixture.root.join("ab.rs"), "fn ab() {}\n").unwrap();

    assert_search_eq(&fixture, json!({"pattern": "?.rs", "target": "files"}));
    assert_search_eq(&fixture, json!({"pattern": "src/*", "target": "files"}));
    assert_search_eq(
        &fixture,
        json!({"pattern": "*", "target": "files", "file_glob": "*.rs"}),
    );
    assert_search_eq(&fixture, json!({"pattern": "alpha", "file_glob": ""}));
    assert_search_eq(
        &fixture,
        json!({"pattern": "bogus-target", "target": "bogus"}),
    );
}

#[test]
fn search_nul_colon_backslash_and_limit_zero_match_native() {
    let fixture = Fixture::new("search-paths");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();

    assert_search_eq(
        &fixture,
        json!({"pattern": "alpha", "path": "bad\u{0000}name"}),
    );
    assert_search_eq(&fixture, json!({"pattern": "alpha", "path": "a:b"}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "path": "a\\b"}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "limit": 0}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "path": "a.txt"}));
}

#[test]
fn read_nul_colon_backslash_and_offset_zero_match_native() {
    let fixture = Fixture::new("read-paths");
    fs::write(fixture.root.join("notes.txt"), "alpha\nbeta\n").unwrap();

    assert_read_eq(&fixture, json!({"path": "bad\u{0000}name"}));
    assert_read_eq(&fixture, json!({"path": "a:b"}));
    assert_read_eq(&fixture, json!({"path": "notes.txt."}));
    assert_read_eq(
        &fixture,
        json!({"path": "notes.txt", "offset": 1, "limit": 0}),
    );
}

#[test]
fn read_oversized_result_publishes_artifact_with_read_token() {
    let fixture = Fixture::new("read-artifact");
    fs::write(
        fixture.root.join("wide.txt"),
        format!("{}\n", "w".repeat(4000)),
    )
    .unwrap();
    let mut config = fixture.config();
    config.max_output_bytes = 512;
    config.max_read_bytes = 8192;
    config.artifact_store.max_object_bytes = 8192;
    config.artifact_store.max_total_bytes = 16384;
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &config,
        "read_file",
        json!({"path": "wide.txt"}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        true,
    );
    assert_eq!(rss.result["ok"], json!(true));
    assert_eq!(rss.result["truncated"], json!(true));
    assert_eq!(
        rss.result["artifacts"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        1
    );
    assert!(
        rss.result["content"]
            .as_str()
            .unwrap_or("")
            .contains("artifact"),
        "published envelope should mention artifact: {}",
        rss.result
    );
    assert_eq!(rss.started, 1);
}

#[test]
fn search_match_file_dir_and_scan_caps_match_native() {
    let fixture = Fixture::new("search-caps-matrix");
    fs::create_dir_all(fixture.root.join("a")).unwrap();
    fs::create_dir_all(fixture.root.join("z")).unwrap();
    fs::write(fixture.root.join("a/match.rs"), "needle a\n").unwrap();
    fs::write(fixture.root.join("z/match.rs"), "needle z\nneedle z2\n").unwrap();
    fs::write(fixture.root.join("root.txt"), "needle root\n").unwrap();

    let mut files = fixture.config();
    files.max_search_files = 1;
    files.artifact_store.root = fixture.parent.join("artifacts-files");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &files, arguments.clone());
    assert_canonical_envelope(&rss.result);

    let mut depth = fixture.config();
    depth.max_search_depth = 1;
    depth.artifact_store.root = fixture.parent.join("artifacts-depth");
    let rss = run_rss_search(&fixture, &depth, arguments.clone());
    assert_canonical_envelope(&rss.result);

    let mut scan = fixture.config();
    scan.max_search_scanned_bytes = 8;
    scan.artifact_store.root = fixture.parent.join("artifacts-scan");
    let rss = run_rss_search(&fixture, &scan, arguments);
    assert_canonical_envelope(&rss.result);
}

#[test]
fn search_depth_rejected_child_dirs_are_not_counted() {
    let fixture = Fixture::new("search-depth-dirs-visited");
    fs::create_dir_all(fixture.root.join("nested/deep")).unwrap();
    fs::write(
        fixture.root.join("nested/deep/hidden.txt"),
        "needle hidden\n",
    )
    .unwrap();

    let mut config = fixture.config();
    config.max_search_depth = 1;
    config.artifact_store.root = fixture.parent.join("artifacts-depth-dirs");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_eq!(rss.result["data"]["dirs_visited"], json!(2));
    assert_canonical_envelope(&rss.result);
}

fn assert_search_exact_envelope(
    label: &str,
    files: &[(&str, &str)],
    mut config_edit: impl FnMut(&mut FileToolConfig),
    arguments: Value,
) -> RssRun {
    let fixture = Fixture::new(label);
    for (name, contents) in files {
        fs::write(fixture.root.join(name), contents).unwrap();
    }
    let mut config = fixture.config();
    config_edit(&mut config);
    config.artifact_store.root = fixture.parent.join(format!("artifacts-{label}"));
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    rss
}

#[test]
fn search_exact_fill_scan_cap_matches_all_lines_without_truncation() {
    let one_line = "needle\n";
    let rss = assert_search_exact_envelope(
        "search-exact-fill-one",
        &[("exact.txt", one_line)],
        |config| config.max_search_scanned_bytes = one_line.len(),
        json!({"pattern": "needle"}),
    );
    assert_eq!(rss.result["truncated"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["data"]["match_count"], json!(1));

    let multi = "n1\nn2\n";
    let rss = assert_search_exact_envelope(
        "search-exact-fill-multi",
        &[("exact.txt", multi)],
        |config| config.max_search_scanned_bytes = multi.len(),
        json!({"pattern": "n"}),
    );
    assert_eq!(rss.result["truncated"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["data"]["match_count"], json!(2));
}

#[test]
fn search_exact_fill_then_later_positive_file_truncates_like_native() {
    let first = "n1\nn2\n";
    let rss = assert_search_exact_envelope(
        "search-exact-fill-later",
        &[("a.txt", first), ("b.txt", "n3\n")],
        |config| config.max_search_scanned_bytes = first.len(),
        json!({"pattern": "n"}),
    );
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["data"]["match_count"], json!(2));
}

#[test]
fn search_final_files_visited_slot_is_fully_matched() {
    let rss = assert_search_exact_envelope(
        "search-final-file-slot",
        &[("a.txt", "n0\n"), ("b.txt", "n1\nn2\n")],
        |config| config.max_search_files = 4,
        json!({"pattern": "n"}),
    );
    assert_eq!(rss.result["truncated"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["data"]["match_count"], json!(3));
}

fn write_search_files(fixture: &Fixture, relative_paths: &[&str]) {
    for name in relative_paths {
        let path = fixture.root.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, "needle\n").unwrap();
    }
}

fn assert_search_exam_budget_eq(
    label: &str,
    max_search_files: usize,
    files: &[&str],
    arguments: Value,
) {
    let fixture = Fixture::new(label);
    write_search_files(&fixture, files);
    let mut config = fixture.config();
    config.max_search_files = max_search_files;
    config.artifact_store.root = fixture.parent.join(format!("artifacts-{label}"));
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
}

#[test]
fn search_enumeration_budget_counts_dot_slots_like_native() {
    let content = json!({"pattern": "needle"});
    let files_target = json!({"pattern": "*.txt", "target": "files"});

    // Budget N with N-1 and N real entries: native counts `.` and `..` first.
    assert_search_exam_budget_eq(
        "exam-n-minus-1",
        4,
        &["a.txt", "b.txt", "c.txt"],
        content.clone(),
    );
    assert_search_exam_budget_eq(
        "exam-n",
        4,
        &["a.txt", "b.txt", "c.txt", "d.txt"],
        content.clone(),
    );
    assert_search_exam_budget_eq("exam-n-pass", 4, &["a.txt", "b.txt"], content.clone());
    assert_search_exam_budget_eq(
        "exam-n-files-target",
        4,
        &["a.txt", "b.txt", "c.txt"],
        files_target.clone(),
    );

    // remaining <= 2 at the search root, including empty directories.
    assert_search_exam_budget_eq("exam-rem-1-file", 1, &["a.txt"], content.clone());
    assert_search_exam_budget_eq("exam-rem-1-empty", 1, &[], content.clone());
    assert_search_exam_budget_eq("exam-rem-2-one", 2, &["a.txt"], content.clone());
    assert_search_exam_budget_eq("exam-rem-2-two", 2, &["a.txt", "b.txt"], content.clone());
    assert_search_exam_budget_eq("exam-rem-2-empty", 2, &[], content.clone());

    // Sibling directory entered with remaining == 2 after a prior tree consumed files.
    assert_search_exam_budget_eq(
        "exam-nested-rem-2",
        5,
        &["adir/f0.txt", "adir/f1.txt", "adir/f2.txt", "zdir/late.txt"],
        content.clone(),
    );

    // After the first subtree consumes the file budget, entering the next
    // sibling increments dirs_visited before truncation (native walk-entry order).
    assert_search_exam_budget_eq(
        "exam-nested-rem-0",
        6,
        &[
            "adir/f0.txt",
            "adir/f1.txt",
            "adir/f2.txt",
            "adir/f3.txt",
            "zdir/late.txt",
        ],
        content,
    );
}

fn assert_policy_denied_before_prepare(
    module: &'static str,
    tool_name: &'static str,
    fixture: &Fixture,
    arguments: Value,
) {
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        module,
        fixture,
        &fixture.config(),
        tool_name,
        arguments.clone(),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        false,
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(
        rss.started, 0,
        "syntactic/path policy must not prepare: {arguments} rss={}",
        rss.result
    );
    assert_eq!(durable.started_len(), 0);
}

#[test]
fn read_path_policy_is_rejected_before_prepare() {
    let fixture = Fixture::new("read-policy");
    fs::write(fixture.root.join("notes.txt"), "alpha\n").unwrap();
    for arguments in [
        json!({}),
        json!({"path": 1}),
        json!({"path": ""}),
        json!({"path": "../outside"}),
        json!({"path": "/tmp"}),
        json!({"path": "bad\u{0000}name"}),
        json!({"path": "a:b"}),
        json!({"path": "a\\b"}),
        json!({"path": "notes.txt."}),
        json!({"path": "notes.txt", "offset": 0}),
        json!({"path": "notes.txt", "offset": -1}),
        json!({"path": "你".repeat(100)}),
    ] {
        assert_policy_denied_before_prepare(
            "read_file_entry.rss",
            "read_file",
            &fixture,
            arguments,
        );
    }
}

#[test]
fn search_path_policy_is_rejected_before_prepare() {
    let fixture = Fixture::new("search-policy");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
    for arguments in [
        json!({}),
        json!({"pattern": 1}),
        json!({"pattern": ""}),
        json!({"pattern": "alpha", "path": "../outside"}),
        json!({"pattern": "alpha", "path": "/tmp"}),
        json!({"pattern": "alpha", "path": "bad\u{0000}name"}),
        json!({"pattern": "alpha", "path": "a:b"}),
        json!({"pattern": "alpha", "path": "a\\b"}),
        json!({"pattern": "alpha", "offset": -1}),
        json!({"pattern": "alpha", "path": "你".repeat(100)}),
    ] {
        assert_policy_denied_before_prepare(
            "search_files_entry.rss",
            "search_files",
            &fixture,
            arguments,
        );
    }
}

#[test]
fn cjk_component_byte_limit_is_rejected_before_prepare_like_native() {
    let fixture = Fixture::new("cjk-component-bytes");
    fs::write(fixture.root.join("notes.txt"), "alpha\n").unwrap();
    let component = "你".repeat(100);
    assert_eq!(component.len(), 300);
    assert_eq!(component.chars().count(), 100);
    assert!(component.chars().count() < 255);
    assert_policy_denied_before_prepare(
        "read_file_entry.rss",
        "read_file",
        &fixture,
        json!({"path": component.clone()}),
    );
    assert_policy_denied_before_prepare(
        "search_files_entry.rss",
        "search_files",
        &fixture,
        json!({"pattern": "alpha", "path": component}),
    );
}

#[test]
fn search_one_nanosecond_budget_ceils_to_one_ms_and_matches_native() {
    assert_eq!(positive_duration_ms(Duration::ZERO), 0);
    assert_eq!(positive_duration_ms(Duration::from_nanos(1)), 1);
    assert_eq!(positive_duration_ms(Duration::from_micros(999)), 1);
    assert_eq!(positive_duration_ms(Duration::from_millis(1)), 1);
    assert_eq!(positive_duration_ms(Duration::from_millis(2)), 2);

    let fixture = Fixture::new("search-1ns-ceil");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
    fs::write(fixture.root.join("b.txt"), "alpha\n").unwrap();
    let mut config = fixture.config();
    config.max_search_wall_time = Duration::from_nanos(1);
    assert_eq!(
        rss_config_json(&config)["max_search_wall_time_ms"],
        json!(1)
    );

    let arguments = json!({"pattern": "alpha"});
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            module: "search_files_entry.rss",
            tool_name: "search_files",
            arguments,
            durable: MemoryDurable::new(),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: JumpClock::new(1_000, 1, 1_001),
            deadline_ms: 1_000_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-1ns-ceil".to_string(),
        },
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["ok"], json!(true), "rss={}", rss.result);
    assert!(rss.started > 0);
}

#[test]
fn search_fake_clock_wall_time_truncates_without_deadline_failure() {
    let fixture = Fixture::new("search-clock");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
    let mut config = fixture.config();
    config.max_search_wall_time = Duration::from_millis(2);
    let durable = MemoryDurable::new();
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            module: "search_files_entry.rss",
            tool_name: "search_files",
            arguments: json!({"pattern": "alpha"}),
            durable,
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: JumpClock::new(1_000, 1, 1_002),
            deadline_ms: 1_000_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-clock".to_string(),
        },
    );
    assert_eq!(rss.result["ok"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["error"], Value::Null);
    assert!(rss.started > 0);
}

#[test]
fn cancellation_during_read_and_search_has_no_later_effects() {
    let fixture = Fixture::new("mid-cancel");
    fs::write(fixture.root.join("notes.txt"), "alpha\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &fixture.config(),
        "read_file",
        json!({"path": "notes.txt"}),
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
    assert_eq!(durable.started_len(), 1);

    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "search_files_entry.rss",
        &fixture,
        &fixture.config(),
        "search_files",
        json!({"pattern": "alpha"}),
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
}

#[test]
fn deadline_during_read_and_search_has_no_later_effects() {
    let fixture = Fixture::new("mid-deadline");
    fs::write(fixture.root.join("notes.txt"), "alpha\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_exec(
        &fixture,
        &fixture.config(),
        RssExec {
            module: "read_file_entry.rss",
            tool_name: "read_file",
            arguments: json!({"path": "notes.txt"}),
            durable: Arc::clone(&durable),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: JumpClock::new(1_000, 2, 5_000),
            deadline_ms: 5_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-deadline-read".to_string(),
        },
    );
    assert_eq!(
        rss.result["error"]["code"], "deadline_elapsed",
        "rss={}",
        rss.result
    );
    assert_eq!(rss.started, 1);

    let durable = MemoryDurable::new();
    let rss = run_rss_exec(
        &fixture,
        &fixture.config(),
        RssExec {
            module: "search_files_entry.rss",
            tool_name: "search_files",
            arguments: json!({"pattern": "alpha"}),
            durable: Arc::clone(&durable),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: JumpClock::new(1_000, 2, 5_000),
            deadline_ms: 5_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-deadline-search".to_string(),
        },
    );
    assert_eq!(
        rss.result["error"]["code"], "deadline_elapsed",
        "rss={}",
        rss.result
    );
    assert_eq!(rss.started, 1);
}

#[test]
fn symlink_swap_never_leaks_outside_bytes() {
    let fixture = Fixture::new("toctou");
    let secret = "outside-secret-do-not-leak\n";
    fs::write(fixture.parent.join("secret.txt"), secret).unwrap();
    fs::write(fixture.root.join("inside.txt"), "inside-ok\n").unwrap();
    fs::remove_file(fixture.root.join("inside.txt")).unwrap();
    symlink(
        fixture.parent.join("secret.txt"),
        fixture.root.join("inside.txt"),
    )
    .unwrap();

    let rss = run_rss_read(&fixture, &fixture.config(), json!({"path": "inside.txt"}));
    let content = rss.result["content"].as_str().unwrap_or("");
    let message = rss.result["error"]["message"].as_str().unwrap_or("");
    assert!(
        !content.contains("outside-secret") && !message.contains("outside-secret"),
        "rss leaked outside bytes: {}",
        rss.result
    );
    assert_canonical_envelope(&rss.result);

    let rss = run_rss_search(
        &fixture,
        &fixture.config(),
        json!({"pattern": "outside-secret"}),
    );
    let content = rss.result["content"].as_str().unwrap_or("");
    assert!(
        !content.contains("outside-secret"),
        "search leaked outside bytes: {}",
        rss.result
    );
}

#[test]
fn durable_replay_returns_stored_result_without_filesystem_effect() {
    let fixture = Fixture::new("replay");
    fs::write(fixture.root.join("notes.txt"), "first\n").unwrap();
    let stored = json!({
        "ok": true,
        "content": "replayed-bytes",
        "data": {"path": "notes.txt", "offset": 1, "line_count": 1},
        "error": null,
        "truncated": false,
        "artifacts": []
    });
    let durable = MemoryDurable::new();
    durable.seed_result("call-replay", stored.clone());
    fs::write(fixture.root.join("notes.txt"), "changed-after-store\n").unwrap();
    let rss = run_rss_exec(
        &fixture,
        &fixture.config(),
        RssExec {
            module: "read_file_entry.rss",
            tool_name: "read_file",
            arguments: json!({"path": "notes.txt"}),
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
        fs::read_to_string(fixture.root.join("notes.txt")).unwrap(),
        "changed-after-store\n"
    );
}

#[test]
fn oversized_read_and_search_artifact_publication_matches_native_with_owner() {
    let fixture = Fixture::new("artifact-parity");
    fs::write(
        fixture.root.join("wide.txt"),
        format!("{}\n", "w".repeat(4000)),
    )
    .unwrap();
    fs::write(
        fixture.root.join("hit.txt"),
        format!("needle {}\n", "x".repeat(4000)),
    )
    .unwrap();
    let mut config = fixture.config();
    config.max_output_bytes = 512;
    config.max_search_output_bytes = 512;
    config.max_read_bytes = 8192;
    config.artifact_store.max_object_bytes = 8192;
    config.artifact_store.max_total_bytes = 16384;

    let arguments = json!({"path": "wide.txt"});
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &config,
        "read_file",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        true,
    );
    assert_canonical_envelope(&rss.result);
    let rss_id = rss.result["artifacts"][0].as_str().expect("rss artifact");
    let (rss_bytes, rss_meta) = rss
        .artifacts
        .as_ref()
        .expect("rss store")
        .stored(rss_id)
        .expect("rss stored");
    assert!(!rss_bytes.is_empty(), "overflow artifact must store bytes");
    assert_eq!(rss_meta["run"], json!("run-test"));
    assert_eq!(
        rss_meta["call_id"],
        json!(rss.durable.started.lock().expect("started")[0].call_id)
    );

    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_tool(
        "search_files_entry.rss",
        &fixture,
        &config,
        "search_files",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        true,
    );
    assert_canonical_envelope(&rss.result);
    if let Some(rss_id) = rss.result["artifacts"]
        .as_array()
        .and_then(|items| items.first().and_then(Value::as_str).map(str::to_string))
    {
        let (rss_bytes, _) = rss
            .artifacts
            .as_ref()
            .expect("rss store")
            .stored(&rss_id)
            .expect("rss search stored");
        assert!(!rss_bytes.is_empty());
    } else {
        assert_eq!(rss.result["ok"], json!(true));
        assert!(
            rss.result["truncated"] == json!(true)
                || rss.result["data"]["matches"]
                    .as_array()
                    .is_some_and(|matches| !matches.is_empty()),
            "search should truncate or return matches: {}",
            rss.result
        );
    }
}

#[test]
fn read_cjk_output_budget_uses_utf8_bytes_like_native() {
    let fixture = Fixture::new("read-cjk-bytes");
    let content = "你好世界".repeat(80);
    fs::write(fixture.root.join("cjk.txt"), &content).unwrap();
    let mut config = fixture.config();
    config.max_output_bytes = 512;
    config.max_search_output_bytes = 512;
    config.max_read_bytes = 8192;
    config.artifact_store.max_object_bytes = 8192;
    config.artifact_store.max_total_bytes = 16384;
    let arguments = json!({"path": "cjk.txt"});
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &config,
        "read_file",
        arguments,
        MemoryDurable::new(),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        true,
    );
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["ok"], json!(true));
    assert_ne!(
        rss.result["error"]["code"],
        json!("result_too_large"),
        "cjk byte budget must shrink/artifact rather than fail commit"
    );
}

#[test]
fn search_cjk_match_budget_uses_utf8_bytes_like_native() {
    let fixture = Fixture::new("search-cjk-bytes");
    fs::write(fixture.root.join("cjk.txt"), "needle 你好世界\n").unwrap();
    let mut config = fixture.config();
    config.max_search_output_bytes = 24;
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
}

#[test]
fn search_file_glob_non_string_is_ignored_like_native() {
    let fixture = Fixture::new("glob-types");
    fs::write(fixture.root.join("keep.rs"), "alpha\n").unwrap();
    fs::write(fixture.root.join("skip.txt"), "alpha\n").unwrap();
    assert_search_eq(&fixture, json!({"pattern": "alpha", "file_glob": 1}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "file_glob": true}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "file_glob": {}}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "file_glob": []}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "file_glob": null}));
    assert_search_eq(&fixture, json!({"pattern": "alpha", "file_glob": "*.rs"}));
}

#[test]
fn search_glob_question_mark_matches_one_utf8_byte_like_native() {
    let fixture = Fixture::new("glob-byte-q");
    fs::write(fixture.root.join("a.rs"), "keep\n").unwrap();
    fs::write(fixture.root.join("你.rs"), "cjk\n").unwrap();
    assert_search_eq(&fixture, json!({"pattern": "?.rs", "target": "files"}));
    assert_search_eq(&fixture, json!({"pattern": "???.rs", "target": "files"}));
    assert_search_eq(&fixture, json!({"pattern": "keep", "file_glob": "?.rs"}));
    assert_search_eq(&fixture, json!({"pattern": "cjk", "file_glob": "???.rs"}));
}

#[cfg(unix)]
#[test]
fn search_skips_non_utf8_names_like_native() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("non-utf8-names");
    fs::write(fixture.root.join("keep.txt"), "keep alpha\n").unwrap();
    let bad = fixture
        .root
        .join(OsString::from_vec(vec![0xff, b'x', 0x80]));
    fs::write(&bad, "secret alpha\n").unwrap();
    assert_search_eq(&fixture, json!({"pattern": "alpha"}));
    assert_search_eq(&fixture, json!({"pattern": "*", "target": "files"}));
}

#[cfg(unix)]
#[test]
fn search_non_utf8_name_consumes_exam_slot_and_does_not_leak_secret() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("search-non-utf8-cap");
    fs::write(
        fixture
            .root
            .join(OsString::from_vec(vec![0xff, b'x', 0x80])),
        "secret needle\n",
    )
    .unwrap();
    fs::write(fixture.root.join("secret.txt"), "secret needle\n").unwrap();
    fs::write(fixture.root.join("other.txt"), "other\n").unwrap();
    let mut config = fixture.config();
    config.max_search_files = 4;
    config.artifact_store.root = fixture.parent.join("artifacts-non-utf8-cap");
    let arguments = json!({"pattern": "secret"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    assert!(
        !rss.result["content"]
            .as_str()
            .is_some_and(|content| content.contains("secret.txt")),
        "secret.txt must not leak after a non-UTF8 exam slot: rss={}",
        rss.result
    );
}

#[cfg(unix)]
#[test]
fn search_remaining_2_invalid_byte_filename_truncates_like_native() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("search-rem2-invalid");
    fs::write(
        fixture
            .root
            .join(OsString::from_vec(vec![0xff, b'x', 0x80])),
        "secret needle\n",
    )
    .unwrap();
    let mut config = fixture.config();
    config.max_search_files = 2;
    config.artifact_store.root = fixture.parent.join("artifacts-rem2-invalid");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["content"], json!(""));
    assert_eq!(rss.result["data"]["match_count"], json!(0));
    assert_eq!(rss.result["data"]["files_visited"], json!(0));
    assert_eq!(rss.result["data"]["dirs_visited"], json!(1));
}

#[cfg(unix)]
#[test]
fn search_nested_remaining_2_hidden_dirent_stops_later_siblings_like_native() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("search-nested-rem2-hidden");
    fs::create_dir_all(fixture.root.join("adir")).unwrap();
    fs::create_dir_all(fixture.root.join("bdir")).unwrap();
    fs::create_dir_all(fixture.root.join("zdir")).unwrap();
    fs::write(fixture.root.join("adir/f0.txt"), "needle\n").unwrap();
    fs::write(fixture.root.join("adir/f1.txt"), "needle\n").unwrap();
    fs::write(fixture.root.join("adir/f2.txt"), "needle\n").unwrap();
    fs::write(
        fixture
            .root
            .join("bdir")
            .join(OsString::from_vec(vec![0xff, 0x80])),
        "secret needle\n",
    )
    .unwrap();
    fs::write(fixture.root.join("zdir/late.txt"), "needle late\n").unwrap();
    let mut config = fixture.config();
    config.max_search_files = 5;
    config.artifact_store.root = fixture.parent.join("artifacts-nested-rem2-hidden");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["data"]["files_visited"], json!(3));
    assert_eq!(rss.result["data"]["dirs_visited"], json!(3));
    assert!(
        !rss.result["content"]
            .as_str()
            .is_some_and(|content| content.contains("late.txt")),
        "later sibling must not leak: rss={}",
        rss.result
    );
}

#[cfg(unix)]
#[test]
fn search_hardlink_only_directory_is_fatal_like_native() {
    let fixture = Fixture::new("search-hardlink-only");
    let outside = fixture.parent.join("outside-shared");
    fs::write(&outside, "needle shared\n").unwrap();
    fs::hard_link(&outside, fixture.root.join("linked")).unwrap();
    let mut config = fixture.config();
    config.artifact_store.root = fixture.parent.join("artifacts-hardlink-only");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["error"]["code"], json!("path_denied"));
    assert_eq!(
        rss.result["error"]["message"],
        json!("regular files with multiple hard links are not permitted")
    );
    assert_eq!(rss.result["content"], json!(""));
}

#[cfg(unix)]
#[test]
fn search_hardlink_in_child_discards_parent_matches_like_native() {
    let fixture = Fixture::new("search-hardlink-child");
    fs::write(fixture.root.join("a.txt"), "needle parent\n").unwrap();
    fs::create_dir(fixture.root.join("sub")).unwrap();
    let outside = fixture.parent.join("outside-shared");
    fs::write(&outside, "needle child\n").unwrap();
    fs::hard_link(&outside, fixture.root.join("sub/linked")).unwrap();
    let mut config = fixture.config();
    config.artifact_store.root = fixture.parent.join("artifacts-hardlink-child");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    assert!(
        !rss.result["content"]
            .as_str()
            .is_some_and(|content| content.contains("a.txt")),
        "parent matches must be discarded: rss={}",
        rss.result
    );
}

#[cfg(unix)]
#[test]
fn search_remaining_2_hardlink_only_truncates_like_native() {
    let fixture = Fixture::new("search-rem2-hardlink");
    let outside = fixture.parent.join("outside-shared-rem2");
    fs::write(&outside, "needle shared\n").unwrap();
    fs::hard_link(&outside, fixture.root.join("linked")).unwrap();
    let mut config = fixture.config();
    config.max_search_files = 2;
    config.artifact_store.root = fixture.parent.join("artifacts-rem2-hardlink");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["ok"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["content"], json!(""));
    assert_eq!(rss.result["data"]["match_count"], json!(0));
    assert_eq!(rss.result["data"]["files_visited"], json!(0));
    assert_eq!(rss.result["data"]["dirs_visited"], json!(1));
}

#[cfg(unix)]
#[test]
fn search_nested_remaining_2_hardlink_sibling_stops_later_siblings_like_native() {
    let fixture = Fixture::new("search-nested-rem2-hardlink");
    fs::create_dir_all(fixture.root.join("adir")).unwrap();
    fs::create_dir_all(fixture.root.join("bdir")).unwrap();
    fs::create_dir_all(fixture.root.join("zdir")).unwrap();
    fs::write(fixture.root.join("adir/f0.txt"), "needle\n").unwrap();
    fs::write(fixture.root.join("adir/f1.txt"), "needle\n").unwrap();
    fs::write(fixture.root.join("adir/f2.txt"), "needle\n").unwrap();
    let outside = fixture.parent.join("outside-shared-nested");
    fs::write(&outside, "secret needle\n").unwrap();
    fs::hard_link(&outside, fixture.root.join("bdir/linked")).unwrap();
    fs::write(fixture.root.join("zdir/late.txt"), "needle late\n").unwrap();
    let mut config = fixture.config();
    config.max_search_files = 5;
    config.artifact_store.root = fixture.parent.join("artifacts-nested-rem2-hardlink");
    let arguments = json!({"pattern": "needle"});
    let rss = run_rss_search(&fixture, &config, arguments);
    assert_canonical_envelope(&rss.result);
    assert_eq!(rss.result["ok"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["data"]["files_visited"], json!(3));
    assert_eq!(rss.result["data"]["dirs_visited"], json!(3));
    assert!(
        rss.result["content"]
            .as_str()
            .is_some_and(|content| content.contains("adir/f0.txt")
                && content.contains("adir/f1.txt")
                && content.contains("adir/f2.txt")),
        "prior matches must remain: rss={}",
        rss.result
    );
    assert!(
        !rss.result["content"]
            .as_str()
            .is_some_and(|content| content.contains("late.txt") || content.contains("linked")),
        "later sibling and hardlink must not leak: rss={}",
        rss.result
    );
}

#[test]
fn search_directory_order_is_byte_lexicographic_including_multibyte() {
    let fixture = Fixture::new("sort-multi");
    for name in ["z.txt", "a.txt", "m.txt", "中.txt", "あ.txt", "A.txt"] {
        fs::write(fixture.root.join(name), "needle\n").unwrap();
    }
    assert_search_eq(&fixture, json!({"pattern": "needle"}));
    assert_search_eq(&fixture, json!({"pattern": "*", "target": "files"}));
}

#[test]
fn search_high_entry_directory_order_matches_native() {
    let fixture = Fixture::new("sort-high");
    for i in (0..80).rev() {
        fs::write(fixture.root.join(format!("f-{i:03}.txt")), "needle\n").unwrap();
    }
    assert_search_eq(&fixture, json!({"pattern": "needle"}));
    assert_search_eq(&fixture, json!({"pattern": "*", "target": "files"}));
}

#[test]
fn search_fake_clock_backward_jump_does_not_extend_budget() {
    let fixture = Fixture::new("search-clock-back");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
    fs::write(fixture.root.join("b.txt"), "alpha\n").unwrap();
    fs::write(fixture.root.join("c.txt"), "alpha\n").unwrap();
    let mut config = fixture.config();
    config.max_search_wall_time = Duration::from_millis(2);
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            module: "search_files_entry.rss",
            tool_name: "search_files",
            arguments: json!({"pattern": "alpha"}),
            durable: MemoryDurable::new(),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: JumpClock::new(1_000, 1, 0),
            deadline_ms: 1_000_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-clock-back".to_string(),
        },
    );
    assert_eq!(rss.result["ok"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["truncated"], json!(true), "rss={}", rss.result);
    assert_eq!(rss.result["error"], Value::Null);
}

struct OverflowAfterClock {
    ok_ticks: AtomicU64,
    overflow_after: u64,
    instant: Instant,
}

impl OverflowAfterClock {
    fn after_ok_ticks(ok_ticks: u64) -> Arc<Self> {
        Arc::new(Self {
            ok_ticks: AtomicU64::new(0),
            overflow_after: ok_ticks,
            instant: Instant::now(),
        })
    }
}

impl LifecycleClock for OverflowAfterClock {
    fn now_ms(&self) -> u64 {
        1_000
    }

    fn now(&self) -> Instant {
        self.instant
    }

    fn monotonic_ms(&self) -> Option<u64> {
        let seen = self.ok_ticks.fetch_add(1, Ordering::SeqCst);
        if seen >= self.overflow_after {
            None
        } else {
            Some(1_000)
        }
    }
}

#[test]
fn search_fake_clock_overflow_uses_nested_capability_error_envelope() {
    let fixture = Fixture::new("search-clock-overflow");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
    let mut config = fixture.config();
    config.max_search_wall_time = Duration::from_millis(2_000);
    let rss = run_rss_exec(
        &fixture,
        &config,
        RssExec {
            module: "search_files_entry.rss",
            tool_name: "search_files",
            arguments: json!({"pattern": "alpha"}),
            durable: MemoryDurable::new(),
            approval: Arc::new(AllowAll),
            cancellation: Arc::new(NeverCancelled),
            clock: OverflowAfterClock::after_ok_ticks(1),
            deadline_ms: 1_000_000,
            install_artifacts: false,
            artifact_limits: default_artifact_limits(),
            call_id: "call-clock-overflow".to_string(),
        },
    );
    assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
    assert_eq!(
        rss.result["error"]["code"],
        json!("internal_error"),
        "overflow must preserve the nested capability code, rss={}",
        rss.result
    );
    assert_eq!(
        rss.result["error"]["message"],
        json!("monotonic clock overflow"),
        "overflow must preserve the nested capability message, rss={}",
        rss.result
    );
    assert_ne!(
        rss.result["error"]["code"],
        json!("cancelled"),
        "top-level code must not collapse overflow to cancelled"
    );
    assert_eq!(rss.result["truncated"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["content"], json!(""));
    assert_eq!(rss.result["data"], json!({}));
    assert_eq!(rss.result["artifacts"], json!([]));
}

#[test]
fn published_result_artifact_is_retracted_when_commit_fails() {
    let fixture = Fixture::new("artifact-rollback");
    fs::write(fixture.root.join("wide.txt"), "你好世界".repeat(80)).unwrap();
    let mut config = fixture.config();
    config.max_output_bytes = 200;
    config.max_search_output_bytes = 200;
    config.max_read_bytes = 8192;
    config.artifact_store.max_object_bytes = 8192;
    config.artifact_store.max_total_bytes = 16384;
    let durable = MemoryDurable::new();
    durable.fail_next_commit();
    let rss = run_rss_tool(
        "read_file_entry.rss",
        &fixture,
        &config,
        "read_file",
        json!({"path": "wide.txt"}),
        Arc::clone(&durable),
        Arc::new(AllowAll),
        Arc::new(NeverCancelled),
        true,
    );
    assert_eq!(rss.result["ok"], json!(false), "rss={}", rss.result);
    assert_eq!(rss.result["error"]["code"], json!("result_commit_failed"));
    assert_eq!(
        rss.artifacts.as_ref().expect("rss store").stored_len(),
        0,
        "commit failure must not leave a visible result artifact"
    );
}
