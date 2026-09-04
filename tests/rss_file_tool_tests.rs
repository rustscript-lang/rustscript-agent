//! Native-equivalence tests for RSS `read_file` and `search_files`.
//!
//! These tests compile the real RSS modules and run them through the RSS VM
//! with generic capability host functions. Native `FileTools` is the oracle.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustscript_agent::capabilities::{
    ApprovalGate, ArtifactCapability, ArtifactLimits, CancellationFlag, CapabilityLifecycle,
    CapabilityOwner, CapabilityRisk, DurableStarted, DurableToolLifecycle, FilesystemCapability,
    FilesystemLimits, LifecycleClock, LifecycleError, LifecycleLimits, NeverCancelled,
    PrepareMetadata, SystemClock, TokenIssuer, UuidIssuer,
};
use rustscript_agent::config::FileToolConfig;
use rustscript_agent::tools::{FileTools, ReadFileRequest, SearchFilesRequest, ToolResult};
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

const REGISTRY_IDENTITY: &str = "rss-file-tool-equivalence";
const TMP_ROOT: &str =
    "/mnt/TEMP/workspace/rustscript-agent/tmp/prod-agent-task-0c-rss-readonly-30473d83";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    parent: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let parent = PathBuf::from(TMP_ROOT).join(format!(
            "rss-file-{}-{}-{}",
            label,
            std::process::id(),
            sequence
        ));
        let root = parent.join("workspace");
        fs::create_dir_all(&root).expect("create rss file fixture");
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
}

impl MemoryDurable {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Mutex::new(Vec::new()),
            results: Mutex::new(std::collections::HashMap::new()),
            parent_ok: Mutex::new(true),
            active: Mutex::new(true),
        })
    }

    fn started_len(&self) -> usize {
        self.started.lock().expect("started").len()
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
        "max_search_wall_time_ms": config.max_search_wall_time.as_millis() as u64,
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

struct RssRun {
    result: Value,
    started: usize,
}

#[allow(clippy::too_many_arguments)]
fn run_rss_tool(
    module: &str,
    fixture: &Fixture,
    config: &FileToolConfig,
    tool_name: &str,
    arguments: Value,
    durable: Arc<MemoryDurable>,
    approval: Arc<dyn ApprovalGate>,
    cancellation: Arc<dyn CancellationFlag>,
    install_artifacts: bool,
) -> RssRun {
    let clock = Arc::new(SystemClock);
    let deadline_ms = clock.now_ms() + 60_000;
    let lifecycle = Arc::new(build_lifecycle(
        &fixture.root,
        Arc::clone(&durable),
        approval,
        cancellation,
        clock,
        deadline_ms,
    ));
    let fs_cap = FilesystemCapability::new(
        lifecycle.as_ref().clone(),
        owner(),
        filesystem_limits(config),
    )
    .expect("filesystem capability");
    let artifacts = if install_artifacts {
        Some(Arc::new(
            ArtifactCapability::new(
                lifecycle.as_ref().clone(),
                owner(),
                ArtifactLimits {
                    max_object_bytes: 8 * 1024 * 1024,
                    max_total_bytes: 64 * 1024 * 1024,
                    max_objects: 64,
                },
            )
            .expect("artifacts"),
        ))
    } else {
        None
    };
    let host = AgentHostBridges {
        lifecycle: Some(Arc::clone(&lifecycle)),
        capability_owner: Some(owner()),
        filesystem: Some(Arc::new(fs_cap)),
        artifacts,
        ..AgentHostBridges::default()
    };
    let context = json!({
        "kind": "execute",
        "arguments": arguments,
        "prepare": {
            "run_id": "run-test",
            "call_id": format!("call-{}", NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)),
            "name": tool_name,
            "argument_digest": "digest",
            "registry_identity": REGISTRY_IDENTITY,
            "risk_class": "read",
            "summary": tool_name,
        },
        "config": rss_config_json(config),
    });
    let runner = compile_rss(module);
    let output = runner
        .with_host(host)
        .run_with_context(json_to_vm_value(&context))
        .unwrap_or_else(|error| panic!("rss {module} run failed: {error}"));
    RssRun {
        result: canonicalize_rss_result(vm_value_to_json(&output)),
        started: durable.started_len(),
    }
}

fn canonicalize_rss_result(value: Value) -> Value {
    let mut result = if value.get("kind").and_then(Value::as_str) == Some("committed") {
        value.get("result").cloned().unwrap_or(value)
    } else {
        value
    };
    if let Some(object) = result.as_object_mut() {
        object.entry("error".to_string()).or_insert(Value::Null);
        object.entry("artifacts".to_string()).or_insert(json!([]));
        object
            .entry("truncated".to_string())
            .or_insert(json!(false));
        object.entry("content".to_string()).or_insert(json!(""));
        object.entry("data".to_string()).or_insert(json!({}));
    }
    result
}

fn run_rss_read(fixture: &Fixture, config: &FileToolConfig, arguments: Value) -> RssRun {
    run_rss_tool(
        "read_file.rss",
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
        "search_files.rss",
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

fn native_read(tools: &FileTools, arguments: &Value) -> ToolResult {
    let request = ReadFileRequest {
        path: arguments["path"].as_str().unwrap_or("").to_string(),
        offset: arguments
            .get("offset")
            .and_then(Value::as_u64)
            .map(|v| v as usize),
        limit: arguments
            .get("limit")
            .and_then(Value::as_u64)
            .map(|v| v as usize),
    };
    tools.read_file(request)
}

fn native_search(tools: &FileTools, arguments: &Value) -> ToolResult {
    let request = SearchFilesRequest {
        path: arguments
            .get("path")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        pattern: arguments["pattern"].as_str().unwrap_or("").to_string(),
        target: arguments
            .get("target")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        file_glob: arguments
            .get("file_glob")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        limit: arguments
            .get("limit")
            .and_then(Value::as_u64)
            .map(|v| v as usize),
        offset: arguments
            .get("offset")
            .and_then(Value::as_u64)
            .map(|v| v as usize),
    };
    tools.search_files(request)
}

fn assert_success_eq(native: &ToolResult, rss: &Value) {
    let native_json = serde_json::to_value(native).expect("serialize native");
    assert_eq!(native_json, *rss, "canonical success envelopes must match");
}

fn assert_error_eq(native: &ToolResult, rss: &Value) {
    assert_eq!(native.ok, rss["ok"].as_bool().unwrap_or(true));
    assert_eq!(
        native.error.as_ref().map(|error| error.code.as_str()),
        rss["error"]["code"].as_str(),
        "error codes must match: native={native:?} rss={rss}"
    );
    let rss_message = rss["error"]["message"].as_str().unwrap_or("");
    assert!(
        !rss_message.contains(TMP_ROOT),
        "rss error leaked temp root: {rss_message}"
    );
    if let Some(native_error) = native.error.as_ref() {
        assert!(
            !native_error.message.contains(TMP_ROOT),
            "native error leaked temp root"
        );
        assert_eq!(
            native_error.message, rss_message,
            "error messages must match: native={native:?} rss={rss}"
        );
    }
}

fn assert_read_eq(fixture: &Fixture, arguments: Value) {
    let config = fixture.config();
    let native = native_read(&fixture.tools(), &arguments);
    let rss = run_rss_read(fixture, &config, arguments);
    if native.ok {
        assert_success_eq(&native, &rss.result);
        assert!(rss.started > 0, "successful read must prepare");
    } else {
        assert_error_eq(&native, &rss.result);
    }
}

fn assert_search_eq(fixture: &Fixture, arguments: Value) {
    let config = fixture.config();
    let native = native_search(&fixture.tools(), &arguments);
    let rss = run_rss_search(fixture, &config, arguments.clone());
    if native.ok != rss.result["ok"].as_bool().unwrap_or(false) {
        panic!(
            "ok mismatch for {arguments}: native={native:?} rss={}",
            rss.result
        );
    }
    if native.ok {
        assert_success_eq(&native, &rss.result);
        assert!(rss.started > 0, "successful search must prepare");
    } else {
        assert_error_eq(&native, &rss.result);
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

#[test]
fn rss_read_file_descriptor_matches_native() {
    let runner = compile_rss("read_file.rss");
    let output = runner
        .run_with_context(json_to_vm_value(&json!({"kind": "descriptor"})))
        .expect("descriptor run");
    let rss = vm_value_to_json(&output);
    assert_eq!(rss, native_descriptor("read_file"));
}

#[test]
fn rss_search_files_descriptor_matches_native() {
    let runner = compile_rss("search_files.rss");
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
    let native = native_read(
        &fixture.tools_with_config(config.clone()),
        &json!({"path": "big.txt"}),
    );
    let rss = run_rss_read(&fixture, &config, json!({"path": "big.txt"}));
    assert_error_eq(&native, &rss.result);

    let mut output_config = fixture.config();
    output_config.max_output_bytes = 32;
    output_config.max_search_output_bytes = 32;
    output_config.artifact_store.root = fixture.parent.join("artifacts-out");
    fs::write(
        fixture.root.join("wide.txt"),
        format!("{}\n", "w".repeat(80)),
    )
    .unwrap();
    let native = native_read(
        &fixture.tools_with_config(output_config.clone()),
        &json!({"path": "wide.txt"}),
    );
    let rss = run_rss_read(&fixture, &output_config, json!({"path": "wide.txt"}));
    assert_error_eq(&native, &rss.result);
    assert_eq!(
        native.error.as_ref().map(|error| error.code.as_str()),
        Some("output_truncated")
    );
}

#[test]
fn malformed_read_args_do_not_prepare_or_touch_fs() {
    let fixture = Fixture::new("read-malformed");
    fs::write(fixture.root.join("notes.txt"), "alpha\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "read_file.rss",
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
        "read_file.rss",
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
        "read_file.rss",
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
        "read_file.rss",
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
    assert_search_eq(&fixture, json!({"pattern": "alpha", "path": "leaf-link"}));

    let mut config = fixture.config();
    config.max_search_matches = 1;
    config.artifact_store.root = fixture.parent.join("artifacts-search");
    let arguments = json!({"pattern": "alpha"});
    let native = native_search(&fixture.tools_with_config(config.clone()), &arguments);
    let rss = run_rss_search(&fixture, &config, arguments);
    if native.ok {
        assert_success_eq(&native, &rss.result);
    } else {
        assert_error_eq(&native, &rss.result);
    }
}

#[test]
fn malformed_search_args_do_not_prepare() {
    let fixture = Fixture::new("search-malformed");
    fs::write(fixture.root.join("a.txt"), "alpha\n").unwrap();
    let durable = MemoryDurable::new();
    let rss = run_rss_tool(
        "search_files.rss",
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
    let output = compile_rss("search_files.rss")
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
        "read_file.rss",
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
    let native = native_search(&fixture.tools_with_config(files.clone()), &arguments);
    let rss = run_rss_search(&fixture, &files, arguments.clone());
    if native.ok {
        assert_success_eq(&native, &rss.result);
    } else {
        assert_error_eq(&native, &rss.result);
    }

    let mut depth = fixture.config();
    depth.max_search_depth = 1;
    depth.artifact_store.root = fixture.parent.join("artifacts-depth");
    let native = native_search(&fixture.tools_with_config(depth.clone()), &arguments);
    let rss = run_rss_search(&fixture, &depth, arguments.clone());
    if native.ok {
        assert_success_eq(&native, &rss.result);
    } else {
        assert_error_eq(&native, &rss.result);
    }

    let mut scan = fixture.config();
    scan.max_search_scanned_bytes = 8;
    scan.artifact_store.root = fixture.parent.join("artifacts-scan");
    let native = native_search(&fixture.tools_with_config(scan.clone()), &arguments);
    let rss = run_rss_search(&fixture, &scan, arguments);
    if native.ok {
        assert_success_eq(&native, &rss.result);
    } else {
        assert_error_eq(&native, &rss.result);
    }
}
