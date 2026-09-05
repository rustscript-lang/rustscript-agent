//! Task 0F RSS static dispatch tests.
//!
//! Compiles `rss/tools/dispatch.rss` and exercises bounded exact-name routing,
//! unknown/disabled/mismatch envelopes, malformed args, and lifecycle counts.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use rustscript_agent::capabilities::{
    ApprovalGate, CancellationFlag, CapabilityLifecycle, CapabilityOwner, CapabilityRisk,
    DurableStarted, DurableToolLifecycle, FilesystemCapability, FilesystemLimits, LifecycleClock,
    LifecycleError, LifecycleLimits, NeverCancelled, PrepareMetadata, SystemClock, TokenIssuer,
    UuidIssuer,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner};
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};

const REGISTRY_IDENTITY: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

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

fn unique_temp_parent(label: &str) -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "rss-dispatch-{}-{}-{}",
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
        fs::create_dir_all(&root).expect("create dispatch fixture");
        Self { root, parent }
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
    fail_next_commit: std::sync::atomic::AtomicBool,
}

impl MemoryDurable {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Mutex::new(Vec::new()),
            results: Mutex::new(std::collections::HashMap::new()),
            parent_ok: Mutex::new(true),
            active: Mutex::new(true),
            fail_next_commit: std::sync::atomic::AtomicBool::new(false),
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

fn owner() -> CapabilityOwner {
    CapabilityOwner::new("profile-test", "session-test", "run-test").expect("owner")
}

fn build_lifecycle(workspace: &Path, durable: Arc<MemoryDurable>) -> CapabilityLifecycle {
    CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity(REGISTRY_IDENTITY)
        .workspace(workspace)
        .limits(LifecycleLimits {
            max_tool_calls: 32,
            max_output_bytes: 1024 * 1024,
            max_summary_bytes: 256,
        })
        .deadline_ms(u64::MAX)
        .clock(Arc::new(SystemClock) as Arc<dyn LifecycleClock>)
        .tokens(Arc::new(UuidIssuer) as Arc<dyn TokenIssuer>)
        .durable(durable)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .cancellation(Arc::new(NeverCancelled) as Arc<dyn CancellationFlag>)
        .build()
        .expect("lifecycle")
}

fn compile_dispatch() -> AgentRunner {
    static RUNNER: OnceLock<AgentRunner> = OnceLock::new();
    RUNNER
        .get_or_init(|| {
            let path = crate_root().join("rss/tools/dispatch_entry.rss");
            AgentRunner::from_file(&path, AgentConfig::default()).unwrap_or_else(|error| {
                panic!("compile rss/tools/dispatch_entry.rss: {error}");
            })
        })
        .clone()
}

fn registry_snapshot() -> Value {
    static SNAPSHOT: OnceLock<Value> = OnceLock::new();
    SNAPSHOT
        .get_or_init(|| {
            let path = crate_root().join("rss/tools/registry.rss");
            let runner = AgentRunner::from_file(&path, AgentConfig::default())
                .expect("RSS tool registry entry should compile");
            let result = runner
                .run_with_context(json_to_vm_value(&json!({
                    "kind": "descriptors",
                    "config": {},
                })))
                .expect("registry descriptors");
            let json = vm_value_to_json(&result);
            json.get("descriptors")
                .cloned()
                .unwrap_or_else(|| json.get("tools").cloned().unwrap_or(json))
        })
        .clone()
}

fn filter_registry(snapshot: &Value, names: &[&str]) -> Value {
    let filtered = snapshot
        .as_array()
        .expect("registry snapshot is an array")
        .iter()
        .filter(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| names.contains(&name))
        })
        .cloned()
        .collect::<Vec<_>>();
    Value::Array(filtered)
}

fn run_dispatch(fixture: &Fixture, durable: Arc<MemoryDurable>, input: Value) -> (Value, usize) {
    let lifecycle = Arc::new(build_lifecycle(&fixture.root, Arc::clone(&durable)));
    let fs_cap = FilesystemCapability::new(
        lifecycle.as_ref().clone(),
        owner(),
        FilesystemLimits {
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 1024 * 1024,
            max_list_entries: 10_000,
        },
    )
    .expect("filesystem capability");
    let host = AgentHostBridges {
        lifecycle: Some(Arc::clone(&lifecycle)),
        capability_owner: Some(owner()),
        filesystem: Some(Arc::new(fs_cap)),
        ..AgentHostBridges::default()
    };
    let output = compile_dispatch()
        .with_host(host)
        .run_with_context(json_to_vm_value(&input))
        .unwrap_or_else(|error| panic!("dispatch run failed: {error}"));
    (vm_value_to_json(&output), durable.started_len())
}

fn dispatch_input(call: Value, registry: Value, identity: &str, config: Value) -> Value {
    json!({
        "call": call,
        "registry": registry,
        "registry_identity": identity,
        "run_id": "run-test",
        "config": config,
    })
}

fn error_code(envelope: &Value) -> &str {
    envelope
        .pointer("/error/code")
        .and_then(Value::as_str)
        .or_else(|| {
            envelope
                .pointer("/content_block/error/code")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            envelope
                .pointer("/content_block/result/error/code")
                .and_then(Value::as_str)
        })
        .unwrap_or("")
}

#[test]
fn dispatch_module_compiles() {
    let _ = compile_dispatch();
}

#[test]
fn dispatch_routes_read_file_without_double_prepare() {
    let fixture = Fixture::new("read-file");
    fs::write(fixture.root.join("hello.txt"), "hello from dispatch\n").expect("write fixture");
    let durable = MemoryDurable::new();
    let registry = registry_snapshot();
    let input = dispatch_input(
        json!({
            "id": "call-read",
            "name": "read_file",
            "arguments": { "path": "hello.txt" },
        }),
        registry,
        REGISTRY_IDENTITY,
        json!({
            "max_read_bytes": 1048576,
            "max_read_lines": 10000,
            "max_tool_output_bytes": 65536,
            "workspace_root": fixture.root.to_string_lossy(),
        }),
    );
    let (envelope, started) = run_dispatch(&fixture, durable, input);
    assert_eq!(envelope["ok"], json!(true), "envelope={envelope}");
    assert_eq!(envelope["terminal"], json!(false));
    assert_eq!(envelope["content_block"]["type"], json!("tool_result"));
    assert_eq!(envelope["content_block"]["name"], json!("read_file"));
    assert_eq!(
        envelope["content_block"]["tool_call_id"],
        json!("call-read")
    );
    assert_eq!(envelope["content_block"]["is_error"], json!(false));
    let content = envelope["content_block"]["content"]
        .as_str()
        .unwrap_or_default();
    assert!(
        content.contains("hello from dispatch"),
        "content={content:?} envelope={envelope}"
    );
    assert_eq!(started, 1, "lifecycle must prepare exactly once");
}

#[test]
fn dispatch_routes_all_six_public_names() {
    let fixture = Fixture::new("six-names");
    fs::write(fixture.root.join("a.txt"), "alpha\n").expect("write");
    let registry = registry_snapshot();
    let names = [
        "read_file",
        "search_files",
        "write_file",
        "patch",
        "terminal",
        "process",
    ];
    for name in names {
        let durable = MemoryDurable::new();
        let arguments = match name {
            "read_file" => json!({"path": "a.txt"}),
            "search_files" => json!({"pattern": "alpha", "path": "."}),
            "write_file" => json!({"path": "written.txt", "content": "ok\n"}),
            "patch" => json!({
                "path": "a.txt",
                "old_string": "alpha",
                "new_string": "beta"
            }),
            "terminal" => json!({}),
            "process" => json!({}),
            _ => unreachable!(),
        };
        let input = dispatch_input(
            json!({
                "id": format!("call-{name}"),
                "name": name,
                "arguments": arguments,
            }),
            registry.clone(),
            REGISTRY_IDENTITY,
            json!({
                "max_read_bytes": 1048576,
                "max_read_lines": 10000,
                "max_write_bytes": 1048576,
                "max_search_files": 10000,
                "max_search_scanned_bytes": 16777216,
                "max_search_depth": 32,
                "max_search_matches": 10000,
                "max_search_output_bytes": 65536,
                "max_search_wall_time_ms": 2000,
                "max_patch_bytes": 8388608,
                "max_tool_output_bytes": 65536,
                "workspace_root": fixture.root.to_string_lossy(),
            }),
        );
        let (envelope, _) = run_dispatch(&fixture, durable, input);
        assert_eq!(
            envelope["content_block"]["name"],
            json!(name),
            "name={name} envelope={envelope}"
        );
        assert_eq!(
            envelope["content_block"]["type"],
            json!("tool_result"),
            "name={name}"
        );
        assert!(
            envelope.get("ok").is_some(),
            "missing ok for {name}: {envelope}"
        );
    }
}

#[test]
fn dispatch_unknown_tool_preserves_typed_envelope() {
    let fixture = Fixture::new("unknown");
    let durable = MemoryDurable::new();
    let input = dispatch_input(
        json!({
            "id": "call-unknown",
            "name": "not_a_real_tool",
            "arguments": {},
        }),
        registry_snapshot(),
        REGISTRY_IDENTITY,
        json!({}),
    );
    let (envelope, started) = run_dispatch(&fixture, durable, input);
    assert_eq!(envelope["ok"], json!(false), "envelope={envelope}");
    assert_eq!(envelope["terminal"], json!(false));
    assert_eq!(error_code(&envelope), "unknown_tool");
    assert_eq!(envelope["content_block"]["is_error"], json!(true));
    assert_eq!(envelope["content_block"]["name"], json!("not_a_real_tool"));
    assert_eq!(started, 0, "unknown tools must not start lifecycle");
}

#[test]
fn dispatch_disabled_tool_is_unknown() {
    let fixture = Fixture::new("disabled");
    let durable = MemoryDurable::new();
    let registry = filter_registry(&registry_snapshot(), &["read_file"]);
    let input = dispatch_input(
        json!({
            "id": "call-disabled",
            "name": "write_file",
            "arguments": { "path": "x.txt", "content": "nope" },
        }),
        registry,
        REGISTRY_IDENTITY,
        json!({}),
    );
    let (envelope, started) = run_dispatch(&fixture, durable, input);
    assert_eq!(error_code(&envelope), "unknown_tool", "envelope={envelope}");
    assert_eq!(started, 0);
}

#[test]
fn dispatch_registry_mismatch_preserves_typed_envelope() {
    let fixture = Fixture::new("mismatch");
    let durable = MemoryDurable::new();
    let input = json!({
        "call": {
            "id": "call-mismatch",
            "name": "read_file",
            "arguments": { "path": "a.txt" },
        },
        "registry": registry_snapshot(),
        "registry_identity": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "admitted_registry_identity": REGISTRY_IDENTITY,
        "run_id": "run-test",
        "config": {},
    });
    let (envelope, started) = run_dispatch(&fixture, durable, input);
    assert_eq!(
        error_code(&envelope),
        "registry_mismatch",
        "envelope={envelope}"
    );
    assert_eq!(envelope["ok"], json!(false));
    assert_eq!(started, 0);
}

#[test]
fn dispatch_duplicate_registry_names_fail_closed() {
    let fixture = Fixture::new("duplicate");
    let durable = MemoryDurable::new();
    let read = filter_registry(&registry_snapshot(), &["read_file"]);
    let mut entries = read.as_array().cloned().unwrap_or_default();
    if let Some(first) = entries.first().cloned() {
        entries.push(first);
    }
    let input = dispatch_input(
        json!({
            "id": "call-dup",
            "name": "read_file",
            "arguments": { "path": "a.txt" },
        }),
        Value::Array(entries),
        REGISTRY_IDENTITY,
        json!({}),
    );
    let (envelope, started) = run_dispatch(&fixture, durable, input);
    assert_eq!(envelope["ok"], json!(false), "envelope={envelope}");
    let code = error_code(&envelope);
    assert!(
        code == "registry_mismatch" || code == "duplicate_tool",
        "unexpected code {code}: {envelope}"
    );
    assert_eq!(started, 0);
}

#[test]
fn dispatch_malformed_args_are_bounded() {
    let fixture = Fixture::new("malformed");
    let durable = MemoryDurable::new();
    let input = dispatch_input(
        json!({
            "id": "call-empty",
            "name": "",
            "arguments": {},
        }),
        registry_snapshot(),
        REGISTRY_IDENTITY,
        json!({}),
    );
    let (envelope, started) = run_dispatch(&fixture, durable, input);
    assert_eq!(envelope["ok"], json!(false), "envelope={envelope}");
    assert!(
        envelope["terminal"] == json!(true)
            || error_code(&envelope) == "unknown_tool"
            || error_code(&envelope) == "malformed_payload",
        "envelope={envelope}"
    );
    assert_eq!(started, 0);
}

#[test]
fn dispatch_does_not_eval_user_names() {
    let fixture = Fixture::new("no-eval");
    let durable = MemoryDurable::new();
    let input = dispatch_input(
        json!({
            "id": "call-inject",
            "name": "../secret",
            "arguments": {},
        }),
        registry_snapshot(),
        REGISTRY_IDENTITY,
        json!({}),
    );
    let (envelope, started) = run_dispatch(&fixture, durable, input);
    assert_eq!(error_code(&envelope), "unknown_tool", "envelope={envelope}");
    assert_eq!(started, 0);
}

#[allow(dead_code)]
fn _instant_marker() -> Instant {
    Instant::now()
}
