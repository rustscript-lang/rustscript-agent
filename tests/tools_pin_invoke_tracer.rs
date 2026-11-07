//! Vertical tracer: admission pins a retained tool program, a typed child
//! bridge invokes it through the existing capability lease, and `read_file`
//! bytes come from that program. Activating another graph does not retarget
//! the already pinned run.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::capabilities::{
    ApprovalGate, CancellationFlag, CapabilityLifecycle, CapabilityOwner, CapabilityRisk,
    DurableStarted, DurableToolLifecycle, FilesystemCapability, FilesystemLimits,
    GuardianApprovalGate, LifecycleError, LifecycleLimits, PrepareMetadata, SystemClock,
    UuidIssuer,
};
use rustscript_agent::plugins::{
    InstallAuthorization, PackageArtifactRef, PackageRequirement, PackageStore, PluginControlStore,
    PublisherKey, ResolveRequest,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, GatewayPersistence};
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};

fn temp_root(label: &str) -> PathBuf {
    let base =
        PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = base.join(format!(
        "pin-tracer-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
    dir
}

struct Signer {
    pair: Ed25519KeyPair,
    key: PublisherKey,
}

fn signer() -> Signer {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key = PublisherKey {
        publisher: "org.rustscript".to_string(),
        verifying_key: pair.public_key().as_ref().to_vec(),
    };
    Signer { pair, key }
}

fn auth(signer: &Signer) -> InstallAuthorization {
    InstallAuthorization {
        admin: true,
        accepted_publishers: vec![signer.key.clone()],
        unsigned_dev_space: None,
    }
}

fn tool_source(offset: i64) -> String {
    format!(
        r#"
use bytes;
fn map_string(value: map, key: string, fallback: string) -> string {{
    let mut result: string = fallback;
    if value.has(key) {{
        if type(value[key]) == "string" {{
            let coerced: string = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_map(value: map, key: string) -> map {{
    let mut result: map = {{}};
    if value.has(key) {{
        if type(value[key]) == "map" {{
            let coerced: map = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_int(value: map, key: string, fallback: int) -> int {{
    let mut result: int = fallback;
    if value.has(key) {{
        if type(value[key]) == "int" {{
            let coerced: int = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_bool(value: map, key: string, fallback: bool) -> bool {{
    let mut result: bool = fallback;
    if value.has(key) {{
        if type(value[key]) == "bool" {{
            let coerced: bool = value[key];
            result = coerced;
        }}
    }}
    result
}}

pub fn run(context: map) -> map {{
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {{
            meta
        }} else => {{
            let file_len: int = map_int(meta, "len", 0);
            let offset: int = {offset};
            let limit: int = file_len - offset;
            let read: map = cap::fs_read_range(token, path, offset, limit);
            if map_bool(read, "ok", false) == false => {{
                read
            }} else => {{
                let payload: bytes = read.bytes;
                let text: string = bytes::to_utf8(payload);
                let result: map = {{ ok: true, content: text, data: {{}}, error: null, truncated: false, artifacts: [] }};
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {{
                    map_map(committed, "result")
                }} else => {{
                    committed
                }}
            }}
        }}
    }}
}}
"#
    )
}

fn manifest(id: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: run.rss
  export: run
dependencies: []
capabilities:
  - workspace.read
effects:
  contract: agent.effects/v1
  entries:
    run:
      direct:
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
      delegated: []
"#
    )
}

fn install_tool(store: &PackageStore, signer: &Signer, dir: &Path, id: &str, offset: i64) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), manifest(id)).unwrap();
    fs::write(dir.join("run.rss"), tool_source(offset)).unwrap();
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer)).unwrap();
}

struct MemoryDurable {
    run: &'static str,
}

impl DurableToolLifecycle for MemoryDurable {
    fn parent_arguments(
        &self,
        run_id: &str,
        call_id: &str,
        tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        assert_eq!(run_id, self.run);
        assert_eq!(tool_name, "read_file");
        assert!(matches!(
            call_id,
            "call-read-1" | "call-read-2" | "call-legal"
        ));
        Ok(Some(json!({"path": "note.txt"})))
    }
    fn assert_active_run(&self, _run_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn prepare_parent(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn replay_result(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        Ok(None)
    }
    fn commit_started(&self, _record: &DurableStarted) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn commit_result(&self, _call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
        Ok(result.clone())
    }
    fn interrupt(&self, _call_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct AllowRead;

impl ApprovalGate for AllowRead {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Ok(metadata.risk_class)
    }
}

struct NoCancel;

impl CancellationFlag for NoCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn vm_text(value: &VmValue, key: &str) -> String {
    let VmValue::Map(entries) = value else {
        panic!("tool result must be a map, got {value:?}");
    };
    entries
        .iter()
        .find(|(entry_key, _)| matches!(entry_key, VmValue::String(text) if text.as_str() == key))
        .and_then(|(_, entry)| match entry {
            VmValue::String(text) => Some(text.to_string()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing string field {key} in {value:?}"))
}

#[test]
fn pinned_read_file_bytes_stay_on_program_a_after_activation_of_b() {
    let root = temp_root("read");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.reada",
        0,
    );
    install_tool(
        &store,
        &signer,
        &root.join("pkg-b"),
        "org.rustscript.tools.readb",
        1,
    );
    let lock_a = store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.reada".to_string(),
            },
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.reada".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let lock_b = store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.readb".to_string(),
            },
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.readb".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let prepared_a = store.prepare(&lock_a).unwrap();
    let program_a = prepared_a
        .program("org.rustscript.tools.reada")
        .expect("prepare must retain program A");
    assert!(prepared_a.program("org.rustscript.tools.readb").is_none());
    let _prepared_b = store.prepare(&lock_b).unwrap();
    assert!(
        _prepared_b.program("org.rustscript.tools.readb").is_some(),
        "prepare must retain program B"
    );

    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    let refs_a: Vec<PackageArtifactRef> = lock_a
        .packages
        .iter()
        .map(|package| PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect();
    let refs_b: Vec<PackageArtifactRef> = lock_b
        .packages
        .iter()
        .map(|package| PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect();
    control.store_lock(&lock_a).unwrap();
    control.store_lock(&lock_b).unwrap();
    control.activate(&lock_a.graph_id, 0, &refs_a).unwrap();

    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let file_bytes = b"pin-tracer-bytes-from-A-not-B";
    fs::write(workspace.join("note.txt"), file_bytes).unwrap();

    let caller = json!({
        "session_id": "session-pin",
        "session_new": 1,
        "profile": "gateway",
        "platform": "api_server",
        "account_id": "session-pin",
        "model": "m",
        "provider": "p",
        "system_prompt": "",
        "session_metadata_json": "{}",
        "run_id": "run-pin-a",
        "parent_run_id": "",
        "input_json": "{\"text\":\"read note\"}",
        "message_id": "message-pin-a",
        "message_run_id": "run-pin-a",
        "script_hash": "s",
        "idempotency_scope": "",
        "idempotency_key": "",
        "request_hash": "",
        "workspace_identity_json": "",
        "event_id": "event-pin-a",
        "now_ms": 50,
        "expires_at_ms": 0,
        "tool_graph_id": lock_b.graph_id,
        "graph_id": lock_b.graph_id
    });
    let pinned = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller,
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    )
    .expect("native admission must pin the active program");
    assert_eq!(pinned.graph_id, lock_a.graph_id);
    assert_ne!(pinned.graph_id, lock_b.graph_id);
    assert!(pinned.shares_program(&program_a) || pinned.entry == "run");

    let owner = CapabilityOwner::new("gateway", "session-pin", "run-pin-a").unwrap();
    let deadline_ms = 9_000_000_000_000u64;
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner.clone())
        .registry_identity("pin-tracer-registry".to_string())
        .workspace(workspace.clone())
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(deadline_ms)
        .clock(Arc::new(SystemClock))
        .tokens(Arc::new(UuidIssuer))
        .durable(Arc::new(MemoryDurable { run: "run-pin-a" }))
        .approval(Arc::new(AllowRead))
        .cancellation(Arc::new(NoCancel))
        .generation(1)
        .build()
        .unwrap();
    let filesystem = Arc::new(
        FilesystemCapability::new(
            lifecycle.clone(),
            owner.clone(),
            FilesystemLimits {
                max_read_bytes: 4096,
                max_write_bytes: 4096,
                max_list_entries: 16,
            },
        )
        .unwrap(),
    );
    let cancellation = rustscript_agent::RunCancellation::with_timeout(Duration::from_secs(30));
    let host = AgentHostBridges {
        provider: None,
        auth_host_factory: None,
        cancellation: Some(cancellation.clone()),
        sleeps: Default::default(),
        skip_sleep: true,
        metrics: None,
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner),
        filesystem: Some(filesystem),
        processes: None,
        artifacts: None,
        control_hook: None,
        pinned_tool: Some(pinned.program_handle()),
        allow_stateless_pin: false,
    };
    let harness = AgentRunner::from_source(
        r#"
pub fn run(context: map) -> map {
    agent_runtime::invoke_pinned_tool({
        tool_name: "read_file",
        call_id: "call-read-1",
        canonical_arguments: "{\"path\":\"note.txt\"}",
        canonical_input: "",
        run_id: "run-pin-a",
        registry_identity: "pin-tracer-registry",
        argument_digest: "{\"path\":\"note.txt\"}",
        risk_class: "read",
        summary: "read note",
        untrusted_graph_id: "forged-graph-b"
    })
}
"#,
        AgentConfig::default(),
    )
    .expect("harness must compile against the typed bridge");
    let first = harness
        .clone()
        .with_host(host.clone())
        .run_with_context(VmValue::map(vec![]))
        .expect("pinned read");
    let text = vm_text(&first, "text");
    assert_eq!(
        text.as_bytes(),
        file_bytes,
        "read bytes must be the file contents produced by program A"
    );

    control
        .activate(&lock_b.graph_id, pinned.generation, &refs_b)
        .unwrap();
    let second = AgentRunner::from_source(
        r#"
pub fn run(context: map) -> map {
    agent_runtime::invoke_pinned_tool({
        tool_name: "read_file",
        call_id: "call-read-2",
        canonical_arguments: "{\"path\":\"note.txt\"}",
        canonical_input: "",
        run_id: "run-pin-a",
        registry_identity: "pin-tracer-registry",
        argument_digest: "{\"path\":\"note.txt\"}",
        risk_class: "read",
        summary: "read note again",
        untrusted_graph_id: "forged-graph-b"
    })
}
"#,
        AgentConfig::default(),
    )
    .expect("second harness must compile")
    .with_host(host)
    .run_with_context(VmValue::map(vec![]))
    .expect("old run still pinned");
    assert_eq!(
        vm_text(&second, "text").as_bytes(),
        file_bytes,
        "activating B must not retarget the run pinned to A"
    );
    let tail = &file_bytes[1..];
    assert_ne!(vm_text(&second, "text").as_bytes(), tail);

    let _ = fs::remove_dir_all(&root);
}

fn caller_json(run_id: &str, key: &str, hash: &str) -> Value {
    json!({
        "session_id": "session-pin",
        "session_new": 1,
        "profile": "gateway",
        "platform": "api_server",
        "account_id": "session-pin",
        "model": "m",
        "provider": "p",
        "system_prompt": "",
        "session_metadata_json": "{}",
        "run_id": run_id,
        "parent_run_id": "",
        "input_json": "{\"text\":\"read note\"}",
        "message_id": format!("message-{run_id}"),
        "message_run_id": run_id,
        "script_hash": "s",
        "idempotency_scope": "pin",
        "idempotency_key": key,
        "request_hash": hash,
        "workspace_identity_json": "",
        "event_id": format!("event-{run_id}"),
        "now_ms": 50,
        "expires_at_ms": 0
    })
}

fn harness_source(call_id: &str) -> String {
    format!(
        r#"
pub fn run(context: map) -> map {{
    agent_runtime::invoke_pinned_tool({{
        tool_name: "read_file",
        call_id: "{call_id}",
        canonical_arguments: "{{\"path\":\"note.txt\"}}",
        canonical_input: "",
        run_id: "run-pin-a",
        registry_identity: "pin-tracer-registry",
        argument_digest: "{{\"path\":\"note.txt\"}}",
        risk_class: "read",
        summary: "read note",
        untrusted_graph_id: "forged-graph-b"
    }})
}}
"#
    )
}

#[test]
fn pinned_handle_rejects_other_owner_without_started_effect() {
    let root = temp_root("bind");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.reada",
        0,
    );
    let lock_a = store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.reada".to_string(),
            },
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.reada".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    let refs_a: Vec<PackageArtifactRef> = lock_a
        .packages
        .iter()
        .map(|package| PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect();
    control.store_lock(&lock_a).unwrap();
    control.activate(&lock_a.graph_id, 0, &refs_a).unwrap();
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("note.txt"), b"untouched").unwrap();
    let pinned = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-a", "", ""),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    )
    .expect("admit A");
    let durable_count = Arc::new(AtomicUsize::new(0));
    let owner = CapabilityOwner::new("gateway", "session-pin", "run-other").unwrap();
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner.clone())
        .registry_identity("pin-tracer-registry".to_string())
        .workspace(workspace.clone())
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(9_000_000_000_000)
        .clock(Arc::new(SystemClock))
        .tokens(Arc::new(UuidIssuer))
        .durable(Arc::new(CountingDurableShared(Arc::clone(&durable_count))))
        .approval(Arc::new(AllowRead))
        .cancellation(Arc::new(NoCancel))
        .generation(1)
        .build()
        .unwrap();
    let cancellation = rustscript_agent::RunCancellation::with_timeout(Duration::from_secs(30));
    let host = AgentHostBridges {
        provider: None,
        auth_host_factory: None,
        cancellation: Some(cancellation),
        sleeps: Default::default(),
        skip_sleep: true,
        metrics: None,
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner),
        filesystem: None,
        processes: None,
        artifacts: None,
        control_hook: None,
        pinned_tool: Some(pinned.program_handle()),
        allow_stateless_pin: false,
    };
    let rejected = AgentRunner::from_source(&harness_source("call-other"), AgentConfig::default())
        .unwrap()
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("mismatch is a tool result, not a runner failure");
    assert_eq!(vm_text(&rejected, "code"), "pinned_binding_mismatch");
    assert_eq!(durable_count.load(Ordering::SeqCst), 0);
    let legal_owner = CapabilityOwner::new("gateway", "session-pin", "run-pin-a").unwrap();
    let legal = CapabilityLifecycle::builder()
        .owner(legal_owner.clone())
        .registry_identity("pin-tracer-registry".to_string())
        .workspace(workspace.clone())
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(9_000_000_000_000)
        .clock(Arc::new(SystemClock))
        .tokens(Arc::new(UuidIssuer))
        .durable(Arc::new(MemoryDurable { run: "run-pin-a" }))
        .approval(Arc::new(AllowRead))
        .cancellation(Arc::new(NoCancel))
        .generation(1)
        .build()
        .unwrap();
    let filesystem = Arc::new(
        FilesystemCapability::new(
            legal.clone(),
            legal_owner.clone(),
            FilesystemLimits {
                max_read_bytes: 4096,
                max_write_bytes: 4096,
                max_list_entries: 16,
            },
        )
        .unwrap(),
    );
    let legal_host = AgentHostBridges {
        provider: None,
        auth_host_factory: None,
        cancellation: Some(rustscript_agent::RunCancellation::with_timeout(
            Duration::from_secs(30),
        )),
        sleeps: Default::default(),
        skip_sleep: true,
        metrics: None,
        lifecycle: Some(Arc::new(legal)),
        capability_owner: Some(legal_owner),
        filesystem: Some(filesystem),
        processes: None,
        artifacts: None,
        control_hook: None,
        pinned_tool: Some(pinned.program_handle()),
        allow_stateless_pin: false,
    };
    let sibling = AgentRunner::from_source(&harness_source("call-legal"), AgentConfig::default())
        .unwrap()
        .with_host(legal_host)
        .run_with_context(VmValue::map(vec![]))
        .expect("legal owner on the same pin must still run");
    assert_eq!(vm_text(&sibling, "text"), "untouched");
    let _ = fs::remove_dir_all(&root);
}

struct CountingDurableShared(Arc<AtomicUsize>);

impl DurableToolLifecycle for CountingDurableShared {
    fn assert_active_run(&self, _run_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn prepare_parent(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn replay_result(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        Ok(None)
    }
    fn commit_started(&self, _record: &DurableStarted) -> Result<(), LifecycleError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn commit_result(&self, _call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
        Ok(result.clone())
    }
    fn interrupt(&self, _call_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

fn activate(
    control: &PluginControlStore,
    lock: &rustscript_agent::plugins::GraphLock,
    generation: u64,
) {
    let refs: Vec<PackageArtifactRef> = lock
        .packages
        .iter()
        .map(|package| PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect();
    control.store_lock(lock).unwrap();
    control.activate(&lock.graph_id, generation, &refs).unwrap();
}

#[test]
fn pinned_replay_keeps_program_a_after_b_activation() {
    let root = temp_root("replay");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.reada",
        0,
    );
    install_tool(
        &store,
        &signer,
        &root.join("pkg-b"),
        "org.rustscript.tools.readb",
        1,
    );
    let lock_a = store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.reada".to_string(),
            },
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.reada".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let lock_b = store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.readb".to_string(),
            },
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.readb".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    activate(&control, &lock_a, 0);
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let context = rustscript_agent::plugins::PinnedAdmitContext {
        original_cancellation: None,
        registry_identity: "pin-tracer-registry".to_string(),
        workspace: workspace.clone(),
    };
    let first = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-replay", "same-key", "hash-a"),
        &context,
    )
    .expect("first admit");
    activate(&control, &lock_b, 1);
    let second = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-replay", "same-key", "hash-a"),
        &context,
    )
    .expect("replay must not require the new active graph");
    assert_eq!(second.graph_id, first.graph_id);
    assert_eq!(second.ref_id, first.ref_id);
    assert_eq!(second.generation, first.generation);
    assert_eq!(
        second.program_handle().entry(),
        first.program_handle().entry()
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn library_only_graph_is_not_a_tool_pin() {
    let root = temp_root("library");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    let dir = root.join("pkg-lib");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("manifest.yaml"),
        r#"format: rustscript.plugin/v1
id: org.rustscript.tools.lib
version: 1.0.0
kind: library
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: run.rss
  export: run
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    run:
      direct: []
      delegated: []
"#,
    )
    .unwrap();
    fs::write(dir.join("run.rss"), "pub fn run() -> string { \"lib\" }\n").unwrap();
    let payload = store.signature_payload(&dir).unwrap();
    fs::write(
        dir.join("signature.ed25519"),
        signer.pair.sign(&payload).as_ref(),
    )
    .unwrap();
    store.install(&dir, &auth(&signer)).unwrap();
    let lock = store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.lib".to_string(),
            },
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.lib".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    activate(&control, &lock, 0);
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let error = match rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-lib", "", ""),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace,
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("library graph must not become a tool pin"),
    };
    assert!(
        error.to_string().contains("no tool package"),
        "unexpected library admit error: {error}"
    );
    let _ = fs::remove_dir_all(&root);
}

// 421 phase A: one AcceptedPublisher stateless tool linked with one pure leaf
// library. The tool does the Native read; the leaf only formats the string.
const LIB_A_ID: &str = "org.rustscript.lib.texta";
const LIB_B_ID: &str = "org.rustscript.lib.textb";
const TOOL_LIB_A_ID: &str = "org.rustscript.tools.readliba";
const TOOL_LIB_B_ID: &str = "org.rustscript.tools.readlibb";
const TOOL_LIB_AB_ID: &str = "org.rustscript.tools.readlibab";

fn tool_lib_manifest(id: &str, lib_id: &str) -> String {
    manifest(id).replace(
        "dependencies: []\n",
        &format!("dependencies:\n  - alias: text\n    id: {lib_id}\n    version: \"1.0.0\"\n"),
    )
}

fn tool_lib_source(offset: i64) -> String {
    format!(
        r#"
use bytes;
use text::{{format}};
fn map_string(value: map, key: string, fallback: string) -> string {{
    let mut result: string = fallback;
    if value.has(key) {{
        if type(value[key]) == "string" {{
            let coerced: string = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_map(value: map, key: string) -> map {{
    let mut result: map = {{}};
    if value.has(key) {{
        if type(value[key]) == "map" {{
            let coerced: map = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_int(value: map, key: string, fallback: int) -> int {{
    let mut result: int = fallback;
    if value.has(key) {{
        if type(value[key]) == "int" {{
            let coerced: int = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_bool(value: map, key: string, fallback: bool) -> bool {{
    let mut result: bool = fallback;
    if value.has(key) {{
        if type(value[key]) == "bool" {{
            let coerced: bool = value[key];
            result = coerced;
        }}
    }}
    result
}}

pub fn run(context: map) -> map {{
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {{
            meta
        }} else => {{
            let file_len: int = map_int(meta, "len", 0);
            let offset: int = {offset};
            let limit: int = file_len - offset;
            let read: map = cap::fs_read_range(token, path, offset, limit);
            if map_bool(read, "ok", false) == false => {{
                read
            }} else => {{
                let payload: bytes = read.bytes;
                let body: string = bytes::to_utf8(payload);
                let labeled: string = format(body);
                let result: map = {{ ok: true, content: labeled, data: {{}}, error: null, truncated: false, artifacts: [] }};
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {{
                    map_map(committed, "result")
                }} else => {{
                    committed
                }}
            }}
        }}
    }}
}}
"#
    )
}

fn lib_manifest_named(id: &str, export: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: library
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: {export}.rss
  export: {export}
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    {export}:
      direct: []
      delegated: []
"#
    )
}

fn install_library(store: &PackageStore, signer: &Signer, dir: &Path, id: &str, body: &str) {
    install_library_named(store, signer, dir, id, "format", body);
}

fn install_library_named(
    store: &PackageStore,
    signer: &Signer,
    dir: &Path,
    id: &str,
    export: &str,
    body: &str,
) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), lib_manifest_named(id, export)).unwrap();
    fs::write(dir.join(format!("{export}.rss")), body).unwrap();
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer)).unwrap();
}

fn tool_lib_pair_manifest(id: &str, lib_a: &str, lib_b: &str) -> String {
    manifest(id).replace(
        "dependencies: []\n",
        &format!(
            "dependencies:\n  - alias: text\n    id: {lib_a}\n    version: \"1.0.0\"\n  - alias: tail\n    id: {lib_b}\n    version: \"1.0.0\"\n"
        ),
    )
}

fn install_lib_tool_pair(
    store: &PackageStore,
    signer: &Signer,
    dir: &Path,
    id: &str,
    lib_a: &str,
    lib_b: &str,
) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("manifest.yaml"),
        tool_lib_pair_manifest(id, lib_a, lib_b),
    )
    .unwrap();
    fs::write(dir.join("run.rss"), tool_lib_pair_source(0)).unwrap();
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer)).unwrap();
}

fn tool_lib_pair_source(offset: i64) -> String {
    format!(
        r#"
use bytes;
use text::{{format}};
use tail::{{suffix}};
fn map_string(value: map, key: string, fallback: string) -> string {{
    let mut result: string = fallback;
    if value.has(key) {{
        if type(value[key]) == "string" {{
            let coerced: string = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_map(value: map, key: string) -> map {{
    let mut result: map = {{}};
    if value.has(key) {{
        if type(value[key]) == "map" {{
            let coerced: map = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_int(value: map, key: string, fallback: int) -> int {{
    let mut result: int = fallback;
    if value.has(key) {{
        if type(value[key]) == "int" {{
            let coerced: int = value[key];
            result = coerced;
        }}
    }}
    result
}}

fn map_bool(value: map, key: string, fallback: bool) -> bool {{
    let mut result: bool = fallback;
    if value.has(key) {{
        if type(value[key]) == "bool" {{
            let coerced: bool = value[key];
            result = coerced;
        }}
    }}
    result
}}

pub fn run(context: map) -> map {{
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {{
            meta
        }} else => {{
            let file_len: int = map_int(meta, "len", 0);
            let offset: int = {offset};
            let limit: int = file_len - offset;
            let read: map = cap::fs_read_range(token, path, offset, limit);
            if map_bool(read, "ok", false) == false => {{
                read
            }} else => {{
                let payload: bytes = read.bytes;
                let body: string = bytes::to_utf8(payload);
                let labeled: string = suffix(format(body));
                let result: map = {{ ok: true, content: labeled, data: {{}}, error: null, truncated: false, artifacts: [] }};
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {{
                    map_map(committed, "result")
                }} else => {{
                    committed
                }}
            }}
        }}
    }}
}}
"#
    )
}

fn install_lib_tool(store: &PackageStore, signer: &Signer, dir: &Path, id: &str, lib: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), tool_lib_manifest(id, lib)).unwrap();
    fs::write(dir.join("run.rss"), tool_lib_source(0)).unwrap();
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer)).unwrap();
}

fn resolve_tool_only(store: &PackageStore, id: &str) -> rustscript_agent::plugins::GraphLock {
    store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: id.to_string(),
            },
            roots: vec![PackageRequirement {
                id: id.to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap()
}

fn lib_refs(lock: &rustscript_agent::plugins::GraphLock) -> Vec<PackageArtifactRef> {
    lock.packages
        .iter()
        .map(|package| PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect()
}

fn invoke_pinned_text(
    workspace: &Path,
    pinned: &rustscript_agent::plugins::PinnedToolAdmission,
    call_id: &str,
    run_id: &'static str,
) -> String {
    let owner = CapabilityOwner::new("gateway", "session-pin", run_id).unwrap();
    let deadline_ms = 9_000_000_000_000u64;
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner.clone())
        .registry_identity("pin-tracer-registry".to_string())
        .workspace(workspace.to_path_buf())
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(deadline_ms)
        .clock(Arc::new(SystemClock))
        .tokens(Arc::new(UuidIssuer))
        .durable(Arc::new(MemoryDurable { run: run_id }))
        .approval(Arc::new(AllowRead))
        .cancellation(Arc::new(NoCancel))
        .generation(1)
        .build()
        .unwrap();
    let filesystem = Arc::new(
        FilesystemCapability::new(
            lifecycle.clone(),
            owner.clone(),
            FilesystemLimits {
                max_read_bytes: 4096,
                max_write_bytes: 4096,
                max_list_entries: 16,
            },
        )
        .unwrap(),
    );
    let cancellation = rustscript_agent::RunCancellation::with_timeout(Duration::from_secs(30));
    let host = AgentHostBridges {
        provider: None,
        auth_host_factory: None,
        cancellation: Some(cancellation),
        sleeps: Default::default(),
        skip_sleep: true,
        metrics: None,
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner),
        filesystem: Some(filesystem),
        processes: None,
        artifacts: None,
        control_hook: None,
        pinned_tool: Some(pinned.program_handle()),
        allow_stateless_pin: false,
    };
    let harness = AgentRunner::from_source(
        &format!(
            r#"
pub fn run(context: map) -> map {{
    agent_runtime::invoke_pinned_tool({{
        tool_name: "read_file",
        call_id: "{call_id}",
        canonical_arguments: "{{\"path\":\"note.txt\"}}",
        canonical_input: "",
        run_id: "{run_id}",
        registry_identity: "pin-tracer-registry",
        argument_digest: "{{\"path\":\"note.txt\"}}",
        risk_class: "read",
        summary: "read note",
        untrusted_graph_id: "forged-graph-b"
    }})
}}
"#
        ),
        AgentConfig::default(),
    )
    .expect("harness must compile against the typed bridge");
    let output = harness
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("pinned read through the library link");
    vm_text(&output, "text")
}

#[test]
fn linked_pure_library_labels_authorized_read_and_pins_program_a() {
    let root = temp_root("liblink");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_library(
        &store,
        &signer,
        &root.join("lib-a"),
        LIB_A_ID,
        "pub fn format(value: string) -> string { \"libA:\" + value }\n",
    );
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        TOOL_LIB_A_ID,
        LIB_A_ID,
    );
    let lock_a = resolve_tool_only(&store, TOOL_LIB_A_ID);
    assert_eq!(lock_a.packages.len(), 2, "tool plus one leaf library");
    assert_eq!(lock_a.edges.len(), 1, "exactly the library edge");
    assert_eq!(lock_a.edges[0].relation, "library");
    let prepared_a = store.prepare(&lock_a).unwrap();
    let program_a = prepared_a
        .program(TOOL_LIB_A_ID)
        .expect("prepare must retain combined tool program A");
    assert_eq!(
        prepared_a.trust(TOOL_LIB_A_ID),
        Some(rustscript_agent::plugins::PackageTrust::AcceptedPublisher)
    );

    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    control.store_lock(&lock_a).unwrap();
    control
        .activate(&lock_a.graph_id, 0, &lib_refs(&lock_a))
        .unwrap();

    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("note.txt"), b"hello").unwrap();
    let pinned = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-a", "", ""),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    )
    .expect("native admission must pin the combined program");
    assert_eq!(pinned.graph_id, lock_a.graph_id);
    assert!(pinned.shares_program(&program_a));
    let text = invoke_pinned_text(&workspace, &pinned, "call-read-1", "run-pin-a");
    assert_eq!(text, "libA:hello");
    let _ = fs::remove_dir_all(&root);
}

/// T14 two-leaf slice: one ToolOnly tool imports exactly two pure leaf
/// libraries. The first leaf formats the authorized read, the second appends
/// its own suffix, and the original commit carries the composed string.
#[test]
fn linked_two_pure_libraries_compose_authorized_read_and_pin_program() {
    let root = temp_root("liblink2");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_library(
        &store,
        &signer,
        &root.join("lib-a"),
        LIB_A_ID,
        "pub fn format(value: string) -> string { \"libA:\" + value }\n",
    );
    install_library_named(
        &store,
        &signer,
        &root.join("lib-b"),
        LIB_B_ID,
        "suffix",
        "pub fn suffix(value: string) -> string { value + \":libB\" }\n",
    );
    install_lib_tool_pair(
        &store,
        &signer,
        &root.join("pkg-ab"),
        TOOL_LIB_AB_ID,
        LIB_A_ID,
        LIB_B_ID,
    );
    let lock = resolve_tool_only(&store, TOOL_LIB_AB_ID);
    assert_eq!(
        lock.packages.len(),
        3,
        "tool plus exactly two leaf libraries"
    );
    assert_eq!(lock.edges.len(), 2, "exactly one library edge per leaf");
    assert!(lock.edges.iter().all(|edge| edge.relation == "library"));
    let prepared = store.prepare(&lock).unwrap();
    let program = prepared
        .program(TOOL_LIB_AB_ID)
        .expect("prepare must retain the combined tool program");
    assert_eq!(
        prepared.trust(TOOL_LIB_AB_ID),
        Some(rustscript_agent::plugins::PackageTrust::AcceptedPublisher)
    );
    assert!(
        prepared.program(LIB_A_ID).is_some(),
        "first leaf keeps its standalone purity proof"
    );
    assert!(
        prepared.program(LIB_B_ID).is_some(),
        "second leaf keeps its standalone purity proof"
    );

    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    control.store_lock(&lock).unwrap();
    control
        .activate(&lock.graph_id, 0, &lib_refs(&lock))
        .unwrap();

    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("note.txt"), b"hello").unwrap();
    let pinned = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-ab", "", ""),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    )
    .expect("native admission must pin the two-leaf combined program");
    assert_eq!(pinned.graph_id, lock.graph_id);
    assert!(pinned.shares_program(&program));
    let text = invoke_pinned_text(&workspace, &pinned, "call-read-1", "run-pin-ab");
    assert_eq!(text, "libA:hello:libB");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn linked_graph_b_relabels_replay_keeps_a_and_missing_package_is_unavailable() {
    let root = temp_root("libab");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_library(
        &store,
        &signer,
        &root.join("lib-a"),
        LIB_A_ID,
        "pub fn format(value: string) -> string { \"libA:\" + value }\n",
    );
    install_library(
        &store,
        &signer,
        &root.join("lib-b"),
        LIB_B_ID,
        "pub fn format(value: string) -> string { \"libB:\" + value }\n",
    );
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        TOOL_LIB_A_ID,
        LIB_A_ID,
    );
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-b"),
        TOOL_LIB_B_ID,
        LIB_B_ID,
    );
    let lock_a = resolve_tool_only(&store, TOOL_LIB_A_ID);
    let lock_b = resolve_tool_only(&store, TOOL_LIB_B_ID);
    assert_ne!(lock_a.graph_id, lock_b.graph_id);
    let program_a = store
        .prepare(&lock_a)
        .unwrap()
        .program(TOOL_LIB_A_ID)
        .unwrap();
    let program_b = store
        .prepare(&lock_b)
        .unwrap()
        .program(TOOL_LIB_B_ID)
        .unwrap();
    assert!(!Arc::ptr_eq(&program_a, &program_b));

    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    control.store_lock(&lock_a).unwrap();
    control.store_lock(&lock_b).unwrap();
    control
        .activate(&lock_a.graph_id, 0, &lib_refs(&lock_a))
        .unwrap();

    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("note.txt"), b"hello").unwrap();
    let context = rustscript_agent::plugins::PinnedAdmitContext {
        original_cancellation: None,
        registry_identity: "pin-tracer-registry".to_string(),
        workspace: workspace.clone(),
    };
    let first = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-a", "lib-key", "hash-a"),
        &context,
    )
    .expect("first admit pins graph A");
    assert_eq!(first.graph_id, lock_a.graph_id);
    assert_eq!(
        invoke_pinned_text(&workspace, &first, "call-read-1", "run-pin-a"),
        "libA:hello"
    );

    control
        .activate(&lock_b.graph_id, 1, &lib_refs(&lock_b))
        .unwrap();
    let replayed = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-a", "lib-key", "hash-a"),
        &context,
    )
    .expect("same idempotency key must replay the original A pin");
    assert_eq!(replayed.graph_id, first.graph_id);
    assert_eq!(replayed.ref_id, first.ref_id);
    assert_eq!(replayed.generation, first.generation);
    assert_eq!(
        replayed.program_handle().entry(),
        first.program_handle().entry()
    );
    assert_eq!(
        invoke_pinned_text(&workspace, &replayed, "call-read-1", "run-pin-a"),
        "libA:hello"
    );

    let second = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-b", "lib-key-b", "hash-b"),
        &context,
    )
    .expect("fresh run on the active graph pins B");
    assert_eq!(second.graph_id, lock_b.graph_id);
    assert_eq!(second.program_handle().entry(), "run");
    assert_eq!(
        invoke_pinned_text(&workspace, &second, "call-read-2", "run-pin-b"),
        "libB:hello"
    );

    let tool_artifact = lock_a
        .packages
        .iter()
        .find(|package| package.id == TOOL_LIB_A_ID)
        .map(|package| package.artifact_id.clone())
        .expect("tool A artifact");
    fs::remove_dir_all(root.join("packages").join("artifacts").join(&tool_artifact)).unwrap();
    control
        .activate(&lock_a.graph_id, 2, &lib_refs(&lock_a))
        .expect("activation records the lock even when captures are gone");
    let before = control.activation().unwrap();
    assert_eq!(before.graph_id, lock_a.graph_id);
    assert_eq!(before.generation, 3);
    let cancel = rustscript_agent::RunCancellation::with_timeout(Duration::from_secs(30));
    let error = match rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-a", "lib-key-gone", "hash-gone"),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: Some(cancel),
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("missing tool A capture must fail closed"),
    };
    assert_eq!(error.code, "plugin_artifact_unavailable");
    assert_eq!(
        control.activation().unwrap(),
        before,
        "a missing old package must not switch the active graph away"
    );
    let _ = fs::remove_dir_all(&root);
}

const TOOL_LIB_C_ID: &str = "org.rustscript.tools.readlibc";

#[test]
fn revoking_library_graph_a_leaves_shared_leaf_graph_c_readable() {
    let root = temp_root("librevoke");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_library(
        &store,
        &signer,
        &root.join("lib-a"),
        LIB_A_ID,
        "pub fn format(value: string) -> string { \"libA:\" + value }\n",
    );
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        TOOL_LIB_A_ID,
        LIB_A_ID,
    );
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-c"),
        TOOL_LIB_C_ID,
        LIB_A_ID,
    );
    let lock_a = resolve_tool_only(&store, TOOL_LIB_A_ID);
    let lock_c = resolve_tool_only(&store, TOOL_LIB_C_ID);
    store.prepare(&lock_a).unwrap();
    store.prepare(&lock_c).unwrap();

    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    control.store_lock(&lock_a).unwrap();
    control.store_lock(&lock_c).unwrap();
    control
        .activate(&lock_a.graph_id, 0, &lib_refs(&lock_a))
        .unwrap();

    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("note.txt"), b"hello").unwrap();
    let context = rustscript_agent::plugins::PinnedAdmitContext {
        original_cancellation: None,
        registry_identity: "pin-tracer-registry".to_string(),
        workspace: workspace.clone(),
    };
    let pinned_a = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-a", "revoke-key-a", "hash-a"),
        &context,
    )
    .expect("admit graph A before revocation");
    assert_eq!(
        invoke_pinned_text(&workspace, &pinned_a, "call-read-1", "run-pin-a"),
        "libA:hello"
    );

    control
        .revoke_graph(&store, &lock_a.graph_id)
        .expect("phase-A tool plus pure-leaf graph must support graph_revoke");
    let revoked = control.graph_revocation(&lock_a.graph_id).unwrap();
    assert!(revoked.is_some());
    assert_eq!(revoked.unwrap().graph_id, lock_a.graph_id);
    assert!(
        control
            .graph_revocation(&lock_c.graph_id)
            .unwrap()
            .is_none(),
        "revoking A must not tombstone the shared-leaf graph C"
    );

    control
        .activate(&lock_c.graph_id, 1, &lib_refs(&lock_c))
        .unwrap();
    let pinned_c = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-c", "revoke-key-c", "hash-c"),
        &context,
    )
    .expect("shared-leaf graph C must still admit after A is revoked");
    assert_eq!(pinned_c.graph_id, lock_c.graph_id);
    assert_eq!(
        invoke_pinned_text(&workspace, &pinned_c, "call-read-2", "run-pin-c"),
        "libA:hello"
    );

    let plain = temp_root("libplain");
    let plain_store = PackageStore::open(plain.join("packages")).unwrap();
    install_tool(
        &plain_store,
        &signer,
        &plain.join("pkg"),
        "org.rustscript.tools.plain",
        0,
    );
    let plain_lock = plain_store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.plain".to_string(),
            },
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.plain".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let plain_db = plain.join("state.db");
    let plain_persistence =
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &plain_db)
            .unwrap();
    plain_persistence.load().unwrap();
    let plain_control = PluginControlStore::new(&plain_persistence);
    plain_control.store_lock(&plain_lock).unwrap();
    let error = plain_control
        .revoke_graph(&plain_store, &plain_lock.graph_id)
        .expect_err("edgeless single-tool graphs keep the previous revoke rejection");
    assert_eq!(error.code, "plugin_lock_invalid");
    let _ = fs::remove_dir_all(&plain);
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 456 F4: Native-boundary safety on the phase-A stateless tool + pure leaf.
//
// Every case below binds a real signed tool/leaf pair, a real captured lock and
// a real sealed pinned program, then runs the sealed program through the same
// `agent_runtime::invoke_pinned_tool` boundary used for a run. Admission is
// already complete before each negative, so an admission-only rejection cannot
// be mistaken for Native coverage.
// ---------------------------------------------------------------------------

struct NativeDurable {
    run: String,
    arguments: Value,
    started: AtomicUsize,
    commits: AtomicUsize,
    results: Mutex<HashMap<String, Value>>,
}

impl NativeDurable {
    fn new(run: &str, arguments: Value) -> Arc<Self> {
        Arc::new(Self {
            run: run.to_string(),
            arguments,
            started: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            results: Mutex::new(HashMap::new()),
        })
    }

    fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }

    fn commits(&self) -> usize {
        self.commits.load(Ordering::SeqCst)
    }
}

impl DurableToolLifecycle for NativeDurable {
    fn assert_active_run(&self, run_id: &str) -> Result<(), LifecycleError> {
        assert_eq!(run_id, self.run.as_str(), "unexpected run identity");
        Ok(())
    }

    fn prepare_parent(
        &self,
        run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), LifecycleError> {
        assert_eq!(run_id, self.run.as_str(), "unexpected run identity");
        Ok(())
    }

    fn parent_arguments(
        &self,
        run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        assert_eq!(run_id, self.run.as_str(), "unexpected run identity");
        Ok(Some(self.arguments.clone()))
    }

    fn replay_result(
        &self,
        run_id: &str,
        call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        assert_eq!(run_id, self.run.as_str(), "unexpected run identity");
        Ok(self
            .results
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(call_id)
            .cloned())
    }

    fn commit_started(&self, _record: &DurableStarted) -> Result<(), LifecycleError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn commit_result(&self, call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.results
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(call_id.to_string(), result.clone());
        Ok(result.clone())
    }

    fn interrupt(&self, _call_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct ToggleCancellation(Arc<AtomicBool>);

impl CancellationFlag for ToggleCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn vm_json(value: &VmValue) -> Value {
    match value {
        VmValue::Null => Value::Null,
        VmValue::Int(number) => json!(number),
        VmValue::Float(number) => json!(number),
        VmValue::Bool(flag) => json!(flag),
        VmValue::String(text) => json!(text.to_string()),
        VmValue::Bytes(bytes) => json!(String::from_utf8_lossy(bytes).into_owned()),
        VmValue::Array(items) => Value::Array(items.iter().map(vm_json).collect()),
        VmValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    let key = match key {
                        VmValue::String(text) => text.to_string(),
                        VmValue::Int(number) => number.to_string(),
                        VmValue::Bool(flag) => flag.to_string(),
                        _ => String::new(),
                    };
                    (key, vm_json(value))
                })
                .collect(),
        ),
        VmValue::Callable(_) => Value::Null,
    }
}

fn rss_literal(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

struct NativeCase {
    workspace: PathBuf,
    pinned: rustscript_agent::plugins::PinnedToolAdmission,
    run_id: String,
    call_id: String,
    tool_name: String,
    arguments: String,
    risk: &'static str,
    deadline_ms: u64,
    max_output_bytes: usize,
    cancelled: Arc<AtomicBool>,
    approval: Arc<dyn ApprovalGate>,
    durable: Arc<NativeDurable>,
}

impl NativeCase {
    fn invoke(&self) -> Value {
        let owner = CapabilityOwner::new("gateway", "session-pin", &self.run_id).unwrap();
        let lifecycle = CapabilityLifecycle::builder()
            .owner(owner.clone())
            .registry_identity("pin-tracer-registry".to_string())
            .workspace(self.workspace.clone())
            .limits(LifecycleLimits {
                max_tool_calls: 8,
                max_output_bytes: self.max_output_bytes,
                max_summary_bytes: 256,
            })
            .deadline_ms(self.deadline_ms)
            .clock(Arc::new(SystemClock))
            .tokens(Arc::new(UuidIssuer))
            .durable(Arc::clone(&self.durable) as Arc<dyn DurableToolLifecycle>)
            .approval(Arc::clone(&self.approval))
            .cancellation(Arc::new(ToggleCancellation(Arc::clone(&self.cancelled))))
            .generation(1)
            .build()
            .unwrap();
        let filesystem = Arc::new(
            FilesystemCapability::new(
                lifecycle.clone(),
                owner.clone(),
                FilesystemLimits {
                    max_read_bytes: 4096,
                    max_write_bytes: 4096,
                    max_list_entries: 16,
                },
            )
            .unwrap(),
        );
        let host = AgentHostBridges {
            provider: None,
            auth_host_factory: None,
            cancellation: Some(rustscript_agent::RunCancellation::with_timeout(
                Duration::from_secs(30),
            )),
            sleeps: Default::default(),
            skip_sleep: true,
            metrics: None,
            lifecycle: Some(Arc::new(lifecycle)),
            capability_owner: Some(owner),
            filesystem: Some(filesystem),
            processes: None,
            artifacts: None,
            control_hook: None,
            pinned_tool: Some(self.pinned.program_handle()),
            allow_stateless_pin: false,
        };
        let arguments = rss_literal(&self.arguments);
        let source = [
            "pub fn run(context: map) -> map {".to_string(),
            "    agent_runtime::invoke_pinned_tool({".to_string(),
            format!("        tool_name: \"{}\",", self.tool_name),
            format!("        call_id: \"{}\",", self.call_id),
            format!("        canonical_arguments: \"{arguments}\","),
            "        canonical_input: \"\",".to_string(),
            format!("        run_id: \"{}\",", self.run_id),
            "        registry_identity: \"pin-tracer-registry\",".to_string(),
            format!("        argument_digest: \"{arguments}\","),
            format!("        risk_class: \"{}\",", self.risk),
            "        summary: \"phase a native case\",".to_string(),
            "        untrusted_graph_id: \"forged-graph-b\"".to_string(),
            "    })".to_string(),
            "}".to_string(),
        ]
        .join("\n");
        let harness = AgentRunner::from_source(&source, AgentConfig::default())
            .expect("native case harness must compile against the typed boundary");
        let output = harness
            .with_host(host)
            .run_with_context(VmValue::map(vec![]))
            .expect("the sealed tool boundary must return a typed envelope");
        vm_json(&output)
    }
}

impl NativeCase {
    /// Runs the sealed tool to a committed result, then presents a late
    /// approval attestation for the same call identity through the actual
    /// `agent_runtime::approval_attest` host boundary.
    fn invoke_then_late_approval(&self) -> Value {
        let owner = CapabilityOwner::new("gateway", "session-pin", &self.run_id).unwrap();
        let lifecycle = CapabilityLifecycle::builder()
            .owner(owner.clone())
            .registry_identity("pin-tracer-registry".to_string())
            .workspace(self.workspace.clone())
            .limits(LifecycleLimits {
                max_tool_calls: 8,
                max_output_bytes: self.max_output_bytes,
                max_summary_bytes: 256,
            })
            .deadline_ms(self.deadline_ms)
            .clock(Arc::new(SystemClock))
            .tokens(Arc::new(UuidIssuer))
            .durable(Arc::clone(&self.durable) as Arc<dyn DurableToolLifecycle>)
            .approval(Arc::clone(&self.approval))
            .cancellation(Arc::new(ToggleCancellation(Arc::clone(&self.cancelled))))
            .generation(1)
            .build()
            .unwrap();
        let filesystem = Arc::new(
            FilesystemCapability::new(
                lifecycle.clone(),
                owner.clone(),
                FilesystemLimits {
                    max_read_bytes: 4096,
                    max_write_bytes: 4096,
                    max_list_entries: 16,
                },
            )
            .unwrap(),
        );
        let host = AgentHostBridges {
            provider: None,
            auth_host_factory: None,
            cancellation: Some(rustscript_agent::RunCancellation::with_timeout(
                Duration::from_secs(30),
            )),
            sleeps: Default::default(),
            skip_sleep: true,
            metrics: None,
            lifecycle: Some(Arc::new(lifecycle)),
            capability_owner: Some(owner),
            filesystem: Some(filesystem),
            processes: None,
            artifacts: None,
            control_hook: None,
            pinned_tool: Some(self.pinned.program_handle()),
            allow_stateless_pin: false,
        };
        let arguments = rss_literal(&self.arguments);
        let source = [
            "pub fn run(context: map) -> map {".to_string(),
            "    let first: map = agent_runtime::invoke_pinned_tool({".to_string(),
            format!("        tool_name: \"{}\",", self.tool_name),
            format!("        call_id: \"{}\",", self.call_id),
            format!("        canonical_arguments: \"{arguments}\","),
            "        canonical_input: \"\",".to_string(),
            format!("        run_id: \"{}\",", self.run_id),
            "        registry_identity: \"pin-tracer-registry\",".to_string(),
            format!("        argument_digest: \"{arguments}\","),
            format!("        risk_class: \"{}\",", self.risk),
            "        summary: \"phase a native case\",".to_string(),
            "        untrusted_graph_id: \"forged-graph-b\"".to_string(),
            "    });".to_string(),
            "    let late: map = agent_runtime::approval_attest({".to_string(),
            format!("        run_id: \"{}\",", self.run_id),
            format!("        call_id: \"{}\",", self.call_id),
            format!("        tool_name: \"{}\",", self.tool_name),
            format!("        argument_digest: \"{arguments}\","),
            "        registry_identity: \"pin-tracer-registry\",".to_string(),
            format!("        risk_class: \"{}\",", self.risk),
            "        summary: \"phase a native case\"".to_string(),
            "    });".to_string(),
            "    { first: first, late: late }".to_string(),
            "}".to_string(),
        ]
        .join("\n");
        let harness = AgentRunner::from_source(&source, AgentConfig::default())
            .expect("late approval harness must compile against the typed boundary");
        let output = harness
            .with_host(host)
            .run_with_context(VmValue::map(vec![]))
            .expect("the sealed boundary must return typed envelopes");
        vm_json(&output)
    }
}

#[test]
fn phase_a_native_late_approval_is_denied_after_completed_commit() {
    let root = temp_root("f4-late-approval");
    let (store, _signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    let (_persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let outcome = NativeCase {
        workspace,
        pinned,
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke_then_late_approval();
    assert_eq!(outcome["first"]["text"], "libA:hello", "{outcome}");
    assert_eq!(durable.commits(), 1, "the first call really committed");
    assert_eq!(
        outcome["late"]["ok"], false,
        "a late approval for a completed call must be denied: {outcome}"
    );
    assert_eq!(
        outcome["late"]["error"]["code"], "approval_denied",
        "{outcome}"
    );
    assert_eq!(
        outcome["late"]["error"]["message"], "completed tool call cannot receive a new approval",
        "{outcome}"
    );
    assert_eq!(durable.commits(), 1, "late approval must not commit again");
    let _ = fs::remove_dir_all(&root);
}

fn phase_a_leaf_body() -> &'static str {
    "pub fn format(value: string) -> string { \"libA:\" + value }\n"
}

fn install_phase_a_pair(
    root: &Path,
    leaf_body: &str,
) -> (PackageStore, Signer, rustscript_agent::plugins::GraphLock) {
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    install_library(&store, &signer, &root.join("lib-a"), LIB_A_ID, leaf_body);
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        TOOL_LIB_A_ID,
        LIB_A_ID,
    );
    let lock = resolve_tool_only(&store, TOOL_LIB_A_ID);
    (store, signer, lock)
}

fn phase_a_open(
    root: &Path,
    store: &PackageStore,
    lock: &rustscript_agent::plugins::GraphLock,
) -> (
    Arc<GatewayPersistence>,
    PathBuf,
    rustscript_agent::plugins::PinnedToolAdmission,
) {
    use rustscript_agent::{plugins::PinnedAdmitContext, plugins::admit_pinned_tool_run};
    let store_prepared = store.prepare(lock).unwrap();
    assert!(store_prepared.program(TOOL_LIB_A_ID).is_some());
    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    {
        let control = PluginControlStore::new(&persistence);
        control.store_lock(lock).unwrap();
        control
            .activate(&lock.graph_id, 0, &lib_refs(lock))
            .unwrap();
    }
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("note.txt"), b"hello").unwrap();
    fs::write(root.join("outside.txt"), b"outside").unwrap();
    let pinned = admit_pinned_tool_run(
        &persistence,
        store,
        &caller_json("run-pin-a", "", ""),
        &PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    )
    .expect("phase-A graph must admit a real sealed pin");
    (persistence, workspace, pinned)
}

#[test]
fn phase_a_native_begin_denies_revoked_graph_and_keeps_shared_leaf() {
    let root = temp_root("f4-revoke-begin");
    let (store, signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-c"),
        TOOL_LIB_C_ID,
        LIB_A_ID,
    );
    let lock_c = resolve_tool_only(&store, TOOL_LIB_C_ID);
    store.prepare(&lock_c).unwrap();
    let (persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let control = PluginControlStore::new(&persistence);
    control
        .store_lock(&lock_c)
        .expect("shared-leaf graph C lock must be stored before activation");
    let durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let positive = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(
        positive["text"], "libA:hello",
        "positive control: {positive}"
    );
    assert_eq!(durable.commits(), 1);

    control
        .revoke_graph(&store, &lock_a.graph_id)
        .expect("phase-A graph revokes through the narrow topology");
    let revoked = NativeCase {
        workspace: workspace.clone(),
        pinned,
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-2".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(
        revoked["ok"], false,
        "an already pinned run must be denied at Native begin after revocation: {revoked}"
    );
    assert_eq!(revoked["code"], "plugin_graph_revoked", "{revoked}");
    assert_eq!(
        durable.commits(),
        1,
        "revocation must not add a successful commit"
    );

    control
        .activate(&lock_c.graph_id, 1, &lib_refs(&lock_c))
        .unwrap();
    let pinned_c = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-c", "", ""),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    )
    .expect("shared-leaf graph C still admits after A is revoked");
    let durable_c = NativeDurable::new("run-pin-c", json!({"path": "note.txt"}));
    let shared = NativeCase {
        workspace,
        pinned: pinned_c,
        run_id: "run-pin-c".to_string(),
        call_id: "call-read-3".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable_c),
    }
    .invoke();
    assert_eq!(
        shared["text"], "libA:hello",
        "shared leaf C must keep a positive Native read: {shared}"
    );
    assert_eq!(durable_c.commits(), 1);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn phase_a_native_replay_denies_revoked_graph_without_new_effect() {
    let root = temp_root("f4-revoke-replay");
    let (store, _signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    let (persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let control = PluginControlStore::new(&persistence);
    let durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let first = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(first["text"], "libA:hello");
    assert_eq!(durable.commits(), 1);

    control
        .revoke_graph(&store, &lock_a.graph_id)
        .expect("phase-A graph revokes");
    let replayed = NativeCase {
        workspace,
        pinned,
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(
        replayed["ok"], false,
        "an already pinned call replay must be denied at Native begin after revocation: {replayed}"
    );
    assert_eq!(replayed["code"], "plugin_graph_revoked", "{replayed}");
    assert_eq!(
        durable.commits(),
        1,
        "revocation must not allow a second successful commit"
    );
    let _ = fs::remove_dir_all(&root);
}

/// Independent shared-leaf control: after tool graph A is revoked, graph C
/// sharing the same leaf still admits and executes. This stands on its own
/// fixture and never runs after an earlier assertion that can fail.
#[test]
fn phase_a_native_shared_leaf_c_succeeds_after_a_revoke() {
    let root = temp_root("f4-shared-leaf");
    let (store, signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-c"),
        TOOL_LIB_C_ID,
        LIB_A_ID,
    );
    let lock_c = resolve_tool_only(&store, TOOL_LIB_C_ID);
    store.prepare(&lock_c).unwrap();
    let (persistence, workspace, _pinned_a) = phase_a_open(&root, &store, &lock_a);
    let control = PluginControlStore::new(&persistence);
    control
        .store_lock(&lock_c)
        .expect("shared-leaf graph C lock must be stored before activation");
    control
        .revoke_graph(&store, &lock_a.graph_id)
        .expect("tool graph A revokes");
    control
        .activate(&lock_c.graph_id, 1, &lib_refs(&lock_c))
        .unwrap();
    let pinned_c = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-pin-c", "", ""),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace: workspace.clone(),
        },
    )
    .expect("shared-leaf graph C still admits after A is revoked");
    let durable_c = NativeDurable::new("run-pin-c", json!({"path": "note.txt"}));
    let shared = NativeCase {
        workspace,
        pinned: pinned_c,
        run_id: "run-pin-c".to_string(),
        call_id: "call-read-3".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable_c),
    }
    .invoke();
    assert_eq!(
        shared["text"], "libA:hello",
        "shared leaf C must keep a positive Native read: {shared}"
    );
    assert_eq!(durable_c.commits(), 1);
    let _ = fs::remove_dir_all(&root);
}

/// Same-owner guard query failure refuses closed: a real injected storage
/// failure on the exact revocation read denies with the typed pin code,
/// without a replay, child dispatch, or managed effect.
#[test]
fn phase_a_native_guard_query_failure_denies_closed_without_effect() {
    let root = temp_root("f4-guard-fault");
    let (store, _signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    let (persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let case = NativeCase {
        workspace: workspace.clone(),
        pinned,
        run_id: "run-pin-a".to_string(),
        call_id: "call-fault-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    };
    // The guard read is the next storage command on this fixture: failing it
    // must refuse closed instead of executing or replaying.
    persistence.inject_persist_failure();
    let denied = case.invoke();
    assert_eq!(
        denied["ok"], false,
        "a failed guard read must refuse execution: {denied}"
    );
    assert_eq!(
        denied["code"], "plugin_graph_pin_required",
        "a failed guard read must refuse closed: {denied}"
    );
    assert!(
        denied
            .get("canonical_result")
            .is_none_or(|value| value == ""),
        "a refused guard read must not leak a canonical result: {denied}"
    );
    assert_eq!(
        durable.commits(),
        0,
        "a refused guard read must not commit a managed effect"
    );
    assert_eq!(
        durable.started(),
        0,
        "a refused guard read must not start the sealed child"
    );
    let _ = fs::remove_dir_all(&root);
}

/// The guard wait honors the elapsed original deadline: with no remaining
/// run budget the exact read keeps deadline_elapsed on a bounded wait instead
/// of minting a fresh clock, starting the child, or committing an effect.
#[test]
fn phase_a_native_guard_honors_elapsed_original_deadline() {
    let root = temp_root("f4-guard-deadline");
    let (store, _signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    let (_persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let owner = CapabilityOwner::new("gateway", "session-pin", "run-pin-a").unwrap();
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner.clone())
        .registry_identity("pin-tracer-registry".to_string())
        .workspace(workspace.clone())
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(9_000_000_000_000)
        .clock(Arc::new(SystemClock))
        .tokens(Arc::new(UuidIssuer))
        .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowRead))
        .cancellation(Arc::new(ToggleCancellation(Arc::new(AtomicBool::new(
            false,
        )))))
        .generation(1)
        .build()
        .unwrap();
    let filesystem = Arc::new(
        FilesystemCapability::new(
            lifecycle.clone(),
            owner.clone(),
            FilesystemLimits {
                max_read_bytes: 4096,
                max_write_bytes: 4096,
                max_list_entries: 16,
            },
        )
        .unwrap(),
    );
    let elapsed = rustscript_agent::RunCancellation::with_timeout(Duration::from_millis(0));
    assert!(
        elapsed.deadline_passed(),
        "the fixture original deadline must already be elapsed"
    );
    let host = AgentHostBridges {
        provider: None,
        auth_host_factory: None,
        cancellation: Some(elapsed),
        sleeps: Default::default(),
        skip_sleep: true,
        metrics: None,
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner),
        filesystem: Some(filesystem),
        processes: None,
        artifacts: None,
        control_hook: None,
        pinned_tool: Some(pinned.program_handle()),
        allow_stateless_pin: false,
    };
    let denied =
        AgentRunner::from_source(&harness_source("call-deadline-1"), AgentConfig::default())
            .unwrap()
            .with_host(host)
            .run_with_context(VmValue::map(vec![]))
            .expect("an elapsed original deadline is a tool result, not a runner failure");
    let denied = vm_json(&denied);
    assert_eq!(
        denied["ok"], false,
        "an elapsed original deadline must refuse execution: {denied}"
    );
    assert_eq!(
        denied["code"], "deadline_elapsed",
        "an elapsed original deadline must keep its exact classification: {denied}"
    );
    assert_eq!(
        durable.commits(),
        0,
        "an elapsed original deadline must not commit a managed effect"
    );
    assert_eq!(
        durable.started(),
        0,
        "an elapsed original deadline must not start the sealed child"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn phase_a_native_begin_denies_cancelled_and_expired_original_clock() {
    let root = temp_root("f4-clock");
    let (store, _signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    let (_persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let cancelled = Arc::new(AtomicBool::new(true));
    let durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let cancelled_result = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-cancel-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::clone(&cancelled),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(cancelled_result["ok"], false, "{cancelled_result}");
    assert_eq!(cancelled_result["code"], "cancelled", "{cancelled_result}");
    assert_eq!(durable.started(), 0, "cancelled call must not start");
    assert_eq!(durable.commits(), 0, "cancelled call must not commit");

    let expired = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-deadline-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 0,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(expired["ok"], false, "{expired}");
    assert_eq!(expired["code"], "deadline_elapsed", "{expired}");
    assert_eq!(durable.started(), 0, "expired call must not start");
    assert_eq!(durable.commits(), 0, "expired call must not commit");

    let fresh = NativeCase {
        workspace,
        pinned,
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(fresh["text"], "libA:hello", "positive control: {fresh}");
    assert_eq!(durable.started(), 1);
    assert_eq!(durable.commits(), 1);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn phase_a_native_boundary_keeps_original_workspace_root_and_owner() {
    let root = temp_root("f4-root");
    let (store, _signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    let (_persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let durable = NativeDurable::new("run-pin-a", json!({"path": "../outside.txt"}));
    let escaped = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-escape-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"../outside.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(escaped["ok"], false, "{escaped}");
    assert_eq!(escaped["code"], "path_denied", "{escaped}");
    assert_eq!(durable.commits(), 0);

    let inside_durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let inside = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&inside_durable),
    }
    .invoke();
    assert_eq!(inside["text"], "libA:hello", "{inside}");
    assert_eq!(inside_durable.commits(), 1);

    // The sealed receipt binds one owner/run; a sibling run cannot reuse it.
    let other_durable = NativeDurable::new("run-other", json!({"path": "note.txt"}));
    let other = NativeCase {
        workspace,
        pinned,
        run_id: "run-other".to_string(),
        call_id: "call-other-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&other_durable),
    }
    .invoke();
    assert_eq!(other["ok"], false, "{other}");
    assert_eq!(other["code"], "pinned_binding_mismatch", "{other}");
    assert_eq!(other_durable.started(), 0);
    assert_eq!(other_durable.commits(), 0);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn phase_a_native_commit_rejects_amplified_leaf_output_under_original_limit() {
    let root = temp_root("f4-amplified");
    let amplifying = "pub fn format(value: string) -> string {\n    let mut out: string = \"libA:\";\n    let mut i: int = 0;\n    while i < 400 {\n        out = out + value;\n        i = i + 1;\n    }\n    out\n}\n";
    let (store, _signer, lock_a) = install_phase_a_pair(&root, amplifying);
    let (_persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let amplified = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 256,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(amplified["ok"], false, "{amplified}");
    assert_eq!(amplified["code"], "result_too_large", "{amplified}");
    assert_eq!(durable.started(), 1, "the call was prepared before commit");
    assert_eq!(durable.commits(), 0, "amplified output must not commit");

    let permitted = NativeCase {
        workspace,
        pinned,
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-2".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: Arc::clone(&durable),
    }
    .invoke();
    assert_eq!(permitted["ok"], true, "{permitted}");
    assert!(
        permitted["text"].as_str().unwrap().len() > 256,
        "the leaf really amplified the output: {permitted}"
    );
    assert_eq!(durable.commits(), 1);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn phase_a_native_read_only_grant_denies_undeclared_write_and_process() {
    let root = temp_root("f4-undeclared");
    let (store, _signer, lock_a) = install_phase_a_pair(&root, phase_a_leaf_body());
    let (_persistence, workspace, pinned) = phase_a_open(&root, &store, &lock_a);
    let gate: Arc<dyn ApprovalGate> = Arc::new(GuardianApprovalGate::new(Arc::new(SystemClock), 8));
    let write_durable = NativeDurable::new("run-pin-a", json!({"path": "denied-write.txt"}));
    let write = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-write-1".to_string(),
        tool_name: "write_file".to_string(),
        arguments: "{\"path\":\"denied-write.txt\"}".to_string(),
        risk: "write",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::clone(&gate),
        durable: Arc::clone(&write_durable),
    }
    .invoke();
    assert_eq!(write["ok"], false, "{write}");
    assert_eq!(write["code"], "approval_denied", "{write}");
    assert_eq!(write_durable.started(), 0);
    assert_eq!(write_durable.commits(), 0);
    assert!(
        !workspace.join("denied-write.txt").exists(),
        "no write may reach the workspace"
    );

    let process_durable = NativeDurable::new("run-pin-a", json!({"command": "true"}));
    let process = NativeCase {
        workspace: workspace.clone(),
        pinned: pinned.clone(),
        run_id: "run-pin-a".to_string(),
        call_id: "call-process-1".to_string(),
        tool_name: "process".to_string(),
        arguments: "{\"command\":\"true\"}".to_string(),
        risk: "execute",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::clone(&gate),
        durable: Arc::clone(&process_durable),
    }
    .invoke();
    assert_eq!(process["ok"], false, "{process}");
    assert_eq!(process["code"], "approval_denied", "{process}");
    assert_eq!(process_durable.started(), 0);
    assert_eq!(process_durable.commits(), 0);

    let read_durable = NativeDurable::new("run-pin-a", json!({"path": "note.txt"}));
    let read = NativeCase {
        workspace,
        pinned,
        run_id: "run-pin-a".to_string(),
        call_id: "call-read-1".to_string(),
        tool_name: "read_file".to_string(),
        arguments: "{\"path\":\"note.txt\"}".to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: gate,
        durable: Arc::clone(&read_durable),
    }
    .invoke();
    assert_eq!(read["text"], "libA:hello", "read stays allowed: {read}");
    assert_eq!(read_durable.commits(), 1);
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// T07: the one admitted stateless caller→callee read topology, exercised
// through the real captured-lock, activate and pin admission path.
// ---------------------------------------------------------------------------

const T07_PIN_CALLER: &str = "org.rustscript.tools.t07pincaller";
const T07_PIN_CALLEE: &str = "org.rustscript.tools.t07pincallee";

fn t07_pin_catalog(tool: &str) -> String {
    format!(
        r#"pub fn managed_authority_catalog(context: map) -> map {{
    {{
        declarations: [{{ tool_name: "{tool}", operation: "workspace_read" }}],
        descriptors: [{{
            name: "{tool}",
            description: "t07 pin fixture descriptor",
            toolset: "coding",
            risk_class: "read",
            schema: {{ type: "object", properties: {{ path: {{ type: "string" }} }}, required: ["path"] }}
        }}]
    }}
}}
"#
    )
}

fn t07_pin_manifest(
    id: &str,
    delegated: bool,
    direct: bool,
    state: bool,
    extra_dependency: bool,
) -> String {
    let dependency = if delegated || extra_dependency {
        format!("dependencies:\n  - alias: child\n    id: {T07_PIN_CALLEE}\n    version: 1.0.0\n")
    } else {
        "dependencies: []\n".to_string()
    };
    let direct_block = if direct {
        "        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n"
    } else {
        ""
    };
    let delegated_block = if delegated {
        "      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n"
    } else {
        "      delegated: []\n"
    };
    let state_block = if state {
        "state:\n  scope: run\n  schema: 1\n"
    } else {
        ""
    };
    format!(
        "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\n{dependency}capabilities:\n  - workspace.read\n{state_block}effects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n{direct_block}{delegated_block}"
    )
}

const T07_PIN_CALLER_SOURCE: &str = "pub fn run(context: map) -> map { { ok: true, content: \"\", data: {}, error: null, truncated: false, artifacts: [] } }\n";

const T07_PIN_CALLEE_SOURCE: &str = r#"pub fn run(context: map) -> map {
    let meta: map = cap::fs_metadata("", "t07.txt");
    { ok: true, content: "", data: { meta_ok: meta["ok"] }, error: null, truncated: false, artifacts: [] }
}
"#;

fn t07_pin_install(
    root: &Path,
    signer: &Signer,
    caller_manifest: &str,
    callee_manifest: &str,
    callee_catalog: &str,
) -> PackageStore {
    let store = PackageStore::open(root.join("packages")).unwrap();
    let write = |name: &str, manifest: &str, source: &str, catalog: &str| {
        let package = root.join(name);
        fs::create_dir_all(&package).unwrap();
        fs::write(package.join("manifest.yaml"), manifest).unwrap();
        fs::write(package.join("run.rss"), source).unwrap();
        fs::write(package.join("catalog.rss"), catalog).unwrap();
    };
    write(
        "caller",
        caller_manifest,
        T07_PIN_CALLER_SOURCE,
        &t07_pin_catalog("read_file"),
    );
    write(
        "callee",
        callee_manifest,
        T07_PIN_CALLEE_SOURCE,
        callee_catalog,
    );
    for name in ["callee", "caller"] {
        let package = root.join(name);
        let signature = signer
            .pair
            .sign(&store.signature_payload(&package).unwrap());
        fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
        store.install(&package, &auth(signer)).unwrap();
    }
    store
}

fn t07_pin_resolve(store: &PackageStore) -> rustscript_agent::plugins::GraphLock {
    store
        .resolve(&rustscript_agent::plugins::ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: T07_PIN_CALLER.into(),
            },
            roots: vec![rustscript_agent::plugins::PackageRequirement {
                id: T07_PIN_CALLER.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: rustscript_agent::plugins::HOST_RUNTIME.into(),
        })
        .unwrap()
}

#[test]
fn t07_two_package_delegation_admits_both_captured_programs() {
    let root = temp_root("t07-pin-admit");
    let signer = signer();
    let store = t07_pin_install(
        &root,
        &signer,
        &t07_pin_manifest(T07_PIN_CALLER, true, true, false, false),
        &t07_pin_manifest(T07_PIN_CALLEE, false, true, false, false),
        &t07_pin_catalog("read_file"),
    );
    let lock = t07_pin_resolve(&store);
    let prepared = store
        .prepare(&lock)
        .expect("the two-package delegation graph must prepare");
    assert!(prepared.program(T07_PIN_CALLER).is_some());
    assert!(
        prepared.program(T07_PIN_CALLEE).is_some(),
        "the captured callee program must be retained beside the caller"
    );
    assert!(
        !Arc::ptr_eq(
            &prepared.program(T07_PIN_CALLER).unwrap(),
            &prepared.program(T07_PIN_CALLEE).unwrap()
        ),
        "caller and callee must be independent captured programs"
    );
    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    {
        let control = PluginControlStore::new(&persistence);
        control.store_lock(&lock).unwrap();
        control
            .activate(&lock.graph_id, 0, &lib_refs(&lock))
            .unwrap();
    }
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("t07.txt"), b"pin-admit").unwrap();
    let pinned = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-t07", "", ""),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation: None,
            registry_identity: "pin-tracer-registry".to_string(),
            workspace,
        },
    )
    .expect("the two-package delegation graph must admit a real sealed pin");
    let child = pinned
        .program_handle()
        .captured_child_identity()
        .expect("the sealed pin must carry the captured callee identity");
    assert_eq!(child.package_id, T07_PIN_CALLEE);
    assert_eq!(child.export, "run");
    assert_eq!(child.entry, "run");
    assert_eq!(child.edge_alias, "child");
    assert!(!child.artifact_id.is_empty());
    assert!(!child.registry_identity.is_empty());
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// T14 captured route table: a pinned program keeps the dispatch table captured
// with its own package. A and B are signed tool packages built from this
// worktree's `rss/tools` sources; B differs only in the single declared route
// for `read_file`, so the observable target identifies which captured table ran.
// ---------------------------------------------------------------------------

const ROUTE_PACKAGE_A: &str = "org.rustscript.tools.dispatchroutea";
const ROUTE_PACKAGE_B: &str = "org.rustscript.tools.dispatchrouteb";

fn dev_tool_source(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("rss/tools")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Entry boundary for a non-embedding captured package: the pinned host hands
/// this export `{prepare, arguments}`, and it forwards them unchanged into the
/// captured package's own `invoke_prepared`. No route is chosen here.
fn captured_route_adapter() -> &'static str {
    r#"
use self::dispatch::{invoke_prepared};
use self::types as types;

pub fn run(context: map) -> map {
    let prepare: map = types::map_map(context, "prepare");
    let arguments: map = types::map_map(context, "arguments");
    invoke_prepared({
        call: {
            name: types::map_string(prepare, "name", ""),
            id: types::map_string(prepare, "call_id", ""),
            arguments: arguments
        },
        prepared_context: {
            kind: "execute",
            prepare: prepare,
            arguments: arguments,
            config: {}
        }
    })
}
"#
}

fn captured_route_manifest(id: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: run.rss
  export: run
dependencies: []
capabilities:
  - clock.read
  - process.spawn
  - workspace.read
  - workspace.write
effects:
  contract: agent.effects/v1
  entries:
    run:
      direct:
        - kind: clock.read
          scope: bound_run
          recovery: none
        - kind: process.spawn
          scope: bound_process
          recovery: none
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
        - kind: workspace.fs.write
          scope: bound_workspace
          recovery: none
      delegated: []
"#
    )
}

fn install_captured_route_package(
    store: &PackageStore,
    signer: &Signer,
    dir: &Path,
    id: &str,
    dispatch_source: &str,
) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), captured_route_manifest(id)).unwrap();
    fs::write(dir.join("run.rss"), captured_route_adapter()).unwrap();
    fs::write(dir.join("dispatch.rss"), dispatch_source).unwrap();
    for name in [
        "types.rss",
        "read_file.rss",
        "search_files.rss",
        "write_file.rss",
        "patch.rss",
        "terminal.rss",
        "process.rss",
    ] {
        fs::write(dir.join(name), dev_tool_source(name)).unwrap();
    }
    let payload = store.signature_payload(dir).unwrap();
    fs::write(
        dir.join("signature.ed25519"),
        signer.pair.sign(&payload).as_ref(),
    )
    .unwrap();
    store.install(dir, &auth(signer)).unwrap();
}

fn route_case(
    workspace: &Path,
    pinned: &rustscript_agent::plugins::PinnedToolAdmission,
    run_id: &str,
    call_id: &str,
) -> Value {
    NativeCase {
        workspace: workspace.to_path_buf(),
        pinned: pinned.clone(),
        run_id: run_id.to_string(),
        call_id: call_id.to_string(),
        tool_name: "read_file".to_string(),
        arguments: json!({ "path": "note.txt" }).to_string(),
        risk: "read",
        deadline_ms: 9_000_000_000_000,
        max_output_bytes: 4096,
        cancelled: Arc::new(AtomicBool::new(false)),
        approval: Arc::new(AllowRead),
        durable: NativeDurable::new(run_id, json!({ "path": "note.txt" })),
    }
    .invoke()
}

#[test]
fn pinned_captured_route_table_stays_on_a_and_new_run_uses_b() {
    let root = temp_root("route-ab");
    let store = PackageStore::open(root.join("packages")).unwrap();
    let signer = signer();
    let dispatch_a = dev_tool_source("dispatch.rss");
    let routed_read = "{ name: \"read_file\", invoke: read_file_run }";
    let routed_search = "{ name: \"read_file\", invoke: search_files_run }";
    assert!(
        dispatch_a.contains(routed_read),
        "the captured dispatch source must declare read_file -> read_file_run"
    );
    let dispatch_b = dispatch_a.replace(routed_read, routed_search);
    assert_ne!(
        dispatch_b, dispatch_a,
        "B must carry a distinguishable captured route target"
    );
    install_captured_route_package(
        &store,
        &signer,
        &root.join("pkg-a"),
        ROUTE_PACKAGE_A,
        &dispatch_a,
    );
    install_captured_route_package(
        &store,
        &signer,
        &root.join("pkg-b"),
        ROUTE_PACKAGE_B,
        &dispatch_b,
    );

    let lock_a = resolve_tool_only(&store, ROUTE_PACKAGE_A);
    let lock_b = resolve_tool_only(&store, ROUTE_PACKAGE_B);
    assert_ne!(lock_a.graph_id, lock_b.graph_id);
    let program_a = store
        .prepare(&lock_a)
        .unwrap()
        .program(ROUTE_PACKAGE_A)
        .expect("A must retain its captured dispatch program");

    let db = root.join("state.db");
    let persistence = Arc::new(
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap(),
    );
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    control.store_lock(&lock_a).unwrap();
    control
        .activate(&lock_a.graph_id, 0, &lib_refs(&lock_a))
        .unwrap();

    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let file_bytes = b"route-table-bytes-from-a\n";
    fs::write(workspace.join("note.txt"), file_bytes).unwrap();
    let context = rustscript_agent::plugins::PinnedAdmitContext {
        original_cancellation: None,
        registry_identity: "pin-tracer-registry".to_string(),
        workspace: workspace.clone(),
    };
    let pinned_a = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-route-a", "route-key-a", "hash-a"),
        &context,
    )
    .expect("native admission must pin captured dispatch package A");
    assert_eq!(pinned_a.graph_id, lock_a.graph_id);
    assert!(pinned_a.shares_program(&program_a));

    let first = route_case(&workspace, &pinned_a, "run-route-a", "call-route-1");
    assert_eq!(first["ok"], json!(true), "A must serve read_file: {first}");
    assert_eq!(
        first["text"].as_str().unwrap_or("<missing>"),
        String::from_utf8_lossy(file_bytes),
        "A's captured table must reach the read_file module: {first}"
    );

    // A is admitted and has already executed; now prepare and activate B.
    let program_b = store
        .prepare(&lock_b)
        .unwrap()
        .program(ROUTE_PACKAGE_B)
        .expect("B must retain its captured dispatch program");
    assert!(!Arc::ptr_eq(&program_a, &program_b));
    control.store_lock(&lock_b).unwrap();
    control
        .activate(&lock_b.graph_id, 1, &lib_refs(&lock_b))
        .unwrap();
    assert_eq!(control.activation().unwrap().graph_id, lock_b.graph_id);

    let second = route_case(&workspace, &pinned_a, "run-route-a", "call-route-2");
    assert_eq!(
        second["ok"],
        json!(true),
        "the run pinned to A must keep A's route after B activation: {second}"
    );
    assert_eq!(
        second["text"].as_str().unwrap_or("<missing>"),
        String::from_utf8_lossy(file_bytes),
        "activating B must not retarget A's captured route table: {second}"
    );
    assert_eq!(
        second["code"],
        json!(""),
        "A's routed read must not report a module or route failure: {second}"
    );

    let pinned_b = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence,
        &store,
        &caller_json("run-route-b", "route-key-b", "hash-b"),
        &context,
    )
    .expect("a fresh run on the active graph must pin B");
    assert_eq!(pinned_b.graph_id, lock_b.graph_id);
    assert!(pinned_b.shares_program(&program_b));

    let from_b = route_case(&workspace, &pinned_b, "run-route-b", "call-route-3");
    assert_eq!(
        from_b["ok"],
        json!(false),
        "B's captured table routes read_file to the search_files module: {from_b}"
    );
    assert_eq!(
        from_b["code"],
        json!("invalid_arguments"),
        "B must execute its own captured route target: {from_b}"
    );
    assert!(
        from_b["message"]
            .as_str()
            .unwrap_or("")
            .contains("search_files requires pattern"),
        "B's result must come from the substituted route target: {from_b}"
    );
    assert_ne!(
        from_b["text"].as_str().unwrap_or(""),
        String::from_utf8_lossy(file_bytes),
        "a B run must not read through A's captured table: {from_b}"
    );
    let _ = fs::remove_dir_all(&root);
}
