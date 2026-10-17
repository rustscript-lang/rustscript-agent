//! Vertical tracer: admission pins a retained tool program, a typed child
//! bridge invokes it through the existing capability lease, and `read_file`
//! bytes come from that program. Activating another graph does not retarget
//! the already pinned run.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::capabilities::{
    ApprovalGate, CancellationFlag, CapabilityLifecycle, CapabilityOwner, CapabilityRisk,
    DurableStarted, DurableToolLifecycle, FilesystemCapability, FilesystemLimits, LifecycleError,
    LifecycleLimits, PrepareMetadata, SystemClock, UuidIssuer,
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
                let result: map = {{ ok: true, text: text }};
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {{
                    map_map(committed, "result")
                }} else => {{
                    result
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

struct MemoryDurable;

impl DurableToolLifecycle for MemoryDurable {
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
    fn commit_result(&self, call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
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
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.reada".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let lock_b = store
        .resolve(&ResolveRequest {
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
    let persistence =
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap();
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
        .durable(Arc::new(MemoryDurable))
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
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.reada".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let db = root.join("state.db");
    let persistence =
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap();
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
        .durable(Arc::new(MemoryDurable))
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
    fn commit_result(&self, call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
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
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.reada".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let lock_b = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.readb".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let db = root.join("state.db");
    let persistence =
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap();
    persistence.load().unwrap();
    let control = PluginControlStore::new(&persistence);
    activate(&control, &lock_a, 0);
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let context = rustscript_agent::plugins::PinnedAdmitContext {
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
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.lib".to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: "0.1.0".to_string(),
        })
        .unwrap();
    let db = root.join("state.db");
    let persistence =
        GatewayPersistence::open(&rustscript_agent::AgentGatewayConfig::default(), &db).unwrap();
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
