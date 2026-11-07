//! Production admission must pin the active signed graph, not the embedded default.
//!
//! The same caller arguments produce different file bytes when graph A or B is
//! active. A typed `graph_id` naming an inactive graph is rejected. Fields
//! inside the input message do not grant a graph. An already admitted run
//! keeps A's program after B is activated and after the service is reopened
//! against a fresh package store.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use hyper_util::rt::TokioExecutor;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::plugins::{
    GraphLock, HOST_RUNTIME, InstallAuthorization, PackageArtifactRef, PackageRequirement,
    PackageStore, PluginControlStore, PublisherKey, ResolveRequest,
};
use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, ScriptedProvider,
    build_agent_gateway_app,
};
use serde_json::{Value, json};

fn temp_root(label: &str) -> PathBuf {
    let base = std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = PathBuf::from(base).join(format!(
        "pin-prod-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
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
                let result: map = {{ ok: true, content: text, data: {{}}, error: null, truncated: false, artifacts: [] }};
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {{
                    map_map(committed, "result")
                }} else if map_bool(committed, "ok", false) == false => {{
                    committed
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

fn lib_manifest(id: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: library
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: format.rss
  export: format
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    format:
      direct: []
      delegated: []
"#
    )
}

fn lib_tool_manifest(id: &str, lib_id: &str) -> String {
    manifest(id).replace(
        "dependencies: []\n",
        &format!("dependencies:\n  - alias: text\n    id: {lib_id}\n    version: \"1.0.0\"\n"),
    )
}

/// Same file-read tool as `tool_source`, but linked against the fixture
/// pure leaf through the `text` alias so the narrow revoke topology
/// applies. The leaf is the identity, so delivered bytes are unchanged.
fn lib_tool_source(offset: i64) -> String {
    tool_source(offset)
        .replace(
            "\nfn map_string(",
            "\nuse text::{format};\nfn map_string(",
        )
        .replace(
            "let result: map = { ok: true, content: text,",
            "let labeled: string = format(text);\n                let result: map = { ok: true, content: labeled,",
        )
}

fn install_library(store: &PackageStore, signer: &Signer, dir: &Path, id: &str, body: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), lib_manifest(id)).unwrap();
    fs::write(dir.join("format.rss"), body).unwrap();
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer)).unwrap();
}

fn install_lib_tool(
    store: &PackageStore,
    signer: &Signer,
    dir: &Path,
    id: &str,
    lib: &str,
    offset: i64,
) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), lib_tool_manifest(id, lib)).unwrap();
    fs::write(dir.join("run.rss"), lib_tool_source(offset)).unwrap();
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer)).unwrap();
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

fn resolve_tool(store: &PackageStore, id: &str) -> GraphLock {
    store
        .resolve(&ResolveRequest {
            harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: id.to_string(),
            },
            roots: vec![PackageRequirement {
                id: id.to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: HOST_RUNTIME.to_string(),
        })
        .unwrap_or_else(|error| panic!("resolve {id}: {error}"))
}

fn artifact_refs(lock: &GraphLock) -> Vec<PackageArtifactRef> {
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

/// Signed tool graph A at the Service layer: revoking the exact admitted
/// graph after admission refuses the worker execution with the exact typed
/// code and never executes the recovered program. The unrevoked positive
/// path stays covered by the production cold-restore test above.
#[tokio::test(flavor = "multi_thread")]
async fn production_signed_a_revoke_denies_worker_execution_before_begin() {
    let root = temp_root("ab-revoke");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    install_library(
        &store,
        &signer,
        &root.join("lib-a"),
        "org.rustscript.lib.abtext",
        "pub fn format(value: string) -> string { value }\n",
    );
    install_lib_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.prodab",
        "org.rustscript.lib.abtext",
        0,
    );
    let lock_a = resolve_tool(&store, "org.rustscript.tools.prodab");
    assert_eq!(
        lock_a.packages.len(),
        2,
        "the fixture graph must be the narrow tool-plus-leaf shape"
    );
    let (home, _workspace) = workspace_home(&root);
    let db = root.join("state.db");
    let state = open_gateway(&db, &home, Arc::clone(&store));
    let persistence = state.persistence().expect("sqlite persistence");
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&lock_a).unwrap();
    let activated = control
        .activate(&lock_a.graph_id, 0, &artifact_refs(&lock_a))
        .unwrap();
    assert_ne!(
        activated.generation, 0,
        "bootstrap CAS must not leave generation 0"
    );

    let provider = ScriptedProvider::new();
    queue_read(&provider, "call-a");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({
                    "message": "read note",
                    "graph_id": lock_a.graph_id,
                    "tool_graph_id": lock_a.graph_id
                }),
                idempotency_key: Some("signed-ab-key".to_string()),
                idempotency_hash: Some("fnv64:0000000000000001".to_string()),
                graph_id: None,
                workspace_branch: None,
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("admit signed A");
    assert_eq!(
        control.pin_for_run(&admitted.run_id).unwrap()["graph_id"],
        lock_a.graph_id,
        "the run must be admitted on the signed graph A"
    );

    // Same-control-store revocation of the exact admitted graph through the
    // narrow public topology, before the worker begins the sealed tool.
    PluginControlStore::new(persistence.as_ref())
        .revoke_graph(store.as_ref(), &lock_a.graph_id)
        .expect("signed graph A revokes through the narrow topology");
    assert!(
        PluginControlStore::new(persistence.as_ref())
            .graph_revocation(&lock_a.graph_id)
            .unwrap()
            .is_some(),
        "the revocation must be durably visible before the worker begins"
    );

    state
        .service()
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let events = state.service().run_events(&admitted.run_id);
    assert!(
        !events
            .iter()
            .any(|event| event["event"] == "tool.completed"),
        "a revoked signed graph must not complete the sealed call: {events:?}"
    );
    assert!(
        !events.iter().any(|event| event["event"] == "run.completed"),
        "a revoked signed run must not complete: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event.to_string().contains("plugin_graph_revoked")),
        "the refusal must be the exact typed graph revocation: {events:?}"
    );
    assert!(
        !observed_text(
            state.service().as_ref(),
            &admitted.run_id,
            &admitted.session_id,
        )
        .contains("AB-marker-bytes"),
        "the revoked leaf must never deliver its labeled bytes"
    );
    // The supported executable ToolOnly restore path refuses the revoked
    // graph as well instead of producing a runnable binding.
    assert!(
        rustscript_agent::plugins::restore_owned_pin(&persistence, &store, &admitted.run_id)
            .is_err_and(|error| error.code == "plugin_graph_revoked"),
        "restoring a revoked signed pin must refuse with the revocation code"
    );
    state.service().shutdown().await.unwrap();
    let _ = fs::remove_dir_all(&root);
}

fn workspace_home(root: &Path) -> (PathBuf, PathBuf) {
    let home = root.join("workspace-home");
    let workspace = root.join("workspace");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&workspace).unwrap();
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    fs::write(home.join("config.yaml"), config).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [root, &home, &workspace] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(workspace.join("note.txt"), b"AB-marker-bytes\n").unwrap();
    (home, workspace)
}

fn tool_response(call_id: &str) -> Value {
    json!({
        "text": "",
        "tool_calls": [{
            "id": call_id,
            "name": "read_file",
            "arguments": {"path": "note.txt"}
        }],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    })
}

fn text_response(text: &str) -> Value {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

fn queue_read(provider: &ScriptedProvider, call_id: &str) {
    provider.push_ok(tool_response(call_id));
    provider.push_ok(text_response("done"));
}

fn observed_text(
    service: &rustscript_agent::AgentService,
    run_id: &str,
    session_id: &str,
) -> String {
    let events = serde_json::to_string(&service.run_events(run_id)).unwrap_or_default();
    let messages = serde_json::to_string(&service.session_messages(session_id)).unwrap_or_default();
    format!("{events}\n{messages}")
}

fn open_gateway(db: &Path, home: &Path, store: Arc<PackageStore>) -> AgentGatewayState {
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), db)
        .expect("sqlite gateway")
        .with_workspace_home(home);
    state
        .service()
        .install_validated_tool_store(store)
        .expect("validated tool store");
    state
}

#[tokio::test(flavor = "multi_thread")]
async fn production_signed_a_survives_activation_of_b_and_reopen() {
    let root = temp_root("ab");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.proda",
        0,
    );
    install_tool(
        &store,
        &signer,
        &root.join("pkg-b"),
        "org.rustscript.tools.prodb",
        1,
    );
    let lock_a = resolve_tool(&store, "org.rustscript.tools.proda");
    let lock_b = resolve_tool(&store, "org.rustscript.tools.prodb");
    let (home, workspace) = workspace_home(&root);
    let db = root.join("state.db");
    let state = open_gateway(&db, &home, Arc::clone(&store));
    let persistence = state.persistence().expect("sqlite persistence");
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&lock_a).unwrap();
    control.store_lock(&lock_b).unwrap();
    let activated = control
        .activate(&lock_a.graph_id, 0, &artifact_refs(&lock_a))
        .unwrap();
    assert_ne!(
        activated.generation, 0,
        "bootstrap CAS must not leave generation 0"
    );

    let provider = ScriptedProvider::new();
    queue_read(&provider, "call-a");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({
                    "message": "read note",
                    "graph_id": lock_b.graph_id,
                    "tool_graph_id": lock_b.graph_id
                }),
                idempotency_key: Some("signed-a-key".to_string()),
                idempotency_hash: Some("fnv64:0000000000000001".to_string()),
                graph_id: None,
                workspace_branch: None,
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("admit A");
    let original_receipt = control.pin_for_run(&admitted.run_id).unwrap();
    assert_eq!(original_receipt["graph_id"], lock_a.graph_id);
    assert_eq!(original_receipt["generation"], activated.generation);
    state.service().evict_run_handle(&admitted.run_id);
    let next = control
        .activate(
            &lock_b.graph_id,
            activated.generation,
            &artifact_refs(&lock_b),
        )
        .unwrap();
    assert_ne!(next.graph_id, lock_a.graph_id);

    state
        .service()
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let restored = observed_text(
        state.service().as_ref(),
        &admitted.run_id,
        &admitted.session_id,
    );
    assert!(
        restored.contains("AB-marker-bytes"),
        "restored run must execute signed A, not the default or B: {restored}"
    );
    assert!(
        !restored.contains("B-marker-bytes\n") || restored.contains("AB-marker-bytes"),
        "A bytes must remain distinguishable: {restored}"
    );

    queue_read(&provider, "call-b");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let admitted_b = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({
                    "message": "read note",
                    "graph_id": lock_a.graph_id
                }),
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("admit B");
    state
        .service()
        .clone()
        .run_worker(admitted_b.run_id.clone(), "ignored".to_string())
        .await;
    let current = observed_text(
        state.service().as_ref(),
        &admitted_b.run_id,
        &admitted_b.session_id,
    );
    assert!(
        current.contains("B-marker-bytes"),
        "new run must execute signed B: {current}"
    );
    assert!(
        !current.contains("AB-marker-bytes"),
        "B must not emit A's offset: {current}"
    );

    let replay_request = AdmitRunRequest {
        input: json!({ "message":"read note", "graph_id":lock_b.graph_id, "tool_graph_id":lock_b.graph_id }),
        idempotency_key: Some("signed-a-key".to_string()),
        idempotency_hash: Some("fnv64:0000000000000001".to_string()),
        graph_id: None,
        workspace_branch: None,
        platform: "tools_pin_production_ab".to_string(),
        ..Default::default()
    };
    let before_replay = state.service().run_events(&admitted.run_id).len();
    let replay = state
        .service()
        .admit_external_with_workspace_selector(
            replay_request.clone(),
            Some("name:lifecycle".to_string()),
        )
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.run_id, admitted.run_id);
    assert_eq!(
        control.pin_for_run(&admitted.run_id).unwrap(),
        original_receipt
    );
    assert_eq!(
        state.service().run_events(&admitted.run_id).len(),
        before_replay
    );
    let receipt_b = control.pin_for_run(&admitted_b.run_id).unwrap();
    drop(state);
    drop(persistence);
    // Reopen the original installed artifacts with a cold verification cache.
    // Damage unrelated active B: restoring A must read only A's required capture.
    fs::write(
        root.join("packages/artifacts")
            .join(&lock_b.packages[0].artifact_id)
            .join("sources/run.rss"),
        "damaged unrelated B",
    )
    .unwrap();
    let fresh = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    fresh.bind_policy(&auth(&signer));
    let reopened = open_gateway(&db, &home, Arc::clone(&fresh));
    let persistence = reopened.persistence().unwrap();
    let control = PluginControlStore::new(persistence.as_ref());
    assert_eq!(
        control.pin_for_run(&admitted.run_id).unwrap(),
        original_receipt
    );
    let event_count = reopened.service().run_events(&admitted.run_id).len();
    let replayed = reopened
        .service()
        .admit_external_with_workspace_selector(
            replay_request.clone(),
            Some("name:lifecycle".to_string()),
        )
        .await
        .unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.run_id, admitted.run_id);
    assert_eq!(
        control.pin_for_run(&admitted.run_id).unwrap(),
        original_receipt
    );
    assert_eq!(
        reopened.service().run_events(&admitted.run_id).len(),
        event_count
    );
    // Execute the recovered actual A Program in a fresh Native adapter with
    // fixture-owned original parent facts, rather than asserting old history.
    let binding =
        rustscript_agent::plugins::restore_owned_pin(&persistence, &fresh, &admitted.run_id)
            .unwrap();
    let durable = Arc::new(ParentFacts {
        arguments: json!({"path":"note.txt"}),
        started: 0.into(),
        committed: 0.into(),
    });
    let result = invoke_original(
        rustscript_agent::AgentHostBridges {
            pinned_tool: Some(binding),
            ..Default::default()
        },
        &original_receipt,
        &workspace,
        json!({"path":"note.txt"}),
        Arc::clone(&durable),
    );
    assert_eq!(result["ok"], true, "cold original A must execute: {result}");
    assert_eq!(result["content"], "AB-marker-bytes\n");
    assert_eq!(durable.started.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        durable.committed.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let mut displayed = rustscript_agent::plugins::admit_pinned_tool_run(
        &persistence, &fresh,
        &json!({"idempotency_scope":"api:chat", "idempotency_key":"signed-a-key", "request_hash":"fnv64:0000000000000001", "workspace_identity_json":json!({"request_selector_present":true,"request_selector":"name:lifecycle"}).to_string()}),
        &rustscript_agent::plugins::PinnedAdmitContext {
            original_cancellation:None, registry_identity:"ignored-replay-context".to_string(), workspace:workspace.clone() },
    ).unwrap();
    displayed.graph_id = lock_b.graph_id.clone();
    displayed.generation = next.generation;
    displayed.ref_id = receipt_b["ref_id"].as_str().unwrap().to_string();
    displayed.run_id = admitted_b.run_id.clone();
    displayed.session_id = admitted_b.session_id.clone();
    displayed.profile = receipt_b["profile"].as_str().unwrap().to_string();
    displayed.entry = "forged-entry".to_string();
    let counts = Arc::new(ParentFacts {
        arguments: json!({"path":"note.txt"}),
        started: 0.into(),
        committed: 0.into(),
    });
    let rejected = invoke_original(
        rustscript_agent::AgentHostBridges {
            pinned_tool: Some(displayed.program_handle()),
            ..Default::default()
        },
        &receipt_b,
        &workspace,
        json!({"path":"note.txt"}),
        Arc::clone(&counts),
    );
    assert_eq!(rejected["ok"], false, "display edits cannot relabel A as B");
    assert_eq!(counts.started.load(std::sync::atomic::Ordering::SeqCst), 0);
    let original = invoke_original(
        rustscript_agent::AgentHostBridges {
            pinned_tool: Some(displayed.program_handle()),
            ..Default::default()
        },
        &original_receipt,
        &workspace,
        json!({"path":"note.txt"}),
        Arc::clone(&counts),
    );
    assert_eq!(
        original["content"], "AB-marker-bytes\n",
        "display edits cannot alter original A binding"
    );
    let source_a = root
        .join("packages/artifacts")
        .join(&lock_a.packages[0].artifact_id)
        .join("sources/run.rss");
    let saved_source = fs::read(&source_a).unwrap();
    // Snapshot the original receipt-only history through the existing typed
    // accessors before damaging the on-disk capture. The receipt and the event
    // history survive revocation/damage; neither is execution permission.
    let original_events = reopened.service().run_events(&admitted.run_id);
    assert_eq!(original_events.len(), event_count);
    let original_handles = reopened.service().handle_count();
    let original_pending = reopened.service().pending_terminal_count();
    let original_refs = control.retained(&lock_a.graph_id).unwrap();
    let original_started = durable.started.load(std::sync::atomic::Ordering::SeqCst);
    let original_committed = durable.committed.load(std::sync::atomic::Ordering::SeqCst);
    let counting_started = counts.started.load(std::sync::atomic::Ordering::SeqCst);
    let counting_committed = counts.committed.load(std::sync::atomic::Ordering::SeqCst);
    for (damage, replacement) in [
        ("missing", None),
        (
            "substituted",
            Some("pub fn run(context: map) -> map { { ok: true } }"),
        ),
    ] {
        match replacement {
            None => fs::remove_file(&source_a).unwrap(),
            Some(source) => fs::write(&source_a, source).unwrap(),
        }
        // Every damage shape gets its own cold store. The service installs a
        // clone so the official restore below runs against this exact cold
        // snapshot, never the previous warm `fresh` store or loaded Program.
        let cold = Arc::new(PackageStore::open(root.join("packages")).unwrap());
        cold.bind_policy(&auth(&signer));
        reopened
            .service()
            .install_validated_tool_store(Arc::clone(&cold))
            .unwrap();
        let history = reopened
            .service()
            .admit_external_with_workspace_selector(
                replay_request.clone(),
                Some("name:lifecycle".to_string()),
            )
            .await;
        let refusal = rustscript_agent::plugins::restore_owned_pin(
            &persistence,
            cold.as_ref(),
            &admitted.run_id,
        );
        let receipt_after = control.pin_for_run(&admitted.run_id).unwrap();
        let events_after = reopened.service().run_events(&admitted.run_id);
        let handles_after = reopened.service().handle_count();
        let pending_after = reopened.service().pending_terminal_count();
        let refs_after = control.retained(&lock_a.graph_id).unwrap();
        let started_after = durable.started.load(std::sync::atomic::Ordering::SeqCst);
        let committed_after = durable.committed.load(std::sync::atomic::Ordering::SeqCst);
        let counting_started_after = counts.started.load(std::sync::atomic::Ordering::SeqCst);
        let counting_committed_after = counts.committed.load(std::sync::atomic::Ordering::SeqCst);
        // Restore the fixture-owned capture before any fallible assertion so a
        // failed round cannot poison the next one or the final cleanup.
        fs::write(&source_a, &saved_source).unwrap();
        println!(
            "PRODUCTION_AB_COLD_REFUSAL {}",
            json!({
                "damage": damage,
                "restore_code": refusal.as_ref().err().map(|error| error.code),
                "history_replayed": history.as_ref().map(|run| run.replayed).unwrap_or(false),
            })
        );
        assert!(
            refusal.is_err(),
            "{damage}: cold executable restore must refuse without a runnable binding"
        );
        let history = match history {
            Ok(history) => history,
            Err(error) => {
                panic!("{damage}: original history replay must stay readable: {error:?}")
            }
        };
        assert!(history.replayed, "{damage}: history query must be a replay");
        assert_eq!(history.run_id, replayed.run_id, "{damage}: run identity");
        assert_eq!(
            history.session_id, replayed.session_id,
            "{damage}: session identity"
        );
        assert_eq!(history.status, replayed.status, "{damage}: terminal status");
        assert_eq!(
            receipt_after, original_receipt,
            "{damage}: pin receipt changed"
        );
        assert_eq!(
            events_after, original_events,
            "{damage}: history events changed"
        );
        assert_eq!(
            events_after.len(),
            event_count,
            "{damage}: event count changed"
        );
        assert_eq!(
            handles_after, original_handles,
            "{damage}: extra run handle"
        );
        assert_eq!(
            pending_after, original_pending,
            "{damage}: extra pending terminal"
        );
        assert_eq!(refs_after, original_refs, "{damage}: extra graph ref");
        assert_eq!(started_after, original_started, "{damage}: extra started");
        assert_eq!(
            committed_after, original_committed,
            "{damage}: extra committed"
        );
        assert_eq!(
            counting_started_after, counting_started,
            "{damage}: extra counted start"
        );
        assert_eq!(
            counting_committed_after, counting_committed,
            "{damage}: extra counted commit"
        );
    }
    let restored_store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    restored_store.bind_policy(&auth(&signer));
    reopened
        .service()
        .install_validated_tool_store(restored_store)
        .unwrap();
    println!(
        "PRODUCTION_COLD_RECOVERY {}",
        json!({"original_receipt":original_receipt,"restored_result":result,"started":durable.started.load(std::sync::atomic::Ordering::SeqCst),"committed":durable.committed.load(std::sync::atomic::Ordering::SeqCst)})
    );
    // Replacing a ref for the same owner cannot replace its original receipt.
    let original_ref = rustscript_agent::plugins::GraphRetention {
        graph_id: lock_a.graph_id.clone(),
        owner_kind: "run".to_string(),
        owner_id: admitted.run_id.clone(),
        ref_id: original_receipt["ref_id"].as_str().unwrap().to_string(),
    };
    control.release(&original_ref).unwrap();
    control
        .retain(&rustscript_agent::plugins::GraphRetention {
            ref_id: "replacement-ref".to_string(),
            ..original_ref
        })
        .unwrap();
    let rejected = reopened
        .service()
        .admit_external_with_workspace_selector(replay_request, Some("name:lifecycle".to_string()))
        .await;
    assert!(
        rejected.is_err(),
        "released original ref must reject service replay"
    );
    assert_eq!(
        reopened.service().run_events(&admitted.run_id).len(),
        event_count
    );
}

/// Session deletion releases only its own run refs in the original RSS cascade.
/// Completion alone retains a pin; unrelated sessions, owner kinds and active
/// deployment each independently protect their graph from collection.
#[tokio::test(flavor = "multi_thread")]
async fn session_delete_releases_native_run_refs_without_collecting_other_owners() {
    use rustscript_agent::plugins::GraphRetention;

    let root = temp_root("session-retention");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    for (label, offset) in [("reta", 0), ("retb", 1)] {
        install_tool(
            &store,
            &signer,
            &root.join(label),
            &format!("org.rustscript.tools.{label}"),
            offset,
        );
    }
    let a = resolve_tool(&store, "org.rustscript.tools.reta");
    let b = resolve_tool(&store, "org.rustscript.tools.retb");
    let (home, _) = workspace_home(&root);
    let state = open_gateway(&root.join("state.db"), &home, Arc::clone(&store));
    let persistence = state.persistence().unwrap();
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&a).unwrap();
    control.store_lock(&b).unwrap();
    let active = control
        .activate(&a.graph_id, 0, &artifact_refs(&a))
        .unwrap();
    let provider = ScriptedProvider::new();
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));

    // Two completed runs in the deleted session, plus a still-live A run in
    // another session. Every pin is produced by normal Native admission.
    let mut completed = Vec::<rustscript_agent::AdmittedRun>::new();
    for call in ["ret-first", "ret-second"] {
        queue_read(&provider, call);
        state
            .service()
            .inject_provider_host(Arc::new(provider.clone()));
        let run = state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    session_id: completed.first().map(|run| run.session_id.clone()),
                    input: json!({"message":"read note"}),
                    ..Default::default()
                },
                Some("name:lifecycle".to_string()),
            )
            .await
            .unwrap();
        state
            .service()
            .clone()
            .run_worker(run.run_id.clone(), "ignored".to_string())
            .await;
        assert!(
            observed_text(state.service().as_ref(), &run.run_id, &run.session_id)
                .contains("AB-marker-bytes")
        );
        assert_eq!(
            control.pin_for_run(&run.run_id).unwrap()["graph_id"],
            a.graph_id
        );
        assert!(
            state
                .service()
                .run_events(&run.run_id)
                .iter()
                .any(|event| event["event"] == "tool.completed")
        );
        completed.push(run);
    }
    let live = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"read note"}),
                ..Default::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .unwrap();
    assert_ne!(live.session_id, completed[0].session_id);
    let live_receipt = control.pin_for_run(&live.run_id).unwrap();
    assert_eq!(live_receipt["graph_id"], a.graph_id);
    assert_eq!(control.retained(&a.graph_id).unwrap().len(), 3);

    // Same owner id, different owner kind: session deletion must preserve it.
    let checkpoint = GraphRetention {
        graph_id: a.graph_id.clone(),
        owner_kind: "checkpoint".to_string(),
        owner_id: completed[0].run_id.clone(),
        ref_id: "ret-checkpoint".to_string(),
    };
    control.retain(&checkpoint).unwrap();
    control
        .activate(&b.graph_id, active.generation, &artifact_refs(&b))
        .unwrap();
    assert!(control.collect_unreferenced().unwrap().is_empty());
    assert!(control.load_lock(&a.graph_id).is_ok());

    persistence
        .session_delete(&completed[0].session_id)
        .unwrap();
    assert_eq!(
        persistence
            .session_delete(&completed[0].session_id)
            .unwrap_err()
            .code,
        "session_not_found"
    );
    for run in &completed {
        assert!(
            persistence.run_get(&run.run_id).unwrap()["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let missing = control.pin_for_run(&run.run_id).unwrap();
        assert_eq!(missing["pinned"], false, "deleted pin receipt must be gone");
        assert_eq!(missing["ref_id"], "");
        assert!(
            rustscript_agent::plugins::restore_owned_pin(&persistence, &store, &run.run_id)
                .is_err()
        );
    }
    assert!(
        persistence
            .message_list(&completed[0].session_id, 0)
            .unwrap()["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let after_first_delete = control.retained(&a.graph_id).unwrap();
    assert!(after_first_delete.contains(&checkpoint));
    assert_eq!(control.pin_for_run(&live.run_id).unwrap(), live_receipt);
    assert!(control.collect_unreferenced().unwrap().is_empty());

    // Isolate the other session's run as the only legitimate A owner. It can
    // still execute the original A after B activation and the first deletion.
    control.release(&checkpoint).unwrap();
    assert!(control.collect_unreferenced().unwrap().is_empty());
    queue_read(&provider, "ret-live");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
        .service()
        .clone()
        .run_worker(live.run_id.clone(), "ignored".to_string())
        .await;
    let live_observed = observed_text(state.service().as_ref(), &live.run_id, &live.session_id);
    assert!(
        live_observed.contains("AB-marker-bytes"),
        "live A result: {live_observed}"
    );
    assert_eq!(control.pin_for_run(&live.run_id).unwrap(), live_receipt);

    // Independently isolate the other owner kind, with no surviving A run.
    control.retain(&checkpoint).unwrap();
    persistence.session_delete(&live.session_id).unwrap();
    assert_eq!(control.pin_for_run(&live.run_id).unwrap()["pinned"], false);
    assert!(control.retained(&a.graph_id).unwrap().contains(&checkpoint));
    assert!(control.collect_unreferenced().unwrap().is_empty());
    control.release(&checkpoint).unwrap();
    let collected = control.collect_unreferenced().unwrap();
    assert_eq!(
        collected,
        vec![a.graph_id.clone()],
        "RET-A-001: deleted sessions must no longer pin old A"
    );
    assert!(control.load_lock(&a.graph_id).is_err());
    assert!(control.retained(&a.graph_id).unwrap().is_empty());
    assert_eq!(
        after_first_delete.len(),
        2,
        "only live A run and checkpoint may survive the first deletion"
    );
    assert_eq!(
        control.load_lock(&b.graph_id).unwrap().lock.graph_id,
        b.graph_id
    );
    assert_eq!(control.activation().unwrap().graph_id, b.graph_id);
    assert!(
        control.retained(&b.graph_id).unwrap().is_empty(),
        "active B alone protects its lock"
    );

    // B remains executable after A has actually been collected.
    queue_read(&provider, "ret-b");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let run_b = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"read note"}),
                ..Default::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .unwrap();
    state
        .service()
        .clone()
        .run_worker(run_b.run_id.clone(), "ignored".to_string())
        .await;
    let result_b = observed_text(state.service().as_ref(), &run_b.run_id, &run_b.session_id);
    assert!(result_b.contains("B-marker-bytes"));
    assert!(!result_b.contains("AB-marker-bytes"));

    // Empty sessions have neither Native receipts nor refs. The session row
    // result, not either preceding delete result, determines existence.
    persistence
        .session_create(&json!({
            "id":"ret-empty", "profile":"default", "platform":"test",
            "account_id":"empty", "chat_id":"empty", "thread_id":"", "user_id":"",
            "generation":1, "system_prompt":"", "model":"test", "provider":"test",
            "toolset_hash":"", "metadata_json":"{}", "title":"", "end_reason":"", "now_ms":1,
        }))
        .unwrap();
    persistence
        .session_delete("ret-empty")
        .expect("empty existing session must delete successfully");
    assert_eq!(
        persistence.session_delete("ret-empty").unwrap_err().code,
        "session_not_found"
    );
    assert_eq!(
        control.pin_for_run(&run_b.run_id).unwrap()["graph_id"],
        b.graph_id
    );
    println!(
        "RET_A_001 collected_old_a=true completed_runs=2 other_session_executed_a=true checkpoint_preserved=true active_b_executed=true deleted_receipts_absent=true empty_session_delete=true"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_explicit_inactive_graph_is_rejected_and_selected_graph_emits_native_bytes() {
    let root = temp_root("http");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.httpa",
        0,
    );
    install_tool(
        &store,
        &signer,
        &root.join("pkg-b"),
        "org.rustscript.tools.httpb",
        1,
    );
    let lock_a = resolve_tool(&store, "org.rustscript.tools.httpa");
    let lock_b = resolve_tool(&store, "org.rustscript.tools.httpb");
    let (home, _workspace) = workspace_home(&root);
    let db = root.join("state.db");
    let state = open_gateway(&db, &home, Arc::clone(&store));
    let persistence = state.persistence().expect("sqlite persistence");
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&lock_a).unwrap();
    control.store_lock(&lock_b).unwrap();
    control
        .activate(&lock_a.graph_id, 0, &artifact_refs(&lock_a))
        .unwrap();
    let provider = ScriptedProvider::new();
    queue_read(&provider, "http-a");
    queue_read(&provider, "http-b");
    state.service().inject_provider_host(Arc::new(provider));
    let router = build_agent_gateway_app(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let (status, created) = json_request(
        &app,
        "POST",
        "/api/sessions",
        json!({"source": "yahu", "model": "local-agent"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let session_id = created["session"]["id"]
        .as_str()
        .expect("session")
        .to_string();

    let handles_before = state.service().handle_count();
    let retained_a = control.retained(&lock_a.graph_id).unwrap();
    let retained_b = control.retained(&lock_b.graph_id).unwrap();
    let (_, messages_before) = json_request(
        &app,
        "GET",
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    let (status, denied_b) = json_request(
        &app,
        "POST",
        "/v1/runs",
        json!({
            "session_id": session_id,
            "input": {
                "message": "read note",
                "graph_id": lock_a.graph_id,
                "tool_graph_id": lock_a.graph_id
            },
            "workspace": "name:lifecycle",
            "graph_id": lock_b.graph_id,
            "tool_graph_id": lock_a.graph_id
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{denied_b}");
    assert_ne!(status, StatusCode::ACCEPTED);
    assert_eq!(denied_b["error"]["code"], "plugin_graph_pin_required");
    assert!(denied_b.get("run_id").is_none(), "{denied_b}");
    for key in ["effect", "handle", "graph_ref", "graph_id", "ref_id"] {
        assert!(
            denied_b.get(key).is_none(),
            "{key} partial write: {denied_b}"
        );
    }
    assert_eq!(
        state.service().handle_count(),
        handles_before,
        "inactive explicit graph must not publish a handle"
    );
    assert_eq!(
        control.retained(&lock_a.graph_id).unwrap(),
        retained_a,
        "inactive explicit graph must not write a graph ref"
    );
    assert_eq!(control.retained(&lock_b.graph_id).unwrap(), retained_b);
    let (_, messages_denied) = json_request(
        &app,
        "GET",
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    assert_eq!(
        messages_denied, messages_before,
        "inactive explicit graph must not write a run or effect"
    );
    assert_eq!(control.activation().unwrap().graph_id, lock_a.graph_id);

    let (status, run_a) = json_request(
        &app,
        "POST",
        "/v1/runs",
        json!({
            "session_id": session_id,
            "input": {
                "message": "read note",
                "graph_id": lock_b.graph_id,
                "tool_graph_id": lock_b.graph_id
            },
            "workspace": "name:lifecycle",
            "graph_id": lock_a.graph_id,
            "tool_graph_id": lock_b.graph_id
        }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run_a}");
    assert_ne!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let run_a_id = run_a["run_id"].as_str().expect("run a").to_string();
    let active_a = control.activation().unwrap();
    let pin_a = control.pin_for_run(&run_a_id).unwrap();
    assert_eq!(pin_a["pinned"], true);
    assert_eq!(pin_a["graph_id"], lock_a.graph_id);
    assert_eq!(pin_a["graph_id"], run_a["graph_id"]);
    assert_eq!(pin_a["graph_id"], active_a.graph_id);
    assert_eq!(pin_a["generation"], active_a.generation);
    assert_eq!(pin_a["run_id"], run_a_id);
    let registry_a = pin_a["registry_identity"].as_str().expect("registry");
    assert!(!registry_a.is_empty());
    assert_ne!(registry_a, lock_a.graph_id);
    assert_ne!(registry_a, lock_b.graph_id);
    let handle_a = state.service().handle(&run_a_id).expect("admitted handle");
    assert!(
        handle_a.cancellation().deadline_instant().is_some(),
        "admission keeps the original clock"
    );
    let events_a = sse_body(&app, &run_a_id).await;
    assert!(events_a.contains("tool.completed"), "tool must commit");
    assert!(events_a.contains("run.completed"), "{events_a}");
    assert!(!events_a.contains("run.cancelled"), "{events_a}");
    let (_, messages_a) = json_request(
        &app,
        "GET",
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    let body_a = messages_a.to_string();
    assert!(
        body_a.contains("AB-marker-bytes"),
        "HTTP run must emit signed A bytes: {body_a}"
    );
    assert!(
        control
            .retained(&lock_a.graph_id)
            .unwrap()
            .iter()
            .any(|reference| {
                reference.owner_kind == "run"
                    && reference.owner_id == run_a_id
                    && !reference.ref_id.is_empty()
            }),
        "selected A must retain its run graph ref"
    );
    assert!(
        !control
            .retained(&lock_b.graph_id)
            .unwrap()
            .iter()
            .any(|reference| reference.owner_id == run_a_id),
        "message graph_id must not retain B for run A"
    );

    assert_eq!(control.pin_for_run(&run_a_id).unwrap(), pin_a);
    let handles_after_a = state.service().handle_count();
    let retained_a_after = control.retained(&lock_a.graph_id).unwrap();
    let retained_b_after = control.retained(&lock_b.graph_id).unwrap();
    let active = control.activation().unwrap();
    control
        .activate(&lock_b.graph_id, active.generation, &artifact_refs(&lock_b))
        .unwrap();
    assert_eq!(control.pin_for_run(&run_a_id).unwrap(), pin_a);
    let (status, denied_a) = json_request(
        &app,
        "POST",
        "/v1/runs",
        json!({
            "session_id": session_id,
            "input": {
                "message": "read note",
                "graph_id": lock_b.graph_id,
                "tool_graph_id": lock_b.graph_id
            },
            "workspace": "name:lifecycle",
            "graph_id": lock_a.graph_id,
            "tool_graph_id": lock_b.graph_id
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{denied_a}");
    assert_ne!(status, StatusCode::ACCEPTED);
    assert_eq!(denied_a["error"]["code"], "plugin_graph_pin_required");
    assert!(denied_a.get("run_id").is_none(), "{denied_a}");
    for key in ["effect", "handle", "graph_ref", "graph_id", "ref_id"] {
        assert!(
            denied_a.get(key).is_none(),
            "{key} partial write: {denied_a}"
        );
    }
    assert_eq!(
        state.service().handle_count(),
        handles_after_a,
        "inactive A must not publish a handle"
    );
    assert_eq!(
        control.retained(&lock_a.graph_id).unwrap(),
        retained_a_after
    );
    assert_eq!(
        control.retained(&lock_b.graph_id).unwrap(),
        retained_b_after
    );
    assert_eq!(control.pin_for_run(&run_a_id).unwrap(), pin_a);
    let (_, messages_after_denial) = json_request(
        &app,
        "GET",
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    assert_eq!(
        messages_after_denial, messages_a,
        "inactive A must not write a run or effect"
    );

    let provider_b = ScriptedProvider::new();
    queue_read(&provider_b, "http-b");
    state.service().inject_provider_host(Arc::new(provider_b));
    let (status, run_b) = json_request(
        &app,
        "POST",
        "/v1/runs",
        json!({
            "session_id": session_id,
            "input": {
                "message": "read note",
                "graph_id": lock_a.graph_id,
                "tool_graph_id": lock_a.graph_id
            },
            "workspace": "name:lifecycle",
            "graph_id": lock_b.graph_id,
            "tool_graph_id": lock_a.graph_id
        }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run_b}");
    assert_ne!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let run_b_id = run_b["run_id"].as_str().expect("run b").to_string();
    let active_b = control.activation().unwrap();
    let pin_b = control.pin_for_run(&run_b_id).unwrap();
    assert_eq!(pin_b["pinned"], true);
    assert_eq!(pin_b["graph_id"], lock_b.graph_id);
    assert_eq!(pin_b["graph_id"], run_b["graph_id"]);
    assert_eq!(pin_b["graph_id"], active_b.graph_id);
    assert_eq!(pin_b["generation"], active_b.generation);
    assert_eq!(pin_b["run_id"], run_b_id);
    let registry_b = pin_b["registry_identity"].as_str().expect("registry");
    assert!(!registry_b.is_empty());
    assert_ne!(registry_b, lock_a.graph_id);
    assert_ne!(registry_b, lock_b.graph_id);
    let handle_b = state.service().handle(&run_b_id).expect("admitted handle");
    assert!(
        handle_b.cancellation().deadline_instant().is_some(),
        "admission keeps the original clock"
    );
    let events_b = sse_body(&app, &run_b_id).await;
    assert!(events_b.contains("tool.completed"), "tool must commit");
    assert!(events_b.contains("run.completed"), "{events_b}");
    assert!(!events_b.contains("run.cancelled"), "{events_b}");
    let (_, messages_b) = json_request(
        &app,
        "GET",
        &format!("/api/sessions/{session_id}/messages"),
        Value::Null,
    )
    .await;
    let body_b = messages_b["data"]
        .as_array()
        .expect("messages")
        .iter()
        .filter(|message| message["run_id"] == run_b_id)
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    assert!(
        body_b.contains("B-marker-bytes"),
        "HTTP run must emit signed B: {body_b}"
    );
    assert!(
        !body_b.contains("AB-marker-bytes"),
        "request graph A must not select A while B is active: {body_b}"
    );
    assert_eq!(control.pin_for_run(&run_a_id).unwrap(), pin_a);
    assert_eq!(
        control.load_lock(&lock_a.graph_id).unwrap().lock.graph_id,
        lock_a.graph_id
    );
    assert_eq!(
        control.load_lock(&lock_b.graph_id).unwrap().lock.graph_id,
        lock_b.graph_id
    );
    assert!(
        control
            .retained(&lock_b.graph_id)
            .unwrap()
            .iter()
            .any(|reference| {
                reference.owner_kind == "run"
                    && reference.owner_id == run_b_id
                    && !reference.ref_id.is_empty()
            }),
        "selected B must retain its run graph ref"
    );
    assert!(
        !control
            .retained(&lock_a.graph_id)
            .unwrap()
            .iter()
            .any(|reference| reference.owner_id == run_b_id),
        "message graph_id must not retain A for run B"
    );
    println!(
        "PRODUCTION_HTTP {}",
        json!({"run_a":run_a_id,"messages_a":messages_a,"run_b":run_b_id,"messages_b":messages_b})
    );
    shutdown.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn production_arguments_json_matches_map_and_malformed_has_no_started() {
    let root = temp_root("arguments-json");
    let (home, _) = workspace_home(&root);
    let state =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .unwrap()
            .with_workspace_home(&home);
    let mut outputs = Vec::new();
    for (label, call) in [
        (
            "map",
            json!({"id":"arg-call", "name":"read_file", "arguments":{"path":"note.txt"}}),
        ),
        (
            "json",
            json!({"id":"arg-call", "name":"read_file", "arguments_json":"{\"path\":\"note.txt\"}"}),
        ),
        (
            "malformed",
            json!({"id":"arg-call", "name":"read_file", "arguments_json":"{bad"}),
        ),
    ] {
        let provider = ScriptedProvider::new();
        provider.push_ok(json!({"text":"", "tool_calls":[call], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
        provider.push_ok(text_response("done"));
        state.service().inject_provider_host(Arc::new(provider));
        let admitted = state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"read note"}),
                    ..Default::default()
                },
                Some("name:lifecycle".to_string()),
            )
            .await
            .unwrap();
        state
            .service()
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string())
            .await;
        let events = serde_json::to_value(state.service().run_events(&admitted.run_id)).unwrap();
        let started = events
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["event"] == "tool.started")
            .count();
        let messages =
            serde_json::to_value(state.service().session_messages(&admitted.session_id)).unwrap();
        if label == "malformed" {
            assert_eq!(
                started, 0,
                "malformed payload must have no effect: {events}"
            );
            assert!(!messages.to_string().contains("AB-marker-bytes"));
        } else {
            assert_eq!(started, 1, "valid {label} must execute: {events}");
            let content = messages
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|message| message["content"].as_array().into_iter().flatten())
                .find(|block| block["type"] == "tool_result")
                .expect("canonical tool result")
                .clone();
            assert!(
                content.to_string().contains("AB-marker-bytes"),
                "{label}: {content}"
            );
            outputs.push(content);
        }
    }
    assert_eq!(
        outputs[0], outputs[1],
        "legacy form must preserve canonical result"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_workspace_pin_restores_without_granting_path_authority() {
    let root = temp_root("no-workspace");
    let (home, workspace) = workspace_home(&root);
    let config_path = home.join("config.yaml");
    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace(&format!("  default: '{}'\n", workspace.display()), "");
    fs::write(&config_path, config).unwrap();
    let state =
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), root.join("state.db"))
            .unwrap()
            .with_workspace_home(&home);
    let provider = ScriptedProvider::new();
    queue_read(&provider, "no-workspace-call");
    state.service().inject_provider_host(Arc::new(provider));
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"read note"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    state.service().evict_run_handle(&admitted.run_id);
    state
        .service()
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let events = serde_json::to_string(&state.service().run_events(&admitted.run_id)).unwrap();
    assert!(
        !events.contains("tool_pin_unavailable"),
        "NoAuthority is a valid original binding: {events}"
    );
    assert!(
        events.contains("workspace_unavailable"),
        "native IO still needs real workspace authority: {events}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unkeyed_pin_receipt_does_not_enter_public_idempotency_namespace() {
    let root = temp_root("receipt-namespace");
    let (home, _) = workspace_home(&root);
    let db = root.join("state.db");
    let state = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &db)
        .unwrap()
        .with_workspace_home(&home);
    let original = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"first"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &db)
        .unwrap()
        .with_workspace_home(&home);
    let new = reopened
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"second"}),
                idempotency_key: Some(original.run_id.clone()),
                idempotency_hash: Some("fnv64:0000000000000002".to_string()),
                graph_id: None,
                workspace_branch: None,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("Native receipt scope must not consume a public key");
    assert!(!new.replayed);
    assert_ne!(new.run_id, original.run_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_default_admission_keeps_original_250ms_budget() {
    let root = temp_root("admission-budget");
    let (home, _) = workspace_home(&root);
    let config = AgentGatewayConfig {
        run_timeout: std::time::Duration::from_millis(250),
        ..Default::default()
    };
    let state = AgentGatewayState::with_sqlite_path(config, root.join("state.db"))
        .unwrap()
        .with_workspace_home(&home);
    state
        .service()
        .materialize_cached_runner()
        .expect("prepare Native tools with the existing runner setup path");
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"read note"}),
                ..Default::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("prepared default must fit original admission budget");
    let handle = state.service().handle(&admitted.run_id).unwrap();
    let deadline = handle.cancellation().deadline_instant().unwrap();
    assert!(
        deadline.saturating_duration_since(std::time::Instant::now())
            <= std::time::Duration::from_millis(250)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn activation_race_reprepares_inside_original_admission_budget() {
    let root = temp_root("activation-race");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.racea",
        0,
    );
    install_tool(
        &store,
        &signer,
        &root.join("pkg-b"),
        "org.rustscript.tools.raceb",
        1,
    );
    let a = resolve_tool(&store, "org.rustscript.tools.racea");
    let b = resolve_tool(&store, "org.rustscript.tools.raceb");
    let (home, _) = workspace_home(&root);
    let state = open_gateway(&root.join("state.db"), &home, store);
    let persistence = state.persistence().unwrap();
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&a).unwrap();
    control.store_lock(&b).unwrap();
    let active = control
        .activate(&a.graph_id, 0, &artifact_refs(&a))
        .unwrap();
    let weak = Arc::downgrade(&persistence);
    let b_raced = b.clone();
    let attempted = Arc::new(std::sync::Mutex::new(Value::Null));
    let recorded = Arc::clone(&attempted);
    persistence.inject_admission_precommit_hook(move |payload| {
        *recorded.lock().unwrap() = payload.clone();
        let persistence = weak.upgrade().unwrap();
        PluginControlStore::new(persistence.as_ref())
            .activate(
                &b_raced.graph_id,
                active.generation,
                &artifact_refs(&b_raced),
            )
            .unwrap();
    });
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"read note"}),
                ..Default::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("activation drift must reprepare, with no partial admission");
    let receipt = control.pin_for_run(&admitted.run_id).unwrap();
    assert_eq!(receipt["graph_id"], b.graph_id);
    assert!(control.retained(&a.graph_id).unwrap().is_empty());
    assert_eq!(control.retained(&b.graph_id).unwrap().len(), 1);
    let stale = attempted.lock().unwrap();
    if stale["run_id"] != admitted.run_id {
        assert!(
            persistence
                .run_get(stale["run_id"].as_str().unwrap())
                .unwrap()["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    if stale["session_id"] != admitted.session_id {
        assert!(
            persistence
                .session_get(stale["session_id"].as_str().unwrap())
                .unwrap()["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        state.service().session_messages(&admitted.session_id).len(),
        1
    );
    assert_eq!(
        state
            .service()
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "run.started")
            .count(),
        1
    );
}

struct ParentFacts {
    arguments: Value,
    started: std::sync::atomic::AtomicUsize,
    committed: std::sync::atomic::AtomicUsize,
}

impl rustscript_agent::capabilities::DurableToolLifecycle for ParentFacts {
    fn assert_active_run(
        &self,
        _: &str,
    ) -> Result<(), rustscript_agent::capabilities::LifecycleError> {
        Ok(())
    }
    fn prepare_parent(
        &self,
        _: &str,
        call: &str,
        name: &str,
    ) -> Result<(), rustscript_agent::capabilities::LifecycleError> {
        if call == "original-call" && name == "read_file" {
            Ok(())
        } else {
            Err(rustscript_agent::capabilities::LifecycleError::MissingParent)
        }
    }
    fn parent_arguments(
        &self,
        _: &str,
        call: &str,
        name: &str,
    ) -> Result<Option<Value>, rustscript_agent::capabilities::LifecycleError> {
        self.prepare_parent("", call, name)?;
        Ok(Some(self.arguments.clone()))
    }
    fn replay_result(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<Value>, rustscript_agent::capabilities::LifecycleError> {
        Ok(None)
    }
    fn commit_started(
        &self,
        _: &rustscript_agent::capabilities::DurableStarted,
    ) -> Result<(), rustscript_agent::capabilities::LifecycleError> {
        self.started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn commit_result(
        &self,
        _: &str,
        result: &Value,
    ) -> Result<Value, rustscript_agent::capabilities::LifecycleError> {
        self.committed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(result.clone())
    }
    fn interrupt(&self, _: &str) -> Result<(), rustscript_agent::capabilities::LifecycleError> {
        Ok(())
    }
}

struct NoCancel;
impl rustscript_agent::capabilities::CancellationFlag for NoCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn invoke_original(
    mut host: rustscript_agent::AgentHostBridges,
    receipt: &Value,
    workspace: &Path,
    arguments: Value,
    durable: Arc<ParentFacts>,
) -> Value {
    use rustscript_agent::capabilities::*;
    let owner = CapabilityOwner::new(
        receipt["profile"].as_str().unwrap(),
        receipt["session_id"].as_str().unwrap(),
        receipt["run_id"].as_str().unwrap(),
    )
    .unwrap();
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner.clone())
        .registry_identity(receipt["registry_identity"].as_str().unwrap())
        .workspace(workspace)
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(9_000_000_000_000)
        .clock(Arc::new(SystemClock))
        .tokens(Arc::new(UuidIssuer))
        .durable(durable)
        .approval(Arc::new(AllowAllApproval))
        .cancellation(Arc::new(NoCancel))
        .generation(1)
        .build()
        .unwrap();
    let fs = Arc::new(
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
    let canonical = arguments.to_string();
    let quoted = serde_json::to_string(&canonical).unwrap();
    let source = format!(
        r#"pub fn run(context: map) -> map {{
        agent_runtime::invoke_pinned_tool({{
            tool_name: "read_file", call_id: "original-call",
            canonical_arguments: {quoted}, argument_digest: {quoted}, canonical_input: "",
            run_id: "", registry_identity: "", risk_class: "read", summary: "read note", untrusted_graph_id: ""
        }})
    }}"#
    );
    host.lifecycle = Some(Arc::new(lifecycle));
    host.capability_owner = Some(owner);
    host.filesystem = Some(fs);
    host.allow_stateless_pin = false;
    // The Narrow execution guard reads the exact sealed graph revocation
    // under a bounded run cancellation; the fixture supplies its own.
    host.cancellation = Some(rustscript_agent::RunCancellation::with_timeout(
        std::time::Duration::from_secs(30),
    ));
    let result = rustscript_agent::AgentRunner::from_source(
        &source,
        rustscript_agent::AgentConfig::default(),
    )
    .unwrap()
    .with_host(host)
    .run_with_context(rustscript_vm::Value::map(vec![]))
    .unwrap();
    let rustscript_vm::Value::Map(entries) = result else {
        panic!("result map");
    };
    let mut object = serde_json::Map::new();
    for (key, value) in entries.iter() {
        if let rustscript_vm::Value::String(key) = key {
            let value = match value {
                rustscript_vm::Value::String(value) => json!(value.as_str()),
                rustscript_vm::Value::Bool(value) => json!(value),
                _ => Value::Null,
            };
            object.insert(key.to_string(), value);
        }
    }
    Value::Object(object)
}

#[tokio::test(flavor = "multi_thread")]
async fn synchronized_argument_forgery_rejected_before_started() {
    let root = temp_root("parent-args");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.parentargs",
        0,
    );
    let lock = resolve_tool(&store, "org.rustscript.tools.parentargs");
    let (home, workspace) = workspace_home(&root);
    fs::write(workspace.join("other.txt"), "forged-other-bytes").unwrap();
    let state = open_gateway(&root.join("state.db"), &home, Arc::clone(&store));
    let persistence = state.persistence().unwrap();
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&lock).unwrap();
    control
        .activate(&lock.graph_id, 0, &artifact_refs(&lock))
        .unwrap();
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"read note"}),
                ..Default::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .unwrap();
    let receipt = control.pin_for_run(&admitted.run_id).unwrap();
    let binding =
        rustscript_agent::plugins::restore_owned_pin(&persistence, &store, &admitted.run_id)
            .unwrap();
    let durable = Arc::new(ParentFacts {
        arguments: json!({"path":"note.txt"}),
        started: 0.into(),
        committed: 0.into(),
    });
    assert_eq!(durable.arguments, json!({"path":"note.txt"}));
    let result = invoke_original(
        rustscript_agent::AgentHostBridges {
            pinned_tool: Some(binding),
            ..Default::default()
        },
        &receipt,
        &workspace,
        json!({"path":"other.txt"}),
        Arc::clone(&durable),
    );
    assert_eq!(
        result["ok"], false,
        "all transport claims were forged together: {result}"
    );
    assert_eq!(durable.started.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        durable.committed.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

async fn json_request(app: &str, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let client =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http::<Body>();
    let response = client
        .request(
            Request::builder()
                .method(method)
                .uri(format!("{app}{uri}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(Body::new(response.into_body()), 1024 * 1024)
        .await
        .unwrap();
    let parsed = serde_json::from_slice(&bytes)
        .unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes).to_string()}));
    (status, parsed)
}

async fn sse_body(app: &str, run_id: &str) -> String {
    let client =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http::<Body>();
    let response = client
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("{app}/v1/runs/{run_id}/events"))
                .header("accept", "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = to_bytes(Body::new(response.into_body()), 2 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// T06: the whole captured A artifact directory is unavailable when the
/// package store is cold. Receipt-only replay still reads A's original pin,
/// the cold executable restore refuses without a fallback to the active B,
/// and no new run handle, pending terminal, event or graph ref appears. B
/// stays executable through the normal entrance while A's capture is absent.
#[tokio::test(flavor = "multi_thread")]
async fn production_signed_a_whole_captured_artifact_directory_unavailable_stays_refused() {
    let root = temp_root("ab-captured-dir");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    install_tool(
        &store,
        &signer,
        &root.join("pkg-a"),
        "org.rustscript.tools.dira",
        0,
    );
    install_tool(
        &store,
        &signer,
        &root.join("pkg-b"),
        "org.rustscript.tools.dirb",
        1,
    );
    let lock_a = resolve_tool(&store, "org.rustscript.tools.dira");
    let lock_b = resolve_tool(&store, "org.rustscript.tools.dirb");
    let (home, workspace) = workspace_home(&root);
    let db = root.join("state.db");
    let state = open_gateway(&db, &home, Arc::clone(&store));
    let persistence = state.persistence().expect("sqlite persistence");
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&lock_a).unwrap();
    control.store_lock(&lock_b).unwrap();
    let activated_a = control
        .activate(&lock_a.graph_id, 0, &artifact_refs(&lock_a))
        .unwrap();
    assert_ne!(activated_a.generation, 0);

    let provider = ScriptedProvider::new();
    queue_read(&provider, "call-a");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({ "message": "read note" }),
                idempotency_key: Some("captured-dir-key".to_string()),
                idempotency_hash: Some("fnv64:0000000000000009".to_string()),
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("admit signed A");
    state
        .service()
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert!(
        observed_text(
            state.service().as_ref(),
            &admitted.run_id,
            &admitted.session_id
        )
        .contains("AB-marker-bytes")
    );
    let original_receipt = control.pin_for_run(&admitted.run_id).unwrap();
    assert_eq!(original_receipt["graph_id"], lock_a.graph_id);

    // Execute A once through the direct owned restore so the fixture-owned
    // start/commit counters are the ones a fallback could increment.
    let durable = Arc::new(ParentFacts {
        arguments: json!({"path":"note.txt"}),
        started: 0.into(),
        committed: 0.into(),
    });
    let binding =
        rustscript_agent::plugins::restore_owned_pin(&persistence, &store, &admitted.run_id)
            .unwrap();
    let executed = invoke_original(
        rustscript_agent::AgentHostBridges {
            pinned_tool: Some(binding),
            ..Default::default()
        },
        &original_receipt,
        &workspace,
        json!({"path":"note.txt"}),
        Arc::clone(&durable),
    );
    assert_eq!(executed["content"], "AB-marker-bytes\n");
    assert_eq!(durable.started.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        durable.committed.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    // B becomes the active graph; a fallback would silently bind these bytes.
    let activated_b = control
        .activate(
            &lock_b.graph_id,
            activated_a.generation,
            &artifact_refs(&lock_b),
        )
        .unwrap();
    assert_eq!(activated_b.graph_id, lock_b.graph_id);
    state.service().evict_run_handle(&admitted.run_id);
    let original_started = durable.started.load(std::sync::atomic::Ordering::SeqCst);
    let original_committed = durable.committed.load(std::sync::atomic::Ordering::SeqCst);
    drop(state);
    drop(persistence);

    // Cold package store over the real graph-fixed capture root.
    let a_capture = root
        .join("packages/artifacts")
        .join(&lock_a.packages[0].artifact_id);
    assert!(
        a_capture.is_dir(),
        "fixture must start from the installed captured directory"
    );
    let parked = root.join("packages/artifacts-parked-a");
    fs::rename(&a_capture, &parked).expect("fixture captured A directory parks");
    let cold = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    cold.bind_policy(&auth(&signer));
    let reopened = open_gateway(&db, &home, Arc::clone(&cold));
    let persistence = reopened.persistence().unwrap();
    let control = PluginControlStore::new(persistence.as_ref());
    assert_eq!(
        control.pin_for_run(&admitted.run_id).unwrap(),
        original_receipt,
        "the historical pin must stay readable without the capture"
    );
    let handles_before = reopened.service().handle_count();
    let pending_before = reopened.service().pending_terminal_count();
    let events_before = reopened.service().run_events(&admitted.run_id).len();
    let refs_before = control.retained(&lock_a.graph_id).unwrap();

    let replay_request = AdmitRunRequest {
        input: json!({ "message":"read note", "graph_id":lock_b.graph_id, "tool_graph_id":lock_b.graph_id }),
        idempotency_key: Some("captured-dir-key".to_string()),
        idempotency_hash: Some("fnv64:0000000000000009".to_string()),
        graph_id: None,
        workspace_branch: None,
        platform: "tools_pin_production_ab".to_string(),
        ..Default::default()
    };
    let replay = reopened
        .service()
        .admit_external_with_workspace_selector(
            replay_request.clone(),
            Some("name:lifecycle".to_string()),
        )
        .await;
    let refusal =
        rustscript_agent::plugins::restore_owned_pin(&persistence, &cold, &admitted.run_id);
    let refusal_code = refusal.as_ref().err().map(|error| error.code);
    let refusal_message = refusal.as_ref().err().map(|error| error.message.clone());
    let receipt_after = control.pin_for_run(&admitted.run_id).unwrap();
    let events_after = reopened.service().run_events(&admitted.run_id).len();
    let handles_after = reopened.service().handle_count();
    let pending_after = reopened.service().pending_terminal_count();
    let refs_after = control.retained(&lock_a.graph_id).unwrap();
    let started_after = durable.started.load(std::sync::atomic::Ordering::SeqCst);
    let committed_after = durable.committed.load(std::sync::atomic::Ordering::SeqCst);

    // B must still run through the normal entrance while A's directory is gone.
    queue_read(&provider, "call-b");
    reopened
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let admitted_b = reopened
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({ "message": "read note" }),
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("active B admits on the normal entrance");
    reopened
        .service()
        .clone()
        .run_worker(admitted_b.run_id.clone(), "ignored".to_string())
        .await;
    let b_text = observed_text(
        reopened.service().as_ref(),
        &admitted_b.run_id,
        &admitted_b.session_id,
    );
    let b_receipt = control.pin_for_run(&admitted_b.run_id).unwrap();

    // Restore the fixture-owned capture before any fallible assertion.
    fs::rename(&parked, &a_capture).expect("fixture captured A directory restores");
    println!(
        "PRODUCTION_AB_CAPTURED_DIR_REFUSAL {}",
        json!({
            "refusal_code": refusal_code,
            "refusal_message": refusal_message.clone(),
            "replay": replay.as_ref().map(|run| (run.run_id.clone(), run.replayed)).ok(),
            "handles_before": handles_before,
            "handles_after": handles_after,
            "pending_before": pending_before,
            "pending_after": pending_after,
            "events_before": events_before,
            "events_after": events_after,
            "started_after": started_after,
            "committed_after": committed_after,
        })
    );
    assert_eq!(
        refusal_code,
        Some("pinned_tool_unavailable"),
        "the cold executable restore must refuse the missing whole capture at the pin boundary"
    );
    assert!(
        refusal_message.is_some(),
        "the refusal must keep its typed message"
    );
    let a_artifact_id = lock_a.packages[0].artifact_id.as_str();
    let b_artifact_id = lock_b.packages[0].artifact_id.as_str();
    assert!(
        refusal_message
            .as_deref()
            .is_some_and(|message| message.contains(a_artifact_id)),
        "the refusal must name the unavailable captured A artifact"
    );
    assert!(
        refusal_message
            .as_deref()
            .is_some_and(|message| !message.contains(b_artifact_id)),
        "the refusal must never name or bind the active B capture"
    );
    let replay = replay.expect("history replay must stay readable without the capture");
    assert!(replay.replayed);
    assert_eq!(replay.run_id, admitted.run_id);
    assert_eq!(receipt_after, original_receipt);
    assert!(
        control
            .retained(&lock_a.graph_id)
            .unwrap()
            .iter()
            .any(|reference| reference.owner_id == admitted.run_id),
        "the original A run ref must stay attached to its own pin"
    );
    assert_eq!(events_after, events_before, "extra A event");
    assert_eq!(handles_after, handles_before, "extra run handle");
    assert_eq!(pending_after, pending_before, "extra pending terminal");
    assert_eq!(refs_after, refs_before, "A graph refs changed");
    assert_eq!(started_after, original_started, "extra started");
    assert_eq!(committed_after, original_committed, "extra committed");
    assert!(
        b_text.contains("B-marker-bytes"),
        "the active B must still execute on the normal entrance: {b_text}"
    );
    assert!(
        !b_text.contains("AB-marker-bytes"),
        "B must not emit A's offset: {b_text}"
    );
    assert_eq!(b_receipt["graph_id"], lock_b.graph_id);
    reopened.service().shutdown().await.unwrap();
    let _ = fs::remove_dir_all(&root);
}

fn policy_lib_manifest(id: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: library
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: policy.rss
  export: prompt
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    prompt:
      direct: []
      delegated: []
    context:
      direct: []
      delegated: []
    guardian:
      direct: []
      delegated: []
"#
    )
}

fn install_policy_library(store: &PackageStore, signer: &Signer, dir: &Path, id: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), policy_lib_manifest(id)).unwrap();
    fs::write(
        dir.join("policy.rss"),
        b"pub fn prompt(context: map) -> map { context }\npub fn context(context: map) -> map { context }\npub fn guardian(context: map) -> map { context }\n",
    )
    .unwrap();
    let payload = store.signature_payload(dir).unwrap();
    let signature = signer.pair.sign(&payload);
    fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(dir, &auth(signer)).unwrap();
}

/// T04: a genuinely resolved `ContextPrompt` lock stays readable and
/// validated with its exact stored shape, while the Native executable
/// admission refuses it with its precise typed code and starts nothing.
/// `ToolOnly` on the same service fixture remains the executable control.
#[tokio::test(flavor = "multi_thread")]
async fn context_prompt_lock_stays_readable_without_a_native_execution_lane() {
    let root = temp_root("context-prompt");
    let signer = signer();
    let store = Arc::new(PackageStore::open(root.join("packages")).unwrap());
    let embedded = store
        .install_embedding_owned()
        .expect("embedded tool catalog installs");
    let policy_id = "org.rustscript.lib.ctxprompt";
    install_policy_library(&store, &signer, &root.join("pkg-policy"), policy_id);

    let installed = store.load_installed().unwrap();
    let embedding = installed
        .iter()
        .find(|package| package.artifact_id == embedded.artifact_id)
        .expect("the embedding revision is captured");
    let tool_id = embedding.manifest.id.clone();
    let request = ResolveRequest {
        harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ContextPrompt {
            tool_package: tool_id.clone(),
            policy_package: policy_id.to_string(),
            prompt_export: "prompt".to_string(),
            context_export: "context".to_string(),
            guardian_export: "guardian".to_string(),
        },
        roots: vec![
            PackageRequirement {
                id: tool_id.clone(),
                version: embedding.manifest.version.clone(),
            },
            PackageRequirement {
                id: policy_id.to_string(),
                version: "1.0.0".to_string(),
            },
        ],
        host_runtime: HOST_RUNTIME.to_string(),
    };
    let lock = store
        .resolve(&request)
        .expect("a genuine ContextPrompt lock resolves");
    let rustscript_agent::plugins::HarnessSelection::ContextPrompt {
        tool_package,
        policy,
    } = &lock.harness_selection
    else {
        panic!("the stored shape must stay ContextPrompt");
    };
    assert_eq!(tool_package, &tool_id);
    assert_eq!(policy.package_id, policy_id);
    assert_eq!(
        policy.artifact_id,
        installed
            .iter()
            .find(|package| package.manifest.id == policy_id)
            .expect("policy revision")
            .artifact_id
    );
    assert_eq!(policy.prompt_export, "prompt");
    assert_eq!(policy.context_export, "context");
    assert_eq!(policy.guardian_export, "guardian");
    assert_eq!(lock.packages.len(), 2);
    assert_eq!(lock.closure.len(), 4);

    let (home, _workspace) = workspace_home(&root);
    let db = root.join("state.db");
    let state = open_gateway(&db, &home, Arc::clone(&store));
    let persistence = state.persistence().expect("sqlite persistence");
    let control = PluginControlStore::new(persistence.as_ref());
    control.store_lock(&lock).expect("the lock persists");
    let stored = control
        .load_lock(&lock.graph_id)
        .expect("the persisted ContextPrompt lock reads back")
        .lock;
    assert_eq!(stored, lock, "the stored ContextPrompt shape changed");
    control
        .activate(&lock.graph_id, 0, &artifact_refs(&lock))
        .expect("the readable graph activates");

    // Native executable admission through the normal service entrance. The
    // context-prompt lock stays readable and validatable, but it has no Native
    // execution lane: two consecutive unkeyed attempts must return the same
    // typed refusal without leaving any durable admission side effect.
    let provider = ScriptedProvider::new();
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let handles_before = state.service().handle_count();
    let pending_before = state.service().pending_terminal_count();
    let run_refs = |control: &PluginControlStore| -> Vec<(String, String)> {
        control
            .retained(&lock.graph_id)
            .expect("the live retention slot reads through the production command")
            .into_iter()
            .filter(|reference| reference.owner_kind == "run")
            .map(|reference| (reference.owner_id, reference.ref_id))
            .collect()
    };
    let observe = |refs: &[(String, String)]| -> (Vec<String>, Vec<bool>, Vec<bool>, Vec<bool>) {
        let mut statuses = Vec::new();
        let mut pinned = Vec::new();
        let mut graph_matches = Vec::new();
        let mut ref_matches = Vec::new();
        for (owner_id, ref_id) in refs {
            let run = persistence
                .run_get(owner_id)
                .expect("the durable run row reads through the typed store");
            statuses.push(
                run.get("rows")
                    .and_then(Value::as_array)
                    .and_then(|rows| rows.first())
                    .and_then(|row| row.get(3))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            let pin = control
                .pin_for_run(owner_id)
                .expect("the durable pin reads through the typed control store");
            pinned.push(pin.get("pinned").and_then(Value::as_bool).unwrap_or(false));
            graph_matches
                .push(pin.get("graph_id").and_then(Value::as_str) == Some(lock.graph_id.as_str()));
            ref_matches.push(pin.get("ref_id").and_then(Value::as_str) == Some(ref_id.as_str()));
        }
        (statuses, pinned, graph_matches, ref_matches)
    };
    let refs_before = run_refs(&control);
    assert!(
        refs_before.is_empty(),
        "the fixture starts with no run-owned ref on the context-prompt graph"
    );

    let refused_first = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({ "message": "read note" }),
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await;
    let refs_after_first = run_refs(&control);
    let first_observations = observe(&refs_after_first);
    let handles_after_first = state.service().handle_count();
    let pending_after_first = state.service().pending_terminal_count();

    let refused_second = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({ "message": "read note" }),
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await;
    let refs_after_second = run_refs(&control);
    let second_observations = observe(&refs_after_second);
    let handles_after_second = state.service().handle_count();
    let pending_after_second = state.service().pending_terminal_count();

    println!(
        "PRODUCTION_CONTEXT_PROMPT_REFUSAL {}",
        json!({
            "first_outcome": format!("{:?}", refused_first.as_ref().err()),
            "second_outcome": format!("{:?}", refused_second.as_ref().err()),
            "handles_before": handles_before,
            "handles_after_first": handles_after_first,
            "handles_after_second": handles_after_second,
            "pending_before": pending_before,
            "pending_after_first": pending_after_first,
            "pending_after_second": pending_after_second,
            "context_prompt_run_refs_before": refs_before.len(),
            "context_prompt_run_refs_after_first": refs_after_first.len(),
            "context_prompt_run_refs_after_second": refs_after_second.len(),
            "first_observed_run_statuses": first_observations.0,
            "second_observed_run_statuses": second_observations.0,
            "first_observed_pin_pinned": first_observations.1,
            "second_observed_pin_pinned": second_observations.1,
            "first_observed_pin_graph_match": first_observations.2,
            "second_observed_pin_graph_match": second_observations.2,
            "first_observed_pin_ref_match": first_observations.3,
            "second_observed_pin_ref_match": second_observations.3,
        })
    );
    assert!(
        matches!(
            &refused_first,
            Err(rustscript_agent::AdmitError::HarnessPolicy(
                "plugin_graph_pin_required"
            ))
        ),
        "ContextPrompt must have no Native execution lane: {refused_first:?}"
    );
    assert!(
        matches!(
            &refused_second,
            Err(rustscript_agent::AdmitError::HarnessPolicy(
                "plugin_graph_pin_required"
            ))
        ),
        "the second unkeyed ContextPrompt attempt must be refused the same way: {refused_second:?}"
    );
    assert_eq!(
        handles_after_second, handles_before,
        "a refused admission started a handle"
    );
    assert_eq!(
        pending_after_second, pending_before,
        "a refused admission queued a terminal"
    );
    assert_eq!(
        refs_after_first.len(),
        refs_before.len(),
        "the first refusal left a run-owned graph ref behind"
    );
    assert_eq!(
        refs_after_second.len(),
        refs_before.len(),
        "the second refusal left another run-owned graph ref behind"
    );
    // Typed read-back for every run ref that did exist: the durable run row
    // must not be `running` and no pin may be attached to this graph/ref. When
    // the refusal happens before durable admission these lists are empty.
    assert!(
        first_observations
            .0
            .iter()
            .chain(second_observations.0.iter())
            .all(|status| status != "running"),
        "a refused admission left a running durable row"
    );
    assert!(
        first_observations
            .1
            .iter()
            .chain(second_observations.1.iter())
            .all(|pinned| !*pinned),
        "a refused admission left a durable pin"
    );
    assert!(
        first_observations
            .2
            .iter()
            .chain(second_observations.2.iter())
            .all(|matched| *matched),
        "an observed pin must name the context-prompt graph"
    );
    assert!(
        first_observations
            .3
            .iter()
            .chain(second_observations.3.iter())
            .all(|matched| *matched),
        "an observed pin must name the retained ref of its run"
    );

    // ToolOnly positive control on the same service fixture.
    install_tool(
        &store,
        &signer,
        &root.join("pkg-tool"),
        "org.rustscript.tools.ctxcontrol",
        0,
    );
    let tool_lock = resolve_tool(&store, "org.rustscript.tools.ctxcontrol");
    control.store_lock(&tool_lock).unwrap();
    let activation = control.activation().unwrap();
    control
        .activate(
            &tool_lock.graph_id,
            activation.generation,
            &artifact_refs(&tool_lock),
        )
        .expect("the ToolOnly control activates");
    queue_read(&provider, "call-control");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let admitted = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({ "message": "read note" }),
                platform: "tools_pin_production_ab".to_string(),
                ..AdmitRunRequest::default()
            },
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("ToolOnly admission stays normal");
    state
        .service()
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let text = observed_text(
        state.service().as_ref(),
        &admitted.run_id,
        &admitted.session_id,
    );
    assert!(
        text.contains("AB-marker-bytes"),
        "ToolOnly must still execute: {text}"
    );
    assert_eq!(
        control.pin_for_run(&admitted.run_id).unwrap()["graph_id"],
        tool_lock.graph_id
    );
    state.service().shutdown().await.unwrap();
    let _ = fs::remove_dir_all(&root);
}
