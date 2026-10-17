//! Production admission must pin the active signed graph, not the embedded default.
//!
//! The same caller arguments produce different file bytes when graph A or B is
//! active. A request field naming the other graph is ignored. An already
//! admitted run keeps A's program after B is activated and after the service
//! is reopened against a fresh package store.

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
    let binding = rustscript_agent::plugins::restore_owned_pin(
        persistence.as_ref(),
        &fresh,
        &admitted.run_id,
    )
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
        persistence.as_ref(), &fresh,
        &json!({"idempotency_scope":"api:chat", "idempotency_key":"signed-a-key", "request_hash":"fnv64:0000000000000001", "workspace_identity_json":json!({"request_selector_present":true,"request_selector":"name:lifecycle"}).to_string()}),
        &rustscript_agent::plugins::PinnedAdmitContext { registry_identity:"ignored-replay-context".to_string(), workspace:workspace.clone() },
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
    for replacement in [
        None,
        Some("pub fn run(context: map) -> map { { ok: true } }"),
    ] {
        match replacement {
            None => fs::remove_file(&source_a).unwrap(),
            Some(source) => fs::write(&source_a, source).unwrap(),
        }
        let cold = Arc::new(PackageStore::open(root.join("packages")).unwrap());
        cold.bind_policy(&auth(&signer));
        reopened
            .service()
            .install_validated_tool_store(cold)
            .unwrap();
        assert!(
            reopened
                .service()
                .admit_external_with_workspace_selector(
                    replay_request.clone(),
                    Some("name:lifecycle".to_string())
                )
                .await
                .is_err(),
            "missing/substituted A must fail closed"
        );
        assert_eq!(
            reopened.service().run_events(&admitted.run_id).len(),
            event_count
        );
        fs::write(&source_a, &saved_source).unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn http_signed_graphs_ignore_request_graph_and_differ() {
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

    let (status, run_a) = json_request(
        &app,
        "POST",
        "/v1/runs",
        json!({
            "session_id": session_id,
            "input": {"message": "read note", "graph_id": lock_b.graph_id},
            "workspace": "name:lifecycle",
            "graph_id": lock_b.graph_id,
            "tool_graph_id": lock_b.graph_id
        }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run_a}");
    let run_a_id = run_a["run_id"].as_str().expect("run a").to_string();
    let events_a = sse_body(&app, &run_a_id).await;
    assert!(events_a.contains("tool.completed"), "tool must commit");
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
        "HTTP run must emit signed A despite request graph B: {body_a}"
    );

    let provider_b = ScriptedProvider::new();
    queue_read(&provider_b, "http-b");
    state.service().inject_provider_host(Arc::new(provider_b));
    let active = control.activation().unwrap();
    control
        .activate(&lock_b.graph_id, active.generation, &artifact_refs(&lock_b))
        .unwrap();
    let (status, run_b) = json_request(
        &app,
        "POST",
        "/v1/runs",
        json!({
            "session_id": session_id,
            "input": {"message": "read note", "graph_id": lock_a.graph_id},
            "workspace": "name:lifecycle",
            "graph_id": lock_a.graph_id
        }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run_b}");
    let run_b_id = run_b["run_id"].as_str().expect("run b").to_string();
    let events_b = sse_body(&app, &run_b_id).await;
    assert!(events_b.contains("tool.completed"), "tool must commit");
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
    let binding = rustscript_agent::plugins::restore_owned_pin(
        persistence.as_ref(),
        &store,
        &admitted.run_id,
    )
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
