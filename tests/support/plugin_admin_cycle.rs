use super::{Http, no_private_text, private_root, signed_tool_effects};
use rustscript_agent::plugins::{
    HarnessSelectionRequest, InstallAuthorization, PackageRequirement, PackageStore, PackageTrust,
    PluginControlStore, PluginErrorKind, ResolveRequest, trusted_tool_package_root,
};
use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, GatewayPersistence, ScriptedProvider,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

fn workspace_home(root: &std::path::Path) -> (PathBuf, PathBuf) {
    let home = root.join("workspace-home");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), config).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [root, &home, &workspace] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    (home, workspace)
}

fn tool_then_stop(call_id: &str, path: &str) -> (Value, Value) {
    (
        json!({
            "text": "",
            "tool_calls": [{
                "id": call_id,
                "name": "write_file",
                "arguments": {"path": path}
            }],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "reasoning": "",
            "stop_reason": "tool_calls"
        }),
        json!({
            "text": "done",
            "tool_calls": [],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "reasoning": "",
            "stop_reason": "stop"
        }),
    )
}

async fn wait_marker(workspace: &std::path::Path, name: &str, marker: &str) -> String {
    let path = workspace.join(name);
    for _ in 0..40 {
        if let Ok(text) = std::fs::read_to_string(&path)
            && text.contains(marker)
        {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| format!("missing {}: {error}", path.display()))
}

async fn reject_unpinned_graphs(
    http: &Http,
    service: &rustscript_agent::AgentService,
    token: &str,
    session_id: &str,
    cases: &[(&str, u16, &str)],
) {
    let handles = service.handle_count();
    for (graph_id, expect, code) in cases {
        let (status, body, raw) = http
            .request(
                "POST",
                "/v1/runs",
                json!({
                    "session_id": session_id,
                    "input": "rejected graph",
                    "workspace": "name:lifecycle",
                    "graph_id": graph_id
                }),
                Some(token),
            )
            .await;
        assert_eq!(status, *expect, "{graph_id}: {raw}");
        assert_eq!(body["error"]["code"], *code, "{graph_id}: {raw}");
        assert!(body.get("run_id").is_none(), "{graph_id}: {raw}");
    }
    assert_eq!(
        service.handle_count(),
        handles,
        "a rejected graph request must not admit a run"
    );
}

#[tokio::test]
async fn host_bound_cycle_rejects_caller_authority_and_pins_native_receipts() {
    let root = private_root();
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (auth, package_a, package_b, package_state) =
        signed_tool_effects::stage_write_pair(&source);
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, source.join("linked")).unwrap();
    let db = root.join("gateway.sqlite");
    let token = "owner-control-token";
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.into()),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let (home, workspace) = workspace_home(&root);
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth, source.clone(), "owner-space")
        .unwrap();
    let provider = ScriptedProvider::new();
    let service = state.service();
    let http = Http::bind(state).await;
    let source_text = source.display().to_string();

    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({
                "admin": true,
                "package": package_a,
                "deployment_space": "owner-space",
                "path": source_text
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 422, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_request_invalid");
    assert!(!raw.contains(&source_text), "{raw}");

    for package in [
        "../outside",
        "/etc/passwd",
        "linked",
        "package-a/../../outside",
    ] {
        let (status, body, raw) = http
            .request(
                "POST",
                "/v1/plugins/install",
                json!({"package": package, "deployment_space": "owner-space"}),
                Some(token),
            )
            .await;
        assert_eq!(status, 422, "{package}: {raw}");
        assert_eq!(body["error"]["code"], "plugin_source_rejected");
        no_private_text(&raw);
        assert!(!raw.contains(&source_text), "{raw}");
    }
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package_a, "deployment_space": "other-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 403, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_space_mismatch");
    no_private_text(&raw);

    let (status, installed_a, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package_a, "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(installed_a["package_id"], "org.rustscript.tools.effecta");
    assert!(!raw.contains(&source_text), "{raw}");
    let (status, _, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package_b, "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let (status, _, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package_state, "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");

    let (session_status, session, raw) = http
        .request("POST", "/api/sessions", json!({}), Some(token))
        .await;
    assert_eq!(session_status, 201, "{raw}");
    let session_id = session["session"]["id"].as_str().unwrap();

    let before = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation()
        .unwrap();
    let (status, resolved, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effecta", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effecta",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(resolved["activated"], false);
    let graph_a = resolved["graph_id"].as_str().unwrap().to_string();
    assert_ne!(graph_a, "org.rustscript.tools.effecta");
    let after_resolve = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation()
        .unwrap();
    assert_eq!(after_resolve.generation, before.generation);
    assert_eq!(after_resolve.graph_id, before.graph_id);
    let (status, prepared, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(prepared["graph_id"], graph_a);
    assert_eq!(prepared["executable"], true);
    let (status, view, raw) = http
        .request(
            "GET",
            &format!("/v1/plugin-graphs/{graph_a}"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(view["graph_id"], graph_a);
    assert!(view["errors"].as_array().unwrap().is_empty());
    assert!(
        !raw.contains(&source_text) && !raw.contains("signature") && !raw.contains("artifact"),
        "{raw}"
    );
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_a,
                "deployment_space": "other-space",
                "expected_generation": before.generation
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 403, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_space_mismatch");
    let (status, activated, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_a,
                "deployment_space": "owner-space",
                "expected_generation": before.generation
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_a = activated["generation"].as_u64().unwrap();
    assert!(generation_a > before.generation, "{raw}");
    assert_eq!(activated["graph_id"], graph_a);
    assert_eq!(
        activated["activation_id"],
        format!("owner-space.{generation_a}")
    );
    let native = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation()
        .unwrap();
    assert_eq!(native.graph_id, activated["graph_id"]);
    assert_eq!(native.generation, generation_a);
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_a,
                "deployment_space": "owner-space",
                "expected_generation": before.generation
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 409, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_activation_conflict");

    let (status, resolved_b, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effectb", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effectb",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let graph_b = resolved_b["graph_id"].as_str().unwrap().to_string();
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_b}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let (status, activated_b, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_b,
                "deployment_space": "owner-space",
                "expected_generation": generation_a
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_b = activated_b["generation"].as_u64().unwrap();
    assert!(generation_b > generation_a);
    assert_eq!(activated_b["graph_id"], graph_b);
    let history_before = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation_history()
        .unwrap();
    assert!(
        history_before
            .iter()
            .any(|entry| { entry.generation == generation_a && entry.graph_id == graph_a })
    );
    let (status, rolled, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-activations/owner-space.{generation_a}/rollback"),
            json!({"admin": true, "graph_id": graph_b}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_roll = rolled["generation"].as_u64().unwrap();
    assert!(generation_roll > generation_b, "{raw}");
    assert_eq!(rolled["graph_id"], graph_a);
    assert_ne!(
        rolled["activation_id"],
        format!("owner-space.{generation_a}")
    );
    let history_after = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation_history()
        .unwrap();
    assert!(
        history_after
            .iter()
            .any(|entry| entry.generation == generation_a)
    );
    assert!(history_after.len() > history_before.len());
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations/other-space.1/rollback",
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 404, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_activation_missing");
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{}/prepare", "x".repeat(200)),
            json!({}),
            Some(token),
        )
        .await;
    assert!(status == 404 || status == 422, "{raw}");
    no_private_text(&raw);
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/missing-graph/prepare",
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 404, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_graph_missing");

    let (status, state_resolved, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effectstate", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effectstate",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let state_graph = state_resolved["graph_id"].as_str().unwrap();
    let (status, body, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{state_graph}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(body["graph_id"], state_graph);
    assert_eq!(body["executable"], true);
    let unchanged = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation()
        .unwrap();
    assert_eq!(unchanged.graph_id, graph_a);
    assert_eq!(unchanged.generation, generation_roll);

    let (tool_a, stop_a) = tool_then_stop("call-a", "out-a.txt");
    provider.push_ok(tool_a);
    provider.push_ok(stop_a);
    service.inject_provider_host(std::sync::Arc::new(provider.clone()));
    reject_unpinned_graphs(
        &http,
        &service,
        token,
        session_id,
        &[
            (graph_b.as_str(), 422, "plugin_graph_pin_required"),
            (state_graph, 422, "plugin_graph_pin_required"),
            ("caller-forged-graph", 422, "plugin_graph_pin_required"),
            ("  ", 422, "plugin_graph_pin_required"),
            ("", 422, "plugin_graph_pin_required"),
        ],
    )
    .await;
    let (status, run_a, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "write a",
                "workspace": "name:lifecycle",
                "graph_id": graph_a
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 202, "{raw}");
    assert_eq!(run_a["graph_id"], graph_a);
    assert_eq!(run_a["activation_generation"], generation_roll);
    let pinned_legal = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .pin_for_run(run_a["run_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(pinned_legal["graph_id"], graph_a);
    assert_eq!(pinned_legal["generation"], generation_roll);
    assert!(run_a["workspace_branch"].is_null());
    assert!(run_a["epoch"].is_null());
    assert_eq!(run_a["publication"], "unsupported");
    let run_a_id = run_a["run_id"].as_str().unwrap().to_string();
    let text_a = wait_marker(&workspace, "out-a.txt", "A-write").await;
    let (_event_status, _events, event_raw) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a_id}/events"),
            json!({}),
            Some(token),
        )
        .await;
    let listed = std::fs::read_dir(&workspace)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|error| error.to_string());
    assert!(
        text_a.contains("A-write"),
        "run A did not write its pinned bytes: {text_a}; workspace={listed}; events={event_raw}"
    );

    let (status, activated_b_again, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_b,
                "deployment_space": "owner-space",
                "expected_generation": generation_roll
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_b2 = activated_b_again["generation"].as_u64().unwrap();
    let (tool_b, stop_b) = tool_then_stop("call-b", "out-b.txt");
    provider.push_ok(tool_b);
    provider.push_ok(stop_b);
    service.inject_provider_host(std::sync::Arc::new(provider.clone()));
    reject_unpinned_graphs(
        &http,
        &service,
        token,
        session_id,
        &[(&graph_a, 422, "plugin_graph_pin_required")],
    )
    .await;
    let (status, run_b, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "write b",
                "workspace": "name:lifecycle",
                "graph_id": graph_b
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 202, "{raw}");
    assert_eq!(run_b["graph_id"], graph_b);
    assert_eq!(run_b["activation_generation"], generation_b2);
    let pinned_b = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .pin_for_run(run_b["run_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(pinned_b["graph_id"], graph_b);
    assert_eq!(pinned_b["generation"], generation_b2);
    let text_b = wait_marker(&workspace, "out-b.txt", "B-write").await;
    assert!(
        text_b.contains("B-write"),
        "run B did not write its pinned bytes: {text_b}"
    );
    let text_a_after = std::fs::read_to_string(workspace.join("out-a.txt")).unwrap();
    assert!(
        text_a_after.contains("A-write"),
        "run B changed run A's bytes: {text_a_after}"
    );
    let pinned_a = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .pin_for_run(&run_a_id)
        .unwrap();
    assert_eq!(pinned_a["graph_id"], graph_a);
    assert_eq!(pinned_a["generation"], generation_roll);

    let artifact = installed_a["artifact_id"].as_str().unwrap();
    let artifact_dir = db
        .parent()
        .unwrap()
        .join(".gateway.sqlite.tool-packages/artifacts")
        .join(artifact);
    std::fs::remove_dir_all(&artifact_dir).unwrap();
    let (status, body, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 422, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_artifact_unavailable");
    no_private_text(&raw);
    assert!(!raw.contains("tool-packages"), "{raw}");
    http.close().await;
    let _ = std::fs::remove_dir_all(&root);
}

const EMBEDDING_PACKAGE: &str = "org.rustscript.embedding.tools";

fn lock_shape(lock: &rustscript_agent::plugins::GraphLock) -> String {
    let packages: Vec<String> = lock
        .packages
        .iter()
        .map(|package| {
            format!(
                "{}@{}:{}:{}",
                package.id, package.version, package.kind, package.artifact_id
            )
        })
        .collect();
    format!(
        "harness={:?} edges={} closure={} packages={packages:?}",
        lock.harness_selection,
        lock.edges.len(),
        lock.closure.len()
    )
}

fn write_probe(note: &str) {
    if let Ok(path) = std::env::var("RUSTSCRIPT_REVOCATION_PROBE") {
        let _ = std::fs::write(path, note);
    }
}

fn bound_packages(db: &std::path::Path, auth: &InstallAuthorization) -> PackageStore {
    let store = PackageStore::open(trusted_tool_package_root(db)).expect("tool package root opens");
    store.bind_policy(auth);
    store
}

fn embedding_request() -> ResolveRequest {
    ResolveRequest {
        roots: vec![PackageRequirement {
            id: EMBEDDING_PACKAGE.into(),
            version: "1.0.0".into(),
        }],
        host_runtime: rustscript_agent::plugins::HOST_RUNTIME.into(),
        harness_selection: HarnessSelectionRequest::ToolOnly {
            tool_package: EMBEDDING_PACKAGE.into(),
        },
    }
}

async fn assert_reentry_rejected(
    http: &Http,
    token: &str,
    graph_id: &str,
    generation: u64,
    activation_id: &str,
) {
    let (status, body, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_id}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 409, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_graph_revoked");
    no_private_text(&raw);
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_id,
                "deployment_space": "owner-space",
                "expected_generation": generation,
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 409, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_graph_revoked");
    no_private_text(&raw);
    let (status, body, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-activations/{activation_id}/rollback"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 409, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_graph_revoked");
    no_private_text(&raw);
}

#[tokio::test]
async fn revoked_formal_graph_prepare_and_activate_return_409() {
    let root = private_root();
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (auth, package_a, package_b, _) = signed_tool_effects::stage_write_pair(&source);
    let db = root.join("gateway.sqlite");
    let token = "owner-control-token";
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.into()),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let (home, workspace) = workspace_home(&root);
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source, "owner-space")
        .unwrap();
    let materialized = match state.service().materialize_cached_runner() {
        Ok(_) => "materialize_ok".to_string(),
        Err(err) => format!("materialize_err {err}"),
    };
    let http = Http::bind(state.clone()).await;
    for (name, package) in [("effect-a", &package_a), ("effect-b", &package_b)] {
        let (status, _, raw) = http
            .request(
                "POST",
                "/v1/plugins/install",
                json!({"package": package, "deployment_space": "owner-space"}),
                Some(token),
            )
            .await;
        assert_eq!(status, 200, "{name} install failed: {raw}");
    }
    let packages = bound_packages(&db, &auth);
    let persistence = GatewayPersistence::open(&config, &db).unwrap();
    let control = PluginControlStore::new(&persistence);
    let locks = control.list_locks().unwrap();
    let mut embedding_id = None;
    let mut embedding_shape = "absent".to_string();
    for graph_id in &locks {
        let loaded = control.load_lock(graph_id).unwrap();
        if loaded
            .lock
            .packages
            .iter()
            .any(|package| package.id == EMBEDDING_PACKAGE)
        {
            embedding_id = Some(graph_id.clone());
            embedding_shape = lock_shape(&loaded.lock);
        }
    }
    let fresh = match packages.resolve(&embedding_request()) {
        Ok(lock) => format!("fresh_resolve_ok {}", lock_shape(&lock)),
        Err(err) => format!("fresh_resolve_err {err}"),
    };
    let embedding_id = embedding_id.unwrap_or_else(|| {
        panic!(
            "formal embedding lock was not stored: materialize={materialized} locks={locks:?} shape={embedding_shape} {fresh}"
        )
    });
    let unbound = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    let unbound_err = control
        .revoke_graph(&unbound, &embedding_id)
        .expect_err("unbound store must not revoke the embedding lock");
    assert_eq!(unbound_err.code, "plugin_lock_invalid");
    assert!(control.graph_revocation(&embedding_id).unwrap().is_none());
    let fact = control
        .revoke_graph(&packages, &embedding_id)
        .unwrap_or_else(|err| {
            panic!(
                "formal embedding revoke refused {}: {err}; shape={embedding_shape} {fresh}",
                err.code
            )
        });
    assert_eq!(fact.graph_id, embedding_id);
    assert!(fact.revoked_at_ms > 0);
    let embedding_note = format!(
        "materialize={materialized} embedding_id={embedding_id} shape={embedding_shape} {fresh} fact_ms={}",
        fact.revoked_at_ms
    );
    write_probe(&embedding_note);

    let mut signed = Vec::new();
    for (name, package_id) in [
        ("effect-a", "org.rustscript.tools.effecta"),
        ("effect-b", "org.rustscript.tools.effectb"),
    ] {
        let (status, body, raw) = http
            .request(
                "POST",
                "/v1/plugin-graphs/resolve",
                json!({
                    "tool_package": package_id,
                    "roots": [{"id": package_id, "version": "1.0.0"}],
                    "deployment_space": "owner-space",
                }),
                Some(token),
            )
            .await;
        assert_eq!(status, 200, "{name} resolve failed: {raw}");
        let graph_id = body["graph_id"].as_str().unwrap().to_string();
        let (status, _, raw) = http
            .request(
                "POST",
                &format!("/v1/plugin-graphs/{graph_id}/prepare"),
                json!({}),
                Some(token),
            )
            .await;
        assert_eq!(status, 200, "{name} prepare failed: {raw}");
        signed.push(graph_id);
    }
    let graph_a = signed[0].clone();
    let graph_b = signed[1].clone();
    let signed_err = control
        .revoke_graph(&packages, &graph_a)
        .expect_err("signed tool graph stays outside the embedding revocation door");
    assert_eq!(signed_err.code, "plugin_lock_invalid");
    assert!(control.graph_revocation(&graph_a).unwrap().is_none());
    let current = control.activation().unwrap();
    assert_eq!(current.graph_id, embedding_id);
    let target = embedding_id.clone();
    let generation = current.generation;
    let activation_id = format!("owner-space.{generation}");
    let stored = control
        .graph_revocation(&target)
        .unwrap()
        .expect("durable revocation");
    assert_eq!(stored.graph_id, target);
    assert!(stored.revoked_at_ms > 0);
    assert!(control.graph_revocation(&graph_b).unwrap().is_none());

    let active_before = control.activation().unwrap();
    let history_before = control.activation_history().unwrap().len();
    let mut workspace_before: Vec<_> = std::fs::read_dir(&workspace)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    workspace_before.sort();
    let (sentinel_before, sentinel_body, _) = http
        .request(
            "GET",
            "/v1/runs/revocation-sentinel/effects",
            json!({}),
            Some(token),
        )
        .await;
    assert_reentry_rejected(&http, token, &target, generation, &activation_id).await;
    let active_after = control.activation().unwrap();
    assert_eq!(active_after.generation, active_before.generation);
    assert_eq!(active_after.graph_id, active_before.graph_id);
    assert_eq!(control.activation_history().unwrap().len(), history_before);
    let mut workspace_after: Vec<_> = std::fs::read_dir(&workspace)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    workspace_after.sort();
    assert_eq!(workspace_before, workspace_after);
    let (sentinel_after, sentinel_body_after, _) = http
        .request(
            "GET",
            "/v1/runs/revocation-sentinel/effects",
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(sentinel_before, sentinel_after);
    assert_eq!(sentinel_body, sentinel_body_after);
    let reopened_persistence = GatewayPersistence::open(&config, &db).unwrap();
    let reopened = PluginControlStore::new(&reopened_persistence);
    let reopened_fact = reopened
        .graph_revocation(&target)
        .unwrap()
        .expect("revocation survives reopen");
    assert_eq!(reopened_fact.graph_id, stored.graph_id);
    assert_eq!(reopened_fact.revoked_at_ms, stored.revoked_at_ms);
    let (status, body, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{target}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 409, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_graph_revoked");

    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_b,
                "deployment_space": "owner-space",
                "expected_generation": active_after.generation,
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "unrevoked graph activate failed: {raw}");
    let generation_b = body["generation"].as_u64().unwrap();
    assert!(generation_b > active_after.generation);
    assert_eq!(body["graph_id"], graph_b);
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_b}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "unrevoked graph prepare failed: {raw}");
    let provider = ScriptedProvider::new();
    let (tool_b, stop_b) = tool_then_stop("call-b", "out-b.txt");
    provider.push_ok(tool_b);
    provider.push_ok(stop_b);
    state
        .service()
        .inject_provider_host(std::sync::Arc::new(provider));
    let (status, session, raw) = http
        .request("POST", "/api/sessions", json!({}), Some(token))
        .await;
    assert_eq!(status, 201, "{raw}");
    let session_id = session["session"]["id"].as_str().unwrap();
    let (status, run_b, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "write b",
                "workspace": "name:lifecycle",
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 202, "{raw}");
    assert_eq!(run_b["graph_id"], graph_b);
    assert_eq!(run_b["activation_generation"], generation_b);
    let text_b = wait_marker(&workspace, "out-b.txt", "B-write").await;
    assert!(text_b.contains("B-write"), "{text_b}");
    let run_b_id = run_b["run_id"].as_str().unwrap();
    let pinned = control.pin_for_run(run_b_id).unwrap();
    assert_eq!(pinned["graph_id"], graph_b);
    assert_eq!(pinned["generation"], generation_b);
    assert_eq!(pinned["pinned"], true);
    assert!(control.graph_revocation(&graph_b).unwrap().is_none());
    write_probe(&format!(
        "{embedding_note}\ntarget={target}\nfact_ms={}",
        stored.revoked_at_ms
    ));
    http.close().await;
    let _ = std::fs::remove_dir_all(&root);
}

fn open_host_state(
    config: &AgentGatewayConfig,
    db: &std::path::Path,
    home: &std::path::Path,
    auth: InstallAuthorization,
    source: &std::path::Path,
) -> AgentGatewayState {
    AgentGatewayState::with_sqlite_path(config.clone(), db)
        .expect("open persistent state")
        .with_workspace_home(home)
        .with_plugin_control(auth, source.to_path_buf(), "owner-space")
        .expect("bind host plugin control")
}

async fn wait_completed(service: &rustscript_agent::AgentService, run_id: &str) {
    for _ in 0..40 {
        if service
            .run_events(run_id)
            .iter()
            .any(|event| event["event"] == "run.completed")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "run {run_id} did not complete: {:?}",
        service.run_events(run_id)
    );
}

async fn shutdown_owned(service: &rustscript_agent::AgentService) {
    for _ in 0..40 {
        match service.shutdown().await {
            Ok(()) => return,
            Err(err) if err.contains("still active") => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("shutdown failed: {err}"),
        }
    }
    panic!("owned workers did not finish");
}

/// Cold `AgentGatewayState` reconstruction on the same sqlite path, source
/// root, and host authorization. This is not a gateway process restart.
#[tokio::test]
async fn signed_graphs_survive_cold_state_without_reinstall() {
    let root = private_root();
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (auth, package_a, package_b, _) = signed_tool_effects::stage_write_pair(&source);
    let db = root.join("gateway.sqlite");
    let token = "owner-control-token";
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.into()),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let (home, workspace) = workspace_home(&root);

    let state = open_host_state(&config, &db, &home, auth.clone(), &source);
    let service = state.service();
    let persistence = state.persistence().expect("persistence");
    let provider = ScriptedProvider::new();
    service.inject_provider_host(std::sync::Arc::new(provider.clone()));
    let http = Http::bind(state).await;
    for package in [&package_a, &package_b] {
        let (status, _, raw) = http
            .request(
                "POST",
                "/v1/plugins/install",
                json!({"package": package, "deployment_space": "owner-space"}),
                Some(token),
            )
            .await;
        assert_eq!(status, 200, "{package}: {raw}");
    }
    let (status, resolved_a, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effecta", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effecta",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let graph_a = resolved_a["graph_id"].as_str().unwrap().to_string();
    let packages_a = resolved_a["packages"].clone();
    let harness_a = resolved_a["harness_selection"].clone();
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let (status, activated_a, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_a,
                "deployment_space": "owner-space",
                "expected_generation": 0
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_a = activated_a["generation"].as_u64().unwrap();
    let (status, resolved_b, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effectb", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effectb",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let graph_b = resolved_b["graph_id"].as_str().unwrap().to_string();
    let (status, session, raw) = http
        .request("POST", "/api/sessions", json!({}), Some(token))
        .await;
    assert_eq!(status, 201, "{raw}");
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (tool_a, stop_a) = tool_then_stop("call-a", "out-a.txt");
    provider.push_ok(tool_a);
    provider.push_ok(stop_a);
    reject_unpinned_graphs(
        &http,
        &service,
        token,
        &session_id,
        &[("caller-forged-graph", 422, "plugin_graph_pin_required")],
    )
    .await;
    let (status, run_a, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "write a",
                "workspace": "name:lifecycle",
                "graph_id": graph_a
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 202, "{raw}");
    let run_a_id = run_a["run_id"].as_str().unwrap().to_string();
    assert_eq!(run_a["graph_id"], graph_a);
    let text_a = wait_marker(&workspace, "out-a.txt", "A-write").await;
    assert!(text_a.contains("A-write"), "{text_a}");
    wait_completed(&service, &run_a_id).await;
    let pin_before = PluginControlStore::new(persistence.as_ref())
        .pin_for_run(&run_a_id)
        .expect("original pin receipt");
    assert_eq!(pin_before["graph_id"], graph_a);
    assert_eq!(pin_before["generation"], generation_a);
    assert_eq!(pin_before["harness_selection"]["mode"], "tool_only");
    drop(persistence);
    http.close().await;
    shutdown_owned(&service).await;
    drop(service);
    drop(provider);

    let reopened = open_host_state(&config, &db, &home, auth.clone(), &source);
    let reopened_service = reopened.service();
    let reopened_persistence = reopened.persistence().expect("reopened persistence");
    assert!(
        reopened_service.handle(&run_a_id).is_none(),
        "cold state must not rebuild the old native grant"
    );
    assert_eq!(reopened_service.handle_count(), 0);
    let reopened_provider = ScriptedProvider::new();
    let (tool_b, stop_b) = tool_then_stop("call-b", "out-b.txt");
    reopened_provider.push_ok(tool_b);
    reopened_provider.push_ok(stop_b);
    reopened_service.inject_provider_host(std::sync::Arc::new(reopened_provider.clone()));
    let http = Http::bind(reopened).await;
    let (status, resolved_again, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effecta", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effecta",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(
        status, 200,
        "cold restart resolve must accept the host publisher, got {status} {raw}"
    );
    assert_eq!(resolved_again["packages"], packages_a);
    assert_eq!(resolved_again["harness_selection"], harness_a);
    let (status, prepared, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(
        status, 200,
        "cold restart prepare of the original graph: {raw}"
    );
    assert_eq!(prepared["graph_id"], graph_a);
    assert_eq!(prepared["executable"], true);
    assert_eq!(prepared["status"], "prepared");
    let (status, viewed, raw) = http
        .request(
            "GET",
            &format!("/v1/plugin-graphs/{graph_a}"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(viewed["contract"], pin_before["harness_selection"]);
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_b}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let (status, activated_b, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_b,
                "deployment_space": "owner-space",
                "expected_generation": generation_a
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_b = activated_b["generation"].as_u64().unwrap();
    let (status, session_b, raw) = http
        .request("POST", "/api/sessions", json!({}), Some(token))
        .await;
    assert_eq!(status, 201, "{raw}");
    let session_b_id = session_b["session"]["id"].as_str().unwrap();
    let (status, run_b, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_b_id,
                "input": "rejected graph",
                "workspace": "name:lifecycle",
                "graph_id": "caller-forged-graph"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 422, "{raw}");
    assert_eq!(run_b["error"]["code"], "plugin_graph_pin_required");
    assert!(run_b.get("run_id").is_none(), "{raw}");
    let (status, run_b, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_b_id,
                "input": "write b",
                "workspace": "name:lifecycle",
                "graph_id": graph_b
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 202, "{raw}");
    assert_eq!(run_b["graph_id"], graph_b);
    assert_eq!(run_b["activation_generation"], generation_b);
    assert_ne!(run_b["run_id"], run_a_id);
    let text_b = wait_marker(&workspace, "out-b.txt", "B-write").await;
    assert!(text_b.contains("B-write"), "{text_b}");
    let run_b_id = run_b["run_id"].as_str().unwrap();
    wait_completed(&reopened_service, run_b_id).await;
    let text_a_after = std::fs::read_to_string(workspace.join("out-a.txt")).unwrap();
    assert_eq!(text_a_after, text_a);
    let pin_after = PluginControlStore::new(reopened_persistence.as_ref())
        .pin_for_run(&run_a_id)
        .expect("original pin after cold state");
    assert_eq!(pin_after, pin_before);
    let pin_b = PluginControlStore::new(reopened_persistence.as_ref())
        .pin_for_run(run_b_id)
        .expect("new pin");
    assert_eq!(pin_b["graph_id"], graph_b);
    assert_eq!(pin_b["harness_selection"]["mode"], "tool_only");
    assert_eq!(
        pin_b["harness_selection"]["tool_package"],
        "org.rustscript.tools.effectb"
    );
    drop(reopened_persistence);
    assert!(reopened_service.handle(&run_a_id).is_none());
    http.close().await;
    shutdown_owned(&reopened_service).await;
    drop(reopened_service);
    drop(reopened_provider);

    let empty = InstallAuthorization {
        admin: true,
        accepted_publishers: Vec::new(),
        unsigned_dev_space: None,
    };
    let denied = open_host_state(&config, &db, &home, empty, &source);
    let denied_service = denied.service();
    let http = Http::bind(denied).await;
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effecta", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effecta",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 403, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_publisher_unauthorized");
    http.close().await;
    shutdown_owned(&denied_service).await;
    drop(denied_service);
    let _ = std::fs::remove_dir_all(&root);
}

fn dev_manifest(id: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {id}
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: invoke.rss
  export: invoke
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct: []
      delegated: []
"#
    )
}

fn write_dev_package(dir: &std::path::Path, id: &str, extra_files: usize) {
    std::fs::create_dir_all(dir).unwrap();
    let manifest = dev_manifest(id);
    rustscript_agent::plugins::parse_plugin_manifest(&manifest).unwrap_or_else(|error| {
        panic!("dev manifest must parse before the budget boundary: {error:?}")
    });
    std::fs::write(dir.join("manifest.yaml"), manifest).unwrap();
    std::fs::write(
        dir.join("invoke.rss"),
        "pub fn invoke(value: int) -> int { value }\n",
    )
    .unwrap();
    for index in 0..extra_files {
        std::fs::write(dir.join(format!("pad{index:02}.txt")), b"x").unwrap();
    }
}

fn regular_file_stats(dir: &std::path::Path) -> (usize, u64, u64) {
    let mut count = 0usize;
    let mut total = 0u64;
    let mut max_len = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            assert!(
                !meta.file_type().is_symlink(),
                "budget fixture must not use a symlink: {}",
                entry.path().display()
            );
            if meta.is_dir() {
                pending.push(entry.path());
            } else if meta.is_file() {
                count += 1;
                total += meta.len();
                max_len = max_len.max(meta.len());
            }
        }
    }
    (count, total, max_len)
}

fn package_fs_identity(db: &std::path::Path) -> Vec<(String, u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let root = trusted_tool_package_root(db);
    let mut rows = Vec::new();
    for label in ["artifacts", "ledger"] {
        let dir = root.join(label);
        if !dir.exists() {
            continue;
        }
        let mut pending = vec![(dir, label.to_string())];
        while let Some((current, prefix)) = pending.pop() {
            let mut children: Vec<_> = std::fs::read_dir(&current)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            children.sort_by_key(|entry| entry.file_name());
            for entry in children {
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                assert!(!meta.file_type().is_symlink(), "{}", path.display());
                let rel = format!("{prefix}/{}", entry.file_name().to_string_lossy());
                rows.push((rel.clone(), meta.len(), meta.ino()));
                if meta.is_dir() {
                    pending.push((path, rel));
                }
            }
        }
    }
    rows.sort();
    rows
}

fn control_snapshot(
    config: &AgentGatewayConfig,
    db: &std::path::Path,
) -> (
    rustscript_agent::plugins::ActivationPointer,
    Vec<rustscript_agent::plugins::ActivationHistoryEntry>,
) {
    let persistence = GatewayPersistence::open(config, db).unwrap();
    let control = PluginControlStore::new(&persistence);
    (
        control.activation().unwrap(),
        control.activation_history().unwrap(),
    )
}

fn fresh_package_ids(
    db: &std::path::Path,
    auth: &InstallAuthorization,
) -> Vec<(String, String, PackageTrust)> {
    let store = PackageStore::open(trusted_tool_package_root(db)).expect("fresh package store");
    store.bind_policy(auth);
    let loaded = store.load_installed().expect("fresh typed load");
    let mut ids: Vec<_> = loaded
        .iter()
        .map(|package| {
            (
                package.manifest.id.clone(),
                package.artifact_id.clone(),
                package.trust,
            )
        })
        .collect();
    ids.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    let lock = store
        .resolve(&ResolveRequest {
            roots: vec![PackageRequirement {
                id: "org.rustscript.tools.effecta".into(),
                version: "1.0.0".into(),
            }],
            host_runtime: rustscript_agent::plugins::HOST_RUNTIME.into(),
            harness_selection: HarnessSelectionRequest::ToolOnly {
                tool_package: "org.rustscript.tools.effecta".into(),
            },
        })
        .expect("fresh store resolves signed A");
    assert!(
        store
            .prepare(&lock)
            .expect("fresh store prepares signed A")
            .program("org.rustscript.tools.effecta")
            .is_some()
    );
    drop(store);
    ids
}

fn dir_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Signed A runs through the registered Axum TCP entry. A valid unsigned
/// package inside the host dev space installs. The same manifest with only
/// the file-count dimension over the capture bound must be a static budget
/// denial and must not add activation, history, run, native effect, artifact,
/// or ledger rows. A fresh PackageStore, not the live cache, is the oracle.
#[tokio::test]
async fn http_file_count_over_budget_does_not_poison_signed_graph() {
    let root = private_root();
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (mut auth, package_a, package_b, _) = signed_tool_effects::stage_write_pair(&source);
    let dev = source.join("dev");
    std::fs::create_dir_all(&dev).unwrap();
    auth.unsigned_dev_space = Some(dev.clone());
    let legal_dir = dev.join("legal");
    let over_dir = dev.join("over");
    write_dev_package(&legal_dir, "org.rustscript.tools.budgetlegal", 0);
    write_dev_package(&over_dir, "org.rustscript.tools.budgetover", 63);
    let outside = source.join("outside-unsigned");
    write_dev_package(&outside, "org.rustscript.tools.budgetoutside", 0);
    let (legal_count, _, _) = regular_file_stats(&legal_dir);
    let (over_count, over_total, over_max) = regular_file_stats(&over_dir);
    assert_eq!(legal_count, 2, "legal control must stay inside every bound");
    assert_eq!(
        over_count, 65,
        "only the file-count dimension is over the bound"
    );
    assert!(
        over_max < 1024 * 1024,
        "file fixture also crossed the file bound"
    );
    assert!(
        over_total < 8 * 1024 * 1024,
        "file fixture also crossed the total bound"
    );
    let scratch = PackageStore::open(root.join("budget-kind-store")).unwrap();
    scratch.bind_policy(&auth);
    let legal_kind = scratch
        .install(&legal_dir, &auth)
        .expect("legal dev package");
    assert_eq!(legal_kind.trust, PackageTrust::DevUnsigned);
    let over_kind = scratch
        .install(&over_dir, &auth)
        .expect_err("65 files must be BudgetExceeded before HTTP");
    assert_eq!(
        over_kind.kind,
        PluginErrorKind::BudgetExceeded,
        "{over_kind:?}"
    );
    drop(scratch);

    let db = root.join("gateway.sqlite");
    let token = "owner-control-token";
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.into()),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let (home, workspace) = workspace_home(&root);
    let state = open_host_state(&config, &db, &home, auth.clone(), &source);
    let service = state.service();
    let provider = ScriptedProvider::new();
    service.inject_provider_host(std::sync::Arc::new(provider.clone()));
    let http = Http::bind(state).await;

    let (status, installed_a, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package_a, "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(installed_a["package_id"], "org.rustscript.tools.effecta");
    assert_eq!(installed_a["trust"], "accepted_publisher");
    let artifact_a = installed_a["artifact_id"].as_str().unwrap().to_string();
    let (status, resolved, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effecta", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effecta",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let graph_a = resolved["graph_id"].as_str().unwrap().to_string();
    let (status, prepared, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(prepared["executable"], true);
    let (status, activated, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_a,
                "deployment_space": "owner-space",
                "expected_generation": 0
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_a = activated["generation"].as_u64().unwrap();
    let (status, installed_legal, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "dev/legal", "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "host unsigned dev install: {raw}");
    assert_eq!(
        installed_legal["package_id"],
        "org.rustscript.tools.budgetlegal"
    );
    assert_eq!(installed_legal["trust"], "dev_unsigned");
    let artifact_legal = installed_legal["artifact_id"].as_str().unwrap().to_string();
    let (status, session, raw) = http
        .request("POST", "/api/sessions", json!({}), Some(token))
        .await;
    assert_eq!(status, 201, "{raw}");
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (tool_a, stop_a) = tool_then_stop("call-a", "out-a.txt");
    provider.push_ok(tool_a);
    provider.push_ok(stop_a);
    reject_unpinned_graphs(
        &http,
        &service,
        token,
        &session_id,
        &[("caller-forged-graph", 422, "plugin_graph_pin_required")],
    )
    .await;
    let (status, run_a, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "write a",
                "workspace": "name:lifecycle",
                "graph_id": graph_a
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 202, "{raw}");
    assert_eq!(run_a["graph_id"], graph_a);
    let run_a_id = run_a["run_id"].as_str().unwrap().to_string();
    let text_a = wait_marker(&workspace, "out-a.txt", "A-write").await;
    assert!(text_a.contains("A-write"), "{text_a}");
    wait_completed(&service, &run_a_id).await;
    let pin_before = {
        let persistence = GatewayPersistence::open(&config, &db).unwrap();
        PluginControlStore::new(&persistence)
            .pin_for_run(&run_a_id)
            .unwrap()
    };
    let run_before = GatewayPersistence::open(&config, &db)
        .unwrap()
        .run_get(&run_a_id)
        .unwrap();
    let control_before = control_snapshot(&config, &db);
    let fs_before = package_fs_identity(&db);
    let ids_before = fresh_package_ids(&db, &auth);
    assert!(ids_before.iter().any(|(id, artifact, trust)| {
        id == "org.rustscript.tools.effecta"
            && artifact == &artifact_a
            && *trust == PackageTrust::AcceptedPublisher
    }));
    assert!(ids_before.iter().any(|(id, artifact, trust)| {
        id == "org.rustscript.tools.budgetlegal"
            && artifact == &artifact_legal
            && *trust == PackageTrust::DevUnsigned
    }));
    assert!(
        ids_before
            .iter()
            .all(|(id, _, _)| id != "org.rustscript.tools.budgetover")
    );
    let handles_before = service.handle_count();
    let workspace_before = dir_names(&workspace);

    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "outside-unsigned", "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 403, "within-budget unsigned outside dev: {raw}");
    assert_eq!(body["error"]["code"], "plugin_publisher_unauthorized");
    assert_eq!(body["error"]["message"], body["error"]["code"]);
    no_private_text(&raw);
    assert_eq!(package_fs_identity(&db), fs_before);
    assert_eq!(fresh_package_ids(&db, &auth), ids_before);

    let (over_status, over_body, over_raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "dev/over", "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    let over_code = over_body["error"]["code"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let over_message = over_body["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        (400..500).contains(&over_status),
        "over-limit install must be 4xx, got {over_status} {over_raw}"
    );
    assert_eq!(over_message, over_code, "denial must be static: {over_raw}");
    assert_ne!(over_code, "plugin_publisher_unauthorized", "{over_raw}");
    assert_ne!(over_code, "plugin_request_invalid", "{over_raw}");
    assert_ne!(over_code, "plugin_source_rejected", "{over_raw}");
    no_private_text(&over_raw);
    assert!(
        !over_raw.contains('/') && !over_raw.contains("pad") && !over_raw.contains("manifest"),
        "budget denial leaked a path or package name: {over_raw}"
    );
    assert!(
        !over_raw.contains(&source.display().to_string()),
        "{over_raw}"
    );
    assert!(
        !over_raw.contains("package files"),
        "budget denial leaked the store chain: {over_raw}"
    );
    assert_eq!(control_snapshot(&config, &db), control_before);
    assert_eq!(package_fs_identity(&db), fs_before);
    assert!(
        package_fs_identity(&db)
            .iter()
            .all(|(name, _, _)| !name.ends_with(".tmp"))
    );
    assert_eq!(fresh_package_ids(&db, &auth), ids_before);
    assert_eq!(service.handle_count(), handles_before);
    assert_eq!(dir_names(&workspace), workspace_before);
    assert_eq!(
        std::fs::read_to_string(workspace.join("out-a.txt")).unwrap(),
        text_a
    );
    let pin_after = {
        let persistence = GatewayPersistence::open(&config, &db).unwrap();
        PluginControlStore::new(&persistence)
            .pin_for_run(&run_a_id)
            .unwrap()
    };
    assert_eq!(pin_after, pin_before);
    assert_eq!(
        GatewayPersistence::open(&config, &db)
            .unwrap()
            .run_get(&run_a_id)
            .unwrap(),
        run_before
    );

    let (status, _, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package_b, "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "healthy signed install after rejection: {raw}");
    let (status, resolved_b, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effectb", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effectb",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let graph_b = resolved_b["graph_id"].as_str().unwrap().to_string();
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "signed A still prepares: {raw}");
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_b}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let (status, activated_b, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph_b,
                "deployment_space": "owner-space",
                "expected_generation": generation_a
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_b = activated_b["generation"].as_u64().unwrap();
    let (tool_b, stop_b) = tool_then_stop("call-b", "out-b.txt");
    provider.push_ok(tool_b);
    provider.push_ok(stop_b);
    service.inject_provider_host(std::sync::Arc::new(provider.clone()));
    let (status, forged, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "rejected graph",
                "workspace": "name:lifecycle",
                "graph_id": "caller-forged-graph"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 422, "{raw}");
    assert_eq!(forged["error"]["code"], "plugin_graph_pin_required");
    assert!(forged.get("run_id").is_none(), "{raw}");
    let (status, run_b, raw) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "write b",
                "workspace": "name:lifecycle",
                "graph_id": graph_b
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 202, "{raw}");
    assert_eq!(run_b["graph_id"], graph_b);
    assert_eq!(run_b["activation_generation"], generation_b);
    let text_b = wait_marker(&workspace, "out-b.txt", "B-write").await;
    assert!(text_b.contains("B-write"), "{text_b}");
    assert_eq!(
        std::fs::read_to_string(workspace.join("out-a.txt")).unwrap(),
        text_a
    );
    let run_b_id = run_b["run_id"].as_str().unwrap().to_string();
    wait_completed(&service, &run_b_id).await;
    let fs_live = package_fs_identity(&db);
    http.close().await;
    shutdown_owned(&service).await;
    drop(service);
    drop(provider);

    let reopened = open_host_state(&config, &db, &home, auth.clone(), &source);
    let reopened_service = reopened.service();
    assert!(reopened_service.handle(&run_a_id).is_none());
    assert_eq!(reopened_service.handle_count(), 0);
    let http = Http::bind(reopened).await;
    let (status, prepared, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "cold prepare without reinstall: {raw}");
    assert_eq!(prepared["graph_id"], graph_a);
    assert_eq!(prepared["executable"], true);
    let (status, _, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_b}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(
        std::fs::read_to_string(workspace.join("out-a.txt")).unwrap(),
        text_a
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("out-b.txt")).unwrap(),
        text_b
    );
    assert_eq!(package_fs_identity(&db), fs_live);
    let ids_cold = fresh_package_ids(&db, &auth);
    assert!(ids_cold.iter().any(|(id, artifact, _)| {
        id == "org.rustscript.tools.effecta" && artifact == &artifact_a
    }));
    assert!(
        ids_cold
            .iter()
            .all(|(id, _, _)| id != "org.rustscript.tools.budgetover")
    );
    http.close().await;
    shutdown_owned(&reopened_service).await;
    drop(reopened_service);
    assert_eq!(
        over_status, 422,
        "budget denial must be 422; store kind was {over_kind:?}; got {over_status} {over_raw}"
    );
    assert_eq!(
        over_code, "plugin_budget_exceeded",
        "HTTP code must be the static budget boundary; store kind was {over_kind:?}; got {over_status} {over_raw}"
    );
    assert_eq!(
        over_message, "plugin_budget_exceeded",
        "HTTP message must equal the static budget code; got {over_status} {over_raw}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
