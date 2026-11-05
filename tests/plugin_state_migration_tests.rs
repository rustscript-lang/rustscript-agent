//! T12: versioned Native plugin state, pure migration, and checkpoint coverage.
//!
//! Every positive path compiles a signed ToolOnly package and goes through the
//! formal package store, graph lock, Native pin, and RSS storage worker. Empty
//! roots or a type-only assertion are not accepted as state support.
#[cfg(feature = "workspace-io-fault")]
use rustscript_agent::AdmitRunRequest;
use rustscript_agent::plugins::{
    HarnessSelectionRequest, InstallAuthorization, PackageRequirement, PackageStore,
    PluginStateBindRequest, PluginStatePayload, PluginStateRestoreRequest, PluginStateRootKey,
    PluginStateRootRef, PluginStateScope, PluginStateSnapshot, PluginStateStore, ResolveRequest,
};
use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, GatewayPersistence,
    config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
    effects::ResourceQuota,
};
use serde_json::json;
#[cfg(feature = "workspace-io-fault")]
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

#[cfg(feature = "workspace-io-fault")]
use futures_util::FutureExt;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::plugins::{HOST_RUNTIME, PublisherKey};
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/plugin_effect_api_cycle.rs"]
mod plugin_effect_api_cycle;
#[allow(dead_code)]
#[path = "support/signed_tool_effects.rs"]
mod signed_tool_effects;

use plugin_effect_api_cycle::{Http, explain};

fn private_root(label: &str) -> PathBuf {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("{label}-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    root
}

fn workspace_home(root: &Path) -> (PathBuf, PathBuf) {
    let home = root.join("workspace-home");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("seed.txt"), b"seed").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&home, &workspace] {
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

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    db: PathBuf,
    token: String,
    auth: InstallAuthorization,
    state: AgentGatewayState,
}

fn open_managed_run_state_fixture(label: &str) -> Fixture {
    build_run_state_fixture(label, true)
}

fn build_run_state_fixture(label: &str, managed: bool) -> Fixture {
    build_run_state_fixture_with_timeout(label, managed, std::time::Duration::from_secs(900))
}

fn build_run_state_fixture_with_timeout(
    label: &str,
    managed: bool,
    run_timeout: std::time::Duration,
) -> Fixture {
    let root = private_root(label);
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (pair, auth) = migration_auth();
    let directory = source.join("package-staterun");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("manifest.yaml"),
        state_manifest("org.rustscript.test.staterun", 1, None, ""),
    )
    .unwrap();
    std::fs::write(directory.join("run.rss"), RUN_STATE_SOURCE).unwrap();
    std::fs::write(
        directory.join("catalog.rss"),
        include_bytes!("../rss/tools/types.rss"),
    )
    .unwrap();
    let directory2 = source.join("package-staterun2");
    std::fs::create_dir_all(&directory2).unwrap();
    std::fs::write(
        directory2.join("manifest.yaml"),
        state_manifest("org.rustscript.test.staterun", 2, Some("migrate"), "[]")
            .replace("version: 1.0.0", "version: 2.0.0"),
    )
    .unwrap();
    std::fs::write(directory2.join("run.rss"), RUN_STATE_SOURCE).unwrap();
    std::fs::write(directory2.join("migrate.rss"), MIGRATION_SOURCE).unwrap();
    std::fs::write(
        directory2.join("catalog.rss"),
        include_bytes!("../rss/tools/types.rss"),
    )
    .unwrap();
    let signer = PackageStore::open(root.join(".sign")).unwrap();
    let signature = pair.sign(&signer.signature_payload(&directory).unwrap());
    std::fs::write(directory.join("signature.ed25519"), signature.as_ref()).unwrap();
    let signature2 = pair.sign(&signer.signature_payload(&directory2).unwrap());
    std::fs::write(directory2.join("signature.ed25519"), signature2.as_ref()).unwrap();
    let directory3 = source.join("package-staterun3");
    std::fs::create_dir_all(&directory3).unwrap();
    std::fs::write(
        directory3.join("manifest.yaml"),
        state_manifest("org.rustscript.test.staterun", 3, None, "")
            .replace("version: 1.0.0", "version: 3.0.0"),
    )
    .unwrap();
    std::fs::write(directory3.join("run.rss"), RUN_STATE_SOURCE).unwrap();
    std::fs::write(
        directory3.join("catalog.rss"),
        include_bytes!("../rss/tools/types.rss"),
    )
    .unwrap();
    let signature3 = pair.sign(&signer.signature_payload(&directory3).unwrap());
    std::fs::write(directory3.join("signature.ed25519"), signature3.as_ref()).unwrap();
    // Same package id and same session schema, different artifact revision.
    let directory1b = source.join("package-staterun1b");
    std::fs::create_dir_all(&directory1b).unwrap();
    std::fs::write(
        directory1b.join("manifest.yaml"),
        state_manifest("org.rustscript.test.staterun", 1, None, "")
            .replace("version: 1.0.0", "version: 1.1.0"),
    )
    .unwrap();
    std::fs::write(directory1b.join("run.rss"), RUN_STATE_SOURCE).unwrap();
    std::fs::write(
        directory1b.join("catalog.rss"),
        include_bytes!("../rss/tools/types.rss"),
    )
    .unwrap();
    let signature1b = pair.sign(&signer.signature_payload(&directory1b).unwrap());
    std::fs::write(directory1b.join("signature.ed25519"), signature1b.as_ref()).unwrap();
    let (home, workspace) = workspace_home(&root);
    let db = root.join("gateway.sqlite");
    let token = uuid::Uuid::new_v4().to_string();
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        run_timeout,
        managed_workspace: managed.then(|| ManagedWorkspaceConfig {
            source_root: workspace,
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let state = AgentGatewayState::with_sqlite_path(config, &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    Fixture {
        root,
        source,
        db,
        token,
        auth,
        state,
    }
}

fn open_fixture(label: &str) -> Fixture {
    let root = private_root(label);
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (auth, _, _, _) = signed_tool_effects::stage_write_pair(&source);
    let (home, _workspace) = workspace_home(&root);
    let db = root.join("gateway.sqlite");
    let token = uuid::Uuid::new_v4().to_string();
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let state = AgentGatewayState::with_sqlite_path(config, &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    Fixture {
        root,
        source,
        db,
        token,
        auth,
        state,
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_signed_tool_graph_prepares_and_activates() {
    let fixture = open_fixture("t12-state-activate");
    let http = Http::bind(fixture.state.clone()).await;
    for package in ["package-state"] {
        let (status, body) = http
            .request(
                "POST",
                "/v1/plugins/install",
                json!({"package": package, "deployment_space": "owner-space"}),
                Some(&fixture.token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{package}: {}", explain(status, &body));
    }
    let (status, resolved) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effectstate", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effectstate",
                "deployment_space": "owner-space"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &resolved));
    let graph = resolved["graph_id"].as_str().unwrap().to_string();
    let (status, prepared) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph}/prepare"),
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(
        status,
        200,
        "stateful signed ToolOnly graph must prepare: {}",
        explain(status, &prepared)
    );
    assert_eq!(prepared["graph_id"], graph);
    assert_eq!(prepared["executable"], true);
    let (status, activated) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph,
                "deployment_space": "owner-space",
                "expected_generation": 0
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(
        status,
        200,
        "stateful signed ToolOnly graph must activate: {}",
        explain(status, &activated)
    );
    assert_eq!(activated["graph_id"], graph);
    // Keep the fixture alive through the assertions; Drop owns cleanup.
    let _ = (&fixture.source, &fixture.db, &fixture.auth);
}

fn seed_session(persistence: &GatewayPersistence, session_id: &str, now_ms: i64) {
    persistence
        .session_create(&json!({
            "id": session_id,
            "profile": "default",
            "platform": "plugin-state-test",
            "account_id": session_id,
            "chat_id": session_id,
            "thread_id": "",
            "user_id": "",
            "generation": 1,
            "system_prompt": "",
            "model": "test-model",
            "provider": "test-provider",
            "toolset_hash": "test-tools",
            "metadata_json": "{}",
            "title": "",
            "end_reason": "",
            "now_ms": now_ms,
        }))
        .expect("seed session");
}

fn seed_run(persistence: &GatewayPersistence, session_id: &str, run_id: &str, now_ms: i64) {
    persistence
        .run_create(&json!({
            "id": run_id,
            "session_id": session_id,
            "parent_run_id": "",
            "input_json": "{}",
            "provider": "test-provider",
            "model": "test-model",
            "script_hash": "",
            "idempotency_scope": "",
            "idempotency_key": "",
            "now_ms": now_ms,
        }))
        .expect("seed run");
}

fn bind_request(
    run_id: &str,
    session_id: &str,
    plugin_id: &str,
    scope: PluginStateScope,
    schema: u32,
) -> PluginStateBindRequest {
    PluginStateBindRequest {
        run_id: run_id.into(),
        session_id: session_id.into(),
        workspace_id: "workspace-1".into(),
        branch_id: "branch-1".into(),
        plugin_id: plugin_id.into(),
        package_id: "org.rustscript.test.state".into(),
        artifact_id: "artifact-state".into(),
        scope,
        graph_id: "graph-state-1".into(),
        epoch: 1,
        schema,
        checkpoint_id: String::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_state_objects_are_immutable_and_roots_advance_by_cas() {
    let fixture = open_fixture("t12-run-state");
    let persistence = fixture.state.persistence().expect("native persistence");
    seed_session(&persistence, "session-run", 10);
    seed_run(&persistence, "session-run", "run-1", 11);
    seed_run(&persistence, "session-run", "run-2", 12);
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let first = store
        .bind_run(&bind_request(
            "run-1",
            "session-run",
            "org.rustscript.test.state",
            PluginStateScope::Run,
            1,
        ))
        .expect("bind run state root");
    assert_eq!(first.binding.schema, 1);
    assert_eq!(first.binding.revision, 1);
    assert_eq!(first.payload.as_str(), "{}");

    let one = PluginStatePayload::parse(r#"{"count":1,"name":"alpha"}"#).unwrap();
    let second = store
        .commit(&first, &one)
        .expect("commit first state object");
    assert_eq!(second.binding.revision, 2);
    assert_eq!(second.binding.object_id, second.binding.object_id);
    assert_eq!(second.payload.as_str(), one.as_str());

    let stale = store
        .commit(
            &first,
            &PluginStatePayload::parse(r#"{"count":99}"#).unwrap(),
        )
        .expect_err("stale revision must not advance the root");
    assert_eq!(stale.code, "plugin_state_conflict");
    let observed = store
        .binding("run-1")
        .expect("read binding")
        .expect("run binding");
    assert_eq!(observed.binding.revision, 2);
    assert_eq!(observed.payload.as_str(), one.as_str());

    let other = store
        .bind_run(&bind_request(
            "run-2",
            "session-run",
            "org.rustscript.test.state",
            PluginStateScope::Run,
            1,
        ))
        .expect("bind second run root");
    assert_eq!(other.binding.revision, 1);
    assert_eq!(other.payload.as_str(), "{}");
    let other_written = store
        .commit(
            &other,
            &PluginStatePayload::parse(r#"{"count":9}"#).unwrap(),
        )
        .expect("second run owns a separate root");
    assert_eq!(other_written.binding.revision, 2);
    let first_again = store
        .binding("run-1")
        .expect("read first binding")
        .expect("first binding");
    assert_eq!(first_again.payload.as_str(), one.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn session_state_pins_old_runs_across_schema_migration() {
    let fixture = open_fixture("t12-session-state");
    let persistence = fixture.state.persistence().expect("native persistence");
    seed_session(&persistence, "session-shared", 20);
    seed_run(&persistence, "session-shared", "run-old", 21);
    seed_run(&persistence, "session-shared", "run-new", 22);
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let old = store
        .bind_run(&bind_request(
            "run-old",
            "session-shared",
            "org.rustscript.test.state",
            PluginStateScope::Session,
            1,
        ))
        .expect("bind session state root");
    let old_data = store
        .commit(&old, &PluginStatePayload::parse(r#"{"v":"old"}"#).unwrap())
        .expect("write session state");
    assert_eq!(old_data.binding.revision, 2);

    let key = PluginStateRootKey {
        owner_kind: "session".into(),
        owner_id: "session-shared".into(),
        workspace_id: "workspace-1".into(),
        branch_id: "branch-1".into(),
        plugin_id: "org.rustscript.test.state".into(),
    };
    let root = store.root(&key).expect("read root").expect("session root");
    assert_eq!(root.schema, 1);
    let migrated = store
        .put_object(
            "org.rustscript.test.state",
            "artifact-state",
            2,
            &PluginStatePayload::parse(r#"{"v":"old","schema":2}"#).unwrap(),
        )
        .expect("persist migrated object");
    let new_root = store
        .migrate_root(&key, root.revision, &migrated)
        .expect("switch session root schema");
    assert_eq!(new_root.schema, 2);
    assert_eq!(new_root.revision, 3);

    let new = store
        .bind_run(&bind_request(
            "run-new",
            "session-shared",
            "org.rustscript.test.state",
            PluginStateScope::Session,
            2,
        ))
        .expect("new admission binds new schema");
    assert_eq!(new.binding.schema, 2);
    assert_eq!(new.payload.as_str(), r#"{"schema":2,"v":"old"}"#);
    let old_again = store
        .binding("run-old")
        .expect("read old binding")
        .expect("old binding");
    assert_eq!(old_again.binding.schema, 1);
    assert_eq!(old_again.payload.as_str(), r#"{"v":"old"}"#);
}

fn migration_auth() -> (Ed25519KeyPair, InstallAuthorization) {
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    (pair, auth)
}

fn state_manifest(
    id: &str,
    schema: u32,
    migration: Option<&str>,
    migration_effects: &str,
) -> String {
    let migration_block = migration
        .map(|entry| format!("  migration:\n    entry: {entry}\n"))
        .unwrap_or_default();
    let migration_entry = migration
        .map(|entry| {
            format!("    {entry}:\n      direct: {migration_effects}\n      delegated: []\n")
        })
        .unwrap_or_default();
    format!(
        "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: session\n  schema: {schema}\n{migration_block}effects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n{migration_entry}"
    )
}

fn open_managed_state_fixture(label: &str) -> Fixture {
    open_state_fixture(label, "session")
}

fn open_state_fixture(label: &str, state_scope: &str) -> Fixture {
    let root = private_root(label);
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (pair, auth) = migration_auth();
    let directory = source.join("package-staterun");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("manifest.yaml"),
        state_manifest("org.rustscript.test.staterun", 1, None, "")
            .replace("scope: session", &format!("scope: {state_scope}")),
    )
    .unwrap();
    std::fs::write(directory.join("run.rss"), RUN_STATE_SOURCE).unwrap();
    std::fs::write(
        directory.join("catalog.rss"),
        include_bytes!("../rss/tools/types.rss"),
    )
    .unwrap();
    let signer = PackageStore::open(root.join(".sign")).unwrap();
    let signature = pair.sign(&signer.signature_payload(&directory).unwrap());
    std::fs::write(directory.join("signature.ed25519"), signature.as_ref()).unwrap();
    let (home, workspace) = workspace_home(&root);
    let db = root.join("gateway.sqlite");
    let token = uuid::Uuid::new_v4().to_string();
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace,
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let state = AgentGatewayState::with_sqlite_path(config, &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    Fixture {
        root,
        source,
        db,
        token,
        auth,
        state,
    }
}

fn open_direct_state_fixture(label: &str, state_scope: &str) -> Fixture {
    let root = private_root(label);
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (pair, auth) = migration_auth();
    let directory = source.join("package-staterun");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("manifest.yaml"),
        state_manifest("org.rustscript.test.staterun", 1, None, "")
            .replace("scope: session", &format!("scope: {state_scope}")),
    )
    .unwrap();
    std::fs::write(directory.join("run.rss"), RUN_STATE_FAILFAST_SOURCE).unwrap();
    std::fs::write(
        directory.join("catalog.rss"),
        include_bytes!("../rss/tools/types.rss"),
    )
    .unwrap();
    let signer = PackageStore::open(root.join(".sign")).unwrap();
    let signature = pair.sign(&signer.signature_payload(&directory).unwrap());
    std::fs::write(directory.join("signature.ed25519"), signature.as_ref()).unwrap();
    let (home, _workspace) = workspace_home(&root);
    let db = root.join("gateway.sqlite");
    let token = uuid::Uuid::new_v4().to_string();
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    let state = AgentGatewayState::with_sqlite_path(config, &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    Fixture {
        root,
        source,
        db,
        token,
        auth,
        state,
    }
}

const RUN_STATE_FAILFAST_SOURCE: &str = r#"
pub fn run(context: map) -> map {
    let prepare: map = context.prepare;
    let prepared: map = agent_runtime::tool_prepare(prepare);
    let mut output: map = prepared;
    if prepared.ok {
        let token: string = prepared.execution_token;
        let current: map = state::read();
        let decoded: map = json::decode(current.document);
        let mut count: int = 0;
        if decoded.has("count") {
            count = decoded.count;
        }
        count = count + 1;
        let document: string = json::encode({ count: count });
        let written: map = state::write(current.revision, document);
        if written.ok {
            let result: map = { ok: true, content: "state", data: { revision: written.revision, schema: written.schema, durable: written.durable }, error: {}, truncated: false, artifacts: [] };
            output = agent_runtime::tool_commit(token, result);
        } else {
            let result: map = { ok: false, content: "", data: {}, error: written.error, truncated: false, artifacts: [] };
            output = agent_runtime::tool_commit(token, result);
        }
    }
    output
}
"#;

const RUN_SOURCE: &str = r#"
pub fn run(context: map) -> map {
    { ok: true, content: "state", data: {}, error: {}, truncated: false, artifacts: [] }
}
"#;

const RUN_STATE_SOURCE: &str = r#"
pub fn run(context: map) -> map {
    let prepare: map = context.prepare;
    let prepared: map = agent_runtime::tool_prepare(prepare);
    let mut output: map = prepared;
    if prepared.ok {
        let token: string = prepared.execution_token;
        let meta: map = cap::fs_metadata(token, "seed.txt");
        if meta.ok {
            let current: map = state::read();
            let decoded: map = json::decode(current.document);
            let mut count: int = 0;
            if decoded.has("count") {
                count = decoded.count;
            }
            count = count + 1;
            let document: string = json::encode({ count: count });
            let written: map = state::write(current.revision, document);
            let reread: map = state::read();
            let written_ok: bool = written.ok;
            let reread_ok: bool = reread.ok;
            let written_revision: int = written.revision;
            let reread_revision: int = reread.revision;
            let reread_document: string = reread.document;
            let same: bool = written_ok && reread_ok && reread_revision == written_revision && reread_document == document;
            let mut durable: bool = false;
            if written_ok {
                let coerced: bool = written.durable;
                durable = coerced;
            }
            let mut error: map = {};
            if written_ok {
                error = {};
            } else {
                let coerced_error: map = written.error;
                error = coerced_error;
            }
            let result: map = { ok: same, content: "state", data: { revision: written_revision, schema: written.schema, durable: durable }, error: error, truncated: false, artifacts: [] };
            output = agent_runtime::tool_commit(token, result);
        }
    }
    output
}
"#;

const MIGRATION_SOURCE: &str = r#"
use json;
pub fn migrate(input: map) -> map {
    let document: string = input["document"];
    let mut decoded: map = json::decode(document);
    decoded.version = 2;
    { schema: 2, document: json::encode(decoded) }
}
"#;

fn try_install_state_package(
    root: &std::path::Path,
    id: &str,
    schema: u32,
    migration: Option<&str>,
    migration_source: &str,
    migration_effects: &str,
) -> Result<(PackageStore, InstallAuthorization), rustscript_agent::plugins::PluginError> {
    let (pair, auth) = migration_auth();
    let packages = root.join("packages");
    let store = PackageStore::open(&packages).unwrap();
    store.bind_policy(&auth);
    let directory = root.join(format!("package-{id}"));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("manifest.yaml"),
        state_manifest(id, schema, migration, migration_effects),
    )
    .unwrap();
    std::fs::write(directory.join("run.rss"), RUN_SOURCE).unwrap();
    if migration.is_some() {
        std::fs::write(directory.join("migrate.rss"), migration_source).unwrap();
    }
    let signature = pair.sign(&store.signature_payload(&directory).unwrap());
    std::fs::write(directory.join("signature.ed25519"), signature.as_ref()).unwrap();
    store.install(&directory, &auth)?;
    Ok((store, auth))
}

fn install_state_package(
    root: &std::path::Path,
    id: &str,
    schema: u32,
    migration: Option<&str>,
    migration_source: &str,
    migration_effects: &str,
) -> (PackageStore, InstallAuthorization) {
    try_install_state_package(
        root,
        id,
        schema,
        migration,
        migration_source,
        migration_effects,
    )
    .unwrap_or_else(|error| panic!("state package {id} installs: {error:?}"))
}

fn prepare_state_package(
    store: &PackageStore,
    id: &str,
) -> Result<rustscript_agent::plugins::GraphLock, rustscript_agent::plugins::PluginError> {
    let lock = store
        .resolve(&ResolveRequest {
            harness_selection: HarnessSelectionRequest::ToolOnly {
                tool_package: id.into(),
            },
            roots: vec![PackageRequirement {
                id: id.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: HOST_RUNTIME.into(),
        })
        .unwrap();
    store.prepare(&lock)?;
    Ok(lock)
}

#[test]
fn pure_rss_migration_is_compiled_and_executed_without_host_imports() {
    let root = private_root("t12-migration-pure");
    let id = "org.rustscript.test.state2";
    let (store, _auth) =
        install_state_package(&root, id, 2, Some("migrate"), MIGRATION_SOURCE, "[]");
    let lock = store
        .resolve(&ResolveRequest {
            harness_selection: HarnessSelectionRequest::ToolOnly {
                tool_package: id.into(),
            },
            roots: vec![PackageRequirement {
                id: id.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: HOST_RUNTIME.into(),
        })
        .unwrap();
    let prepared = store.prepare(&lock).expect("stateful graph prepares");
    let migration = prepared
        .state_migration(id)
        .expect("compiled pure migration entry");
    assert_eq!(migration.target_schema, 2);
    let old = PluginStatePayload::parse(r#"{"count":1}"#).unwrap();
    let cancellation = rustscript_agent::RunCancellation::with_deadline(
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    );
    let new = migration
        .evaluate(1, &old, &cancellation)
        .expect("real RSS migration runs");
    assert_eq!(new.as_str(), r#"{"count":1,"version":2}"#);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn migration_with_sql_or_effectful_host_import_is_rejected_before_execution() {
    let root = private_root("t12-migration-impure");
    let id = "org.rustscript.test.stateimpure";
    let impure = r#"
use sqlite as sqlite;
pub fn migrate(input: map) -> map {
    let rows = sqlite::query("select 1", [], {});
    { schema: 2, document: input.document }
}
"#;
    let (store, _auth) = install_state_package(&root, id, 2, Some("migrate"), impure, "[]");
    let error = prepare_state_package(&store, id).expect_err("impure migration must not prepare");
    let rendered = format!("{error:?}");
    assert!(
        rendered.contains("plugin_state_migration_impure"),
        "unexpected rejection: {rendered}"
    );
    let _ = std::fs::remove_dir_all(root);

    let root = private_root("t12-migration-effect");
    let id = "org.rustscript.test.stateeffect";
    let error = match try_install_state_package(
        &root,
        id,
        2,
        Some("migrate"),
        MIGRATION_SOURCE,
        "[{kind: workspace.fs.write, scope: bound_workspace, recovery: none}]",
    ) {
        Ok(_) => panic!("effectful migration must be rejected before execution"),
        Err(error) => error,
    };
    assert!(
        format!("{error:?}").contains("state migration must be pure"),
        "unexpected rejection: {error:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

async fn run_state_plugin(http: &Http, token: &str) -> String {
    let (status, body) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "package-staterun", "deployment_space": "owner-space"}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &body));
    let (status, resolved) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.test.staterun", "version": "1.0.0"}],
                "tool_package": "org.rustscript.test.staterun",
                "deployment_space": "owner-space"
            }),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &resolved));
    let graph = resolved["graph_id"].as_str().unwrap().to_string();
    let (status, prepared) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph}/prepare"),
            json!({}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &prepared));
    let (status, activated) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({"graph_id": graph, "deployment_space": "owner-space", "expected_generation": 0}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &activated));
    graph
}

async fn admit_state_run(
    http: &Http,
    token: &str,
    session_id: &str,
    provider: &rustscript_agent::ScriptedProvider,
) -> String {
    let (status, admitted) =
        admit_state_run_response(http, token, session_id, None, None, provider).await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    admitted["run_id"].as_str().unwrap().to_string()
}

async fn admit_state_run_on_branch(
    http: &Http,
    token: &str,
    session_id: &str,
    branch: &str,
    graph: &str,
    provider: &rustscript_agent::ScriptedProvider,
) -> String {
    let (status, admitted) =
        admit_state_run_response(http, token, session_id, Some(branch), Some(graph), provider)
            .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    admitted["run_id"].as_str().unwrap().to_string()
}

async fn admit_state_run_response(
    http: &Http,
    token: &str,
    session_id: &str,
    branch: Option<&str>,
    graph: Option<&str>,
    provider: &rustscript_agent::ScriptedProvider,
) -> (u16, serde_json::Value) {
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": "state-call", "name": "read_file", "arguments": {"path": "seed.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(json!({
        "text": "done",
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    }));
    let mut body = json!({"session_id": session_id, "input": "state run"});
    if let Some(branch) = branch {
        body["workspace_branch"] = json!(branch);
    }
    if let Some(graph) = graph {
        body["graph_id"] = json!(graph);
    }
    http.request(
        "POST",
        "/v1/runs",
        body,
        Some(token),
        Some(&uuid::Uuid::new_v4().to_string()),
    )
    .await
}

#[cfg(feature = "workspace-io-fault")]
async fn admit_run_with_identity(
    http: &Http,
    token: &str,
    session_id: &str,
    input: &str,
    graph: Option<&str>,
    idempotency_key: &str,
) -> (u16, serde_json::Value) {
    let mut body = json!({"session_id": session_id, "input": input});
    if let Some(graph) = graph {
        body["graph_id"] = json!(graph);
    }
    http.request("POST", "/v1/runs", body, Some(token), Some(idempotency_key))
        .await
}

fn script_state_turns(provider: &rustscript_agent::ScriptedProvider) {
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": "state-call", "name": "read_file", "arguments": {"path": "seed.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(json!({
        "text": "done",
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    }));
}

/// Installs one signed package version, prepares its graph, and activates it.
async fn activate_state_package(
    http: &Http,
    token: &str,
    package: &str,
    version: &str,
) -> (String, u64) {
    let (status, body) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package, "deployment_space": "owner-space"}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{package}: {}", explain(status, &body));
    let (status, resolved) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.test.staterun", "version": version}],
                "tool_package": "org.rustscript.test.staterun",
                "deployment_space": "owner-space"
            }),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{version}: {}", explain(status, &resolved));
    let graph = resolved["graph_id"].as_str().unwrap().to_string();
    let (status, prepared) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph}/prepare"),
            json!({}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{version}: {}", explain(status, &prepared));
    let (status, activated) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph,
                "deployment_space": "owner-space",
                "expected_generation": resolved["generation"].as_u64().unwrap_or(0)
            }),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{version}: {}", explain(status, &activated));
    (graph, activated["generation"].as_u64().unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_tool_state_read_write_uses_the_native_bridge_and_durable_cas() {
    let fixture = open_managed_run_state_fixture("t12-native-read-write");
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let provider = rustscript_agent::ScriptedProvider::new();
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let run_id = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let run = persistence.run_get(&run_id).unwrap_or_default();
        let status = run["rows"][0][3].as_str().unwrap_or("");
        if status == "completed" {
            break;
        }
        if status == "failed" {
            let events = fixture.state.service().run_events(&run_id);
            panic!("state run failed: events={events:?}");
        }
        if std::time::Instant::now() >= deadline {
            let events = fixture.state.service().run_events(&run_id);
            panic!("state run did not finish: run={run} events={events:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let first = store
        .binding(&run_id)
        .expect("state binding")
        .expect("run state binding");
    assert_eq!(first.binding.revision, 2);
    assert_eq!(first.payload.as_str(), r#"{"count":1}"#);
    let record = ["local-agent", "gateway", "default"]
        .iter()
        .find_map(|profile| {
            persistence
                .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
                    owner: rustscript_agent::effects::ManagedOwnerScope {
                        profile: (*profile).into(),
                        session_id: session_id.clone(),
                        run_id: run_id.clone(),
                    },
                    call_id: "state-call".into(),
                })
                .ok()
                .flatten()
        })
        .expect("managed state effect receipt");
    let publication = record
        .prepared
        .as_ref()
        .expect("prepared managed receipt")
        .plugin_state
        .as_ref()
        .expect("state publication in the receipt");
    assert!(!publication.ephemeral);
    assert_eq!(publication.owner_kind, "session");
    assert_eq!(publication.object_id, first.binding.object_id);
    assert_eq!(publication.schema_version, first.binding.schema);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let second_run = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    loop {
        let run = persistence.run_get(&second_run).unwrap_or_default();
        let status = run["rows"][0][3].as_str().unwrap_or("");
        if status == "completed" {
            break;
        }
        if status == "failed" {
            let events = fixture.state.service().run_events(&second_run);
            panic!("second state run failed: events={events:?}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "second state run did not finish"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let second = store
        .binding(&second_run)
        .expect("second state binding")
        .expect("second run state binding");
    assert_eq!(second.binding.revision, 3);
    assert_eq!(second.payload.as_str(), r#"{"count":2}"#);
    assert_ne!(first.binding.object_id, second.binding.object_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_mode_state_write_without_managed_receipt_fails_closed() {
    for scope in ["run", "session", "invocation"] {
        let fixture = open_direct_state_fixture(&format!("t12-direct-deny-{scope}"), scope);
        let http = Http::bind(fixture.state.clone()).await;
        run_state_plugin(&http, &fixture.token).await;
        let (status, session) = http
            .request(
                "POST",
                "/api/sessions",
                json!({}),
                Some(&fixture.token),
                None,
            )
            .await;
        assert_eq!(status, 201, "{scope}: {}", explain(status, &session));
        let session_id = session["session"]["id"].as_str().unwrap().to_string();
        let provider = rustscript_agent::ScriptedProvider::new();
        fixture
            .state
            .service()
            .inject_provider_host(Arc::new(provider.clone()));
        let run_id = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
        wait_run_terminal(&fixture.state, &run_id).await;
        let events = fixture.state.service().run_events(&run_id);
        let failed = events
            .iter()
            .find(|event| event["event"] == "tool.failed")
            .unwrap_or_else(|| panic!("{scope}: state write must fail the tool call: {events:?}"));
        assert_eq!(
            failed["data"]["error_code"], "plugin_state_effect_unavailable",
            "{scope}: {events:?}"
        );
        let persistence = fixture.state.persistence().unwrap();
        let store = PluginStateStore::open(Arc::clone(&persistence));
        let binding = store.binding(&run_id).expect("binding read");
        if scope == "invocation" {
            assert!(binding.is_none(), "invocation state must not persist");
            assert_eq!(
                store
                    .session_max_schema("org.rustscript.test.staterun")
                    .unwrap(),
                0
            );
        } else {
            let binding = binding.expect("durable run binding");
            assert_eq!(binding.binding.schema, 1);
            assert_eq!(binding.binding.revision, 1);
            assert_eq!(binding.payload.as_str(), "{}");
            let key = PluginStateRootKey {
                owner_kind: scope.to_string(),
                owner_id: if scope == "run" {
                    run_id.clone()
                } else {
                    session_id.clone()
                },
                workspace_id: binding.binding.workspace_id.clone(),
                branch_id: binding.binding.branch_id.clone(),
                plugin_id: binding.binding.plugin_id.clone(),
            };
            let root = store.root(&key).expect("root read").expect("state root");
            assert_eq!(root.schema, 1);
            assert_eq!(root.revision, 1);
            assert_eq!(root.object_id, binding.binding.object_id);
            let receipt = ["local-agent", "gateway", "default"]
                .iter()
                .find_map(|profile| {
                    persistence
                        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
                            owner: rustscript_agent::effects::ManagedOwnerScope {
                                profile: (*profile).into(),
                                session_id: session_id.clone(),
                                run_id: run_id.clone(),
                            },
                            call_id: "state-call".into(),
                        })
                        .ok()
                        .flatten()
                });
            assert!(
                receipt.is_none(),
                "{scope}: direct mode cannot own a managed effect receipt"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_roots_restore_exact_state_into_a_new_branch_and_run() {
    let fixture = open_fixture("t12-checkpoint-state");
    let persistence = fixture.state.persistence().expect("native persistence");
    seed_session(&persistence, "session-cp", 30);
    seed_run(&persistence, "session-cp", "run-source", 31);
    seed_run(&persistence, "session-cp", "run-restored", 32);
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let source = store
        .bind_run(&bind_request(
            "run-source",
            "session-cp",
            "org.rustscript.test.state",
            PluginStateScope::Session,
            1,
        ))
        .expect("bind source state");
    let written = store
        .commit(
            &source,
            &PluginStatePayload::parse(r#"{"count":1}"#).unwrap(),
        )
        .expect("write source state");
    assert_eq!(written.binding.revision, 2);
    let roots = store
        .checkpoint_roots("run-source")
        .expect("checkpoint roots");
    assert!(!roots.is_empty());
    assert_eq!(
        roots
            .iter()
            .find(|root| root.owner_kind == "session")
            .expect("session root")
            .object_id,
        written.binding.object_id
    );

    let restore_roots: Vec<PluginStateRootRef> = roots
        .iter()
        .map(|root| PluginStateRootRef {
            owner_kind: root.owner_kind.clone(),
            owner_id: root.owner_id.clone(),
            workspace_id: root.workspace_id.clone(),
            branch_id: root.branch_id.clone(),
            plugin_id: root.plugin_id.clone(),
            package_id: root.package_id.clone(),
            artifact_id: root.artifact_id.clone(),
            schema: root.schema,
            revision: root.revision,
            object_id: root.object_id.clone(),
        })
        .collect();
    let restored = store
        .restore_binding(&PluginStateRestoreRequest {
            scope: PluginStateScope::Session,
            run_id: "run-restored".into(),
            session_id: "session-cp".into(),
            workspace_id: "workspace-1".into(),
            branch_id: "branch-restored".into(),
            plugin_id: "org.rustscript.test.state".into(),
            package_id: "org.rustscript.test.state".into(),
            artifact_id: "artifact-state".into(),
            graph_id: "graph-state-1".into(),
            epoch: 1,
            checkpoint_id: "checkpoint-1".into(),
            roots: restore_roots.clone(),
        })
        .expect("restore exact state root");
    assert_eq!(restored.binding.revision, 1);
    assert_eq!(restored.binding.checkpoint_id, "checkpoint-1");
    assert_eq!(restored.binding.object_id, written.binding.object_id);
    assert_eq!(restored.payload.as_str(), r#"{"count":1}"#);
    let source_again = store
        .binding("run-source")
        .expect("source binding")
        .expect("source state binding");
    assert_eq!(source_again.binding.revision, 2);
    assert_eq!(source_again.payload.as_str(), r#"{"count":1}"#);

    let advanced = store
        .commit(
            &restored,
            &PluginStatePayload::parse(r#"{"count":2}"#).unwrap(),
        )
        .expect("restored branch advances independently");
    assert_eq!(advanced.binding.revision, 2);
    let source_final = store
        .binding("run-source")
        .expect("source binding")
        .expect("source state binding");
    assert_eq!(source_final.binding.object_id, written.binding.object_id);

    let forged = store
        .restore_binding(&PluginStateRestoreRequest {
            scope: PluginStateScope::Session,
            run_id: "run-restored".into(),
            session_id: "session-cp".into(),
            workspace_id: "workspace-1".into(),
            branch_id: "branch-forged".into(),
            plugin_id: "org.rustscript.test.state".into(),
            package_id: "org.rustscript.test.state".into(),
            artifact_id: "artifact-state".into(),
            graph_id: "graph-state-1".into(),
            epoch: 1,
            checkpoint_id: "checkpoint-forged".into(),
            roots: restore_roots
                .iter()
                .map(|root| PluginStateRootRef {
                    plugin_id: "org.rustscript.test.foreign".into(),
                    ..root.clone()
                })
                .collect(),
        })
        .expect_err("foreign checkpoint root must be rejected");
    assert_eq!(forged.code, "plugin_state_root_missing");
    assert_eq!(
        store
            .binding("run-restored")
            .expect("binding")
            .expect("binding")
            .binding
            .checkpoint_id,
        "checkpoint-1"
    );
}

fn complete_durable_run(persistence: &GatewayPersistence, run_id: &str) {
    persistence
        .run_transition(&json!({
            "run_id": run_id,
            "from_status": "queued",
            "to_status": "running",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": 40
        }))
        .expect("start durable blocker run");
}

fn terminal_run_payload(run_id: &str) -> serde_json::Value {
    json!({
        "run_id": run_id,
        "to_status": "completed",
        "error_code": "",
        "error_message": "",
        "event_1_id": "",
        "event_1_type": "",
        "event_1_payload": "",
        "event_2_id": "",
        "event_2_type": "",
        "event_2_payload": "",
        "event_count": 0,
        "message_id": "",
        "message_session_id": "",
        "message_role": "",
        "message_content_json": "",
        "message_run_id": "",
        "message_finish_reason": "",
        "now_ms": 41
    })
}

fn terminate_durable_run(persistence: &GatewayPersistence, run_id: &str) {
    persistence
        .run_terminal(&terminal_run_payload(run_id))
        .expect("terminate durable blocker run");
}

fn wait_approval_durable_run(persistence: &GatewayPersistence, run_id: &str) {
    persistence
        .run_transition(&json!({
            "run_id": run_id,
            "from_status": "running",
            "to_status": "waiting_approval",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": 43
        }))
        .expect("park durable blocker run");
}

fn complete_waiting_durable_run(persistence: &GatewayPersistence, run_id: &str) {
    persistence
        .run_transition(&json!({
            "run_id": run_id,
            "from_status": "waiting_approval",
            "to_status": "completed",
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": 44
        }))
        .expect("complete parked blocker run");
}

async fn wait_run_terminal(state: &AgentGatewayState, run_id: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let persistence = state.persistence().unwrap();
        let run = persistence.run_get(run_id).unwrap_or_default();
        let status = run["rows"][0][3].as_str().unwrap_or("");
        if status == "completed" {
            return;
        }
        if status == "failed" {
            let events = state.service().run_events(run_id);
            panic!("run {run_id} failed: events={events:?}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "run {run_id} did not finish"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

async fn wait_run_any_terminal(state: &AgentGatewayState, run_id: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let persistence = state.persistence().unwrap();
        let run = persistence.run_get(run_id).unwrap_or_default();
        let status = run["rows"][0][3].as_str().unwrap_or("").to_string();
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            if status == "failed" {
                panic!(
                    "run {run_id} failed: {:?}",
                    state.service().run_events(run_id)
                );
            }
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "run {run_id} did not reach a terminal status, last={status}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

async fn wait_provider_call(provider: &rustscript_agent::ScriptedProvider) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while provider.call_count() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "hanging provider was never entered"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn create_session(http: &Http, token: &str) -> String {
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    session["session"]["id"].as_str().unwrap().to_string()
}

/// R1 direct regression: a same-schema session-state admission must not wait
/// for another nonterminal run, keep the maintenance lease, or consume the
/// deadline; a real switch must still wait, cancel on the original deadline,
/// release the lease, and succeed on retry.
#[tokio::test(flavor = "multi_thread")]
async fn same_schema_admission_does_not_wait_for_nonterminal_run() {
    let fixture = build_run_state_fixture_with_timeout(
        "t12-same-schema-nonblocking",
        true,
        std::time::Duration::from_secs(10),
    );
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let seed_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(seed_provider.clone()));
    let baseline_run = admit_state_run(&http, &fixture.token, &session_id, &seed_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema1 session root");
    let root_before = store.root(&key).expect("root").expect("schema1 root");
    assert_eq!(root_before.schema, 1);

    let holder = rustscript_agent::ScriptedProvider::new();
    holder.push_hang();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(holder.clone()));
    let blocking_run = admit_state_run(&http, &fixture.token, &session_id, &holder).await;
    wait_provider_call(&holder).await;
    let blocking_status = persistence.run_get(&blocking_run).unwrap()["rows"][0][3]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert_eq!(blocking_status, "running");

    let same_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(same_provider.clone()));
    let started = std::time::Instant::now();
    let (status, body) = admit_state_run_response(
        &http,
        &fixture.token,
        &session_id,
        None,
        None,
        &same_provider,
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(
        status,
        202,
        "same-schema admission must not wait for a nonterminal run: {elapsed:?} {}",
        explain(status, &body)
    );
    assert!(
        elapsed < std::time::Duration::from_millis(1500),
        "same-schema admission consumed the run deadline: {elapsed:?}"
    );
    assert_eq!(
        persistence.run_get(&blocking_run).unwrap()["rows"][0][3]
            .as_str()
            .unwrap_or(""),
        "running",
        "the same-schema admission must not wait for or terminate the blocker"
    );
    let same_run = body["run_id"].as_str().unwrap().to_string();
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &same_run).await,
        "completed"
    );

    let other_session = create_session(&http, &fixture.token).await;
    let other_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(other_provider.clone()));
    let other_run = admit_state_run(&http, &fixture.token, &other_session, &other_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &other_run).await,
        "completed"
    );

    let (status, stopped) = http
        .request(
            "POST",
            &format!("/v1/runs/{blocking_run}/stop"),
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &stopped));
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &blocking_run).await,
        "cancelled"
    );

    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    let switch_blocker = "switch-approval-blocker";
    seed_run(&persistence, &session_id, switch_blocker, 77);
    complete_durable_run(&persistence, switch_blocker);
    wait_approval_durable_run(&persistence, switch_blocker);
    let switch_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(switch_provider.clone()));
    let switch_started = std::time::Instant::now();
    let (status, busy) = admit_state_run_response(
        &http,
        &fixture.token,
        &session_id,
        None,
        Some(&graph2),
        &switch_provider,
    )
    .await;
    let switch_elapsed = switch_started.elapsed();
    assert_eq!(status, 422, "{}", explain(status, &busy));
    assert_eq!(busy["error"]["code"], "invalid_admission");
    assert!(
        switch_elapsed >= std::time::Duration::from_millis(3000),
        "a real schema switch must wait for the nonterminal run: {switch_elapsed:?}"
    );
    assert_eq!(
        persistence.run_get(switch_blocker).unwrap()["rows"][0][3]
            .as_str()
            .unwrap_or(""),
        "waiting_approval",
        "the switch attempt must not terminate the parked blocker"
    );
    complete_waiting_durable_run(&persistence, switch_blocker);

    let retry_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(retry_provider.clone()));
    let (status, retried) = admit_state_run_response(
        &http,
        &fixture.token,
        &session_id,
        None,
        Some(&graph2),
        &retry_provider,
    )
    .await;
    assert_eq!(status, 202, "{}", explain(status, &retried));
    let retry_run = retried["run_id"].as_str().unwrap().to_string();
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &retry_run).await,
        "completed"
    );
    let root_after = store.root(&key).expect("root").expect("schema2 root");
    assert_eq!(root_after.schema, 2);
    assert_eq!(
        store
            .binding(&retry_run)
            .expect("binding")
            .expect("schema2 binding")
            .binding
            .schema,
        2
    );
}

/// 401-R1-A: an existing session root was created by artifact A of a package.
/// A compatible new artifact revision B of the same package declares the same
/// session schema. While an old A-pinned run is still nonterminal, admitting a
/// run pinned to B must reuse the live root (package/artifact A) and its data
/// instead of rejecting the root identity. The guard still re-verifies the exact
/// live root inside the durable transaction, so a real schema change between
/// preparation and commit fails closed (separate assertion below).
#[tokio::test(flavor = "multi_thread")]
async fn same_schema_new_artifact_reuses_live_root_and_fails_closed_on_schema_switch() {
    let fixture = open_managed_run_state_fixture("t12-same-schema-artifact-upgrade");
    let http = Http::bind(fixture.state.clone()).await;
    let graph1 = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let baseline_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&baseline_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(baseline_provider.clone()));
    let baseline_run =
        admit_state_run(&http, &fixture.token, &session_id, &baseline_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema1 session root");
    let root_before = store.root(&key).expect("root").expect("schema1 root");
    assert_eq!(root_before.schema, 1);
    let baseline_binding = store
        .binding(&baseline_run)
        .expect("baseline binding")
        .expect("baseline state binding");
    assert_eq!(baseline_binding.payload.as_str(), r#"{"count":1}"#);
    assert_eq!(
        baseline_binding.binding.artifact_id,
        root_before.artifact_id
    );

    // An A-pinned run stays nonterminal: the same-schema guard must not wait.
    let holder = rustscript_agent::ScriptedProvider::new();
    holder.push_hang();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(holder.clone()));
    let holder_run = admit_state_run(&http, &fixture.token, &session_id, &holder).await;
    wait_provider_call(&holder).await;
    assert_eq!(
        persistence.run_get(&holder_run).unwrap()["rows"][0][3]
            .as_str()
            .unwrap_or(""),
        "running"
    );

    // Signed install + activation of the compatible same-schema new artifact.
    let (graph_b, _) =
        activate_state_package(&http, &fixture.token, "package-staterun1b", "1.1.0").await;

    let upgrade_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&upgrade_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(upgrade_provider.clone()));
    let started = std::time::Instant::now();
    let (status, upgraded) = admit_state_run_response(
        &http,
        &fixture.token,
        &session_id,
        None,
        Some(&graph_b),
        &upgrade_provider,
    )
    .await;
    let elapsed = started.elapsed();

    // Always settle the hanging old run before asserting so a RED failure can
    // still tear the fixture down (the provider only returns on cancellation).
    let (stop_status, stopped) = http
        .request(
            "POST",
            &format!("/v1/runs/{holder_run}/stop"),
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(stop_status, 200, "{}", explain(stop_status, &stopped));
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &holder_run).await,
        "cancelled"
    );

    assert_eq!(
        status,
        202,
        "same-schema new artifact admission must reuse the live root: {}",
        explain(status, &upgraded)
    );
    assert!(
        elapsed < std::time::Duration::from_millis(1500),
        "compatible same-schema admission must not wait for the old run: {elapsed:?}"
    );
    let upgraded_run = upgraded["run_id"].as_str().unwrap().to_string();
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &upgraded_run).await,
        "completed"
    );
    let upgraded_binding = store
        .binding(&upgraded_run)
        .expect("upgraded binding")
        .expect("schema1 upgraded binding");
    assert_eq!(upgraded_binding.binding.schema, 1);
    assert_eq!(
        upgraded_binding.binding.artifact_id, root_before.artifact_id,
        "the compatible admission continues on the live root artifact identity"
    );
    // count 1 from the baseline; the hanging holder never reached its tool.
    assert_eq!(
        upgraded_binding.payload.as_str(),
        r#"{"count":2}"#,
        "the new artifact run reads the durable data created under artifact A"
    );
    let root_after_upgrade = store.root(&key).expect("root").expect("schema1 root");
    assert_eq!(root_after_upgrade.schema, 1);
    assert!(!graph1.is_empty());
}

/// 401-R1-A orthogonal guard: a real session schema switch that lands between
/// preparation and the durable admission must still fail the admission closed.
/// The switch runs through the production `switch_plugin_state_schema` path
/// inside the real guarded transaction's precommit seam.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn same_schema_guard_fails_closed_on_real_schema_switch_before_commit() {
    let fixture = open_managed_run_state_fixture("t12-guard-schema-switch-failclosed");
    let http = Http::bind(fixture.state.clone()).await;
    let graph1 = run_state_plugin(&http, &fixture.token).await;
    assert!(!graph1.is_empty());
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let baseline_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&baseline_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(baseline_provider.clone()));
    let baseline_run =
        admit_state_run(&http, &fixture.token, &session_id, &baseline_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema1 session root");
    assert_eq!(store.root(&key).expect("root").expect("root").schema, 1);

    // Install/resolve/prepare schema2 without activating it: the running
    // admission keeps the active graph1 pin it prepared.
    let (status, installed) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "package-staterun2", "deployment_space": "owner-space"}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &installed));
    let (status, resolved2) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.test.staterun", "version": "2.0.0"}],
                "tool_package": "org.rustscript.test.staterun",
                "deployment_space": "owner-space"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &resolved2));
    let graph2 = resolved2["graph_id"].as_str().unwrap().to_string();
    let (status, prepared2) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph2}/prepare"),
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &prepared2));

    let service = fixture.state.service().clone();
    let switch_session = session_id.clone();
    let switch_graph = graph2.clone();
    #[allow(clippy::type_complexity)]
    let switch_result: Arc<std::sync::Mutex<Option<Result<Option<u64>, &'static str>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let recorded = Arc::clone(&switch_result);
    // The boundary hook fires once at admission start and once immediately
    // before the real commit gate. Only the latter is the prepare->commit
    // window this test exercises.
    let boundary_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Arc::clone(&boundary_calls);
    fixture
        .state
        .service()
        .observe_admission_commit_boundary(Arc::new(move || {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return;
            }
            let cancellation = rustscript_agent::RunCancellation::with_deadline(
                std::time::Instant::now() + std::time::Duration::from_secs(15),
            );
            let result =
                service.switch_plugin_state_schema(&switch_session, &switch_graph, &cancellation);
            *recorded.lock().expect("switch result") = Some(result);
        }));

    let admission_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&admission_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(admission_provider.clone()));
    let (status, body) = admit_state_run_response(
        &http,
        &fixture.token,
        &session_id,
        None,
        None,
        &admission_provider,
    )
    .await;
    assert_eq!(
        status,
        503,
        "a root schema change between preparation and commit must fail closed: {}",
        explain(status, &body)
    );
    assert_eq!(body["error"]["code"], "persistence_unavailable");
    let switched = (*switch_result.lock().expect("switch result")).expect("precommit switch ran");
    assert!(
        switched.is_ok(),
        "the real switch itself succeeds: {switched:?}"
    );
    assert_eq!(
        store.root(&key).expect("root").expect("root").schema,
        2,
        "the concurrent switch published schema2"
    );
    // The guarded admission rolled back: no run row was committed for it.
    assert!(
        store
            .session_root_key(&session_id, "org.rustscript.test.staterun")
            .expect("session key")
            .is_some()
    );
    assert!(!graph1.is_empty());
}

#[cfg(feature = "workspace-io-fault")]
const LEASE_CLEANUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
/// Independent, bounded teardown net used only after the primary cleanup has
/// already recorded a failure. It can never turn that failure into a pass.
#[cfg(feature = "workspace-io-fault")]
const LEASE_TEARDOWN_FALLBACK_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(feature = "workspace-io-fault")]
const FORCED_OBSERVATION_FAILURE: &str = "forced-maintenance-wait-observation-failure";

/// Durable run status parsed from the typed `run.get` row. An unrecognised
/// string stays distinct: only the explicit terminal statuses of the storage
/// contract may skip a typed transition.
#[cfg(feature = "workspace-io-fault")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum DurableRunStatus {
    Queued,
    Running,
    WaitingApproval,
    Compacting,
    Completed,
    Failed,
    Cancelled,
    Unrecognized(String),
}

#[cfg(feature = "workspace-io-fault")]
impl DurableRunStatus {
    fn parse(value: &str) -> Self {
        match value {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "waiting_approval" => Self::WaitingApproval,
            "compacting" => Self::Compacting,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            other => Self::Unrecognized(other.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::WaitingApproval => "waiting_approval",
            Self::Compacting => "compacting",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unrecognized(other) => other,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Named failure of one durable status read. A failed read is never folded
/// into "no run": the caller keeps the committed run id and must still try the
/// existing typed terminal transition.
#[cfg(feature = "workspace-io-fault")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunStatusReadError {
    /// The storage command itself failed (worker error, timeout, injected fault).
    Storage(String),
    /// `run.get` succeeded but returned no row for an already committed run id.
    MissingRun(String),
    /// `run.get` returned a row whose status column is absent or not a string.
    MalformedRow(String),
}

#[cfg(feature = "workspace-io-fault")]
impl RunStatusReadError {
    fn injected() -> Self {
        Self::Storage(
            "fixture one-shot cleanup status-read failure (injected at the fixture cleanup \
             reader before the store call)"
                .to_string(),
        )
    }

    fn is_injected(&self) -> bool {
        matches!(self, Self::Storage(message) if message.contains("fixture one-shot"))
    }
}

#[cfg(feature = "workspace-io-fault")]
impl std::fmt::Display for RunStatusReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(message) => write!(formatter, "storage: {message}"),
            Self::MissingRun(message) => write!(formatter, "missing_run: {message}"),
            Self::MalformedRow(message) => write!(formatter, "malformed_row: {message}"),
        }
    }
}

/// Typed durable status read. A `run.get` error, a missing row for a known run
/// id, and an unexpected row shape all stay distinct `Err` values.
#[cfg(feature = "workspace-io-fault")]
fn durable_run_status(
    persistence: &GatewayPersistence,
    run_id: &str,
) -> Result<DurableRunStatus, RunStatusReadError> {
    let data = persistence
        .run_get(run_id)
        .map_err(|error| RunStatusReadError::Storage(error.to_string()))?;
    let row = data
        .get("rows")
        .and_then(|rows| rows.as_array())
        .and_then(|rows| rows.first())
        .ok_or_else(|| {
            RunStatusReadError::MissingRun(format!("run.get returned no row for run {run_id}"))
        })?;
    let status = row
        .get(3)
        .and_then(|status| status.as_str())
        .ok_or_else(|| {
            RunStatusReadError::MalformedRow(format!(
                "run.get row for {run_id} carries no string status column"
            ))
        })?;
    Ok(DurableRunStatus::parse(status))
}

/// One-shot, fixture-local fault for the cleanup status reader. It is armed
/// only for this case's terminalization guard probe and is consumed by exactly
/// one read. It deliberately does not use the store's shared `fail_next` slot,
/// which concurrent durable traffic could consume first, and adds no global
/// hook: only the cleanup reader of this fixture can observe it.
#[cfg(feature = "workspace-io-fault")]
#[derive(Debug, Default)]
struct CleanupStatusFault {
    armed: std::sync::atomic::AtomicBool,
    consumptions: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "workspace-io-fault")]
impl CleanupStatusFault {
    fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn take(&self) -> bool {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.consumptions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    fn consumptions(&self) -> usize {
        self.consumptions.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(feature = "workspace-io-fault")]
struct CleanupStatusReader<'a> {
    persistence: &'a GatewayPersistence,
    fault: Option<&'a CleanupStatusFault>,
}

#[cfg(feature = "workspace-io-fault")]
impl CleanupStatusReader<'_> {
    fn read(&self, run_id: &str) -> Result<DurableRunStatus, RunStatusReadError> {
        if self.fault.is_some_and(CleanupStatusFault::take) {
            return Err(RunStatusReadError::injected());
        }
        durable_run_status(self.persistence, run_id)
    }
}

#[cfg(feature = "workspace-io-fault")]
#[derive(Debug)]
struct CleanupSettleOutcome {
    initial_probe: Result<DurableRunStatus, RunStatusReadError>,
    transition_attempted: bool,
    transition_error: Option<String>,
    final_probe: Result<DurableRunStatus, RunStatusReadError>,
}

/// Terminalizes A through the existing typed `run.terminal` transition inside
/// one owned blocking cleanup operation. A status read failure or an
/// unrecognised shape is not "no run": the committed run id is known, so the
/// transition is still attempted, and a second read verifies the outcome. No
/// retry loop and no production API change.
#[cfg(feature = "workspace-io-fault")]
fn settle_durable_run_for_cleanup(
    persistence: &GatewayPersistence,
    run_id: &str,
    fault: Option<&CleanupStatusFault>,
) -> CleanupSettleOutcome {
    let reader = CleanupStatusReader { persistence, fault };
    let initial_probe = reader.read(run_id);
    // Only an explicit terminal durable state may skip the transition; a read
    // failure stays a read failure.
    let skip_transition = matches!(&initial_probe, Ok(status) if status.is_terminal());
    let mut transition_attempted = false;
    let mut transition_error = None;
    if !skip_transition {
        transition_attempted = true;
        if let Err(error) = persistence.run_terminal(&terminal_run_payload(run_id)) {
            transition_error = Some(error.to_string());
        }
    }
    let final_probe = reader.read(run_id);
    CleanupSettleOutcome {
        initial_probe,
        transition_attempted,
        transition_error,
        final_probe,
    }
}

#[cfg(feature = "workspace-io-fault")]
fn panic_payload_text(payload: &Box<dyn std::any::Any + Send>) -> String {
    let inner: &dyn std::any::Any = &**payload;
    if let Some(text) = inner.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = inner.downcast_ref::<String>() {
        text.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[cfg(feature = "workspace-io-fault")]
#[derive(Debug)]
struct LeaseObservation {
    schema_in_window: u32,
    b_finished_in_window: bool,
}
#[cfg(feature = "workspace-io-fault")]
#[derive(Debug)]
struct LeaseCleanupEvidence {
    a_run_id: String,
    b_run_id: String,
    a_terminal_status: String,
    b_joined: bool,
    lease_wait_observed: bool,
    cleanup_elapsed: std::time::Duration,
    /// The status read at the terminalization guard, preserved instead of
    /// being folded into an empty status.
    a_status_probe_error: Option<RunStatusReadError>,
    a_transition_attempted: bool,
    a_transition_error: Option<String>,
    cleanup_status_fault_consumptions: usize,
    storage_wait_timed_out: bool,
    /// Set only when the primary cleanup failed and the independent, bounded
    /// teardown net had to finish the job.
    teardown_fallback: Option<String>,
}

#[cfg(feature = "workspace-io-fault")]
#[derive(Debug)]
struct LeaseCleanupFailure {
    failures: Vec<String>,
    evidence: LeaseCleanupEvidence,
}

#[cfg(feature = "workspace-io-fault")]
struct LeaseCaseOutcome {
    observation: Result<LeaseObservation, Box<dyn std::any::Any + Send>>,
    cleanup: Result<LeaseCleanupEvidence, LeaseCleanupFailure>,
}

/// Fixture case options. A closed enum keeps the case signature from growing
/// stacked boolean parameters.
#[cfg(feature = "workspace-io-fault")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseCaseMode {
    /// Ordinary guarded-commit rendezvous; the observation must succeed.
    GuardedCommit,
    /// Force the observation panic after B entered its lease-held wait.
    ForcedObservationFailure,
    /// Forced observation panic plus exactly one injected `run.get` failure at
    /// the cleanup terminalization guard.
    CleanupStatusReadFailureOnce,
}

#[cfg(feature = "workspace-io-fault")]
impl LeaseCaseMode {
    fn forces_observation_failure(self) -> bool {
        !matches!(self, Self::GuardedCommit)
    }

    fn injects_cleanup_status_failure(self) -> bool {
        matches!(self, Self::CleanupStatusReadFailureOnce)
    }
}

/// 401-R1-B: the session maintenance lease must publish inside the same short
/// commit-gate critical section as the admission maintenance check. A
/// same-schema admission A that already passed that check must complete its
/// durable commit before a schema-switch admission B can observe an empty
/// nonterminal set. The test parks A inside the real guarded transaction, starts
/// B for schema2 on the same session/root, then lets A commit while its reply is
/// lost and its memory publication is deliberately deferred at the original
/// proof seam. B must not publish schema2 while A's run is durably nonterminal.
#[cfg(feature = "workspace-io-fault")]
async fn lease_linearization_case(fixture_label: &str, mode: LeaseCaseMode) -> LeaseCaseOutcome {
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn wait_flag(flag: &Arc<AtomicBool>, what: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !flag.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "{what} was not reached"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    let fixture = open_managed_run_state_fixture(fixture_label);
    let http = Http::bind(fixture.state.clone()).await;
    let _graph1 = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let baseline_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&baseline_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(baseline_provider.clone()));
    let baseline_run =
        admit_state_run(&http, &fixture.token, &session_id, &baseline_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let key_b1 = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema1 session root");
    assert_eq!(store.root(&key_b1).expect("root").expect("root").schema, 1);
    let baseline_binding = store
        .binding(&baseline_run)
        .expect("baseline binding")
        .expect("baseline state binding");
    let workspace_id = baseline_binding.binding.workspace_id.clone();
    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": baseline_run,
                "workspace_id": workspace_id,
                "source_branch_id": baseline_binding.binding.branch_id,
                "expected_epoch": baseline_binding.binding.epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, created) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/branches"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": baseline_binding.binding.branch_id,
                "checkpoint_id": checkpoint_id,
                "request_id": uuid::Uuid::new_v4().to_string()
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &created));
    let branch_b2 = created["branch"]["branch_id"].as_str().unwrap().to_string();
    assert_ne!(branch_b2, baseline_binding.binding.branch_id);
    // The branch materializes its state root on its first admission. Admit a
    // graph1 run through the checkpoint pin so branch b2 holds a schema1 root.
    let key_b2 = PluginStateRootKey {
        branch_id: branch_b2.clone(),
        ..key_b1.clone()
    };
    let b2_seed_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&b2_seed_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(b2_seed_provider.clone()));
    let b2_seed_run = admit_state_run_on_branch(
        &http,
        &fixture.token,
        &session_id,
        &branch_b2,
        &_graph1,
        &b2_seed_provider,
    )
    .await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &b2_seed_run).await,
        "completed"
    );
    assert_eq!(
        store
            .root(&key_b2)
            .expect("root")
            .expect("branch b2 root")
            .schema,
        1
    );

    // Activate schema2 and migrate only branch b1. Branch b2 keeps the old
    // schema1 root, so a schema2 admission on b2 is a real migration while a
    // schema2 admission on b1 takes the same-schema guard path.
    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    let migrate_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&migrate_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(migrate_provider.clone()));
    let migrated_run = admit_state_run(&http, &fixture.token, &session_id, &migrate_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &migrated_run).await,
        "completed"
    );
    assert_eq!(store.root(&key_b1).expect("root").expect("root").schema, 2);
    assert_eq!(
        store
            .root(&key_b2)
            .expect("root")
            .expect("branch b2 root")
            .schema,
        1
    );

    let candidates = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded_candidates = Arc::clone(&candidates);
    fixture
        .state
        .service()
        .observe_state_candidates(Arc::new(move |object_id: &str| {
            recorded_candidates
                .lock()
                .expect("candidate log")
                .push(object_id.to_string());
        }));

    let precommit_run_id: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let precommit_run_slot = Arc::clone(&precommit_run_id);
    let a_precommit = Arc::new(AtomicBool::new(false));
    let a_release = Arc::new(AtomicBool::new(false));
    let a_precommit_seen = Arc::clone(&a_precommit);
    let a_release_slot = Arc::clone(&a_release);
    persistence.inject_admission_precommit_hook(move |payload| {
        *precommit_run_slot.lock().expect("A precommit run") =
            payload["run_id"].as_str().map(str::to_string);
        a_precommit_seen.store(true, Ordering::SeqCst);
        while !a_release_slot.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });

    let proof_entered = Arc::new(AtomicBool::new(false));
    let proof_release = Arc::new(AtomicBool::new(false));
    let lease_wait_entered = Arc::new(AtomicBool::new(false));
    let lease_wait_release = Arc::new(AtomicBool::new(false));
    // Three hooks below block a real blocking-pool thread on these flags. If an
    // assertion unwinds first, the runtime would wait forever for that parked
    // thread and hide the real failure, so release all of them on unwind.
    struct ReleaseParkedHooksOnDrop(Arc<AtomicBool>, Arc<AtomicBool>, Arc<AtomicBool>);
    impl Drop for ReleaseParkedHooksOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
            self.1.store(true, Ordering::SeqCst);
            self.2.store(true, Ordering::SeqCst);
        }
    }
    let _release_parked_hooks = ReleaseParkedHooksOnDrop(
        Arc::clone(&a_release),
        Arc::clone(&proof_release),
        Arc::clone(&lease_wait_release),
    );
    let proof_entered_seen = Arc::clone(&proof_entered);
    let proof_release_slot = Arc::clone(&proof_release);
    fixture
        .state
        .service()
        .observe_original_proof_reads(Arc::new(move |op: &str, _gate_free: bool| {
            if op == "admission.replay" {
                proof_entered_seen.store(true, Ordering::SeqCst);
                while !proof_release_slot.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }));
    // Test-only one-shot rendezvous inside B's real maintenance wait: the
    // callback fires only after B acquired the session lease and a durable
    // read returned A's nonterminal run. It receives no identity or payload
    // and parks the admission thread until cleanup releases it.
    let lease_wait_seen = Arc::clone(&lease_wait_entered);
    let lease_wait_release_slot = Arc::clone(&lease_wait_release);
    fixture
        .state
        .service()
        .observe_session_maintenance_wait(Arc::new(move || {
            lease_wait_seen.store(true, Ordering::SeqCst);
            while !lease_wait_release_slot.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }));

    let a_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&a_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(a_provider.clone()));
    persistence.inject_admission_ack_loss();
    let service_a = fixture.state.service().clone();
    let a_session = session_id.clone();
    let mut a_task = tokio::spawn(async move {
        service_a
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!("lease linearization A"),
                    session_id: Some(a_session),
                    idempotency_key: Some("t12-lease-linearization-a".into()),
                    idempotency_hash: Some("fnv64:0000000000000c03".into()),
                    platform: "test".into(),
                    ..AdmitRunRequest::default()
                },
                None,
            )
            .await
    });
    wait_flag(&a_precommit, "A precommit").await;

    // A is parked inside its real gate after the maintenance check. Start B on
    // the sibling branch whose live root is still schema1, so B must migrate.
    let b_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&b_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(b_provider.clone()));
    let service_b = fixture.state.service().clone();
    let b_session = session_id.clone();
    let b_graph = graph2.clone();
    let b_branch = branch_b2.clone();
    let mut b_task = tokio::spawn(async move {
        service_b
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!("lease linearization B"),
                    session_id: Some(b_session),
                    graph_id: Some(b_graph),
                    workspace_branch: Some(b_branch),
                    platform: "test".into(),
                    ..AdmitRunRequest::default()
                },
                None,
            )
            .await
    });
    let observation = AssertUnwindSafe(async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // In the pre-fix ordering B reaches its candidate put (and therefore
        // its nonterminal read) before A commits. Wait for that signal when it
        // appears; in the fixed ordering the lease publication is serialized
        // by the gate, so B cannot produce a candidate until after A settles
        // and this bounded wait simply expires.
        let candidate_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < candidate_deadline {
            if !candidates.lock().expect("candidate log").is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            !b_task.is_finished(),
            "B cannot publish while A is still inside its commit gate"
        );

        // A commits durably, loses its reply, drops the gate, and parks at the
        // first original-proof read. Its admission message is not in memory yet.
        a_release.store(true, Ordering::SeqCst);
        let proof_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !proof_entered.load(Ordering::SeqCst) {
            if a_task.is_finished() {
                let run_id = precommit_run_id
                    .lock()
                    .expect("A precommit run")
                    .clone()
                    .unwrap_or_default();
                panic!("A finished before original proof read: run={run_id}");
            }
            if std::time::Instant::now() >= proof_deadline {
                panic!("A original proof read was not reached and A is still running");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Rendezvous on B's real lease-held wait. The observer fires only after
        // B acquired `SessionMaintenanceLease` and one `session_nonterminal_runs`
        // read returned A's run, immediately before B waits. B stays parked in
        // that callback until the cleanup section releases it, so everything
        // below runs while the lease is provably held and the wait loop has
        // provably been entered.
        wait_flag(&lease_wait_entered, "B session maintenance wait").await;
        let schema_in_window = store.root(&key_b2).expect("root").expect("root").schema;
        let b_finished_in_window = b_task.is_finished();

        // Cross-session positive control while B waits: an unrelated session is
        // not blocked by this session's maintenance lease. The lease is keyed
        // by session id (`SessionMaintenanceLease::acquire` inserts the session
        // id), so a different session id only avoids a same-key lease conflict;
        // admissions still share the ParkingMutex-backed lease set, the global
        // `commit_gate`, and the single serialized durable worker. Total HTTP
        // admission latency is therefore not lease-specific and carries no
        // product SLA (no 1500ms bound exists outside this test file). The
        // non-blocking contract is proved functionally instead: the unrelated
        // session admits (202) and runs to terminal `completed` while A is
        // still durably nonterminal and B (same session, lease path) is parked
        // in its proven wait with nothing published.
        // Negative control: B shares the session lock and stays blocked (the
        // decisive assertions below), and the sibling
        // `session_schema_switch_waits_under_lease_without_blocking_other_sessions`
        // test pins the same-session refusal to 409 `session_busy`.
        let other_session = create_session(&http, &fixture.token).await;
        let other_provider = rustscript_agent::ScriptedProvider::new();
        script_state_turns(&other_provider);
        fixture
            .state
            .service()
            .inject_provider_host(Arc::new(other_provider.clone()));
        let other_started = std::time::Instant::now();
        let (other_status, other_body) = admit_state_run_response(
            &http,
            &fixture.token,
            &other_session,
            None,
            Some(&graph2),
            &other_provider,
        )
        .await;
        let other_elapsed = other_started.elapsed();
        assert_eq!(other_status, 202, "{}", explain(other_status, &other_body));
        // Diagnostics are best-effort only: a stderr IO failure must not panic
        // before cleanup and must not replace the functional assertions.
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!(
                "other-session admission latency under parallel load (observation only, never lease-bound): {other_elapsed:?}\n"
            ),
        );
        let other_run = other_body["run_id"].as_str().unwrap().to_string();
        assert_eq!(
            wait_run_any_terminal(&fixture.state, &other_run).await,
            "completed"
        );
        wait_provider_call(&other_provider).await;
        // Rendezvous: the unrelated session completed its full admit-to-terminal
        // lifecycle while the original session still held the lease path blocked.
        // A must still be durably nonterminal (its run id was captured by the
        // precommit hook), B must still be pending, and B must have published no
        // migration candidate yet.
        let a_run_while_other_done = precommit_run_id
            .lock()
            .expect("A precommit run")
            .clone()
            .expect("A precommit run captured before the other-session admission");
        let a_status_while_other_done =
            durable_run_status(&persistence, &a_run_while_other_done)
                .expect("A durable status while the unrelated session completed");
        assert_eq!(
            a_status_while_other_done,
            DurableRunStatus::Running,
            "the unrelated session completed while A was still durably nonterminal"
        );
        assert!(
            !b_task.is_finished(),
            "B (same session, lease path) must still be pending after the unrelated session completed"
        );
        assert!(
            candidates.lock().expect("candidate log").is_empty(),
            "B must have published no migration candidate while the unrelated session completed"
        );
        if mode.forces_observation_failure() {
            panic!("{FORCED_OBSERVATION_FAILURE}");
        }
        LeaseObservation {
            schema_in_window,
            b_finished_in_window,
        }
    })
    .catch_unwind()
    .await;

    // Unified failure-safe cleanup. All parked hooks are released, A's admitted
    // run is settled through the existing typed transition, and both admission
    // tasks are joined under ONE absolute deadline (never refreshed per step).
    // The observation failure, if any, stays the primary failure.
    //
    // A cleanup status read that fails is a read failure, not an empty status:
    // A's committed run id is still known, so the typed transition is always
    // attempted. The synchronous storage commands run inside one owned
    // blocking cleanup operation under the same absolute deadline, so they can
    // never park the async runtime (and its timers) past that deadline. The
    // storage command keeps its own 30s internal response bound; dropping a
    // timed-out join does not cancel an operation already inside the worker.
    let cleanup_started = std::time::Instant::now();
    let cleanup_deadline: tokio::time::Instant = (cleanup_started + LEASE_CLEANUP_BUDGET).into();
    a_release.store(true, Ordering::SeqCst);
    proof_release.store(true, Ordering::SeqCst);
    lease_wait_release.store(true, Ordering::SeqCst);
    let mut failures: Vec<String> = Vec::new();
    let mut a_run_id = precommit_run_id
        .lock()
        .expect("A precommit run")
        .clone()
        .unwrap_or_default();

    match tokio::time::timeout_at(cleanup_deadline, &mut a_task).await {
        Ok(Ok(Ok(admitted))) => a_run_id = admitted.run_id,
        Ok(Ok(Err(error))) => {
            failures.push(format!("A delayed publication failed: {error:?}"));
        }
        Ok(Err(error)) => failures.push(format!("A admission task join failed: {error}")),
        Err(_) => failures.push("A admission did not finish within the cleanup budget".into()),
    }

    // End A through the existing typed terminal transition; the run's worker is
    // not part of this lease-ordering assertion.
    let cleanup_status_fault = Arc::new(CleanupStatusFault::default());
    if mode.injects_cleanup_status_failure() {
        cleanup_status_fault.arm();
    }
    let mut storage_wait_timed_out = false;
    let settle = if a_run_id.is_empty() {
        failures.push(
            "A's committed run id was never captured; no typed terminal transition was possible"
                .into(),
        );
        None
    } else {
        let persistence_settle = Arc::clone(&persistence);
        let settle_run_id = a_run_id.clone();
        let settle_fault = Arc::clone(&cleanup_status_fault);
        let settle_task = tokio::task::spawn_blocking(move || {
            settle_durable_run_for_cleanup(&persistence_settle, &settle_run_id, Some(&settle_fault))
        });
        match tokio::time::timeout_at(cleanup_deadline, settle_task).await {
            Ok(Ok(outcome)) => Some(outcome),
            Ok(Err(error)) => {
                failures.push(format!(
                    "cleanup terminalization task failed to run: {error}"
                ));
                None
            }
            Err(_) => {
                storage_wait_timed_out = true;
                failures.push(
                    "cleanup terminalization did not finish inside the shared budget; the \
                     started storage operation keeps its own 30s bound"
                        .into(),
                );
                None
            }
        }
    };
    let a_status_probe_error = settle
        .as_ref()
        .and_then(|outcome| outcome.initial_probe.as_ref().err().cloned());
    // This probe is also the pre-terminalization record: it runs after A's
    // admission joined and before the typed transition. A read failure here is
    // kept as `a_status_probe_error` above and never replaces the transition;
    // the verified final status below is the decisive assertion.
    if let Some(Ok(status)) = settle.as_ref().map(|outcome| &outcome.initial_probe)
        && !matches!(status, DurableRunStatus::Running)
    {
        failures.push(format!(
            "A's run was {:?} durably when its memory publication landed",
            status.as_str()
        ));
    }
    let a_transition_attempted = settle
        .as_ref()
        .is_some_and(|outcome| outcome.transition_attempted);
    let a_transition_error = settle
        .as_ref()
        .and_then(|outcome| outcome.transition_error.clone());
    let a_terminal_status = match settle.as_ref().map(|outcome| &outcome.final_probe) {
        Some(Ok(status)) => status.as_str().to_string(),
        Some(Err(error)) => {
            failures.push(format!(
                "A's run status after cleanup terminalization was unreadable: {error}"
            ));
            String::new()
        }
        None => String::new(),
    };
    if !a_run_id.is_empty() && a_terminal_status != "completed" {
        failures.push(format!(
            "A's run was not terminal after cleanup: {a_terminal_status:?}"
        ));
    }

    let mut b_run_id = String::new();
    let mut b_joined = false;
    match tokio::time::timeout_at(cleanup_deadline, &mut b_task).await {
        Ok(Ok(Ok(admitted))) => {
            b_joined = true;
            b_run_id = admitted.run_id;
        }
        Ok(Ok(Err(error))) => {
            b_joined = true;
            failures.push(format!("B migration admission failed: {error:?}"));
        }
        Ok(Err(error)) => failures.push(format!("B admission task join failed: {error}")),
        Err(_) => failures.push("B admission did not join within the cleanup budget".into()),
    }
    let cleanup_elapsed = cleanup_started.elapsed();

    // Independent, bounded teardown net. The primary result above is already
    // recorded, so this can never turn a failure into a pass. It exists only
    // to avoid leaving A nonterminal (and B parked in its lease wait for the
    // fixture's 900s run timeout) behind a failed primary cleanup, which would
    // otherwise hold the runtime's blocking pool past the test's own budget.
    let mut teardown_fallback: Option<String> = None;
    if a_terminal_status != "completed" || !b_joined {
        let fallback_deadline: tokio::time::Instant =
            (std::time::Instant::now() + LEASE_TEARDOWN_FALLBACK_BUDGET).into();
        let mut note = String::new();
        if !a_run_id.is_empty() {
            let persistence_fallback = Arc::clone(&persistence);
            let fallback_run_id = a_run_id.clone();
            let fallback_settle = tokio::task::spawn_blocking(move || {
                settle_durable_run_for_cleanup(&persistence_fallback, &fallback_run_id, None)
            });
            match tokio::time::timeout_at(fallback_deadline, fallback_settle).await {
                Ok(Ok(outcome)) => note.push_str(&format!(
                    "terminal attempted={} error={:?} final={:?}; ",
                    outcome.transition_attempted, outcome.transition_error, outcome.final_probe
                )),
                Ok(Err(error)) => note.push_str(&format!("terminal task failed to run: {error}; ")),
                Err(_) => note.push_str("terminal task exceeded the fallback budget; "),
            }
        }
        if !b_joined {
            match tokio::time::timeout_at(fallback_deadline, &mut b_task).await {
                Ok(Ok(_)) => note.push_str("joined B"),
                Ok(Err(error)) => note.push_str(&format!("B join failed: {error}")),
                Err(_) => note.push_str("B join exceeded the fallback budget"),
            }
        }
        teardown_fallback = Some(note);
    }

    let evidence = LeaseCleanupEvidence {
        a_run_id,
        b_run_id,
        a_terminal_status,
        b_joined,
        lease_wait_observed: lease_wait_entered.load(Ordering::SeqCst),
        cleanup_elapsed,
        a_status_probe_error,
        a_transition_attempted,
        a_transition_error,
        cleanup_status_fault_consumptions: cleanup_status_fault.consumptions(),
        storage_wait_timed_out,
        teardown_fallback,
    };
    let cleanup = if failures.is_empty() {
        Ok(evidence)
    } else {
        Err(LeaseCleanupFailure { failures, evidence })
    };
    let outcome = LeaseCaseOutcome {
        observation,
        cleanup,
    };

    if let (Ok(seen), Ok(evidence)) = (&outcome.observation, &outcome.cleanup) {
        let root_after = store.root(&key_b2).expect("root").expect("schema2 root");
        assert_eq!(root_after.schema, 2);
        assert_eq!(
            store.root(&key_b1).expect("root").expect("b1 root").schema,
            2,
            "A's branch root stays at the schema it admitted"
        );
        let b_binding = store
            .binding(&evidence.b_run_id)
            .expect("B binding")
            .expect("schema2 binding");
        assert_eq!(b_binding.binding.schema, 2);
        assert_eq!(b_binding.binding.branch_id, branch_b2);
        assert_eq!(b_binding.binding.object_id, root_after.object_id);
        // Decisive assertions, evaluated after all tasks settled so a RED run
        // can still tear down deterministically.
        assert_eq!(
            seen.schema_in_window, 1,
            "B published schema2 while A's durable run was nonterminal (B done={})",
            seen.b_finished_in_window
        );
        assert!(
            !seen.b_finished_in_window,
            "B admission finished while A's durable run was still nonterminal"
        );
        let observed = candidates.lock().expect("candidate log").clone();
        assert!(
            observed.len() >= 2,
            "ordinary memory drift must reprepare B's candidate, observed={observed:?}"
        );
        assert!(!evidence.a_run_id.is_empty());
    } else if outcome.observation.is_ok()
        && let Err(failure) = &outcome.cleanup
    {
        panic!(
            "lease cleanup failed: {}; evidence: {:?}",
            failure.failures.join("; "),
            failure.evidence
        );
    }

    outcome
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn maintenance_lease_linearizes_with_guarded_commit_and_lost_reply() {
    let outcome =
        lease_linearization_case("t12-lease-linearization", LeaseCaseMode::GuardedCommit).await;
    if let Err(payload) = outcome.observation {
        std::panic::resume_unwind(payload);
    }
    match outcome.cleanup {
        Ok(evidence) => {
            assert_eq!(
                evidence.cleanup_status_fault_consumptions, 0,
                "the ordinary case injects no cleanup status failure"
            );
            assert!(
                evidence.teardown_fallback.is_none(),
                "the ordinary case must settle inside the primary cleanup: {:?}",
                evidence.teardown_fallback
            );
            assert!(evidence.a_transition_attempted);
            assert!(evidence.a_status_probe_error.is_none());
        }
        Err(failure) => panic!(
            "lease cleanup failed: {}; evidence: {:?}",
            failure.failures.join("; "),
            failure.evidence
        ),
    }
}

/// Failure-path control for the maintenance-wait rendezvous: the observation is
/// forced to panic only after B is parked inside its real lease-held wait and
/// the unrelated session completed. It proves the unified cleanup releases the
/// parked hooks, terminalizes A through the typed transition, joins B within
/// the shared budget, and rethrows the original panic payload unchanged.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn maintenance_wait_failure_cleanup_preserves_first_panic() {
    let outcome = lease_linearization_case(
        "t12-lease-cleanup-control",
        LeaseCaseMode::ForcedObservationFailure,
    )
    .await;
    let payload = outcome
        .observation
        .expect_err("the forced observation failure must be captured");
    let text = panic_payload_text(&payload);
    assert!(
        text.contains(FORCED_OBSERVATION_FAILURE),
        "original panic payload must be preserved, got {text:?}"
    );
    let evidence = match outcome.cleanup {
        Ok(evidence) => evidence,
        Err(failure) => panic!(
            "cleanup must settle A and join B after the forced failure: {}; evidence: {:?}",
            failure.failures.join("; "),
            failure.evidence
        ),
    };
    assert!(
        evidence.lease_wait_observed,
        "the forced failure must trigger only after B entered its lease-held wait"
    );
    assert!(
        evidence.b_joined,
        "B admission must be joined during cleanup"
    );
    assert_eq!(
        evidence.a_terminal_status, "completed",
        "A must be terminal through the typed transition during cleanup"
    );
    assert!(
        evidence.cleanup_elapsed < LEASE_CLEANUP_BUDGET,
        "cleanup must finish inside the shared budget: {:?}",
        evidence.cleanup_elapsed
    );
    assert_eq!(evidence.cleanup_status_fault_consumptions, 0);
    assert!(evidence.a_transition_attempted);
    assert!(evidence.a_transition_error.is_none());
    assert!(!evidence.storage_wait_timed_out);
    assert!(evidence.teardown_fallback.is_none());
    assert!(!evidence.a_run_id.is_empty());
    assert!(!evidence.b_run_id.is_empty());
}

/// Direct regression for the cleanup status-read error branch: after B entered
/// its real lease-held wait and the observation failure was captured, exactly
/// one `run.get` at the cleanup terminalization guard fails. That read failure
/// is not "no run": A's committed run id is known, so the existing typed
/// transition must still run, A must become durably `completed`, B must leave
/// its wait and join inside the shared budget, storage must stay responsive,
/// the fault must be consumed exactly once, and the original observation panic
/// payload must remain primary.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn maintenance_wait_failure_cleanup_terminalizes_after_status_read_error() {
    let outcome = lease_linearization_case(
        "t12-lease-cleanup-status-error",
        LeaseCaseMode::CleanupStatusReadFailureOnce,
    )
    .await;
    let payload = outcome
        .observation
        .expect_err("the forced observation failure must be captured");
    let text = panic_payload_text(&payload);
    assert!(
        text.contains(FORCED_OBSERVATION_FAILURE),
        "original panic payload must be preserved, got {text:?}"
    );
    let evidence = match outcome.cleanup {
        Ok(evidence) => evidence,
        Err(failure) => panic!(
            "one cleanup status-read error must not skip A's typed terminal transition: {}; \
             evidence: {:?}",
            failure.failures.join("; "),
            failure.evidence
        ),
    };
    assert!(
        evidence.lease_wait_observed,
        "the injected read must land only after B entered its lease-held wait"
    );
    assert_eq!(
        evidence.cleanup_status_fault_consumptions, 1,
        "the fixture cleanup reader must consume the injected failure exactly once"
    );
    let status_probe_error = evidence
        .a_status_probe_error
        .expect("the guard status read must fail once");
    assert!(
        status_probe_error.is_injected(),
        "the recorded guard failure must be the injected one, got {status_probe_error:?}"
    );
    assert!(
        evidence.a_transition_attempted,
        "a failed status read must not skip the typed terminal transition"
    );
    assert!(
        evidence.a_transition_error.is_none(),
        "the typed transition must succeed after the read failure: {:?}",
        evidence.a_transition_error
    );
    assert_eq!(
        evidence.a_terminal_status, "completed",
        "A must be durably terminal after the typed transition"
    );
    assert!(
        evidence.b_joined,
        "B must leave its lease-held wait and join once A is terminal"
    );
    assert!(
        !evidence.b_run_id.is_empty(),
        "B's real admission must have completed its durable commit"
    );
    assert!(
        !evidence.storage_wait_timed_out,
        "the cleanup storage operation must stay inside the shared budget"
    );
    assert!(
        evidence.teardown_fallback.is_none(),
        "the primary cleanup must settle A and join B without the teardown net: {:?}",
        evidence.teardown_fallback
    );
    assert!(
        evidence.cleanup_elapsed < LEASE_CLEANUP_BUDGET,
        "cleanup must finish inside the shared budget: {:?}",
        evidence.cleanup_elapsed
    );
    assert!(!evidence.a_run_id.is_empty());
}

/// R2 direct regression: failed or re-prepared migration candidates are
/// deterministically settled through the existing typed bounded collector
/// outside the global gate. Old abandoned objects disappear, the retained set
/// is bounded, prepared root/binding objects stay readable, and a candidate
/// that is still in flight is protected so its admission can commit.
///
/// The repeated failure uses the existing one-shot post-CAS admission guard
/// failpoint so every attempt deterministically rolls back after the candidate
/// exists. It is a fixture seam on the real guarded transaction, not a
/// production behavior change.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn abandoned_migration_candidates_are_bounded_and_protected() {
    let fixture = open_managed_run_state_fixture("t12-candidate-settle");
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let identity_key = "t12-candidate-settlement-key";

    let baseline_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&baseline_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(baseline_provider.clone()));
    let (status, baseline) = admit_run_with_identity(
        &http,
        &fixture.token,
        &session_id,
        "candidate baseline",
        None,
        identity_key,
    )
    .await;
    assert_eq!(status, 202, "{}", explain(status, &baseline));
    let baseline_run = baseline["run_id"].as_str().unwrap().to_string();
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema1 session root");
    let root_before = store.root(&key).expect("root").expect("schema1 root");
    assert_eq!(root_before.schema, 1);
    let baseline_binding = store
        .binding(&baseline_run)
        .expect("baseline binding")
        .expect("baseline state binding");
    assert_eq!(
        baseline_binding.binding.object_id, root_before.object_id,
        "the published root and run binding reference the same durable object"
    );
    assert!(store.object_payload(&root_before.object_id).is_ok());

    let candidates = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&candidates);
    fixture
        .state
        .service()
        .observe_state_candidates(Arc::new(move |object_id: &str| {
            recorded
                .lock()
                .expect("candidate log")
                .push(object_id.to_string());
        }));

    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    for attempt in 0..70 {
        persistence.inject_admission_state_fail();
        let attempt_key = format!("t12-candidate-failure-{attempt}");
        let (status, body) = admit_run_with_identity(
            &http,
            &fixture.token,
            &session_id,
            "candidate failure",
            Some(&graph2),
            &attempt_key,
        )
        .await;
        assert_eq!(
            status,
            503,
            "failed admission {attempt}: {}",
            explain(status, &body)
        );
        assert_eq!(body["error"]["code"], "persistence_unavailable");
    }
    let ids = candidates.lock().expect("candidate log").clone();
    assert_eq!(
        ids.len(),
        70,
        "each failed admission prepared one candidate"
    );
    let existing = ids
        .iter()
        .filter(|object_id| store.object_payload(object_id).is_ok())
        .count();
    assert!(
        existing < ids.len(),
        "abandoned candidates must be reclaimed"
    );
    assert_eq!(
        existing, 64,
        "the existing collector retains a bounded recent orphan set"
    );
    assert!(
        store.object_payload(&root_before.object_id).is_ok(),
        "the published root object must never be collected"
    );
    assert!(
        store
            .object_payload(&baseline_binding.binding.object_id)
            .is_ok(),
        "the run binding object must never be collected"
    );
    let root_mid = store.root(&key).expect("root").expect("schema1 root");
    assert_eq!(root_mid.schema, 1);
    assert_eq!(root_mid.revision, root_before.revision);

    let (candidate_tx, candidate_rx) = std::sync::mpsc::channel::<String>();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release_observer = Arc::clone(&release);
    fixture
        .state
        .service()
        .observe_state_candidates(Arc::new(move |object_id: &str| {
            candidate_tx
                .send(object_id.to_string())
                .expect("candidate id");
            let (lock, cvar) = &*release_observer;
            let mut released = lock.lock().expect("candidate release");
            while !*released {
                released = cvar.wait(released).expect("candidate release wait");
            }
        }));
    let live_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&live_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(live_provider.clone()));
    let service = fixture.state.service().clone();
    let live_session = session_id.clone();
    let live_graph = graph2.clone();
    let live_admission = tokio::spawn(async move {
        service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!("candidate live"),
                    session_id: Some(live_session),
                    graph_id: Some(live_graph),
                    platform: "test".into(),
                    ..AdmitRunRequest::default()
                },
                None,
            )
            .await
    });
    let live_candidate = tokio::task::spawn_blocking(move || {
        candidate_rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("live candidate prepared")
    })
    .await
    .unwrap();
    assert!(
        store.object_payload(&live_candidate).is_ok(),
        "the in-flight candidate exists before collection"
    );
    let _ = store.collect_orphans();
    assert!(
        store.object_payload(&live_candidate).is_ok(),
        "an unsettled candidate must be protected from concurrent collection"
    );
    {
        let (lock, cvar) = &*release;
        *lock.lock().expect("candidate release") = true;
        cvar.notify_all();
    }
    let live_run = live_admission
        .await
        .expect("live admission task")
        .expect("live candidate admission commits");
    assert!(!live_run.replayed);
    let root_after = store.root(&key).expect("root").expect("schema2 root");
    assert_eq!(root_after.schema, 2);
    assert_eq!(
        root_after.object_id, live_candidate,
        "the protected candidate becomes the published root"
    );
    let live_binding = store
        .binding(&live_run.run_id)
        .expect("live binding")
        .expect("schema2 binding");
    assert_eq!(live_binding.binding.object_id, live_candidate);
    assert_eq!(live_binding.binding.schema, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_schema_switch_waits_under_lease_without_blocking_other_sessions() {
    let fixture = open_managed_run_state_fixture("t12-session-switch");
    let http = Http::bind(fixture.state.clone()).await;
    let graph1 = run_state_plugin(&http, &fixture.token).await;
    assert!(!graph1.is_empty());
    let (status, body) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "package-staterun2", "deployment_space": "owner-space"}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &body));
    let (status, resolved2) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.test.staterun", "version": "2.0.0"}],
                "tool_package": "org.rustscript.test.staterun",
                "deployment_space": "owner-space"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &resolved2));
    let graph2 = resolved2["graph_id"].as_str().unwrap().to_string();
    let (status, prepared2) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph2}/prepare"),
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &prepared2));

    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let first_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(first_provider.clone()));
    let first_run = admit_state_run(&http, &fixture.token, &session_id, &first_provider).await;
    let persistence = fixture.state.persistence().unwrap();
    wait_run_terminal(&fixture.state, &first_run).await;
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let first_binding = store
        .binding(&first_run)
        .expect("binding")
        .expect("state binding");
    assert_eq!(first_binding.binding.schema, 1);

    let blocker = "blocker-run";
    seed_run(&persistence, &session_id, blocker, 42);
    complete_durable_run(&persistence, blocker);
    let cancellation = rustscript_agent::RunCancellation::with_deadline(
        std::time::Instant::now() + std::time::Duration::from_secs(15),
    );
    let service = fixture.state.service().clone();
    let session_for_switch = session_id.clone();
    let graph_for_switch = graph2.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = service.switch_plugin_state_schema(
            &session_for_switch,
            &graph_for_switch,
            &cancellation,
        );
        sender.send(result).unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let (status, busy) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "must not race schema switch"}),
            Some(&fixture.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &busy));
    assert_eq!(busy["error"]["code"], "session_busy");

    let (status, other_session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &other_session));
    let other_id = other_session["session"]["id"].as_str().unwrap().to_string();
    let other_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(other_provider.clone()));
    let other_run = admit_state_run(&http, &fixture.token, &other_id, &other_provider).await;
    wait_run_terminal(&fixture.state, &other_run).await;

    terminate_durable_run(&persistence, blocker);
    let switched = receiver
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("switch thread completed");
    let revision = switched.expect("session schema switch succeeds");
    assert!(revision.is_some());
    let root_key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("switch session key");
    let root = store.root(&root_key).expect("root").expect("root");
    assert_eq!(root.schema, 2);

    let expired = rustscript_agent::RunCancellation::with_deadline(
        std::time::Instant::now() - std::time::Duration::from_secs(1),
    );
    let error = fixture
        .state
        .service()
        .switch_plugin_state_schema(&session_id, &graph2, &expired)
        .expect_err("expired switch must not hold the session lease");
    assert_eq!(error, "cancelled");
    let (status, activated2) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph2,
                "deployment_space": "owner-space",
                "expected_generation": resolved2["generation"].as_u64().unwrap_or(0)
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &activated2));
    let final_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(final_provider.clone()));
    let final_run = admit_state_run(&http, &fixture.token, &session_id, &final_provider).await;
    wait_run_terminal(&fixture.state, &final_run).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_checkpoint_records_real_stateful_roots() {
    let fixture = open_managed_state_fixture("t12-managed-state-checkpoint");
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let run_id = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    wait_run_terminal(&fixture.state, &run_id).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let binding = store
        .binding(&run_id)
        .expect("state binding")
        .expect("state binding");
    assert_eq!(binding.payload.as_str(), r#"{"count":1}"#);
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let entry = effects["entries"]
        .as_array()
        .and_then(|entries| entries.first())
        .expect("state run emitted a managed read receipt")
        .clone();
    let workspace_id = entry["workspace_id"].as_str().unwrap().to_string();
    let branch_id = entry["branch_id"].as_str().unwrap().to_string();
    let epoch = entry["epoch"].as_u64().unwrap();
    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": branch_id,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    assert_eq!(checkpoint["checkpoint"]["plugin_state"]["kind"], "stateful");
    assert_eq!(
        checkpoint["checkpoint"]["public_config"]["config"]["policy_revision"],
        "stateful_session"
    );
    assert_eq!(
        checkpoint["checkpoint"]["plugin_state"]["manifest_state_present"],
        true
    );
    assert_eq!(
        checkpoint["checkpoint"]["plugin_state"]["invocation_excluded_from_checkpoint"],
        false
    );
    let roots = checkpoint["checkpoint"]["plugin_state"]["roots"]
        .as_array()
        .expect("stateful roots");
    assert!(!roots.is_empty());
    assert_eq!(roots[0]["plugin_id"], "org.rustscript.test.staterun");
    assert_eq!(roots[0]["schema"], "1");
    assert!(
        roots
            .iter()
            .any(|root| root["immutable_root_id"] == binding.binding.object_id)
    );

    let call_id = entry["call_id"].as_str().unwrap().to_string();
    let record = ["local-agent", "gateway", "default"]
        .iter()
        .find_map(|profile| {
            persistence
                .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
                    owner: rustscript_agent::effects::ManagedOwnerScope {
                        profile: (*profile).into(),
                        session_id: session_id.clone(),
                        run_id: run_id.clone(),
                    },
                    call_id: call_id.clone(),
                })
                .ok()
                .flatten()
        })
        .expect("managed effect receipt for the state run");
    assert_eq!(record.identity.call_id, call_id);
    let prepared = record.prepared.as_ref().expect("prepared effect receipt");
    let publication = prepared
        .plugin_state
        .as_ref()
        .expect("state write must carry its Native effect publication");
    assert_eq!(publication.object_id, binding.binding.object_id);
    assert_eq!(publication.expected_revision, 1);
    assert_eq!(publication.owner_kind, "session");
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .expect("managed workspace head");
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    let restore_provider = rustscript_agent::ScriptedProvider::new();
    restore_provider.push_ok(json!({
        "text": "restored",
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    }));
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(restore_provider));
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": head.branch_id,
                "checkpoint_id": checkpoint_id,
                "expected_source": {
                    "store_id": head.store_id,
                    "workspace_id": head.workspace_id,
                    "branch_id": head.branch_id,
                    "epoch": head.epoch,
                    "head_object_id": head.head_object_id,
                    "head_version": head.head_version
                },
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "restore exact state"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    let restored_run = restored["new_run_id"].as_str().unwrap().to_string();
    assert_ne!(restored_run, run_id);
    wait_run_terminal(&fixture.state, &restored_run).await;
    let restored_binding = store
        .binding(&restored_run)
        .expect("restored binding")
        .expect("restored binding");
    assert_eq!(restored_binding.binding.schema, 1);
    assert_eq!(restored_binding.payload.as_str(), r#"{"count":1}"#);
    let source_binding = store
        .binding(&run_id)
        .expect("source binding")
        .expect("source binding");
    assert_eq!(source_binding.payload.as_str(), r#"{"count":1}"#);
    assert_ne!(
        restored_binding.binding.branch_id,
        source_binding.binding.branch_id
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn state_authorization_rejects_wrong_profile_and_inactive_run_without_pointer_change() {
    let fixture = open_fixture("t12-state-authorize");
    let persistence = fixture.state.persistence().expect("native persistence");
    seed_session(&persistence, "session-auth", 50);
    seed_run(&persistence, "session-auth", "run-auth", 51);
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let bound = store
        .bind_run(&bind_request(
            "run-auth",
            "session-auth",
            "org.rustscript.test.state",
            PluginStateScope::Session,
            1,
        ))
        .expect("bind state");
    let written = store
        .commit(
            &bound,
            &PluginStatePayload::parse(r#"{"count":1}"#).unwrap(),
        )
        .expect("write state");
    let wrong = store
        .authorize(&written.binding, "other-profile", "graph-state-1", 52)
        .expect_err("wrong profile must not authorize state");
    assert_eq!(wrong.code, "plugin_state_unauthorized");
    complete_durable_run(&persistence, "run-auth");
    terminate_durable_run(&persistence, "run-auth");
    let inactive = store
        .authorize(&written.binding, "default", "graph-state-1", 53)
        .expect_err("terminal run must not authorize state");
    assert_eq!(inactive.code, "plugin_state_unauthorized");
    let unchanged = store
        .binding("run-auth")
        .expect("binding")
        .expect("binding");
    assert_eq!(unchanged.binding.revision, written.binding.revision);
    assert_eq!(unchanged.binding.object_id, written.binding.object_id);
}

fn bind_branch_request(
    run_id: &str,
    session_id: &str,
    branch_id: &str,
    schema: u32,
) -> PluginStateBindRequest {
    PluginStateBindRequest {
        branch_id: branch_id.into(),
        ..bind_request(
            run_id,
            session_id,
            "org.rustscript.test.state",
            PluginStateScope::Session,
            schema,
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_session_commit_rejects_root_and_binding_together() {
    let fixture = open_fixture("t12-session-cas-atomic");
    let persistence = fixture.state.persistence().expect("native persistence");
    seed_session(&persistence, "session-cas", 60);
    seed_run(&persistence, "session-cas", "run-cas-a", 61);
    seed_run(&persistence, "session-cas", "run-cas-b", 62);
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let a = store
        .bind_run(&bind_branch_request(
            "run-cas-a",
            "session-cas",
            "branch-1",
            1,
        ))
        .expect("bind first run");
    let b = store
        .bind_run(&bind_branch_request(
            "run-cas-b",
            "session-cas",
            "branch-1",
            1,
        ))
        .expect("bind second run");
    assert_eq!(a.binding.object_id, b.binding.object_id);
    let winner = store
        .commit(&a, &PluginStatePayload::parse(r#"{"writer":"a"}"#).unwrap())
        .expect("first commit wins the session root CAS");
    assert_eq!(winner.binding.revision, 2);

    let loser_payload = PluginStatePayload::parse(r#"{"writer":"b"}"#).unwrap();
    let conflict = store
        .commit(&b, &loser_payload)
        .expect_err("stale second commit must conflict");
    assert_eq!(conflict.code, "plugin_state_conflict");

    let key = PluginStateRootKey {
        owner_kind: "session".into(),
        owner_id: "session-cas".into(),
        workspace_id: "workspace-1".into(),
        branch_id: "branch-1".into(),
        plugin_id: "org.rustscript.test.state".into(),
    };
    let root = store.root(&key).expect("root").expect("session root");
    assert_eq!(root.revision, 2);
    assert_eq!(root.object_id, winner.binding.object_id);
    let loser = store
        .binding("run-cas-b")
        .expect("loser binding")
        .expect("loser binding");
    assert_eq!(loser.binding.revision, 1);
    assert_eq!(loser.binding.object_id, b.binding.object_id);
    assert_eq!(loser.payload.as_str(), "{}");
    assert_ne!(loser.binding.object_id, winner.binding.object_id);

    // Root CAS matches but the run binding does not: the root must not move.
    let mut forged = winner.binding.clone();
    forged.run_id = "run-cas-b".into();
    let forged_snapshot = PluginStateSnapshot {
        binding: forged,
        payload: winner.payload.clone(),
    };
    let reverse = store
        .commit(
            &forged_snapshot,
            &PluginStatePayload::parse(r#"{"writer":"forged"}"#).unwrap(),
        )
        .expect_err("binding CAS mismatch must reject the whole commit");
    assert_eq!(reverse.code, "plugin_state_conflict");
    let root = store.root(&key).expect("root").expect("session root");
    assert_eq!(root.revision, 2);
    assert_eq!(root.object_id, winner.binding.object_id);
    let loser = store
        .binding("run-cas-b")
        .expect("loser binding")
        .expect("loser binding");
    assert_eq!(loser.binding.revision, 1);
    assert_eq!(loser.payload.as_str(), "{}");
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_roots_restore_exact_source_branch_and_reject_ambiguity() {
    let fixture = open_fixture("t12-checkpoint-exact-branch");
    let persistence = fixture.state.persistence().expect("native persistence");
    seed_session(&persistence, "session-exact", 70);
    seed_run(&persistence, "session-exact", "run-a", 71);
    seed_run(&persistence, "session-exact", "run-b", 72);
    seed_run(&persistence, "session-exact", "run-restored", 73);
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let a = store
        .bind_run(&bind_branch_request(
            "run-a",
            "session-exact",
            "branch-1",
            1,
        ))
        .expect("bind branch a");
    let a_written = store
        .commit(&a, &PluginStatePayload::parse(r#"{"branch":"a"}"#).unwrap())
        .expect("write branch a");
    let b = store
        .bind_run(&bind_branch_request(
            "run-b",
            "session-exact",
            "branch-2",
            1,
        ))
        .expect("bind branch b");
    let mut b_written = b.clone();
    for index in 2..=5 {
        b_written = store
            .commit(
                &b_written,
                &PluginStatePayload::parse(&format!(r#"{{"branch":"b","n":{index}}}"#)).unwrap(),
            )
            .expect("write branch b");
    }
    assert_eq!(b_written.binding.revision, 5);
    assert!(b_written.binding.revision > a_written.binding.revision);

    let roots = store
        .checkpoint_roots("run-a")
        .expect("checkpoint roots for a");
    assert_eq!(roots.len(), 1, "checkpoint must capture exactly run a root");
    assert_eq!(roots[0].branch_id, "branch-1");
    assert_eq!(roots[0].object_id, a_written.binding.object_id);
    assert_eq!(roots[0].revision, a_written.binding.revision);
    let restore_roots: Vec<PluginStateRootRef> = roots
        .iter()
        .map(|root| PluginStateRootRef {
            owner_kind: root.owner_kind.clone(),
            owner_id: root.owner_id.clone(),
            workspace_id: root.workspace_id.clone(),
            branch_id: root.branch_id.clone(),
            plugin_id: root.plugin_id.clone(),
            package_id: root.package_id.clone(),
            artifact_id: root.artifact_id.clone(),
            schema: root.schema,
            revision: root.revision,
            object_id: root.object_id.clone(),
        })
        .collect();
    let restored = store
        .restore_binding(&PluginStateRestoreRequest {
            scope: PluginStateScope::Session,
            run_id: "run-restored".into(),
            session_id: "session-exact".into(),
            workspace_id: "workspace-1".into(),
            branch_id: "branch-restored".into(),
            plugin_id: "org.rustscript.test.state".into(),
            package_id: "org.rustscript.test.state".into(),
            artifact_id: "artifact-state".into(),
            graph_id: "graph-state-1".into(),
            epoch: 1,
            checkpoint_id: "checkpoint-exact".into(),
            roots: restore_roots.clone(),
        })
        .expect("restore branch a exact root");
    assert_eq!(restored.payload.as_str(), r#"{"branch":"a"}"#);
    assert_eq!(restored.binding.object_id, a_written.binding.object_id);
    assert_eq!(restored.binding.schema, 1);

    // A later session migration must not change the old run's captured root.
    let migrated_object = store
        .put_object(
            "org.rustscript.test.state",
            "artifact-state",
            2,
            &PluginStatePayload::parse(r#"{"branch":"a","schema":2}"#).unwrap(),
        )
        .expect("persist migrated object");
    let session_key = PluginStateRootKey {
        owner_kind: "session".into(),
        owner_id: "session-exact".into(),
        workspace_id: "workspace-1".into(),
        branch_id: "branch-1".into(),
        plugin_id: "org.rustscript.test.state".into(),
    };
    let live = store
        .root(&session_key)
        .expect("root")
        .expect("branch a root");
    store
        .migrate_root(&session_key, live.revision, &migrated_object)
        .expect("migrate branch a session root");
    let old = store
        .checkpoint_roots("run-a")
        .expect("checkpoint roots after migration");
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].schema, 1);
    assert_eq!(old[0].revision, a_written.binding.revision);
    assert_eq!(old[0].object_id, a_written.binding.object_id);

    let ambiguous: Vec<PluginStateRootRef> = restore_roots
        .iter()
        .cloned()
        .chain(std::iter::once(PluginStateRootRef {
            owner_id: "session-exact".into(),
            branch_id: "branch-2".into(),
            schema: b_written.binding.schema,
            revision: b_written.binding.revision,
            object_id: b_written.binding.object_id.clone(),
            ..restore_roots[0].clone()
        }))
        .collect();
    let rejected = store
        .restore_binding(&PluginStateRestoreRequest {
            scope: PluginStateScope::Session,
            run_id: "run-restored".into(),
            session_id: "session-exact".into(),
            workspace_id: "workspace-1".into(),
            branch_id: "branch-ambiguous".into(),
            plugin_id: "org.rustscript.test.state".into(),
            package_id: "org.rustscript.test.state".into(),
            artifact_id: "artifact-state".into(),
            graph_id: "graph-state-1".into(),
            epoch: 1,
            checkpoint_id: "checkpoint-ambiguous".into(),
            roots: ambiguous,
        })
        .expect_err("multiple checkpoint roots are ambiguous");
    assert!(
        rejected.code == "plugin_state_root_mismatch"
            || rejected.code == "plugin_state_root_ambiguous"
    );
    let existing = store
        .binding("run-restored")
        .expect("restored binding")
        .expect("restored binding");
    assert_eq!(existing.binding.checkpoint_id, "checkpoint-exact");
    assert_eq!(existing.binding.object_id, a_written.binding.object_id);
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_waits_for_state_writer_busy_then_succeeds_after_settle() {
    let fixture = open_managed_state_fixture("t12-state-writer-fence");
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let run_id = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    wait_run_terminal(&fixture.state, &run_id).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let binding = store
        .binding(&run_id)
        .expect("state binding")
        .expect("state binding");
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let entry = effects["entries"]
        .as_array()
        .and_then(|entries| entries.first())
        .expect("managed read receipt")
        .clone();
    let workspace_id = entry["workspace_id"].as_str().unwrap().to_string();
    let branch_id = entry["branch_id"].as_str().unwrap().to_string();
    let epoch = entry["epoch"].as_u64().unwrap();
    let hold_cancel = rustscript_agent::RunCancellation::with_deadline(
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    );
    let hold = store
        .hold_writer_for_test(&binding.binding, &hold_cancel)
        .expect("hold the formal state writer lease");
    let started = std::time::Instant::now();
    let (status, busy) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": branch_id,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &busy));
    assert_eq!(busy["error"]["code"], "managed_checkpoint_busy");
    assert!(started.elapsed() >= std::time::Duration::from_secs(4));
    drop(hold);
    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": branch_id,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    let roots = checkpoint["checkpoint"]["plugin_state"]["roots"]
        .as_array()
        .expect("stateful roots");
    assert!(!roots.is_empty());
    assert_eq!(roots[0]["immutable_root_id"], binding.binding.object_id);
    assert_eq!(roots[0]["revision"], binding.binding.revision);
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_migrates_each_real_branch_only_on_its_own_commit() {
    let fixture = open_managed_run_state_fixture("t12-admission-dual-branch");
    let http = Http::bind(fixture.state.clone()).await;
    let graph1 = run_state_plugin(&http, &fixture.token).await;
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let run_a = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    wait_run_terminal(&fixture.state, &run_a).await;
    let binding_a = store
        .binding(&run_a)
        .expect("branch a binding")
        .expect("branch a binding");
    assert_eq!(binding_a.binding.schema, 1);
    assert_eq!(binding_a.binding.revision, 2);
    assert_eq!(binding_a.payload.as_str(), r#"{"count":1}"#);

    let workspace_id = binding_a.binding.workspace_id.clone();
    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_a,
                "workspace_id": workspace_id,
                "source_branch_id": binding_a.binding.branch_id,
                "expected_epoch": binding_a.binding.epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, created) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/branches"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": binding_a.binding.branch_id,
                "checkpoint_id": checkpoint_id,
                "request_id": uuid::Uuid::new_v4().to_string()
            }),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &created));
    let branch_b = created["branch"]["branch_id"].as_str().unwrap().to_string();
    assert_ne!(branch_b, binding_a.binding.branch_id);

    let provider_b = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider_b.clone()));
    let run_b = admit_state_run_on_branch(
        &http,
        &fixture.token,
        &session_id,
        &branch_b,
        &graph1,
        &provider_b,
    )
    .await;
    wait_run_terminal(&fixture.state, &run_b).await;
    let binding_b = store
        .binding(&run_b)
        .expect("branch b binding")
        .expect("branch b binding");
    assert_eq!(binding_b.binding.branch_id, branch_b);
    assert_eq!(binding_b.binding.schema, 1);
    assert_eq!(binding_b.binding.revision, 2);
    assert_eq!(binding_b.payload.as_str(), r#"{"count":2}"#);

    let key_a = PluginStateRootKey {
        owner_kind: "session".into(),
        owner_id: session_id.clone(),
        workspace_id: workspace_id.clone(),
        branch_id: binding_a.binding.branch_id.clone(),
        plugin_id: "org.rustscript.test.staterun".into(),
    };
    let key_b = PluginStateRootKey {
        branch_id: branch_b.clone(),
        ..key_a.clone()
    };
    let root_a_before = store.root(&key_a).expect("root a").expect("root a");
    let root_b_before = store.root(&key_b).expect("root b").expect("root b");
    assert_eq!(root_a_before.schema, 1);
    assert_eq!(root_a_before.revision, 2);
    assert_eq!(root_b_before.schema, 1);
    assert_eq!(root_b_before.revision, 2);
    assert_ne!(root_a_before.object_id, root_b_before.object_id);

    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    let provider_a2 = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider_a2.clone()));
    let run_a2 = admit_state_run(&http, &fixture.token, &session_id, &provider_a2).await;
    wait_run_terminal(&fixture.state, &run_a2).await;
    let binding_a2 = store
        .binding(&run_a2)
        .expect("branch a migrated binding")
        .expect("branch a migrated binding");
    assert_eq!(binding_a2.binding.schema, 2);
    assert_eq!(binding_a2.payload.as_str(), r#"{"count":2}"#);
    let root_a_after = store.root(&key_a).expect("root a").expect("root a");
    assert_eq!(root_a_after.schema, 2);
    assert_eq!(root_a_after.object_id, binding_a2.binding.object_id);
    assert_eq!(root_a_after.revision, binding_a2.binding.revision);
    let root_b_after_a = store.root(&key_b).expect("root b").expect("root b");
    assert_eq!(root_b_after_a.schema, 1);
    assert_eq!(root_b_after_a.revision, root_b_before.revision);
    assert_eq!(root_b_after_a.object_id, root_b_before.object_id);
    let binding_b_after_a = store
        .binding(&run_b)
        .expect("branch b old binding")
        .expect("branch b old binding");
    assert_eq!(binding_b_after_a.binding.schema, 1);
    assert_eq!(binding_b_after_a.binding.revision, 2);

    let provider_b2 = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider_b2.clone()));
    let run_b2 = admit_state_run_on_branch(
        &http,
        &fixture.token,
        &session_id,
        &branch_b,
        &graph2,
        &provider_b2,
    )
    .await;
    wait_run_terminal(&fixture.state, &run_b2).await;
    let binding_b2 = store
        .binding(&run_b2)
        .expect("branch b migrated binding")
        .expect("branch b migrated binding");
    assert_eq!(binding_b2.binding.schema, 2);
    assert_eq!(binding_b2.payload.as_str(), r#"{"count":3}"#);
    let root_b_after = store.root(&key_b).expect("root b").expect("root b");
    assert_eq!(root_b_after.schema, 2);
    assert_eq!(root_b_after.object_id, binding_b2.binding.object_id);
    let root_a_after_b = store.root(&key_a).expect("root a").expect("root a");
    assert_eq!(root_a_after_b.object_id, root_a_after.object_id);
    assert_eq!(root_a_after_b.revision, root_a_after.revision);
    assert_eq!(store.binding(&run_a).unwrap().unwrap().binding.schema, 1);
    assert_eq!(store.binding(&run_b).unwrap().unwrap().binding.schema, 1);
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn managed_commit_guard_failure_rolls_back_state_root_binding_and_receipt() {
    let fixture = open_managed_run_state_fixture("t12-managed-commit-state-guard");
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let first_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(first_provider.clone()));
    let first_run = admit_state_run(&http, &fixture.token, &session_id, &first_provider).await;
    wait_run_terminal(&fixture.state, &first_run).await;
    let first_binding = store
        .binding(&first_run)
        .expect("first binding")
        .expect("first binding");
    assert_eq!(first_binding.binding.schema, 1);
    assert_eq!(first_binding.binding.revision, 2);
    assert_eq!(first_binding.payload.as_str(), r#"{"count":1}"#);
    let key = PluginStateRootKey {
        owner_kind: "session".into(),
        owner_id: session_id.clone(),
        workspace_id: first_binding.binding.workspace_id.clone(),
        branch_id: first_binding.binding.branch_id.clone(),
        plugin_id: "org.rustscript.test.staterun".into(),
    };
    let root_before = store.root(&key).expect("root").expect("root");
    assert_eq!(root_before.schema, 1);
    assert_eq!(root_before.revision, 2);

    fixture
        .state
        .service()
        .inject_managed_effect_fault(rustscript_agent::effects::ManagedEffectFault::CommitAfterHead)
        .unwrap();
    let guard_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(guard_provider.clone()));
    let guard_run = admit_state_run(&http, &fixture.token, &session_id, &guard_provider).await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let run = persistence.run_get(&guard_run).unwrap_or_default();
        let status = run["rows"][0][3].as_str().unwrap_or("");
        if status == "completed" || status == "failed" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "guarded commit run did not finish"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    let reopened = PluginStateStore::open(Arc::clone(&persistence));
    let guard_binding = reopened
        .binding(&guard_run)
        .expect("guard binding")
        .expect("guard binding");
    assert_eq!(guard_binding.binding.schema, 1);
    assert_eq!(guard_binding.binding.revision, root_before.revision);
    assert_eq!(guard_binding.payload.as_str(), r#"{"count":1}"#);
    let root_after = reopened.root(&key).expect("root").expect("root");
    assert_eq!(root_after.schema, 1);
    assert_eq!(root_after.revision, root_before.revision);
    assert_eq!(root_after.object_id, root_before.object_id);

    let record = ["local-agent", "gateway", "default"]
        .iter()
        .find_map(|profile| {
            persistence
                .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
                    owner: rustscript_agent::effects::ManagedOwnerScope {
                        profile: (*profile).into(),
                        session_id: session_id.clone(),
                        run_id: guard_run.clone(),
                    },
                    call_id: "state-call".into(),
                })
                .ok()
                .flatten()
        })
        .expect("guarded managed receipt");
    assert!(
        record.prepared.is_some(),
        "prepared state object survives rollback"
    );
    assert!(
        record.outcome.is_none(),
        "guard failure must not finalize the receipt"
    );
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .expect("branch head");
    assert_eq!(head.head_object_id, record.identity.expected_head);
    assert_eq!(head.head_version, record.identity.expected_head_version);

    let retry_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(retry_provider.clone()));
    let retry_run = admit_state_run(&http, &fixture.token, &session_id, &retry_provider).await;
    wait_run_terminal(&fixture.state, &retry_run).await;
    let retry_binding = reopened
        .binding(&retry_run)
        .expect("retry binding")
        .expect("retry binding");
    assert_eq!(retry_binding.binding.schema, 1);
    assert_eq!(retry_binding.binding.revision, root_before.revision + 1);
    assert_eq!(retry_binding.payload.as_str(), r#"{"count":2}"#);
    let root_retry = reopened.root(&key).expect("root").expect("root");
    assert_eq!(root_retry.revision, root_before.revision + 1);
    assert_eq!(root_retry.object_id, retry_binding.binding.object_id);
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn admission_failure_after_prepare_keeps_root_and_binding_values() {
    let fixture = open_managed_run_state_fixture("t12-admission-failure-boundary");
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let first_run = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    wait_run_terminal(&fixture.state, &first_run).await;
    let first_binding = store
        .binding(&first_run)
        .expect("first binding")
        .expect("first binding");
    assert_eq!(first_binding.binding.schema, 1);
    assert_eq!(first_binding.binding.revision, 2);
    assert_eq!(first_binding.payload.as_str(), r#"{"count":1}"#);
    let key = PluginStateRootKey {
        owner_kind: "session".into(),
        owner_id: session_id.clone(),
        workspace_id: first_binding.binding.workspace_id.clone(),
        branch_id: first_binding.binding.branch_id.clone(),
        plugin_id: "org.rustscript.test.staterun".into(),
    };
    let root_before = store.root(&key).expect("root").expect("root");
    assert_eq!(root_before.schema, 1);
    assert_eq!(root_before.revision, 2);
    let messages_before = fixture.state.service().session_messages(&session_id).len();

    activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    fixture
        .state
        .persistence()
        .unwrap()
        .inject_admission_state_fail();
    let fail_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(fail_provider.clone()));
    let (status, body) = admit_state_run_response(
        &http,
        &fixture.token,
        &session_id,
        None,
        None,
        &fail_provider,
    )
    .await;
    assert_eq!(status, 503, "{}", explain(status, &body));
    assert_eq!(body["error"]["code"], "persistence_unavailable");

    let reopened = PluginStateStore::open(Arc::clone(&persistence));
    let root_after = reopened.root(&key).expect("root").expect("root");
    assert_eq!(root_after.schema, 1);
    assert_eq!(root_after.revision, root_before.revision);
    assert_eq!(root_after.object_id, root_before.object_id);
    let binding_after = reopened
        .binding(&first_run)
        .expect("binding")
        .expect("binding");
    assert_eq!(binding_after.binding.schema, 1);
    assert_eq!(binding_after.binding.revision, 2);
    assert_eq!(binding_after.payload.as_str(), r#"{"count":1}"#);
    assert_eq!(
        fixture.state.service().session_messages(&session_id).len(),
        messages_before,
        "a failed admission must not publish a user message or run"
    );

    let retry_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(retry_provider.clone()));
    let retry_run = admit_state_run(&http, &fixture.token, &session_id, &retry_provider).await;
    wait_run_terminal(&fixture.state, &retry_run).await;
    let retry_binding = reopened
        .binding(&retry_run)
        .expect("retry binding")
        .expect("retry binding");
    assert_eq!(retry_binding.binding.schema, 2);
    assert_eq!(retry_binding.payload.as_str(), r#"{"count":2}"#);
    let root_retry = reopened.root(&key).expect("root").expect("root");
    assert_eq!(root_retry.schema, 2);
    assert_eq!(root_retry.object_id, retry_binding.binding.object_id);
    assert_eq!(root_retry.revision, root_before.revision + 2);
    assert_eq!(
        reopened
            .binding(&first_run)
            .expect("old binding")
            .expect("old binding")
            .binding
            .schema,
        1
    );

    let (status, other_session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &other_session));
    let other_session_id = other_session["session"]["id"].as_str().unwrap().to_string();
    let other_provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(other_provider.clone()));
    let other_run =
        admit_state_run(&http, &fixture.token, &other_session_id, &other_provider).await;
    wait_run_terminal(&fixture.state, &other_run).await;
    let other_binding = reopened
        .binding(&other_run)
        .expect("other binding")
        .expect("other binding");
    assert_eq!(other_binding.binding.schema, 2);
    assert_eq!(other_binding.payload.as_str(), r#"{"count":1}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn invocation_state_lives_only_for_its_call_and_never_becomes_durable() {
    let fixture = open_state_fixture("t12-invocation-state", "invocation");
    let http = Http::bind(fixture.state.clone()).await;
    run_state_plugin(&http, &fixture.token).await;
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let mut published = Vec::new();
    for index in 0..2 {
        let provider = rustscript_agent::ScriptedProvider::new();
        fixture
            .state
            .service()
            .inject_provider_host(Arc::new(provider.clone()));
        let run_id = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
        wait_run_terminal(&fixture.state, &run_id).await;
        assert!(
            store.binding(&run_id).expect("binding read").is_none(),
            "invocation state must not create a durable run binding"
        );
        assert!(
            store
                .checkpoint_roots(&run_id)
                .expect("checkpoint roots")
                .is_empty(),
            "invocation state must not enter checkpoint roots"
        );
        let (status, effects) = http
            .request(
                "GET",
                &format!("/v1/runs/{run_id}/effects?limit=128"),
                json!(null),
                Some(&fixture.token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{}", explain(status, &effects));
        let entry = effects["entries"]
            .as_array()
            .and_then(|entries| entries.first())
            .cloned()
            .expect("state call entry");
        let call_id = entry["call_id"].as_str().expect("call id").to_string();
        let workspace_id = entry["workspace_id"]
            .as_str()
            .expect("workspace")
            .to_string();
        let branch_id = entry["branch_id"].as_str().expect("branch").to_string();
        let epoch = entry["epoch"].as_u64().expect("epoch");
        let record = ["local-agent", "gateway", "default"]
            .iter()
            .find_map(|profile| {
                persistence
                    .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
                        owner: rustscript_agent::effects::ManagedOwnerScope {
                            profile: (*profile).into(),
                            session_id: session_id.clone(),
                            run_id: run_id.clone(),
                        },
                        call_id: call_id.clone(),
                    })
                    .ok()
                    .flatten()
            })
            .expect("invocation state effect receipt");
        let publication = record
            .prepared
            .as_ref()
            .expect("prepared receipt")
            .plugin_state
            .as_ref()
            .expect("invocation state audit");
        assert!(publication.ephemeral);
        assert_eq!(publication.owner_kind, "invocation");
        assert!(
            publication.object_id.ends_with(":2"),
            "each call starts from an empty invocation root: {}",
            publication.object_id
        );
        if index == 0 {
            let (status, checkpoint) = http
                .request(
                    "POST",
                    &format!("/v1/workspaces/{workspace_id}/checkpoints"),
                    json!({
                        "source_run_id": run_id,
                        "workspace_id": workspace_id,
                        "source_branch_id": branch_id,
                        "expected_epoch": epoch,
                        "request_id": uuid::Uuid::new_v4().to_string(),
                        "mode": "at_closed_batch"
                    }),
                    Some(&fixture.token),
                    None,
                )
                .await;
            assert_eq!(status, 201, "{}", explain(status, &checkpoint));
            let coverage = &checkpoint["checkpoint"]["plugin_state"];
            assert_eq!(coverage["kind"], "stateful");
            assert_eq!(coverage["manifest_state_present"], true);
            assert_eq!(coverage["invocation_excluded_from_checkpoint"], true);
            assert!(coverage["roots"].as_array().unwrap().is_empty());
            assert_eq!(
                checkpoint["checkpoint"]["public_config"]["config"]["policy_revision"],
                "stateful_invocation_ephemeral"
            );
        }
        published.push(publication.object_id.clone());
    }
    assert_ne!(published[0], published[1]);
    assert_eq!(
        store
            .session_max_schema("org.rustscript.test.staterun")
            .unwrap(),
        0
    );
}

/// 401-R2-A: the collector's protected set must be read at the actual typed
/// worker execution boundary. A caller that captured the set before a candidate
/// P was registered must not be able to delete P with that stale snapshot.
/// P stays prepared (admission parked after its durable put) while more than 64
/// later failed candidates push it out of the recent-orphan window.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn stale_collector_snapshot_cannot_delete_prepared_candidate() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let fixture = open_managed_run_state_fixture("t12-r2a-stale-snapshot");
    let http = Http::bind(fixture.state.clone()).await;
    let _graph1 = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let other_session = create_session(&http, &fixture.token).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));

    for session in [&session_id, &other_session] {
        let provider = rustscript_agent::ScriptedProvider::new();
        script_state_turns(&provider);
        fixture
            .state
            .service()
            .inject_provider_host(Arc::new(provider.clone()));
        let run = admit_state_run(&http, &fixture.token, session, &provider).await;
        assert_eq!(
            wait_run_any_terminal(&fixture.state, &run).await,
            "completed"
        );
    }
    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;

    // C: park one real collector after it captured the caller-side ids and
    // before it issues the typed command.
    let collect_entered = Arc::new(AtomicBool::new(false));
    let collect_release = Arc::new(AtomicBool::new(false));
    let collect_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::clone(&collect_entered);
    let release = Arc::clone(&collect_release);
    let calls = Arc::clone(&collect_calls);
    persistence.inject_plugin_state_collect_observer(Arc::new(move || {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            entered.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }));
    let collector_store = store.clone();
    let collector = std::thread::spawn(move || {
        let _ = collector_store.collect_orphans_result_for_test();
    });
    let entered_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !collect_entered.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < entered_deadline,
            "collector did not reach the stale snapshot"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // P: a real prepared migration candidate parked after its durable put, not
    // the latest object after the later orphans are produced.
    let (candidate_tx, candidate_rx) = std::sync::mpsc::channel::<String>();
    let candidate_release = Arc::new(AtomicBool::new(false));
    let first_candidate = Arc::new(AtomicBool::new(true));
    let release_slot = Arc::clone(&candidate_release);
    let first_slot = Arc::clone(&first_candidate);
    fixture
        .state
        .service()
        .observe_state_candidates(Arc::new(move |object_id: &str| {
            if first_slot.swap(false, Ordering::SeqCst) {
                candidate_tx
                    .send(object_id.to_string())
                    .expect("candidate id");
                while !release_slot.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }));
    let p_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&p_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(p_provider.clone()));
    let service = fixture.state.service().clone();
    let p_session = session_id.clone();
    let p_graph = graph2.clone();
    let p_task = tokio::spawn(async move {
        service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!("r2a prepared candidate"),
                    session_id: Some(p_session),
                    graph_id: Some(p_graph),
                    platform: "test".into(),
                    ..AdmitRunRequest::default()
                },
                None,
            )
            .await
    });
    let p_candidate = tokio::task::spawn_blocking(move || {
        candidate_rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("prepared candidate id")
    })
    .await
    .unwrap();
    assert!(store.object_payload(&p_candidate).is_ok());

    // More than 64 later orphans, each through the real failed-migration path.
    for attempt in 0..65 {
        persistence.inject_admission_state_fail();
        let (status, body) = admit_run_with_identity(
            &http,
            &fixture.token,
            &other_session,
            "r2a later orphan",
            Some(&graph2),
            &format!("t12-r2a-orphan-{attempt}"),
        )
        .await;
        assert_eq!(status, 503, "{}", explain(status, &body));
    }
    assert!(store.object_payload(&p_candidate).is_ok());

    // Release the stale collector. The worker must use the current protected
    // set, not C's pre-P snapshot.
    collect_release.store(true, Ordering::SeqCst);
    collector.join().expect("collector thread");
    let p_readable_after_stale_collect = store.object_payload(&p_candidate).is_ok();

    candidate_release.store(true, Ordering::SeqCst);
    let p_admitted = tokio::time::timeout(std::time::Duration::from_secs(30), p_task)
        .await
        .expect("P admission settles")
        .expect("P admission join");
    let p_result_ok = p_admitted.is_ok();

    // Decisive assertions after cleanup.
    assert!(
        p_readable_after_stale_collect,
        "a stale collector snapshot deleted a live prepared candidate"
    );
    let p_admitted = p_admitted.expect("P admission commits with its candidate intact");
    let root = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("root");
    let root = store.root(&root).expect("root").expect("root");
    assert_eq!(root.schema, 2);
    assert_eq!(root.object_id, p_candidate);
    let binding = store
        .binding(&p_admitted.run_id)
        .expect("P binding")
        .expect("P binding");
    assert_eq!(binding.binding.object_id, p_candidate);
    assert!(p_result_ok);
}

/// 401-R2-B (unknown put): a durable `plugin.state_object_put` whose reply is
/// lost must still settle through the candidate owner created before the put.
/// Repeating it more than 64 times must not accumulate durable orphans.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn unknown_put_reply_is_bounded_by_the_pre_put_candidate_owner() {
    let fixture = open_managed_run_state_fixture("t12-r2b-unknown-put");
    let http = Http::bind(fixture.state.clone()).await;
    let _graph1 = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let baseline_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&baseline_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(baseline_provider.clone()));
    let baseline_run =
        admit_state_run(&http, &fixture.token, &session_id, &baseline_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema1 root");
    let root_before = store.root(&key).expect("root").expect("root");
    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;

    let reserved = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&reserved);
    persistence.observe_plugin_state_candidate_reservations(Arc::new(move |object_id: &str| {
        recorded
            .lock()
            .expect("reserved candidates")
            .push(object_id.to_string());
    }));

    for attempt in 0..70 {
        persistence.inject_plugin_state_put_ack_loss();
        let (status, body) = admit_run_with_identity(
            &http,
            &fixture.token,
            &session_id,
            "r2b unknown put",
            Some(&graph2),
            &format!("t12-r2b-unknown-{attempt}"),
        )
        .await;
        assert_eq!(status, 422, "{}", explain(status, &body));
        assert_eq!(body["error"]["code"], "invalid_admission");
    }
    let ids = reserved.lock().expect("reserved candidates").clone();
    assert_eq!(ids.len(), 70, "each attempt reserved one candidate owner");
    let existing = ids
        .iter()
        .filter(|object_id| store.object_payload(object_id).is_ok())
        .count();
    assert!(
        existing <= 64,
        "unknown puts accumulated {existing} durable candidates"
    );
    assert_eq!(
        store.candidate_registry_len_for_test(),
        0,
        "every pre-put owner settled"
    );
    assert!(store.object_payload(&root_before.object_id).is_ok());
    assert!(
        store
            .object_payload(
                &store
                    .binding(&baseline_run)
                    .expect("baseline binding")
                    .expect("binding")
                    .binding
                    .object_id
            )
            .is_ok()
    );

    let recovered_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&recovered_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(recovered_provider.clone()));
    let (status, recovered) = admit_run_with_identity(
        &http,
        &fixture.token,
        &session_id,
        "r2b recovered",
        Some(&graph2),
        "t12-r2b-recovered",
    )
    .await;
    assert_eq!(status, 202, "{}", explain(status, &recovered));
    let recovered_run = recovered["run_id"].as_str().unwrap().to_string();
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &recovered_run).await,
        "completed"
    );
    assert_eq!(store.root(&key).expect("root").expect("root").schema, 2);
}

/// 401-R2-B (collector error): a real collector SQL failure must not be
/// swallowed while candidates keep being created. Bounded debt refuses new
/// candidate writes until the same collector succeeds again.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn collector_failure_backpressures_new_candidates_and_recovers() {
    let fixture = open_managed_run_state_fixture("t12-r2b-collector-error");
    let http = Http::bind(fixture.state.clone()).await;
    let _graph1 = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let baseline_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&baseline_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(baseline_provider.clone()));
    let baseline_run =
        admit_state_run(&http, &fixture.token, &session_id, &baseline_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema1 root");
    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    let payload = PluginStatePayload::parse("{}").expect("empty state document");

    // A real in-transaction SQL failure, surfaced by the typed collector.
    persistence.inject_plugin_state_collect_failpoint();
    let first = store.collect_orphans_result_for_test();
    assert!(first.is_err(), "the real collector failure must surface");

    let mut refused_ids = Vec::new();
    for _ in 0..70 {
        persistence.inject_plugin_state_collect_failpoint();
        let (object_id, result) = store.candidate_put_for_test(
            "org.rustscript.test.staterun",
            &root_artifact(&store, &key),
            2,
            &payload,
        );
        assert!(
            result.is_err(),
            "a failed collector must refuse the next candidate write"
        );
        refused_ids.push(object_id);
    }
    for object_id in &refused_ids {
        assert!(
            store.object_payload(object_id).is_err(),
            "backpressured candidate must not be durable"
        );
    }

    // Recovered collector re-opens candidate writes.
    assert!(store.collect_orphans_result_for_test().is_ok());
    let (recovered_id, recovered) = store.candidate_put_for_test(
        "org.rustscript.test.staterun",
        &root_artifact(&store, &key),
        2,
        &payload,
    );
    assert!(recovered.is_ok(), "candidate write resumes after recovery");
    assert!(store.collect_orphans_result_for_test().is_ok());
    assert!(
        store.object_payload(&recovered_id).is_ok(),
        "a recovered candidate write is bounded by the existing 64-orphan rule"
    );

    let recovered_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&recovered_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(recovered_provider.clone()));
    let (status, recovered) = admit_run_with_identity(
        &http,
        &fixture.token,
        &session_id,
        "r2b collector recovered",
        Some(&graph2),
        "t12-r2b-collector-recovered",
    )
    .await;
    assert_eq!(status, 202, "{}", explain(status, &recovered));
    let recovered_run = recovered["run_id"].as_str().unwrap().to_string();
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &recovered_run).await,
        "completed"
    );
    assert_eq!(store.root(&key).expect("root").expect("root").schema, 2);
}

#[cfg(feature = "workspace-io-fault")]
fn root_artifact(store: &PluginStateStore, key: &PluginStateRootKey) -> String {
    store
        .root(key)
        .expect("root")
        .expect("root row")
        .artifact_id
}

// ---------------------------------------------------------------------------
// 406 baseline negative controls. These helpers only use the real typed
// producer, managed HTTP/RSS run, storage worker, and collector. No state
// algorithm or protection rule is changed.
// ---------------------------------------------------------------------------

#[cfg(feature = "workspace-io-fault")]
struct ReleaseFlag(Arc<std::sync::atomic::AtomicBool>);

#[cfg(feature = "workspace-io-fault")]
impl Drop for ReleaseFlag {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "workspace-io-fault")]
struct R2ASetup {
    fixture: Fixture,
    http: Arc<Http>,
    session_id: String,
    other_session: String,
    q_session: String,
    graph2: String,
    #[allow(dead_code)]
    schema2_run: String,
    persistence: Arc<GatewayPersistence>,
    store: PluginStateStore,
}

#[cfg(feature = "workspace-io-fault")]
async fn r2a_setup(label: &str) -> R2ASetup {
    let fixture = open_managed_run_state_fixture(label);
    let http = Arc::new(Http::bind(fixture.state.clone()).await);
    let _graph1 = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let other_session = create_session(&http, &fixture.token).await;
    let q_session = create_session(&http, &fixture.token).await;
    for sid in [&session_id, &other_session, &q_session] {
        let provider = rustscript_agent::ScriptedProvider::new();
        script_state_turns(&provider);
        fixture
            .state
            .service()
            .inject_provider_host(Arc::new(provider.clone()));
        let run = admit_state_run(&http, &fixture.token, sid, &provider).await;
        assert_eq!(
            wait_run_any_terminal(&fixture.state, &run).await,
            "completed",
            "baseline schema1 run"
        );
    }
    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    // Move the controlled session to schema 2 before the target run so its
    // admission has no migration candidate of its own.
    let provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let schema2_run = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &schema2_run).await,
        "completed",
        "schema2 baseline run"
    );
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    R2ASetup {
        fixture,
        http,
        session_id,
        other_session,
        q_session,
        graph2,
        schema2_run,
        persistence,
        store,
    }
}

#[cfg(feature = "workspace-io-fault")]
async fn r2a_checkpoint_object(env: &R2ASetup, run_id: &str) -> (String, String) {
    let (status, effects) = env
        .http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&env.fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let entry = effects["entries"]
        .as_array()
        .and_then(|entries| entries.first())
        .expect("managed state effect")
        .clone();
    let workspace_id = entry["workspace_id"].as_str().unwrap().to_string();
    let branch_id = entry["branch_id"].as_str().unwrap().to_string();
    let epoch = entry["epoch"].as_u64().unwrap();
    let (status, checkpoint) = env
        .http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": branch_id,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&env.fixture.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    let roots = checkpoint["checkpoint"]["plugin_state"]["roots"]
        .as_array()
        .expect("stateful roots");
    let object_id = roots
        .iter()
        .find(|root| root["plugin_id"] == "org.rustscript.test.staterun")
        .and_then(|root| root["immutable_root_id"].as_str())
        .expect("state root object")
        .to_string();
    (checkpoint_id, object_id)
}

#[cfg(feature = "workspace-io-fault")]
async fn r2a_reference_objects(env: &R2ASetup) -> (String, String, String) {
    let key = env
        .store
        .session_root_key(&env.session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("session root");
    let root = env.store.root(&key).expect("root").expect("root row");
    let package_id = root.package_id.clone();
    let artifact_id = root.artifact_id.clone();

    // Root-only reference: a second branch root with no run binding.
    let payload = PluginStatePayload::parse(r#"{"ref":"root-only"}"#).unwrap();
    let root_only = env
        .store
        .put_object(&package_id, &artifact_id, 2, &payload)
        .expect("root-only object");
    let mut root_only_key = key.clone();
    root_only_key.branch_id = "r2a-root-only-branch".into();
    env.store
        .cas_root(&root_only_key, 0, &root_only)
        .expect("root-only cas");

    // Binding-only reference: run-a keeps revision 2 while the shared session
    // root advances through run-b.
    seed_session(&env.persistence, "r2a-bind-session", 7_000);
    seed_run(&env.persistence, "r2a-bind-session", "r2a-run-a", 7_001);
    seed_run(&env.persistence, "r2a-bind-session", "r2a-run-b", 7_002);
    let request_a = bind_request(
        "r2a-run-a",
        "r2a-bind-session",
        "org.rustscript.test.staterun",
        PluginStateScope::Session,
        1,
    );
    let snapshot_a = env.store.bind_run(&request_a).expect("bind run-a");
    env.store
        .commit(
            &snapshot_a,
            &PluginStatePayload::parse(r#"{"ref":"a1"}"#).unwrap(),
        )
        .expect("commit run-a");
    let request_b = bind_request(
        "r2a-run-b",
        "r2a-bind-session",
        "org.rustscript.test.staterun",
        PluginStateScope::Session,
        1,
    );
    let snapshot_b = env.store.bind_run(&request_b).expect("bind run-b");
    env.store
        .commit(
            &snapshot_b,
            &PluginStatePayload::parse(r#"{"ref":"b1"}"#).unwrap(),
        )
        .expect("commit run-b");
    let binding_only = env
        .store
        .binding("r2a-run-a")
        .expect("run-a binding read")
        .expect("run-a binding")
        .binding
        .object_id;

    // Checkpoint-only reference: a fresh single-run session captures a real
    // checkpoint root, then the same run binding advances so the checkpoint
    // object is referenced by the checkpoint receipt only.
    let checkpoint_session = create_session(&env.http, &env.fixture.token).await;
    let checkpoint_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&checkpoint_provider);
    env.fixture
        .state
        .service()
        .inject_provider_host(Arc::new(checkpoint_provider.clone()));
    let checkpoint_run = admit_state_run(
        &env.http,
        &env.fixture.token,
        &checkpoint_session,
        &checkpoint_provider,
    )
    .await;
    assert_eq!(
        wait_run_any_terminal(&env.fixture.state, &checkpoint_run).await,
        "completed",
        "checkpoint source run"
    );
    let (_checkpoint_id, checkpoint_object) = r2a_checkpoint_object(env, &checkpoint_run).await;
    let checkpoint_snapshot = env
        .store
        .binding(&checkpoint_run)
        .expect("checkpoint binding read")
        .expect("checkpoint binding");
    let advanced = env
        .store
        .commit(
            &checkpoint_snapshot,
            &PluginStatePayload::parse(r#"{"after":"checkpoint"}"#).unwrap(),
        )
        .expect("advance past checkpoint");
    assert_ne!(advanced.binding.object_id, checkpoint_object);
    (root_only.object_id, binding_only, checkpoint_object)
}

#[cfg(feature = "workspace-io-fault")]
async fn r2a_orphans(env: &R2ASetup, label: &str) {
    for attempt in 0..65 {
        env.persistence.inject_admission_state_fail();
        let (status, body) = admit_run_with_identity(
            &env.http,
            &env.fixture.token,
            &env.other_session,
            "r2a later orphan",
            Some(&env.graph2),
            &format!("{label}-orphan-{attempt}"),
        )
        .await;
        assert_eq!(status, 503, "{}", explain(status, &body));
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2a_guest_staged_state_object_survives_collector() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let env = r2a_setup("r2a-staged").await;
    let (root_only, binding_only, checkpoint_only) = r2a_reference_objects(&env).await;

    let (put_tx, put_rx) = std::sync::mpsc::channel::<String>();
    let release = Arc::new(AtomicBool::new(false));
    let release_slot = Arc::clone(&release);
    let first = Arc::new(AtomicBool::new(true));
    let first_slot = Arc::clone(&first);
    env.persistence
        .inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
            if first_slot.swap(false, Ordering::SeqCst) {
                put_tx
                    .send(object_id.to_string())
                    .expect("guest staged object id");
                while !release_slot.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }));
    let _release_guard = ReleaseFlag(Arc::clone(&release));

    let target_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&target_provider);
    env.fixture
        .state
        .service()
        .inject_provider_host(Arc::new(target_provider.clone()));
    let target_run = admit_state_run(
        &env.http,
        &env.fixture.token,
        &env.session_id,
        &target_provider,
    )
    .await;
    let p_object = tokio::task::spawn_blocking(move || {
        put_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("guest state::write reaches staged put")
    })
    .await
    .unwrap();
    assert!(
        env.store.object_payload(&p_object).is_ok(),
        "staged guest object must be durable before the pause"
    );

    r2a_orphans(&env, "r2a-staged").await;
    env.store
        .collect_orphans_result_for_test()
        .expect("generic collector after 65 newer orphans");

    let p_staged_readable = env.store.object_payload(&p_object).is_ok();
    release.store(true, Ordering::SeqCst);
    drop(_release_guard);
    let status = wait_any_status(&env.fixture.state, &target_run).await;
    let key = env
        .store
        .session_root_key(&env.session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("session root");
    let root = env.store.root(&key).expect("root").expect("root row");
    let committed = root.object_id == p_object;
    eprintln!(
        "r2a staged observed: p_readable={p_staged_readable} run={status} root_is_p={committed} root_object={}",
        root.object_id
    );

    assert!(
        env.store.object_payload(&root_only).is_ok(),
        "404-R2-A reference: root-only object was deleted"
    );
    assert!(
        env.store.object_payload(&binding_only).is_ok(),
        "404-R2-A reference: binding-only object was deleted"
    );
    assert!(
        env.store.object_payload(&checkpoint_only).is_ok(),
        "404-R2-A reference: checkpoint-only object was deleted"
    );
    assert!(
        p_staged_readable,
        "404-R2-A staged: generic collector deleted the staged guest state object {p_object}"
    );
    assert_eq!(status, "completed", "staged guest run must commit");
    assert!(committed, "staged guest object must commit");
}

#[cfg(feature = "workspace-io-fault")]
async fn wait_flag(flag: &std::sync::atomic::AtomicBool, label: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    while !flag.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {label}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

#[cfg(feature = "workspace-io-fault")]
async fn wait_any_status(state: &AgentGatewayState, run_id: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let persistence = state.persistence().unwrap();
        let run = persistence.run_get(run_id).unwrap_or_default();
        let status = run["rows"][0][3].as_str().unwrap_or("").to_string();
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "run {run_id} did not reach terminal status, last={status}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2a_guest_prepared_state_object_survives_collector() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let env = r2a_setup("r2a-prepared").await;
    let prepare_gate = env
        .fixture
        .state
        .service()
        .arm_managed_prepare_gate()
        .expect("arm prepare gate");

    let (put_tx, put_rx) = std::sync::mpsc::channel::<String>();
    let release_put = Arc::new(AtomicBool::new(false));
    let release_slot = Arc::clone(&release_put);
    let first = Arc::new(AtomicBool::new(true));
    let first_slot = Arc::clone(&first);
    env.persistence
        .inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
            if first_slot.swap(false, Ordering::SeqCst) {
                put_tx
                    .send(object_id.to_string())
                    .expect("prepared staged object id");
                while !release_slot.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }));
    let _release_guard = ReleaseFlag(Arc::clone(&release_put));

    let target_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&target_provider);
    env.fixture
        .state
        .service()
        .inject_provider_host(Arc::new(target_provider.clone()));
    let target_run = admit_state_run(
        &env.http,
        &env.fixture.token,
        &env.session_id,
        &target_provider,
    )
    .await;
    let p_object = tokio::task::spawn_blocking(move || {
        put_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("guest state::write reaches staged put")
    })
    .await
    .unwrap();

    // Newer typed objects age P past the recent-64 set while its real
    // effect.prepare is about to run.
    let key = env
        .store
        .session_root_key(&env.q_session, "org.rustscript.test.staterun")
        .expect("q session key")
        .expect("q session root");
    let q_root = env.store.root(&key).expect("q root").expect("q root row");
    let mut orphan_ids = Vec::new();
    for attempt in 0..65 {
        orphan_ids.push(
            env.store
                .put_object(
                    &q_root.package_id,
                    &q_root.artifact_id,
                    q_root.schema,
                    &PluginStatePayload::parse(&format!(r#"{{"orphan":{attempt}}}"#)).unwrap(),
                )
                .expect("newer typed orphan object")
                .object_id,
        );
    }
    release_put.store(true, Ordering::SeqCst);
    drop(_release_guard);
    prepare_gate
        .wait_arrived(1)
        .expect("real effect.prepare reaches the gate");

    env.store
        .collect_orphans_result_for_test()
        .expect("generic collector after 65 newer orphans");
    let p_prepared_readable = env.store.object_payload(&p_object).is_ok();
    // The prepared receipt is durable, so its object ref is part of the typed
    // collector reference set: a NULL-filtered stateless receipt must not
    // stall the collector, and exactly the oldest true orphan is reclaimed
    // while the prepared object survives.
    let readable_orphans = orphan_ids
        .iter()
        .filter(|object_id| env.store.object_payload(object_id).is_ok())
        .count();
    eprintln!("r2a prepared orphans readable={readable_orphans}");
    prepare_gate.release();
    let status = wait_any_status(&env.fixture.state, &target_run).await;
    let session_key = env
        .store
        .session_root_key(&env.session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("session root");
    let root = env
        .store
        .root(&session_key)
        .expect("root")
        .expect("root row");
    let committed = root.object_id == p_object;
    eprintln!(
        "r2a prepared observed: p_readable={p_prepared_readable} run={status} root_is_p={committed} root_object={}",
        root.object_id
    );
    assert!(
        p_prepared_readable,
        "404-R2-A prepared: generic collector deleted the prepared guest state object {p_object}"
    );
    assert_eq!(
        readable_orphans, 64,
        "stateless prepared receipts must not stall collection of true orphans"
    );
    assert_eq!(status, "completed", "prepared guest run must commit");
    assert!(committed, "prepared guest object must commit");
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2b_queued_admission_owner_survives_caller_timeout() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let env = r2a_setup("r2b-queued").await;
    let candidate_id = Arc::new(std::sync::Mutex::new(None::<String>));
    let candidate_slot = Arc::clone(&candidate_id);
    env.fixture
        .state
        .service()
        .observe_state_candidates(Arc::new(move |object_id: &str| {
            *candidate_slot.lock().expect("candidate slot") = Some(object_id.to_string());
        }));

    let q_run_id = Arc::new(std::sync::Mutex::new(None::<String>));
    let precommit_entered = Arc::new(AtomicBool::new(false));
    let precommit_release = Arc::new(AtomicBool::new(false));
    let entered_slot = Arc::clone(&precommit_entered);
    let release_slot = Arc::clone(&precommit_release);
    let run_slot = Arc::clone(&q_run_id);
    env.persistence
        .inject_admission_precommit_hook(move |payload: &serde_json::Value| {
            *run_slot.lock().expect("queued run id") =
                Some(payload["run_id"].as_str().unwrap_or_default().to_string());
            entered_slot.store(true, Ordering::SeqCst);
            while !release_slot.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

    let http = Arc::clone(&env.http);
    let token = env.fixture.token.clone();
    let session = env.q_session.clone();
    let graph = env.graph2.clone();
    env.persistence
        .inject_control_reply_timeout_for_test(std::time::Duration::from_secs(2));
    let q_task = tokio::spawn(async move {
        admit_run_with_identity(
            &http,
            &token,
            &session,
            "r2b queued admission",
            Some(&graph),
            "r2b-queued-q",
        )
        .await
    });
    wait_flag(&precommit_entered, "queued admission precommit").await;
    let p_object = candidate_id
        .lock()
        .expect("candidate id")
        .clone()
        .expect("prepared migration candidate");
    assert!(
        env.store.object_payload(&p_object).is_ok(),
        "queued admission P must be durable before the collector"
    );

    // 65 newer unreferenced objects through the real typed producer. The
    // paused admission holds the global commit gate, so the ageing objects use
    // the same plugin.state_object_put worker command instead of admissions.
    let key = env
        .store
        .session_root_key(&env.q_session, "org.rustscript.test.staterun")
        .expect("q session key")
        .expect("q session root");
    let q_root = env.store.root(&key).expect("q root").expect("q root row");
    for attempt in 0..65 {
        env.store
            .put_object(
                &q_root.package_id,
                &q_root.artifact_id,
                q_root.schema,
                &PluginStatePayload::parse(&format!(r#"{{"orphan":{attempt}}}"#)).unwrap(),
            )
            .expect("newer typed orphan object");
    }

    let collect_entered = Arc::new(AtomicBool::new(false));
    let gate_release = Arc::new(AtomicBool::new(false));
    let entered_slot = Arc::clone(&collect_entered);
    let release_slot = Arc::clone(&gate_release);
    env.persistence
        .inject_worker_execute_gate(Arc::new(move |op: &str| {
            if op == "plugin.state_collect" {
                entered_slot.store(true, Ordering::SeqCst);
                while !release_slot.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }));
    let _release_guard = ReleaseFlag(Arc::clone(&gate_release));
    let collector_store = env.store.clone();
    let collector = std::thread::spawn(move || collector_store.collect_orphans_result_for_test());
    wait_flag(&collect_entered, "queued collector at worker boundary").await;

    // Q's admission.create is enqueued strictly after C in the same worker.
    precommit_release.store(true, Ordering::SeqCst);
    let (q_status, q_body) = tokio::time::timeout(std::time::Duration::from_secs(90), q_task)
        .await
        .expect("queued admission caller settles")
        .expect("queued admission join");
    assert_ne!(
        q_status,
        202,
        "queued admission must be unknown after the real storage timeout: {}",
        explain(q_status, &q_body)
    );
    let q_run = q_run_id
        .lock()
        .expect("queued run id")
        .clone()
        .expect("run id captured before admission.create");
    // The caller released only its own reference on the unknown result. The
    // still-queued admission.create request keeps one worker-held reservation
    // sidecar until the worker settles it, so the queued object stays
    // protected while the earlier collector runs.
    let owner_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let held = env.store.candidate_registry_len_for_test();
        if held == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < owner_deadline,
            "worker-held admission owner did not survive the caller timeout (held={held})"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    gate_release.store(true, Ordering::SeqCst);
    drop(_release_guard);
    let collector_result = collector.join().expect("collector thread");
    // The collector caller itself timed out; the queued request still runs.
    let _ = collector_result;
    // run_get is enqueued after Q, so it returns only after the worker settled Q.
    let run_row = env.persistence.run_get(&q_run).unwrap_or_default();
    let q_rows = run_row["rows"].as_array().cloned().unwrap_or_default();
    eprintln!(
        "r2b queued observed: p_readable={} q_run_rows={} registry={} collector_rc={:?}",
        env.store.object_payload(&p_object).is_ok(),
        q_rows.len(),
        env.store.candidate_registry_len_for_test(),
        collector_result.as_ref().err().map(|error| error.code)
    );

    assert!(
        env.store.object_payload(&p_object).is_ok(),
        "404-R2-B queued: earlier collector deleted P required by still-queued admission"
    );
    assert!(
        !q_rows.is_empty(),
        "404-R2-B queued: admission returned no durable formal result after worker resume"
    );
    assert_eq!(
        env.store.candidate_registry_len_for_test(),
        0,
        "both owner references must be clear after the queued request settles"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2b_inflight_candidate_put_owner_covers_unknown_caller() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let env = r2a_setup("r2b-inflight").await;
    let reserved_id = Arc::new(std::sync::Mutex::new(None::<String>));
    let reserved_slot = Arc::clone(&reserved_id);
    env.persistence
        .observe_plugin_state_candidate_reservations(Arc::new(move |object_id: &str| {
            let mut slot = reserved_slot.lock().expect("reservation slot");
            if slot.is_none() {
                *slot = Some(object_id.to_string());
            }
        }));

    let put_entered = Arc::new(AtomicBool::new(false));
    let gate_release = Arc::new(AtomicBool::new(false));
    let entered_slot = Arc::clone(&put_entered);
    let release_slot = Arc::clone(&gate_release);
    let armed = Arc::new(AtomicBool::new(false));
    let armed_slot = Arc::clone(&armed);
    env.persistence
        .inject_worker_execute_gate(Arc::new(move |op: &str| {
            if op == "plugin.state_object_put" && !armed_slot.swap(true, Ordering::SeqCst) {
                entered_slot.store(true, Ordering::SeqCst);
                while !release_slot.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }));
    let _release_guard = ReleaseFlag(Arc::clone(&gate_release));

    let http = Arc::clone(&env.http);
    let token = env.fixture.token.clone();
    let session = env.q_session.clone();
    let graph = env.graph2.clone();
    env.persistence
        .inject_control_reply_timeout_for_test(std::time::Duration::from_secs(2));
    let q_task = tokio::spawn(async move {
        admit_run_with_identity(
            &http,
            &token,
            &session,
            "r2b inflight candidate put",
            Some(&graph),
            "r2b-inflight-q",
        )
        .await
    });
    wait_flag(&put_entered, "in-flight candidate put at worker boundary").await;
    let p_object = reserved_id
        .lock()
        .expect("reservation id")
        .clone()
        .expect("candidate reservation before the put");
    // The caller is still blocked on the real storage response; the put has
    // not run yet.
    let (q_status, q_body) = tokio::time::timeout(std::time::Duration::from_secs(90), q_task)
        .await
        .expect("in-flight put caller settles")
        .expect("in-flight put join");
    assert_ne!(
        q_status,
        202,
        "unknown in-flight put caller must surface the storage timeout: {}",
        explain(q_status, &q_body)
    );
    let held = env.store.candidate_registry_len_for_test();

    let collector_store = env.store.clone();
    let collector = std::thread::spawn(move || collector_store.collect_orphans_result_for_test());
    gate_release.store(true, Ordering::SeqCst);
    drop(_release_guard);
    let collector_result = collector.join().expect("collector thread");
    eprintln!(
        "r2b inflight observed: held_at_timeout={} p_readable_after_settle={} collector_rc={:?} registry_after={}",
        held,
        env.store.object_payload(&p_object).is_ok(),
        collector_result.as_ref().err().map(|error| error.code),
        env.store.candidate_registry_len_for_test()
    );
    assert!(
        held > 0,
        "404-R2-B inflight: caller timeout removed the only owner while plugin.state_object_put is still executing"
    );
    assert!(
        collector_result.is_ok(),
        "collector queued behind the put must settle with the real worker result"
    );
    assert!(
        env.store.object_payload(&p_object).is_ok(),
        "the worker still executes a real put after its caller became unknown"
    );
    assert_eq!(
        env.store.candidate_registry_len_for_test(),
        0,
        "owner registry must clear after the request settles"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2b_collector_health_is_not_cleared_by_delayed_success() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let fixture = open_fixture("r2b-health-order");
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let success_entered = Arc::new(AtomicBool::new(false));
    let release_success = Arc::new(AtomicBool::new(false));
    let entered_slot = Arc::clone(&success_entered);
    let release_slot = Arc::clone(&release_success);
    let first = Arc::new(AtomicBool::new(true));
    let first_slot = Arc::clone(&first);
    persistence.inject_plugin_state_collect_result_observer(Arc::new(move |ok: bool| {
        if ok && first_slot.swap(false, Ordering::SeqCst) {
            entered_slot.store(true, Ordering::SeqCst);
            while !release_slot.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }));

    let old_store = store.clone();
    let old_success = std::thread::spawn(move || old_store.collect_orphans_result_for_test());
    wait_flag(&success_entered, "older successful collector reply").await;

    // A newer collector fails with a real in-transaction SQL guard fault.
    persistence.inject_plugin_state_collect_failpoint();
    let newer = store.collect_orphans_result_for_test();
    assert!(
        newer.is_err(),
        "the real SQL guard fault must surface from the collector"
    );
    assert!(
        store.collection_debt_for_test(),
        "the newer failure must record collection debt"
    );

    release_success.store(true, Ordering::SeqCst);
    old_success
        .join()
        .expect("old collector thread")
        .expect("older collector itself succeeded");
    assert!(
        store.collection_debt_for_test(),
        "404-R2-B health: delayed older success cleared the newer collector failure debt"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2b_guest_plain_puts_ignore_collector_debt_and_exceed_bound() {
    let fixture = open_managed_run_state_fixture("r2b-guest-debt");
    let http = Http::bind(fixture.state.clone()).await;
    let _graph = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let baseline_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&baseline_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(baseline_provider.clone()));
    let baseline_run =
        admit_state_run(&http, &fixture.token, &session_id, &baseline_provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed"
    );
    let persistence = fixture.state.persistence().unwrap();
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let baseline_root = store
        .root(
            &store
                .session_root_key(&session_id, "org.rustscript.test.staterun")
                .expect("session key")
                .expect("schema1 session root"),
        )
        .expect("root")
        .expect("root row")
        .object_id;
    eprintln!("r2b guest debt diag: baseline_root={baseline_root}");
    let collect_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_slot = Arc::clone(&collect_calls);
    persistence.inject_plugin_state_collect_observer(Arc::new(move || {
        calls_slot.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));

    let ids = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let ids_slot = Arc::clone(&ids);
    persistence.inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
        let mut ids = ids_slot.lock().expect("put ids");
        if ids.last().is_none_or(|last| last != object_id) {
            ids.push(object_id.to_string());
        }
    }));

    // Break the collector with the real SQL guard fault.
    persistence.inject_plugin_state_collect_failpoint();
    assert!(
        store.collect_orphans_result_for_test().is_err(),
        "real collector guard fault must surface"
    );
    assert!(
        store.collection_debt_for_test(),
        "failed collector must record debt"
    );

    // Formal guest producer: each run stages/prepares a plain state object.
    // With the collector degraded the unified reservation boundary refuses the
    // put before any durable write or managed prepare cut, so no one-shot
    // fixture fault is armed here; the typed refusal is asserted from events.
    //
    // 406 armed AfterOperationBeforePrepare for each of 72 guest runs because a
    // put used to become durable before preparation. The unified boundary now
    // refuses the put earlier, so that one-shot cut was never consumed and
    // leaked into the recovery run (real diagnosis: diag5-diag8). The refusal
    // count is preserved as 72 by pairing 56 guest runs (below the managed
    // effect retention bound of 64 receipts) with 16 direct typed producer
    // attempts that assert the same refusal without consuming managed slots.
    let session_key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("session root");
    let baseline_row = store.root(&session_key).expect("root").expect("root row");
    let mut statuses = std::collections::BTreeMap::new();
    for attempt in 0..56 {
        let provider = rustscript_agent::ScriptedProvider::new();
        script_state_turns(&provider);
        fixture
            .state
            .service()
            .inject_provider_host(Arc::new(provider.clone()));
        let run = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
        let status = wait_any_status(&fixture.state, &run).await;
        let events = fixture.state.service().run_events(&run);
        let failed = events
            .iter()
            .find(|event| event["event"] == "tool.failed")
            .unwrap_or_else(|| {
                panic!("debt-refused guest run {attempt} must fail the tool call: {events:?}")
            });
        assert_eq!(
            failed["data"]["error_code"], "plugin_state_unavailable",
            "debt backpressure must surface as the typed state refusal: {events:?}"
        );
        *statuses.entry(status.clone()).or_insert(0usize) += 1;
        assert!(
            matches!(status.as_str(), "completed" | "failed"),
            "guest run {attempt} reached {status}"
        );
    }
    let direct_payload = PluginStatePayload::parse(r#"{"refused":"debt"}"#).unwrap();
    for attempt in 0..16 {
        let (attempted_id, result) = store.candidate_put_for_test(
            &baseline_row.package_id,
            &baseline_row.artifact_id,
            baseline_row.schema,
            &direct_payload,
        );
        let error = match result {
            Ok(_) => panic!("debt-refused typed put {attempt} unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            error.code, "plugin_state_unavailable",
            "typed producer {attempt} ({attempted_id}) must surface the debt refusal"
        );
    }

    let ids_snapshot = ids.lock().expect("put ids").clone();
    let readable_ids: Vec<String> = ids_snapshot
        .iter()
        .filter(|object_id| store.object_payload(object_id).is_ok())
        .cloned()
        .collect();
    eprintln!(
        "r2b guest debt observed: put_ids={} readable={} statuses={statuses:?} collect_calls={} debt={}",
        ids_snapshot.len(),
        readable_ids.len(),
        collect_calls.load(std::sync::atomic::Ordering::SeqCst),
        store.collection_debt_for_test()
    );

    // A further guest producer must be refused while collection debt exists.
    // The correct typed backpressure now refuses at the state reservation
    // boundary, before any managed operation/prepare cut is reached. Arming
    // the old prepare-time fixture cut here would leave a one-shot fault that
    // the refusal never consumes, poisoning the later recovery run; the real
    // assertion is the precise debt refusal below.
    let puts_before_next = ids.lock().expect("put ids").len();
    let next_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&next_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(next_provider.clone()));
    let (admit_status, body) = admit_run_with_identity(
        &http,
        &fixture.token,
        &session_id,
        "r2b debt next",
        None,
        "r2b-debt-next",
    )
    .await;
    let mut next_accepted = admit_status == 202;
    if admit_status == 202 {
        let next_run = body["run_id"].as_str().unwrap_or_default().to_string();
        let _ = wait_any_status(&fixture.state, &next_run).await;
        let events = fixture.state.service().run_events(&next_run);
        let failed = events
            .iter()
            .find(|event| event["event"] == "tool.failed")
            .unwrap_or_else(|| {
                panic!("the debt-refused guest run must fail the tool call: {events:?}")
            });
        assert_eq!(
            failed["data"]["error_code"], "plugin_state_unavailable",
            "debt backpressure must surface as the typed state refusal: {events:?}"
        );
        assert_eq!(
            ids.lock().expect("put ids").len(),
            puts_before_next,
            "a debt-refused guest put must not create a durable object"
        );
        next_accepted = false;
    }
    eprintln!(
        "r2b guest debt next: admit_status={admit_status} next_accepted={next_accepted} readable_bound={}",
        readable_ids.len()
    );

    // Recovery: the real collector succeeds again (debt clears), then a formal
    // guest effect/admission must commit and advance the root.
    let recovered_collect = store.collect_orphans_result_for_test().is_ok();
    let recovered_debt = store.collection_debt_for_test();
    let recovered_provider = rustscript_agent::ScriptedProvider::new();
    script_state_turns(&recovered_provider);
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(recovered_provider.clone()));
    let recovered_run =
        admit_state_run(&http, &fixture.token, &session_id, &recovered_provider).await;
    let recovered_status = wait_any_status(&fixture.state, &recovered_run).await;
    let session_key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("session root");
    let recovered_root = store
        .root(&session_key)
        .expect("root")
        .expect("root row")
        .object_id;
    eprintln!(
        "r2b guest debt recovery: collect_ok={recovered_collect} debt={recovered_debt} run={recovered_status} root_after={recovered_root}"
    );
    let recovered_root_observed = ids
        .lock()
        .expect("put ids")
        .iter()
        .any(|object_id| object_id == &recovered_root);
    let observed_snapshot = ids.lock().expect("put ids").clone();
    let observed_payload = observed_snapshot
        .first()
        .and_then(|object_id| store.object_payload(object_id).ok())
        .map(|payload| payload.as_str().to_string())
        .unwrap_or_default();
    let root_payload = store
        .object_payload(&recovered_root)
        .ok()
        .map(|payload| payload.as_str().to_string())
        .unwrap_or_default();
    let recovered_binding = store
        .binding(&recovered_run)
        .ok()
        .flatten()
        .map(|snapshot| {
            format!(
                "rev={} obj={} schema={}",
                snapshot.binding.revision, snapshot.binding.object_id, snapshot.binding.schema
            )
        })
        .unwrap_or_default();
    eprintln!(
        "r2b guest debt diag: observed_puts={} root_after={recovered_root} observed={observed_snapshot:?} observed_payload={observed_payload} root_payload={root_payload} binding={recovered_binding}",
        observed_snapshot.len(),
    );
    assert!(
        recovered_collect,
        "the same collector must recover after its real SQL fault clears"
    );
    assert!(
        !recovered_debt,
        "a successful sweep must clear collection debt"
    );
    assert_eq!(
        recovered_status, "completed",
        "formal guest effect/admission must succeed after collector recovery"
    );
    assert!(
        recovered_root_observed,
        "the recovered guest commit must advance the session root to a new object"
    );

    assert!(
        readable_ids.len() <= 64,
        "404-R2-B gc-health: formal guest plain puts left {} durable unreferenced objects while collector debt was set",
        readable_ids.len()
    );
    assert!(
        !next_accepted,
        "404-R2-B gc-health: a new plain guest put was accepted without a proven bounded sweep"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2b_new_persistence_health_does_not_default_to_swept() {
    let fixture = open_fixture("r2b-new-persistence");
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let payload = PluginStatePayload::parse(r#"{"orphan":"older"}"#).unwrap();
    for _ in 0..70 {
        store
            .put_object("org.rustscript.test.state", "artifact-state", 1, &payload)
            .expect("older unreferenced object write");
    }
    persistence.shutdown();
    drop(store);
    drop(persistence);

    let reopened = Arc::new(
        GatewayPersistence::open(fixture.state.service().config(), &fixture.db)
            .expect("reopen persistence worker"),
    );
    let store = PluginStateStore::open(Arc::clone(&reopened));
    let collect_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_slot = Arc::clone(&collect_calls);
    reopened.inject_plugin_state_collect_observer(Arc::new(move || {
        calls_slot.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    // A fresh worker starts at NeedsSweep instead of defaulting to swept: the
    // first related put must prove one bounded sweep. The armed failpoint
    // makes that sweep fail, so the put is refused with a precise degraded
    // error before any durable write.
    let put_ids = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let put_slot = Arc::clone(&put_ids);
    reopened.inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
        put_slot
            .lock()
            .expect("put ids")
            .push(object_id.to_string());
    }));
    reopened.inject_plugin_state_collect_failpoint();
    let executed_before = reopened.executed_storage_commands();
    let refused = store
        .put_object(
            "org.rustscript.test.state",
            "artifact-state",
            1,
            &PluginStatePayload::parse(r#"{"orphan":"new"}"#).unwrap(),
        )
        .expect_err("first put on a fresh worker must not bypass the proof sweep");
    assert_eq!(
        refused.code, "plugin_state_unavailable",
        "fresh-worker refusal must be the precise degraded error"
    );
    assert!(
        collect_calls.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "404-R2-B gc-health: a fresh worker treated the default false health as a completed bounded sweep and accepted a plain put without any collector attempt"
    );
    assert_eq!(
        reopened.executed_storage_commands(),
        executed_before + 1,
        "only the proof sweep may execute; the refused put writes nothing"
    );
    assert!(
        put_ids.lock().expect("put ids").is_empty(),
        "a backpressured put must never become durable"
    );
    // Recovery: the one-shot failpoint is consumed, so the same explicit
    // collector succeeds, clears the health, and the next put proceeds.
    assert!(store.collect_orphans_result_for_test().is_ok());
    store
        .put_object(
            "org.rustscript.test.state",
            "artifact-state",
            1,
            &PluginStatePayload::parse(r#"{"orphan":"new"}"#).unwrap(),
        )
        .expect("plain producer write resumes after collector recovery");
    assert_eq!(
        put_ids.lock().expect("put ids").len(),
        1,
        "exactly the recovered put became durable"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn r2c_injected_collect_payload_native_budget() {
    let fixture = open_fixture("r2c-native-budget");
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let payload = PluginStatePayload::parse(r#"{"leaf":"kept"}"#).unwrap();
    let kept = store
        .put_object("org.rustscript.test.state", "artifact-state", 1, &payload)
        .expect("kept object");
    let _kept_lease = store.hold_candidate_reservation_for_test(&kept.object_id);

    let before = persistence.executed_storage_commands();
    store
        .collect_orphans_result_for_test()
        .expect("in-budget collector");
    assert_eq!(
        persistence.executed_storage_commands(),
        before + 1,
        "an in-budget collector must execute the real SQL once"
    );
    assert!(store.object_payload(&kept.object_id).is_ok());

    // Fill only the real Native reservation registry. The ids are opaque
    // reservation strings (no authority grant) and the collector payload is
    // assembled by the same worker injection path.
    let mut reservation_ids = Vec::new();
    let mut leases = Vec::new();
    for _ in 0..25_800 {
        let id = uuid::Uuid::new_v4().to_string();
        reservation_ids.push(id.clone());
        leases.push(store.hold_candidate_reservation_for_test(&id));
    }
    reservation_ids.push(kept.object_id.clone());
    reservation_ids.sort();
    let protected_json = serde_json::to_string(&reservation_ids).expect("reservation json");
    let payload_wire = serde_json::to_string(&json!({
        "failpoint": "",
        "protected_ids_json": protected_json,
    }))
    .expect("worker payload json");
    eprintln!(
        "r2c native budget input: reservations={} protected_json_bytes={} worker_payload_bytes={} metadata_limit_bytes={}",
        reservation_ids.len(),
        protected_json.len(),
        payload_wire.len(),
        1024 * 1024
    );
    assert!(
        protected_json.len() < 1024 * 1024,
        "test input must stay below the RSS SQL parameter limit"
    );
    assert!(
        payload_wire.len() > 1024 * 1024,
        "test input must exceed the Native transport budget after injection"
    );
    let before = persistence.executed_storage_commands();
    let result = store.collect_orphans_result_for_test();
    let after = persistence.executed_storage_commands();
    eprintln!(
        "r2c native budget result: {:?} executed_before={before} executed_after={after}",
        result.as_ref().err().map(|error| error.code)
    );
    assert!(
        result.is_err(),
        "404-R2-NATIVE-BUDGET: oversized injected collector payload was accepted"
    );
    assert_eq!(
        after, before,
        "404-R2-NATIVE-BUDGET: SQL executed for a payload that exceeds the Native budget"
    );
    assert!(
        store.object_payload(&kept.object_id).is_ok(),
        "protected P must remain readable after the typed budget rejection"
    );
    drop(leases);
}

// ---------------------------------------------------------------------------
// 411 evidence-only: 410-F1/F2 runtime counterexamples and 410-E2 exact bounds.
// These tests add no production behavior; they exercise the existing producer,
// collector, and trusted-switch paths with the existing fixture seams.
// ---------------------------------------------------------------------------

/// 410-F1: a producer that passed the caller health check while Healthy is
/// enqueued behind a real failing collector. The worker must apply the current
/// health decision at its own put execution boundary; today it does not.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f411_queued_healthy_put_crosses_newer_collector_debt() {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    let fixture = open_fixture("f411-f1-queue");
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let ops = Arc::new(StdMutex::new(Vec::<String>::new()));
    let ops_slot = Arc::clone(&ops);
    persistence.inject_worker_execute_gate(Arc::new(move |op: &str| {
        ops_slot.lock().unwrap().push(op.to_string());
    }));

    // A fresh worker never defaults to swept: prove one real bounded sweep.
    store
        .collect_orphans_result_for_test()
        .expect("baseline sweep");
    assert!(
        !store.collection_debt_for_test(),
        "baseline sweep must be Healthy"
    );

    let p_entered = Arc::new(AtomicBool::new(false));
    let p_release = Arc::new(AtomicBool::new(false));
    let debt_at_pause = Arc::new(AtomicBool::new(true));
    let entered_slot = Arc::clone(&p_entered);
    let release_slot = Arc::clone(&p_release);
    let debt_slot = Arc::clone(&debt_at_pause);
    let armed = Arc::new(AtomicBool::new(false));
    let armed_slot = Arc::clone(&armed);
    let health_probe = store.clone();
    persistence.observe_plugin_state_candidate_reservations(Arc::new(move |_object_id: &str| {
        if !armed_slot.swap(true, Ordering::SeqCst) {
            // The producer already passed ensure_object_capacity() before it
            // registered this reservation; this pause is after that caller
            // check and before the put request is enqueued.
            debt_slot.store(health_probe.collection_debt_for_test(), Ordering::SeqCst);
            entered_slot.store(true, Ordering::SeqCst);
            while !release_slot.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }));
    let _release_guard = ReleaseFlag(Arc::clone(&p_release));

    let p_store = store.clone();
    let p_thread = std::thread::spawn(move || {
        let payload = PluginStatePayload::parse(r#"{"f411":"queued-put"}"#).unwrap();
        p_store.candidate_put_for_test("pkg.f411", "artifact.f411", 1, &payload)
    });
    wait_flag(&p_entered, "producer paused after the caller health check").await;
    assert!(
        !debt_at_pause.load(Ordering::SeqCst),
        "the caller must have observed Healthy before its request is queued"
    );

    // C is a real typed collector with the existing in-transaction SQL guard
    // fault. It is enqueued and executed while P has not issued its put.
    persistence.inject_plugin_state_collect_failpoint();
    let c_error = store
        .collect_orphans_result_for_test()
        .expect_err("the real SQL guard fault must surface from the collector");
    assert!(
        store.collection_debt_for_test(),
        "the worker must record the newer collector failure in execution order"
    );

    p_release.store(true, Ordering::SeqCst);
    drop(_release_guard);
    let (p_id, p_result) = p_thread.join().expect("producer thread");
    let sequence = ops.lock().unwrap().clone();
    let collect_positions: Vec<usize> = sequence
        .iter()
        .enumerate()
        .filter(|(_, op)| op.as_str() == "plugin.state_collect")
        .map(|(index, _)| index)
        .collect();
    let put_positions: Vec<usize> = sequence
        .iter()
        .enumerate()
        .filter(|(_, op)| op.as_str() == "plugin.state_object_put")
        .map(|(index, _)| index)
        .collect();
    let p_durable = store.object_payload(&p_id).is_ok();
    let p_code = p_result.as_ref().err().map(|error| error.code);
    eprintln!(
        "f411 F1 observed: sequence={sequence:?} collect_positions={collect_positions:?} put_positions={put_positions:?} c_code={} debt_after_c={} p_code={p_code:?} p_durable={p_durable}",
        c_error.code,
        store.collection_debt_for_test()
    );

    // Recovery and business success are recorded before the finding assertion
    // so a RED run still carries the full control evidence.
    let recovery = store.collect_orphans_result_for_test();
    let debt_after_recovery = store.collection_debt_for_test();
    let payload = PluginStatePayload::parse(r#"{"f411":"after-recovery"}"#).unwrap();
    let (next_id, next_result) =
        store.candidate_put_for_test("pkg.f411", "artifact.f411", 1, &payload);
    let next_durable = store.object_payload(&next_id).is_ok();
    eprintln!(
        "f411 F1 recovery: recovery_ok={} debt_after_recovery={debt_after_recovery} next_put_ok={} next_durable={next_durable}",
        recovery.is_ok(),
        next_result.is_ok()
    );

    assert!(
        put_positions.first().is_some_and(|put| {
            collect_positions
                .get(1)
                .is_some_and(|collect| put > collect)
        }),
        "the worker must execute C then P in FIFO order: {sequence:?}"
    );
    assert!(
        collect_positions
            .last()
            .is_some_and(|collect| { put_positions.first().is_some_and(|put| collect > put) }),
        "the refused put must run its own bounded quiet reclamation after the refusal: {sequence:?}"
    );
    assert!(
        recovery.is_ok() && !debt_after_recovery && next_result.is_ok() && next_durable,
        "an explicit successful sweep must recover and allow the next business put"
    );
    assert_eq!(
        p_code,
        Some("plugin_state_unavailable"),
        "410-F1: the queued producer must be refused with the exact typed code"
    );
    assert!(
        !p_durable,
        "410-F1 RED: a durable put executed although the worker had already recorded collector debt"
    );
}

/// 410-F1 quiet: the backpressure-path collector captures the old epoch, a
/// newer explicit sweep succeeds, then the quiet collector fails for real. The
/// worker records no failure (`report_health=false`) and the caller epoch check
/// ignores it, so a real failed sweep leaves health Healthy.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f411_quiet_collector_failure_after_newer_success_is_ignored() {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    let fixture = open_fixture("f411-f1-quiet");
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));

    let results = Arc::new(StdMutex::new(Vec::<bool>::new()));
    let results_slot = Arc::clone(&results);
    persistence.inject_plugin_state_collect_result_observer(Arc::new(move |ok: bool| {
        results_slot.lock().unwrap().push(ok);
    }));

    store
        .collect_orphans_result_for_test()
        .expect("baseline sweep");

    let quiet_entered = Arc::new(AtomicBool::new(false));
    let quiet_release = Arc::new(AtomicBool::new(false));
    let seen_quiet = Arc::new(AtomicBool::new(false));
    let entered_slot = Arc::clone(&quiet_entered);
    let release_slot = Arc::clone(&quiet_release);
    let seen_slot = Arc::clone(&seen_quiet);
    persistence.inject_plugin_state_collect_enqueue_observer(Arc::new(
        move |report_health: bool| {
            if !report_health && !seen_slot.swap(true, Ordering::SeqCst) {
                entered_slot.store(true, Ordering::SeqCst);
                while !release_slot.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        },
    ));
    let _release_guard = ReleaseFlag(Arc::clone(&quiet_release));

    // Production path: the durable put succeeds but its reply is lost, so the
    // typed producer abandons its owner and runs the quiet reclamation. The
    // in-transaction SQL fault is latched by that quiet caller when it enters
    // the collector, before its request is issued.
    persistence.inject_plugin_state_collect_failpoint();
    persistence.inject_plugin_state_put_ack_loss();
    let quiet_store = store.clone();
    let quiet_thread = std::thread::spawn(move || {
        let payload = PluginStatePayload::parse(r#"{"f411":"quiet"}"#).unwrap();
        quiet_store.candidate_put_for_test("pkg.f411", "artifact.f411", 1, &payload)
    });
    wait_flag(
        &quiet_entered,
        "quiet collector enqueued after the epoch snapshot",
    )
    .await;

    // A newer explicit sweep executes and succeeds while the quiet request has
    // not been issued yet.
    store
        .collect_orphans_result_for_test()
        .expect("newer explicit sweep");
    assert!(!store.collection_debt_for_test());

    // The pending quiet collector then executes the latched real SQL fault.
    quiet_release.store(true, Ordering::SeqCst);
    drop(_release_guard);
    let (_quiet_id, quiet_put) = quiet_thread.join().expect("quiet producer thread");
    let observed = results.lock().unwrap().clone();
    let debt = store.collection_debt_for_test();
    let payload = PluginStatePayload::parse(r#"{"f411":"after-quiet"}"#).unwrap();
    let (_probe_id, probe) = store.candidate_put_for_test("pkg.f411", "artifact.f411", 1, &payload);
    eprintln!(
        "f411 F1 quiet observed: collect_results={observed:?} put_lost_reply_err={} debt={debt} next_put_ok={} next_put_code={:?}",
        quiet_put.is_err(),
        probe.is_ok(),
        probe.as_ref().err().map(|error| error.code)
    );

    assert!(
        quiet_put.is_err(),
        "the lost put reply must surface as the original typed error"
    );
    assert_eq!(
        observed,
        vec![true, true, false],
        "the quiet collector must have failed for real after the newer success"
    );
    assert!(
        debt,
        "410-F1 quiet RED: a real quiet collector failure was not recorded as worker debt"
    );
    assert!(
        probe.is_err(),
        "a failed quiet sweep must still refuse the next producer until an explicit success"
    );
}

/// 410-F2 corrected: the trusted session schema switch writes a durable
/// object, then the original cancellation is observed before the root CAS.
/// The released owner records one bounded dirty generation, so every later
/// put first runs a bounded worker-ordered sweep. The recent-64 retention
/// contract still holds: a just-abandoned object may stay readable while it
/// is within the recent 64, the in-flight transient peaks at 65 (64 recent +
/// 1 newest), and the final explicit settle sweep reclaims down to 64.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f412_trusted_switch_abandon_is_bounded_by_dirty_sweep() {
    use std::sync::Mutex as StdMutex;

    let fixture = open_managed_run_state_fixture("f411-f2-switch");
    let http = Http::bind(fixture.state.clone()).await;
    let _graph1 = run_state_plugin(&http, &fixture.token).await;
    let session_id = create_session(&http, &fixture.token).await;
    let provider = rustscript_agent::ScriptedProvider::new();
    fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let baseline_run = admit_state_run(&http, &fixture.token, &session_id, &provider).await;
    assert_eq!(
        wait_run_any_terminal(&fixture.state, &baseline_run).await,
        "completed",
        "schema 1 baseline run"
    );
    // Only after the session holds a schema 1 root does the schema 2 graph
    // become active, exactly like the production switch path.
    let (graph2, _) =
        activate_state_package(&http, &fixture.token, "package-staterun2", "2.0.0").await;
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let key = store
        .session_root_key(&session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema 1 root");
    let root_before = store.root(&key).expect("root").expect("root row");
    assert_eq!(root_before.schema, 1);

    let ops = Arc::new(StdMutex::new(Vec::<String>::new()));
    let ops_slot = Arc::clone(&ops);
    persistence.inject_worker_execute_gate(Arc::new(move |op: &str| {
        ops_slot.lock().unwrap().push(op.to_string());
    }));
    let current = Arc::new(StdMutex::new(None::<rustscript_agent::RunCancellation>));
    let put_ids = Arc::new(StdMutex::new(Vec::<String>::new()));
    let current_slot = Arc::clone(&current);
    let ids_slot = Arc::clone(&put_ids);
    // Fires after the real durable put and before the switch's next
    // ensure_open(); requesting the cancellation there keeps the original
    // clock and proves the cancellation follows the successful put.
    persistence.inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
        ids_slot.lock().unwrap().push(object_id.to_string());
        if let Some(cancel) = current_slot.lock().unwrap().as_ref() {
            cancel.request(rustscript_agent::CancellationReason::Requested);
        }
    }));

    let service = fixture.state.service().clone();
    const ATTEMPTS: usize = 70;
    // Bounded dirty bookkeeping before the abandon burst: every attempt must
    // advance the dirty generation by exactly one last-owner release.
    let (dirty_before, swept_before, sealed_before) = store.candidate_dirty_generations_for_test();
    assert!(
        !sealed_before,
        "the dirty counter must not be sealed before the burst"
    );
    let ops_before = ops.lock().unwrap().len();
    let mut max_readable: usize = 0;
    for attempt in 0..ATTEMPTS {
        let cancel = rustscript_agent::RunCancellation::with_deadline(
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        );
        *current.lock().unwrap() = Some(cancel.clone());
        let error = service
            .switch_plugin_state_schema(&session_id, &graph2, &cancel)
            .expect_err("a cancelled switch after the durable put must not publish the root");
        assert_eq!(error, "cancelled", "attempt {attempt}");
        // The worker sidecar settles just after the attempt returns; poll
        // briefly rather than asserting on the racy instant.
        {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if store.candidate_registry_len_for_test() == 0 {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "attempt {attempt}: the abandoned owner must be released"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
        // Transient bound sampled every attempt: recent 64 plus the newest
        // in-flight orphan, never the unbounded 70 of the pre-fix run.
        let readable_now = put_ids
            .lock()
            .unwrap()
            .iter()
            .filter(|object_id| store.object_payload(object_id).is_ok())
            .count();
        max_readable = max_readable.max(readable_now);
        assert!(
            readable_now <= 65,
            "attempt {attempt}: {readable_now} readable orphans exceed the recent-64 plus in-flight transient bound"
        );
    }
    *current.lock().unwrap() = None;
    let ids = put_ids.lock().unwrap().clone();
    let sequence = ops.lock().unwrap().clone();
    let collects_during = sequence[ops_before..]
        .iter()
        .filter(|op| op.as_str() == "plugin.state_collect")
        .count();
    let readable = ids
        .iter()
        .filter(|object_id| store.object_payload(object_id).is_ok())
        .count();
    let root_after = store.root(&key).expect("root").expect("root row");
    let debt = store.collection_debt_for_test();
    // The worker-sidecar release races the attempt return by nanoseconds, so
    // the dirty count is polled to its exact expected value, not asserted
    // on a racy snapshot.
    let (dirty_after, swept_covered, sealed_after) = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let generations = store.candidate_dirty_generations_for_test();
            if generations.0 == dirty_before + ATTEMPTS as u64 {
                break generations;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "dirty generation did not advance by one per abandon: {generations:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    };
    eprintln!(
        "f412 F2 switch observed: attempts={ATTEMPTS} put_ids={} readable_orphans={readable} max_readable={max_readable} collects_during={collects_during} registry={} root_schema={} root_revision={} debt={debt} dirty={dirty_before}->{dirty_after} swept={swept_before}->{swept_covered} sealed={sealed_after}",
        ids.len(),
        store.candidate_registry_len_for_test(),
        root_after.schema,
        root_after.revision
    );
    assert_eq!(ids.len(), ATTEMPTS, "each switch attempt writes one object");
    assert_eq!(
        root_after.object_id, root_before.object_id,
        "the cancelled switch must not publish a new root"
    );
    assert_eq!(
        root_after.revision, root_before.revision,
        "the cancelled switch must not advance the root revision"
    );
    assert!(
        !debt,
        "successful puts must not mark collection debt (dirty is sweep-pending, not Debt)"
    );
    assert!(
        !sealed_after,
        "the bounded dirty counter must not seal during the burst"
    );
    assert_eq!(
        dirty_after,
        dirty_before + ATTEMPTS as u64,
        "every abandoned attempt records exactly one dirty generation"
    );
    assert!(
        collects_during >= ATTEMPTS - 1,
        "every put after the first must first run a bounded dirty sweep, saw {collects_during}"
    );
    assert!(
        max_readable <= 65,
        "the cross-request transient must stay within recent-64 plus one in-flight orphan, saw {max_readable}"
    );

    // One final bounded explicit settle sweep reclaims to the recent-64
    // contract and proves the dirty generations were really processed.
    store
        .collect_orphans_result_for_test()
        .expect("bounded sweep");
    let (dirty_settled, swept_settled, sealed_settled) =
        store.candidate_dirty_generations_for_test();
    let readable_after = ids
        .iter()
        .filter(|object_id| store.object_payload(object_id).is_ok())
        .count();
    eprintln!(
        "f412 F2 switch after sweep: readable={readable_after} dirty={dirty_settled} swept={swept_settled} sealed={sealed_settled}"
    );
    assert!(
        !store.collection_debt_for_test(),
        "the settle sweep must succeed without Debt"
    );
    assert_eq!(
        swept_settled, dirty_settled,
        "the settle sweep must cover every abandoned generation"
    );
    assert!(
        !sealed_settled,
        "the settle sweep must not seal the dirty counter"
    );
    assert_eq!(
        readable_after, 64,
        "the bounded collector retains exactly the recent 64 true orphans"
    );

    // Business recovery: an ordinary uncancelled switch on the same root
    // publishes the new schema and advances the revision.
    let ok_cancel = rustscript_agent::RunCancellation::with_deadline(
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    );
    let switched = service
        .switch_plugin_state_schema(&session_id, &graph2, &ok_cancel)
        .expect("an uncancelled switch must publish");
    let root_final = store.root(&key).expect("root").expect("root row");
    eprintln!(
        "f412 F2 switch recovery: switched={switched:?} schema={} revision={}",
        root_final.schema, root_final.revision
    );
    assert_eq!(root_final.schema, 2, "recovery must publish schema 2");
    assert!(
        root_final.revision > root_after.revision,
        "recovery must advance the root revision"
    );
    assert!(
        !store.collection_debt_for_test(),
        "business recovery must leave no collection debt"
    );
}

/// 410-E2: exact typed budget code plus the real registry count/byte bounds and
/// the full-wire-under/aggregate-over collector boundary. Production caps are
/// the real ones; nothing is enlarged or bypassed.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f411_native_budget_exact_codes_and_registry_bounds() {
    use std::sync::Mutex as StdMutex;

    let fixture = open_fixture("f411-e2-budget");
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));
    let payload = PluginStatePayload::parse(r#"{"leaf":"kept"}"#).unwrap();
    let kept = store
        .put_object("org.rustscript.test.state", "artifact-state", 1, &payload)
        .expect("kept object");
    let _kept_lease = store.hold_candidate_reservation_for_test(&kept.object_id);
    let executed_before_puts = persistence.executed_storage_commands();

    // (a) Real registry count bound: 65,536 unique Native identities (the kept
    // object already owns one entry).
    let mut leases = Vec::new();
    for index in 0..65_535u32 {
        let id = format!("f411-{index:08}-{}", "c".repeat(16));
        leases.push(store.hold_candidate_reservation_for_test(&id));
    }
    let count_fill = store.candidate_registry_len_for_test();
    let executed_before = persistence.executed_storage_commands();
    let (count_id, count_result) =
        store.candidate_put_for_test("pkg.f411", "artifact.f411", 1, &payload);
    let count_executed = persistence.executed_storage_commands();
    let count_code = count_result.as_ref().err().map(|error| error.code);
    eprintln!(
        "f411 E2 count bound: registry={count_fill} code={count_code:?} sql_executed={} object_present={} kept_readable={}",
        count_executed - executed_before,
        store.object_payload(&count_id).is_ok(),
        store.object_payload(&kept.object_id).is_ok()
    );
    assert_eq!(count_fill, 65_536, "the real Native count bound is reached");
    assert_eq!(
        count_code,
        Some("plugin_state_budget_exceeded"),
        "over-count reservations must return the exact typed code"
    );
    assert_eq!(
        count_executed, executed_before,
        "no SQL may execute for an over-count reservation"
    );
    assert!(store.object_payload(&count_id).is_err());
    assert!(store.object_payload(&kept.object_id).is_ok());
    drop(leases);
    // Settle the mass abandonment while the registry is small again: one
    // bounded explicit sweep must cover every released generation without
    // Debt, so the byte-bound section below starts from a clean lifecycle
    // instead of sweeping 65k drops under a full registry.
    store
        .collect_orphans_result_for_test()
        .expect("settle sweep after the count-bound abandonment");
    let (dirty_settled_a, swept_settled_a, sealed_settled_a) =
        store.candidate_dirty_generations_for_test();
    eprintln!(
        "f411 E2 count settle: dirty={dirty_settled_a} swept={swept_settled_a} sealed={sealed_settled_a}"
    );
    assert!(
        !sealed_settled_a,
        "the settle sweep must not seal the dirty counter"
    );
    assert_eq!(
        swept_settled_a, dirty_settled_a,
        "the settle sweep must cover every count-bound abandonment"
    );
    assert!(
        !store.collection_debt_for_test(),
        "settling a clean mass abandonment must not leave Debt"
    );

    // (b) Real registry byte bound: 8 MiB of identity bytes. 41,942 x 200
    // bytes plus the kept 36-byte id still leaves room for one 36-byte uuid;
    // exactly filling the remaining 172 bytes then refuses the next uuid.
    let mut leases = Vec::new();
    let long = "b".repeat(200 - "f411-00000000-".len());
    for index in 0..41_942u32 {
        let id = format!("f411-{index:08}-{long}");
        assert_eq!(id.len(), 200);
        leases.push(store.hold_candidate_reservation_for_test(&id));
    }
    let (inside_id, inside_result) =
        store.candidate_put_for_test("pkg.f411", "artifact.f411", 1, &payload);
    assert!(
        inside_result.is_ok(),
        "a put that still fits the real byte bound must be accepted: {:?}",
        inside_result.as_ref().err().map(|error| error.code)
    );
    let edge_id = format!("f411-edge-{}", "e".repeat(172 - "f411-edge-".len()));
    assert_eq!(edge_id.len(), 172);
    leases.push(store.hold_candidate_reservation_for_test(&edge_id));
    let executed_before = persistence.executed_storage_commands();
    let (over_id, over_result) =
        store.candidate_put_for_test("pkg.f411", "artifact.f411", 1, &payload);
    let over_executed = persistence.executed_storage_commands();
    let over_code = over_result.as_ref().err().map(|error| error.code);
    eprintln!(
        "f411 E2 byte bound: accepted_inside={} code={over_code:?} sql_executed={} object_present={}",
        inside_result.is_ok() && store.object_payload(&inside_id).is_ok(),
        over_executed - executed_before,
        store.object_payload(&over_id).is_ok()
    );
    assert_eq!(
        over_code,
        Some("plugin_state_budget_exceeded"),
        "over-byte reservations must return the exact typed code"
    );
    assert_eq!(
        over_executed, executed_before,
        "no SQL may execute for an over-byte reservation"
    );
    drop(leases);

    // (c) Collector injection boundary: full wire stays under the Native cap
    // while the aggregate (2x repeat + 64-byte element charge + wire) exceeds
    // it. The worker must fail closed with the exact code and run no SQL.
    let mut leases = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..6_000 {
        let id = uuid::Uuid::new_v4().to_string();
        ids.push(id.clone());
        leases.push(store.hold_candidate_reservation_for_test(&id));
    }
    ids.push(kept.object_id.clone());
    ids.sort();
    let observed = Arc::new(StdMutex::new(None::<(usize, usize, usize)>));
    let observed_slot = Arc::clone(&observed);
    persistence.observe_plugin_state_collect_budget(Arc::new(
        move |count: usize, wire: usize, aggregate: usize| {
            *observed_slot.lock().unwrap() = Some((count, wire, aggregate));
        },
    ));
    let executed_before = persistence.executed_storage_commands();
    let result = store.collect_orphans_result_for_test();
    let executed_after = persistence.executed_storage_commands();
    let inputs = *observed.lock().unwrap();
    eprintln!(
        "f411 E2 aggregate boundary: inputs={inputs:?} code={:?} sql_executed={} kept_readable={}",
        result.as_ref().err().map(|error| error.code),
        executed_after - executed_before,
        store.object_payload(&kept.object_id).is_ok()
    );
    let (count, wire, aggregate) = inputs.expect("worker budget inputs are observed");
    assert_eq!(
        count, 6_001,
        "the protected set is read at the worker boundary"
    );
    assert!(
        wire < 1024 * 1024,
        "the full wire payload stays under the Native cap: {wire}"
    );
    assert!(
        aggregate > 1024 * 1024,
        "the aggregate repeat weight exceeds the Native cap: {aggregate}"
    );
    // The worker's fail-closed branch answers `plugin_state_budget_exceeded`,
    // but the typed collector surface flattens every non-allowlisted storage
    // code to `plugin_state_unavailable` (`PluginStateError::storage`). Record
    // the observable caller code; the exact registry code is asserted above.
    assert_eq!(
        result.as_ref().err().map(|error| error.code),
        Some("plugin_state_unavailable"),
        "the aggregate-over collector must fail closed with the typed collector code"
    );
    assert_eq!(
        executed_after, executed_before,
        "no SQL may execute for an over-aggregate collector payload"
    );
    assert!(
        store.object_payload(&kept.object_id).is_ok(),
        "the protected P must remain readable after the typed budget rejection"
    );
    drop(leases);
    let _ = executed_before_puts;
}

/// 410-F2 guest corrected: a guest state write becomes durable, the managed
/// prepare then fails. The released owner records one bounded dirty
/// generation, so the next ordinary request first runs a bounded
/// worker-ordered sweep and processes that generation. The staged object may
/// legitimately stay readable while it sits inside the recent-64 retention
/// window; only after 65 newer orphans age it out does the bounded collector
/// reclaim it. Business recovery (root advance on the next request) is
/// asserted directly.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f412_guest_abandon_is_reclaimed_by_dirty_sweep_across_requests() {
    use rustscript_agent::effects::ManagedEffectFault;
    use std::sync::Mutex as StdMutex;

    let env = r2a_setup("f411-f2-guest-prepare").await;
    let ops = Arc::new(StdMutex::new(Vec::<String>::new()));
    let ops_slot = Arc::clone(&ops);
    env.persistence
        .inject_worker_execute_gate(Arc::new(move |op: &str| {
            ops_slot.lock().unwrap().push(op.to_string());
        }));
    let put_ids = Arc::new(StdMutex::new(Vec::<String>::new()));
    let ids_slot = Arc::clone(&put_ids);
    env.persistence
        .inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
            ids_slot.lock().unwrap().push(object_id.to_string());
        }));
    let key = env
        .store
        .session_root_key(&env.session_id, "org.rustscript.test.staterun")
        .expect("session key")
        .expect("schema 2 root");
    let root_before = env.store.root(&key).expect("root").expect("root row");

    env.fixture
        .state
        .service()
        .inject_managed_effect_fault(ManagedEffectFault::AfterOperationBeforePrepare)
        .expect("arm the one-shot prepare fault");
    // Dirty baseline before the failed run: exactly one last-owner release
    // (the abandoned staged object) must land during it.
    let dirty_before_failure = env.store.candidate_dirty_generations_for_test().0;
    let failed_provider = rustscript_agent::ScriptedProvider::new();
    env.fixture
        .state
        .service()
        .inject_provider_host(Arc::new(failed_provider.clone()));
    let failed_run = admit_state_run(
        &env.http,
        &env.fixture.token,
        &env.session_id,
        &failed_provider,
    )
    .await;
    let failed_status = wait_run_any_terminal(&env.fixture.state, &failed_run).await;
    let staged_id = put_ids
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the guest write reached a durable put before the prepare failure");
    let staged_readable_after_failure = env.store.object_payload(&staged_id).is_ok();
    let root_after_failure = env.store.root(&key).expect("root").expect("root row");
    assert_eq!(
        root_after_failure.object_id, root_before.object_id,
        "the failed prepare must not publish the staged object"
    );
    // The worker sidecar settles just after the run returns; poll briefly
    // rather than asserting on the racy instant.
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if env.store.candidate_registry_len_for_test() == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the abandoned staged owner must be released"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
    let registry_after_failure = env.store.candidate_registry_len_for_test();
    // The released staged owner must record exactly one dirty generation
    // (polled: the worker sidecar settles just after the run returns).
    // Dirty is sweep-pending reclamation, never failure Debt.
    let (dirty_at_abandon, swept_at_abandon, sealed_at_abandon) = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let generations = env.store.candidate_dirty_generations_for_test();
            if generations.0 > dirty_before_failure {
                break generations;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the abandoned staged owner must record one dirty generation: {generations:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    };
    assert_eq!(
        dirty_at_abandon,
        dirty_before_failure + 1,
        "exactly the abandoned staged object records a dirty generation during the failed run"
    );
    assert!(
        !sealed_at_abandon,
        "the abandoned staged owner must not seal the dirty counter"
    );
    assert!(
        !env.store.collection_debt_for_test(),
        "an abandoned guest write is dirty, not Debt"
    );

    // The next ordinary request must run a real bounded collector for the
    // abandoned generation before its own business put, and must recover
    // the business root on the same bindings.
    let ops_before_recovery = ops.lock().unwrap().len();
    let ok_provider = rustscript_agent::ScriptedProvider::new();
    env.fixture
        .state
        .service()
        .inject_provider_host(Arc::new(ok_provider.clone()));
    let ok_run =
        admit_state_run(&env.http, &env.fixture.token, &env.session_id, &ok_provider).await;
    let ok_status = wait_run_any_terminal(&env.fixture.state, &ok_run).await;
    let sequence = ops.lock().unwrap().clone();
    let collects = sequence[ops_before_recovery..]
        .iter()
        .filter(|op| op.as_str() == "plugin.state_collect")
        .count();
    let (dirty_after_next, swept_after_next, _) = env.store.candidate_dirty_generations_for_test();
    let staged_readable_after_next = env.store.object_payload(&staged_id).is_ok();
    let root_after_next = env.store.root(&key).expect("root").expect("root row");
    eprintln!(
        "f412 F2 guest observed: failed_status={failed_status} staged_durable={staged_readable_after_failure} root_unchanged={} registry={registry_after_failure} dirty={dirty_at_abandon} swept={swept_at_abandon} next_status={ok_status} collects_during_next={collects} staged_after_next={staged_readable_after_next} swept_after_next={swept_after_next} root_advanced={}",
        root_after_failure.object_id == root_before.object_id,
        root_after_next.object_id != root_before.object_id
    );
    assert!(
        staged_readable_after_failure,
        "the guest write must be durable before the prepare failure"
    );
    assert_eq!(ok_status, "completed");
    // The next successful request must run a real bounded collector for the
    // abandoned generation: the pre-fix run had zero collects here.
    assert!(
        collects >= 1,
        "the next request must run a bounded dirty sweep for the abandoned generation, saw {collects}"
    );
    assert!(
        swept_after_next >= dirty_at_abandon,
        "the next request's sweep must cover the abandoned generation: swept={swept_after_next} dirty_at_abandon={dirty_at_abandon}"
    );
    assert!(
        dirty_after_next >= dirty_at_abandon,
        "dirty generations only move forward across the next request: after={dirty_after_next} abandon={dirty_at_abandon}"
    );
    assert!(
        root_after_next.object_id != root_before.object_id,
        "the next request must publish its own business object (business recovery)"
    );
    assert!(
        !env.store.collection_debt_for_test(),
        "dirty reclamation across requests must not leave collection debt"
    );
    // The staged object may still be readable inside its recent-64 window;
    // that is the retention contract, not a leak. Record, do not forbid.
    eprintln!(
        "f412 F2 guest retention note: staged_after_next={staged_readable_after_next} (allowed while inside recent 64)"
    );

    // 65 newer typed objects age the abandoned object out of the recent-64 set;
    // only then does the bounded collector reclaim it, proving it was a true
    // unreferenced orphan all along. Each of these puts first runs its own
    // bounded dirty sweep, so the cross-request count stays capped throughout.
    let q_key = env
        .store
        .session_root_key(&env.q_session, "org.rustscript.test.staterun")
        .expect("q session key")
        .expect("q root");
    let q_root = env.store.root(&q_key).expect("q root").expect("q root row");
    let mut newer_ids = Vec::new();
    for attempt in 0..65 {
        newer_ids.push(
            env.store
                .put_object(
                    &q_root.package_id,
                    &q_root.artifact_id,
                    q_root.schema,
                    &PluginStatePayload::parse(&format!(r#"{{"f411_orphan":{attempt}}}"#)).unwrap(),
                )
                .expect("newer typed orphan object")
                .object_id,
        );
    }
    env.store
        .collect_orphans_result_for_test()
        .expect("bounded sweep after 65 newer orphans");
    let staged_readable_after_sweep = env.store.object_payload(&staged_id).is_ok();
    let newer_readable = newer_ids
        .iter()
        .filter(|object_id| env.store.object_payload(object_id).is_ok())
        .count();
    eprintln!(
        "f412 F2 guest after sweep: staged_readable={staged_readable_after_sweep} newer_readable={newer_readable}"
    );
    assert!(
        !staged_readable_after_sweep,
        "the abandoned guest object must be a true orphan reclaimed by the bounded sweep once aged out of recent 64"
    );
    assert_eq!(
        newer_readable, 64,
        "the bounded collector retains exactly the recent 64 newer orphans"
    );
    assert!(
        !env.store.collection_debt_for_test(),
        "the aging sweep must succeed without Debt"
    );
}

/// 410-F2 dirty concurrency: a last-owner release that lands mid-sweep must
/// not be cleared by that sweep's later success, and a late worker success
/// must not shadow newer dirt. The worker parks at its own collect snapshot
/// (already taken, covering generation S); the test releases the last owner
/// (dirty S+1) and only then lets the sweep run. The success covers exactly
/// S, so dirty stays pending and the next put runs its own bounded sweep.
/// The worker-side sidecar release never self-waits: a put whose reply is
/// lost still settles, the registry returns to zero, and ordinary business
/// puts keep succeeding without Debt.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f412_dirty_generation_survives_racing_release_and_late_success() {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    let fixture = open_fixture("f412-dirty-race");
    let persistence = fixture.state.persistence().expect("native persistence");
    let store = PluginStateStore::open(Arc::clone(&persistence));

    store
        .collect_orphans_result_for_test()
        .expect("baseline sweep");
    let (dirty_base, swept_base, sealed_base) = store.candidate_dirty_generations_for_test();
    assert!(!sealed_base, "baseline must not seal the dirty counter");
    assert_eq!(
        dirty_base, swept_base,
        "baseline sweep must cover all prior dirt"
    );
    assert!(
        !store.collection_debt_for_test(),
        "baseline must be Healthy"
    );

    // Hold one real reservation, then run an explicit sweep parked at its
    // own worker snapshot; the release lands strictly after the snapshot.
    let lease = store.hold_candidate_reservation_for_test("f412-dirty-race-owner");
    let (dirty_held, _, _) = store.candidate_dirty_generations_for_test();
    assert_eq!(
        dirty_held, dirty_base,
        "holding a reservation is not an abandonment"
    );
    let snapshot_entered = Arc::new(AtomicBool::new(false));
    let snapshot_release = Arc::new(AtomicBool::new(false));
    let snapshot_seen = Arc::new(AtomicBool::new(false));
    let snapshot_gen = Arc::new(StdMutex::new(None::<u64>));
    let entered_slot = Arc::clone(&snapshot_entered);
    let release_slot = Arc::clone(&snapshot_release);
    let seen_slot = Arc::clone(&snapshot_seen);
    let gen_slot = Arc::clone(&snapshot_gen);
    persistence.inject_plugin_state_collect_snapshot_observer(Arc::new(move |generation: u64| {
        if !seen_slot.swap(true, Ordering::SeqCst) {
            *gen_slot.lock().unwrap() = Some(generation);
            entered_slot.store(true, Ordering::SeqCst);
            while !release_slot.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }));
    let sweep_store = store.clone();
    let sweep_thread = std::thread::spawn(move || sweep_store.collect_orphans_result_for_test());
    wait_flag(&snapshot_entered, "worker parked at its collect snapshot").await;

    // The sweep already snapshotted generation S; this last-owner release
    // moves dirt to S+1 while the sweep is still in flight.
    drop(lease);
    let (dirty_racing, swept_racing, _) = store.candidate_dirty_generations_for_test();
    assert_eq!(
        dirty_racing,
        dirty_base + 1,
        "the mid-sweep release must record one dirty generation"
    );
    assert_eq!(
        swept_racing, swept_base,
        "no sweep has covered the mid-sweep release yet"
    );
    snapshot_release.store(true, Ordering::SeqCst);
    let sweep_result = sweep_thread.join().expect("parked sweep thread");
    let covered = snapshot_gen
        .lock()
        .unwrap()
        .expect("snapshot generation observed");
    let (dirty_covered, swept_covered, sealed_covered) =
        store.candidate_dirty_generations_for_test();
    eprintln!(
        "f412 dirty race observed: sweep_ok={} snapshot_gen={covered} dirty={dirty_covered} swept={swept_covered} sealed={sealed_covered}",
        sweep_result.is_ok()
    );
    persistence.clear_plugin_state_collect_snapshot_observer();
    assert!(sweep_result.is_ok(), "the parked sweep must still succeed");
    assert_eq!(
        covered, swept_base,
        "the sweep snapshot predates the mid-sweep release"
    );
    assert_eq!(
        swept_covered, swept_base,
        "the late success clears exactly the generation it covered, not the newer dirt"
    );
    assert_eq!(
        dirty_covered,
        dirty_base + 1,
        "the mid-sweep release stays pending after the older success"
    );
    assert!(
        !sealed_covered,
        "a racing release must not seal the dirty counter"
    );
    assert!(
        !store.collection_debt_for_test(),
        "a covered-older success is not a failure: no Debt"
    );

    // The next business put first runs its own bounded sweep for the pending
    // dirt, then succeeds durably; ordinary success is not degraded by
    // routine Drops.
    let put_ops = Arc::new(StdMutex::new(0usize));
    let put_ops_slot = Arc::clone(&put_ops);
    persistence.inject_worker_execute_gate(Arc::new(move |op: &str| {
        if op == "plugin.state_collect" {
            *put_ops_slot.lock().unwrap() += 1;
        }
    }));
    let payload = PluginStatePayload::parse(r#"{"f412":"after-race"}"#).unwrap();
    let (next_id, next_result) =
        store.candidate_put_for_test("pkg.f412", "artifact.f412", 1, &payload);
    let next_collects = *put_ops.lock().unwrap();
    persistence.clear_worker_execute_gate();
    assert!(
        next_result.is_ok(),
        "a business put after a racing release must succeed once its own sweep covers the dirt"
    );
    assert!(
        store.object_payload(&next_id).is_ok(),
        "the post-race business object must be durable"
    );
    assert!(
        next_collects >= 1,
        "the post-race put must first run a bounded sweep for the pending dirt, saw {next_collects}"
    );
    // The post-race sweep covered the racing release; only the post-race
    // put's own release may still be pending, and no Debt exists.
    let (dirty_settled, swept_settled, sealed_settled) =
        store.candidate_dirty_generations_for_test();
    eprintln!(
        "f412 dirty race settled: dirty={dirty_settled} swept={swept_settled} sealed={sealed_settled} collects_for_put={next_collects}"
    );
    assert!(
        swept_settled >= dirty_racing,
        "the post-race sweep must cover the racing release: swept={swept_settled} racing={dirty_racing}"
    );
    assert!(
        !sealed_settled,
        "routine releases must not seal the counter"
    );
    assert!(
        !store.collection_debt_for_test(),
        "ordinary business success must not leave collection debt"
    );

    // Worker Drop releases its own sidecar without self-wait: a put whose
    // reply is lost still settles (registry back to zero, dirty recorded),
    // and the next put recovers through the same bounded path.
    persistence.inject_plugin_state_put_ack_loss();
    let payload = PluginStatePayload::parse(r#"{"f412":"lost-reply"}"#).unwrap();
    let (_lost_id, lost_result) =
        store.candidate_put_for_test("pkg.f412", "artifact.f412", 1, &payload);
    assert!(
        lost_result.is_err(),
        "the lost put reply must surface as the original typed error"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if store.candidate_registry_len_for_test() == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the worker sidecar must settle without self-wait after a lost reply"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let payload = PluginStatePayload::parse(r#"{"f412":"after-loss"}"#).unwrap();
    let (recovered_id, recovered_result) =
        store.candidate_put_for_test("pkg.f412", "artifact.f412", 1, &payload);
    assert!(
        recovered_result.is_ok() && store.object_payload(&recovered_id).is_ok(),
        "business puts must keep succeeding after a lost reply settles"
    );
    assert!(
        !store.collection_debt_for_test(),
        "a lost reply is not a collector failure: no Debt"
    );
}

/// 410-E1 boundary: the durable prepared receipt alone protects the object when
/// no Native registry owner remains. The existing formal prepare gate is placed
/// after the durable `effect.prepare` but still holds the caller lease, so the
/// owner-zero state is produced here by the existing `AfterPrepared` fixture
/// cut (after the durable receipt, before any commit owner).
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f411_durable_only_prepared_reference_protects_object() {
    use rustscript_agent::effects::ManagedEffectFault;
    use std::sync::Mutex as StdMutex;

    let env = r2a_setup("f411-e1-durable-only").await;
    let put_ids = Arc::new(StdMutex::new(Vec::<String>::new()));
    let ids_slot = Arc::clone(&put_ids);
    env.persistence
        .inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
            ids_slot.lock().unwrap().push(object_id.to_string());
        }));
    env.fixture
        .state
        .service()
        .inject_managed_effect_fault(ManagedEffectFault::AfterPrepared)
        .expect("arm the one-shot post-prepare cut");
    let provider = rustscript_agent::ScriptedProvider::new();
    env.fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let run = admit_state_run(&env.http, &env.fixture.token, &env.session_id, &provider).await;
    let status = wait_run_any_terminal(&env.fixture.state, &run).await;
    let staged_id = put_ids
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("staged put before the durable prepared receipt");
    let registry_after_cut = env.store.candidate_registry_len_for_test();
    let staged_readable = env.store.object_payload(&staged_id).is_ok();

    let key = env
        .store
        .session_root_key(&env.q_session, "org.rustscript.test.staterun")
        .expect("q session key")
        .expect("q root");
    let q_root = env.store.root(&key).expect("q root").expect("q root row");
    let mut orphan_ids = Vec::new();
    for attempt in 0..65 {
        orphan_ids.push(
            env.store
                .put_object(
                    &q_root.package_id,
                    &q_root.artifact_id,
                    q_root.schema,
                    &PluginStatePayload::parse(&format!(r#"{{"f411_e1_orphan":{attempt}}}"#))
                        .unwrap(),
                )
                .expect("newer typed orphan object")
                .object_id,
        );
    }
    env.store
        .collect_orphans_result_for_test()
        .expect("bounded sweep with a durable-only prepared reference");
    let readable_orphans = orphan_ids
        .iter()
        .filter(|object_id| env.store.object_payload(object_id).is_ok())
        .count();
    let staged_readable_after = env.store.object_payload(&staged_id).is_ok();
    eprintln!(
        "f411 E1 observed: run_status={status} registry_after_durable_prepare={registry_after_cut} staged_readable_before={staged_readable} staged_readable_after={staged_readable_after} readable_orphans={readable_orphans}"
    );
    assert_eq!(
        registry_after_cut, 0,
        "the durable prepared receipt must not need a Native registry owner"
    );
    assert!(
        staged_readable,
        "the durable put must exist before the collector runs"
    );
    assert!(
        staged_readable_after,
        "410-E1: the durable-only prepared reference failed to protect the object"
    );
    assert_eq!(
        readable_orphans, 64,
        "stateless NULL prepared receipts must not stall the bounded collection"
    );
}

/// 410-E1 boundary measurement: the existing formal prepare gate sits after the
/// durable `effect.prepare` but inside `prepare_result`, so the caller lease is
/// still held while the gate blocks. This records that exact boundary instead
/// of repeating the prepared survival test through the same gate.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn f411_prepare_gate_retains_the_caller_lease_boundary() {
    use std::sync::Mutex as StdMutex;

    let env = r2a_setup("f411-e1-gate-boundary").await;
    let put_ids = Arc::new(StdMutex::new(Vec::<String>::new()));
    let ids_slot = Arc::clone(&put_ids);
    env.persistence
        .inject_plugin_state_object_put_observer(Arc::new(move |object_id: &str| {
            ids_slot.lock().unwrap().push(object_id.to_string());
        }));
    let gate = env
        .fixture
        .state
        .service()
        .arm_managed_prepare_gate()
        .expect("arm the formal prepare gate");
    let provider = rustscript_agent::ScriptedProvider::new();
    env.fixture
        .state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let run = admit_state_run(&env.http, &env.fixture.token, &env.session_id, &provider).await;
    gate.wait_arrived(1)
        .expect("the real effect.prepare reaches the formal gate");
    let registry_at_gate = env.store.candidate_registry_len_for_test();
    let staged_id = put_ids
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("staged put before the formal gate");
    eprintln!(
        "f411 E1 gate boundary observed: registry_at_durable_prepare_gate={registry_at_gate} staged_readable={}",
        env.store.object_payload(&staged_id).is_ok()
    );
    gate.release();
    let status = wait_run_any_terminal(&env.fixture.state, &run).await;
    eprintln!("f411 E1 gate boundary after release: status={status}");
    assert_eq!(
        registry_at_gate, 1,
        "the formal prepare gate retains exactly the caller lease after the durable prepare"
    );
}
