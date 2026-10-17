//! Exact plugin-control persistence through the production RSS SQLite path.
//!
//! These tests do not call the resolver, do not install a newer package, and
//! do not treat a persisted graph id as host-catalog authority.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::plugins::{
    ActivationPointer, COMPILE_ENVIRONMENT, EffectOrigin, GraphLock, GraphRetention, HOST_RUNTIME,
    LockedEdge, LockedEffect, LockedEffectItem, LockedPackage, PackageArtifactRef,
    PluginControlStore, ScopeBinding, ValidatedLockMetadata,
};
use rustscript_agent::{AgentGatewayConfig, GatewayPersistence};
use serde_json::json;

fn db_path(label: &str) -> PathBuf {
    let base = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
            .expect("RUSTSCRIPT_AGENT_TEST_TMPDIR must point into assigned TEMP"),
    );
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_nanos();
    let dir = base.join(format!(
        "plugin-control-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("assigned temp accepts the db directory");
    dir.join("gateway.db")
}

fn open(path: &Path) -> GatewayPersistence {
    GatewayPersistence::open(&AgentGatewayConfig::default(), path).expect("repository opens")
}

fn origin(relation: &str, alias: &str, requirement: &str) -> EffectOrigin {
    EffectOrigin {
        relation: relation.into(),
        caller_package: "org.example.tools".into(),
        caller_entry: "invoke".into(),
        alias: alias.into(),
        callee_package: if relation == "direct" {
            "org.example.tools".into()
        } else {
            "org.example.lib".into()
        },
        callee_version: if relation == "direct" {
            "1.2.3".into()
        } else {
            "0.4.1".into()
        },
        callee_entry: "invoke".into(),
        version_requirement: requirement.into(),
    }
}

fn sample_lock(graph_id: &str, tool_artifact: &str) -> GraphLock {
    GraphLock {
        graph_id: graph_id.into(),
        host_runtime: HOST_RUNTIME.into(),
        compile_environment: COMPILE_ENVIRONMENT.into(),
        packages: vec![
            LockedPackage {
                id: "org.example.tools".into(),
                version: "1.2.3".into(),
                kind: "tool".into(),
                artifact_id: tool_artifact.into(),
            },
            LockedPackage {
                id: "org.example.lib".into(),
                version: "0.4.1".into(),
                kind: "library".into(),
                artifact_id: "artifact-lib-exact".into(),
            },
        ],
        edges: vec![LockedEdge {
            from: "org.example.tools".into(),
            from_entry: "invoke".into(),
            alias: "files".into(),
            to: "org.example.lib".into(),
            to_version: "0.4.1".into(),
            to_artifact_id: "artifact-lib-exact".into(),
            to_entry: "invoke".into(),
            relation: "library".into(),
            version_requirement: "^0.4.1".into(),
            bindings: vec![ScopeBinding {
                kind: "workspace.fs.read".into(),
                scope: "bound_workspace".into(),
                recovery: "none".into(),
            }],
        }],
        closure: vec![LockedEffect {
            package: "org.example.tools".into(),
            entry: "invoke".into(),
            effects: vec![
                LockedEffectItem {
                    kind: "workspace.fs.read".into(),
                    scope: "bound_workspace".into(),
                    recovery: "none".into(),
                    via: origin("direct", "", ""),
                },
                LockedEffectItem {
                    kind: "workspace.fs.read".into(),
                    scope: "bound_workspace".into(),
                    recovery: "none".into(),
                    via: origin("library", "files", "^0.4.1"),
                },
            ],
        }],
    }
}

fn refs_of(lock: &GraphLock) -> Vec<PackageArtifactRef> {
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

fn admit(persistence: &GatewayPersistence) {
    persistence
        .admission_create(&json!({
            "session_id": "kept-session",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "kept-session",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "session_metadata_json": "{}",
            "run_id": "kept-run",
            "parent_run_id": "",
            "input_json": "{\"text\":\"keep\"}",
            "message_id": "kept-message",
            "message_run_id": "kept-run",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "workspace_identity_json": "",
            "event_id": "kept-event",
            "now_ms": 2_000_000,
            "expires_at_ms": 0,
        }))
        .expect("existing admission row commits");
}

fn assert_session_kept(persistence: &GatewayPersistence) {
    let session = persistence
        .session_get("kept-session")
        .expect("existing session remains readable");
    assert_eq!(session["rows"].as_array().map(Vec::len), Some(1));
    assert!(
        session.to_string().contains("kept-session"),
        "existing session row was not preserved: {session}"
    );
}

fn code(err: &rustscript_agent::plugins::PluginControlError) -> &'static str {
    err.code
}

#[test]
fn exact_lock_survives_close_and_reopen_without_reresolve() {
    let path = db_path("reopen");
    let persistence = open(&path);
    let store = PluginControlStore::new(&persistence);
    let original = sample_lock("graph-exact", "artifact-tool-old");
    let stored = store.store_lock(&original).expect("store exact lock");
    assert_eq!(stored.graph_id, "graph-exact");
    assert!(!stored.idempotent);
    persistence.shutdown();
    drop(persistence);

    let reopened = open(&path);
    let store = PluginControlStore::new(&reopened);
    let ValidatedLockMetadata { lock } = store.load_lock("graph-exact").expect("load exact lock");
    assert_eq!(lock, original);
    assert_eq!(lock.packages[0].version, "1.2.3");
    assert_eq!(lock.packages[0].artifact_id, "artifact-tool-old");
    assert_eq!(lock.packages[1].artifact_id, "artifact-lib-exact");
    assert_eq!(
        store.package_refs("graph-exact").expect("refs"),
        refs_of(&original)
    );
    assert_eq!(store.activation().expect("inactive").generation, 0);
    reopened.shutdown();
}

#[test]
fn identical_store_is_idempotent_and_changed_bytes_conflict() {
    let path = db_path("idempotent");
    let persistence = open(&path);
    let store = PluginControlStore::new(&persistence);
    let original = sample_lock("graph-fixed", "artifact-a");
    store.store_lock(&original).expect("first store");
    let again = store.store_lock(&original).expect("identical store");
    assert!(again.idempotent);
    assert_eq!(store.list_locks().expect("list").len(), 1);
    let mut changed = original.clone();
    changed.packages[0].artifact_id = "artifact-b".into();
    let conflict = store.store_lock(&changed).expect_err("immutable id");
    assert_eq!(code(&conflict), "plugin_lock_conflict");
    let loaded = store.load_lock("graph-fixed").expect("original remains");
    assert_eq!(loaded.lock.packages[0].artifact_id, "artifact-a");
    persistence.shutdown();
}

#[test]
fn invalid_lock_writes_nothing() {
    let path = db_path("invalid");
    let persistence = open(&path);
    let store = PluginControlStore::new(&persistence);
    let mut forged = sample_lock("graph-bad", "artifact-a");
    forged.compile_environment = "other".into();
    let schema_err = store.store_lock(&forged).expect_err("schema reject");
    assert_eq!(code(&schema_err), "plugin_lock_invalid");
    let mut illegal = sample_lock("graph-spawn", "artifact-a");
    illegal.closure[0].effects[0].kind = "process.spawn".into();
    illegal.closure[0].effects[0].scope = "bound_process".into();
    illegal.closure[0].effects[0].recovery = "checkpoint".into();
    let semantic = store.store_lock(&illegal).expect_err("recovery reject");
    assert_eq!(code(&semantic), "plugin_lock_invalid");
    let mut dangling = sample_lock("graph-edge", "artifact-a");
    dangling.edges[0].to = "org.example.missing".into();
    let reference = store.store_lock(&dangling).expect_err("dangling edge");
    assert_eq!(code(&reference), "plugin_lock_invalid");
    assert!(store.list_locks().expect("empty").is_empty());
    persistence.shutdown();
}

#[test]
fn activation_cas_history_and_concurrent_single_winner() {
    let path = db_path("cas");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    let first = sample_lock("graph-a", "artifact-a");
    let second = sample_lock("graph-b", "artifact-b");
    store.store_lock(&first).expect("store a");
    store.store_lock(&second).expect("store b");
    let stale = store
        .activate("graph-a", 7, &refs_of(&first))
        .expect_err("stale generation");
    assert_eq!(code(&stale), "plugin_activation_conflict");
    assert_eq!(store.activation().expect("still empty").generation, 0);
    assert!(store.activation_history().expect("no history").is_empty());

    let barrier = Arc::new(Barrier::new(2));
    let left = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let barrier = Arc::clone(&barrier);
        let refs = refs_of(&first);
        move || {
            barrier.wait();
            PluginControlStore::new(&persistence).activate("graph-a", 0, &refs)
        }
    });
    let right = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let barrier = Arc::clone(&barrier);
        let refs = refs_of(&second);
        move || {
            barrier.wait();
            PluginControlStore::new(&persistence).activate("graph-b", 0, &refs)
        }
    });
    let left = left.join().expect("left thread");
    let right = right.join().expect("right thread");
    let outcomes = [left, right];
    assert_eq!(outcomes.iter().filter(|item| item.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|item| item
                .as_ref()
                .err()
                .is_some_and(|err| err.code == "plugin_activation_conflict"))
            .count(),
        1
    );
    let active = store.activation().expect("winner");
    assert_eq!(active.generation, 1);
    assert!(active.graph_id == "graph-a" || active.graph_id == "graph-b");
    let history = store.activation_history().expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].generation, 1);
    assert_eq!(history[0].graph_id, active.graph_id);
    assert_eq!(history[0].previous_graph_id, "");

    let loser = if active.graph_id == "graph-a" {
        "graph-b"
    } else {
        "graph-a"
    };
    let switched = store
        .activate(
            loser,
            1,
            &refs_of(&sample_lock(
                loser,
                if loser == "graph-a" {
                    "artifact-a"
                } else {
                    "artifact-b"
                },
            )),
        )
        .expect("second generation");
    assert_eq!(switched.generation, 2);
    let conflict = store
        .activate("graph-a", 1, &refs_of(&first))
        .expect_err("stale after switch");
    assert_eq!(code(&conflict), "plugin_activation_conflict");
    let history = store.activation_history().expect("history after conflict");
    assert_eq!(history.len(), 2);
    assert_eq!(history[1].generation, 2);
    assert_eq!(history[1].previous_graph_id, active.graph_id);
    assert_eq!(store.activation().expect("pointer").generation, 2);
    assert_eq!(
        store.load_lock("graph-a").expect("a remains").lock.graph_id,
        "graph-a"
    );
    assert_eq!(
        store.load_lock("graph-b").expect("b remains").lock.graph_id,
        "graph-b"
    );
    persistence.shutdown();
}

#[test]
fn missing_refs_do_not_activate() {
    let path = db_path("refs");
    let persistence = open(&path);
    let store = PluginControlStore::new(&persistence);
    let lock = sample_lock("graph-refs", "artifact-a");
    store.store_lock(&lock).expect("store");
    let missing_graph = store
        .activate("graph-absent", 0, &[])
        .expect_err("unknown graph");
    assert_eq!(code(&missing_graph), "plugin_graph_missing");
    let missing_refs = store
        .activate("graph-refs", 0, &[])
        .expect_err("empty refs");
    assert_eq!(code(&missing_refs), "plugin_package_ref_missing");
    let mut wrong = refs_of(&lock);
    wrong[0].artifact_id = "artifact-other".into();
    let mismatch = store
        .activate("graph-refs", 0, &wrong)
        .expect_err("artifact mismatch");
    assert_eq!(code(&mismatch), "plugin_package_ref_missing");
    assert_eq!(store.activation().expect("unchanged").generation, 0);
    let activated = store
        .activate("graph-refs", 0, &refs_of(&lock))
        .expect("exact refs");
    assert_eq!(
        activated,
        ActivationPointer {
            graph_id: "graph-refs".into(),
            generation: 1,
            updated_at_ms: activated.updated_at_ms,
        }
    );
    persistence.shutdown();
}

#[test]
fn partial_commit_rolls_back_and_preserves_existing_rows() {
    let path = db_path("rollback");
    let persistence = open(&path);
    admit(&persistence);
    let store = PluginControlStore::new(&persistence);
    let kept = sample_lock("graph-kept", "artifact-kept");
    store.store_lock(&kept).expect("store kept");
    store
        .activate("graph-kept", 0, &refs_of(&kept))
        .expect("activate kept");
    persistence.inject_fail_plugin_control_partial();
    let failed = store
        .store_lock(&sample_lock("graph-new", "artifact-new"))
        .expect_err("partial store rolls back");
    assert_eq!(code(&failed), "plugin_control_unavailable");
    assert!(store.load_lock("graph-new").is_err());
    assert_eq!(
        store
            .load_lock("graph-kept")
            .expect("kept lock")
            .lock
            .packages[0]
            .artifact_id,
        "artifact-kept"
    );
    assert_eq!(store.activation().expect("pointer").graph_id, "graph-kept");
    assert_eq!(store.activation_history().expect("history").len(), 1);
    assert_session_kept(&persistence);
    persistence.shutdown();
    drop(persistence);

    let reopened = open(&path);
    let store = PluginControlStore::new(&reopened);
    assert!(store.load_lock("graph-new").is_err());
    assert_eq!(store.activation().expect("reopened pointer").generation, 1);
    assert_session_kept(&reopened);
    let pending = sample_lock("graph-pending", "artifact-pending");
    store.store_lock(&pending).expect("store pending");
    reopened.inject_fail_plugin_control_partial();
    let rolled = store
        .activate("graph-pending", 1, &refs_of(&pending))
        .expect_err("partial activation rolls back");
    assert_eq!(code(&rolled), "plugin_control_unavailable");
    assert_eq!(
        store.activation().expect("still kept").graph_id,
        "graph-kept"
    );
    assert_eq!(store.activation_history().expect("history intact").len(), 1);
    reopened.shutdown();
}

#[test]
fn retention_survives_restart_and_gc_keeps_referenced_graphs() {
    let path = db_path("gc");
    let persistence = open(&path);
    let store = PluginControlStore::new(&persistence);
    let active = sample_lock("graph-active", "artifact-active");
    let held = sample_lock("graph-held", "artifact-held");
    let loose = sample_lock("graph-loose", "artifact-loose");
    store.store_lock(&active).expect("store active");
    store.store_lock(&held).expect("store held");
    store.store_lock(&loose).expect("store loose");
    store
        .activate("graph-active", 0, &refs_of(&active))
        .expect("activate");
    let retention = GraphRetention {
        graph_id: "graph-held".into(),
        owner_kind: "run".into(),
        owner_id: "run-1".into(),
        ref_id: "ref-1".into(),
    };
    assert!(!store.retain(&retention).expect("retain"));
    assert!(store.retain(&retention).expect("idempotent retain"));
    let bad = GraphRetention {
        graph_id: "graph-held".into(),
        owner_kind: "guest".into(),
        owner_id: "run-1".into(),
        ref_id: "ref-2".into(),
    };
    assert_eq!(
        code(&store.retain(&bad).expect_err("owner kind")),
        "plugin_ref_invalid"
    );
    persistence.shutdown();
    drop(persistence);

    let reopened = open(&path);
    let store = PluginControlStore::new(&reopened);
    let collected = store.collect_unreferenced().expect("collect loose");
    assert_eq!(collected, vec!["graph-loose".to_string()]);
    assert!(store.load_lock("graph-loose").is_err());
    assert_eq!(
        store
            .load_lock("graph-active")
            .expect("active kept")
            .lock
            .graph_id,
        "graph-active"
    );
    assert_eq!(
        store
            .load_lock("graph-held")
            .expect("held kept")
            .lock
            .graph_id,
        "graph-held"
    );
    store.release(&retention).expect("release");
    let collected = store.collect_unreferenced().expect("collect held");
    assert_eq!(collected, vec!["graph-held".to_string()]);
    assert!(store.load_lock("graph-held").is_err());
    let active_ref = GraphRetention {
        graph_id: "graph-active".into(),
        owner_kind: "checkpoint".into(),
        owner_id: "checkpoint-1".into(),
        ref_id: "ref-active".into(),
    };
    store.retain(&active_ref).expect("retain active");
    assert!(
        store
            .collect_unreferenced()
            .expect("active retained")
            .is_empty()
    );
    store.release(&active_ref).expect("release active ref");
    assert!(
        store
            .collect_unreferenced()
            .expect("active pointer")
            .is_empty(),
        "the active graph is not collected"
    );
    assert_eq!(
        store.activation().expect("still active").graph_id,
        "graph-active"
    );
    reopened.shutdown();
}

#[test]
fn approval_storage_does_not_create_plugin_control_rows() {
    let path = db_path("approval-fence");
    let persistence = open(&path);
    admit(&persistence);
    persistence
        .approval_request(&json!({
            "id": "plugin.lock_put",
            "run_id": "kept-run",
            "session_id": "kept-session",
            "tool_call_id": "tool-1",
            "tool_name": "plugin.lock_put",
            "arguments_json": "{}",
            "risk_class": "read",
            "decision_scope": "",
            "one_time": 0,
            "requested_at_ms": 2_000_000,
            "expires_at_ms": 0,
        }))
        .expect("approval storage accepts its own operation");
    let store = PluginControlStore::new(&persistence);
    assert!(store.list_locks().expect("no locks").is_empty());
    assert_eq!(store.activation().expect("no activation").generation, 0);
    assert_session_kept(&persistence);
    persistence.shutdown();
}

#[test]
fn loaded_metadata_does_not_grant_execution_authority() {
    let path = db_path("authority");
    let persistence = open(&path);
    let store = PluginControlStore::new(&persistence);
    let lock = sample_lock("graph-meta", "artifact-meta");
    store.store_lock(&lock).expect("store");
    let ValidatedLockMetadata { lock: loaded } = store.load_lock("graph-meta").expect("load");
    assert_eq!(loaded, lock);
    assert_eq!(
        store
            .activation()
            .expect("load is not activation")
            .generation,
        0
    );
    assert!(store.activation_history().expect("no history").is_empty());
    persistence.shutdown();
}
