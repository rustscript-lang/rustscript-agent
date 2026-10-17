//! Exact plugin-control persistence through the production RSS SQLite path.
//!
//! These tests do not call the resolver, do not install a newer package, and
//! do not treat a persisted graph id as host-catalog authority.

use std::fs;
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustscript_agent::plugins::{
    ActivationPointer, COMPILE_ENVIRONMENT, EffectOrigin, GraphLock, GraphRetention, HOST_RUNTIME,
    LockedEdge, LockedEffect, LockedEffectItem, LockedPackage, PackageArtifactRef,
    PluginControlStore, ScopeBinding, ValidatedLockMetadata,
};
use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, AgentProviderHost, GatewayPersistence,
    ScriptedProvider,
};
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

#[test]
fn conflicting_live_ref_is_not_idempotent_and_release_does_not_delete_other_ref() {
    let path = db_path("ref-identity");
    let persistence = open(&path);
    let store = PluginControlStore::new(&persistence);
    let lock = sample_lock("graph-ref-id", "artifact-ref-id");
    store.store_lock(&lock).expect("store");
    let live = GraphRetention {
        graph_id: "graph-ref-id".into(),
        owner_kind: "run".into(),
        owner_id: "run-1".into(),
        ref_id: "ref-live".into(),
    };
    assert!(!store.retain(&live).expect("first retain"));
    let other = GraphRetention {
        ref_id: "ref-other".into(),
        ..live.clone()
    };
    let conflict = store
        .retain(&other)
        .expect_err("different live ref is not an idempotent retain");
    assert_eq!(code(&conflict), "plugin_ref_invalid");
    assert_eq!(
        store.retained("graph-ref-id").expect("rows"),
        vec![live.clone()]
    );
    let release_other = store
        .release(&other)
        .expect_err("different live ref is not an idempotent release");
    assert_eq!(code(&release_other), "plugin_ref_invalid");
    assert_eq!(
        store.retained("graph-ref-id").expect("other release"),
        vec![live.clone()]
    );
    assert!(store.collect_unreferenced().expect("held").is_empty());
    store.release(&live).expect("release live ref");
    assert!(store.retained("graph-ref-id").expect("released").is_empty());
    store
        .release(&live)
        .expect("absent requested identity stays idempotent");
    assert_eq!(
        store.collect_unreferenced().expect("collect"),
        vec!["graph-ref-id".to_string()]
    );
    persistence.shutdown();
}

#[test]
fn retain_after_collect_between_preread_and_commit_is_not_success() {
    let path = db_path("retain-collected");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-raced", "artifact-raced"))
        .expect("store");
    let retention = GraphRetention {
        graph_id: "graph-raced".into(),
        owner_kind: "checkpoint".into(),
        owner_id: "checkpoint-1".into(),
        ref_id: "ref-raced".into(),
    };
    let pause = persistence.arm_plugin_retain_precommit_pause();
    let worker = thread::spawn({
        let persistence = Arc::clone(&persistence);
        move || PluginControlStore::new(&persistence).retain(&retention)
    });
    pause.wait_entered();
    assert_eq!(
        PluginControlStore::new(&persistence)
            .collect_unreferenced()
            .expect("collect during stale pre-read"),
        vec!["graph-raced".to_string()]
    );
    pause.release();
    let missing = worker
        .join()
        .expect("retain thread")
        .expect_err("graph collected before retain commit must not succeed");
    assert_eq!(code(&missing), "plugin_graph_missing");
    assert!(
        PluginControlStore::new(&persistence)
            .load_lock("graph-raced")
            .is_err()
    );
    assert!(
        PluginControlStore::new(&persistence)
            .retained("graph-raced")
            .expect("no ref")
            .is_empty()
    );
    persistence.shutdown();
}

#[test]
fn concurrent_distinct_refs_keep_one_live_identity() {
    let path = db_path("retain-race");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-slot", "artifact-slot"))
        .expect("store");
    let _precommit_gate = persistence.arm_plugin_control_precommit_gate(2);
    let run = |ref_id: &'static str| {
        let persistence = Arc::clone(&persistence);
        thread::spawn(move || {
            PluginControlStore::new(&persistence).retain(&GraphRetention {
                graph_id: "graph-slot".into(),
                owner_kind: "run".into(),
                owner_id: "run-1".into(),
                ref_id: ref_id.into(),
            })
        })
    };
    let left = run("ref-left");
    let right = run("ref-right");
    let left = left.join().expect("left thread");
    let right = right.join().expect("right thread");
    persistence.disarm_plugin_control_precommit_gate();
    let outcomes = [left, right];
    assert_eq!(outcomes.iter().filter(|item| item.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|item| item
                .as_ref()
                .err()
                .is_some_and(|err| err.code == "plugin_ref_invalid"))
            .count(),
        1
    );
    let stored = store.retained("graph-slot").expect("one slot");
    assert_eq!(stored.len(), 1);
    let winner = stored[0].ref_id.as_str();
    assert!(winner == "ref-left" || winner == "ref-right");
    let loser = if winner == "ref-left" {
        "ref-right"
    } else {
        "ref-left"
    };
    let release_loser = store
        .release(&GraphRetention {
            graph_id: "graph-slot".into(),
            owner_kind: "run".into(),
            owner_id: "run-1".into(),
            ref_id: loser.into(),
        })
        .expect_err("loser must not delete the live ref");
    assert_eq!(code(&release_loser), "plugin_ref_invalid");
    assert_eq!(store.retained("graph-slot").expect("still winner").len(), 1);
    store.release(&stored[0]).expect("winner release");
    assert_eq!(
        store.collect_unreferenced().expect("collect"),
        vec!["graph-slot".to_string()]
    );
    persistence.shutdown();
}

#[test]
fn same_graph_same_generation_activate_has_one_winner() {
    let path = db_path("cas-same");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    let lock = sample_lock("graph-cas", "artifact-cas");
    store.store_lock(&lock).expect("store");
    let refs = refs_of(&lock);
    let _precommit_gate = persistence.arm_plugin_control_precommit_gate(2);
    let spawn = || {
        let persistence = Arc::clone(&persistence);
        let refs = refs.clone();
        thread::spawn(move || PluginControlStore::new(&persistence).activate("graph-cas", 0, &refs))
    };
    let left = spawn();
    let right = spawn();
    let left = left.join().expect("left thread");
    let right = right.join().expect("right thread");
    persistence.disarm_plugin_control_precommit_gate();
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
    assert_eq!(active.graph_id, "graph-cas");
    assert_eq!(active.generation, 1);
    let history = store.activation_history().expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].generation, 1);
    assert_eq!(history[0].graph_id, "graph-cas");
    let winner = outcomes.into_iter().find_map(Result::ok).expect("winner");
    assert_eq!(winner.generation, 1);
    assert_eq!(winner.graph_id, "graph-cas");
    persistence.shutdown();
}

#[test]
fn activate_receipt_survives_later_legitimate_activation() {
    let path = db_path("cas-successor");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    let lock = sample_lock("graph-receipt", "artifact-receipt");
    store.store_lock(&lock).expect("store");
    let refs = refs_of(&lock);
    let hook_persistence = Arc::clone(&persistence);
    let hook_refs = refs.clone();
    persistence.arm_plugin_activate_receipt_hook(move || {
        PluginControlStore::new(&hook_persistence)
            .activate("graph-receipt", 1, &hook_refs)
            .expect("later legitimate activation");
    });
    let first = store
        .activate("graph-receipt", 0, &refs)
        .expect("this invocation returns its own receipt");
    assert_eq!(first.graph_id, "graph-receipt");
    assert_eq!(first.generation, 1);
    let latest = store.activation().expect("latest pointer");
    assert_eq!(latest.generation, 2);
    assert_eq!(latest.graph_id, "graph-receipt");
    assert_ne!(first.generation, latest.generation);
    let history = store.activation_history().expect("both commits");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].generation, 1);
    assert_eq!(first.updated_at_ms, history[0].activated_at_ms);
    persistence.shutdown();
}

#[tokio::test]
async fn guest_approval_storage_does_not_forward_plugin_control_ops() {
    let path = db_path("guest-fence");
    let source = r#"
pub fn run(context: map) -> map {
    let run_id: string = context["run_id"];
    let session_id: string = context["session_id"];
    let retain: map = agent::approval_storage("plugin.retain", {
        run_id: run_id.copy(),
        session_id: session_id.copy(),
        graph_id: "graph-guest",
        owner_kind: "run",
        owner_id: "run-guest",
        ref_id: "ref-guest"
    });
    let activate: map = agent::approval_storage("plugin.activate", {
        run_id: run_id.copy(),
        session_id: session_id.copy(),
        graph_id: "graph-guest",
        expected_generation: 0
    });
    let lock_put: map = agent::approval_storage("plugin.lock_put", {
        run_id: run_id.copy(),
        session_id: session_id.copy(),
        graph_id: "graph-guest"
    });
    let release: map = agent::approval_storage("plugin.release", {
        run_id: run_id.copy(),
        session_id: session_id.copy(),
        graph_id: "graph-guest",
        owner_kind: "run",
        owner_id: "run-guest",
        ref_id: "ref-guest"
    });
    let listed: map = agent::approval_storage("list", {
        run_id: run_id.copy(),
        session_id: session_id.copy()
    });
    let retain_error: map = retain["error"];
    let activate_error: map = activate["error"];
    let lock_error: map = lock_put["error"];
    let release_error: map = release["error"];
    let retain_code: string = retain_error["code"];
    let activate_code: string = activate_error["code"];
    let lock_code: string = lock_error["code"];
    let release_code: string = release_error["code"];
    let list_ok: bool = listed["ok"];
    let mut list_flag: string = "0";
    if list_ok == true {
        list_flag = "1";
    }
    let answer: string = "retain=" + retain_code.copy() + ";activate=" + activate_code.copy() + ";lock=" + lock_code.copy() + ";release=" + release_code.copy() + ";list_ok=" + list_flag;
    { kind: "run.completed", answer: answer }
}
"#;
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        source,
        &path,
    )
    .expect("guest fixture compiles through the production host catalog");
    let service = state.service();
    let provider = ScriptedProvider::new();
    let host: Arc<dyn AgentProviderHost> = Arc::new(provider.clone());
    service.inject_provider_host(host);
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "guest fence"}),
            platform: "plugin_store_recovery".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admit");
    Arc::clone(&service)
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        provider.call_count(),
        0,
        "plugin control must not reach the fake provider"
    );
    let persistence = state.persistence().expect("sqlite persistence");
    let store = PluginControlStore::new(persistence.as_ref());
    assert!(store.list_locks().expect("locks").is_empty());
    assert_eq!(store.activation().expect("activation").generation, 0);
    assert!(store.activation_history().expect("history").is_empty());
    assert!(store.retained("graph-guest").expect("refs").is_empty());
    let messages = persistence
        .message_list(&admitted.session_id, 0)
        .expect("messages");
    let rendered = messages.to_string();
    assert!(
        rendered.contains("retain=approval_operation_invalid;activate=approval_operation_invalid;lock=approval_operation_invalid;release=approval_operation_invalid;list_ok=1"),
        "guest host did not deny plugin control ops: {rendered}"
    );
    persistence.shutdown();
}

const SEAM_CHILD_MARKER: &str = "RUSTSCRIPT_PLUGIN_STORE_SEAM_CHILD";
const SEAM_CHILD_BOUND: Duration = Duration::from_secs(20);
const SEAM_CHILD_OUTPUT_LIMIT: usize = 64 * 1024;

struct SeamOwnedChild(Option<Child>);

impl SeamOwnedChild {
    fn wait_before(
        &mut self,
        deadline: Instant,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        loop {
            let child = self.0.as_mut().expect("owned seam child");
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.0.take();
                    return Ok(Some(status));
                }
                Ok(None) if Instant::now() >= deadline => {
                    self.kill_and_reap();
                    return Ok(None);
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    self.kill_and_reap();
                    return Err(error);
                }
            }
        }
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for SeamOwnedChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

struct SeamBoundedOutput {
    bytes: Vec<u8>,
    discarded: usize,
}

fn capture_seam_output(mut reader: impl Read) -> std::io::Result<SeamBoundedOutput> {
    let mut output = SeamBoundedOutput {
        bytes: Vec::with_capacity(SEAM_CHILD_OUTPUT_LIMIT),
        discarded: 0,
    };
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(read) => {
                let keep = read.min(SEAM_CHILD_OUTPUT_LIMIT.saturating_sub(output.bytes.len()));
                output.bytes.extend_from_slice(&buffer[..keep]);
                output.discarded += read - keep;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn seam_child_is_current(test_name: &str) -> bool {
    let Ok(marker) = std::env::var(SEAM_CHILD_MARKER) else {
        return false;
    };
    let mut parts = marker.splitn(3, ':');
    let (Some(marked_test), Some(parent_pid), Some(nonce)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if marked_test != test_name
        || parent_pid.parse::<libc::pid_t>().ok() != Some(unsafe { libc::getppid() })
        || uuid::Uuid::parse_str(nonce).is_err()
    {
        return false;
    }
    std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|args| args[0] == "--exact" && args[1] == test_name)
}

/// Parent returns true after the exact child has passed. The child returns false
/// and runs the body. A hang is killed and reaped before drain threads are joined.
fn seam_parent_finished(test_name: &str) -> bool {
    if seam_child_is_current(test_name) {
        return false;
    }
    let deadline = Instant::now() + SEAM_CHILD_BOUND;
    let nonce = uuid::Uuid::new_v4();
    let marker = format!("{test_name}:{}:{nonce}", std::process::id());
    let mut child = SeamOwnedChild(Some(
        Command::new(std::env::current_exe().expect("seam test executable"))
            .args(["--exact", test_name, "--nocapture"])
            .env_clear()
            .envs(
                [
                    "PATH",
                    "HOME",
                    "XDG_CACHE_HOME",
                    "RUSTC",
                    "RUSTUP_HOME",
                    "RUSTUP_TOOLCHAIN",
                    "CARGO_HOME",
                    "LD_LIBRARY_PATH",
                    "CEF_PATH",
                    "TMPDIR",
                    "TEMP",
                    "TMP",
                    "TEMPDIR",
                    "TEST_TMPDIR",
                    "RUSTSCRIPT_AGENT_TEST_TMP",
                    "RUSTSCRIPT_AGENT_TEST_TMPDIR",
                ]
                .into_iter()
                .filter_map(|key| std::env::var_os(key).map(|value| (key, value))),
            )
            .env("CARGO_TERM_COLOR", "never")
            .env(SEAM_CHILD_MARKER, marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn exact seam child"),
    ));
    let stdout = child
        .0
        .as_mut()
        .expect("owned seam child")
        .stdout
        .take()
        .expect("seam child stdout");
    let stderr = child
        .0
        .as_mut()
        .expect("owned seam child")
        .stderr
        .take()
        .expect("seam child stderr");
    let stdout_reader = thread::spawn(move || capture_seam_output(stdout));
    let stderr_reader = thread::spawn(move || capture_seam_output(stderr));
    let status = child.wait_before(deadline);
    let stdout = stdout_reader
        .join()
        .expect("seam stdout drain joined")
        .expect("seam stdout");
    let stderr = stderr_reader
        .join()
        .expect("seam stderr drain joined")
        .expect("seam stderr");
    let stdout_text = String::from_utf8_lossy(&stdout.bytes);
    let stderr_text = String::from_utf8_lossy(&stderr.bytes);
    let output = format!("{stdout_text}\n{stderr_text}");
    let truncated = stdout.discarded + stderr.discarded;
    let ran_exactly_one = output
        .lines()
        .filter(|line| line.trim() == "running 1 test")
        .count()
        == 1
        && output
            .lines()
            .filter(|line| line.trim() == format!("test {test_name} ... ok"))
            .count()
            == 1
        && output.lines().any(|line| {
            line.trim()
                .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
        });
    let evidence: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("SEAM_EVIDENCE"))
        .collect();
    let status = status.expect("seam child wait");
    assert!(
        matches!(status, Some(ref exit) if exit.success()) && ran_exactly_one && truncated == 0,
        "exact seam child {test_name} failed: status={status:?} ran_exactly_one={ran_exactly_one} truncated={truncated} evidence={evidence:?}"
    );
    true
}

fn seam_note(phase: &str) {
    eprintln!("SEAM_EVIDENCE phase={phase}");
    let _ = std::io::stderr().flush();
}

fn seam_retention(graph_id: &str, ref_id: &str) -> GraphRetention {
    GraphRetention {
        graph_id: graph_id.into(),
        owner_kind: "run".into(),
        owner_id: "run-seam".into(),
        ref_id: ref_id.into(),
    }
}

#[test]
fn seam_retain_release_before_entry_still_reaches_command() {
    let path = db_path("seam-release-before");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-before", "artifact-before"))
        .expect("store");
    let retention = seam_retention("graph-before", "ref-before");
    let pause = persistence.arm_plugin_retain_precommit_pause();
    pause.release();
    let worker = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let retention = retention.clone();
        move || PluginControlStore::new(&persistence).retain(&retention)
    });
    let committed = worker
        .join()
        .expect("retain thread")
        .expect("release before entry");
    assert!(!committed, "first retain is not idempotent");
    pause.wait_entered();
    assert_eq!(
        store.retained("graph-before").expect("rows"),
        vec![retention]
    );
    persistence.shutdown();
}

#[test]
fn seam_retain_controller_drop_must_not_commit() {
    let path = db_path("seam-drop");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-drop", "artifact-drop"))
        .expect("store");
    let retention = seam_retention("graph-drop", "ref-drop");
    let pause = persistence.arm_plugin_retain_precommit_pause();
    let worker = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let retention = retention.clone();
        move || PluginControlStore::new(&persistence).retain(&retention)
    });
    pause.wait_entered();
    drop(pause);
    let outcome = worker.join().expect("retain thread");
    let err = outcome.expect_err("controller drop after entered pause must not commit");
    assert_eq!(code(&err), "plugin_control_fixture_aborted");
    assert!(store.retained("graph-drop").expect("rows").is_empty());
    persistence.shutdown();
}

#[test]
fn seam_retain_controller_unwind_must_not_commit() {
    let path = db_path("seam-unwind");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-unwind", "artifact-unwind"))
        .expect("store");
    let retention = seam_retention("graph-unwind", "ref-unwind");
    let worker = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let retention = retention.clone();
        move || PluginControlStore::new(&persistence).retain(&retention)
    });
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let pause = persistence.arm_plugin_retain_precommit_pause();
        pause.wait_entered();
        panic!("controller unwind");
    }));
    assert!(unwound.is_err(), "controller panic must unwind");
    let outcome = worker.join().expect("retain thread");
    let err = outcome.expect_err("unwinding controller must not commit the paused retain");
    assert_eq!(code(&err), "plugin_control_fixture_aborted");
    assert!(store.retained("graph-unwind").expect("rows").is_empty());
    persistence.shutdown();
}

#[test]
fn seam_retain_forgotten_controller_is_bounded_fixture_fault() {
    if seam_parent_finished("seam_retain_forgotten_controller_is_bounded_fixture_fault") {
        return;
    }
    let path = db_path("seam-forget");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-forget", "artifact-forget"))
        .expect("store");
    let retention = seam_retention("graph-forget", "ref-forget");
    let pause = persistence.arm_plugin_retain_precommit_pause();
    let worker = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let retention = retention.clone();
        move || PluginControlStore::new(&persistence).retain(&retention)
    });
    pause.wait_entered();
    seam_note("entered");
    std::mem::forget(pause);
    let outcome = worker.join().expect("retain thread");
    let err = outcome.expect_err("forgotten controller must not commit");
    assert_eq!(code(&err), "plugin_control_fixture_timeout");
    assert!(store.retained("graph-forget").expect("rows").is_empty());
    persistence.shutdown();
}

#[test]
fn seam_gate_missing_precheck_participant_is_bounded_fixture_fault() {
    if seam_parent_finished("seam_gate_missing_precheck_participant_is_bounded_fixture_fault") {
        return;
    }
    let path = db_path("seam-missing-gate");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-miss", "artifact-miss"))
        .expect("store");
    let retention = seam_retention("graph-miss", "ref-miss");
    let _precommit_gate = persistence.arm_plugin_control_precommit_gate(2);
    let pause = persistence.arm_plugin_retain_precommit_pause();
    let worker = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let retention = retention.clone();
        move || PluginControlStore::new(&persistence).retain(&retention)
    });
    pause.wait_entered();
    seam_note("entered");
    let missing =
        PluginControlStore::new(&persistence).retain(&seam_retention("graph-absent", "ref-absent"));
    assert_eq!(
        code(&missing.expect_err("missing graph")),
        "plugin_graph_missing"
    );
    seam_note("peer_precheck_failed");
    pause.release();
    seam_note("released_toward_gate");
    let outcome = worker.join().expect("retain thread");
    let err = outcome.expect_err("missing gate participant must not commit");
    assert!(
        code(&err) == "plugin_control_fixture_timeout"
            || code(&err) == "plugin_control_fixture_aborted",
        "bounded fixture fault, got {}",
        code(&err)
    );
    assert!(store.retained("graph-miss").expect("rows").is_empty());
    persistence.disarm_plugin_control_precommit_gate();
    persistence.shutdown();
}

#[test]
fn seam_gate_extra_call_after_completion_does_not_wait() {
    if seam_parent_finished("seam_gate_extra_call_after_completion_does_not_wait") {
        return;
    }
    let path = db_path("seam-extra");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    store
        .store_lock(&sample_lock("graph-extra", "artifact-extra"))
        .expect("store");
    let _precommit_gate = persistence.arm_plugin_control_precommit_gate(2);
    let spawn_ref = |ref_id: &'static str| {
        let persistence = Arc::clone(&persistence);
        thread::spawn(move || {
            PluginControlStore::new(&persistence).retain(&seam_retention("graph-extra", ref_id))
        })
    };
    let left = spawn_ref("ref-left");
    let right = spawn_ref("ref-right");
    let left = left.join().expect("left thread");
    let right = right.join().expect("right thread");
    assert_eq!([left, right].iter().filter(|item| item.is_ok()).count(), 1);
    seam_note("first_round_done");
    let before = store.retained("graph-extra").expect("winner");
    assert_eq!(before.len(), 1);
    let pause = persistence.arm_plugin_retain_precommit_pause();
    let third = spawn_ref("ref-third");
    pause.wait_entered();
    seam_note("entered");
    pause.release();
    seam_note("released_toward_gate");
    let outcome = third.join().expect("third thread");
    let err = outcome.expect_err("completed rendezvous must not start another wait");
    assert_eq!(code(&err), "plugin_control_fixture_closed");
    assert_eq!(store.retained("graph-extra").expect("unchanged"), before);
    persistence.disarm_plugin_control_precommit_gate();
    persistence.shutdown();
}

#[test]
fn seam_activate_precheck_failure_drops_unconsumed_hook() {
    let path = db_path("seam-hook-precheck");
    let persistence = Arc::new(open(&path));
    let captured = Arc::clone(&persistence);
    persistence.arm_plugin_activate_receipt_hook(move || {
        let _keep = &captured;
    });
    let store = PluginControlStore::new(&persistence);
    let failed = store
        .activate("graph-hook-missing", 0, &[])
        .expect_err("precheck fails before the hook");
    assert_eq!(code(&failed), "plugin_graph_missing");
    assert_eq!(
        Arc::strong_count(&persistence),
        1,
        "unconsumed receipt hook retained persistence after precheck failure"
    );
    persistence.shutdown();
}

#[test]
fn seam_activate_command_failure_drops_unconsumed_hook() {
    let path = db_path("seam-hook-command");
    let persistence = Arc::new(open(&path));
    let store = PluginControlStore::new(&persistence);
    let lock = sample_lock("graph-hook-cmd", "artifact-hook-cmd");
    store.store_lock(&lock).expect("store");
    let captured = Arc::clone(&persistence);
    persistence.arm_plugin_activate_receipt_hook(move || {
        let _keep = &captured;
    });
    persistence.inject_fail_plugin_control_partial();
    let failed = store
        .activate("graph-hook-cmd", 0, &refs_of(&lock))
        .expect_err("command fails before the hook is consumed");
    assert_eq!(code(&failed), "plugin_control_unavailable");
    assert_eq!(store.activation().expect("no pointer").generation, 0);
    assert_eq!(
        Arc::strong_count(&persistence),
        1,
        "unconsumed receipt hook retained persistence after command failure"
    );
    persistence.shutdown();
}
