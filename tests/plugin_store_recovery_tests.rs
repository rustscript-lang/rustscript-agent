//! Exact plugin-control persistence through the production RSS SQLite path.
//!
//! Persistence tests do not call the resolver, do not install a newer package,
//! and do not treat a persisted graph id as host-catalog authority. Capture
//! boundary tests at the bottom use PackageStore install, resolve, and prepare.

use std::fs;
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustscript_agent::plugins::{
    ActivationPointer, COMPILE_ENVIRONMENT, EffectOrigin, GraphLock, GraphRetention, HOST_RUNTIME,
    HarnessSelectionRequest, InstallAuthorization, LockedEdge, LockedEffect, LockedEffectItem,
    LockedPackage, PackageArtifactRef, PackageRequirement, PackageStore, PackageTrust,
    PluginControlStore, PluginError, PluginErrorKind, PublisherKey, ResolveRequest, ScopeBinding,
    ValidatedLockMetadata,
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
        harness_selection: rustscript_agent::plugins::HarnessSelection::Unselected,
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
    let revoke: map = agent::approval_storage("plugin.graph_revoke", {run_id:run_id.copy(),session_id:session_id.copy(),graph_id:"graph-guest"});
    let get: map = agent::approval_storage("plugin.graph_revocation_get", {run_id:run_id.copy(),session_id:session_id.copy(),graph_id:"graph-guest"});
    let requirement: map = agent::approval_storage("plugin.pin_requirement_get", {run_id:run_id.copy(),session_id:session_id.copy(),owner_id:run_id.copy()});
    let fixture: map = agent::approval_storage("plugin.fixture_pin_state", {run_id:run_id.copy(),session_id:session_id.copy(),owner_id:run_id.copy(),mutation:"drop_requirement"});
    let revoke_error:map=revoke["error"];let revoke_code:string=revoke_error["code"];
    let get_error:map=get["error"];let get_code:string=get_error["code"];
    let requirement_error:map=requirement["error"];let requirement_code:string=requirement_error["code"];
    let fixture_error:map=fixture["error"];let fixture_code:string=fixture_error["code"];
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
    let answer: string = "retain=" + retain_code.copy() + ";activate=" + activate_code.copy() + ";lock=" + lock_code.copy() + ";release=" + release_code.copy() + ";list_ok=" + list_flag + ";revoke=" + revoke_code + ";get=" + get_code + ";requirement=" + requirement_code + ";fixture=" + fixture_code;
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
    let persistence = state.persistence().expect("sqlite persistence");
    let store = PluginControlStore::new(persistence.as_ref());
    let locks_before = store.list_locks().expect("Native admission locks");
    let active_before = store.activation().expect("Native admission activation");
    let history_before = store
        .activation_history()
        .expect("Native admission history");
    assert_eq!(
        locks_before.len(),
        1,
        "Native default bootstrap owns one graph"
    );
    assert_eq!(active_before.generation, 1);
    Arc::clone(&service)
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        provider.call_count(),
        0,
        "plugin control must not reach the fake provider"
    );
    assert_eq!(store.list_locks().expect("locks"), locks_before);
    assert_eq!(store.activation().expect("activation"), active_before);
    assert_eq!(store.activation_history().expect("history"), history_before);
    assert!(store.retained("graph-guest").expect("refs").is_empty());
    let messages = persistence
        .message_list(&admitted.session_id, 0)
        .expect("messages");
    let rendered = messages.to_string();
    assert!(rendered.contains(";revoke=approval_operation_invalid;get=approval_operation_invalid;requirement=approval_operation_invalid;fixture=approval_operation_invalid"));
    assert!(
        store
            .graph_revocation(&active_before.graph_id)
            .unwrap()
            .is_none()
    );
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
    let pause = persistence.arm_plugin_retain_precommit_pause();
    let worker = thread::spawn({
        let persistence = Arc::clone(&persistence);
        let retention = retention.clone();
        move || PluginControlStore::new(&persistence).retain(&retention)
    });
    let unwound = catch_unwind(AssertUnwindSafe(move || {
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

fn graph_required_lock(graph_id: &str) -> GraphLock {
    let mut lock = sample_lock(graph_id, "artifact-required");
    lock.harness_selection = rustscript_agent::plugins::HarnessSelection::ToolOnly {
        tool_package: "org.example.tools".into(),
    };
    lock
}

fn graph_required_admission(key: &str) -> serde_json::Value {
    json!({
        "session_id":"required-session", "session_new":1, "profile":"gateway",
        "platform":"api_server", "account_id":"required-session", "model":"m", "provider":"p",
        "system_prompt":"", "session_metadata_json":"{}", "run_id":"required-run",
        "parent_run_id":"", "input_json":"{\"text\":\"call\"}",
        "message_id":"required-message", "message_run_id":"required-run", "script_hash":"s",
        "idempotency_scope":"api:chat", "idempotency_key":key, "request_hash":"proof",
        "workspace_identity_json":"", "event_id":"required-event", "now_ms":2000000,
        "expires_at_ms":0, "tool_graph_id":"graph-required", "tool_graph_generation":1,
        "tool_ref_id":"required-ref", "tool_pin_now_ms":2000000,
        "registry_identity":"required-registry", "workspace":""
    })
}

fn graph_pair() -> serde_json::Value {
    json!({"run_id":"required-run", "event_id_a":"requested", "event_type_a":"tool.requested",
        "payload_json_a":"{}", "event_id_b":"started", "event_type_b":"tool.started",
        "payload_json_b":"{}", "now_ms":2000001, "max_events":1})
}

#[test]
fn required_graph_identity_survives_replacement_collection_terminal_and_session_delete() {
    for key in ["", "required-key"] {
        let path = db_path("identity-lifetime");
        let p = open(&path);
        let control = PluginControlStore::new(&p);
        let a = graph_required_lock("graph-required");
        let b = graph_required_lock("graph-other");
        control.store_lock(&a).unwrap();
        control.store_lock(&b).unwrap();
        control.activate(&a.graph_id, 0, &refs_of(&a)).unwrap();
        p.admission_create(&graph_required_admission(key)).unwrap();
        let requirement = control
            .pin_requirement_for_run("required-run")
            .unwrap()
            .unwrap();
        assert_eq!(requirement.graph_id, a.graph_id);
        assert_eq!(requirement.ref_id, "required-ref");
        let mut second = graph_required_admission("");
        second["session_new"] = json!(0);
        second["tool_graph_id"] = json!(b.graph_id);
        second["tool_ref_id"] = json!("different-ref");
        second["message_id"] = json!("second-message");
        let denied = p.admission_create(&second).unwrap_err();
        assert_eq!(
            denied.code, "plugin_graph_pin_required",
            "second identity must not publish: {denied:?}"
        );
        control
            .release(&GraphRetention {
                graph_id: a.graph_id.clone(),
                owner_kind: "run".into(),
                owner_id: "required-run".into(),
                ref_id: "required-ref".into(),
            })
            .unwrap();
        control
            .retain(&GraphRetention {
                graph_id: b.graph_id.clone(),
                owner_kind: "run".into(),
                owner_id: "required-run".into(),
                ref_id: "replacement-ref".into(),
            })
            .unwrap();
        assert_eq!(
            p.event_append_pair(&graph_pair()).unwrap_err().code,
            "plugin_graph_pin_required"
        );
        control.activate(&b.graph_id, 1, &refs_of(&b)).unwrap();
        assert!(
            control
                .collect_unreferenced()
                .unwrap()
                .contains(&a.graph_id)
        );
        p.run_transition(&json!({"run_id":"required-run","from_status":"running","to_status":"completed","error_code":"","error_message":"","recovery_reason":"","now_ms":2000002})).unwrap();
        assert_eq!(
            control.pin_requirement_for_run("required-run").unwrap(),
            Some(requirement.clone())
        );
        p.shutdown();
        drop(p);
        let reopened = open(&path);
        let control = PluginControlStore::new(&reopened);
        assert_eq!(
            control.pin_requirement_for_run("required-run").unwrap(),
            Some(requirement)
        );
        reopened.session_delete("required-session").unwrap();
        assert_eq!(
            control.pin_requirement_for_run("required-run").unwrap(),
            None
        );
        assert!(
            reopened.run_get("required-run").unwrap()["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        reopened.shutdown();
    }
}

#[test]
fn revoke_api_refuses_non_embedding_graphs_without_creating_a_fact() {
    let path = db_path("revoke-domain");
    let p = open(&path);
    let control = PluginControlStore::new(&p);
    let lock = sample_lock("non-embedding", "artifact-foreign");
    control.store_lock(&lock).unwrap();
    let packages =
        rustscript_agent::plugins::PackageStore::open(path.parent().unwrap().join("packages"))
            .unwrap();
    assert_eq!(
        control
            .revoke_graph(&packages, &lock.graph_id)
            .unwrap_err()
            .code,
        "plugin_lock_invalid"
    );
    assert!(control.graph_revocation(&lock.graph_id).unwrap().is_none());
    p.shutdown();
}

#[test]
fn unpinned_caller_scope_collision_and_stateless_pair_do_not_create_requirement() {
    for collision in [false, true] {
        let p = open(&db_path("unpinned-collision"));
        let mut admission = graph_required_admission(if collision {
            "required-run"
        } else {
            "ordinary-key"
        });
        admission["tool_graph_id"] = json!("");
        admission["tool_ref_id"] = json!("");
        if collision {
            admission["idempotency_scope"] = json!("native.tool-pin");
        }
        p.admission_create(&admission).unwrap();
        assert_eq!(
            PluginControlStore::new(&p)
                .pin_requirement_for_run("required-run")
                .unwrap(),
            None
        );
        p.event_append_pair(&graph_pair()).unwrap();
        p.shutdown();
    }
}

#[test]
fn required_graph_release_rejects_new_pair_without_cropping_or_retry_repair() {
    for key in ["", "required-key"] {
        let path = db_path("required-release");
        let persistence = open(&path);
        let store = PluginControlStore::new(&persistence);
        let lock = graph_required_lock("graph-required");
        store.store_lock(&lock).unwrap();
        store.activate(&lock.graph_id, 0, &refs_of(&lock)).unwrap();
        let admission = graph_required_admission(key);
        persistence.admission_create(&admission).unwrap();
        let before = persistence.event_replay(&json!({"run_id":"required-run", "after_seq":0, "max_events":128, "max_bytes":65536})).unwrap();
        store
            .release(&GraphRetention {
                graph_id: lock.graph_id.clone(),
                owner_kind: "run".into(),
                owner_id: "required-run".into(),
                ref_id: "required-ref".into(),
            })
            .unwrap();
        if !key.is_empty() {
            let retry = persistence.admission_create(&admission).unwrap();
            assert_eq!(retry["replayed"], true);
        }
        assert!(store.retained(&lock.graph_id).unwrap().is_empty());
        let result = persistence.event_append_pair(&graph_pair());
        assert_eq!(
            result.as_ref().err().map(|e| e.code.as_str()),
            Some("plugin_graph_pin_required"),
            "released required pin must reject before event writes: {result:?}"
        );
        assert_eq!(persistence.event_replay(&json!({"run_id":"required-run", "after_seq":0, "max_events":128, "max_bytes":65536})).unwrap(), before);
        persistence.shutdown();
    }
}

const CAPTURE_FILE_BYTES: usize = 1024 * 1024;
const CAPTURE_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const CAPTURE_FILES: usize = 64;
const CAPTURE_DEPTH: usize = 32;
const CAPTURE_WALK_ENTRIES: usize = 4096;
const ENTRY_SOURCE: &str = "pub fn invoke(value: int) -> int { value }\n";
static CAPTURE_SEQ: AtomicU64 = AtomicU64::new(0);

struct CaptureDir {
    path: PathBuf,
}

impl CaptureDir {
    fn new(label: &str) -> Self {
        let base = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
                .expect("RUSTSCRIPT_AGENT_TEST_TMPDIR must point into assigned TEMP"),
        );
        let dir = base.join(format!(
            "capture-bound-{label}-{}-{}",
            std::process::id(),
            CAPTURE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("assigned temp accepts the capture fixture");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CaptureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn tool_manifest(id: &str) -> String {
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
state:
  scope: run
  schema: 1
"#
    )
}

fn dev_auth(dev: &Path) -> InstallAuthorization {
    InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: Some(dev.to_path_buf()),
    }
}

fn write_tool(dir: &Path, id: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("manifest.yaml"), tool_manifest(id)).unwrap();
    fs::write(dir.join("invoke.rss"), ENTRY_SOURCE).unwrap();
}

fn write_extra_files(dir: &Path, count: usize) {
    for index in 0..count {
        fs::write(dir.join(format!("extra{index:02}.txt")), b"x").unwrap();
    }
}

fn regular_file_count(dir: &Path) -> usize {
    let mut count = 0usize;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                count += 1;
            }
        }
    }
    count
}

fn child_names(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            names.push(entry.unwrap().file_name().into_string().unwrap());
        }
    }
    names.sort();
    names
}

fn assert_budget(err: PluginError) {
    assert_eq!(err.kind, PluginErrorKind::BudgetExceeded, "{err:?}");
    assert!(
        !err.chain.is_empty(),
        "budget rejection must keep the typed chain: {err:?}"
    );
}

fn resolve_tool(store: &PackageStore, id: &str) -> GraphLock {
    store
        .resolve(&ResolveRequest {
            harness_selection: HarnessSelectionRequest::Unselected,
            roots: vec![PackageRequirement {
                id: id.to_string(),
                version: "1.0.0".to_string(),
            }],
            host_runtime: HOST_RUNTIME.to_string(),
        })
        .expect("healthy package resolves")
}

fn reopen_store(store_root: &Path, auth: &InstallAuthorization) -> PackageStore {
    let store = PackageStore::open(store_root).expect("formal store reopens");
    store.bind_policy(auth);
    store
}

fn signer() -> (Ed25519KeyPair, PublisherKey) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key = PublisherKey {
        publisher: "org.rustscript".to_string(),
        verifying_key: pair.public_key().as_ref().to_vec(),
    };
    (pair, key)
}

fn sign_package(store: &PackageStore, pair: &Ed25519KeyPair, dir: &Path) {
    let payload = store
        .signature_payload(dir)
        .expect("legal package has a formal signature payload");
    fs::write(dir.join("signature.ed25519"), pair.sign(&payload).as_ref()).unwrap();
}

#[test]
fn capture_bound_signed_and_dev_unsigned_install_resolve_and_prepare() {
    let root = CaptureDir::new("trust");
    let dev = root.path().join("dev");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let (pair, key) = signer();
    let signed_dir = root.path().join("signed");
    write_tool(&signed_dir, "org.rustscript.tools.capsigned");
    sign_package(&store, &pair, &signed_dir);
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![key],
        unsigned_dev_space: Some(dev.clone()),
    };
    let signed = store.install(&signed_dir, &auth).unwrap();
    assert_eq!(signed.trust, PackageTrust::AcceptedPublisher);
    assert!(signed.declared_capabilities().is_empty());
    let dev_dir = dev.join("pkg");
    write_tool(&dev_dir, "org.rustscript.tools.capdev");
    let dev_revision = store.install(&dev_dir, &auth).unwrap();
    assert_eq!(dev_revision.trust, PackageTrust::DevUnsigned);
    assert!(dev_revision.declared_capabilities().is_empty());
    drop(store);
    let store = reopen_store(&store_root, &auth);
    let loaded = store.load_installed().unwrap();
    assert_eq!(loaded.len(), 2);
    let signed_lock = resolve_tool(&store, "org.rustscript.tools.capsigned");
    let dev_lock = resolve_tool(&store, "org.rustscript.tools.capdev");
    assert!(
        signed_lock
            .closure
            .iter()
            .all(|item| item.effects.is_empty())
    );
    assert!(dev_lock.closure.iter().all(|item| item.effects.is_empty()));
    assert!(
        store
            .prepare(&signed_lock)
            .unwrap()
            .program("org.rustscript.tools.capsigned")
            .is_some()
    );
    assert!(
        store
            .prepare(&dev_lock)
            .unwrap()
            .program("org.rustscript.tools.capdev")
            .is_some()
    );
    assert_eq!(
        store.install(&signed_dir, &auth).unwrap().artifact_id,
        signed.artifact_id
    );
    assert_eq!(
        child_names(&store_root.join("artifacts")),
        child_names(&store_root.join("ledger"))
    );
}

#[test]
fn capture_bound_exact_file_count_installs_and_sixty_fifth_does_not_poison() {
    let root = CaptureDir::new("files");
    let dev = root.path().join("dev");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let auth = dev_auth(&dev);
    let healthy_dir = dev.join("healthy");
    write_tool(&healthy_dir, "org.rustscript.tools.caphealthy");
    let healthy = store.install(&healthy_dir, &auth).unwrap();
    let exact_dir = dev.join("exact");
    write_tool(&exact_dir, "org.rustscript.tools.capcount");
    write_extra_files(&exact_dir, CAPTURE_FILES - 2);
    assert_eq!(regular_file_count(&exact_dir), CAPTURE_FILES);
    let exact = store.install(&exact_dir, &auth).unwrap();
    let loaded = store.load_installed().unwrap();
    let exact_loaded = loaded
        .iter()
        .find(|package| package.artifact_id == exact.artifact_id)
        .unwrap();
    assert_eq!(exact_loaded.sources.len(), CAPTURE_FILES - 1);
    let over_dir = dev.join("over");
    write_tool(&over_dir, "org.rustscript.tools.capover");
    write_extra_files(&over_dir, CAPTURE_FILES - 1);
    assert_eq!(regular_file_count(&over_dir), CAPTURE_FILES + 1);
    match store.signature_payload(&over_dir) {
        Err(err) => assert_budget(err),
        Ok(_) => panic!("65 files must not be read as a payload"),
    }
    assert_budget(
        store
            .install(&over_dir, &auth)
            .expect_err("65 files must not be installed"),
    );
    drop(store);
    let store = reopen_store(&store_root, &auth);
    let loaded = store
        .load_installed()
        .expect("healthy and exact packages stay loadable");
    assert_eq!(loaded.len(), 2);
    let lock = resolve_tool(&store, "org.rustscript.tools.caphealthy");
    assert!(
        store
            .prepare(&lock)
            .unwrap()
            .program("org.rustscript.tools.caphealthy")
            .is_some()
    );
    assert_eq!(
        store.install(&healthy_dir, &auth).unwrap().artifact_id,
        healthy.artifact_id
    );
    assert_eq!(
        store.install(&exact_dir, &auth).unwrap().artifact_id,
        exact.artifact_id
    );
    let artifacts = child_names(&store_root.join("artifacts"));
    let ledger = child_names(&store_root.join("ledger"));
    assert_eq!(artifacts, ledger);
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts.iter().all(|name| !name.ends_with(".tmp")));
    assert!(artifacts.contains(&healthy.artifact_id));
    assert!(artifacts.contains(&exact.artifact_id));
}

#[test]
fn capture_bound_exact_file_bytes_are_readable_and_one_extra_byte_is_rejected() {
    let root = CaptureDir::new("file-byte");
    let dev = root.path().join("dev");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let auth = dev_auth(&dev);
    let healthy_dir = dev.join("healthy");
    write_tool(&healthy_dir, "org.rustscript.tools.caphealthy");
    let healthy = store.install(&healthy_dir, &auth).unwrap();
    let exact_dir = dev.join("exact");
    write_tool(&exact_dir, "org.rustscript.tools.capfile");
    let exact_pad = exact_dir.join("pad.bin");
    fs::File::create(&exact_pad)
        .unwrap()
        .set_len(CAPTURE_FILE_BYTES as u64)
        .unwrap();
    assert_eq!(
        fs::metadata(&exact_pad).unwrap().len(),
        CAPTURE_FILE_BYTES as u64
    );
    assert!(
        store.signature_payload(&exact_dir).is_ok(),
        "exactly 1MiB is inside the file bound"
    );
    let over_dir = dev.join("over");
    write_tool(&over_dir, "org.rustscript.tools.capfileover");
    let over_pad = over_dir.join("pad.bin");
    fs::File::create(&over_pad)
        .unwrap()
        .set_len((CAPTURE_FILE_BYTES + 1) as u64)
        .unwrap();
    let over_total: u64 = fs::read_dir(&over_dir)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert!(
        over_total < CAPTURE_TOTAL_BYTES as u64,
        "file fixture must not also cross the total bound"
    );
    match store.signature_payload(&over_dir) {
        Err(err) => assert_budget(err),
        Ok(_) => panic!("1MiB+1 must fail before an unbounded payload"),
    }
    assert_budget(
        store
            .install(&over_dir, &auth)
            .expect_err("1MiB+1 must not be installed"),
    );
    drop(store);
    let store = reopen_store(&store_root, &auth);
    let loaded = store.load_installed().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].artifact_id, healthy.artifact_id);
    assert_eq!(
        store.install(&healthy_dir, &auth).unwrap().artifact_id,
        healthy.artifact_id
    );
    assert_eq!(
        child_names(&store_root.join("artifacts")),
        vec![healthy.artifact_id.clone()]
    );
    assert_eq!(
        child_names(&store_root.join("ledger")),
        vec![healthy.artifact_id]
    );
}

#[test]
fn capture_bound_exact_total_bytes_are_readable_and_one_extra_byte_is_rejected() {
    let root = CaptureDir::new("total-byte");
    let dev = root.path().join("dev");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let auth = dev_auth(&dev);
    let healthy_dir = dev.join("healthy");
    write_tool(&healthy_dir, "org.rustscript.tools.caphealthy");
    let healthy = store.install(&healthy_dir, &auth).unwrap();
    let exact_dir = dev.join("exact");
    write_tool(&exact_dir, "org.rustscript.tools.captotal");
    fill_total(&exact_dir, CAPTURE_TOTAL_BYTES);
    assert!(max_regular_file(&exact_dir) <= CAPTURE_FILE_BYTES as u64);
    assert_eq!(tree_bytes(&exact_dir), CAPTURE_TOTAL_BYTES as u64);
    assert!(regular_file_count(&exact_dir) < CAPTURE_FILES);
    assert!(
        store.signature_payload(&exact_dir).is_ok(),
        "exactly 8MiB is inside the total bound"
    );
    let over_dir = dev.join("over");
    write_tool(&over_dir, "org.rustscript.tools.captotalover");
    fill_total(&over_dir, CAPTURE_TOTAL_BYTES + 1);
    assert!(
        max_regular_file(&over_dir) <= CAPTURE_FILE_BYTES as u64,
        "total fixture must not also cross the file bound"
    );
    assert_eq!(
        regular_file_count(&over_dir),
        regular_file_count(&exact_dir)
    );
    match store.signature_payload(&over_dir) {
        Err(err) => assert_budget(err),
        Ok(_) => panic!("8MiB+1 must fail before an unbounded payload"),
    }
    assert_budget(
        store
            .install(&over_dir, &auth)
            .expect_err("8MiB+1 must not be installed"),
    );
    drop(store);
    let store = reopen_store(&store_root, &auth);
    assert_eq!(store.load_installed().unwrap().len(), 1);
    assert_eq!(
        store.install(&healthy_dir, &auth).unwrap().artifact_id,
        healthy.artifact_id
    );
    assert_eq!(
        child_names(&store_root.join("artifacts")),
        vec![healthy.artifact_id.clone()]
    );
    assert_eq!(
        child_names(&store_root.join("ledger")),
        vec![healthy.artifact_id]
    );
}

#[test]
fn capture_bound_exact_depth_installs_and_one_past_is_rejected() {
    let root = CaptureDir::new("depth");
    let dev = root.path().join("dev");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let auth = dev_auth(&dev);
    let healthy_dir = dev.join("healthy");
    write_tool(&healthy_dir, "org.rustscript.tools.caphealthy");
    let healthy = store.install(&healthy_dir, &auth).unwrap();
    let depth_dir = dev.join("depth");
    write_tool(&depth_dir, "org.rustscript.tools.capdepth");
    nest_empty(&depth_dir, CAPTURE_DEPTH);
    assert_eq!(deepest_directory(&depth_dir), CAPTURE_DEPTH);
    let depth = store.install(&depth_dir, &auth).unwrap();
    let deep_over = dev.join("depth-over");
    write_tool(&deep_over, "org.rustscript.tools.capdepthover");
    nest_empty(&deep_over, CAPTURE_DEPTH + 1);
    match store.signature_payload(&deep_over) {
        Err(err) => assert_budget(err),
        Ok(_) => panic!("depth 33 must fail before unbounded recursion"),
    }
    assert_budget(
        store
            .install(&deep_over, &auth)
            .expect_err("depth 33 must not be installed"),
    );
    drop(store);
    let store = reopen_store(&store_root, &auth);
    assert_eq!(store.load_installed().unwrap().len(), 2);
    assert_eq!(
        store.install(&healthy_dir, &auth).unwrap().artifact_id,
        healthy.artifact_id
    );
    assert_eq!(
        store.install(&depth_dir, &auth).unwrap().artifact_id,
        depth.artifact_id
    );
    let artifacts = child_names(&store_root.join("artifacts"));
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts.iter().all(|name| !name.ends_with(".tmp")));
    assert_eq!(artifacts, child_names(&store_root.join("ledger")));
}

#[test]
fn capture_bound_exact_walk_installs_and_one_past_is_rejected() {
    let root = CaptureDir::new("walk");
    let dev = root.path().join("dev");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let auth = dev_auth(&dev);
    let healthy_dir = dev.join("healthy");
    write_tool(&healthy_dir, "org.rustscript.tools.caphealthy");
    let healthy = store.install(&healthy_dir, &auth).unwrap();
    let walk_dir = dev.join("walk");
    write_tool(&walk_dir, "org.rustscript.tools.capwalk");
    write_empty_dirs(&walk_dir, CAPTURE_WALK_ENTRIES - 3);
    assert_eq!(walk_nodes(&walk_dir), CAPTURE_WALK_ENTRIES);
    let walk = store.install(&walk_dir, &auth).unwrap();
    let walk_over = dev.join("walk-over");
    write_tool(&walk_over, "org.rustscript.tools.capwalkover");
    write_empty_dirs(&walk_over, CAPTURE_WALK_ENTRIES - 2);
    assert_eq!(walk_nodes(&walk_over), CAPTURE_WALK_ENTRIES + 1);
    match store.signature_payload(&walk_over) {
        Err(err) => assert_budget(err),
        Ok(_) => panic!("4097 walk nodes must fail before an unbounded listing"),
    }
    assert_budget(
        store
            .install(&walk_over, &auth)
            .expect_err("4097 walk nodes must not be installed"),
    );
    drop(store);
    let store = reopen_store(&store_root, &auth);
    assert_eq!(store.load_installed().unwrap().len(), 2);
    assert_eq!(
        store.install(&healthy_dir, &auth).unwrap().artifact_id,
        healthy.artifact_id
    );
    assert_eq!(
        store.install(&walk_dir, &auth).unwrap().artifact_id,
        walk.artifact_id
    );
    let artifacts = child_names(&store_root.join("artifacts"));
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts.iter().all(|name| !name.ends_with(".tmp")));
    assert_eq!(artifacts, child_names(&store_root.join("ledger")));
}

#[test]
fn capture_bound_fifo_and_internal_symlink_are_rejected_without_blocking_or_following() {
    let root = CaptureDir::new("special");
    let dev = root.path().join("dev");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let auth = dev_auth(&dev);
    let healthy_dir = dev.join("healthy");
    write_tool(&healthy_dir, "org.rustscript.tools.caphealthy");
    let healthy = store.install(&healthy_dir, &auth).unwrap();
    drop(store);
    let fifo_dir = dev.join("fifo");
    write_tool(&fifo_dir, "org.rustscript.tools.capfifo");
    let fifo = fifo_dir.join("pipe");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = mpsc::channel();
    let fifo_store = store_root.clone();
    let fifo_auth = auth.clone();
    thread::spawn(move || {
        let store = PackageStore::open(&fifo_store).unwrap();
        let result = store
            .install(&fifo_dir, &fifo_auth)
            .map(|_| ())
            .map_err(|err| err.kind);
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Err(PluginErrorKind::PathEscape)) => {}
        Ok(other) => panic!("fifo must be a typed non-regular rejection, got {other:?}"),
        Err(_) => panic!("fifo open blocked the formal install path"),
    }
    let link_dir = dev.join("link");
    write_tool(&link_dir, "org.rustscript.tools.caplink");
    std::os::unix::fs::symlink("invoke.rss", link_dir.join("alias.rss")).unwrap();
    let store = reopen_store(&store_root, &auth);
    assert_eq!(
        store.install(&link_dir, &auth).unwrap_err().kind,
        PluginErrorKind::SymlinkDenied
    );
    let loaded = store.load_installed().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].artifact_id, healthy.artifact_id);
    assert_eq!(
        child_names(&store_root.join("artifacts")),
        vec![healthy.artifact_id]
    );
}

fn fill_total(dir: &Path, total: usize) {
    let fixed = fs::metadata(dir.join("manifest.yaml")).unwrap().len() as usize
        + fs::metadata(dir.join("invoke.rss")).unwrap().len() as usize;
    assert!(fixed < CAPTURE_FILE_BYTES && total >= fixed);
    let mut remain = total - fixed;
    let mut index = 0usize;
    while remain > 0 {
        let chunk = remain.min(CAPTURE_FILE_BYTES);
        fs::File::create(dir.join(format!("pad{index:02}.bin")))
            .unwrap()
            .set_len(chunk as u64)
            .unwrap();
        remain -= chunk;
        index += 1;
        assert!(
            index + 2 <= CAPTURE_FILES,
            "total fixture must stay inside the file count"
        );
    }
}

fn tree_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry.file_type().unwrap().is_file() {
                total += entry.metadata().unwrap().len();
            }
        }
    }
    total
}

fn max_regular_file(dir: &Path) -> u64 {
    let mut max = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry.file_type().unwrap().is_file() {
                max = max.max(entry.metadata().unwrap().len());
            }
        }
    }
    max
}

fn nest_empty(dir: &Path, depth: usize) {
    let mut cursor = dir.to_path_buf();
    for _ in 0..depth {
        cursor.push("n");
        fs::create_dir(&cursor).unwrap();
    }
}

fn deepest_directory(dir: &Path) -> usize {
    let mut depth = 0usize;
    let mut cursor = dir.join("n");
    while cursor.is_dir() {
        depth += 1;
        cursor.push("n");
    }
    depth
}

fn write_empty_dirs(dir: &Path, count: usize) {
    for index in 0..count {
        fs::create_dir(dir.join(format!("e{index:04}"))).unwrap();
    }
}

fn walk_nodes(dir: &Path) -> usize {
    let mut nodes = 1usize;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() || kind.is_file() {
                nodes += 1;
                if kind.is_dir() {
                    pending.push(entry.path());
                }
            }
        }
    }
    nodes
}

fn cold_lib_manifest(id: &str) -> String {
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

fn cold_tool_manifest(id: &str, lib: &str) -> String {
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
dependencies:
  - alias: text
    id: {lib}
    version: "1.0.0"
capabilities:
  - workspace.read
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct:
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
      delegated: []
"#
    )
}

/// T05: a real signed catalog is installed, resolved, persisted, and then
/// re-resolved from a cold `PackageStore` after the warm store and repository
/// are dropped. The new resolve keeps the same plan semantics while the
/// original persisted lock id and package refs stay the exact stored object.
#[test]
fn cold_reopen_re_resolves_the_same_plan_and_preserves_the_persisted_lock() {
    let root = CaptureDir::new("cold-reresolve");
    let store_root = root.path().join("store");
    let store = PackageStore::open(&store_root).unwrap();
    let (pair, key) = signer();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![key],
        unsigned_dev_space: None,
    };
    let lib_id = "org.rustscript.lib.coldleaf";
    let tool_id = "org.rustscript.tools.coldtool";

    let lib_dir = root.path().join("lib");
    fs::create_dir_all(&lib_dir).unwrap();
    fs::write(lib_dir.join("manifest.yaml"), cold_lib_manifest(lib_id)).unwrap();
    fs::write(
        lib_dir.join("format.rss"),
        b"pub fn format(value: string) -> string { value }\n",
    )
    .unwrap();
    sign_package(&store, &pair, &lib_dir);
    let lib_revision = store
        .install(&lib_dir, &auth)
        .expect("signed leaf installs");

    let tool_dir = root.path().join("tool");
    fs::create_dir_all(&tool_dir).unwrap();
    fs::write(
        tool_dir.join("manifest.yaml"),
        cold_tool_manifest(tool_id, lib_id),
    )
    .unwrap();
    fs::write(
        tool_dir.join("invoke.rss"),
        b"pub fn invoke(context: map) -> map { context }\n",
    )
    .unwrap();
    sign_package(&store, &pair, &tool_dir);
    let tool_revision = store
        .install(&tool_dir, &auth)
        .expect("signed tool installs");

    let request = ResolveRequest {
        harness_selection: HarnessSelectionRequest::ToolOnly {
            tool_package: tool_id.to_string(),
        },
        roots: vec![PackageRequirement {
            id: tool_id.to_string(),
            version: "1.0.0".to_string(),
        }],
        host_runtime: HOST_RUNTIME.to_string(),
    };
    let original = store.resolve(&request).expect("signed catalog resolves");
    assert_eq!(original.packages.len(), 2, "the plan must carry the leaf");
    assert_eq!(
        original.edges.len(),
        1,
        "the dependency edge must be planned"
    );
    assert!(
        !original.closure.is_empty(),
        "the plan must carry the effect closure"
    );

    let db = root.path().join("gateway.db");
    let persistence = open(&db);
    let control = PluginControlStore::new(&persistence);
    let receipt = control.store_lock(&original).expect("original plan stores");
    assert_eq!(receipt.graph_id, original.graph_id);
    assert!(!receipt.idempotent);
    let stored_refs = control
        .package_refs(&original.graph_id)
        .expect("stored refs");
    assert_eq!(stored_refs, refs_of(&original));
    let stored_locks = control.list_locks().expect("stored lock list");
    persistence.shutdown();
    drop(persistence);
    drop(store);

    // Cold reopen from the same root: no warm verified cache or prepared graph.
    let cold = reopen_store(&store_root, &auth);
    let reopened = open(&db);
    let control = PluginControlStore::new(&reopened);
    let installed = cold.load_installed().expect("cold catalog captures");
    let cold_leaf = installed
        .iter()
        .find(|package| package.manifest.id == lib_id)
        .expect("cold catalog keeps the leaf revision");
    assert_eq!(cold_leaf.artifact_id, lib_revision.artifact_id);
    assert_eq!(cold_leaf.trust, lib_revision.trust);
    assert_eq!(cold_leaf.manifest.id, lib_id);
    assert_eq!(cold_leaf.manifest.version, "1.0.0");
    assert_eq!(cold_leaf.manifest.kind, "library");
    assert_eq!(cold_leaf.manifest.entry.export, "format");
    let cold_tool = installed
        .iter()
        .find(|package| package.manifest.id == tool_id)
        .expect("cold catalog keeps the tool revision");
    assert_eq!(cold_tool.artifact_id, tool_revision.artifact_id);
    assert_eq!(cold_tool.trust, tool_revision.trust);
    assert_eq!(cold_tool.manifest.id, tool_id);
    assert_eq!(cold_tool.manifest.version, "1.0.0");
    assert_eq!(cold_tool.manifest.kind, "tool");
    assert_eq!(cold_tool.manifest.entry.export, "invoke");
    assert_eq!(cold_tool.manifest.dependencies.len(), 1);

    // The persisted lock keeps its original object identity: same id, same
    // exact document, same refs, and a re-store is idempotent rather than a
    // new root with equal bytes.
    let loaded = control
        .load_lock(&original.graph_id)
        .expect("original persisted lock reads back")
        .lock;
    assert_eq!(loaded, original, "persisted lock identity changed");
    let restored = control.store_lock(&original).expect("re-store original");
    assert!(restored.idempotent, "identical re-store must be idempotent");
    assert_eq!(restored.graph_id, original.graph_id);
    assert_eq!(
        control.package_refs(&original.graph_id).expect("refs"),
        stored_refs
    );
    assert_eq!(control.list_locks().expect("locks"), stored_locks);

    // A fresh resolve is semantically identical but owns its own opaque id.
    let fresh = cold.resolve(&request).expect("cold re-resolve");
    assert_ne!(
        fresh.graph_id, original.graph_id,
        "a fresh resolve must not reuse the persisted lock id"
    );
    assert_eq!(
        fresh.packages, original.packages,
        "package revisions changed"
    );
    assert_eq!(fresh.edges, original.edges, "edges changed");
    assert_eq!(fresh.closure, original.closure, "closure changed");
    assert_eq!(fresh.harness_selection, original.harness_selection);
    assert_eq!(fresh.host_runtime, original.host_runtime);
    assert_eq!(fresh.compile_environment, original.compile_environment);
    assert_eq!(refs_of(&fresh), stored_refs, "artifact refs changed");
    reopened.shutdown();
}
