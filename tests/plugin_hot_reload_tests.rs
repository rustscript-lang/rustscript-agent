//! Stored graph permission review data never grants activation authority.

use std::path::PathBuf;

use rustscript_agent::plugins::{
    COMPILE_ENVIRONMENT, EffectOrigin, GraphLock, HOST_RUNTIME, LockedEdge, LockedEffect,
    LockedEffectItem, LockedPackage, PluginControlStore, ScopeBinding,
};
use rustscript_agent::{AgentGatewayConfig, GatewayPersistence};

// T16 G4 helpers: the existing signed-tool producer and the existing HTTP
// managed cycle stay unchanged; the solo graph case reuses them as-is. Each
// test binary compiles the shared support modules from source and exercises a
// subset of them, so the unused-in-this-binary part is allowed here only.
#[path = "support/plugin_effect_api_cycle.rs"]
#[allow(dead_code)]
mod plugin_effect_api_cycle;
#[path = "support/signed_tool_effects.rs"]
#[allow(dead_code)]
mod signed_tool_effects;

// The typed sample_lock fixture follows plugin_store_recovery_tests.
fn sample_lock(graph_id: &str, version: &str) -> GraphLock {
    let direct = EffectOrigin {
        relation: "direct".into(),
        caller_package: "org.example.tools".into(),
        caller_entry: "invoke".into(),
        alias: String::new(),
        callee_package: "org.example.tools".into(),
        callee_version: version.into(),
        callee_entry: "invoke".into(),
        version_requirement: String::new(),
    };
    let delegated = EffectOrigin {
        relation: "library".into(),
        alias: "files".into(),
        callee_package: "org.example.lib".into(),
        callee_version: "0.4.1".into(),
        version_requirement: "^0.4.1".into(),
        ..direct.clone()
    };
    GraphLock {
        graph_id: graph_id.into(),
        harness_selection: rustscript_agent::plugins::HarnessSelection::Unselected,
        host_runtime: HOST_RUNTIME.into(),
        compile_environment: COMPILE_ENVIRONMENT.into(),
        packages: vec![
            LockedPackage {
                id: "org.example.tools".into(),
                version: version.into(),
                kind: "tool".into(),
                artifact_id: format!("artifact-tools-{version}"),
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
                    via: direct,
                },
                LockedEffectItem {
                    kind: "workspace.fs.read".into(),
                    scope: "bound_workspace".into(),
                    recovery: "none".into(),
                    via: delegated,
                },
            ],
        }],
    }
}

fn open() -> GatewayPersistence {
    let base = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR").expect("lease TEMP"));
    let dir = base.join(format!("permission-diff-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("fixture directory");
    GatewayPersistence::open(&AgentGatewayConfig::default(), &dir.join("gateway.db"))
        .expect("production typed persistence")
}

// 421 phase A: synthetic narrow lock for one read-only tool plus one pure
// leaf library. Mirrors resolve output: ToolOnly selection, one
// library-relation edge, a single direct read on the tool entry, and an empty
// leaf entry.
fn phase_a_lock(graph_id: &str, leaf_artifact: &str) -> GraphLock {
    let direct = EffectOrigin {
        relation: "direct".into(),
        caller_package: "org.rustscript.tools.readliba".into(),
        caller_entry: "run".into(),
        alias: String::new(),
        callee_package: "org.rustscript.tools.readliba".into(),
        callee_version: "1.0.0".into(),
        callee_entry: "run".into(),
        version_requirement: String::new(),
    };
    GraphLock {
        graph_id: graph_id.into(),
        harness_selection: rustscript_agent::plugins::HarnessSelection::ToolOnly {
            tool_package: "org.rustscript.tools.readliba".into(),
        },
        host_runtime: HOST_RUNTIME.into(),
        compile_environment: COMPILE_ENVIRONMENT.into(),
        packages: vec![
            LockedPackage {
                id: "org.rustscript.lib.texta".into(),
                version: "1.0.0".into(),
                kind: "library".into(),
                artifact_id: leaf_artifact.into(),
            },
            LockedPackage {
                id: "org.rustscript.tools.readliba".into(),
                version: "1.0.0".into(),
                kind: "tool".into(),
                artifact_id: "artifact-tool-exact".into(),
            },
        ],
        edges: vec![LockedEdge {
            from: "org.rustscript.tools.readliba".into(),
            from_entry: "run".into(),
            alias: "text".into(),
            to: "org.rustscript.lib.texta".into(),
            to_version: "1.0.0".into(),
            to_artifact_id: leaf_artifact.into(),
            to_entry: "format".into(),
            relation: "library".into(),
            version_requirement: "1.0.0".into(),
            bindings: vec![],
        }],
        closure: vec![
            LockedEffect {
                package: "org.rustscript.lib.texta".into(),
                entry: "format".into(),
                effects: vec![],
            },
            LockedEffect {
                package: "org.rustscript.tools.readliba".into(),
                entry: "run".into(),
                effects: vec![LockedEffectItem {
                    kind: "workspace.fs.read".into(),
                    scope: "bound_workspace".into(),
                    recovery: "none".into(),
                    via: direct,
                }],
            },
        ],
    }
}

#[test]
fn phase_a_leaf_swap_needs_no_reapproval_and_hot_cut_advances() {
    use rustscript_agent::plugins::PackageArtifactRef;
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let before = phase_a_lock("graph-leaf-a", "artifact-leaf-a");
    let after = phase_a_lock("graph-leaf-b", "artifact-leaf-b");
    for lock in [&before, &after] {
        store.store_lock(lock).expect("legal phase-A graph");
    }
    let diff = readonly_diff(&store, &before.graph_id, &after.graph_id).expect("diff");
    assert!(
        !diff.requires_reapproval,
        "identical read-only permission with a new leaf revision: {diff:?}"
    );
    assert!(
        diff.metadata
            .package_revisions
            .iter()
            .any(|revision| revision.package == "org.rustscript.lib.texta"),
        "leaf revision change is still tracked: {diff:?}"
    );
    let refs = |lock: &GraphLock| {
        lock.packages
            .iter()
            .map(|package| PackageArtifactRef {
                package_id: package.id.clone(),
                version: package.version.clone(),
                kind: package.kind.clone(),
                artifact_id: package.artifact_id.clone(),
            })
            .collect::<Vec<_>>()
    };
    let pointer = store
        .activate(&before.graph_id, 0, &refs(&before))
        .expect("activate A");
    assert_eq!(pointer.graph_id, before.graph_id);
    let pointer = store
        .activate(&after.graph_id, pointer.generation, &refs(&after))
        .expect("hot cut to B");
    assert_eq!(pointer.graph_id, after.graph_id);
    assert_eq!(pointer.generation, 2);
    assert_eq!(store.activation_history().expect("history").len(), 2);
    persistence.shutdown();
}

#[test]
fn patch_direct_effect_addition_requires_reapproval_without_writes() {
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let before = sample_lock("graph-before", "1.0.0");
    let mut after = sample_lock("graph-after", "1.0.1");
    let mut added = after.closure[0].effects[0].clone();
    added.kind = "clock.read".into();
    added.scope = "bound_run".into();
    after.closure[0].effects.push(added);
    store.store_lock(&before).expect("valid old graph");
    store.store_lock(&after).expect("valid patch");
    let activation = store.activation().expect("activation before");
    let history = store.activation_history().expect("history before");
    let refs = store.package_refs(&before.graph_id).expect("refs before");
    let diff =
        readonly_diff(&store, &before.graph_id, &after.graph_id).expect("stored permission diff");
    assert!(
        diff.requires_reapproval,
        "new direct permission requires review"
    );
    assert!(
        format!("{diff:?}").contains("Added"),
        "diff explains addition: {diff:?}"
    );
    assert_eq!(diff.changes.len(), 1);
    assert_eq!(
        diff.changes[0].kind,
        rustscript_agent::plugins::PermissionChangeKind::Added
    );
    assert_eq!(diff.changes[0].identity.kind, "clock.read");
    assert_eq!(diff.changes[0].identity.relation, "direct");
    assert_eq!(store.activation().expect("activation after"), activation);
    assert_eq!(store.activation_history().expect("history after"), history);
    assert_eq!(
        store.package_refs(&before.graph_id).expect("refs after"),
        refs
    );
    persistence.shutdown();
}

#[test]
fn callee_effect_expansion_requires_review_for_patch_and_major_versions() {
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let before = sample_lock("graph-before", "1.0.0");
    store.store_lock(&before).expect("old graph");
    for (id, version) in [("graph-patch", "1.0.1"), ("graph-major", "2.0.0")] {
        let mut after = sample_lock(id, version);
        let mut added = after.closure[0].effects[1].clone();
        added.kind = "clock.read".into();
        added.scope = "bound_run".into();
        after.closure[0].effects.push(added);
        after.edges[0].bindings.push(ScopeBinding {
            kind: "clock.read".into(),
            scope: "bound_run".into(),
            recovery: "none".into(),
        });
        store.store_lock(&after).expect("valid delegated patch");
        let diff = readonly_diff(&store, &before.graph_id, id).expect("diff");
        assert!(
            diff.requires_reapproval,
            "callee expansion requires review: {diff:?}"
        );
        assert!(diff.changes.iter().any(|change| {
            change.identity.relation == "library" && change.identity.kind == "clock.read"
        }));
    }
    assert_eq!(
        store
            .activation()
            .expect("no automatic activation")
            .generation,
        0
    );
    assert!(store.activation_history().expect("no history").is_empty());
    persistence.shutdown();
}

#[test]
fn recovery_downgrade_requires_review_but_strengthening_does_not() {
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let mut checkpoint = sample_lock("graph-checkpoint", "1.0.0");
    checkpoint.closure[0].effects[0].kind = "workspace.fs.write".into();
    checkpoint.closure[0].effects[0].recovery = "checkpoint".into();
    let mut none = checkpoint.clone();
    none.graph_id = "graph-none".into();
    none.packages[0].version = "1.0.1".into();
    none.closure[0].effects[0].via.callee_version = "1.0.1".into();
    none.closure[0].effects[0].recovery = "none".into();
    store
        .store_lock(&checkpoint)
        .expect("legal checkpoint graph");
    store.store_lock(&none).expect("legal none graph");
    let down = readonly_diff(&store, &checkpoint.graph_id, &none.graph_id).expect("downgrade");
    assert!(
        down.requires_reapproval,
        "recovery guarantee reduced: {down:?}"
    );
    assert!(format!("{down:?}").contains("RecoveryDowngraded"));
    assert_eq!(
        down.changes[0].kind,
        rustscript_agent::plugins::PermissionChangeKind::RecoveryDowngraded
    );
    assert_eq!(down.changes[0].before[0].recovery, "checkpoint");
    assert_eq!(down.changes[0].after[0].recovery, "none");
    let up = readonly_diff(&store, &none.graph_id, &checkpoint.graph_id).expect("strengthening");
    assert!(
        !up.requires_reapproval,
        "strengthening does not reduce recovery"
    );
    assert!(format!("{up:?}").contains("RecoveryChanged"));
    assert!(!format!("{up:?}").contains("RecoveryDowngraded"));
    assert_eq!(
        up.changes[0].kind,
        rustscript_agent::plugins::PermissionChangeKind::RecoveryChanged
    );
    assert_eq!(store.activation().expect("unchanged").generation, 0);
    persistence.shutdown();
}

#[test]
fn identical_permissions_patch_remains_unchecked_and_explicit_cas_advances() {
    use rustscript_agent::plugins::{GraphRetention, PackageArtifactRef};
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let before = sample_lock("graph-old", "1.0.0");
    let mut after = sample_lock("graph-new", "1.0.1");
    after.packages.reverse();
    after.closure[0].effects.reverse();
    for lock in [&before, &after] {
        store.store_lock(lock).expect("legal lock");
    }
    let retention = GraphRetention {
        graph_id: before.graph_id.clone(),
        owner_kind: "run".into(),
        owner_id: "run-kept".into(),
        ref_id: "ref-kept".into(),
    };
    store.retain(&retention).expect("retain previous graph");
    let old_refs = store.package_refs(&before.graph_id).expect("old refs");
    store
        .activate(&before.graph_id, 0, &old_refs)
        .expect("explicit initial activation");
    let activation = store.activation().expect("before");
    let history = store.activation_history().expect("history before");
    let holds = store.retained(&before.graph_id).expect("holds before");
    let new_refs: Vec<PackageArtifactRef> = store.package_refs(&after.graph_id).expect("new refs");
    let diff = readonly_diff(&store, &before.graph_id, &after.graph_id).expect("patch diff");
    assert!(!diff.requires_reapproval);
    assert!(
        diff.changes.is_empty(),
        "revisions are not permission changes: {diff:?}"
    );
    assert!(
        format!("{diff:?}").contains("Unchecked"),
        "compatibility is unverified: {diff:?}"
    );
    assert_eq!(store.activation().expect("after diff"), activation);
    assert_eq!(
        store.activation_history().expect("history after diff"),
        history
    );
    assert_eq!(
        store.retained(&before.graph_id).expect("holds after"),
        holds
    );
    assert_eq!(
        store
            .package_refs(&before.graph_id)
            .expect("old refs after"),
        old_refs
    );
    assert_eq!(
        store.package_refs(&after.graph_id).expect("new refs after"),
        new_refs
    );
    let second = store
        .activate(&after.graph_id, activation.generation, &new_refs)
        .expect("explicit CAS");
    assert_eq!(second.generation, activation.generation + 1);
    let third = store
        .activate(&before.graph_id, second.generation, &old_refs)
        .expect("explicit return to retained graph");
    assert_eq!(third.generation, second.generation + 1);
    assert_eq!(store.activation().expect("read back"), third);
    let history = store.activation_history().expect("three activations");
    assert_eq!(history.len(), 3);
    assert_eq!(history[2].previous_graph_id, after.graph_id);
    assert_eq!(history[2].generation, 3);
    assert_eq!(
        store
            .activate(&after.graph_id, 1, &new_refs)
            .expect_err("stale CAS")
            .code,
        "plugin_activation_conflict"
    );
    assert_eq!(
        store
            .retained(&before.graph_id)
            .expect("retained old graph"),
        vec![retention]
    );
    persistence.shutdown();
}

// T13 stateful rollback: rolling back one stateful activation advances the
// generation, the old run stays on the old graph, and the referenced state
// root stays readable. Collection must not delete the referenced graph.
#[test]
fn stateful_rollback_advances_generation_and_keeps_referenced_state_root() {
    use rustscript_agent::plugins::{
        GraphRetention, PackageArtifactRef, PluginStateBindRequest, PluginStatePayload,
        PluginStateScope, PluginStateStore,
    };
    use std::sync::Arc;

    fn stateful_lock(graph_id: &str, version: &str) -> GraphLock {
        let direct = EffectOrigin {
            relation: "direct".into(),
            caller_package: "org.example.stateful".into(),
            caller_entry: "run".into(),
            alias: String::new(),
            callee_package: "org.example.stateful".into(),
            callee_version: version.into(),
            callee_entry: "run".into(),
            version_requirement: String::new(),
        };
        GraphLock {
            graph_id: graph_id.into(),
            harness_selection: rustscript_agent::plugins::HarnessSelection::ToolOnly {
                tool_package: "org.example.stateful".into(),
            },
            host_runtime: HOST_RUNTIME.into(),
            compile_environment: COMPILE_ENVIRONMENT.into(),
            packages: vec![LockedPackage {
                id: "org.example.stateful".into(),
                version: version.into(),
                kind: "tool".into(),
                artifact_id: format!("artifact-stateful-{version}"),
            }],
            edges: vec![],
            closure: vec![LockedEffect {
                package: "org.example.stateful".into(),
                entry: "run".into(),
                effects: vec![
                    LockedEffectItem {
                        kind: "workspace.fs.read".into(),
                        scope: "bound_workspace".into(),
                        recovery: "none".into(),
                        via: direct.clone(),
                    },
                    LockedEffectItem {
                        kind: "workspace.fs.write".into(),
                        scope: "bound_workspace".into(),
                        recovery: "checkpoint".into(),
                        via: direct,
                    },
                ],
            }],
        }
    }

    let persistence = Arc::new(open());
    let store = PluginControlStore::new(&persistence);
    let before = stateful_lock("graph-stateful-old", "1.0.0");
    let after = stateful_lock("graph-stateful-new", "1.0.1");
    for lock in [&before, &after] {
        store.store_lock(lock).expect("legal stateful graph");
    }
    let retention = GraphRetention {
        graph_id: before.graph_id.clone(),
        owner_kind: "run".into(),
        owner_id: "run-stateful-old".into(),
        ref_id: "ref-stateful-old".into(),
    };
    store.retain(&retention).expect("retain stateful graph");
    persistence
        .session_create(&serde_json::json!({
            "id": "session-stateful",
            "profile": "default",
            "platform": "plugin-hot-reload-test",
            "account_id": "session-stateful",
            "chat_id": "session-stateful",
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
            "now_ms": 10,
        }))
        .expect("seed session");
    persistence
        .run_create(&serde_json::json!({
            "id": "run-stateful-old",
            "session_id": "session-stateful",
            "parent_run_id": "",
            "input_json": "{}",
            "provider": "test-provider",
            "model": "test-model",
            "script_hash": "",
            "idempotency_scope": "",
            "idempotency_key": "",
            "now_ms": 11,
        }))
        .expect("seed run");
    let state = PluginStateStore::open(Arc::clone(&persistence));
    let bound = state
        .bind_run(&PluginStateBindRequest {
            run_id: "run-stateful-old".into(),
            session_id: "session-stateful".into(),
            workspace_id: "workspace-stateful".into(),
            branch_id: "branch-stateful".into(),
            plugin_id: "org.example.stateful".into(),
            package_id: "org.example.stateful".into(),
            artifact_id: "artifact-stateful-1.0.0".into(),
            scope: PluginStateScope::Run,
            graph_id: before.graph_id.clone(),
            epoch: 1,
            schema: 1,
            checkpoint_id: String::new(),
        })
        .expect("bind stateful root");
    let written = state
        .commit(
            &bound,
            &PluginStatePayload::parse(r#"{"count":1}"#).expect("payload"),
        )
        .expect("commit stateful value");
    assert_eq!(written.binding.revision, 2);
    let refs = |lock: &GraphLock| {
        lock.packages
            .iter()
            .map(|package| PackageArtifactRef {
                package_id: package.id.clone(),
                version: package.version.clone(),
                kind: package.kind.clone(),
                artifact_id: package.artifact_id.clone(),
            })
            .collect::<Vec<_>>()
    };
    let first = store
        .activate(&before.graph_id, 0, &refs(&before))
        .expect("activate stateful graph");
    assert_eq!(first.generation, 1);
    let second = store
        .activate(&after.graph_id, first.generation, &refs(&after))
        .expect("activate next graph");
    assert_eq!(second.generation, 2);
    let third = store
        .activate(&before.graph_id, second.generation, &refs(&before))
        .expect("rollback to stateful graph");
    assert_eq!(third.generation, second.generation + 1);
    assert_eq!(third.generation, 3);
    assert_eq!(third.graph_id, before.graph_id);
    assert_eq!(store.activation().expect("pointer after rollback"), third);
    let history = store.activation_history().expect("three activations");
    assert_eq!(history.len(), 3);
    assert_eq!(history[2].generation, 3);
    assert_eq!(history[2].previous_graph_id, after.graph_id);
    assert_eq!(
        store.retained(&before.graph_id).expect("old run stays"),
        vec![retention]
    );
    let key = rustscript_agent::plugins::PluginStateRootKey {
        owner_kind: "run".into(),
        owner_id: "run-stateful-old".into(),
        workspace_id: "workspace-stateful".into(),
        branch_id: "branch-stateful".into(),
        plugin_id: "org.example.stateful".into(),
    };
    let root = state
        .root(&key)
        .expect("read state root")
        .expect("referenced state root survives rollback");
    assert_eq!(root.object_id, written.binding.object_id);
    assert_eq!(root.revision, written.binding.revision);
    assert_eq!(
        state
            .object_payload(&root.object_id)
            .expect("read state object")
            .as_str(),
        written.payload.as_str()
    );
    let collected = store.collect_unreferenced().expect("collect");
    assert_eq!(collected, vec![after.graph_id.clone()]);
    assert_eq!(
        store
            .load_lock(&before.graph_id)
            .expect("referenced stateful graph loads")
            .lock,
        before
    );
    persistence.shutdown();
}

// T13 control-plane qualification: two management activations armed at the
// production precommit rendezvous both observe the same generation. Exactly
// one CAS winner persists; the loser is the existing typed conflict with no
// history or secondary activation root. A rollback to the run-pinned graph
// takes a new generation, the old run keeps its original graph/registry pin,
// and checkpoint/run refs keep still-referenced graphs out of collection.
#[test]
fn concurrent_activation_has_one_cas_winner_then_pinned_rollback_and_retention() {
    use rustscript_agent::plugins::{
        GraphRetention, HarnessSelection, PackageArtifactRef, PluginControlError,
    };
    use std::sync::Arc;

    fn pinnable_lock(graph_id: &str, version: &str) -> GraphLock {
        let mut lock = sample_lock(graph_id, version);
        lock.harness_selection = HarnessSelection::ToolOnly {
            tool_package: "org.example.tools".into(),
        };
        lock
    }

    /// One typed admission fact set for this concurrency case. Every argument
    /// is a distinct identity field of the single pinned admission the test
    /// submits, so a bag struct would only rename the same fields.
    #[allow(clippy::too_many_arguments)]
    fn pin_admission(
        session_id: &str,
        session_new: u32,
        run_id: &str,
        graph_id: &str,
        generation: u64,
        ref_id: &str,
        registry_identity: &str,
        now_ms: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "session_id": session_id,
            "session_new": session_new,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": session_id,
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "session_metadata_json": "{}",
            "run_id": run_id,
            "parent_run_id": "",
            "input_json": "{\"text\":\"read\"}",
            "message_id": format!("message-{run_id}"),
            "message_run_id": run_id,
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "proof",
            "workspace_identity_json": "",
            "event_id": format!("event-{run_id}"),
            "now_ms": now_ms,
            "expires_at_ms": 0,
            "tool_graph_id": graph_id,
            "tool_graph_generation": generation,
            "tool_ref_id": ref_id,
            "tool_pin_now_ms": now_ms,
            "tool_registry_identity": registry_identity,
            "registry_identity": registry_identity,
            "workspace": ""
        })
    }

    let persistence = Arc::new(open());
    let store = PluginControlStore::new(&persistence);
    let old = pinnable_lock("graph-t13-old", "1.0.0");
    let left_candidate = pinnable_lock("graph-t13-next-left", "1.0.1");
    let right_candidate = pinnable_lock("graph-t13-next-right", "2.0.0");
    let unreferenced = pinnable_lock("graph-t13-unreferenced", "1.0.2");
    for lock in [&old, &left_candidate, &right_candidate, &unreferenced] {
        store.store_lock(lock).expect("legal graph lock");
    }
    let refs = |lock: &GraphLock| {
        lock.packages
            .iter()
            .map(|package| PackageArtifactRef {
                package_id: package.id.clone(),
                version: package.version.clone(),
                kind: package.kind.clone(),
                artifact_id: package.artifact_id.clone(),
            })
            .collect::<Vec<_>>()
    };
    let first = store
        .activate(&old.graph_id, 0, &refs(&old))
        .expect("activate the run-pinned graph");
    assert_eq!(first.generation, 1);

    // The original run is pinned by the production admission transaction,
    // which also installs its run retention ref.
    persistence
        .admission_create(&pin_admission(
            "session-t13",
            1,
            "run-t13-old",
            &old.graph_id,
            first.generation,
            "ref-t13-old",
            "registry-t13-old",
            100,
        ))
        .expect("pin the original run");
    let old_pin = store.pin_for_run("run-t13-old").expect("original pin");
    assert_eq!(old_pin["pinned"], true);
    assert_eq!(old_pin["graph_id"], old.graph_id);
    assert_eq!(old_pin["generation"], first.generation);
    assert_eq!(old_pin["registry_identity"], "registry-t13-old");
    let old_requirement = store
        .pin_requirement_for_run("run-t13-old")
        .expect("required pin")
        .expect("original run is pin-required");
    assert_eq!(old_requirement.graph_id, old.graph_id);
    assert_eq!(old_requirement.ref_id, "ref-t13-old");
    let old_run_ref = GraphRetention {
        graph_id: old.graph_id.clone(),
        owner_kind: "run".into(),
        owner_id: "run-t13-old".into(),
        ref_id: "ref-t13-old".into(),
    };
    assert!(
        store
            .retained(&old.graph_id)
            .expect("refs")
            .contains(&old_run_ref)
    );

    // Checkpoint refs protect every candidate even before the race outcome
    // is known; the unactivated, unreferenced graph is the collection control.
    let checkpoints: Vec<GraphRetention> = [&old, &left_candidate, &right_candidate]
        .iter()
        .map(|lock| GraphRetention {
            graph_id: lock.graph_id.clone(),
            owner_kind: "checkpoint".into(),
            owner_id: format!("checkpoint-{}", lock.graph_id),
            ref_id: format!("ref-checkpoint-{}", lock.graph_id),
        })
        .collect();
    for checkpoint in &checkpoints {
        store.retain(checkpoint).expect("checkpoint retention ref");
    }

    // Both activations pass the same-generation precheck, then meet at the
    // existing production precommit rendezvous. Neither can commit before
    // the other arrives, so the race is deterministic and no sleep is used.
    let _gate = persistence.arm_plugin_control_precommit_gate(2);
    let spawn = |graph_id: &'static str, lock: GraphLock| {
        let persistence = Arc::clone(&persistence);
        std::thread::spawn(move || {
            PluginControlStore::new(&persistence).activate(graph_id, 1, &refs(&lock))
        })
    };
    let left = spawn("graph-t13-next-left", left_candidate.clone());
    let right = spawn("graph-t13-next-right", right_candidate.clone());
    let left = left.join().expect("left activation thread");
    let right = right.join().expect("right activation thread");
    drop(_gate);
    persistence.disarm_plugin_control_precommit_gate();
    let outcomes = [
        ("graph-t13-next-left", left),
        ("graph-t13-next-right", right),
    ];
    let successes = outcomes
        .iter()
        .filter_map(|(graph_id, outcome)| outcome.as_ref().ok().map(|pointer| (*graph_id, pointer)))
        .collect::<Vec<_>>();
    assert_eq!(successes.len(), 1, "exactly one CAS winner: {outcomes:?}");
    let (winner_graph, winner_pointer) = successes[0];
    assert_eq!(winner_pointer.generation, 2);
    let (loser_graph, loser) = outcomes
        .iter()
        .find(|(graph_id, _)| *graph_id != winner_graph)
        .expect("one losing candidate");
    let loser_error = loser
        .as_ref()
        .expect_err("the losing activation must be a typed conflict");
    assert_eq!(
        loser_error,
        &PluginControlError {
            code: "plugin_activation_conflict",
            message: "plugin activation generation does not match",
        },
        "no fixture error and no half activation: {loser:?}"
    );
    println!(
        "T13_CAS_RACE {}",
        serde_json::json!({
            "winner": winner_graph,
            "winner_generation": winner_pointer.generation,
            "loser": *loser_graph,
            "loser_code": loser_error.code,
        })
    );

    // The durable pointer and history agree with the one committed winner;
    // the loser keeps its lock and refs but has no history or activation root.
    let active = store.activation().expect("persistent pointer");
    assert_eq!(active, *winner_pointer);
    assert_eq!(store.activation_history().expect("history").len(), 2);
    let history = store.activation_history().expect("history after race");
    assert_eq!(history[0].graph_id, old.graph_id);
    assert_eq!(history[0].generation, 1);
    assert_eq!(history[1].graph_id, winner_graph);
    assert_eq!(history[1].generation, 2);
    assert_eq!(history[1].previous_graph_id, old.graph_id);
    assert!(
        !history.iter().any(|entry| entry.graph_id == *loser_graph),
        "loser must not leave a partial history root: {history:?}"
    );
    for graph in [&old, &left_candidate, &right_candidate] {
        assert_eq!(
            store
                .load_lock(&graph.graph_id)
                .expect("lock survives")
                .lock,
            *graph
        );
    }
    assert_eq!(
        store.package_refs(loser_graph).expect("loser refs"),
        refs(if *loser_graph == "graph-t13-next-left" {
            &left_candidate
        } else {
            &right_candidate
        }),
        "loser keeps its exact package refs"
    );

    // Rollback is a new generation, never a generation rewind.
    let activated_loser = store
        .activate(
            loser_graph,
            winner_pointer.generation,
            &refs(if *loser_graph == "graph-t13-next-left" {
                &left_candidate
            } else {
                &right_candidate
            }),
        )
        .expect("activate the losing candidate afterwards");
    assert_eq!(activated_loser.generation, 3);
    let rollback = store
        .activate(&old.graph_id, activated_loser.generation, &refs(&old))
        .expect("rollback to the run-pinned graph");
    assert_eq!(rollback.graph_id, old.graph_id);
    assert_eq!(rollback.generation, 4, "rollback advances, never rewinds");
    assert_eq!(
        store.activation().expect("pointer after rollback"),
        rollback
    );
    let history = store.activation_history().expect("four activations");
    assert_eq!(history.len(), 4);
    assert_eq!(history[2].graph_id, *loser_graph);
    assert_eq!(history[2].generation, 3);
    assert_eq!(history[2].previous_graph_id, winner_graph);
    assert_eq!(history[3].graph_id, old.graph_id);
    assert_eq!(history[3].generation, 4);
    assert_eq!(history[3].previous_graph_id, *loser_graph);
    let stale = store
        .activate(&old.graph_id, 1, &refs(&old))
        .expect_err("stale generation after rollback");
    assert_eq!(stale.code, "plugin_activation_conflict");
    assert_eq!(store.activation().expect("pointer after stale"), rollback);

    // The old run keeps the original graph and registry pin across the later
    // activations; refs were not rewritten by rollback.
    assert_eq!(
        store
            .pin_for_run("run-t13-old")
            .expect("old pin after rollback"),
        old_pin
    );
    assert_eq!(
        store
            .pin_requirement_for_run("run-t13-old")
            .expect("old requirement after rollback")
            .expect("still required"),
        old_requirement
    );
    let old_after = store
        .retained(&old.graph_id)
        .expect("old refs after rollback");
    assert!(old_after.contains(&old_run_ref));
    assert!(
        old_after.contains(
            checkpoints
                .iter()
                .find(|checkpoint| checkpoint.graph_id == old.graph_id)
                .expect("old checkpoint")
        )
    );

    // A subsequent run admits against the current persistent pointer, while
    // the old run's receipt stays byte-for-byte unchanged.
    let current = store.activation().expect("current pointer");
    persistence
        .admission_create(&pin_admission(
            "session-t13",
            0,
            "run-t13-new",
            &current.graph_id,
            current.generation,
            "ref-t13-new",
            "registry-t13-new",
            101,
        ))
        .expect("pin a subsequent run on the current pointer");
    let new_pin = store.pin_for_run("run-t13-new").expect("new pin");
    assert_eq!(new_pin["pinned"], true);
    assert_eq!(new_pin["graph_id"], current.graph_id);
    assert_eq!(new_pin["generation"], current.generation);
    assert_eq!(new_pin["registry_identity"], "registry-t13-new");
    assert_eq!(
        store.pin_for_run("run-t13-old").expect("old pin remains"),
        old_pin
    );

    // Referenced graphs survive collection; only the unreferenced control
    // graph is removed. Releasing checkpoint refs makes them collectible.
    let collected = store.collect_unreferenced().expect("bounded collection");
    assert_eq!(collected, vec![unreferenced.graph_id.clone()]);
    assert!(store.load_lock(&unreferenced.graph_id).is_err());
    for graph in [&old, &left_candidate, &right_candidate] {
        assert!(
            store.load_lock(&graph.graph_id).is_ok(),
            "referenced graph {} must survive collection",
            graph.graph_id
        );
    }
    for checkpoint in &checkpoints {
        store.release(checkpoint).expect("release checkpoint ref");
    }
    let mut expected_collected = vec![
        left_candidate.graph_id.clone(),
        right_candidate.graph_id.clone(),
    ];
    expected_collected.sort();
    assert_eq!(
        store
            .collect_unreferenced()
            .expect("collection after release"),
        expected_collected,
        "only released candidates become collectible"
    );
    assert!(store.load_lock(&old.graph_id).is_ok());
    assert_eq!(
        store
            .pin_for_run("run-t13-old")
            .expect("old pin after collection"),
        old_pin
    );

    persistence.shutdown();
}

#[test]
fn removed_effects_are_reported_with_compatibility_unchecked() {
    use rustscript_agent::plugins::CompatibilityCheck;
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let before = sample_lock("graph-full", "1.0.0");
    let mut after = sample_lock("graph-reduced", "1.0.1");
    after.closure[0].effects.clear();
    after.edges[0].bindings.clear();
    store.store_lock(&before).expect("full");
    store.store_lock(&after).expect("reduced");
    let diff = readonly_diff(&store, &before.graph_id, &after.graph_id).expect("diff");
    assert!(!diff.requires_reapproval);
    assert_eq!(diff.compatibility, CompatibilityCheck::Unchecked);
    assert!(
        format!("{diff:?}").contains("Removed"),
        "explain removals: {diff:?}"
    );
    assert_eq!(
        diff.changes
            .iter()
            .filter(|change| change.identity.relation == "direct")
            .count(),
        1
    );
    assert!(
        diff.changes
            .iter()
            .any(|change| change.identity.relation == "library")
    );
    assert_eq!(store.activation().expect("no activation").generation, 0);
    persistence.shutdown();
}

#[test]
fn delegated_binding_expansion_is_compared_even_with_unchanged_closure() {
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let before = sample_lock("graph-bind-old", "1.0.0");
    let mut after = sample_lock("graph-bind-new", "1.0.1");
    after.edges[0].bindings.push(ScopeBinding {
        kind: "clock.read".into(),
        scope: "bound_run".into(),
        recovery: "none".into(),
    });
    store.store_lock(&before).expect("old");
    store
        .store_lock(&after)
        .expect("expanded allowed delegation");
    let diff = readonly_diff(&store, &before.graph_id, &after.graph_id).expect("diff");
    assert!(
        diff.requires_reapproval,
        "edge upper bound expands: {diff:?}"
    );
    assert_eq!(diff.changes.len(), 1);
    assert!(format!("{diff:?}").contains("EdgeBinding"));
    assert_eq!(
        diff.changes[0].identity.location,
        rustscript_agent::plugins::PermissionLocation::EdgeBinding
    );
    assert_eq!(diff.changes[0].identity.kind, "clock.read");
    persistence.shutdown();
}

#[test]
fn pure_dependency_entry_and_edge_changes_remain_explicitly_unchecked() {
    use rustscript_agent::plugins::CompatibilityCheck;
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let mut before = sample_lock("graph-pure-old", "1.0.0");
    before.closure[0].effects.clear();
    before.edges[0].bindings.clear();
    store.store_lock(&before).expect("pure old graph");
    let mut after = before.clone();
    after.graph_id = "graph-pure-new".into();
    after.packages[1].version = "0.4.2".into();
    after.packages[1].artifact_id = "artifact-lib-new".into();
    after.edges[0].to_version = "0.4.2".into();
    after.edges[0].to_artifact_id = "artifact-lib-new".into();
    after.edges[0].alias = "renamed".into();
    after.edges[0].from_entry = "run".into();
    after.closure[0].entry = "run".into();
    store
        .store_lock(&after)
        .expect("valid pure dependency revision");
    let diff = readonly_diff(&store, &before.graph_id, &after.graph_id).expect("diff");
    assert!(!diff.requires_reapproval);
    assert!(diff.changes.is_empty());
    assert_eq!(diff.compatibility, CompatibilityCheck::Unchecked);
    let text = format!("{diff:?}");
    assert!(
        text.contains("edges_changed: true"),
        "edge changes must be visible: {text}"
    );
    assert!(
        text.contains("entries_changed: true"),
        "entry changes must be visible: {text}"
    );
    assert!(
        text.contains("0.4.2"),
        "revisions must be separate from permission changes: {text}"
    );
    assert!(diff.metadata.edges_changed);
    assert!(diff.metadata.entries_changed);
    assert_eq!(diff.metadata.package_revisions.len(), 1);
    assert_eq!(
        diff.metadata.package_revisions[0]
            .after
            .as_ref()
            .expect("candidate revision")
            .version,
        "0.4.2"
    );
    persistence.shutdown();
}

fn readonly_diff(
    store: &PluginControlStore<'_>,
    old: &str,
    new: &str,
) -> Result<rustscript_agent::plugins::PermissionDiff, rustscript_agent::plugins::PluginControlError>
{
    let snapshot = || {
        let ids = store.list_locks().expect("stored ids");
        let graphs = ids
            .iter()
            .map(|id| {
                (
                    store.load_lock(id).expect("exact graph"),
                    store.package_refs(id).expect("package refs"),
                    store.retained(id).expect("run/checkpoint refs"),
                )
            })
            .collect::<Vec<_>>();
        (
            ids,
            graphs,
            store.activation().expect("pointer"),
            store.activation_history().expect("history"),
        )
    };
    let before = snapshot();
    let diff = store.permission_diff(old, new);
    assert_eq!(
        snapshot(),
        before,
        "permission comparison is read-only even on error"
    );
    if let Ok(diff) = &diff {
        assert_eq!(
            diff.compatibility,
            rustscript_agent::plugins::CompatibilityCheck::Unchecked
        );
        let unique = diff
            .changes
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            unique.len(),
            diff.changes.len(),
            "no duplicate change items"
        );
        assert!(
            diff.changes.windows(2).all(|pair| pair[0] < pair[1]),
            "deterministic ordering"
        );
        assert!(diff.changes.len() <= 4 * 4096, "bounded change output");
    }
    diff
}

#[test]
fn ordering_duplicates_and_graph_ids_do_not_change_permission_semantics() {
    use rustscript_agent::plugins::PermissionLocation;
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let mut old = sample_lock("graph-order-old", "1.0.0");
    let mut other_entry = old.closure[0].clone();
    other_entry.package = "org.example.lib".into();
    other_entry.effects.clear();
    old.closure.push(other_entry);
    let mut other_edge = old.edges[0].clone();
    other_edge.alias = "other".into();
    other_edge.bindings.clear();
    old.edges.push(other_edge);
    let mut new = old.clone();
    new.graph_id = "graph-order-new".into();
    let mut added = new.closure[0].effects[0].clone();
    added.kind = "clock.read".into();
    added.scope = "bound_run".into();
    new.closure[0].effects.push(added.clone());
    let mut permuted = new.clone();
    permuted.graph_id = "graph-order-permuted".into();
    permuted.packages.reverse();
    permuted.edges.reverse();
    for edge in &mut permuted.edges {
        edge.bindings.reverse();
    }
    for entry in &mut permuted.closure {
        entry.effects.reverse();
    }
    permuted.closure.reverse();
    let mut duplicates = new.clone();
    duplicates.graph_id = "graph-order-duplicates".into();
    duplicates.closure[0].effects.push(added);
    let duplicate_binding = duplicates.edges[0].bindings[0].clone();
    duplicates.edges[0].bindings.push(duplicate_binding);
    for lock in [&old, &new, &permuted, &duplicates] {
        store.store_lock(lock).expect("valid ordering fixture");
    }
    let expected = readonly_diff(&store, &old.graph_id, &new.graph_id).expect("baseline diff");
    assert!(expected.requires_reapproval);
    assert_eq!(expected.changes.len(), 1);
    assert_eq!(
        expected.changes[0].identity.location,
        PermissionLocation::Closure
    );
    assert_eq!(
        readonly_diff(&store, &old.graph_id, &permuted.graph_id).expect("permuted diff"),
        expected
    );
    assert_eq!(
        readonly_diff(&store, &old.graph_id, &duplicates.graph_id).expect("deduplicated diff"),
        expected
    );
    assert!(
        readonly_diff(&store, &new.graph_id, &permuted.graph_id)
            .expect("identity-only diff")
            .changes
            .is_empty()
    );
    persistence.shutdown();
}

#[test]
fn revision_replacement_is_distinct_from_logical_callee_expansion() {
    use rustscript_agent::plugins::{GraphRetention, PermissionChangeKind};
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let old = sample_lock("graph-id-old", "1.0.0");
    let mut revision = sample_lock("graph-id-revision", "1.0.1");
    revision.packages[1].version = "0.4.2".into();
    revision.packages[1].artifact_id = "artifact-lib-revision".into();
    revision.edges[0].to_version = "0.4.2".into();
    revision.edges[0].to_artifact_id = "artifact-lib-revision".into();
    revision.closure[0].effects[1].via.callee_version = "0.4.2".into();
    let mut callee = revision.clone();
    callee.graph_id = "graph-id-callee".into();
    callee.packages[1].id = "org.example.other-lib".into();
    callee.edges[0].to = "org.example.other-lib".into();
    callee.closure[0].effects[1].via.callee_package = "org.example.other-lib".into();
    let mut alias = revision.clone();
    alias.graph_id = "graph-id-alias".into();
    alias.edges[0].alias = "other".into();
    alias.closure[0].effects[1].via.alias = "other".into();
    let mut entry = revision.clone();
    entry.graph_id = "graph-id-entry".into();
    entry.edges[0].to_entry = "run".into();
    entry.closure[0].effects[1].via.callee_entry = "run".into();
    let mut relation = revision.clone();
    relation.graph_id = "graph-id-relation".into();
    relation.packages[1].kind = "tool".into();
    relation.edges[0].relation = "plugin".into();
    relation.closure[0].effects[1].via.relation = "plugin".into();
    for lock in [&old, &revision, &callee, &alias, &entry, &relation] {
        store.store_lock(lock).expect("valid identity fixture");
    }
    let refs = store.package_refs(&old.graph_id).expect("initial refs");
    store
        .activate(&old.graph_id, 0, &refs)
        .expect("explicit starting activation");
    for owner_kind in ["run", "checkpoint"] {
        store
            .retain(&GraphRetention {
                graph_id: old.graph_id.clone(),
                owner_kind: owner_kind.into(),
                owner_id: format!("{owner_kind}-kept"),
                ref_id: format!("ref-{owner_kind}"),
            })
            .expect("existing durable ref");
    }
    let diff = readonly_diff(&store, &old.graph_id, &revision.graph_id).expect("revision only");
    assert!(!diff.requires_reapproval);
    assert!(diff.changes.is_empty());
    assert_eq!(diff.metadata.package_revisions.len(), 2);
    for candidate in [&callee, &alias, &entry, &relation] {
        let diff = readonly_diff(&store, &old.graph_id, &candidate.graph_id)
            .expect("logical callee change");
        assert!(
            diff.requires_reapproval,
            "new logical call identity requires review"
        );
        assert!(
            diff.changes
                .iter()
                .any(|change| change.kind == PermissionChangeKind::Added)
        );
        assert!(
            diff.changes
                .iter()
                .any(|change| change.kind == PermissionChangeKind::Removed)
        );
        assert!(diff.metadata.edges_changed);
    }
    persistence.shutdown();
}

#[test]
fn invalid_scope_and_missing_graph_errors_preserve_state_and_hide_paths() {
    let persistence = open();
    let store = PluginControlStore::new(&persistence);
    let old = sample_lock("graph-error-old", "1.0.0");
    store.store_lock(&old).expect("old");
    let mut invalid = old.clone();
    invalid.graph_id = "graph-error-invalid".into();
    invalid.closure[0].effects[0].scope = "invalid_second_scope".into();
    assert_eq!(
        store
            .store_lock(&invalid)
            .expect_err("validator remains strict")
            .code,
        "plugin_lock_invalid"
    );
    for (old_id, new_id) in [
        ("/private/permission-review-sentinel", old.graph_id.as_str()),
        (old.graph_id.as_str(), "/private/permission-review-sentinel"),
    ] {
        let error = readonly_diff(&store, old_id, new_id).expect_err("missing graph");
        assert_eq!(error.code, "plugin_graph_missing");
        assert!(!format!("{error:?}").contains("/private/"));
        assert!(!error.to_string().contains("permission-review-sentinel"));
    }
    assert_eq!(
        store.list_locks().expect("no invalid graph"),
        vec![old.graph_id]
    );
    persistence.shutdown();
}

// T16 G4: one signed ToolOnly tool graph is already a supported managed shape.
// The same validated topology activates it and executes a real Native read
// through the managed boundary, so revocation must accept it as well, tombstone
// it durably, keep the historical lock/refs/pin readable, refuse the next Native
// begin of an already pinned run, and keep refusing after a durable reopen.
mod solo_signed_tool_revocation {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{Value, json};

    use rustscript_agent::plugins::PluginControlStore;
    use rustscript_agent::{
        AgentGatewayState, AgentProviderHost, GatewayPersistence, RunCancellation, ScriptedProvider,
    };

    use super::plugin_effect_api_cycle::{
        Cycle, Http, activate, bound_store, contains_marker, event_names, explain, install_pair,
        shutdown_when_idle, stop_turn, tool_call, wait_until,
    };

    struct PausingToolProvider {
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        call_id: String,
        tool_name: String,
        arguments: Value,
        step: AtomicUsize,
    }

    fn pausing_tool_provider(
        call_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> (
        Arc<PausingToolProvider>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        (
            Arc::new(PausingToolProvider {
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(Some(release_rx)),
                call_id: call_id.to_string(),
                tool_name: tool_name.to_string(),
                arguments,
                step: AtomicUsize::new(0),
            }),
            entered_rx,
            release_tx,
        )
    }

    impl AgentProviderHost for PausingToolProvider {
        fn call(&self, _request: &Value, _cancellation: &RunCancellation) -> Value {
            if self.step.fetch_add(1, Ordering::SeqCst) > 0 {
                return json!({"ok": true, "response": stop_turn("after-tool"), "error": {}});
            }
            if let Some(entered) = self
                .entered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                let _ = entered.send(());
            }
            if let Some(release) = self
                .release
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                release
                    .recv_timeout(Duration::from_secs(60))
                    .expect("fixture must release the paused provider turn");
            }
            json!({
                "ok": true,
                "response": json!({
                    "text": "",
                    "tool_calls": [{
                        "id": self.call_id,
                        "name": self.tool_name,
                        "arguments": self.arguments,
                    }],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                    "reasoning": "",
                    "stop_reason": "tool_calls"
                }),
                "error": {}
            })
        }
    }

    fn terminal_event(events: &[Value]) -> Option<Value> {
        events
            .iter()
            .find(|event| {
                matches!(
                    event["event"].as_str(),
                    Some("run.completed") | Some("run.failed") | Some("run.cancelled")
                )
            })
            .cloned()
    }

    async fn effect_entries(http: &Http, token: &str, run_id: &str) -> Vec<Value> {
        let (status, effects) = http
            .request(
                "GET",
                &format!("/v1/runs/{run_id}/effects?limit=128"),
                json!(null),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{}", explain(status, &effects));
        effects["entries"].as_array().cloned().unwrap_or_default()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn solo_signed_tool_read_revoke_blocks_pinned_begin_and_survives_reopen() {
        let cycle = Cycle::open(&format!("solo-revoke-{}", uuid::Uuid::new_v4().simple()));
        let http = Http::bind(cycle.state.clone()).await;
        install_pair(&http, &cycle.token, &cycle.source).await;
        let (graph_a, generation) = activate(
            &http,
            &cycle.token,
            &cycle.config,
            &cycle.db,
            "org.rustscript.tools.effecta",
        )
        .await;
        std::fs::write(cycle.workspace.join("note.txt"), b"solo-read-marker\n").unwrap();
        std::fs::write(cycle.workspace.join("second.txt"), b"revoked-read-marker\n").unwrap();

        // The activated shape is the real solo signed tool graph: one package,
        // no edge, ToolOnly selection. Nothing here is a synthetic lock helper.
        {
            let persistence = GatewayPersistence::open(&cycle.config, &cycle.db).unwrap();
            let control = PluginControlStore::new(&persistence);
            let lock = control.load_lock(&graph_a).expect("stored solo lock").lock;
            assert_eq!(
                lock.packages
                    .iter()
                    .map(|package| package.id.clone())
                    .collect::<Vec<_>>(),
                vec!["org.rustscript.tools.effecta".to_string()],
                "the activated graph must carry exactly the signed tool"
            );
            assert!(
                lock.edges.is_empty(),
                "the activated graph must not be a delegation or leaf shape"
            );
            persistence.shutdown();
        }

        let (status, session) = http
            .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
            .await;
        assert_eq!(status, 201, "{}", explain(status, &session));
        let session_id = session["session"]["id"].as_str().unwrap().to_string();

        // A real read through the managed Native boundary proves the graph is
        // executable before it is revoked.
        let provider = ScriptedProvider::new();
        provider.push_ok(tool_call("solo-read-1", "read_file", "note.txt"));
        provider.push_ok(stop_turn("solo read done"));
        cycle
            .state
            .service()
            .inject_provider_host(Arc::new(provider));
        let (status, admitted) = http
            .request(
                "POST",
                "/v1/runs",
                json!({"session_id": session_id, "input": "read the solo signed graph"}),
                Some(&cycle.token),
                None,
            )
            .await;
        assert_eq!(status, 202, "{}", explain(status, &admitted));
        assert_eq!(admitted["graph_id"], graph_a.as_str());
        assert_eq!(admitted["activation_generation"], generation);
        let run_read = admitted["run_id"].as_str().unwrap().to_string();
        wait_until(|| {
            event_names(&cycle.state, &run_read)
                .iter()
                .any(|name| name == "run.completed")
        })
        .await;
        assert!(
            contains_marker(&cycle.state, &run_read, "solo-read-marker"),
            "the real Native read must deliver the stored bytes"
        );
        assert!(
            effect_entries(&http, &cycle.token, &run_read)
                .await
                .iter()
                .any(|entry| entry["call_id"] == "solo-read-1"),
            "the real Native read must register its managed receipt"
        );

        // Second run: admitted and pinned on the same solo graph, paused at the
        // provider turn before the tool begins.
        let (provider, entered, release) =
            pausing_tool_provider("solo-read-2", "read_file", json!({"path": "second.txt"}));
        cycle.state.service().inject_provider_host(provider);
        let (status, admitted) = http
            .request(
                "POST",
                "/v1/runs",
                json!({"session_id": session_id, "input": "read after the revocation"}),
                Some(&cycle.token),
                None,
            )
            .await;
        assert_eq!(status, 202, "{}", explain(status, &admitted));
        assert_eq!(admitted["graph_id"], graph_a.as_str());
        let run_held = admitted["run_id"].as_str().unwrap().to_string();
        entered
            .recv_timeout(Duration::from_secs(60))
            .expect("the worker must reach the provider after sealing the pin");

        let persistence = GatewayPersistence::open(&cycle.config, &cycle.db).unwrap();
        let control = PluginControlStore::new(&persistence);
        let activation_before = control.activation().expect("activation before revoke");
        let history_before = control
            .activation_history()
            .expect("activation history before revoke");
        let refs_before = control.package_refs(&graph_a).expect("refs before revoke");
        let held_before = control
            .retained(&graph_a)
            .expect("retained refs before revoke");
        let lock_before = control.load_lock(&graph_a).expect("lock before revoke");

        let fact = control
            .revoke_graph(&bound_store(&cycle.db, &cycle.auth), &graph_a)
            .expect("a supported solo signed tool graph must revoke");
        assert_eq!(fact.graph_id, graph_a);
        assert_eq!(
            control
                .graph_revocation(&graph_a)
                .expect("durable revocation read")
                .map(|fact| fact.graph_id),
            Some(graph_a.clone()),
            "the tombstone must be durably present"
        );
        assert_eq!(
            control
                .load_lock(&graph_a)
                .expect("historical lock stays readable"),
            lock_before,
            "revocation must not delete the historical lock"
        );
        assert_eq!(
            control
                .package_refs(&graph_a)
                .expect("historical refs stay readable"),
            refs_before,
            "revocation must not delete the historical refs"
        );
        assert_eq!(
            control
                .retained(&graph_a)
                .expect("historical retained refs stay readable"),
            held_before,
            "revocation must not delete the historical retention refs"
        );
        assert_eq!(
            control.activation().expect("activation after revoke"),
            activation_before,
            "revocation must not move the activation pointer"
        );
        assert_eq!(
            control.activation_history().expect("history after revoke"),
            history_before,
            "revocation must not rewrite activation history"
        );
        assert_eq!(
            control
                .pin_for_run(&run_held)
                .expect("historical pin stays readable")["graph_id"],
            graph_a.as_str(),
            "revocation must not delete the pinned run receipt"
        );
        persistence.shutdown();

        // Release the original provider turn: the already pinned Native read
        // must be refused before it begins.
        release.send(()).expect("release the paused provider turn");
        wait_until(|| terminal_event(&cycle.state.service().run_events(&run_held)).is_some()).await;
        let events = cycle.state.service().run_events(&run_held);
        assert!(
            !events.iter().any(|event| event["event"] == "tool.started"),
            "a revoked solo graph must not start the pinned call: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| event["event"] == "tool.completed"),
            "a revoked solo graph must not complete the pinned call: {events:?}"
        );
        let terminal = terminal_event(&events).expect("terminal event");
        assert_ne!(
            terminal["event"], "run.completed",
            "a revoked pinned solo run must not complete: {terminal}"
        );
        assert!(
            events
                .iter()
                .any(|event| event.to_string().contains("plugin_graph_revoked")),
            "the refusal must be the exact typed graph revocation: {events:?}"
        );
        assert!(
            !effect_entries(&http, &cycle.token, &run_held)
                .await
                .iter()
                .any(|entry| entry["call_id"] == "solo-read-2"),
            "a refused Native begin must not register a new managed receipt"
        );
        assert!(
            !contains_marker(&cycle.state, &run_held, "revoked-read-marker"),
            "the revoked pinned read must never deliver its bytes"
        );

        let (status, denied) = http
            .request(
                "POST",
                "/v1/runs",
                json!({"session_id": session_id, "input": "after the solo revocation"}),
                Some(&cycle.token),
                None,
            )
            .await;
        assert_eq!(status, 409, "{}", explain(status, &denied));
        assert_eq!(denied["error"]["code"], "plugin_graph_revoked");

        http.close().await;
        shutdown_when_idle(&cycle.state).await;
        let Cycle {
            root,
            source,
            db,
            token,
            config,
            auth,
            state,
            ..
        } = cycle;
        drop(state);

        // Durable reopen: the tombstone survives and still refuses admission on
        // the same stored activation pointer.
        {
            let persistence = GatewayPersistence::open(&config, &db).unwrap();
            let control = PluginControlStore::new(&persistence);
            assert!(
                control.graph_revocation(&graph_a).unwrap().is_some(),
                "the durable tombstone must survive reopen"
            );
            assert!(
                control.load_lock(&graph_a).is_ok(),
                "the historical lock must stay readable after reopen"
            );
            assert_eq!(control.activation().unwrap().graph_id, graph_a);
            persistence.shutdown();
        }
        let reopened = AgentGatewayState::with_sqlite_path(config.clone(), &db)
            .unwrap()
            .with_workspace_home(root.join("workspace-home"))
            .with_plugin_control(auth.clone(), source.clone(), "owner-space")
            .unwrap();
        let http = Http::bind(reopened.clone()).await;
        let (status, session) = http
            .request("POST", "/api/sessions", json!({}), Some(&token), None)
            .await;
        assert_eq!(status, 201, "{}", explain(status, &session));
        let session_id = session["session"]["id"].as_str().unwrap().to_string();
        let (status, denied) = http
            .request(
                "POST",
                "/v1/runs",
                json!({"session_id": session_id, "input": "after the durable reopen"}),
                Some(&token),
                None,
            )
            .await;
        assert_eq!(status, 409, "{}", explain(status, &denied));
        assert_eq!(denied["error"]["code"], "plugin_graph_revoked");
        http.close().await;
        shutdown_when_idle(&reopened).await;
    }
}
