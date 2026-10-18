use super::*;
#[tokio::test(flavor = "multi_thread")]
async fn failed_native_spawn_without_owned_terminal_evidence_remains_indeterminate_not_no_process()
{
    let fixture = ManagedFixture::new(|_| {});
    let run=fixture.calls(vec![json!({"id":"unknown-writer","name":"terminal","arguments":{"argv":["/nonexistent-managed-fixture-program"],"timeout_ms":1000}})]).await;
    let request = ManagedFixture::request(&run, "unknown-writer");
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(
        record.prepared.is_none(),
        "a Native spawn attempt without an owned terminal-status witness cannot certify NoProcess"
    );
    assert!(record.outcome.is_none());
    assert_eq!(
        fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap()
            .head_version,
        1
    );
    let fixture = fixture.reopen().await;
    assert!(matches!(
        fixture
            .state
            .service()
            .replay_managed_call(request)
            .unwrap(),
        rustscript_agent::effects::ManagedCallReplay::Indeterminate { .. }
    ));
    fixture.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_durable_reference_lookup_retains_owned_view_despite_final_success() {
    use rustscript_agent::effects::ManagedEffectFault;
    let fixture = CutFixture::write(ManagedEffectFault::ObjectReferenceUnavailable).await;
    let request = fixture.request();
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    assert_eq!(
        fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .count(),
        1,
        "no durable reference answer means no deletion, even for a positively settled Native owner"
    );
    fixture.state.service().shutdown().await.unwrap();
    let CutFixture {
        root,
        home,
        config,
        state,
        ..
    } = fixture;
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(home);
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    assert_eq!(
        fs::read_dir(root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .count(),
        1
    );
    reopened.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn replaced_prepared_tree_or_result_cannot_become_a_committed_missing_object() {
    for kind in ["tree", "result"] {
        let fixture = ManagedFixture::new(|_| {});
        let gate = fixture
            .state
            .service()
            .arm_managed_call_prepare_gate("ready")
            .unwrap();
        let provider = Arc::new(ScriptedProvider::new());
        provider.push_ok(response(Some(json!({"id":"ready","name":"write_file","arguments":{"path":"ready.txt","content":"synced original bytes"}}))));
        provider.push_ok(response(None));
        fixture.state.service().inject_provider_host(provider);
        let run = fixture
            .state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"seal then retain exact Native object identity"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let worker = tokio::spawn(
            fixture
                .state
                .service()
                .run_worker(run.run_id.clone(), "ignored".into()),
        );
        let arrived = gate.wait_arrived(1);
        if arrived.is_err() {
            gate.release();
            worker.await.unwrap();
            panic!("prepared object barrier absent: {arrived:?}");
        }
        let request = ManagedFixture::request(&run, "ready");
        let before = fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        let prepared = before.prepared.as_ref().unwrap();
        let path = if kind == "tree" {
            fixture
                .root
                .join(".gateway.sqlite.effects/trees")
                .join(&prepared.candidate_root.as_ref().unwrap().object_id)
        } else {
            fixture
                .root
                .join(".gateway.sqlite.effects/results")
                .join(&prepared.canonical_result.object_id)
        };
        let retained = path.with_extension("quarantine");
        fs::rename(&path, &retained).unwrap();
        if kind == "tree" {
            fs::create_dir(&path).unwrap();
        } else {
            fs::write(&path, b"replacement").unwrap();
        }
        gate.release();
        worker.await.unwrap();
        drop(gate);
        let after = fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert!(
            after.outcome.is_none(),
            "the exact prepared {kind} identity must be retained and checked before publication"
        );
        assert_eq!(
            fixture
                .state
                .persistence()
                .unwrap()
                .managed_workspace_head(&before.identity.workspace)
                .unwrap()
                .head_version,
            1
        );
        assert_eq!(after.prepared, before.prepared);
        assert!(!fixture.root.join("workspace/ready.txt").exists());
        if kind == "tree" {
            fs::remove_dir(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        fs::rename(retained, path).unwrap();
        let fixture = fixture.reopen().await;
        assert!(matches!(
            fixture
                .state
                .service()
                .replay_managed_call(request)
                .unwrap(),
            rustscript_agent::effects::ManagedCallReplay::Staged { .. }
        ));
        fixture.state.service().shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn physical_ready_objects_survive_actual_prepare_sql_rollback_without_registry_or_receipt_publication()
 {
    use rustscript_agent::effects::{
        ManagedCallReplay, ManagedEffectFault, ManagedObjectReferencesRequest,
    };
    let fixture = CutFixture::terminal(ManagedEffectFault::PrepareAfterObjectRegistry).await;
    let request = fixture.request();
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(
        record.prepared.is_none(),
        "a real SQL failure after object registration must roll back registry and receipt together"
    );
    assert!(record.outcome.is_none());
    assert_eq!(
        fs::read(fixture.root.join("external-sentinel")).unwrap(),
        b"x"
    );
    let store = fixture.root.join(".gateway.sqlite.effects");
    let mut orphan_ids = Vec::new();
    for namespace in ["trees", "results"] {
        for object in fs::read_dir(store.join(namespace)).unwrap() {
            let id = object.unwrap().file_name().into_string().unwrap();
            if id != record.identity.expected_head {
                assert!(
                    fixture
                        .state
                        .persistence()
                        .unwrap()
                        .managed_object_metadata(&ManagedObjectReferencesRequest {
                            store_id: record.identity.workspace.store_id.clone(),
                            object_id: id.clone()
                        })
                        .unwrap()
                        .is_none()
                );
                orphan_ids.push((namespace, id));
            }
        }
    }
    assert_eq!(
        orphan_ids.len(),
        3,
        "one candidate, original result and conflict result must physically precede the rejected SQL preparation"
    );
    fixture.state.service().shutdown().await.unwrap();
    let CutFixture {
        root,
        home,
        config,
        state,
        ..
    } = fixture;
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(home);
    assert!(matches!(
        reopened.service().replay_managed_call(request).unwrap(),
        ManagedCallReplay::Indeterminate { .. }
    ));
    for (namespace, id) in orphan_ids {
        assert!(
            root.join(".gateway.sqlite.effects")
                .join(namespace)
                .join(id)
                .exists(),
            "unregistered evidence must remain quarantined and charged after reopen"
        );
    }
    assert_eq!(fs::read(root.join("external-sentinel")).unwrap(), b"x");
    reopened.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_object_and_writer_io_faults_never_publish_and_reopen_without_reexecution() {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedEffectFault::*};
    for cut in [
        ResultPartialWrite,
        ResultFileFsync,
        TreeRename,
        SealedMetadata,
        TreeDirectoryFsync,
        WriterReap,
        WriterDrain,
    ] {
        let fixture = CutFixture::terminal(cut).await;
        let request = fixture.request();
        assert_eq!(
            fs::read(fixture.root.join("external-sentinel")).unwrap(),
            b"x",
            "the original terminal must have run exactly once before {cut:?}"
        );
        let before = fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert!(
            before.prepared.is_none(),
            "{cut:?}: failed immutable IO or writer settlement cannot mint prepared evidence"
        );
        assert!(before.outcome.is_none());
        let head = fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&before.identity.workspace)
            .unwrap();
        assert_eq!(head.head_version, 1);
        assert!(
            !fixture
                .state
                .service()
                .run_events(&fixture.run.run_id)
                .iter()
                .any(|event| event["event"] == "tool.completed")
        );
        fixture.state.service().shutdown().await.unwrap();
        let CutFixture {
            root,
            home,
            config,
            state,
            ..
        } = fixture;
        drop(state);
        let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
            .unwrap()
            .with_workspace_home(home);
        assert!(matches!(
            reopened.service().replay_managed_call(request).unwrap(),
            ManagedCallReplay::Indeterminate { .. }
        ));
        assert_eq!(
            reopened
                .persistence()
                .unwrap()
                .managed_workspace_head(&before.identity.workspace)
                .unwrap(),
            head
        );
        assert_eq!(fs::read(root.join("external-sentinel")).unwrap(), b"x");
        reopened.service().shutdown().await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn owned_cleanup_failure_retains_view_charge_and_exact_committed_reference_on_fresh_restart()
{
    use rustscript_agent::effects::ManagedEffectFault;
    let fixture = CutFixture::write(ManagedEffectFault::OwnedCleanup).await;
    let request = fixture.request();
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    let views = fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
        .unwrap()
        .map(|item| item.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        views.len(),
        1,
        "cleanup failure must retain the view and reservation, not discard its charge"
    );
    fixture.state.service().shutdown().await.unwrap();
    let CutFixture {
        root,
        home,
        config,
        state,
        ..
    } = fixture;
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(home);
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    assert_eq!(
        fs::read_dir(root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .count(),
        1
    );
    reopened.service().shutdown().await.unwrap();
}
