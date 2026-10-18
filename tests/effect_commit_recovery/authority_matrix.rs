//! Additional production gates; each fixture owns its service and barrier.
use super::*;
#[tokio::test(flavor = "multi_thread")]
async fn managed_guardian_ask_retains_original_allow_deny_and_review_counts_without_reapproval_on_replay()
 {
    for allow in [true, false] {
        let fixture = ManagedFixture::new(|config| {
            config.approvals.write = "ask".into();
            config.approvals.process = "ask".into();
        });
        let provider = Arc::new(ScriptedProvider::new());
        let mut guardian = response(None);
        guardian["text"]=json!(json!({"outcome":if allow{"allow"}else{"deny"},"risk_level":"low","user_authorization":"unknown","rationale":"bounded synthetic request within the authorized workspace"}).to_string());
        provider.push_ok(response(Some(json!({"id":"reviewed-write","name":"write_file","arguments":{"path":"reviewed.txt","content":"reviewed bytes"}}))));
        provider.push_ok(guardian.clone());
        if allow {
            provider.push_ok(response(Some(json!({"id":"reviewed-terminal","name":"terminal","arguments":{"argv":["/bin/cat","reviewed.txt"],"timeout_ms":1000}}))));
            provider.push_ok(guardian);
            provider.push_ok(response(None));
        }
        fixture
            .state
            .service()
            .inject_provider_host(provider.clone());
        let run = fixture
            .state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"write the file then read it through the terminal"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        fixture
            .state
            .service()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;
        assert_eq!(
            provider.call_count(),
            if allow { 5 } else { 2 },
            "one Guardian review per write/execute action, no synthetic approvals; events={:?}",
            fixture
                .state
                .service()
                .run_events(&run.run_id)
                .iter()
                .filter(|event| event["event"] != "model.requested")
                .map(|event| (
                    &event["event"],
                    &event["data"]["error_code"],
                    &event["data"]["error_message"],
                    &event["data"]["code"]
                ))
                .collect::<Vec<_>>()
        );
        if allow {
            for call in ["reviewed-write", "reviewed-terminal"] {
                let request = ManagedFixture::request(&run, call);
                let record = fixture
                    .state
                    .persistence()
                    .unwrap()
                    .managed_effect_get(&request)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    record.identity.approval_basis,
                    rustscript_agent::effects::ManagedApprovalBasis::GuardianAttested
                );
                assert!(record.outcome.is_some());
                assert!(matches!(
                    fixture
                        .state
                        .service()
                        .replay_managed_call(request)
                        .unwrap(),
                    rustscript_agent::effects::ManagedCallReplay::Final { .. }
                ));
            }
            assert_eq!(provider.call_count(), 5);
        } else {
            assert!(
                fixture
                    .state
                    .persistence()
                    .unwrap()
                    .managed_effect_get(&ManagedFixture::request(&run, "reviewed-write"))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
                    .unwrap()
                    .count(),
                0
            );
        }
        assert!(!fixture.root.join("workspace/reviewed.txt").exists());
        fixture.state.service().shutdown().await.unwrap();
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn prepared_call_rechecks_current_source_store_marker_and_original_cancellation_before_linearization()
 {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedPublicationStatus};
    for cut in ["source", "source-symlink", "store", "marker", "cancel"] {
        let fixture = ManagedFixture::new(|_| {});
        let gate = fixture
            .state
            .service()
            .arm_managed_call_prepare_gate("fenced")
            .unwrap();
        let provider = Arc::new(ScriptedProvider::new());
        provider.push_ok(response(Some(json!({"id":"fenced","name":"write_file","arguments":{"path":"private.txt","content":"never-published"}}))));
        provider.push_ok(response(None));
        fixture.state.service().inject_provider_host(provider);
        let run = fixture
            .state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"recheck original authority"}),
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
        let arrival = gate.wait_arrived(1);
        if arrival.is_err() {
            gate.release();
            worker.await.unwrap();
            panic!("{cut}: preparation did not reach owned barrier: {arrival:?}");
        }
        let request = ManagedFixture::request(&run, "fenced");
        let before = fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert_eq!(before.state, ManagedPublicationStatus::Staged);
        let head = fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&before.identity.workspace)
            .unwrap();
        let source = fixture.root.join("workspace");
        let store = fixture.root.join(".gateway.sqlite.effects");
        match cut {
            "source" | "source-symlink" => {
                fs::rename(&source, fixture.root.join("old-source")).unwrap();
                if cut == "source" {
                    fs::create_dir(&source).unwrap();
                } else {
                    std::os::unix::fs::symlink(fixture.root.join("old-source"), &source).unwrap();
                }
            }
            "store" => {
                fs::rename(&store, fixture.root.join("old-store")).unwrap();
                fs::create_dir(&store).unwrap();
            }
            "marker" => {
                fs::rename(store.join("store-id"), store.join("old-marker")).unwrap();
                fs::write(store.join("store-id"), b"replaced-marker-not-authority").unwrap();
            }
            "cancel" => {
                fixture
                    .state
                    .service()
                    .handle(&run.run_id)
                    .unwrap()
                    .cancellation()
                    .request(rustscript_agent::CancellationReason::Requested);
            }
            _ => unreachable!(),
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
            "{cut}: current authority must be rechecked after preparation"
        );
        assert_eq!(after.prepared, before.prepared);
        assert_eq!(
            after.identity.original_deadline_ms,
            before.identity.original_deadline_ms
        );
        assert_eq!(
            fixture
                .state
                .persistence()
                .unwrap()
                .managed_workspace_head(&before.identity.workspace)
                .unwrap(),
            head
        );
        assert!(
            !fixture
                .state
                .service()
                .run_events(&run.run_id)
                .iter()
                .any(|event| event["event"] == "tool.completed")
        );
        match cut {
            "source" | "source-symlink" => {
                if cut == "source" {
                    fs::remove_dir(&source).unwrap();
                } else {
                    fs::remove_file(&source).unwrap();
                }
                fs::rename(fixture.root.join("old-source"), &source).unwrap();
            }
            "store" => {
                fs::remove_dir(&store).unwrap();
                fs::rename(fixture.root.join("old-store"), &store).unwrap();
            }
            "marker" => {
                fs::remove_file(store.join("store-id")).unwrap();
                fs::rename(store.join("old-marker"), store.join("store-id")).unwrap();
            }
            _ => {}
        }
        assert!(!source.join("private.txt").exists());
        let fixture = fixture.reopen().await;
        assert!(matches!(
            fixture
                .state
                .service()
                .replay_managed_call(request)
                .unwrap(),
            ManagedCallReplay::Staged { .. }
        ));
        fixture.state.service().shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_guardian_deny_preserves_business_review_and_prevents_intent_view_write_and_spawn()
{
    for tool in ["write_file", "terminal"] {
        let fixture = ManagedFixture::new(|config| {
            config.approvals.write = "deny".into();
            config.approvals.process = "deny".into();
        });
        let sentinel = fixture.root.join("denied-sentinel");
        let call = if tool == "write_file" {
            json!({"id":"denied","name":tool,"arguments":{"path":"denied.txt","content":"denied"}})
        } else {
            json!({"id":"denied","name":tool,"arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'",sentinel.display())],"timeout_ms":1000}})
        };
        let run = fixture.calls(vec![call]).await;
        assert!(!sentinel.exists());
        assert!(!fixture.root.join("workspace/denied.txt").exists());
        assert!(
            fixture
                .state
                .persistence()
                .unwrap()
                .managed_effect_get(&ManagedFixture::request(&run, "denied"))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
                .unwrap()
                .count(),
            0
        );
        assert!(
            !fixture
                .state
                .service()
                .run_events(&run.run_id)
                .iter()
                .any(|event| event["event"] == "tool.started")
        );
        let events = fixture.state.service().run_events(&run.run_id);
        assert!(
            events.iter().any(|event| event["event"] == "run.failed"
                && event["data"]["error_message"]
                    == "configured approval policy denied this action"),
            "retain the original RSS policy-denial observation"
        );
        fixture.state.service().shutdown().await.unwrap();
    }
}
