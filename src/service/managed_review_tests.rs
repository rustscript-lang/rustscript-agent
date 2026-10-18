use super::*;
use crate::effects::{EffectError, EffectErrorKind, ManagedEffectGetRequest, ManagedOwnerScope};
use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};

#[tokio::test(flavor = "multi_thread")]
async fn live_register_lookup_keeps_original_clock_and_never_enqueues_after_cancel_or_expiry() {
    let (_root, state) = fixture();
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"original lookup context"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let admitted = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .clone()
        .unwrap();
    let persistence = state.persistence().unwrap();
    let mut results = Vec::new();
    for target in ["effect.head", "effect.object_metadata"] {
        for expire in [false, true] {
            let original =
                crate::RunCancellation::with_timeout(std::time::Duration::from_millis(150));
            let binding = admitted.with_cancellation_for_test(original.clone());
            let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
            let capture = Arc::clone(&observed);
            let clock = original.clone();
            *persistence.managed_request_hook.lock().unwrap() =
                Some(Arc::new(move |op, cancel, enqueue| {
                    if op == target {
                        if !enqueue {
                            if expire {
                                std::thread::sleep(clock.remaining_deadline().unwrap());
                            } else {
                                clock.request(crate::CancellationReason::Requested);
                            }
                        }
                        capture
                            .lock()
                            .unwrap()
                            .push((enqueue, cancel.shares_original_clock(&clock)));
                    }
                }));
            let result = binding.register("lookup", "read_file", r#"{"path":"none"}"#, "read", 1);
            *persistence.managed_request_hook.lock().unwrap() = None;
            let rows = observed.lock().unwrap().clone();
            results.push((
                target,
                rows,
                result.is_err(),
                binding.call("lookup").is_none(),
            ));
        }
    }
    service.shutdown().await.unwrap();
    for (target, rows, denied, absent) in results {
        assert_eq!(
            rows,
            [(false, true)],
            "{target}: original context must reach request owner, with no enqueue after expiry/cancel"
        );
        assert!(denied && absent);
    }
}

struct LiveClockReplayProvider {
    binding: Arc<crate::effects::broker::ManagedRunBinding>,
    step: std::sync::atomic::AtomicUsize,
    replay: std::sync::Mutex<Option<Result<bool, String>>>,
}
impl crate::AgentProviderHost for LiveClockReplayProvider {
    fn call(&self, _request: &Value, _cancellation: &crate::RunCancellation) -> Value {
        let call = if self.step.fetch_add(1, std::sync::atomic::Ordering::AcqRel) == 0 {
            Some(
                json!({"id":"clock-write","name":"write_file","arguments":{"path":"clock.txt","content":"same"}}),
            )
        } else {
            *self.replay.lock().unwrap() = Some(
                self.binding
                    .replay_live("clock-write", "write_file", None, None)
                    .map(|result| result.is_some()),
            );
            None
        };
        json!({"ok":true,"response":response(call),"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_live_repository_callers_share_the_admitted_clock_through_replay_and_cleanup() {
    let (_root, state) = fixture();
    let service = state.service();
    let persistence = state.persistence().unwrap();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = Arc::clone(&observed);
    *persistence.managed_request_hook.lock().unwrap() =
        Some(Arc::new(move |op, cancel, enqueue| {
            if enqueue {
                capture
                    .lock()
                    .unwrap()
                    .push((op.to_string(), cancel.clone()));
            }
        }));
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"audit all actual live SDK paths"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let binding = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .clone()
        .unwrap();
    let provider = Arc::new(LiveClockReplayProvider {
        binding: Arc::clone(&binding),
        step: std::sync::atomic::AtomicUsize::new(0),
        replay: std::sync::Mutex::new(None),
    });
    service.inject_provider_host(provider.clone());
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    // The provider replay ran before terminal cleanup revoked the live grant.
    let replay = provider.replay.lock().unwrap().take();
    *persistence.managed_request_hook.lock().unwrap() = None;
    let rows = observed.lock().unwrap().clone();
    service.shutdown().await.unwrap();
    assert_eq!(replay, Some(Ok(true)));
    assert!(
        rows.iter()
            .all(|(_, clock)| clock.shares_original_clock(&binding.cancel))
    );
    for required in [
        "effect.workspace_get",
        "effect.workspace_register",
        "effect.head",
        "effect.object_metadata",
        "effect.get",
        "effect.begin",
        "effect.prepare",
        "effect.commit",
        "effect.object_refs",
    ] {
        assert!(
            rows.iter().any(|(op, _)| op == required),
            "missing actual production caller {required}"
        );
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn expired_original_lost_commit_ack_does_not_query_with_new_authority_and_fresh_read_recovers_once()
 {
    let (root, state) =
        fixture_config(|config| config.run_timeout = std::time::Duration::from_secs(10));
    let service = state.service();
    let persistence = state.persistence().unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    let sentinel = root.join("expired-ack-sentinel");
    provider.push_ok(response(Some(json!({"id":"expired-ack","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'; printf durable", sentinel.display())],"timeout_ms":1000}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"lost acknowledgement under original deadline"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let binding = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .clone()
        .unwrap();
    let original = binding.cancel.clone();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = Arc::clone(&observed);
    let committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let after_commit = Arc::clone(&committed);
    *persistence.managed_request_hook.lock().unwrap() =
        Some(Arc::new(move |op, cancel, enqueue| {
            if op == "effect.commit" && enqueue {
                after_commit.store(true, std::sync::atomic::Ordering::Release);
            }
            if op == "effect.get" && after_commit.load(std::sync::atomic::Ordering::Acquire) {
                if !enqueue {
                    std::thread::sleep(original.remaining_deadline().unwrap());
                }
                capture
                    .lock()
                    .unwrap()
                    .push((enqueue, cancel.shares_original_clock(&original)));
            }
        }));
    persistence.inject_drop_managed_commit_ack();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    *persistence.managed_request_hook.lock().unwrap() = None;
    let rows = observed.lock().unwrap().clone();
    let request = ManagedEffectGetRequest {
        owner: binding.owner.clone(),
        call_id: "expired-ack".into(),
    };
    let record = persistence.managed_effect_get(&request).unwrap().unwrap();
    let outcome = record.outcome.as_ref().unwrap();
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let replay = service.replay_managed_call(request.clone()).unwrap();
    let live = service.run_events(&run.run_id);
    service.shutdown().await.unwrap();
    assert_eq!(
        rows,
        [(false, true)],
        "lost ack must remain unknown in the expired live context; no additional SDK request"
    );
    assert!(committed.load(std::sync::atomic::Ordering::Acquire));
    assert!(!persistence.managed_commit_ack_drop_armed());
    assert!(
        live.iter()
            .all(|event| event["event_id"] != outcome.output_event.event_id)
    );
    assert!(matches!(
        replay,
        crate::effects::ManagedCallReplay::Final { .. }
    ));
    assert_eq!(head.head_version, 2);
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    drop(binding);
    drop(persistence);
    drop(service);
    drop(state);
    let config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: root.join("workspace"),
            quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
        }),
        ..Default::default()
    };
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(root.join("home"));
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    reopened.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_directory_sync_is_bottom_up_for_seed_and_prepare_and_fault_denies_publication() {
    for fault_phase in ["observe", "seed", "prepare"] {
        let (root, state) = fixture();
        fs::create_dir_all(root.join("workspace/nested/deep")).unwrap();
        fs::create_dir(root.join("workspace/nested/empty")).unwrap();
        fs::write(root.join("workspace/nested/deep/run"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(
            root.join("workspace/nested/deep/run"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let service = state.service();
        let runtime = service.inner.managed_effects.read().clone().unwrap();
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = Arc::clone(&observed);
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(fault_phase == "seed"));
        let inject = Arc::clone(&fail);
        *runtime.tree_sync.observer.lock() = Some(Arc::new(move |name, fd| {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) }, 0);
            let stat = unsafe { stat.assume_init() };
            assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFDIR);
            assert_eq!(stat.st_mode & 0o777, 0o555);
            capture.lock().unwrap().push(name.to_string());
            if name == "nested/deep" && inject.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(EffectError::new(
                    EffectErrorKind::Io,
                    "instance nested directory sync fault",
                ));
            }
            Ok(())
        }));
        let admission = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"nested immutable durability"}),
                    ..Default::default()
                },
                None,
            )
            .await;
        if fault_phase == "seed" {
            let denied = admission.is_err();
            let census = state
                .persistence()
                .unwrap()
                .managed_object_census()
                .unwrap();
            service.shutdown().await.unwrap();
            assert!(
                denied,
                "a seed child-directory fsync failure must deny admission"
            );
            assert!(
                census.is_empty(),
                "a failed seed cannot enter the synced registry"
            );
            continue;
        }
        let run = admission.unwrap();
        let binding = service
            .handle(&run.run_id)
            .unwrap()
            .pinned_tool
            .as_ref()
            .unwrap()
            .managed
            .clone()
            .unwrap();
        let before = state
            .persistence()
            .unwrap()
            .managed_workspace_head(&binding.workspace.identity)
            .unwrap();
        fail.store(
            fault_phase == "prepare",
            std::sync::atomic::Ordering::Release,
        );
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(Some(json!({"id":"nested-sync","name":"write_file","arguments":{"path":"nested/deep/new","content":"private"}}))));
        provider.push_ok(response(None));
        service.inject_provider_host(provider);
        service
            .clone()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;
        let persistence = state.persistence().unwrap();
        let after = persistence
            .managed_workspace_head(&binding.workspace.identity)
            .unwrap();
        let record = persistence
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: ManagedOwnerScope {
                    profile: "gateway".into(),
                    session_id: run.session_id,
                    run_id: run.run_id,
                },
                call_id: "nested-sync".into(),
            })
            .unwrap()
            .unwrap();
        let names = observed.lock().unwrap().clone();
        let census = persistence.managed_object_census().unwrap();
        service.shutdown().await.unwrap();
        if fault_phase == "observe" {
            assert_eq!(
                names,
                [
                    "nested/empty",
                    "nested/deep",
                    "nested",
                    "nested/empty",
                    "nested/deep",
                    "nested"
                ],
                "every created directory must really fsync after mode sealing, child before parent"
            );
            assert_eq!(after.head_version, before.head_version + 1);
            let tree = root
                .join(".gateway.sqlite.effects/trees")
                .join(&after.head_object_id);
            assert_eq!(
                fs::metadata(tree.join("nested/deep/run"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o555
            );
            assert!(tree.join("nested/empty").is_dir());
        } else {
            assert!(names.iter().filter(|name| *name == "nested/deep").count() >= 2);
            assert_eq!(after, before);
            assert!(record.prepared.is_none() && record.outcome.is_none());
            assert_eq!(
                census.len(),
                1,
                "failed candidate cannot be registered synced"
            );
            assert!(
                root.join(".gateway.sqlite.effects/trees")
                    .join(&before.head_object_id)
                    .exists()
            );
            assert!(
                fs::read_dir(root.join(".gateway.sqlite.effects/views"))
                    .unwrap()
                    .next()
                    .is_some(),
                "unknown private outcome remains retained"
            );
        }
    }
}
