use super::*;
use crate::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, ScriptedProvider};

#[tokio::test(flavor = "multi_thread")]
async fn original_native_token_rejects_sibling_and_changed_claims_then_same_vm_writes_authorized_bytes()
 {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(format!(
        "managed-authority-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let workspace = root.join("workspace");
    let home = root.join("home");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&home).unwrap();
    for path in [&root, &workspace, &home] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
    let mut config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace,
            quota: super::super::ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: crate::config::ManagedRetentionLimits::default(),
        }),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    let state = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home);
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let weak = Arc::downgrade(&service);
    let checked = Arc::new(AtomicBool::new(false));
    let checked_in = Arc::clone(&checked);
    *runtime.native_write_observer.lock() = Some(Arc::new(move |call| {
        let service = weak.upgrade().unwrap();
        let host = service
            .capability_host_bridges(&call.identity.owner.run_id)
            .unwrap()
            .unwrap();
        let lifecycle = host.lifecycle.unwrap();
        let owner = host.capability_owner.unwrap();
        let adapter = call.adapters.lock().clone().unwrap();
        let original = lifecycle
            .authorize(&owner, &adapter.token, CapabilityRisk::Write)
            .unwrap();
        assert!(call.adapters("sibling-token-not-authority").is_err());
        assert!(
            adapter
                .filesystem
                .write_atomic("sibling-token-not-authority", "denied.txt", "*", b"denied")
                .is_err()
        );
        let mut variants = Vec::new();
        let mut wrong = original.clone();
        wrong.owner = CapabilityOwner::new("gateway", "different-session", owner.run()).unwrap();
        variants.push(("owner", wrong));
        let mut wrong = original.clone();
        wrong.call_id = "other-call".into();
        variants.push(("call", wrong));
        let mut wrong = original.clone();
        wrong.tool_name = "terminal".into();
        variants.push(("tool", wrong));
        let mut wrong = original.clone();
        wrong.argument_digest = "{}".into();
        variants.push(("arguments", wrong));
        let mut wrong = original.clone();
        wrong.registry_identity = "wrong-registry".into();
        variants.push(("registry", wrong));
        let mut wrong = original.clone();
        wrong.generation += 1;
        variants.push(("generation", wrong));
        let mut wrong = original.clone();
        wrong.deadline_ms += 1;
        variants.push(("deadline", wrong));
        let mut wrong = original.clone();
        wrong.workspace = PathBuf::from("/not-the-admitted-workspace");
        variants.push(("workspace", wrong));
        let mut wrong = original.clone();
        wrong.risk_ceiling = CapabilityRisk::Execute;
        variants.push(("risk", wrong));
        for (field, claims) in variants {
            assert!(
                call.authorize(&claims, CapabilityRisk::Write).is_err(),
                "changed {field} must fail before Native IO"
            );
        }
        let binding = call.binding().unwrap();
        for trust in [
            crate::plugins::PackageTrust::AcceptedPublisher,
            crate::plugins::PackageTrust::DevUnsigned,
        ] {
            let mut contract = binding.contract.clone();
            contract.trust = trust;
            assert!(
                binding
                    .runtime
                    .prepare_run_binding(
                        Arc::clone(&binding.authority),
                        binding.owner.clone(),
                        binding.code.clone(),
                        contract,
                        binding.cancel.clone()
                    )
                    .is_err(),
                "a signature or development trust cannot mint managed authority"
            );
        }
        let mut graph = binding.contract.clone();
        graph.single_builtin_graph = false;
        assert!(
            binding
                .runtime
                .prepare_run_binding(
                    Arc::clone(&binding.authority),
                    binding.owner.clone(),
                    binding.code.clone(),
                    graph,
                    binding.cancel.clone()
                )
                .is_err()
        );
        let mut pure = binding.contract.clone();
        pure.effects.clear();
        let pure = binding
            .runtime
            .prepare_run_binding(
                Arc::clone(&binding.authority),
                binding.owner.clone(),
                binding.code.clone(),
                pure,
                binding.cancel.clone(),
            )
            .unwrap();
        pure.bind_admitted_limits(
            FilesystemLimits::default(),
            ProcessLimits::default(),
            original.output_budget,
        )
        .unwrap();
        assert!(
            pure.register(
                "undeclared",
                "write_file",
                "{}",
                "write",
                original.deadline_ms
            )
            .is_err()
        );
        drop(pure);
        call.authorize(&original, CapabilityRisk::Write).unwrap();
        checked_in.store(true, Ordering::SeqCst);
    }));
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"","tool_calls":[{"id":"native","name":"write_file","arguments":{"path":"allowed.txt","content":"authorized original RSS bytes"}}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    provider.push_ok(json!({"text":"done","tool_calls":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"Native exact claims"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    assert!(
        checked.load(Ordering::SeqCst),
        "real RSS Native write must reach the claim checks"
    );
    let request = ManagedEffectGetRequest {
        owner: ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id,
            run_id: run.run_id,
        },
        call_id: "native".into(),
    };
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    let candidate = &record.prepared.unwrap().candidate_root.unwrap().object_id;
    assert_eq!(
        fs::read(
            root.join(".gateway.sqlite.effects/trees")
                .join(candidate)
                .join("allowed.txt")
        )
        .unwrap(),
        b"authorized original RSS bytes"
    );
    assert!(
        !root
            .join(".gateway.sqlite.effects/trees")
            .join(candidate)
            .join("denied.txt")
            .exists()
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}

fn native_fixture() -> (PathBuf, AgentGatewayState) {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(format!(
        "managed-native-ready-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let workspace = root.join("workspace");
    let home = root.join("home");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir(&home).unwrap();
    for path in [&root, &workspace, &home] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
    let mut config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace,
            quota: super::super::ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: crate::config::ManagedRetentionLimits::default(),
        }),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    config.approvals.process = "allow".into();
    let state = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home);
    (root, state)
}
async fn run_native_fixture(service: &Arc<crate::AgentService>, call: Value) -> crate::AdmittedRun {
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"","tool_calls":[call],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    provider.push_ok(json!({"text":"done","tool_calls":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"Native ready boundary"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    run
}
#[tokio::test(flavor = "multi_thread")]
async fn extra_native_descriptor_lease_retains_actual_final_view_even_with_empty_sdk_references() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let held = Arc::new(Mutex::new(None));
    let owner = Arc::clone(&held);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let adapter = call.adapters.lock().clone().unwrap();
        let binding = call.binding().unwrap();
        let lease = binding
            .runtime
            .leases
            .lease_existing_for_test(&adapter.view_id)
            .unwrap();
        *owner.lock() = Some((
            lease,
            Arc::clone(&adapter.root),
            adapter.work.path().to_owned(),
            Arc::clone(&call),
        ));
    }));
    let _run=run_native_fixture(&service,json!({"id":"lease-held","name":"write_file","arguments":{"path":"retained.txt","content":"original operation"}})).await;
    let retained = held
        .lock()
        .take()
        .expect("real Native second descriptor lease");
    let call = Arc::clone(&retained.3);
    let adapter = call.adapters.lock().clone().unwrap();
    assert!(
        runtime
            .repository
            .object_references(&ManagedObjectReferencesRequest {
                store_id: runtime.store_id.clone(),
                object_id: adapter.view_id.clone()
            })
            .unwrap()
            .is_empty()
    );
    assert!(*call.phase.lock() == CallPhase::Final);
    assert_eq!(*call.native_operations.lock(), 0);
    assert!(retained.2.join("retained.txt").is_file());
    assert!(matches!(
        call.cleanup_final_view(),
        ManagedViewRetention::Retained
    ));
    assert!(
        adapter
            .view_charge
            .lock()
            .as_ref()
            .is_some_and(|ticket| !ticket.sole_known_lease())
    );
    assert!(retained.2.is_dir());
    drop(retained);
    drop(adapter);
    drop(call);
    drop(runtime);
    service.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn valid_original_terminal_authority_rejects_native_close_after_initial_bypass_before_spawn_then_foreground_succeeds()
 {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let sentinel = root.join("native-bypass-sentinel");
    let forbidden = sentinel.clone();
    let checked = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&checked);
    let weak = Arc::downgrade(&service);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let adapter = call.adapters.lock().clone().unwrap();
        let service = weak.upgrade().unwrap();
        let host = service
            .capability_host_bridges(&call.identity.owner.run_id)
            .unwrap()
            .unwrap();
        let owner = host.capability_owner.unwrap();
        let claims = adapter
            .lifecycle
            .authorize(&owner, &adapter.token, CapabilityRisk::Execute)
            .unwrap();
        call.authorize(&claims, CapabilityRisk::Execute).unwrap();
        let denied = adapter.processes.spawn(
            &adapter.token,
            &[
                "/bin/sh".into(),
                "-c".into(),
                format!("printf x >> '{}'", forbidden.display()),
            ],
            ".",
            &[],
            ProcessLimits {
                close_after_initial: false,
                ..ProcessLimits::default()
            },
        );
        assert_eq!(
            denied.unwrap_err().code(),
            "managed_open_effect_unsupported"
        );
        assert!(!forbidden.exists());
        call.authorize(&claims, CapabilityRisk::Execute).unwrap();
        observed.store(true, Ordering::SeqCst);
    }));
    let run=run_native_fixture(&service,json!({"id":"foreground","name":"terminal","arguments":{"argv":["/bin/true"],"timeout_ms":1000}})).await;
    assert!(checked.load(Ordering::SeqCst));
    assert!(!sentinel.exists());
    let replay = service
        .replay_managed_call(ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id,
            },
            call_id: "foreground".into(),
        })
        .unwrap();
    let super::super::ManagedCallReplay::Final {
        canonical_result, ..
    } = replay
    else {
        panic!("authorized foreground result absent")
    };
    assert_eq!(
        serde_json::from_str::<Value>(canonical_result.as_str()).unwrap()["ok"],
        true
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}
