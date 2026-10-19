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
                        (
                            Arc::clone(&binding.policy_catalog),
                            Arc::clone(&binding.registry_snapshot)
                        ),
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
                    (
                        Arc::clone(&binding.policy_catalog),
                        Arc::clone(&binding.registry_snapshot)
                    ),
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
                (
                    Arc::clone(&binding.policy_catalog),
                    Arc::clone(&binding.registry_snapshot),
                ),
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
            pure.seal_call_policy("write_file", CapabilityRisk::Write, "{}")
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
async fn fresh_host_rejects_wrong_risk_name_arguments_and_registry_then_same_vm_executes_original()
{
    let (root, state) = native_fixture();
    fs::write(root.join("workspace/seed.txt"), b"seed").unwrap();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let weak = Arc::downgrade(&service);
    let checked = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&checked);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if seen.swap(true, Ordering::SeqCst) {
            return;
        }
        let service = weak.upgrade().unwrap();
        let binding = call.binding().unwrap();
        assert!(binding.call("second").is_none());
        let mut host = service
            .capability_host_bridges(&call.identity.owner.run_id)
            .unwrap()
            .unwrap();
        host.pinned_tool = service.retained_tool_for_test(&call.identity.owner.run_id);
        let args = json!({"path":"second.txt","content":"same VM authorized original"});
        let canonical = args.to_string();
        let context = json!({"run":call.identity.owner.run_id,"registry":call.identity.code.registry_identity,"arguments":canonical,"input":json!({"call":{"id":"second","name":"write_file","arguments":args},"config":service.run_context(&call.identity.owner.run_id).unwrap().limits}).to_string()});
        let native = crate::runtime::agent_host::AgentHostState {
            provider: Arc::new(ScriptedProvider::new()),
            cancellation: host.cancellation.clone().unwrap(),
            sleeps: Arc::clone(&host.sleeps),
            skip_sleep: host.skip_sleep,
            metrics: host.metrics.clone(),
            lifecycle: host.lifecycle.clone(),
            capability_owner: host.capability_owner.clone(),
            filesystem: host.filesystem.clone(),
            processes: host.processes.clone(),
            artifacts: host.artifacts.clone(),
            leases: Default::default(),
            control_hook: None,
            pinned_tool: host.pinned_tool.clone(),
            allow_stateless_pin: false,
            expected_call: None,
            provider_arguments: Default::default(),
        };
        let forged = json!({"tool_name":"write_file","call_id":"second","canonical_arguments":canonical,"canonical_input":context["input"],"run_id":call.identity.owner.run_id,"registry_identity":call.identity.code.registry_identity,"argument_digest":canonical,"risk_class":"read","summary":"original","untrusted_graph_id":"","operation":"workspace_read","permissions":["workspace_write","foreground_process"]});
        assert_eq!(
            native.invoke_managed_boundary_for_test(&forged)["ok"],
            false
        );
        assert!(binding.call("second").is_none());
        let changed = json!({"run_id":call.identity.owner.run_id,"call_id":call.identity.call_id,"tool_name":call.identity.tool_name,"argument_digest":call.original_arguments,"registry_identity":call.identity.code.registry_identity,"risk_class":"write","summary":"probe"});
        assert_eq!(
            native.changed_managed_child_prepare_for_test(
                Arc::clone(&call),
                &call.original_arguments,
                &changed
            )["code"],
            "pinned_call_mismatch"
        );
        let source = r#"pub fn run(context:map)->map {
            let run:string=context["run"];let registry:string=context["registry"];let args:string=context["arguments"];let input:string=context["input"];
            let attest:map=agent_runtime::approval_attest({run_id:run,call_id:"second",tool_name:"write_file",argument_digest:args,registry_identity:registry,risk_class:"read",summary:"original"});
            let risk:map=agent_runtime::invoke_pinned_tool({tool_name:"write_file",call_id:"second",canonical_arguments:args,canonical_input:input,run_id:run,registry_identity:registry,argument_digest:args,risk_class:"read",summary:"original",untrusted_graph_id:""});
            let execute:map=agent_runtime::invoke_pinned_tool({tool_name:"write_file",call_id:"second",canonical_arguments:args,canonical_input:input,run_id:run,registry_identity:registry,argument_digest:args,risk_class:"execute",summary:"original",untrusted_graph_id:""});
            let name:map=agent_runtime::invoke_pinned_tool({tool_name:"read_file",call_id:"second",canonical_arguments:args,canonical_input:input,run_id:run,registry_identity:registry,argument_digest:args,risk_class:"write",summary:"original",untrusted_graph_id:""});
            let arguments:map=agent_runtime::invoke_pinned_tool({tool_name:"write_file",call_id:"second",canonical_arguments:"{}",canonical_input:input,run_id:run,registry_identity:registry,argument_digest:"{}",risk_class:"write",summary:"original",untrusted_graph_id:""});
            let changed_registry:map=agent_runtime::invoke_pinned_tool({tool_name:"write_file",call_id:"second",canonical_arguments:args,canonical_input:input,run_id:run,registry_identity:"changed",argument_digest:args,risk_class:"write",summary:"original",untrusted_graph_id:""});
            let approve:map=agent_runtime::approval_attest({run_id:run,call_id:"second",tool_name:"write_file",argument_digest:args,registry_identity:registry,risk_class:"write",summary:"original"});
            let original:map=agent_runtime::invoke_pinned_tool({tool_name:"write_file",call_id:"second",canonical_arguments:args,canonical_input:input,run_id:run,registry_identity:registry,argument_digest:args,risk_class:"write",summary:"original",untrusted_graph_id:""});
            {attest:attest,risk:risk,execute:execute,name:name,arguments:arguments,changed_registry:changed_registry,approve:approve,original:original}
        }"#;
        let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
            .unwrap()
            .with_host(host);
        let result = crate::domain::vm_value_to_json(
            &runner
                .run_with_context(crate::domain::json_to_vm_value(&context))
                .unwrap(),
        );
        for key in [
            "attest",
            "risk",
            "execute",
            "name",
            "arguments",
            "changed_registry",
        ] {
            assert_eq!(result[key]["ok"], false, "{key}");
        }
        assert_eq!(result["approve"]["ok"], true);
        assert_eq!(result["original"]["ok"], true);
    }));
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"","tool_calls":[{"id":"first","name":"read_file","arguments":{"path":"seed.txt"}},{"id":"second","name":"write_file","arguments":{"path":"second.txt","content":"same VM authorized original"}}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    provider.push_ok(json!({"text":"done","tool_calls":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"real Native parent pair"}),
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
    assert!(checked.load(Ordering::SeqCst));
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id,
            },
            call_id: "second".into(),
        })
        .unwrap()
        .unwrap();
    let candidate = record.prepared.unwrap().candidate_root.unwrap();
    assert_eq!(
        fs::read(
            root.join(".gateway.sqlite.effects/trees")
                .join(candidate.object_id)
                .join("second.txt")
        )
        .unwrap(),
        b"same VM authorized original"
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn read_policy_denies_native_write_and_spawn_even_with_writable_export_union() {
    let (root, state) = native_fixture();
    fs::write(root.join("workspace/seed.txt"), b"original read bytes").unwrap();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let checked = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&checked);
    let weak = Arc::downgrade(&service);
    let sentinel = root.join("native-spawn-denied");
    let denied_sentinel = sentinel.clone();
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let binding = call.binding().unwrap();
        assert!(
            binding
                .contract
                .effects
                .iter()
                .any(|e| e.kind == "workspace.fs.write")
        );
        assert!(
            binding
                .contract
                .effects
                .iter()
                .any(|e| e.kind == "process.spawn")
        );
        // Exercise actual Native reservation tickets, separately from token
        // authorization. Detail objects are really written for the large cases.
        for (name, risk, multiplier, objects) in [
            ("read_file", CapabilityRisk::Read, 1, 2),
            ("write_file", CapabilityRisk::Write, 2, 4),
            ("terminal", CapabilityRisk::Execute, 2, 4),
        ] {
            for large in [false, true] {
                let text = if large {
                    "x".repeat(6000)
                } else {
                    "small".into()
                };
                let args = match risk {
                    CapabilityRisk::Read => json!({"path":text}),
                    CapabilityRisk::Write => json!({"path":"reservation.txt","content":text}),
                    CapabilityRisk::Execute => json!({"argv":["/bin/true"],"stdin":text}),
                }
                .to_string();
                let policy = binding.seal_call_policy(name, risk, &args).unwrap();
                let probe = binding
                    .register(
                        &format!("reservation-{name}-{large}"),
                        name,
                        &args,
                        policy,
                        call.identity.original_deadline_ms,
                    )
                    .unwrap();
                assert_eq!(probe._detail_object.is_some(), large);
                let limits = binding.admitted_limits.lock().unwrap();
                let bytes = binding.runtime.config.quota.max_bytes * multiplier
                    + (limits.output_budget as u64) * multiplier;
                assert!(probe.reservation.take_object(bytes + 1).is_err());
                let mut tickets = vec![probe.reservation.take_object(bytes).unwrap()];
                assert!(probe.reservation.take_object(1).is_err());
                for _ in 1..objects {
                    tickets.push(probe.reservation.take_object(0).unwrap());
                }
                assert!(probe.reservation.take_object(0).is_err());
                drop(tickets);
                probe.interrupt_unpublished();
            }
        }
        assert!(
            binding
                .seal_call_policy(
                    "terminal",
                    CapabilityRisk::Execute,
                    r#"{"argv":["/bin/true"],"background":true}"#
                )
                .is_err()
        );
        assert!(
            binding
                .seal_call_policy(
                    "process",
                    CapabilityRisk::Execute,
                    r#"{"action":"poll","process_id":"not-an-owned-handle"}"#
                )
                .is_err()
        );
        assert!(binding.call("process").is_none());
        let adapter = call.adapters.lock().clone().unwrap();
        let host = weak
            .upgrade()
            .unwrap()
            .capability_host_bridges(&call.identity.owner.run_id)
            .unwrap()
            .unwrap();
        let claims = host
            .lifecycle
            .unwrap()
            .authorize(
                &host.capability_owner.unwrap(),
                &adapter.token,
                CapabilityRisk::Read,
            )
            .unwrap();
        assert!(
            call.enter_operation(&claims, ManagedNativeOperation::FsWrite)
                .is_err()
        );
        assert!(
            call.enter_operation(&claims, ManagedNativeOperation::ProcessSpawn)
                .is_err()
        );
        let active: Vec<_> = (0..32)
            .map(|_| {
                call.enter_operation(&claims, ManagedNativeOperation::FsRead)
                    .unwrap()
            })
            .collect();
        assert!(
            call.enter_operation(&claims, ManagedNativeOperation::FsRead)
                .is_err()
        );
        drop(active);
        assert_eq!(*call.native_operations.lock(), 0);
        let spawns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&spawns);
        adapter
            .processes
            .set_before_os_spawn_hook(Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }));
        assert!(
            adapter
                .filesystem
                .write_atomic(&adapter.token, "denied.txt", "*", b"denied")
                .is_err()
        );
        assert!(
            adapter
                .processes
                .spawn(
                    &adapter.token,
                    &[
                        "/bin/sh".into(),
                        "-c".into(),
                        format!("printf denied > '{}'", denied_sentinel.display())
                    ],
                    ".",
                    &[],
                    ProcessLimits {
                        close_after_initial: true,
                        ..Default::default()
                    }
                )
                .is_err()
        );
        assert!(!adapter.work.path().join("denied.txt").exists());
        assert!(!denied_sentinel.exists());
        assert_eq!(spawns.load(Ordering::SeqCst), 0);
        assert_eq!(
            adapter
                .filesystem
                .read_range(&adapter.token, "seed.txt", 0, 100)
                .unwrap()
                .bytes,
            b"original read bytes"
        );
        observed.store(true, Ordering::SeqCst);
    }));
    let run = run_native_fixture(
        &service,
        json!({"id":"read","name":"read_file","arguments":{"path":"seed.txt"}}),
    )
    .await;
    assert!(checked.load(Ordering::SeqCst));
    assert!(!sentinel.exists());
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id,
            },
            call_id: "read".into(),
        })
        .unwrap()
        .unwrap();
    assert!(record.prepared.as_ref().unwrap().candidate_root.is_none());
    assert_eq!(
        record.prepared.as_ref().unwrap().operation_class,
        ManagedOperationClass::ReadOnly
    );
    assert_eq!(
        record.outcome.unwrap().disposition,
        ManagedPublicationStatus::ReadOnly
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn captured_policy_rejects_forged_risk_before_reservation_then_original_rss_writes() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let checked = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&checked);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let binding = call.binding().unwrap();
        assert!(
            binding
                .seal_call_policy(
                    &call.identity.tool_name,
                    CapabilityRisk::Read,
                    &call.original_arguments
                )
                .is_err(),
            "captured write class must reject read risk before any reservation"
        );
        assert!(binding.call("forged-risk").is_none());
        observed.store(true, Ordering::SeqCst);
    }));
    let run = run_native_fixture(&service, json!({"id":"original","name":"write_file","arguments":{"path":"allowed.txt","content":"original authorized bytes"}})).await;
    assert!(checked.load(Ordering::SeqCst));
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id,
            },
            call_id: "original".into(),
        })
        .unwrap()
        .unwrap();
    let candidate = record.prepared.unwrap().candidate_root.unwrap();
    assert_eq!(
        fs::read(
            root.join(".gateway.sqlite.effects/trees")
                .join(candidate.object_id)
                .join("allowed.txt")
        )
        .unwrap(),
        b"original authorized bytes"
    );
    drop(runtime);
    service.shutdown().await.unwrap();
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
            .object_references(
                &ManagedObjectReferencesRequest {
                    store_id: runtime.store_id.clone(),
                    object_id: adapter.view_id.clone()
                },
                &call.binding().unwrap().cancel
            )
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
        let spawns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&spawns);
        adapter
            .processes
            .set_before_os_spawn_hook(Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
            }));
        assert!(
            adapter
                .filesystem
                .write_atomic(&adapter.token, "execute-fs-write-denied", "*", b"denied")
                .is_err()
        );
        assert!(!adapter.work.path().join("execute-fs-write-denied").exists());
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
        assert_eq!(spawns.load(Ordering::SeqCst), 0);
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
