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
            maintenance_policy: Default::default(),
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
                "a signature flipped onto the embedding package, or development trust, cannot mint managed authority"
            );
        }
        let mut graph = binding.contract.clone();
        graph.topology = None;
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
        let mut unsigned_publisher = binding.contract.clone();
        unsigned_publisher.trust = crate::plugins::PackageTrust::AcceptedPublisher;
        unsigned_publisher.topology = None;
        let mut publisher_code = binding.code.clone();
        publisher_code.package_id = "publisher-tool".into();
        assert!(
            binding
                .runtime
                .prepare_run_binding(
                    Arc::clone(&binding.authority),
                    binding.owner.clone(),
                    publisher_code,
                    unsigned_publisher,
                    (
                        Arc::clone(&binding.policy_catalog),
                        Arc::clone(&binding.registry_snapshot)
                    ),
                    binding.cancel.clone()
                )
                .is_err(),
            "accepted publisher without a sealed topology cannot grant"
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
    native_fixture_config(|_| {})
}
pub(super) fn native_fixture_config(
    configure: impl FnOnce(&mut AgentGatewayConfig),
) -> (PathBuf, AgentGatewayState) {
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
            maintenance_policy: Default::default(),
        }),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    config.approvals.process = "allow".into();
    configure(&mut config);
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
            child_call: None,
            child_read: None,
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
            plugin_state_call: None,
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
                        false,
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
        // Current classification: a background producer and a process control
        // action are sealable; neither mints publication authority, and the
        // handle string still authorizes nothing.
        let background = binding
            .seal_call_policy(
                "terminal",
                CapabilityRisk::Execute,
                r#"{"argv":["/bin/true"],"background":true}"#,
            )
            .unwrap();
        assert_eq!(
            background.publication(),
            crate::effects::authority::ManagedPublicationAuthority::None
        );
        assert!(background.background());
        let control = binding
            .seal_call_policy(
                "process",
                CapabilityRisk::Execute,
                r#"{"action":"poll","process_id":"not-an-owned-handle"}"#,
            )
            .unwrap();
        assert_eq!(
            control.publication(),
            crate::effects::authority::ManagedPublicationAuthority::None
        );
        assert!(!control.background());
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

/// Minimal provider that reads the producer's returned handle out of the
/// previous tool result, so the continuation is a real same-run Native call.
struct SiblingCallsProvider {
    turns: std::sync::Mutex<usize>,
}

fn find_process_handle(value: &Value) -> Option<String> {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(id)) = fields.get("process_id") {
                return Some(id.clone());
            }
            fields.values().find_map(find_process_handle)
        }
        Value::Array(items) => items.iter().find_map(find_process_handle),
        _ => None,
    }
}

impl crate::AgentProviderHost for SiblingCallsProvider {
    fn call(&self, request: &Value, _cancel: &crate::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        *turns += 1;
        let turn = *turns;
        let handle = find_process_handle(request).unwrap_or_default();
        let reply = |call: Value| {
            json!({"text":"","tool_calls":[call],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"})
        };
        let response = match turn {
            1 => reply(json!({"id":"spawn","name":"terminal","arguments":{
                "argv":["/bin/sh","-c","sleep 0.5"],"background":true,"timeout_ms":3000}})),
            2 => reply(json!({"id":"poll","name":"process","arguments":{
                "action":"poll","process_id":handle}})),
            _ => json!({"text":"done","tool_calls":[],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"}),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_process_facades_share_the_run_table_without_sharing_call_authority() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    struct Seen {
        call_id: String,
        facade: Arc<crate::capabilities::ProcessCapability>,
        bound: Option<String>,
        attempts: usize,
        table: usize,
        token: String,
    }
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Seen>::new()));
    let record = Arc::clone(&seen);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let adapter = call.adapters.lock().clone().unwrap();
        record.lock().unwrap().push(Seen {
            call_id: call.identity.call_id.clone(),
            facade: Arc::clone(&adapter.processes),
            bound: adapter.processes.bound_call_id(),
            attempts: adapter.processes.spawn_attempts(),
            table: adapter.processes.table_len(),
            token: adapter.token.clone(),
        });
    }));
    let provider = Arc::new(SiblingCallsProvider {
        turns: std::sync::Mutex::new(0),
    });
    service.inject_provider_host(provider as Arc<dyn crate::AgentProviderHost>);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"sibling managed calls"}),
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
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "two managed calls bound their own facade");
    assert_eq!(seen[0].call_id, "spawn");
    assert_eq!(seen[1].call_id, "poll");
    // Each facade keeps the context it was created for. The later call can
    // never rebind the earlier call's Native authority (the previous design
    // shared one mutable current-call slot, so both read "poll").
    assert_eq!(seen[0].bound.as_deref(), Some("spawn"));
    assert_eq!(seen[1].bound.as_deref(), Some("poll"));
    assert!(
        !Arc::ptr_eq(&seen[0].facade, &seen[1].facade),
        "a later call must receive its own facade over the shared run table"
    );
    // The run resources are still shared: one cumulative spawn budget and one
    // child table behind both facades. The producer had not spawned yet when
    // its own facade was observed, so the later call already sees the charge.
    assert_eq!(seen[0].attempts, 0);
    assert_eq!(seen[1].attempts, 1);
    assert_eq!(seen[0].facade.spawn_attempts(), 1);
    assert_eq!(seen[1].facade.spawn_attempts(), 1);
    assert_eq!(seen[0].table, 0);
    assert_eq!(seen[1].table, 1, "the poll call sees the run's child");
    // Real Native negative control: the poll call's facade cannot borrow the
    // producer's open-child authority, and the refusal performs no OS spawn.
    let before = seen[1].facade.spawn_attempts();
    let denied = seen[1].facade.spawn(
        &seen[1].token,
        &["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
        ".",
        &[],
        crate::capabilities::ProcessLimits {
            close_after_initial: false,
            ..Default::default()
        },
    );
    assert!(denied.is_err(), "a sibling call cannot open a managed child");
    assert_eq!(seen[1].facade.spawn_attempts(), before, "no OS attempt charged");
    drop(seen);
    assert!(
        !root.join("workspace").join("produced").exists(),
        "no publication was inferred from a handle"
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// Deterministic per-turn tool script for the Native lifecycle tests.
struct TurnScript {
    turns: std::sync::Mutex<usize>,
    build: fn(usize, &str) -> Value,
}

impl crate::AgentProviderHost for TurnScript {
    fn call(&self, request: &Value, _cancel: &crate::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        *turns += 1;
        let turn = *turns;
        let handle = find_process_handle(request).unwrap_or_default();
        let reply = |call: Value| {
            json!({"text":"","tool_calls":[call],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"})
        };
        let response = match (self.build)(turn, &handle) {
            call if call.is_null() => json!({"text":"done","tool_calls":[],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"}),
            call => reply(call),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

async fn run_turn_script(
    service: &Arc<crate::AgentService>,
    build: fn(usize, &str) -> Value,
) -> crate::AdmittedRun {
    service.inject_provider_host(Arc::new(TurnScript {
        turns: std::sync::Mutex::new(0),
        build,
    }) as Arc<dyn crate::AgentProviderHost>);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"managed native lifecycle"}),
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

/// Every observed failure for one run: the run-level failure plus any per-tool
/// failure data. The branch writer refusals surface either at admission (run
/// failure) or at the tool step.
fn failure_text(service: &crate::AgentService, run_id: &str) -> String {
    service
        .run_events(run_id)
        .iter()
        .filter(|event| matches!(event["event"].as_str(), Some("tool.failed" | "run.failed")))
        .map(|event| event["data"].to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_branch_writer_gate_excludes_a_sibling_writer() {
    let (root, state) = native_fixture();
    let service = state.service();
    let run = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"producer","name":"terminal","arguments":{
            "argv":["/bin/sh","-c","sleep 3"],"background":true,"timeout_ms":5000}}),
        2 => json!({"id":"sibling","name":"write_file","arguments":{
            "path":"sibling.txt","content":"sibling"}}),
        _ => Value::Null,
    })
    .await;
    // The native bind refusal carries its exact typed message on the tool
    // result, while the run event keeps the stable public code.
    let results = serde_json::to_string(&service.session_messages(&run.session_id)).unwrap();
    assert!(
        results.contains("managed writer busy: open"),
        "a sibling writer on the branch must be refused: {results}"
    );
    assert!(
        failure_text(&service, &run.run_id).contains("managed_view_unavailable"),
        "the refusal keeps the existing public bind code"
    );
    assert!(
        service
            .run_events(&run.run_id)
            .iter()
            .any(|event| event["event"] == "run.completed"),
        "an ordinary bind refusal stays recoverable: {:?}",
        service.run_events(&run.run_id)
    );
    assert!(
        !root.join("workspace/sibling.txt").exists(),
        "the excluded writer performed no IO"
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
fn terminal_once(turn: usize, _: &str) -> Value {
    match turn {
        1 => json!({"id":"publish","name":"terminal","arguments":{
            "argv":["/bin/true"],"timeout_ms":2000}}),
        _ => Value::Null,
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn managed_unknown_commit_retains_finalizing_and_blocks_later_writers() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    runtime.arm_fault(super::ManagedEffectFault::CommitAfterDecision);
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some(binding);
        }
    }));
    let first = run_turn_script(&service, terminal_once).await;
    let branch = service
        .managed_runtime_for_test()
        .unwrap()
        .branches
        .lock()
        .keys()
        .next()
        .cloned()
        .expect("branch registered");
    assert_eq!(
        runtime.writer_phase_for_test(&branch),
        Some(super::ManagedWriterPhase::Finalizing),
        "an unknown commit outcome retains Finalizing and its owner"
    );
    // A later writer in a fresh run on the same branch cannot enter while the
    // unknown finalization is unresolved.
    let second = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"retry","name":"write_file","arguments":{
            "path":"after-unknown.txt","content":"late"}}),
        _ => Value::Null,
    })
    .await;
    let second_failures = failure_text(&service, &second.run_id);

    assert!(
        second_failures.contains("managed writer busy: finalizing"),
        "finalizing must exclude a later writer: {second_failures}"
    );
    assert!(!root.join("workspace/after-unknown.txt").exists());
    // A shutdown request must not overwrite the unknown state.
    if let Some(binding) = captured.lock().unwrap().clone() {
        binding.retain_unresolved_cleanup();
        assert_ne!(
            binding.cleanup_run(std::time::Duration::from_secs(1)),
            ManagedCleanup::Quiescent,
            "a retained finalizer is never reported clean"
        );
    }
    let _ = &first;
    assert_eq!(
        runtime.writer_phase_for_test(&branch),
        Some(super::ManagedWriterPhase::Finalizing)
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_cleanup_result_is_typed_idempotent_and_leaves_no_owner() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some(binding);
        }
    }));
    let run = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"producer","name":"terminal","arguments":{
            "argv":["/bin/sh","-c","sleep 5"],"background":true,"timeout_ms":6000}}),
        _ => Value::Null,
    })
    .await;
    let binding = captured.lock().unwrap().clone().expect("binding captured");
    let signals = binding.processes.lock().clone().map(|p| p.kill_signals());
    drop(run);
    let first = binding.cleanup_run(std::time::Duration::from_secs(2));
    let second = binding.cleanup_run(std::time::Duration::from_secs(2));
    assert_eq!(first, ManagedCleanup::Quiescent);
    assert_eq!(second, ManagedCleanup::Quiescent);
    assert_eq!(
        binding.processes.lock().clone().map(|p| p.kill_signals()),
        signals,
        "repeated cleanup must not signal a child again"
    );
    assert_eq!(
        binding.processes.lock().clone().map(|p| p.table_len()),
        Some(0)
    );
    assert!(!root.join("workspace").join("never").exists());
    drop(runtime);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_repeated_kill_observes_terminal_without_a_second_signal() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let seen: Arc<std::sync::Mutex<Vec<Arc<crate::capabilities::ProcessCapability>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let slot = Arc::clone(&seen);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let adapter = call.adapters.lock().clone().unwrap();
        slot.lock().unwrap().push(Arc::clone(&adapter.processes));
    }));
    let run = run_turn_script(&service, |turn, handle| match turn {
        1 => json!({"id":"spawn","name":"terminal","arguments":{
            "argv":["/bin/sh","-c","sleep 5"],"background":true,"timeout_ms":6000}}),
        2 => json!({"id":"kill","name":"process","arguments":{
            "action":"kill","process_id":handle}}),
        3 => json!({"id":"kill-again","name":"process","arguments":{
            "action":"kill","process_id":handle}}),
        _ => Value::Null,
    })
    .await;
    let facade = seen.lock().unwrap().first().cloned().expect("facade");
    assert_eq!(
        facade.kill_signals(),
        1,
        "a repeated kill must not send a second signal"
    );
    let results = service.session_messages(&run.session_id);
    let json = serde_json::to_value(results).unwrap();
    let blocks: Vec<Value> = json
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|message| message["content"].as_array().into_iter().flatten())
        .filter(|block| block["type"] == "tool_result")
        .cloned()
        .collect();
    assert!(blocks.len() >= 3, "three tool results: {blocks:?}");
    for block in &blocks[1..3] {
        assert_ne!(block["is_error"], true, "kill must succeed: {block:?}");
        assert_eq!(block["result"]["status"], "signaled", "{block:?}");
        assert_eq!(block["result"]["signal"], 9, "{block:?}");
    }
    // Kill publication receipt: the first kill is the Finalizing publisher of
    // the run's captured-base view, with real TreeWrite candidate/head/bytes;
    // the repeated kill stays terminal without a second signal.
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let owner = ManagedOwnerScope {
        profile: "gateway".into(),
        session_id: run.session_id.clone(),
        run_id: run.run_id.clone(),
    };
    let kill = state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedEffectGetRequest {
            owner,
            call_id: "kill".into(),
        })
        .unwrap()
        .expect("kill receipt");
    let prepared = kill.prepared.as_ref().expect("kill prepared");
    assert_eq!(prepared.operation_class, ManagedOperationClass::TreeWrite);
    assert_eq!(prepared.writer_state, ManagedWriterState::Settled);
    let outcome = kill.outcome.as_ref().expect("kill outcome");
    assert_eq!(outcome.disposition, ManagedPublicationStatus::Committed);
    let candidate = prepared.candidate_root.as_ref().expect("captured candidate");
    assert_eq!(outcome.publication.base_head, kill.identity.expected_head);
    assert_eq!(
        outcome.publication.candidate_head.as_deref(),
        Some(candidate.object_id.as_str())
    );
    assert_ne!(
        outcome.publication.candidate_head.as_deref(),
        Some(outcome.publication.base_head.as_str())
    );
    runtime.verify_tree(&candidate.object_id).expect("candidate root");
    let metadata = runtime
        .repository
        .object_metadata(
            &ManagedObjectReferencesRequest {
                store_id: candidate.store_id.clone(),
                object_id: candidate.object_id.clone(),
            },
            &cancel,
        )
        .unwrap()
        .expect("candidate metadata");
    assert_eq!(metadata, *candidate);
    let result = runtime
        .read_result(&outcome.canonical_result_ref)
        .expect("kill canonical result");
    assert_eq!(result["data"]["signal"], 9, "kill bytes: {result}");
    assert!(!root.join("workspace").join("never").exists());
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// S1 completion reservation on the one branch writer gate: an owning run with
/// an Open root reserves only with a proven quiescent child set, a file-only /
/// no-child run reserves from Idle while already admitted operations drain, and
/// an unknown drop never reopens the gate.
#[tokio::test(flavor = "multi_thread")]
async fn managed_completion_reservation_excludes_idle_admissions_and_needs_owner_quiescence() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    type Captured = (Arc<ManagedBranchState>, String, Arc<ManagedRunBinding>);
    let captured: Arc<std::sync::Mutex<Option<Captured>>> = Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if call.identity.call_id != "poll" {
            return;
        }
        let binding = call.binding().unwrap();
        let branch = Arc::clone(&binding.branch);
        let run_id = binding.owner.run_id.clone();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        // A live child is not quiescent, so the owner may not finalize.
        assert!(
            branch
                .reserve_completion_publication(
                    &run_id,
                    None,
                    || Err("owned child still live".to_string()),
                    deadline,
                )
                .is_err()
        );
        // A failed owner quiescence proof has already sealed every new
        // admission: the branch is retained Finalizing, never re-opened to the
        // run's own Open writer, until an explicit verified disposition.
        assert_eq!(branch.writer_phase(), ManagedWriterPhase::Finalizing);
        // A foreign run may never take this retained root.
        assert!(
            branch
                .reserve_completion_publication(
                    "other-run",
                    None,
                    || Ok(()),
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                )
                .is_err()
        );
        // The retained Finalizing owner ends only through an explicit verified
        // disposition, never by re-reading a stale Open assumption.
        assert!(branch.release_retained_completion_owner(&run_id));
        assert_eq!(branch.writer_phase(), ManagedWriterPhase::Idle);
        // With the owner's quiescence proof the same gate turns Finalizing.
        let reservation = branch
            .reserve_completion_publication(&run_id, None, || Ok(()), deadline)
            .expect("quiescent owner may reserve completion");
        assert_eq!(reservation.phase(), ManagedWriterPhase::Finalizing);
        assert!(
            branch
                .enter_checked(branch.epoch, (&run_id, "late-file"), || Ok(()))
                .is_err(),
            "finalizing excludes a new file admission"
        );
        assert!(
            branch
                .reserve_completion_publication(
                    &run_id,
                    None,
                    || Ok(()),
                    std::time::Instant::now() + std::time::Duration::from_secs(1)
                )
                .is_err(),
            "one completion reservation at a time"
        );
        // The verified disposition reopens the gate for this run's own work.
        assert!(reservation.dispose_verified());
        assert_eq!(branch.writer_phase(), ManagedWriterPhase::Idle);
        assert!(
            branch
                .enter_checked(branch.epoch, (&run_id, "after"), || Ok(()))
                .is_ok()
        );
        *slot.lock().unwrap() = Some((branch, run_id, binding));
    }));
    let run = run_turn_script(&service, |turn, handle| match turn {
        1 => json!({"id":"producer","name":"terminal","arguments":{
            "argv":["/bin/sh","-c","sleep 2"],"background":true,"timeout_ms":4000}}),
        2 => json!({"id":"poll","name":"process","arguments":{
            "action":"poll","process_id":handle}}),
        _ => Value::Null,
    })
    .await;
    let (branch, run_id, binding) = captured.lock().unwrap().clone().expect("captured");
    // The run terminal released the dead run's root: no stale Open owner.
    assert_eq!(branch.writer_phase(), ManagedWriterPhase::Idle);
    // File-only / no-child completion reserves from Idle.
    let reservation = branch
        .reserve_completion_publication(
            &run_id,
            None,
            || Ok(()),
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .expect("idle branch reserves completion");
    assert_eq!(reservation.phase(), ManagedWriterPhase::Finalizing);
    assert!(
        branch
            .enter_checked(branch.epoch, (&run_id, "contending"), || Ok(()))
            .is_err(),
        "a reserved completion excludes a contending file admission"
    );
    // Unknown outcome: dropping the reservation retains Finalizing.
    drop(reservation);
    assert_eq!(branch.writer_phase(), ManagedWriterPhase::Finalizing);
    assert_ne!(
        binding.cleanup_run(std::time::Duration::from_secs(1)),
        ManagedCleanup::Quiescent,
        "a retained completion owner is never reported clean"
    );
    assert!(
        branch
            .reserve_completion_publication(
                &run_id,
                None,
                || Ok(()),
                std::time::Instant::now() + std::time::Duration::from_secs(1)
            )
            .is_err(),
        "a retained Finalizing owner cannot be re-taken"
    );
    assert!(
        branch.release_retained_completion_owner(&run_id),
        "an explicit verified disposition releases the retained owner"
    );
    assert_eq!(branch.writer_phase(), ManagedWriterPhase::Idle);
    assert!(
        !branch.release_retained_completion_owner(&run_id),
        "a repeated disposition is a no-op"
    );
    assert_eq!(branch.writer_phase(), ManagedWriterPhase::Idle);
    assert!(!root.join("workspace").join("never").exists());
    drop(run);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// The successful public `PluginControlStore::revoke_graph` notifies the
/// registered Native owners of the same store, even when the call is made
/// through another store object on the same persistence.
#[tokio::test(flavor = "multi_thread")]
async fn managed_public_revoke_notifies_same_store_native_owners() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let persistence = state.persistence().unwrap();
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    let seen: Arc<std::sync::Mutex<Option<(usize, usize)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let seen_slot = Arc::clone(&seen);
    let weak = Arc::downgrade(&service);
    let observer_persistence = Arc::clone(&persistence);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if call.identity.call_id != "poll" {
            return;
        }
        let binding = call.binding().unwrap();
        assert!(
            binding.check().is_ok(),
            "the run is live during its native call"
        );
        let processes = binding
            .processes
            .lock()
            .clone()
            .expect("the producer established the run process table");
        let owned = (processes.table_len(), processes.spawn_attempts());
        assert_eq!(
            owned,
            (1, 1),
            "a real OS child is owned before the revoke, so a later empty table proves a reap"
        );
        *seen_slot.lock().unwrap() = Some(owned);
        // Another store object on the same persistence performs the public
        // revocation while this Native owner still owns a live child.
        let service = weak.upgrade().unwrap();
        let store = crate::plugins::PluginControlStore::new(&observer_persistence);
        store
            .revoke_graph(&service.tool_store().unwrap(), &binding.code.graph_id)
            .unwrap();
        *slot.lock().unwrap() = Some(binding);
    }));
    let run = run_turn_script(&service, |turn, handle| match turn {
        1 => json!({"id":"spawn","name":"terminal","arguments":{
            "argv":["/bin/sh","-c","sleep 2"],"background":true,"timeout_ms":4000}}),
        2 => json!({"id":"poll","name":"process","arguments":{
            "action":"poll","process_id":handle}}),
        _ => Value::Null,
    })
    .await;
    let binding = captured.lock().unwrap().clone().expect("binding captured");
    let owned = seen.lock().unwrap().expect("pre-revoke child observation");
    assert_eq!(
        owned,
        (1, 1),
        "the revoke happened with a real owned handle, not before any spawn"
    );
    let original_deadline = binding
        .cancel
        .deadline_instant()
        .expect("the admission's original clock");
    // The registry the runtime registered in is the store-scoped one, so a
    // second store object cannot bypass the notification.
    assert!(Arc::ptr_eq(
        &runtime.revoke_listeners,
        &persistence.managed_revoke_listeners
    ));
    assert!(
        binding.revoked.load(Ordering::SeqCst),
        "the public revoke notified the Native owner"
    );
    assert_eq!(
        binding.check().unwrap_err(),
        "plugin_graph_revoked",
        "a notified owner refuses further work"
    );
    assert!(
        binding.cancel.requested().is_some(),
        "the notified run is cancelled"
    );
    // The cancelled run reaches its terminal boundary and the one typed
    // cleanup really reaps the owned child: a graph revoke is not only a
    // notification or a later denied call.
    assert_eq!(
        *binding.cleanup.lock(),
        Some(ManagedCleanup::Quiescent),
        "revoke-driven terminal cleanup reached proven quiescence"
    );
    assert_eq!(
        binding.processes.lock().clone().map(|p| p.table_len()),
        Some(0),
        "the owned child was really reaped"
    );
    assert!(
        std::time::Instant::now() < original_deadline,
        "the real reap completed inside the admission's original clock"
    );
    assert_eq!(
        binding.processes.lock().clone().map(|p| p.spawn_attempts()),
        Some(1),
        "the reaped table is the same run that really spawned one OS child"
    );
    assert_eq!(
        binding.processes.lock().clone().map(|p| p.active_stdin_workers()),
        Some(0)
    );
    // Listeners are weak and run-lifetime bound: the live run keeps exactly one
    // and a finished run leaves nothing behind.
    drop(binding);
    assert_eq!(runtime.revoke_listeners.live(), 1);
    drop(run);
    service.shutdown().await.unwrap();
    // The terminated run record may still own its Native binding, but the
    // registry never accumulates: one notification prunes every dead slot, so
    // the stored slots equal the live owners.
    runtime.revoke_listeners.notify("no-such-graph");
    assert!(runtime.revoke_listeners.live() <= 1);
    assert_eq!(
        runtime.revoke_listeners.slot_count(),
        runtime.revoke_listeners.live(),
        "dead listeners are pruned, never cached"
    );
    drop(runtime);
}

/// A managed workspace state over an existing root, so one test can simulate a
/// process restart on the same durable store.
fn state_at(root: &std::path::Path) -> AgentGatewayState {
    let workspace = root.join("workspace");
    let home = root.join("home");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&home).unwrap();
    for path in [root, workspace.as_path(), home.as_path()] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
    let mut config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace,
            quota: super::super::ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: crate::config::ManagedRetentionLimits::default(),
            maintenance_policy: Default::default(),
        }),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    config.approvals.process = "allow".into();
    AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home)
}

/// Restart history: a durable managed row without a decided outcome leaves the
/// branch Unresolved, so no later writer may treat it as drained. A branch whose
/// rows are all decided resolves normally.
///
/// The reopen path itself is exercised elsewhere; here the derivation runs over
/// the durable history with the branch's "already derived" marker cleared, which
/// is exactly the state a fresh process starts in.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn managed_restart_history_is_unresolved_only_when_proof_is_incomplete() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<(ManagedWorkspaceIdentity, Arc<ManagedRunBinding>)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    let fault_runtime = Arc::downgrade(&runtime);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some((call.identity.workspace.clone(), binding));
        }
        // Cut the read-only call after its durable preparation: the row is
        // staged and no publication can be inferred from it.
        if call.identity.call_id == "staged"
            && let Some(runtime) = fault_runtime.upgrade()
        {
            runtime.arm_fault(super::ManagedEffectFault::AfterPrepared);
        }
    }));
    let _ = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"seed","name":"write_file","arguments":{
            "path":"seed.txt","content":"seed"}}),
        2 => json!({"id":"staged","name":"read_file","arguments":{
            "path":"seed.txt"}}),
        _ => Value::Null,
    })
    .await;
    let (identity, binding) = captured.lock().unwrap().clone().expect("identity");
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: "staged".into(),
        })
        .unwrap()
        .expect("staged row");
    assert!(record.outcome.is_none(), "no final result was ever decided");
    runtime.forget_restart_checked(&identity.branch_id);
    let branch = Arc::clone(&binding.branch);
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    assert_eq!(
        runtime.restart_gate(&branch, &identity.branch_id, &identity.workspace_id, &cancel),
        super::ManagedRestartGate::Unresolved,
        "an undecided durable row is never proof of drainage"
    );
    runtime.adopt_restart_gate(&branch, super::ManagedRestartGate::Unresolved);
    assert_eq!(branch.writer_phase(), super::ManagedWriterPhase::Unresolved);
    assert!(
        branch
            .enter_checked(branch.epoch, ("run", "call"), || Ok(()))
            .is_err(),
        "an unresolved restart gate excludes writers"
    );
    assert!(!root.join("workspace/seed.staged").exists());
    drop(binding);
    runtime.forget_restart_checked(&identity.branch_id);
    drop(runtime);
    service.shutdown().await.unwrap();

    // Positive: a branch whose rows are all decided resolves.
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<(ManagedWorkspaceIdentity, Arc<ManagedRunBinding>)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some((call.identity.workspace.clone(), binding));
        }
    }));
    let _ = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"decided","name":"write_file","arguments":{
            "path":"decided.txt","content":"decided"}}),
        _ => Value::Null,
    })
    .await;
    let (identity, binding) = captured.lock().unwrap().clone().expect("identity");
    runtime.forget_restart_checked(&identity.branch_id);
    let branch = Arc::clone(&binding.branch);
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    assert_eq!(
        runtime.restart_gate(&branch, &identity.branch_id, &identity.workspace_id, &cancel),
        super::ManagedRestartGate::Resolved,
        "a fully decided history resolves"
    );
    runtime.adopt_restart_gate(&branch, super::ManagedRestartGate::Resolved);
    assert_eq!(branch.writer_phase(), super::ManagedWriterPhase::Idle);
    assert!(
        branch
            .enter_checked(branch.epoch, ("run", "call"), || Ok(()))
            .is_ok(),
        "a resolved branch admits writers"
    );
    assert!(!root.join("workspace/decided.txt").exists());
    drop(binding);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// The 32-bound counts actual OS spawn attempts across the run and is not
/// refunded: a refused attempt after the bound sends no OS spawn, and the limit
/// is shared by every facade of the run.
#[tokio::test(flavor = "multi_thread")]
async fn managed_spawn_budget_counts_actual_os_attempts_and_is_not_refunded() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let outcomes = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let record = Arc::clone(&outcomes);
    let observed = Arc::new(std::sync::Mutex::new(0usize));
    let counter = Arc::clone(&observed);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let adapter = call.adapters.lock().clone().unwrap();
        let mut results = record.lock().unwrap();
        // The producer call's own open-child authority spawns 32 real children;
        // each one is an actual OS attempt charged to the shared run budget.
        for _ in 0..32 {
            let spawned = adapter.processes.spawn(
                &adapter.token,
                &["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                "",
                &[],
                crate::capabilities::ProcessLimits {
                    close_after_initial: false,
                    timeout_ms: 2000,
                    ..Default::default()
                },
            );
            results.push(match spawned {
                Ok(_) => "ok".into(),
                Err(error) => error.code().into(),
            });
        }
        // The 33rd attempt is refused and sends no OS spawn.
        let over = adapter.processes.spawn(
            &adapter.token,
            &["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
            "",
            &[],
            crate::capabilities::ProcessLimits {
                close_after_initial: false,
                timeout_ms: 2000,
                ..Default::default()
            },
        );
        results.push(match over {
            Ok(_) => "ok".into(),
            Err(error) => error.code().into(),
        });
        *counter.lock().unwrap() = adapter.processes.spawn_attempts();
    }));
    let _ = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"producer","name":"terminal","arguments":{
            "argv":["/bin/sh","-c","true"],"background":true,"timeout_ms":3000}}),
        _ => Value::Null,
    })
    .await;
    let results = outcomes.lock().unwrap().clone();
    assert_eq!(results.len(), 33, "32 attempts plus the refused one");
    assert!(
        results[..32].iter().all(|code| code == "ok"),
        "the first 32 attempts are within the bound: {results:?}"
    );
    assert_eq!(
        results[32], "budget_exceeded",
        "the cumulative attempt budget is enforced: {results:?}"
    );
    assert_eq!(
        *observed.lock().unwrap(),
        32,
        "a refused attempt is not charged and the budget is never refunded"
    );
    assert!(!root.join("workspace").join("never").exists());
    drop(runtime);
    service.shutdown().await.unwrap();
}


/// Durable restart proof: a committed background producer whose exact returned
/// handle has no same-owner, same-base Native wait/kill finalizer is not
/// drainage. An ordinary decided write is not a substitute for that proof.
#[tokio::test(flavor = "multi_thread")]
async fn managed_restart_uncovered_background_producer_is_unresolved() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<(ManagedWorkspaceIdentity, Arc<ManagedRunBinding>)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some((call.identity.workspace.clone(), binding));
        }
    }));
    // A fully decided ordinary write from an earlier run is not proof that a
    // later background producer's child was drained.
    let _ = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"ordinary","name":"write_file","arguments":{
            "path":"ordinary.txt","content":"ordinary"}}),
        _ => Value::Null,
    })
    .await;
    let _ = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"producer","name":"terminal","arguments":{
            "argv":["/bin/sh","-c","sleep 30"],"background":true,"timeout_ms":60000}}),
        _ => Value::Null,
    })
    .await;
    let (identity, binding) = captured.lock().unwrap().clone().expect("identity");
    runtime.forget_restart_checked(&identity.branch_id);
    let page = state.persistence().unwrap().managed_effect_list(&crate::effects::ManagedEffectListRequest{
        workspace_id: identity.workspace_id.clone(), after_effect_id: None, limit: 128}).unwrap();
    for entry in &page.entries { eprintln!("ROW {} {} {} {:?}", entry.effect_id, entry.call_id, entry.run_id, entry.state); }
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let gate = runtime.restart_gate(
        &binding.branch,
        &identity.branch_id,
        &identity.workspace_id,
        &cancel,
    );
    assert_eq!(
        gate,
        super::ManagedRestartGate::Unresolved,
        "a committed background producer without an exact wait/kill finalizer proves nothing"
    );
    runtime.adopt_restart_gate(&binding.branch, gate);
    assert_eq!(
        binding.branch.writer_phase(),
        super::ManagedWriterPhase::Unresolved
    );
    assert!(
        binding
            .branch
            .enter_checked(binding.branch.epoch, ("run", "late"), || Ok(()))
            .is_err(),
        "an uncovered producer keeps the branch closed to new writers"
    );
    drop(binding);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// A live Open writer with zero active call guards is still the branch owner:
/// restore preparation and the shared publication gate read consume that one
/// gate. After a proven cleanup the same operation is admitted again.
struct WindowProvider {
    turns: std::sync::Mutex<usize>,
    reached: std::sync::Mutex<std::sync::mpsc::Sender<usize>>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl crate::AgentProviderHost for WindowProvider {
    fn call(&self, _request: &Value, _cancel: &crate::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        *turns += 1;
        let turn = *turns;
        let reply = |call: Option<Value>| {
            json!({"text":if call.is_some() { "" } else { "done" },"tool_calls":call.into_iter().collect::<Vec<_>>(),
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"})
        };
        let response = match turn {
            1 => reply(Some(json!({"id":"producer","name":"terminal","arguments":{
                "argv":["/bin/sh","-c","sleep 30"],"background":true,"timeout_ms":60000}}))),
            2 => {
                let _ = self.reached.lock().unwrap().send(turn);
                let (lock, cvar) = &*self.release;
                let mut released = lock.lock().unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                while !*released {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    let (guard, _) = cvar
                        .wait_timeout(released, std::time::Duration::from_millis(100))
                        .unwrap();
                    released = guard;
                }
                reply(None)
            }
            _ => reply(None),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

fn window_provider(
    reached: std::sync::mpsc::Sender<usize>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
) -> Arc<dyn crate::AgentProviderHost> {
    Arc::new(WindowProvider {
        turns: std::sync::Mutex::new(0),
        reached: std::sync::Mutex::new(reached),
        release,
    })
}

fn wait_provider_turn(rx: std::sync::mpsc::Receiver<usize>) {
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .expect("provider reached its second turn");
}

/// A second run whose authority stays live while its second turn is gated and
/// which performs only a read-only managed call (no head change).
struct BlankWindowProvider {
    turns: std::sync::Mutex<usize>,
    reached: std::sync::Mutex<std::sync::mpsc::Sender<usize>>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl crate::AgentProviderHost for BlankWindowProvider {
    fn call(&self, _request: &Value, _cancel: &crate::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        *turns += 1;
        let turn = *turns;
        let reply = |call: Option<Value>| {
            json!({"text":if call.is_some() { "" } else { "done" },"tool_calls":call.into_iter().collect::<Vec<_>>(),
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"})
        };
        let response = match turn {
            1 => reply(Some(json!({"id":"read","name":"read_file","arguments":{
                "path":"seed.txt"}}))),
            2 => {
                let _ = self.reached.lock().unwrap().send(turn);
                let (lock, cvar) = &*self.release;
                let mut released = lock.lock().unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                while !*released && std::time::Instant::now() < deadline {
                    let (guard, _) = cvar
                        .wait_timeout(released, std::time::Duration::from_millis(100))
                        .unwrap();
                    released = guard;
                }
                reply(None)
            }
            _ => reply(None),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}


/// Releases a blocked provider turn even when an assertion unwinds.
struct ReleaseGuard(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.0;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_live_open_writer_blocks_restore_until_cleanup() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some(binding);
        }
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    service.inject_provider_host(window_provider(tx, Arc::clone(&release)));
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"live open writer gate"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let worker = tokio::spawn(service.clone().run_worker(run.run_id.clone(), "ignored".into()));
    tokio::task::spawn_blocking(move || wait_provider_turn(rx))
        .await
        .unwrap();
    let binding = captured.lock().unwrap().clone().expect("binding");
    let guard = ReleaseGuard(Arc::clone(&release));
    let branch_id = binding.admitted_branch.branch_id.clone();
    assert_eq!(
        runtime.writer_phase_for_test(&branch_id),
        Some(super::ManagedWriterPhase::Open)
    );
    assert_eq!(
        binding.branch.state.lock().active,
        0,
        "no call guard is active in this provider window"
    );
    assert!(
        runtime.source_has_active_writer(&branch_id),
        "an Open writer with zero active guards is not an idle branch"
    );
    let persistence = state.persistence().unwrap();
    let head = persistence.managed_workspace_head(&binding.admitted_branch).unwrap();
    let source = ManagedSourceCas {
        store_id: head.store_id.clone(),
        workspace_id: head.workspace_id.clone(),
        branch_id: head.branch_id.clone(),
        epoch: head.epoch,
        head_object_id: head.head_object_id.clone(),
        head_version: head.head_version,
    };
    let frozen = runtime
        .repository
        .object_metadata(
            &ManagedObjectReferencesRequest {
                store_id: head.store_id.clone(),
                object_id: head.head_object_id.clone(),
            },
            &binding.cancel,
        )
        .unwrap()
        .expect("head object");
    let identity = ManagedWorkspaceIdentity {
        branch_id: head.branch_id.clone(),
        ..binding.workspace.identity.clone()
    };
    let refused = runtime
        .prepare_restore_branch(&binding.authority, &identity, &source, &frozen)
        .err()
        .expect("restore preparation refuses under a live open writer");
    assert!(
        refused.contains("managed_restore_busy"),
        "restore must refuse while the producer view is open: {refused}"
    );
    assert_eq!(
        runtime.writer_phase_for_test(&branch_id),
        Some(super::ManagedWriterPhase::Open),
        "the refused restore keeps the writer owner"
    );
    drop(persistence);
    drop(guard);
    worker.await.unwrap();
    assert_eq!(
        runtime.writer_phase_for_test(&branch_id),
        Some(super::ManagedWriterPhase::Idle),
        "terminal cleanup released the proven-quiescent writer"
    );
    // Positive control: a fresh run whose authority is live and whose
    // read-only managed call leaves the head unchanged. Restore preparation is
    // admitted now that no writer owns the branch.
    let (tx2, rx2) = std::sync::mpsc::channel();
    let release2 = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    service.inject_provider_host(Arc::new(BlankWindowProvider {
        turns: std::sync::Mutex::new(0),
        reached: std::sync::Mutex::new(tx2),
        release: Arc::clone(&release2),
    }) as Arc<dyn crate::AgentProviderHost>);
    let second = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"restore positive control"}),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("second run admitted on the idle branch");
    let worker2 = tokio::spawn(
        service
            .clone()
            .run_worker(second.run_id.clone(), "ignored".into()),
    );
    tokio::task::spawn_blocking(move || wait_provider_turn(rx2))
        .await
        .unwrap();
    let guard2 = ReleaseGuard(Arc::clone(&release2));
    let binding2 = captured.lock().unwrap().clone().expect("second binding");
    let restored = runtime
        .prepare_restore_branch(&binding2.authority, &identity, &source, &frozen)
        .expect("restore is admissible after proven cleanup");
    drop(restored);
    drop(guard2);
    let _ = worker2.await;
    drop(binding2);
    drop(binding);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// The completion reservation on an Open writer must seal new admissions
/// before it proves process quiescence. A two-contender schedule observes the
/// admission attempt inside the proof window.
#[tokio::test(flavor = "multi_thread")]
async fn managed_completion_open_path_seals_admission_before_quiescence() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some(binding);
        }
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    service.inject_provider_host(window_provider(tx, Arc::clone(&release)));
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"completion seal"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let worker = tokio::spawn(service.clone().run_worker(run.run_id.clone(), "ignored".into()));
    tokio::task::spawn_blocking(move || wait_provider_turn(rx))
        .await
        .unwrap();
    let binding = captured.lock().unwrap().clone().expect("binding");
    let guard = ReleaseGuard(Arc::clone(&release));
    assert_eq!(
        binding.branch.writer_phase(),
        super::ManagedWriterPhase::Open
    );
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let admit = {
        let branch = Arc::clone(&binding.branch);
        let run_id = binding.owner.run_id.clone();
        let entered = Arc::clone(&entered);
        move || {
            if branch
                .enter_checked(branch.epoch, (&run_id, "late"), || Ok(()))
                .is_ok()
            {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // The proof itself fails here: a live child is not quiescence.
            Err("managed_completion_busy".to_string())
        }
    };
    let reservation = binding.branch.reserve_completion_publication(
        &binding.owner.run_id,
        None,
        admit,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    );
    assert!(
        !entered.load(std::sync::atomic::Ordering::SeqCst),
        "new admissions are sealed before the quiescence proof runs"
    );
    assert!(
        reservation.is_err(),
        "a live child cannot yield a completion reservation"
    );
    drop(guard);
    let _ = worker.await;
    drop(binding);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// Cleanup must not invalidate the generation, drop reachable handles or
/// report quiescence until reap and output drain are actually proven. A
/// retained timeout is retryable by the same owner.
#[tokio::test(flavor = "multi_thread")]
async fn managed_cleanup_timeout_preserves_generation_handles_and_view() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some(binding);
        }
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    service.inject_provider_host(window_provider(tx, Arc::clone(&release)));
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"cleanup ownership"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let worker = tokio::spawn(service.clone().run_worker(run.run_id.clone(), "ignored".into()));
    tokio::task::spawn_blocking(move || wait_provider_turn(rx))
        .await
        .unwrap();
    let binding = captured.lock().unwrap().clone().expect("binding");
    let processes = binding.processes.lock().clone().expect("process table");
    let generation = processes.generation_for_test();
    assert_eq!(processes.table_len(), 1);
    let guard = ReleaseGuard(Arc::clone(&release));
    processes.reject_next_reap_proof_for_test();
    let first = binding.cleanup_run(std::time::Duration::from_secs(1));
    assert_eq!(
        first,
        super::ManagedCleanup::TimedOut,
        "an unproven reap is never reported as quiescent"
    );
    assert_eq!(
        processes.generation_for_test(),
        generation,
        "a failed cleanup does not invalidate the owner generation"
    );
    assert_eq!(
        processes.table_len(),
        1,
        "a failed cleanup keeps the owner's reachable handles"
    );
    assert!(
        binding.run_view.lock().is_some(),
        "a failed cleanup keeps the run view"
    );
    processes.allow_reap_proof_for_test();
    drop(guard);
    worker.await.unwrap();
    let second = binding.cleanup_run(std::time::Duration::from_secs(2));
    assert_eq!(
        second,
        super::ManagedCleanup::Quiescent,
        "the same owner can retry cleanup to a proven quiescent result"
    );
    assert_eq!(processes.table_len(), 0);
    assert!(binding.run_view.lock().is_none());
    assert!(!root.join("workspace").join("never").exists());
    drop(binding);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// A head-derived branch creation reserves the shared branch writer gate for
/// its head read and durable submit. That reservation is not a foreign writer:
/// after a completed file run the source is Idle and the create must reach the
/// durable submit, leave the source head untouched and stay non-destructive.
#[tokio::test(flavor = "multi_thread")]
async fn managed_head_branch_create_succeeds_after_an_idle_file_run() {
    let (_root, state) = native_fixture_config(|config| {
        config.bearer_token = Some("synthetic-maintenance-fixture".into());
        config
            .managed_workspace
            .as_mut()
            .unwrap()
            .maintenance_policy
            .branch = true;
    });
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if call.identity.call_id == "write" {
            *slot.lock().unwrap() = call.binding().ok();
        }
    }));
    let run = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"write","name":"write_file","arguments":{
            "path":"made.txt","content":"made"}}),
        _ => Value::Null,
    })
    .await;
    let binding = captured
        .lock()
        .unwrap()
        .clone()
        .expect("binding captured");
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let identity = binding.admitted_branch.clone();
    let head = runtime
        .repository
        .head(&identity, &cancel)
        .expect("source head");
    assert_eq!(
        runtime.writer_phase_for_test(&identity.branch_id),
        Some(ManagedWriterPhase::Idle),
        "a completed file run leaves the source branch writer Idle"
    );
    let source = ManagedSourceCas {
        store_id: head.store_id.clone(),
        workspace_id: head.workspace_id.clone(),
        branch_id: head.branch_id.clone(),
        epoch: head.epoch,
        head_object_id: head.head_object_id.clone(),
        head_version: head.head_version,
    };
    let request = ManagedBranchCreateRequest {
        workspace_id: head.workspace_id.clone(),
        source_branch_id: head.branch_id.clone(),
        checkpoint_id: None,
        expected_source: Some(source.clone()),
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    let receipt = service
        .create_managed_branch(request)
        .await
        .expect("head-derived branch create must not make its own reservation foreign");
    assert_eq!(receipt.source, source);
    assert_eq!(receipt.checkpoint_id, None);
    assert_ne!(receipt.branch.branch_id, head.branch_id);
    assert_eq!(receipt.branch.epoch, head.epoch + 1);
    let after = runtime
        .repository
        .head(&identity, &cancel)
        .expect("source head after branch creation");
    assert_eq!(after, head, "branch creation must not move the source head");
    assert_eq!(
        runtime.writer_phase_for_test(&identity.branch_id),
        Some(ManagedWriterPhase::Idle),
        "the create reservation released the source writer"
    );
    assert!(
        !runtime.source_has_active_writer(&identity.branch_id),
        "the source branch stays an active idle branch"
    );
    drop(binding);
    drop(run);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// A publication whose durable submit succeeded but whose readback cannot be
/// confirmed must transfer the maintenance reservation to `Unresolved`. The
/// verified success, a known no-submit conflict and an early rejection stay
/// owned decisions that release the branch to Idle.
#[tokio::test(flavor = "multi_thread")]
async fn managed_publication_confirm_readback_mismatch_keeps_the_writer_fenced() {
    let (_root, state) = native_fixture_config(|config| {
        config.bearer_token = Some("synthetic-maintenance-fixture".into());
        config
            .managed_workspace
            .as_mut()
            .unwrap()
            .maintenance_policy
            .publish = true;
    });
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<Arc<ManagedRunBinding>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if call.identity.call_id == "write" {
            *slot.lock().unwrap() = call.binding().ok();
        }
    }));
    let run = run_turn_script(&service, |turn, _| match turn {
        1 => json!({"id":"write","name":"write_file","arguments":{
            "path":"published.txt","content":"published"}}),
        _ => Value::Null,
    })
    .await;
    let binding = captured
        .lock()
        .unwrap()
        .clone()
        .expect("binding captured");
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let identity = binding.admitted_branch.clone();
    let workspace_id = binding.workspace.identity.workspace_id.clone();
    let head = runtime
        .repository
        .head(&identity, &cancel)
        .expect("source head");
    let publish = |expected: ManagedWorkspaceHead| ManagedPublishRequest {
        workspace_id: workspace_id.clone(),
        branch_id: expected.branch_id.clone(),
        expected_head: expected,
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    // Verified success: the receipt and the readback pointer agree.
    let verified = publish(head.clone());
    let receipt = service
        .publish_managed_workspace_blocking(verified.clone(), &cancel)
        .expect("verified publication");
    assert_eq!(receipt.status, "committed");
    assert_eq!(receipt.request_id, verified.request_id);
    assert_eq!(
        runtime.writer_phase_for_test(&identity.branch_id),
        Some(ManagedWriterPhase::Idle),
        "a verified publication releases the branch writer"
    );
    // Known no-submit conflict: stale expected head, no receipt, still Idle.
    let mut stale = head.clone();
    stale.head_version = stale.head_version.saturating_add(1);
    let conflict = publish(stale);
    let rejected = service
        .publish_managed_workspace_blocking(conflict.clone(), &cancel)
        .expect_err("a stale expected head is a known rejection");
    assert_eq!(rejected.to_string(), "managed_source_conflict");
    assert!(
        runtime
            .repository
            .publish_receipt(&workspace_id, &conflict.request_id, &cancel)
            .expect("receipt lookup")
            .is_none(),
        "a known rejection durably submitted nothing"
    );
    assert_eq!(
        runtime.writer_phase_for_test(&identity.branch_id),
        Some(ManagedWriterPhase::Idle),
        "a known no-submit conflict keeps the branch open"
    );
    // Unknown: the real submit succeeded, the readback cannot confirm it.
    runtime.arm_publication_readback_mismatch_for_test();
    let unconfirmed = publish(head.clone());
    let unknown = service
        .publish_managed_workspace_blocking(unconfirmed.clone(), &cancel)
        .expect_err("an unconfirmed readback is a submitted-unknown outcome");
    assert_eq!(unknown.to_string(), "managed_submitted_unknown");
    assert!(
        runtime
            .repository
            .publish_receipt(&workspace_id, &unconfirmed.request_id, &cancel)
            .expect("receipt lookup")
            .is_some(),
        "the durable submit really committed before the readback cut"
    );
    assert_eq!(
        runtime.writer_phase_for_test(&identity.branch_id),
        Some(ManagedWriterPhase::Unresolved),
        "a submitted but unconfirmed publication stays fenced"
    );
    assert!(
        runtime
            .reserve_maintenance(&identity.branch_id, "publish:after-unknown")
            .is_err(),
        "a new writer cannot enter an unconfirmed publication"
    );
    assert!(runtime.source_has_active_writer(&identity.branch_id));
    drop(binding);
    drop(run);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// The first admission into a branch in this process seals the branch writer
/// and derives its restart ownership. A sibling admission that observes the
/// branch while the derivation is still Checking must not open the writer or
/// reach any OS operation; it waits on the same gate and proceeds only after
/// the derived `Resolved` verdict is adopted.
#[tokio::test(flavor = "multi_thread")]
async fn managed_startup_checking_barrier_blocks_a_sibling_admission_until_resolved() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (command_tx, command_rx) = std::sync::mpsc::channel::<&'static str>();
    let command_rx = std::sync::Mutex::new(command_rx);
    let branch_slot: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let observed = Arc::clone(&branch_slot);
    runtime.inject_restart_check_observer(Arc::new(move |branch_id, _cancel| {
        *observed.lock().unwrap() = Some(branch_id.to_string());
        let _ = entered_tx.send(());
        let _ = command_rx
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(20));
    }));
    let first = tokio::spawn({
        let service = service.clone();
        async move {
            service
                .admit_external_with_workspace_selector(
                    AdmitRunRequest {
                        input: json!({"message":"startup barrier one"}),
                        ..Default::default()
                    },
                    None,
                )
                .await
        }
    });
    let entered = tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(20))
    })
    .await
    .unwrap();
    assert!(
        entered.is_ok(),
        "the startup derivation must reach its barrier"
    );
    let branch_id = branch_slot
        .lock()
        .unwrap()
        .clone()
        .expect("derived branch id");
    assert_eq!(
        runtime.writer_phase_for_test(&branch_id),
        Some(ManagedWriterPhase::Opening),
        "the branch is sealed while its startup derivation is Checking"
    );
    let second = tokio::spawn({
        let service = service.clone();
        async move {
            service
                .admit_external_with_workspace_selector(
                    AdmitRunRequest {
                        input: json!({"message":"startup barrier two"}),
                        ..Default::default()
                    },
                    None,
                )
                .await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        !second.is_finished(),
        "a sibling admission cannot pass a still-Checking startup gate"
    );
    command_tx.send("go").unwrap();
    assert!(
        first.await.unwrap().is_ok(),
        "the deriving admission resolves after its complete history proof"
    );
    assert!(
        second.await.unwrap().is_ok(),
        "the sibling admission proceeds once Resolved is adopted"
    );
    assert_eq!(
        runtime.writer_phase_for_test(&branch_id),
        Some(ManagedWriterPhase::Idle),
        "the adopted Resolved gate reopens the branch writer"
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// A cancelled startup derivation keeps the branch `Unresolved` and is never
/// adopted as `Resolved`: the deriving admission and every sibling admission
/// stay rejected.
#[tokio::test(flavor = "multi_thread")]
async fn managed_startup_restart_cancel_is_never_adopted_as_resolved() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (command_tx, command_rx) = std::sync::mpsc::channel::<&'static str>();
    let command_rx = std::sync::Mutex::new(command_rx);
    let branch_slot: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let observed = Arc::clone(&branch_slot);
    runtime.inject_restart_check_observer(Arc::new(move |branch_id, cancel| {
        *observed.lock().unwrap() = Some(branch_id.to_string());
        let _ = entered_tx.send(());
        let command = command_rx
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(20));
        if command == Ok("cancel") {
            cancel.request(crate::CancellationReason::Requested);
        }
    }));
    let first = tokio::spawn({
        let service = service.clone();
        async move {
            service
                .admit_external_with_workspace_selector(
                    AdmitRunRequest {
                        input: json!({"message":"startup cancel one"}),
                        ..Default::default()
                    },
                    None,
                )
                .await
        }
    });
    let entered = tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(20))
    })
    .await
    .unwrap();
    assert!(
        entered.is_ok(),
        "the startup derivation must reach its barrier"
    );
    let branch_id = branch_slot
        .lock()
        .unwrap()
        .clone()
        .expect("derived branch id");
    assert_eq!(
        runtime.writer_phase_for_test(&branch_id),
        Some(ManagedWriterPhase::Opening),
        "the branch is sealed while its startup derivation is Checking"
    );
    let second = tokio::spawn({
        let service = service.clone();
        async move {
            service
                .admit_external_with_workspace_selector(
                    AdmitRunRequest {
                        input: json!({"message":"startup cancel two"}),
                        ..Default::default()
                    },
                    None,
                )
                .await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        !second.is_finished(),
        "a sibling admission cannot pass a still-Checking startup gate"
    );
    command_tx.send("cancel").unwrap();
    assert!(
        first.await.unwrap().is_err(),
        "a cancelled derivation cannot admit its own run"
    );
    let sibling = second.await.unwrap();
    assert!(
        sibling
            .as_ref()
            .err()
            .is_some_and(|error| format!("{error:?}").contains("managed_restart_unresolved")),
        "the sibling observes the Unresolved verdict: {sibling:?}"
    );
    assert_eq!(
        runtime.writer_phase_for_test(&branch_id),
        Some(ManagedWriterPhase::Unresolved),
        "a cancelled derivation is never adopted as Resolved"
    );
    let later = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"startup cancel later"}),
                ..Default::default()
            },
            None,
        )
        .await;
    let later_message = later.as_ref().err().map(|error| format!("{error:?}"));
    assert!(
        later_message
            .as_deref()
            .is_some_and(|message| message.contains("managed_restart_unresolved")),
        "an Unresolved branch keeps rejecting later admissions: {later:?}"
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// Ordered unique `process_id` values visible in a provider request. The
/// producer's own committed tool result is the only handle source used here.
fn request_process_ids(value: &Value) -> Vec<String> {
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                for (key, field) in fields {
                    if key == "process_id"
                        && let Value::String(id) = field
                        && !id.is_empty()
                        && !out.iter().any(|seen| seen == id)
                    {
                        out.push(id.clone());
                    }
                    walk(field, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

/// Real two-child same-run schedule: the first background spawn copies and
/// installs the run root, the second joins it, and one later control call is
/// the first same-run continuation.
struct SharedViewProvider {
    turns: std::sync::Mutex<usize>,
    handles: Arc<std::sync::Mutex<Vec<String>>>,
}

impl crate::AgentProviderHost for SharedViewProvider {
    fn call(&self, request: &Value, _cancel: &crate::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        *turns += 1;
        let turn = *turns;
        {
            let mut known = self.handles.lock().unwrap();
            *known = request_process_ids(request);
        }
        let handles = self.handles.lock().unwrap().clone();
        let reply = |call: Value| {
            json!({"text":"","tool_calls":[call],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"})
        };
        let response = match turn {
            1 => reply(json!({"id":"spawn-one","name":"terminal","arguments":{
                "argv":["/bin/sh","-c","exit 0"],"background":true,"timeout_ms":3000}})),
            2 => reply(json!({"id":"spawn-two","name":"terminal","arguments":{
                "argv":["/bin/sh","-c","sleep 30"],"background":true,"timeout_ms":60000}})),
            3 => reply(json!({"id":"probe","name":"process","arguments":{
                "action":"poll","process_id":handles.first().cloned().unwrap_or_default()}})),
            _ => json!({"text":"done","tool_calls":[],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"}),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

/// The second background spawn of one run must join the already-owned
/// `OwnedRunWriterView` root and ticket and the same Native process table. It
/// gets its own per-call facade, ledger and token, and it must not copy or
/// install a second root. Different runs, Closing/Finalizing/Unresolved and
/// concurrent first spawns still refuse (covered by the existing gate tests).
#[tokio::test(flavor = "multi_thread")]
async fn managed_second_background_spawn_joins_the_run_root_and_table() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    struct Seen {
        call_id: String,
        view_id: String,
        root: Arc<ConfinedFsRoot>,
        bound: Option<String>,
        attempts: usize,
        table: usize,
        run_view: Option<(String, bool)>,
        pids: Vec<u32>,
    }
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Seen>::new()));
    let record = Arc::clone(&seen);
    let handles = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let probe_handles = Arc::clone(&handles);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let adapter = call.adapters.lock().clone().unwrap();
        let run_view = call.binding().ok().and_then(|binding| {
            binding
                .run_view
                .lock()
                .as_ref()
                .map(|view| (view.view_id.clone(), view.ticket.is_some()))
        });
        let mut pids = Vec::new();
        if call.identity.call_id == "probe" {
            pids = adapter.processes.live_pids();
            assert_eq!(pids.len(), 2, "both Native handles are in the table");
            assert!(
                pids.iter().any(|pid| Path::new(&format!("/proc/{pid}")).exists()),
                "the stdin-held child is a real live OS process: {pids:?}"
            );
            // A real same-run policy poll through the probe's own facade: it
            // proves the shared table keeps the later Native handle reachable.
            // Only the second (stdin-held) child is asserted live; the first
            // child is already terminal by design.
            let known = probe_handles.lock().unwrap();
            if let Some(second) = known.get(1) {
                let snap = adapter
                    .processes
                    .poll(&adapter.token, second, 0, 1)
                    .expect("shared table must resolve same-run handles");
                assert!(snap.running, "the second child is still live: {second}");
            }
        }
        record.lock().unwrap().push(Seen {
            call_id: call.identity.call_id.clone(),
            view_id: adapter.view_id.clone(),
            root: Arc::clone(&adapter.root),
            bound: adapter.processes.bound_call_id(),
            attempts: adapter.processes.spawn_attempts(),
            table: adapter.processes.table_len(),
            run_view,
            pids,
        });
    }));
    let provider = Arc::new(SharedViewProvider {
        turns: std::sync::Mutex::new(0),
        handles: Arc::clone(&handles),
    });
    service.inject_provider_host(provider as Arc<dyn crate::AgentProviderHost>);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"second background spawn"}),
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
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3, "both spawns and the probe bound a facade");
    let (one, two, probe) = (&seen[0], &seen[1], &seen[2]);
    assert_eq!(one.call_id, "spawn-one");
    assert_eq!(two.call_id, "spawn-two");
    assert_eq!(probe.call_id, "probe");
    assert_eq!(
        one.bound.as_deref(),
        Some("spawn-one"),
        "each facade keeps its own Native call"
    );
    assert_eq!(two.bound.as_deref(), Some("spawn-two"));
    assert_eq!(
        two.view_id, one.view_id,
        "the second spawn joins the first view id"
    );
    assert!(
        Arc::ptr_eq(&one.root, &two.root),
        "the second spawn must use the same rooted view, not a copy"
    );
    assert!(
        Arc::ptr_eq(&one.root, &probe.root),
        "control calls keep the same rooted view"
    );
    assert_eq!(one.attempts, 0, "the first bind precedes its OS spawn");
    assert_eq!(two.attempts, 1, "one cumulative run spawn budget");
    assert_eq!(two.table, 1, "the second spawn sees the first child");
    assert_eq!(
        two.run_view.as_ref().map(|view| view.0.as_str()),
        Some(one.view_id.as_str()),
        "the run view is installed exactly once"
    );
    assert_eq!(
        two.run_view.as_ref().map(|view| view.1),
        Some(true),
        "the run view keeps its single quota ticket"
    );
    assert_eq!(probe.attempts, 2, "two real OS spawn attempts");
    assert_eq!(probe.table, 2, "one shared run table holds both children");
    assert_eq!(probe.pids.len(), 2, "both Native handles are reachable");
    let mut distinct = probe.pids.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 2, "two distinct OS process identities");
    // Both spawns committed as non-publishing producer receipts.
    drop(seen);
    let results = service.session_messages(&run.session_id);
    let json = serde_json::to_value(results).unwrap();
    let blocks: Vec<Value> = json
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|message| message["content"].as_array().into_iter().flatten())
        .filter(|block| block["type"] == "tool_result")
        .cloned()
        .collect();
    assert!(blocks.len() >= 3, "three tool results: {blocks:?}");
    for block in &blocks[..2] {
        assert_ne!(block["is_error"], true, "both spawns succeed: {block:?}");
    }
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// Classifier derivation over a real durable two-producer history in one
/// process: P1 and P2 both committed producer receipts, but only wait(P2)
/// published the shared root. The durable records carry no root generation and
/// no quiesced child set, so P1's non-anchor sibling must stay Unresolved
/// without demanding a second TreeWrite. This is a classifier check, not an OS
/// restart end-to-end claim.
#[tokio::test(flavor = "multi_thread")]
async fn managed_restart_two_producer_history_without_sibling_proof_is_unresolved() {
    let (_root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let captured: Arc<std::sync::Mutex<Option<(ManagedWorkspaceIdentity, Arc<ManagedRunBinding>)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        if let Ok(binding) = call.binding() {
            *slot.lock().unwrap() = Some((call.identity.workspace.clone(), binding));
        }
    }));
    let handles = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    service.inject_provider_host(Arc::new(SharedLifecycleProvider {
        turns: std::sync::Mutex::new(0),
        handles: Arc::clone(&handles),
        file_gate_and_repeat: false,
    }) as Arc<dyn crate::AgentProviderHost>);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"two producer restart history"}),
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
    let (_identity, binding) = captured.lock().unwrap().clone().expect("binding");
    let identity = binding.admitted_branch.clone();
    let persistence = state.persistence().unwrap();
    let owner = ManagedOwnerScope {
        profile: "gateway".into(),
        session_id: run.session_id.clone(),
        run_id: run.run_id.clone(),
    };
    let receipt = |call_id: &str| {
        persistence
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: owner.clone(),
                call_id: call_id.into(),
            })
            .unwrap()
            .unwrap_or_else(|| panic!("missing receipt {call_id}"))
    };
    // Real durable facts: both spawns are producers, wait(P1) is a
    // non-publishing receipt, and wait(P2) is the single group publication.
    for producer in ["spawn-p1", "spawn-p2"] {
        let record = receipt(producer);
        assert_eq!(
            record.outcome.as_ref().map(|outcome| &outcome.disposition),
            Some(&ManagedPublicationStatus::ReadOnly)
        );
    }
    let wait_p1 = receipt("wait-p1");
    assert_eq!(
        wait_p1.outcome.as_ref().map(|outcome| &outcome.disposition),
        Some(&ManagedPublicationStatus::ReadOnly)
    );
    let wait_p2 = receipt("wait-p2");
    let prepared = wait_p2.prepared.as_ref().expect("wait-p2 prepared");
    assert_eq!(prepared.operation_class, ManagedOperationClass::TreeWrite);
    assert_eq!(
        wait_p2.outcome.as_ref().map(|outcome| &outcome.disposition),
        Some(&ManagedPublicationStatus::Committed)
    );
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    runtime.forget_restart_checked(&identity.branch_id);
    let gate = runtime.restart_gate(
        &binding.branch,
        &identity.branch_id,
        &identity.workspace_id,
        &cancel,
    );
    assert_eq!(
        gate,
        ManagedRestartGate::Unresolved,
        "a two-producer group with one exact finalizer must not infer the other sibling drained"
    );
    runtime.adopt_restart_gate(&binding.branch, gate);
    assert_eq!(
        binding.branch.writer_phase(),
        ManagedWriterPhase::Unresolved
    );
    assert!(
        binding
            .branch
            .enter_checked(binding.branch.epoch, (&run.run_id, "late"), || Ok(()))
            .is_err(),
        "the branch stays fenced for new writers"
    );
    drop(binding);
    drop(runtime);
    service.shutdown().await.unwrap();
}

/// Real two-child lifecycle: P1 exits, P2 holds stdin. wait(P1) while P2 is
/// live returns the real control result as a non-publishing receipt, the head
/// does not move and the view stays Open. Only after P2 is fed/closed and both
/// children are terminal/reaped/drained does one wait(P2) publish the shared
/// root exactly once; a repeated terminal wait must not publish again.
struct SharedLifecycleProvider {
    turns: std::sync::Mutex<usize>,
    handles: Arc<std::sync::Mutex<Vec<String>>>,
    /// Include the refused file admission and the repeated terminal wait.
    file_gate_and_repeat: bool,
}

impl crate::AgentProviderHost for SharedLifecycleProvider {
    fn call(&self, request: &Value, _cancel: &crate::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        *turns += 1;
        let turn = *turns;
        {
            let mut known = self.handles.lock().unwrap();
            *known = request_process_ids(request);
        }
        let handles = self.handles.lock().unwrap().clone();
        let reply = |call: Value| {
            json!({"text":"","tool_calls":[call],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"})
        };
        let first = handles.first().cloned().unwrap_or_default();
        let second = handles.get(1).cloned().unwrap_or_default();
        let spawn = |id: &str, script: &str, timeout_ms: u64| {
            reply(json!({"id":id,"name":"terminal","arguments":{
                "argv":["/bin/sh","-c",script],"background":true,"timeout_ms":timeout_ms}}))
        };
        let wait = |id: &str, handle: &str, timeout_ms: u64| {
            reply(json!({"id":id,"name":"process","arguments":{
                "action":"wait","process_id":handle,"timeout_ms":timeout_ms}}))
        };
        let write = reply(json!({"id":"write-p2","name":"process","arguments":{
            "action":"write","process_id":second,"data":"hello\n","timeout_ms":2000}}));
        let close = reply(json!({"id":"close-p2","name":"process","arguments":{
            "action":"close","process_id":second}}));
        let response = match turn {
            1 => spawn(
                "spawn-p1",
                "printf 'p1' > p1.txt",
                4000,
            ),
            2 => spawn(
                "spawn-p2",
                "read line; printf 'p2:%s' \"$line\" > p2.txt",
                8000,
            ),
            3 => wait("wait-p1", &first, 3000),
            4 if self.file_gate_and_repeat => reply(json!({"id":"file-gate","name":"write_file","arguments":{
                "path":"gate.txt","content":"gate"}})),
            4 => write,
            5 if self.file_gate_and_repeat => write,
            5 => close,
            6 if self.file_gate_and_repeat => close,
            6 => wait("wait-p2", &second, 5000),
            7 => wait("wait-p2", &second, 5000),
            8 => wait("wait-again", &second, 1000),
            _ => json!({"text":"done","tool_calls":[],
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
                "reasoning":"","stop_reason":"stop"}),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_live_sibling_control_receipt_and_single_group_publication() {
    let (root, state) = native_fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let persistence = state.persistence().unwrap();
    struct Seen {
        call_id: String,
        head: (String, u64),
        table: usize,
        kill_signals: usize,
        view_id: Option<String>,
        view_ticket: bool,
        writer_phase: ManagedWriterPhase,
        second_live: bool,
    }
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Seen>::new()));
    let record = Arc::clone(&seen);
    let branch_identity = Arc::new(std::sync::Mutex::new(None::<ManagedWorkspaceIdentity>));
    let identity_slot = Arc::clone(&branch_identity);
    let handles = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let probe_handles = Arc::clone(&handles);
    let observer_persistence = Arc::clone(&persistence);
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        let adapter = call.adapters.lock().clone().unwrap();
        let binding = call.binding().unwrap();
        *identity_slot.lock().unwrap() = Some(binding.admitted_branch.clone());
        let head = observer_persistence
            .managed_workspace_head(&binding.admitted_branch)
            .expect("workspace head");
        let view = binding
            .run_view
            .lock()
            .as_ref()
            .map(|view| (view.view_id.clone(), view.ticket.is_some()));
        let mut second_live = false;
        if call.identity.call_id == "write-p2" {
            let known = probe_handles.lock().unwrap();
            if let Some(second) = known.get(1) {
                let snap = adapter
                    .processes
                    .poll(&adapter.token, second, 0, 1)
                    .expect("live sibling stays reachable");
                second_live = snap.running;
            }
        }
        record.lock().unwrap().push(Seen {
            call_id: call.identity.call_id.clone(),
            head: (head.head_object_id.clone(), head.head_version),
            table: adapter.processes.table_len(),
            kill_signals: adapter.processes.kill_signals(),
            view_id: view.as_ref().map(|view| view.0.clone()),
            view_ticket: view.as_ref().is_some_and(|view| view.1),
            writer_phase: binding.branch.writer_phase(),
            second_live,
        });
    }));
    let provider = Arc::new(SharedLifecycleProvider {
        turns: std::sync::Mutex::new(0),
        handles: Arc::clone(&handles),
        file_gate_and_repeat: true,
    });
    service.inject_provider_host(provider as Arc<dyn crate::AgentProviderHost>);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"live sibling publication"}),
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
    let seen = seen.lock().unwrap();
    // The refused file admission never binds a facade; the other seven
    // calls (two spawns and five control calls) all reach their Native facade.
    assert_eq!(seen.len(), 7, "all admitted calls bound a facade");
    let by = |call_id: &str| {
        seen.iter()
            .find(|seen| seen.call_id == call_id)
            .unwrap_or_else(|| panic!("missing bind {call_id}"))
    };
    let wait_one = by("wait-p1");
    let write_two = by("write-p2");
    let base = wait_one.head.clone();
    // wait(P1): real terminal result, but P2 is live so nothing is published.
    assert_eq!(wait_one.head, base, "the head never moves on a receipt");
    assert!(wait_one.view_id.is_some(), "the produced view stays installed");
    assert!(wait_one.view_ticket, "the shared view keeps its ticket");
    assert_eq!(wait_one.kill_signals, 0, "no wait sends a kill signal");
    // The file admission between the two waits is refused by the open view.
    let blocks = {
        let results = service.session_messages(&run.session_id);
        let json = serde_json::to_value(results).unwrap();
        json.as_array()
            .unwrap()
            .iter()
            .flat_map(|message| message["content"].as_array().into_iter().flatten())
            .filter(|block| block["type"] == "tool_result")
            .cloned()
            .collect::<Vec<Value>>()
    };
    assert!(blocks.len() >= 8, "eight tool results: {blocks:?}");
    assert_ne!(blocks[0]["is_error"], true, "spawn P1: {blocks:?}");
    assert_ne!(blocks[1]["is_error"], true, "spawn P2: {blocks:?}");
    assert_ne!(blocks[2]["is_error"], true, "wait P1 is a real receipt: {blocks:?}");
    assert_eq!(
        blocks[3]["is_error"], true,
        "a file admission while the run view is Open is refused: {blocks:?}"
    );
    let refusal = blocks[3].to_string();
    assert!(
        refusal.contains("managed writer busy"),
        "the file refusal is the Native writer gate: {refusal}"
    );
    assert_ne!(blocks[4]["is_error"], true, "stdin write: {blocks:?}");
    assert_ne!(blocks[5]["is_error"], true, "stdin close: {blocks:?}");
    assert_ne!(blocks[6]["is_error"], true, "publishing wait: {blocks:?}");
    assert_ne!(blocks[7]["is_error"], true, "repeat wait: {blocks:?}");
    // After wait(P1), the sibling is still live and the run view still owns
    // the branch in Open.
    assert_eq!(write_two.head, base, "no candidate and no CAS before publish");
    assert_eq!(write_two.table, 2, "both children still in the shared table");
    assert!(write_two.second_live, "P2 is still running after wait(P1)");
    assert_eq!(write_two.kill_signals, 0);
    assert_eq!(
        write_two.view_id.as_deref(),
        wait_one.view_id.as_deref(),
        "the same view survives a non-publishing receipt"
    );
    assert!(write_two.view_ticket);
    assert_eq!(
        write_two.writer_phase,
        ManagedWriterPhase::Open,
        "the writer gate stays Open with its Native owner"
    );
    drop(seen);
    let owner = ManagedOwnerScope {
        profile: "gateway".into(),
        session_id: run.session_id.clone(),
        run_id: run.run_id.clone(),
    };
    let receipt = |call_id: &str| {
        persistence
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: owner.clone(),
                call_id: call_id.into(),
            })
            .unwrap()
            .unwrap_or_else(|| panic!("missing receipt {call_id}"))
    };
    let wait_one = receipt("wait-p1");
    let prepared = wait_one.prepared.as_ref().expect("wait-p1 prepared");
    assert_eq!(
        prepared.operation_class,
        ManagedOperationClass::ReadOnly,
        "a live sibling yields a non-publishing receipt"
    );
    assert_eq!(prepared.writer_state, ManagedWriterState::NoProcess);
    assert!(prepared.candidate_root.is_none(), "no candidate is prepared");
    let outcome = wait_one.outcome.as_ref().expect("wait-p1 outcome");
    assert_eq!(outcome.disposition, ManagedPublicationStatus::ReadOnly);
    assert_eq!(outcome.publication.candidate_head, None);
    assert_eq!(outcome.publication.base_head, base.0);
    assert_eq!(outcome.publication.base_head_version, base.1);
    let spawn_one = receipt("spawn-p1");
    let spawn_two = receipt("spawn-p2");
    for spawn in [&spawn_one, &spawn_two] {
        assert_eq!(
            spawn.outcome.as_ref().map(|outcome| &outcome.disposition),
            Some(&ManagedPublicationStatus::ReadOnly)
        );
        let handle = &spawn
            .outcome
            .as_ref()
            .unwrap()
            .canonical_result_ref;
        let result = runtime.read_result(handle).expect("producer result");
        assert!(
            result["data"]["process_id"].as_str().is_some(),
            "canonical producer handle: {result}"
        );
    }
    let wait_two = receipt("wait-p2");
    let prepared = wait_two.prepared.as_ref().expect("wait-p2 prepared");
    assert_eq!(prepared.operation_class, ManagedOperationClass::TreeWrite);
    assert_eq!(prepared.writer_state, ManagedWriterState::Settled);
    let candidate = prepared.candidate_root.as_ref().expect("real candidate");
    let outcome = wait_two.outcome.as_ref().expect("wait-p2 outcome");
    assert_eq!(outcome.disposition, ManagedPublicationStatus::Committed);
    assert_eq!(
        outcome.publication.base_head, base.0,
        "the publisher uses the producer's original base"
    );
    assert_eq!(outcome.publication.base_head_version, base.1);
    assert_eq!(
        outcome.publication.candidate_head.as_deref(),
        Some(candidate.object_id.as_str())
    );
    runtime.verify_tree(&candidate.object_id).expect("candidate root");
    let tree = runtime.path.join("trees").join(&candidate.object_id);
    assert_eq!(
        std::fs::read_to_string(tree.join("p1.txt")).unwrap(),
        "p1",
        "the published shared root contains P1 output"
    );
    assert_eq!(
        std::fs::read_to_string(tree.join("p2.txt")).unwrap(),
        "p2:hello",
        "the published shared root contains P2 output"
    );
    // Repeated terminal wait after publication: real result, no second
    // TreeWrite, no re-signal, retired view not required to publish again.
    let wait_again = receipt("wait-again");
    let prepared = wait_again.prepared.as_ref().expect("wait-again prepared");
    assert_eq!(prepared.operation_class, ManagedOperationClass::ReadOnly);
    assert_eq!(prepared.writer_state, ManagedWriterState::NoProcess);
    assert!(prepared.candidate_root.is_none());
    let outcome = wait_again.outcome.as_ref().expect("wait-again outcome");
    assert_eq!(outcome.disposition, ManagedPublicationStatus::ReadOnly);
    assert_eq!(outcome.publication.candidate_head, None);
    let identity = branch_identity
        .lock()
        .unwrap()
        .clone()
        .expect("branch identity");
    let final_head = persistence
        .managed_workspace_head(&identity)
        .unwrap();
    assert!(
        final_head.head_version > base.1,
        "the one publication advances the branch head"
    );
    assert!(
        !root.join("workspace").join("p1.txt").exists()
            && !root.join("workspace").join("p2.txt").exists(),
        "the original source workspace is not modified by the view children"
    );
    drop(runtime);
    service.shutdown().await.unwrap();
}
