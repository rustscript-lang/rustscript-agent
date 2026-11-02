use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_does_not_revoke_b_with_the_same_installed_package() {
    let (_root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let first = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"A"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let pin = service
        .handle(&first.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let a = &pin.managed.as_ref().unwrap().code;
    let control = crate::plugins::PluginControlStore::new(&p);
    let mut b = control.load_lock(&a.graph_id).unwrap().lock;
    b.graph_id = uuid::Uuid::new_v4().to_string();
    control.store_lock(&b).unwrap();
    let refs: Vec<_> = b
        .packages
        .iter()
        .map(|p| crate::plugins::PackageArtifactRef {
            package_id: p.id.clone(),
            version: p.version.clone(),
            kind: p.kind.clone(),
            artifact_id: p.artifact_id.clone(),
        })
        .collect();
    let activated = control
        .activate(&b.graph_id, a.activation_generation, &refs)
        .unwrap();
    control
        .revoke_graph(&service.tool_store().unwrap(), &a.graph_id)
        .unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"B-write","name":"write_file","arguments":{"path":"b.txt","content":"B"}}),
    )));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"B after revoke A"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let pin_b = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let binding = pin_b.managed.as_ref().unwrap();
    assert_eq!(binding.code.graph_id, b.graph_id);
    assert_eq!(binding.code.artifact_id, a.artifact_id);
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    let record = p
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: "B-write".into(),
        })
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    assert_eq!(control.activation().unwrap(), activated);
    assert!(control.graph_revocation(&b.graph_id).unwrap().is_none());
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn current_http_routes_preserve_missing_package_and_revoked_graph_codes() {
    use std::future::IntoFuture;
    let (root, state, source) = super::protocol::maintenance_source().await;
    let service = state.service();
    let p = state.persistence().unwrap();
    let request = super::protocol::restore_request(&state, &source).await;
    let pin = service
        .handle(&source.source_run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let code = &pin.managed.as_ref().unwrap().code;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        axum::serve(listener, crate::build_agent_gateway_app(state.clone()))
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .into_future(),
    );
    let path = format!("/v1/workspaces/{}/restore", source.workspace_id);
    let artifact = root
        .join(".gateway.sqlite.tool-packages/artifacts")
        .join(&code.artifact_id);
    let held = root.join("http-held-package");
    fs::rename(&artifact, &held).unwrap();
    let missing =
        super::protocol::maintenance_http(address, &path, serde_json::to_value(&request).unwrap())
            .await;
    fs::rename(&held, &artifact).unwrap();
    assert_eq!(missing.0, 422);
    assert_eq!(missing.1["error"]["code"], "plugin_artifact_unavailable");
    let control = crate::plugins::PluginControlStore::new(&p);
    let checkpoint_ref = control
        .retained(&code.graph_id)
        .unwrap()
        .into_iter()
        .find(|r| r.owner_kind == "checkpoint" && r.owner_id == request.checkpoint_id)
        .unwrap();
    control.release(&checkpoint_ref).unwrap();
    let missing_pin =
        super::protocol::maintenance_http(address, &path, serde_json::to_value(&request).unwrap())
            .await;
    assert_eq!(missing_pin.0, 422);
    assert_eq!(missing_pin.1["error"]["code"], "plugin_graph_pin_required");
    control.retain(&checkpoint_ref).unwrap();
    control
        .revoke_graph(&service.tool_store().unwrap(), &code.graph_id)
        .unwrap();
    let revoked =
        super::protocol::maintenance_http(address, &path, serde_json::to_value(&request).unwrap())
            .await;
    assert_eq!(revoked.0, 409);
    assert_eq!(revoked.1["error"]["code"], "plugin_graph_revoked");
    let ordinary = super::protocol::maintenance_http(
        address,
        "/v1/runs",
        json!({"input":"must not admit revoked graph"}),
    )
    .await;
    assert_eq!(ordinary.0, 409);
    assert_eq!(ordinary.1["error"]["code"], "plugin_graph_revoked");
    for code in [
        "plugin_graph_revoked",
        "plugin_graph_pin_required",
        "plugin_artifact_unavailable",
    ] {
        assert!(!crate::runtime::agent_host::error_is_retryable_code(code));
    }
    let _ = stop.send(());
    server.await.unwrap().unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn already_begun_call_finishes_after_revoke_and_exact_replay_does_not_execute_again() {
    let (root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let sentinel = root.join("revoked-entered-sentinel");
    let provider = Arc::new(ExactReplayProvider {
        persistence: p.clone(),
        service: Arc::downgrade(&service),
        run_id: std::sync::Mutex::new(String::new()),
        call: json!({"id":"once","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'; printf observed",sentinel.display())],"timeout_ms":1000}}),
        step: std::sync::atomic::AtomicUsize::new(0),
        replayed: std::sync::Mutex::new(None),
    });
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"begin then revoke"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    *provider.run_id.lock().unwrap() = run.run_id.clone();
    let pin = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let graph = pin.managed.as_ref().unwrap().code.graph_id.clone();
    let revoker = p.clone();
    let graph_copy = graph.clone();
    *p.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueue| {
        if op == "effect.prepare" && enqueue {
            revoker
                .plugin_control_command(
                    "plugin.graph_revoke",
                    &json!({"graph_id":graph_copy,"now_ms":100,"failpoint":""}),
                )
                .unwrap();
        }
    }));
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    *p.managed_request_hook.lock().unwrap() = None;
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    assert_eq!(
        provider.replayed.lock().unwrap().as_ref().unwrap()["ok"],
        true
    );
    let record = p
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: pin.managed.as_ref().unwrap().owner.clone(),
            call_id: "once".into(),
        })
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    assert!(
        crate::plugins::PluginControlStore::new(&p)
            .graph_revocation(&graph)
            .unwrap()
            .is_some()
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_requirement_binding_or_exact_ref_cannot_exempt_managed_begin() {
    for mutation in ["drop_requirement", "drop_binding", "replace_ref"] {
        let (_root, state) = fixture();
        let service = state.service();
        let p = state.persistence().unwrap();
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(Some(json!({"id":"missing-state","name":"write_file","arguments":{"path":"never.txt","content":"deny"}}))));
        provider.push_ok(response(None));
        service.inject_provider_host(provider);
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"text":"missing required state"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let pin = service
            .handle(&run.run_id)
            .unwrap()
            .pinned_tool
            .clone()
            .unwrap();
        p.mutate_graph_pin_for_test(&run.run_id, mutation).unwrap();
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new())
            .await;
        let events = service.run_events(&run.run_id);
        assert!(
            events.iter().any(|e| e["event"] == "tool.failed"
                && e["data"]["error_code"] == "plugin_graph_pin_required"),
            "{mutation} must fail typed: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e["event"].as_str(), Some("tool.requested" | "tool.started")))
        );
        assert!(
            p.managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                owner: pin.managed.as_ref().unwrap().owner.clone(),
                call_id: "missing-state".into()
            })
            .unwrap()
            .is_none()
        );
        service.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn required_identity_is_typed_durable_state_not_caller_receipt() {
    let (_root, state) = fixture();
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"requirement"}),
                idempotency_key: Some("caller-key".into()),
                idempotency_hash: Some("fnv64:0000000000000000".into()),
                graph_id: None,
                workspace_branch: None,
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let p = state.persistence().unwrap();
    let pin = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let binding = pin.managed.as_ref().unwrap();
    let result = p.plugin_control_command(
        "plugin.pin_requirement_get",
        &json!({"owner_id":run.run_id}),
    );
    assert!(
        result.is_ok(),
        "required identity must be readable through the closed typed owner: {result:?}"
    );
    let rows = result.unwrap();
    assert_eq!(
        rows["rows"][0],
        json!([
            run.run_id,
            binding.code.graph_id,
            binding.code.graph_ref_id,
            "required"
        ])
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn missing_checkpoint_package_is_distinct_from_revocation_even_with_prepared_cache() {
    let (root, state, source) = super::protocol::maintenance_source().await;
    let service = state.service();
    let request = super::protocol::restore_request(&state, &source).await;
    let pin = service
        .handle(&source.source_run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let code = &pin.managed.as_ref().unwrap().code;
    let path = root
        .join(".gateway.sqlite.tool-packages/artifacts")
        .join(&code.artifact_id);
    let held = root.join("owned-held-package");
    fs::rename(&path, &held).unwrap();
    let result = service.restore_managed_checkpoint_and_admit(request).await;
    fs::rename(&held, &path).unwrap();
    service.shutdown().await.unwrap();
    assert_eq!(
        result.as_ref().err().map(ToString::to_string),
        Some("plugin_artifact_unavailable".into()),
        "missing package must not use an in-memory prepared graph: {result:?}"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_graph_a_survives_collection_and_b_activation_but_revoked_restore_is_atomic() {
    let (_root, state, source) = super::protocol::maintenance_source().await;
    let service = state.service();
    let p = state.persistence().unwrap();
    let request = super::protocol::restore_request(&state, &source).await;
    let pin = service
        .handle(&source.source_run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let code = &pin.managed.as_ref().unwrap().code;
    let control = crate::plugins::PluginControlStore::new(&p);
    let a = control.load_lock(&code.graph_id).unwrap().lock;
    let mut b = a.clone();
    b.graph_id = uuid::Uuid::new_v4().to_string();
    control.store_lock(&b).unwrap();
    let refs: Vec<_> = b
        .packages
        .iter()
        .map(|p| crate::plugins::PackageArtifactRef {
            package_id: p.id.clone(),
            version: p.version.clone(),
            kind: p.kind.clone(),
            artifact_id: p.artifact_id.clone(),
        })
        .collect();
    let active_b = control
        .activate(&b.graph_id, code.activation_generation, &refs)
        .unwrap();
    control
        .release(&crate::plugins::GraphRetention {
            graph_id: a.graph_id.clone(),
            owner_kind: "run".into(),
            owner_id: source.source_run_id.clone(),
            ref_id: code.graph_ref_id.clone(),
        })
        .unwrap();
    assert!(
        !control
            .collect_unreferenced()
            .unwrap()
            .contains(&a.graph_id)
    );
    assert_eq!(control.load_lock(&a.graph_id).unwrap().lock, a);
    assert_eq!(control.activation().unwrap(), active_b);
    let ordinary = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"new run uses B"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let ordinary_pin = service
        .handle(&ordinary.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    assert_eq!(
        ordinary_pin.managed.as_ref().unwrap().code.graph_id,
        b.graph_id
    );
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    service
        .clone()
        .run_worker(ordinary.run_id, String::new())
        .await;
    let restored = service
        .restore_managed_checkpoint_and_admit(request)
        .await
        .unwrap();
    let restored_pin = service
        .handle(&restored.new_run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    assert_eq!(
        restored_pin.managed.as_ref().unwrap().code.graph_id,
        a.graph_id
    );
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"restored-read-a","name":"read_file","arguments":{"path":"original.txt"}}),
    )));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    service
        .clone()
        .run_worker(restored.new_run_id.clone(), String::new())
        .await;
    let record = p
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: restored_pin.managed.as_ref().unwrap().owner.clone(),
            call_id: "restored-read-a".into(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(record.identity.code.graph_id, a.graph_id);
    let result = service
        .managed_runtime_for_test()
        .unwrap()
        .read_result(&record.outcome.unwrap().canonical_result_ref)
        .unwrap();
    assert!(result.to_string().contains("frozen A"));
    assert_eq!(control.activation().unwrap(), active_b);
    service.shutdown().await.unwrap();
    let (_second_root, second, next_source) = super::protocol::maintenance_source().await;
    let service = second.service();
    let p = second.persistence().unwrap();
    let next_request = super::protocol::restore_request(&second, &next_source).await;
    let second_pin = service
        .handle(&next_source.source_run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let graph_id = &second_pin.managed.as_ref().unwrap().code.graph_id;
    let control = crate::plugins::PluginControlStore::new(&p);
    let runtime = service.managed_runtime_for_test().unwrap();
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let before = runtime
        .repository
        .checkpoint_context(&next_source, &cancel)
        .unwrap()
        .head;
    p.plugin_control_command(
        "plugin.graph_revoke",
        &json!({"graph_id":graph_id,"now_ms":300,"failpoint":""}),
    )
    .unwrap();
    let denied = service
        .restore_managed_checkpoint_and_admit(next_request.clone())
        .await;
    assert_eq!(denied.unwrap_err().to_string(), "plugin_graph_revoked");
    assert_eq!(
        runtime
            .repository
            .checkpoint_context(&next_source, &cancel)
            .unwrap()
            .head,
        before
    );
    assert!(
        runtime
            .repository
            .lookup_restore_receipt(&next_request, &cancel)
            .unwrap()
            .is_none()
    );
    assert!(control.load_lock(graph_id).is_ok());
    assert!(
        control
            .retained(graph_id)
            .unwrap()
            .iter()
            .any(|r| r.owner_id == next_source.source_run_id)
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_graph_revoke_is_monotonic_rollback_safe_and_survives_reopen() {
    let (root, state) = fixture();
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"pin"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let pin = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let graph = &pin.managed.as_ref().unwrap().code.graph_id;
    let p = state.persistence().unwrap();
    let result = p.plugin_control_command(
        "plugin.graph_revoke",
        &json!({"graph_id":graph,"now_ms":100,"failpoint":""}),
    );
    assert!(
        result.is_ok(),
        "trusted closed revoke command must persist a graph fact: {result:?}"
    );
    let first = p
        .plugin_control_command("plugin.graph_revocation_get", &json!({"graph_id":graph}))
        .unwrap();
    assert_eq!(first["rows"][0][0], *graph);
    assert_eq!(first["rows"][0][1], 100);
    let control = crate::plugins::PluginControlStore::new(&p);
    let typed = control
        .revoke_graph(&service.tool_store().unwrap(), graph)
        .unwrap();
    assert_eq!(typed.revoked_at_ms, 100);
    assert_eq!(control.graph_revocation(graph).unwrap(), Some(typed));
    p.plugin_control_command(
        "plugin.graph_revoke",
        &json!({"graph_id":graph,"now_ms":200,"failpoint":""}),
    )
    .unwrap();
    assert_eq!(
        p.plugin_control_command("plugin.graph_revocation_get", &json!({"graph_id":graph}))
            .unwrap(),
        first
    );
    assert!(
        p.plugin_control_command(
            "plugin.graph_revoke",
            &json!({"graph_id":"rollback-graph","now_ms":300,"failpoint":"after_partial_write"})
        )
        .is_err()
    );
    assert!(
        p.plugin_control_command(
            "plugin.graph_revocation_get",
            &json!({"graph_id":"rollback-graph"})
        )
        .unwrap()["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    service.shutdown().await.unwrap();
    p.shutdown();
    drop(p);
    drop(service);
    drop(state);
    let reopened = crate::GatewayPersistence::open(
        &AgentGatewayConfig::default(),
        &root.join("gateway.sqlite"),
    )
    .unwrap();
    assert_eq!(
        reopened
            .plugin_control_command("plugin.graph_revocation_get", &json!({"graph_id":graph}))
            .unwrap(),
        first
    );
    reopened.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_retained_graph_refuses_new_native_call_after_successful_diagnostic_read() {
    let (_root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"revoked-call","name":"write_file","arguments":{"path":"denied.txt","content":"must not publish"}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"revoke before begin"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let pin = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let binding = pin.managed.as_ref().unwrap();
    let graph = &binding.code.graph_id;
    let before = p
        .plugin_control_command("plugin.graph_revocation_get", &json!({"graph_id":graph}))
        .unwrap();
    assert!(before["rows"].as_array().unwrap().is_empty());
    p.plugin_control_command(
        "plugin.graph_revoke",
        &json!({"graph_id":graph,"now_ms":100,"failpoint":""}),
    )
    .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let events = service.run_events(&run.run_id);
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "tool.failed"
                && e["data"]["error_code"] == "plugin_graph_revoked"),
        "revoked retained graph must fail with safe typed code: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e["event"].as_str(), Some("tool.requested" | "tool.started")))
    );
    assert!(
        p.managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: "revoked-call".into()
        })
        .unwrap()
        .is_none()
    );
    assert!(
        crate::plugins::PluginControlStore::new(&p)
            .retained(graph)
            .unwrap()
            .iter()
            .any(|r| r.owner_id == run.run_id)
    );
    let pair = p.event_append_pair(&json!({"run_id":run.run_id,"event_id_a":"non-effect-a","event_type_a":"tool.requested","payload_json_a":"{}","event_id_b":"non-effect-b","event_type_b":"tool.started","payload_json_b":"{}","now_ms":200,"max_events":1}));
    assert_eq!(pair.unwrap_err().code, "plugin_graph_revoked");
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_graph_fresh_admission_returns_distinct_code_without_publication() {
    let (_root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let first = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"first"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let pin = service
        .handle(&first.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let graph = &pin.managed.as_ref().unwrap().code.graph_id;
    p.plugin_control_command(
        "plugin.graph_revoke",
        &json!({"graph_id":graph,"now_ms":100,"failpoint":""}),
    )
    .unwrap();
    let captured = Arc::new(std::sync::Mutex::new(None));
    let sink = captured.clone();
    p.inject_admission_precommit_hook(move |payload| {
        *sink.lock().unwrap() = Some(payload.clone());
    });
    let result = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"must not admit"}),
                ..Default::default()
            },
            None,
        )
        .await;
    assert_eq!(
        result.as_ref().err().map(|e| format!("{e:?}")),
        Some("PluginGraphRevoked".into()),
        "revocation must reject fresh admission: {result:?}"
    );
    assert_eq!(
        crate::plugins::PluginControlStore::new(&p)
            .retained(graph)
            .unwrap()
            .iter()
            .filter(|r| r.owner_kind == "run")
            .count(),
        1
    );
    let payload = captured.lock().unwrap().clone().unwrap();
    let run_id = payload["run_id"].as_str().unwrap();
    let session_id = payload["session_id"].as_str().unwrap();
    assert!(
        p.run_get(run_id).unwrap()["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        p.session_get(session_id).unwrap()["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        p.message_list(session_id, 0).unwrap()["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        p.event_replay(&json!({"run_id":run_id,"after_seq":0,"max_events":128,"max_bytes":65536}))
            .unwrap()["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        crate::plugins::PluginControlStore::new(&p)
            .pin_requirement_for_run(run_id)
            .unwrap()
            .is_none()
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn released_required_managed_pin_refuses_native_begin_without_intent_or_execution() {
    let (root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"must-not-start","name":"write_file","arguments":{"path":"denied.txt","content":"must not publish"}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"new managed call"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let pin = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    let binding = pin.managed.as_ref().unwrap();
    crate::plugins::PluginControlStore::new(&p)
        .release(&crate::plugins::GraphRetention {
            graph_id: binding.code.graph_id.clone(),
            owner_kind: "run".into(),
            owner_id: run.run_id.clone(),
            ref_id: binding.code.graph_ref_id.clone(),
        })
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let events = service.run_events(&run.run_id);
    let failed: Vec<_> = events
        .iter()
        .filter(|e| e["event"] == "tool.failed")
        .collect();
    assert!(
        failed
            .iter()
            .any(|e| e["data"]["error_code"] == "plugin_graph_pin_required"),
        "typed pin rejection must reach real tool.failed: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e["event"].as_str(), Some("tool.requested" | "tool.started")))
    );
    let owner = crate::effects::ManagedOwnerScope {
        profile: binding.owner.profile.clone(),
        session_id: run.session_id.clone(),
        run_id: run.run_id.clone(),
    };
    assert!(
        p.managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner,
            call_id: "must-not-start".into()
        })
        .unwrap()
        .is_none()
    );
    assert!(!root.join("workspace/denied.txt").exists());
    service.shutdown().await.unwrap();
}
