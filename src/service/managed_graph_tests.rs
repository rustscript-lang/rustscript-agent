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
async fn begun_call_finishes_and_exact_replay_does_not_execute_again() {
    let (root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let sentinel = root.join("begun-entered-sentinel");
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
                input: json!({"text":"begin then exact replay"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    *provider.run_id.lock().unwrap() = run.run_id.clone();
    // No revocation: the begun Native call must finish and the same-identity
    // exact replay must verify without a second native execution.
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    assert_eq!(
        provider.replayed.lock().unwrap().as_ref().unwrap()["ok"],
        true
    );
    let record = p
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: service
                .handle(&run.run_id)
                .unwrap()
                .pinned_tool
                .clone()
                .unwrap()
                .managed
                .as_ref()
                .unwrap()
                .owner
                .clone(),
            call_id: "once".into(),
        })
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    let events = service.run_events(&run.run_id);
    let completed = events
        .iter()
        .find(|event| event["event"] == "tool.completed")
        .expect("managed tool completion");
    assert_eq!(
        completed["data"]["name"], "terminal",
        "managed completion must retain the selected tool name"
    );
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
    // R470-2: clear the prepare hook the moment the worker returns, before
    // any fallible summary read, so a failed read cannot unwind with the
    // p→hook→p cycle still installed. Summaries stay Results until the
    // shutdown completes; only then are they asserted.
    *p.managed_request_hook.lock().unwrap() = None;
    let request = crate::effects::ManagedEffectGetRequest {
        owner: pin.managed.as_ref().unwrap().owner.clone(),
        call_id: "once".into(),
    };
    let events = service.run_events(&run.run_id);
    let record_result = p.managed_effect_get(&request);
    let replay_result = service.replay_managed_call(request.clone());
    let facade_result = service.replay_durable_tool_result(&run.run_id, "once", "terminal");
    let step = provider.step.load(std::sync::atomic::Ordering::SeqCst);
    let replayed_none = provider.replayed.lock().unwrap().is_none();
    let tombstone_result = crate::plugins::PluginControlStore::new(&p).graph_revocation(&graph);
    let shutdown_result = service.shutdown().await;
    shutdown_result.unwrap();
    let record = record_result.unwrap().unwrap();
    let replay = replay_result.unwrap();
    let facade = facade_result.unwrap().unwrap();
    let tombstone = tombstone_result.unwrap().is_some();
    // Already-begun first result finishes exactly once under the early
    // Service revoke; the second provider never runs. This is Service
    // scheduling coverage only, never a Native PASS from a missing probe.
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    assert_eq!(
        step, 1,
        "second provider must never run after the early revoke"
    );
    assert!(
        replayed_none,
        "Native replay probe must stay None when the Service guard stops the second provider"
    );
    let completed = events
        .iter()
        .filter(|event| event["event"] == "tool.completed")
        .count();
    let failed = events
        .iter()
        .filter(|event| event["event"] == "tool.failed")
        .count();
    assert_eq!(
        completed, 1,
        "begun first result must complete exactly once"
    );
    assert_eq!(failed, 0, "begun first result must not fail");
    assert!(
        events.iter().any(|event| event["event"] == "run.failed"
            && event.to_string().contains("plugin_graph_revoked")),
        "run must end revoked after the early Service denial: {events:?}"
    );
    assert!(
        record.outcome.is_some(),
        "original outcome must stay durable"
    );
    let crate::effects::ManagedCallReplay::Final {
        outcome,
        canonical_result,
    } = replay
    else {
        panic!("original canonical receipt must stay queryable after revocation");
    };
    // R470-1: exact first-result contract, not a substring probe. The live
    // command prints exactly `observed` with a clean exit, so the sealed
    // canonical bytes must decode to that complete success value, and the
    // history receipt must carry the original durable outcome.
    assert_eq!(
        *outcome,
        record
            .outcome
            .clone()
            .expect("original outcome must stay durable"),
        "history canonical must belong to the original durable outcome"
    );
    let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
    let tool_result = crate::service::canonical_tool_result(&full)
        .expect("history canonical must decode through the existing ToolResult contract");
    assert!(
        tool_result.ok,
        "first result must be an exact success: {full:?}"
    );
    assert_eq!(
        tool_result.content, "observed",
        "first result content must equal the actual command output: {full:?}"
    );
    assert!(
        tool_result.error.is_none(),
        "first result must carry no error: {full:?}"
    );
    assert!(
        !tool_result.truncated,
        "first result must not be truncated: {full:?}"
    );
    assert!(
        tool_result.artifacts.is_empty(),
        "first result must carry no artifacts: {full:?}"
    );
    assert_eq!(
        serde_json::to_value(&facade).unwrap(),
        full,
        "the durable facade must return the full original result, not a projection"
    );
    assert!(tombstone, "exact graph tombstone must exist");
    assert_eq!(
        completed, 1,
        "revoked scheduling must not commit a second result"
    );
}

struct TerminalSameCallRevokeProvider {
    persistence: Arc<crate::GatewayPersistence>,
    service: std::sync::Weak<crate::AgentService>,
    run_id: std::sync::Mutex<String>,
    call: Value,
    step: std::sync::atomic::AtomicUsize,
    denied: std::sync::Mutex<Option<Value>>,
    pre_revoke_outcome: std::sync::Mutex<Option<Value>>,
}

impl crate::AgentProviderHost for TerminalSameCallRevokeProvider {
    fn call(&self, _request: &Value, cancellation: &crate::RunCancellation) -> Value {
        if self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return json!({"ok":true,"response":response(Some(self.call.clone())),"error":{}});
        }
        let service = self.service.upgrade().unwrap();
        let run_id = self.run_id.lock().unwrap().clone();
        let pin = service
            .handle(&run_id)
            .unwrap()
            .pinned_tool
            .clone()
            .unwrap();
        let binding = pin.managed.as_ref().unwrap().clone();
        let graph = binding.code.graph_id.clone();
        // Legal live entry: bridge, original pin, and final receipt are all
        // obtained before the revoke, proving reachability.
        let host = service.capability_host_bridges(&run_id).unwrap().unwrap();
        assert_eq!(
            host.cancellation.as_ref().unwrap().deadline_instant(),
            cancellation.deadline_instant()
        );
        let request = crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: "once".into(),
        };
        let record = self
            .persistence
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert!(
            record.outcome.is_some(),
            "terminal same-call revoke needs a committed final before revoking"
        );
        // R470-1: snapshot the full pre-revoke final outcome; the outer
        // scope compares it verbatim after the revoke and the refused call.
        *self.pre_revoke_outcome.lock().unwrap() =
            Some(serde_json::to_value(record.outcome.as_ref().unwrap()).unwrap());
        let crate::effects::ManagedArgumentIdentity::Inline {
            canonical_arguments,
        } = &record.identity.argument_identity
        else {
            panic!("small fixture arguments should remain inline");
        };
        let canonical = canonical_arguments.clone();
        self.persistence
            .plugin_control_command(
                "plugin.graph_revoke",
                &json!({"graph_id":graph,"now_ms":100,"failpoint":""}),
            )
            .unwrap();
        assert!(
            crate::plugins::PluginControlStore::new(&self.persistence)
                .graph_revocation(&graph)
                .unwrap()
                .is_some(),
            "revocation must be durably visible before the same-call invoke"
        );
        let mut host = host;
        host.pinned_tool = Some(pin);
        let wire = json!({"tool_name":"terminal","call_id":"once","canonical_arguments":canonical,"canonical_input":json!({"call":self.call,"config":service.run_context(&run_id).unwrap().limits}).to_string(),"run_id":run_id,"registry_identity":host.lifecycle.as_ref().unwrap().registry_identity(),"argument_digest":canonical,"risk_class":"execute","summary":"terminal","untrusted_graph_id":""});
        let input = rustscript_vm::Value::map(
            wire.as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| {
                    (
                        rustscript_vm::Value::string(key),
                        rustscript_vm::Value::string(value.as_str().unwrap()),
                    )
                })
                .collect(),
        );
        let source = r#"pub fn run(context:map)->map {
            let tool_name:string=context["tool_name"];let call_id:string=context["call_id"];let canonical_arguments:string=context["canonical_arguments"];let canonical_input:string=context["canonical_input"];let run_id:string=context["run_id"];let registry_identity:string=context["registry_identity"];let argument_digest:string=context["argument_digest"];let risk_class:string=context["risk_class"];let summary:string=context["summary"];let untrusted_graph_id:string=context["untrusted_graph_id"];
            agent_runtime::invoke_pinned_tool({tool_name:tool_name,call_id:call_id,canonical_arguments:canonical_arguments,canonical_input:canonical_input,run_id:run_id,registry_identity:registry_identity,argument_digest:argument_digest,risk_class:risk_class,summary:summary,untrusted_graph_id:untrusted_graph_id})
        }"#;
        let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
            .unwrap()
            .with_host(host);
        let denied = native_json(&runner.run_with_context(input).unwrap());
        *self.denied.lock().unwrap() = Some(denied);
        json!({"ok":true,"response":response(None),"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_same_call_revoke_refuses_native_execution_after_live_entry() {
    let (root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let sentinel = root.join("revoked-entered-sentinel");
    let provider = Arc::new(TerminalSameCallRevokeProvider {
        persistence: p.clone(),
        service: Arc::downgrade(&service),
        run_id: std::sync::Mutex::new(String::new()),
        call: json!({"id":"once","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'; printf observed",sentinel.display())],"timeout_ms":1000}}),
        step: std::sync::atomic::AtomicUsize::new(0),
        denied: std::sync::Mutex::new(None),
        pre_revoke_outcome: std::sync::Mutex::new(None),
    });
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"terminal same-call revoke after live entry"}),
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
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    let request = crate::effects::ManagedEffectGetRequest {
        owner: pin.managed.as_ref().unwrap().owner.clone(),
        call_id: "once".into(),
    };
    let events = service.run_events(&run.run_id);
    let record_result = p.managed_effect_get(&request);
    let replay_result = service.replay_managed_call(request.clone());
    let facade_result = service.replay_durable_tool_result(&run.run_id, "once", "terminal");
    let denied_option = provider.denied.lock().unwrap().clone();
    let baseline_option = provider.pre_revoke_outcome.lock().unwrap().clone();
    let tombstone_result = crate::plugins::PluginControlStore::new(&p).graph_revocation(&graph);
    service.shutdown().await.unwrap();
    let record = record_result.unwrap().unwrap();
    let replay = replay_result.unwrap();
    let facade = facade_result.unwrap().unwrap();
    let tombstone = tombstone_result.unwrap().is_some();
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    let denied = denied_option.expect("same-call Native denial envelope must be stored");
    assert_eq!(
        denied["ok"], false,
        "revoked same-call invoke must be refused: {denied}"
    );
    assert_eq!(
        denied["code"], "plugin_graph_revoked",
        "same-call invoke must keep the exact revocation code: {denied}"
    );
    assert!(
        denied
            .get("canonical_result")
            .is_none_or(|value| value == ""),
        "refused same-call invoke must not leak a canonical result: {denied}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.completed")
            .count(),
        1,
        "refused same-call invoke must not commit a second result"
    );
    assert!(
        record.outcome.is_some(),
        "original outcome must stay durable"
    );
    let crate::effects::ManagedCallReplay::Final {
        outcome,
        canonical_result,
    } = replay
    else {
        panic!("original canonical receipt must stay queryable after revocation");
    };
    // R470-1: the post-revoke outcome and the history receipt must equal
    // the full pre-revoke final baseline snapshotted in the provider, and
    // the sealed canonical bytes must decode to the complete first result.
    let baseline = baseline_option
        .expect("provider must snapshot the pre-revoke final outcome before revoking");
    assert_eq!(
        serde_json::to_value(
            record
                .outcome
                .as_ref()
                .expect("original outcome must stay durable")
        )
        .unwrap(),
        baseline,
        "post-revoke outcome must equal the pre-revoke final baseline"
    );
    assert_eq!(
        serde_json::to_value(outcome.as_ref()).unwrap(),
        baseline,
        "history canonical must belong to the pre-revoke final baseline"
    );
    let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
    let tool_result = crate::service::canonical_tool_result(&full)
        .expect("history canonical must decode through the existing ToolResult contract");
    assert!(
        tool_result.ok,
        "first result must be an exact success: {full:?}"
    );
    assert_eq!(
        tool_result.content, "observed",
        "first result content must equal the actual command output: {full:?}"
    );
    assert!(
        tool_result.error.is_none(),
        "first result must carry no error: {full:?}"
    );
    assert!(
        !tool_result.truncated,
        "first result must not be truncated: {full:?}"
    );
    assert!(
        tool_result.artifacts.is_empty(),
        "first result must carry no artifacts: {full:?}"
    );
    assert_eq!(
        serde_json::to_value(&facade).unwrap(),
        full,
        "the durable facade must return the full original result, not a projection"
    );
    assert!(tombstone, "exact graph tombstone must exist");
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
        // Early run-level refusal: the refresh guard rejects before any
        // provider dispatch, so the run terminates with run.failed carrying
        // the generic terminal code plus the precise graph reason in the
        // message. tool.failed never fires; the per-mutation typed refusal
        // at the native-begin boundary is covered by
        // native_begin_boundary_refuses_mutated_pin_with_typed_code.
        let failed: Vec<_> = events
            .iter()
            .filter(|e| e["event"] == "run.failed")
            .collect();
        assert_eq!(
            failed.len(),
            1,
            "{mutation} must terminate the run exactly once: {events:?}"
        );
        assert_eq!(failed[0]["data"]["error_code"], "agent_failed");
        // The precise graph reason survives in the message in one of two
        // closed forms: bare from the refresh guard, or wrapped with the run
        // identity when capability-host construction rejects first. Both pin
        // the exact code; nothing else is accepted.
        let message = failed[0]["data"]["error_message"]
            .as_str()
            .expect("run.failed carries a text message");
        assert!(
            message == "plugin_graph_pin_required"
                || message
                    == format!(
                        "run {} context metadata is invalid: plugin_graph_pin_required",
                        run.run_id
                    ),
            "{mutation} must retain the precise graph reason: {events:?}"
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
    // The not-begun call never executes: no tool lifecycle events at all.
    // The refusal surfaces at run level with the exact revocation code.
    assert!(
        !events
            .iter()
            .any(|e| e["event"].as_str().is_some_and(|name| {
                matches!(
                    name,
                    "tool.requested" | "tool.started" | "tool.completed" | "tool.failed"
                )
            })),
        "refused call must not emit tool events: {events:?}"
    );
    assert!(
        events.iter().any(|e| e["event"] == "run.failed"
            && e["data"]["error_code"] == "agent_failed"
            && e["data"]["error_message"]
                .as_str()
                .is_some_and(|message| message.contains("plugin_graph_revoked"))),
        "revoked retained graph must fail the run with the exact revocation refusal: {events:?}"
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
    let payload = captured.lock().unwrap().clone();
    assert!(
        payload.is_none(),
        "early revocation rejection must skip the admission transaction entirely"
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_between_prepare_and_commit_rolls_back_without_publication() {
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
    let graph = service
        .handle(&first.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap()
        .managed
        .as_ref()
        .unwrap()
        .code
        .graph_id
        .clone();
    // Revoke after preparation but before the admission transaction: the
    // precommit hook runs inside admission_create, after prepare_production_pin.
    let revoker = p.clone();
    let graph_copy = graph.clone();
    let captured = Arc::new(std::sync::Mutex::new(None));
    let sink = captured.clone();
    p.inject_admission_precommit_hook(move |payload| {
        *sink.lock().unwrap() = Some(payload.clone());
        revoker
            .plugin_control_command(
                "plugin.graph_revoke",
                &json!({"graph_id":graph_copy,"now_ms":100,"failpoint":""}),
            )
            .unwrap();
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
    let payload = captured.lock().unwrap().clone().unwrap();
    let run_id = payload["run_id"].as_str().unwrap();
    let session_id = payload["session_id"].as_str().unwrap();
    assert_eq!(
        result.as_ref().err().map(|e| format!("{e:?}")),
        Some("PluginGraphRevoked".into()),
        "post-prepare revocation must refuse with the same typed code: {result:?}"
    );
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
        .filter(|e| e["event"] == "run.failed")
        .collect();
    // Early run-level refusal: releasing the required pin rejects before any
    // provider dispatch. The terminal carries the generic agent_failed code
    // with the precise pin reason; the typed gate refusal is covered by
    // native_begin_boundary_refuses_mutated_pin_with_typed_code.
    assert_eq!(
        failed.len(),
        1,
        "released pin must terminate the run exactly once: {events:?}"
    );
    assert_eq!(failed[0]["data"]["error_code"], "agent_failed");
    assert_eq!(
        failed[0]["data"]["error_message"], "plugin_graph_pin_required",
        "typed pin rejection must reach the real run terminal: {events:?}"
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

#[tokio::test(flavor = "multi_thread")]
async fn native_begin_boundary_refuses_mutated_pin_with_typed_code() {
    use crate::AgentProviderHost;
    for mutation in ["drop_requirement", "drop_binding", "replace_ref"] {
        let (_root, state) = fixture();
        let service = state.service();
        let p = state.persistence().unwrap();
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(Some(json!({"id":"native-begin","name":"write_file","arguments":{"path":"never.txt","content":"deny"}}))));
        provider.push_ok(response(None));
        service.inject_provider_host(provider.clone());
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"text":"mutated pin at native begin"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let handle = service.handle(&run.run_id).unwrap();
        let durable = crate::durable_provider::DurableProviderHost::new(
            (*service).clone(),
            run.run_id.clone(),
            provider.clone(),
            service.inner.metrics.clone(),
        );
        // Legal tool parent: one real provider turn passes the admitted gate.
        let request = json!({"model":"synthetic","messages":[]});
        assert_eq!(durable.call(&request, &handle.cancel)["ok"], true);
        // Mutate only after the legal parent exists, at the native-begin
        // boundary the real worker would cross next.
        p.mutate_graph_pin_for_test(&run.run_id, mutation).unwrap();
        assert_eq!(
            service.check_harness_run(
                &run.run_id,
                &handle.cancel,
                #[cfg(feature = "workspace-io-fault")]
                None,
            ),
            Err("plugin_graph_pin_required"),
            "{mutation}"
        );
        assert_eq!(
            durable.call(&request, &handle.cancel)["error"]["code"],
            "plugin_graph_pin_required",
            "{mutation}"
        );
        let context = serde_json::to_value(service.run_context(&run.run_id).unwrap()).unwrap();
        assert_eq!(
            service.refresh_provider_context(&run.run_id, &context, &handle.cancel)["error"]["code"],
            "plugin_graph_pin_required",
            "{mutation}"
        );
        assert_eq!(
            provider.requests().len(),
            1,
            "{mutation} must not reach the transport again"
        );
        service.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn native_probe_positive_control_executes_legal_parent_through_pinned_begin() {
    use crate::AgentProviderHost;
    let (_root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let call = json!({"id":"native-begin","name":"write_file","arguments":{"path":"control.txt","content":"control"}});
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(call.clone())));
    provider.push_ok(response(None));
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"legal parent before native begin"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    let durable = crate::durable_provider::DurableProviderHost::new(
        (*service).clone(),
        run.run_id.clone(),
        provider.clone(),
        service.inner.metrics.clone(),
    );
    let request = json!({"model":"synthetic","messages":[]});
    assert_eq!(durable.call(&request, &handle.cancel)["ok"], true);
    let host = service
        .capability_host_bridges(&run.run_id)
        .unwrap()
        .unwrap();
    let canonical = call["arguments"].to_string();
    let result = native_probe(
        &service,
        host,
        &run.run_id,
        &call,
        &canonical,
        "write",
        true,
    );
    assert_eq!(result["ok"], true, "{result}");
    let pin = handle.pinned_tool.clone().unwrap();
    let binding = pin.managed.as_ref().unwrap();
    let record = p
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: "native-begin".into(),
        })
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    assert!(record.prepared.as_ref().unwrap().candidate_root.is_some());
    assert_eq!(provider.requests().len(), 1);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn native_begin_after_pin_mutation_reaches_boundary_and_refuses_without_intent() {
    use crate::AgentProviderHost;
    for mutation in ["drop_requirement", "drop_binding", "replace_ref"] {
        let (root, state) = fixture();
        let service = state.service();
        let p = state.persistence().unwrap();
        let call = json!({"id":"native-begin","name":"write_file","arguments":{"path":"never.txt","content":"deny"}});
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(Some(call.clone())));
        provider.push_ok(response(None));
        service.inject_provider_host(provider.clone());
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"text":"mutated pin at real native begin"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let handle = service.handle(&run.run_id).unwrap();
        let durable = crate::durable_provider::DurableProviderHost::new(
            (*service).clone(),
            run.run_id.clone(),
            provider.clone(),
            service.inner.metrics.clone(),
        );
        // Legal tool parent: one real provider turn passes the admitted gate.
        let request = json!({"model":"synthetic","messages":[]});
        assert_eq!(durable.call(&request, &handle.cancel)["ok"], true);
        let pin = handle.pinned_tool.clone().unwrap();
        let binding = pin.managed.as_ref().unwrap();
        let workspace = binding.admitted_branch.clone();
        let head_before = p.managed_workspace_head(&workspace).unwrap().head_version;
        // Obtain the original host while the admission is still valid; the
        // mutation is applied only after the parent turn and host capture.
        let host = service
            .capability_host_bridges(&run.run_id)
            .unwrap()
            .unwrap();
        p.mutate_graph_pin_for_test(&run.run_id, mutation).unwrap();
        let canonical = call["arguments"].to_string();
        let result = native_probe(
            &service,
            host,
            &run.run_id,
            &call,
            &canonical,
            "write",
            true,
        );
        // All three static pin mutations reach the later child `tool_prepare`
        // cut: the exact typed LifecycleError is serialized as the complete
        // three-field canonical error envelope, and the outer human message is
        // the LifecycleError message, not the code.
        assert_eq!(result["ok"], false, "{mutation}: {result}");
        assert_eq!(result["kind"], "error", "{mutation}: {result}");
        assert_eq!(
            result["code"], "plugin_graph_pin_required",
            "{mutation}: {result}"
        );
        assert_eq!(
            result["message"], "tool graph pin is required",
            "{mutation}: {result}"
        );
        assert_eq!(result["content"], "", "{mutation}: {result}");
        assert_eq!(result["text"], "", "{mutation}: {result}");
        let canonical_result = result["canonical_result"].as_str().unwrap_or_else(|| {
            panic!("{mutation} must return the pinned Native outcome: {result}")
        });
        assert_eq!(
            serde_json::from_str::<Value>(canonical_result).unwrap(),
            json!({
                "ok": false,
                "kind": "error",
                "error": {
                    "code": "plugin_graph_pin_required",
                    "message": "tool graph pin is required",
                },
            }),
            "{mutation} canonical must be the exact typed refusal: {result}"
        );
        assert!(
            result.get("managed_publication").is_none(),
            "{mutation} must not return a managed success publication: {result}"
        );
        assert!(
            p.managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                owner: binding.owner.clone(),
                call_id: "native-begin".into(),
            })
            .unwrap()
            .is_none()
        );
        assert!(
            !service
                .run_events(&run.run_id)
                .iter()
                .any(|e| matches!(e["event"].as_str(), Some("tool.requested" | "tool.started")))
        );
        assert_eq!(
            p.managed_workspace_head(&workspace).unwrap().head_version,
            head_before,
            "{mutation} must not publish a branch effect"
        );
        assert!(!root.join("workspace/never.txt").exists());
        assert_eq!(provider.requests().len(), 1, "{mutation}");
        service.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn native_begin_after_release_or_revoke_reaches_boundary_and_refuses_without_effect() {
    use crate::AgentProviderHost;
    for case in ["release", "revoke"] {
        let (root, state) = fixture();
        let service = state.service();
        let p = state.persistence().unwrap();
        let call = json!({"id":"native-begin","name":"write_file","arguments":{"path":"never.txt","content":"deny"}});
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(Some(call.clone())));
        provider.push_ok(response(None));
        service.inject_provider_host(provider.clone());
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"text":"released or revoked at real native begin"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let handle = service.handle(&run.run_id).unwrap();
        let pin = handle.pinned_tool.clone().unwrap();
        let binding = pin.managed.as_ref().unwrap();
        let graph = binding.code.graph_id.clone();
        let workspace = binding.admitted_branch.clone();
        let durable = crate::durable_provider::DurableProviderHost::new(
            (*service).clone(),
            run.run_id.clone(),
            provider.clone(),
            service.inner.metrics.clone(),
        );
        let request = json!({"model":"synthetic","messages":[]});
        assert_eq!(durable.call(&request, &handle.cancel)["ok"], true);
        let head_before = p.managed_workspace_head(&workspace).unwrap().head_version;
        let host = service
            .capability_host_bridges(&run.run_id)
            .unwrap()
            .unwrap();
        if case == "release" {
            crate::plugins::PluginControlStore::new(&p)
                .release(&crate::plugins::GraphRetention {
                    graph_id: graph.clone(),
                    owner_kind: "run".into(),
                    owner_id: run.run_id.clone(),
                    ref_id: binding.code.graph_ref_id.clone(),
                })
                .unwrap();
        } else {
            p.plugin_control_command(
                "plugin.graph_revoke",
                &json!({"graph_id":graph,"now_ms":100,"failpoint":""}),
            )
            .unwrap();
        }
        let canonical = call["arguments"].to_string();
        let result = native_probe(
            &service,
            host,
            &run.run_id,
            &call,
            &canonical,
            "write",
            true,
        );
        // Two legally distinct static cuts. The formal release reaches the
        // later child `tool_prepare` LifecycleError and serializes the complete
        // three-field canonical error envelope; the revoke reaches the early
        // fresh-authority guard with an empty kind and an empty canonical
        // envelope. Each case keeps its own exact shape.
        assert_eq!(result["ok"], false, "{case}: {result}");
        if case == "release" {
            assert_eq!(result["kind"], "error", "{case}: {result}");
            assert_eq!(
                result["code"], "plugin_graph_pin_required",
                "{case}: {result}"
            );
            assert_eq!(
                result["message"], "tool graph pin is required",
                "{case}: {result}"
            );
            assert_eq!(result["content"], "", "{case}: {result}");
            assert_eq!(result["text"], "", "{case}: {result}");
            let canonical_result = result["canonical_result"].as_str().unwrap_or_else(|| {
                panic!("{case} must return the pinned Native outcome: {result}")
            });
            assert_eq!(
                serde_json::from_str::<Value>(canonical_result).unwrap(),
                json!({
                    "ok": false,
                    "kind": "error",
                    "error": {
                        "code": "plugin_graph_pin_required",
                        "message": "tool graph pin is required",
                    },
                }),
                "{case} canonical must be the exact typed refusal: {result}"
            );
        } else {
            assert_eq!(result["kind"], "", "{case}: {result}");
            assert_eq!(result["code"], "plugin_graph_revoked", "{case}: {result}");
            assert_eq!(
                result["message"], "plugin_graph_revoked",
                "{case}: {result}"
            );
            assert_eq!(result["content"], "", "{case}: {result}");
            assert_eq!(result["text"], "", "{case}: {result}");
            assert_eq!(result["canonical_result"], "", "{case}: {result}");
        }
        assert!(
            result.get("managed_publication").is_none(),
            "{case} must not return a managed success publication: {result}"
        );
        assert!(
            p.managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                owner: binding.owner.clone(),
                call_id: "native-begin".into(),
            })
            .unwrap()
            .is_none()
        );
        assert!(
            !service
                .run_events(&run.run_id)
                .iter()
                .any(|e| matches!(e["event"].as_str(), Some("tool.requested" | "tool.started")))
        );
        assert_eq!(
            p.managed_workspace_head(&workspace).unwrap().head_version,
            head_before,
            "{case} must not publish a branch effect"
        );
        assert!(!root.join("workspace/never.txt").exists());
        assert_eq!(provider.requests().len(), 1, "{case}");
        service.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn after_revoke_completed_identity_native_replay_refuses_execution_and_preserves_history() {
    use crate::AgentProviderHost;
    let (root, state) = fixture();
    let service = state.service();
    let p = state.persistence().unwrap();
    let sentinel = root.join("after-revoke-replay-sentinel");
    let call = json!({"id":"once","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'; printf observed",sentinel.display())],"timeout_ms":1000}});
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(call.clone())));
    provider.push_ok(response(None));
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"text":"completed identity after revoke"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    let durable = crate::durable_provider::DurableProviderHost::new(
        (*service).clone(),
        run.run_id.clone(),
        provider.clone(),
        service.inner.metrics.clone(),
    );
    // Real parent provider turn: the tool call and its arguments become the
    // durable parent fact consumed by the pinned Native entry.
    assert_eq!(
        durable.call(&json!({"model":"synthetic","messages":[]}), &handle.cancel)["ok"],
        true
    );
    let pin = handle.pinned_tool.clone().unwrap();
    let binding = pin.managed.as_ref().unwrap();
    let graph = binding.code.graph_id.clone();
    let owner = binding.owner.clone();
    let workspace = binding.admitted_branch.clone();
    // The original host/cancel pair, captured before any graph revocation.
    let host = service
        .capability_host_bridges(&run.run_id)
        .unwrap()
        .unwrap();
    // Revoke exactly while the first legal Native call is enqueueing its
    // effect.prepare. The hook holds only a Weak owner, so no p->hook->p
    // strong cycle survives a panic, and it is cleared immediately after the
    // first call returns, before any assert or fallible summary read.
    let weak = Arc::downgrade(&p);
    let graph_copy = graph.clone();
    *p.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueue| {
        if op == "effect.prepare"
            && enqueue
            && let Some(revoker) = weak.upgrade()
        {
            revoker
                .plugin_control_command(
                    "plugin.graph_revoke",
                    &json!({"graph_id":graph_copy,"now_ms":100,"failpoint":""}),
                )
                .unwrap();
        }
    }));
    let canonical = call["arguments"].to_string();
    let first = native_probe(
        &service,
        host.clone(),
        &run.run_id,
        &call,
        &canonical,
        "execute",
        true,
    );
    *p.managed_request_hook.lock().unwrap() = None;
    let request = crate::effects::ManagedEffectGetRequest {
        owner: owner.clone(),
        call_id: "once".into(),
    };
    let record_result = p.managed_effect_get(&request);
    let tombstone_result = crate::plugins::PluginControlStore::new(&p).graph_revocation(&graph);
    let terminal_before_refusal = handle.is_terminal();
    let replay_result = service.replay_managed_call(request.clone());
    let head_before_result = p.managed_workspace_head(&workspace);
    let messages_before_result = p.message_list(&run.session_id, 0);
    let events_before = service.run_events(&run.run_id);
    // Same original host/cancel and complete identity, directly at the pinned
    // Native entry after the revoke: fresh execution must be refused.
    let refused = native_probe(
        &service,
        host,
        &run.run_id,
        &call,
        &canonical,
        "execute",
        false,
    );
    let record_after_result = p.managed_effect_get(&request);
    let events_after = service.run_events(&run.run_id);
    let head_after_result = p.managed_workspace_head(&workspace);
    let messages_after_result = p.message_list(&run.session_id, 0);
    let shutdown_result = service.shutdown().await;
    shutdown_result.unwrap();
    // First legal call: one complete success and exactly one sentinel append.
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    assert!(
        !terminal_before_refusal,
        "the refusal probe must run before the run terminal"
    );
    let record = record_result.unwrap().unwrap();
    let original_outcome = record.outcome.clone().expect("first call must commit");
    assert!(
        tombstone_result.unwrap().is_some(),
        "exact graph tombstone must exist"
    );
    // Read-only service history keeps the original full canonical result and
    // the original durable outcome; only fresh execution is refused.
    let crate::effects::ManagedCallReplay::Final {
        outcome: history_outcome,
        canonical_result: history_canonical,
    } = replay_result.unwrap()
    else {
        panic!("original canonical receipt must stay queryable after revocation");
    };
    assert_eq!(*history_outcome, original_outcome);
    let first_canonical = first["canonical_result"]
        .as_str()
        .expect("first call must return a complete canonical result");
    assert_eq!(history_canonical.as_str(), first_canonical);
    let first_full: Value = serde_json::from_str(first_canonical).unwrap();
    let first_tool = crate::service::canonical_tool_result(&first_full)
        .expect("first canonical must decode through the existing ToolResult contract");
    assert!(first_tool.ok);
    assert_eq!(first_tool.content, "observed");
    // Fresh Native execution after revoke: exact typed refusal, empty
    // canonical, and no newly returned managed success publication.
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(refused["code"], "plugin_graph_revoked", "{refused}");
    assert_eq!(refused["message"], "plugin_graph_revoked", "{refused}");
    assert!(
        refused.get("canonical_result").is_some(),
        "the refusal must still carry the pinned Native envelope: {refused}"
    );
    assert_eq!(refused["canonical_result"], "", "{refused}");
    assert!(
        refused.get("managed_publication").is_none(),
        "the refusal must not return a managed success publication: {refused}"
    );
    // The durable record is untouched: exact identity and outcome.
    let record_after = record_after_result.unwrap().unwrap();
    assert_eq!(record_after.identity, record.identity);
    assert_eq!(record_after.outcome, record.outcome);
    let head_before = head_before_result.unwrap().head_version;
    let head_after = head_after_result.unwrap().head_version;
    assert_eq!(head_after, head_before);
    let messages_before = messages_before_result.unwrap()["rows"]
        .as_array()
        .unwrap()
        .len();
    let messages_after = messages_after_result.unwrap()["rows"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(messages_after, messages_before);
    for event in [
        "tool.requested",
        "tool.started",
        "tool.output",
        "tool.completed",
    ] {
        assert_eq!(
            events_before
                .iter()
                .filter(|value| value["event"] == event)
                .count(),
            1,
            "{event} must remain a single durable fact"
        );
        assert_eq!(
            events_after
                .iter()
                .filter(|value| value["event"] == event)
                .count(),
            1,
            "{event} must not be duplicated by the refused execution"
        );
    }
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    assert_eq!(provider.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn released_and_revoked_pins_refuse_at_native_begin_boundary() {
    use crate::AgentProviderHost;
    for case in ["release", "revoke"] {
        let (_root, state) = fixture();
        let service = state.service();
        let p = state.persistence().unwrap();
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(Some(json!({"id":"native-begin","name":"write_file","arguments":{"path":"never.txt","content":"deny"}}))));
        provider.push_ok(response(None));
        service.inject_provider_host(provider.clone());
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"text":"released or revoked pin at native begin"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let handle = service.handle(&run.run_id).unwrap();
        let pin = handle.pinned_tool.clone().unwrap();
        let binding = pin.managed.as_ref().unwrap();
        let graph = binding.code.graph_id.clone();
        let durable = crate::durable_provider::DurableProviderHost::new(
            (*service).clone(),
            run.run_id.clone(),
            provider.clone(),
            service.inner.metrics.clone(),
        );
        // Legal tool parent: one real provider turn passes the admitted gate.
        let request = json!({"model":"synthetic","messages":[]});
        assert_eq!(durable.call(&request, &handle.cancel)["ok"], true);
        if case == "release" {
            crate::plugins::PluginControlStore::new(&p)
                .release(&crate::plugins::GraphRetention {
                    graph_id: graph.clone(),
                    owner_kind: "run".into(),
                    owner_id: run.run_id.clone(),
                    ref_id: binding.code.graph_ref_id.clone(),
                })
                .unwrap();
        } else {
            p.plugin_control_command(
                "plugin.graph_revoke",
                &json!({"graph_id":graph,"now_ms":100,"failpoint":""}),
            )
            .unwrap();
        }
        let expected = if case == "revoke" {
            "plugin_graph_revoked"
        } else {
            "plugin_graph_pin_required"
        };
        assert_eq!(
            service.check_harness_run(
                &run.run_id,
                &handle.cancel,
                #[cfg(feature = "workspace-io-fault")]
                None,
            ),
            Err(expected),
            "{case}"
        );
        assert_eq!(
            durable.call(&request, &handle.cancel)["error"]["code"],
            expected,
            "{case}"
        );
        assert_eq!(
            provider.requests().len(),
            1,
            "{case} must not reach the transport again"
        );
        service.shutdown().await.unwrap();
    }
}
