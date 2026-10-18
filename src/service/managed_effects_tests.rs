//! Native live replay through the exact private retained worker program.
#[path = "managed_protocol_tests.rs"]
mod protocol;
#[path = "managed_review_tests.rs"]
mod review;
use crate::config::{ManagedRetentionLimits, ManagedWorkspaceConfig};
use crate::effects::ResourceQuota;
use crate::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Arc};
fn response(call: Option<Value>) -> Value {
    json!({"text":if call.is_some() { "" } else { "done" },"tool_calls":call.into_iter().collect::<Vec<_>>(),"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"})
}

fn fixture() -> (PathBuf, AgentGatewayState) {
    fixture_config(|_| {})
}
fn fixture_config(configure: impl FnOnce(&mut AgentGatewayConfig)) -> (PathBuf, AgentGatewayState) {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-case-{}", uuid::Uuid::new_v4().simple()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&home).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for path in [&root, &workspace, &home] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
    let mut config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace,
            quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.approvals.process = "allow".into();
    configure(&mut config);
    let state = AgentGatewayState::with_sqlite_path(config.clone(), root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home);
    (root, state)
}
struct ExactReplayProvider {
    persistence: Arc<crate::GatewayPersistence>,
    service: std::sync::Weak<crate::AgentService>,
    run_id: std::sync::Mutex<String>,
    call: Value,
    step: std::sync::atomic::AtomicUsize,
    replayed: std::sync::Mutex<Option<Value>>,
}
fn native_json(value: &rustscript_vm::Value) -> Value {
    use rustscript_vm::Value as V;
    match value {
        V::Null => Value::Null,
        V::Bool(value) => json!(value),
        V::Int(value) => json!(value),
        V::String(value) => json!(value.as_str()),
        V::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    let V::String(key) = key else {
                        panic!("Native result key must be text");
                    };
                    (key.as_str().to_string(), native_json(value))
                })
                .collect(),
        ),
        V::Array(values) => Value::Array(values.iter().map(native_json).collect()),
        _ => panic!("unexpected non-JSON Native result"),
    }
}
impl crate::AgentProviderHost for ExactReplayProvider {
    fn call(&self, _request: &Value, cancellation: &crate::RunCancellation) -> Value {
        if self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return json!({"ok":true,"response":response(Some(self.call.clone())),"error":{}});
        }
        let service = self.service.upgrade().unwrap();
        let run_id = self.run_id.lock().unwrap().clone();
        let host = service.capability_host_bridges(&run_id).unwrap().unwrap();
        assert_eq!(
            host.cancellation.as_ref().unwrap().deadline_instant(),
            cancellation.deadline_instant()
        );
        let mut host = host;
        host.pinned_tool = service.handle(&run_id).unwrap().pinned_tool.clone();
        let owner = host.capability_owner.as_ref().unwrap();
        let request = crate::effects::ManagedEffectGetRequest {
            owner: crate::effects::ManagedOwnerScope {
                profile: owner.profile().into(),
                session_id: owner.session().into(),
                run_id: owner.run().into(),
            },
            call_id: "once".into(),
        };
        let record = self
            .persistence
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        let crate::effects::ManagedArgumentIdentity::Inline {
            canonical_arguments,
        } = &record.identity.argument_identity
        else {
            panic!("small fixture arguments should remain inline");
        };
        let wire = json!({"tool_name":"terminal","call_id":"once","canonical_arguments":canonical_arguments,"canonical_input":json!({"call":self.call,"config":service.run_context(&run_id).unwrap().limits}).to_string(),"run_id":run_id,"registry_identity":host.lifecycle.as_ref().unwrap().registry_identity(),"argument_digest":canonical_arguments,"risk_class":"execute","summary":"terminal","untrusted_graph_id":""});
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
        for field in [
            "graph",
            "artifact",
            "export",
            "activation-generation",
            "graph-ref",
            "package",
            "registry",
        ] {
            let pin = host.pinned_tool.as_ref().unwrap();
            let mut code = pin.managed.as_ref().unwrap().code.clone();
            match field {
                "graph" => code.graph_id.push_str("-wrong"),
                "artifact" => code.artifact_id.push_str("-wrong"),
                "export" => code.export.push_str("_wrong"),
                "activation-generation" => code.activation_generation += 1,
                "graph-ref" => code.graph_ref_id.push_str("-wrong"),
                "package" => code.package_id.push_str("-wrong"),
                "registry" => code.registry_identity.push_str("-wrong"),
                _ => unreachable!(),
            };
            let mut changed = host.clone();
            changed.pinned_tool = Some(pin.with_native_code_identity_for_test(code));
            let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
                .unwrap()
                .with_host(changed);
            let denied = native_json(&runner.run_with_context(input.clone()).unwrap());
            assert_eq!(
                denied["ok"], false,
                "wrong sealed Native {field} must not issue a replay/completion witness"
            );
            assert!(
                denied
                    .get("canonical_result")
                    .is_none_or(|value| value == "")
            );
        }
        let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
            .unwrap()
            .with_host(host);
        let result = runner.run_with_context(input).unwrap();
        *self.replayed.lock().unwrap() = Some(native_json(&result));
        json!({"ok":true,"response":response(None),"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn live_exact_receipt_replay_uses_original_fenced_native_result_without_second_execution() {
    let (root, state) = fixture();
    let service = state.service();
    let sentinel = root.join("once-sentinel");
    let provider = Arc::new(ExactReplayProvider {
        persistence: state.persistence().unwrap(),
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
                input: json!({"message":"execute then exactly replay this Native call"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    *provider.run_id.lock().unwrap() = run.run_id.clone();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let replayed = provider
        .replayed
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| {
            panic!(
                "Native replay probe absent; provider calls={}, codes={:?}",
                provider.step.load(std::sync::atomic::Ordering::SeqCst),
                service
                    .run_events(&run.run_id)
                    .iter()
                    .map(|event| (
                        event["event"].clone(),
                        event["data"]["error_code"].clone(),
                        event["data"]["code"].clone()
                    ))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        replayed["ok"], true,
        "committed exact replay must be original Native outcome; code={}, reason={}",
        replayed["code"], replayed["message"]
    );
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "once".into(),
    };
    let crate::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = service.replay_managed_call(request.clone()).unwrap()
    else {
        panic!("expected committed receipt");
    };
    assert_eq!(
        replayed["canonical_result"].as_str().unwrap(),
        canonical_result.as_str()
    );
    assert_eq!(replayed["managed_publication"]["status"], "committed");
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert_eq!(
        state
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap()
            .head_version,
        2
    );
    for event in [
        "tool.requested",
        "tool.started",
        "tool.output",
        "tool.completed",
    ] {
        assert_eq!(
            service
                .run_events(&run.run_id)
                .iter()
                .filter(|value| value["event"] == event)
                .count(),
            1
        );
    }
    assert_eq!(provider.step.load(std::sync::atomic::Ordering::SeqCst), 2);
    drop(service);
    state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn service_durable_replay_reads_full_canonical_receipt_after_pruning_and_fresh_reopen() {
    let (root, state) = fixture_config(|config| config.max_events_per_run = 8);
    let service = state.service();
    service
        .set_run_limits(
            crate::config::RunLimits::new(64, 128, 4 * 1024 * 1024, root.join("workspace"))
                .unwrap(),
        )
        .unwrap();
    fs::write(root.join("workspace/prune.txt"), b"bounded").unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"large","name":"terminal","arguments":{"argv":["/bin/sh","-c","/usr/bin/python3 -c 'import sys; sys.stdout.write(chr(34)*350000)'; exit 7"],"timeout_ms":1000}}))));
    for id in ["prune-one", "prune-two"] {
        provider.push_ok(response(Some(
            json!({"id":id,"name":"read_file","arguments":{"path":"prune.txt"}}),
        )));
    }
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run=service.admit_external_with_workspace_selector(AdmitRunRequest{input:json!({"message":"retain exact receipt while pruning the observation events"}),..Default::default()},None).await.unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    assert!(
        !service.run_events(&run.run_id).iter().any(
            |event| event["event"] == "tool.output" && event["data"]["tool_call_id"] == "large"
        )
    );
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "large".into(),
    };
    let crate::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = service.replay_managed_call(request).unwrap()
    else {
        panic!("expected final receipt");
    };
    let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
    let replay = service
        .replay_durable_tool_result(&run.run_id, "large", "terminal")
        .unwrap()
        .expect("a managed receipt must remain available after its events are pruned");
    let decoded = serde_json::to_value(&replay).unwrap();
    assert!(
        decoded == full,
        "the facade must not reconstruct the full result from the bounded message projection; differing fields={:?}",
        full.as_object()
            .unwrap()
            .keys()
            .chain(decoded.as_object().unwrap().keys())
            .filter(|key| full.get(*key) != decoded.get(*key))
            .map(|key| (
                key,
                full.get(key).map(|v| serde_json::to_vec(v).unwrap().len()),
                decoded
                    .get(key)
                    .map(|v| serde_json::to_vec(v).unwrap().len())
            ))
            .collect::<std::collections::BTreeSet<_>>()
    );
    let config = (*service.inner.config).clone();
    service.shutdown().await.unwrap();
    drop(service);
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(root.join("home"));
    let replay = reopened
        .service()
        .replay_durable_tool_result(&run.run_id, "large", "terminal")
        .unwrap()
        .expect("fresh facade must find the immutable receipt");
    assert!(serde_json::to_value(&replay).unwrap() == full);
    assert!(
        reopened
            .service()
            .replay_durable_tool_result(&run.run_id, "large", "write_file")
            .is_err()
    );
    reopened.service().shutdown().await.unwrap();
}

/// Authored Native observation fixture exercises legacy fields that no single
/// six-tool failure currently emits together; it creates no guest authority.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn failed_multiartifact_native_observation_replays_every_field_after_pruning_and_fresh_reopen()
 {
    let (root, state) = fixture_config(|config| config.max_events_per_run = 8);
    let service = state.service();
    fs::write(root.join("workspace/prune.txt"), b"observed").unwrap();
    let full = json!({"ok":false,"content":"partial observation retained","data":{"partial":"legacy diagnostic","nested":{"count":3}},"error":{"code":"fixture_observation_failed","message":"original failure detail"},"truncated":true,"artifacts":["artifact:first-native-ref","artifact:second-native-ref"]});
    *service
        .managed_runtime_for_test()
        .unwrap()
        .canonical_observation_fixture
        .lock() = Some(full.clone());
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"failed","name":"write_file","arguments":{"path":"private.txt","content":"discard private mutation"}}))));
    for id in ["prune-one", "prune-two"] {
        provider.push_ok(response(Some(
            json!({"id":id,"name":"read_file","arguments":{"path":"prune.txt"}}),
        )));
    }
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"retain a failed Native legacy observation"}),
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
        !service
            .run_events(&run.run_id)
            .iter()
            .any(|event| event["event"] == "tool.output"
                && event["data"]["tool_call_id"] == "failed")
    );
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id,
            run_id: run.run_id.clone(),
        },
        call_id: "failed".into(),
    };
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::NotPublished
    );
    assert!(record.prepared.as_ref().unwrap().candidate_root.is_none());
    assert_eq!(
        record
            .prepared
            .as_ref()
            .unwrap()
            .canonical_result
            .object_kind,
        crate::effects::ManagedObjectKind::CanonicalResult
    );
    let replay = service
        .replay_durable_tool_result(&run.run_id, "failed", "write_file")
        .unwrap()
        .unwrap();
    assert!(serde_json::to_value(replay).unwrap() == full);
    let crate::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = service.replay_managed_call(request.clone()).unwrap()
    else {
        panic!("expected immutable failure receipt");
    };
    assert!(serde_json::from_str::<Value>(canonical_result.as_str()).unwrap() == full);
    assert!(!root.join("workspace/private.txt").exists());
    let config = (*service.inner.config).clone();
    service.shutdown().await.unwrap();
    drop(service);
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(root.join("home"));
    let replay = reopened
        .service()
        .replay_durable_tool_result(&run.run_id, "failed", "write_file")
        .unwrap()
        .unwrap();
    assert!(serde_json::to_value(replay).unwrap() == full);
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    reopened.service().shutdown().await.unwrap();
}
