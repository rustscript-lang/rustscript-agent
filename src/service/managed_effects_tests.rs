//! Native live replay through the exact private retained worker program.
#[path = "managed_graph_tests.rs"]
mod graph;
#[cfg(feature = "workspace-io-fault")]
#[path = "managed_linearization_tests.rs"]
mod linearization;
#[path = "managed_protocol_tests.rs"]
mod protocol;
#[path = "managed_review_tests.rs"]
mod review;
#[path = "managed_run_effect_tests.rs"]
mod run_query;
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
            maintenance_policy: Default::default(),
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
const NATIVE_PROBE_SOURCE: &str = r#"pub fn run(context:map)->map {
            let tool_name:string=context["tool_name"];let call_id:string=context["call_id"];let canonical_arguments:string=context["canonical_arguments"];let canonical_input:string=context["canonical_input"];let run_id:string=context["run_id"];let registry_identity:string=context["registry_identity"];let argument_digest:string=context["argument_digest"];let risk_class:string=context["risk_class"];let summary:string=context["summary"];let untrusted_graph_id:string=context["untrusted_graph_id"];
            let attest:map=agent_runtime::approval_attest({run_id:run_id,call_id:call_id,tool_name:tool_name,argument_digest:argument_digest,registry_identity:registry_identity,risk_class:risk_class,summary:summary});
            let invoked:map=agent_runtime::invoke_pinned_tool({tool_name:tool_name,call_id:call_id,canonical_arguments:canonical_arguments,canonical_input:canonical_input,run_id:run_id,registry_identity:registry_identity,argument_digest:argument_digest,risk_class:risk_class,summary:summary,untrusted_graph_id:untrusted_graph_id});
            {attest:attest, invoke:invoked}
        }"#;
const NATIVE_PROBE_REPLAY_SOURCE: &str = r#"pub fn run(context:map)->map {
            let tool_name:string=context["tool_name"];let call_id:string=context["call_id"];let canonical_arguments:string=context["canonical_arguments"];let canonical_input:string=context["canonical_input"];let run_id:string=context["run_id"];let registry_identity:string=context["registry_identity"];let argument_digest:string=context["argument_digest"];let risk_class:string=context["risk_class"];let summary:string=context["summary"];let untrusted_graph_id:string=context["untrusted_graph_id"];
            agent_runtime::invoke_pinned_tool({tool_name:tool_name,call_id:call_id,canonical_arguments:canonical_arguments,canonical_input:canonical_input,run_id:run_id,registry_identity:registry_identity,argument_digest:argument_digest,risk_class:risk_class,summary:summary,untrusted_graph_id:untrusted_graph_id})
        }"#;
/// The original private Native probe: build the exact pinned invocation wire
/// from an already-authorized host, then enter `agent_runtime::invoke_pinned_tool`
/// through the real RSS host bridge. Fixtures own the parent/identity facts.
fn native_probe_input(
    service: &crate::AgentService,
    host: &crate::AgentHostBridges,
    run_id: &str,
    call: &Value,
    canonical: &str,
    risk_class: &str,
) -> rustscript_vm::Value {
    let wire = json!({"tool_name":call["name"],"call_id":call["id"],"canonical_arguments":canonical,"canonical_input":json!({"call":call,"config":service.run_context(run_id).unwrap().limits}).to_string(),"run_id":run_id,"registry_identity":host.lifecycle.as_ref().unwrap().registry_identity(),"argument_digest":canonical,"risk_class":risk_class,"summary":call["name"],"untrusted_graph_id":""});
    rustscript_vm::Value::map(
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
    )
}
fn native_probe(
    service: &crate::AgentService,
    mut host: crate::AgentHostBridges,
    run_id: &str,
    call: &Value,
    canonical: &str,
    risk_class: &str,
    attest: bool,
) -> Value {
    host.pinned_tool = service.handle(run_id).unwrap().pinned_tool.clone();
    let input = native_probe_input(service, &host, run_id, call, canonical, risk_class);
    let source = if attest {
        NATIVE_PROBE_SOURCE
    } else {
        NATIVE_PROBE_REPLAY_SOURCE
    };
    let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
        .unwrap()
        .with_host(host);
    let result = native_json(&runner.run_with_context(input).unwrap());
    if attest {
        assert_eq!(
            result["attest"]["ok"], true,
            "the fixture must obtain the real approval attestation before Native begin: {result}"
        );
        result["invoke"].clone()
    } else {
        result
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

/// 461: after a real Service managed call has durably committed, a real
/// same-control-store graph revocation must stop the *execution replay* of that
/// call. The provider hook revokes the admitted graph and then replays the same
/// call id through the actual host bridge / lifecycle / journal path.
struct RevokingReplayProvider {
    persistence: Arc<crate::GatewayPersistence>,
    service: std::sync::Weak<crate::AgentService>,
    run_id: std::sync::Mutex<String>,
    call_id: String,
    revoke: bool,
    step: std::sync::atomic::AtomicUsize,
    replay: std::sync::Mutex<Option<Value>>,
    revoked: std::sync::Mutex<Option<String>>,
}

impl crate::AgentProviderHost for RevokingReplayProvider {
    fn call(&self, _request: &Value, _cancellation: &crate::RunCancellation) -> Value {
        if self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return json!({"ok":true,"response":response(Some(json!({"id":self.call_id,"name":"read_file","arguments":{"path":"seed.txt"}}))),"error":{}});
        }
        let service = self.service.upgrade().unwrap();
        let run_id = self.run_id.lock().unwrap().clone();
        let pin = service
            .handle(&run_id)
            .unwrap()
            .pinned_tool
            .clone()
            .unwrap();
        let binding = pin.managed.as_ref().unwrap();
        let graph = binding.code.graph_id.clone();
        let owner = binding.owner.clone();
        if self.revoke {
            // The same durable control store that admitted the pin now records
            // the tombstone, exactly as the accepted service revoke fixture does.
            self.persistence
                .plugin_control_command(
                    "plugin.graph_revoke",
                    &json!({"graph_id":graph,"now_ms":201,"failpoint":""}),
                )
                .unwrap();
            *self.revoked.lock().unwrap() = Some(graph.clone());
            assert!(
                crate::plugins::PluginControlStore::new(&self.persistence)
                    .graph_revocation(&graph)
                    .unwrap()
                    .is_some(),
                "the revocation must be durably visible before the replay"
            );
        }
        let request = crate::effects::ManagedEffectGetRequest {
            owner,
            call_id: self.call_id.clone(),
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
        let canonical = canonical_arguments.clone();
        let mut host = service.capability_host_bridges(&run_id).unwrap().unwrap();
        host.pinned_tool = Some(pin);
        let wire = json!({
            "tool_name":"read_file",
            "call_id":self.call_id,
            "canonical_arguments":canonical,
            "canonical_input":"",
            "run_id":run_id,
            "registry_identity":host.lifecycle.as_ref().unwrap().registry_identity(),
            "argument_digest":canonical,
            "risk_class":"read",
            "summary":"exact replay of the committed call",
            "untrusted_graph_id":""
        });
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
            agent_runtime::invoke_pinned_tool({tool_name:context["tool_name"],call_id:context["call_id"],canonical_arguments:context["canonical_arguments"],canonical_input:context["canonical_input"],run_id:context["run_id"],registry_identity:context["registry_identity"],argument_digest:context["argument_digest"],risk_class:context["risk_class"],summary:context["summary"],untrusted_graph_id:context["untrusted_graph_id"]})
        }"#;
        let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
            .unwrap()
            .with_host(host);
        let result = runner.run_with_context(input).unwrap();
        *self.replay.lock().unwrap() = Some(native_json(&result));
        json!({"ok":true,"response":response(None),"error":{}})
    }
}

/// F4 evidence: a revoked graph must refuse the execution replay of an already
/// durably committed call, instead of returning the retained success.
#[tokio::test(flavor = "multi_thread")]
async fn phase_a_service_replay_denies_revoke_before_exact_execution_replay() {
    let (root, state) = fixture();
    let service = state.service();
    fs::write(root.join("workspace/seed.txt"), b"seeded").unwrap();
    let provider = Arc::new(RevokingReplayProvider {
        persistence: state.persistence().unwrap(),
        service: Arc::downgrade(&service),
        run_id: std::sync::Mutex::new(String::new()),
        call_id: "svc-replay-1".into(),
        revoke: true,
        step: std::sync::atomic::AtomicUsize::new(0),
        replay: std::sync::Mutex::new(None),
        revoked: std::sync::Mutex::new(None),
    });
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"commit once, then replay after revocation"}),
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

    let events = service.run_events(&run.run_id);
    let completed = events
        .iter()
        .filter(|event| {
            event["event"] == "tool.completed" && event["data"]["tool_call_id"] == "svc-replay-1"
        })
        .count();
    assert_eq!(completed, 1, "the original call must commit exactly once");
    let graph = provider
        .revoked
        .lock()
        .unwrap()
        .clone()
        .expect("the fixture must revoke the admitted graph before the replay");
    let replay = provider
        .replay
        .lock()
        .unwrap()
        .clone()
        .expect("the real execution replay probe must produce an envelope");
    println!("phase_a_service replay evidence: graph={graph} envelope={replay}");
    assert_eq!(
        replay["ok"], false,
        "a revoked graph must refuse the execution replay: {replay}"
    );
    assert_eq!(
        replay["code"], "plugin_graph_revoked",
        "the replay refusal must be the exact typed graph revocation: {replay}"
    );
    assert!(
        replay["canonical_result"].as_str().unwrap_or("").is_empty(),
        "the refused replay must not leak the original canonical success: {replay}"
    );
    assert_eq!(
        service
            .run_events(&run.run_id)
            .iter()
            .filter(|event| event["event"] == "tool.completed")
            .count(),
        1,
        "the refused replay must not commit a second result"
    );
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "svc-replay-1".into(),
    };
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(
        record.outcome.is_some(),
        "the original receipt must stay durable after the refusal"
    );
    let crate::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = service.replay_managed_call(request.clone()).unwrap()
    else {
        panic!("the committed canonical receipt must stay queryable after the refusal");
    };
    assert_eq!(
        serde_json::from_str::<Value>(canonical_result.as_str()).unwrap()["content"],
        json!("seeded"),
        "history must still return the original canonical content"
    );
    service.shutdown().await.unwrap();
}

/// Unrevoked same-identity execution replay stays a live replay of the
/// original Native outcome: the guard only denies after a revocation.
#[tokio::test(flavor = "multi_thread")]
async fn phase_a_service_replay_without_revoke_returns_original_success() {
    let (root, state) = fixture();
    let service = state.service();
    fs::write(root.join("workspace/seed.txt"), b"seeded").unwrap();
    let provider = Arc::new(RevokingReplayProvider {
        persistence: state.persistence().unwrap(),
        service: Arc::downgrade(&service),
        run_id: std::sync::Mutex::new(String::new()),
        call_id: "svc-replay-1".into(),
        revoke: false,
        step: std::sync::atomic::AtomicUsize::new(0),
        replay: std::sync::Mutex::new(None),
        revoked: std::sync::Mutex::new(None),
    });
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"commit once, then replay without revocation"}),
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

    let replay = provider
        .replay
        .lock()
        .unwrap()
        .clone()
        .expect("the live execution replay probe must produce an envelope");
    assert_eq!(
        replay["ok"], true,
        "an unrevoked graph must replay the original success: {replay}"
    );
    assert_eq!(replayed_kind(&replay), "replay");
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "svc-replay-1".into(),
    };
    let crate::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = service.replay_managed_call(request).unwrap()
    else {
        panic!("expected committed receipt");
    };
    assert_eq!(
        replay["canonical_result"].as_str().unwrap(),
        canonical_result.as_str()
    );
    assert_eq!(
        service
            .run_events(&run.run_id)
            .iter()
            .filter(|event| {
                event["event"] == "tool.completed"
                    && event["data"]["tool_call_id"] == "svc-replay-1"
            })
            .count(),
        1,
        "the live replay must not commit a second result"
    );
    service.shutdown().await.unwrap();
}

fn replayed_kind(replay: &Value) -> &str {
    replay["kind"].as_str().unwrap_or("")
}

// ===== guard_contract_465_：当前合同边界证据（只证据，不修生产） =====
// 覆盖 R464-1 冷历史 receipt 回放、R464-3 lifecycle 图错误码、R464-4 原
// 取消分类/返回边界、R464-7 final replay 顺序。RED 为缺陷证据，GREEN 为正控。

/// R464-1：正式 ToolOnly producer 带 key 完成 run，撤销确切图后，先正向
/// 关闭 owners 并丢弃 Arc pins，再经正式构造器重开同一物理根。同 key /
/// hash / selector 必须返回原 run/status 且 replayed=true，不构造可执行
/// pin，不新增事件/effect/ref；公开可执行 ToolOnly restore 仍精确拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_1_cold_toolonly_history_replay_after_revoke() {
    let (root, state) = fixture();
    let service = state.service();
    fs::write(root.join("workspace/seed.txt"), b"seeded").unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"cold-1","name":"read_file","arguments":{"path":"seed.txt"}}),
    )));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let request = AdmitRunRequest {
        input: json!({"message":"commit once, then cold-reopen history after revocation"}),
        idempotency_key: Some("guard-465-r464-1".to_string()),
        idempotency_hash: Some("fnv64:0000000000000465".to_string()),
        ..Default::default()
    };
    let run = service
        .admit_external_with_workspace_selector(request.clone(), None)
        .await
        .unwrap();
    let persistence = state.persistence().unwrap();
    let control = crate::plugins::PluginControlStore::new(&persistence);
    let receipt = control.pin_for_run(&run.run_id).unwrap();
    assert_eq!(receipt["pinned"], true);
    assert_eq!(
        receipt["harness_selection"]["mode"], "tool_only",
        "R464-1 只覆盖 ToolOnly 准入，当前夹具必须 pin 住 ToolOnly 程序"
    );
    let graph = receipt["graph_id"].as_str().unwrap().to_string();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    assert_eq!(
        service
            .run_events(&run.run_id)
            .iter()
            .filter(|event| {
                event["event"] == "tool.completed" && event["data"]["tool_call_id"] == "cold-1"
            })
            .count(),
        1,
        "原 ToolOnly 调用必须实际提交一次"
    );
    // 撤销确切图：经正式 typed producer 记录 tombstone。
    persistence
        .plugin_control_command(
            "plugin.graph_revoke",
            &json!({"graph_id":graph,"now_ms":201,"failpoint":""}),
        )
        .unwrap();
    assert!(
        control.graph_revocation(&graph).unwrap().is_some(),
        "撤销必须在同一控制存储内持久可见"
    );
    // 撤销后 canonical 历史仍可读（只读 receipt，不执行）。
    let owner = crate::effects::ManagedOwnerScope {
        profile: "gateway".into(),
        session_id: run.session_id.clone(),
        run_id: run.run_id.clone(),
    };
    let get = crate::effects::ManagedEffectGetRequest {
        owner,
        call_id: "cold-1".into(),
    };
    let crate::effects::ManagedCallReplay::Final {
        canonical_result: before_canonical,
        ..
    } = service.replay_managed_call(get.clone()).unwrap()
    else {
        panic!("撤销后原 canonical receipt 必须仍可查询");
    };
    let before_events = service.run_events(&run.run_id).len();
    // 公开可执行 ToolOnly restore 仍精确拒绝（正控，通过）。
    let store = service.tool_store().unwrap();
    assert!(
        crate::plugins::restore_owned_pin(&persistence, &store, &run.run_id)
            .is_err_and(|error| error.code == "plugin_graph_revoked"),
        "撤销后可执行 ToolOnly restore 必须精确拒绝"
    );
    // 热路径（retained handle）返回历史。
    let warm = service
        .admit_external_with_workspace_selector(request.clone(), None)
        .await
        .unwrap();
    assert!(warm.replayed, "热路径必须返回原 run");
    assert_eq!(warm.run_id, run.run_id);
    // 正向关闭 owners 并丢弃 Arc pins。
    service.evict_run_handle(&run.run_id);
    service.shutdown().await.unwrap();
    let config = (*service.inner.config).clone();
    let db = root.join("gateway.sqlite");
    drop(service);
    drop(store);
    drop(persistence);
    drop(state);
    // 正式重开同一物理根（无复制、无手写 SQL）。重开服务自带嵌入
    // tool store，与原 admission 的 embedding 图一致。
    let reopened = AgentGatewayState::with_sqlite_path(config, &db)
        .unwrap()
        .with_workspace_home(root.join("home"));
    let cold = reopened
        .service()
        .admit_external_with_workspace_selector(request.clone(), None)
        .await
        .expect("冷 ToolOnly 历史回放必须返回原 run/status，不构造可执行 pin");
    assert!(cold.replayed, "冷重开必须标记 replayed");
    assert_eq!(cold.run_id, run.run_id);
    assert_eq!(cold.status, warm.status);
    assert_eq!(
        reopened.service().run_events(&run.run_id).len(),
        before_events,
        "冷历史返回不得新增事件"
    );
    let reopened_persistence = reopened.persistence().unwrap();
    let control2 = crate::plugins::PluginControlStore::new(&reopened_persistence);
    assert_eq!(
        control2.pin_for_run(&run.run_id).unwrap(),
        receipt,
        "冷历史返回不得替换 receipt/ref"
    );
    let crate::effects::ManagedCallReplay::Final {
        canonical_result: after_canonical,
        ..
    } = reopened.service().replay_managed_call(get.clone()).unwrap()
    else {
        panic!("冷重开后原 canonical receipt 必须仍可查询");
    };
    assert_eq!(after_canonical, before_canonical);
    reopened.service().shutdown().await.unwrap();
}

/// R464-3 探针：在同一正式活 binding 上，撤销前后分别经官方 tool_replay
/// lifecycle 入口与官方 Native invoke 查询已完成调用。撤销前两者都返回原
/// 成功（正控）；撤销后两者都必须精确 plugin_graph_revoked，不得返回原
/// canonical 成功，不得新增 started/completion。
struct Guard465ReplayCodeProvider {
    persistence: Arc<crate::GatewayPersistence>,
    service: std::sync::Weak<crate::AgentService>,
    run_id: std::sync::Mutex<String>,
    call_id: String,
    step: std::sync::atomic::AtomicUsize,
    tool_replay_before: std::sync::Mutex<Option<Value>>,
    native_before: std::sync::Mutex<Option<Value>>,
    tool_replay_after: std::sync::Mutex<Option<Value>>,
    native_after: std::sync::Mutex<Option<Value>>,
}

fn guard465_tool_replay_input(
    run_id: &str,
    call_id: &str,
    canonical: &str,
    registry: &str,
) -> Value {
    json!({
        "run_id": run_id,
        "call_id": call_id,
        "tool_name": "read_file",
        "argument_digest": canonical,
        "registry_identity": registry,
        "risk_class": "read",
        "summary": "guard465 replay code probe",
    })
}

fn guard465_vm_map(input: &Value) -> rustscript_vm::Value {
    rustscript_vm::Value::map(
        input
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                (
                    rustscript_vm::Value::string(key),
                    rustscript_vm::Value::string(value.as_str().unwrap()),
                )
            })
            .collect(),
    )
}

impl crate::AgentProviderHost for Guard465ReplayCodeProvider {
    fn call(&self, _request: &Value, _cancellation: &crate::RunCancellation) -> Value {
        if self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return json!({"ok":true,"response":response(Some(json!({"id":self.call_id,"name":"read_file","arguments":{"path":"seed.txt"}}))),"error":{}});
        }
        let service = self.service.upgrade().unwrap();
        let run_id = self.run_id.lock().unwrap().clone();
        let pin = service
            .handle(&run_id)
            .unwrap()
            .pinned_tool
            .clone()
            .unwrap();
        let binding = pin.managed.as_ref().unwrap();
        let graph = binding.code.graph_id.clone();
        let record = self
            .persistence
            .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                owner: binding.owner.clone(),
                call_id: self.call_id.clone(),
            })
            .unwrap()
            .unwrap();
        let crate::effects::ManagedArgumentIdentity::Inline {
            canonical_arguments,
        } = &record.identity.argument_identity
        else {
            panic!("small fixture arguments should remain inline");
        };
        let canonical = canonical_arguments.clone();
        let mut host = service.capability_host_bridges(&run_id).unwrap().unwrap();
        host.pinned_tool = Some(pin);
        let registry = host.lifecycle.as_ref().unwrap().registry_identity();
        let replay_source = "pub fn run(context:map)->map { agent_runtime::tool_replay(context) }";
        // 撤销前：官方 tool_replay 入口必须返回原成功（正控）。
        let before_input = guard465_tool_replay_input(&run_id, &self.call_id, &canonical, registry);
        let before_runner =
            crate::AgentRunner::from_source(replay_source, crate::AgentConfig::default())
                .unwrap()
                .with_host(host.clone());
        let before_replay = native_json(
            &before_runner
                .run_with_context(guard465_vm_map(&before_input))
                .unwrap(),
        );
        // 撤销前：官方 Native invoke 必须返回原成功（正控）。
        let wire = json!({"tool_name":"read_file","call_id":self.call_id,"canonical_arguments":canonical,"canonical_input":"","run_id":run_id,"registry_identity":registry,"argument_digest":canonical,"risk_class":"read","summary":"guard465 replay code probe","untrusted_graph_id":""});
        let invoke_source = r#"pub fn run(context:map)->map {
            agent_runtime::invoke_pinned_tool({tool_name:context["tool_name"],call_id:context["call_id"],canonical_arguments:context["canonical_arguments"],canonical_input:context["canonical_input"],run_id:context["run_id"],registry_identity:context["registry_identity"],argument_digest:context["argument_digest"],risk_class:context["risk_class"],summary:context["summary"],untrusted_graph_id:context["untrusted_graph_id"]})
        }"#;
        let invoke_runner =
            crate::AgentRunner::from_source(invoke_source, crate::AgentConfig::default())
                .unwrap()
                .with_host(host.clone());
        let before_native = native_json(
            &invoke_runner
                .run_with_context(guard465_vm_map(&wire))
                .unwrap(),
        );
        *self.tool_replay_before.lock().unwrap() = Some(before_replay);
        *self.native_before.lock().unwrap() = Some(before_native);
        // 撤销确切图。
        self.persistence
            .plugin_control_command(
                "plugin.graph_revoke",
                &json!({"graph_id":graph,"now_ms":202,"failpoint":""}),
            )
            .unwrap();
        assert!(
            crate::plugins::PluginControlStore::new(&self.persistence)
                .graph_revocation(&graph)
                .unwrap()
                .is_some(),
            "撤销必须在回放探针前持久可见"
        );
        // 撤销后：官方 Native invoke 必须精确拒绝。
        let after_native_runner =
            crate::AgentRunner::from_source(invoke_source, crate::AgentConfig::default())
                .unwrap()
                .with_host(host.clone());
        let after_native = native_json(
            &after_native_runner
                .run_with_context(guard465_vm_map(&wire))
                .unwrap(),
        );
        *self.native_after.lock().unwrap() = Some(after_native);
        // 撤销后：官方 tool_replay 入口必须精确拒绝（当前 contracts 缺陷 RED）。
        let after_input = guard465_tool_replay_input(&run_id, &self.call_id, &canonical, registry);
        let after_replay_runner =
            crate::AgentRunner::from_source(replay_source, crate::AgentConfig::default())
                .unwrap()
                .with_host(host);
        let after_replay = native_json(
            &after_replay_runner
                .run_with_context(guard465_vm_map(&after_input))
                .unwrap(),
        );
        *self.tool_replay_after.lock().unwrap() = Some(after_replay);
        json!({"ok":true,"response":response(None),"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_3_tool_replay_keeps_exact_revocation_code() {
    let (root, state) = fixture();
    let service = state.service();
    fs::write(root.join("workspace/seed.txt"), b"seeded").unwrap();
    let provider = Arc::new(Guard465ReplayCodeProvider {
        persistence: state.persistence().unwrap(),
        service: Arc::downgrade(&service),
        run_id: std::sync::Mutex::new(String::new()),
        call_id: "code-1".into(),
        step: std::sync::atomic::AtomicUsize::new(0),
        tool_replay_before: std::sync::Mutex::new(None),
        native_before: std::sync::Mutex::new(None),
        tool_replay_after: std::sync::Mutex::new(None),
        native_after: std::sync::Mutex::new(None),
    });
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"commit once, probe replay codes around revocation"}),
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
    let events = service.run_events(&run.run_id);
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event["event"] == "tool.completed" && event["data"]["tool_call_id"] == "code-1"
            })
            .count(),
        1,
        "原调用必须精确提交一次"
    );
    let before_replay = provider.tool_replay_before.lock().unwrap().clone().unwrap();
    assert_eq!(
        before_replay["ok"], true,
        "撤销前官方 tool_replay 必须返回原成功: {before_replay}"
    );
    let before_native = provider.native_before.lock().unwrap().clone().unwrap();
    assert_eq!(
        before_native["ok"], true,
        "撤销前官方 Native invoke 必须返回原成功: {before_native}"
    );
    assert_eq!(replayed_kind(&before_native), "replay");
    let after_native = provider.native_after.lock().unwrap().clone().unwrap();
    assert_eq!(
        after_native["ok"], false,
        "撤销后 Native 执行回放必须拒绝: {after_native}"
    );
    assert_eq!(
        after_native["code"], "plugin_graph_revoked",
        "撤销后 Native 回放必须精确分类: {after_native}"
    );
    assert!(
        after_native["canonical_result"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "被拒绝的回放不得泄露原 canonical 成功"
    );
    let after_replay = provider.tool_replay_after.lock().unwrap().clone().unwrap();
    assert_eq!(
        after_replay["ok"], false,
        "撤销后官方 tool_replay 必须拒绝: {after_replay}"
    );
    assert_eq!(
        after_replay["error"]["code"], "plugin_graph_revoked",
        "撤销后官方 tool_replay 必须精确分类，不得吞为 result_commit_failed: {after_replay}"
    );
    assert_eq!(
        service
            .run_events(&run.run_id)
            .iter()
            .filter(|event| event["event"] == "tool.completed")
            .count(),
        1,
        "被拒绝的回放不得提交第二个结果"
    );
    service.shutdown().await.unwrap();
}

/// R464-4 正控与 RED：原 admission 根（构造时配置短且受支持的 run_timeout，
/// 不重建时钟）在 guard 已有入口处保持原 deadline/root。requested 必须保留
/// 既有 cancelled 分类，不得转成 pin_required。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_4_requested_keeps_cancelled() {
    let (_root, state) =
        fixture_config(|config| config.run_timeout = std::time::Duration::from_secs(2));
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"guard465 requested root"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    let original = handle.cancel.clone();
    let deadline = original
        .deadline_instant()
        .expect("原 admission 根必须携带有限 deadline");
    assert!(
        deadline > std::time::Instant::now(),
        "夹具 deadline 必须是未来时刻"
    );
    let pinned = handle.pinned_tool.clone().expect("准入必须 pin 住工具程序");
    let persistence = state.persistence().unwrap();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = Arc::clone(&observed);
    let root_clock = original.clone();
    *persistence.managed_request_hook.lock().unwrap() =
        Some(Arc::new(move |op, cancel, enqueued| {
            if op == "plugin.graph_revocation_get" {
                capture
                    .lock()
                    .unwrap()
                    .push((enqueued, cancel.shares_original_clock(&root_clock)));
            }
        }));
    pinned
        .check_execution_authority(Some(&original))
        .expect("开放的原根必须通过 guard 精确读");
    original.request(crate::CancellationReason::Requested);
    let err = pinned
        .check_execution_authority(Some(&original))
        .expect_err("已 requested 的原根必须拒绝");
    assert_eq!(
        err, "cancelled",
        "原 requested 必须保留既有 cancelled 分类，不得转成 pin_required"
    );
    *persistence.managed_request_hook.lock().unwrap() = None;
    let rows = observed.lock().unwrap().clone();
    assert!(!rows.is_empty(), "guard 必须经过队列边界可观测读");
    assert!(
        rows.iter().all(|(_, shared)| *shared),
        "guard 读必须共享原 admission 时钟: {rows:?}"
    );
    service.shutdown().await.unwrap();
}

/// R464-4 RED：原 admission 根自然到期（按记录的 deadline 做一次有界等待，
/// 不猜阶段、不重建时钟）必须保留既有 deadline_elapsed 分类。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_4_elapsed_keeps_deadline_elapsed() {
    let (_root, state) =
        fixture_config(|config| config.run_timeout = std::time::Duration::from_secs(2));
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"guard465 elapsed root"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    let original = handle.cancel.clone();
    let deadline = original
        .deadline_instant()
        .expect("原 admission 根必须携带有限 deadline");
    assert!(
        deadline > std::time::Instant::now(),
        "夹具 deadline 必须是未来时刻"
    );
    let pinned = handle.pinned_tool.clone().expect("准入必须 pin 住工具程序");
    let persistence = state.persistence().unwrap();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = Arc::clone(&observed);
    let root_clock = original.clone();
    *persistence.managed_request_hook.lock().unwrap() =
        Some(Arc::new(move |op, cancel, enqueued| {
            if op == "plugin.graph_revocation_get" {
                capture
                    .lock()
                    .unwrap()
                    .push((enqueued, cancel.shares_original_clock(&root_clock)));
            }
        }));
    pinned
        .check_execution_authority(Some(&original))
        .expect("开放的原根必须通过 guard 精确读");
    std::thread::sleep(
        original.remaining_deadline().unwrap_or_default() + std::time::Duration::from_millis(250),
    );
    assert!(original.deadline_passed(), "原 deadline 必须已过");
    let err = pinned
        .check_execution_authority(Some(&original))
        .expect_err("已到期的原根必须拒绝");
    assert_eq!(
        err, "deadline_elapsed",
        "原到期必须保留既有 deadline_elapsed 分类，不得转成 pin_required"
    );
    *persistence.managed_request_hook.lock().unwrap() = None;
    let rows = observed.lock().unwrap().clone();
    assert!(!rows.is_empty(), "guard 必须经过队列边界可观测读");
    assert!(
        rows.iter().all(|(_, shared)| *shared),
        "guard 读必须共享原 admission 时钟: {rows:?}"
    );
    service.shutdown().await.unwrap();
}

/// R464-4 正控：开放的原根下发生真实查询故障，guard 仍精确 pin_required。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_4_query_failure_stays_pin_required() {
    let (_root, state) = fixture();
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"guard465 query failure root"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    let original = handle.cancel.clone();
    assert!(
        original.deadline_instant().is_some(),
        "原 admission 根必须携带有限 deadline"
    );
    let pinned = handle.pinned_tool.clone().expect("准入必须 pin 住工具程序");
    pinned
        .check_execution_authority(Some(&original))
        .expect("开放的原根必须通过 guard 精确读");
    state.persistence().unwrap().inject_persist_failure();
    let err = pinned
        .check_execution_authority(Some(&original))
        .expect_err("真实查询故障必须拒绝");
    assert_eq!(
        err, "plugin_graph_pin_required",
        "真实查询故障必须精确 pin_required: {err}"
    );
    service.shutdown().await.unwrap();
}

/// R464-7 探针：正式 journal/broker typed API 建立的状态（miss / final），
/// 在撤销图下经同一正式活 binding 做执行回放。只有真正的 final 执行回放才
/// 走新拒绝；miss 保持原有缺席语义，final 的身份/参数不匹配保持原有分类。
#[derive(Clone, Copy)]
enum Guard465JournalProbe {
    Miss,
    FinalExact,
    WrongCanonical,
    WrongTool,
}

struct Guard465JournalProvider {
    persistence: Arc<crate::GatewayPersistence>,
    service: std::sync::Weak<crate::AgentService>,
    run_id: std::sync::Mutex<String>,
    call_id: String,
    probe: Guard465JournalProbe,
    step: std::sync::atomic::AtomicUsize,
    outcome: std::sync::Mutex<Option<Result<String, String>>>,
}

impl crate::AgentProviderHost for Guard465JournalProvider {
    fn call(&self, _request: &Value, _cancellation: &crate::RunCancellation) -> Value {
        if self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return json!({"ok":true,"response":response(Some(json!({"id":self.call_id,"name":"read_file","arguments":{"path":"seed.txt"}}))),"error":{}});
        }
        let service = self.service.upgrade().unwrap();
        let run_id = self.run_id.lock().unwrap().clone();
        let pin = service
            .handle(&run_id)
            .unwrap()
            .pinned_tool
            .clone()
            .unwrap();
        let binding = pin.managed.as_ref().unwrap();
        let graph = binding.code.graph_id.clone();
        let record = self
            .persistence
            .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                owner: binding.owner.clone(),
                call_id: self.call_id.clone(),
            })
            .unwrap()
            .unwrap();
        let crate::effects::ManagedArgumentIdentity::Inline {
            canonical_arguments,
        } = &record.identity.argument_identity
        else {
            panic!("small fixture arguments should remain inline");
        };
        let canonical = canonical_arguments.clone();
        let args: Value = serde_json::from_str(&canonical).unwrap();
        self.persistence
            .plugin_control_command(
                "plugin.graph_revoke",
                &json!({"graph_id":graph,"now_ms":203,"failpoint":""}),
            )
            .unwrap();
        assert!(
            crate::plugins::PluginControlStore::new(&self.persistence)
                .graph_revocation(&graph)
                .unwrap()
                .is_some(),
            "撤销必须在回放探针前持久可见"
        );
        let probed = match self.probe {
            Guard465JournalProbe::Miss => {
                binding.replay_live("never-registered-465", "read_file", None, None)
            }
            Guard465JournalProbe::FinalExact => {
                binding.replay_live(&self.call_id, "read_file", Some(&args), Some(&canonical))
            }
            Guard465JournalProbe::WrongCanonical => binding.replay_live(
                &self.call_id,
                "read_file",
                Some(&args),
                Some("{\"path\":\"wrong.txt\"}"),
            ),
            Guard465JournalProbe::WrongTool => {
                binding.replay_live(&self.call_id, "write_file", Some(&args), Some(&canonical))
            }
        };
        *self.outcome.lock().unwrap() = Some(match probed {
            Ok(None) => Ok("miss".to_string()),
            Ok(Some(_)) => Ok("final".to_string()),
            Err(message) => Err(message),
        });
        json!({"ok":true,"response":response(None),"error":{}})
    }
}

async fn guard465_journal_probe_round(
    probe: Guard465JournalProbe,
) -> (
    Arc<crate::AgentService>,
    String,
    Option<Result<String, String>>,
) {
    let (root, state) = fixture();
    let service = state.service();
    fs::write(root.join("workspace/seed.txt"), b"seeded").unwrap();
    let provider = Arc::new(Guard465JournalProvider {
        persistence: state.persistence().unwrap(),
        service: Arc::downgrade(&service),
        run_id: std::sync::Mutex::new(String::new()),
        call_id: "journal-1".into(),
        probe,
        step: std::sync::atomic::AtomicUsize::new(0),
        outcome: std::sync::Mutex::new(None),
    });
    service.inject_provider_host(provider.clone());
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"commit once, probe journal replay ordering under revoke"}),
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
    assert_eq!(
        service
            .run_events(&run.run_id)
            .iter()
            .filter(|event| {
                event["event"] == "tool.completed" && event["data"]["tool_call_id"] == "journal-1"
            })
            .count(),
        1,
        "原调用必须精确提交一次"
    );
    let outcome = provider.outcome.lock().unwrap().clone();
    (service, run.run_id.clone(), outcome)
}

/// R464-7 正控：miss 在撤销图下仍是普通缺席，不走新拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_7_miss_stays_absent_under_revoke() {
    let (service, run_id, outcome) = guard465_journal_probe_round(Guard465JournalProbe::Miss).await;
    assert_eq!(
        outcome.unwrap().unwrap(),
        "miss",
        "撤销图下未登记调用必须仍是普通缺席"
    );
    assert_eq!(
        service
            .run_events(&run_id)
            .iter()
            .filter(|event| event["event"] == "tool.completed")
            .count(),
        1
    );
    service.shutdown().await.unwrap();
}

/// R464-7 正控：真正的 final 执行回放在撤销图下走新拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_7_final_revoked_refuses_execution() {
    let (service, run_id, outcome) =
        guard465_journal_probe_round(Guard465JournalProbe::FinalExact).await;
    assert_eq!(
        outcome.unwrap().unwrap_err(),
        "plugin_graph_revoked",
        "真正的 final 执行回放必须走新拒绝"
    );
    assert_eq!(
        service
            .run_events(&run_id)
            .iter()
            .filter(|event| event["event"] == "tool.completed")
            .count(),
        1,
        "被拒绝的回放不得提交第二个结果"
    );
    service.shutdown().await.unwrap();
}

/// R464-7 RED：final 记录配错 canonical 时，撤销不得覆盖原参数身份分类。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_7_final_argument_mismatch_keeps_identity_error() {
    let (service, _run_id, outcome) =
        guard465_journal_probe_round(Guard465JournalProbe::WrongCanonical).await;
    assert_eq!(
        outcome.unwrap().unwrap_err(),
        "managed replay argument identity mismatch",
        "参数身份不匹配必须保留原有分类，不得被撤销覆盖"
    );
    service.shutdown().await.unwrap();
}

/// R464-7 RED：final 记录配错 tool 时，撤销不得覆盖原身份分类。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_465_r464_7_final_tool_mismatch_keeps_identity_error() {
    let (service, _run_id, outcome) =
        guard465_journal_probe_round(Guard465JournalProbe::WrongTool).await;
    assert_eq!(
        outcome.unwrap().unwrap_err(),
        "managed replay identity mismatch",
        "调用身份不匹配必须保留原有分类，不得被撤销覆盖"
    );
    service.shutdown().await.unwrap();
}

// ===== guard_contract_468_：R467-1/R467-2 当前合同缺陷证据（只证据，不修生产） =====
// R467-1：公开 memory 构造器（AgentGatewayState::new，即 closed embedded
// sealed runtime）下，同 canonical 请求/key 两次准入必须返回原 run。
// 当前 service.rs:7198 处 receipt-only 门在 persistence=None 时直接拒绝，
// 按静态分析第二次请求失败为 PluginGraphPinRequired（本用例取 RED）。
// R467-2：direct managed final replay 在原根开放时进入 freshness 查询
// （plugin.graph_revocation_get，enqueue 边界），查询中原根 requested 或
// 有限 deadline 到期。当前 journal.rs:1392-1399 把查询失败一律改写成
// pin_required，正确分类应为 cancelled / deadline_elapsed（本组取 RED）。
// 所有探针只用已有 fixture/producer/hook，不新增生产逻辑与通用框架。

/// R467-1：memory 显式无状态准入自带 ExplicitStateless 证明与 retained
/// handle；同 key/hash/selector 第二次准入必须返回原 run/session/status
/// 且 replayed=true，不新增事件与 handle。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_468_r467_1_stateless_memory_replay_returns_original() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("memory 构造器必须装好当前受支持的无状态 sealed runtime");
    let service = state.service();
    let request = AdmitRunRequest {
        input: json!({"message":"stateless memory idempotent replay"}),
        idempotency_key: Some("guard-468-r467-1".to_string()),
        idempotency_hash: Some("fnv64:0000000000004681".to_string()),
        ..Default::default()
    };
    let first = service
        .admit_external_with_workspace_selector(request.clone(), None)
        .await
        .expect("首次显式无状态准入必须成功，否则为 setup 失败而非 qualified RED");
    assert!(!first.replayed, "首次准入不得标记 replayed: {first:?}");
    // 正向原准入证明：retained handle 真实存在，且为 ExplicitStateless。
    let handle = service
        .handle(&first.run_id)
        .expect("原 run 必须保留 retained handle，不得凭 persistence=None 放行");
    let pin = handle
        .pinned_tool
        .clone()
        .expect("无状态准入必须 seal 住原 pin");
    assert!(
        pin.managed.is_none(),
        "显式无状态 pin 不得携带 managed binding"
    );
    assert!(
        matches!(
            handle.native_disposition.clone(),
            Some(super::super::NativeRuntimeDisposition::ExplicitStateless(_))
        ),
        "原准入证明必须是 ExplicitStateless retained handle"
    );
    let before_events = service.run_events(&first.run_id).len();
    let before_handles = service.handle_count();
    // 同 canonical 请求/key 第二次准入必须返回原 run。
    let second = service
        .admit_external_with_workspace_selector(request.clone(), None)
        .await
        .expect("显式无状态 memory 历史必须返回原 run/status，不得构造可执行 pin");
    assert!(second.replayed, "历史返回必须标记 replayed");
    assert_eq!(second.run_id, first.run_id, "幂等历史必须返回原 run");
    assert_eq!(
        second.session_id, first.session_id,
        "幂等历史不得新建 session"
    );
    assert_eq!(second.status, first.status, "幂等历史必须返回原 status");
    assert_eq!(
        service.run_events(&first.run_id).len(),
        before_events,
        "历史返回不得新增事件"
    );
    assert_eq!(
        service.handle_count(),
        before_handles,
        "历史返回不得新增 handle"
    );
    service.shutdown().await.unwrap();
}

/// R467-2 关根方式：requested 直接 request 原根；elapsed 在 enqueue 边界
/// 做一次有界等待，让原已配置有限 deadline 在该精确缝隙到期。不建新根、
/// 不延预算、无重试轮询。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Guard468FinalClose {
    Requested,
    Elapsed,
}

/// 468 lifecycle 探针原有内联源码，提为测试常量，使 admission 前编译的
/// 程序与 provider 实际执行的是同一份源码。
const GUARD468_LIFECYCLE_REPLAY_SOURCE: &str =
    "pub fn run(context:map)->map { agent_runtime::tool_replay(context) }";

/// 491：把探针的不可变编译成本移出原 2s admission 窗口。
///
/// 只保留由既有 fixture 源码编译出的 immutable 代码句柄（program + registry，
/// 入口固定为 `run`）；不含 run/owner/receipt/authority/grant/token。每次实际
/// 调用仍从 admitted handle 现取 fresh host bridges 再绑定，原 provider 顺序、
/// 原根时钟、原 cut 与全部语义断言不变。
struct GuardRetainedProbeCode {
    runner: std::sync::Mutex<Option<crate::AgentRunner>>,
}

impl GuardRetainedProbeCode {
    /// admission 前编译：只准备代码，不建 run、不建 authority。
    fn compile(source: &str) -> Result<Self, String> {
        crate::AgentRunner::from_source(source, crate::AgentConfig::default())
            .map(|runner| Self {
                runner: std::sync::Mutex::new(Some(runner)),
            })
            .map_err(|error| error.to_string())
    }

    /// 取走 immutable 代码，并安装本次实际调用刚取得的 host bridges。
    fn bind(&self, host: crate::AgentHostBridges) -> crate::AgentRunner {
        self.runner
            .lock()
            .unwrap()
            .take()
            .expect("retained probe code must bind exactly once")
            .with_host(host)
    }
}

/// 共享的 admission 前编译 Native 探针执行器：调用方只提供已冻结的
/// `GuardRetainedProbeCode`；这里在 original pinned handle 上现取 pin 并绑定
/// fresh host bridges，绝不重新编译（编译成本已在原 2s 窗口之外）。
fn run_retained_native_probe_result(
    probe: &GuardRetainedProbeCode,
    service: &crate::AgentService,
    host: crate::AgentHostBridges,
    run_id: &str,
    call: &Value,
    canonical: &str,
    risk_class: &str,
) -> Result<Value, String> {
    let mut host = host;
    let pinned_tool = service
        .handle(run_id)
        .ok_or("the admitted run handle must stay live for the Native probe")?
        .pinned_tool
        .clone();
    host.pinned_tool = pinned_tool;
    let input = native_probe_input(service, &host, run_id, call, canonical, risk_class);
    let runner = probe.bind(host);
    runner
        .run_with_context(input)
        .map(|value| native_json(&value))
        .map_err(|error| format!("retained Native probe execution failed: {error:?}"))
}

fn run_retained_native_probe(
    probe: &GuardRetainedProbeCode,
    service: &crate::AgentService,
    host: crate::AgentHostBridges,
    run_id: &str,
    call: &Value,
    canonical: &str,
    risk_class: &str,
) -> Value {
    run_retained_native_probe_result(probe, service, host, run_id, call, canonical, risk_class)
        .unwrap()
}

/// step 2 的 original bridge 事实：同一原时钟、Some(D)、owner run/profile/
/// session、durable parent canonical arguments 与 sealed registry。
/// 495：返回普通 Result，供首个 final 之前的失败统一走清理路径。
/// 508：run_id/session_id 由既有 `AdmittedRun` 一并携带，参数回到 7 个。
fn original_bridge_facts(
    host: &crate::AgentHostBridges,
    run: &crate::service::AdmittedRun,
    original: &crate::RunCancellation,
    binding: &crate::effects::broker::ManagedRunBinding,
    call_id: &str,
    tool_name: &str,
    call_arguments: &Value,
) -> Result<(), String> {
    let bridge = host
        .cancellation
        .as_ref()
        .ok_or("admission bridge must carry a cancellation root")?;
    if !bridge.shares_original_clock(original) {
        return Err("bridge cancellation must share the original admission clock".into());
    }
    if bridge.deadline_instant() != original.deadline_instant() {
        return Err("bridge deadline must be the original admission deadline".into());
    }
    if bridge.deadline_instant().is_none() {
        return Err("the original admission root must carry Some(D)".into());
    }
    let owner = host
        .capability_owner
        .as_ref()
        .ok_or("admission bridge must carry the capability owner")?;
    if owner.run() != run.run_id.as_str() {
        return Err("bridge owner run must be original".into());
    }
    if owner.session() != run.session_id.as_str() {
        return Err("bridge owner session must be original".into());
    }
    if owner.profile() != binding.owner.profile.as_str() {
        return Err("bridge owner profile must be original".into());
    }
    let lifecycle = host
        .lifecycle
        .as_ref()
        .ok_or("admission bridge must carry the lifecycle")?;
    let parent = lifecycle
        .parent_arguments(owner, call_id, tool_name)
        .map_err(|_| "durable parent arguments must stay readable".to_string())?
        .ok_or("the durable provider parent tool call must be sealed")?;
    if &parent != call_arguments {
        return Err(
            "durable parent canonical arguments must equal the exact first call arguments".into(),
        );
    }
    if lifecycle.registry_identity() != binding.code.registry_identity {
        return Err("bridge must seal the original registry identity".into());
    }
    Ok(())
}

fn assert_original_bridge(
    host: &crate::AgentHostBridges,
    run: &crate::service::AdmittedRun,
    original: &crate::RunCancellation,
    binding: &crate::effects::broker::ManagedRunBinding,
    call_id: &str,
    tool_name: &str,
    call_arguments: &Value,
) {
    if let Err(failure) = original_bridge_facts(
        host,
        run,
        original,
        binding,
        call_id,
        tool_name,
        call_arguments,
    ) {
        panic!("{failure}");
    }
}

/// step 3：首个真实 Native managed final 的 typed 事实。
/// 495：返回普通 Result；调用方可先清理再报告首个 final 的失败。
fn first_native_final_facts(
    persistence: &crate::GatewayPersistence,
    binding: &crate::effects::broker::ManagedRunBinding,
    call_id: &str,
    tool_name: &str,
    canonical: &str,
) -> Result<crate::effects::ManagedEffectRecord, String> {
    let record = persistence
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: call_id.into(),
        })
        .map_err(|_| "managed record query must succeed".to_string())?
        .ok_or("the first Native call must have a typed managed effect record")?;
    let outcome = record
        .outcome
        .as_ref()
        .ok_or("the first Native call must commit a durable final outcome")?;
    if !matches!(
        record.state,
        crate::effects::ManagedPublicationStatus::ReadOnly
            | crate::effects::ManagedPublicationStatus::Committed
    ) {
        return Err(format!(
            "legitimate first final must be read_only or committed: {record:?}"
        ));
    }
    if outcome.disposition != record.state {
        return Err("final disposition must equal the committed record state".into());
    }
    if outcome.replayed {
        return Err("the first final must be a real commit, not a replay".into());
    }
    if record.effect_id != outcome.publication.effect_id {
        return Err("the typed record must keep the original effect id".into());
    }
    if record.identity.owner != binding.owner {
        return Err("owner must be the original binding owner".into());
    }
    if record.identity.call_id.as_str() != call_id {
        return Err("call id must be the exact first call".into());
    }
    if record.identity.tool_name.as_str() != tool_name {
        return Err("tool name must be the exact first tool".into());
    }
    if record.identity.code != binding.code {
        return Err(
            "graph/generation/registry/package identity must be the admitted sealed code".into(),
        );
    }
    let crate::effects::ManagedArgumentIdentity::Inline {
        canonical_arguments,
    } = &record.identity.argument_identity
    else {
        return Err("small fixture arguments must remain inline".into());
    };
    if canonical_arguments.as_str() != canonical {
        return Err("the first final must seal the exact first call canonical arguments".into());
    }
    Ok(record)
}

fn assert_first_native_final(
    persistence: &crate::GatewayPersistence,
    binding: &crate::effects::broker::ManagedRunBinding,
    call_id: &str,
    tool_name: &str,
    canonical: &str,
) -> crate::effects::ManagedEffectRecord {
    match first_native_final_facts(persistence, binding, call_id, tool_name, canonical) {
        Ok(record) => record,
        Err(failure) => panic!("{failure}"),
    }
}

fn count_tool_events(
    service: &crate::AgentService,
    run_id: &str,
    event: &str,
    call_id: &str,
) -> usize {
    service
        .run_events(run_id)
        .iter()
        .filter(|row| row["event"] == event && row["data"]["tool_call_id"] == call_id)
        .count()
}

/// 468 首个只读 final 的稳定 admission/call 事实。
///
/// `run` 是唯一一次 admission 的 typed 结果（run/session 身份唯一来源）；
/// `handle` 是同一 run 已保留的 owned handle，original 取消根只从它派生，
/// 不另存可被替换的副本；`binding` 是同一 handle 上 pinned 的 managed
/// binding。`first_probe`/`call`/`canonical`/`args` 是 admission 前编译的
/// invoke-only 探针与首个调用的原始字节，`call_id` 是它 sealed 的调用 id。
struct Guard468FirstFinal<'a> {
    run: &'a crate::service::AdmittedRun,
    handle: &'a crate::service::RunHandle,
    binding: &'a crate::effects::broker::ManagedRunBinding,
    first_probe: &'a GuardRetainedProbeCode,
    call: &'a Value,
    canonical: &'a str,
    args: &'a Value,
    call_id: &'a str,
}

impl Guard468FirstFinal<'_> {
    /// 原取消/时钟根直接取自保留 handle 的 cancel（同一 Arc 根）。
    fn original(&self) -> &crate::RunCancellation {
        &self.handle.cancel
    }
}

/// 495：468 首个只读 Native final 的全部验证收集为普通 Result。
///
/// 只读动作按真实审批模型使用 admission 前编译的 invoke-only 源码，不申请
/// 写审批；parent/bridge/首个 final/事件仍是同一原 10s 根上的真实事实。
/// 任一事实不成立时返回 Err，由调用方先撤 hook、shutdown，再报告失败。
fn guard468_first_final(
    service: &crate::AgentService,
    persistence: &crate::GatewayPersistence,
    provider: &Arc<crate::ScriptedProvider>,
    facts: &Guard468FirstFinal<'_>,
) -> Result<crate::effects::ManagedEffectRecord, String> {
    use crate::AgentProviderHost;
    let run_id = facts.run.run_id.as_str();
    let call_id = facts.call_id;
    let original = facts.original();
    if original.deadline_instant().is_none() {
        return Err("the original admission root must carry Some(D)".into());
    }
    // step 2：正式 DurableProviderHost parent，恰好一次真实 provider 请求。
    let durable = crate::durable_provider::DurableProviderHost::new(
        (*service).clone(),
        run_id.to_string(),
        provider.clone(),
        service.inner.metrics.clone(),
    );
    let request = json!({"model":"synthetic","messages":[]});
    let parent = durable.call(&request, original);
    if parent["ok"] != true {
        return Err(format!(
            "the formal durable provider parent must succeed: {parent}"
        ));
    }
    if provider.requests().len() != 1 {
        return Err(format!(
            "the narrow fixture must issue exactly one real provider request, got {}",
            provider.requests().len()
        ));
    }
    let host = match service.capability_host_bridges(run_id) {
        Ok(Some(host)) => host,
        Ok(None) => {
            return Err("the admitted run must expose its original capability bridges".into());
        }
        Err(error) => return Err(format!("capability host bridge query failed: {error}")),
    };
    original_bridge_facts(
        &host,
        facts.run,
        original,
        facts.binding,
        call_id,
        "read_file",
        facts.args,
    )?;
    // step 3：真实 invoke_pinned_tool 执行首个只读 final，无写审批申请。
    let first = run_retained_native_probe_result(
        facts.first_probe,
        service,
        host,
        run_id,
        facts.call,
        facts.canonical,
        "read",
    )?;
    if first["ok"] != true {
        return Err(format!(
            "the first Native invoke must commit the read-only final: {first}"
        ));
    }
    let invoke_canonical: Value = match first["canonical_result"].as_str() {
        Some(result) => serde_json::from_str(result)
            .map_err(|error| format!("first Native canonical_result is not JSON: {error}"))?,
        None => {
            return Err(format!(
                "the first Native invoke must return canonical_result: {first}"
            ));
        }
    };
    // The plugin tool's final content is the audited pure leaf applied to the
    // known `path` call argument, not a builtin read_file echo and not a value
    // copied from the final managed record.
    if invoke_canonical["content"] != json!(signed_leaf_478::GUARD468_EXPECTED_CONTENT) {
        return Err(format!(
            "the first Native read must return the exact pure-leaf content: {invoke_canonical}"
        ));
    }
    let first_record = first_native_final_facts(
        persistence,
        facts.binding,
        call_id,
        "read_file",
        facts.canonical,
    )?;
    if first_record.state != crate::effects::ManagedPublicationStatus::ReadOnly {
        return Err(format!(
            "the read-only 468 first final must be read_only: {first_record:?}"
        ));
    }
    let started = count_tool_events(service, run_id, "tool.started", call_id);
    if started != 1 {
        return Err(format!(
            "the first Native call must start exactly once, got {started}"
        ));
    }
    let completed = count_tool_events(service, run_id, "tool.completed", call_id);
    if completed != 1 {
        return Err(format!(
            "the first Native call must complete exactly once, got {completed}"
        ));
    }
    Ok(first_record)
}

struct Guard468CloseEvidence {
    before: Result<String, String>,
    binding_after: Option<Result<String, String>>,
    lifecycle_after: Option<Value>,
    hook_rows: Vec<(String, bool, bool)>,
    root_requested: bool,
    root_deadline_passed: bool,
    tool_completed: usize,
}

/// 一次正式 fixture：真实提交一次终态→正控→有限 hook 关原根→单次精确回放。
/// 返回前清理 hook 并 shutdown，再由调用方断言。
async fn guard468_close_round(
    close: Guard468FinalClose,
    lifecycle: bool,
    call_id: &str,
) -> Guard468CloseEvidence {
    // The four rounds reuse the audited signed phase-A ToolOnly + pure-leaf
    // fixture through a dedicated test body (real prepare -> pure leaf over the
    // known `path` argument -> canonical result -> real commit). No file is
    // opened; the original 10 s root is still created only by the single target
    // admission below.
    let label = format!("468-{call_id}");
    let (state, signed_graph) = signed_leaf_478::open_guard468_signed_read_chain(&label).await;
    let service = state.service();
    let persistence = state.persistence().unwrap();
    let call = json!({"id":call_id,"name":"read_file","arguments":{"path":"seed.txt"}});
    let canonical = call["arguments"].to_string();
    let args = call["arguments"].clone();
    // 491：原 10s 根只在下面唯一一次正式 admission 创建。先把 service 自身的
    // agent/template 与两条不可变 Native 探针编译完，窗口内不再 from_source。
    if let Err(error) = service.materialize_cached_runner() {
        let cleanup = service.shutdown().await;
        panic!("guard468 fixture runner materialization failed: {error} (shutdown: {cleanup:?})");
    }
    // 495：只读 468 使用 admission 前编译的 invoke-only 源码，不申请写审批。
    let first_probe = match GuardRetainedProbeCode::compile(NATIVE_PROBE_REPLAY_SOURCE) {
        Ok(code) => code,
        Err(error) => {
            let cleanup = service.shutdown().await;
            panic!(
                "guard468 Native first-final probe compile failed: {error} (shutdown: {cleanup:?})"
            );
        }
    };
    let lifecycle_probe = if lifecycle {
        match GuardRetainedProbeCode::compile(GUARD468_LIFECYCLE_REPLAY_SOURCE) {
            Ok(code) => Some(code),
            Err(error) => {
                let cleanup = service.shutdown().await;
                panic!("guard468 lifecycle probe compile failed: {error} (shutdown: {cleanup:?})");
            }
        }
    } else {
        None
    };
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(call.clone())));
    service.inject_provider_host(provider.clone());
    // 唯一一次真实 admission：它创建 original 10s 根、owned handle 与 pinned binding。
    let run = match service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"commit once, probe final freshness close classification"}),
                ..Default::default()
            },
            None,
        )
        .await
    {
        Ok(run) => run,
        Err(error) => {
            let cleanup = service.shutdown().await;
            panic!("guard468 single admission failed: {error} (shutdown: {cleanup:?})");
        }
    };
    let run_id = run.run_id.clone();
    let handle = service.handle(&run_id).unwrap();
    let original = handle.cancel.clone();
    let pin = handle
        .pinned_tool
        .clone()
        .expect("the single admission must pin an owned managed tool");
    let binding = pin
        .managed
        .as_ref()
        .expect("the admitted pin must own a managed binding")
        .clone();
    // The activated signed lock and the admitted pin/managed code must be the
    // same ToolOnly phase-A graph/generation/package/catalog. A mismatch is
    // still before any cut and uses the existing first-failure cleanup protocol.
    if let Err(primary) = signed_leaf_478::guard468_signed_pin_facts(&pin, &binding, &signed_graph)
    {
        *persistence.managed_request_hook.lock().unwrap() = None;
        let cleanup = service.shutdown().await;
        panic!(
            "guard468 signed pin validation failed before any cut: {primary} (shutdown: {cleanup:?})"
        );
    }
    // step 2/3：parent、original bridge 与首个只读 final 全部收集为 Result；
    // 任一失败都先清 hook、shutdown，再连同清理结果报告。
    let first_final_facts = Guard468FirstFinal {
        run: &run,
        handle: &handle,
        binding: &binding,
        first_probe: &first_probe,
        call: &call,
        canonical: &canonical,
        args: &args,
        call_id,
    };
    let first_record = match guard468_first_final(
        &service,
        &persistence,
        &provider,
        &first_final_facts,
    ) {
        Ok(record) => record,
        Err(primary) => {
            *persistence.managed_request_hook.lock().unwrap() = None;
            let cleanup = service.shutdown().await;
            panic!(
                "guard468 first-final validation failed before any cut: {primary} (shutdown: {cleanup:?})"
            );
        }
    };
    // step 4：同一 binding 上的未撤销正控。
    let before = match binding.replay_live(call_id, "read_file", Some(&args), Some(&canonical)) {
        Ok(None) => Ok("miss".to_string()),
        Ok(Some(_)) => Ok("final".to_string()),
        Err(message) => Err(message),
    };
    // 有限 hook：只匹配 exact fresh graph 查询的 enqueue 边界，恰触发一次。
    let hook_rows = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hook_rows_in = Arc::clone(&hook_rows);
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired_in = Arc::clone(&fired);
    *persistence.managed_request_hook.lock().unwrap() =
        Some(Arc::new(move |op, cancel, enqueued| {
            if op != "plugin.graph_revocation_get" || enqueued {
                return;
            }
            hook_rows_in.lock().unwrap().push((
                op.to_string(),
                enqueued,
                cancel.shares_original_clock(&original),
            ));
            if fired_in
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_err()
            {
                return;
            }
            match close {
                Guard468FinalClose::Requested => {
                    original.request(crate::CancellationReason::Requested)
                }
                Guard468FinalClose::Elapsed => std::thread::sleep(
                    original.remaining_deadline().unwrap_or_default()
                        + std::time::Duration::from_millis(100),
                ),
            }
        }));
    let (binding_after, lifecycle_after) = if before == Ok("final".to_string()) {
        if lifecycle {
            let mut host = service.capability_host_bridges(&run_id).unwrap().unwrap();
            host.pinned_tool = Some(pin.clone());
            let registry = host.lifecycle.as_ref().unwrap().registry_identity();
            let input = guard465_tool_replay_input(&run_id, call_id, &canonical, registry);
            let runner = lifecycle_probe
                .as_ref()
                .expect("lifecycle probe code must be compiled before admission")
                .bind(host);
            let replayed = native_json(&runner.run_with_context(guard465_vm_map(&input)).unwrap());
            (None, Some(replayed))
        } else {
            let probed = binding.replay_live(call_id, "read_file", Some(&args), Some(&canonical));
            (
                Some(match probed {
                    Ok(None) => Ok("miss".to_string()),
                    Ok(Some(_)) => Ok("final".to_string()),
                    Err(message) => Err(message),
                }),
                None,
            )
        }
    } else {
        (None, None)
    };
    // 保留原始 Option/Result，撤 hook 与 shutdown 之后才判定缺失。
    let handle = service.handle(&run_id);
    let root_requested = handle
        .as_ref()
        .is_some_and(|handle| handle.cancel.requested().is_some());
    let root_deadline_passed = handle
        .as_ref()
        .is_some_and(|handle| handle.cancel.deadline_passed());
    let tool_completed = count_tool_events(&service, &run_id, "tool.completed", call_id);
    // 495：终态记录也先收成 Result；撤 hook、shutdown 之后才判定缺失或比较。
    let after_record: Result<crate::effects::ManagedEffectRecord, String> = persistence
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: call_id.into(),
        })
        .map_err(|error| format!("managed record query failed: {error}"))
        .and_then(|record| {
            record.ok_or_else(|| "the first committed final must stay queryable".to_string())
        });
    let rows = hook_rows.lock().unwrap().clone();
    drop(handle);
    *persistence.managed_request_hook.lock().unwrap() = None;
    let shutdown_result = service.shutdown().await;
    let after_record = match after_record {
        Ok(record) => record,
        Err(failure) => {
            panic!("guard468 post-cut record invalid: {failure} (shutdown: {shutdown_result:?})")
        }
    };
    shutdown_result.unwrap();
    assert_eq!(
        after_record.effect_id, first_record.effect_id,
        "the refusal must not replace the original effect"
    );
    assert_eq!(
        after_record.outcome, first_record.outcome,
        "the whole canonical history must stay exactly the first committed final"
    );
    Guard468CloseEvidence {
        before,
        binding_after,
        lifecycle_after,
        hook_rows: rows,
        root_requested,
        root_deadline_passed,
        tool_completed,
    }
}

fn guard468_assert_freshness_stage(rows: &[(String, bool, bool)]) {
    assert!(
        !rows.is_empty(),
        "必须实际经过 exact fresh graph 查询的 enqueue 边界：{rows:?}"
    );
    assert!(
        rows.iter().all(|(op, enqueued, shared)| {
            op == "plugin.graph_revocation_get" && !enqueued && *shared
        }),
        "查询必须是原根时钟下的 plugin.graph_revocation_get enqueue 边界：{rows:?}"
    );
}

/// R467-2 requested：原根在新增 freshness 查询中被 request，直接 binding
/// 回放必须保留 cancelled 分类，不得改成 pin_required。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_468_r467_2_requested_binding_keeps_cancelled() {
    let evidence = guard468_close_round(Guard468FinalClose::Requested, false, "close-1").await;
    assert_eq!(
        evidence.before,
        Ok("final".to_string()),
        "正控必须先成功，否则为 setup 失败而非 qualified RED"
    );
    guard468_assert_freshness_stage(&evidence.hook_rows);
    assert!(evidence.root_requested, "hook 必须关闭原根，不得替换新根");
    assert_eq!(
        evidence.binding_after.unwrap(),
        Err("cancelled".to_string()),
        "原 requested 在新增 freshness 查询中必须保留 cancelled 分类"
    );
    assert_eq!(evidence.tool_completed, 1, "被拒绝的回放不得提交第二个结果");
}

/// R467-2 requested：同一条件下官方 tool_replay lifecycle 入口必须精确
/// cancelled，不得改成 pin_required。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_468_r467_2_requested_lifecycle_keeps_cancelled() {
    let evidence = guard468_close_round(Guard468FinalClose::Requested, true, "close-2").await;
    assert_eq!(
        evidence.before,
        Ok("final".to_string()),
        "正控必须先成功，否则为 setup 失败而非 qualified RED"
    );
    guard468_assert_freshness_stage(&evidence.hook_rows);
    assert!(evidence.root_requested, "hook 必须关闭原根，不得替换新根");
    let replayed = evidence.lifecycle_after.unwrap();
    assert_eq!(
        replayed["ok"], false,
        "关闭原根后 tool_replay 必须拒绝：{replayed}"
    );
    assert_eq!(
        replayed["error"]["code"], "cancelled",
        "官方 tool_replay 必须精确 cancelled，不得吞成 pin_required：{replayed}"
    );
    assert_eq!(evidence.tool_completed, 1, "被拒绝的回放不得提交第二个结果");
}

/// R467-2 elapsed：原有限 deadline 在新增 freshness 查询的受控缝隙到期，
/// 直接 binding 回放必须保留 deadline_elapsed 分类，不得改成 pin_required。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_468_r467_2_elapsed_binding_keeps_deadline_elapsed() {
    let evidence = guard468_close_round(Guard468FinalClose::Elapsed, false, "close-3").await;
    assert_eq!(
        evidence.before,
        Ok("final".to_string()),
        "正控必须先成功，否则为 setup 失败而非 qualified RED"
    );
    guard468_assert_freshness_stage(&evidence.hook_rows);
    assert!(
        evidence.root_deadline_passed,
        "原有限 deadline 必须已在查询缝隙到期"
    );
    assert_eq!(
        evidence.binding_after.unwrap(),
        Err("deadline_elapsed".to_string()),
        "原到期在新增 freshness 查询中必须保留 deadline_elapsed 分类"
    );
    assert_eq!(evidence.tool_completed, 1, "被拒绝的回放不得提交第二个结果");
}

/// R467-2 elapsed：同一条件下官方 tool_replay lifecycle 入口必须精确
/// deadline_elapsed，不得改成 pin_required。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_468_r467_2_elapsed_lifecycle_keeps_deadline_elapsed() {
    let evidence = guard468_close_round(Guard468FinalClose::Elapsed, true, "close-4").await;
    assert_eq!(
        evidence.before,
        Ok("final".to_string()),
        "正控必须先成功，否则为 setup 失败而非 qualified RED"
    );
    guard468_assert_freshness_stage(&evidence.hook_rows);
    assert!(
        evidence.root_deadline_passed,
        "原有限 deadline 必须已在查询缝隙到期"
    );
    let replayed = evidence.lifecycle_after.unwrap();
    assert_eq!(
        replayed["ok"], false,
        "原到期后 tool_replay 必须拒绝：{replayed}"
    );
    assert_eq!(
        replayed["error"]["code"], "deadline_elapsed",
        "官方 tool_replay 必须精确 deadline_elapsed，不得吞成 pin_required：{replayed}"
    );
    assert_eq!(evidence.tool_completed, 1, "被拒绝的回放不得提交第二个结果");
}

// ===== guard471：retained stateless authority 负控（仅测试，不改生产） =====
// memory 无持久化路径下，缺 retained handle 的历史复用必须闭门失败，
// 不能凭 persistence=None 放行，更不能返回 Ok。

/// R467-1 负控：未知 id 与被驱逐的 retained handle 都必须闭门失败。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_471_r467_1_stateless_absent_handle_refuses_replay() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("memory 构造器必须装好当前受支持的无状态 sealed runtime");
    let service = state.service();
    assert!(
        matches!(
            service.validate_owned_admission_receipt("no-such-run"),
            Err(crate::AdmitError::PluginGraphPinRequired)
        ),
        "未知 run 必须闭门失败，不能凭缺席放行"
    );
    let request = AdmitRunRequest {
        input: json!({"message":"stateless memory idempotent replay"}),
        idempotency_key: Some("guard-471-evicted".to_string()),
        idempotency_hash: Some("fnv64:0000000000004711".to_string()),
        ..Default::default()
    };
    let first = service
        .admit_external_with_workspace_selector(request.clone(), None)
        .await
        .expect("首次显式无状态准入必须成功，否则为 setup 失败而非 qualified RED");
    let handles_before = service.handle_count();
    service.evict_run_handle(&first.run_id);
    assert!(service.handle(&first.run_id).is_none());
    let replayed = service
        .admit_external_with_workspace_selector(request.clone(), None)
        .await;
    assert!(
        matches!(replayed, Err(crate::AdmitError::PluginGraphPinRequired)),
        "被驱逐的 retained handle 必须闭门失败，不得返回 Ok：{replayed:?}"
    );
    assert_eq!(
        service.handle_count(),
        handles_before - 1,
        "失败的复用不得重建 handle"
    );
    service.shutdown().await.unwrap();
}

/// R467-1 负控：retained handle 缺 pin、缺 disposition 或证明错配时，
/// 历史收据校验必须闭门失败。只用已 retained 的真实 pin/证明交叉装配，
/// 不伪造 guest 证明，不新增生产 API。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_471_r467_1_stateless_absent_or_mismatched_proof_refuses_receipt() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("memory 构造器必须装好当前受支持的无状态 sealed runtime");
    let service = state.service();
    let first = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"stateless proof zero"}),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("首次显式无状态准入必须成功，否则为 setup 失败而非 qualified RED");
    let second = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"stateless proof one"}),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("第二次显式无状态准入必须成功，否则为 setup 失败而非 qualified RED");
    let live_zero = service
        .handle(&first.run_id)
        .expect("原 run 必须保留 retained handle");
    let pin_zero = live_zero
        .pinned_tool
        .clone()
        .expect("无状态准入必须 seal 住原 pin");
    let proof_zero = live_zero
        .native_disposition
        .clone()
        .expect("原准入证明必须是 ExplicitStateless");
    let live_one = service
        .handle(&second.run_id)
        .expect("第二个 run 必须保留 retained handle");
    let proof_one = live_one
        .native_disposition
        .clone()
        .expect("第二个准入证明必须是 ExplicitStateless");
    drop(live_zero);
    drop(live_one);
    let craft = |pinned: Option<crate::runtime::agent_host::PinnedToolProgram>,
                 disposition: Option<super::super::NativeRuntimeDisposition>| {
        super::super::RunHandle {
            cancel: crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
            terminal_at: std::sync::Mutex::new(None),
            permit: std::sync::Mutex::new(None),
            started_at: std::time::Instant::now(),
            terminal: std::sync::atomic::AtomicBool::new(false),
            cancel_reason: std::sync::Mutex::new(None),
            subscribers: std::sync::Mutex::new(super::super::SubscriberState {
                count: 0,
                notified: false,
            }),
            disconnect_policy: crate::config::ClientDisconnectPolicy::KeepRunning,
            tool_cancel: crate::runtime::cancellation::CancellationToken::new(),
            capability_host: std::sync::Mutex::new(super::super::CapabilityHostPhase::Empty),
            capability_host_cv: std::sync::Condvar::new(),
            workspace_authority: None,
            legacy_workspace_root: None,
            coding_system_prompt: std::sync::Arc::from(""),
            occupancy: std::sync::atomic::AtomicBool::new(false),
            restore_worker_started: None,
            cleanup_outcome: std::sync::Mutex::new(None),
            pinned_tool: pinned,
            native_disposition: disposition,
        }
    };
    service.inner.runs.lock().expect("runs lock").insert(
        "guard-471-missing-pin".to_string(),
        Arc::new(craft(None, Some(proof_zero.clone()))),
    );
    service.inner.runs.lock().expect("runs lock").insert(
        "guard-471-missing-disposition".to_string(),
        Arc::new(craft(Some(pin_zero.clone()), None)),
    );
    service.inner.runs.lock().expect("runs lock").insert(
        "guard-471-wrong-binding".to_string(),
        Arc::new(craft(Some(pin_zero), Some(proof_one))),
    );
    for id in [
        "guard-471-missing-pin",
        "guard-471-missing-disposition",
        "guard-471-wrong-binding",
    ] {
        assert!(
            matches!(
                service.validate_owned_admission_receipt(id),
                Err(crate::AdmitError::PluginGraphPinRequired)
            ),
            "缺 pin、缺 disposition 或证明错配必须闭门失败：{id}"
        );
    }
    service.shutdown().await.unwrap();
}

// ===== guard471：Native invoke_pinned_tool managed Err 分支直接证据 =====
// 图不撤销、entry 放行之后，在 repository fresh 查询缝隙关闭原根，
// 字面 invoke_pinned_tool 的 cancelled/deadline_elapsed 映射必须精确落盘。

/// 471 探针原有内联源码，提为测试常量，使 admission 前编译的程序与 provider
/// 实际执行的是同一份源码。
const GUARD471_NATIVE_INVOKE_SOURCE: &str = r#"pub fn run(context:map)->map {
            let tool_name:string=context["tool_name"];let call_id:string=context["call_id"];let canonical_arguments:string=context["canonical_arguments"];let canonical_input:string=context["canonical_input"];let run_id:string=context["run_id"];let registry_identity:string=context["registry_identity"];let argument_digest:string=context["argument_digest"];let risk_class:string=context["risk_class"];let summary:string=context["summary"];let untrusted_graph_id:string=context["untrusted_graph_id"];
            agent_runtime::invoke_pinned_tool({tool_name:tool_name,call_id:call_id,canonical_arguments:canonical_arguments,canonical_input:canonical_input,run_id:run_id,registry_identity:registry_identity,argument_digest:argument_digest,risk_class:risk_class,summary:summary,untrusted_graph_id:untrusted_graph_id})
        }"#;

struct Guard471NativeManagedEvidence {
    positive: Value,
    denied: Value,
    hook_rows: Vec<(String, bool, bool)>,
    root_requested: bool,
    root_deadline_passed: bool,
    tool_completed: usize,
    history_canonical: String,
    close_query_index: usize,
}

/// 一次正式 fixture：真实终态→未撤销正控→有限 hook 关原根→同源 Native
/// invoke 拒绝。hook 在 worker 返回后清理，shutdown 后再断言。
async fn guard471_native_managed_round(close: Guard468FinalClose) -> Guard471NativeManagedEvidence {
    use crate::AgentProviderHost;
    let (root, state) =
        fixture_config(|config| config.run_timeout = std::time::Duration::from_secs(2));
    let service = state.service();
    let persistence = state.persistence().unwrap();
    let sentinel = root.join("native-managed-sentinel");
    let call = json!({"id":"once","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'; printf observed",sentinel.display())],"timeout_ms":1000}});
    let canonical = call["arguments"].to_string();
    let args = call["arguments"].clone();
    // 491：原 2s 根只在下面唯一一次正式 admission 创建。先把 service 自身的
    // agent/template 与三份不可变 Native 探针编译完，窗口内不再 from_source。
    if let Err(error) = service.materialize_cached_runner() {
        let cleanup = service.shutdown().await;
        panic!("guard471 fixture runner materialization failed: {error} (shutdown: {cleanup:?})");
    }
    let first_probe = match GuardRetainedProbeCode::compile(NATIVE_PROBE_SOURCE) {
        Ok(code) => code,
        Err(error) => {
            let cleanup = service.shutdown().await;
            panic!(
                "guard471 Native first-final probe compile failed: {error} (shutdown: {cleanup:?})"
            );
        }
    };
    let positive_probe = match GuardRetainedProbeCode::compile(GUARD471_NATIVE_INVOKE_SOURCE) {
        Ok(code) => code,
        Err(error) => {
            let cleanup = service.shutdown().await;
            panic!(
                "guard471 positive Native probe compile failed: {error} (shutdown: {cleanup:?})"
            );
        }
    };
    let denied_probe = match GuardRetainedProbeCode::compile(GUARD471_NATIVE_INVOKE_SOURCE) {
        Ok(code) => code,
        Err(error) => {
            let cleanup = service.shutdown().await;
            panic!("guard471 denied Native probe compile failed: {error} (shutdown: {cleanup:?})");
        }
    };
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(call.clone())));
    service.inject_provider_host(provider.clone());
    // 唯一一次真实 admission：它创建 original 2s 根、owned handle 与 pinned binding。
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"probe Native managed mapping after entry"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let run_id = run.run_id.clone();
    let handle = service.handle(&run_id).unwrap();
    let original = handle.cancel.clone();
    let pin = handle
        .pinned_tool
        .clone()
        .expect("the single admission must pin an owned managed tool");
    let binding = pin
        .managed
        .as_ref()
        .expect("the admitted pin must own a managed binding")
        .clone();
    assert!(
        original.deadline_instant().is_some(),
        "the original admission root must carry Some(D)"
    );
    // step 2：正式 DurableProviderHost parent，恰好一次真实 provider 请求。
    let durable = crate::durable_provider::DurableProviderHost::new(
        (*service).clone(),
        run_id.clone(),
        provider.clone(),
        service.inner.metrics.clone(),
    );
    let request = json!({"model":"synthetic","messages":[]});
    let parent = durable.call(&request, &original);
    assert_eq!(
        parent["ok"], true,
        "the formal durable provider parent must succeed: {parent}"
    );
    assert_eq!(
        provider.requests().len(),
        1,
        "the narrow fixture must issue exactly one real provider request"
    );
    let host = service
        .capability_host_bridges(&run_id)
        .unwrap()
        .expect("the admitted run must expose its original capability bridges");
    assert_original_bridge(&host, &run, &original, &binding, "once", "terminal", &args);
    // step 3：真实 approval_attest + invoke_pinned_tool 执行首个 Native final。
    let first = run_retained_native_probe(
        &first_probe,
        &service,
        host.clone(),
        &run_id,
        &call,
        &canonical,
        "execute",
    );
    assert_eq!(
        first["attest"]["ok"], true,
        "the first Native call must obtain the real approval attestation: {first}"
    );
    assert_eq!(
        first["invoke"]["ok"], true,
        "the first Native invoke must commit the execute final: {first}"
    );
    let invoke_canonical: Value =
        serde_json::from_str(first["invoke"]["canonical_result"].as_str().unwrap()).unwrap();
    assert_eq!(
        invoke_canonical["content"], "observed",
        "the first Native terminal must observe its once-executed output: {invoke_canonical}"
    );
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"x",
        "the first Native terminal must execute exactly once"
    );
    let first_record =
        assert_first_native_final(&persistence, &binding, "once", "terminal", &canonical);
    assert_eq!(
        count_tool_events(&service, &run_id, "tool.started", "once"),
        1,
        "the first Native call must start exactly once"
    );
    assert_eq!(
        count_tool_events(&service, &run_id, "tool.completed", "once"),
        1,
        "the first Native call must complete exactly once"
    );
    // step 4：未撤销 Native invoke 精确同 calling 必须回放历史 canonical。
    let positive = run_retained_native_probe(
        &positive_probe,
        &service,
        host.clone(),
        &run_id,
        &call,
        &canonical,
        "execute",
    );
    let history = service
        .replay_managed_call(crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: "once".into(),
        })
        .unwrap();
    let crate::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = history
    else {
        panic!("the committed final must stay queryable as history");
    };
    let history_canonical = canonical_result.as_str().to_string();
    assert_eq!(
        positive["ok"], true,
        "the unrevoked positive Native invoke must succeed: {positive}"
    );
    assert_eq!(
        replayed_kind(&positive),
        "replay",
        "the unrevoked positive Native invoke must be the original replay: {positive}"
    );
    assert_eq!(
        positive["canonical_result"].as_str().unwrap(),
        history_canonical,
        "the positive replay must equal the durable history canonical"
    );
    // 有限 hook：只匹配 exact fresh 查询的 enqueue 边界。第一次是 Native
    // entry guard 的读；第二次才是 entry 放行后 repository 的 final
    // freshness 读，只在该次（恰一次）关闭原根。
    let hook_rows = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hook_rows_in = Arc::clone(&hook_rows);
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen_in = Arc::clone(&seen);
    let close_query = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let close_query_out = Arc::clone(&close_query);
    *persistence.managed_request_hook.lock().unwrap() =
        Some(Arc::new(move |op, cancel, enqueued| {
            if op != "plugin.graph_revocation_get" || enqueued {
                return;
            }
            hook_rows_in.lock().unwrap().push((
                op.to_string(),
                enqueued,
                cancel.shares_original_clock(&original),
            ));
            if seen_in.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 != 2 {
                return;
            }
            close_query_out.store(2, std::sync::atomic::Ordering::SeqCst);
            match close {
                Guard468FinalClose::Requested => {
                    original.request(crate::CancellationReason::Requested)
                }
                Guard468FinalClose::Elapsed => std::thread::sleep(
                    original.remaining_deadline().unwrap_or_default()
                        + std::time::Duration::from_millis(100),
                ),
            }
        }));
    let denied = run_retained_native_probe(
        &denied_probe,
        &service,
        host,
        &run_id,
        &call,
        &canonical,
        "execute",
    );
    // 保留原始 Option/Result，撤 hook 与 shutdown 之后才判定缺失。
    let handle = service.handle(&run_id);
    let root_requested = handle
        .as_ref()
        .is_some_and(|handle| handle.cancel.requested().is_some());
    let root_deadline_passed = handle
        .as_ref()
        .is_some_and(|handle| handle.cancel.deadline_passed());
    let tool_completed = count_tool_events(&service, &run_id, "tool.completed", "once");
    let after_record = persistence
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: "once".into(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        after_record.effect_id, first_record.effect_id,
        "the refusal must not replace the original effect"
    );
    assert_eq!(
        after_record.outcome, first_record.outcome,
        "the whole canonical history must stay exactly the first committed final"
    );
    let rows = hook_rows.lock().unwrap().clone();
    let close_query_index = close_query.load(std::sync::atomic::Ordering::SeqCst);
    drop(handle);
    *persistence.managed_request_hook.lock().unwrap() = None;
    let shutdown_result = service.shutdown().await;
    shutdown_result.unwrap();
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"x",
        "the refused Native invoke must not append a second sentinel"
    );
    Guard471NativeManagedEvidence {
        positive,
        denied,
        hook_rows: rows,
        root_requested,
        root_deadline_passed,
        tool_completed,
        history_canonical,
        close_query_index,
    }
}

/// R467-2 requested：Native entry 放行后关原根，字面 invoke 分支必须
/// 精确 cancelled，无 canonical、无第二结果，正控先成功。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_471_r467_2_native_invoke_requested_keeps_cancelled() {
    let evidence = guard471_native_managed_round(Guard468FinalClose::Requested).await;
    assert_eq!(
        evidence.positive["ok"],
        true,
        "正控必须先成功，否则为 setup 失败而非 qualified RED：{positive}",
        positive = evidence.positive
    );
    assert_eq!(
        replayed_kind(&evidence.positive),
        "replay",
        "未撤销正控必须是原 Native 结果回放：{positive}",
        positive = evidence.positive
    );
    assert_eq!(
        evidence.positive["canonical_result"].as_str().unwrap(),
        evidence.history_canonical,
        "正控回放必须等于历史 canonical"
    );
    assert_eq!(
        evidence.close_query_index, 2,
        "原根必须在 entry guard 之后的第二次 repository freshness 查询关闭"
    );
    guard468_assert_freshness_stage(&evidence.hook_rows);
    assert!(evidence.root_requested, "hook 必须关闭原根，不得替换新根");
    assert_eq!(
        evidence.denied["ok"],
        false,
        "关闭原根后 Native invoke 必须拒绝：{denied}",
        denied = evidence.denied
    );
    assert_eq!(
        evidence.denied["code"],
        "cancelled",
        "字面 invoke 分支必须精确 cancelled：{denied}",
        denied = evidence.denied
    );
    assert_eq!(
        evidence.denied["message"],
        "cancelled",
        "拒绝 message 必须携带精确分类：{denied}",
        denied = evidence.denied
    );
    assert!(
        evidence
            .denied
            .get("canonical_result")
            .is_none_or(|value| value == ""),
        "被拒绝的 invoke 不得泄露 canonical 结果：{denied}",
        denied = evidence.denied
    );
    assert_eq!(evidence.tool_completed, 1, "被拒绝的回放不得提交第二个结果");
}

/// R467-2 elapsed：原有限 deadline 在 fresh 查询缝隙到期，字面 invoke
/// 分支必须精确 deadline_elapsed，无 canonical、无第二结果。
#[tokio::test(flavor = "multi_thread")]
async fn guard_contract_471_r467_2_native_invoke_elapsed_keeps_deadline_elapsed() {
    let evidence = guard471_native_managed_round(Guard468FinalClose::Elapsed).await;
    assert_eq!(
        evidence.positive["ok"],
        true,
        "正控必须先成功，否则为 setup 失败而非 qualified RED：{positive}",
        positive = evidence.positive
    );
    assert_eq!(
        replayed_kind(&evidence.positive),
        "replay",
        "未撤销正控必须是原 Native 结果回放：{positive}",
        positive = evidence.positive
    );
    assert_eq!(
        evidence.positive["canonical_result"].as_str().unwrap(),
        evidence.history_canonical,
        "正控回放必须等于历史 canonical"
    );
    assert_eq!(
        evidence.close_query_index, 2,
        "原根必须在 entry guard 之后的第二次 repository freshness 查询关闭"
    );
    guard468_assert_freshness_stage(&evidence.hook_rows);
    assert!(
        evidence.root_deadline_passed,
        "原有限 deadline 必须已在查询缝隙到期"
    );
    assert_eq!(
        evidence.denied["ok"],
        false,
        "原到期后 Native invoke 必须拒绝：{denied}",
        denied = evidence.denied
    );
    assert_eq!(
        evidence.denied["code"],
        "deadline_elapsed",
        "字面 invoke 分支必须精确 deadline_elapsed：{denied}",
        denied = evidence.denied
    );
    assert_eq!(
        evidence.denied["message"],
        "deadline_elapsed",
        "拒绝 message 必须携带精确分类：{denied}",
        denied = evidence.denied
    );
    assert!(
        evidence
            .denied
            .get("canonical_result")
            .is_none_or(|value| value == ""),
        "被拒绝的 invoke 不得泄露 canonical 结果：{denied}",
        denied = evidence.denied
    );
    assert_eq!(evidence.tool_completed, 1, "被拒绝的回放不得提交第二个结果");
}

// ============================================================================
// 478: first-party signedA — a formally installed signed ToolOnly tool that
// links the approved pure `string -> string` leaf library.
//
// Evidence 1 drives the real Service run to its durable read-only final, then
// replays the exact same call through the actual Native `invoke_pinned_tool`
// bridge while the original run/capability are live, then revokes the exact
// graph through the same control store and re-invokes through the original
// binding bridge.
// Evidence 2 keeps the same signed tool/read pipeline but makes the approved
// pure export fail deterministically at VM runtime on the real provided value.
// ============================================================================
mod signed_leaf_478 {
    use super::{native_json, response};
    use crate::effects::{
        ManagedArgumentIdentity, ManagedCallReplay, ManagedEffectGetRequest, ManagedOwnerScope,
        ManagedPublicationStatus,
    };
    use crate::plugins::{
        InstallAuthorization, PackageStore, PluginControlStore, PublisherKey,
        trusted_tool_package_root,
    };
    use crate::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const LEAF_ID: &str = "org.rustscript.lib.phasetext";
    const TOOL_A_ID: &str = "org.rustscript.tools.phasea";
    const TOOL_C_ID: &str = "org.rustscript.tools.phasec";

    // The same approved pure library export used by the existing 421/456
    // signed tool + leaf fixture.
    const VALID_LEAF: &[u8] = b"pub fn format(value: string) -> string { \"libA:\" + value }\n";
    // Same manifest/export/host-import contract as VALID_LEAF, but a real
    // runtime failure for the value whose length is 5: `size - 5 == 0` and the
    // VM's checked integer division raises DivisionByZero.
    //
    // The 478 body used an arrow-form `if ... => { assignment } else => {
    // assignment }` and the production parser rejected it with
    // `ParseError { line: 8, message: "if expression branch must end with an
    // expression" }`: an arrow-form branch is an expression position, so an
    // assignment statement cannot terminate it. This body therefore uses the
    // ordinary statement `while` form already used by the bundled RSS tools,
    // and keeps the divisor/scale dependency observable: the loop bound is the
    // quotient itself, so a value of length 2 (2 / -3 == 0) yields `libF:hi`.
    const FAILING_LEAF: &[u8] = b"pub fn format(value: string) -> string {\n    let size: int = value.length;\n    let divisor: int = size - 5;\n    let scale: int = size / divisor;\n    let mut cursor: int = 0;\n    let mut out: string = \"libF:\";\n    while cursor < scale {\n        out = out + \"x\";\n        cursor = cursor + 1;\n    }\n    out + value\n}\n";

    const PHASE_A_RUN_SOURCE: &str = r#"use bytes;
use text::{format};
fn map_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}

fn map_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}

fn map_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}

fn map_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}

pub fn run(context: map) -> map {
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_string(prepared, "kind", "") == "replay" => {
        map_map(prepared, "result")
    } else if map_bool(prepared, "ok", false) == false => {
        prepared
    } else => {
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {
            meta
        } else => {
            let file_len: int = map_int(meta, "len", 0);
            let read: map = cap::fs_read_range(token, path, 0, file_len);
            if map_bool(read, "ok", false) == false => {
                read
            } else => {
                let payload: bytes = read.bytes;
                let labeled: string = format(bytes::to_utf8(payload));
                let result: map = { ok: true, content: labeled, data: {}, error: null, truncated: false, artifacts: [] };
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {
                    map_map(committed, "result")
                } else => {
                    committed
                }
            }
        }
    }
}
"#;

    struct SignedLeafChain {
        workspace: std::path::PathBuf,
        db: std::path::PathBuf,
        state: AgentGatewayState,
        store: Arc<PackageStore>,
        graph_a: String,
        generation_a: u64,
    }

    fn effect_request(run: &crate::service::AdmittedRun, call_id: &str) -> ManagedEffectGetRequest {
        ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id.clone(),
                run_id: run.run_id.clone(),
            },
            call_id: call_id.into(),
        }
    }

    /// The fallible formal half of the fixture: resolve → prepare → activate
    /// through the same production entry points the HTTP handlers use. Returns
    /// the original error text instead of panicking so every caller can shut
    /// the already-created Service down before reporting the first cause.
    async fn activate_tool_result(
        state: &AgentGatewayState,
        tool_id: &str,
    ) -> Result<(String, u64), String> {
        let service = state.service();
        let resolved = service
            .resolve_controlled_graph(&json!({
                "roots": [{"id": tool_id, "version": "1.0.0"}],
                "tool_package": tool_id,
                "deployment_space": "owner-space"
            }))
            .map_err(|error| format!("resolve_controlled_graph({tool_id}): {error:?}"))?;
        let graph = resolved["graph_id"]
            .as_str()
            .ok_or_else(|| format!("resolve_controlled_graph({tool_id}) returned no graph_id"))?
            .to_string();
        service
            .prepare_controlled_graph(&graph)
            .map_err(|error| format!("prepare_controlled_graph({tool_id}): {error:?}"))?;
        let persistence = state
            .persistence()
            .ok_or_else(|| format!("persistence({tool_id}) unavailable"))?;
        let expected = PluginControlStore::new(&persistence)
            .activation()
            .map_err(|error| format!("activation({tool_id}): {error:?}"))?
            .generation;
        let activated = service
            .activate_controlled_graph(&json!({
                "graph_id": graph,
                "deployment_space": "owner-space",
                "expected_generation": expected
            }))
            .map_err(|error| format!("activate_controlled_graph({tool_id}): {error:?}"))?;
        Ok((
            activated["graph_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            activated["generation"].as_u64().unwrap_or_default(),
        ))
    }

    /// Formally installs the signed phase-A tool (plus the shared-leaf tool C)
    /// and activates tool A through the production resolve/prepare/activate
    /// path. The fixture root/db/source are per-test, so the same package ids
    /// can carry different approved library bodies in separate stores.
    async fn open_signed_leaf_chain_with(
        label: &str,
        leaf_body: &[u8],
        tool_source: &str,
        run_timeout: std::time::Duration,
    ) -> SignedLeafChain {
        use crate::config::{
            ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig,
        };
        use crate::effects::ResourceQuota;
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let leaf_manifest = format!(
            "format: rustscript.plugin/v1\nid: {LEAF_ID}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: format.rss\n  export: format\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    format:\n      direct: []\n      delegated: []\n"
        );
        let tool_manifest = |id: &str| {
            format!(
                "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: text\n    id: {LEAF_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
            )
        };

        let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("t478-{label}-{}", uuid::Uuid::new_v4().simple()));
        let workspace = root.join("workspace");
        let home = root.join("home");
        let source = root.join("controlled-source");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(workspace.join("seed.txt"), b"seed").unwrap();
        std::fs::write(
            home.join("config.yaml"),
            format!(
                "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",
                workspace.display(),
                workspace.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&root, &workspace, &home, &source] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            std::fs::set_permissions(
                home.join("config.yaml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
        let auth = InstallAuthorization {
            admin: true,
            accepted_publishers: vec![PublisherKey {
                publisher: "org.rustscript".into(),
                verifying_key: pair.public_key().as_ref().to_vec(),
            }],
            unsigned_dev_space: None,
        };
        let mut config = AgentGatewayConfig {
            managed_workspace: Some(ManagedWorkspaceConfig {
                source_root: workspace.clone(),
                quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
                retention: ManagedRetentionLimits::default(),
                maintenance_policy: ManagedMaintenancePolicy {
                    create_checkpoint: true,
                    restore: true,
                    branch: true,
                    publish: false,
                },
            }),
            ..AgentGatewayConfig::default()
        };
        config.approvals.write = "allow".into();
        config.approvals.process = "allow".into();
        config.run_timeout = run_timeout;
        let db = root.join("gateway.sqlite");
        let state = AgentGatewayState::with_sqlite_path(config, &db)
            .unwrap()
            .with_workspace_home(&home)
            .with_plugin_control(auth.clone(), source.clone(), "owner-space")
            .unwrap();
        let store = Arc::new(PackageStore::open(trusted_tool_package_root(&db)).unwrap());
        let stage = |dir: &str, manifest: &str, files: &[(&str, &[u8])]| {
            let package = source.join(dir);
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
            for (name, body) in files {
                std::fs::write(package.join(name), body).unwrap();
            }
            let payload = store.signature_payload(&package).unwrap();
            std::fs::write(
                package.join("signature.ed25519"),
                pair.sign(&payload).as_ref(),
            )
            .unwrap();
            store.install(&package, &auth).unwrap();
        };
        stage(
            "package-phaselib",
            &leaf_manifest,
            &[("format.rss", leaf_body)],
        );
        for (dir, id) in [("package-phasea", TOOL_A_ID), ("package-phasec", TOOL_C_ID)] {
            stage(
                dir,
                &tool_manifest(id),
                &[
                    ("run.rss", tool_source.as_bytes()),
                    (
                        "catalog.rss",
                        include_bytes!("../../rss/tools/types.rss").as_slice(),
                    ),
                ],
            );
        }
        // A prepare/activation rejection must not leak the already-created
        // Service: shut it down first, then report the original cause.
        let (graph_a, generation_a) = match activate_tool_result(&state, TOOL_A_ID).await {
            Ok(activated) => activated,
            Err(error) => {
                let cleanup = state.service().shutdown().await;
                panic!("signed leaf fixture activation failed: {error} (shutdown: {cleanup:?})");
            }
        };
        SignedLeafChain {
            workspace,
            db,
            state,
            store,
            graph_a,
            generation_a,
        }
    }

    /// Existing 478/481 callers keep the phase-A tool source and the 900 s budget.
    async fn open_signed_leaf_chain(label: &str, leaf_body: &[u8]) -> SignedLeafChain {
        open_signed_leaf_chain_with(
            label,
            leaf_body,
            PHASE_A_RUN_SOURCE,
            std::time::Duration::from_secs(900),
        )
        .await
    }

    /// Dedicated 468 read-only tool body. It keeps the real managed
    /// prepare/commit contract but performs no filesystem IO: the audited pure
    /// leaf (`VALID_LEAF`, `"libA:" + value`) is applied to the known `path`
    /// call argument (`seed.txt`), and the resulting canonical read result is
    /// really committed. A bare pure return would stay
    /// `pinned_result_uncommitted`.
    const GUARD468_PURE_TOOL_SOURCE: &str = r#"use text::{format};
fn map_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}

fn map_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}

fn map_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}

pub fn run(context: map) -> map {
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_string(prepared, "kind", "") == "replay" => {
        map_map(prepared, "result")
    } else if map_bool(prepared, "ok", false) == false => {
        prepared
    } else => {
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let value: string = map_string(arguments, "path", "");
        let labeled: string = format(value);
        let result: map = { ok: true, content: labeled, data: {}, error: null, truncated: false, artifacts: [] };
        let committed: map = agent_runtime::tool_commit(token, result);
        if map_string(committed, "kind", "") == "committed" => {
            map_map(committed, "result")
        } else => {
            committed
        }
    }
}
"#;

    /// Activated signed-lock facts returned beside the state so the caller
    /// can independently compare them with the admitted pin before any Native
    /// final.
    pub(super) struct Guard468SignedReadGraph {
        pub(super) graph: String,
        pub(super) generation: u64,
        pub(super) lock: crate::plugins::GraphLock,
        pub(super) trust_ok: bool,
        pub(super) catalog_present: bool,
        pub(super) contract_present: bool,
    }

    /// Narrow reuse entry for the four read-only 468 rounds. It reuses this
    /// module's already-audited signed phase-A ToolOnly + pure-leaf fixture.
    /// Signing, install, resolve/prepare/activate all finish before the single
    /// admission; only the original 10 s budget is handed to the same helper, so
    /// no re-admission, clock reset or write approval is introduced.
    pub(super) async fn open_guard468_signed_read_chain(
        label: &str,
    ) -> (AgentGatewayState, Guard468SignedReadGraph) {
        let chain = open_signed_leaf_chain_with(
            label,
            VALID_LEAF,
            GUARD468_PURE_TOOL_SOURCE,
            std::time::Duration::from_secs(10),
        )
        .await;
        let persistence = chain
            .state
            .persistence()
            .expect("signed phase-A fixture persistence");
        let lock = crate::plugins::PluginControlStore::new(&persistence)
            .load_lock(&chain.graph_a)
            .expect("activated signed phase-A lock")
            .lock;
        let prepared = chain
            .store
            .prepare(&lock)
            .expect("prepared signed phase-A graph");
        let trust_ok =
            prepared.trust(TOOL_A_ID) == Some(crate::plugins::PackageTrust::AcceptedPublisher);
        let catalog_present = prepared.managed_policy_catalog(TOOL_A_ID).is_some();
        let contract_present = prepared.managed_contract(TOOL_A_ID).is_some();
        (
            chain.state,
            Guard468SignedReadGraph {
                graph: chain.graph_a,
                generation: chain.generation_a,
                lock,
                trust_ok,
                catalog_present,
                contract_present,
            },
        )
    }

    /// Independently compare the activated signed lock and the
    /// admitted pin/managed code before any Native final. The four test bodies
    /// stay unchanged; a mismatch is reported through the caller's first-failure
    /// cleanup path.
    pub(super) fn guard468_signed_pin_facts(
        pin: &crate::runtime::agent_host::PinnedToolProgram,
        binding: &crate::effects::broker::ManagedRunBinding,
        expected: &Guard468SignedReadGraph,
    ) -> Result<(), String> {
        use crate::plugins::HarnessSelection;
        let tool = expected
            .lock
            .packages
            .iter()
            .find(|package| package.id == TOOL_A_ID)
            .ok_or("activated signed graph must contain the phase-A tool package")?;
        if expected.lock.graph_id != expected.graph {
            return Err("activated signed lock must be the sealed graph".into());
        }
        if expected.lock.harness_selection
            != (HarnessSelection::ToolOnly {
                tool_package: TOOL_A_ID.into(),
            })
        {
            return Err("activated signed graph must select ToolOnly phase A".into());
        }
        if expected.lock.packages.len() != 2
            || tool.kind != "tool"
            || !expected
                .lock
                .packages
                .iter()
                .any(|package| package.id == LEAF_ID && package.kind == "library")
        {
            return Err("activated signed graph must be exactly phase-A tool plus one leaf".into());
        }
        if !expected.trust_ok || !expected.catalog_present || !expected.contract_present {
            return Err(
                "activated phase-A graph must be AcceptedPublisher with managed catalog/contract"
                    .into(),
            );
        }
        if !expected.lock.closure.iter().any(|row| {
            row.package == TOOL_A_ID
                && row.entry == "run"
                && row.effects.iter().any(|effect| {
                    effect.kind == "workspace.fs.read" && effect.scope == "bound_workspace"
                })
        }) {
            return Err(
                "activated phase-A catalog must declare workspace.fs.read/bound_workspace".into(),
            );
        }
        if !matches!(
            &pin.harness_selection,
            HarnessSelection::ToolOnly { tool_package }
                if tool_package.as_str() == TOOL_A_ID
        ) {
            return Err("admitted pin must select ToolOnly phase A".into());
        }
        if pin.graph_id != expected.graph
            || pin.package_id != TOOL_A_ID
            || pin.artifact_id != tool.artifact_id
            || pin.state.is_some()
        {
            return Err("admitted pin must be the stateless activated phase-A tool package".into());
        }
        if binding.code.graph_id != expected.graph
            || binding.code.activation_generation != expected.generation
            || binding.code.package_id != TOOL_A_ID
            || binding.code.artifact_id != tool.artifact_id
            || binding.code.export != "run"
        {
            return Err(
                "admitted managed code must match the activated phase-A graph/generation/package/artifact/export"
                    .into(),
            );
        }
        Ok(())
    }

    /// The known 468 `path` argument (`seed.txt`) formatted by this
    /// module's audited `VALID_LEAF` (`pub fn format(value) -> "libA:" + value`).
    /// The expectation is derived from these two known inputs only, never copied
    /// from the final managed record.
    pub(super) const GUARD468_EXPECTED_CONTENT: &str = "libA:seed.txt";

    struct SignedLeafReplayProvider {
        persistence: Arc<crate::GatewayPersistence>,
        store: Arc<PackageStore>,
        service: std::sync::Weak<crate::AgentService>,
        run_id: std::sync::Mutex<String>,
        graph: String,
        call_id: String,
        path: String,
        step: AtomicUsize,
        replayed: std::sync::Mutex<Option<Value>>,
        refused: std::sync::Mutex<Option<Value>>,
        revoked: std::sync::Mutex<Option<String>>,
        receipt_before: std::sync::Mutex<Option<Value>>,
        receipt_after: std::sync::Mutex<Option<Value>>,
        live: AtomicBool,
        shared_clock: AtomicBool,
    }

    impl crate::AgentProviderHost for SignedLeafReplayProvider {
        fn call(&self, _request: &Value, cancellation: &crate::RunCancellation) -> Value {
            if self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return json!({"ok":true,"response":response(Some(json!({"id":self.call_id,"name":"read_file","arguments":{"path":self.path}}))),"error":{}});
            }
            let service = self.service.upgrade().unwrap();
            let run_id = self.run_id.lock().unwrap().clone();
            // The replay must run against the original live run/capability,
            // not a reconstructed run.
            self.live.store(
                !service.handle(&run_id).unwrap().is_terminal(),
                Ordering::SeqCst,
            );
            let pin = service
                .handle(&run_id)
                .unwrap()
                .pinned_tool
                .clone()
                .expect("the admitted run must carry the sealed signed tool pin");
            let binding = pin.managed.as_ref().unwrap();
            assert_eq!(
                binding.code.graph_id, self.graph,
                "the live pin must be the exact activated signed graph A"
            );
            let owner = binding.owner.clone();
            let request = ManagedEffectGetRequest {
                owner,
                call_id: self.call_id.clone(),
            };
            let before = self
                .persistence
                .managed_effect_get(&request)
                .unwrap()
                .expect("the first actual call must have a durable receipt");
            *self.receipt_before.lock().unwrap() = Some(serde_json::to_value(&before).unwrap());
            let ManagedArgumentIdentity::Inline {
                canonical_arguments,
            } = &before.identity.argument_identity
            else {
                panic!("small fixture arguments should remain inline");
            };
            let canonical = canonical_arguments.clone();
            let mut host = service.capability_host_bridges(&run_id).unwrap().unwrap();
            // The bridge must reference the run's original absolute deadline
            // instead of creating another clock root.
            self.shared_clock.store(
                host.cancellation.as_ref().unwrap().deadline_instant()
                    == cancellation.deadline_instant(),
                Ordering::SeqCst,
            );
            host.pinned_tool = Some(pin);
            let wire = json!({
                "tool_name":"read_file",
                "call_id":self.call_id,
                "canonical_arguments":canonical,
                "canonical_input":"",
                "run_id":run_id,
                "registry_identity":host.lifecycle.as_ref().unwrap().registry_identity(),
                "argument_digest":canonical,
                "risk_class":"read",
                "summary":"exact signed leaf replay of the committed call",
                "untrusted_graph_id":""
            });
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
                agent_runtime::invoke_pinned_tool({tool_name:context["tool_name"],call_id:context["call_id"],canonical_arguments:context["canonical_arguments"],canonical_input:context["canonical_input"],run_id:context["run_id"],registry_identity:context["registry_identity"],argument_digest:context["argument_digest"],risk_class:context["risk_class"],summary:context["summary"],untrusted_graph_id:context["untrusted_graph_id"]})
            }"#;
            let replay = {
                let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
                    .unwrap()
                    .with_host(host.clone());
                native_json(&runner.run_with_context(input.clone()).unwrap())
            };
            *self.replayed.lock().unwrap() = Some(replay);
            let after = self
                .persistence
                .managed_effect_get(&request)
                .unwrap()
                .expect("the original receipt must stay durable after the replay");
            *self.receipt_after.lock().unwrap() = Some(serde_json::to_value(&after).unwrap());
            // Same durable control store that admitted the pin: revoke the
            // exact graph A, then re-invoke through the original binding
            // bridge of the still-live run.
            PluginControlStore::new(&self.persistence)
                .revoke_graph(&self.store, &self.graph)
                .expect("the signed tool + pure leaf topology must revoke");
            assert!(
                PluginControlStore::new(&self.persistence)
                    .graph_revocation(&self.graph)
                    .unwrap()
                    .is_some(),
                "the revocation must be durably visible before the second invoke"
            );
            *self.revoked.lock().unwrap() = Some(self.graph.clone());
            let refused = {
                let runner = crate::AgentRunner::from_source(source, crate::AgentConfig::default())
                    .unwrap()
                    .with_host(host);
                native_json(&runner.run_with_context(input).unwrap())
            };
            *self.refused.lock().unwrap() = Some(refused);
            json!({"ok":true,"response":response(None),"error":{}})
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_leaf_a_native_replay_then_same_store_revoke_refuses_and_history_holds() {
        let chain = open_signed_leaf_chain("replay", VALID_LEAF).await;
        let service = chain.state.service();
        std::fs::write(chain.workspace.join("note.txt"), b"hello").unwrap();
        let call_id = "read-lib-a";
        let provider = Arc::new(SignedLeafReplayProvider {
            persistence: chain.state.persistence().unwrap(),
            store: Arc::clone(&chain.store),
            service: Arc::downgrade(&service),
            run_id: std::sync::Mutex::new(String::new()),
            graph: chain.graph_a.clone(),
            call_id: call_id.into(),
            path: "note.txt".into(),
            step: AtomicUsize::new(0),
            replayed: std::sync::Mutex::new(None),
            refused: std::sync::Mutex::new(None),
            revoked: std::sync::Mutex::new(None),
            receipt_before: std::sync::Mutex::new(None),
            receipt_after: std::sync::Mutex::new(None),
            live: AtomicBool::new(false),
            shared_clock: AtomicBool::new(false),
        });
        service.inject_provider_host(provider.clone());
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"read once through the signed leaf, then replay the exact call"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        {
            let pinned = service
                .handle(&run.run_id)
                .unwrap()
                .pinned_tool
                .clone()
                .unwrap();
            let binding = pinned.managed.as_ref().expect("the run must be managed");
            assert_eq!(binding.code.graph_id, chain.graph_a);
            assert_eq!(binding.code.activation_generation, chain.generation_a);
        }
        *provider.run_id.lock().unwrap() = run.run_id.clone();
        service
            .clone()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;

        let events = service.run_events(&run.run_id);
        println!(
            "478 signed leaf replay evidence: graph={} generation={} events={events:?}",
            chain.graph_a, chain.generation_a
        );
        assert!(
            provider.live.load(Ordering::SeqCst),
            "the Native replay must run while the original run is live"
        );
        assert!(
            provider.shared_clock.load(Ordering::SeqCst),
            "the Native bridge must reference the run's original deadline"
        );
        assert_eq!(
            provider.revoked.lock().unwrap().clone().as_deref(),
            Some(chain.graph_a.as_str()),
            "the fixture must revoke the exact admitted graph A"
        );

        // First actual call: one committed read-only receipt through the leaf.
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event["event"] == "tool.completed" && event["data"]["tool_call_id"] == call_id
                })
                .count(),
            1,
            "the first actual call must commit exactly one tool result: {events:?}"
        );

        let before = provider
            .receipt_before
            .lock()
            .unwrap()
            .clone()
            .expect("durable receipt before the replay");
        let after = provider
            .receipt_after
            .lock()
            .unwrap()
            .clone()
            .expect("durable receipt after the replay");
        // The durable final receipt carries the original graph A, run and
        // effect identity.
        assert_eq!(before["identity"]["code"]["graph_id"], json!(chain.graph_a));
        assert_eq!(
            before["identity"]["code"]["activation_generation"],
            json!(chain.generation_a)
        );
        assert_eq!(
            before["identity"]["owner"]["run_id"],
            json!(run.run_id.clone())
        );
        assert_eq!(before["identity"]["call_id"], json!(call_id));
        assert_eq!(before["state"], json!("read_only"));
        assert!(
            before["effect_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "the receipt must carry the original effect id: {before}"
        );

        // Positive unrevoked replay: exact original canonical, no second
        // effect or completion.
        let replay = provider
            .replayed
            .lock()
            .unwrap()
            .clone()
            .expect("the real Native replay must produce an envelope");
        println!("478 signed leaf native replay envelope: {replay}");
        assert_eq!(replay["ok"], json!(true), "replay must succeed: {replay}");
        assert_eq!(replay["kind"], json!("replay"), "{replay}");
        assert!(
            replay["content"]
                .as_str()
                .unwrap_or("")
                .contains("libA:hello"),
            "the replay must return the original leaf-labeled canonical bytes: {replay}"
        );
        assert_eq!(
            before["effect_id"], after["effect_id"],
            "the replay must not create a second effect record"
        );
        assert_eq!(
            before["outcome"], after["outcome"],
            "the replay must not commit a second outcome"
        );

        let request = effect_request(&run, call_id);
        let ManagedCallReplay::Final {
            canonical_result, ..
        } = service.replay_managed_call(request.clone()).unwrap()
        else {
            panic!("the original read-only receipt must stay final");
        };
        assert_eq!(
            replay["canonical_result"].as_str().unwrap(),
            canonical_result.as_str(),
            "the Native replay must return the exact durable canonical result"
        );
        let canonical: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(canonical["ok"], json!(true));
        assert_eq!(canonical["content"], json!("libA:hello"));

        // Exact same-control-store revocation: the original binding bridge
        // must refuse the execution replay with the typed code only.
        let refused = provider
            .refused
            .lock()
            .unwrap()
            .clone()
            .expect("the revoked Native invoke must produce an envelope");
        println!("478 signed leaf revoked native invoke envelope: {refused}");
        assert_eq!(refused["ok"], json!(false), "{refused}");
        assert_eq!(
            refused["code"],
            json!("plugin_graph_revoked"),
            "the refused invoke must carry the exact typed revocation: {refused}"
        );
        assert!(
            refused["canonical_result"]
                .as_str()
                .unwrap_or("")
                .is_empty(),
            "the refused invoke must not leak the canonical success: {refused}"
        );
        assert_eq!(
            service
                .run_events(&run.run_id)
                .iter()
                .filter(|event| {
                    event["event"] == "tool.completed" && event["data"]["tool_call_id"] == call_id
                })
                .count(),
            1,
            "the refused replay must not commit a second result"
        );

        // History stays the complete original read-only final.
        let ManagedCallReplay::Final {
            canonical_result, ..
        } = service.replay_managed_call(request.clone()).unwrap()
        else {
            panic!("history must keep the original final after the revocation");
        };
        let history: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(history["ok"], json!(true));
        assert_eq!(history["content"], json!("libA:hello"));
        let record = chain
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert_eq!(record.state, ManagedPublicationStatus::ReadOnly);
        assert_eq!(
            record.outcome.as_ref().unwrap().disposition,
            ManagedPublicationStatus::ReadOnly
        );

        // The shared pure leaf stays valid for another signed tool after A is
        // revoked: activate tool C on the same leaf package. Every remaining
        // fallible fixture step is collected so the owned Service is shut down
        // before these assertions and the first cause survives.
        // 共享 pure leaf 一次真实读取回归的 6 项证据；顺序与下面的解构一致：
        // run_id、generation_c、graph_c、pinned_graph、canonical final、
        // workspace bytes。别名只命名既有事实，不改变任何取值或校验。
        type SharedLeafEvidence = (String, u64, String, String, Value, Vec<u8>);
        let shared_leaf: Result<SharedLeafEvidence, String> = async {
            let (graph_c, generation_c) = activate_tool_result(&chain.state, TOOL_C_ID).await?;
            let read_c = Arc::new(crate::ScriptedProvider::new());
            read_c.push_ok(response(Some(json!({"id":"read-lib-c","name":"read_file","arguments":{"path":"note.txt"}}))));
            read_c.push_ok(response(None));
            service.inject_provider_host(read_c);
            let run_c = service
                .admit_external_with_workspace_selector(
                    AdmitRunRequest {
                        input: json!({"message":"read through the shared pure leaf after A revoked"}),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .map_err(|error| format!("shared leaf admit: {error:?}"))?;
            let pinned_graph = service
                .handle(&run_c.run_id)
                .and_then(|handle| handle.pinned_tool.clone())
                .and_then(|pin| pin.managed.as_ref().map(|binding| binding.code.graph_id.clone()))
                .ok_or_else(|| "the shared leaf run has no sealed managed pin".to_string())?;
            service
                .clone()
                .run_worker(run_c.run_id.clone(), "ignored".into())
                .await;
            let shared = match service
                .replay_managed_call(effect_request(&run_c, "read-lib-c"))
                .map_err(|error| format!("shared leaf replay: {error}"))?
            {
                ManagedCallReplay::Final {
                    canonical_result, ..
                } => serde_json::from_str::<Value>(canonical_result.as_str())
                    .map_err(|error| format!("shared leaf canonical json: {error}"))?,
                other => {
                    return Err(format!(
                        "the shared leaf read must commit a final receipt: {other:?}"
                    ));
                }
            };
            let bytes = std::fs::read(chain.workspace.join("note.txt"))
                .map_err(|error| format!("workspace read after the shared leaf run: {error}"))?;
            Ok((
                run_c.run_id.clone(),
                generation_c,
                graph_c,
                pinned_graph,
                shared,
                bytes,
            ))
        }
        .await;

        // Cleanup always runs; then the first cause, then cleanup facts.
        let cleanup = service.shutdown().await;
        let (shared_run_id, generation_c, graph_c, pinned_graph, shared, workspace_bytes) =
            match shared_leaf {
                Ok(evidence) => evidence,
                Err(error) => {
                    panic!("shared leaf regression failed: {error} (shutdown: {cleanup:?})")
                }
            };
        assert!(generation_c > chain.generation_a);
        assert_eq!(
            pinned_graph, graph_c,
            "the shared leaf run must pin the newly activated graph C"
        );
        assert_eq!(shared["content"], json!("libA:hello"));
        assert_eq!(
            workspace_bytes, b"hello",
            "the signed read must not mutate the served workspace bytes"
        );
        assert!(
            cleanup.is_ok(),
            "the owned service must shut down: {cleanup:?}"
        );
        for run_id in [&run.run_id, &shared_run_id] {
            assert_eq!(
                service
                    .handle(run_id)
                    .and_then(|handle| { *handle.cleanup_outcome.lock().unwrap() }),
                Some(crate::CleanupOutcome::Clean),
                "run {run_id} must retain a Clean capability-host cleanup outcome"
            );
            assert!(
                service.capability_host_closed(run_id),
                "run {run_id} must leave a closed capability host"
            );
            assert!(
                !service.capability_host_retained(run_id),
                "run {run_id} must not retain capability host state"
            );
            assert_eq!(
                service.process_owner_count(run_id),
                0,
                "run {run_id} must leave no live process owner"
            );
            assert!(
                service
                    .capability_host_bridges(run_id)
                    .ok()
                    .flatten()
                    .is_none(),
                "run {run_id} must not expose a usable capability host bridge/token"
            );
        }
        let _ = &chain.db;
    }

    /// Defensive bounded poll budget for one pure invocation: the leaf performs
    /// no host operation, so a Pending poll must never be the steady state.
    const PURE_INVOCATION_POLLS: usize = 1_000;

    #[derive(Debug)]
    enum LeafInvocation {
        Complete(rustscript_vm::Value),
        Typed(rustscript_vm::InvocationError),
    }

    /// Test-only probe of an already compiled pure leaf program: it evaluates
    /// the capture-time program on the real VM with the capture-time registry
    /// and keeps the VM's own typed invocation error instead of collapsing it
    /// into a string. No production seam is added for it.
    fn invoke_compiled_pure_leaf(
        program: &Arc<rustscript_vm::Program>,
        registry: &Arc<rustscript_vm::HostFunctionRegistry>,
        entry: &str,
        input: rustscript_vm::Value,
    ) -> Result<LeafInvocation, String> {
        let mut vm = rustscript_vm::Vm::try_new(program.as_ref().clone())
            .map_err(|error| format!("leaf vm init: {error}"))?;
        registry
            .bind_vm_cached(&mut vm)
            .map_err(|error| format!("leaf registry bind: {error}"))?;
        vm.set_fuel(10_000_000);
        match vm.run() {
            Ok(rustscript_vm::VmStatus::Halted) => {}
            other => return Err(format!("leaf root frame did not halt: {other:?}")),
        }
        let callable = vm
            .resolve_exported_callable(entry)
            .map_err(|error| format!("leaf export `{entry}`: {error}"))?;
        let mut invocation = vm
            .start_invocation(callable, vec![input])
            .map_err(|error| format!("leaf invocation start: {error}"))?;
        for _ in 0..PURE_INVOCATION_POLLS {
            match invocation
                .poll_next()
                .map_err(|error| format!("leaf invocation poll: {error}"))?
            {
                rustscript_vm::InvocationPoll::Pending => continue,
                rustscript_vm::InvocationPoll::Ready(Some(Ok(
                    rustscript_vm::InvocationItem::Complete(value),
                ))) => return Ok(LeafInvocation::Complete(value)),
                rustscript_vm::InvocationPoll::Ready(Some(Ok(
                    rustscript_vm::InvocationItem::Event(_),
                ))) => continue,
                rustscript_vm::InvocationPoll::Ready(Some(Err(error))) => {
                    return Ok(LeafInvocation::Typed(error));
                }
                rustscript_vm::InvocationPoll::Ready(None) => {
                    return Err("leaf invocation ended without a result".to_string());
                }
            }
        }
        Err("leaf invocation did not settle within the bounded poll budget".to_string())
    }

    struct PreparedLeafProbe {
        entry: String,
        control: Result<LeafInvocation, String>,
        failing: Result<LeafInvocation, String>,
    }

    /// Provenance: the exact `PreparedGraph` artifact the formal
    /// resolve → prepare path produced for this signed store. The probe never
    /// recompiles a re-typed copy of the fixture body, so the typed observation
    /// is about the same pure leaf program the Service later invokes.
    fn prepared_leaf_probe(chain: &SignedLeafChain) -> Result<PreparedLeafProbe, String> {
        let lock = chain
            .store
            .resolve(&crate::plugins::ResolveRequest {
                harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: TOOL_A_ID.into(),
                },
                roots: vec![crate::plugins::PackageRequirement {
                    id: TOOL_A_ID.into(),
                    version: "1.0.0".into(),
                }],
                host_runtime: crate::plugins::HOST_RUNTIME.into(),
            })
            .map_err(|error| format!("typed probe resolve: {error:?}"))?;
        let prepared = chain
            .store
            .prepare(&lock)
            .map_err(|error| format!("typed probe prepare: {error:?}"))?;
        let program = prepared
            .program(LEAF_ID)
            .ok_or_else(|| "typed probe: prepared leaf program missing".to_string())?;
        let registry = prepared
            .registry(LEAF_ID)
            .ok_or_else(|| "typed probe: prepared leaf registry missing".to_string())?
            .map_err(|error| format!("typed probe: prepared leaf registry unusable: {error}"))?;
        let entry = prepared
            .entry_callable(LEAF_ID)
            .ok_or_else(|| "typed probe: prepared leaf entry callable missing".to_string())?
            .to_string();
        let control = invoke_compiled_pure_leaf(
            &program,
            &registry,
            &entry,
            rustscript_vm::Value::string("hi"),
        );
        let failing = invoke_compiled_pure_leaf(
            &program,
            &registry,
            &entry,
            rustscript_vm::Value::string("hello"),
        );
        Ok(PreparedLeafProbe {
            entry,
            control,
            failing,
        })
    }

    /// Sealed managed pin of an admitted run: (graph id, activation generation).
    fn sealed_pin(service: &crate::AgentService, run_id: &str) -> Option<(String, u64)> {
        service
            .handle(run_id)
            .and_then(|handle| handle.pinned_tool.clone())
            .and_then(|pin| {
                pin.managed.as_ref().map(|binding| {
                    (
                        binding.code.graph_id.clone(),
                        binding.code.activation_generation,
                    )
                })
            })
    }

    struct LeafFailureObservations {
        run_id: String,
        control_canonical: Value,
        control_graph: String,
        failing_graph: String,
        failing_generation: u64,
        events: Vec<Value>,
        record: Option<crate::effects::ManagedEffectRecord>,
        first_replay: ManagedCallReplay,
        second_replay: ManagedCallReplay,
    }

    struct LeafCleanupFacts {
        cleanup_outcome: Option<crate::CleanupOutcome>,
        host_closed: bool,
        host_retained: bool,
        process_owners: usize,
        bridges_gone: bool,
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_pure_leaf_runtime_failure_is_bounded_and_leaves_no_success_receipt() {
        let chain = open_signed_leaf_chain("leaf-fail", FAILING_LEAF).await;
        let service = chain.state.service();
        std::fs::write(chain.workspace.join("note.txt"), b"hello").unwrap();
        std::fs::write(chain.workspace.join("short.txt"), b"hi").unwrap();

        // Typed program proof. It executes before the first Service call; its
        // assertion is deferred so the owned Service is always cleaned up.
        let typed = prepared_leaf_probe(&chain);
        let mut failing_run_id: Option<String> = None;
        let observed: Result<LeafFailureObservations, String> = {
            let service = service.clone();
            let persistence = chain.state.persistence();
            let failing_run_id = &mut failing_run_id;
            async move {
                // Control: the same signed tool/leaf graph with a real
                // non-failing value (length 2), so the fixture itself is sound.
                let control = Arc::new(crate::ScriptedProvider::new());
                control.push_ok(response(Some(json!({"id":"read-short","name":"read_file","arguments":{"path":"short.txt"}}))));
                control.push_ok(response(None));
                service.inject_provider_host(control);
                let run_ok = service
                    .admit_external_with_workspace_selector(
                        AdmitRunRequest {
                            input: json!({"message":"read the short file through the approved pure leaf"}),
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                    .map_err(|error| format!("control admit: {error:?}"))?;
                let (control_graph, _) = sealed_pin(&service, &run_ok.run_id)
                    .ok_or_else(|| "the control run has no sealed managed pin".to_string())?;
                service
                    .clone()
                    .run_worker(run_ok.run_id.clone(), "ignored".into())
                    .await;
                let control_canonical = match service
                    .replay_managed_call(effect_request(&run_ok, "read-short"))
                    .map_err(|error| format!("control replay: {error}"))?
                {
                    ManagedCallReplay::Final {
                        canonical_result, ..
                    } => serde_json::from_str::<Value>(canonical_result.as_str())
                        .map_err(|error| format!("control canonical json: {error}"))?,
                    other => {
                        return Err(format!(
                            "the control call must commit a final receipt: {other:?}"
                        ));
                    }
                };

                // The same graph/tool/read path with the real value whose
                // length makes the approved pure export hit checked division.
                let failing = Arc::new(crate::ScriptedProvider::new());
                failing.push_ok(response(Some(json!({"id":"read-fail","name":"read_file","arguments":{"path":"note.txt"}}))));
                failing.push_ok(response(None));
                service.inject_provider_host(failing);
                let run = service
                    .admit_external_with_workspace_selector(
                        AdmitRunRequest {
                            input: json!({"message":"read the failing value through the approved pure leaf"}),
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                    .map_err(|error| format!("failing admit: {error:?}"))?;
                *failing_run_id = Some(run.run_id.clone());
                let (failing_graph, failing_generation) = sealed_pin(&service, &run.run_id)
                    .ok_or_else(|| "the failing run has no sealed managed pin".to_string())?;
                service
                    .clone()
                    .run_worker(run.run_id.clone(), "ignored".into())
                    .await;
                let events = service.run_events(&run.run_id);
                let request = effect_request(&run, "read-fail");
                let record = persistence
                    .as_ref()
                    .ok_or_else(|| "fixture persistence unavailable".to_string())?
                    .managed_effect_get(&request)
                    .map_err(|error| format!("failing record read: {error}"))?;
                let first_replay = service
                    .replay_managed_call(request.clone())
                    .map_err(|error| format!("failing replay 1: {error}"))?;
                let second_replay = service
                    .replay_managed_call(request)
                    .map_err(|error| format!("failing replay 2: {error}"))?;
                Ok(LeafFailureObservations {
                    run_id: run.run_id.clone(),
                    control_canonical,
                    control_graph,
                    failing_graph,
                    failing_generation,
                    events,
                    record,
                    first_replay,
                    second_replay,
                })
            }
        }
        .await;

        // Cleanup always runs: both worker futures returned, this test installs
        // no observer hook of its own, and shutdown closes every capability
        // host and joins the janitor/storage owners.
        let cleanup = service.shutdown().await;
        let cleanup_facts = failing_run_id.as_ref().map(|run_id| LeafCleanupFacts {
            cleanup_outcome: service
                .handle(run_id)
                .and_then(|handle| *handle.cleanup_outcome.lock().unwrap()),
            host_closed: service.capability_host_closed(run_id),
            host_retained: service.capability_host_retained(run_id),
            process_owners: service.process_owner_count(run_id),
            bridges_gone: service
                .capability_host_bridges(run_id)
                .ok()
                .flatten()
                .is_none(),
        });

        // First cause, then the collected evidence, then the cleanup facts.
        let probe = match typed {
            Ok(probe) => probe,
            Err(error) => {
                panic!("prepared pure leaf typed probe failed: {error} (shutdown: {cleanup:?})")
            }
        };
        let observed = match observed {
            Ok(observed) => observed,
            Err(error) => {
                panic!("pure leaf service evidence failed: {error} (shutdown: {cleanup:?})")
            }
        };

        // 1. Typed proof on the same prepared pure leaf program.
        assert_eq!(
            probe.entry, "format",
            "the prepared leaf entry callable must be the declared export"
        );
        match probe.control {
            Ok(LeafInvocation::Complete(value)) => assert_eq!(
                value,
                rustscript_vm::Value::string("libF:hi"),
                "the same prepared program must return libF:hi for the short control"
            ),
            other => panic!(
                "the non-failing control must complete on the prepared leaf program: {other:?}"
            ),
        }
        match probe.failing {
            Ok(LeafInvocation::Typed(rustscript_vm::InvocationError::Vm(
                rustscript_vm::VmError::DivisionByZero,
            ))) => {}
            other => panic!(
                "the prepared leaf must fail with the typed \
                 InvocationError::Vm(VmError::DivisionByZero): {other:?}"
            ),
        }

        // 2. The real Service path on the same signed graph A.
        let call_id = "read-fail";
        assert_eq!(
            observed.control_graph, chain.graph_a,
            "the short control must run the same signed graph A"
        );
        assert_eq!(
            observed.failing_graph, chain.graph_a,
            "the failing call must run the same signed graph A"
        );
        assert_eq!(
            observed.control_canonical["ok"],
            json!(true),
            "the control call must succeed: {}",
            observed.control_canonical
        );
        assert_eq!(
            observed.control_canonical["content"],
            json!("libF:hi"),
            "the control call must return the leaf-labeled short bytes: {}",
            observed.control_canonical
        );

        let started: Vec<&Value> = observed
            .events
            .iter()
            .filter(|event| event["event"] == "tool.started")
            .collect();
        assert_eq!(
            started.len(),
            1,
            "the failing call must produce exactly one real tool.started: {:?}",
            observed.events
        );
        assert_eq!(
            started[0]["run_id"],
            json!(observed.run_id),
            "tool.started must belong to the observed run: {:?}",
            started[0]
        );
        assert_eq!(
            started[0]["data"]["tool_call_id"],
            json!(call_id),
            "tool.started must carry the exact failing call id: {:?}",
            started[0]
        );
        assert_eq!(
            started[0]["data"]["generation"],
            json!(observed.failing_generation),
            "tool.started must carry the sealed activation generation of graph A: {:?}",
            started[0]
        );
        assert_eq!(
            observed
                .events
                .iter()
                .filter(|event| event["event"] == "tool.completed"
                    && event["data"]["tool_call_id"] == json!(call_id))
                .count(),
            0,
            "a failed pure export must not report a completed tool call: {:?}",
            observed.events
        );
        let terminals: Vec<&Value> = observed
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event["event"].as_str(),
                    Some("run.completed") | Some("run.failed") | Some("run.cancelled")
                )
            })
            .collect();
        assert_eq!(
            terminals.len(),
            1,
            "the failed run must surface exactly one terminal run event: {:?}",
            observed.events
        );
        let terminal = terminals[0];
        assert_eq!(
            terminal["event"], "run.failed",
            "a bounded Native runtime failure must fail the run: {terminal}"
        );
        assert_eq!(
            terminal["run_id"],
            json!(observed.run_id),
            "the terminal event must belong to the observed run: {terminal}"
        );
        assert_eq!(
            terminal["data"]["error_code"],
            json!("agent_failed"),
            "the bounded failure must keep the existing run failure classification: {terminal}"
        );
        assert!(
            terminal["data"]["error_message"]
                .as_str()
                .unwrap_or_default()
                .contains("division by zero"),
            "the failure must carry the actual bounded VM message: {terminal}"
        );
        assert!(
            !serde_json::to_string(&observed.events)
                .unwrap_or_default()
                .contains("libF:hello"),
            "no success canonical may appear in the failed run events: {:?}",
            observed.events
        );

        // 3. Tight record oracle: the begun (never prepared) managed call.
        let record = observed
            .record
            .as_ref()
            .expect("the begun managed call must keep a durable receipt");
        assert_eq!(
            record.state,
            ManagedPublicationStatus::Indeterminate,
            "an interrupted managed call must be recorded as Indeterminate"
        );
        assert!(
            record.prepared.is_none(),
            "the failing call never reached a prepared observation"
        );
        assert!(
            record.outcome.is_none(),
            "the failing call must not carry a committed outcome"
        );
        assert_eq!(
            record.identity.code.graph_id, observed.failing_graph,
            "the receipt must carry the exact signed graph A"
        );
        assert_eq!(
            record.identity.owner.run_id, observed.run_id,
            "the receipt must carry the exact failing run"
        );
        assert_eq!(
            record.identity.call_id, call_id,
            "the receipt must carry the exact failing call"
        );
        match (&observed.first_replay, &observed.second_replay) {
            (
                ManagedCallReplay::Indeterminate { record: first },
                ManagedCallReplay::Indeterminate { record: second },
            ) => {
                assert_eq!(
                    first.as_ref(),
                    record,
                    "the replay must return the exact durable record"
                );
                assert_eq!(
                    first.as_ref(),
                    second.as_ref(),
                    "the exact Indeterminate replay must be repeatable"
                );
            }
            (first, second) => panic!(
                "the interrupted call must stay exactly Indeterminate, got {first:?} / {second:?}"
            ),
        }

        // 4. The served workspace bytes are unchanged by both reads.
        assert_eq!(
            std::fs::read(chain.workspace.join("note.txt")).unwrap(),
            b"hello",
            "the failed read must not mutate the served workspace bytes"
        );
        assert_eq!(
            std::fs::read(chain.workspace.join("short.txt")).unwrap(),
            b"hi",
            "the control read must not mutate the served workspace bytes"
        );

        // 5. Bounded cleanup facts of the already-shut-down owned Service.
        assert!(
            cleanup.is_ok(),
            "the owned service must shut down: {cleanup:?}"
        );
        let facts = cleanup_facts.expect("the failing run must stay queryable for cleanup facts");
        assert_eq!(
            facts.cleanup_outcome,
            Some(crate::CleanupOutcome::Clean),
            "the failed run must record a Clean capability-host cleanup outcome"
        );
        assert!(
            facts.host_closed,
            "the failed run must leave a closed capability host"
        );
        assert!(
            !facts.host_retained,
            "the failed run must not retain capability host state"
        );
        assert_eq!(
            facts.process_owners, 0,
            "the failed run must leave no live process owner"
        );
        assert!(
            facts.bridges_gone,
            "the failed run must expose no usable capability host bridge/token"
        );
        let _ = &chain.db;
    }

    // ============================================================================
    // 485: the original admission deadline driven into a retained child VM after
    // a delayed entry. Layer proof only: it reuses the signed ToolOnly fixture
    // and the production `invoke_retained_tool`; it claims no full Service run,
    // no durable effect receipt and no run terminal.
    // ============================================================================

    /// Clock-only library body. The short control (`length <= 2`) returns at
    /// once; a longer input enters an ordinary `while true { }` pure CPU loop
    /// that cannot finish inside the child window. The constant loop is chosen
    /// before the first execution: it performs no arithmetic on the input
    /// length, so the long leg does not rest on an unwitnessed counted-loop
    /// bound or on an unused counter being kept alive. The RSS compiler already
    /// accepts `while true { }` in the captured-pure fixture.
    const CLOCK_LEAF: &[u8] = b"pub fn format(value: string) -> string {\n    let mut out: string = \"libC:\" + value;\n    if value.length > 2 {\n        while true { }\n    }\n    out\n}\n";

    /// Clock-only tool body: the same manifest/permissions as phase A, but the
    /// only host interaction is the pure `agent::control_check()` executed
    /// immediately before the pure leaf call. No prepare/commit, no I/O, no
    /// capability token, and nothing after the marker but the leaf call.
    const CLOCK_TOOL_SOURCE: &str = r#"use agent;
use text::{format};
fn map_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}

fn map_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}

pub fn run(context: map) -> map {
    let arguments: map = map_map(context, "arguments");
    let value: string = map_string(arguments, "value", "");
    let control: map = agent::control_check();
    let labeled: string = format(value);
    { ok: true, content: labeled, control: control }
}
"#;

    struct ClockRetainedTool {
        program: Arc<rustscript_vm::Program>,
        registry: Result<Arc<rustscript_vm::HostFunctionRegistry>, String>,
        entry: String,
    }

    /// Compiled linked tool program/registry/entry from the same signed store
    /// the Service activated. Called before admission so no compilation work
    /// shares the timed window.
    fn prepared_clock_tool(chain: &SignedLeafChain) -> Result<ClockRetainedTool, String> {
        let lock = chain
            .store
            .resolve(&crate::plugins::ResolveRequest {
                harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: TOOL_A_ID.into(),
                },
                roots: vec![crate::plugins::PackageRequirement {
                    id: TOOL_A_ID.into(),
                    version: "1.0.0".into(),
                }],
                host_runtime: crate::plugins::HOST_RUNTIME.into(),
            })
            .map_err(|error| format!("clock retained tool resolve: {error:?}"))?;
        let prepared = chain
            .store
            .prepare(&lock)
            .map_err(|error| format!("clock retained tool prepare: {error:?}"))?;
        let program = prepared
            .program(TOOL_A_ID)
            .ok_or_else(|| "clock retained tool program missing".to_string())?;
        let registry = prepared
            .registry(TOOL_A_ID)
            .ok_or_else(|| "clock retained tool registry missing".to_string())?;
        let entry = prepared
            .entry_callable(TOOL_A_ID)
            .ok_or_else(|| "clock retained tool entry callable missing".to_string())?
            .to_string();
        Ok(ClockRetainedTool {
            program,
            registry,
            entry,
        })
    }

    /// One observation of the child clock at the `agent::control_check()` marker.
    #[derive(Clone)]
    struct ClockRow {
        tag: &'static str,
        at: std::time::Instant,
        deadline: Option<std::time::Instant>,
        shares: bool,
        same_root: bool,
        armed: bool,
        child: crate::runtime::rss_runner::RunCancellation,
    }

    /// Recording-only control hook. It never sleeps, never requests cancellation
    /// and never fabricates a clock: it only snapshots the live child.
    fn clock_bridges(
        original: &crate::runtime::rss_runner::RunCancellation,
        tag: &'static str,
        rows: Arc<std::sync::Mutex<Vec<ClockRow>>>,
    ) -> crate::runtime::agent_host::AgentHostBridges {
        let original = original.clone();
        let mut bridges = crate::runtime::agent_host::AgentHostBridges::default();
        let hook: crate::runtime::agent_host::ControlCheckHook =
            Arc::new(move |child: &crate::runtime::rss_runner::RunCancellation| {
                rows.lock().unwrap().push(ClockRow {
                    tag,
                    at: std::time::Instant::now(),
                    deadline: child.deadline_instant(),
                    shares: child.shares_original_clock(&original),
                    same_root: child.same_root(&original),
                    armed: child.watcher_is_armed(),
                    child: child.clone(),
                });
            });
        bridges.control_hook = Some(hook);
        bridges
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn child_clock_485_delayed_entry_keeps_original_deadline_before_child_budget() {
        use crate::runtime::rss_runner::invoke_retained_tool;
        use std::sync::Mutex;
        use std::time::{Duration, Instant};

        const T: Duration = Duration::from_secs(2);
        const RESERVE: Duration = Duration::from_millis(700);
        const ALLOWANCE: Duration = Duration::from_millis(250);
        const LONG_LEN: usize = 64 * 1024;

        // Compile/sign/install/activate and prepare the retained program before
        // the original clock exists.
        let chain =
            open_signed_leaf_chain_with("child-clock", CLOCK_LEAF, CLOCK_TOOL_SOURCE, T).await;
        let service = chain.state.service();
        let tool = match prepared_clock_tool(&chain) {
            Ok(tool) => tool,
            Err(error) => {
                let cleanup = service.shutdown().await;
                panic!("clock retained tool preparation failed: {error} (shutdown: {cleanup:?})");
            }
        };
        assert_eq!(
            tool.entry, "run",
            "the retained tool entry must be the declared export"
        );
        // Compile the Service's own agent runner before the clock exists so
        // admission cannot spend the short T on lazy compilation.
        if let Err(error) = service.materialize_cached_runner() {
            let cleanup = service.shutdown().await;
            panic!("clock fixture runner materialization failed: {error} (shutdown: {cleanup:?})");
        }

        let run = match service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"485 child clock delayed entry"}),
                    ..Default::default()
                },
                None,
            )
            .await
        {
            Ok(run) => run,
            Err(error) => {
                let cleanup = service.shutdown().await;
                panic!("clock admission failed: {error:?} (shutdown: {cleanup:?})");
            }
        };
        let handle = match service.handle(&run.run_id) {
            Some(handle) => handle,
            None => {
                let cleanup = service.shutdown().await;
                panic!("admitted clock run has no handle (shutdown: {cleanup:?})");
            }
        };
        // T was configured on the fixture before admission; this is the
        // admission's own root, never a fresh child `with_timeout`.
        let admitted_at = Instant::now();
        let original = handle.cancel.clone();
        let deadline = original
            .deadline_instant()
            .expect("the original admission must carry Some(D)");
        assert!(
            deadline > admitted_at,
            "the original deadline must still be in the future"
        );
        assert!(
            deadline <= admitted_at + T,
            "T must be configured before admission, not at child entry"
        );
        assert!(
            !original.has_deadline_overflow(),
            "the original clock must be a real Instant deadline"
        );
        assert_eq!(
            sealed_pin(&service, &run.run_id).map(|pin| pin.0),
            Some(chain.graph_a.clone()),
            "the admitted run must pin the signed phase-A graph"
        );

        let rows = Arc::new(Mutex::new(Vec::new()));
        let short = invoke_retained_tool(
            Arc::clone(&tool.program),
            &tool.entry,
            clock_bridges(&original, "short", Arc::clone(&rows)),
            crate::domain::json_to_vm_value(&json!({"arguments": {"value": "hi"}})),
            &original,
            &tool.registry,
            None,
        );

        // One delayed entry: wait until RESERVE before the original D, then run
        // the long pure input on the real child VM.
        let mut long_entry = None;
        let mut long_ended = Instant::now();
        let long = match &short {
            Ok(_) => {
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .saturating_sub(RESERVE),
                );
                long_entry = Some(Instant::now());
                let result = invoke_retained_tool(
                    Arc::clone(&tool.program),
                    &tool.entry,
                    clock_bridges(&original, "long", Arc::clone(&rows)),
                    crate::domain::json_to_vm_value(&json!({
                        "arguments": {"value": "x".repeat(LONG_LEN)}
                    })),
                    &original,
                    &tool.registry,
                    None,
                );
                long_ended = Instant::now();
                result
            }
            Err(_) => Err("short control failed; the long leg was not run".to_string()),
        };
        let observed = rows.lock().unwrap().clone();
        let cleanup = service.shutdown().await;
        let cleanup_facts = (
            service
                .handle(&run.run_id)
                .and_then(|handle| *handle.cleanup_outcome.lock().unwrap()),
            service.capability_host_closed(&run.run_id),
            service.capability_host_retained(&run.run_id),
            service.process_owner_count(&run.run_id),
            service
                .capability_host_bridges(&run.run_id)
                .ok()
                .flatten()
                .is_none(),
        );
        let _ = &chain.db;

        // 1. Short positive control on the very same original clock.
        let short = match short {
            Ok(value) => value,
            Err(error) => {
                panic!("short clock control failed: {error} (shutdown: {cleanup:?})")
            }
        };
        let short_json = native_json(&short);
        assert_eq!(short_json["ok"], json!(true));
        assert_eq!(short_json["content"], json!("libC:hi"));
        assert_eq!(
            short_json["control"]["ok"],
            json!(true),
            "the marker must read an open clock: {}",
            short_json["control"]
        );

        // 2. Both markers observed the same live child clock.
        assert_eq!(
            observed.len(),
            2,
            "one marker per retained invocation, got {}",
            observed.len()
        );
        let short_row = &observed[0];
        let long_row = &observed[1];
        assert_eq!((short_row.tag, long_row.tag), ("short", "long"));
        for row in [short_row, long_row] {
            assert_eq!(
                row.deadline,
                Some(deadline),
                "the child must carry the original Some(D)"
            );
            assert!(
                row.shares,
                "the child must share the original request/deadline flags"
            );
            assert!(
                !row.same_root,
                "a child owns a distinct inner root, not the original Arc"
            );
            assert!(
                row.armed,
                "the child epoch watcher must already be armed at the marker"
            );
            assert!(
                row.at < deadline,
                "the marker must be reached before the original D"
            );
        }

        // 3. The long leg is a delayed entry: the delay from admission exceeds
        // the existing settle allowance, so D + allowance is strictly earlier
        // than a hypothetical child-entry + full T.
        let entry = long_entry.expect("the long leg must enter after the control");
        assert!(
            entry.duration_since(admitted_at) > ALLOWANCE,
            "the long child must enter after a distinguishable delay"
        );
        assert!(
            deadline + ALLOWANCE < entry + T,
            "D + allowance must be strictly earlier than child entry + T"
        );
        assert!(entry < deadline, "the long child must enter before D");

        // 4. The long leg terminates only from the original deadline.
        let error = match long {
            Ok(value) => panic!(
                "the long pure child must not complete: {:?}",
                native_json(&value)
            ),
            Err(error) => error,
        };
        assert!(
            error == "run cancelled (deadline)" || error.starts_with("run exceeded its deadline ("),
            "the long child must terminate on the original deadline, got {error}"
        );
        assert!(
            long_ended <= deadline + ALLOWANCE,
            "the cancel settle exceeded the existing allowance: {error}"
        );
        assert!(
            long_ended < entry + T,
            "the child must not receive a fresh full T from its entry"
        );
        assert!(
            original.requested().is_none(),
            "the case must not synthesize an explicit cancellation request"
        );
        assert!(original.deadline_passed());
        assert!(
            !long_row.child.watcher_is_armed(),
            "the long child watcher must be disarmed and joined"
        );
        assert!(
            !short_row.child.watcher_is_armed(),
            "the control child watcher must be disarmed and joined"
        );

        // 5. Owned service cleanup. This layer case starts no worker, so the
        // run handle releases an Empty capability host to Closed(None)/Clean.
        assert!(
            cleanup.is_ok(),
            "the owned service must shut down: {cleanup:?}"
        );
        assert_eq!(cleanup_facts.0, Some(crate::CleanupOutcome::Clean));
        assert!(
            cleanup_facts.1,
            "the run must leave a closed capability host"
        );
        assert!(
            !cleanup_facts.2,
            "the run must not retain capability host state"
        );
        assert_eq!(cleanup_facts.3, 0, "the run must leave no process owner");
        assert!(cleanup_facts.4, "the run must expose no usable bridge");
    }
}
