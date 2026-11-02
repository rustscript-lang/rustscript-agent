//! Production managed maintenance through HTTP, original admission and Native FS.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, ScriptedProvider, build_agent_gateway_app,
    config::ManagedWorkspaceConfig,
    effects::{ManagedEffectGetRequest, ManagedOwnerScope},
};
use serde_json::{Value, json};
async fn request(address: SocketAddr, path: &str, body: Value) -> (u16, Value) {
    post(address, path, body, Some("synthetic-maintenance-fixture")).await
}

async fn post(address: SocketAddr, path: &str, body: Value, bearer: Option<&str>) -> (u16, Value) {
    exchange(address, "POST", path, Some(body), bearer).await
}

async fn exchange(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (u16, Value) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{path}"))
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = request
        .body(Full::new(Bytes::from(
            body.map(|value| value.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let response = client.request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("HTTP JSON body")
    };
    (status, body)
}

struct CancellationGateProvider {
    step: std::sync::atomic::AtomicUsize,
    entered: std::sync::atomic::AtomicBool,
}
impl rustscript_agent::AgentProviderHost for CancellationGateProvider {
    fn call(&self, _request: &Value, cancellation: &rustscript_agent::RunCancellation) -> Value {
        use std::sync::atomic::Ordering;
        if self.step.fetch_add(1, Ordering::SeqCst) == 0 {
            return json!({"ok":true,"response":{"text":"", "tool_calls":[{"id":"write-b", "name":"write_file", "arguments":{"path":"value.txt", "content":"B"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"},"error":{}});
        }
        self.entered.store(true, Ordering::Release);
        while cancellation.requested().is_none() && !cancellation.deadline_passed() {
            std::thread::sleep(Duration::from_millis(5));
        }
        json!({"ok":false,"error":{"code":"cancelled","message":"owned synthetic provider observed original cancellation","retryable":false}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_files_checkpoint_restore_new_admission() {
    roundtrip(false, false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_replay_uses_original_source_proof() {
    roundtrip(true, false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_cancels_active_source_before_capacity_one_admission() {
    roundtrip(false, true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_compaction_restores_summary_and_retained_tail_to_actual_model() {
    roundtrip(false, false, true).await;
}

async fn roundtrip(check_replay: bool, active_source: bool, compacted: bool) {
    roundtrip_case(check_replay, active_source, compacted).await;
}
async fn roundtrip_case(check_replay: bool, active_source: bool, compacted: bool) {
    let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-checkpoint-{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    for name in ["AGENTS.md", "CLAUDE.md", ".cursorrules"] {
        std::fs::write(workspace.join(name), format!("FROZEN_A_{name}")).unwrap();
    }
    use std::os::unix::fs::PermissionsExt;
    for directory in [&root, &workspace, &home] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(home.join("config.yaml"), format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n", workspace.display(), workspace.display())).unwrap();
    let mut config = AgentGatewayConfig {
        bearer_token: Some("synthetic-maintenance-fixture".into()),
        max_concurrent_runs: 1,
        managed_workspace: Some(ManagedWorkspaceConfig::for_workspace(&workspace).unwrap()),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy
        .create_checkpoint = true;
    config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy
        .restore = true;
    let compaction = rustscript_agent::config_file::CompactionSettings {
        retained_tail: 1,
        ..Default::default()
    };
    let state = AgentGatewayState::with_agent_selection_and_compaction(
        config,
        json!({}),
        Some(&root.join("gateway.sqlite")),
        compaction,
    )
    .unwrap_or_else(|error| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/storage/admission.rss");
        let diagnostic = rustscript_agent::AgentRunner::from_file(
            path,
            rustscript_agent::AgentConfig::default(),
        )
        .err();
        panic!(
            "fixture storage initialization: {error}; ordinary source compilation: {diagnostic:?}"
        );
    })
    .with_workspace_home(&home);
    let service = state.service();
    service
        .set_provider_profile(
            rustscript_agent::config::ProviderProfile::new(
                "frozen-profile",
                json!({"protocol":"provider","temperature":0.25,"max_output_tokens":1024}),
            )
            .unwrap(),
        )
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    for response in [
        json!({"text":"", "tool_calls":[{"id":"write-a", "name":"write_file", "arguments":{"path":"value.txt", "content":"A"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}),
        json!({"text":"closed A", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}),
    ] {
        provider.push_ok(response);
    }
    service.inject_provider_host(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let app = build_agent_gateway_app(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    let observed = Arc::clone(&service);
    let persistence = state.persistence().unwrap();
    let outcome = tokio::spawn(async move {
        let session_id = uuid::Uuid::new_v4().to_string();
        let (status, _) = request(address, "/api/sessions", json!({"id":session_id})).await;
        assert_eq!(status, 201, "original HTTP session creation");
        let (status, run) = request(address, "/v1/runs", json!({"input":"write A", "session_id":session_id,"provider":"frozen-profile"})).await;
        assert_eq!(status, 202, "original HTTP admission: {run}");
        let run_id = run["run_id"].as_str().unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if observed.run_events(run_id).iter().any(|event| event["event"] == "run.completed") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("actual worker completes Native write");
        let record = persistence.managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {profile:"gateway".into(), session_id:session_id.clone(), run_id:run_id.into()},
            call_id:"write-a".into(),
        }).unwrap().unwrap();
        let publication = record.outcome.as_ref().unwrap();
        let head = persistence.managed_workspace_head(&record.identity.workspace).unwrap();
        assert_eq!(Some(head.head_object_id.as_str()), publication.publication.candidate_head.as_deref());
        let workspace_id = &record.identity.workspace.workspace_id;
        let frozen_messages = persistence.message_list(&session_id, 0).unwrap();
        let mut frozen_summary = None;
        if compacted {
            let compactor = observed.clone();
            let session = session_id.clone();
            let result = tokio::task::spawn_blocking(move || compactor.compact_session_explicit(&session)).await.unwrap().unwrap();
            assert_eq!(result["status"], "committed");
            let latest = persistence.compaction_latest(&session_id).unwrap();
            frozen_summary = Some(latest);
        }
        let (status, checkpoint) = request(address, &format!("/v1/workspaces/{workspace_id}/checkpoints"), json!({
            "source_run_id":run_id,
            "workspace_id":workspace_id,
            "source_branch_id":record.identity.workspace.branch_id,
            "expected_epoch":record.identity.epoch,
            "request_id":uuid::Uuid::new_v4().to_string(),
            "mode":"at_closed_batch"
        })).await;
        assert_eq!(status, 201, "checkpoint must traverse production management: {checkpoint}");
        let checkpoint = &checkpoint["checkpoint"];
        assert_eq!(checkpoint["frozen_root"]["object_id"], head.head_object_id);
        assert!(checkpoint["history"]["message_count"].as_u64().unwrap() >= 3);
        assert_eq!(checkpoint["history"]["closed_output_refs"][0]["call_id"], "write-a");
        assert_eq!(checkpoint["graph"]["graph_id"], record.identity.code.graph_id);
        assert_eq!(checkpoint["plugin_state"]["roots"], json!([]));
        assert!(checkpoint["public_config"]["config"].get("provider_options").is_none());
        assert!(checkpoint["public_config"]["config"].get("limits").is_none());
        assert!(checkpoint["public_config"]["config"].get("metadata").is_none());
        observed.set_provider_profile(rustscript_agent::config::ProviderProfile::new("frozen-profile", json!({"protocol":"provider","temperature":0.75,"max_output_tokens":2048})).unwrap()).unwrap();
        for name in ["AGENTS.md", "CLAUDE.md", ".cursorrules"] {
            std::fs::write(workspace.join(name), format!("HOST_LIVE_{name}")).unwrap();
        }
        let provider = Arc::new(ScriptedProvider::new());
        let mut writes = vec![json!({"id":"write-b", "name":"write_file", "arguments":{"path":"value.txt", "content":"B"}})];
        for (index, name) in ["AGENTS.md", "CLAUDE.md", ".cursorrules"].iter().enumerate() {
            writes.push(json!({"id":format!("guidance-b-{index}"), "name":"write_file", "arguments":{"path":name, "content":format!("MANAGED_B_{name}")}}));
        }
        provider.push_ok(json!({"text":"", "tool_calls":writes, "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
        provider.push_ok(json!({"text":"closed B", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
        let source_gate = Arc::new(CancellationGateProvider {
            step: std::sync::atomic::AtomicUsize::new(0),
            entered: std::sync::atomic::AtomicBool::new(false),
        });
        if active_source { observed.inject_provider_host(source_gate.clone()); }
        else { observed.inject_provider_host(provider); }
        let (status, later) = request(address, "/v1/runs", json!({"input":"advance source to B", "session_id":session_id})).await;
        assert_eq!(status, 202);
        let later_run = later["run_id"].as_str().unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            while if active_source {
                !source_gate.entered.load(std::sync::atomic::Ordering::Acquire)
            } else {
                !observed.run_events(later_run).iter().any(|event| event["event"] == "run.completed")
            } {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let source_before = persistence.managed_workspace_head(&record.identity.workspace).unwrap();
        if !active_source {
            for index in 0..3 {
                let guidance_write = persistence.managed_effect_get(&ManagedEffectGetRequest {
                    owner: ManagedOwnerScope {profile:"gateway".into(),session_id:session_id.clone(),run_id:later_run.into()},
                    call_id:format!("guidance-b-{index}"),
                }).unwrap().unwrap();
                assert_eq!(guidance_write.outcome.unwrap().disposition, rustscript_agent::effects::ManagedPublicationStatus::Committed);
            }
        }
        assert_ne!(head.head_object_id, source_before.head_object_id);
        assert!(source_before.head_version > head.head_version);
        let provider = Arc::new(ScriptedProvider::new());
        provider.push_ok(json!({"text":"", "tool_calls":[{"id":"restored-read-a", "name":"read_file", "arguments":{"path":"value.txt"}},{"id":"restored-write-c", "name":"write_file", "arguments":{"path":"value.txt", "content":"C"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
        provider.push_ok(json!({"text":"closed C", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
        observed.inject_provider_host(provider.clone());
        let restore_request = json!({
            "workspace_id":workspace_id,
            "source_branch_id":record.identity.workspace.branch_id,
            "checkpoint_id":checkpoint["checkpoint_id"],
            "expected_source":{
                "store_id":source_before.store_id,
                "workspace_id":source_before.workspace_id,
                "branch_id":source_before.branch_id,
                "epoch":source_before.epoch,
                "head_object_id":source_before.head_object_id,
                "head_version":source_before.head_version
            },
            "request_id":uuid::Uuid::new_v4().to_string(),
            "input":{"text":"read restored A, then write C"},
            "cancel_active_source":true,
            "graph_selection":"checkpoint_exact"
        });
        let (status, restored) = request(address, &format!("/v1/workspaces/{workspace_id}/restore"), restore_request.clone()).await;
        assert_eq!(status, 202, "atomic restore and original new admission: {restored}");
        if active_source {
            assert!(observed.run_events(later_run).iter().any(|event| event["event"] == "run.cancelled"),
                "the old source worker must exit and release its original capacity before a new run is admitted");
        }
        assert_eq!(restored["source_before"]["head_object_id"], source_before.head_object_id);
        assert_eq!(restored["new_branch"]["head_object_id"], head.head_object_id);
        assert_eq!(restored["source_after"]["epoch"], source_before.epoch + 1);
        assert_eq!(restored["new_branch"]["epoch"], source_before.epoch + 1);
        assert_eq!(restored["new_branch"]["head_version"], 1);
        let new_run = restored["new_run_id"].as_str().unwrap();
        let new_session = restored["new_session_id"].as_str().unwrap();
        assert_ne!(new_run, run_id);
        assert_ne!(new_run, later_run);
        assert_ne!(new_session, session_id);
        tokio::time::timeout(Duration::from_secs(20), async {
            while !observed.run_events(new_run).iter().any(|event| event["event"] == "run.completed") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let provider_requests = provider.requests();
        assert_eq!(provider_requests[0]["provider_options"]["temperature"], 0.25, "restore consumes private frozen safe options");
        assert_eq!(provider_requests[0]["provider_options"]["max_output_tokens"], 1024);
        let first_request = provider_requests.first().expect("restored provider actually called").to_string();
        if let Some(summary) = frozen_summary {
            let summary_json = summary["rows"][0][7].as_str().expect("typed committed summary column");
            let summary: Value = serde_json::from_str(summary_json).unwrap();
            let expected_summary = summary["text"].as_str().unwrap().to_string();
            assert!(first_request.contains(&serde_json::to_string(&expected_summary).unwrap()[1..serde_json::to_string(&expected_summary).unwrap().len()-1]), "restored model consumes exact frozen summary");
            assert!(first_request.contains("closed A"), "retained tail remains in model context");
            let boundary = summary["retained_tail_ordinal"].as_i64().unwrap();
            let mut expected = vec![json!({"role":"user","content":[{"type":"text","text":expected_summary}]})];
            let column = |page: &Value, name: &str| page["columns"].as_array().unwrap().iter().position(|value|value==name).unwrap();
            for row in frozen_messages["rows"].as_array().unwrap() {
                if row[column(&frozen_messages,"ordinal")].as_i64().unwrap() > boundary {
                    let content: Value = serde_json::from_str(row[column(&frozen_messages,"content_json")].as_str().unwrap()).unwrap();
                    expected.push(json!({"role":row[column(&frozen_messages,"role")],"content":content}));
                }
            }
            let current = persistence.message_list(new_session, 0).unwrap();
            let input = current["rows"].as_array().unwrap().iter().find(|row|row[column(&current,"ordinal")].as_i64()==Some(5)).unwrap();
            let input_content: Value = serde_json::from_str(input[column(&current,"content_json")].as_str().unwrap()).unwrap();
            assert!(input_content.to_string().contains("read restored A, then write C"));
            expected.push(json!({"role":"user","content":input_content}));
            let actual = provider_requests[0]["messages"].as_array().unwrap().iter().skip(1).map(|message|json!({"role":message["role"],"content":message["content"]})).collect::<Vec<_>>();
            assert_eq!(actual, expected, "actual selected frozen summary + exact retained tail + new admitted input");
            let restored_summary = persistence.compaction_latest(new_session).unwrap();
            assert_eq!(restored_summary["rows"][0][7], summary_json);
        }
        for name in ["AGENTS.md", "CLAUDE.md", ".cursorrules"] {
            assert!(first_request.contains(&format!("FROZEN_A_{name}")), "restored model must consume frozen guidance {name}");
        }
        assert!(!first_request.contains("HOST_LIVE_"), "host guidance must not enter restored model context");
        assert!(!first_request.contains("MANAGED_B_"), "current managed head must not replace frozen guidance");
        assert!(!first_request.contains("/managed-effects/"), "private store path must not enter model context");
        assert!(!first_request.contains(".gateway.sqlite.effects"), "private frozen root path must not enter model context");
        let read = observed.replay_managed_call(ManagedEffectGetRequest {
            owner:ManagedOwnerScope {profile:"gateway".into(),session_id:new_session.into(),run_id:new_run.into()},
            call_id:"restored-read-a".into(),
        }).unwrap();
        let rustscript_agent::effects::ManagedCallReplay::Final {canonical_result, ..} = read else {
            panic!("restored read must have a durable final Native result")
        };
        let read: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(read["ok"], true);
        assert_eq!(read["content"], "A");
        let written = persistence.managed_effect_get(&ManagedEffectGetRequest {
            owner:ManagedOwnerScope {profile:"gateway".into(),session_id:new_session.into(),run_id:new_run.into()},
            call_id:"restored-write-c".into(),
        }).unwrap().unwrap();
        assert_ne!(written.identity.workspace.branch_id, record.identity.workspace.branch_id);
        assert_eq!(written.identity.epoch, source_before.epoch + 1);
            assert_eq!(written.outcome.as_ref().unwrap().disposition, rustscript_agent::effects::ManagedPublicationStatus::Committed);
        let retired = persistence.managed_workspace_head(&record.identity.workspace).unwrap();
        assert_eq!(retired.head_object_id, source_before.head_object_id);
        assert_eq!(retired.epoch, source_before.epoch + 1);
        if check_replay {
            let before_replay_messages = persistence.message_list(new_session, 0).unwrap();
            let before_replay_context = observed.run_context(new_run).unwrap();
            let before_replay_events = observed.run_events(new_run);
            let before_replay_calls = provider.requests().len();
            let before_replay_head = persistence.managed_workspace_head(&written.identity.workspace).unwrap();
            let before_replay_result = persistence.managed_effect_get(&ManagedEffectGetRequest {
                owner:ManagedOwnerScope {profile:"gateway".into(),session_id:new_session.into(),run_id:new_run.into()},
                call_id:"restored-write-c".into(),
            }).unwrap();
            let (status, replay) = request(address, &format!("/v1/workspaces/{workspace_id}/restore"), restore_request.clone()).await;
            assert_eq!(status, 202, "exact original SOURCE request must replay: {replay}");
            assert_eq!(replay["replayed"], true);
            let replay_path = format!("/v1/workspaces/{workspace_id}/restore");
            let (left, right) = tokio::join!(
                request(address, &replay_path, restore_request.clone()),
                request(address, &replay_path, restore_request.clone())
            );
            for (status, concurrent) in [left, right] {
                assert_eq!(status, 202);
                assert_eq!(concurrent, replay, "same-request concurrent exact retries are one receipt/run, never two CAS winners");
            }
            for field in ["receipt_id", "new_branch", "new_run_id", "new_session_id", "new_run_deadline_at_ms", "source_before", "source_after"] {
                assert_eq!(replay[field], restored[field], "exact replay preserves {field}");
            }
            let mut changed = restore_request.clone();
            changed["expected_source"] = restored["source_after"].clone();
            let (status, denied) = request(address, &format!("/v1/workspaces/{workspace_id}/restore"), changed).await;
            assert_eq!(status, 409);
            assert_eq!(denied["error"]["code"], "managed_request_conflict");
            let mut changed_input = restore_request;
            changed_input["input"]["text"] = json!("different original input");
            let (status, denied) = request(address, &format!("/v1/workspaces/{workspace_id}/restore"), changed_input).await;
            assert_eq!(status, 409);
            assert_eq!(denied["error"]["code"], "managed_request_conflict");
            assert_eq!(persistence.managed_workspace_head(&record.identity.workspace).unwrap(), retired);
            assert_eq!(persistence.managed_workspace_head(&written.identity.workspace).unwrap(), before_replay_head);
            assert_eq!(persistence.message_list(new_session, 0).unwrap(), before_replay_messages);
            assert_eq!(observed.run_context(new_run).unwrap().limits, before_replay_context.limits);
            assert_eq!(observed.run_context(new_run).unwrap().metadata, before_replay_context.metadata);
            assert_eq!(observed.run_events(new_run), before_replay_events);
            assert_eq!(provider.requests().len(), before_replay_calls, "replay/conflicts never restart the worker or issue provider/tool IO");
            assert_eq!(persistence.managed_effect_get(&ManagedEffectGetRequest {
                owner:ManagedOwnerScope {profile:"gateway".into(),session_id:new_session.into(),run_id:new_run.into()},
                call_id:"restored-write-c".into(),
            }).unwrap(), before_replay_result);
        }
        assert!(!workspace.join("value.txt").exists(), "source directory is never overwritten");
        for name in ["AGENTS.md", "CLAUDE.md", ".cursorrules"] {
            assert_eq!(std::fs::read_to_string(workspace.join(name)).unwrap(), format!("HOST_LIVE_{name}"));
        }
    }).await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    service.halt();
    let cleanup = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match service.shutdown().await {
                Ok(()) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await;
    drop(std::net::TcpListener::bind(address).expect("owned listener released"));
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
    cleanup.expect("owned worker and storage shutdown");
}

fn restart_fixture() -> (PathBuf, AgentGatewayConfig, AgentGatewayState) {
    let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-restart-{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for path in [&root, &workspace, &home] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(home.join("config.yaml"), format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n", workspace.display(), workspace.display())).unwrap();
    let mut config = AgentGatewayConfig {
        bearer_token: Some("synthetic-maintenance-fixture".into()),
        max_concurrent_runs: 1,
        managed_workspace: Some(ManagedWorkspaceConfig::for_workspace(&workspace).unwrap()),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    let policy = &mut config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy;
    policy.create_checkpoint = true;
    policy.restore = true;
    let state = AgentGatewayState::with_sqlite_path(config.clone(), root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home);
    (root, config, state)
}

struct RestartServer {
    address: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl RestartServer {
    async fn start(state: AgentGatewayState) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let app = build_agent_gateway_app(state);
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            address,
            shutdown,
            task,
        }
    }

    async fn close(self, service: &rustscript_agent::AgentService) -> Result<(), String> {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        service.halt();
        // The first shutdown is the qualification result. On a failed fixture,
        // finish cleanup separately, retaining the first error and test panic.
        let first = tokio::time::timeout(Duration::from_secs(10), service.shutdown())
            .await
            .expect("bounded first shutdown");
        if first.is_err() {
            tokio::time::timeout(Duration::from_secs(10), async {
                while service.shutdown().await.is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("failed-fixture cleanup must still join owners");
        }
        drop(std::net::TcpListener::bind(self.address).expect("owned listener released"));
        println!(
            "restart owned server joined; first service.shutdown={first:?}; listener released"
        );
        first
    }
}

async fn restart_wait_terminal(service: &rustscript_agent::AgentService, run: &str) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let events = service.run_events(run);
            if events.iter().any(|event| event["event"] == "run.completed") {
                #[cfg(feature = "workspace-io-fault")]
                if !service.handle(run).unwrap().worker_is_idle_for_test() {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    continue;
                }
                break;
            }
            assert!(
                !events.iter().any(|event| matches!(
                    event["event"].as_str(),
                    Some("run.failed" | "run.cancelled")
                )),
                "unexpected synthetic worker terminal: {events:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|error| {
        panic!(
            "real HTTP worker terminal: {error}; events={:?}",
            service.run_events(run)
        )
    });
}

fn restart_response(call: Option<Value>) -> Value {
    json!({"text":if call.is_some() { "" } else { "closed" }, "tool_calls":call.into_iter().collect::<Vec<_>>(), "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"})
}

fn restart_run_facts(state: &AgentGatewayState, runs: &[String]) -> Value {
    let service = state.service();
    let persistence = state.persistence().unwrap();
    Value::Array(
        runs.iter()
            .map(|run| {
                let context = service.run_context(run).unwrap();
                json!({"run":persistence.run_get(run).unwrap(), "events":service.run_events(run),
            "metadata":context.metadata, "limits":context.limits,
            "history":persistence.message_list(&context.session_id, 0).unwrap()})
            })
            .collect(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_restores_facts_not_old_authority() {
    use rustscript_agent::effects::{
        ManagedCheckpointReceipt, ManagedEffectListRequest, ManagedRestoreAndAdmitResult,
    };
    let (root, config, state) = restart_fixture();
    let service = state.service();
    service
        .set_provider_profile(
            rustscript_agent::config::ProviderProfile::new(
                "restart-profile",
                json!({"protocol":"provider"}),
            )
            .unwrap(),
        )
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    for (id, content) in [("restart-write-a", "A"), ("restart-write-b", "B")] {
        provider.push_ok(restart_response(Some(
            json!({"id":id,"name":"write_file","arguments":{"path":"value.txt","content":content}}),
        )));
        provider.push_ok(restart_response(None));
    }
    provider.push_ok(restart_response(Some(
        json!({"id":"restart-read-a","name":"read_file","arguments":{"path":"value.txt"}}),
    )));
    provider.push_ok(restart_response(None));
    service.inject_provider_host(provider.clone());
    let server = RestartServer::start(state.clone()).await;
    let address = server.address;
    let observed = state.clone();
    let scenario_provider = provider.clone();
    let outcome = tokio::spawn(async move {
        let service = observed.service();
        let persistence = observed.persistence().unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        assert_eq!(request(address, "/api/sessions", json!({"id":session})).await.0, 201);
        let (status, a) = request(address, "/v1/runs", json!({"input":"write A","session_id":session,"provider":"restart-profile"})).await;
        assert_eq!(status, 202);
        let a = a["run_id"].as_str().unwrap().to_string();
        restart_wait_terminal(&service, &a).await;
        let write_a = persistence.managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {profile:"gateway".into(),session_id:session.clone(),run_id:a.clone()},call_id:"restart-write-a".into(),
        }).unwrap().unwrap();
        let old_identity = write_a.identity.workspace.clone();
        let head_a = persistence.managed_workspace_head(&old_identity).unwrap();
        let path = format!("/v1/workspaces/{}/checkpoints", old_identity.workspace_id);
        let (status, checkpoint) = request(address, &path, json!({"source_run_id":a,"workspace_id":old_identity.workspace_id,
            "source_branch_id":old_identity.branch_id,"expected_epoch":head_a.epoch,"request_id":uuid::Uuid::new_v4().to_string(),"mode":"at_closed_batch"})).await;
        assert_eq!(status, 201, "{checkpoint}");
        let checkpoint: ManagedCheckpointReceipt = serde_json::from_value(checkpoint).unwrap();
        assert_eq!(checkpoint.checkpoint.frozen_root.object_id, head_a.head_object_id);
        service.inject_provider_host(scenario_provider.clone());
        let (status, b) = request(address, "/v1/runs", json!({"input":"write B","session_id":session})).await;
        assert_eq!(status, 202);
        let b = b["run_id"].as_str().unwrap().to_string();
        restart_wait_terminal(&service, &b).await;
        let write_b = persistence.managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {profile:"gateway".into(),session_id:session.clone(),run_id:b.clone()},call_id:"restart-write-b".into(),
        }).unwrap().unwrap();
        assert_eq!(write_b.identity.workspace, old_identity, "B is a real writer on the same branch");
        let head_b = persistence.managed_workspace_head(&old_identity).unwrap();
        assert_ne!(head_b.head_object_id, head_a.head_object_id);
        let body = json!({"workspace_id":old_identity.workspace_id,"source_branch_id":old_identity.branch_id,
            "checkpoint_id":checkpoint.checkpoint.checkpoint_id,"expected_source":{"store_id":head_b.store_id,"workspace_id":head_b.workspace_id,
            "branch_id":head_b.branch_id,"epoch":head_b.epoch,"head_object_id":head_b.head_object_id,"head_version":head_b.head_version},
            "request_id":uuid::Uuid::new_v4().to_string(),"input":{"text":"read frozen A"},"cancel_active_source":true,"graph_selection":"checkpoint_exact"});
        let restore_path = format!("/v1/workspaces/{}/restore", old_identity.workspace_id);
        service.inject_provider_host(scenario_provider);
        let (status, restored) = request(address, &restore_path, body.clone()).await;
        assert_eq!(status, 202, "{restored}");
        let receipt: ManagedRestoreAndAdmitResult = serde_json::from_value(restored).unwrap();
        restart_wait_terminal(&service, &receipt.new_run_id).await;
        assert_eq!(receipt.source_before.head_object_id, head_b.head_object_id);
        assert_eq!(receipt.new_branch.head_object_id, head_a.head_object_id);
        assert_ne!(receipt.new_session_id, session);
        assert_ne!(receipt.new_run_id, a);
        assert_ne!(receipt.new_run_id, b);
        let context = service.run_context(&receipt.new_run_id).unwrap();
        println!("restart phase=terminal-before-reopen receipt={} context_deadline={} old_runs={:?} old_session={session}", serde_json::to_string(&receipt).unwrap(), context.metadata["deadline_at_ms"], [&a, &b]);
        assert_eq!(context.metadata["deadline_at_ms"], receipt.new_run_deadline_at_ms, "formal receipt and frozen context must preserve the same original new-run deadline");
        let read_request = ManagedEffectGetRequest {owner:ManagedOwnerScope {profile:"gateway".into(),session_id:receipt.new_session_id.clone(),run_id:receipt.new_run_id.clone()},call_id:"restart-read-a".into()};
        let rustscript_agent::effects::ManagedCallReplay::Final {canonical_result, ..} = service.replay_managed_call(read_request.clone()).unwrap() else {panic!("actual Native read result")};
        let result: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(result["content"], "A");
        assert_eq!(result["ok"], true);
        let mut current_identity = old_identity.clone();
        current_identity.branch_id.clear(); // Existing typed head API selects durable current_branch_id.
        let current = persistence.managed_workspace_head(&current_identity).unwrap();
        let retired = persistence.managed_workspace_head(&old_identity).unwrap();
        assert_eq!(current.branch_id, receipt.new_branch.branch_id);
        assert_eq!(current.head_object_id, checkpoint.checkpoint.frozen_root.object_id);
        assert_eq!(retired.head_object_id, head_b.head_object_id);
        assert_eq!(retired.epoch, receipt.source_after.epoch);
        let runs = vec![a, b, receipt.new_run_id.clone()];
        let facts = restart_run_facts(&observed, &runs);
        let effects_request = ManagedEffectListRequest {workspace_id:old_identity.workspace_id.clone(),after_effect_id:None,limit:100};
        let effects = persistence.managed_effect_list(&effects_request).unwrap();
        assert_eq!(effects.entries.len(), 3, "A/B writes and restored A read have real durable results");
        let read = persistence.managed_effect_get(&read_request).unwrap();
        println!("restart pre-close receipt={} old_runs={:?} checkpoint={}", serde_json::to_string(&receipt).unwrap(), &runs[..2], serde_json::to_string(&checkpoint).unwrap());
        (restore_path, body, receipt, checkpoint, old_identity, current_identity, current, retired, runs, facts, effects_request, effects, read_request, read)
    }).await;
    let cleanup = server.close(&service).await;
    drop(service);
    drop(state);
    let (
        path,
        body,
        receipt,
        checkpoint,
        old_identity,
        current_identity,
        current,
        retired,
        runs,
        facts,
        effects_request,
        effects,
        read_request,
        read,
    ) = match outcome {
        Ok(facts) => facts,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    };
    cleanup.expect("first shutdown joins service janitor/storage after worker occupancy release");
    let state = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .expect("same configured root reopens after actual shutdown and owner release")
        .with_workspace_home(root.join("home"));
    let service = state.service();
    let no_provider = Arc::new(ScriptedProvider::new());
    service.inject_provider_host(no_provider.clone());
    let server = RestartServer::start(state.clone()).await;
    let address = server.address;
    let observed = state.clone();
    let calls_before = provider.requests().len();
    let outcome = tokio::spawn(async move {
        let service = observed.service();
        let persistence = observed.persistence().unwrap();
        let loaded_facts = restart_run_facts(&observed, &runs);
        // Keep the full comparison below, after independently exercising exact
        // replay and old-run refusal, so an event mismatch does not hide them.
        for (loaded, original) in loaded_facts.as_array().unwrap().iter().zip(facts.as_array().unwrap()) {
            for field in ["run", "metadata", "limits", "history"] {
                assert_eq!(loaded[field], original[field], "reopen preserves {field}");
            }
        }
        assert_eq!(persistence.managed_workspace_head(&old_identity).unwrap(), retired);
        assert_eq!(persistence.managed_workspace_head(&current_identity).unwrap(), current);
        assert_eq!(current.head_object_id, checkpoint.checkpoint.frozen_root.object_id);
        let admissions_before = service.metrics().snapshot().admissions_accepted;
        let (status, replay) = request(address, &path, body).await;
        assert_eq!(status, 202, "formal exact retry after reopen: {replay}");
        let mut replay: ManagedRestoreAndAdmitResult = serde_json::from_value(replay).unwrap();
        assert!(replay.replayed);
        replay.replayed = receipt.replayed;
        assert_eq!(replay, receipt, "exact retry consumes original proof/receipt, without new admission or deadline");
        for old in &runs[..2] {
            service.clone().run_worker(old.clone(), "public id and frozen metadata grant no continuation".into()).await;
        }
        let after_retry_facts = restart_run_facts(&observed, &runs);
        assert_eq!(after_retry_facts, loaded_facts, "exact retry and old-run refusal change no loaded facts");
        assert_eq!(service.metrics().snapshot().admissions_accepted, admissions_before, "exact retry creates no new admission");
        assert_eq!(persistence.managed_effect_list(&effects_request).unwrap(), effects);
        assert_eq!(persistence.managed_effect_get(&read_request).unwrap(), read);
        assert_eq!(persistence.managed_workspace_head(&old_identity).unwrap(), retired);
        assert_eq!(persistence.managed_workspace_head(&current_identity).unwrap(), current);
        assert!(no_provider.requests().is_empty(), "neither retry nor old run invokes a provider");
        println!("restart reopened: exact receipt/current/retired/frozen root, run facts/history/resultrefs unchanged; old-run provider calls=0; new deadline={}", receipt.new_run_deadline_at_ms);
        for (loaded, original) in loaded_facts.as_array().unwrap().iter().zip(facts.as_array().unwrap()) {
            for (after, before) in loaded["events"].as_array().unwrap().iter().zip(original["events"].as_array().unwrap()) {
                if after != before {
                    println!("restart event mismatch={}", json!({"run":loaded["run"]["rows"][0][0],"before":before,"after":after}));
                }
            }
        }
        assert_eq!(loaded_facts, facts, "load preserves terminal status/events/history and original clocks");
        assert_eq!(after_retry_facts, facts);
    }).await;
    let cleanup = server.close(&service).await;
    assert_eq!(
        provider.requests().len(),
        calls_before,
        "source provider cannot be reused after reopen"
    );
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
    cleanup.expect("first reopened shutdown joins all owned workers");
}

#[tokio::test(flavor = "multi_thread")]
async fn active_run_reopen_is_gateway_restart_not_a_deadline_execution() {
    let (root, config, state) = restart_fixture();
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            rustscript_agent::AdmitRunRequest {
                input: json!({"message":"active restart characterization"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let metadata = service.run_context(&run.run_id).unwrap().metadata;
    service.halt();
    service
        .shutdown()
        .await
        .expect("first shutdown joins janitor and storage with no run worker");
    drop(service);
    drop(state);
    let state = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(root.join("home"));
    let service = state.service();
    let persistence = state.persistence().unwrap();
    let row = persistence.run_get(&run.run_id).unwrap();
    let columns = row["columns"].as_array().unwrap();
    let values = &row["rows"][0];
    let cell =
        |name: &str| values[columns.iter().position(|column| column == name).unwrap()].clone();
    assert_eq!(cell("status"), "failed");
    assert_eq!(cell("error_code"), "gateway_restart");
    assert_eq!(service.run_context(&run.run_id).unwrap().metadata, metadata);
    let provider = Arc::new(ScriptedProvider::new());
    service.inject_provider_host(provider.clone());
    service
        .clone()
        .run_worker(
            run.run_id.clone(),
            "public id cannot resume after load".into(),
        )
        .await;
    assert!(provider.requests().is_empty());
    assert_eq!(persistence.run_get(&run.run_id).unwrap(), row);
    assert!(service.handle(&run.run_id).is_none());
    println!(
        "formal active reopen: failed/gateway_restart; original deadline={} unchanged; no handle/provider; separate from clock negative",
        metadata["deadline_at_ms"]
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_branch_from_checkpoint_preserves_source() {
    let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-branch-{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for directory in [&root, &workspace, &home] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(
        home.join("config.yaml"),
        format!(
            "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",
            workspace.display(),
            workspace.display()
        ),
    )
    .unwrap();
    let mut config = AgentGatewayConfig {
        bearer_token: Some("synthetic-maintenance-fixture".into()),
        max_concurrent_runs: 1,
        managed_workspace: Some(ManagedWorkspaceConfig::for_workspace(&workspace).unwrap()),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy
        .create_checkpoint = true;
    config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy
        .branch = true;
    let state = AgentGatewayState::with_agent_selection_and_compaction(
        config,
        json!({}),
        Some(&root.join("gateway.sqlite")),
        rustscript_agent::config_file::CompactionSettings::default(),
    )
    .unwrap()
    .with_workspace_home(&home);
    let service = state.service();
    service
        .set_provider_profile(
            rustscript_agent::config::ProviderProfile::new(
                "frozen-profile",
                json!({"protocol":"provider","temperature":0.25,"max_output_tokens":1024}),
            )
            .unwrap(),
        )
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"", "tool_calls":[{"id":"write-a", "name":"write_file", "arguments":{"path":"value.txt", "content":"A"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
    provider.push_ok(json!({"text":"closed A", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
    service.inject_provider_host(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let app = build_agent_gateway_app(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    let observed = Arc::clone(&service);
    let persistence = state.persistence().unwrap();
    let outcome = tokio::spawn(async move {
        let session_id = uuid::Uuid::new_v4().to_string();
        let (status, _) = request(address, "/api/sessions", json!({"id": session_id})).await;
        assert_eq!(status, 201, "original HTTP session creation");
        let (status, run) = request(
            address,
            "/v1/runs",
            json!({"input":"write A", "session_id": session_id, "provider":"frozen-profile"}),
        )
        .await;
        assert_eq!(status, 202, "original HTTP admission: {run}");
        let run_id = run["run_id"].as_str().unwrap().to_string();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if observed
                    .run_events(&run_id)
                    .iter()
                    .any(|event| event["event"] == "run.completed")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actual worker completes Native write");
        let record = persistence
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: ManagedOwnerScope {
                    profile: "gateway".into(),
                    session_id: session_id.clone(),
                    run_id: run_id.clone(),
                },
                call_id: "write-a".into(),
            })
            .unwrap()
            .unwrap();
        let head = persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        let workspace_id = record.identity.workspace.workspace_id.clone();
        let source_branch_id = record.identity.workspace.branch_id.clone();
        let messages_before = persistence.message_list(&session_id, 0).unwrap();
        let (status, checkpoint) = request(
            address,
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch_id,
                "expected_epoch": record.identity.epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
        )
        .await;
        assert_eq!(status, 201, "checkpoint before branch: {checkpoint}");
        let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
            .as_str()
            .unwrap()
            .to_string();
        let frozen_root = checkpoint["checkpoint"]["frozen_root"]["object_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(frozen_root, head.head_object_id);
        let branch_request = json!({
            "workspace_id": workspace_id,
            "source_branch_id": source_branch_id,
            "checkpoint_id": checkpoint_id,
            "request_id": uuid::Uuid::new_v4().to_string(),
            "expected_source": {
                "store_id": head.store_id,
                "workspace_id": workspace_id,
                "branch_id": source_branch_id,
                "epoch": head.epoch,
                "head_object_id": head.head_object_id,
                "head_version": head.head_version
            }
        });
        let (status, created) = request(
            address,
            &format!("/v1/workspaces/{workspace_id}/branches"),
            branch_request.clone(),
        )
        .await;
        assert_eq!(
            status, 201,
            "non-destructive branch must be created over real TCP, not left at the missing route: {created}"
        );
        assert!(created.get("new_run_id").is_none(), "branch must not create a run");
        assert!(
            created.get("new_session_id").is_none(),
            "branch must not create a session"
        );
        assert_eq!(created["source"]["branch_id"], source_branch_id);
        assert_eq!(created["source"]["epoch"], head.epoch);
        assert_eq!(created["source"]["head_object_id"], head.head_object_id);
        assert_eq!(created["source"]["head_version"], head.head_version);
        assert_ne!(created["branch"]["branch_id"], source_branch_id);
        assert_eq!(created["branch"]["epoch"], head.epoch + 1);
        assert_eq!(created["branch"]["head_object_id"], frozen_root);
        assert_eq!(created["branch"]["head_version"], 1);
        assert_eq!(created["checkpoint_id"], checkpoint_id);
        assert_eq!(created["replayed"], false);
        let (status, replay) = request(
            address,
            &format!("/v1/workspaces/{workspace_id}/branches"),
            branch_request,
        )
        .await;
        assert_eq!(status, 201, "same proof must replay the durable receipt: {replay}");
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["branch"]["branch_id"], created["branch"]["branch_id"]);
        assert_eq!(replay["branch"]["epoch"], created["branch"]["epoch"]);
        assert_eq!(replay["checkpoint_id"], checkpoint_id);
        assert!(replay.get("new_run_id").is_none(), "replay must not create a run");
        let source_after = persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        assert_eq!(source_after.epoch, head.epoch);
        assert_eq!(source_after.head_object_id, head.head_object_id);
        assert_eq!(source_after.head_version, head.head_version);
        assert_eq!(source_after.branch_id, source_branch_id);
        assert_eq!(persistence.message_list(&session_id, 0).unwrap(), messages_before);
        assert!(!workspace.join("value.txt").exists());
    })
    .await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    service.halt();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match service.shutdown().await {
                Ok(()) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("owned worker and storage shutdown");
    drop(std::net::TcpListener::bind(address).expect("owned listener released"));
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_branch_run_uses_selected_branch() {
    let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-branch-run-{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for directory in [&root, &workspace, &home] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(
        home.join("config.yaml"),
        format!(
            "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",
            workspace.display(),
            workspace.display()
        ),
    )
    .unwrap();
    let mut config = AgentGatewayConfig {
        bearer_token: Some("synthetic-maintenance-fixture".into()),
        max_concurrent_runs: 1,
        managed_workspace: Some(ManagedWorkspaceConfig::for_workspace(&workspace).unwrap()),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy
        .create_checkpoint = true;
    config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy
        .branch = true;
    let state = AgentGatewayState::with_agent_selection_and_compaction(
        config,
        json!({}),
        Some(&root.join("gateway.sqlite")),
        rustscript_agent::config_file::CompactionSettings::default(),
    )
    .unwrap()
    .with_workspace_home(&home);
    let service = state.service();
    service
        .set_provider_profile(
            rustscript_agent::config::ProviderProfile::new(
                "frozen-profile",
                json!({"protocol":"provider","temperature":0.25,"max_output_tokens":1024}),
            )
            .unwrap(),
        )
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"", "tool_calls":[{"id":"write-a", "name":"write_file", "arguments":{"path":"value.txt", "content":"A"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
    provider.push_ok(json!({"text":"closed A", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
    let branch_provider = Arc::clone(&provider);
    branch_provider.push_ok(json!({"text":"", "tool_calls":[{"id":"read-a", "name":"read_file", "arguments":{"path":"value.txt"}}, {"id":"write-c", "name":"write_file", "arguments":{"path":"branch-only.txt", "content":"C"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
    branch_provider.push_ok(json!({"text":"closed C", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
    service.inject_provider_host(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let app = build_agent_gateway_app(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    let observed = Arc::clone(&service);
    let persistence = state.persistence().unwrap();
    let outcome = tokio::spawn(async move {
        let session_id = uuid::Uuid::new_v4().to_string();
        let (status, _) = request(address, "/api/sessions", json!({"id": session_id})).await;
        assert_eq!(status, 201);
        let (status, run) = request(
            address,
            "/v1/runs",
            json!({"input":"write A", "session_id": session_id, "provider":"frozen-profile"}),
        )
        .await;
        assert_eq!(status, 202, "source admission: {run}");
        let run_id = run["run_id"].as_str().unwrap().to_string();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if observed
                    .run_events(&run_id)
                    .iter()
                    .any(|event| event["event"] == "run.completed")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("source run completes");
        let record = persistence
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: ManagedOwnerScope {
                    profile: "gateway".into(),
                    session_id: session_id.clone(),
                    run_id: run_id.clone(),
                },
                call_id: "write-a".into(),
            })
            .unwrap()
            .unwrap();
        let workspace_id = record.identity.workspace.workspace_id.clone();
        let source_branch_id = record.identity.workspace.branch_id.clone();
        let head = persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        let (status, checkpoint) = request(
            address,
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch_id,
                "expected_epoch": record.identity.epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
        )
        .await;
        assert_eq!(status, 201, "checkpoint: {checkpoint}");
        let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
            .as_str()
            .unwrap()
            .to_string();
        let graph_id = checkpoint["checkpoint"]["graph"]["graph_id"]
            .as_str()
            .unwrap()
            .to_string();
        let branch_request = json!({
            "workspace_id": workspace_id,
            "source_branch_id": source_branch_id,
            "checkpoint_id": checkpoint_id,
            "request_id": uuid::Uuid::new_v4().to_string(),
            "expected_source": {
                "store_id": head.store_id,
                "workspace_id": workspace_id,
                "branch_id": source_branch_id,
                "epoch": head.epoch,
                "head_object_id": head.head_object_id,
                "head_version": head.head_version
            }
        });
        let (status, created) = request(
            address,
            &format!("/v1/workspaces/{workspace_id}/branches"),
            branch_request.clone(),
        )
        .await;
        assert_eq!(status, 201, "branch: {created}");
        let selected_branch = created["branch"]["branch_id"].as_str().unwrap().to_string();
        let unknown = format!("br-{}", "ab".repeat(16));
        let (status, missing) = request(
            address,
            "/v1/runs",
            json!({
                "input": "unknown branch must not grant",
                "session_id": session_id,
                "provider": "frozen-profile",
                "workspace_branch": unknown,
                "graph_id": graph_id
            }),
        )
        .await;
        assert_eq!(status, 404, "unknown branch id must not grant: {missing}");
        assert_eq!(missing["error"]["code"], "managed_branch_missing");
        observed.inject_provider_host(branch_provider);
        let (status, branch_run) = request(
            address,
            "/v1/runs",
            json!({
                "input": "write C on the selected branch",
                "session_id": session_id,
                "provider": "frozen-profile",
                "workspace_branch": selected_branch,
                "graph_id": graph_id
            }),
        )
        .await;
        assert_eq!(
            status, 202,
            "selected branch admission must be accepted: {branch_run}"
        );
        assert_eq!(
            branch_run["workspace_branch"], selected_branch,
            "typed workspace_branch must be the admitted branch: {branch_run}"
        );
        assert_eq!(
            branch_run["head_object_id"],
            created["branch"]["head_object_id"]
        );
        assert_eq!(
            branch_run["head_version"],
            created["branch"]["head_version"]
        );
        assert_eq!(branch_run["graph_id"], graph_id);
        assert!(branch_run["publication"].is_null());
        let mut conflict = branch_request.clone();
        conflict["expected_source"]["epoch"] = json!(head.epoch.saturating_add(9));
        let (status, conflicted) = request(
            address,
            &format!("/v1/workspaces/{workspace_id}/branches"),
            conflict,
        )
        .await;
        assert_eq!(status, 409, "different proof must conflict: {conflicted}");
        assert_eq!(conflicted["error"]["code"], "managed_request_conflict");
        let mut stale = branch_request.clone();
        stale["request_id"] = json!(uuid::Uuid::new_v4().to_string());
        stale["expected_source"]["head_object_id"] = json!(format!("obj-{}", "cd".repeat(16)));
        let (status, stale_body) = request(
            address,
            &format!("/v1/workspaces/{workspace_id}/branches"),
            stale,
        )
        .await;
        assert_eq!(
            status, 409,
            "current head CAS must reject a stale selector: {stale_body}"
        );
        assert_eq!(stale_body["error"]["code"], "managed_source_conflict");
        let branch_run_id = branch_run["run_id"].as_str().unwrap().to_string();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if observed
                    .run_events(&branch_run_id)
                    .iter()
                    .any(|event| event["event"] == "run.completed")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("selected branch run completes");
        let branch_write = persistence
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: ManagedOwnerScope {
                    profile: "gateway".into(),
                    session_id: session_id.clone(),
                    run_id: branch_run_id.clone(),
                },
                call_id: "write-c".into(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(branch_write.identity.workspace.branch_id, selected_branch);
        assert_ne!(branch_write.identity.workspace.branch_id, source_branch_id);
        let read_request = ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: branch_run_id,
            },
            call_id: "read-a".into(),
        };
        let rustscript_agent::effects::ManagedCallReplay::Final {
            canonical_result, ..
        } = observed.replay_managed_call(read_request).unwrap()
        else {
            panic!("selected branch must read the checkpoint tree");
        };
        let read_result: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(read_result["content"], "A");
        let source_after = persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        assert_eq!(source_after.branch_id, source_branch_id);
        assert_eq!(source_after.epoch, head.epoch);
        assert_eq!(source_after.head_object_id, head.head_object_id);
        assert!(!workspace.join("branch-only.txt").exists());
        assert!(!workspace.join("value.txt").exists());
        let mut selected_identity = record.identity.workspace.clone();
        selected_identity.branch_id = selected_branch;
        let selected_head = persistence
            .managed_workspace_head(&selected_identity)
            .unwrap();
        assert_ne!(selected_head.head_object_id, source_after.head_object_id);
    })
    .await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    service.halt();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match service.shutdown().await {
                Ok(()) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("owned worker and storage shutdown");
    drop(std::net::TcpListener::bind(address).expect("owned listener released"));
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_workspace_publish_is_a_durable_receipt_not_an_effect_commit() {
    let root = PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-publish-{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for directory in [&root, &workspace, &home] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(
        home.join("config.yaml"),
        format!(
            "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",
            workspace.display(),
            workspace.display()
        ),
    )
    .unwrap();
    let mut config = AgentGatewayConfig {
        bearer_token: Some("synthetic-maintenance-fixture".into()),
        max_concurrent_runs: 1,
        managed_workspace: Some(ManagedWorkspaceConfig::for_workspace(&workspace).unwrap()),
        ..Default::default()
    };
    config.approvals.write = "allow".into();
    config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy
        .publish = true;
    let reopened_config = config.clone();
    let state = AgentGatewayState::with_agent_selection_and_compaction(
        config,
        json!({}),
        Some(&root.join("gateway.sqlite")),
        rustscript_agent::config_file::CompactionSettings::default(),
    )
    .unwrap()
    .with_workspace_home(&home);
    let service = state.service();
    service
        .set_provider_profile(
            rustscript_agent::config::ProviderProfile::new(
                "frozen-profile",
                json!({"protocol":"provider","temperature":0.25,"max_output_tokens":1024}),
            )
            .unwrap(),
        )
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"", "tool_calls":[{"id":"write-a", "name":"write_file", "arguments":{"path":"value.txt", "content":"A"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
    provider.push_ok(json!({"text":"closed A", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
    service.inject_provider_host(provider.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let app = build_agent_gateway_app(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    let observed = Arc::clone(&service);
    let persistence = state.persistence().unwrap();
    let workspace_path = workspace.clone();
    let database = root.join("gateway.sqlite");
    let outcome = tokio::spawn(async move {
        let (status, anonymous) = post(
            address,
            "/v1/workspaces/ws-00000000000000000000000000000001/publish",
            json!({
                "workspace_id": "ws-00000000000000000000000000000001",
                "branch_id": "br-00000000000000000000000000000001",
                "request_id": uuid::Uuid::new_v4().to_string(),
                "expected_head": {
                    "workspace_id": "ws-00000000000000000000000000000001",
                    "branch_id": "br-00000000000000000000000000000001",
                    "epoch": 1,
                    "head_object_id": format!("obj-{}", "ab".repeat(16)),
                    "head_version": 1,
                    "store_id": format!("store-{}", "ab".repeat(16)),
                    "schema_version": 1,
                    "process_lineage_tainted": false
                }
            }),
            None,
        )
        .await;
        assert_eq!(
            status, 401,
            "missing bearer stays unauthorized: {anonymous}"
        );
        let session_id = uuid::Uuid::new_v4().to_string();
        let (status, _) = request(address, "/api/sessions", json!({"id": session_id})).await;
        assert_eq!(status, 201, "original HTTP session creation");
        let (status, run) = request(
            address,
            "/v1/runs",
            json!({"input":"write A", "session_id": session_id, "provider":"frozen-profile"}),
        )
        .await;
        assert_eq!(status, 202, "original HTTP admission: {run}");
        assert!(
            run["publication"].is_null(),
            "run projection is not a publication"
        );
        let run_id = run["run_id"].as_str().unwrap().to_string();
        wait_terminal(&observed, &run_id).await;
        let record = persistence
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: ManagedOwnerScope {
                    profile: "gateway".into(),
                    session_id: session_id.clone(),
                    run_id: run_id.clone(),
                },
                call_id: "write-a".into(),
            })
            .unwrap()
            .unwrap();
        let head = persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        let workspace_id = record.identity.workspace.workspace_id.clone();
        let branch_id = record.identity.workspace.branch_id.clone();
        let publish_path = format!("/v1/workspaces/{workspace_id}/publish");
        let request_id = uuid::Uuid::new_v4().to_string();
        let body = json!({
            "workspace_id": workspace_id,
            "branch_id": branch_id,
            "request_id": request_id,
            "expected_head": head
        });
        let (status, foreign) = request(
            address,
            "/v1/workspaces/ws-00000000000000000000000000000001/publish",
            body.clone(),
        )
        .await;
        assert_eq!(status, 403, "path/body workspace mismatch: {foreign}");
        assert_eq!(foreign["error"]["code"], "managed_authority_required");
        assert!(
            !foreign
                .to_string()
                .contains(&workspace_path.display().to_string())
        );
        let mut missing_head = body["expected_head"].clone();
        missing_head["branch_id"] = json!("br-00000000000000000000000000000001");
        let (status, missing) = request(
            address,
            &publish_path,
            json!({
                "workspace_id": workspace_id,
                "branch_id": "br-00000000000000000000000000000001",
                "request_id": uuid::Uuid::new_v4().to_string(),
                "expected_head": missing_head
            }),
        )
        .await;
        assert_eq!(status, 404, "missing branch: {missing}");
        assert_eq!(missing["error"]["code"], "managed_branch_missing");
        assert!(
            !missing
                .to_string()
                .contains(&workspace_path.display().to_string())
        );
        let mut extra = body.clone();
        extra["host_path"] = json!("/tmp/not-a-grant");
        let (status, rejected) = request(address, &publish_path, extra).await;
        assert_eq!(status, 422, "host path is not a publish grant: {rejected}");
        assert_eq!(rejected["error"]["code"], "managed_request_invalid");
        let messages_before = persistence.message_list(&session_id, 0).unwrap();
        let (status, published) = request(address, &publish_path, body.clone()).await;
        assert_eq!(
            status, 200,
            "explicit publish commits a receipt: {published}"
        );
        assert_eq!(published["status"], "committed");
        assert_eq!(published["workspace_id"], workspace_id);
        assert_eq!(published["branch_id"], branch_id);
        assert_eq!(published["epoch"], json!(head.epoch));
        assert_eq!(published["head_object_id"], head.head_object_id);
        assert_eq!(published["head_version"], json!(head.head_version));
        assert!(published["previous_published_head"].is_null());
        assert_eq!(published["request_id"], request_id);
        assert!(published["published_at_ms"].as_i64().unwrap_or(0) > 0);
        assert!(
            !published
                .to_string()
                .contains(&workspace_path.display().to_string())
        );
        let pointer = persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .unwrap()
            .expect("typed publication getter");
        assert_eq!(pointer.head_object_id, head.head_object_id);
        assert_eq!(pointer.head_version, head.head_version);
        assert_eq!(pointer.epoch, head.epoch);
        assert_eq!(pointer.request_id, request_id);
        assert!(pointer.previous_published_head.is_none());
        let head_after = persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        assert_eq!(head_after, head, "publish must not move the branch head");
        assert_eq!(
            persistence.message_list(&session_id, 0).unwrap(),
            messages_before
        );
        assert!(!workspace_path.join("value.txt").exists());
        let (status, replay) = request(address, &publish_path, body.clone()).await;
        assert_eq!(status, 200, "same proof replays the receipt: {replay}");
        assert_eq!(replay, published);
        let mut conflict = body.clone();
        conflict["expected_head"]["epoch"] = json!(head.epoch.saturating_add(1));
        let (status, conflicted) = request(address, &publish_path, conflict).await;
        assert_eq!(status, 409, "different proof conflicts: {conflicted}");
        assert_eq!(conflicted["error"]["code"], "managed_request_conflict");
        let next = Arc::new(ScriptedProvider::new());
        next.push_ok(json!({"text":"", "tool_calls":[{"id":"write-c", "name":"write_file", "arguments":{"path":"other.txt", "content":"C"}}], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"tool_calls"}));
        next.push_ok(json!({"text":"closed C", "tool_calls":[], "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}, "reasoning":"", "stop_reason":"stop"}));
        observed.inject_provider_host(next);
        let (status, advanced_run) = request(
            address,
            "/v1/runs",
            json!({"input":"write C", "session_id": session_id, "provider":"frozen-profile"}),
        )
        .await;
        assert_eq!(status, 202, "head-advancing admission: {advanced_run}");
        assert!(
            advanced_run["publication"].is_null(),
            "a later run is not the publication"
        );
        let advanced_id = advanced_run["run_id"].as_str().unwrap().to_string();
        wait_terminal(&observed, &advanced_id).await;
        let advanced_head = persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        assert_ne!(
            (
                advanced_head.head_object_id.as_str(),
                advanced_head.head_version
            ),
            (head.head_object_id.as_str(), head.head_version),
            "the later write must move the branch head before the stale publish"
        );
        let (status, replay_after) = request(address, &publish_path, body.clone()).await;
        assert_eq!(
            status, 200,
            "replay stays immutable after the head moves: {replay_after}"
        );
        assert_eq!(replay_after, published);
        let still = persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .unwrap()
            .unwrap();
        assert_eq!(still.head_object_id, head.head_object_id);
        let mut stale = body.clone();
        stale["request_id"] = json!(uuid::Uuid::new_v4().to_string());
        let (status, stale_body) = request(address, &publish_path, stale).await;
        assert_eq!(status, 409, "old head is not republished: {stale_body}");
        assert_eq!(stale_body["error"]["code"], "managed_source_conflict");
        assert_eq!(
            persistence
                .managed_workspace_publication(&workspace_id, "gateway")
                .unwrap()
                .unwrap()
                .head_object_id,
            head.head_object_id
        );
        provider.push_hang();
        let (status, busy_run) = request(
            address,
            "/v1/runs",
            json!({"input":"hold the writer", "session_id": session_id, "provider":"frozen-profile"}),
        )
        .await;
        assert_eq!(status, 202, "busy writer admission: {busy_run}");
        let mut current = body.clone();
        current["request_id"] = json!(uuid::Uuid::new_v4().to_string());
        current["expected_head"] = json!(advanced_head);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (status, busy) = request(address, &publish_path, current.clone()).await;
                if status == 409 && busy["error"]["code"] == "managed_checkpoint_busy" {
                    return;
                }
                assert_ne!(status, 200, "active run must not publish: {busy}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("active writer blocks publication");
        (workspace_id, body, published)
    });
    let (workspace_id, body, published) = match outcome.await {
        Ok(value) => value,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    };
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    service.halt();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match service.shutdown().await {
                Ok(()) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("owned worker and storage shutdown");
    drop(std::net::TcpListener::bind(address).expect("owned listener released"));
    drop(service);
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(reopened_config, &database)
        .unwrap()
        .with_workspace_home(&home);
    let reopened_service = reopened.service();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let app = build_agent_gateway_app(reopened.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    let persistence = reopened.persistence().unwrap();
    let replayed = request(
        address,
        &format!("/v1/workspaces/{workspace_id}/publish"),
        body,
    )
    .await;
    assert_eq!(
        replayed.0, 200,
        "reopened same proof returns the original receipt: {}",
        replayed.1
    );
    assert_eq!(replayed.1, published);
    let pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .unwrap()
        .unwrap();
    assert_eq!(pointer.request_id, published["request_id"]);
    assert_eq!(pointer.head_object_id, published["head_object_id"]);
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    reopened_service.halt();
    reopened_service.shutdown().await.unwrap();
}

async fn wait_terminal(service: &rustscript_agent::AgentService, run_id: &str) {
    let run_id = run_id.to_string();
    tokio::time::timeout(Duration::from_secs(20), async move {
        loop {
            if service.run_events(&run_id).iter().any(|event| {
                matches!(
                    event["event"].as_str(),
                    Some("run.completed" | "run.failed" | "run.cancelled")
                )
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("run reaches a terminal event");
}
