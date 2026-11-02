//! Deterministic typed-producer fixtures; real Native HTTP production is covered separately.
use super::*;
use crate::effects::journal::*;
use http_body_util::{BodyExt, Full};
use std::time::Duration;

async fn get(state: AgentGatewayState, path: String) -> (u16, Value) {
    let token = state.service().inner.config.bearer_token.clone().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            crate::build_agent_gateway_app(state)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    let result = tokio::spawn(async move {
        let client: hyper_util::client::legacy::Client<_, Full<bytes::Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let request = hyper::Request::get(format!("http://{address}{path}"))
            .header(hyper::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Full::new(bytes::Bytes::new()))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(10), client.request(request))
            .await
            .unwrap()
            .unwrap();
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    })
    .await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(std::net::TcpListener::bind(address).unwrap());
    result.unwrap_or_else(|error| std::panic::resume_unwind(error.into_panic()))
}
async fn admit(state: &AgentGatewayState) -> crate::AdmittedRun {
    state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"typed ordered fixture"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
}
fn binding(
    state: &AgentGatewayState,
    run: &crate::AdmittedRun,
) -> Arc<crate::effects::broker::ManagedRunBinding> {
    state
        .service()
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .clone()
        .unwrap()
}
fn seed(state: &AgentGatewayState, run: &crate::AdmittedRun, index: usize) -> ManagedEffectSummary {
    seed_identity(state, run, index, |_| {})
}
fn seed_identity(
    state: &AgentGatewayState,
    run: &crate::AdmittedRun,
    index: usize,
    change: impl FnOnce(&mut ManagedCallIdentity),
) -> ManagedEffectSummary {
    let host = state
        .service()
        .capability_host_bridges(&run.run_id)
        .unwrap()
        .unwrap();
    let deadline = host.lifecycle.as_ref().unwrap().original_deadline_ms();
    let binding = binding(state, run);
    let args = r#"{"path":"never-executed.txt"}"#;
    let call = binding
        .register(
            &format!("ordered-{index}"),
            "read_file",
            args,
            binding
                .seal_call_policy("read_file", crate::capabilities::CapabilityRisk::Read, args)
                .unwrap(),
            deadline,
        )
        .unwrap();
    let mut record = call.record();
    record.effect_id = format!("effect-{index:032x}");
    change(&mut record.identity);
    let event = |suffix: &str, seq: usize| json!({"event_id":format!("ordered-{index}-{suffix}"),"event_type":format!("tool.{suffix}"),"seq":seq,"payload_json":"{}","created_at_ms":crate::domain::timestamp()});
    let projections = json!({"normal":{"output":event("requested",100+index*2),"terminal":event("started",101+index*2)}});
    binding.runtime.repository.command_with_cancellation("effect.begin",&json!({"effect_id":record.effect_id,"run_id":run.run_id,"call_id":record.identity.call_id,"workspace_id":record.identity.workspace.workspace_id,"branch_id":record.identity.workspace.branch_id,"record_json":serde_json::to_string(&record).unwrap(),"commit_id":call.receipt_id,"sealed_class":call.policy.class().as_str(),"projections_json":projections.to_string()}),&binding.cancel).unwrap();
    call.interrupt_unpublished();
    let stored = state
        .persistence()
        .unwrap()
        .managed_effect_by_id(&record.effect_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.effect_id, record.effect_id);
    ManagedEffectSummary {
        effect_id: record.effect_id,
        run_id: run.run_id.clone(),
        call_id: record.identity.call_id,
        state: ManagedPublicationStatus::Indeterminate,
        workspace_id: record.identity.workspace.workspace_id,
        branch_id: record.identity.workspace.branch_id,
        epoch: record.identity.epoch,
        prepared_at_ms: None,
        decided_at_ms: None,
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn journal_owner_run_identity_is_scoped_before_page_limit() {
    let (_root, state) = authenticated_fixture();
    let run = admit(&state).await;
    let foreign = admit(&state).await;
    seed_identity(&state, &run, 0, |identity| {
        identity.owner.run_id = foreign.run_id.clone()
    });
    let expected = seed(&state, &run, 1);
    let result = get(
        state.clone(),
        format!("/v1/runs/{}/effects?limit=1", run.run_id),
    )
    .await;
    state.service().shutdown().await.unwrap();
    assert_eq!(
        result,
        (
            200,
            serde_json::to_value(ManagedEffectPage {
                entries: vec![expected],
                next_cursor: None,
                has_more: false
            })
            .unwrap()
        ),
        "column run ID cannot substitute for the original journal owner"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_and_missing_cursors_are_denied_even_for_empty_runs() {
    let (_root, state) = authenticated_fixture();
    let target = admit(&state).await;
    let foreign = admit(&state).await;
    let empty = admit(&state).await;
    let own = seed(&state, &target, 1);
    let other = seed(&state, &foreign, 2);
    let mut results = Vec::new();
    for run in [&target.run_id, &empty.run_id] {
        for cursor in [&other.effect_id, "effect-ffffffffffffffffffffffffffffffff"] {
            results.push(
                get(
                    state.clone(),
                    format!("/v1/runs/{run}/effects?after_effect_id={cursor}"),
                )
                .await,
            );
        }
    }
    let empty_page = get(state.clone(), format!("/v1/runs/{}/effects", empty.run_id)).await;
    let end = get(
        state.clone(),
        format!(
            "/v1/runs/{}/effects?after_effect_id={}",
            target.run_id, own.effect_id
        ),
    )
    .await;
    state.service().shutdown().await.unwrap();
    for result in results {
        assert_eq!(
            result,
            (
                403,
                json!({"error":{"code":"managed_effects_unavailable","message":"managed_effects_unavailable"}})
            ),
            "cursor existence must not bypass exact run scope"
        );
    }
    for page in [empty_page, end] {
        assert_eq!(
            page,
            (
                200,
                json!({"entries":[],"next_cursor":null,"has_more":false})
            )
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn native_source_is_revalidated_after_page_read_without_existence_disclosure() {
    let (root, state) = authenticated_fixture();
    let run = admit(&state).await;
    seed(&state, &run, 1);
    let source = root.join("workspace");
    let moved = root.join("retired-source");
    let p = state.persistence().unwrap();
    *p.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueued| {
        if op == "effect.run_list" && !enqueued {
            fs::rename(&source, &moved).unwrap();
            fs::create_dir(&source).unwrap();
        }
    }));
    let result = get(state.clone(), format!("/v1/runs/{}/effects", run.run_id)).await;
    *p.managed_request_hook.lock().unwrap() = None;
    state.service().shutdown().await.unwrap();
    assert_eq!(
        result,
        (
            403,
            json!({"error":{"code":"managed_effects_unavailable","message":"managed_effects_unavailable"}})
        ),
        "replaced source cannot use a previously acquired query authority"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_run_effect_query_returns_static_timeout() {
    let (_root, state) = authenticated_fixture();
    let run = admit(&state).await;
    let p = state.persistence().unwrap();
    *p.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, cancel, enqueued| {
        if op == "effect.run_list" && !enqueued {
            cancel.request(crate::CancellationReason::Requested);
        }
    }));
    let result = get(state.clone(), format!("/v1/runs/{}/effects", run.run_id)).await;
    *p.managed_request_hook.lock().unwrap() = None;
    state.service().shutdown().await.unwrap();
    assert_eq!(
        result,
        (
            408,
            json!({"error":{"code":"managed_query_cancelled","message":"managed_query_cancelled"}})
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn formal_wrong_profile_and_binding_scopes_share_static_denial() {
    let (root, state) = authenticated_fixture();
    let capture = Arc::new(std::sync::Mutex::new(Value::Null));
    let observed = capture.clone();
    state
        .persistence()
        .unwrap()
        .inject_admission_precommit_hook(move |payload| {
            *observed.lock().unwrap() = payload.clone();
        });
    let run = admit(&state).await;
    let original = capture.lock().unwrap().clone();
    let p = state.persistence().unwrap();
    let mut results = Vec::new();
    for case in ["profile", "session", "workspace", "branch"] {
        let mut payload = original.clone();
        let id = uuid::Uuid::new_v4().to_string();
        let session = uuid::Uuid::new_v4().to_string();
        for (key, value) in [
            ("run_id", id.as_str()),
            ("session_id", session.as_str()),
            ("message_id", id.as_str()),
            ("message_run_id", id.as_str()),
            ("event_id", id.as_str()),
            ("tool_graph_id", ""),
            ("tool_ref_id", ""),
            ("idempotency_key", ""),
        ] {
            payload[key] = json!(value);
        }
        payload["session_new"] = json!(1);
        payload["account_id"] = json!(id);
        let mut foreign = binding(&state, &run).workspace.clone();
        foreign.identity.workspace_id = format!("ws-{}", uuid::Uuid::new_v4().simple());
        foreign.identity.branch_id = format!("br-{}", uuid::Uuid::new_v4().simple());
        if case == "profile" {
            foreign.profile = "foreign-profile".into();
        }
        let path = root.join(format!("foreign-{case}"));
        fs::create_dir(&path).unwrap();
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).unwrap();
        foreign.identity.source_identity = DirectoryIdentity {
            device_decimal: metadata.dev().to_string(),
            inode_decimal: metadata.ino().to_string(),
        };
        p.managed_effect_command("effect.workspace_register",&json!({"workspace_json":serde_json::to_string(&foreign).unwrap(),"store_id":foreign.identity.store_id,"profile":foreign.profile,"source_device":foreign.identity.source_identity.device_decimal,"source_inode":foreign.identity.source_identity.inode_decimal})).unwrap();
        let mut binding: Value =
            serde_json::from_str(payload["managed_binding_json"].as_str().unwrap()).unwrap();
        binding["session_id"] = json!(session);
        match case {
            "profile" => {
                payload["profile"] = json!("foreign-profile");
                binding["workspace_id"] = json!(foreign.identity.workspace_id);
                binding["branch_id"] = json!(foreign.identity.branch_id);
            }
            "session" => binding["session_id"] = json!(run.session_id),
            "workspace" | "branch" => {
                binding["workspace_id"] = json!(foreign.identity.workspace_id);
                binding["branch_id"] = json!(foreign.identity.branch_id);
            }
            _ => unreachable!(),
        }
        payload["managed_binding_json"] = json!(binding.to_string());
        p.admission_create(&payload).unwrap();
        assert!(
            !p.run_get(&id).unwrap()["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        results.push(get(state.clone(), format!("/v1/runs/{id}/effects")).await);
    }
    state.service().shutdown().await.unwrap();
    for result in results {
        assert_eq!(
            result,
            (
                403,
                json!({"error":{"code":"managed_effects_unavailable","message":"managed_effects_unavailable"}})
            )
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn storage_failure_run_effect_query_uses_only_static_fields() {
    let (_root, state) = authenticated_fixture();
    let run = admit(&state).await;
    state.persistence().unwrap().inject_persist_failure();
    let result = get(state.clone(), format!("/v1/runs/{}/effects", run.run_id)).await;
    state.service().shutdown().await.unwrap();
    assert_eq!(
        result,
        (
            503,
            json!({"error":{"code":"managed_storage_unavailable","message":"managed_storage_unavailable"}})
        )
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn terminal_retired_source_and_restored_run_remain_read_only_historical_queries() {
    let (_root, state, source) = super::protocol::maintenance_source().await;
    let service = state.service();
    let p = state.persistence().unwrap();
    // Deterministic nonzero usage through the existing formal typed fixture seam.
    p.record_synthetic_usage_for_test(&source.source_run_id)
        .unwrap();
    let request = super::protocol::restore_request(&state, &source).await;
    let old = get(
        state.clone(),
        format!("/v1/runs/{}/effects", source.source_run_id),
    )
    .await;
    let restored = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await
        .unwrap();
    let snapshot = || {
        json!({
            "activation":p.plugin_control_command("plugin.activation_get",&json!({})).unwrap(),
            "activation_history":p.plugin_control_command("plugin.activation_history",&json!({})).unwrap(),
            "source":p.run_get(&source.source_run_id).unwrap(),
            "restored":p.run_get(&restored.new_run_id).unwrap(),
            "messages":p.message_list(&restored.new_session_id,0).unwrap(),
            "source_events":service.run_events(&source.source_run_id),
            "head":p.managed_workspace_head(&ManagedWorkspaceIdentity {store_id:request.expected_source.store_id.clone(),workspace_id:source.workspace_id.clone(),branch_id:source.source_branch_id.clone(),source_identity:DirectoryIdentity {device_decimal:"unused-for-head".into(),inode_decimal:"unused-for-head".into()}}).unwrap(),
            "clock":service.run_context(&source.source_run_id).unwrap().metadata["deadline_at_ms"],
            "source_context":service.run_context(&source.source_run_id).unwrap(),
            "closed_inventory":service.managed_runtime_for_test().unwrap().repository.checkpoint_context(&source,&crate::RunCancellation::with_timeout(Duration::from_secs(5))).unwrap(),
        })
    };
    let before = snapshot();
    assert!(
        before["closed_inventory"]["external"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["provider_request_count"].as_u64().unwrap() > 0),
        "formal nonzero provider usage fixture"
    );
    let historical = get(
        state.clone(),
        format!("/v1/runs/{}/effects", source.source_run_id),
    )
    .await;
    let fresh = get(
        state.clone(),
        format!("/v1/runs/{}/effects", restored.new_run_id),
    )
    .await;
    let after = snapshot();
    service.shutdown().await.unwrap();
    assert_eq!(old.0, 200);
    assert_eq!(
        historical, old,
        "retired source stays queryable under fresh Native authorization"
    );
    assert_eq!(
        fresh,
        (
            200,
            json!({"entries":[],"next_cursor":null,"has_more":false})
        )
    );
    assert_eq!(
        before, after,
        "queries cannot revive execution, change activation/head or erase retained history"
    );
}

fn authenticated_fixture() -> (PathBuf, AgentGatewayState) {
    fixture_config(|config| {
        config.bearer_token = Some(uuid::Uuid::new_v4().to_string());
        config.max_concurrent_runs = 8;
    })
}
#[tokio::test(flavor = "multi_thread")]
async fn ordered_interleaved_run_pages_filter_before_limit_and_has_more() {
    let (_root, state) = authenticated_fixture();
    let target = admit(&state).await;
    let foreign = admit(&state).await;
    seed(&state, &foreign, 0);
    let first = seed(&state, &target, 1);
    seed(&state, &foreign, 2);
    let last = seed(&state, &target, 3);
    seed(&state, &foreign, 4);
    let a = get(
        state.clone(),
        format!("/v1/runs/{}/effects?limit=1", target.run_id),
    )
    .await;
    let b = get(
        state.clone(),
        format!(
            "/v1/runs/{}/effects?limit=1&after_effect_id={}",
            target.run_id, first.effect_id
        ),
    )
    .await;
    state.service().shutdown().await.unwrap();
    assert_eq!(a.0, 200);
    assert_eq!(b.0, 200);
    assert_eq!(
        a.1,
        serde_json::to_value(ManagedEffectPage {
            entries: vec![first.clone()],
            next_cursor: Some(first.effect_id),
            has_more: true
        })
        .unwrap()
    );
    assert_eq!(
        b.1,
        serde_json::to_value(ManagedEffectPage {
            entries: vec![last],
            next_cursor: None,
            has_more: false
        })
        .unwrap()
    );
}
