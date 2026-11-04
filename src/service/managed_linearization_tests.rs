//! Actual maintenance request linearization and original-clock boundaries.
// Provider fixtures return synthetic typed responses through the actual durable
// provider request/step/failure producer; no storage outcome is substituted.
use super::*;
use crate::effects::journal::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn management_restore_busy_is_typed_at_actual_http_boundary() {
    let (state, _source, request) = race_source(2).await;
    let service = state.service();
    let gate = Arc::new(Latch::default());
    let release = LatchRelease(gate.clone());
    let observer = gate.clone();
    service.inject_prompt_read_entered_observer(Arc::new(move || observer.arrive()));
    let mut rival = request.clone();
    rival.request_id = uuid::Uuid::new_v4().to_string();
    let first_service = service.clone();
    let first = tokio::spawn(async move {
        first_service
            .restore_managed_checkpoint_and_admit(request)
            .await
    });
    gate.wait(1); // real restore has closed SOURCE and entered original prompt preparation
    let results = http_denials(
        state.clone(),
        vec![(
            format!("/v1/workspaces/{}/restore", rival.workspace_id),
            serde_json::to_value(&rival).unwrap(),
        )],
    )
    .await;
    drop(release);
    let winner = first.await.unwrap();
    *service.inner.prompt_read_entered.lock().unwrap() = None;
    let rt = service.managed_runtime_for_test().unwrap();
    let loser_absent = rt
        .repository
        .lookup_restore_receipt(&rival, &read_clock())
        .unwrap()
        .is_none();
    service.shutdown().await.unwrap();
    assert!(winner.is_ok());
    assert!(loser_absent);
    assert_eq!(
        results[0].0, 409,
        "HTTP restore contention retains its typed busy classification"
    );
    assert_eq!(results[0].1["error"]["code"], "managed_restore_busy");
    assert_eq!(results[0].1["error"]["message"], "managed_restore_busy");
}

async fn http_denials(state: AgentGatewayState, cases: Vec<(String, Value)>) -> Vec<(u16, Value)> {
    http_inputs(
        state,
        cases
            .into_iter()
            .map(|(path, body)| HttpInput {
                path,
                body: body.to_string(),
                content_type: Some("application/json"),
                authenticated: true,
            })
            .collect(),
    )
    .await
    .into_iter()
    .map(|(status, body)| (status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
    .collect()
}

struct HttpInput {
    path: String,
    body: String,
    content_type: Option<&'static str>,
    authenticated: bool,
}

async fn http_inputs(state: AgentGatewayState, cases: Vec<HttpInput>) -> Vec<(u16, Vec<u8>)> {
    use http_body_util::{BodyExt, Full};
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
        let mut results = Vec::new();
        for input in cases {
            let mut req = hyper::Request::post(format!("http://{address}{}", input.path));
            if let Some(content_type) = input.content_type {
                req = req.header("content-type", content_type);
            }
            if input.authenticated {
                req = req.header("authorization", "Bearer synthetic-maintenance-fixture");
            }
            let req = req.body(Full::new(bytes::Bytes::from(input.body))).unwrap();
            let response = client.request(req).await.unwrap();
            let status = response.status().as_u16();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            results.push((status, bytes.to_vec()));
        }
        results
    })
    .await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(std::net::TcpListener::bind(address).expect("owned management socket released"));
    match result {
        Ok(result) => result,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}
// Each case uses the production router, its configured DefaultBodyLimit and
// actual authenticated sockets. Unknown keys below prove schema rejection only.
#[derive(Clone, Copy, Debug)]
enum JsonRefusal {
    Syntax,
    MissingContentType,
    NonJsonContentType,
    UnknownField,
    WrongType,
    OverLimit,
    MissingAuthorization,
}

fn management_refusal_snapshot(
    state: &AgentGatewayState,
    source: &ManagedCheckpointCreateRequest,
    restore: &ManagedRestoreAndAdmitRequest,
) -> Value {
    let service = state.service();
    let rt = service.managed_runtime_for_test().unwrap();
    let context = rt
        .repository
        .checkpoint_context(source, &read_clock())
        .unwrap();
    let memory = service.inner.store.read();
    let mut runs = memory.runs.keys().cloned().collect::<Vec<_>>();
    let mut sessions = memory.sessions.keys().cloned().collect::<Vec<_>>();
    runs.sort();
    sessions.sort();
    drop(memory);
    json!({
        "durable_context": context,
        "checkpoint_receipt": rt.repository.checkpoint_receipt(source, &read_clock(), None).unwrap(),
        "restore_receipt": rt.repository.lookup_restore_receipt(restore, &read_clock()).unwrap(),
        "memory_runs": runs,
        "memory_sessions": sessions,
        "source_events": service.run_events(&source.source_run_id),
        "maintenance_attempts": service.inner.maintenance_attempts.lock().len(),
    })
}

async fn json_refusal_at_both_routes(case: JsonRefusal, expected_status: u16) {
    let (state, mut source, mut restore) = race_source(2).await;
    let service = state.service();
    const PRIVATE_MARKER: &str = "PRIVATE_JSON_REFUSAL_161";
    source.request_id = format!("{PRIVATE_MARKER}-{}", uuid::Uuid::new_v4());
    restore.request_id = format!("{PRIVATE_MARKER}-{}", uuid::Uuid::new_v4());
    let outcome = tokio::spawn(async move {
        let mut statuses = Vec::new();
        for (path, mut body) in action_cases(&source, &restore, &source.workspace_id) {
            let before = management_refusal_snapshot(&state, &source, &restore);
            assert!(before["checkpoint_receipt"].is_null());
            assert!(before["restore_receipt"].is_null());
            let mut content_type = Some("application/json");
            match case {
                JsonRefusal::MissingContentType => content_type = None,
                JsonRefusal::NonJsonContentType => content_type = Some("text/plain"),
                JsonRefusal::UnknownField => body["workspace_path"] = json!(PRIVATE_MARKER),
                JsonRefusal::WrongType => body["source_branch_id"] = json!({"private":PRIVATE_MARKER}),
                _ => {}
            }
            let mut body = body.to_string();
            if matches!(case, JsonRefusal::Syntax) {
                body = format!("{{\"workspace_id\":\"{PRIVATE_MARKER}\",");
            }
            if matches!(case, JsonRefusal::OverLimit) {
                // Valid JSON plus legal trailing whitespace: only the actual
                // production DefaultBodyLimit can account for this rejection.
                body.push_str(&" ".repeat(state.service().config().max_body_bytes + 1));
                assert!(body.len() > state.service().config().max_body_bytes);
            }
            let results = http_inputs(state.clone(), vec![HttpInput {
                path: path.clone(), body, content_type,
                authenticated: !matches!(case, JsonRefusal::MissingAuthorization),
            }]).await;
            let after = management_refusal_snapshot(&state, &source, &restore);
            assert_eq!(after, before, "{case:?} {path}: typed head/current branch, history, journal, receipts and memory unchanged");
            let (status, response) = &results[0];
            let expected = if matches!(case, JsonRefusal::MissingAuthorization) {
                json!({"error":{"code":"unauthorized","message":"missing or invalid bearer token"}})
            } else {
                json!({"error":{"code":"managed_request_invalid","message":"managed_request_invalid"}})
            };
            assert_eq!(response, expected.to_string().as_bytes(), "{case:?} {path}: exact static response");
            assert!(!String::from_utf8_lossy(response).contains(PRIVATE_MARKER));
            println!("{case:?} {}: HTTP {status}; exact static body and typed no-partial-state verified", path.rsplit('/').next().unwrap());
            statuses.push(*status);
        }
        assert_eq!(statuses, vec![expected_status; 2], "{case:?}: each existing route preserves extractor status");
    }).await;
    service.shutdown().await.unwrap();
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn management_json_rejection_syntax_400() {
    json_refusal_at_both_routes(JsonRefusal::Syntax, 400).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn management_json_rejection_missing_content_type_415() {
    json_refusal_at_both_routes(JsonRefusal::MissingContentType, 415).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn management_json_rejection_non_json_content_type_415() {
    json_refusal_at_both_routes(JsonRefusal::NonJsonContentType, 415).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn management_json_rejection_unknown_field_422() {
    json_refusal_at_both_routes(JsonRefusal::UnknownField, 422).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn management_json_rejection_wrong_type_422() {
    json_refusal_at_both_routes(JsonRefusal::WrongType, 422).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn management_json_rejection_configured_body_limit_413() {
    json_refusal_at_both_routes(JsonRefusal::OverLimit, 413).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn management_configured_bearer_missing_authorization_401() {
    json_refusal_at_both_routes(JsonRefusal::MissingAuthorization, 401).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn management_json_and_suffix_media_types_reach_existing_business_routes() {
    for content_type in ["application/json", "application/vnd.maintenance+json"] {
        let (state, source, restore) = race_source(2).await;
        let service = state.service();
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(None));
        service.inject_provider_host(provider);
        let observed = service.clone();
        let outcome = tokio::spawn(async move {
            let results = http_inputs(
                state.clone(),
                action_cases(&source, &restore, &source.workspace_id)
                    .into_iter()
                    .map(|(path, body)| HttpInput {
                        path,
                        body: body.to_string(),
                        content_type: Some(content_type),
                        authenticated: true,
                    })
                    .collect(),
            )
            .await;
            assert_eq!(
                results[0].0, 201,
                "{content_type}: original checkpoint receipt"
            );
            assert_eq!(
                results[1].0, 202,
                "{content_type}: original restore admission"
            );
            let receipt: Value = serde_json::from_slice(&results[1].1).unwrap();
            let new_run = receipt["new_run_id"].as_str().unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                while !observed
                    .run_events(new_run)
                    .iter()
                    .any(|e| e["event"] == "run.completed")
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let rt = observed.managed_runtime_for_test().unwrap();
            assert!(
                rt.repository
                    .checkpoint_receipt(&source, &read_clock(), None)
                    .unwrap()
                    .is_some()
            );
            let durable = rt
                .repository
                .lookup_restore_receipt(&restore, &read_clock())
                .unwrap()
                .unwrap();
            assert_eq!(durable.new_run_id, new_run);
        })
        .await;
        service.shutdown().await.unwrap();
        if let Err(error) = outcome {
            std::panic::resume_unwind(error.into_panic());
        }
    }
}

fn action_cases(
    source: &ManagedCheckpointCreateRequest,
    restore: &ManagedRestoreAndAdmitRequest,
    path_workspace: &str,
) -> Vec<(String, Value)> {
    vec![
        (
            format!("/v1/workspaces/{path_workspace}/checkpoints"),
            serde_json::to_value(source).unwrap(),
        ),
        (
            format!("/v1/workspaces/{path_workspace}/restore"),
            serde_json::to_value(restore).unwrap(),
        ),
    ]
}
fn assert_static_denial(status: u16, body: &Value) {
    assert!(
        matches!(status, 400 | 401 | 403 | 409 | 422 | 503),
        "management route must explicitly reject, never route-absent 404 or success: {status}"
    );
    let code = body["error"]["code"]
        .as_str()
        .expect("static redacted management error code");
    assert!(matches!(
        code,
        "managed_authority_required"
            | "managed_management_denied"
            | "managed_source_conflict"
            | "managed_request_invalid"
            | "managed_storage_unavailable"
    ));
    assert_eq!(body["error"]["message"], code);
}

#[tokio::test(flavor = "multi_thread")]
async fn management_routes_fail_closed_scope_matrix() {
    let (state, mut source, restore) = race_source(2).await;
    let service = state.service();
    let rt = service.managed_runtime_for_test().unwrap();
    source.request_id = uuid::Uuid::new_v4().to_string();
    let before = rt
        .repository
        .checkpoint_context(&source, &read_clock())
        .unwrap();
    let before_runs = service.inner.store.read().runs.len();
    let before_sessions = service.inner.store.read().sessions.len();
    let other = format!("ws-{}", uuid::Uuid::new_v4().simple());
    let mut cases = action_cases(&source, &restore, &other); // mismatched path/body identity
    let mut cross = source.clone();
    cross.workspace_id = other.clone();
    let mut cross_restore = restore.clone();
    cross_restore.workspace_id = other.clone();
    cross_restore.expected_source.workspace_id = other.clone();
    cases.extend(action_cases(&cross, &cross_restore, &other));
    let (other_state, foreign_source, _) = race_source(1).await;
    let mut foreign = source.clone();
    foreign.source_run_id = foreign_source.source_run_id;
    cases.push((
        format!("/v1/workspaces/{}/checkpoints", source.workspace_id),
        serde_json::to_value(foreign).unwrap(),
    ));
    for field in ["profile", "owner", "authority", "workspace_path"] {
        for (path, mut body) in action_cases(&source, &restore, &source.workspace_id) {
            body[field] = json!("synthetic-untrusted-scope-value");
            cases.push((path, body));
        }
    }
    let results = http_denials(state.clone(), cases).await;
    let after = rt
        .repository
        .checkpoint_context(&source, &read_clock())
        .unwrap();
    let absent = rt
        .repository
        .checkpoint_receipt(&source, &read_clock(), None)
        .unwrap()
        .is_none();
    let restore_absent = rt
        .repository
        .lookup_restore_receipt(&restore, &read_clock())
        .unwrap()
        .is_none();
    let after_runs = service.inner.store.read().runs.len();
    let after_sessions = service.inner.store.read().sessions.len();
    service.shutdown().await.unwrap();
    other_state.service().shutdown().await.unwrap();
    assert_eq!(results.len(), 13);
    for (index, (status, body)) in results.into_iter().enumerate() {
        let (expected_status, code) = if index < 5 {
            // Path/body mismatch and real foreign workspace/run identity.
            (403, "managed_authority_required")
        } else {
            // Additional profile/owner/path keys are DTO schema errors only.
            (422, "managed_request_invalid")
        };
        assert_eq!(status, expected_status, "scope matrix case {index}");
        assert_eq!(body, json!({"error":{"code":code,"message":code}}));
    }
    assert_eq!(before.head, after.head);
    assert!(absent && restore_absent);
    assert_eq!(before_runs, after_runs);
    assert_eq!(before_sessions, after_sessions);
}

#[tokio::test(flavor = "multi_thread")]
async fn management_routes_fail_closed_policy_native_and_nonmanaged_entries() {
    let (source_state, source, restore) = race_source(1).await;
    let (_root, policy_state) = fixture_config(|config| {
        config.bearer_token = Some("synthetic-maintenance-fixture".into());
    });
    let (root, native_state) = fixture_config(management_config);
    let denied_home = root.join("no-workspace-policy");
    fs::create_dir(&denied_home).unwrap();
    let native_state = native_state.with_workspace_home(denied_home);
    let direct = AgentGatewayState::new(AgentGatewayConfig {
        bearer_token: Some("synthetic-maintenance-fixture".into()),
        ..Default::default()
    })
    .unwrap();
    let mut results = Vec::new();
    for state in [&policy_state, &native_state, &direct] {
        let service = state.service();
        let before_runs = service.inner.store.read().runs.len();
        let before_sessions = service.inner.store.read().sessions.len();
        results.extend(
            http_denials(
                state.clone(),
                action_cases(&source, &restore, &source.workspace_id),
            )
            .await,
        );
        assert_eq!(service.inner.store.read().runs.len(), before_runs);
        assert_eq!(service.inner.store.read().sessions.len(), before_sessions);
        // CLI/import/stateless embeddings have no management HTTP surface of
        // their own: call the original Native service owner, never invent a route.
        assert!(
            service
                .create_managed_checkpoint(source.clone())
                .await
                .is_err()
        );
        assert!(
            service
                .restore_managed_checkpoint_and_admit(restore.clone())
                .await
                .is_err()
        );
        assert_eq!(service.inner.store.read().runs.len(), before_runs);
        service.shutdown().await.unwrap();
    }
    // Ordinary nonmanaged operation remains usable in the same default direct
    // embedding after management denial.
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    let ordinary_state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
    let ordinary_service = ordinary_state.service();
    ordinary_service.inject_provider_host(provider);
    let ordinary = ordinary_service
        .admit(AdmitRunRequest {
            input: json!({"message":"ordinary direct remains supported"}),
            ..Default::default()
        })
        .await
        .unwrap();
    ordinary_service
        .clone()
        .run_worker(ordinary.run_id.clone(), String::new())
        .await;
    assert!(
        ordinary_service
            .run_events(&ordinary.run_id)
            .iter()
            .any(|e| e["event"] == "run.completed")
    );
    ordinary_service.shutdown().await.unwrap();
    source_state.service().shutdown().await.unwrap();
    for (status, body) in results {
        assert_static_denial(status, &body);
    }
}

#[derive(Default)]
struct Latch {
    state: std::sync::Mutex<(usize, bool)>,
    changed: std::sync::Condvar,
}
impl Latch {
    fn arrive(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 += 1;
        self.changed.notify_all();
        while !state.1 {
            let (next, timeout) = self
                .changed
                .wait_timeout(state, Duration::from_secs(4))
                .unwrap();
            state = next;
            assert!(!timeout.timed_out(), "owned explicit latch release");
        }
    }
    fn wait(&self, n: usize) {
        let mut state = self.state.lock().unwrap();
        while state.0 < n {
            let (next, timeout) = self
                .changed
                .wait_timeout(state, Duration::from_secs(3))
                .unwrap();
            state = next;
            assert!(
                !timeout.timed_out(),
                "actual linearization boundary arrival"
            );
        }
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}
struct LatchRelease(Arc<Latch>);
impl Drop for LatchRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn race_source(
    capacity: usize,
) -> (
    AgentGatewayState,
    ManagedCheckpointCreateRequest,
    ManagedRestoreAndAdmitRequest,
) {
    let (_root, state) = fixture_config(|config| {
        management_config(config);
        config.max_concurrent_runs = capacity;
    });
    let service = state.service();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"cas-a","name":"write_file","arguments":{"path":"value.txt","content":"A"}}),
    )));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = admitted(&service).await;
    let bound = binding(&service, &run);
    let source = checkpoint_request(&bound);
    service.clone().run_worker(run.run_id, String::new()).await;
    let restore = super::protocol::restore_request(&state, &source).await;
    (state, source, restore)
}

#[tokio::test(flavor = "multi_thread")]
async fn current_branch_default_and_distinct_request_cas_race() {
    let (state, source, request) = race_source(1).await;
    let service = state.service();
    let p = state.persistence().unwrap();
    let rt = service.managed_runtime_for_test().unwrap();
    let original_runs = service.inner.store.read().runs.len();
    let gate = Arc::new(Latch::default());
    let release = LatchRelease(gate.clone());
    let observed = gate.clone();
    *p.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueued| {
        if op == "effect.checkpoint_context" && !enqueued {
            observed.arrive();
        }
    }));
    let mut rival = request.clone();
    rival.request_id = uuid::Uuid::new_v4().to_string();
    let s = service.clone();
    let a = request.clone();
    let first = tokio::spawn(async move { s.restore_managed_checkpoint_and_admit(a).await });
    let s = service.clone();
    let b = rival.clone();
    let second = tokio::spawn(async move { s.restore_managed_checkpoint_and_admit(b).await });
    gate.wait(2);
    drop(release);
    let a = first.await.unwrap();
    let b = second.await.unwrap();
    *p.managed_request_hook.lock().unwrap() = None;
    assert_eq!(
        usize::from(a.is_ok()) + usize::from(b.is_ok()),
        1,
        "different request IDs competing on the same SOURCE yield one winner"
    );
    let (winner, loser_request, loser) = match (a, b) {
        (Ok(a), Err(b)) => (a, rival, b),
        (Err(a), Ok(b)) => (b, request, a),
        _ => unreachable!(),
    };
    assert!(matches!(
        loser.to_string().as_str(),
        "managed_restore_busy" | "managed_source_conflict"
    ));
    assert!(
        rt.repository
            .lookup_restore_receipt(&loser_request, &read_clock())
            .unwrap()
            .is_none()
    );
    assert_eq!(service.inner.store.read().runs.len(), original_runs + 1);
    let restored_run = service.handle(&winner.new_run_id).unwrap();
    let restored_binding = restored_run
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .clone()
        .unwrap();
    assert_eq!(
        restored_binding.admitted_branch.branch_id,
        winner.new_branch.branch_id
    );
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    assert!(service.start_managed_restore_worker(&winner.new_run_id));
    assert!(
        !service.start_managed_restore_worker(&winner.new_run_id),
        "same restored worker starts once"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !restored_run
            .terminal
            .load(std::sync::atomic::Ordering::Acquire)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"default-new","name":"write_file","arguments":{"path":"new.txt","content":"new-current"}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let ordinary = admitted(&service).await;
    let ordinary_binding = binding(&service, &ordinary);
    service
        .clone()
        .run_worker(ordinary.run_id.clone(), String::new())
        .await;
    assert_eq!(
        ordinary_binding.admitted_branch.branch_id,
        winner.new_branch.branch_id
    );
    assert_ne!(
        ordinary_binding.admitted_branch.branch_id,
        source.source_branch_id
    );
    assert_eq!(ordinary_binding.admitted_epoch(), winner.new_branch.epoch);
    let record = p
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ordinary_binding.owner.clone(),
            call_id: "default-new".into(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        record.outcome.unwrap().disposition,
        ManagedPublicationStatus::Committed
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_loses_to_actual_source_commit_at_preparation_boundary() {
    let (state, source, request) = race_source(2).await;
    let service = state.service();
    let p = state.persistence().unwrap();
    let rt = service.managed_runtime_for_test().unwrap();
    let before_runs = service.inner.store.read().runs.len();
    let gate = Arc::new(Latch::default());
    let release = LatchRelease(gate.clone());
    let observer = gate.clone();
    *p.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueued| {
        if op == "effect.checkpoint_context" && !enqueued {
            observer.arrive();
        }
    }));
    // The writer fixture is prepared before the restore is spawned so its
    // admission no longer burns the restore's own watchdog window; the real
    // worker still starts only after the restore is observed at its arrival.
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"cas-b","name":"write_file","arguments":{"path":"value.txt","content":"B"}}),
    )));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let writer = admitted(&service).await;
    let writer_binding = binding(&service, &writer);
    let s = service.clone();
    let req = request.clone();
    let restore = tokio::spawn(async move { s.restore_managed_checkpoint_and_admit(req).await });
    gate.wait(1);
    let result = tokio::spawn(
        service
            .clone()
            .run_worker(writer.run_id.clone(), String::new()),
    )
    .await;
    drop(release);
    let restored = restore.await.unwrap();
    *p.managed_request_hook.lock().unwrap() = None;
    result.unwrap();
    let record = p
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: writer_binding.owner.clone(),
            call_id: "cas-b".into(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        record.outcome.unwrap().disposition,
        ManagedPublicationStatus::Committed
    );
    assert_eq!(restored.unwrap_err().to_string(), "managed_source_conflict");
    assert!(
        rt.repository
            .lookup_restore_receipt(&request, &read_clock())
            .unwrap()
            .is_none()
    );
    assert_eq!(service.inner.store.read().runs.len(), before_runs + 1);
    let head = rt
        .repository
        .checkpoint_context(&source, &read_clock())
        .unwrap()
        .head;
    assert_eq!(head.epoch, request.expected_source.epoch);
    assert_ne!(head.head_object_id, request.expected_source.head_object_id);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_races_ordinary_admission_and_rechecks_related_inputs() {
    let (state, source, request) = race_source(2).await;
    let service = state.service();
    let gate = Arc::new(Latch::default());
    let release = LatchRelease(gate.clone());
    let observer = gate.clone();
    let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = preparations.clone();
    service.inject_prompt_read_entered_observer(Arc::new(move || {
        if count.fetch_add(1, std::sync::atomic::Ordering::AcqRel) == 0 {
            observer.arrive();
        }
    }));
    let s = service.clone();
    let ordinary = tokio::spawn(async move { admitted(&s).await });
    gate.wait(1);
    let first_preparation = std::time::Instant::now();
    // A related provider projection changes while ordinary prompt IO is paused.
    service
        .set_provider_profile(
            crate::config::ProviderProfile::new(
                "local-agent",
                json!({"protocol":"provider","temperature":0.375}),
            )
            .unwrap(),
        )
        .unwrap();
    // An unrelated generation is not itself an admission failure condition.
    service
        .inner
        .store_generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let restored = service.restore_managed_checkpoint_and_admit(request).await;
    drop(release);
    let ordinary = ordinary.await.unwrap();
    *service.inner.prompt_read_entered.lock().unwrap() = None;
    let restored = restored.unwrap();
    let bound = binding(&service, &ordinary);
    assert_eq!(
        bound.admitted_branch.branch_id,
        restored.new_branch.branch_id
    );
    assert_ne!(bound.admitted_branch.branch_id, source.source_branch_id);
    assert_eq!(
        service
            .run_context(&ordinary.run_id)
            .unwrap()
            .provider_options["temperature"],
        0.375
    );
    assert!(preparations.load(std::sync::atomic::Ordering::Acquire) >= 2);
    let handle = service.handle(&ordinary.run_id).unwrap();
    let clock = handle.cancel.deadline_instant().unwrap();
    assert!(
        clock <= first_preparation + service.inner.config.run_timeout,
        "reprepare keeps the ordinary admission's original bounded clock"
    );
    // Both successful admissions own distinct current-branch bindings and a
    // single original capacity permit; finish through their actual workers.
    for id in [&restored.new_run_id, &ordinary.run_id] {
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(None));
        service.inject_provider_host(provider);
        service.clone().run_worker(id.clone(), String::new()).await;
    }
    service.shutdown().await.unwrap();
}

#[derive(Default)]
struct ProviderBarrier {
    entered: std::sync::atomic::AtomicBool,
    fail: std::sync::atomic::AtomicBool,
}
impl crate::AgentProviderHost for ProviderBarrier {
    fn call(&self, _: &Value, cancellation: &crate::RunCancellation) -> Value {
        use std::sync::atomic::Ordering;
        self.entered.store(true, Ordering::Release);
        while !self.fail.load(Ordering::Acquire)
            && cancellation.requested().is_none()
            && !cancellation.deadline_passed()
        {
            std::thread::sleep(Duration::from_millis(2));
        }
        json!({"ok":false,"error":{"code":"synthetic_provider_failed","message":"owned synthetic provider failure","retryable":false}})
    }
}
struct ProviderRelease(Arc<ProviderBarrier>);
impl Drop for ProviderRelease {
    fn drop(&mut self) {
        self.0
            .fail
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_rejects_unsettled_provider_original_deadline() {
    unsettled(4, "deadline").await;
}
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_rejects_unsettled_provider_management_deadline() {
    unsettled(30, "management").await;
}
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_rejects_unsettled_provider_failed() {
    unsettled(30, "failed").await;
}
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_rejects_unsettled_provider_cancelled() {
    unsettled(30, "cancelled").await;
}
async fn unsettled(seconds: u64, mode: &'static str) {
    let (_root, state) = fixture_config(|config| {
        management_config(config);
        config.run_timeout = Duration::from_secs(seconds);
    });
    let service = state.service();
    let provider = Arc::new(ProviderBarrier::default());
    let release = ProviderRelease(provider.clone());
    service.inject_provider_host(provider.clone());
    let run = admitted(&service).await;
    let bound = binding(&service, &run);
    let original = bound.cancel.clone();
    let context = service.run_context(&run.run_id).unwrap();
    let request = checkpoint_request(&bound);
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    let rt = service.managed_runtime_for_test().unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !provider.entered.load(std::sync::atomic::Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        service.has_provider_request(&run.run_id, 1),
        "barrier follows real durable provider request"
    );
    let before = rt
        .repository
        .checkpoint_context(&request, &read_clock())
        .unwrap();
    let s = service.clone();
    let req = request.clone();
    let started = std::time::Instant::now();
    let checkpoint = tokio::spawn(async move { s.create_managed_checkpoint(req).await });
    let probe = service.clone();
    let r = rt.clone();
    let branch = bound.admitted_branch.branch_id.clone();
    let handle = service.handle(&run.run_id).unwrap();
    let p = provider.clone();
    let check = tokio::spawn(async move {
        paused(&r, &branch).await;
        assert!(probe.inner.commit_gate.try_lock().is_some());
        if mode == "failed" {
            p.fail.store(true, std::sync::atomic::Ordering::Release);
        }
        if mode == "cancelled" {
            handle.request_user_stop();
        }
    })
    .await;
    let result = tokio::time::timeout(Duration::from_secs(6), checkpoint).await;
    drop(release);
    let worker_result = worker.await;
    let after = rt
        .repository
        .checkpoint_context(&request, &read_clock())
        .unwrap();
    let absent = rt
        .repository
        .checkpoint_receipt(&request, &read_clock(), None)
        .unwrap()
        .is_none();
    let same_clock = bound.cancel.shares_original_clock(&original);
    let same_deadline = bound.cancel.deadline_instant() == original.deadline_instant();
    let same_limits = service.run_context(&run.run_id).unwrap().limits == context.limits;
    let unpaused = !rt.checkpoint_pausing_for_test(&request.source_branch_id);
    service.shutdown().await.unwrap();
    if let Err(error) = check {
        std::panic::resume_unwind(error.into_panic());
    }
    worker_result.unwrap();
    let result = result
        .expect("owned provider wait releases within management bound")
        .unwrap();
    assert!(
        result.is_err(),
        "unsettled {mode} must reject without a checkpoint: {result:?}"
    );
    assert_eq!(result.unwrap_err().to_string(), "managed_checkpoint_busy");
    assert!(absent, "unsettled provider cannot publish a receipt");
    assert!(same_clock && same_deadline && same_limits && unpaused);
    assert_eq!(before.head, after.head);
    assert!(after.effects.is_empty());
    assert!(
        after.messages.iter().all(|m| m.tool_call_id.is_none()),
        "no half tool history"
    );
    if mode == "deadline" {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "original remaining run deadline is the tighter bound"
        );
    }
}

fn management_config(config: &mut AgentGatewayConfig) {
    config.bearer_token = Some("synthetic-maintenance-fixture".into());
    let policy = &mut config
        .managed_workspace
        .as_mut()
        .unwrap()
        .maintenance_policy;
    policy.create_checkpoint = true;
    policy.restore = true;
}
async fn admitted(service: &Arc<crate::AgentService>) -> crate::AdmittedRun {
    service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"synthetic actual linearization fixture"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
}
fn binding(
    service: &crate::AgentService,
    run: &crate::AdmittedRun,
) -> Arc<crate::effects::broker::ManagedRunBinding> {
    service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .clone()
        .unwrap()
}
fn checkpoint_request(
    binding: &crate::effects::broker::ManagedRunBinding,
) -> ManagedCheckpointCreateRequest {
    ManagedCheckpointCreateRequest {
        source_run_id: binding.owner.run_id.clone(),
        workspace_id: binding.admitted_branch.workspace_id.clone(),
        source_branch_id: binding.admitted_branch.branch_id.clone(),
        expected_epoch: binding.admitted_epoch(),
        request_id: uuid::Uuid::new_v4().to_string(),
        mode: ManagedCheckpointMode::AtClosedBatch,
    }
}
fn read_clock() -> crate::RunCancellation {
    crate::RunCancellation::with_timeout(Duration::from_secs(5))
}
async fn paused(runtime: &crate::effects::broker::ManagedEffectRuntime, branch: &str) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !runtime.checkpoint_pausing_for_test(branch) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("actual checkpoint pause publication");
}

/// 536: bounded test-local observation for the whole-batch timeout. Rows hold
/// only fixed typed phases, counters and enums (no ids, payloads, paths, SQL,
/// SSE text or raw errors). They stay in memory during the 3s window; the
/// artifact is serialized only after the original cleanup.
const WHOLE_BATCH_OBS_CAP: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WholeBatchStage {
    BeforeWindow,
    ProbeInstalled,
    RssEntered,
    RssExited,
    WorkerFutureReturned,
    SampleBegin,
    ProviderCalls,
    EventModelRequested,
    EventModelCompleted,
    EventToolCompleted,
    EventRunCompleted,
    EventRunFailed,
    EventRunCancelled,
    HandleTerminal,
    ClockRoot,
    EffectState,
    SampleEnd,
}

impl WholeBatchStage {
    fn token(self) -> &'static str {
        match self {
            Self::BeforeWindow => "before_window",
            Self::ProbeInstalled => "probe_installed",
            Self::RssEntered => "rss_entered",
            Self::RssExited => "rss_exited",
            Self::WorkerFutureReturned => "worker_future_returned",
            Self::SampleBegin => "sample_begin",
            Self::ProviderCalls => "provider_calls",
            Self::EventModelRequested => "event_model_requested",
            Self::EventModelCompleted => "event_model_completed",
            Self::EventToolCompleted => "event_tool_completed",
            Self::EventRunCompleted => "event_run_completed",
            Self::EventRunFailed => "event_run_failed",
            Self::EventRunCancelled => "event_run_cancelled",
            Self::HandleTerminal => "handle_terminal",
            Self::ClockRoot => "clock_root",
            Self::EffectState => "effect_state",
            Self::SampleEnd => "sample_end",
        }
    }
}

/// Rows that must exist for a complete post-window sample. `RssExited` is
/// deliberately absent: a detached blocking job may still be running.
const WHOLE_BATCH_EXPECTED: &[WholeBatchStage] = &[
    WholeBatchStage::BeforeWindow,
    WholeBatchStage::ProbeInstalled,
    WholeBatchStage::RssEntered,
    WholeBatchStage::WorkerFutureReturned,
    WholeBatchStage::SampleBegin,
    WholeBatchStage::ProviderCalls,
    WholeBatchStage::EventModelRequested,
    WholeBatchStage::EventModelCompleted,
    WholeBatchStage::EventToolCompleted,
    WholeBatchStage::EventRunCompleted,
    WholeBatchStage::EventRunFailed,
    WholeBatchStage::EventRunCancelled,
    WholeBatchStage::HandleTerminal,
    WholeBatchStage::ClockRoot,
    WholeBatchStage::EffectState,
    WholeBatchStage::SampleEnd,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WholeBatchEffectState {
    Absent,
    PreparedNoOutcome,
    Committed,
    OtherTypedOutcome,
    ReadError,
}

impl WholeBatchEffectState {
    fn token(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::PreparedNoOutcome => "prepared_no_outcome",
            Self::Committed => "committed",
            Self::OtherTypedOutcome => "other_typed_outcome",
            Self::ReadError => "read_error",
        }
    }
}

#[derive(Clone, Copy)]
enum WholeBatchEvent {
    Stage(WholeBatchStage),
    WorkerFuture {
        ok: bool,
    },
    Count {
        stage: WholeBatchStage,
        count: u64,
    },
    Terminal {
        terminal: Option<bool>,
    },
    Clock {
        requested: bool,
        has_deadline: bool,
        remaining_ms: Option<u64>,
        shares_original: bool,
    },
    Effect {
        state: WholeBatchEffectState,
    },
}

impl WholeBatchEvent {
    fn stage(self) -> WholeBatchStage {
        match self {
            Self::Stage(stage) => stage,
            Self::WorkerFuture { .. } => WholeBatchStage::WorkerFutureReturned,
            Self::Count { stage, .. } => stage,
            Self::Terminal { .. } => WholeBatchStage::HandleTerminal,
            Self::Clock { .. } => WholeBatchStage::ClockRoot,
            Self::Effect { .. } => WholeBatchStage::EffectState,
        }
    }
}

struct WholeBatchRow {
    event: WholeBatchEvent,
    elapsed_us: u64,
}

impl WholeBatchRow {
    fn to_value(&self, sequence: usize) -> Value {
        let elapsed_us = self.elapsed_us;
        match self.event {
            WholeBatchEvent::Stage(stage) => {
                json!({"sequence": sequence, "stage": stage.token(), "elapsed_us": elapsed_us})
            }
            WholeBatchEvent::WorkerFuture { ok } => json!({
                "sequence": sequence,
                "stage": WholeBatchStage::WorkerFutureReturned.token(),
                "elapsed_us": elapsed_us,
                "ok": ok,
            }),
            WholeBatchEvent::Count { stage, count } => json!({
                "sequence": sequence,
                "stage": stage.token(),
                "elapsed_us": elapsed_us,
                "count": count,
            }),
            WholeBatchEvent::Terminal { terminal } => json!({
                "sequence": sequence,
                "stage": WholeBatchStage::HandleTerminal.token(),
                "elapsed_us": elapsed_us,
                "terminal": terminal,
            }),
            WholeBatchEvent::Clock {
                requested,
                has_deadline,
                remaining_ms,
                shares_original,
            } => json!({
                "sequence": sequence,
                "stage": WholeBatchStage::ClockRoot.token(),
                "elapsed_us": elapsed_us,
                "requested": requested,
                "has_deadline": has_deadline,
                "remaining_ms": remaining_ms,
                "shares_original": shares_original,
            }),
            WholeBatchEvent::Effect { state } => json!({
                "sequence": sequence,
                "stage": WholeBatchStage::EffectState.token(),
                "elapsed_us": elapsed_us,
                "effect": state.token(),
            }),
        }
    }
}

#[derive(Default)]
struct WholeBatchRows {
    rows: Vec<WholeBatchRow>,
    overflow: bool,
}

struct WholeBatchObservation {
    origin: std::time::Instant,
    rows: std::sync::Mutex<WholeBatchRows>,
}

impl WholeBatchObservation {
    fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
            rows: std::sync::Mutex::new(WholeBatchRows {
                rows: Vec::with_capacity(WHOLE_BATCH_OBS_CAP),
                overflow: false,
            }),
        }
    }

    fn elapsed_us(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    fn record(&self, event: WholeBatchEvent) {
        let elapsed_us = self.elapsed_us();
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if rows.rows.len() >= WHOLE_BATCH_OBS_CAP {
            rows.overflow = true;
            return;
        }
        rows.rows.push(WholeBatchRow { event, elapsed_us });
    }

    fn record_stage(&self, stage: WholeBatchStage) {
        self.record(WholeBatchEvent::Stage(stage));
    }

    fn document(&self) -> Value {
        let rows = self
            .rows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let stages: Vec<WholeBatchStage> = rows.rows.iter().map(|row| row.event.stage()).collect();
        let missing: Vec<&'static str> = WHOLE_BATCH_EXPECTED
            .iter()
            .filter(|expected| !stages.iter().any(|stage| stage == *expected))
            .map(|expected| expected.token())
            .collect();
        json!({
            "artifact": "checkpoint-whole-batch-observation",
            "case": "536",
            "cap": WHOLE_BATCH_OBS_CAP,
            "row_count": rows.rows.len(),
            "overflow": rows.overflow,
            "missing_stages": missing,
            "rss_exit_observed": stages.contains(&WholeBatchStage::RssExited),
            "sampling": "after_original_3s_window",
            "probe_exit_is_whole_worker_return": false,
            "commit_after_timeout_does_not_date_commit_before_timeout": true,
            "rows": rows.rows.iter().enumerate().map(|(index, row)| row.to_value(index + 1)).collect::<Vec<Value>>(),
        })
    }
}

/// Reuses the accepted one-shot per-instance worker probe. The guard's clause
/// runs when the blocking runner returns; it is not the whole-worker future
/// returning, and a timeout-dropped future can leave that job running.
struct WholeBatchWorkerProbe {
    observation: Arc<WholeBatchObservation>,
}

impl crate::service::WorkerProbeInstall for WholeBatchWorkerProbe {
    fn install(self: Box<Self>) -> crate::service::WorkerProbeGuard {
        self.observation.record_stage(WholeBatchStage::RssEntered);
        let observation = self.observation.clone();
        crate::service::WorkerProbeGuard::new(move || {
            observation.record_stage(WholeBatchStage::RssExited);
        })
    }
}

fn whole_batch_effect_state(
    persistence: &crate::GatewayPersistence,
    request: &ManagedEffectGetRequest,
) -> WholeBatchEffectState {
    match persistence.managed_effect_get(request) {
        Err(_) => WholeBatchEffectState::ReadError,
        Ok(None) => WholeBatchEffectState::Absent,
        Ok(Some(record)) => match record.outcome {
            None if record.prepared.is_none() => WholeBatchEffectState::Absent,
            None => WholeBatchEffectState::PreparedNoOutcome,
            Some(outcome) if outcome.disposition == ManagedPublicationStatus::Committed => {
                WholeBatchEffectState::Committed
            }
            Some(_) => WholeBatchEffectState::OtherTypedOutcome,
        },
    }
}

/// Only serialization path: the accepted 471 writer (own `.tmp` guard, readback,
/// atomic rename). The private path field is retargeted at the fixture root so
/// the document never travels through the 471 document/finalize labels.
fn whole_batch_write_observation(
    observation: &WholeBatchObservation,
    root: &std::path::Path,
) -> Result<(), super::Guard471TraceFailure> {
    let mut writer = super::Guard471Trace::new("whole-batch-536", root, observation.origin);
    writer.path = root.join("checkpoint-whole-batch-observation.json");
    writer.write(&observation.document())
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_waits_for_whole_tool_batch_complete() {
    let (root, state) = fixture_config(management_config);
    let (_other_root, other_state) = fixture_config(management_config);
    let other = other_state.service();
    let service = state.service();
    let observation = Arc::new(WholeBatchObservation::new());
    observation.record_stage(WholeBatchStage::BeforeWindow);
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(json!({"text":"","tool_calls":[
        {"id":"whole-first","name":"write_file","arguments":{"path":"first.txt","content":"one"}},
        {"id":"whole-second","name":"write_file","arguments":{"path":"second.txt","content":"two"}}
    ],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"tool_calls"}));
    provider.push_ok(response(None));
    service.inject_provider_host(provider.clone());
    let run = admitted(&service).await;
    let bound = binding(&service, &run);
    let original_clock = bound.cancel.clone();
    let original_context = service.run_context(&run.run_id).unwrap();
    let request = checkpoint_request(&bound);
    let gate = service
        .arm_managed_call_prepare_gate("whole-second")
        .unwrap();
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    gate.wait_arrived(1).unwrap();
    let p = state.persistence().unwrap();
    let first_request = ManagedEffectGetRequest {
        owner: bound.owner.clone(),
        call_id: "whole-first".into(),
    };
    let second_request = ManagedEffectGetRequest {
        owner: bound.owner.clone(),
        call_id: "whole-second".into(),
    };
    let first = p.managed_effect_get(&first_request).unwrap().unwrap();
    let second = p.managed_effect_get(&second_request).unwrap().unwrap();
    let rt = service.managed_runtime_for_test().unwrap();
    let s = service.clone();
    let req = request.clone();
    let checkpoint = tokio::spawn(async move { s.create_managed_checkpoint(req).await });
    let other_provider = Arc::new(crate::ScriptedProvider::new());
    other_provider.push_ok(response(Some(json!({"id":"other-write","name":"write_file","arguments":{"path":"other.txt","content":"independent"}}))));
    other_provider.push_ok(response(None));
    other.inject_provider_host(other_provider.clone());
    let observed = service.clone();
    let independent = other.clone();
    let branch = bound.admitted_branch.branch_id.clone();
    let request_probe = request.clone();
    let runtime = rt.clone();
    let observation_probe = observation.clone();
    let check = tokio::spawn(async move {
        paused(&runtime, &branch).await;
        assert!(
            first.outcome.is_some(),
            "first output was durable before second real production call paused"
        );
        assert!(
            second.outcome.is_none(),
            "second actual call has no durable output yet"
        );
        assert!(
            runtime
                .repository
                .checkpoint_receipt(&request_probe, &read_clock(), None)
                .unwrap()
                .is_none()
        );
        let context = runtime
            .repository
            .checkpoint_context(&request_probe, &read_clock())
            .unwrap();
        assert_eq!(
            context
                .effects
                .iter()
                .filter(|effect| effect.outcome.is_some())
                .count(),
            1
        );
        assert!(
            observed.inner.commit_gate.try_lock().is_some(),
            "global commit gate is released while waiting on real tool IO"
        );
        let other_run = tokio::time::timeout(Duration::from_secs(3), admitted(&independent))
            .await
            .expect("other workspace admit cannot wait on batch IO");
        let other_binding = binding(&independent, &other_run);
        assert_ne!(
            other_binding.admitted_branch.workspace_id,
            bound.admitted_branch.workspace_id
        );
        *independent
            .inner
            .worker_probe
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(Box::new(WholeBatchWorkerProbe {
            observation: observation_probe.clone(),
        }));
        observation_probe.record_stage(WholeBatchStage::ProbeInstalled);
        let other_worker_result = tokio::time::timeout(
            Duration::from_secs(3),
            independent
                .clone()
                .run_worker(other_run.run_id.clone(), String::new()),
        )
        .await;
        observation_probe.record(WholeBatchEvent::WorkerFuture {
            ok: other_worker_result.is_ok(),
        });
        observation_probe.record_stage(WholeBatchStage::SampleBegin);
        observation_probe.record(WholeBatchEvent::Count {
            stage: WholeBatchStage::ProviderCalls,
            count: other_provider.call_count(),
        });
        let other_events = independent.run_events(&other_run.run_id);
        for (stage, name) in [
            (WholeBatchStage::EventModelRequested, "model.requested"),
            (WholeBatchStage::EventModelCompleted, "model.completed"),
            (WholeBatchStage::EventToolCompleted, "tool.completed"),
            (WholeBatchStage::EventRunCompleted, "run.completed"),
            (WholeBatchStage::EventRunFailed, "run.failed"),
            (WholeBatchStage::EventRunCancelled, "run.cancelled"),
        ] {
            let count = other_events
                .iter()
                .filter(|event| event.get("event").and_then(Value::as_str) == Some(name))
                .count();
            observation_probe.record(WholeBatchEvent::Count {
                stage,
                count: u64::try_from(count).unwrap_or(u64::MAX),
            });
        }
        observation_probe.record(WholeBatchEvent::Terminal {
            terminal: independent
                .handle(&other_run.run_id)
                .as_ref()
                .map(|handle| handle.is_terminal()),
        });
        observation_probe.record(WholeBatchEvent::Clock {
            requested: other_binding.cancel.requested().is_some(),
            has_deadline: other_binding.cancel.deadline_instant().is_some(),
            remaining_ms: other_binding
                .cancel
                .remaining_deadline()
                .map(|remaining| u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
            shares_original: other_binding.cancel.shares_original_clock(&original_clock),
        });
        observation_probe.record(WholeBatchEvent::Effect {
            state: whole_batch_effect_state(
                independent.inner.persistence.as_ref().unwrap(),
                &ManagedEffectGetRequest {
                    owner: other_binding.owner.clone(),
                    call_id: "other-write".into(),
                },
            ),
        });
        observation_probe.record_stage(WholeBatchStage::SampleEnd);
        other_worker_result.expect("other workspace actual commit cannot wait on batch IO");
        let result = independent
            .inner
            .persistence
            .as_ref()
            .unwrap()
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: other_binding.owner.clone(),
                call_id: "other-write".into(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            result.outcome.unwrap().disposition,
            ManagedPublicationStatus::Committed
        );
        assert!(bound.cancel.shares_original_clock(&original_clock));
        assert_eq!(
            bound.cancel.deadline_instant(),
            original_clock.deadline_instant()
        );
        assert!(
            bound.cancel.requested().is_none(),
            "checkpoint pause never requests user stop"
        );
        assert_eq!(
            observed.run_context(&run.run_id).unwrap().limits,
            original_context.limits
        );
        assert_eq!(
            provider.requests().len(),
            1,
            "no next provider invocation while original batch is draining"
        );
    })
    .await;
    let premature = checkpoint.is_finished();
    gate.release();
    let worker_result = worker.await;
    let checkpoint_result = checkpoint.await;
    let first = p.managed_effect_get(&first_request).unwrap().unwrap();
    let second = p.managed_effect_get(&second_request).unwrap().unwrap();
    let final_context = rt
        .repository
        .checkpoint_context(&request, &read_clock())
        .unwrap();
    service.shutdown().await.unwrap();
    other.shutdown().await.unwrap();
    other_state.service().shutdown().await.unwrap();
    let observation_write = whole_batch_write_observation(&observation, &root);
    if let Err(failure) = &observation_write {
        super::guard471_report_secondary(
            std::io::stderr().lock(),
            "checkpoint-whole-batch-observation-write-failed",
            *failure,
        );
    }
    if let Err(error) = check {
        std::panic::resume_unwind(error.into_panic());
    }
    worker_result.unwrap();
    assert!(
        !premature,
        "no mixed checkpoint before second durable output"
    );
    let receipt = checkpoint_result
        .unwrap()
        .expect("same enumerated batch closes using original tokens");
    let refs = &receipt.checkpoint.history.closed_output_refs;
    assert_eq!(refs.len(), 2);
    for record in [first, second] {
        let output = refs
            .iter()
            .find(|r| r.call_id == record.identity.call_id)
            .unwrap();
        let outcome = record.outcome.unwrap();
        assert_eq!(output.run_id, record.identity.owner.run_id);
        let message = final_context
            .messages
            .iter()
            .find(|m| m.id == outcome.message.id)
            .unwrap();
        assert_eq!(
            output.parent_message_id,
            message.parent_message_id.as_ref().unwrap().as_str()
        );
        assert_eq!(output.output_message_id, outcome.message.id);
        assert_eq!(output.receipt_id, record.prepared.unwrap().effect_id);
        assert_eq!(output.result, outcome.canonical_result_ref);
    }
    observation_write.expect("checkpoint whole batch observation write");
}
