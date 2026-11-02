//! Run effect query contracts through the production Axum app on real TCP.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};
use rustscript_agent::{
    ScriptedProvider,
    config::{ManagedRetentionLimits, ManagedWorkspaceConfig},
    effects::{ManagedEffectGetRequest, ManagedEffectPage, ManagedOwnerScope, ResourceQuota},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Arc};
use std::{net::SocketAddr, time::Duration};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    config: AgentGatewayConfig,
    state: AgentGatewayState,
    token: String,
}
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("q-{}", uuid::Uuid::new_v4().simple()));
        let workspace = root.join("w");
        let home = root.join("h");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(workspace.join("seed.txt"), b"seed").unwrap();
        fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
        let token = uuid::Uuid::new_v4().to_string();
        let mut config = AgentGatewayConfig {
            bearer_token: Some(token.clone()),
            managed_workspace: Some(ManagedWorkspaceConfig {
                source_root: workspace,
                quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
                retention: ManagedRetentionLimits::default(),
                maintenance_policy: Default::default(),
            }),
            ..Default::default()
        };
        config.approvals.write = "allow".into();
        let state = AgentGatewayState::with_sqlite_path(config.clone(), root.join("g.sqlite"))
            .unwrap()
            .with_workspace_home(&home);
        Self {
            root,
            home,
            config,
            state,
            token,
        }
    }
    async fn run(&self, http: &Http, calls: Vec<Value>) -> (String, String) {
        let provider = Arc::new(ScriptedProvider::new());
        for call in calls {
            provider.push_ok(json!({"text":"","tool_calls":[call],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"tool_calls"}));
        }
        provider.push_ok(json!({"text":"done","tool_calls":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
        self.state.service().inject_provider_host(provider);
        let (status, session) = http
            .request("POST", "/api/sessions", json!({}), Some(&self.token))
            .await;
        assert_eq!(status, 201);
        let session = session["session"]["id"].as_str().unwrap().to_string();
        let (status, run) = http
            .request(
                "POST",
                "/v1/runs",
                json!({"session_id":session,"input":"perform fixture calls"}),
                Some(&self.token),
            )
            .await;
        assert_eq!(status, 202, "HTTP run admission");
        let run = run["run_id"].as_str().unwrap().to_string();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let events = self.state.service().run_events(&run);
                if events.iter().any(|e| e["event"] == "run.completed") {
                    break;
                }
                assert!(
                    !events
                        .iter()
                        .any(|e| e["event"] == "run.failed" || e["event"] == "run.cancelled"),
                    "fixture run must complete"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("HTTP-created run terminal deadline");
        (session, run)
    }
}

struct Http {
    address: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Http {
    async fn bind(state: AgentGatewayState) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                build_agent_gateway_app(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            address,
            shutdown,
            server,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        token: Option<&str>,
    ) -> (u16, Value) {
        let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(format!("http://{}{}", self.address, path));
        if let Some(token) = token {
            request = request.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = request
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(15), client.request(request))
            .await
            .unwrap()
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn close(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(std::net::TcpListener::bind(self.address).expect("owned TCP released"));
    }
}
#[tokio::test]
async fn run_effect_route_requires_configured_auth_before_query_parsing() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).unwrap();
    let http = Http::bind(state.clone()).await;
    let result = http
        .request(
            "GET",
            "/v1/runs/missing/effects?authority=untrusted",
            json!(null),
            None,
        )
        .await;
    http.close().await;
    state.service().shutdown().await.unwrap();
    assert_eq!(result.0, 403, "managed route must fail closed");
    assert_eq!(result.1["error"]["code"], "managed_management_denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_run_path_is_a_static_typed_error() {
    let fixture = Fixture::new();
    let http = Http::bind(fixture.state.clone()).await;
    let result = http
        .request(
            "GET",
            "/v1/runs/%FF/effects",
            json!(null),
            Some(&fixture.token),
        )
        .await;
    http.close().await;
    fixture.state.service().shutdown().await.unwrap();
    assert_eq!(
        result,
        (
            422,
            json!({"error":{"code":"managed_request_invalid","message":"managed_request_invalid"}})
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_query_dto_and_transport_auth_are_static_over_real_http() {
    let fixture = Fixture::new();
    let http = Http::bind(fixture.state.clone()).await;
    let (_, run) = fixture.run(&http, vec![]).await;
    let path = format!("/v1/runs/{run}/effects");
    let mut invalid = Vec::new();
    for query in [
        "limit=0",
        "limit=129",
        "limit=-1",
        "limit=no",
        "limit=18446744073709551616",
        "limit=1&limit=2",
        "after_effect_id=",
        "after_effect_id=..%2Fprivate",
        "after_effect_id=effect-0000000000000000000000000000000A",
        "after_effect_id=effect-000000000000000000000000000000001",
    ] {
        invalid.push(
            http.request(
                "GET",
                &format!("{path}?{query}"),
                json!(null),
                Some(&fixture.token),
            )
            .await,
        );
    }
    for field in [
        "workspace_id",
        "branch_id",
        "profile",
        "owner",
        "authority",
        "graph_id",
        "workspace_path",
    ] {
        invalid.push(
            http.request(
                "GET",
                &format!("{path}?{field}=PRIVATE_MARKER"),
                json!(null),
                Some(&fixture.token),
            )
            .await,
        );
    }
    let missing = http.request("GET", &path, json!(null), None).await;
    let wrong = http
        .request("GET", &path, json!(null), Some("invalid-synthetic"))
        .await;
    let max = http
        .request(
            "GET",
            &format!("{path}?limit=128"),
            json!(null),
            Some(&fixture.token),
        )
        .await;
    http.close().await;
    fixture.state.service().shutdown().await.unwrap();
    for result in invalid {
        assert_eq!(
            result,
            (
                422,
                json!({"error":{"code":"managed_request_invalid","message":"managed_request_invalid"}})
            )
        );
    }
    for result in [missing, wrong] {
        assert_eq!(result.0, 401);
        assert_eq!(result.1["error"]["code"], "unauthorized");
    }
    assert_eq!(
        max,
        (
            200,
            json!({"entries":[],"next_cursor":null,"has_more":false})
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bearer_does_not_replace_native_authorization_or_disclose_missing_runs() {
    let fixture = Fixture::new();
    let http = Http::bind(fixture.state.clone()).await;
    let (session, run) = fixture.run(&http, vec![]).await;
    let p = fixture.state.persistence().unwrap();
    p.run_create(&json!({"id":"formal-unmanaged","session_id":session,"parent_run_id":"","input_json":"{}","provider":"synthetic","model":"m","script_hash":"","idempotency_scope":"","idempotency_key":"","now_ms":1})).unwrap();
    let mut results = Vec::new();
    for id in ["missing", "formal-unmanaged"] {
        results.push(
            http.request(
                "GET",
                &format!("/v1/runs/{id}/effects"),
                json!(null),
                Some(&fixture.token),
            )
            .await,
        );
    }
    let other = Fixture::new();
    let foreign = Http::bind(other.state.clone()).await;
    results.push(
        foreign
            .request(
                "GET",
                &format!("/v1/runs/{run}/effects"),
                json!(null),
                Some(&other.token),
            )
            .await,
    );
    foreign.close().await;
    other.state.service().shutdown().await.unwrap();
    http.close().await;
    let denied_home = fixture.root.join("denied-home");
    fs::create_dir(&denied_home).unwrap();
    let native = Http::bind(fixture.state.clone().with_workspace_home(&denied_home)).await;
    results.push(
        native
            .request(
                "GET",
                &format!("/v1/runs/{run}/effects"),
                json!(null),
                Some(&fixture.token),
            )
            .await,
    );
    native.close().await;
    fixture.state.service().shutdown().await.unwrap();
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
async fn http_created_native_run_effects_match_durable_summaries_and_reopen() {
    let fixture = Fixture::new();
    let http = Http::bind(fixture.state.clone()).await;
    let (session,run) = fixture.run(&http,vec![json!({"id":"write-one","name":"write_file","arguments":{"path":"result.txt","content":"private canonical content"}})]).await;
    let p = fixture.state.persistence().unwrap();
    let record = p
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session.clone(),
                run_id: run.clone(),
            },
            call_id: "write-one".into(),
        })
        .unwrap()
        .expect("real Native effect persisted");
    let expected = p
        .managed_effect_list(&rustscript_agent::effects::ManagedEffectListRequest {
            workspace_id: record.identity.workspace.workspace_id.clone(),
            after_effect_id: None,
            limit: 128,
        })
        .unwrap();
    assert_eq!(expected.entries.len(), 1);
    assert_eq!(expected.entries[0].run_id, run);
    let before = (
        p.run_get(&run).unwrap(),
        fixture.state.service().session_messages(&session),
        fixture.state.service().run_events(&run),
    );
    let result = http
        .request(
            "GET",
            &format!("/v1/runs/{run}/effects"),
            json!(null),
            Some(&fixture.token),
        )
        .await;
    http.close().await;
    let after = (
        p.run_get(&run).unwrap(),
        fixture.state.service().session_messages(&session),
        fixture.state.service().run_events(&run),
    );
    fixture.state.service().shutdown().await.unwrap();
    assert_eq!(
        result.0, 200,
        "actual planned route must expose the legitimate managed run page"
    );
    let page: ManagedEffectPage = serde_json::from_value(result.1.clone()).unwrap();
    assert_eq!(page, expected);
    assert!(
        !result.1.to_string().contains(
            fixture
                .config
                .managed_workspace
                .as_ref()
                .unwrap()
                .source_root
                .to_str()
                .unwrap()
        )
    );
    assert!(!result.1.to_string().contains("private canonical content"));
    assert_eq!(before, after, "read cannot alter run/history/events");
    drop(p);
    drop(fixture.state);
    let reopened_state =
        AgentGatewayState::with_sqlite_path(fixture.config.clone(), fixture.root.join("g.sqlite"))
            .unwrap()
            .with_workspace_home(&fixture.home);
    let reopened = Http::bind(reopened_state.clone()).await;
    let second = reopened
        .request(
            "GET",
            &format!("/v1/runs/{run}/effects"),
            json!(null),
            Some(&fixture.token),
        )
        .await;
    reopened.close().await;
    reopened_state.service().shutdown().await.unwrap();
    assert_eq!(second.0, 200);
    assert_eq!(second.1, serde_json::to_value(expected).unwrap());
}
