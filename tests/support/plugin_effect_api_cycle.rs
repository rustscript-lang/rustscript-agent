//! T16 HTTP cycle helpers. Production routes and the signed-tool producer stay unchanged.
use super::signed_tool_effects;
use http_body_util::BodyExt;
use rustscript_agent::plugins::{InstallAuthorization, PackageStore, PluginControlStore};
use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, AgentProviderHost, GatewayPersistence, RunCancellation,
    ScriptedProvider,
    config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
    effects::ResourceQuota,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub struct Http {
    address: std::net::SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Http {
    pub async fn bind(state: AgentGatewayState) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                rustscript_agent::build_agent_gateway_app(state)
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
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

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        token: Option<&str>,
        idempotency: Option<&str>,
    ) -> (u16, Value) {
        let client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(format!("http://{}{path}", self.address));
        if let Some(token) = token {
            request = request.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(key) = idempotency {
            request = request.header("idempotency-key", key);
        }
        let request = request
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                body.to_string(),
            )))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(20), client.request(request))
            .await
            .expect("HTTP deadline")
            .expect("HTTP transport");
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    pub async fn typed_sse(&self, token: &str, run_id: &str) -> Vec<TypedEvent> {
        let client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let request = hyper::Request::builder()
            .method("GET")
            .uri(format!("http://{}/v1/runs/{run_id}/events", self.address))
            .header(hyper::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(hyper::header::ACCEPT, "text/event-stream")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(20), client.request(request))
            .await
            .expect("SSE deadline")
            .expect("SSE transport");
        assert_eq!(response.status().as_u16(), 200, "SSE status");
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.starts_with("text/event-stream"),
            "SSE content type"
        );
        let bytes = tokio::time::timeout(Duration::from_secs(20), response.into_body().collect())
            .await
            .expect("SSE body deadline")
            .expect("SSE body")
            .to_bytes();
        let text = String::from_utf8(bytes.to_vec()).expect("SSE utf-8");
        let events = parse_typed_events(&text);
        drop(text);
        events
    }

    pub async fn close(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedEvent {
    pub name: String,
    pub seq: u64,
    pub terminal: bool,
}

fn parse_typed_events(text: &str) -> Vec<TypedEvent> {
    let mut events = Vec::new();
    let mut sse_name = String::new();
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("event: ") {
            sse_name = name.to_string();
            continue;
        }
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        let name = value["event"]
            .as_str()
            .unwrap_or(sse_name.as_str())
            .to_string();
        if !sse_name.is_empty() {
            assert_eq!(sse_name, name, "SSE event name diverges from typed payload");
        }
        let seq = value["seq"].as_u64().expect("typed SSE seq");
        let terminal = matches!(
            name.as_str(),
            "run.completed" | "run.cancelled" | "run.failed"
        );
        events.push(TypedEvent {
            name,
            seq,
            terminal,
        });
        sse_name.clear();
    }
    events
}

pub fn assert_typed_terminal(events: &[TypedEvent], terminal: &str) {
    assert!(!events.is_empty(), "SSE replay was empty");
    for pair in events.windows(2) {
        assert!(pair[1].seq > pair[0].seq, "SSE seq must increase");
    }
    assert_eq!(events[0].seq, 1, "SSE seq origin");
    let terminals: Vec<_> = events.iter().filter(|event| event.terminal).collect();
    assert_eq!(terminals.len(), 1, "one terminal event");
    assert_eq!(
        events.last().map(|event| event.name.as_str()),
        Some(terminal)
    );
    assert!(events.iter().any(|event| event.name == "run.started"));
}

/// Same hold as the existing second-call provider gate: after the second business
/// response is computed, before the agent loop observes it. Guardian turns do not count.
pub struct SecondBusinessGate {
    provider: ScriptedProvider,
    release: Arc<(Mutex<bool>, Condvar)>,
    holding: AtomicBool,
}

impl SecondBusinessGate {
    pub fn new(provider: ScriptedProvider) -> Self {
        Self {
            provider,
            release: Arc::new((Mutex::new(false), Condvar::new())),
            holding: AtomicBool::new(false),
        }
    }

    pub fn holding(&self) -> bool {
        self.holding.load(Ordering::Acquire)
    }

    pub fn release(&self) {
        let (flag, cv) = &*self.release;
        *flag.lock().expect("gate flag") = true;
        cv.notify_all();
    }
}

impl AgentProviderHost for SecondBusinessGate {
    fn call(&self, request: &Value, cancellation: &RunCancellation) -> Value {
        let outcome = self.provider.call(request, cancellation);
        if is_guardian(request) || business_len(&self.provider.requests()) < 2 {
            return outcome;
        }
        self.holding.store(true, Ordering::Release);
        let (flag, cv) = &*self.release;
        let mut ready = flag.lock().expect("gate flag");
        let deadline = Instant::now() + Duration::from_secs(15);
        while !*ready {
            if cancellation.requested().is_some() || cancellation.deadline_passed() {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (guard, _) = cv
                .wait_timeout(ready, deadline.saturating_duration_since(now))
                .expect("gate wait");
            ready = guard;
        }
        self.holding.store(false, Ordering::Release);
        outcome
    }
}

fn is_guardian(request: &Value) -> bool {
    request["messages"]
        .as_array()
        .and_then(|messages| messages.first())
        .and_then(|message| message["content"].as_str())
        .is_some_and(|text| {
            text.starts_with("You are Guardian, reviewing one proposed tool action.")
        })
        || request
            .to_string()
            .contains("You are Guardian, reviewing one proposed tool action.")
}

fn business_len(requests: &[Value]) -> usize {
    requests
        .iter()
        .filter(|request| !is_guardian(request))
        .count()
}

pub struct Cycle {
    pub root: PathBuf,
    pub workspace: PathBuf,
    pub source: PathBuf,
    pub db: PathBuf,
    pub token: String,
    pub config: AgentGatewayConfig,
    pub auth: InstallAuthorization,
    pub state: AgentGatewayState,
}

impl Cycle {
    pub fn open(label: &str) -> Self {
        Self::open_timeout(label, Duration::from_secs(900))
    }

    pub fn open_timeout(label: &str, run_timeout: Duration) -> Self {
        let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(label);
        let _ = std::fs::remove_dir_all(&root);
        let workspace = root.join("workspace");
        let home = root.join("workspace-home");
        let source = root.join("controlled-source");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(workspace.join("seed.txt"), b"seed").unwrap();
        let yaml = format!(
            "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
            workspace.display(),
            workspace.display(),
            workspace.display()
        );
        std::fs::write(home.join("config.yaml"), yaml).unwrap();
        #[cfg(unix)]
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
        let token = uuid::Uuid::new_v4().to_string();
        let mut config = AgentGatewayConfig {
            bearer_token: Some(token.clone()),
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
        config.run_timeout = run_timeout;
        let db = root.join("gateway.sqlite");
        let (auth, _, _, _) = signed_tool_effects::stage_write_pair(&source);
        let bound = InstallAuthorization {
            admin: auth.admin,
            accepted_publishers: auth.accepted_publishers.clone(),
            unsigned_dev_space: auth.unsigned_dev_space.clone(),
        };
        let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
            .unwrap()
            .with_workspace_home(&home)
            .with_plugin_control(auth, source.clone(), "owner-space")
            .unwrap();
        Self {
            root,
            workspace,
            source,
            db,
            token,
            config,
            auth: bound,
            state,
        }
    }
}

pub fn tool_call(id: &str, name: &str, path: &str) -> Value {
    json!({
        "text": "",
        "tool_calls": [{"id": id, "name": name, "arguments": {"path": path, "content": "ignored"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    })
}

pub fn stop_turn(text: &str) -> Value {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

pub fn explain(status: u16, body: &Value) -> String {
    format!(
        "status={status} code={} message={}",
        body["error"]["code"], body["error"]["message"]
    )
}

pub fn assert_closed(body: &Value, token: &str, hidden: &[&Path]) {
    let text = body.to_string();
    assert!(
        !text.contains(token),
        "response leaked the owner credential"
    );
    for path in hidden {
        let rendered = path.display().to_string();
        assert!(
            !rendered.is_empty() && !text.contains(&rendered),
            "response leaked a host path"
        );
    }
}

pub async fn install_pair(http: &Http, token: &str, source: &Path) {
    let (status, body) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"admin": true, "package": "package-a", "deployment_space": "owner-space", "path": source.display().to_string()}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 422, "{}", explain(status, &body));
    assert_eq!(body["error"]["code"], "plugin_request_invalid");
    let (status, body) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "package-a", "deployment_space": "owner-space"}),
            None,
            None,
        )
        .await;
    assert_eq!(status, 401, "{}", explain(status, &body));
    assert_eq!(body["error"]["code"], "unauthorized");
    for package in ["package-a", "package-b"] {
        let (status, body) = http
            .request(
                "POST",
                "/v1/plugins/install",
                json!({"package": package, "deployment_space": "owner-space"}),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{package}: {}", explain(status, &body));
    }
}

pub async fn activate(
    http: &Http,
    token: &str,
    config: &AgentGatewayConfig,
    db: &Path,
    package_id: &str,
) -> (String, u64) {
    let (status, resolved) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({"roots": [{"id": package_id, "version": "1.0.0"}], "tool_package": package_id, "deployment_space": "owner-space"}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &resolved));
    assert_eq!(resolved["activated"], false);
    let graph = resolved["graph_id"].as_str().unwrap().to_string();
    assert_ne!(graph, package_id);
    let (status, prepared) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph}/prepare"),
            json!({}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &prepared));
    assert_eq!(prepared["executable"], true);
    let expected = current_generation(config, db);
    let (status, activated) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({"graph_id": graph, "deployment_space": "owner-space", "expected_generation": expected}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(
        status,
        200,
        "expected={expected} {}",
        explain(status, &activated)
    );
    let (status, conflict) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({"graph_id": graph, "deployment_space": "owner-space", "expected_generation": expected}),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &conflict));
    assert_eq!(conflict["error"]["code"], "plugin_activation_conflict");
    let generation = activated["generation"].as_u64().unwrap();
    assert!(generation > expected);
    assert_eq!(activated["graph_id"], graph);
    (graph, generation)
}

pub async fn wait_until(ready: impl FnMut() -> bool) {
    wait_for(ready, Duration::from_secs(20)).await;
}

pub async fn wait_for(mut ready: impl FnMut() -> bool, bound: Duration) {
    let deadline = Instant::now() + bound;
    while !ready() {
        assert!(Instant::now() < deadline, "fixture wait exceeded {bound:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub fn event_names(state: &AgentGatewayState, run_id: &str) -> Vec<String> {
    state
        .service()
        .run_events(run_id)
        .iter()
        .filter_map(|event| event["event"].as_str().map(str::to_string))
        .collect()
}

pub fn contains_marker(state: &AgentGatewayState, run_id: &str, marker: &str) -> bool {
    let events = state.service().run_events(run_id);
    if events
        .iter()
        .any(|event| event.to_string().contains(marker))
    {
        return true;
    }
    // Managed tool.output events keep publication metadata only. The output
    // text is published on the same-run tool-result message before the next
    // provider response is observed.
    let Some(session_id) = events.iter().find_map(|event| {
        event["data"]["session_id"]
            .as_str()
            .or_else(|| event["session_id"].as_str())
    }) else {
        return false;
    };
    state
        .service()
        .session_messages(session_id)
        .iter()
        .any(|message| {
            message["run_id"].as_str() == Some(run_id) && message.to_string().contains(marker)
        })
}

pub async fn shutdown_when_idle(state: &AgentGatewayState) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match state.service().shutdown().await {
            Ok(()) => return,
            Err(message) if message.contains("still active") && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(message) => panic!("{message}"),
        }
    }
}

pub fn current_generation(config: &AgentGatewayConfig, db: &Path) -> u64 {
    let persistence = GatewayPersistence::open(config, db).unwrap();
    PluginControlStore::new(&persistence)
        .activation()
        .unwrap()
        .generation
}

pub fn embedding_graph_id(config: &AgentGatewayConfig, db: &Path) -> String {
    let persistence = GatewayPersistence::open(config, db).unwrap();
    let control = PluginControlStore::new(&persistence);
    let locks = control.list_locks().unwrap();
    locks
        .iter()
        .find(|graph_id| {
            control
                .load_lock(graph_id)
                .unwrap()
                .lock
                .packages
                .iter()
                .any(|package| package.id == "org.rustscript.embedding.tools")
        })
        .cloned()
        .unwrap_or_else(|| panic!("formal embedding lock missing from {locks:?}"))
}

pub fn bound_store(db: &Path, auth: &InstallAuthorization) -> PackageStore {
    let store = PackageStore::open(rustscript_agent::plugins::trusted_tool_package_root(db))
        .expect("tool package root opens");
    store.bind_policy(auth);
    store
}

pub fn pin_for_run(config: &AgentGatewayConfig, db: &Path, run_id: &str) -> Value {
    let persistence = GatewayPersistence::open(config, db).unwrap();
    PluginControlStore::new(&persistence)
        .pin_for_run(run_id)
        .unwrap()
}

pub fn revoke_graph(
    config: &AgentGatewayConfig,
    db: &Path,
    packages: &PackageStore,
    graph_id: &str,
) -> Result<(), rustscript_agent::plugins::PluginControlError> {
    let persistence = GatewayPersistence::open(config, db).unwrap();
    PluginControlStore::new(&persistence)
        .revoke_graph(packages, graph_id)
        .map(|_| ())
}

pub fn assert_signed_write_pair_prepares_captured_catalog(root: &Path) {
    let (auth, package_a, package_b, package_state) = signed_tool_effects::stage_write_pair(root);
    let store = PackageStore::open(root.join("store")).unwrap();
    for (dir, id, marker, expect_catalog) in [
        (&package_a, "org.rustscript.tools.effecta", "A-write", true),
        (&package_b, "org.rustscript.tools.effectb", "B-write", true),
        (
            &package_state,
            "org.rustscript.tools.effectstate",
            "S-write",
            false,
        ),
    ] {
        let installed = store.install(&root.join(dir), &auth).unwrap();
        assert_eq!(
            installed.trust,
            rustscript_agent::plugins::PackageTrust::AcceptedPublisher
        );
        let lock = store
            .resolve(&rustscript_agent::plugins::ResolveRequest {
                harness_selection: rustscript_agent::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: id.into(),
                },
                roots: vec![rustscript_agent::plugins::PackageRequirement {
                    id: id.into(),
                    version: "1.0.0".into(),
                }],
                host_runtime: rustscript_agent::plugins::HOST_RUNTIME.into(),
            })
            .unwrap();
        let prepared = store.prepare(&lock).unwrap();
        assert_eq!(
            prepared.trust(id),
            Some(rustscript_agent::plugins::PackageTrust::AcceptedPublisher)
        );
        assert_ne!(
            prepared.trust(id),
            Some(rustscript_agent::plugins::PackageTrust::EmbeddingOwnedBuiltin)
        );
        let run = std::str::from_utf8(prepared.captured_source(id, "run.rss").unwrap()).unwrap();
        assert!(run.contains("cap::fs_write_atomic"), "{id}");
        assert!(run.contains(marker), "{id}");
        if expect_catalog {
            assert_eq!(
                prepared.captured_source(id, "catalog.rss").unwrap(),
                include_bytes!("../../rss/tools/types.rss"),
                "{id}"
            );
        } else {
            assert!(
                prepared.captured_source(id, "catalog.rss").is_none(),
                "{id}"
            );
        }
    }
}
