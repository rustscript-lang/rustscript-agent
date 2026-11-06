//! Plugin graph control through the production Axum app on real TCP.
//! Host binding and the verified owner credential authorize these routes.
//! Request JSON, graph ids, signatures, paths, and run identifiers do not.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rustscript_agent::build_agent_gateway_app;
use rustscript_agent::plugins::PluginControlStore;
use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, GatewayPersistence};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
    ) -> (u16, Value, String) {
        let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(format!("http://{}{path}", self.address));
        if let Some(token) = token {
            request = request.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = request
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(120), client.request(request))
            .await
            .unwrap()
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, parsed, raw)
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

fn private_root() -> PathBuf {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("plugin-admin-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn static_denial(body: &Value, raw: &str) {
    assert_eq!(body["error"]["code"], "managed_management_denied");
    assert!(
        !raw.contains('/') && !raw.contains("passwd") && !raw.contains("run-public"),
        "denial must not echo paths or caller identifiers: {raw}"
    );
}

#[tokio::test]
async fn unset_bearer_rejects_plugin_control_without_partial_native_effects() {
    let root = private_root();
    let db = root.join("gateway.sqlite");
    let config = AgentGatewayConfig::default();
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db).unwrap();
    let (before_activation, before_history) = {
        let before = GatewayPersistence::open(&config, &db).unwrap();
        let before_control = PluginControlStore::new(&before);
        (
            before_control.activation().unwrap(),
            before_control.activation_history().unwrap(),
        )
    };
    let http = Http::bind(state.clone()).await;
    let forged = json!({
        "admin": true,
        "path": "/etc/passwd",
        "graph_id": "caller-graph",
        "token": "run-public",
        "deployment_space": "other-space"
    });
    let routes = [
        ("POST", "/v1/plugins/install"),
        ("POST", "/v1/plugin-graphs/resolve"),
        ("POST", "/v1/plugin-graphs/caller-graph/prepare"),
        ("POST", "/v1/plugin-activations"),
        ("GET", "/v1/plugin-graphs/caller-graph"),
        ("POST", "/v1/plugin-activations/other-space.1/rollback"),
    ];
    for (method, path) in routes {
        let (status, body, raw) = http.request(method, path, forged.clone(), None).await;
        assert_eq!(status, 403, "{method} {path} raw={raw}");
        static_denial(&body, &raw);
    }
    http.close().await;
    {
        let reopened = GatewayPersistence::open(&config, &db).unwrap();
        let control = PluginControlStore::new(&reopened);
        let activation = control.activation().unwrap();
        assert_eq!(activation.graph_id, before_activation.graph_id);
        assert_eq!(activation.generation, before_activation.generation);
        assert_eq!(control.activation_history().unwrap(), before_history);
    }

    let http = Http::bind(state).await;
    let (session_status, session, _) = http.request("POST", "/api/sessions", json!({}), None).await;
    assert_eq!(session_status, 201);
    let session_id = session["session"]["id"].as_str().unwrap();
    let (run_status, run, _) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "ordinary"}),
            None,
        )
        .await;
    assert_eq!(run_status, 202);
    assert!(run["run_id"].as_str().is_some());
    http.close().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[allow(dead_code)]
#[path = "support/signed_tool_effects.rs"]
mod signed_tool_effects;

#[path = "support/plugin_admin_cycle.rs"]
mod plugin_admin_cycle;

fn no_private_text(raw: &str) {
    assert!(
        !raw.contains("/etc") && !raw.contains("passwd") && !raw.contains(".sqlite"),
        "response leaked a private path: {raw}"
    );
}

#[tokio::test]
async fn bearer_without_host_binding_rejects_forged_admin_and_run_identifier() {
    let root = private_root();
    let db = root.join("gateway.sqlite");
    let token = "owner-control-token";
    let config = AgentGatewayConfig {
        bearer_token: Some(token.into()),
        ..AgentGatewayConfig::default()
    };
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db).unwrap();
    let before = GatewayPersistence::open(&config, &db).unwrap();
    let before_activation = PluginControlStore::new(&before).activation().unwrap();
    drop(before);
    let http = Http::bind(state).await;
    let forged = json!({"admin": true, "path": "/etc/passwd", "package": "package-a", "deployment_space": "owner-space"});
    let (status, body, raw) = http
        .request("POST", "/v1/plugins/install", forged, Some(token))
        .await;
    assert_eq!(status, 403, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_control_unconfigured");
    no_private_text(&raw);
    let (status, body, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": "package-a", "deployment_space": "owner-space"}),
            Some("run-public-id"),
        )
        .await;
    assert_eq!(status, 401, "{raw}");
    assert_eq!(body["error"]["code"], "unauthorized");
    http.close().await;
    let reopened = GatewayPersistence::open(&config, &db).unwrap();
    let activation = PluginControlStore::new(&reopened).activation().unwrap();
    assert_eq!(activation, before_activation);
    let _ = std::fs::remove_dir_all(&root);
}

fn gateway_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rustscript-agent-gateway")
}

fn scrub_plugin_env(cmd: &mut tokio::process::Command) {
    for key in [
        "RUSTSCRIPT_AGENT_PLUGIN_SOURCE_ROOT",
        "RUSTSCRIPT_AGENT_PLUGIN_UNSIGNED_DEV",
        "RUSTSCRIPT_AGENT_PLUGIN_DEPLOYMENT_SPACE",
        "RUSTSCRIPT_AGENT_PLUGIN_PUBLISHER_DIR",
        "RUSTSCRIPT_AGENT_STATE_DB",
        "RUSTSCRIPT_AGENT_HOME",
        "RUSTSCRIPT_AGENT_GATEWAY_ADDR",
        "RUSTSCRIPT_AGENT_BEARER_TOKEN",
        "RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS",
        "PD_EDGE_AGENT_GATEWAY_ADDR",
        "PD_EDGE_AGENT_BEARER_TOKEN",
        "PD_EDGE_AGENT_ALLOW_ANONYMOUS",
        "PD_EDGE_AGENT_STATE_DB",
    ] {
        cmd.env_remove(key);
    }
}

struct GatewayChild {
    child: tokio::process::Child,
    stderr_path: PathBuf,
}

impl GatewayChild {
    fn spawn(root: &std::path::Path, envs: &[(&str, &std::path::Path)]) -> Self {
        let stderr_path = root.join("stderr.log");
        let stderr = std::fs::File::create(&stderr_path).unwrap();
        let mut cmd = tokio::process::Command::new(gateway_bin());
        scrub_plugin_env(&mut cmd);
        cmd.env("HOME", root)
            .env("RUSTSCRIPT_AGENT_HOME", root)
            .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
            .env("RUSTSCRIPT_AGENT_BEARER_TOKEN", "owner-control-token")
            .current_dir(root)
            .stderr(std::process::Stdio::from(stderr))
            .stdout(std::process::Stdio::null());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let child = cmd.spawn().expect("spawn gateway");
        Self { child, stderr_path }
    }

    fn stderr_text(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    async fn wait_listening(&mut self) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(45);
        loop {
            let text = self.stderr_text();
            if let Some(position) = text.find("listening on http://") {
                let rest = &text[position + "listening on http://".len()..];
                let address = rest.lines().next().unwrap_or("").trim().to_string();
                if !address.is_empty() {
                    return address;
                }
            }
            if self.child.try_wait().ok().flatten().is_some() {
                panic!("gateway exited before listen: {}", self.stderr_text());
            }
            if std::time::Instant::now() >= deadline {
                panic!("gateway did not listen: {}", self.stderr_text());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_exit_before_listen(&mut self, expected: &str) {
        let status = tokio::time::timeout(Duration::from_secs(45), self.child.wait())
            .await
            .expect("gateway exit")
            .expect("wait gateway");
        let text = self.stderr_text();
        assert!(!status.success(), "{text}");
        assert!(!text.contains("listening on http://"), "{text}");
        assert!(text.contains(expected), "{text}");
    }

    async fn stop(&mut self) {
        if let Some(pid) = self.child.id() {
            let _ = std::process::Command::new("kill")
                .args(["-INT", &pid.to_string()])
                .status();
        }
        let _ = tokio::time::timeout(Duration::from_secs(15), self.child.wait()).await;
    }
}

async fn binary_request(
    address: &str,
    method: &str,
    path: &str,
    body: Value,
) -> (u16, Value, String) {
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{path}"))
        .header(hyper::header::AUTHORIZATION, "Bearer owner-control-token")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(30), client.request(request))
        .await
        .expect("gateway response timeout")
        .expect("gateway response");
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed, raw)
}

#[tokio::test]
async fn binary_missing_source_root_stays_unbound() {
    let root = private_root();
    let mut child = GatewayChild::spawn(&root, &[]);
    let address = child.wait_listening().await;
    let (status, body, raw) = binary_request(
        &address,
        "POST",
        "/v1/plugins/install",
        json!({"package": "package-a", "deployment_space": "owner-space"}),
    )
    .await;
    assert_eq!(status, 403, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_control_unconfigured");
    child.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn binary_missing_deployment_space_fails_before_listen() {
    let root = private_root();
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let mut child = GatewayChild::spawn(
        &root,
        &[("RUSTSCRIPT_AGENT_PLUGIN_SOURCE_ROOT", source.as_path())],
    );
    child
        .wait_exit_before_listen("plugin control deployment space is not configured")
        .await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn binary_illegal_deployment_space_fails_before_listen() {
    let root = private_root();
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let stderr_path = root.join("stderr.log");
    let stderr = std::fs::File::create(&stderr_path).unwrap();
    let mut cmd = tokio::process::Command::new(gateway_bin());
    scrub_plugin_env(&mut cmd);
    cmd.env("HOME", &root)
        .env("RUSTSCRIPT_AGENT_HOME", &root)
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_BEARER_TOKEN", "owner-control-token")
        .env("RUSTSCRIPT_AGENT_PLUGIN_SOURCE_ROOT", &source)
        .env("RUSTSCRIPT_AGENT_PLUGIN_DEPLOYMENT_SPACE", "owner/space")
        .current_dir(&root)
        .stderr(std::process::Stdio::from(stderr))
        .stdout(std::process::Stdio::null());
    let mut child = cmd.spawn().expect("spawn gateway");
    let status = tokio::time::timeout(Duration::from_secs(45), child.wait())
        .await
        .expect("gateway exit")
        .expect("wait gateway");
    let text = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(!status.success(), "{text}");
    assert!(!text.contains("listening on http://"), "{text}");
    assert!(
        text.contains("plugin deployment space is invalid"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn binary_unsigned_dev_rejects_signed_package() {
    let root = private_root();
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let (_auth, package_a, _, _) = signed_tool_effects::stage_write_pair(&source);
    let db = root.join("gateway.sqlite");
    let mut child = GatewayChild::spawn(
        &root,
        &[
            ("RUSTSCRIPT_AGENT_PLUGIN_SOURCE_ROOT", source.as_path()),
            ("RUSTSCRIPT_AGENT_PLUGIN_UNSIGNED_DEV", source.as_path()),
            (
                "RUSTSCRIPT_AGENT_PLUGIN_DEPLOYMENT_SPACE",
                std::path::Path::new("owner-space"),
            ),
            ("RUSTSCRIPT_AGENT_STATE_DB", db.as_path()),
        ],
    );
    let address = child.wait_listening().await;
    let (status, body, raw) = binary_request(
        &address,
        "POST",
        "/v1/plugins/install",
        json!({"package": package_a, "deployment_space": "owner-space"}),
    )
    .await;
    assert_eq!(status, 403, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_publisher_unauthorized");
    child.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn binary_signed_policy_survives_process_restart_without_reinstall() {
    let root = private_root();
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let (auth, package_a, _, _) = signed_tool_effects::stage_write_pair(&source);
    let publishers = root.join("publishers");
    std::fs::create_dir_all(&publishers).unwrap();
    let key = &auth.accepted_publishers[0];
    std::fs::write(publishers.join(&key.publisher), &key.verifying_key).unwrap();
    let db = root.join("gateway.sqlite");
    let spawn_signed = |root: &std::path::Path| {
        let stderr_path = root.join("stderr.log");
        let stderr = std::fs::File::create(&stderr_path).unwrap();
        let mut cmd = tokio::process::Command::new(gateway_bin());
        scrub_plugin_env(&mut cmd);
        cmd.env("HOME", root)
            .env("RUSTSCRIPT_AGENT_HOME", root)
            .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
            .env("RUSTSCRIPT_AGENT_BEARER_TOKEN", "owner-control-token")
            .env("RUSTSCRIPT_AGENT_PLUGIN_SOURCE_ROOT", &source)
            .env("RUSTSCRIPT_AGENT_PLUGIN_PUBLISHER_DIR", &publishers)
            .env("RUSTSCRIPT_AGENT_PLUGIN_DEPLOYMENT_SPACE", "owner-space")
            .env("RUSTSCRIPT_AGENT_STATE_DB", &db)
            .current_dir(root)
            .stderr(std::process::Stdio::from(stderr))
            .stdout(std::process::Stdio::null());
        GatewayChild {
            child: cmd.spawn().expect("spawn signed gateway"),
            stderr_path,
        }
    };
    let mut first = spawn_signed(&root);
    let address = first.wait_listening().await;
    let (status, _, raw) = binary_request(
        &address,
        "POST",
        "/v1/plugins/install",
        json!({"package": package_a, "deployment_space": "owner-space"}),
    )
    .await;
    assert_eq!(status, 200, "{raw}");
    let (status, resolved, raw) = binary_request(
        &address,
        "POST",
        "/v1/plugin-graphs/resolve",
        json!({
            "roots": [{"id": "org.rustscript.tools.effecta", "version": "1.0.0"}],
            "tool_package": "org.rustscript.tools.effecta",
            "deployment_space": "owner-space"
        }),
    )
    .await;
    assert_eq!(status, 200, "{raw}");
    let graph_id = resolved["graph_id"].as_str().unwrap().to_string();
    let (status, _, raw) = binary_request(
        &address,
        "POST",
        &format!("/v1/plugin-graphs/{graph_id}/prepare"),
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{raw}");
    let (status, activated, raw) = binary_request(
        &address,
        "POST",
        "/v1/plugin-activations",
        json!({
            "graph_id": graph_id,
            "deployment_space": "owner-space",
            "expected_generation": 0
        }),
    )
    .await;
    assert_eq!(status, 200, "{raw}");
    let generation = activated["generation"].as_u64().unwrap();
    first.stop().await;

    let mut second = spawn_signed(&root);
    let address = second.wait_listening().await;
    let (status, prepared, raw) = binary_request(
        &address,
        "POST",
        &format!("/v1/plugin-graphs/{graph_id}/prepare"),
        json!({}),
    )
    .await;
    assert_eq!(
        status, 200,
        "process restart prepare without reinstall: {raw}"
    );
    assert_eq!(prepared["graph_id"], graph_id);
    assert_eq!(prepared["executable"], true);
    let (status, body, raw) = binary_request(
        &address,
        "POST",
        "/v1/plugin-activations",
        json!({
            "graph_id": graph_id,
            "deployment_space": "owner-space",
            "expected_generation": 0
        }),
    )
    .await;
    assert_eq!(status, 409, "{raw}");
    assert_eq!(body["error"]["code"], "plugin_activation_conflict");
    let (status, viewed, raw) = binary_request(
        &address,
        "GET",
        &format!("/v1/plugin-graphs/{graph_id}"),
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(viewed["graph_id"], graph_id);
    assert_eq!(viewed["contract"]["mode"], "tool_only");
    assert!(generation > 0);
    second.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}

// Stateful rollback negative control: the live session-max schema for the
// target package is newer than the rollback target's manifest schema, so the
// existing HTTP rollback route must refuse with `state_incompatible`, leave
// the activation generation untouched, and keep the referenced state root
// (and its object) readable.
#[tokio::test]
async fn stateful_rollback_refuses_newer_live_schema_without_advancing_generation() {
    use rustscript_agent::plugins::{
        PluginStateBindRequest, PluginStatePayload, PluginStateRootKey, PluginStateScope,
        PluginStateStore,
    };
    use std::sync::Arc;

    let root = private_root();
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&source).unwrap();
    let (auth, _package_a, _package_b, package_state) =
        signed_tool_effects::stage_write_pair(&source);
    let db = root.join("gateway.sqlite");
    let token = "owner-control-token";
    let config = AgentGatewayConfig {
        bearer_token: Some(token.into()),
        ..AgentGatewayConfig::default()
    };
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_plugin_control(auth, source.clone(), "owner-space")
        .unwrap();
    let http = Http::bind(state.clone()).await;

    let (status, _, raw) = http
        .request(
            "POST",
            "/v1/plugins/install",
            json!({"package": package_state, "deployment_space": "owner-space"}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");

    let (status, resolved, raw) = http
        .request(
            "POST",
            "/v1/plugin-graphs/resolve",
            json!({
                "roots": [{"id": "org.rustscript.tools.effectstate", "version": "1.0.0"}],
                "tool_package": "org.rustscript.tools.effectstate",
                "deployment_space": "owner-space"
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let graph = resolved["graph_id"].as_str().unwrap().to_string();

    let (status, prepared, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph}/prepare"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    assert_eq!(prepared["graph_id"], graph);
    assert_eq!(prepared["executable"], true);

    let (status, first, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph,
                "deployment_space": "owner-space",
                "expected_generation": 0
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_a = first["generation"].as_u64().unwrap();
    let (status, second, raw) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": graph,
                "deployment_space": "owner-space",
                "expected_generation": generation_a
            }),
            Some(token),
        )
        .await;
    assert_eq!(status, 200, "{raw}");
    let generation_b = second["generation"].as_u64().unwrap();
    assert!(generation_b > generation_a);

    // The referenced run root stays at the target schema (1); a second run
    // moves the live session-max schema to 2, newer than the rollback target.
    let persistence = state.persistence().expect("native persistence");
    persistence
        .session_create(&serde_json::json!({
            "id": "session-rollback-state",
            "profile": "default",
            "platform": "plugin-admin-api-test",
            "account_id": "session-rollback-state",
            "chat_id": "session-rollback-state",
            "thread_id": "",
            "user_id": "",
            "generation": 1,
            "system_prompt": "",
            "model": "test-model",
            "provider": "test-provider",
            "toolset_hash": "test-tools",
            "metadata_json": "{}",
            "title": "",
            "end_reason": "",
            "now_ms": 10,
        }))
        .expect("seed session");
    for (run_id, now_ms) in [("run-rollback-old", 11), ("run-rollback-new", 12)] {
        persistence
            .run_create(&serde_json::json!({
                "id": run_id,
                "session_id": "session-rollback-state",
                "parent_run_id": "",
                "input_json": "{}",
                "provider": "test-provider",
                "model": "test-model",
                "script_hash": "",
                "idempotency_scope": "",
                "idempotency_key": "",
                "now_ms": now_ms,
            }))
            .expect("seed run");
    }
    let store = PluginStateStore::open(Arc::clone(&persistence));
    // `session_max_schema` only tracks session-owned roots, so both roots
    // below use session scope: the referenced root stays at the target
    // schema (1) while a second workspace/branch moves the live max to 2.
    let referenced = store
        .bind_run(&PluginStateBindRequest {
            run_id: "run-rollback-old".into(),
            session_id: "session-rollback-state".into(),
            workspace_id: "workspace-rollback".into(),
            branch_id: "branch-rollback".into(),
            plugin_id: "org.rustscript.tools.effectstate".into(),
            package_id: "org.rustscript.tools.effectstate".into(),
            artifact_id: "artifact-rollback-state".into(),
            scope: PluginStateScope::Session,
            graph_id: graph.clone(),
            epoch: 1,
            schema: 1,
            checkpoint_id: String::new(),
        })
        .expect("bind referenced root");
    let written = store
        .commit(
            &referenced,
            &PluginStatePayload::parse(r#"{"count":1}"#).expect("payload"),
        )
        .expect("commit referenced value");
    store
        .bind_run(&PluginStateBindRequest {
            run_id: "run-rollback-new".into(),
            session_id: "session-rollback-state".into(),
            workspace_id: "workspace-rollback-next".into(),
            branch_id: "branch-rollback-next".into(),
            plugin_id: "org.rustscript.tools.effectstate".into(),
            package_id: "org.rustscript.tools.effectstate".into(),
            artifact_id: "artifact-rollback-state".into(),
            scope: PluginStateScope::Session,
            graph_id: graph.clone(),
            epoch: 1,
            schema: 2,
            checkpoint_id: String::new(),
        })
        .expect("bind newer live root");
    assert_eq!(
        store
            .session_max_schema("org.rustscript.tools.effectstate")
            .expect("live max schema"),
        2
    );

    let before = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation()
        .unwrap();
    assert_eq!(before.generation, generation_b);
    let history_before =
        PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
            .activation_history()
            .unwrap();
    assert_eq!(history_before.len(), 2);

    let (status, body, raw) = http
        .request(
            "POST",
            &format!("/v1/plugin-activations/owner-space.{generation_a}/rollback"),
            json!({}),
            Some(token),
        )
        .await;
    assert_eq!(status, 422, "{raw}");
    assert_eq!(body["error"]["code"], "state_incompatible", "{raw}");

    let after = PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
        .activation()
        .unwrap();
    assert_eq!(after, before);
    let history_after =
        PluginControlStore::new(&GatewayPersistence::open(&config, &db).unwrap())
            .activation_history()
            .unwrap();
    assert_eq!(history_after, history_before);

    let key = PluginStateRootKey {
        owner_kind: "session".into(),
        owner_id: "session-rollback-state".into(),
        workspace_id: "workspace-rollback".into(),
        branch_id: "branch-rollback".into(),
        plugin_id: "org.rustscript.tools.effectstate".into(),
    };
    let surviving = store
        .root(&key)
        .expect("read referenced root")
        .expect("referenced state root survives refused rollback");
    assert_eq!(surviving.revision, written.binding.revision);
    assert_eq!(
        store
            .object_payload(&surviving.object_id)
            .expect("read referenced object")
            .as_str(),
        written.payload.as_str()
    );

    http.close().await;
    let _ = std::fs::remove_dir_all(&root);
}
