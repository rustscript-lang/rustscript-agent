//! Task 9: real service worker, unified cancellation/deadline, zero-residue cleanup.

mod common;

use std::any::Any;
use std::fs;
use std::future::Future;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use rustscript_agent::config::{ProviderProfile, RunLimits};
use rustscript_agent::{
    AdmitRunRequest, AgentConfig, AgentGatewayConfig, AgentGatewayState, AgentRunner, AgentService,
    LlmContentBlock, ScriptedProvider, ToolCall,
};
use serde_json::{Value as JsonValue, json};

fn text_response(text: &str) -> JsonValue {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

fn tool_response(text: &str, tool_calls: JsonValue) -> JsonValue {
    json!({
        "text": text,
        "tool_calls": tool_calls,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    })
}

fn background_sleep_call() -> JsonValue {
    json!([{
        "id": "call-sleep",
        "name": "terminal",
        "arguments": {
            "argv": ["/bin/sleep", "30"],
            "background": true,
            "timeout_ms": 5000
        }
    }])
}

fn guardian_high_authorized_response() -> JsonValue {
    text_response(
        r#"{"outcome":"allow","risk_level":"high","user_authorization":"high","rationale":"The admitted request explicitly authorizes this exact synthetic child process."}"#,
    )
}

fn admit_request() -> AdmitRunRequest {
    AdmitRunRequest {
        input: json!({"message": "hello"}),
        platform: "run_lifecycle_tests".to_string(),
        ..AdmitRunRequest::default()
    }
}

const STOP_CHILD_USER_INTENT: &str = "For this lifecycle test, start exactly one `/bin/sleep 30` process as a background child inside the selected `lifecycle` workspace. I explicitly authorize this process launch; I will stop it immediately.";
const DEADLINE_CHILD_USER_INTENT: &str = "For this deadline test, start exactly one `/bin/sleep 30` process as a background child. I explicitly authorize this exact process launch; the admitted deadline must terminate it.";

fn admit_stop_child_request() -> AdmitRunRequest {
    AdmitRunRequest {
        input: json!({"message": STOP_CHILD_USER_INTENT}),
        platform: "run_lifecycle_tests".to_string(),
        ..AdmitRunRequest::default()
    }
}

fn short_config(run_timeout: Duration) -> AgentGatewayConfig {
    AgentGatewayConfig {
        run_timeout,
        cancellation_grace: Duration::from_millis(80),
        ..AgentGatewayConfig::default()
    }
}

fn terminal_events(service: &AgentService, run_id: &str) -> Vec<String> {
    service
        .run_events(run_id)
        .into_iter()
        .filter_map(|event| {
            let name = event.get("event")?.as_str()?;
            matches!(name, "run.completed" | "run.cancelled" | "run.failed")
                .then(|| name.to_string())
        })
        .collect()
}

fn cancel_reason(service: &AgentService, run_id: &str) -> String {
    service
        .run_events(run_id)
        .into_iter()
        .find(|event| event["event"] == "run.cancelled")
        .and_then(|event| {
            event
                .pointer("/data/reason")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default()
}

async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

fn pid_alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let Some(close) = stat.rfind(')') else {
                return true;
            };
            let state = stat[close + 1..].split_whitespace().next().unwrap_or("");
            state != "Z"
        }
        Err(_) => false,
    }
}

fn failed_error_code(service: &AgentService, run_id: &str) -> String {
    service
        .run_events(run_id)
        .into_iter()
        .rev()
        .find_map(|event| {
            (event.get("event").and_then(JsonValue::as_str) == Some("run.failed"))
                .then(|| {
                    event
                        .pointer("/data/error_code")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string)
                })
                .flatten()
        })
        .unwrap_or_default()
}

fn loop_service(config: AgentGatewayConfig, provider: &ScriptedProvider) -> AgentGatewayState {
    let state =
        AgentGatewayState::with_agent_file(config, rustscript_agent::bundled_agent_main_path())
            .expect("bundled agent loop should compile");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
}

struct LifecycleWorkspaceFixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
}

fn lifecycle_workspace_fixture_at(root: PathBuf) -> LifecycleWorkspaceFixture {
    let home = root.join("workspace-home");
    let workspace = root.join("workspace");
    fs::create_dir_all(&home).expect("private workspace home");
    fs::create_dir_all(&workspace).expect("private lifecycle workspace");
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    rustscript_agent::config_file::ConfigFile::from_str(&config)
        .expect("synthetic lifecycle workspace config");
    fs::write(home.join("config.yaml"), config).expect("synthetic workspace policy");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &home, &workspace] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private lifecycle fixture directory mode");
        }
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("private workspace config mode");
    }
    LifecycleWorkspaceFixture {
        root,
        home,
        workspace,
    }
}

fn lifecycle_workspace_fixture(label: &str) -> LifecycleWorkspaceFixture {
    lifecycle_workspace_fixture_at(unique_temp_dir(label))
}

fn lifecycle_workspace_fixture_with_guard(
    label: &str,
) -> (LifecycleWorkspaceFixture, OwnedPrivateFixtureDirectory) {
    let root = unique_temp_dir(label);
    let guard = OwnedPrivateFixtureDirectory::create(root.clone())
        .expect("create owned private lifecycle fixture root");
    (lifecycle_workspace_fixture_at(root), guard)
}

fn loop_service_with_workspace(
    config: AgentGatewayConfig,
    provider: &ScriptedProvider,
    workspace: &LifecycleWorkspaceFixture,
) -> AgentGatewayState {
    let state =
        AgentGatewayState::with_agent_file(config, rustscript_agent::bundled_agent_main_path())
            .expect("bundled agent loop should compile")
            .with_workspace_home(workspace.home.clone());
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
}

fn test_temp_root() -> PathBuf {
    let root = std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "rustscript-agent-run-lifecycle-{}",
                std::process::id()
            ))
        });
    fs::create_dir_all(&root).expect("test temp root should exist");
    assert_temp_path_is_lease_safe(&root);
    root
}

fn unique_temp_dir(label: &str) -> PathBuf {
    test_temp_root().join(format!(
        "{}-{}-{}",
        label,
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
}

struct OwnedPrivateFixtureDirectory {
    path: PathBuf,
    owned: bool,
}

impl OwnedPrivateFixtureDirectory {
    fn create(path: PathBuf) -> std::io::Result<Self> {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self { path, owned: true })
    }

    fn cleanup(&mut self) -> std::io::Result<()> {
        if self.owned {
            fs::remove_dir_all(&self.path)?;
            self.owned = false;
        }
        Ok(())
    }
}

impl Drop for OwnedPrivateFixtureDirectory {
    fn drop(&mut self) {
        if self.owned {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn write_private_fixture_file(path: &std::path::Path, contents: &str) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("create private fixture file");
    file.write_all(contents.as_bytes())
        .expect("write private fixture file");
}

#[test]
fn private_auth_home_is_removed_after_fixture_setup_error() {
    let auth_home = unique_temp_dir("tls-fixture-setup-error");
    let setup_result = (|| -> std::io::Result<()> {
        let _auth_home = OwnedPrivateFixtureDirectory::create(auth_home.clone())?;
        write_private_fixture_file(&auth_home.join("config.yaml"), "synthetic: config\n");
        write_private_fixture_file(&auth_home.join("auth.yaml"), "token: synthetic-only\n");
        Err(std::io::Error::other(
            "injected setup failure after private fixture files",
        ))
    })();
    let remained_after_error = auth_home.exists();
    if remained_after_error {
        fs::remove_dir_all(&auth_home).expect("remove RED-test fixture residue");
    }

    assert!(setup_result.is_err(), "the setup failure must be injected");
    assert!(
        !remained_after_error,
        "owned synthetic auth home must be removed when setup returns an error"
    );

    let preexisting = unique_temp_dir("tls-fixture-preexisting");
    fs::create_dir(&preexisting).expect("create test-owned preexisting directory");
    let marker = preexisting.join("owner-marker");
    fs::write(&marker, b"test-owned").expect("write test-owned marker");
    let creation_error = OwnedPrivateFixtureDirectory::create(preexisting.clone());
    let marker_preserved = fs::read(&marker).is_ok_and(|bytes| bytes == b"test-owned");
    fs::remove_dir_all(&preexisting).expect("remove test-owned preexisting directory");
    assert!(
        creation_error.is_err(),
        "guard must refuse a preexisting path"
    );
    assert!(
        marker_preserved,
        "refusing a path must preserve its existing contents"
    );
}

#[derive(Debug)]
struct OwnedLoopbackRequest {
    method: String,
    path: String,
    has_bearer: bool,
    body_bytes: usize,
}

type OwnedServerPanic = Box<dyn Any + Send + 'static>;
type OwnedServerIo = Pin<Box<dyn Future<Output = Result<(), OwnedServerPanic>> + Send>>;

const OWNED_LOOPBACK_SERVER_GRACEFUL_BOUND: Duration = Duration::from_secs(5);

struct OwnedLoopbackServer {
    address: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    io: Option<OwnedServerIo>,
    completed: Option<Result<(), OwnedServerPanic>>,
}

impl OwnedLoopbackServer {
    fn from_future<F>(
        address: SocketAddr,
        shutdown: tokio::sync::oneshot::Sender<()>,
        future: F,
    ) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self {
            address,
            shutdown: Some(shutdown),
            io: Some(Box::pin(AssertUnwindSafe(future).catch_unwind())),
            completed: None,
        }
    }

    fn start(
        listener: tokio::net::TcpListener,
        address: SocketAddr,
        server_tls: Arc<rustls::ServerConfig>,
        accepted_tx: tokio::sync::oneshot::Sender<OwnedLoopbackRequest>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let io = async move {
            use tokio::io::AsyncReadExt;

            let mut shutdown_rx = shutdown_rx;
            let tcp = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(_) => return,
                },
                _ = &mut shutdown_rx => return,
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(server_tls);
            let Ok(Ok(mut stream)) =
                tokio::time::timeout(Duration::from_secs(2), acceptor.accept(tcp)).await
            else {
                return;
            };
            let request = tokio::time::timeout(Duration::from_secs(2), async {
                let mut received = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut chunk).await.map_err(|_| ())?;
                    if count == 0 {
                        return Err(());
                    }
                    received.extend_from_slice(&chunk[..count]);
                    if received.len() > 128 * 1024 {
                        return Err(());
                    }
                    if let Some(request) = parse_owned_loopback_request(&received) {
                        return Ok(request);
                    }
                }
            })
            .await;
            let Ok(Ok(request)) = request else {
                return;
            };
            let _ = accepted_tx.send(request);
            let _ = shutdown_rx.await;
        };
        Self::from_future(address, shutdown_tx, io)
    }

    async fn shutdown_and_reap(&mut self, graceful_bound: Duration) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let graceful_bound = graceful_bound.min(OWNED_LOOPBACK_SERVER_GRACEFUL_BOUND);
        let mut completion = self.completed.take();
        let mut io = self.io.take();
        let mut failure = None;
        match (completion.is_some(), io.as_mut()) {
            (true, _) => {}
            (false, Some(io)) => match tokio::time::timeout(graceful_bound, io.as_mut()).await {
                Ok(result) => completion = Some(result),
                Err(_) => {
                    failure = Some(
                        "owned TLS server exceeded graceful shutdown bound; owned future was dropped",
                    );
                }
            },
            (false, None) => {
                failure = Some("owned TLS server future was already consumed");
            }
        }
        if matches!(completion.as_ref(), Some(Err(_))) {
            failure = Some("owned TLS server future panicked");
        }

        // The future owns the listener and accepted stream; drop it before probing the exact address.
        drop(io);
        let socket_failure = match std::net::TcpListener::bind(self.address) {
            Ok(probe) => {
                drop(probe);
                None
            }
            Err(error) => Some(format!(
                "owned TLS server socket was not released after dropping its future: {error}"
            )),
        };
        match (failure, socket_failure) {
            (None, None) => Ok(()),
            (Some(message), None) => Err(message.to_string()),
            (None, Some(error)) => Err(error),
            (Some(message), Some(error)) => Err(format!("{message}; {error}")),
        }
    }
}

async fn poll_during_operation<T, F>(
    server: &mut OwnedLoopbackServer,
    operation: F,
) -> Result<T, OwnedServerPanic>
where
    F: Future<Output = T>,
{
    let mut operation = Box::pin(AssertUnwindSafe(operation).catch_unwind());
    loop {
        if server.completed.is_some() || server.io.is_none() {
            return operation.await;
        }
        let server_io = server
            .io
            .as_mut()
            .expect("owned TLS server future is present")
            .as_mut();
        tokio::select! {
            result = operation.as_mut() => return result,
            result = server_io => server.completed = Some(result),
        }
    }
}

fn resume_observation_panic<T>(observation: Result<T, OwnedServerPanic>) -> T {
    match observation {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn panic_with_owned_marker(marker: Arc<()>) {
    std::panic::panic_any(marker);
}

struct OwnedLoopbackHttpsTransport {
    port: u16,
    tls: Arc<rustls::ClientConfig>,
}

fn owned_loopback_transport_error() -> rustscript_agent::auth::oauth::OAuthError {
    rustscript_agent::auth::oauth::OAuthError::Transport {
        message: "owned loopback TLS fixture transport failed".to_string(),
    }
}

impl rustscript_agent::auth::oauth::BoundedHttpsTransport for OwnedLoopbackHttpsTransport {
    fn send(
        &self,
        request: &rustscript_agent::auth::oauth::PreparedHttpsRequest,
        context: &rustscript_agent::auth::oauth::OAuthIoContext,
    ) -> Result<
        rustscript_agent::auth::oauth::RawHttpsResponse,
        rustscript_agent::auth::oauth::OAuthError,
    > {
        context.check()?;
        let url = url::Url::parse(&request.url).map_err(|_| owned_loopback_transport_error())?;
        if url.scheme() != "https"
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(self.port)
            || request.body.len() > context.max_request_body_bytes()
        {
            return Err(owned_loopback_transport_error());
        }
        let timeout = context.remaining()?.max(Duration::from_millis(1));
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));
        let socket = std::net::TcpStream::connect_timeout(&address, timeout)
            .map_err(|_| owned_loopback_transport_error())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|_| owned_loopback_transport_error())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(1)))
            .map_err(|_| owned_loopback_transport_error())?;
        let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())
            .map_err(|_| owned_loopback_transport_error())?;
        let connection = rustls::ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|_| owned_loopback_transport_error())?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let target = format!(
            "{}{}",
            url.path(),
            url.query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        let mut wire = format!(
            "{} {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: keep-alive\r\nContent-Length: {}\r\n",
            request.method,
            self.port,
            request.body.len()
        )
        .into_bytes();
        for (name, value) in &request.headers {
            if name.eq_ignore_ascii_case("host")
                || name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            wire.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(request.body.as_bytes());
        context.check()?;
        stream
            .write_all(&wire)
            .map_err(|_| owned_loopback_transport_error())?;
        stream
            .flush()
            .map_err(|_| owned_loopback_transport_error())?;
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(20)))
            .map_err(|_| owned_loopback_transport_error())?;
        let mut response_byte = [0_u8; 1];
        loop {
            context.check()?;
            match stream.read(&mut response_byte) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Ok(_) | Err(_) => return Err(owned_loopback_transport_error()),
            }
        }
    }
}

fn owned_loopback_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])
        .expect("generate owned loopback TLS certificate");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certified.cert.der().clone())
        .expect("trust only the owned loopback TLS certificate");
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                .into(),
        )
        .expect("configure owned loopback TLS server");
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

fn parse_owned_loopback_request(bytes: &[u8]) -> Option<OwnedLoopbackRequest> {
    let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut lines = headers.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    if request_line.next()? != "HTTP/1.1" {
        return None;
    }
    let mut content_length = None;
    let mut has_bearer = false;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        }
        if name.eq_ignore_ascii_case("authorization") {
            has_bearer = value.trim().to_ascii_lowercase().starts_with("bearer ");
        }
    }
    let body_bytes = content_length?;
    if bytes.len() < header_end + 4 + body_bytes {
        return None;
    }
    Some(OwnedLoopbackRequest {
        method,
        path,
        has_bearer,
        body_bytes,
    })
}

fn assert_temp_path_is_lease_safe(path: &std::path::Path) {
    if let Some(test_tmpdir) = std::env::var_os("TEST_TMPDIR") {
        let root = PathBuf::from(test_tmpdir);
        assert!(
            path.starts_with(&root),
            "run-lifecycle temp paths must stay under TEST_TMPDIR ({}); got {}",
            root.display(),
            path.display()
        );
        return;
    }
    let rendered = path.to_string_lossy();
    assert!(
        path.starts_with(std::env::temp_dir()),
        "run-lifecycle temp paths must use std::env::temp_dir when TEST_TMPDIR is unset: {rendered}"
    );
    let worktrees = format!("/{}s/", "worktree");
    let lease_tmp = format!("/mnt/{}/workspace/rustscript-agent/tmp/", "TEMP");
    let prod_tmp = format!("/tmp/{}-agent-", "prod");
    assert!(
        !rendered.contains(&worktrees)
            && !rendered.contains(&lease_tmp)
            && !rendered.contains(&prod_tmp),
        "run-lifecycle temp paths must not write into a hardcoded sibling lease path: {rendered}"
    );
}

fn temporary_db_path() -> PathBuf {
    test_temp_root().join(format!("{}.db", uuid::Uuid::new_v4()))
}

fn loop_service_sqlite(
    config: AgentGatewayConfig,
    provider: &ScriptedProvider,
    path: &std::path::Path,
) -> AgentGatewayState {
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        config,
        rustscript_agent::bundled_agent_main_path(),
        path,
    )
    .expect("bundled agent loop should compile against sqlite");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    state
}

fn assistant_messages(service: &AgentService, session_id: &str) -> Vec<JsonValue> {
    service
        .session_messages(session_id)
        .into_iter()
        .filter(|message| message["role"] == "assistant")
        .collect()
}

fn event_names(service: &AgentService, run_id: &str) -> Vec<String> {
    service
        .run_events(run_id)
        .into_iter()
        .filter_map(|event| {
            event
                .get("event")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn tool_event_count(service: &AgentService, run_id: &str) -> usize {
    event_names(service, run_id)
        .into_iter()
        .filter(|name| name.starts_with("tool."))
        .count()
}

fn named_event_count(service: &AgentService, run_id: &str, name: &str) -> usize {
    event_names(service, run_id)
        .into_iter()
        .filter(|event_name| event_name == name)
        .count()
}

fn event_attempts(service: &AgentService, run_id: &str, name: &str) -> Vec<u64> {
    service
        .run_events(run_id)
        .into_iter()
        .filter(|event| event["event"] == name)
        .filter_map(|event| event["data"]["attempt"].as_u64())
        .collect()
}

fn retryable_provider_error() -> JsonValue {
    json!({
        "status": 503,
        "type": "server_error",
        "code": "unavailable",
        "message": "down",
        "param": "",
        "request_id": "",
        "retryable": true
    })
}

fn activity_values(service: &AgentService) -> [u64; 5] {
    let snapshot = service.metrics().snapshot();
    [
        snapshot.model_calls,
        snapshot.tool_calls,
        snapshot.tool_failures,
        snapshot.turns,
        snapshot.truncations,
    ]
}

fn prometheus_counter(render: &str, name: &str) -> u64 {
    let prefix = format!("{name} ");
    let mut values = Vec::new();
    for line in render.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            if rest.starts_with('{') {
                continue;
            }
            values.push(
                rest.split_whitespace()
                    .next()
                    .expect("prometheus sample value")
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("{name} should be a u64, got {rest:?}")),
            );
        }
    }
    assert_eq!(
        values.len(),
        1,
        "{name} must have exactly one unlabelled sample, got {values:?} in:\n{render}"
    );
    values[0]
}

fn assert_prometheus_matches_snapshot(service: &AgentService) {
    let snapshot = service.metrics().snapshot();
    let render = service.metrics().render_prometheus();
    assert_eq!(
        prometheus_counter(&render, "agent_model_calls_total"),
        snapshot.model_calls
    );
    assert_eq!(
        prometheus_counter(&render, "agent_tool_calls_total"),
        snapshot.tool_calls
    );
    assert_eq!(
        prometheus_counter(&render, "agent_tool_failures_total"),
        snapshot.tool_failures
    );
    assert_eq!(
        prometheus_counter(&render, "agent_turns_total"),
        snapshot.turns
    );
    assert_eq!(
        prometheus_counter(&render, "agent_truncations_total"),
        snapshot.truncations
    );
}

fn assert_frozen_prompt_exactly_once(
    service: &AgentService,
    run_id: &str,
    provider: &ScriptedProvider,
) {
    let prompt = service
        .run_context(run_id)
        .expect("frozen context")
        .coding_system_prompt
        .expect("admission must freeze a coding system prompt");
    assert!(!prompt.is_empty(), "frozen coding prompt must be non-empty");
    let requests = provider.requests();
    assert!(
        !requests.is_empty(),
        "provider must observe at least one request"
    );
    for request in &requests {
        let messages = request["messages"]
            .as_array()
            .expect("provider request messages");
        let system: Vec<_> = messages
            .iter()
            .filter(|message| message["role"] == "system")
            .collect();
        assert_eq!(
            system.len(),
            1,
            "frozen prompt must appear as exactly one system message: {request}"
        );
        assert_eq!(messages[0]["role"], json!("system"));
        let text = messages[0]["content"][0]["text"]
            .as_str()
            .expect("system text");
        assert_eq!(text, prompt);
        for later in messages.iter().skip(1) {
            assert_ne!(
                later["content"][0]["text"].as_str(),
                Some(prompt.as_str()),
                "frozen prompt must not be duplicated into later messages"
            );
        }
    }
}

fn has_tool_result_event(service: &AgentService, run_id: &str, tool_call_id: &str) -> bool {
    service.run_events(run_id).into_iter().any(|event| {
        matches!(
            event.get("event").and_then(JsonValue::as_str),
            Some("tool.output" | "tool.completed" | "tool.failed")
        ) && event
            .pointer("/data/tool_call_id")
            .and_then(JsonValue::as_str)
            == Some(tool_call_id)
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn scripted_real_worker_completes_with_provider_answer() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("loop-ok"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let terminals = terminal_events(&service, &admitted.run_id);
    assert_eq!(
        terminals,
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let payload = service
        .run_events(&admitted.run_id)
        .into_iter()
        .find(|event| event["event"] == "run.completed")
        .expect("completed terminal");
    let rendered = payload.to_string();
    assert!(
        rendered.contains("loop-ok"),
        "completed output should carry the scripted answer: {rendered}"
    );
    assert_eq!(provider.call_count(), 1);
    assert!(!service.capability_host_retained(&admitted.run_id));
    assert!(service.capability_host_closed(&admitted.run_id));
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_hanging_provider_cancels_once() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(5), || provider.call_count() >= 1).await,
        "provider should enter the hanging call"
    );
    assert_eq!(service.stop(&admitted.run_id).as_deref(), Some("stopping"));
    worker.await.expect("worker join");

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert!(service.capability_host_closed(&admitted.run_id));
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_terminates_child_process_without_residue() {
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response("", background_sleep_call()));
    provider.push_ok(guardian_high_authorized_response());
    provider.push_hang();
    let (workspace, mut workspace_guard) = lifecycle_workspace_fixture_with_guard("stop-child");
    let database = workspace.root.join("stop-child.sqlite3");
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig::default(),
        rustscript_agent::bundled_agent_main_path(),
        &database,
    )
    .expect("private lifecycle approval database")
    .with_workspace_home(workspace.home.clone());
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let service = state.service();
    let admitted = service
        .admit_external_with_workspace_selector(
            admit_stop_child_request(),
            Some("name:lifecycle".to_string()),
        )
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    let observation_started = Instant::now();
    let spawned = wait_until(Duration::from_secs(8), || {
        service.process_owner_count(&admitted.run_id) > 0
    })
    .await;
    let business_followup_reached = if spawned {
        wait_until(
            Duration::from_secs(8).saturating_sub(observation_started.elapsed()),
            || provider.call_count() >= 3,
        )
        .await
    } else {
        false
    };
    let requests = provider.requests();
    let guardian_positions: Vec<usize> = requests
        .iter()
        .enumerate()
        .filter_map(|(index, request)| {
            request
                .to_string()
                .contains("You are Guardian, reviewing one proposed tool action.")
                .then_some(index + 1)
        })
        .collect();
    let context = service.run_context(&admitted.run_id);
    let admitted_user_intent = context
        .as_ref()
        .and_then(|run| run.input.get("message"))
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let guardian_has_admitted_intent = !admitted_user_intent.is_empty()
        && guardian_positions.iter().any(|position| {
            requests
                .get(position - 1)
                .is_some_and(|request| request.to_string().contains(admitted_user_intent))
        });
    let guardian_has_terminal_action = guardian_positions.iter().any(|position| {
        requests.get(position - 1).is_some_and(|request| {
            let request = request.to_string();
            request.contains("terminal") && request.contains("/bin/sleep")
        })
    });
    let input_is_canonical_stop_intent = context
        .as_ref()
        .is_some_and(|run| run.input == json!({"message": STOP_CHILD_USER_INTENT}));
    let workspace_binding_matches = context
        .as_ref()
        .and_then(|run| run.limits["workspace_root"].as_str())
        .is_some_and(|path| workspace.workspace.to_str() == Some(path));
    let events = service.run_events(&admitted.run_id);
    let pre_stop_events: Vec<String> = events
        .iter()
        .filter_map(|event| event.get("event").and_then(JsonValue::as_str))
        .map(str::to_string)
        .collect();
    let typed_error_codes: Vec<String> = events
        .iter()
        .filter_map(|event| {
            let name = event.get("event").and_then(JsonValue::as_str)?;
            let code = event
                .pointer("/data/error_code")
                .or_else(|| event.pointer("/data/error/code"))
                .and_then(JsonValue::as_str)?;
            Some(format!("{name}:{code}"))
        })
        .collect();
    let pids = service.process_owner_pids(&admitted.run_id);
    let live_pids_before_stop = pids.iter().filter(|pid| pid_alive(**pid)).count();
    let pre_stop_provider_calls = provider.call_count();
    let pre_stop_provider_requests = requests.len();
    let business_requests = pre_stop_provider_requests.saturating_sub(guardian_positions.len());
    let diagnostic = format!(
        "pre-stop: provider_calls={pre_stop_provider_calls} provider_requests={pre_stop_provider_requests} business_requests={business_requests} business_followup_reached={business_followup_reached} guardian_positions={guardian_positions:?} guardian_has_admitted_intent={guardian_has_admitted_intent} guardian_has_terminal_action={guardian_has_terminal_action} input_is_canonical_stop_intent={input_is_canonical_stop_intent} workspace_binding_matches={workspace_binding_matches} workspace_config_exists={} capability_host_retained={} capability_host_closed={} process_owners={} owned_pids={} live_owned_pids={live_pids_before_stop} events={pre_stop_events:?} typed_error_codes={typed_error_codes:?} run_error_code={}",
        workspace.home.join("config.yaml").is_file(),
        service.capability_host_retained(&admitted.run_id),
        service.capability_host_closed(&admitted.run_id),
        service.process_owner_count(&admitted.run_id),
        pids.len(),
        failed_error_code(&service, &admitted.run_id)
    );

    let stop_result = service.stop(&admitted.run_id);
    let worker_result = worker.await;
    let terminals = terminal_events(&service, &admitted.run_id);
    let reason = cancel_reason(&service, &admitted.run_id);
    let owners_after_stop = service.process_owner_count(&admitted.run_id);
    let live_pids_after_stop = pids.iter().filter(|pid| pid_alive(**pid)).count();
    let capability_closed = service.capability_host_closed(&admitted.run_id);
    drop(service);
    drop(state);
    let fixture_cleanup = workspace_guard.cleanup();

    assert_eq!(stop_result.as_deref(), Some("stopping"), "{diagnostic}");
    assert!(worker_result.is_ok(), "worker join failed: {diagnostic}");
    assert_eq!(terminals, vec!["run.cancelled".to_string()], "{diagnostic}");
    assert_eq!(reason, "requested", "{diagnostic}");
    assert_eq!(owners_after_stop, 0, "{diagnostic}");
    assert_eq!(live_pids_after_stop, 0, "{diagnostic}");
    assert!(capability_closed, "{diagnostic}");
    fixture_cleanup.expect("remove private stop workspace fixture");
    assert!(
        spawned,
        "child process should be owned before stop: {diagnostic}"
    );
    assert!(
        business_followup_reached,
        "live follow-up provider call should be held before stop: {diagnostic}"
    );
    assert_eq!(
        pre_stop_provider_calls, 3,
        "business/review/business call sequence: {diagnostic}"
    );
    assert_eq!(
        pre_stop_provider_requests, 3,
        "business/review/business request sequence: {diagnostic}"
    );
    assert_eq!(
        business_requests, 2,
        "business request count excludes one Guardian review: {diagnostic}"
    );
    assert_eq!(
        guardian_positions,
        vec![2],
        "Guardian must review between business turns: {diagnostic}"
    );
    assert!(
        guardian_has_admitted_intent,
        "Guardian must receive canonical admitted user intent: {diagnostic}"
    );
    assert!(
        guardian_has_terminal_action,
        "Guardian must receive the exact native terminal action: {diagnostic}"
    );
    assert!(
        input_is_canonical_stop_intent,
        "admitted run input must remain canonical: {diagnostic}"
    );
    assert!(
        workspace_binding_matches,
        "run must remain bound to the selected private workspace: {diagnostic}"
    );
    assert!(!pids.is_empty(), "no owned PID was observed: {diagnostic}");
    assert_eq!(
        live_pids_before_stop,
        pids.len(),
        "every owned PID should be live before stop: {diagnostic}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_terminates_child_process_without_residue() {
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response("", background_sleep_call()));
    provider.push_ok(guardian_high_authorized_response());
    provider.push_hang();
    let fixture_root = unique_temp_dir("deadline-child");
    let mut fixture_guard = OwnedPrivateFixtureDirectory::create(fixture_root.clone())
        .expect("create private deadline approval fixture");
    let database = fixture_root.join("deadline-child.sqlite3");
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        short_config(Duration::from_millis(250)),
        rustscript_agent::bundled_agent_main_path(),
        &database,
    )
    .expect("private deadline approval database");
    state
        .service()
        .inject_provider_host(Arc::new(provider.clone()));
    let service = state.service();
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": DEADLINE_CHILD_USER_INTENT}),
            platform: "run_lifecycle_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admission should succeed");
    let started = Instant::now();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let elapsed = started.elapsed();
    let terminals = terminal_events(&service, &admitted.run_id);
    let reason = cancel_reason(&service, &admitted.run_id);
    let owners_after_deadline = service.process_owner_count(&admitted.run_id);
    let capability_closed = service.capability_host_closed(&admitted.run_id);
    drop(service);
    drop(state);
    let fixture_cleanup = fixture_guard.cleanup();

    assert_eq!(terminals, vec!["run.cancelled".to_string()]);
    assert_eq!(reason, "deadline");
    assert_eq!(owners_after_deadline, 0);
    assert!(capability_closed);
    fixture_cleanup.expect("remove private deadline workspace fixture");
    assert!(
        elapsed < Duration::from_secs(2),
        "deadline should not wait for the child sleep: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_is_cumulative_from_admission() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(short_config(Duration::from_millis(400)), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let cancellation = service
        .handle(&admitted.run_id)
        .expect("live handle")
        .cancellation()
        .clone();
    let admitted_deadline = cancellation.deadline_instant().expect("admission deadline");
    let preparation_observed = Arc::new(AtomicBool::new(false));
    service.inject_agent_compile_lookup_observer(Arc::new({
        let cancellation = cancellation.clone();
        let preparation_observed = Arc::clone(&preparation_observed);
        move || {
            preparation_observed.store(true, Ordering::SeqCst);
            assert_eq!(cancellation.deadline_instant(), Some(admitted_deadline));
            // Consume the admitted budget during preparation. A worker must
            // not gain a new budget when it finally starts the RSS invocation.
            thread::sleep(admitted_deadline.saturating_duration_since(Instant::now()));
            assert_eq!(cancellation.remaining_deadline(), Some(Duration::ZERO));
        }
    }));
    // Preserve the queue delay as well as preparation time in the same budget.
    tokio::time::sleep(Duration::from_millis(250)).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("expired worker and cleanup must finish within the outer bound");

    assert!(preparation_observed.load(Ordering::SeqCst));
    assert_eq!(cancellation.deadline_instant(), Some(admitted_deadline));
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "deadline");
    assert_eq!(
        provider.call_count(),
        0,
        "preparation exhausted the admission deadline before provider work"
    );
    assert!(service.capability_host_closed(&admitted.run_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn race_stop_and_completion_commits_exactly_one_terminal() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("race-ok"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");

    let terminals = terminal_events(&service, &admitted.run_id);
    assert_eq!(terminals.len(), 1, "{terminals:?}");
    assert!(
        terminals[0] == "run.completed" || terminals[0] == "run.cancelled",
        "race must commit exactly one terminal: {terminals:?}"
    );
    assert!(service.capability_host_closed(&admitted.run_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn persisted_restart_fails_typed_when_wall_deadline_expired() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(short_config(Duration::from_millis(80)), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let context = service
        .run_context(&admitted.run_id)
        .expect("frozen context");
    assert!(
        context
            .metadata
            .get("created_at_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "admission must freeze created_at_ms"
    );
    assert!(
        context
            .metadata
            .get("deadline_at_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "admission must freeze deadline_at_ms"
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    service.evict_run_handle(&admitted.run_id);

    let started = Instant::now();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let elapsed = started.elapsed();

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "deadline");
    assert_eq!(provider.call_count(), 0);
    assert!(
        elapsed < Duration::from_millis(400),
        "expired restart must not grant a fresh timeout: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_success_multi_turn_and_prometheus_matches_snapshot() {
    let workspace = lifecycle_workspace_fixture("metrics-success");
    fs::write(
        workspace.workspace.join("README.md"),
        "lifecycle metrics fixture\n",
    )
    .expect("readable lifecycle README fixture");
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-read".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("done"));
    let state = loop_service_with_workspace(AgentGatewayConfig::default(), &provider, &workspace);
    let service = state.service();
    let admitted = service
        .admit_external_with_workspace_selector(admit_request(), Some("name:lifecycle".to_string()))
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(activity_values(&service), [2, 1, 0, 2, 0]);
    assert_prometheus_matches_snapshot(&service);
    assert_frozen_prompt_exactly_once(&service, &admitted.run_id, &provider);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert!(service.capability_host_closed(&admitted.run_id));
    drop(service);
    drop(state);
    fs::remove_dir_all(workspace.root).expect("remove private metrics workspace fixture");
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_retryable_failure_then_success_without_turn_on_retry() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_ok(text_response("recovered"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 2);
    assert_eq!(activity_values(&service), [2, 0, 0, 1, 0]);
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.requested"),
        1
    );
    assert_eq!(
        event_attempts(&service, &admitted.run_id, "model.requested"),
        vec![1]
    );
    assert_eq!(
        event_attempts(&service, &admitted.run_id, "model.failed"),
        vec![1]
    );
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.completed"),
        1
    );
    assert_eq!(assistant_messages(&service, &admitted.session_id).len(), 1);
    assert_prometheus_matches_snapshot(&service);
    assert_frozen_prompt_exactly_once(&service, &admitted.run_id, &provider);
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_retry_exhaustion_without_turns() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_error(retryable_provider_error());
    provider.push_error(retryable_provider_error());
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 3);
    assert_eq!(activity_values(&service), [3, 0, 0, 0, 0]);
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.requested"),
        1
    );
    assert_eq!(
        event_attempts(&service, &admitted.run_id, "model.requested"),
        vec![1]
    );
    assert_eq!(
        event_attempts(&service, &admitted.run_id, "model.failed"),
        vec![1, 2, 3]
    );
    assert_eq!(assistant_messages(&service, &admitted.session_id).len(), 0);
    assert_prometheus_matches_snapshot(&service);
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_accounts_truncated_tool_result_once() {
    let root = unique_temp_dir("trunc");
    fs::create_dir_all(&root).expect("truncation workspace");
    fs::write(root.join("big.txt"), "x".repeat(4096)).expect("truncated fixture");
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-trunc".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "big.txt"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("after-trunc"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    service
        .set_run_limits(RunLimits::new(8, 8, 512, &root).expect("limits"))
        .expect("set run limits");
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let snapshot = service.metrics().snapshot();
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(snapshot.model_calls, 2);
    assert_eq!(snapshot.turns, 2);
    assert_eq!(snapshot.tool_calls, 1);
    assert_eq!(snapshot.truncations, 1);
    assert_prometheus_matches_snapshot(&service);
    let _ = fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_tool_replay_does_not_increment_activity() {
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-replay".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "a.txt"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    let worker = {
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        tokio::spawn(async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        })
    };
    assert!(
        wait_until(Duration::from_secs(2), || {
            has_tool_result_event(&service, &admitted.run_id, &call.id)
        })
        .await,
        "worker should commit the first tool result: {:?}",
        service.run_events(&admitted.run_id)
    );
    let before = activity_values(&service);
    assert_eq!(before, [1, 1, 1, 1, 0]);
    let replayed = common::dispatch_rss(&service, &admitted.run_id, std::slice::from_ref(&call))
        .expect("durable replay");
    assert_eq!(replayed.len(), 1);
    assert!(!replayed[0].ok);
    assert_eq!(activity_values(&service), before);
    assert_prometheus_matches_snapshot(&service);

    service.stop(&admitted.run_id);
    worker.await.expect("worker join");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uncooperative_dispatcher_cleanup_is_bounded_and_fail_closed() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("ok"));
    let mut config = short_config(Duration::from_secs(8));
    config.cancellation_grace = Duration::from_millis(80);
    let state = loop_service(config, &provider);
    let service = state.service();
    service.inject_uncooperative_dispatch();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let started = Instant::now();
    let finished = tokio::time::timeout(
        Duration::from_secs(3),
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string()),
    )
    .await;
    let elapsed = started.elapsed();
    service.release_uncooperative_dispatch();
    assert!(
        finished.is_ok(),
        "uncooperative dispatcher must not block cleanup indefinitely: {elapsed:?}"
    );
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        failed_error_code(&service, &admitted.run_id),
        "cleanup_timeout"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "uncooperative dispatcher must not block cleanup indefinitely: {elapsed:?}"
    );
    assert!(service.capability_host_closed(&admitted.run_id));
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_stopping_requests_cancel_before_provider() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    assert_eq!(service.stop(&admitted.run_id).as_deref(), Some("stopping"));
    service.evict_run_handle(&admitted.run_id);
    tokio::time::timeout(
        Duration::from_secs(4),
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("restore stopping must stay bounded");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert_eq!(provider.call_count(), 0);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_runner_uses_http_sqlite_and_fuel_and_rejects_stale_cache() {
    let mut config = AgentGatewayConfig::default();
    config.http.allowed_hosts = vec!["example.test".to_string()];
    config.sqlite.database_root = Some("/tmp/agent-sqlite-task9".to_string());
    config.fuel = Some(12_345);
    let state =
        AgentGatewayState::with_agent_file(config, rustscript_agent::bundled_agent_main_path())
            .expect("compile gateway agent");
    let service = state.service();
    let installed = service
        .cached_runner_config()
        .expect("gateway should install a runner");
    assert_eq!(installed.http.allowed_hosts, ["example.test"]);
    assert_eq!(
        installed.sqlite.database_root.as_deref(),
        Some("/tmp/agent-sqlite-task9")
    );
    assert_eq!(installed.fuel, Some(12_345));

    let stale = AgentRunner::from_file(
        rustscript_agent::bundled_agent_main_path(),
        AgentConfig::default(),
    )
    .expect("compile default runner");
    service.install_agent_runner(stale);
    assert_ne!(
        service.cached_runner_config().expect("stale cache").fuel,
        Some(12_345)
    );
    let refreshed = service
        .materialize_cached_runner()
        .expect("rebuild stale runner");
    assert_eq!(refreshed.http.allowed_hosts, ["example.test"]);
    assert_eq!(refreshed.fuel, Some(12_345));
}

#[tokio::test(flavor = "multi_thread")]
async fn huge_persisted_deadline_restore_fails_typed_without_panic() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    service.set_context_deadline_at_ms(&admitted.run_id, u64::MAX);
    service.evict_run_handle(&admitted.run_id);
    tokio::time::timeout(
        Duration::from_secs(4),
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("huge deadline restore must not hang");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()]
    );
    assert_eq!(
        failed_error_code(&service, &admitted.run_id),
        "invalid_deadline"
    );
    assert_eq!(provider.call_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn injected_provider_is_one_shot_and_second_run_uses_default() {
    let hang = ScriptedProvider::new();
    hang.push_hang();
    let ok = ScriptedProvider::new();
    ok.push_ok(text_response("second-ok"));
    let state = AgentGatewayState::with_agent_file(
        AgentGatewayConfig::default(),
        rustscript_agent::bundled_agent_main_path(),
    )
    .expect("compile");
    let service = state.service();
    service.inject_provider_host(Arc::new(hang.clone()));
    service.inject_provider_host(Arc::new(ok.clone()));
    let first = service.admit(admit_request()).await.expect("admit first");
    tokio::time::timeout(
        Duration::from_secs(8),
        service
            .clone()
            .run_worker(first.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("first injected run");
    assert_eq!(
        terminal_events(&service, &first.run_id),
        vec!["run.completed".to_string()]
    );
    assert_eq!(ok.call_count(), 1);
    assert_eq!(hang.call_count(), 0);

    let second = service.admit(admit_request()).await.expect("admit second");
    tokio::time::timeout(
        Duration::from_secs(8),
        service
            .clone()
            .run_worker(second.run_id.clone(), "ignored".to_string()),
    )
    .await
    .expect("second run without inject must not hang on the consumed host");
    assert_eq!(
        ok.call_count(),
        1,
        "one-shot inject must not leak to the second run"
    );
    assert_eq!(hang.call_count(), 0);
    assert_eq!(
        terminal_events(&service, &second.run_id).len(),
        1,
        "second run must still commit a terminal without the injected host: {:?}",
        service.run_events(&second.run_id)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_backoff_sleep_is_interrupted_by_stop() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(4), || provider.call_count() >= 1).await,
        "first retryable provider error should land"
    );
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()]
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_expired_restart_keeps_remaining_deadline() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let timeout = Duration::from_secs(5);
    let state = loop_service(short_config(timeout), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    tokio::time::sleep(Duration::from_millis(400)).await;
    service.evict_run_handle(&admitted.run_id);
    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(4), || provider.call_count() >= 1).await,
        "restored worker should reach the hang"
    );
    let remaining = service
        .handle(&admitted.run_id)
        .expect("restored handle")
        .cancellation()
        .remaining_deadline()
        .expect("deadline");
    assert!(
        remaining < timeout - Duration::from_millis(200),
        "restart must keep the remaining deadline, not a fresh {timeout:?}: {remaining:?}"
    );
    assert!(remaining > Duration::from_millis(100));
    let _ = service.stop(&admitted.run_id);
    worker.await.expect("worker join");
}

async fn pending_owned_loopback_server() -> (OwnedLoopbackServer, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind pending owned loopback server");
    let address = listener.local_addr().expect("pending owned server address");
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = OwnedLoopbackServer::from_future(address, shutdown, async move {
        let _listener = listener;
        let _ = shutdown_rx.await;
        std::future::pending::<()>().await;
    });
    (server, address)
}

#[tokio::test(flavor = "multi_thread")]
async fn owned_loopback_pending_future_is_dropped_and_socket_rebound() {
    let (mut server, address) = pending_owned_loopback_server().await;
    let started = Instant::now();
    let observation = poll_during_operation(&mut server, async {}).await;
    let cleanup = server.shutdown_and_reap(Duration::from_millis(40)).await;
    let elapsed = started.elapsed();
    let rebound = std::net::TcpListener::bind(address).map(drop).is_ok();
    let cleanup_failed = cleanup.is_err();
    let cleanup_failure_panicked = AssertUnwindSafe(async move {
        cleanup.expect("cleanup failure without an observation panic must fail closed");
    })
    .catch_unwind()
    .await
    .is_err();

    assert!(observation.is_ok(), "injected observation must complete");
    assert!(
        cleanup_failed,
        "shutdown-ignoring owned future must report cleanup failure"
    );
    assert!(
        cleanup_failure_panicked,
        "an unmasked cleanup error must fail the caller"
    );
    assert!(
        elapsed <= Duration::from_secs(5),
        "cleanup exceeded its bound"
    );
    assert!(
        rebound,
        "dropping the owned future must release the exact address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn observation_panic_keeps_payload_after_server_cleanup_failure() {
    let (mut server, address) = pending_owned_loopback_server().await;
    let auth_home = unique_temp_dir("tls-reap-panic-auth");
    let mut auth_home_guard = OwnedPrivateFixtureDirectory::create(auth_home.clone())
        .expect("create owned private synthetic auth home");
    write_private_fixture_file(&auth_home.join("auth.yaml"), "token: synthetic-only\n");
    let marker = Arc::new(());
    let observation = poll_during_operation(&mut server, async {
        panic_with_owned_marker(Arc::clone(&marker));
    })
    .await;
    let server_cleanup = server.shutdown_and_reap(Duration::from_millis(40)).await;
    let auth_cleanup = auth_home_guard.cleanup();
    let server_cleanup_failed = server_cleanup.is_err();
    let auth_cleanup_succeeded = auth_cleanup.is_ok();
    let auth_home_removed = !auth_home.exists();
    let socket_rebound = std::net::TcpListener::bind(address).map(drop).is_ok();
    let captured = AssertUnwindSafe(async move {
        resume_observation_panic(observation);
        server_cleanup.expect("cleanup failure must follow the original observation panic");
        auth_cleanup.expect("private synthetic auth home cleanup");
    })
    .catch_unwind()
    .await;
    let original_payload_preserved = captured
        .as_ref()
        .err()
        .and_then(|payload| payload.downcast_ref::<Arc<()>>())
        .is_some_and(|payload| Arc::ptr_eq(payload, &marker));

    assert!(
        server_cleanup_failed,
        "pending server cleanup must fail closed"
    );
    assert!(
        auth_cleanup_succeeded,
        "auth cleanup must be attempted before rethrow"
    );
    assert!(
        auth_home_removed,
        "auth directory must be absent after cleanup"
    );
    assert!(socket_rebound, "server socket must be absent after cleanup");
    assert!(
        original_payload_preserved,
        "the original observation panic payload must retain identity"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn owned_loopback_server_future_panic_is_captured_and_socket_rebound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind panicking owned loopback server");
    let address = listener
        .local_addr()
        .expect("panicking owned server address");
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let mut server = OwnedLoopbackServer::from_future(address, shutdown, async move {
        let _listener = listener;
        let _ = shutdown_rx.await;
        panic!("injected owned TLS server future panic");
    });
    let observation = poll_during_operation(&mut server, async {}).await;
    let cleanup = server.shutdown_and_reap(Duration::from_secs(5)).await;
    let rebound = std::net::TcpListener::bind(address).map(drop).is_ok();

    assert!(observation.is_ok(), "observation itself must not panic");
    assert!(
        cleanup.is_err(),
        "server future panic must be recorded as cleanup failure"
    );
    assert!(
        rebound,
        "captured server panic must still release the socket"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn owned_loopback_server_is_reaped_after_postspawn_error_and_panic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind first owned loopback server");
    let address = listener.local_addr().expect("first owned server address");
    let (server_tls, _) = owned_loopback_tls_configs();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    drop(accepted_rx);
    let mut server = OwnedLoopbackServer::start(listener, address, server_tls, accepted_tx);
    let operation = poll_during_operation(&mut server, async {
        Err::<(), _>("injected post-spawn error")
    })
    .await;
    let cleanup = server
        .shutdown_and_reap(OWNED_LOOPBACK_SERVER_GRACEFUL_BOUND)
        .await;
    assert_eq!(
        resume_observation_panic(operation),
        Err("injected post-spawn error")
    );
    cleanup.expect("error path must signal and close the owned socket");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind second owned loopback server");
    let address = listener.local_addr().expect("second owned server address");
    let (server_tls, _) = owned_loopback_tls_configs();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    drop(accepted_rx);
    let mut server = OwnedLoopbackServer::start(listener, address, server_tls, accepted_tx);
    let operation = poll_during_operation(&mut server, async {
        panic!("injected post-spawn panic");
    })
    .await;
    let cleanup = server
        .shutdown_and_reap(OWNED_LOOPBACK_SERVER_GRACEFUL_BOUND)
        .await;
    assert!(
        operation.is_err(),
        "post-spawn panic must be captured for cleanup"
    );
    cleanup.expect("unwind path must signal and close the owned socket");
}

#[tokio::test(flavor = "multi_thread")]
async fn hanging_http_adapter_stop_cancels() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind owned TLS fixture server");
    let address = listener.local_addr().expect("local addr");
    let port = address.port();
    let base_url = format!("https://127.0.0.1:{port}/v1");
    let (server_tls, client_tls) = owned_loopback_tls_configs();
    let transport: Arc<dyn rustscript_agent::auth::oauth::BoundedHttpsTransport> =
        Arc::new(OwnedLoopbackHttpsTransport {
            port,
            tls: client_tls,
        });
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel::<OwnedLoopbackRequest>();
    let mut config = short_config(Duration::from_secs(8));
    config.provider = Some("custom".to_string());
    config.model = "loopback-hang-model".to_string();
    config.http.allowed_hosts = vec!["127.0.0.1".to_string()];
    config.http.allowed_schemes = vec!["https".to_string()];
    config.http.allowed_ports = vec![port];
    config.http.allow_private_ips = true;
    let state =
        AgentGatewayState::with_agent_file(config, rustscript_agent::bundled_agent_main_path())
            .expect("compile adapter run");
    let service = state.service();
    let auth_home = unique_temp_dir("hanging-http-auth");
    let mut auth_home_guard = OwnedPrivateFixtureDirectory::create(auth_home.clone())
        .expect("create owned private synthetic auth home");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    let auth_config_yaml = fs::read_to_string(fixture.join("config.yaml"))
        .expect("read synthetic provider config")
        .replace("openai-codex", "custom")
        .replace("https://chatgpt.com/backend-api/codex", &base_url)
        .replace("fixture-codex", "synthetic-custom");
    let mut auth_config_value: serde_yaml::Value =
        serde_yaml::from_str(&auth_config_yaml).expect("parse synthetic provider config");
    auth_config_value["providers"]["custom"]["oauth"] = serde_yaml::Value::Null;
    let auth_config =
        serde_yaml::to_string(&auth_config_value).expect("serialize synthetic provider config");
    let auth_data = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("read synthetic provider credential")
        .replace("1788440000000", "1900003600000")
        .replace("openai-codex", "custom")
        .replace("fixture-codex", "synthetic-custom")
        .replace("SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_CUSTOM_ACCESS")
        .replace("SYNTHETIC_REFRESH_TOKEN", "SYNTHETIC_CUSTOM_REFRESH");
    rustscript_agent::config_file::ConfigFile::from_str(&auth_config)
        .expect("strict synthetic provider config");
    let auth_config_path = auth_home.join("config.yaml");
    let auth_data_path = auth_home.join("auth.yaml");
    write_private_fixture_file(&auth_config_path, &auth_config);
    write_private_fixture_file(&auth_data_path, &auth_data);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&auth_home)
                .expect("fixture directory mode")
                .permissions()
                .mode()
                & 0o077,
            0,
            "synthetic auth home must exclude group and other"
        );
        assert_eq!(
            fs::metadata(&auth_config_path)
                .expect("synthetic config mode")
                .permissions()
                .mode()
                & 0o077,
            0,
            "synthetic config must exclude group and other"
        );
        assert_eq!(
            fs::metadata(&auth_data_path)
                .expect("synthetic credential mode")
                .permissions()
                .mode()
                & 0o077,
            0,
            "synthetic credential must exclude group and other"
        );
    }
    let factory_home = auth_home.clone();
    let oauth = Arc::new(rustscript_agent::auth::oauth::OAuthHost::new(
        transport,
        Arc::new(rustscript_agent::auth::oauth::ScriptedCallback::new()),
        Arc::new(rustscript_agent::auth::oauth::ScriptedBrowser::new()),
        Arc::new(rustscript_agent::auth::oauth::ScriptedClock::new(
            1_900_000_000_000,
        )),
        Arc::new(rustscript_agent::auth::oauth::ScriptedCancel::new()),
    ));
    service.set_auth_host_factory(std::sync::Arc::new(move |cancellation| {
        rustscript_agent::auth::host::AuthHost::new(factory_home.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    }));
    service.upsert_provider_profile(
        ProviderProfile::new(
            "custom",
            json!({
                "base_url": base_url,
                "credential_id": "synthetic-custom"
            }),
        )
        .expect("synthetic custom profile"),
    );
    // The provider adapter is compiled on its first call. Prepare that RSS
    // snapshot before admission so the test's four-second window measures the
    // HTTP lifecycle, not unrelated setup work on a loaded CI runner.
    let harness_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss");
    AgentRunner::from_file(&harness_path, AgentConfig::default())
        .expect("compile adapter harness before admission");
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admission should succeed");
    let named_dispatch_runner = AgentRunner::from_bundled_named(
        "rss/llm/provider_dispatch.rss",
        "dispatch",
        AgentConfig::default(),
    );
    let mut server = OwnedLoopbackServer::start(listener, address, server_tls, accepted_tx);
    let mut worker = None;
    let observation_result = poll_during_operation(&mut server, async {
        worker = Some(tokio::spawn({
            let service = service.clone();
            let run_id = admitted.run_id.clone();
            async move {
                service.run_worker(run_id, "ignored".to_string()).await;
            }
        }));
        let accepted = tokio::time::timeout(Duration::from_secs(4), accepted_rx).await;
        let request_observation = match accepted {
            Ok(Ok(observation)) => Some(observation),
            _ => None,
        };
        let connected = request_observation.as_ref().is_some_and(|request| {
            request.method == "POST"
                && request.path == "/v1/chat/completions"
                && request.has_bearer
                && request.body_bytes > 0
        });
        let named_dispatch_diagnostic = (!connected).then(|| {
            let runner = match &named_dispatch_runner {
                Ok(runner) => runner,
                Err(error) => return format!("constructor_error={error}"),
            };
            let request = rustscript_vm::Value::map(vec![
                (
                    rustscript_vm::Value::string("provider"),
                    rustscript_vm::Value::string("local-agent"),
                ),
                (
                    rustscript_vm::Value::string("provider_options"),
                    rustscript_vm::Value::map(vec![]),
                ),
            ]);
            let context = rustscript_vm::Value::map(vec![(
                rustscript_vm::Value::string("request"),
                request,
            )]);
            struct DiagnosticSink;
            impl rustscript_agent::RunEventSink for DiagnosticSink {
                fn deliver(
                    &mut self,
                    _value: rustscript_vm::Value,
                ) -> Result<(), rustscript_agent::RunDeliveryError> {
                    Ok(())
                }
            }
            let cancellation =
                rustscript_agent::RunCancellation::with_timeout(Duration::from_secs(2));
            match runner.run_named_with_context_and_events(
                "dispatch",
                context,
                &mut DiagnosticSink,
                &cancellation,
            ) {
                Ok(value) => format!("dispatch_value={value:?}"),
                Err(error) => format!("dispatch_error={error:?}"),
            }
        });
        let worker_finished_before_stop = worker
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished);
        let pre_stop_diagnostic = (!connected).then(|| {
            let run_context = service.run_context(&admitted.run_id);
            let provider_binding = run_context
                .as_ref()
                .and_then(|context| context.provider.as_deref())
                .unwrap_or("<missing>");
            let profile_binding = run_context
                .as_ref()
                .and_then(|context| context.metadata.pointer("/provider_profile"))
                .and_then(JsonValue::as_str)
                .unwrap_or("<missing>");
            let provider_error_codes = service
                .run_events(&admitted.run_id)
                .into_iter()
                .filter(|event| event["event"] == "model.failed")
                .filter_map(|event| {
                    event
                        .pointer("/data/error_code")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string)
                })
                .collect::<Vec<_>>();
            format!(
                "provider={provider_binding}; profile={profile_binding}; events={:?}; terminal={:?}; provider_error_codes={provider_error_codes:?}; run_error_code={}; worker_finished={worker_finished_before_stop}; cancel_reason={}; model_calls={}; loopback_request={request_observation:?}; named_dispatcher={named_dispatch_diagnostic:?}",
                event_names(&service, &admitted.run_id),
                terminal_events(&service, &admitted.run_id),
                failed_error_code(&service, &admitted.run_id),
                cancel_reason(&service, &admitted.run_id),
                service.metrics().snapshot().model_calls
            )
        });
        (request_observation, connected, pre_stop_diagnostic)
    })
    .await;
    let stop_result = service.stop(&admitted.run_id);
    let worker_result = match worker.as_mut() {
        Some(worker) => Some(tokio::time::timeout(Duration::from_secs(6), worker).await),
        None => None,
    };
    let worker_reaped = match worker_result.as_ref() {
        Some(Err(_)) => match worker.as_mut() {
            Some(worker) => {
                worker.abort();
                tokio::time::timeout(Duration::from_secs(1), worker)
                    .await
                    .is_ok()
            }
            None => false,
        },
        Some(Ok(_)) | None => true,
    };
    let terminal = terminal_events(&service, &admitted.run_id);
    let reason = cancel_reason(&service, &admitted.run_id);
    let server_cleanup = server
        .shutdown_and_reap(OWNED_LOOPBACK_SERVER_GRACEFUL_BOUND)
        .await;
    let auth_cleanup = auth_home_guard.cleanup();
    let auth_home_removed = !auth_home.exists();
    let (request_observation, connected, pre_stop_diagnostic) =
        resume_observation_panic(observation_result);

    assert!(worker_reaped, "timed-out HTTP worker task was not reaped");
    server_cleanup
        .expect("hanging HTTP server must be gracefully closed and its socket rebindable");
    auth_cleanup.expect("private synthetic auth home cleanup");
    assert!(
        auth_home_removed,
        "private synthetic auth home must be absent after cleanup"
    );
    if let Some(worker_result) = worker_result {
        worker_result
            .expect("hanging HTTP stop must stay bounded")
            .expect("worker join");
    }
    assert!(
        connected,
        "RssAdapterProvider should connect within the run setup window; pre-stop state: {pre_stop_diagnostic:?}; request: {request_observation:?}"
    );
    assert_eq!(
        stop_result.as_deref(),
        Some("stopping"),
        "pre-stop state: {pre_stop_diagnostic:?}"
    );
    assert_eq!(
        terminal,
        vec!["run.cancelled".to_string()],
        "pre-stop state: {pre_stop_diagnostic:?}"
    );
    assert_eq!(
        reason, "requested",
        "pre-stop state: {pre_stop_diagnostic:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn first_tool_effect_succeeds_with_parent_already_durable() {
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-parent".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("after-tool"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let names = event_names(&service, &admitted.run_id);
    let completed = names
        .iter()
        .position(|name| name == "model.completed")
        .expect("provider step must be durable before tools");
    let tool_started = names
        .iter()
        .position(|name| name.starts_with("tool."))
        .expect("tool effect must run");
    assert!(
        completed < tool_started,
        "durable provider parent must precede tool events: {names:?}"
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    let parent = assistants
        .iter()
        .find(|message| {
            message["content"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|block| {
                    block["type"] == "tool_call" && block["tool_call_id"] == json!(call.id)
                })
        })
        .expect("assistant tool_call parent");
    let parent_id = parent["id"].as_str().expect("parent id");
    let tool_messages: Vec<_> = service
        .session_messages(&admitted.session_id)
        .into_iter()
        .filter(|message| message["tool_call_id"] == json!(call.id))
        .collect();
    assert!(
        !tool_messages.is_empty(),
        "tool result message should exist"
    );
    assert!(
        tool_messages
            .iter()
            .all(|message| message["parent_message_id"] == json!(parent_id)),
        "tool result parent_message_id must point at the durable assistant: {tool_messages:?}"
    );
    assert_eq!(provider.call_count(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn persist_failpoint_leaves_executor_count_zero() {
    let path = temporary_db_path();
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-persist-fail".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("should-not-run"));
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &path);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    state
        .persistence()
        .expect("sqlite persistence")
        .inject_fail_after_partial_write();

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let failed = service
        .run_events(&admitted.run_id)
        .into_iter()
        .find(|event| event["event"] == "run.failed")
        .expect("failed terminal");
    let rendered = failed.to_string();
    assert!(
        rendered.contains("provider_step_persist_failed")
            || rendered.contains("failed to persist provider step"),
        "persist failure must be typed: {rendered}"
    );
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert_eq!(provider.call_count(), 1);
    drop(state);
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread")]
async fn post_commit_crash_restart_replays_provider_and_runs_tool_once() {
    let path = temporary_db_path();
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-crash".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("after-restart"));
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &path);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service.inject_crash_after_provider_commit();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert!(
        terminal_events(&service, &admitted.run_id).is_empty(),
        "crash after commit must leave the run started: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 1);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    // Process restart of leftover running runs is `gateway_restart`. This
    // seam is a worker crash after the provider step is durable: evict the
    // live handle and resume the same started run so replay, not a second
    // inner call, drives tool dispatch.
    service.evict_run_handle(&admitted.run_id);
    service.inject_provider_host(Arc::new(provider.clone()));
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(
        provider.call_count(),
        2,
        "restart must replay the committed provider step without a second inner call"
    );
    assert_eq!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        2
    );
    assert!(has_tool_result_event(&service, &admitted.run_id, &call.id));
    drop(state);
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread")]
async fn final_text_commits_one_assistant_row() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("only-once"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()]
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    assert_eq!(
        assistants.len(),
        1,
        "provider step already stored the assistant text: {assistants:?}"
    );
    let rendered = assistants[0].to_string();
    assert!(
        rendered.contains("only-once"),
        "assistant row must keep the provider text: {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tool_call_and_text_combined_are_preserved() {
    let provider = ScriptedProvider::new();
    let call = ToolCall {
        id: "call-combined".to_string(),
        name: "read_file".to_string(),
        arguments: json!({"path": "README.md"}),
    };
    provider.push_ok(tool_response(
        "thinking",
        json!([{"id": call.id, "name": call.name, "arguments": call.arguments}]),
    ));
    provider.push_ok(text_response("done"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    let combined = assistants
        .iter()
        .find(|message| {
            let blocks = message["content"].as_array().cloned().unwrap_or_default();
            blocks
                .iter()
                .any(|block| block["type"] == "text" && block["text"] == "thinking")
                && blocks.iter().any(|block| {
                    block["type"] == "tool_call" && block["tool_call_id"] == json!(call.id)
                })
        })
        .expect("combined text+tool_call assistant");
    assert!(
        combined["content"]
            .as_array()
            .expect("blocks")
            .iter()
            .any(|block| block["arguments_json"].as_str()
                == Some(call.arguments.to_string().as_str())
                || block["arguments"] == call.arguments),
        "tool_call arguments must be preserved: {combined}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_and_retry_provider_ordinals_are_stable() {
    let provider = ScriptedProvider::new();
    provider.push_error(retryable_provider_error());
    provider.push_ok(text_response("stable"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()]
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    assert_eq!(
        assistants.len(),
        1,
        "retryable failure must not create an assistant row: {assistants:?}"
    );
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.requested"),
        1
    );
    assert_eq!(
        event_attempts(&service, &admitted.run_id, "model.requested"),
        vec![1]
    );
    assert_eq!(
        event_attempts(&service, &admitted.run_id, "model.failed"),
        vec![1]
    );
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.completed"),
        1
    );
    let _ordinal = assistants[0]["ordinal"].as_u64();
    assert!(
        _ordinal.is_some(),
        "committed assistant must have an ordinal"
    );

    let fresh = loop_service(AgentGatewayConfig::default(), &ScriptedProvider::new());
    let service = fresh.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("fresh admit should succeed");
    let run_id = admitted.run_id.clone();
    let blocks = [LlmContentBlock {
        block_type: "text".to_string(),
        text: Some("stable".to_string()),
        ..LlmContentBlock::default()
    }];
    let left = {
        let service = service.clone();
        let run_id = run_id.clone();
        let blocks = blocks.clone();
        thread::spawn(move || {
            service.commit_provider_step(&run_id, 1, &blocks, None, Some("stop"), None, None, None)
        })
    };
    let right = {
        let service = service.clone();
        let run_id = run_id.clone();
        let blocks = blocks.clone();
        thread::spawn(move || {
            service.commit_provider_step(&run_id, 1, &blocks, None, Some("stop"), None, None, None)
        })
    };
    let left_commit = left.join().expect("left join").expect("left commit");
    let right_commit = right.join().expect("right join").expect("right commit");
    assert_eq!(left_commit.message_id(), right_commit.message_id());
    assert_eq!(left_commit.envelope(), right_commit.envelope());
    let after = assistant_messages(&service, &admitted.session_id);
    assert_eq!(
        after.len(),
        1,
        "concurrent replay must not duplicate ordinals"
    );
    assert_eq!(after[0]["id"].as_str(), Some(left_commit.message_id()));
    let concurrent_ordinals: Vec<_> = after
        .iter()
        .filter_map(|message| message["ordinal"].as_u64())
        .collect();
    assert_eq!(concurrent_ordinals.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_workers_occupy_run_once() {
    let provider = ScriptedProvider::new();
    provider.push_hang();
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service.admit(admit_request()).await.expect("admit");
    let worker1 = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    assert!(
        wait_until(Duration::from_secs(2), || provider.call_count() == 1).await,
        "first worker should occupy the provider call"
    );
    let worker2 = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    tokio::time::timeout(Duration::from_millis(400), worker2)
        .await
        .expect("second worker must return while first occupies")
        .expect("second worker join");
    assert_eq!(provider.call_count(), 1);
    service.stop(&admitted.run_id);
    worker1.await.expect("first worker");
    assert_eq!(provider.call_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_ok_envelope_does_not_commit_durable_success() {
    let provider = ScriptedProvider::new();
    provider.push_envelope(json!({
        "ok": true,
        "response": "not-an-object",
        "error": {}
    }));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service.admit(admit_request()).await.expect("admit");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        event_names(&service, &admitted.run_id)
            .into_iter()
            .filter(|name| name == "model.completed")
            .count(),
        0,
        "malformed envelope must not persist model.completed: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert!(
        assistant_messages(&service, &admitted.session_id).is_empty(),
        "malformed envelope must not persist an assistant step"
    );
    assert_ne!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn model_requested_persist_failpoint_leaves_provider_and_tools_zero() {
    let path = temporary_db_path();
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("should not run"));
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &path);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    state
        .persistence()
        .expect("sqlite")
        .inject_fail_model_requested_append();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(provider.call_count(), 0);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.requested"),
        0
    );
    assert_eq!(assistant_messages(&service, &admitted.session_id).len(), 0);
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    let failed = service
        .run_events(&admitted.run_id)
        .into_iter()
        .find(|event| event["event"] == "run.failed")
        .expect("failed terminal");
    let rendered = failed.to_string();
    assert!(
        rendered.contains("provider_step_persist_failed")
            || rendered.contains("failed to persist provider step"),
        "persist failure must be typed: {rendered}"
    );
    drop(state);
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_after_provider_request_redrive_retries_once() {
    let path = temporary_db_path();
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("after-redrive"));
    let state = loop_service_sqlite(AgentGatewayConfig::default(), &provider, &path);
    let service = state.service();
    let admitted = service
        .admit(admit_request())
        .await
        .expect("admit should succeed");
    service.inject_crash_after_provider_request();
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert!(
        terminal_events(&service, &admitted.run_id).is_empty(),
        "crash after request boundary must leave the run started: {:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 0);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.requested"),
        1
    );
    assert_eq!(
        event_attempts(&service, &admitted.run_id, "model.requested"),
        vec![1]
    );
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.completed"),
        0
    );
    assert!(assistant_messages(&service, &admitted.session_id).is_empty());
    service.evict_run_handle(&admitted.run_id);
    service.inject_provider_host(Arc::new(provider.clone()));
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.completed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(provider.call_count(), 1);
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.requested"),
        1
    );
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.completed"),
        1
    );
    assert_eq!(assistant_messages(&service, &admitted.session_id).len(), 1);
    assert_eq!(service.metrics().snapshot().turns, 1);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    drop(state);
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_request_fingerprint_mismatch_fails_closed_without_inner() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("should not run"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service.admit(admit_request()).await.expect("admit");
    service
        .commit_provider_request(
            &admitted.run_id,
            1,
            1,
            true,
            &json!({"model": "mismatch-model", "provider": "openai"}),
        )
        .expect("mismatched request boundary");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(provider.call_count(), 0);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert_eq!(
        named_event_count(&service, &admitted.run_id, "model.completed"),
        0
    );
    assert!(assistant_messages(&service, &admitted.session_id).is_empty());
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unsafe_pending_request_fails_closed_without_inner() {
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("should not run"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let admitted = service.admit(admit_request()).await.expect("admit");
    service
        .commit_provider_request(
            &admitted.run_id,
            1,
            1,
            false,
            &json!({"model": "mismatch-model"}),
        )
        .expect("unsafe request boundary");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(provider.call_count(), 0);
    assert_eq!(tool_event_count(&service, &admitted.run_id), 0);
    assert!(assistant_messages(&service, &admitted.session_id).is_empty());
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.failed".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn capability_host_init_panic_does_not_overwrite_closed_and_redrive_cancels_once() {
    // Empty restore after init panic is covered by
    // `capability_host_init_panic_wakes_waiters_and_allows_retry`. This test
    // pins the stop+close-before-panic contract: the guard must not overwrite
    // Closed, occupancy must unwind, and redrive commits exactly one cancel.
    let provider = ScriptedProvider::new();
    provider.push_ok(text_response("after-init-panic"));
    let state = loop_service(AgentGatewayConfig::default(), &provider);
    let service = state.service();
    let parent = unique_temp_dir("init-panic");
    let workspace = parent.join("workspace");
    fs::create_dir_all(&workspace).expect("isolated workspace");
    service
        .set_run_limits(RunLimits::new(8, 8, 64 * 1024, &workspace).expect("run limits"))
        .expect("set isolated run limits");
    let admitted = service.admit(admit_request()).await.expect("admit");

    let entered = Arc::new(Barrier::new(2));
    let panic_gate = Arc::new(Barrier::new(2));
    let panic_once = Arc::new(AtomicBool::new(true));
    let observer_entered = Arc::clone(&entered);
    let observer_gate = Arc::clone(&panic_gate);
    let observer_panic = Arc::clone(&panic_once);
    service.inject_capability_host_init_entered_observer(Arc::new(move || {
        if observer_panic.swap(false, Ordering::SeqCst) {
            observer_entered.wait();
            observer_gate.wait();
            panic!("injected capability host init panic");
        }
    }));

    let worker = tokio::spawn({
        let service = service.clone();
        let run_id = admitted.run_id.clone();
        async move {
            service.run_worker(run_id, "ignored".to_string()).await;
        }
    });
    entered.wait();
    assert_eq!(service.stop(&admitted.run_id).as_deref(), Some("stopping"));
    service.cleanup_session_capability_host(&admitted.session_id);
    assert!(
        service.capability_host_closed(&admitted.run_id),
        "stop/cleanup must sticky-close before the init panic"
    );

    panic_gate.wait();
    assert!(
        worker
            .await
            .expect_err("init panic must fail the worker join")
            .is_panic(),
        "run_worker must propagate the injected init panic"
    );
    assert!(
        service.capability_host_closed(&admitted.run_id),
        "init panic guard must not overwrite Closed"
    );
    assert!(!service.capability_host_retained(&admitted.run_id));
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert!(
        terminal_events(&service, &admitted.run_id).is_empty(),
        "init panic must not hide the panic behind a terminal: {:?}",
        service.run_events(&admitted.run_id)
    );

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    assert_eq!(
        terminal_events(&service, &admitted.run_id),
        vec!["run.cancelled".to_string()],
        "{:?}",
        service.run_events(&admitted.run_id)
    );
    assert_eq!(cancel_reason(&service, &admitted.run_id), "requested");
    assert!(service.capability_host_closed(&admitted.run_id));
    assert_eq!(service.process_owner_count(&admitted.run_id), 0);
    assert_eq!(provider.call_count(), 0);
    drop(service);
    drop(state);
    fs::remove_dir_all(&parent).expect("isolated init-panic workspace should be removed");
}

fn collect_test_rs_files(directory: &std::path::Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("tests directory should be readable") {
        let path = entry.expect("directory entry should be readable").path();
        if path.is_dir() {
            collect_test_rs_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn test_sources_do_not_hardcode_sibling_lease_temp_roots() {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    collect_test_rs_files(&tests_root, &mut sources);
    assert!(
        !sources.is_empty(),
        "tests/ must contain Rust sources to audit"
    );

    let forbidden = [
        format!("/mnt/{}/workspace/", "TEMP"),
        format!("{}-t", "coding"),
        ["prod", "agent", "task"].join("-"),
        format!("/{}s/", "worktree"),
        format!("/tmp/{}-agent-", "prod"),
    ];

    let mut violations = Vec::new();
    for path in &sources {
        let source = fs::read_to_string(path).expect("test source should be readable");
        for fragment in &forbidden {
            if source.contains(fragment.as_str()) {
                violations.push(format!("{} contains {fragment}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "test sources must not hardcode sibling lease temp roots: {violations:?}"
    );
}
