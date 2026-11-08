//! Gateway startup wiring of the loaded `config.yaml` into the existing
//! `AgentGatewayConfig` / `ProviderProfile` boundaries.
//!
//! These cases drive the packaged `rustscript-agent-gateway` binary over real
//! loopback HTTP. A present config must supply the default model/provider and
//! the public provider profiles (protocol, base URL, named credential ID)
//! before the listener binds; a missing config keeps the built-in local-agent
//! defaults, and a present-but-invalid config must fail closed before listen.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_root(label: &str) -> PathBuf {
    let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("gateway-provider-config-tests"))
        .join(format!(
            "gateway-provider-config-{label}-{}",
            uuid::Uuid::new_v4()
        ));
    std::fs::create_dir_all(&root).expect("gateway provider config test root");
    root
}

fn home(root: &Path) -> PathBuf {
    root.join(".rustscript-agent")
}

fn write_config(root: &Path, document: &str) {
    let home = home(root);
    std::fs::create_dir_all(&home).expect("agent home");
    std::fs::write(home.join("config.yaml"), document).expect("write config.yaml");
}

/// A synthetic api_key credential fixture. The access-token value is a fixed
/// non-production string so the transport attempt can be observed without any
/// real secret.
fn write_auth_fixture(root: &Path, credential_id: &str, provider: &str) {
    let home = home(root);
    std::fs::create_dir_all(&home).expect("agent home");
    let document = format!(
        "version: 1\ncredentials:\n  {credential_id}:\n    provider: {provider}\n    \
         kind: api_key\n    source: fixture\n    token_type: Bearer\n    \
         access_token: fixture-not-a-real-credential\n    expires_at_ms: 1900000000000\n"
    );
    let path = home.join("auth.yaml");
    std::fs::write(&path, document).expect("write auth.yaml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("auth.yaml mode");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .expect("agent home mode");
    }
}

fn spawn_gateway(root: &Path, stderr_path: &Path) -> tokio::process::Child {
    let stderr_file = std::fs::File::create(stderr_path).expect("gateway stderr file");
    // Clear the inherited environment so a developer or CI shell cannot hand
    // real platform tokens or provider settings to the packaged binary. Only
    // the explicit test inputs and the executable search path remain.
    let path = std::env::var_os("PATH").expect("the test process must carry PATH");
    tokio::process::Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"))
        .env_clear()
        .env("PATH", path)
        .env("HOME", root)
        .env("TMPDIR", root)
        .env("TMP", root)
        .env("TEMP", root)
        .env("TEST_TMPDIR", root)
        .env("RUSTSCRIPT_AGENT_TEST_TMP", root)
        .env("RUSTSCRIPT_AGENT_TEST_TMPDIR", root)
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", "127.0.0.1:0")
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("gateway binary should spawn")
}

async fn wait_for_listening(
    child: &mut tokio::process::Child,
    stderr_path: &Path,
    timeout: Duration,
) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = std::fs::read_to_string(stderr_path)
            && let Some(position) = text.find("listening on http://")
        {
            let rest = &text[position + "listening on http://".len()..];
            let address = rest.lines().next().unwrap_or("").trim().to_string();
            if !address.is_empty() {
                return Some(address);
            }
        }
        if let Ok(Some(_)) = child.try_wait() {
            return None;
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn stop_child(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else {
        return;
    };
    let signal = std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("send SIGINT to the gateway child");
    assert!(signal.success(), "the gateway child must accept SIGINT");
    match tokio::time::timeout(Duration::from_secs(15), child.wait()).await {
        Ok(result) => {
            result.expect("the gateway child must be reaped after SIGINT");
        }
        Err(_) => {
            child
                .start_kill()
                .expect("the gateway child must accept SIGKILL after its bound");
            let result = tokio::time::timeout(Duration::from_secs(15), child.wait())
                .await
                .expect("the gateway child must exit after SIGKILL");
            result.expect("the gateway child must be reaped after SIGKILL");
        }
    }
}

async fn http_request(host: &str, method: &str, path: &str, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(host)
        .await
        .expect("connect to gateway");
    let request = if method == "GET" {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write gateway request");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

fn response_body(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn response_json(response: &str) -> Value {
    serde_json::from_str(response_body(response)).expect("gateway JSON response")
}

fn assert_status(response: &str, expected: &str) {
    let first = response.lines().next().unwrap_or("");
    assert!(
        first.contains(expected),
        "expected HTTP status {expected}, got first line {first:?}"
    );
}

async fn create_session(host: &str, body: &Value) -> Value {
    let response = http_request(host, "POST", "/api/sessions", &body.to_string()).await;
    assert_status(&response, "201");
    response_json(&response)
}

async fn admit_run(host: &str, session_id: &str, input: &str) -> String {
    let body = json!({ "session_id": session_id, "input": input });
    let response = http_request(host, "POST", "/v1/runs", &body.to_string()).await;
    assert_status(&response, "202");
    let run = response_json(&response);
    run["run_id"].as_str().expect("admitted run id").to_string()
}

/// Reads the run SSE body until the named event appears or the bounded
/// observation window closes. A subscription made before the run's live
/// delivery sender exists can end after replaying partial history; reconnect
/// and replay until the event is observed. The bound only prevents a hung
/// test.
async fn read_run_events(host: &str, run_id: &str, event: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    let needle = format!("\"event\":\"{event}\"");
    let mut collected = String::new();
    loop {
        if collected.contains(&needle) || Instant::now() >= deadline {
            return collected;
        }
        let attempt_deadline = (Instant::now() + Duration::from_secs(5)).min(deadline);
        let body = read_events_once(host, run_id, &needle, attempt_deadline).await;
        collected.push_str(&body);
        if !collected.contains(&needle) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn read_events_once(host: &str, run_id: &str, needle: &str, deadline: Instant) -> String {
    let mut stream = match tokio::net::TcpStream::connect(host).await {
        Ok(stream) => stream,
        Err(_) => return String::new(),
    };
    let request = format!(
        "GET /v1/runs/{run_id}/events HTTP/1.1\r\nHost: {host}\r\n\
         Accept: text/event-stream\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return String::new();
    }
    let mut body = Vec::new();
    loop {
        if body
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
        {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => body.extend_from_slice(&chunk[..read]),
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&body).into_owned()
}

/// Extracts `error_code` from the first `model.failed` SSE data record.
fn model_failed_code(events: &str) -> Option<String> {
    for line in events.lines() {
        let Some(payload) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        if value["event"] == "model.failed" {
            return value["error_code"].as_str().map(ToOwned::to_owned);
        }
    }
    None
}

const CONFIG_WITH_AUTH: &str = "version: 1\nmodel:\n  provider: openai\n  model: fixture-model\n\
     providers:\n  openai:\n    protocol: openai-chat-completions\n    \
     base_url: https://127.0.0.1:9/v1\n    auth: demo-primary\n";

/// The loaded config supplies the gateway's default model/provider, visible
/// through the real HTTP model and session surfaces.
#[tokio::test(flavor = "multi_thread")]
async fn binary_present_config_supplies_model_and_provider_defaults() {
    let root = test_root("defaults");
    write_config(&root, CONFIG_WITH_AUTH);
    let stderr_path = root.join("stderr.log");
    let mut child = spawn_gateway(&root, &stderr_path);
    let address = match wait_for_listening(&mut child, &stderr_path, Duration::from_secs(30)).await
    {
        Some(address) => address,
        None => {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("the configured gateway must bind and listen: {stderr}");
        }
    };

    let models = http_request(&address, "GET", "/v1/models", "").await;
    assert_status(&models, "200");
    let models = response_json(&models);
    assert_eq!(models["data"][0]["id"], "fixture-model");
    assert_eq!(models["data"][0]["owned_by"], "openai");

    let session = create_session(&address, &json!({})).await;
    assert_eq!(session["session"]["model"], "fixture-model");
    assert_eq!(session["session"]["provider"], "openai");

    stop_child(&mut child).await;
}

/// A named credential selected by the startup profile must reach the real RSS
/// provider dispatch and the packaged headless native HTTPS factory. The
/// test's synthetic listener accepts the native TCP connection and closes it
/// before trust establishment completes, so the observed result is the
/// transport-layer failure code from the real TLS attempt. The pre-fix binary
/// stopped before any connection (`transport_unavailable`); a credential
/// admission failure would answer `missing_credential`. Neither is accepted
/// here, and this is not a provider authentication or model success.
#[tokio::test(flavor = "multi_thread")]
async fn binary_named_credential_reaches_provider_dispatch() {
    let root = test_root("named-credential");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the synthetic provider listener");
    let provider_port = listener
        .local_addr()
        .expect("synthetic provider listener address")
        .port();
    let config = format!(
        "version: 1\nmodel:\n  provider: openai\n  model: fixture-model\n\
         providers:\n  openai:\n    protocol: openai-chat-completions\n    \
         base_url: https://127.0.0.1:{provider_port}/v1\n    auth: demo-primary\n"
    );
    write_config(&root, &config);
    write_auth_fixture(&root, "demo-primary", "openai");
    let stderr_path = root.join("stderr.log");
    let mut child = spawn_gateway(&root, &stderr_path);
    let address = match wait_for_listening(&mut child, &stderr_path, Duration::from_secs(30)).await
    {
        Some(address) => address,
        None => {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("the configured gateway must bind and listen: {stderr}");
        }
    };
    // One semaphore permit per accepted native TCP connection. The listener
    // never completes a TLS handshake: the connection is closed immediately.
    let accepted = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let accept_permits = std::sync::Arc::clone(&accepted);
    let accept_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            drop(stream);
            accept_permits.add_permits(1);
        }
    });

    let session = create_session(&address, &json!({ "provider": "openai" })).await;
    let session_id = session["session"]["id"].as_str().expect("session id");
    let run_id = admit_run(&address, session_id, "credential propagation").await;
    let events = read_run_events(&address, &run_id, "model.failed").await;
    let code = model_failed_code(&events);
    // Assert the typed transport result before waiting for the connection so
    // the pre-fix binary fails immediately instead of consuming the bound.
    assert_eq!(
        code.as_deref(),
        Some("transport_error"),
        "the packaged factory must attempt the configured native HTTPS request; \
         transport_unavailable means the OAuth/HTTPS host is still missing, \
         missing_credential means the named credential never reached the store; \
         actual events: {events}"
    );
    assert!(
        !events.contains("\"event\":\"model.completed\""),
        "a closed TLS handshake must not be reported as a completed model turn: {events}"
    );
    let permit = tokio::time::timeout(Duration::from_secs(10), accepted.acquire())
        .await
        .expect("the packaged factory must open a native TCP connection")
        .expect("the accept semaphore stays open");
    drop(permit);
    stop_child(&mut child).await;
    accept_task.abort();
    let _ = accept_task.await;
}

/// Without the credential selector, the same run must still answer the typed
/// `missing_credential` failure. It must not borrow the credential belonging to
/// another configured provider.
#[tokio::test(flavor = "multi_thread")]
async fn binary_no_auth_keeps_missing_credential_without_cross_use() {
    let root = test_root("no-auth");
    write_config(
        &root,
        "version: 1\nmodel:\n  provider: openai\n  model: fixture-model\n\
         providers:\n  openai:\n    protocol: openai-chat-completions\n    \
         base_url: https://127.0.0.1:9/v1\n  other:\n    protocol: openai-chat-completions\n    \
         base_url: https://127.0.0.1:8/v1\n    auth: other-primary\n",
    );
    write_auth_fixture(&root, "other-primary", "other");
    let stderr_path = root.join("stderr.log");
    let mut child = spawn_gateway(&root, &stderr_path);
    let address = match wait_for_listening(&mut child, &stderr_path, Duration::from_secs(30)).await
    {
        Some(address) => address,
        None => {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("the configured gateway must bind and listen: {stderr}");
        }
    };

    let session = create_session(&address, &json!({ "provider": "openai" })).await;
    let session_id = session["session"]["id"].as_str().expect("session id");
    let run_id = admit_run(&address, session_id, "no credential selected").await;
    let events = read_run_events(&address, &run_id, "model.failed").await;
    let code = model_failed_code(&events);
    stop_child(&mut child).await;

    assert_eq!(
        code.as_deref(),
        Some("missing_credential"),
        "the selected provider has no credential, and another provider's \
         credential must not be borrowed; actual events: {events}"
    );
}

/// A missing config keeps the built-in local-agent defaults.
#[tokio::test(flavor = "multi_thread")]
async fn binary_missing_config_keeps_local_agent_defaults() {
    let root = test_root("missing-config");
    let stderr_path = root.join("stderr.log");
    let mut child = spawn_gateway(&root, &stderr_path);
    let address = match wait_for_listening(&mut child, &stderr_path, Duration::from_secs(30)).await
    {
        Some(address) => address,
        None => {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("the default gateway must bind and listen: {stderr}");
        }
    };

    let models = http_request(&address, "GET", "/v1/models", "").await;
    assert_status(&models, "200");
    let models = response_json(&models);
    assert_eq!(models["data"][0]["id"], "local-agent");
    assert_eq!(models["data"][0]["owned_by"], "local-agent");

    let session = create_session(&address, &json!({})).await;
    assert_eq!(session["session"]["model"], "local-agent");
    assert_eq!(session["session"]["provider"], "local-agent");

    stop_child(&mut child).await;
}

/// A present-but-invalid config fails before the listener binds and its static
/// startup error never echoes the configured value.
#[tokio::test(flavor = "multi_thread")]
async fn binary_present_invalid_config_fails_before_listen_without_echo() {
    let root = test_root("invalid-config");
    let sentinel = "fixture-invalid-host-sentinel.example";
    write_config(
        &root,
        &format!(
            "version: 1\nmodel:\n  provider: openai\n  model: fixture-model\n\
             providers:\n  openai:\n    protocol: openai-chat-completions\n    \
             base_url: http://{sentinel}/v1\n"
        ),
    );
    let stderr_path = root.join("stderr.log");
    let mut child = spawn_gateway(&root, &stderr_path);
    let listening = wait_for_listening(&mut child, &stderr_path, Duration::from_secs(25)).await;
    let status = if listening.is_some() {
        stop_child(&mut child).await;
        panic!("an invalid config must fail before the listener binds");
    } else {
        tokio::time::timeout(Duration::from_secs(20), child.wait())
            .await
            .expect("the invalid gateway must exit")
            .expect("child wait")
    };
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        !status.success(),
        "an invalid config must exit non-zero: {stderr}"
    );
    assert!(
        stderr.contains("agent config.yaml could not be loaded"),
        "startup must report the static config error: {stderr}"
    );
    assert!(
        !stderr.contains(sentinel),
        "startup diagnostics must not echo the invalid value: {stderr}"
    );
}
