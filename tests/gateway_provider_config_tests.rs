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

#[cfg(feature = "config-fixture")]
#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;

#[cfg(feature = "config-fixture")]
use provider_opaque_fixture::FixtureHome;
#[cfg(feature = "config-fixture")]
use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse,
};
#[cfg(feature = "config-fixture")]
use rustscript_agent::config::ProviderProfile;
#[cfg(feature = "config-fixture")]
use rustscript_agent::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState};
#[cfg(feature = "config-fixture")]
use std::collections::BTreeMap;
#[cfg(feature = "config-fixture")]
use std::sync::{Arc, Mutex};

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
        .env("RUSTSCRIPT_AGENT_HOME", home(root))
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

#[cfg(feature = "config-fixture")]
const SCHEMA_WIRE_PROVIDER: &str = "openai";
#[cfg(feature = "config-fixture")]
const SCHEMA_WIRE_BASE_URL: &str = "https://provider.synthetic.test/v1";
#[cfg(feature = "config-fixture")]
const SCHEMA_WIRE_CREDENTIAL: &str = "schema-wire-fixture-credential";
#[cfg(feature = "config-fixture")]
const SCHEMA_WIRE_ACCESS: &str = "SYNTHETIC_SCHEMA_WIRE_ACCESS";
#[cfg(feature = "config-fixture")]
const SCHEMA_WIRE_MODEL: &str = "fixture-model";
#[cfg(feature = "config-fixture")]
const SCHEMA_WIRE_ANSWER: &str = "fixture-final-reply";

/// A strict synthetic Chat Completions upstream. It validates the complete
/// provider wire request in private memory and rejects schema-shaped defects
/// with the typed 400 a strict server would return; only a fully valid wire
/// request receives the fixed synthetic final reply. It never persists, logs,
/// or returns the observed request body.
#[cfg(feature = "config-fixture")]
struct StrictChatTransport {
    expected_tools: Vec<(String, String, Value)>,
    calls: Mutex<usize>,
    violations: Mutex<Vec<String>>,
}

#[cfg(feature = "config-fixture")]
impl StrictChatTransport {
    fn new(expected_tools: Vec<(String, String, Value)>) -> Self {
        Self {
            expected_tools,
            calls: Mutex::new(0),
            violations: Mutex::new(Vec::new()),
        }
    }

    fn reject(&self, code: &str) -> RawHttpsResponse {
        RawHttpsResponse {
            status: 400,
            headers: BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: format!(
                "{{\"error\":{{\"type\":\"invalid_request_error\",\"code\":\"{code}\",\
                 \"message\":\"synthetic upstream rejected the provider wire request\"}}}}"
            )
            .into_bytes(),
        }
    }
}

#[cfg(feature = "config-fixture")]
impl BoundedHttpsTransport for StrictChatTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        *self.calls.lock().expect("strict transport call lock") += 1;
        let parsed: Value = match serde_json::from_str(&request.body) {
            Ok(value) => value,
            Err(_) => {
                self.violations
                    .lock()
                    .expect("strict transport violation lock")
                    .push("provider request body is not JSON".to_string());
                return Ok(self.reject("invalid_request"));
            }
        };
        let mut violations = self
            .violations
            .lock()
            .expect("strict transport violation lock");
        let mut schema_invalid = false;
        if request.method != "POST" {
            violations.push("provider request method is not POST".to_string());
        }
        if request.url != format!("{SCHEMA_WIRE_BASE_URL}/chat/completions") {
            violations
                .push("provider request URL is not the synthetic fixture endpoint".to_string());
        }
        if parsed["model"] != json!(SCHEMA_WIRE_MODEL) {
            violations.push("provider request model is not the fixture model".to_string());
        }
        match parsed["tools"].as_array() {
            None => violations.push("provider request has no tools array".to_string()),
            Some(tools) => {
                if tools.len() != self.expected_tools.len() {
                    violations.push(format!(
                        "provider request tool count {} does not match the native registry",
                        tools.len()
                    ));
                }
                for (index, tool) in tools.iter().enumerate() {
                    let Some((name, description, schema)) = self.expected_tools.get(index) else {
                        violations.push(format!("unexpected provider tool at index {index}"));
                        continue;
                    };
                    if tool["function"]["name"].as_str() != Some(name.as_str()) {
                        violations.push(format!("provider tool order mismatch at index {index}"));
                        continue;
                    }
                    if tool["function"]["description"].as_str() != Some(description.as_str()) {
                        violations.push(format!(
                            "tool {name} description must equal the native descriptor"
                        ));
                        continue;
                    }
                    let parameters = &tool["function"]["parameters"];
                    if !parameters.is_object() {
                        schema_invalid = true;
                        violations.push(format!("tool {name} parameters must be a JSON object"));
                    } else if parameters != schema {
                        schema_invalid = true;
                        violations.push(format!(
                            "tool {name} parameters must equal the native registry schema"
                        ));
                    }
                }
            }
        }
        if !violations.is_empty() {
            let code = if schema_invalid {
                "invalid_tool_schema"
            } else {
                "invalid_request"
            };
            return Ok(self.reject(code));
        }
        drop(violations);
        Ok(RawHttpsResponse {
            status: 200,
            headers: BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: format!(
                "{{\"id\":\"chatcmpl-schema-wire\",\"object\":\"chat.completion\",\
                 \"model\":\"{SCHEMA_WIRE_MODEL}\",\"choices\":[{{\"index\":0,\
                 \"message\":{{\"role\":\"assistant\",\"content\":\"{SCHEMA_WIRE_ANSWER}\"}},\
                 \"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\
                 \"completion_tokens\":1,\"total_tokens\":2}}}}"
            )
            .into_bytes(),
        })
    }
}

/// The complete bundled coding pipeline must hand the canonical Chat codec
/// the native registry schemas as schema_json strings: every wire tool
/// `parameters` is then a JSON object equal to the matching native descriptor
/// schema, in registry order, while the admission snapshot itself stays
/// native and unchanged.
#[cfg(feature = "config-fixture")]
#[tokio::test(flavor = "multi_thread")]
async fn bundled_chat_pipeline_emits_native_tool_schemas_as_wire_objects() {
    let root = test_root("schema-wire");
    let workspace_home = root.join("workspace-home");
    let workspace = root.join("project");
    std::fs::create_dir_all(&workspace_home).expect("workspace home");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let workspace_config = format!(
        "version: 1\nmodel:\n  provider: {SCHEMA_WIRE_PROVIDER}\n  model: {SCHEMA_WIRE_MODEL}\n\
         providers:\n  {SCHEMA_WIRE_PROVIDER}:\n    protocol: openai-chat-completions\n    \
         base_url: '{SCHEMA_WIRE_BASE_URL}'\nworkspaces:\n  allowed_roots:\n    - '{}'\n  \
         default: '{}'\n",
        workspace.display(),
        workspace.display()
    );
    std::fs::write(workspace_home.join("config.yaml"), workspace_config)
        .expect("workspace authority config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&workspace_home, std::fs::Permissions::from_mode(0o700))
            .expect("workspace home mode");
        std::fs::set_permissions(
            workspace_home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("workspace config mode");
    }

    let home = FixtureHome::for_profile(
        "schema-wire",
        SCHEMA_WIRE_PROVIDER,
        SCHEMA_WIRE_BASE_URL,
        SCHEMA_WIRE_CREDENTIAL,
        SCHEMA_WIRE_ACCESS,
    );
    let native_before = rustscript_agent::bundled_tool_registry()
        .expect("bundled native registry")
        .snapshot()
        .schemas();
    let expected_tools: Vec<(String, String, Value)> = native_before
        .as_array()
        .expect("native descriptor array")
        .iter()
        .map(|descriptor| {
            (
                descriptor["name"]
                    .as_str()
                    .expect("native descriptor name")
                    .to_string(),
                descriptor["description"]
                    .as_str()
                    .expect("native descriptor description")
                    .to_string(),
                descriptor["schema"].clone(),
            )
        })
        .collect();
    assert!(
        !expected_tools.is_empty(),
        "the bundled registry must expose native tool descriptors"
    );
    let transport = Arc::new(StrictChatTransport::new(expected_tools));

    let db_path = root.join("gateway.sqlite3");
    let state = AgentGatewayState::with_sqlite_path(
        AgentGatewayConfig {
            provider: Some(SCHEMA_WIRE_PROVIDER.to_string()),
            model: SCHEMA_WIRE_MODEL.to_string(),
            run_timeout: Duration::from_secs(30),
            ..AgentGatewayConfig::default()
        },
        &db_path,
    )
    .expect("bundled coding gateway state")
    .with_workspace_home(workspace_home.clone());
    let service = state.service();
    service.set_auth_host_factory(home.auth_factory(Arc::clone(&transport)));
    service.upsert_provider_profile(
        ProviderProfile::new(
            SCHEMA_WIRE_PROVIDER,
            json!({
                "profile": SCHEMA_WIRE_PROVIDER,
                "protocol": "openai-chat-completions",
                "base_url": SCHEMA_WIRE_BASE_URL,
                "credential_id": SCHEMA_WIRE_CREDENTIAL
            }),
        )
        .expect("public fixture provider profile"),
    );
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "return the fixture final reply"}),
            model: Some(SCHEMA_WIRE_MODEL.to_string()),
            provider: Some(SCHEMA_WIRE_PROVIDER.to_string()),
            platform: "gateway_provider_config_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admission through the real service");
    let context_before = service
        .run_context(&admitted.run_id)
        .expect("admitted native run context")
        .tool_schemas;
    assert!(
        context_before == native_before,
        "admission context must retain the native tool descriptors"
    );
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let context_after = service
        .run_context(&admitted.run_id)
        .expect("retained native run context")
        .tool_schemas;
    assert!(
        context_after == context_before,
        "the native tool_schemas snapshot must not be rewritten"
    );
    let native_after = rustscript_agent::bundled_tool_registry()
        .expect("bundled native registry after the run")
        .snapshot()
        .schemas();
    assert!(
        native_after == native_before,
        "the bundled native registry descriptors must not be mutated"
    );

    let violations = transport
        .violations
        .lock()
        .expect("strict transport violation lock")
        .clone();
    assert!(
        violations.is_empty(),
        "strict synthetic upstream must accept every tool schema: {violations:?}"
    );
    assert_eq!(
        *transport.calls.lock().expect("strict transport call lock"),
        1,
        "one provider turn"
    );
    let events = service.run_events(&admitted.run_id);
    let completed = events
        .iter()
        .filter(|event| event["event"] == "run.completed")
        .count();
    assert_eq!(
        completed, 1,
        "the bundled coding pipeline must complete one run"
    );
    let assistants: Vec<Value> = service
        .session_messages(&admitted.session_id)
        .into_iter()
        .filter(|message| message["role"] == "assistant")
        .collect();
    assert_eq!(assistants.len(), 1, "one assistant final reply");
    assert!(
        assistants[0].to_string().contains(SCHEMA_WIRE_ANSWER),
        "the synthetic final reply must persist"
    );

    let mut renderer = rustscript_agent::gateway::EventRenderer::new();
    let mut delivered = Vec::new();
    for event in &events {
        let kind = event["event"].as_str().expect("canonical event kind");
        for action in renderer.on_event(kind, &event["data"]) {
            match action {
                rustscript_agent::gateway::RenderAction::Send { text } => delivered.push(text),
                rustscript_agent::gateway::RenderAction::SendDelta { text } => {
                    renderer.note_sent(delivered.len() as i64 + 1);
                    delivered.push(text);
                }
                rustscript_agent::gateway::RenderAction::Edit { text, .. } => delivered.push(text),
            }
        }
    }
    assert_eq!(
        delivered
            .iter()
            .filter(|text| text.as_str() == SCHEMA_WIRE_ANSWER)
            .count(),
        1,
        "the real bundled pipeline must render its buffered final reply, not only a done status"
    );

    drop(service);
    drop(state);
    drop(home);
    std::fs::remove_dir_all(&root).expect("remove schema-wire fixture root");
}
