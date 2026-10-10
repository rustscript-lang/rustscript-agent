//! Native trusted transport identity regression through the production harness.

#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;

use provider_opaque_fixture::{
    canonical_request, harness_context, read_provider_fixture, sse_events, vm_value_to_json,
};
use rustscript_agent::auth::host::AuthHost;
use rustscript_agent::auth::oauth::{
    BoundedHttpsStream, BoundedHttpsTransport, OAuthError, OAuthHost, OAuthIoContext,
    PreparedHttpsRequest, RawHttpsResponse, RawHttpsResponseHead, ScriptedBrowser,
    ScriptedCallback, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
};
use rustscript_agent::config::ProviderProfile;
use rustscript_agent::{
    AdmitRunRequest, AgentConfig, AgentGatewayConfig, AgentGatewayState, AgentHostBridges,
    AgentRunner, RunCancellation,
};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CREDENTIAL_ID: &str = "fixture-codex";
const PROVIDER: &str = "openai-codex";
const CLAIM_ACCOUNT_ID: &str = "acct-from-access-claim";

struct PrivateAuthHome(PathBuf);

impl PrivateAuthHome {
    fn new(access_token: &str) -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        fs::create_dir_all(&root).expect("fixture root");
        let path = root.join(format!("codex-metadata-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).expect("private auth home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let mut config: serde_yaml::Value = serde_yaml::from_str(
            &fs::read_to_string(fixture.join("config.yaml")).expect("config fixture"),
        )
        .expect("config fixture YAML");
        config["providers"][PROVIDER]["transport_identity"] =
            serde_yaml::Value::String("codex_access_claim".to_string());
        fs::write(
            path.join("config.yaml"),
            serde_yaml::to_string(&config).expect("config serialization"),
        )
        .expect("write config");

        let mut auth: serde_yaml::Value = serde_yaml::from_str(
            &fs::read_to_string(fixture.join("auth.yaml")).expect("auth fixture"),
        )
        .expect("auth fixture YAML");
        let credential = auth["credentials"][CREDENTIAL_ID]
            .as_mapping_mut()
            .expect("credential mapping");
        credential.remove(serde_yaml::Value::String("refresh_token".to_string()));
        credential.insert(
            serde_yaml::Value::String("access_token".to_string()),
            serde_yaml::Value::String(access_token.to_string()),
        );
        credential.insert(
            serde_yaml::Value::String("expires_at_ms".to_string()),
            serde_yaml::Value::Number(
                (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock")
                    .as_millis() as i64
                    + 3_600_000)
                    .into(),
            ),
        );
        fs::write(
            path.join("auth.yaml"),
            serde_yaml::to_string(&auth).expect("auth serialization"),
        )
        .expect("write auth");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("file mode");
            }
        }
        Self(path)
    }
}

impl Drop for PrivateAuthHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct DiscardSink;

impl rustscript_agent::RunEventSink for DiscardSink {
    fn deliver(&mut self, _value: Value) -> Result<(), rustscript_agent::RunDeliveryError> {
        Ok(())
    }
}

fn access_token_for_payload(payload: &str) -> String {
    format!("e30.{}.AA", base64url_encode(payload.as_bytes()))
}

fn access_token_with_account_claim() -> String {
    let payload = format!(
        r#"{{"https://api.openai.com/auth":{{"chatgpt_account_id":"{CLAIM_ACCOUNT_ID}"}}}}"#
    );
    access_token_for_payload(&payload)
}

fn base64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (first << 16) | (second << 8) | third;
        output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(value & 63) as usize] as char);
        }
    }
    output
}

fn run_restricted_harness(
    access_token: &str,
    scripted_transport: Arc<ScriptedHttpsTransport>,
    request: JsonValue,
) -> JsonValue {
    let home = PrivateAuthHome::new(access_token);
    let transport: Arc<dyn BoundedHttpsTransport> = scripted_transport;
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_millis() as u64,
        )),
        Arc::new(ScriptedCancel::new()),
    ));
    let home_path = home.0.clone();
    let factory: Arc<dyn Fn(RunCancellation) -> Result<AuthHost, String> + Send + Sync> =
        Arc::new(move |cancellation| {
            AuthHost::new(home_path.clone(), cancellation)
                .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
        });
    let runner = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss"),
        AgentConfig::default(),
    )
    .expect("production harness compiles")
    .with_host(AgentHostBridges {
        auth_host_factory: Some(factory),
        ..AgentHostBridges::default()
    });
    let mut sink = DiscardSink;
    let context = harness_context(
        "openai_responses",
        request,
        json!({
            "provider": PROVIDER,
            "base_url": "https://chatgpt.com/backend-api/codex",
            "model": "gpt-6.1-sol"
        }),
        CREDENTIAL_ID,
    );
    vm_value_to_json(
        &runner
            .run_named_with_context_and_events(
                "run_harness",
                context,
                &mut sink,
                &RunCancellation::with_timeout(Duration::from_secs(30)),
            )
            .expect("harness invocation"),
    )
}

#[test]
fn admitted_codex_access_claim_assembles_native_headers_from_same_access_token() {
    let token = access_token_with_account_claim();
    let scripted_transport = Arc::new(ScriptedHttpsTransport::new());
    scripted_transport.push_json(
        200,
        json!({
            "id": "resp_test",
            "object": "response",
            "status": "completed",
            "model": "gpt-6.1-sol",
            "output": [{
                "type": "message",
                "id": "msg_test",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "OK"}]
            }],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "error": null
        }),
    );
    let result = run_restricted_harness(
        &token,
        Arc::clone(&scripted_transport),
        canonical_request(false),
    );
    let sent = scripted_transport.take_sent();
    assert_eq!(
        result["ok"],
        json!(true),
        "{result}; sent_count={}",
        sent.len()
    );
    assert_eq!(result["response"]["text"], json!("OK"));
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0]
            .headers
            .get("chatgpt-account-id")
            .map(String::as_str),
        Some(CLAIM_ACCOUNT_ID)
    );
    assert_eq!(
        sent[0].headers.get("originator").map(String::as_str),
        Some("codex_cli_rs")
    );
    assert_eq!(
        sent[0].headers.get("user-agent").map(String::as_str),
        Some("rustscript-agent-access-e2e/0.1")
    );
    assert!(!sent[0].body.contains(CLAIM_ACCOUNT_ID));
    assert!(!result.to_string().contains(CLAIM_ACCOUNT_ID));
}

#[test]
fn flat_only_access_claim_is_denied_before_restricted_rss_transport() {
    let payload = r#"{"https://api.openai.com/auth.chatgpt_account_id":"acct-flat-only"}"#;
    let token = access_token_for_payload(payload);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let result = run_restricted_harness(&token, Arc::clone(&transport), canonical_request(false));
    assert_eq!(result["ok"], json!(false));
    assert_eq!(transport.take_sent().len(), 0);
    assert!(!result.to_string().contains("acct-flat-only"));
}

#[test]
fn conflicting_flat_alternate_is_denied_before_restricted_rss_transport() {
    let payload = format!(
        r#"{{"https://api.openai.com/auth":{{"chatgpt_account_id":"{CLAIM_ACCOUNT_ID}"}},"https://api.openai.com/auth.chatgpt_account_id":"acct-alternate"}}"#
    );
    let token = access_token_for_payload(&payload);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let result = run_restricted_harness(&token, Arc::clone(&transport), canonical_request(false));
    assert_eq!(result["ok"], json!(false));
    assert_eq!(transport.take_sent().len(), 0);
    assert!(!result.to_string().contains("acct-alternate"));
}

#[test]
fn public_header_override_cannot_replace_native_account_header() {
    let token = access_token_with_account_claim();
    let mut request = canonical_request(false);
    request["headers"] = json!({"chatgpt-account-id":"acct-public-override"});
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        200,
        json!({
            "id": "resp_header_guard",
            "object": "response",
            "status": "completed",
            "model": "gpt-6.1-sol",
            "output": [{
                "type": "message",
                "id": "msg_header_guard",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "OK"}]
            }],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "error": null
        }),
    );
    let result = run_restricted_harness(&token, Arc::clone(&transport), request);
    let sent = transport.take_sent();
    assert_eq!(result["ok"], json!(true));
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0]
            .headers
            .get("chatgpt-account-id")
            .map(String::as_str),
        Some(CLAIM_ACCOUNT_ID)
    );
    assert!(!sent[0].body.contains("acct-public-override"));
    assert!(!result.to_string().contains("acct-public-override"));
}

struct QueuedSseTransport {
    responses: Mutex<VecDeque<Vec<Vec<u8>>>>,
    sent: Mutex<Vec<PreparedHttpsRequest>>,
}

impl QueuedSseTransport {
    fn new(transcripts: impl IntoIterator<Item = String>) -> Self {
        let responses = transcripts
            .into_iter()
            .map(|transcript| {
                sse_events(&transcript)
                    .into_iter()
                    .map(String::into_bytes)
                    .collect()
            })
            .collect();
        Self {
            responses: Mutex::new(responses),
            sent: Mutex::new(Vec::new()),
        }
    }

    fn take_sent(&self) -> Vec<PreparedHttpsRequest> {
        std::mem::take(&mut *self.sent.lock().expect("sent requests"))
    }
}

impl BoundedHttpsTransport for QueuedSseTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        _context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        Err(OAuthError::Transport {
            message: "unexpected buffered request".to_string(),
        })
    }

    fn start_stream(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        context.check()?;
        self.sent
            .lock()
            .expect("sent requests")
            .push(request.clone());
        let chunks = self
            .responses
            .lock()
            .expect("queued responses")
            .pop_front()
            .ok_or_else(|| OAuthError::Transport {
                message: "no queued SSE fixture".to_string(),
            })?;
        Ok(Box::new(QueuedSseReader {
            head: RawHttpsResponseHead {
                status: 200,
                headers: std::collections::BTreeMap::from([(
                    "content-type".to_string(),
                    "text/event-stream".to_string(),
                )]),
            },
            chunks: chunks.into(),
            cancelled: false,
        }))
    }
}

struct QueuedSseReader {
    head: RawHttpsResponseHead,
    chunks: VecDeque<Vec<u8>>,
    cancelled: bool,
}

impl BoundedHttpsStream for QueuedSseReader {
    fn head(&self) -> &RawHttpsResponseHead {
        &self.head
    }

    fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, OAuthError> {
        if self.cancelled {
            return Ok(None);
        }
        Ok(self.chunks.pop_front())
    }

    fn cancel(&mut self) {
        self.cancelled = true;
        self.chunks.clear();
    }
}

fn response_completed_sse(response: JsonValue) -> String {
    format!(
        "event: response.completed\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"type": "response.completed", "response": response})
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn bundled_main_codex_responses_tool_continuation_is_durable_and_access_only() {
    use rustscript_agent::config::RunLimits;

    let root = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
    );
    let workspace_root = root.join(format!("codex-main-tool-{}", uuid::Uuid::new_v4()));
    let workspace = workspace_root.join("workspace");
    fs::create_dir_all(&workspace).expect("fixture workspace");
    fs::write(workspace.join("README.md"), "fixture-read-value\n").expect("fixture text");

    let home = PrivateAuthHome::new(&access_token_with_account_claim());
    let home_path = home.0.clone();
    let auth_path = home_path.join("auth.yaml");
    let auth_before = fs::read(&auth_path).expect("private auth fixture bytes");
    let first = read_provider_fixture("openai_responses/stream.sse");
    let second = response_completed_sse(json!({
        "id": "resp_final",
        "object": "response",
        "status": "completed",
        "model": "gpt-6.1-sol",
        "output": [{
            "type": "message",
            "id": "msg_final",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "I read fixture-read-value."}]
        }],
        "usage": {"input_tokens": 17, "output_tokens": 6, "total_tokens": 23}
    }));
    let transport = Arc::new(QueuedSseTransport::new([first, second]));
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_millis() as u64,
        )),
        Arc::new(ScriptedCancel::new()),
    ));
    let factory: Arc<dyn Fn(RunCancellation) -> Result<AuthHost, String> + Send + Sync> = {
        let home_path = home_path.clone();
        Arc::new(move |cancellation| {
            AuthHost::new(home_path.clone(), cancellation)
                .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
        })
    };

    let db_path = root.join(format!("codex-main-tool-{}.sqlite", uuid::Uuid::new_v4()));
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig {
            provider: Some(PROVIDER.to_string()),
            model: "gpt-6.1-sol".to_string(),
            run_timeout: Duration::from_secs(45),
            ..AgentGatewayConfig::default()
        },
        rustscript_agent::bundled_agent_main_path(),
        &db_path,
    )
    .expect("bundled Main with production SQLite driver");
    let service = state.service().clone();
    service
        .set_run_limits(
            RunLimits::new(8, 8, 64 * 1024, &workspace).expect("bounded fixture run limits"),
        )
        .expect("install fixture run limits");
    service.upsert_provider_profile(
        ProviderProfile::new(
            PROVIDER,
            json!({
                "profile": PROVIDER,
                "protocol": "codex-responses",
                "base_url": "https://chatgpt.com/backend-api/codex",
                "credential_id": CREDENTIAL_ID
            }),
        )
        .expect("public Codex Responses profile"),
    );
    service.set_auth_host_factory(factory);

    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "Read README.md and report its contents."}),
            model: Some("gpt-6.1-sol".to_string()),
            provider: Some(PROVIDER.to_string()),
            platform: "codex_access_main_fixture".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("fixture Main admission");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events = service.run_events(&admitted.run_id);
    let event_count = |name: &str| events.iter().filter(|event| event["event"] == name).count();
    let event_names: Vec<_> = events
        .iter()
        .filter_map(|event| event["event"].as_str())
        .collect();
    let failure_codes: Vec<_> = events
        .iter()
        .filter_map(|event| {
            event
                .pointer("/data/error_code")
                .and_then(JsonValue::as_str)
        })
        .collect();
    let observed_sends = transport.sent.lock().expect("sent requests").len();
    assert_eq!(
        event_count("model.requested"),
        2,
        "one request per Main turn"
    );
    assert_eq!(
        event_count("model.completed"),
        2,
        "both turns completed; events={event_names:?}; failure_codes={failure_codes:?}; sends={observed_sends}"
    );
    assert_eq!(event_count("tool.completed"), 1, "one durable read tool");
    assert_eq!(event_count("run.completed"), 1, "one terminal run");

    let messages = service.session_messages(&admitted.session_id);
    let assistants: Vec<_> = messages
        .iter()
        .filter(|message| message["role"] == "assistant")
        .collect();
    assert_eq!(assistants.len(), 2, "tool-call parent and final answer");
    assert!(
        messages.iter().any(|message| {
            message["role"] == "user"
                && message["tool_call_id"] == "call_xy"
                && message.to_string().contains("fixture-read-value")
        }),
        "durable tool_result must preserve call ID and read output"
    );
    assert!(
        assistants[1]
            .to_string()
            .contains("I read fixture-read-value.")
    );

    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        2,
        "two exact Responses calls, no refresh attempt"
    );
    for request in &sent {
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.url,
            "https://chatgpt.com/backend-api/codex/responses"
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("text/event-stream")
        );
        assert_eq!(
            request
                .headers
                .get("chatgpt-account-id")
                .map(String::as_str),
            Some(CLAIM_ACCOUNT_ID)
        );
        assert_eq!(
            request.headers.get("originator").map(String::as_str),
            Some("codex_cli_rs")
        );
        assert_eq!(
            request.headers.get("user-agent").map(String::as_str),
            Some("rustscript-agent-access-e2e/0.1")
        );
        let wire: JsonValue = serde_json::from_str(&request.body).expect("Responses request JSON");
        assert_eq!(wire["model"], "gpt-6.1-sol");
        assert_eq!(wire["stream"], true);
        assert_eq!(wire["store"], false);
        assert!(!wire["instructions"].as_str().unwrap_or_default().is_empty());
        let tools = wire["tools"].as_array().expect("Main tool schemas");
        assert!(!tools.is_empty());
        assert!(tools.iter().all(|tool| {
            tool["parameters"].is_object()
                && tool["parameters"]["required"].is_array()
                && tool["parameters"]["additionalProperties"] == false
        }));
        assert!(!request.body.contains(CLAIM_ACCOUNT_ID));
        assert!(!request.body.contains("SYNTHETIC_REFRESH_TOKEN"));
    }
    let continuation: JsonValue = serde_json::from_str(&sent[1].body).expect("second request");
    let input: Vec<JsonValue> =
        serde_json::from_value(continuation["input"].clone()).expect("Responses input items");
    assert!(
        input.iter().any(|item| {
            item["type"] == "function_call_output"
                && item["call_id"] == "call_xy"
                && item["output"]
                    .as_str()
                    .is_some_and(|output| output.contains("fixture-read-value"))
        }),
        "second request carries the matching tool result"
    );
    assert_eq!(service.metrics().snapshot().model_calls, 2);
    assert_eq!(
        fs::read(&auth_path).expect("auth still readable"),
        auth_before
    );

    drop(service);
    drop(state);
    drop(home);
    assert!(!home_path.exists(), "private access-only home removed");
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = PathBuf::from(format!("{}{suffix}", db_path.display()));
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_dir_all(&workspace_root);
}
