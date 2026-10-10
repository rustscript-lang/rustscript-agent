//! Explicit one-call cached-access E2E through bundled Main and production SQLite.

use rustscript_agent::auth::host::{AuthHost, RunOAuthCancel, SystemOAuthClock};
use rustscript_agent::auth::native_https::NativeHttpsTransport;
use rustscript_agent::auth::oauth::{
    BoundedHttpsStream, BoundedHttpsTransport, OAuthError, OAuthHost, OAuthIoContext,
    PreparedHttpsRequest, RawHttpsResponse, ScriptedBrowser, ScriptedCallback,
};
use rustscript_agent::config::{ProviderProfile, RunLimits};
use rustscript_agent::registry::ToolRegistry;
use rustscript_agent::tool_schema::ToolDescriptor;
use rustscript_agent::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, RunCancellation};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const SOURCE_AUTH: &str = "/home/wow/.hermes/auth.json";
const TEST_TMP: &str =
    "/mnt/TEMP/workspace/rustscript-agent/tmp/codex-access-responses-e2e-40cf68a2";
const PROVIDER: &str = "openai-codex";
const CREDENTIAL_ID: &str = "live-codex-access-only";
const RESPONSE_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
const ALLOW_LIVE_ENV: &str = "RUSTSCRIPT_AGENT_ALLOW_CODEX_ACCESS_LIVE_E2E";

fn has_exact_assistant_ok_for_run(messages: &[Value], session_id: &str, run_id: &str) -> bool {
    let assistant_messages: Vec<_> = messages
        .iter()
        .filter(|message| {
            message["session_id"] == session_id
                && message["run_id"] == run_id
                && message["role"] == "assistant"
        })
        .collect();
    assistant_messages.len() == 1
        && assistant_messages[0]["content"] == json!([{"type": "text", "text": "OK"}])
        && assistant_messages[0]["finish_reason"] == "stop"
}

fn safe_value_type(value: Option<&Value>) -> &'static str {
    match value {
        None => "missing",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn safe_finish_category(value: Option<&Value>) -> &'static str {
    match value.and_then(Value::as_str) {
        Some("stop") => "stop",
        Some("tool_calls") => "tool_calls",
        Some("length") => "length",
        Some("") => "empty",
        Some(_) => "other",
        None if value.is_none() => "missing",
        None => "other",
    }
}

fn safe_block_category(value: &Value) -> &'static str {
    match value.get("type").and_then(Value::as_str) {
        Some("text") => "text",
        Some("tool_call") => "tool_call",
        Some(_) => "other",
        None => "missing",
    }
}

fn safe_persisted_shape_diagnostic(messages: &[Value], session_id: &str, run_id: &str) -> String {
    let assistant_messages: Vec<_> = messages
        .iter()
        .filter(|message| message.get("role").and_then(Value::as_str) == Some("assistant"))
        .collect();
    let session_matches = assistant_messages
        .iter()
        .filter(|message| message.get("session_id").and_then(Value::as_str) == Some(session_id))
        .count();
    let run_matches = assistant_messages
        .iter()
        .filter(|message| message.get("run_id").and_then(Value::as_str) == Some(run_id))
        .count();
    let joint_matches = assistant_messages
        .iter()
        .filter(|message| {
            message.get("session_id").and_then(Value::as_str) == Some(session_id)
                && message.get("run_id").and_then(Value::as_str) == Some(run_id)
        })
        .count();
    let mut summary = format!(
        "total_messages={} assistant_total={} assistant_session_matches={} assistant_run_matches={} assistant_session_run_matches={}",
        messages.len(),
        assistant_messages.len(),
        session_matches,
        run_matches,
        joint_matches
    );
    for (index, message) in assistant_messages.iter().enumerate() {
        let session = message.get("session_id");
        let run = message.get("run_id");
        let content = message.get("content");
        let blocks = content.and_then(Value::as_array);
        let block_types = blocks
            .into_iter()
            .flatten()
            .map(|block| safe_block_category(block))
            .collect::<Vec<_>>()
            .join(",");
        let text_lengths = blocks
            .into_iter()
            .flatten()
            .map(|block| {
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .map(|text| text.chars().count().to_string())
                    .unwrap_or_else(|| "missing".to_string())
            })
            .collect::<Vec<_>>()
            .join(",");
        let text_exact_ok = blocks
            .into_iter()
            .flatten()
            .map(|block| block.get("text").and_then(Value::as_str) == Some("OK"))
            .map(|matches| matches.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let exact_array_equality = content == Some(&json!([{"type": "text", "text": "OK"}]));
        let finish = message.get("finish_reason");
        summary.push_str(&format!(
            " assistant[{index}]:session_present={} session_type={} session_match={} run_present={} run_type={} run_match={} content_type={} content_array={} canonical_block_count={} block_types=[{}] text_lengths=[{}] text_exact_ok=[{}] exact_array_equality={} finish_type={} finish_category={}",
            session.is_some(),
            safe_value_type(session),
            session.and_then(Value::as_str) == Some(session_id),
            run.is_some(),
            safe_value_type(run),
            run.and_then(Value::as_str) == Some(run_id),
            safe_value_type(content),
            blocks.is_some(),
            blocks.map_or_else(|| "not_array".to_string(), |items| items.len().to_string()),
            block_types,
            text_lengths,
            text_exact_ok,
            exact_array_equality,
            safe_value_type(finish),
            safe_finish_category(finish)
        ));
    }
    summary
}

#[test]
fn exact_persisted_assistant_ok_requires_one_canonical_text_block() {
    let valid = json!({
        "session_id": "session-a",
        "run_id": "run-a",
        "role": "assistant",
        "content": [{"type": "text", "text": "OK"}],
        "finish_reason": "stop"
    });
    assert!(has_exact_assistant_ok_for_run(
        std::slice::from_ref(&valid),
        "session-a",
        "run-a"
    ));

    let mut wrong_text = valid.clone();
    wrong_text["content"][0]["text"] = json!("OK plus");
    assert!(!has_exact_assistant_ok_for_run(
        &[wrong_text],
        "session-a",
        "run-a"
    ));

    let mut extra_block = valid.clone();
    extra_block["content"] = json!([
        {"type": "text", "text": "OK"},
        {"type": "text", "text": "additional"}
    ]);
    assert!(!has_exact_assistant_ok_for_run(
        &[extra_block],
        "session-a",
        "run-a"
    ));

    let mut tool_call_block = valid.clone();
    tool_call_block["content"] = json!([
        {"type": "text", "text": "OK"},
        {"type": "tool_call", "name": "manual_access_noop"}
    ]);
    assert!(!has_exact_assistant_ok_for_run(
        &[tool_call_block],
        "session-a",
        "run-a"
    ));

    let mut wrong_finish = valid.clone();
    wrong_finish["finish_reason"] = json!("tool_calls");
    assert!(!has_exact_assistant_ok_for_run(
        &[wrong_finish],
        "session-a",
        "run-a"
    ));

    let mut wrong_role = valid.clone();
    wrong_role["role"] = json!("user");
    assert!(!has_exact_assistant_ok_for_run(
        &[wrong_role],
        "session-a",
        "run-a"
    ));
    assert!(!has_exact_assistant_ok_for_run(
        std::slice::from_ref(&valid),
        "other-session",
        "run-a"
    ));
    assert!(!has_exact_assistant_ok_for_run(
        std::slice::from_ref(&valid),
        "session-a",
        "other-run"
    ));
    assert!(!has_exact_assistant_ok_for_run(
        &[valid.clone(), valid.clone()],
        "session-a",
        "run-a"
    ));
}

fn live_input_value() -> Value {
    json!(EXPECTED_LIVE_PROMPT)
}

#[test]
fn live_input_preserves_the_fixed_prompt_as_plain_canonical_text() {
    let content = rustscript_agent::decode_message_content(&live_input_value());
    let preserves_prompt = content.as_array().is_some_and(|blocks| {
        blocks.len() == 1
            && blocks[0].get("type").and_then(Value::as_str) == Some("text")
            && blocks[0].get("text").and_then(Value::as_str) == Some(EXPECTED_LIVE_PROMPT)
    });
    assert!(
        preserves_prompt,
        "manual live request did not reach canonical user content as the fixed prompt"
    );
}

fn insert_yaml(mapping: &mut serde_yaml::Mapping, key: &str, value: serde_yaml::Value) {
    mapping.insert(serde_yaml::Value::String(key.into()), value);
}

struct LiveArtifacts {
    root: PathBuf,
}

impl LiveArtifacts {
    fn create() -> Self {
        let assigned = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"),
        );
        assert_eq!(
            assigned,
            PathBuf::from(TEST_TMP),
            "live artifacts must use assigned temp"
        );
        let root = assigned.join(format!("codex-access-live-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).expect("private live artifact root");
        Self { root }
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn database(&self) -> PathBuf {
        self.root.join("agent.sqlite")
    }
}

impl Drop for LiveArtifacts {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct PrivateLiveHome {
    path: PathBuf,
}

impl PrivateLiveHome {
    fn create(
        path: PathBuf,
        workspace: &Path,
        mut access_token: String,
        expires_at_ms: u64,
    ) -> Self {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).expect("private auth home");
        let home = Self { path };

        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config_auth_rss/config.yaml");
        let mut config: serde_yaml::Value =
            serde_yaml::from_slice(&fs::read(fixture).expect("provider structure fixture"))
                .expect("provider structure YAML");
        config["providers"][PROVIDER]["auth"] = serde_yaml::Value::String(CREDENTIAL_ID.into());
        config["providers"][PROVIDER]["transport_identity"] =
            serde_yaml::Value::String("codex_access_claim".into());
        config["workspaces"]["allowed_roots"] =
            serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(
                workspace.display().to_string(),
            )]);
        config["workspaces"]["default"] =
            serde_yaml::Value::String(workspace.display().to_string());
        let mut config_bytes = serde_yaml::to_string(&config)
            .expect("private provider config")
            .into_bytes();
        write_private(&home.path.join("config.yaml"), &config_bytes);
        config_bytes.zeroize();

        let mut credential = serde_yaml::Mapping::new();
        insert_yaml(
            &mut credential,
            "provider",
            serde_yaml::Value::String(PROVIDER.into()),
        );
        insert_yaml(
            &mut credential,
            "kind",
            serde_yaml::Value::String("oauth".into()),
        );
        insert_yaml(
            &mut credential,
            "source",
            serde_yaml::Value::String("codex-device".into()),
        );
        insert_yaml(
            &mut credential,
            "token_type",
            serde_yaml::Value::String("Bearer".into()),
        );
        insert_yaml(
            &mut credential,
            "access_token",
            serde_yaml::Value::String(std::mem::take(&mut access_token)),
        );
        insert_yaml(
            &mut credential,
            "expires_at_ms",
            serde_yaml::Value::Number(expires_at_ms.into()),
        );
        insert_yaml(
            &mut credential,
            "scopes",
            serde_yaml::Value::Sequence(Vec::new()),
        );
        insert_yaml(
            &mut credential,
            "generation",
            serde_yaml::Value::Number(1_u64.into()),
        );
        insert_yaml(
            &mut credential,
            "status",
            serde_yaml::Value::String("active".into()),
        );
        let mut credentials = serde_yaml::Mapping::new();
        credentials.insert(
            serde_yaml::Value::String(CREDENTIAL_ID.into()),
            serde_yaml::Value::Mapping(credential),
        );
        let mut auth = serde_yaml::Mapping::new();
        auth.insert(
            serde_yaml::Value::String("version".into()),
            serde_yaml::Value::Number(1_u64.into()),
        );
        auth.insert(
            serde_yaml::Value::String("credentials".into()),
            serde_yaml::Value::Mapping(credentials),
        );
        let mut auth_bytes = serde_yaml::to_string(&auth)
            .expect("private access-only auth")
            .into_bytes();
        write_private(&home.path.join("auth.yaml"), &auth_bytes);
        auth_bytes.zeroize();
        access_token.zeroize();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&home.path)
                    .expect("home metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            for name in ["config.yaml", "auth.yaml"] {
                assert_eq!(
                    fs::metadata(home.path.join(name))
                        .expect("private file metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        home
    }
}

impl Drop for PrivateLiveHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("create private file");
    file.write_all(bytes).expect("write private file");
    file.sync_all().expect("sync private file");
}

fn read_source_auth_readonly() -> Vec<u8> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(SOURCE_AUTH)
        .expect("open authorized auth source read-only");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .expect("read authorized auth source");
    bytes
}

#[test]
#[ignore = "manual: verifies read-only auth-source access without network"]
fn manual_auth_source_readonly_open_audit() {
    assert_eq!(
        std::env::var(ALLOW_LIVE_ENV).as_deref(),
        Ok("1"),
        "explicit auth-source audit guard is required"
    );
    let mut bytes = read_source_auth_readonly();
    let present = !bytes.is_empty();
    bytes.zeroize();
    assert!(present, "authorized auth source is empty");
}

fn authorized_access_and_source_snapshot() -> (String, Vec<u8>) {
    let bytes = read_source_auth_readonly();
    let document: Value = serde_json::from_slice(&bytes).expect("auth source JSON");
    let entries = document
        .get("credential_pool")
        .and_then(|pool| pool.get(PROVIDER))
        .and_then(Value::as_array)
        .expect("fixed provider credential pool");
    let entry = entries.first().expect("cached provider entry zero");
    let access_token = entry
        .get("access_token")
        .and_then(Value::as_str)
        .expect("cached access field")
        .to_string();
    drop(document);
    (access_token, bytes)
}

fn actual_expiry_ms(access_token: &str) -> u64 {
    assert!(access_token.len() <= 64 * 1024, "bounded access token");
    let mut segments = access_token.split('.');
    let header = segments.next().expect("JWT header segment");
    let payload = segments.next().expect("JWT payload segment");
    let signature = segments.next().expect("JWT signature segment");
    assert!(segments.next().is_none(), "three JWT segments");
    assert!(
        !header.is_empty() && !signature.is_empty(),
        "nonempty JWT envelope"
    );
    let payload_bytes = decode_base64url(payload).expect("JWT payload encoding");
    assert!(payload_bytes.len() <= 64 * 1024, "bounded JWT payload");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("JWT payload JSON");
    let expiry = payload
        .get("exp")
        .and_then(Value::as_u64)
        .expect("actual access-token expiry");
    let expiry_ms = expiry.checked_mul(1000).expect("expiry milliseconds");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis() as u64;
    const REFRESH_SKEW_MS: u64 = 120_000;
    assert!(
        expiry_ms > now_ms.saturating_add(REFRESH_SKEW_MS),
        "cached access token is within configured refresh skew"
    );
    expiry_ms
}

fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 4 == 1 {
        return None;
    }
    let mut output = Vec::with_capacity(input.len().saturating_mul(3) / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits).wrapping_sub(1);
        }
    }
    (accumulator == 0).then_some(output)
}

#[derive(Default)]
struct RequestCounts {
    allowed: AtomicUsize,
    blocked: AtomicUsize,
    request_shape: Mutex<RequestShape>,
    response_shape: Arc<Mutex<ResponseShape>>,
}

struct OneResponsePostTransport {
    inner: NativeHttpsTransport,
    counts: Arc<RequestCounts>,
}

impl OneResponsePostTransport {
    fn new(counts: Arc<RequestCounts>) -> Self {
        Self {
            inner: NativeHttpsTransport::new(),
            counts,
        }
    }

    fn admit(&self, request: &PreparedHttpsRequest) -> Result<(), OAuthError> {
        if request.method != "POST" || request.url != RESPONSE_URL {
            self.counts.blocked.fetch_add(1, Ordering::SeqCst);
            return Err(OAuthError::Transport {
                message: "manual access E2E blocked a non-singleton Responses request".into(),
            });
        }
        let wire = serde_json::from_str::<Value>(&request.body).ok();
        *self
            .counts
            .request_shape
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            RequestShape::observe(wire.as_ref());
        let model_ok = wire
            .as_ref()
            .is_some_and(|wire| wire["model"] == "gpt-6.1-sol");
        let stream_ok = wire.as_ref().is_some_and(|wire| wire["stream"] == true);
        let store_ok = wire.as_ref().is_some_and(|wire| wire["store"] == false);
        let instructions_ok = wire.as_ref().is_some_and(|wire| {
            wire["instructions"]
                .as_str()
                .is_some_and(|instructions| !instructions.is_empty())
        });
        let tools = wire.as_ref().and_then(|wire| wire["tools"].as_array());
        let tool = tools.and_then(|tools| (tools.len() == 1).then(|| &tools[0]));
        let parameters = tool.and_then(|tool| tool.get("parameters"));
        let parameters_object = parameters.is_some_and(Value::is_object);
        let required_empty = parameters
            .and_then(|parameters| parameters.get("required"))
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        let additional_properties_closed = parameters
            .and_then(|parameters| parameters.get("additionalProperties"))
            == Some(&Value::Bool(false));
        let tool_type_ok = tool.is_some_and(|tool| tool["type"] == "function");
        let valid_body = model_ok
            && stream_ok
            && store_ok
            && instructions_ok
            && tool_type_ok
            && parameters_object
            && required_empty
            && additional_properties_closed;
        if !valid_body {
            return Err(OAuthError::InvalidIntent {
                reason: "manual access E2E request body failed local validation".into(),
            });
        }
        if self
            .counts
            .allowed
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Ok(());
        }
        self.counts.blocked.fetch_add(1, Ordering::SeqCst);
        Err(OAuthError::Transport {
            message: "manual access E2E blocked a non-singleton Responses request".into(),
        })
    }
}

impl BoundedHttpsTransport for OneResponsePostTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.admit(request)?;
        self.inner.send(request, context)
    }

    fn start_stream(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        self.admit(request)?;
        let inner = self.inner.start_stream(request, context)?;
        self.counts
            .response_shape
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .status = Some(inner.head().status);
        Ok(Box::new(ObservedBoundedStream {
            inner,
            observation: Arc::clone(&self.counts.response_shape),
        }))
    }
}

fn event_count(events: &[Value], name: &str) -> usize {
    events.iter().filter(|event| event["event"] == name).count()
}

// Test-only observation: bounded safe counters; stream head, chunks, and cancel delegate unchanged.
const OBSERVED_SSE_RECORD_LIMIT_BYTES: usize = 64 * 1024;
const EXPECTED_LIVE_PROMPT: &str = "Reply with exactly OK. Do not invoke any tools.";

#[derive(Default)]
struct RequestShape {
    seen: bool,
    json_valid: bool,
    input_type: &'static str,
    input_count: usize,
    user_message_count: usize,
    input_text_count: usize,
    fixed_prompt_match: bool,
    instructions_type: &'static str,
    instructions_nonempty: bool,
    model_match: bool,
    stream_true: bool,
    store_false: bool,
    tools_type: &'static str,
    tools_count: usize,
    max_output_tokens_numeric: bool,
    max_output_tokens: Option<i64>,
    reasoning_type: &'static str,
    reasoning_effort: &'static str,
}

impl RequestShape {
    fn observe(wire: Option<&Value>) -> Self {
        let mut shape = Self {
            seen: true,
            ..Self::default()
        };
        let Some(wire) = wire else {
            return shape;
        };
        shape.json_valid = true;
        let input = wire.get("input");
        shape.input_type = safe_value_type(input);
        if let Some(items) = input.and_then(Value::as_array) {
            shape.input_count = items.len();
            for item in items {
                if item.get("role").and_then(Value::as_str) != Some("user") {
                    continue;
                }
                shape.user_message_count = shape.user_message_count.saturating_add(1);
                if let Some(parts) = item.get("content").and_then(Value::as_array) {
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) == Some("input_text") {
                            shape.input_text_count = shape.input_text_count.saturating_add(1);
                            shape.fixed_prompt_match |= part.get("text").and_then(Value::as_str)
                                == Some(EXPECTED_LIVE_PROMPT);
                        }
                    }
                }
            }
        }
        shape.instructions_type = safe_value_type(wire.get("instructions"));
        shape.instructions_nonempty = wire
            .get("instructions")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
        shape.model_match = wire.get("model").and_then(Value::as_str) == Some("gpt-6.1-sol");
        shape.stream_true = wire.get("stream") == Some(&Value::Bool(true));
        shape.store_false = wire.get("store") == Some(&Value::Bool(false));
        let tools = wire.get("tools");
        shape.tools_type = safe_value_type(tools);
        shape.tools_count = tools.and_then(Value::as_array).map_or(0, Vec::len);
        let max_output = wire.get("max_output_tokens");
        shape.max_output_tokens_numeric = max_output.is_some_and(Value::is_number);
        shape.max_output_tokens = max_output.and_then(Value::as_i64);
        let reasoning = wire.get("reasoning");
        shape.reasoning_type = safe_value_type(reasoning);
        shape.reasoning_effort = match reasoning {
            None => "missing",
            Some(Value::Null) => "null",
            Some(Value::Object(_)) => match reasoning
                .and_then(|value| value.get("effort"))
                .and_then(Value::as_str)
            {
                Some("none") => "none",
                Some("minimal") => "minimal",
                Some("low") => "low",
                Some("medium") => "medium",
                Some("high") => "high",
                Some("xhigh") => "xhigh",
                Some(_) => "other",
                None => "missing",
            },
            Some(value) => safe_value_type(Some(value)),
        };
        shape
    }

    fn safe_summary(&self) -> String {
        format!(
            "seen={} json_valid={} input_type={} input_count={} user_message_count={} input_text_count={} fixed_prompt_match={} instructions_type={} instructions_nonempty={} model_match={} stream_true={} store_false={} tools_type={} tools_count={} max_output_tokens_numeric={} max_output_tokens={:?} reasoning_type={} reasoning_effort={}",
            self.seen,
            self.json_valid,
            self.input_type,
            self.input_count,
            self.user_message_count,
            self.input_text_count,
            self.fixed_prompt_match,
            self.instructions_type,
            self.instructions_nonempty,
            self.model_match,
            self.stream_true,
            self.store_false,
            self.tools_type,
            self.tools_count,
            self.max_output_tokens_numeric,
            self.max_output_tokens,
            self.reasoning_type,
            self.reasoning_effort
        )
    }
}

#[derive(Default)]
struct TextShape {
    count: usize,
    nonempty: usize,
    chars: usize,
}

impl TextShape {
    fn observe(&mut self, text: &str) {
        self.count = self.count.saturating_add(1);
        if !text.is_empty() {
            self.nonempty = self.nonempty.saturating_add(1);
        }
        self.chars = self.chars.saturating_add(text.chars().count());
    }
}

#[derive(Default)]
struct ItemShape {
    message: usize,
    reasoning: usize,
    function_call: usize,
    other: usize,
}

impl ItemShape {
    fn observe(&mut self, item: &Value) {
        let count = match item.get("type").and_then(Value::as_str) {
            Some("message") => &mut self.message,
            Some("reasoning") => &mut self.reasoning,
            Some("function_call") => &mut self.function_call,
            _ => &mut self.other,
        };
        *count = count.saturating_add(1);
    }
}

struct ResponseShape {
    status: Option<u16>,
    parse_coverage: bool,
    parse_errors: usize,
    read_error: bool,
    eof_observed: bool,
    partial_at_eof: bool,
    output_text_delta: usize,
    refusal_delta: usize,
    output_item_done: usize,
    response_completed: usize,
    response_incomplete: usize,
    response_failed: usize,
    done_marker: usize,
    other_events: usize,
    delta_text: TextShape,
    completed_status_completed: usize,
    completed_status_incomplete: usize,
    completed_status_failed: usize,
    completed_status_missing: usize,
    completed_status_other: usize,
    completed_response_missing: usize,
    completed_response_null: usize,
    completed_response_other_type: usize,
    completed_output_missing: usize,
    completed_output_null: usize,
    completed_output_other_type: usize,
    completed_output_arrays: usize,
    completed_output_items: usize,
    output_items: ItemShape,
    done_items: ItemShape,
    content_missing: usize,
    content_null: usize,
    content_other_type: usize,
    content_arrays: usize,
    content_parts_output_text: usize,
    content_parts_refusal: usize,
    content_parts_other: usize,
    output_text: TextShape,
    refusal_text: TextShape,
    reasoning_summary_arrays: usize,
    reasoning_summary_other_type: usize,
    reasoning_summary_items: usize,
    reasoning_summary_text: TextShape,
    usage_output_tokens_numeric: usize,
    usage_output_tokens: Option<i64>,
    usage_reasoning_tokens_numeric: usize,
    usage_reasoning_tokens: Option<i64>,
    line: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
    after_cr: bool,
    first_line: bool,
    dropping_record: bool,
    discard_line_has_bytes: bool,
}

impl Default for ResponseShape {
    fn default() -> Self {
        Self {
            status: None,
            parse_coverage: true,
            parse_errors: 0,
            read_error: false,
            eof_observed: false,
            partial_at_eof: false,
            output_text_delta: 0,
            refusal_delta: 0,
            output_item_done: 0,
            response_completed: 0,
            response_incomplete: 0,
            response_failed: 0,
            done_marker: 0,
            other_events: 0,
            delta_text: TextShape::default(),
            completed_status_completed: 0,
            completed_status_incomplete: 0,
            completed_status_failed: 0,
            completed_status_missing: 0,
            completed_status_other: 0,
            completed_response_missing: 0,
            completed_response_null: 0,
            completed_response_other_type: 0,
            completed_output_missing: 0,
            completed_output_null: 0,
            completed_output_other_type: 0,
            completed_output_arrays: 0,
            completed_output_items: 0,
            output_items: ItemShape::default(),
            done_items: ItemShape::default(),
            content_missing: 0,
            content_null: 0,
            content_other_type: 0,
            content_arrays: 0,
            content_parts_output_text: 0,
            content_parts_refusal: 0,
            content_parts_other: 0,
            output_text: TextShape::default(),
            refusal_text: TextShape::default(),
            reasoning_summary_arrays: 0,
            reasoning_summary_other_type: 0,
            reasoning_summary_items: 0,
            reasoning_summary_text: TextShape::default(),
            usage_output_tokens_numeric: 0,
            usage_output_tokens: None,
            usage_reasoning_tokens_numeric: 0,
            usage_reasoning_tokens: None,
            line: Vec::new(),
            data: Vec::new(),
            has_data: false,
            after_cr: false,
            first_line: true,
            dropping_record: false,
            discard_line_has_bytes: false,
        }
    }
}

impl ResponseShape {
    fn feed(&mut self, chunk: &[u8]) {
        for byte in chunk.iter().copied() {
            if self.dropping_record {
                self.consume_discarded_byte(byte);
            } else if byte == b'\r' {
                self.finish_line();
                self.after_cr = true;
            } else if byte == b'\n' {
                if self.after_cr {
                    self.after_cr = false;
                } else {
                    self.finish_line();
                }
            } else {
                self.after_cr = false;
                if self.line.len() >= OBSERVED_SSE_RECORD_LIMIT_BYTES {
                    self.parse_coverage = false;
                    self.dropping_record = true;
                    self.discard_line_has_bytes = true;
                    self.clear_pending();
                } else {
                    self.line.push(byte);
                }
            }
        }
    }

    fn consume_discarded_byte(&mut self, byte: u8) {
        if byte == b'\r' {
            self.finish_discarded_line();
            self.after_cr = true;
        } else if byte == b'\n' {
            if self.after_cr {
                self.after_cr = false;
            } else {
                self.finish_discarded_line();
            }
        } else {
            self.after_cr = false;
            self.discard_line_has_bytes = true;
        }
    }

    fn finish_discarded_line(&mut self) {
        if self.discard_line_has_bytes {
            self.discard_line_has_bytes = false;
        } else {
            self.dropping_record = false;
            self.has_data = false;
            self.data.zeroize();
            self.data.clear();
            self.first_line = false;
        }
    }

    fn finish_line(&mut self) {
        let mut line = std::mem::take(&mut self.line);
        if self.first_line {
            self.first_line = false;
            if line.starts_with(&[0xef, 0xbb, 0xbf]) {
                line.drain(..3);
            }
        }
        if line.is_empty() {
            self.dispatch_data();
            line.zeroize();
            return;
        }
        if line.starts_with(b"data:") {
            let mut payload = &line[5..];
            if payload.first() == Some(&b' ') {
                payload = &payload[1..];
            }
            let separator = usize::from(self.has_data);
            if self
                .data
                .len()
                .saturating_add(separator)
                .saturating_add(payload.len())
                > OBSERVED_SSE_RECORD_LIMIT_BYTES
            {
                self.parse_coverage = false;
                self.dropping_record = true;
                self.discard_line_has_bytes = false;
                self.has_data = false;
                self.data.zeroize();
                self.data.clear();
            } else {
                if self.has_data {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(payload);
                self.has_data = true;
            }
        }
        line.zeroize();
    }

    fn dispatch_data(&mut self) {
        if !self.has_data {
            return;
        }
        let mut data = std::mem::take(&mut self.data);
        self.has_data = false;
        if data.as_slice() == b"[DONE]" {
            self.done_marker = self.done_marker.saturating_add(1);
        } else if let Ok(event) = serde_json::from_slice::<Value>(&data) {
            self.observe_event(&event);
        } else {
            self.parse_errors = self.parse_errors.saturating_add(1);
            self.parse_coverage = false;
        }
        data.zeroize();
    }

    fn observe_event(&mut self, event: &Value) {
        match event.get("type").and_then(Value::as_str) {
            Some("response.output_text.delta") => {
                self.output_text_delta = self.output_text_delta.saturating_add(1);
                if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                    self.delta_text.observe(delta);
                }
            }
            Some("response.refusal.delta") => {
                self.refusal_delta = self.refusal_delta.saturating_add(1);
                if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                    self.delta_text.observe(delta);
                }
            }
            Some("response.output_item.done") => {
                self.output_item_done = self.output_item_done.saturating_add(1);
                if let Some(item) = event.get("item") {
                    self.done_items.observe(item);
                }
            }
            Some("response.completed") => {
                self.response_completed = self.response_completed.saturating_add(1);
                match event.get("response") {
                    None => {
                        self.completed_response_missing =
                            self.completed_response_missing.saturating_add(1)
                    }
                    Some(Value::Null) => {
                        self.completed_response_null =
                            self.completed_response_null.saturating_add(1)
                    }
                    Some(Value::Object(_)) => {
                        self.observe_completed_response(event.get("response").unwrap())
                    }
                    Some(_) => {
                        self.completed_response_other_type =
                            self.completed_response_other_type.saturating_add(1)
                    }
                }
            }
            Some("response.incomplete") => {
                self.response_incomplete = self.response_incomplete.saturating_add(1)
            }
            Some("response.failed") => {
                self.response_failed = self.response_failed.saturating_add(1)
            }
            _ => self.other_events = self.other_events.saturating_add(1),
        }
    }

    fn observe_completed_response(&mut self, response: &Value) {
        match response.get("status").and_then(Value::as_str) {
            Some("completed") => {
                self.completed_status_completed = self.completed_status_completed.saturating_add(1)
            }
            Some("incomplete") => {
                self.completed_status_incomplete =
                    self.completed_status_incomplete.saturating_add(1)
            }
            Some("failed") => {
                self.completed_status_failed = self.completed_status_failed.saturating_add(1)
            }
            None if response.get("status").is_none() => {
                self.completed_status_missing = self.completed_status_missing.saturating_add(1)
            }
            _ => self.completed_status_other = self.completed_status_other.saturating_add(1),
        }
        match response.get("output") {
            None => self.completed_output_missing = self.completed_output_missing.saturating_add(1),
            Some(Value::Null) => {
                self.completed_output_null = self.completed_output_null.saturating_add(1)
            }
            Some(Value::Array(output)) => {
                self.completed_output_arrays = self.completed_output_arrays.saturating_add(1);
                self.completed_output_items =
                    self.completed_output_items.saturating_add(output.len());
                for item in output {
                    self.output_items.observe(item);
                    self.observe_output_item(item);
                }
            }
            Some(_) => {
                self.completed_output_other_type =
                    self.completed_output_other_type.saturating_add(1)
            }
        }
        if let Some(usage) = response.get("usage") {
            if let Some(tokens) = usage.get("output_tokens").and_then(Value::as_i64) {
                self.usage_output_tokens_numeric =
                    self.usage_output_tokens_numeric.saturating_add(1);
                self.usage_output_tokens = Some(tokens);
            }
            let reasoning_tokens = usage.get("reasoning_tokens").or_else(|| {
                usage
                    .get("output_tokens_details")
                    .and_then(|v| v.get("reasoning_tokens"))
            });
            if let Some(tokens) = reasoning_tokens.and_then(Value::as_i64) {
                self.usage_reasoning_tokens_numeric =
                    self.usage_reasoning_tokens_numeric.saturating_add(1);
                self.usage_reasoning_tokens = Some(tokens);
            }
        }
    }

    fn observe_output_item(&mut self, item: &Value) {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => self.observe_content(item.get("content")),
            Some("reasoning") => self.observe_reasoning_summary(item.get("summary")),
            _ => {}
        }
    }

    fn observe_content(&mut self, content: Option<&Value>) {
        let Some(content) = content else {
            self.content_missing = self.content_missing.saturating_add(1);
            return;
        };
        match content {
            Value::Null => self.content_null = self.content_null.saturating_add(1),
            Value::Array(parts) => {
                self.content_arrays = self.content_arrays.saturating_add(1);
                for part in parts {
                    match part.get("type").and_then(Value::as_str) {
                        Some("output_text") => {
                            self.content_parts_output_text =
                                self.content_parts_output_text.saturating_add(1);
                            if let Some(text) = part.get("text").and_then(Value::as_str) {
                                self.output_text.observe(text);
                            }
                        }
                        Some("refusal") => {
                            self.content_parts_refusal =
                                self.content_parts_refusal.saturating_add(1);
                            if let Some(text) = part
                                .get("refusal")
                                .or_else(|| part.get("text"))
                                .and_then(Value::as_str)
                            {
                                self.refusal_text.observe(text);
                            }
                        }
                        _ => self.content_parts_other = self.content_parts_other.saturating_add(1),
                    }
                }
            }
            _ => self.content_other_type = self.content_other_type.saturating_add(1),
        }
    }

    fn observe_reasoning_summary(&mut self, summary: Option<&Value>) {
        let Some(summary) = summary else {
            self.reasoning_summary_other_type = self.reasoning_summary_other_type.saturating_add(1);
            return;
        };
        if let Some(parts) = summary.as_array() {
            self.reasoning_summary_arrays = self.reasoning_summary_arrays.saturating_add(1);
            self.reasoning_summary_items = self.reasoning_summary_items.saturating_add(parts.len());
            for part in parts {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    self.reasoning_summary_text.observe(text);
                }
            }
        } else {
            self.reasoning_summary_other_type = self.reasoning_summary_other_type.saturating_add(1);
        }
    }

    fn observe_eof(&mut self) {
        self.eof_observed = true;
        self.partial_at_eof = !self.line.is_empty() || self.has_data || self.dropping_record;
        if self.partial_at_eof {
            self.parse_coverage = false;
        }
        self.clear_pending();
    }

    fn clear_pending(&mut self) {
        self.line.zeroize();
        self.line.clear();
        self.data.zeroize();
        self.data.clear();
        self.has_data = false;
    }

    fn safe_summary(&self) -> String {
        format!(
            "status={:?} parse_coverage={} parse_errors={} read_error={} eof_observed={} partial_at_eof={} event_output_text_delta={} event_refusal_delta={} event_output_item_done={} event_response_completed={} event_response_incomplete={} event_response_failed={} event_done={} event_other={} delta_count={} delta_nonempty={} delta_chars={} completed_status_completed={} completed_status_incomplete={} completed_status_failed={} completed_status_missing={} completed_status_other={} completed_response_missing={} completed_response_null={} completed_response_other_type={} completed_output_missing={} completed_output_null={} completed_output_other_type={} completed_output_arrays={} completed_output_items={} item_message={} item_reasoning={} item_function_call={} item_other={} done_item_message={} done_item_reasoning={} done_item_function_call={} done_item_other={} content_missing={} content_null={} content_other_type={} content_arrays={} content_output_text={} content_refusal={} content_other={} output_text_count={} output_text_nonempty={} output_text_chars={} refusal_text_count={} refusal_text_nonempty={} refusal_text_chars={} reasoning_summary_arrays={} reasoning_summary_other_type={} reasoning_summary_items={} reasoning_summary_text_count={} reasoning_summary_text_nonempty={} reasoning_summary_text_chars={} usage_output_tokens_numeric={} usage_output_tokens={:?} usage_reasoning_tokens_numeric={} usage_reasoning_tokens={:?}",
            self.status,
            self.parse_coverage,
            self.parse_errors,
            self.read_error,
            self.eof_observed,
            self.partial_at_eof,
            self.output_text_delta,
            self.refusal_delta,
            self.output_item_done,
            self.response_completed,
            self.response_incomplete,
            self.response_failed,
            self.done_marker,
            self.other_events,
            self.delta_text.count,
            self.delta_text.nonempty,
            self.delta_text.chars,
            self.completed_status_completed,
            self.completed_status_incomplete,
            self.completed_status_failed,
            self.completed_status_missing,
            self.completed_status_other,
            self.completed_response_missing,
            self.completed_response_null,
            self.completed_response_other_type,
            self.completed_output_missing,
            self.completed_output_null,
            self.completed_output_other_type,
            self.completed_output_arrays,
            self.completed_output_items,
            self.output_items.message,
            self.output_items.reasoning,
            self.output_items.function_call,
            self.output_items.other,
            self.done_items.message,
            self.done_items.reasoning,
            self.done_items.function_call,
            self.done_items.other,
            self.content_missing,
            self.content_null,
            self.content_other_type,
            self.content_arrays,
            self.content_parts_output_text,
            self.content_parts_refusal,
            self.content_parts_other,
            self.output_text.count,
            self.output_text.nonempty,
            self.output_text.chars,
            self.refusal_text.count,
            self.refusal_text.nonempty,
            self.refusal_text.chars,
            self.reasoning_summary_arrays,
            self.reasoning_summary_other_type,
            self.reasoning_summary_items,
            self.reasoning_summary_text.count,
            self.reasoning_summary_text.nonempty,
            self.reasoning_summary_text.chars,
            self.usage_output_tokens_numeric,
            self.usage_output_tokens,
            self.usage_reasoning_tokens_numeric,
            self.usage_reasoning_tokens
        )
    }
}

impl Drop for ResponseShape {
    fn drop(&mut self) {
        self.clear_pending();
    }
}

struct ObservedBoundedStream {
    inner: Box<dyn BoundedHttpsStream>,
    observation: Arc<Mutex<ResponseShape>>,
}

impl BoundedHttpsStream for ObservedBoundedStream {
    fn head(&self) -> &rustscript_agent::auth::oauth::RawHttpsResponseHead {
        self.inner.head()
    }

    fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, OAuthError> {
        match self.inner.read_chunk() {
            Ok(Some(chunk)) => {
                self.observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .feed(&chunk);
                Ok(Some(chunk))
            }
            Ok(None) => {
                self.observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .observe_eof();
                Ok(None)
            }
            Err(error) => {
                self.observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .read_error = true;
                Err(error)
            }
        }
    }

    fn cancel(&mut self) {
        self.inner.cancel();
    }
}

#[test]
fn bounded_split_sse_observer_counts_structure_without_retaining_text() {
    let events = [
        json!({"type":"response.output_text.delta","delta":"synthetic-visible-delta"}),
        json!({"type":"response.refusal.delta","delta":"synthetic-refusal-delta"}),
        json!({"type":"response.output_item.done","item":{"type":"function_call"}}),
        json!({
            "type":"response.completed",
            "response":{
                "status":"completed",
                "output":[
                    {"type":"message","content":[
                        {"type":"output_text","text":"synthetic-completed-text"},
                        {"type":"refusal","refusal":"synthetic-completed-refusal"},
                        {"type":"other-part","text":"not-counted"}
                    ]},
                    {"type":"reasoning","summary":[{"type":"summary_text","text":"synthetic-summary"}]},
                    {"type":"function_call"}
                ],
                "usage":{"output_tokens":42,"output_tokens_details":{"reasoning_tokens":7}}
            }
        }),
        json!({"type":"response.completed","response":{"status":"completed","output":[]}}),
        json!({"type":"response.completed","response":{"output":null}}),
        json!({"type":"response.completed","response":{"status":"other-status"}}),
        json!({"type":"response.incomplete"}),
        json!({"type":"response.failed"}),
    ];
    let mut stream = Vec::new();
    for event in events {
        stream.extend_from_slice(b"data: ");
        stream.extend_from_slice(&serde_json::to_vec(&event).expect("synthetic SSE event"));
        stream.extend_from_slice(b"\r\n\r\n");
    }
    stream.extend_from_slice(b"data: [DONE]\n\n");

    let mut observation = ResponseShape::default();
    for chunk in stream.chunks(11) {
        observation.feed(chunk);
    }

    assert!(observation.parse_coverage);
    assert_eq!(observation.output_text_delta, 1);
    assert_eq!(observation.refusal_delta, 1);
    assert_eq!(observation.output_item_done, 1);
    assert_eq!(observation.response_completed, 4);
    assert_eq!(observation.response_incomplete, 1);
    assert_eq!(observation.response_failed, 1);
    assert_eq!(observation.done_marker, 1);
    assert_eq!(observation.delta_text.count, 2);
    assert_eq!(observation.delta_text.nonempty, 2);
    assert_eq!(
        observation.delta_text.chars,
        "synthetic-visible-delta synthetic-refusal-delta"
            .replace(' ', "")
            .chars()
            .count()
    );
    assert_eq!(observation.completed_status_completed, 2);
    assert_eq!(observation.completed_status_missing, 1);
    assert_eq!(observation.completed_status_other, 1);
    assert_eq!(observation.completed_output_arrays, 2);
    assert_eq!(observation.completed_output_items, 3);
    assert_eq!(observation.completed_output_null, 1);
    assert_eq!(observation.completed_output_missing, 1);
    assert_eq!(observation.output_items.message, 1);
    assert_eq!(observation.output_items.reasoning, 1);
    assert_eq!(observation.output_items.function_call, 1);
    assert_eq!(observation.content_parts_output_text, 1);
    assert_eq!(observation.content_parts_refusal, 1);
    assert_eq!(observation.content_parts_other, 1);
    assert_eq!(observation.output_text.count, 1);
    assert_eq!(observation.output_text.nonempty, 1);
    assert_eq!(observation.refusal_text.count, 1);
    assert_eq!(observation.refusal_text.nonempty, 1);
    assert_eq!(observation.reasoning_summary_arrays, 1);
    assert_eq!(observation.reasoning_summary_items, 1);
    assert_eq!(observation.reasoning_summary_text.count, 1);
    assert_eq!(observation.usage_output_tokens, Some(42));
    assert_eq!(observation.usage_reasoning_tokens, Some(7));
    let report = observation.safe_summary();
    assert!(!report.contains("synthetic"));
    assert!(observation.line.is_empty());
    assert!(observation.data.is_empty());
    stream.zeroize();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: requires explicit cached access-only authorization"]
async fn one_cached_access_token_runs_bundled_main_once_without_tools_or_auth_side_effects() {
    assert_eq!(
        std::env::var(ALLOW_LIVE_ENV).as_deref(),
        Ok("1"),
        "explicit live authorization guard is required"
    );

    let mut source_before;
    let mut access_token;
    (access_token, source_before) = authorized_access_and_source_snapshot();
    let expires_at_ms = actual_expiry_ms(&access_token);
    let artifacts = LiveArtifacts::create();
    let workspace = artifacts.workspace();
    let mut workspace_builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        workspace_builder.mode(0o700);
    }
    workspace_builder
        .create(&workspace)
        .expect("empty private workspace");
    let home = PrivateLiveHome::create(
        artifacts.home(),
        &workspace,
        std::mem::take(&mut access_token),
        expires_at_ms,
    );
    access_token.zeroize();

    let mut private_auth_before =
        fs::read(home.path.join("auth.yaml")).expect("private access file");
    let counts = Arc::new(RequestCounts::default());
    let home_path = home.path.clone();
    let request_counts = Arc::clone(&counts);
    let auth_factory: Arc<dyn Fn(RunCancellation) -> Result<AuthHost, String> + Send + Sync> =
        Arc::new(move |cancellation| {
            let transport: Arc<dyn BoundedHttpsTransport> =
                Arc::new(OneResponsePostTransport::new(Arc::clone(&request_counts)));
            let oauth = Arc::new(OAuthHost::new(
                transport,
                Arc::new(ScriptedCallback::new()),
                Arc::new(ScriptedBrowser::new()),
                Arc::new(SystemOAuthClock),
                Arc::new(RunOAuthCancel::new(cancellation.clone())),
            ));
            AuthHost::new(home_path.clone(), cancellation).map(|host| host.with_oauth_host(oauth))
        });

    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig {
            provider: Some(PROVIDER.into()),
            model: "gpt-6.1-sol".into(),
            run_timeout: Duration::from_secs(60),
            ..AgentGatewayConfig::default()
        },
        rustscript_agent::bundled_agent_main_path(),
        artifacts.database(),
    )
    .expect("bundled Main with production SQLite driver");
    let service = state.service().clone();
    service
        .set_run_limits(RunLimits::new(1, 1, 16 * 1024, &workspace).expect("private live limits"))
        .expect("install private live limits");
    let registry = ToolRegistry::from_descriptors([ToolDescriptor::new(
        "manual_access_noop",
        "A non-executable safety sentinel; do not call it.",
        "coding",
        "read",
        json!({"type":"object","properties":{},"required":[],"additionalProperties":false}),
    )])
    .expect("nonempty harmless tool registry");
    service
        .set_tool_registry(registry)
        .expect("install restricted tool registry");
    service.set_auth_host_factory(auth_factory);
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

    let admitted = service
        .admit(AdmitRunRequest {
            input: live_input_value(),
            model: Some("gpt-6.1-sol".into()),
            provider: Some(PROVIDER.into()),
            platform: "codex_access_live_e2e".into(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("single access-only Main admission");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".into())
        .await;

    let events = service.run_events(&admitted.run_id);
    let requested = event_count(&events, "model.requested");
    let completed = event_count(&events, "model.completed");
    let run_completed = event_count(&events, "run.completed");
    let tool_started = event_count(&events, "tool.started");
    let tool_completed = event_count(&events, "tool.completed");
    let run_failed = event_count(&events, "run.failed");
    let model_calls = service.metrics().snapshot().model_calls;
    let allowed = counts.allowed.load(Ordering::SeqCst);
    let blocked = counts.blocked.load(Ordering::SeqCst);

    let error_codes: Vec<String> = events
        .iter()
        .filter_map(|event| event.pointer("/data/error_code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    let error_statuses: Vec<i64> = events
        .iter()
        .filter_map(|event| event.pointer("/data/status").and_then(Value::as_i64))
        .collect();
    let messages = service.session_messages(&admitted.session_id);
    let assistant_ok =
        has_exact_assistant_ok_for_run(&messages, &admitted.session_id, &admitted.run_id);
    eprintln!(
        "SAFE_PERSISTED_SHAPE {}",
        safe_persisted_shape_diagnostic(&messages, &admitted.session_id, &admitted.run_id)
    );
    let workspace_empty = fs::read_dir(&workspace)
        .expect("private workspace listing")
        .next()
        .is_none();

    let mut private_auth_after =
        fs::read(home.path.join("auth.yaml")).expect("private access file after run");
    let private_auth_unchanged = private_auth_before == private_auth_after;
    private_auth_before.zeroize();
    private_auth_after.zeroize();

    let home_path = home.path.clone();
    let artifacts_path = artifacts.root.clone();
    drop(service);
    drop(state);
    drop(home);
    let private_home_removed = !home_path.exists();
    drop(artifacts);
    let artifacts_removed = !artifacts_path.exists();

    let mut source_after = read_source_auth_readonly();
    // Record byte changes as an observation; they do not identify the writer.
    let source_auth_unchanged = source_before == source_after;
    source_before.zeroize();
    source_after.zeroize();

    eprintln!(
        "SAFE_LIVE_SUMMARY requested={requested} completed={completed} run_completed={run_completed} tool_started={tool_started} tool_completed={tool_completed} run_failed={run_failed} model_calls={model_calls} allowed_response_posts={allowed} blocked_nonresponse_attempts={blocked} error_codes={error_codes:?} error_statuses={error_statuses:?} workspace_empty={workspace_empty} private_auth_unchanged={private_auth_unchanged} source_auth_unchanged={source_auth_unchanged} private_home_removed={private_home_removed} artifacts_removed={artifacts_removed}"
    );
    eprintln!(
        "SAFE_WIRE_SHAPE {}",
        counts
            .request_shape
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .safe_summary()
    );
    eprintln!(
        "SAFE_RAW_RESPONSE_SHAPE {}",
        counts
            .response_shape
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .safe_summary()
    );

    assert_eq!(requested, 1, "one authorized logical request");
    assert_eq!(completed, 1, "one completed response");
    assert_eq!(run_completed, 1, "Main completed");
    assert_eq!(tool_started, 0, "no live tool invocation");
    assert_eq!(tool_completed, 0, "no live tool completion");
    assert_eq!(run_failed, 0, "no live run failure");
    assert_eq!(model_calls, 1, "exactly one model call");
    assert_eq!(allowed, 1, "one exact Responses POST");
    assert_eq!(
        blocked, 0,
        "zero token/refresh/login/other endpoint attempts"
    );
    assert!(assistant_ok, "fixed benign completion was not returned");
    assert!(workspace_empty, "private workspace changed");
    assert!(private_auth_unchanged, "private access file changed");
    assert!(private_home_removed, "private auth home was not removed");
    assert!(artifacts_removed, "live artifacts were not removed");
}
