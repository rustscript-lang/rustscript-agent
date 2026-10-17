//! Explicit cached-access E2E through bundled Main and production SQLite.

#[path = "support/live_rust_program.rs"]
mod live_rust_program;

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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const SOURCE_AUTH: &str = "/home/wow/.hermes/auth.json";
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
        let assigned = [
            "RUSTSCRIPT_AGENT_TEST_TMP",
            "RUSTSCRIPT_AGENT_TEST_TMPDIR",
            "TEST_TMPDIR",
        ]
        .into_iter()
        .find_map(|key| std::env::var_os(key).filter(|value| !value.is_empty()))
        .map(PathBuf::from)
        .expect("caller must provide assigned live E2E scratch");
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
    fixed_prompt_validated: AtomicUsize,
    request_guard_validated: AtomicUsize,
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
        let model_ok = wire
            .as_ref()
            .is_some_and(|wire| wire["model"] == "gpt-6.1-sol");
        let fixed_input_ok = wire
            .as_ref()
            .is_some_and(|wire| fixed_prompt_is_one_canonical_user_text(wire.get("input")));
        if fixed_input_ok {
            self.counts
                .fixed_prompt_validated
                .fetch_add(1, Ordering::SeqCst);
        }
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
        let tool_name_ok = tool.is_some_and(|tool| tool["name"] == "manual_access_noop");
        let valid_body = fixed_input_ok
            && model_ok
            && stream_ok
            && store_ok
            && instructions_ok
            && tool_type_ok
            && tool_name_ok
            && parameters_object
            && required_empty
            && additional_properties_closed;
        if !valid_body {
            return Err(OAuthError::InvalidIntent {
                reason: "manual access E2E request body failed local validation".into(),
            });
        }
        self.counts
            .request_guard_validated
            .fetch_add(1, Ordering::SeqCst);
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
        self.inner.start_stream(request, context)
    }
}

fn event_count(events: &[Value], name: &str) -> usize {
    events.iter().filter(|event| event["event"] == name).count()
}

const EXPECTED_LIVE_PROMPT: &str = "Reply with exactly OK. Do not invoke any tools.";

fn fixed_prompt_is_one_canonical_user_text(input: Option<&Value>) -> bool {
    let Some(messages) = input.and_then(Value::as_array) else {
        return false;
    };
    if messages.len() != 1 {
        return false;
    }
    let message = &messages[0];
    if message.get("type").and_then(Value::as_str) != Some("message")
        || message.get("role").and_then(Value::as_str) != Some("user")
    {
        return false;
    }
    let Some(content) = message.get("content").and_then(Value::as_array) else {
        return false;
    };
    content.len() == 1
        && content[0].get("type").and_then(Value::as_str) == Some("input_text")
        && content[0].get("text").and_then(Value::as_str) == Some(EXPECTED_LIVE_PROMPT)
}

#[test]
fn live_wire_guard_accepts_only_one_plain_fixed_prompt() {
    let plain = json!([{
        "type": "message",
        "role": "user",
        "content": [{"type": "input_text", "text": EXPECTED_LIVE_PROMPT}]
    }]);
    assert!(fixed_prompt_is_one_canonical_user_text(Some(&plain)));

    let wrapped = json!([{
        "type": "message",
        "role": "user",
        "content": {"message": EXPECTED_LIVE_PROMPT}
    }]);
    assert!(!fixed_prompt_is_one_canonical_user_text(Some(&wrapped)));

    let wrong = json!([{
        "type": "message",
        "role": "user",
        "content": [{"type": "input_text", "text": "a different prompt"}]
    }]);
    assert!(!fixed_prompt_is_one_canonical_user_text(Some(&wrong)));
    assert!(!fixed_prompt_is_one_canonical_user_text(None));
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
    let fixed_prompt_validated = counts.fixed_prompt_validated.load(Ordering::SeqCst);
    let request_guard_validated = counts.request_guard_validated.load(Ordering::SeqCst);

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
        "SAFE_LIVE_SUMMARY requested={requested} completed={completed} run_completed={run_completed} tool_started={tool_started} tool_completed={tool_completed} run_failed={run_failed} model_calls={model_calls} allowed_response_posts={allowed} blocked_nonresponse_attempts={blocked} fixed_prompt_validated={fixed_prompt_validated} request_guard_validated={request_guard_validated} error_codes={error_codes:?} error_statuses={error_statuses:?} workspace_empty={workspace_empty} private_auth_unchanged={private_auth_unchanged} source_auth_unchanged={source_auth_unchanged} private_home_removed={private_home_removed} artifacts_removed={artifacts_removed}"
    );
    eprintln!(
        "SAFE_REQUEST_GUARD fixed_prompt_exact={} full_request_validated_before_send={}",
        fixed_prompt_validated == 1,
        request_guard_validated == 1
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
    assert_eq!(
        fixed_prompt_validated, 1,
        "exact plain prompt passed wire guard"
    );
    assert_eq!(
        request_guard_validated, 1,
        "all request fields passed before send"
    );
    assert!(assistant_ok, "fixed benign completion was not returned");
    assert!(workspace_empty, "private workspace changed");
    assert!(private_auth_unchanged, "private access file changed");
    assert!(private_home_removed, "private auth home was not removed");
    assert!(artifacts_removed, "live artifacts were not removed");
}
