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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const SOURCE_AUTH: &str = "/home/wow/.hermes/auth.json";
const TEST_TMP: &str =
    "/mnt/TEMP/workspace/rustscript-agent/tmp/codex-access-responses-e2e-40cf68a2";
const PROVIDER: &str = "openai-codex";
const CREDENTIAL_ID: &str = "live-codex-access-only";
const RESPONSE_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
const ALLOW_LIVE_ENV: &str = "RUSTSCRIPT_AGENT_ALLOW_CODEX_ACCESS_LIVE_E2E";

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

fn authorized_access_and_source_snapshot() -> (String, Vec<u8>) {
    let bytes = fs::read(SOURCE_AUTH).expect("read authorized auth source");
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
        self.inner.start_stream(request, context)
    }
}

fn event_count(events: &[Value], name: &str) -> usize {
    events.iter().filter(|event| event["event"] == name).count()
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
            input: json!({"message":"Reply with exactly OK. Do not invoke any tools."}),
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
    let assistant_ok = messages.iter().any(|message| {
        message["role"] == "assistant"
            && message["content"].as_str() == Some("OK")
            && message["finish_reason"] == "stop"
    });
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

    let mut source_after = fs::read(SOURCE_AUTH).expect("re-read authorized auth source");
    let source_auth_unchanged = source_before == source_after;
    source_before.zeroize();
    source_after.zeroize();

    eprintln!(
        "SAFE_LIVE_SUMMARY requested={requested} completed={completed} run_completed={run_completed} tool_started={tool_started} tool_completed={tool_completed} run_failed={run_failed} model_calls={model_calls} allowed_response_posts={allowed} blocked_nonresponse_attempts={blocked} error_codes={error_codes:?} error_statuses={error_statuses:?} workspace_empty={workspace_empty} private_auth_unchanged={private_auth_unchanged} source_auth_unchanged={source_auth_unchanged} private_home_removed={private_home_removed} artifacts_removed={artifacts_removed}"
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
    assert!(source_auth_unchanged, "source auth file changed");
    assert!(private_home_removed, "private auth home was not removed");
    assert!(artifacts_removed, "live artifacts were not removed");
}
