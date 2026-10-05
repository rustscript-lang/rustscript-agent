use rustscript_agent::RunCancellation;
use rustscript_agent::auth::host::{
    AuthHost, DeviceInstructionSender, PublicDeviceInstruction, device_instruction_channel,
};
use rustscript_agent::auth::oauth::{
    OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
    ScriptedHttpsTransport,
};
use rustscript_agent::auth::store::AuthStore;
use rustscript_agent::cli::{CliOutput, execute_auth_cli};
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryError, AuthEntryRunner};
use rustscript_vm::{
    CompileSourceFileOptions, ParserDialect, SharedParserOptions, SourceFlavor, Value,
    compile_source_at_path_with_flavor_and_options, parse_source_with_dialect,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const ENTRY_PATH: &str = "rss/auth/login.rss";
const CODEX_PATH: &str = "rss/auth/codex_device.rss";
const TYPES_PATH: &str = "rss/auth/types.rss";
const CREDENTIAL_ID: &str = "fixture-codex";
const START_MS: u64 = 1_900_000_000_000;
const DEVICE_SECRET: &str = "SYNTHETIC_DEVICE_SECRET_61c4";
const CODE_SECRET: &str = "SYNTHETIC_AUTH_CODE_SECRET_28b1";
const VERIFIER_SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const ACCESS_SECRET: &str = "SYNTHETIC_ACCESS_TOKEN_SECRET_a513";
const REFRESH_SECRET: &str = "SYNTHETIC_REFRESH_TOKEN_SECRET_d6e2";
const ALIAS: &str = "fixture-device-alias";
const USER_CODE: &str = "PUBLIC-CODE-7QK";

const STARTER_ENTRY: &str = r#"
use auth;
struct AuthCommandInput { operation: string, provider: string?, credential_id: string? }
struct AuthEntryResult { ok: bool, operation: string, credential_id: string?, generation: int, status: string, error: string? }
pub fn run(home: resource<auth.host_home>, command: AuthCommandInput) -> AuthEntryResult {
    {ok: false, operation: command.operation, credential_id: null, generation: 0, status: "unsupported_operation", error: "unsupported_operation"}
}
"#;
const STARTER_SOURCES: &[(&str, &str)] = &[
    (ENTRY_PATH, STARTER_ENTRY),
    (CODEX_PATH, include_str!("../rss/auth/codex_device.rss")),
    (TYPES_PATH, include_str!("../rss/auth/types.rss")),
];

const LOGIN_SOURCES: &[(&str, &str)] = &[
    (ENTRY_PATH, include_str!("../rss/auth/login.rss")),
    (CODEX_PATH, include_str!("../rss/auth/codex_device.rss")),
    (TYPES_PATH, include_str!("../rss/auth/types.rss")),
];

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new(provider_alias: Option<&str>, flow: &str) -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 test TEMP"),
        );
        fs::create_dir_all(&root).expect("create assigned test temp");
        let home = root.join(format!("task6-login-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).expect("create auth fixture home");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/codex_device/config.yaml");
        let mut config = fs::read_to_string(source).expect("read configured device provider");
        if let Some(alias) = provider_alias {
            config = config
                .replace("openai-codex", alias)
                .replace("codex-device", flow);
        } else if flow != "codex-device" {
            config = config.replace("codex-device", flow);
        }
        fs::write(home.join("config.yaml"), config).expect("write selected provider config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
                .expect("secure fixture home");
            fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
                .expect("secure fixture config");
        }
        Self(home)
    }

    fn config_bytes(&self) -> Vec<u8> {
        fs::read(self.0.join("config.yaml")).expect("read config fixture bytes")
    }

    fn auth_exists(&self) -> bool {
        self.0.join("auth.yaml").exists()
    }

    fn stored_metadata(&self) -> Option<rustscript_agent::auth::store::AuthMetadata> {
        AuthStore::from_home(&self.0)
            .ok()?
            .load_metadata(CREDENTIAL_ID)
            .ok()
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(operation: &str, provider: Option<&str>) -> AuthCommandInput {
    AuthCommandInput {
        operation: operation.to_owned(),
        provider: provider.map(str::to_owned),
        credential_id: None,
    }
}

fn command_with_credential(
    operation: &str,
    provider: Option<&str>,
    credential_id: Option<&str>,
) -> AuthCommandInput {
    AuthCommandInput {
        operation: operation.to_owned(),
        provider: provider.map(str::to_owned),
        credential_id: credential_id.map(str::to_owned),
    }
}

fn starter_runner() -> AuthEntryRunner {
    AuthEntryRunner::from_bundle(ENTRY_PATH, STARTER_SOURCES)
        .expect("compile guest baseline bundle")
}

fn login_runner() -> AuthEntryRunner {
    AuthEntryRunner::from_bundle(ENTRY_PATH, LOGIN_SOURCES)
        .expect("compile production login bundle")
}

fn oauth_host(transport: Arc<ScriptedHttpsTransport>) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(START_MS)),
        Arc::new(ScriptedCancel::new()),
    ))
}

fn build_host(
    home: &Path,
    child: RunCancellation,
    transport: Arc<ScriptedHttpsTransport>,
    sender: Option<DeviceInstructionSender>,
) -> Result<AuthHost, String> {
    let mut host = AuthHost::new_for_enrollment(home, child, CREDENTIAL_ID)?;
    host = host.with_oauth_host(oauth_host(transport));
    if let Some(sender) = sender {
        host = host.with_device_instruction_sender(sender);
    }
    Ok(host)
}

fn run_value(
    runner: &AuthEntryRunner,
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
    sender: Option<DeviceInstructionSender>,
    input: AuthCommandInput,
) -> Result<Value, AuthEntryError> {
    let home = home.0.clone();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    runner.run_with_host_factory(input, &cancellation, move |child| {
        build_host(&home, child, transport, sender)
    })
}

fn run_cli(
    runner: &AuthEntryRunner,
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
    sender: Option<DeviceInstructionSender>,
    input: AuthCommandInput,
) -> CliOutput {
    let home = home.0.clone();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    execute_auth_cli(runner, input, &cancellation, move |child| {
        build_host(&home, child, transport, sender)
    })
}

fn run_starter(input: AuthCommandInput) -> Value {
    let home = FixtureHome::new(None, "codex-device");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    run_value(&starter_runner(), &home, transport, None, input)
        .expect("execute guest baseline with the native enrollment host")
}

fn queue_success(transport: &ScriptedHttpsTransport) {
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}","public":"poll-ok"}}"#),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","token_type":"Bearer","expires_in":3600,"public":"exchange-ok"}}"#
        ),
    );
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected RSS result, got {value:?}");
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn text(value: &Value) -> &str {
    let Value::String(text) = value else {
        panic!("expected RSS string, got {value:?}");
    };
    text
}

fn cli_row(output: &CliOutput) -> serde_json::Value {
    serde_json::from_str(output.stdout.trim()).expect("one redacted JSON status row")
}

fn assert_no_secret(value: &str) {
    for secret in [
        DEVICE_SECRET,
        CODE_SECRET,
        VERIFIER_SECRET,
        ACCESS_SECRET,
        REFRESH_SECRET,
    ] {
        assert!(
            !value.contains(secret),
            "private material leaked in {value}"
        );
    }
}

fn assert_failure(value: &Value, code: &str) {
    assert_eq!(field(value, "ok"), &Value::Bool(false));
    assert_eq!(text(field(value, "status")), code);
    assert_eq!(text(field(value, "error")), code);
}

struct DiagnosticDialect;

impl ParserDialect for DiagnosticDialect {
    fn allow_let_mut_binding(&self) -> bool {
        true
    }
    fn allow_macro_calls(&self) -> bool {
        true
    }
    fn allow_plus_equal_operator(&self) -> bool {
        true
    }
    fn allow_for_in_loop(&self) -> bool {
        true
    }
}

#[test]
fn diagnostic_login_rss_parse() {
    for (path, source) in LOGIN_SOURCES {
        let parsed = parse_source_with_dialect(
            source,
            &DiagnosticDialect,
            SharedParserOptions {
                source_id: 0,
                allow_implicit_externs: true,
                allow_implicit_semicolons: false,
                enforce_mutable_bindings: false,
                import_scan_mode: true,
            },
        );
        assert!(parsed.is_ok(), "{path}: {parsed:?}");
    }
}

#[test]
fn diagnostic_login_rss_compile() {
    let catalog = rustscript_agent::auth::host::auth_host_catalog();
    let mut options =
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    for (path, source) in LOGIN_SOURCES {
        options.set_module_override_source(
            format!("/__rustscript_agent_auth_bundle__/{path}"),
            *source,
        );
    }
    let entry_path = Path::new("/__rustscript_agent_auth_bundle__/rss/auth/login.rss");
    let result = compile_source_at_path_with_flavor_and_options(
        entry_path,
        LOGIN_SOURCES[0].1,
        SourceFlavor::RustScript,
        options,
    );
    result.unwrap_or_else(|error| panic!("{error:?}"));
}

#[test]
fn guest_login_baseline_reports_unsupported_operation() {
    let result = run_starter(command("auth.login", None));
    assert_failure(&result, "unsupported_operation");
}

#[test]
fn login_requires_explicit_provider() {
    let home = FixtureHome::new(None, "codex-device");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let result = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        None,
        command("auth.login", None),
    )
    .expect("login result");
    assert_failure(&result, "provider_required");
    assert_eq!(result_map_generation(&result), 0);
    assert!(transport.take_sent().is_empty());
    assert!(!home.auth_exists());
}

fn result_map_generation(value: &Value) -> i64 {
    match field(value, "generation") {
        Value::Int(value) => *value,
        other => panic!("expected integer generation, got {other:?}"),
    }
}

#[test]
fn alias_device_flow_saves_native_credentials_and_renders_only_redacted_metadata() {
    let home = FixtureHome::new(Some(ALIAS), "codex-device");
    let config_before = home.config_bytes();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_success(&transport);
    let (sender, receiver) = device_instruction_channel();
    let runner = login_runner();

    let first = run_cli(
        &runner,
        &home,
        transport.clone(),
        Some(sender),
        command("auth.login", Some(ALIAS)),
    );
    assert_eq!(first.exit_code, 0, "{}", first.stderr);
    assert!(first.stderr.is_empty());
    assert_eq!(
        cli_row(&first),
        serde_json::json!({
            "provider": ALIAS,
            "credential_id": CREDENTIAL_ID,
            "status": "active",
            "generation": 1,
            "source": "codex-device"
        })
    );
    let instruction: PublicDeviceInstruction =
        receiver.try_recv().expect("native queue instruction");
    assert_eq!(instruction.user_code, USER_CODE);
    assert_eq!(
        instruction.verification_url,
        "https://auth.example.test/codex/device"
    );
    assert!(receiver.try_recv().is_err(), "one instruction is queued");
    assert_eq!(transport.take_sent().len(), 3, "start, poll, exchange only");
    assert_eq!(
        home.config_bytes(),
        config_before,
        "login leaves config bytes unchanged"
    );
    let first_metadata = home.stored_metadata().expect("real native save");
    assert_eq!(first_metadata.credential_id, CREDENTIAL_ID);
    assert_eq!(first_metadata.provider, ALIAS);
    assert_eq!(first_metadata.generation, 1);
    assert_eq!(first_metadata.status, "active");
    assert_eq!(first_metadata.source, "codex-device");
    assert_no_secret(&first.stdout);
    assert_no_secret(&first.stderr);

    queue_success(&transport);
    let (sender, receiver) = device_instruction_channel();
    let second = run_cli(
        &runner,
        &home,
        transport.clone(),
        Some(sender),
        command("auth.login", Some(ALIAS)),
    );
    assert_eq!(second.exit_code, 0, "{}", second.stderr);
    assert_eq!(cli_row(&second)["generation"], 2);
    assert_eq!(
        receiver.try_recv().expect("second instruction").user_code,
        USER_CODE
    );
    assert_eq!(transport.take_sent().len(), 3);
    assert_eq!(home.config_bytes(), config_before);
    assert_eq!(
        home.stored_metadata()
            .expect("updated native save")
            .generation,
        2
    );
    assert_no_secret(&second.stdout);
    assert_no_secret(&second.stderr);
}

#[test]
fn configured_device_flow_treats_403_and_404_as_pending_before_exchange() {
    let home = FixtureHome::new(Some(ALIAS), "codex-device");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    transport.push_raw(403, r#"{"error":"pending-forbidden"}"#);
    transport.push_raw(404, r#"{"error":"pending-not-found"}"#);
    transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}","public":"poll-ok"}}"#),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{ACCESS_SECRET}","token_type":"Bearer","expires_in":3600,"public":"exchange-ok"}}"#
        ),
    );
    let (sender, receiver) = device_instruction_channel();
    let result = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        Some(sender),
        command("auth.login", Some(ALIAS)),
    )
    .expect("scripted pending login");
    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(transport.take_sent().len(), 5);
    assert_eq!(
        receiver.try_recv().expect("device instruction").user_code,
        USER_CODE
    );
    assert_eq!(
        home.stored_metadata()
            .expect("pending flow save")
            .generation,
        1
    );
    assert_no_secret(&format!("{result:?}"));
}

#[test]
fn unavailable_and_closed_instruction_queues_stop_after_start_without_saving() {
    let home = FixtureHome::new(None, "codex-device");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    let unavailable = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        None,
        command("auth.login", Some("openai-codex")),
    )
    .expect("unavailable UI result");
    assert_failure(&unavailable, "ui_unavailable");
    assert_eq!(transport.take_sent().len(), 1);
    assert!(!home.auth_exists());

    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    let (sender, receiver) = device_instruction_channel();
    drop(receiver);
    let closed = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        Some(sender),
        command("auth.login", Some("openai-codex")),
    )
    .expect("closed UI result");
    assert_failure(&closed, "ui_sink_closed");
    assert_eq!(transport.take_sent().len(), 1);
    assert!(!home.auth_exists());
    assert_no_secret(&format!("{unavailable:?}{closed:?}"));
}

#[test]
fn credential_override_unknown_provider_and_non_device_flow_fail_before_oauth() {
    let home = FixtureHome::new(None, "codex-device");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let invalid = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        None,
        command_with_credential("auth.login", Some("openai-codex"), Some("untrusted-id")),
    )
    .expect("invalid command result");
    assert_failure(&invalid, "invalid_command");
    assert!(transport.take_sent().is_empty());

    let unknown = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        None,
        command("auth.login", Some("untrusted-provider-marker")),
    )
    .expect("unknown provider result");
    assert_failure(&unknown, "provider_not_found");
    assert!(!text(field(&unknown, "status")).contains("untrusted-provider-marker"));
    assert!(transport.take_sent().is_empty());

    let browser_home = FixtureHome::new(None, "browser");
    let unsupported = run_value(
        &login_runner(),
        &browser_home,
        transport.clone(),
        None,
        command("auth.login", Some("openai-codex")),
    )
    .expect("unsupported flow result");
    assert_failure(&unsupported, "login_flow_unsupported");
    assert!(transport.take_sent().is_empty());
    assert!(!home.auth_exists());
    assert!(!browser_home.auth_exists());
}
