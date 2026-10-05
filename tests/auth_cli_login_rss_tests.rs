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
use rustscript_vm::Value;
use serde_yaml::Value as YamlValue;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const ENTRY_PATH: &str = "rss/auth/login.rss";
const CODEX_PATH: &str = "rss/auth/codex_device.rss";
const TYPES_PATH: &str = "rss/auth/types.rss";
const CREDENTIAL_ID: &str = "fixture-codex";
const UNRELATED_CREDENTIAL_ID: &str = "unrelated-configured";
const ORPHAN_CREDENTIAL_ID: &str = "orphan-existing";
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

    fn add_provider(&self, alias: &str, auth: Option<YamlValue>) {
        let mut config: YamlValue =
            serde_yaml::from_slice(&self.config_bytes()).expect("parse config fixture");
        let selected_alias = config["model"]["provider"]
            .as_str()
            .expect("selected fixture provider")
            .to_owned();
        let mut provider = config["providers"][selected_alias.as_str()].clone();
        let fields = provider.as_mapping_mut().expect("provider fixture mapping");
        let auth_key = YamlValue::String("auth".to_owned());
        match auth {
            Some(value) => {
                fields.insert(auth_key, value);
            }
            None => {
                fields.remove(&auth_key);
            }
        }
        config["providers"][alias] = provider;
        self.write_config_document(&config);
    }

    fn write_config_document(&self, config: &YamlValue) {
        fs::write(
            self.0.join("config.yaml"),
            serde_yaml::to_string(config).expect("serialize config fixture"),
        )
        .expect("write config fixture");
    }

    fn write_auth_document(&self, auth: &YamlValue) {
        fs::write(
            self.0.join("auth.yaml"),
            serde_yaml::to_string(auth).expect("serialize auth fixture"),
        )
        .expect("write auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.0.join("auth.yaml"), fs::Permissions::from_mode(0o600))
                .expect("secure auth fixture");
        }
    }

    fn auth_bytes(&self) -> Vec<u8> {
        fs::read(self.0.join("auth.yaml")).expect("read auth fixture bytes")
    }

    fn auth_lock_exists(&self) -> bool {
        self.0.join("auth.yaml.lock").exists()
    }

    fn auth_lock_bytes(&self) -> Vec<u8> {
        fs::read(self.0.join("auth.yaml.lock")).expect("read auth lock bytes")
    }

    fn entry_names(&self) -> Vec<String> {
        let mut names = fs::read_dir(&self.0)
            .expect("read fixture home entries")
            .map(|entry| {
                entry
                    .expect("fixture home entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 fixture entry name")
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn prepare_enrollment(&self) {
        AuthHost::new_for_enrollment(
            &self.0,
            RunCancellation::with_timeout(Duration::from_secs(30)),
            CREDENTIAL_ID,
        )
        .expect("prepare native enrollment fixture");
    }

    fn auth_exists(&self) -> bool {
        self.0.join("auth.yaml").exists()
    }

    fn stored_metadata(&self) -> Option<rustscript_agent::auth::store::AuthMetadata> {
        self.stored_metadata_for(CREDENTIAL_ID)
    }

    fn stored_metadata_for(
        &self,
        credential_id: &str,
    ) -> Option<rustscript_agent::auth::store::AuthMetadata> {
        AuthStore::from_home(&self.0)
            .ok()?
            .load_metadata(credential_id)
            .ok()
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn auth_fixture_document() -> YamlValue {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss/auth.yaml");
    serde_yaml::from_slice(&fs::read(path).expect("read native auth fixture"))
        .expect("parse native auth fixture")
}

fn auth_credential_value(auth_bytes: &[u8], credential_id: &str) -> Option<YamlValue> {
    let auth: YamlValue = serde_yaml::from_slice(auth_bytes).expect("parse stored auth bytes");
    auth["credentials"]
        .as_mapping()?
        .get(YamlValue::String(credential_id.to_owned()))
        .cloned()
}

fn assert_credential_preserved(
    home: &FixtureHome,
    credential_id: &str,
    credential_before: &YamlValue,
    metadata_before: &rustscript_agent::auth::store::AuthMetadata,
) {
    let credential_after = auth_credential_value(&home.auth_bytes(), credential_id)
        .expect("preserved credential remains in auth store");
    assert!(
        credential_after.eq(credential_before),
        "unrelated credential data changed"
    );
    let metadata_after = home
        .stored_metadata_for(credential_id)
        .expect("preserved credential metadata remains loadable");
    assert!(
        metadata_after.eq(metadata_before),
        "unrelated credential metadata changed"
    );
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
    let mut host = AuthHost::new_for_login(home, child)?;
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
        .expect("execute guest baseline with the configured-login host")
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

fn assert_fresh_home_unchanged(
    home: &FixtureHome,
    config_before: &[u8],
    entries_before: &[String],
) {
    assert!(!home.auth_exists(), "auth.yaml was created");
    assert!(!home.auth_lock_exists(), "auth lock was created");
    assert_eq!(home.config_bytes(), config_before, "config bytes changed");
    assert_eq!(home.entry_names(), entries_before, "home entries changed");
}

#[test]
fn pre_oauth_rejections_leave_fresh_home_without_auth_store_or_lock() {
    let runner = login_runner();
    let missing_provider = FixtureHome::new(None, "codex-device");
    let empty_provider = FixtureHome::new(None, "codex-device");
    let credential_override = FixtureHome::new(None, "codex-device");
    let unknown_provider = FixtureHome::new(None, "codex-device");
    let missing_auth = FixtureHome::new(None, "codex-device");
    missing_auth.add_provider("selected-no-auth", None);
    let null_auth = FixtureHome::new(None, "codex-device");
    null_auth.add_provider("selected-null-auth", Some(YamlValue::Null));
    let unsupported_flow = FixtureHome::new(None, "browser");

    let cases = [
        (
            &missing_provider,
            command("auth.login", None),
            "provider_required",
            0,
        ),
        (
            &empty_provider,
            command("auth.login", Some("")),
            "provider_required",
            0,
        ),
        (
            &credential_override,
            command_with_credential("auth.login", Some("openai-codex"), Some("untrusted-id")),
            "invalid_command",
            0,
        ),
        (
            &unknown_provider,
            command("auth.login", Some("untrusted-provider-marker")),
            "provider_not_found",
            1,
        ),
        (
            &missing_auth,
            command("auth.login", Some("selected-no-auth")),
            "credential_id_required",
            1,
        ),
        (
            &null_auth,
            command("auth.login", Some("selected-null-auth")),
            "credential_id_required",
            1,
        ),
        (
            &unsupported_flow,
            command("auth.login", Some("openai-codex")),
            "login_flow_unsupported",
            1,
        ),
    ];

    for (home, input, code, generation) in cases {
        let entries_before = home.entry_names();
        assert_eq!(entries_before, ["config.yaml"]);
        assert!(!home.auth_exists());
        assert!(!home.auth_lock_exists());
        let config_before = home.config_bytes();
        let transport = Arc::new(ScriptedHttpsTransport::new());

        let result = run_value(&runner, home, transport.clone(), None, input)
            .expect("pre-OAuth login rejection result");
        assert_failure(&result, code);
        assert_eq!(result_map_generation(&result), generation);
        assert!(transport.take_sent().is_empty(), "OAuth transport was used");
        assert_fresh_home_unchanged(home, &config_before, &entries_before);
        assert_no_secret(&format!("{result:?}"));
    }
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

#[test]
fn missing_and_null_selected_provider_auth_fail_without_store_mutation() {
    let runner = login_runner();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    for (alias, auth) in [
        ("selected-no-auth", None),
        ("selected-null-auth", Some(YamlValue::Null)),
    ] {
        let home = FixtureHome::new(None, "codex-device");
        home.add_provider(alias, auth);
        // Native enrollment setup owns creation of its required lock file.
        // Snapshot after setup so this checks the RSS path for file mutation.
        home.prepare_enrollment();
        let config_before = home.config_bytes();
        let entries_before = home.entry_names();
        let lock_before = home.auth_lock_bytes();
        assert!(!home.auth_exists());

        let result = run_value(
            &runner,
            &home,
            transport.clone(),
            None,
            command("auth.login", Some(alias)),
        )
        .expect("missing selected auth result");
        assert_failure(&result, "credential_id_required");
        assert_eq!(
            result_map_generation(&result),
            1,
            "missing-auth errors report the policy snapshot generation"
        );
        assert!(transport.take_sent().is_empty());
        assert!(!home.auth_exists());
        assert!(home.auth_lock_exists());
        assert!(home.auth_lock_bytes() == lock_before, "auth lock changed");
        assert!(home.config_bytes() == config_before, "config bytes changed");
        assert_eq!(home.entry_names(), entries_before);
    }
}

#[test]
fn empty_selected_provider_auth_is_rejected_by_native_config_validation() {
    let alias = "selected-empty-auth";
    let home = FixtureHome::new(None, "codex-device");
    home.add_provider(alias, Some(YamlValue::String(String::new())));
    let config_before = home.config_bytes();
    let transport = Arc::new(ScriptedHttpsTransport::new());

    let native_error = match AuthHost::new_for_enrollment(
        &home.0,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        CREDENTIAL_ID,
    ) {
        Ok(_) => panic!("empty auth must fail native config validation"),
        Err(error) => error,
    };
    assert_eq!(native_error, "config_invalid");
    assert!(!native_error.contains(alias));
    assert!(!home.auth_exists());
    assert!(home.auth_lock_exists());
    let entries_before_run = home.entry_names();
    let lock_before_run = home.auth_lock_bytes();

    let runner_error = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        None,
        command("auth.login", Some(alias)),
    )
    .expect_err("native host setup rejects the invalid config before RSS");
    assert_eq!(runner_error, AuthEntryError::HostSetup);
    assert!(!runner_error.to_string().contains(alias));
    assert!(transport.take_sent().is_empty());
    assert!(!home.auth_exists());
    assert!(home.config_bytes() == config_before, "config bytes changed");
    assert!(
        home.auth_lock_bytes() == lock_before_run,
        "auth lock changed"
    );
    assert_eq!(home.entry_names(), entries_before_run);
}

fn result_map_generation(value: &Value) -> i64 {
    match field(value, "generation") {
        Value::Int(value) => *value,
        other => panic!("expected integer generation, got {other:?}"),
    }
}

#[test]
fn existing_credential_provider_mismatch_fails_before_transport_or_mutation() {
    let home = FixtureHome::new(Some(ALIAS), "codex-device");
    let mut auth = auth_fixture_document();
    auth["credentials"][CREDENTIAL_ID]["expires_at_ms"] =
        serde_yaml::to_value(START_MS + 3_600_000).expect("fixture expiry");
    auth["credentials"][CREDENTIAL_ID]["last_refresh_at_ms"] =
        serde_yaml::to_value(START_MS - 1_000).expect("fixture refresh time");
    home.write_auth_document(&auth);
    home.prepare_enrollment();
    let auth_before = home.auth_bytes();
    let config_before = home.config_bytes();
    let entries_before = home.entry_names();
    let lock_before = home.auth_lock_bytes();
    let transport = Arc::new(ScriptedHttpsTransport::new());

    let result = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        None,
        command("auth.login", Some(ALIAS)),
    )
    .expect("provider mismatch result");
    assert_failure(&result, "credential_provider_mismatch");
    assert_eq!(result_map_generation(&result), 4);
    assert!(transport.take_sent().is_empty());
    assert!(home.auth_bytes() == auth_before, "auth bytes changed");
    assert!(home.config_bytes() == config_before, "config bytes changed");
    assert_eq!(home.entry_names(), entries_before);
    assert!(home.auth_lock_bytes() == lock_before, "auth lock changed");
    assert_no_secret(&format!("{result:?}"));
}

#[test]
fn alias_device_flow_saves_native_credentials_and_renders_only_redacted_metadata() {
    let home = FixtureHome::new(Some(ALIAS), "codex-device");
    home.add_provider(
        "unrelated-anchor",
        Some(YamlValue::String(UNRELATED_CREDENTIAL_ID.to_owned())),
    );
    let mut auth = auth_fixture_document();
    let template = auth["credentials"][CREDENTIAL_ID].clone();
    let mut unrelated = template.clone();
    unrelated["account_id"] = YamlValue::String("acct_unrelated_synthetic".to_owned());
    let mut orphan = template;
    orphan["account_id"] = YamlValue::String("acct_orphan_synthetic".to_owned());
    let mut credentials = serde_yaml::Mapping::new();
    credentials.insert(
        YamlValue::String(UNRELATED_CREDENTIAL_ID.to_owned()),
        unrelated,
    );
    credentials.insert(YamlValue::String(ORPHAN_CREDENTIAL_ID.to_owned()), orphan);
    auth["credentials"] = YamlValue::Mapping(credentials);
    home.write_auth_document(&auth);
    home.prepare_enrollment();
    let config_before = home.config_bytes();
    let auth_before = home.auth_bytes();
    let unrelated_before = auth_credential_value(&auth_before, UNRELATED_CREDENTIAL_ID)
        .expect("configured unrelated credential fixture");
    let orphan_before = auth_credential_value(&auth_before, ORPHAN_CREDENTIAL_ID)
        .expect("orphan credential fixture");
    let unrelated_metadata_before = home
        .stored_metadata_for(UNRELATED_CREDENTIAL_ID)
        .expect("configured unrelated metadata fixture");
    let orphan_metadata_before = home
        .stored_metadata_for(ORPHAN_CREDENTIAL_ID)
        .expect("orphan metadata fixture");
    assert!(auth_credential_value(&auth_before, CREDENTIAL_ID).is_none());
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
    assert_no_secret(&format!("{instruction:?}"));
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
    assert_credential_preserved(
        &home,
        UNRELATED_CREDENTIAL_ID,
        &unrelated_before,
        &unrelated_metadata_before,
    );
    assert_credential_preserved(
        &home,
        ORPHAN_CREDENTIAL_ID,
        &orphan_before,
        &orphan_metadata_before,
    );

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
    let second_instruction = receiver.try_recv().expect("second instruction");
    assert_eq!(second_instruction.user_code, USER_CODE);
    assert_no_secret(&format!("{second_instruction:?}"));
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
    assert_credential_preserved(
        &home,
        UNRELATED_CREDENTIAL_ID,
        &unrelated_before,
        &unrelated_metadata_before,
    );
    assert_credential_preserved(
        &home,
        ORPHAN_CREDENTIAL_ID,
        &orphan_before,
        &orphan_metadata_before,
    );
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
fn fresh_ui_unavailable_failure_does_not_create_auth_or_lock() {
    let home = FixtureHome::new(None, "codex-device");
    let config_before = home.config_bytes();
    let entries_before = home.entry_names();
    assert_eq!(entries_before, ["config.yaml"]);
    assert!(!home.auth_exists());
    assert!(!home.auth_lock_exists());

    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    let result = run_value(
        &login_runner(),
        &home,
        transport.clone(),
        None,
        command("auth.login", Some("openai-codex")),
    )
    .expect("unavailable UI result on fresh home");

    assert_failure(&result, "ui_unavailable");
    assert_eq!(transport.take_sent().len(), 1, "start only");
    assert_fresh_home_unchanged(&home, &config_before, &entries_before);
    assert_no_secret(&format!("{result:?}"));
}

#[test]
fn full_public_instruction_channel_stops_at_start_without_store_mutation() {
    let home = FixtureHome::new(None, "codex-device");
    home.prepare_enrollment();
    let runner = login_runner();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let (sender, receiver) = device_instruction_channel();

    for generation in 1..=4 {
        queue_success(&transport);
        let output = run_cli(
            &runner,
            &home,
            transport.clone(),
            Some(sender.clone()),
            command("auth.login", Some("openai-codex")),
        );
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        assert_eq!(cli_row(&output)["generation"], generation);
        assert_eq!(transport.take_sent().len(), 3, "start, poll, exchange");
        assert_eq!(
            home.stored_metadata()
                .expect("successful public-channel login save")
                .generation,
            generation as u64
        );
    }

    let saved_home_auth = home.auth_bytes();
    let saved_home_config = home.config_bytes();
    let saved_home_entries = home.entry_names();
    let saved_home_lock = home.auth_lock_bytes();

    let fresh_home = FixtureHome::new(None, "codex-device");
    fresh_home.prepare_enrollment();
    let fresh_config = fresh_home.config_bytes();
    let fresh_entries = fresh_home.entry_names();
    let fresh_lock = fresh_home.auth_lock_bytes();
    assert!(!fresh_home.auth_exists());
    let fifth_transport = Arc::new(ScriptedHttpsTransport::new());
    fifth_transport.push_raw(
        200,
        &format!(
            r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"{USER_CODE}","expires_in":900,"interval":"0"}}"#
        ),
    );
    let full = run_value(
        &runner,
        &fresh_home,
        fifth_transport.clone(),
        Some(sender),
        command("auth.login", Some("openai-codex")),
    )
    .expect("full channel result");
    assert_failure(&full, "ui_sink_full");
    assert_eq!(fifth_transport.take_sent().len(), 1, "start only");
    assert!(!fresh_home.auth_exists());
    assert!(
        fresh_home.config_bytes() == fresh_config,
        "fresh config changed"
    );
    assert_eq!(fresh_home.entry_names(), fresh_entries);
    assert!(
        fresh_home.auth_lock_bytes() == fresh_lock,
        "fresh auth lock changed"
    );
    assert!(
        home.auth_bytes() == saved_home_auth,
        "previous auth bytes changed"
    );
    assert!(
        home.config_bytes() == saved_home_config,
        "previous config bytes changed"
    );
    assert_eq!(home.entry_names(), saved_home_entries);
    assert!(
        home.auth_lock_bytes() == saved_home_lock,
        "previous auth lock changed"
    );
    assert_eq!(
        home.stored_metadata()
            .expect("previous saved credential remains")
            .generation,
        4
    );
    assert_no_secret(&format!("{full:?}"));

    for _ in 0..4 {
        let instruction: PublicDeviceInstruction = receiver
            .try_recv()
            .expect("one of four public queued instructions");
        assert_no_secret(&format!("{instruction:?}"));
    }
    assert!(
        receiver.try_recv().is_err(),
        "the failed fifth run queued nothing"
    );
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
