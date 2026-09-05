use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::auth::config::{AuthConfig, AuthConfigError, MAX_AUTH_YAML_BYTES};
use rustscript_agent::config_file::{
    AgentPaths, ConfigFile, ConfigFileError, MAX_CONFIG_YAML_BYTES, MAX_YAML_DEPTH, MAX_YAML_NODES,
    load_config,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(test_name: &str) -> Self {
        let base = std::env::var_os("TEST_TMPDIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after UNIX epoch")
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = base.join(format!(
            "rustscript-agent-config-{test_name}-{}-{nonce}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create config test root");
        Self { path: root }
    }
}

impl AsRef<Path> for TempRoot {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<std::ffi::OsStr> for TempRoot {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}

impl Deref for TempRoot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn temp_root(test_name: &str) -> TempRoot {
    TempRoot::new(test_name)
}

fn write_fixture(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write YAML fixture");
}

fn valid_config(auth: &str) -> String {
    format!(
        "version: 1\nagent:\n  source: bundled:coding\n  max_turns: 64\n  max_tool_calls: 128\n  max_tool_output_bytes: 1048576\nmodel:\n  provider: openai-codex\n  model: gpt-5-codex\nproviders:\n  openai-codex:\n    protocol: codex-responses\n    base_url: https://chatgpt.com/backend-api/codex\n    auth: {auth}\n    oauth:\n      flow: codex-device\n      issuer: https://auth.openai.com\n      client_id: public-client-id\n      device_user_code_path: /api/accounts/deviceauth/usercode\n      device_poll_path: /api/accounts/deviceauth/token\n      authorization_path: /codex/device\n      token_endpoint: https://auth.openai.com/oauth/token\n      redirect_uri: https://auth.openai.com/deviceauth/callback\n      refresh_skew_seconds: 120\nworkspaces:\n  allowed_roots:\n    - /tmp/rustscript-agent-workspace\n  default: /tmp/rustscript-agent-workspace\napprovals:\n  read: allow\n  write: ask\n  process: ask\ncompaction:\n  enabled: true\n  max_context_messages: 120\n  retained_tail: 32\n"
    )
}

fn valid_auth(credential_id: &str) -> String {
    format!(
        "version: 1\ncredentials:\n  {credential_id}:\n    provider: openai-codex\n    kind: oauth\n    source: codex-device\n    token_type: Bearer\n    access_token: SYNTHETIC_ACCESS_TOKEN\n    refresh_token: SYNTHETIC_REFRESH_TOKEN\n    expires_at_ms: 1788440000000\n    scopes: []\n    account_id: acct_synthetic\n    generation: 4\n    status: active\n    last_refresh_at_ms: 1788436400000\n"
    )
}

#[test]
fn missing_config_and_auth_files_are_typed_errors() {
    let root = temp_root("missing");
    let paths = AgentPaths::from_home(&root).expect("absolute home should resolve");

    let config_error = load_config(&paths.config).expect_err("missing config must fail");
    assert!(matches!(config_error, ConfigFileError::MissingFile { .. }));

    let auth_error = AuthConfig::load(&paths.auth).expect_err("missing auth must fail");
    assert!(matches!(auth_error, AuthConfigError::MissingFile { .. }));
}

#[test]
fn home_override_controls_all_persistent_paths() {
    let root = temp_root("home-override");
    let previous = std::env::var_os("RUSTSCRIPT_AGENT_HOME");
    unsafe { std::env::set_var("RUSTSCRIPT_AGENT_HOME", &root) };
    let paths = AgentPaths::resolve().expect("home override should resolve");
    match previous {
        Some(value) => unsafe { std::env::set_var("RUSTSCRIPT_AGENT_HOME", value) },
        None => unsafe { std::env::remove_var("RUSTSCRIPT_AGENT_HOME") },
    }

    assert_eq!(paths.home, root.path);
    assert_eq!(paths.config, root.join("config.yaml"));
    assert_eq!(paths.auth, root.join("auth.yaml"));
    assert_eq!(paths.auth_lock, root.join("auth.yaml.lock"));
    assert_eq!(paths.state, root.join("state.db"));
}

#[test]
fn config_rejects_secret_keys_at_nested_paths() {
    for key in [
        "access_token",
        "refresh_token",
        "api_key",
        "authorization",
        "cookie",
    ] {
        let source = valid_config("codex-primary").replace(
            "      refresh_skew_seconds: 120",
            &format!("      {key}: SYNTHETIC_SECRET\n      refresh_skew_seconds: 120"),
        );
        let root = temp_root(key);
        let path = root.join("config.yaml");
        write_fixture(&path, &source);
        let error = load_config(&path).expect_err("secret-bearing config key must fail");
        assert!(
            matches!(error, ConfigFileError::SecretKey { .. }),
            "{key} should be classified as a secret key: {error:?}"
        );
        assert!(error.to_string().contains("providers.openai-codex.oauth"));
    }

    let nested_auth = valid_config("codex-primary").replace(
        "    auth: codex-primary",
        "    auth:\n      access_token: SYNTHETIC_SECRET",
    );
    let root = temp_root("nested-auth-secret");
    let path = root.join("config.yaml");
    write_fixture(&path, &nested_auth);
    let error = load_config(&path).expect_err("nested auth secret must fail");
    assert!(matches!(error, ConfigFileError::SecretKey { .. }));
    assert!(
        error
            .to_string()
            .contains("providers.openai-codex.auth.access_token")
    );
}

#[test]
fn auth_rejects_behavior_keys_and_unknown_keys() {
    let root = temp_root("auth-separation");
    let path = root.join("auth.yaml");
    write_fixture(
        &path,
        &valid_auth("codex-primary").replace(
            "    provider: openai-codex",
            "    provider: openai-codex\n    model: gpt-5-codex",
        ),
    );
    let error = AuthConfig::load(&path).expect_err("model must not enter auth.yaml");
    assert!(matches!(error, AuthConfigError::BehaviorKey { .. }));
    assert!(
        error
            .to_string()
            .contains("credentials.codex-primary.model")
    );

    write_fixture(
        &path,
        &valid_auth("codex-primary").replace(
            "    provider: openai-codex",
            "    provider: openai-codex\n    unexpected: value",
        ),
    );
    let error = AuthConfig::load(&path).expect_err("unknown auth key must fail");
    assert!(matches!(error, AuthConfigError::UnknownKey { .. }));
}

#[test]
fn invalid_auth_reference_is_rejected_when_loading_a_pair() {
    let root = temp_root("auth-reference");
    let paths = AgentPaths::from_home(&root).expect("absolute home should resolve");
    write_fixture(&paths.config, &valid_config("missing-credential"));
    write_fixture(&paths.auth, &valid_auth("codex-primary"));

    let error = ConfigFile::load_pair(&paths).expect_err("missing auth reference must fail");
    assert!(matches!(
        error,
        ConfigFileError::InvalidAuthReference { .. }
    ));
    assert!(error.to_string().contains("missing-credential"));
}

#[test]
fn provider_endpoints_require_https_except_loopback_callback() {
    let root = temp_root("https-policy");
    let path = root.join("config.yaml");

    write_fixture(
        &path,
        &valid_config("codex-primary").replace(
            "base_url: https://chatgpt.com/backend-api/codex",
            "base_url: http://chatgpt.com/backend-api/codex",
        ),
    );
    let error = load_config(&path).expect_err("remote provider HTTP must fail");
    assert!(matches!(error, ConfigFileError::HttpsRequired { .. }));

    write_fixture(
        &path,
        &valid_config("codex-primary").replace(
            "redirect_uri: https://auth.openai.com/deviceauth/callback",
            "redirect_uri: http://127.0.0.1:43127/callback",
        ),
    );
    load_config(&path).expect("loopback callback HTTP is allowed");

    write_fixture(
        &path,
        &valid_config("codex-primary").replace(
            "redirect_uri: https://auth.openai.com/deviceauth/callback",
            "redirect_uri: http://auth.openai.com/deviceauth/callback",
        ),
    );
    let error = load_config(&path).expect_err("remote callback HTTP must fail");
    assert!(matches!(error, ConfigFileError::HttpsRequired { .. }));
}

#[test]
fn yaml_reading_is_bounded_before_parse_and_nested_documents_are_rejected() {
    let root = temp_root("bounds");
    let config_path = root.join("config.yaml");
    let oversized = "x".repeat(MAX_CONFIG_YAML_BYTES + 1);
    write_fixture(&config_path, &oversized);
    let error = load_config(&config_path).expect_err("oversized config must fail before parse");
    assert!(matches!(error, ConfigFileError::FileTooLarge { .. }));

    let mut nested = String::from("version: 1\nagent:\n");
    for level in 0..(MAX_YAML_DEPTH + 2) {
        nested.push_str(&"  ".repeat(level + 1));
        nested.push_str(&format!("level{level}:\n"));
    }
    nested.push_str(&"  ".repeat(MAX_YAML_DEPTH + 3));
    nested.push_str("value: true\n");
    write_fixture(&config_path, &nested);
    let error = load_config(&config_path).expect_err("overly nested YAML must fail");
    assert!(matches!(error, ConfigFileError::YamlTooDeep { .. }));

    let auth_path = root.join("auth.yaml");
    let oversized_auth = "x".repeat(MAX_AUTH_YAML_BYTES + 1);
    write_fixture(&auth_path, &oversized_auth);
    let error = AuthConfig::load(&auth_path).expect_err("oversized auth must fail before parse");
    assert!(matches!(error, AuthConfigError::FileTooLarge { .. }));
}

#[test]
fn malformed_yaml_is_typed_and_auth_debug_redacts_tokens() {
    let root = temp_root("malformed-redacted");
    let config_path = root.join("config.yaml");
    write_fixture(&config_path, "version: [1\n");
    let error = load_config(&config_path).expect_err("malformed YAML must fail");
    assert!(matches!(error, ConfigFileError::MalformedYaml { .. }));

    let auth = AuthConfig::from_str(&valid_auth("codex-primary")).expect("fixture auth");
    let debug = format!("{auth:?}");
    assert!(!debug.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!debug.contains("SYNTHETIC_REFRESH_TOKEN"));
    assert!(debug.contains("REDACTED"));

    let inline_config = "x".repeat(MAX_CONFIG_YAML_BYTES + 1);
    let error = ConfigFile::from_str(&inline_config).expect_err("inline config must be bounded");
    assert!(matches!(error, ConfigFileError::FileTooLarge { .. }));

    let inline_auth = "x".repeat(MAX_AUTH_YAML_BYTES + 1);
    let error = AuthConfig::from_str(&inline_auth).expect_err("inline auth must be bounded");
    assert!(matches!(error, AuthConfigError::FileTooLarge { .. }));
}

#[test]
fn config_rejects_duplicate_and_unknown_keys_at_each_schema_level() {
    let cases = [
        (
            "root-unknown",
            valid_config("codex-primary")
                .replace("version: 1\n", "version: 1\nunexpected: value\n"),
        ),
        (
            "provider-unknown",
            valid_config("codex-primary").replace(
                "    protocol: codex-responses",
                "    protocol: codex-responses\n    unexpected: value",
            ),
        ),
        (
            "oauth-unknown",
            valid_config("codex-primary").replace(
                "      flow: codex-device",
                "      flow: codex-device\n      unexpected: value",
            ),
        ),
        (
            "root-duplicate",
            valid_config("codex-primary").replace("version: 1\n", "version: 1\nversion: 1\n"),
        ),
        (
            "provider-duplicate",
            valid_config("codex-primary").replace(
                "    protocol: codex-responses",
                "    protocol: codex-responses\n    protocol: codex-responses",
            ),
        ),
        (
            "oauth-duplicate",
            valid_config("codex-primary").replace(
                "      flow: codex-device",
                "      flow: codex-device\n      flow: codex-device",
            ),
        ),
    ];

    for (name, source) in cases {
        let root = temp_root(name);
        let path = root.join("config.yaml");
        write_fixture(&path, &source);
        let error = load_config(&path).expect_err("strict config maps must reject the fixture");
        assert!(!error.to_string().contains("SYNTHETIC_"));
    }

    let auth_cases = [
        (
            "auth-root-unknown",
            valid_auth("codex-primary").replace("version: 1\n", "version: 1\nunexpected: value\n"),
        ),
        (
            "auth-entry-unknown",
            valid_auth("codex-primary").replace(
                "    provider: openai-codex",
                "    provider: openai-codex\n    unexpected: value",
            ),
        ),
        (
            "auth-entry-duplicate",
            valid_auth("codex-primary").replace(
                "    provider: openai-codex",
                "    provider: openai-codex\n    provider: openai-codex",
            ),
        ),
    ];

    for (name, source) in auth_cases {
        let root = temp_root(name);
        let path = root.join("auth.yaml");
        write_fixture(&path, &source);
        let error = AuthConfig::load(&path).expect_err("strict auth maps must reject the fixture");
        assert!(!error.to_string().contains("SYNTHETIC_"));
    }
}

#[test]
fn openai_codex_authority_and_port_are_allowlisted_without_rejecting_custom_https() {
    let cases = [
        (
            "base-host",
            "base_url: https://chatgpt.com/backend-api/codex",
            "base_url: https://api.openai.com/backend-api/codex",
        ),
        (
            "base-port",
            "base_url: https://chatgpt.com/backend-api/codex",
            "base_url: https://chatgpt.com:8443/backend-api/codex",
        ),
        (
            "issuer-host",
            "issuer: https://auth.openai.com",
            "issuer: https://accounts.openai.com",
        ),
        (
            "issuer-port",
            "issuer: https://auth.openai.com",
            "issuer: https://auth.openai.com:8443",
        ),
        (
            "token-host",
            "token_endpoint: https://auth.openai.com/oauth/token",
            "token_endpoint: https://evil.example/oauth/token",
        ),
        (
            "token-port",
            "token_endpoint: https://auth.openai.com/oauth/token",
            "token_endpoint: https://auth.openai.com:8443/oauth/token",
        ),
        (
            "redirect-host",
            "redirect_uri: https://auth.openai.com/deviceauth/callback",
            "redirect_uri: https://evil.example/deviceauth/callback",
        ),
        (
            "redirect-port",
            "redirect_uri: https://auth.openai.com/deviceauth/callback",
            "redirect_uri: https://auth.openai.com:8443/deviceauth/callback",
        ),
    ];

    for (name, needle, replacement) in cases {
        let root = temp_root(name);
        let path = root.join("config.yaml");
        write_fixture(
            &path,
            &valid_config("codex-primary").replace(needle, replacement),
        );
        let error = load_config(&path).expect_err("untrusted provider authority must fail");
        assert!(
            error.to_string().contains("provider authority"),
            "authority rejection should be explicit: {error}"
        );
    }

    let root = temp_root("custom-provider");
    let path = root.join("config.yaml");
    let custom = valid_config("custom-primary")
        .replace("openai-codex", "custom-provider")
        .replace(
            "https://chatgpt.com/backend-api/codex",
            "https://llm.example:8443/api",
        )
        .replace("https://auth.openai.com", "https://auth.example:9443");
    write_fixture(&path, &custom);
    load_config(&path).expect("explicit custom provider authorities must remain configurable");
}

#[test]
fn oauth_endpoint_paths_are_strict_relative_paths() {
    let cases = [
        "https://evil.example/path",
        "//evil.example/path",
        "/../evil",
        "/api/../evil",
        "/api/%2e%2e/evil",
        "/\\evil.example/path",
        "/api?next=https://evil.example",
        "/api#fragment",
        "/%",
    ];
    let fields = [
        ("device_user_code_path", "/api/accounts/deviceauth/usercode"),
        ("device_poll_path", "/api/accounts/deviceauth/token"),
        ("authorization_path", "/codex/device"),
    ];

    for (field, valid_value) in fields {
        for (index, endpoint) in cases.iter().copied().enumerate() {
            let root = temp_root(&format!("{field}-{index}"));
            let path = root.join("config.yaml");
            let needle = format!("      {field}: {valid_value}");
            let replacement = format!("      {field}: {endpoint}");
            let source = valid_config("codex-primary").replace(&needle, &replacement);
            write_fixture(&path, &source);
            let error = load_config(&path).expect_err("endpoint authority escape must fail");
            assert!(
                error.to_string().contains("relative endpoint"),
                "endpoint rejection should identify the relative-path policy: {error}"
            );
        }
    }
}

#[test]
fn loopback_http_callback_requires_a_listener_port_and_exact_loopback_host() {
    let rejected = [
        "http://localhost/callback",
        "http://localhost:0/callback",
        "http://0.0.0.0:43127/callback",
        "http://[::]:43127/callback",
        "http://127.0.0.1:43127/callback?state=synthetic",
        "http://user:password@127.0.0.1:43127/callback",
    ];

    for (index, callback) in rejected.into_iter().enumerate() {
        let root = temp_root(&format!("loopback-rejected-{index}"));
        let path = root.join("config.yaml");
        let source = valid_config("codex-primary").replace(
            "redirect_uri: https://auth.openai.com/deviceauth/callback",
            &format!("redirect_uri: {callback}"),
        );
        write_fixture(&path, &source);
        load_config(&path).expect_err("unsafe loopback callback must fail");
    }

    let root = temp_root("loopback-accepted");
    let path = root.join("config.yaml");
    let source = valid_config("codex-primary").replace(
        "redirect_uri: https://auth.openai.com/deviceauth/callback",
        "redirect_uri: http://127.0.0.1:43127/callback",
    );
    write_fixture(&path, &source);
    load_config(&path).expect("a nonzero explicit loopback listener port is allowed");
}

#[test]
fn yaml_bounds_cover_broad_alias_tag_and_multiple_document_inputs() {
    let broad = format!(
        "[{}]",
        std::iter::repeat_n("x", MAX_YAML_NODES)
            .collect::<Vec<_>>()
            .join(",")
    );
    let root = temp_root("broad");
    let path = root.join("config.yaml");
    write_fixture(&path, &broad);
    let error = load_config(&path).expect_err("broad small-byte YAML must exceed the node budget");
    assert!(error.to_string().contains("node limit"));

    let items = std::iter::repeat_n("x", MAX_YAML_NODES / 2)
        .collect::<Vec<_>>()
        .join(",");
    let aliased = format!("base: &base [{items}]\ncopy: *base\n");
    let root = temp_root("alias-amplification");
    let path = root.join("config.yaml");
    write_fixture(&path, &aliased);
    let error = load_config(&path).expect_err("alias expansion must count against the node budget");
    assert!(error.to_string().contains("node limit"));

    let tagged = format!("!tag {broad}\n");
    let root = temp_root("tagged");
    let path = root.join("config.yaml");
    write_fixture(&path, &tagged);
    let error = load_config(&path).expect_err("tagged nested values must remain bounded");
    assert!(
        error.to_string().contains("node limit"),
        "tagged bound error: {error:?}"
    );

    let root = temp_root("multiple-documents");
    let path = root.join("config.yaml");
    write_fixture(&path, "version: 1\n---\nversion: 1\n");
    let error = load_config(&path).expect_err("multiple YAML documents must fail closed");
    assert!(error.to_string().contains("multiple YAML documents"));
}

#[test]
fn malformed_yaml_inputs_return_errors_without_panicking() {
    let root = temp_root("malformed-no-panic");
    let path = root.join("config.yaml");
    for (index, source) in [":\n", "[\n", "{\n", "&anchor *anchor\n", "[,]\n", "!!\n"]
        .into_iter()
        .enumerate()
    {
        write_fixture(&path, source);
        let result = std::panic::catch_unwind(|| load_config(&path));
        assert!(result.is_ok(), "malformed fixture {index} panicked");
        assert!(result.unwrap_or_else(|_| unreachable!()).is_err());
    }
}

#[test]
fn auth_yaml_uses_the_same_preparse_budget_and_document_fence() {
    let items = std::iter::repeat_n("x", MAX_YAML_NODES)
        .collect::<Vec<_>>()
        .join(",");
    let tagged = format!("!tag [{items}]\n");
    let error = AuthConfig::from_str(&tagged).expect_err("tagged auth input must remain bounded");
    assert!(matches!(error, AuthConfigError::YamlTooComplex { .. }));

    let error = AuthConfig::from_str("version: 1\n---\nversion: 1\n")
        .expect_err("multiple auth documents must fail closed");
    assert!(matches!(error, AuthConfigError::MultipleDocuments { .. }));
}

#[test]
fn parse_errors_never_echo_token_shaped_scalar_values() {
    let root = temp_root("config-error-redaction");
    let path = root.join("config.yaml");
    let source = valid_config("codex-primary")
        .replace("  max_turns: 64", "  max_turns: SYNTHETIC_ACCESS_TOKEN");
    write_fixture(&path, &source);
    let error = load_config(&path).expect_err("wrongly typed config value must fail");
    assert!(!error.to_string().contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!format!("{error:?}").contains("SYNTHETIC_ACCESS_TOKEN"));

    let auth_path = root.join("auth.yaml");
    let source = valid_auth("codex-primary").replace(
        "    expires_at_ms: 1788440000000",
        "    expires_at_ms: SYNTHETIC_REFRESH_TOKEN",
    );
    write_fixture(&auth_path, &source);
    let error = AuthConfig::load(&auth_path).expect_err("wrongly typed auth value must fail");
    assert!(!error.to_string().contains("SYNTHETIC_REFRESH_TOKEN"));
}

#[test]
fn invalid_home_inputs_fail_closed() {
    for home in [
        Path::new(""),
        Path::new("relative"),
        Path::new("/tmp/../escape"),
    ] {
        assert!(
            AgentPaths::from_home(home).is_err(),
            "home must be rejected: {home:?}"
        );
    }

    let previous = std::env::var_os("RUSTSCRIPT_AGENT_HOME");
    unsafe { std::env::set_var("RUSTSCRIPT_AGENT_HOME", "") };
    assert!(AgentPaths::resolve().is_err());
    match previous {
        Some(value) => unsafe { std::env::set_var("RUSTSCRIPT_AGENT_HOME", value) },
        None => unsafe { std::env::remove_var("RUSTSCRIPT_AGENT_HOME") },
    }
}
