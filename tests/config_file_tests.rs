use std::fs;
use std::path::{Path, PathBuf};

use rustscript_agent::auth::config::{AuthConfig, AuthConfigError, MAX_AUTH_YAML_BYTES};
use rustscript_agent::config_file::{
    AgentPaths, ConfigFile, ConfigFileError, MAX_CONFIG_YAML_BYTES, MAX_YAML_DEPTH, load_config,
};

const TEST_TEMP_ROOT: &str =
    "/mnt/TEMP/workspace/rustscript-agent/tmp/prod-agent-task-1-config-auth-luna-5e7e2edd";

fn temp_root(test_name: &str) -> PathBuf {
    let root = PathBuf::from(TEST_TEMP_ROOT).join(format!(
        "rustscript-agent-config-{test_name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create config test root");
    root
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

    assert_eq!(paths.home, root);
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
