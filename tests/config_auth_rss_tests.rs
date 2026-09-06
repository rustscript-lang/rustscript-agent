use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustscript_agent::config::{PolicyIntent, check_policy, load_snapshot};
use rustscript_agent::config_file::ConfigFileError;
use rustscript_agent::{ConfigFixtureHost, agent_host_catalog, config_fixture_catalog};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const ACCESS_TOKEN: &str = "SYNTHETIC_ACCESS_TOKEN";
const REFRESH_TOKEN: &str = "SYNTHETIC_REFRESH_TOKEN";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss")
}

fn temp_home(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    let root = base
        .join("config-auth-rss")
        .join(format!("{label}-{nanos}-{sequence}"));
    fs::create_dir_all(&root).expect("temp home");
    root
}

fn copy_fixture_home(label: &str, config_name: &str, auth_name: &str) -> PathBuf {
    let home = temp_home(label);
    fs::copy(fixture_dir().join(config_name), home.join("config.yaml")).expect("copy config");
    fs::copy(fixture_dir().join(auth_name), home.join("auth.yaml")).expect("copy auth");
    home
}

fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(values.iter().map(vm_value_to_json).collect()),
        Value::Map(entries) => {
            let mut object = serde_json::Map::new();
            for (key, value) in entries.iter() {
                if let Value::String(key) = key {
                    object.insert(key.to_string(), vm_value_to_json(value));
                }
            }
            JsonValue::Object(object)
        }
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn collect_strings(value: &JsonValue, out: &mut Vec<String>) {
    match value {
        JsonValue::Null => {}
        JsonValue::Bool(_) | JsonValue::Number(_) => {}
        JsonValue::String(text) => out.push(text.clone()),
        JsonValue::Array(values) => {
            for item in values {
                collect_strings(item, out);
            }
        }
        JsonValue::Object(entries) => {
            for (key, item) in entries {
                out.push(key.clone());
                collect_strings(item, out);
            }
        }
    }
}

fn assert_no_raw_secrets(value: &JsonValue) {
    let rendered = value.to_string();
    assert!(
        !rendered.contains(ACCESS_TOKEN),
        "raw access token leaked: {rendered}"
    );
    assert!(
        !rendered.contains(REFRESH_TOKEN),
        "raw refresh token leaked: {rendered}"
    );
    let mut tokens = Vec::new();
    collect_strings(value, &mut tokens);
    let forbidden: HashSet<&str> = ["access_token", "refresh_token", ACCESS_TOKEN, REFRESH_TOKEN]
        .into_iter()
        .collect();
    for token in tokens {
        assert!(
            !forbidden.contains(token.as_str()),
            "secret field or token leaked: {token}"
        );
    }
}

fn run_kind(home: &Path, kind: &str) -> (JsonValue, Vec<JsonValue>) {
    let complete = ConfigFixtureHost::bind(home)
        .run(kind)
        .unwrap_or_else(|error| panic!("RSS config/auth fixture should complete: {error}"));
    (vm_value_to_json(&complete), Vec::new())
}

fn assert_secret_free_run(complete: &JsonValue, events: &[JsonValue]) {
    assert_no_raw_secrets(complete);
    for event in events {
        assert_no_raw_secrets(event);
    }
}

fn assert_path_qualified_error(complete: &JsonValue, code: &str, path_needle: &str) {
    assert_eq!(complete["ok"], false);
    assert_eq!(complete["error"]["code"], code);
    let path = complete["error"]["path"].as_str().unwrap_or_default();
    assert!(
        path.contains(path_needle),
        "expected path-qualified error containing {path_needle:?}, got {path:?} from {complete}"
    );
    assert!(
        !path.contains("auth file is missing"),
        "error.path must be a path, not Display prose: {path}"
    );
}

#[test]
fn load_snapshot_exposes_opaque_credential_refs_without_raw_tokens() {
    let home = copy_fixture_home("snapshot", "config.yaml", "auth.yaml");
    let snapshot = load_snapshot(&home).expect("fixture snapshot should load");
    assert_eq!(snapshot.public_config.model.provider, "openai-codex");
    assert_eq!(snapshot.credential_refs, vec!["fixture-codex".to_string()]);
    assert_eq!(snapshot.policy_handle.class(), "OpaquePolicyHandle");
    assert!(snapshot.policy_generation >= 1);
    assert!(
        snapshot
            .policy_summary
            .providers
            .iter()
            .any(|name| name == "openai-codex")
    );
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains(ACCESS_TOKEN));
    assert!(!debug.contains(REFRESH_TOKEN));
    assert!(!debug.contains("oph_"));
}

#[test]
fn rust_load_snapshot_and_policy_check_match_rss_surface() {
    let home = copy_fixture_home("rust-check", "config.yaml", "auth.yaml");
    let snapshot = load_snapshot(&home).expect("load");
    let inspect = check_policy(
        &snapshot.policy_handle,
        &PolicyIntent {
            op: "inspect".into(),
            ..PolicyIntent::default()
        },
    )
    .expect("inspect");
    assert!(inspect.ok);

    let overreach = check_policy(
        &snapshot.policy_handle,
        &PolicyIntent {
            op: "add_workspace_root".into(),
            path: Some("/tmp/extra-root".into()),
            ..PolicyIntent::default()
        },
    )
    .expect_err("overreach");
    assert!(matches!(overreach, ConfigFileError::PolicyOverreach { .. }));

    let admitted = check_policy(
        &snapshot.policy_handle,
        &PolicyIntent {
            op: "add_workspace_root".into(),
            path: Some("/tmp/rustscript-agent-workspace".into()),
            ..PolicyIntent::default()
        },
    )
    .expect_err("frozen admitted root still cannot be added");
    assert!(matches!(admitted, ConfigFileError::PolicyOverreach { .. }));
}

#[test]
fn rss_config_auth_entry_loads_public_snapshot_without_secrets() {
    let home = copy_fixture_home("rss-load", "config.yaml", "auth.yaml");
    let (complete, events) = run_kind(&home, "load");
    assert_eq!(complete["ok"], true);
    assert_eq!(complete["policy_handle_class"], "OpaquePolicyHandle");
    assert_eq!(
        complete["public_config"]["model"]["provider"],
        "openai-codex"
    );
    assert!(complete.get("policy_handle").is_none());
    assert_secret_free_run(&complete, &events);
}

#[test]
fn rss_config_auth_entry_rejects_forged_and_copied_handles() {
    let home = copy_fixture_home("rss-forge", "config.yaml", "auth.yaml");
    let (forged, events) = run_kind(&home, "forge_handle");
    assert_eq!(forged["ok"], false);
    assert_eq!(forged["error"]["code"], "policy_handle_invalid");
    assert_secret_free_run(&forged, &events);

    let (copied, events) = run_kind(&home, "copy_handle");
    assert_eq!(copied["ok"], true);
    assert_secret_free_run(&copied, &events);
}

#[test]
fn rss_config_auth_entry_denies_stringify_serialize_and_path_supply() {
    let home = copy_fixture_home("rss-opaque", "config.yaml", "auth.yaml");
    let (stringify, events) = run_kind(&home, "stringify_handle");
    assert_eq!(stringify["ok"], true);
    assert_eq!(stringify["handle_type"], "callable");
    let rendered = stringify["rendered"].as_str().unwrap_or_default();
    assert!(
        !rendered.contains('{'),
        "stringify must not produce JSON: {rendered}"
    );
    assert!(
        !rendered.contains("OpaquePolicyHandle"),
        "stringify must not leak a reconstructible class token: {rendered}"
    );
    assert_eq!(stringify["reconstructed_ok"], false);
    assert_eq!(stringify["reconstructed_code"], "policy_handle_invalid");
    assert_secret_free_run(&stringify, &events);

    let (serialize, events) = run_kind(&home, "serialize_handle");
    assert_eq!(serialize["ok"], true);
    assert_eq!(serialize["handle_type"], "callable");
    assert_eq!(serialize["echoed"], "<callable>");
    assert_secret_free_run(&serialize, &events);

    let (supplied, events) = run_kind(&home, "supply_path");
    assert_path_qualified_error(&supplied, "home_invalid", home.to_string_lossy().as_ref());
    assert_secret_free_run(&supplied, &events);
}

#[test]
fn rss_config_auth_entry_rejects_overreach_and_expired_handles() {
    let home = copy_fixture_home("rss-policy", "config.yaml", "auth.yaml");
    let (overreach, events) = run_kind(&home, "expand_workspace");
    assert_eq!(overreach["ok"], false);
    assert_eq!(overreach["error"]["code"], "policy_overreach");
    assert_secret_free_run(&overreach, &events);

    let (expired, events) = run_kind(&home, "expire");
    assert_eq!(expired["ok"], false);
    assert_eq!(expired["error"]["code"], "policy_expired");
    assert_secret_free_run(&expired, &events);
}

#[test]
fn rss_config_auth_entry_reports_missing_file_path() {
    let home = temp_home("missing-file");
    let (complete, events) = run_kind(&home, "load");
    assert_path_qualified_error(&complete, "config_invalid", "config.yaml");
    assert!(
        complete["error"]["path"]
            .as_str()
            .unwrap_or_default()
            .contains(&home.join("config.yaml").display().to_string())
    );
    assert_secret_free_run(&complete, &events);
}

#[test]
fn rss_config_auth_entry_reports_invalid_home_path() {
    let home = PathBuf::from("relative-not-absolute");
    let (complete, events) = run_kind(&home, "load");
    assert_path_qualified_error(&complete, "home_invalid", "relative-not-absolute");
    assert_secret_free_run(&complete, &events);
}

#[test]
fn rss_config_auth_entry_reports_https_failure_path() {
    let home = copy_fixture_home("https-fail", "config.yaml", "auth.yaml");
    let config = fs::read_to_string(home.join("config.yaml")).expect("read config");
    fs::write(
        home.join("config.yaml"),
        config.replace(
            "https://chatgpt.com/backend-api/codex",
            "http://chatgpt.com/backend-api/codex",
        ),
    )
    .expect("write http config");
    let (complete, events) = run_kind(&home, "load");
    assert_path_qualified_error(
        &complete,
        "https_required",
        "providers.openai-codex.base_url",
    );
    assert_secret_free_run(&complete, &events);
}

#[test]
fn rss_config_auth_entry_reports_invalid_auth_reference_path() {
    let home = copy_fixture_home("auth-ref", "config.yaml", "auth.yaml");
    let config = fs::read_to_string(home.join("config.yaml")).expect("read config");
    fs::write(
        home.join("config.yaml"),
        config.replace("auth: fixture-codex", "auth: missing-credential"),
    )
    .expect("write invalid auth ref");
    let (complete, events) = run_kind(&home, "load");
    assert_path_qualified_error(
        &complete,
        "invalid_auth_reference",
        "providers.openai-codex.auth",
    );
    assert_secret_free_run(&complete, &events);
}

#[test]
fn production_agent_host_catalog_omits_stage_a_config_bridge() {
    let catalog = agent_host_catalog();
    let names: Vec<&str> = catalog
        .functions()
        .iter()
        .map(|schema| schema.name.as_str())
        .collect();
    assert!(
        !names.contains(&"config::load_snapshot"),
        "Stage A config bridge must not be on the production catalog: {names:?}"
    );
    assert!(
        !names.contains(&"config::check_policy"),
        "fixture check_policy must not be on the production catalog: {names:?}"
    );
}

#[test]
fn config_fixture_catalog_exposes_stage_a_bridge() {
    let catalog = config_fixture_catalog();
    let names: Vec<&str> = catalog
        .functions()
        .iter()
        .map(|schema| schema.name.as_str())
        .collect();
    assert!(
        names.contains(&"config::load_snapshot"),
        "fixture catalog missing load_snapshot: {names:?}"
    );
    assert!(
        names.contains(&"config::check_policy"),
        "fixture catalog missing check_policy: {names:?}"
    );
}

#[test]
fn rust_reload_revokes_previous_handle() {
    let home = copy_fixture_home("reload", "config.yaml", "auth.yaml");
    let first = load_snapshot(&home).expect("first load");
    let second = load_snapshot(&home).expect("second load");
    assert_ne!(first.policy_generation, second.policy_generation);
    let stale = check_policy(
        &first.policy_handle,
        &PolicyIntent {
            op: "inspect".into(),
            ..PolicyIntent::default()
        },
    )
    .expect_err("revoked handle");
    assert!(matches!(
        stale,
        ConfigFileError::PolicyStaleGeneration { .. }
    ));
    let inspect = check_policy(
        &second.policy_handle,
        &PolicyIntent {
            op: "inspect".into(),
            ..PolicyIntent::default()
        },
    )
    .expect("new handle");
    assert!(inspect.ok);
}
