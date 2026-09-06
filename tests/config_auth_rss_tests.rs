use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rustscript_agent::config::{PolicyIntent, check_policy, load_snapshot};
use rustscript_agent::config_file::{AgentPaths, ConfigFileError};
use rustscript_agent::{AgentConfig, AgentRunner, RunCancellation, RunDeliveryError, RunEventSink};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static HOME_ENV_LOCK: Mutex<()> = Mutex::new(());

const ACCESS_TOKEN: &str = "SYNTHETIC_ACCESS_TOKEN";
const REFRESH_TOKEN: &str = "SYNTHETIC_REFRESH_TOKEN";

struct RecordingSink {
    events: Vec<Value>,
}

impl RunEventSink for RecordingSink {
    fn deliver(&mut self, value: Value) -> std::result::Result<(), RunDeliveryError> {
        self.events.push(value);
        Ok(())
    }
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss")
}

fn entry_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/config_entry.rss")
}

fn entry_runner() -> AgentRunner {
    AgentRunner::from_file(entry_path(), AgentConfig::default())
        .expect("RSS config/auth entry should compile")
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

fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite json number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => Value::Array(std::sync::Arc::new(
            values.iter().map(json_to_vm_value).collect::<Vec<_>>(),
        )),
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
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
    let _lock = HOME_ENV_LOCK.lock().expect("home env lock");
    let runner = entry_runner();
    let mut sink = RecordingSink { events: Vec::new() };
    let cancellation = RunCancellation::default();
    let complete = runner
        .run_with_context_and_events(
            json_to_vm_value(&json!({
                "kind": kind,
                "host_home": home.to_string_lossy(),
            })),
            &mut sink,
            &cancellation,
        )
        .expect("RSS config/auth entry should complete");
    let events = sink.events.iter().map(vm_value_to_json).collect();
    (vm_value_to_json(&complete), events)
}

fn assert_secret_free_run(complete: &JsonValue, events: &[JsonValue]) {
    assert_no_raw_secrets(complete);
    for event in events {
        assert_no_raw_secrets(event);
    }
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
    let inspect = check_policy(
        &snapshot.policy_handle,
        &PolicyIntent {
            op: "inspect".to_string(),
            ..PolicyIntent::default()
        },
    )
    .expect("minted handle should inspect");
    assert!(inspect.ok);
}

#[test]
fn generic_https_urls_do_not_use_provider_name_authority_mapping() {
    let home = temp_home("https-generic");
    let paths = AgentPaths::from_home(&home).expect("home");
    let config = fs::read_to_string(fixture_dir().join("config.yaml")).expect("fixture config");
    fs::write(
        &paths.config,
        config.replace(
            "base_url: https://chatgpt.com/backend-api/codex",
            "base_url: https://api.openai.com/backend-api/codex",
        ),
    )
    .expect("write config");
    fs::copy(fixture_dir().join("auth.yaml"), &paths.auth).expect("copy auth");
    load_snapshot(&home).expect("openai-codex HTTPS hosts stay generic");
}

#[test]
fn unknown_provider_names_are_not_rejected_by_generic_loader() {
    let home = temp_home("unknown-provider");
    let paths = AgentPaths::from_home(&home).expect("home");
    fs::write(
        &paths.config,
        "version: 1\nmodel:\n  provider: unknown-empty\n  model: local-agent\n",
    )
    .expect("write config");
    fs::write(&paths.auth, "version: 1\n").expect("write auth");
    load_snapshot(&home).expect("unknown provider names are RSS selection data");
}

#[test]
fn auth_references_require_existing_credential_ids_not_provider_matching() {
    let home = copy_fixture_home(
        "custom-mismatch",
        "custom_provider.yaml",
        "custom_auth.yaml",
    );
    let snapshot = load_snapshot(&home).expect("credential ID existence is enough");
    assert_eq!(snapshot.credential_refs, vec!["fixture-custom".to_string()]);

    let missing = temp_home("missing-id");
    let paths = AgentPaths::from_home(&missing).expect("home");
    fs::copy(fixture_dir().join("config.yaml"), &paths.config).expect("copy config");
    fs::write(&paths.auth, "version: 1\n").expect("empty auth");
    let error = load_snapshot(&missing).expect_err("missing credential IDs still fail");
    assert!(matches!(
        error,
        ConfigFileError::InvalidAuthReference { .. }
    ));
}

#[test]
fn rss_config_auth_entry_loads_bounded_public_snapshot_without_tokens() {
    let home = copy_fixture_home("rss-load", "config.yaml", "auth.yaml");
    let (complete, events) = run_kind(&home, "load");
    assert_secret_free_run(&complete, &events);
    assert_eq!(complete["ok"], json!(true));
    assert_eq!(complete["policy_handle_class"], json!("OpaquePolicyHandle"));
    assert_eq!(complete["selected_provider"], json!("openai-codex"));
    assert_eq!(complete["selected_model"], json!("gpt-5-codex"));
    assert_eq!(complete["credential_refs"][0]["id"], json!("fixture-codex"));
    assert!(complete.get("policy_handle").is_none());
    assert!(complete.get("public_config").is_some());
}

#[test]
fn rss_config_auth_entry_rejects_forged_policy_handle() {
    let home = copy_fixture_home("rss-forge", "config.yaml", "auth.yaml");
    let (complete, events) = run_kind(&home, "forge_handle");
    assert_secret_free_run(&complete, &events);
    assert_eq!(complete["ok"], json!(false));
    assert_eq!(complete["error"]["code"], json!("policy_handle_invalid"));
}

#[test]
fn rss_config_auth_entry_copies_alias_the_same_policy_entry() {
    let home = copy_fixture_home("rss-copy", "config.yaml", "auth.yaml");
    let (complete, events) = run_kind(&home, "copy_handle");
    assert_secret_free_run(&complete, &events);
    assert_eq!(complete["ok"], json!(true));
    assert_eq!(complete["policy_handle_class"], json!("OpaquePolicyHandle"));
}

#[test]
fn rss_config_auth_entry_rejects_workspace_approval_and_header_overreach() {
    let home = copy_fixture_home("rss-overreach", "config.yaml", "auth.yaml");
    for kind in ["expand_workspace", "raise_approval", "add_header"] {
        let (complete, events) = run_kind(&home, kind);
        assert_secret_free_run(&complete, &events);
        assert_eq!(complete["ok"], json!(false), "{kind}");
        assert_eq!(
            complete["error"]["code"],
            json!("policy_overreach"),
            "{kind}"
        );
    }
}

#[test]
fn rss_config_auth_entry_rejects_stale_generation_and_expiry() {
    let home = copy_fixture_home("rss-stale", "config.yaml", "auth.yaml");
    let (stale, stale_events) = run_kind(&home, "stale_generation");
    assert_secret_free_run(&stale, &stale_events);
    assert_eq!(stale["ok"], json!(false));
    assert_eq!(stale["error"]["code"], json!("policy_stale_generation"));

    let (expired, expired_events) = run_kind(&home, "expire");
    assert_secret_free_run(&expired, &expired_events);
    assert_eq!(expired["ok"], json!(false));
    assert_eq!(expired["error"]["code"], json!("policy_expired"));
}

#[test]
fn rss_config_auth_entry_admits_explicit_custom_provider() {
    let home = copy_fixture_home("rss-custom", "custom_provider.yaml", "custom_auth.yaml");
    let (complete, events) = run_kind(&home, "load");
    assert_secret_free_run(&complete, &events);
    assert_eq!(complete["ok"], json!(true));
    assert_eq!(complete["selected_provider"], json!("custom-provider"));
    assert_eq!(
        complete["credential_refs"][0]["id"],
        json!("fixture-custom")
    );
}

#[test]
fn rss_config_auth_entry_negative_scan_keeps_tokens_out_of_events_and_output() {
    let home = copy_fixture_home("rss-scan", "config.yaml", "auth.yaml");
    for kind in [
        "load",
        "forge_handle",
        "copy_handle",
        "expand_workspace",
        "raise_approval",
        "add_header",
        "stale_generation",
        "expire",
    ] {
        let (complete, events) = run_kind(&home, kind);
        assert_secret_free_run(&complete, &events);
        let durable = json!({ "complete": complete, "events": events });
        assert_no_raw_secrets(&durable);
    }
}
