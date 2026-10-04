use rustscript_agent::auth::host::AuthHost;
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryRunner};
use rustscript_agent::{CancellationReason, RunCancellation};
use rustscript_vm::{
    CompileSourceFileOptions, SourceFlavor, Value, compile_source_at_path_with_flavor_and_options,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const ENTRY_PATH: &str = "rss/auth/commands.rss";
const SOURCES: &[(&str, &str)] = &[
    (ENTRY_PATH, include_str!("../rss/auth/commands.rss")),
    (
        "rss/config/selection.rss",
        include_str!("../rss/config/selection.rss"),
    ),
];

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new(label: &str) -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 test temp"),
        );
        let home = root.join(format!("task6-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), home.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900000000000")
            .replace("1788436400000", "1899996400000");
        fs::write(home.join("auth.yaml"), auth).expect("write auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("private home");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("private fixture file");
            }
        }
        Self(home)
    }

    fn directory_entries(&self) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(&self.0)
            .expect("read fixture directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();
        entries
    }

    fn file_bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.0.join(name)).expect("read fixture bytes")
    }

    fn yaml(&self, name: &str) -> serde_yaml::Value {
        serde_yaml::from_slice(&self.file_bytes(name)).expect("parse fixture YAML")
    }

    fn write_yaml(&self, name: &str, value: &serde_yaml::Value) {
        fs::write(
            self.0.join(name),
            serde_yaml::to_string(value).expect("serialize fixture YAML"),
        )
        .expect("write fixture YAML");
    }

    fn add_provider(&self, name: &str, credential_id: Option<&str>) {
        let mut config = self.yaml("config.yaml");
        let mut provider = config["providers"]["openai-codex"].clone();
        provider["auth"] = credential_id
            .map(|id| serde_yaml::Value::String(id.to_owned()))
            .unwrap_or(serde_yaml::Value::Null);
        config["providers"]
            .as_mapping_mut()
            .expect("provider mapping")
            .insert(serde_yaml::Value::String(name.to_owned()), provider);
        self.write_yaml("config.yaml", &config);
    }

    fn set_default_selection(&self, provider: &str, model: &str, source: &str) {
        let mut config = self.yaml("config.yaml");
        config["model"]["provider"] = serde_yaml::Value::String(provider.to_owned());
        config["model"]["model"] = serde_yaml::Value::String(model.to_owned());
        config["agent"]["source"] = serde_yaml::Value::String(source.to_owned());
        self.write_yaml("config.yaml", &config);
    }

    fn clear_providers(&self) {
        let mut config = self.yaml("config.yaml");
        config["providers"]
            .as_mapping_mut()
            .expect("provider mapping")
            .clear();
        self.write_yaml("config.yaml", &config);
    }

    fn add_credential(&self, id: &str, status: &str) {
        let mut auth = self.yaml("auth.yaml");
        let mut credential = auth["credentials"]["fixture-codex"].clone();
        credential["status"] = serde_yaml::Value::String(status.to_owned());
        auth["credentials"]
            .as_mapping_mut()
            .expect("credential mapping")
            .insert(serde_yaml::Value::String(id.to_owned()), credential);
        self.write_yaml("auth.yaml", &auth);
    }

    fn remove_credential(&self, id: &str) {
        let mut auth = self.yaml("auth.yaml");
        auth["credentials"]
            .as_mapping_mut()
            .expect("credential mapping")
            .remove(serde_yaml::Value::String(id.to_owned()));
        self.write_yaml("auth.yaml", &auth);
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(
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

fn run_command_with_cancellation(
    home: &Path,
    input: AuthCommandInput,
    cancellation: RunCancellation,
) -> Result<Value, rustscript_agent::runtime::AuthEntryError> {
    let runner =
        AuthEntryRunner::from_bundle(ENTRY_PATH, SOURCES).expect("compile checked-in RSS bundle");
    runner.run_with_host_factory(input, &cancellation, {
        let home = home.to_path_buf();
        move |child| AuthHost::new_for_commands(home, child)
    })
}

fn run_command(
    home: &Path,
    input: AuthCommandInput,
) -> Result<Value, rustscript_agent::runtime::AuthEntryError> {
    run_command_with_cancellation(
        home,
        input,
        RunCancellation::with_timeout(Duration::from_secs(10)),
    )
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected RSS record, got {value:?}");
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn optional_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(fields) = value else {
        panic!("expected RSS record, got {value:?}");
    };
    fields.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn text(value: &Value) -> &str {
    let Value::String(value) = value else {
        panic!("expected string, got {value:?}");
    };
    value
}

fn report_rows(value: &Value) -> Vec<serde_json::Value> {
    text(field(value, "status"))
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON object per report line"))
        .collect()
}

fn logout_row(value: &Value) -> serde_json::Value {
    serde_json::from_str(text(field(value, "status"))).expect("one JSON logout report")
}

#[test]
fn rss_command_bundle_compiles_with_the_registered_auth_catalog() {
    let catalog = rustscript_agent::auth::host::auth_host_catalog();
    let mut options =
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    for (path, source) in SOURCES {
        options.set_module_override_source(
            format!("/__rustscript_agent_auth_bundle__/{path}"),
            *source,
        );
    }
    let compiled = compile_source_at_path_with_flavor_and_options(
        Path::new("/__rustscript_agent_auth_bundle__/rss/auth/commands.rss"),
        SOURCES[0].1,
        SourceFlavor::RustScript,
        options,
    );
    assert!(compiled.is_ok(), "{:?}", compiled.err());
}

#[test]
fn config_check_uses_the_real_default_provider_model_and_source() {
    let home = FixtureHome::new("default-selection");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(&home.0, command("config.check", None, None))
        .expect("run checked-in command entry with Commands factory");

    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(
        report_rows(&result),
        vec![
            serde_json::json!({
                "provider": "openai-codex",
                "credential_id": "fixture-codex",
                "status": "active",
                "source": "codex-device",
                "generation": 4
            }),
            serde_json::json!({
                "kind": "selection",
                "provider": "openai-codex",
                "model": "gpt-5-codex",
                "source": "bundled:coding"
            })
        ]
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn auth_status_reports_all_public_provider_rows_in_snapshot_order() {
    let home = FixtureHome::new("all-provider-status");
    home.add_provider("alpha-no-auth", None);
    home.add_provider("beta-disabled", Some("disabled-credential"));
    home.add_credential("disabled-credential", "disabled");
    home.add_provider("charlie-reauth", Some("reauth-credential"));
    home.add_credential("reauth-credential", "reauth_required");
    home.add_provider("delta-missing", Some("missing-credential"));
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(&home.0, command("auth.status", None, None))
        .expect("run checked-in command entry with Commands factory");

    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert!(
        optional_field(&result, "credential_id").is_none_or(|value| matches!(value, Value::Null))
    );
    assert_eq!(
        report_rows(&result),
        vec![
            serde_json::json!({"provider":"alpha-no-auth","status":"not_configured","generation":0}),
            serde_json::json!({"provider":"beta-disabled","credential_id":"disabled-credential","status":"disabled","source":"codex-device","generation":4}),
            serde_json::json!({"provider":"charlie-reauth","credential_id":"reauth-credential","status":"reauth_required","source":"codex-device","generation":4}),
            serde_json::json!({"provider":"delta-missing","credential_id":"missing-credential","status":"missing","generation":0}),
            serde_json::json!({"provider":"openai-codex","credential_id":"fixture-codex","status":"active","source":"codex-device","generation":4})
        ]
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!rendered.contains("SYNTHETIC_REFRESH_TOKEN"));
}

#[test]
fn auth_status_renders_active_metadata_from_the_real_commands_host() {
    let home = FixtureHome::new("active-status");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(&home.0, command("auth.status", Some("openai-codex"), None))
        .expect("run checked-in command entry with Commands factory");

    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(field(&result, "operation"), &Value::string("auth.status"));
    assert_eq!(
        field(&result, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&result, "generation"), &Value::Int(1));
    assert!(optional_field(&result, "error").is_none_or(|value| matches!(value, Value::Null)));
    assert_eq!(
        report_rows(&result),
        vec![serde_json::json!({
            "provider": "openai-codex",
            "credential_id": "fixture-codex",
            "status": "active",
            "source": "codex-device",
            "generation": 4
        })]
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!rendered.contains("SYNTHETIC_REFRESH_TOKEN"));
}

#[test]
fn auth_logout_reports_unadmitted_credentials_as_absent_without_writing() {
    let home = FixtureHome::new("logout-unadmitted");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(
        &home.0,
        command("auth.logout", None, Some("orphan-credential")),
    )
    .expect("run checked-in command entry with Commands factory");

    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(
        logout_row(&result),
        serde_json::json!({"credential_id":"orphan-credential","status":"already_absent"})
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn auth_logout_removes_only_the_admitted_credential_and_repeats_as_absent() {
    let home = FixtureHome::new("logout-configured");
    home.add_credential("peer-credential", "active");
    home.add_credential("peer-two", "disabled");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.yaml("auth.yaml");
    let peer_before = before_auth["credentials"]["peer-credential"].clone();
    let mut expected_credentials = before_auth["credentials"].clone();
    expected_credentials
        .as_mapping_mut()
        .expect("credential mapping")
        .remove(serde_yaml::Value::String("fixture-codex".to_owned()));

    let first = run_command(&home.0, command("auth.logout", None, Some("fixture-codex")))
        .expect("delete configured credential through the native Commands host");

    assert_eq!(field(&first, "ok"), &Value::Bool(true), "{first:?}");
    assert_eq!(
        logout_row(&first),
        serde_json::json!({"credential_id":"fixture-codex","status":"deleted"})
    );
    let after_first = home.yaml("auth.yaml");
    assert_eq!(after_first["credentials"], expected_credentials);
    assert_eq!(after_first["credentials"]["peer-credential"], peer_before);
    assert!(home.0.join("auth.yaml.lock").exists());
    let mut after_delete_entries = before_entries;
    after_delete_entries.push("auth.yaml.lock".into());
    after_delete_entries.sort();
    assert_eq!(home.directory_entries(), after_delete_entries);

    let second = run_command(&home.0, command("auth.logout", None, Some("fixture-codex")))
        .expect("repeat configured credential deletion through the native Commands host");

    assert_eq!(field(&second, "ok"), &Value::Bool(true), "{second:?}");
    assert_eq!(
        logout_row(&second),
        serde_json::json!({"credential_id":"fixture-codex","status":"already_absent"})
    );
    assert_eq!(home.yaml("auth.yaml"), after_first);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.directory_entries(), after_delete_entries);
    assert_ne!(home.yaml("auth.yaml"), before_auth);
}

#[test]
fn config_check_uses_non_vendor_default_and_allows_unconfigured_provider() {
    let home = FixtureHome::new("alternate-default");
    home.add_provider("community", None);
    home.set_default_selection("community", "community-model-v1", "bundled:coding");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(&home.0, command("config.check", None, None))
        .expect("check real alternate provider selection");

    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    let rows = report_rows(&result);
    assert!(rows.iter().any(|row| {
        row["provider"] == "community"
            && row["status"] == "not_configured"
            && row["credential_id"].is_null()
            && row["source"].is_null()
            && row["generation"] == 0
    }));
    assert_eq!(
        rows.last().expect("selection summary"),
        &serde_json::json!({
            "kind": "selection",
            "provider": "community",
            "model": "community-model-v1",
            "source": "bundled:coding"
        })
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn config_check_rejects_invalid_default_provider_and_empty_provider_set() {
    for empty in [false, true] {
        let home = FixtureHome::new(if empty {
            "empty-providers"
        } else {
            "invalid-default"
        });
        if empty {
            home.clear_providers();
        } else {
            home.set_default_selection("unconfigured-provider", "model-x", "bundled:coding");
        }
        let before_entries = home.directory_entries();
        let before_config = home.file_bytes("config.yaml");
        let before_auth = home.file_bytes("auth.yaml");

        let result = run_command(&home.0, command("config.check", None, None))
            .expect("evaluate configured default selection");

        assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
        assert_eq!(
            field(&result, "error"),
            &Value::string("provider_not_found")
        );
        assert!(
            !report_rows(&result)
                .iter()
                .any(|row| row["kind"] == "selection")
        );
        assert_eq!(home.directory_entries(), before_entries);
        assert_eq!(home.file_bytes("config.yaml"), before_config);
        assert_eq!(home.file_bytes("auth.yaml"), before_auth);
    }
}

#[test]
fn config_check_fails_for_missing_disabled_and_reauth_references() {
    let home = FixtureHome::new("inactive-references");
    home.add_provider("disabled-provider", Some("disabled-reference"));
    home.add_credential("disabled-reference", "disabled");
    home.add_provider("reauth-provider", Some("reauth-reference"));
    home.add_credential("reauth-reference", "reauth_required");
    home.add_provider("missing-provider", Some("missing-reference"));
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(&home.0, command("config.check", None, None))
        .expect("check all typed credential references");

    assert_eq!(field(&result, "ok"), &Value::Bool(false));
    assert_eq!(
        field(&result, "error"),
        &Value::string("credential_check_failed")
    );
    let rows = report_rows(&result);
    for (provider, status) in [
        ("disabled-provider", "disabled"),
        ("reauth-provider", "reauth_required"),
        ("missing-provider", "missing"),
    ] {
        assert!(
            rows.iter()
                .any(|row| row["provider"] == provider && row["status"] == status)
        );
    }
    assert!(
        rows.iter()
            .any(|row| row["provider"] == "openai-codex" && row["status"] == "active")
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn auth_status_rejects_empty_and_unknown_selectors_without_fallback() {
    let home = FixtureHome::new("status-selectors");
    home.add_provider("alpha-no-auth", None);
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    for (provider, expected) in [
        ("", "provider_required"),
        ("OpenAI-Codex", "provider_not_found"),
        ("unknown-provider", "provider_not_found"),
    ] {
        let result = run_command(&home.0, command("auth.status", Some(provider), None))
            .expect("run exact provider selector");
        assert_eq!(field(&result, "ok"), &Value::Bool(false));
        assert_eq!(field(&result, "status"), &Value::string(expected));
        assert_eq!(field(&result, "error"), &Value::string(expected));
    }

    let result = run_command(&home.0, command("auth.status", Some("alpha-no-auth"), None))
        .expect("select provider without auth");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(
        report_rows(&result),
        vec![serde_json::json!({
            "provider": "alpha-no-auth",
            "status": "not_configured",
            "generation": 0
        })]
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn auth_logout_configured_missing_reference_is_absent_without_mutation() {
    let home = FixtureHome::new("logout-configured-missing");
    home.remove_credential("fixture-codex");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(&home.0, command("auth.logout", None, Some("fixture-codex")))
        .expect("preflight configured missing credential");

    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(
        logout_row(&result),
        serde_json::json!({"credential_id":"fixture-codex","status":"already_absent"})
    );
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn auth_status_selected_provider_reports_inactive_and_missing_metadata_as_information() {
    let home = FixtureHome::new("selected-inactive-status");
    home.add_provider("disabled-provider", Some("disabled-reference"));
    home.add_credential("disabled-reference", "disabled");
    home.add_provider("reauth-provider", Some("reauth-reference"));
    home.add_credential("reauth-reference", "reauth_required");
    home.add_provider("missing-provider", Some("missing-reference"));
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    for (provider, credential_id, status) in [
        ("disabled-provider", "disabled-reference", "disabled"),
        ("reauth-provider", "reauth-reference", "reauth_required"),
        ("missing-provider", "missing-reference", "missing"),
    ] {
        let result = run_command(&home.0, command("auth.status", Some(provider), None))
            .expect("diagnose one selected provider");

        assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
        assert_eq!(
            field(&result, "credential_id"),
            &Value::string(credential_id)
        );
        let expected = if status == "missing" {
            serde_json::json!({
                "provider": provider,
                "credential_id": credential_id,
                "status": status,
                "generation": 0
            })
        } else {
            serde_json::json!({
                "provider": provider,
                "credential_id": credential_id,
                "status": status,
                "source": "codex-device",
                "generation": 4
            })
        };
        assert_eq!(report_rows(&result), vec![expected]);
    }

    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn auth_logout_preflight_preserves_typed_store_read_errors() {
    const CORRUPT_AUTH: &[u8] = b"version: 1\ncredentials: [malformed\n";
    let home = FixtureHome::new("logout-corrupt-store");
    let home_path = home.0.clone();
    let before_config = home.file_bytes("config.yaml");
    let runner = AuthEntryRunner::from_bundle(ENTRY_PATH, SOURCES)
        .expect("compile the checked-in RSS bundle");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));

    let result = runner
        .run_with_host_factory(
            command("auth.logout", None, Some("fixture-codex")),
            &cancellation,
            move |child| {
                let host = AuthHost::new_for_commands(home_path.clone(), child)?;
                fs::write(home_path.join("auth.yaml"), CORRUPT_AUTH)
                    .map_err(|error| error.to_string())?;
                Ok(host)
            },
        )
        .expect("typed metadata read failure returns an RSS result");

    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(field(&result, "error"), &Value::string("corrupt_file"));
    assert_eq!(
        logout_row(&result),
        serde_json::json!({"credential_id":"fixture-codex","status":"corrupt_file"})
    );
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), CORRUPT_AUTH.to_vec());
    assert_eq!(home.directory_entries(), ["auth.yaml", "config.yaml"]);
}

#[test]
fn auth_logout_deletes_real_orphan_and_preserves_full_peer_yaml() {
    let home = FixtureHome::new("logout-orphan");
    home.add_credential("orphan-credential", "active");
    home.add_credential("peer-disabled", "disabled");
    home.add_credential("peer-reauth", "reauth_required");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.yaml("auth.yaml");
    let mut expected_credentials = before_auth["credentials"].clone();
    expected_credentials
        .as_mapping_mut()
        .expect("credential mapping")
        .remove(serde_yaml::Value::String("orphan-credential".to_owned()));

    let result = run_command(
        &home.0,
        command("auth.logout", None, Some("orphan-credential")),
    )
    .expect("delete orphan discovered by the trusted snapshot");

    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(
        logout_row(&result),
        serde_json::json!({"credential_id":"orphan-credential","status":"deleted"})
    );
    assert_eq!(home.yaml("auth.yaml")["credentials"], expected_credentials);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    let mut expected_entries = before_entries;
    expected_entries.push("auth.yaml.lock".into());
    expected_entries.sort();
    assert_eq!(home.directory_entries(), expected_entries);
}

#[test]
fn admin_invalid_fields_unsupported_commands_and_control_ids_are_safe() {
    let home = FixtureHome::new("admin-invalid-inputs");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    for (input, expected) in [
        (
            command("auth.status", None, Some("unexpected-id")),
            "invalid_command",
        ),
        (
            command("auth.logout", Some("openai-codex"), Some("fixture-codex")),
            "invalid_command",
        ),
        (
            command("config.check", Some("openai-codex"), None),
            "invalid_command",
        ),
        (
            command("config.check", None, Some("fixture-codex")),
            "invalid_command",
        ),
        (command("auth.logout", None, None), "credential_id_required"),
        (
            command("auth.logout", None, Some("")),
            "credential_id_required",
        ),
    ] {
        let result = run_command(&home.0, input).expect("validate bounded command selectors");
        assert_eq!(field(&result, "ok"), &Value::Bool(false));
        assert_eq!(field(&result, "status"), &Value::string(expected));
        assert_eq!(field(&result, "error"), &Value::string(expected));
    }

    for operation in ["auth.login", "config.path"] {
        let result = run_command(&home.0, command(operation, None, None))
            .expect("preserve pending command as unsupported");
        assert_eq!(field(&result, "ok"), &Value::Bool(false));
        assert_eq!(
            field(&result, "status"),
            &Value::string("unsupported_operation")
        );
        assert_eq!(
            field(&result, "error"),
            &Value::string("unsupported_operation")
        );
    }

    let control_id = "orphan\r\ncredential";
    let result = run_command(&home.0, command("auth.logout", None, Some(control_id)));
    assert!(matches!(
        result,
        Err(rustscript_agent::runtime::AuthEntryError::InvalidInput)
    ));
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}

#[test]
fn cancelled_deadline_and_corrupt_auth_inputs_fail_closed_without_artifacts() {
    for deadline in [false, true] {
        let home = FixtureHome::new(if deadline {
            "logout-deadline"
        } else {
            "logout-cancelled"
        });
        let before_entries = home.directory_entries();
        let before_config = home.file_bytes("config.yaml");
        let before_auth = home.file_bytes("auth.yaml");
        let cancellation = if deadline {
            RunCancellation::with_timeout(Duration::from_millis(0))
        } else {
            let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
            cancellation.request(CancellationReason::Requested);
            cancellation
        };

        let result = run_command_with_cancellation(
            &home.0,
            command("auth.logout", None, Some("fixture-codex")),
            cancellation,
        );
        match result {
            Err(rustscript_agent::runtime::AuthEntryError::Cancelled(reason)) => {
                assert_eq!(
                    reason,
                    if deadline {
                        CancellationReason::Deadline
                    } else {
                        CancellationReason::Requested
                    }
                );
            }
            other => panic!("expected the exact cancellation/deadline, got {other:?}"),
        }
        assert_eq!(home.directory_entries(), before_entries);
        assert_eq!(home.file_bytes("config.yaml"), before_config);
        assert_eq!(home.file_bytes("auth.yaml"), before_auth);
    }

    const PRIVATE_BACKEND_TEXT: &str = "BACKEND_PRIVATE_CORRUPT_AUTH_SENTINEL";
    let home = FixtureHome::new("corrupt-auth");
    fs::write(
        home.0.join("auth.yaml"),
        format!("version: 1\ncredentials: [malformed\n{PRIVATE_BACKEND_TEXT}"),
    )
    .expect("corrupt only the synthetic auth fixture");
    let before_entries = home.directory_entries();
    let before_config = home.file_bytes("config.yaml");
    let before_auth = home.file_bytes("auth.yaml");

    let result = run_command(&home.0, command("auth.status", Some("openai-codex"), None));
    let rendered = format!("{result:?}");
    assert!(!rendered.contains(PRIVATE_BACKEND_TEXT));
    assert!(!rendered.contains(home.0.to_string_lossy().as_ref()));
    if let Ok(value) = result {
        assert_eq!(field(&value, "ok"), &Value::Bool(false), "{value:?}");
    }
    assert_eq!(home.directory_entries(), before_entries);
    assert_eq!(home.file_bytes("config.yaml"), before_config);
    assert_eq!(home.file_bytes("auth.yaml"), before_auth);
}
