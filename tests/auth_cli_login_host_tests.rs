use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::host::{AuthHost, auth_host_catalog},
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

const LOGIN_IDS: [&str; 2] = ["login-alpha", "login-beta"];
const RSS: &str = r#"
use auth;
use config;

pub fn snapshot(home: resource<auth.host_home>) -> ConfigSnapshotEnvelope {
    config::load_snapshot(&home)
}

pub fn metadata_result(
    policy: resource<auth.policy>,
    credential_id: string
) -> AuthMetadataResultEnvelope {
    auth::load_metadata_result(credential_id, &policy)
}

pub fn save_result(request: SaveCredentialRequest) -> AuthSaveResultEnvelope {
    auth::save_if_generation_result(&request)
}

pub fn close_slot(slot: resource<auth.secret_slot>) -> int {
    auth::close_slot(slot);
    1
}
"#;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new(references: &[&str], with_auth: bool) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test TEMP"));
        let home = root.join(format!("auth-login-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let mut config: serde_yaml::Value = serde_yaml::from_slice(
            &fs::read(fixture.join("config.yaml")).expect("read config fixture"),
        )
        .expect("parse config fixture");
        let template = config["providers"]["openai-codex"].clone();
        let providers = config["providers"]
            .as_mapping_mut()
            .expect("provider mapping");
        providers.clear();
        for index in 0..references.len().max(1) {
            let name = if index == 0 {
                "openai-codex".to_owned()
            } else {
                format!("login-provider-{index}")
            };
            let mut provider = template.clone();
            provider["auth"] = references
                .get(index)
                .map(|id| serde_yaml::Value::String((*id).to_owned()))
                .unwrap_or(serde_yaml::Value::Null);
            // Admission must follow credential references, not OAuth business labels.
            provider["oauth"]["flow"] = serde_yaml::Value::String("test-unclassified-flow".into());
            providers.insert(serde_yaml::Value::String(name), provider);
        }
        fs::write(
            home.join("config.yaml"),
            serde_yaml::to_string(&config).expect("serialize config fixture"),
        )
        .expect("write config fixture");
        if with_auth {
            let auth = fs::read_to_string(fixture.join("auth.yaml"))
                .expect("read orphan credential fixture")
                .replace("1788440000000", "1900000000000")
                .replace("1788436400000", "1899996400000");
            fs::write(home.join("auth.yaml"), auth).expect("write auth fixture");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
                .expect("config mode");
            if with_auth {
                fs::set_permissions(home.join("auth.yaml"), fs::Permissions::from_mode(0o600))
                    .expect("auth mode");
            }
        }
        Self(home)
    }

    fn set_references(&self, references: &[&str]) {
        let path = self.0.join("config.yaml");
        let mut config: serde_yaml::Value =
            serde_yaml::from_slice(&fs::read(&path).expect("config bytes"))
                .expect("parse current config");
        let template = config["providers"]["openai-codex"].clone();
        let providers = config["providers"]
            .as_mapping_mut()
            .expect("provider mapping");
        providers.clear();
        for index in 0..references.len().max(1) {
            let name = if index == 0 {
                "openai-codex".to_owned()
            } else {
                format!("login-provider-{index}")
            };
            let mut provider = template.clone();
            provider["auth"] = references
                .get(index)
                .map(|id| serde_yaml::Value::String((*id).to_owned()))
                .unwrap_or(serde_yaml::Value::Null);
            providers.insert(serde_yaml::Value::String(name), provider);
        }
        fs::write(
            &path,
            serde_yaml::to_string(&config).expect("serialize config"),
        )
        .expect("update config references");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("config mode");
        }
    }

    fn entries(&self) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(&self.0)
            .expect("read home entries")
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
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cancellation() -> RunCancellation {
    RunCancellation::with_timeout(Duration::from_secs(30))
}

fn compile_vm(auth: &AuthHost) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        RSS,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile typed RSS against the pinned auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("install the production auth host catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind the restricted auth registry");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
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

fn invoke_result(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, rustscript_vm::VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    invoke_result(vm, name, args).unwrap_or_else(|failure| panic!("RSS {name}: {failure:?}"))
}

fn bind(auth: &AuthHost) -> (Vm, Value, Value) {
    let mut vm = compile_vm(auth);
    let home = auth.bind_vm(&mut vm).expect("bind real native owner");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&home, "host_home").clone()]);
    let policy = field(&snapshot, "policy_handle").clone();
    assert_eq!(vm.host_context().resource_count(), 2);
    (vm, policy, snapshot)
}

fn error_code(result: &Value) -> &str {
    let Value::String(code) = field(field(result, "error"), "code") else {
        panic!("expected typed error code: {result:?}");
    };
    code
}

#[cfg(feature = "config-fixture")]
fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::string(key), value))
            .collect(),
    )
}

#[cfg(feature = "config-fixture")]
fn save_request(
    policy: &Value,
    credential_id: &str,
    expected_generation: i64,
    access_slot: Value,
) -> Value {
    record(vec![
        ("credential_id", Value::string(credential_id)),
        ("expected_generation", Value::Int(expected_generation)),
        ("policy_handle", policy.clone()),
        (
            "metadata",
            record(vec![
                ("provider", Value::string("login-test-provider")),
                ("kind", Value::string("oauth")),
                ("source", Value::string("synthetic-login-test")),
                ("token_type", Value::string("Bearer")),
                ("expires_at_ms", Value::Int(2_000_000_000_000)),
                ("scopes", Value::array(vec![])),
                ("account_id", Value::string("synthetic-login-account")),
                ("generation", Value::Int(expected_generation)),
                ("status", Value::string("active")),
                ("last_refresh_at_ms", Value::Null),
                ("has_refresh_token", Value::Bool(false)),
            ]),
        ),
        ("access_slot", access_slot),
        ("refresh_action", Value::string("clear")),
        ("refresh_slot", Value::Null),
    ])
}

#[test]
fn login_guest_admits_multiple_absent_configured_ids_and_denies_orphan_query_and_save() {
    let home = FixtureHome::new(&LOGIN_IDS, true);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let entries_before = home.entries();
    assert!(!home.0.join("auth.yaml.lock").exists());

    let auth = AuthHost::new_for_login(home.0.clone(), cancellation())
        .expect("explicit configured-login admission");
    let (mut vm, policy, snapshot) = bind(&auth);
    assert_eq!(
        field(&snapshot, "credential_refs"),
        &Value::array(LOGIN_IDS.into_iter().map(Value::string).collect()),
    );
    assert_eq!(vm.host_context().resource_count(), 2);

    for id in LOGIN_IDS {
        let result = invoke(
            &mut vm,
            "metadata_result",
            &[policy.clone(), Value::string(id)],
        );
        assert_eq!(field(&result, "ok"), &Value::Bool(false));
        assert_eq!(error_code(&result), "credential_not_found");
    }
    let orphan = invoke(
        &mut vm,
        "metadata_result",
        &[policy.clone(), Value::string("fixture-codex")],
    );
    assert_eq!(field(&orphan, "ok"), &Value::Bool(false));
    assert_eq!(error_code(&orphan), "credential_not_admitted");

    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(home.entries(), entries_before);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn login_guest_preserves_existing_configured_metadata_and_generation() {
    let references = ["fixture-codex", LOGIN_IDS[0]];
    let home = FixtureHome::new(&references, true);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let entries_before = home.entries();
    assert!(!home.0.join("auth.yaml.lock").exists());

    let auth = AuthHost::new_for_login(home.0.clone(), cancellation())
        .expect("configured existing and absent references");
    let (mut vm, policy, _) = bind(&auth);
    let existing = invoke(
        &mut vm,
        "metadata_result",
        &[policy.clone(), Value::string("fixture-codex")],
    );
    assert_eq!(field(&existing, "ok"), &Value::Bool(true));
    let existing_value = field(&existing, "value");
    assert_eq!(field(existing_value, "outcome"), &Value::string("loaded"));
    let metadata = field(existing_value, "metadata");
    assert_eq!(
        field(metadata, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(metadata, "provider"), &Value::string("openai-codex"));
    assert_eq!(field(metadata, "kind"), &Value::string("oauth"));
    assert_eq!(field(metadata, "source"), &Value::string("codex-device"));
    assert_eq!(field(metadata, "token_type"), &Value::string("Bearer"));
    assert_eq!(
        field(metadata, "expires_at_ms"),
        &Value::Int(1_900_000_000_000)
    );
    assert_eq!(field(metadata, "scopes"), &Value::array(vec![]));
    assert_eq!(
        field(metadata, "account_id"),
        &Value::string("acct_synthetic")
    );
    assert_eq!(field(metadata, "generation"), &Value::Int(4));
    assert_eq!(field(metadata, "status"), &Value::string("active"));
    assert_eq!(
        field(metadata, "last_refresh_at_ms"),
        &Value::Int(1_899_996_400_000)
    );
    assert_eq!(field(metadata, "has_refresh_token"), &Value::Bool(true));

    let absent = invoke(
        &mut vm,
        "metadata_result",
        &[policy.clone(), Value::string(LOGIN_IDS[0])],
    );
    assert_eq!(field(&absent, "ok"), &Value::Bool(false));
    assert_eq!(error_code(&absent), "credential_not_found");
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(home.entries(), entries_before);

    #[cfg(feature = "config-fixture")]
    {
        let access_slot = auth
            .fixture_slot(
                &mut vm,
                "fixture-codex",
                4,
                false,
                "LOGIN_EXISTING_ACCESS_SLOT_FIXTURE",
            )
            .expect("public fixture slot at existing generation four");
        let saved = invoke(
            &mut vm,
            "save_result",
            &[save_request(&policy, "fixture-codex", 4, access_slot)],
        );
        assert_eq!(field(&saved, "ok"), &Value::Bool(true), "{saved:?}");
        let value = field(&saved, "value");
        assert_eq!(field(value, "outcome"), &Value::string("committed"));
        assert_eq!(
            field(field(value, "metadata"), "generation"),
            &Value::Int(5)
        );
        let store = rustscript_agent::auth::store::AuthStore::from_home(&home.0)
            .expect("read persisted auth store");
        assert_eq!(
            store
                .load_metadata("fixture-codex")
                .expect("saved credential")
                .generation,
            5,
        );
        assert_eq!(
            fs::read(home.0.join("config.yaml")).expect("config unchanged"),
            config_before
        );
        assert_ne!(
            fs::read(home.0.join("auth.yaml")).expect("auth updated"),
            auth_before
        );
        let mut expected_entries = entries_before;
        expected_entries.push("auth.yaml.lock".into());
        expected_entries.sort();
        assert_eq!(home.entries(), expected_entries);
        assert!(!format!("{saved:?}").contains("LOGIN_EXISTING_ACCESS_SLOT_FIXTURE"));
    }
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn login_authorized_fixture_slot_saves_absent_configured_credential_from_generation_zero() {
    let home = FixtureHome::new(&LOGIN_IDS, true);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let entries_before = home.entries();
    let auth = AuthHost::new_for_login(home.0.clone(), cancellation())
        .expect("explicit configured-login admission");
    let (mut vm, policy, _) = bind(&auth);
    let orphan_slot = auth
        .fixture_slot(
            &mut vm,
            LOGIN_IDS[0],
            0,
            false,
            "LOGIN_ORPHAN_DENIAL_FIXTURE",
        )
        .expect("real admitted slot used to exercise orphan save denial");
    let rejected = invoke(
        &mut vm,
        "save_result",
        &[save_request(
            &policy,
            "fixture-codex",
            0,
            orphan_slot.clone(),
        )],
    );
    assert_eq!(field(&rejected, "ok"), &Value::Bool(false));
    assert_eq!(error_code(&rejected), "credential_not_admitted");
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(home.entries(), entries_before);
    assert_eq!(invoke(&mut vm, "close_slot", &[orphan_slot]), Value::Int(1));
    assert_eq!(vm.host_context().resource_count(), 2);

    let access_slot = auth
        .fixture_slot(&mut vm, LOGIN_IDS[0], 0, false, "LOGIN_ACCESS_SLOT_FIXTURE")
        .expect("host-issued slot for a configured absent credential at generation zero");
    let saved = invoke(
        &mut vm,
        "save_result",
        &[save_request(&policy, LOGIN_IDS[0], 0, access_slot)],
    );
    assert_eq!(field(&saved, "ok"), &Value::Bool(true), "{saved:?}");
    let value = field(&saved, "value");
    assert_eq!(field(value, "outcome"), &Value::string("committed"));
    assert_eq!(
        field(field(value, "metadata"), "generation"),
        &Value::Int(1),
    );
    let store = rustscript_agent::auth::store::AuthStore::from_home(&home.0)
        .expect("read persisted auth store");
    assert_eq!(
        store
            .load_metadata(LOGIN_IDS[0])
            .expect("saved target")
            .generation,
        1
    );
    assert_eq!(
        store
            .load_metadata("fixture-codex")
            .expect("orphan remains")
            .generation,
        4,
    );
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before,
    );
    let mut expected_entries = entries_before;
    expected_entries.push("auth.yaml.lock".into());
    expected_entries.sort();
    assert_eq!(home.entries(), expected_entries);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert!(!format!("{saved:?}").contains("LOGIN_ACCESS_SLOT_FIXTURE"));
}

#[test]
fn login_empty_refs_and_absent_auth_are_read_only_and_fail_closed_for_orphans() {
    let empty = FixtureHome::new(&[], true);
    let entries_before = empty.entries();
    let config_before = fs::read(empty.0.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(empty.0.join("auth.yaml")).expect("auth bytes");
    let auth = AuthHost::new_for_login(empty.0.clone(), cancellation()).expect("empty policy");
    let (mut vm, policy, snapshot) = bind(&auth);
    assert_eq!(field(&snapshot, "credential_refs"), &Value::array(vec![]));
    let denied = invoke(
        &mut vm,
        "metadata_result",
        &[policy, Value::string("fixture-codex")],
    );
    assert_eq!(error_code(&denied), "credential_not_admitted");
    assert_eq!(empty.entries(), entries_before);
    assert_eq!(
        fs::read(empty.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(empty.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );

    let absent = FixtureHome::new(&LOGIN_IDS, false);
    let absent_entries = absent.entries();
    let absent_config = fs::read(absent.0.join("config.yaml")).expect("config bytes");
    let host = AuthHost::new_for_login(absent.0.clone(), cancellation())
        .expect("missing auth document is an empty read-only store");
    let (mut vm, policy, snapshot) = bind(&host);
    assert_eq!(
        field(&snapshot, "credential_refs"),
        &Value::array(LOGIN_IDS.into_iter().map(Value::string).collect()),
    );
    for id in LOGIN_IDS {
        let result = invoke(
            &mut vm,
            "metadata_result",
            &[policy.clone(), Value::string(id)],
        );
        assert_eq!(error_code(&result), "credential_not_found");
    }
    assert_eq!(absent.entries(), absent_entries);
    assert!(!absent.0.join("auth.yaml").exists());
    assert!(!absent.0.join("auth.yaml.lock").exists());
    assert_eq!(
        fs::read(absent.0.join("config.yaml")).expect("config unchanged"),
        absent_config
    );
}

#[test]
fn login_unique_reference_cap_and_id_validation_are_applied_before_publish() {
    let ids: Vec<String> = (0..63)
        .map(|index| format!("login-limit-{index}"))
        .collect();
    let mut references: Vec<&str> = ids.iter().map(String::as_str).collect();
    references.push(ids[0].as_str());
    let at_unique_limit = FixtureHome::new(&references, true);
    let auth = AuthHost::new_for_login(at_unique_limit.0.clone(), cancellation())
        .expect("63 unique refs and a shared alias are within the cap");
    let (_vm, _policy, snapshot) = bind(&auth);
    let Value::Array(refs) = field(&snapshot, "credential_refs") else {
        panic!("credential refs are a typed array");
    };
    assert_eq!(refs.len(), 63);
    assert!(
        !refs
            .iter()
            .any(|value| value == &Value::string("fixture-codex"))
    );

    let cap_ids: Vec<String> = (0..64)
        .map(|index| format!("login-at-cap-{index}"))
        .collect();
    let cap_refs: Vec<&str> = cap_ids.iter().map(String::as_str).collect();
    let at_cap = FixtureHome::new(&cap_refs, true);
    let auth = AuthHost::new_for_login(at_cap.0.clone(), cancellation())
        .expect("64 unique configured IDs fit the admission cap");
    let (_vm, _policy, snapshot) = bind(&auth);
    let Value::Array(refs) = field(&snapshot, "credential_refs") else {
        panic!("credential refs are a typed array");
    };
    assert_eq!(refs.len(), 64);

    let ids: Vec<String> = (0..65)
        .map(|index| format!("login-over-limit-{index}"))
        .collect();
    let references: Vec<&str> = ids.iter().map(String::as_str).collect();
    let over_limit = FixtureHome::new(&references, true);
    let rejection = AuthHost::new_for_login(over_limit.0.clone(), cancellation())
        .err()
        .expect("65 configured IDs exceed the admission cap");
    assert_eq!(rejection, "credential_limit_exceeded");
    assert!(!over_limit.0.join("auth.yaml.lock").exists());

    let invalid = FixtureHome::new(&["invalid/login-id"], true);
    let rejection = AuthHost::new_for_login(invalid.0.clone(), cancellation())
        .err()
        .expect("configured IDs use the existing credential validator");
    assert_eq!(rejection, "invalid_credential_id");
}

#[test]
fn login_reload_freezes_old_guest_and_updates_future_bindings() {
    let home = FixtureHome::new(&LOGIN_IDS, true);
    let auth = AuthHost::new_for_login(home.0.clone(), cancellation()).expect("login host");
    let (mut old_vm, old_policy, old_snapshot) = bind(&auth);
    assert_eq!(field(&old_snapshot, "policy_generation"), &Value::Int(1));
    assert!(
        auth.bind_vm(&mut old_vm).is_err(),
        "duplicate bind remains rejected"
    );

    home.set_references(&[LOGIN_IDS[1], "login-gamma"]);
    let config_after_edit = fs::read(home.0.join("config.yaml")).expect("edited config");
    let auth_before_reload = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    assert_eq!(auth.reload().expect("publish updated configured set"), 2);
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("reload is read-only"),
        config_after_edit
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("reload is read-only"),
        auth_before_reload
    );

    let old_missing = invoke(
        &mut old_vm,
        "metadata_result",
        &[old_policy.clone(), Value::string(LOGIN_IDS[0])],
    );
    assert_eq!(error_code(&old_missing), "credential_not_found");
    let old_newly_added = invoke(
        &mut old_vm,
        "metadata_result",
        &[old_policy, Value::string("login-gamma")],
    );
    assert_eq!(error_code(&old_newly_added), "credential_not_admitted");

    let (mut new_vm, new_policy, new_snapshot) = bind(&auth);
    assert_eq!(field(&new_snapshot, "policy_generation"), &Value::Int(2));
    assert_eq!(
        field(&new_snapshot, "credential_refs"),
        &Value::array(vec![
            Value::string(LOGIN_IDS[1]),
            Value::string("login-gamma")
        ]),
    );
    let removed = invoke(
        &mut new_vm,
        "metadata_result",
        &[new_policy.clone(), Value::string(LOGIN_IDS[0])],
    );
    assert_eq!(error_code(&removed), "credential_not_admitted");
    let added = invoke(
        &mut new_vm,
        "metadata_result",
        &[new_policy, Value::string("login-gamma")],
    );
    assert_eq!(error_code(&added), "credential_not_found");
}

#[test]
fn login_revoke_and_cancellation_keep_typed_policy_boundaries() {
    for revoke in [false, true] {
        let home = FixtureHome::new(&LOGIN_IDS, true);
        let cancellation = cancellation();
        let auth =
            AuthHost::new_for_login(home.0.clone(), cancellation.clone()).expect("login host");
        let (mut vm, policy, _) = bind(&auth);
        if revoke {
            auth.revoke();
        } else {
            cancellation.request(CancellationReason::Requested);
        }
        let result = invoke(
            &mut vm,
            "metadata_result",
            &[policy, Value::string(LOGIN_IDS[0])],
        );
        assert_eq!(field(&result, "ok"), &Value::Bool(false));
        assert_eq!(error_code(&result), "policy_inactive");
        if !revoke {
            assert_eq!(
                field(field(&result, "error"), "cancelled"),
                &Value::Bool(true)
            );
        }
        assert_eq!(vm.host_context().resource_count(), 2);
    }
}

#[test]
fn login_legacy_strict_and_single_id_enrollment_reject_unselected_missing_references() {
    let home = FixtureHome::new(&LOGIN_IDS, true);
    let strict = AuthHost::new(home.0.clone(), cancellation())
        .err()
        .expect("strict continues requiring every configured credential");
    assert_eq!(strict, "credential_reference_invalid");
    let enrollment = AuthHost::new_for_enrollment(home.0.clone(), cancellation(), LOGIN_IDS[0])
        .err()
        .expect("single-ID enrollment only exempts its selected reference");
    assert_eq!(enrollment, "credential_reference_invalid");
}

#[test]
fn login_constructor_rejects_corrupt_config_and_auth_without_artifacts() {
    let bad_config = FixtureHome::new(&LOGIN_IDS, true);
    let auth_before = fs::read(bad_config.0.join("auth.yaml")).expect("auth bytes");
    let bad_config_bytes = b"version: [\n";
    fs::write(bad_config.0.join("config.yaml"), bad_config_bytes).expect("corrupt config");
    let entries_before = bad_config.entries();
    let failure = AuthHost::new_for_login(bad_config.0.clone(), cancellation())
        .err()
        .expect("corrupt config is rejected");
    assert_eq!(failure, "config_invalid");
    assert_eq!(
        fs::read(bad_config.0.join("config.yaml")).expect("config unchanged"),
        bad_config_bytes
    );
    assert_eq!(
        fs::read(bad_config.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(bad_config.entries(), entries_before);

    let bad_auth = FixtureHome::new(&LOGIN_IDS, true);
    let auth_bytes = b"version: 1\ncredentials: [\n";
    fs::write(bad_auth.0.join("auth.yaml"), auth_bytes).expect("corrupt auth");
    let config_before = fs::read(bad_auth.0.join("config.yaml")).expect("config bytes");
    let entries_before = bad_auth.entries();
    let failure = AuthHost::new_for_login(bad_auth.0.clone(), cancellation())
        .err()
        .expect("corrupt auth is rejected");
    assert_eq!(failure, "auth_invalid");
    assert_eq!(
        fs::read(bad_auth.0.join("auth.yaml")).expect("auth unchanged"),
        auth_bytes
    );
    assert_eq!(
        fs::read(bad_auth.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(bad_auth.entries(), entries_before);
}
