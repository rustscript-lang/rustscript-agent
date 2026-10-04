use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::{
            OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
            ScriptedHttpsTransport,
        },
        store::AuthStore,
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

const MISSING: [&str; 3] = ["cmd-missing-a", "cmd-missing-b", "cmd-missing-c"];
const SNAPSHOT_RSS: &str = r#"
use config;
pub fn snapshot(home: resource<auth.host_home>) -> ConfigSnapshotEnvelope {
    config::load_snapshot(&home)
}
"#;
const METADATA_RSS: &str = r#"
use auth;
use config;
pub fn snapshot(home: resource<auth.host_home>) -> ConfigSnapshotEnvelope {
    config::load_snapshot(&home)
}
pub fn metadata_result(policy: resource<auth.policy>, credential_id: string) -> AuthMetadataResultEnvelope {
    auth::load_metadata_result(credential_id, &policy)
}
pub fn legacy_metadata(policy: resource<auth.policy>, credential_id: string) -> AuthMetadataEnvelope {
    auth::load_metadata(credential_id, &policy)
}
"#;
const DELETE_RSS: &str = r#"
use auth;
use config;
pub fn snapshot(home: resource<auth.host_home>) -> ConfigSnapshotEnvelope {
    config::load_snapshot(&home)
}
pub fn delete_result(policy: resource<auth.policy>, credential_id: string) -> AuthDeleteResultEnvelope {
    auth::delete_result(credential_id, &policy)
}
"#;
const COMMAND_ENROLLMENT_RSS: &str = r#"
use auth;
use config;
use oauth;
pub fn snapshot(home: resource<auth.host_home>) -> ConfigSnapshotEnvelope {
    config::load_snapshot(&home)
}
pub fn transport(request: TransportPublicRequest, credential_use: TransportCredentialUse) -> TransportResponseEnvelope {
    oauth::transport(&request, &credential_use)
}
pub fn capture(request: TransportPublicRequest, credential_use: TransportCredentialUse, payload: TransportPayloadIntent, capture_intent: TransportCaptureIntent) -> TransportCaptureEnvelope {
    oauth::transport_capture(&request, &credential_use, payload, capture_intent)
}
pub fn exchange_selected(request: TransportPublicRequest, credential_use: TransportCredentialUse, payload: TransportPayloadIntent) -> TransportResponseEnvelope {
    oauth::transport_payload(&request, &credential_use, payload)
}
pub fn save_result(request: SaveCredentialRequest) -> AuthSaveResultEnvelope {
    auth::save_if_generation_result(&request)
}
pub fn metadata_result(policy: resource<auth.policy>, credential_id: string) -> AuthMetadataResultEnvelope {
    auth::load_metadata_result(credential_id, &policy)
}
"#;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn with_missing_references(ids: &[&str]) -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture TEMP"),
        );
        let path = root.join(format!("auth-command-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("private fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let mut config: serde_yaml::Value =
            serde_yaml::from_slice(&fs::read(fixture.join("config.yaml")).expect("config fixture"))
                .expect("valid config fixture");
        let providers = config["providers"]
            .as_mapping_mut()
            .expect("providers mapping");
        let template = providers
            .get(serde_yaml::Value::String("openai-codex".into()))
            .expect("template provider")
            .clone();
        for (index, id) in ids.iter().enumerate() {
            let name = if index == 0 {
                "openai-codex".to_owned()
            } else {
                format!("command-provider-{index}")
            };
            let mut provider = template.clone();
            provider["auth"] = serde_yaml::Value::String((*id).to_owned());
            providers.insert(serde_yaml::Value::String(name), provider);
        }
        fs::write(
            path.join("config.yaml"),
            serde_yaml::to_string(&config).expect("serialize synthetic config"),
        )
        .expect("write config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("auth fixture")
            .replace("1788440000000", "1900000000000")
            .replace("1788436400000", "1899996400000");
        fs::write(path.join("auth.yaml"), auth).expect("write synthetic auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        Self(path)
    }

    fn add_stored_credential(&self, id: &str) {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config_auth_rss/auth.yaml");
        let mut auth: serde_yaml::Value = serde_yaml::from_slice(
            &fs::read(self.0.join("auth.yaml")).expect("stored credentials before"),
        )
        .expect("auth YAML");
        let template: serde_yaml::Value =
            serde_yaml::from_slice(&fs::read(fixture).expect("synthetic credential fixture"))
                .expect("credential template");
        let template = template["credentials"]["fixture-codex"].clone();
        auth["credentials"][id] = template;
        fs::write(
            self.0.join("auth.yaml"),
            serde_yaml::to_string(&auth).expect("serialize auth fixture"),
        )
        .expect("write orphaned synthetic credential");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.0.join("auth.yaml"), fs::Permissions::from_mode(0o600))
                .expect("auth file mode");
        }
    }

    fn add_missing_reference(&self, id: &str) {
        let path = self.0.join("config.yaml");
        let mut config: serde_yaml::Value =
            serde_yaml::from_slice(&fs::read(&path).expect("config bytes")).expect("config YAML");
        let providers = config["providers"]
            .as_mapping_mut()
            .expect("providers mapping");
        let mut provider = providers
            .get(serde_yaml::Value::String("openai-codex".into()))
            .expect("provider template")
            .clone();
        provider["auth"] = serde_yaml::Value::String(id.to_owned());
        providers.insert(
            serde_yaml::Value::String("reload-added-provider".into()),
            provider,
        );
        fs::write(
            &path,
            serde_yaml::to_string(&config).expect("serialize config"),
        )
        .expect("add reload reference");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("config mode");
        }
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected named RSS record, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing field {name} in {value:?}"))
}

fn string(value: &Value) -> &str {
    let Value::String(value) = value else {
        panic!("expected RSS string, got {value:?}");
    };
    value
}

fn compile_vm(auth: &AuthHost, source: &str) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile real RSS against auth host catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth host catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted RSS catalog");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}

fn invoke_result(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, rustscript_vm::VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    invoke_result(vm, name, args).unwrap_or_else(|failure| panic!("RSS call {name}: {failure:?}"))
}

fn cancellation() -> RunCancellation {
    RunCancellation::with_timeout(Duration::from_secs(30))
}

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::string(key), value))
            .collect(),
    )
}

fn request(policy: &Value, credential_id: &str, path: &str, body: &str) -> Value {
    record(vec![
        ("policy_handle", policy.clone()),
        ("credential_id", Value::string(credential_id)),
        ("method", Value::string("POST")),
        ("path", Value::string(path)),
        (
            "public_headers",
            Value::array(vec![record(vec![
                ("name", Value::string("content-type")),
                ("value", Value::string("application/json")),
            ])]),
        ),
        ("public_body", Value::string(body)),
    ])
}

fn scripted_oauth(transport: Arc<ScriptedHttpsTransport>) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ))
}

#[test]
fn commands_snapshot_admits_missing_refs_and_orphan_without_writing_config_or_auth() {
    let home = FixtureHome::with_missing_references(&MISSING);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes before");
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes before");

    let strict = AuthHost::new(home.0.clone(), cancellation())
        .err()
        .expect("strict mode rejects missing configured credential refs");
    assert_eq!(strict, "credential_reference_invalid");
    let enrollment = AuthHost::new_for_enrollment(home.0.clone(), cancellation(), MISSING[0])
        .err()
        .expect("one-ID enrollment does not exempt other missing refs");
    assert_eq!(enrollment, "credential_reference_invalid");

    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation())
        .expect("trusted command snapshot tolerates missing configured refs");
    let mut vm = compile_vm(&auth, SNAPSHOT_RSS);
    let bound = auth.bind_vm(&mut vm).expect("bind real host-home resource");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let refs = field(&snapshot, "credential_refs");
    assert_eq!(
        refs,
        Value::array(
            [MISSING[0], MISSING[1], MISSING[2], "fixture-codex"]
                .into_iter()
                .map(Value::string)
                .collect(),
        ),
        "snapshot contains bounded configured refs plus the orphaned stored ID",
    );
    let providers = field(&field(&snapshot, "public_config"), "providers");
    let Value::Array(providers) = providers else {
        panic!("public providers are a typed array");
    };
    assert_eq!(providers.len(), MISSING.len());
    for provider in providers.iter() {
        assert!(MISSING.contains(&string(&field(provider, "auth"))));
    }
    let public = format!("{snapshot:?}");
    assert!(!public.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!public.contains("SYNTHETIC_REFRESH_TOKEN"));
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before,
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before,
    );
}

#[test]
fn metadata_result_is_fully_named_and_distinguishes_missing_from_backend_failure() {
    let home = FixtureHome::with_missing_references(&MISSING);
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation()).expect("commands host");
    let mut vm = compile_vm(&auth, METADATA_RSS);
    let bound = auth.bind_vm(&mut vm).expect("bind real host-home resource");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let policy = field(&snapshot, "policy_handle");

    let present = invoke(
        &mut vm,
        "metadata_result",
        &[policy.clone(), Value::string("fixture-codex")],
    );
    assert_eq!(field(&present, "ok"), Value::Bool(true));
    assert_eq!(field(&present, "error"), Value::Null);
    let value = field(&present, "value");
    assert_eq!(field(&value, "ok"), Value::Bool(true));
    assert_eq!(field(&value, "error"), Value::Null);
    assert_eq!(field(&value, "outcome"), Value::string("loaded"));
    let metadata = field(&value, "metadata");
    assert_eq!(
        field(&metadata, "credential_id"),
        Value::string("fixture-codex")
    );
    assert_eq!(field(&metadata, "generation"), Value::Int(4));
    assert_eq!(field(&metadata, "has_refresh_token"), Value::Bool(true));

    let missing = invoke(
        &mut vm,
        "metadata_result",
        &[policy.clone(), Value::string(MISSING[0])],
    );
    assert_eq!(field(&missing, "ok"), Value::Bool(false));
    assert_eq!(field(&missing, "value"), Value::Null);
    assert_eq!(
        field(&field(&missing, "error"), "code"),
        Value::string("credential_not_found"),
    );
    let denied = invoke(
        &mut vm,
        "metadata_result",
        &[policy.clone(), Value::string("not-admitted")],
    );
    assert_eq!(field(&denied, "ok"), Value::Bool(false));
    assert_eq!(field(&denied, "value"), Value::Null);
    assert_eq!(
        field(&field(&denied, "error"), "code"),
        Value::string("credential_not_admitted"),
    );

    let legacy = invoke_result(
        &mut vm,
        "legacy_metadata",
        &[policy, Value::string(MISSING[0])],
    )
    .expect_err("legacy metadata preserves its historical trap contract");
    assert!(legacy.to_string().contains("credential_unavailable"));
    let visible = format!("{present:?} {missing:?} {denied:?} {legacy:?}");
    assert!(!visible.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!visible.contains("SYNTHETIC_REFRESH_TOKEN"));
    assert!(!visible.contains(home.0.to_string_lossy().as_ref()));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn delete_result_removes_an_orphan_through_atomic_store_and_preserves_other_credentials() {
    const PEER: &str = "command-orphan-peer";
    let home = FixtureHome::with_missing_references(&MISSING);
    home.add_stored_credential(PEER);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes before");
    let store = AuthStore::from_home(&home.0).expect("real auth store");
    let peer_before = store
        .load_metadata(PEER)
        .expect("unrelated stored credential");
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation()).expect("commands host");
    let mut vm = compile_vm(&auth, DELETE_RSS);
    let bound = auth.bind_vm(&mut vm).expect("bind real host-home resource");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let policy = field(&snapshot, "policy_handle");

    let deleted = invoke(
        &mut vm,
        "delete_result",
        &[policy, Value::string("fixture-codex")],
    );
    assert_eq!(field(&deleted, "ok"), Value::Bool(true));
    assert_eq!(field(&deleted, "error"), Value::Null);
    let value = field(&deleted, "value");
    assert_eq!(field(&value, "deleted"), Value::Bool(true));
    assert!(!format!("{deleted:?}").contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!format!("{deleted:?}").contains("SYNTHETIC_REFRESH_TOKEN"));
    assert!(
        store.load_metadata("fixture-codex").is_err(),
        "the selected orphan is removed from the actual store",
    );
    assert_eq!(
        store.load_metadata(PEER).expect("peer remains"),
        peer_before
    );
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before,
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn commands_snapshot_saves_a_generation_zero_native_flow_and_reload_stays_frozen() {
    const DEVICE: &str = "COMMAND_DEVICE_PRIVATE_761c";
    const CODE: &str = "COMMAND_CODE_PRIVATE_8ab2";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    const ACCESS: &str = "COMMAND_ACCESS_PRIVATE_9f51";
    const REFRESH: &str = "COMMAND_REFRESH_PRIVATE_23d8";
    const RELOADED: &str = "cmd-reload-added";
    let target = MISSING[0];
    let home = FixtureHome::with_missing_references(&MISSING);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes before");
    let store = AuthStore::from_home(&home.0).expect("real auth store");
    assert!(store.load_metadata(target).is_err(), "target starts absent");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation())
        .expect("trusted command mode")
        .with_oauth_host(scripted_oauth(transport.clone()));
    let mut vm = compile_vm(&auth, COMMAND_ENROLLMENT_RSS);
    let bound = auth
        .bind_vm(&mut vm)
        .expect("bind native host-home resource");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    assert_eq!(field(&snapshot, "policy_generation"), Value::Int(1));
    let policy = field(&snapshot, "policy_handle");

    transport.push_raw(
        200,
        &format!(r#"{{"device_code":"{DEVICE}","user_code":"TEST-USER","verification_uri":"https://auth.openai.com/device","expires_in":900,"interval":5}}"#),
    );
    let started = invoke(
        &mut vm,
        "transport",
        &[
            request(
                &policy,
                target,
                "/api/accounts/deviceauth/usercode",
                r#"{"client_id":"public-client-id"}"#,
            ),
            record(vec![("kind", Value::string("none"))]),
        ],
    );
    assert_eq!(field(&started, "status"), Value::Int(200));
    let device = field(&started, "device_handle");

    transport.push_raw(
        200,
        &format!(
            r#"{{"authorization_code":"{CODE}","code_verifier":"{VERIFIER}","public":"captured"}}"#
        ),
    );
    let captured = invoke(
        &mut vm,
        "capture",
        &[
            request(
                &policy,
                target,
                "/oauth/token",
                r#"{"grant_type":"device_code"}"#,
            ),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device),
            ]),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("device")),
                ("device_field", Value::string("device_id")),
            ]),
            record(vec![
                ("code_field", Value::string("authorization_code")),
                (
                    "redirect_uri",
                    Value::string("https://auth.openai.com/deviceauth/callback"),
                ),
            ]),
        ],
    );
    let code = field(&captured, "code_handle");
    let verifier = field(&captured, "verifier_handle");

    transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{ACCESS}","refresh_token":"{REFRESH}","token_type":"Bearer","expires_in":3600,"public":"exchanged"}}"#),
    );
    let exchanged = invoke(
        &mut vm,
        "exchange_selected",
        &[
            request(
                &policy,
                target,
                "/oauth/token",
                r#"{"grant_type":"authorization_code"}"#,
            ),
            record(vec![
                ("kind", Value::string("code_verifier")),
                ("code_handle", code),
                ("verifier_handle", verifier),
            ]),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("authorization_code")),
                ("code_field", Value::string("authorization_code")),
            ]),
        ],
    );
    let saved = invoke(
        &mut vm,
        "save_result",
        &[record(vec![
            ("credential_id", Value::string(target)),
            ("expected_generation", Value::Int(0)),
            ("policy_handle", policy.clone()),
            (
                "metadata",
                record(vec![
                    ("provider", Value::string("openai-codex")),
                    ("kind", Value::string("oauth")),
                    ("source", Value::string("synthetic-command-test")),
                    ("token_type", Value::string("Bearer")),
                    ("expires_at_ms", Value::Int(1_900_000_000_000)),
                    ("scopes", Value::array(vec![])),
                    ("account_id", Value::string("synthetic-command-account")),
                    ("generation", Value::Int(0)),
                    ("status", Value::string("active")),
                    ("last_refresh_at_ms", Value::Null),
                    ("has_refresh_token", Value::Bool(true)),
                ]),
            ),
            ("access_slot", field(&exchanged, "access_slot")),
            ("refresh_action", Value::string("replace")),
            ("refresh_slot", field(&exchanged, "refresh_slot")),
        ])],
    );
    assert_eq!(field(&saved, "ok"), Value::Bool(true));
    let save_value = field(&saved, "value");
    assert_eq!(field(&save_value, "outcome"), Value::string("committed"));
    assert_eq!(
        field(&field(&save_value, "metadata"), "generation"),
        Value::Int(1),
        "a native save admitted at generation zero commits generation one",
    );
    assert_eq!(
        store
            .load_metadata(target)
            .expect("saved metadata")
            .generation,
        1
    );
    assert_eq!(
        store
            .load_metadata("fixture-codex")
            .expect("unrelated credential")
            .generation,
        4,
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    let public = format!("{snapshot:?} {started:?} {captured:?} {exchanged:?} {saved:?}");
    for secret in [DEVICE, CODE, VERIFIER, ACCESS, REFRESH] {
        assert!(
            !public.contains(secret),
            "secret escaped a typed RSS result"
        );
    }
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged by save"),
        config_before,
    );

    home.add_missing_reference(RELOADED);
    let config_after_edit = fs::read(home.0.join("config.yaml")).expect("edited config");
    let auth_after_save = fs::read(home.0.join("auth.yaml")).expect("persisted auth bytes");
    assert_eq!(auth.reload().expect("reload commands admission"), 2);
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("reload is read-only"),
        config_after_edit
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("reload is read-only"),
        auth_after_save
    );

    let old_snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    assert_eq!(field(&old_snapshot, "policy_generation"), Value::Int(1));
    let old_denied = invoke(
        &mut vm,
        "metadata_result",
        &[policy.clone(), Value::string(RELOADED)],
    );
    assert_eq!(field(&old_denied, "ok"), Value::Bool(false));
    assert_eq!(field(&old_denied, "value"), Value::Null);
    assert_eq!(
        field(&field(&old_denied, "error"), "code"),
        Value::string("credential_not_admitted"),
    );

    let mut new_vm = compile_vm(&auth, COMMAND_ENROLLMENT_RSS);
    let new_bound = auth.bind_vm(&mut new_vm).expect("bind after reload");
    let new_snapshot = invoke(&mut new_vm, "snapshot", &[field(&new_bound, "host_home")]);
    assert_eq!(field(&new_snapshot, "policy_generation"), Value::Int(2));
    let refs = field(&new_snapshot, "credential_refs");
    let Value::Array(refs) = refs else {
        panic!("reloaded refs are a typed array");
    };
    assert!(refs.iter().any(|value| string(value) == RELOADED));
    let new_policy = field(&new_snapshot, "policy_handle");
    let latest = invoke(
        &mut new_vm,
        "metadata_result",
        &[new_policy.clone(), Value::string(target)],
    );
    assert_eq!(field(&latest, "ok"), Value::Bool(true));
    assert_eq!(
        field(&field(&field(&latest, "value"), "metadata"), "generation"),
        Value::Int(1),
    );
    let new_missing = invoke(
        &mut new_vm,
        "metadata_result",
        &[new_policy, Value::string(RELOADED)],
    );
    assert_eq!(field(&new_missing, "ok"), Value::Bool(false));
    assert_eq!(field(&new_missing, "value"), Value::Null);
    assert_eq!(
        field(&field(&new_missing, "error"), "code"),
        Value::string("credential_not_found"),
    );
    assert_eq!(new_vm.host_context().resource_count(), 2);
}

#[test]
fn delete_result_removes_configured_credential_and_preserves_peer_and_config_bytes() {
    const PEER: &str = "configured-delete-peer";
    let home = FixtureHome::with_missing_references(&["fixture-codex"]);
    home.add_stored_credential(PEER);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let store = AuthStore::from_home(&home.0).expect("real auth store");
    let peer_before = store.load_metadata(PEER).expect("peer credential");
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation()).expect("commands host");
    let mut vm = compile_vm(&auth, DELETE_RSS);
    let bound = auth.bind_vm(&mut vm).expect("bind real host-home resource");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let policy = field(&snapshot, "policy_handle");

    let deleted = invoke(
        &mut vm,
        "delete_result",
        &[policy, Value::string("fixture-codex")],
    );
    assert_eq!(field(&deleted, "ok"), Value::Bool(true));
    assert_eq!(
        field(&field(&deleted, "value"), "deleted"),
        Value::Bool(true)
    );
    assert!(store.load_metadata("fixture-codex").is_err());
    assert_eq!(
        store.load_metadata(PEER).expect("peer preserved"),
        peer_before
    );
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn commands_union_includes_64_ids_and_rejects_the_65th() {
    let at_limit: Vec<String> = (0..63)
        .map(|index| format!("command-limit-{index}"))
        .collect();
    let at_limit_refs: Vec<&str> = at_limit.iter().map(String::as_str).collect();
    let home = FixtureHome::with_missing_references(&at_limit_refs);
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation())
        .expect("configured refs plus one stored orphan fit exactly 64");
    let mut vm = compile_vm(&auth, SNAPSHOT_RSS);
    let bound = auth
        .bind_vm(&mut vm)
        .expect("bind at-limit command snapshot");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let refs = field(&snapshot, "credential_refs");
    let Value::Array(refs) = refs else {
        panic!("credential refs are a typed array");
    };
    assert_eq!(refs.len(), 64);
    assert!(refs.iter().any(|value| string(value) == "fixture-codex"));
    assert!(refs.iter().any(|value| string(value) == at_limit[62]));
    assert_eq!(vm.host_context().resource_count(), 2);

    let over_limit: Vec<String> = (0..64)
        .map(|index| format!("command-over-limit-{index}"))
        .collect();
    let over_limit_refs: Vec<&str> = over_limit.iter().map(String::as_str).collect();
    let over_home = FixtureHome::with_missing_references(&over_limit_refs);
    let config_before = fs::read(over_home.0.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(over_home.0.join("auth.yaml")).expect("auth bytes");
    let rejection = AuthHost::new_for_commands(over_home.0.clone(), cancellation())
        .err()
        .expect("configured refs plus stored orphan exceed 64");
    assert_eq!(rejection, "credential_limit_exceeded");
    assert_eq!(
        fs::read(over_home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(over_home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
}

#[test]
fn commands_constructor_rejects_invalid_config_credential_ids() {
    let home = FixtureHome::with_missing_references(&["invalid/credential"]);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let rejection = AuthHost::new_for_commands(home.0.clone(), cancellation())
        .err()
        .expect("invalid configured credential ID");
    assert_eq!(rejection, "invalid_credential_id");
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
}

#[test]
fn commands_snapshot_treats_absent_auth_as_empty_without_creating_auth_file() {
    let home = FixtureHome::with_missing_references(&MISSING);
    fs::remove_file(home.0.join("auth.yaml")).expect("remove synthetic auth fixture");
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let strict = AuthHost::new(home.0.clone(), cancellation())
        .err()
        .expect("strict mode still rejects missing refs with absent auth file");
    assert_eq!(strict, "credential_reference_invalid");
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation())
        .expect("commands mode reads absent auth as empty");
    let mut vm = compile_vm(&auth, SNAPSHOT_RSS);
    let bound = auth.bind_vm(&mut vm).expect("bind command home");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    assert_eq!(
        field(&snapshot, "credential_refs"),
        Value::array(MISSING.iter().copied().map(Value::string).collect()),
    );
    assert!(!home.0.join("auth.yaml").exists());
    assert_eq!(auth.reload().expect("reload absent auth"), 2);
    assert!(!home.0.join("auth.yaml").exists());
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
}

#[test]
fn command_result_rejects_a_real_wrong_type_resource_without_deleting() {
    let home = FixtureHome::with_missing_references(&MISSING);
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation()).expect("commands host");
    let mut vm = compile_vm(&auth, DELETE_RSS);
    let bound = auth
        .bind_vm(&mut vm)
        .expect("bind real auth host-home resource");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let failure = invoke_result(
        &mut vm,
        "delete_result",
        &[field(&bound, "host_home"), Value::string("fixture-codex")],
    )
    .expect_err("auth.host_home cannot stand in for auth.policy");
    assert!(!format!("{failure:?} {failure}").contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!format!("{failure:?} {failure}").contains("SYNTHETIC_REFRESH_TOKEN"));
    assert_eq!(
        AuthStore::from_home(&home.0)
            .expect("store")
            .load_metadata("fixture-codex")
            .unwrap()
            .generation,
        4
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(field(&snapshot, "policy_generation"), Value::Int(1));
}

#[test]
fn command_result_rejects_a_policy_resource_from_another_vm_without_mutation() {
    let home = FixtureHome::with_missing_references(&MISSING);
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation()).expect("commands host");
    let mut origin_vm = compile_vm(&auth, DELETE_RSS);
    let origin_bound = auth.bind_vm(&mut origin_vm).expect("bind origin owner");
    let origin_snapshot = invoke(
        &mut origin_vm,
        "snapshot",
        &[field(&origin_bound, "host_home")],
    );
    let foreign_policy = field(&origin_snapshot, "policy_handle");

    let mut target_vm = compile_vm(&auth, DELETE_RSS);
    let target_bound = auth.bind_vm(&mut target_vm).expect("bind target owner");
    let target_snapshot = invoke(
        &mut target_vm,
        "snapshot",
        &[field(&target_bound, "host_home")],
    );
    let failure = invoke_result(
        &mut target_vm,
        "delete_result",
        &[foreign_policy, Value::string("fixture-codex")],
    )
    .expect_err("a native policy resource belongs to its issuing VM arena");
    assert!(!format!("{failure:?} {failure}").contains("SYNTHETIC_ACCESS_TOKEN"));
    assert!(!format!("{failure:?} {failure}").contains("SYNTHETIC_REFRESH_TOKEN"));
    assert!(
        AuthStore::from_home(&home.0)
            .expect("store")
            .load_metadata("fixture-codex")
            .is_ok(),
        "foreign-resource rejection cannot delete the credential",
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(origin_vm.host_context().resource_count(), 2);
    assert_eq!(target_vm.host_context().resource_count(), 2);
    assert_eq!(field(&target_snapshot, "policy_generation"), Value::Int(1));
}

#[test]
fn cancelled_and_deadline_command_owners_cannot_delete_credentials() {
    for deadline in [false, true] {
        let home = FixtureHome::with_missing_references(&MISSING);
        let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
        let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
        let registration =
            AuthHost::new_for_commands(home.0.clone(), cancellation()).expect("registration host");
        let mut vm = compile_vm(&registration, DELETE_RSS);
        let cancellation = RunCancellation::with_timeout(if deadline {
            Duration::from_millis(600)
        } else {
            Duration::from_secs(30)
        });
        let auth = AuthHost::new_for_commands(home.0.clone(), cancellation.clone())
            .expect("mutation owner");
        let bound = auth.bind_vm(&mut vm).expect("bind mutation owner");
        let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
        let policy = field(&snapshot, "policy_handle");
        if deadline {
            std::thread::sleep(Duration::from_millis(650));
        } else {
            cancellation.request(CancellationReason::Requested);
        }

        let rejected = invoke(
            &mut vm,
            "delete_result",
            &[policy, Value::string("fixture-codex")],
        );
        assert_eq!(field(&rejected, "ok"), Value::Bool(false));
        assert_eq!(field(&rejected, "value"), Value::Null);
        let failure = field(&rejected, "error");
        assert_eq!(field(&failure, "code"), Value::string("policy_inactive"));
        assert_eq!(field(&failure, "cancelled"), Value::Bool(!deadline));
        assert_eq!(field(&failure, "deadline_exceeded"), Value::Bool(deadline));
        assert_eq!(
            AuthStore::from_home(&home.0)
                .expect("store")
                .load_metadata("fixture-codex")
                .expect("credential remains")
                .generation,
            4,
        );
        assert_eq!(
            fs::read(home.0.join("config.yaml")).expect("config unchanged"),
            config_before
        );
        assert_eq!(
            fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
            auth_before
        );
        assert_eq!(vm.host_context().resource_count(), 2);
    }
}

#[test]
fn metadata_backend_failure_uses_static_code_without_path_or_file_text() {
    const BACKEND_TEXT: &str = "BACKEND_FAILURE_PRIVATE_yaml_fragment";
    let home = FixtureHome::with_missing_references(&MISSING);
    let auth = AuthHost::new_for_commands(home.0.clone(), cancellation()).expect("commands host");
    let mut vm = compile_vm(&auth, METADATA_RSS);
    let bound = auth.bind_vm(&mut vm).expect("bind command home");
    let snapshot = invoke(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    fs::write(
        home.0.join("auth.yaml"),
        format!("version: 1\ncredentials: [malformed\n{BACKEND_TEXT}"),
    )
    .expect("corrupt only the synthetic auth fixture");

    let failed = invoke(
        &mut vm,
        "metadata_result",
        &[policy, Value::string("fixture-codex")],
    );
    assert_eq!(field(&failed, "ok"), Value::Bool(false));
    assert_eq!(field(&failed, "value"), Value::Null);
    assert_eq!(
        field(&field(&failed, "error"), "code"),
        Value::string("corrupt_file"),
    );
    let visible = format!("{failed:?}");
    assert!(!visible.contains(BACKEND_TEXT));
    assert!(!visible.contains(home.0.to_string_lossy().as_ref()));
    assert!(!visible.contains("credentials: [malformed"));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn commands_constructor_rejects_corrupt_config_and_auth_files() {
    let invalid_config = FixtureHome::with_missing_references(&MISSING);
    let auth_before = fs::read(invalid_config.0.join("auth.yaml")).expect("auth before");
    let config_source = "version: [\n";
    fs::write(invalid_config.0.join("config.yaml"), config_source).expect("corrupt config syntax");
    let config_failure = AuthHost::new_for_commands(invalid_config.0.clone(), cancellation())
        .err()
        .expect("invalid config structure rejected");
    assert_eq!(config_failure, "config_invalid");
    assert_eq!(
        fs::read(invalid_config.0.join("config.yaml")).expect("config unchanged"),
        config_source.as_bytes(),
    );
    assert_eq!(
        fs::read(invalid_config.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before,
    );

    let corrupt_auth = FixtureHome::with_missing_references(&MISSING);
    let corrupt_source = "version: 1\ncredentials: [\n";
    fs::write(corrupt_auth.0.join("auth.yaml"), corrupt_source).expect("corrupt auth YAML");
    let auth_failure = AuthHost::new_for_commands(corrupt_auth.0.clone(), cancellation())
        .err()
        .expect("corrupt auth rejected");
    assert_eq!(auth_failure, "auth_invalid");
    assert_eq!(
        fs::read(corrupt_auth.0.join("auth.yaml")).expect("corrupt auth remains"),
        corrupt_source.as_bytes(),
    );
}

#[cfg(unix)]
#[test]
fn commands_constructor_rejects_insecure_auth_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let home = FixtureHome::with_missing_references(&MISSING);
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    fs::set_permissions(home.0.join("auth.yaml"), fs::Permissions::from_mode(0o644))
        .expect("make synthetic auth fixture insecure");
    let rejection = AuthHost::new_for_commands(home.0.clone(), cancellation())
        .err()
        .expect("insecure auth permissions rejected");
    assert!(!rejection.contains(home.0.to_string_lossy().as_ref()));
    assert!(!rejection.contains("SYNTHETIC_ACCESS_TOKEN"));
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );
    assert_eq!(
        fs::metadata(home.0.join("auth.yaml"))
            .expect("auth metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644,
    );
}
