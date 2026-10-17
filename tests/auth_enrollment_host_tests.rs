use rustscript_agent::{
    RunCancellation,
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

const TARGET: &str = "enrollment-target";

struct FixtureHome(PathBuf);
impl FixtureHome {
    fn new(empty_auth: bool) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!("auth-enrollment-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("private fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("fixture config")
            .replace("fixture-codex", TARGET)
            .replace("https://auth.openai.com", "https://auth.example.test")
            .replace(
                "https://chatgpt.com/backend-api/codex",
                "https://api.example.test/backend",
            );
        fs::write(path.join("config.yaml"), config).expect("copy synthetic config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            fs::set_permissions(path.join("config.yaml"), fs::Permissions::from_mode(0o600))
                .expect("config mode");
        }
        let home = Self(path);
        if empty_auth {
            home.write_auth("version: 1\ncredentials: {}\n");
        }
        home
    }
    fn write_auth(&self, contents: &str) {
        fs::write(self.0.join("auth.yaml"), contents).expect("synthetic auth");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.0.join("auth.yaml"), fs::Permissions::from_mode(0o600))
                .expect("auth mode");
        }
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

#[test]
fn enrollment_admits_missing_and_empty_auth_store_without_creating_credentials() {
    for empty_auth in [false, true] {
        let home = FixtureHome::new(empty_auth);
        let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
        let auth_before = fs::read(home.0.join("auth.yaml")).ok();
        let host = AuthHost::new_for_enrollment(home.0.clone(), cancellation(), TARGET)
            .expect("explicit enrollment admission");
        let (mut vm, policy, snapshot) = bind(&host);
        assert_eq!(
            field(&snapshot, "credential_refs"),
            Value::array(vec![Value::string(TARGET)])
        );
        let providers = field(&field(&snapshot, "public_config"), "providers");
        let Value::Array(providers) = providers else {
            panic!("public providers");
        };
        assert_eq!(field(&providers[0], "auth"), Value::string(TARGET));
        let failure = call_result(&mut vm, "metadata", &[Value::string(TARGET), policy])
            .expect_err("no placeholder metadata");
        assert!(failure.to_string().ends_with("credential_unavailable"));
        assert_no_secrets(&format!("{failure:?}\n{failure}"));
        assert_eq!(vm.host_context().resource_count(), 2);
        assert!(
            AuthStore::from_home(&home.0)
                .expect("store")
                .load()
                .expect("redacted auth")
                .credentials
                .is_empty()
        );
        assert_eq!(
            fs::read(home.0.join("config.yaml")).expect("config unchanged"),
            config_before
        );
        assert_eq!(fs::read(home.0.join("auth.yaml")).ok(), auth_before);
    }
}

#[test]
fn normal_constructor_rejects_missing_and_empty_auth_store() {
    for empty_auth in [false, true] {
        let home = FixtureHome::new(empty_auth);
        assert!(
            AuthStore::from_home(&home.0)
                .expect("store")
                .load()
                .expect("valid empty store")
                .credentials
                .is_empty()
        );
        let rejection = AuthHost::new(home.0.clone(), cancellation())
            .err()
            .expect("strict missing reference");
        assert_eq!(rejection, "credential_reference_invalid");
        assert_eq!(home.0.join("auth.yaml").exists(), empty_auth);
    }
}

const DEVICE: &str = "ENROLLMENT_DEVICE_PRIVATE_c319";
const CODE: &str = "ENROLLMENT_CODE_PRIVATE_b714";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const ACCESS: &str = "ENROLLMENT_ACCESS_PRIVATE_e751";
const REFRESH: &str = "ENROLLMENT_REFRESH_PRIVATE_a281";
const LOSER_ACCESS: &str = "ENROLLMENT_LOSER_ACCESS_PRIVATE_d217";

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected named record: {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing field {name}"))
}
fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::string(key), value))
            .collect(),
    )
}
fn call_result(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, rustscript_vm::VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}
fn call(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    call_result(vm, name, args).unwrap_or_else(|failure| panic!("{name}: {failure:?}"))
}
fn public_projection(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(value) => serde_json::Value::Bool(*value),
        Value::Int(value) => serde_json::json!(value),
        Value::String(value) => serde_json::Value::String(value.to_string()),
        Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(public_projection).collect())
        }
        Value::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    let Value::String(key) = key else {
                        panic!("public record key must be string");
                    };
                    (key.to_string(), public_projection(value))
                })
                .collect(),
        ),
        _ => panic!("unexpected public carrier: {value:?}"),
    }
}
fn assert_public(value: &Value) {
    let rendered = format!("{value:?}\n{}", public_projection(value));
    assert_no_secrets(&rendered);
}
fn assert_no_secrets(rendered: &str) {
    for secret in [
        DEVICE,
        CODE,
        VERIFIER,
        ACCESS,
        REFRESH,
        LOSER_ACCESS,
        "SYNTHETIC_ACCESS_TOKEN",
        "SYNTHETIC_REFRESH_TOKEN",
    ] {
        assert!(!rendered.contains(secret), "private data in public output");
    }
}
fn vm_for(auth: &AuthHost) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/enrollment_contract.rss");
    let source = fs::read_to_string(&path).expect("generic enrollment RSS contract");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile real enrollment contract against exact catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("restricted binding");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}
fn bind(auth: &AuthHost) -> (Vm, Value, Value) {
    let mut vm = vm_for(auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    assert_public(&snapshot);
    let policy = field(&snapshot, "policy_handle");
    assert_eq!(vm.host_context().resource_count(), 2);
    (vm, policy, snapshot)
}
fn enrollment_host(home: &FixtureHome, transport: &Arc<ScriptedHttpsTransport>) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    AuthHost::new_for_enrollment(home.0.clone(), cancellation(), TARGET)
        .expect("trusted enrollment host")
        .with_oauth_host(oauth)
}
fn request(policy: &Value, id: &str, body: &str) -> Value {
    record(vec![
        ("policy_handle", policy.clone()),
        ("credential_id", Value::string(id)),
        ("method", Value::string("POST")),
        ("path", Value::string("/oauth/token")),
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
fn native_count(auth: &AuthHost, expected: usize) {
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        expected
    );
    #[cfg(not(feature = "config-fixture"))]
    let _ = (auth, expected);
}
/// All capabilities are issued by real native responses, never fixture slots.
fn exchange(
    vm: &mut Vm,
    policy: &Value,
    auth: &AuthHost,
    transport: &Arc<ScriptedHttpsTransport>,
    refresh: bool,
    access: &str,
) -> Value {
    let roots = vm.host_context().resource_count();
    assert_eq!(roots, 2);
    native_count(auth, 0);
    transport.push_raw(200, &format!(r#"{{"device_code":"{DEVICE}","user_code":"TEST-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#));
    let started = call(
        vm,
        "transport",
        &[
            request(policy, TARGET, r#"{"client_id":"public-client-id"}"#),
            record(vec![("kind", Value::string("none"))]),
        ],
    );
    assert_public(&started);
    assert_eq!(field(&started, "status"), Value::Int(200));
    let device = field(&started, "device_handle");
    assert!(matches!(device, Value::Int(_)));
    assert_eq!(vm.host_context().resource_count(), roots + 1);
    native_count(auth, 1);
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url, "https://auth.example.test/oauth/token");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&sent[0].body).expect("start JSON")["client_id"],
        "public-client-id"
    );

    transport.push_raw(
        200,
        &format!(
            r#"{{"authorization_code":"{CODE}","code_verifier":"{VERIFIER}","public":"captured"}}"#
        ),
    );
    let captured = call(
        vm,
        "capture",
        &[
            request(policy, TARGET, r#"{"grant_type":"device_code"}"#),
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
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
        ],
    );
    assert_public(&captured);
    assert_eq!(
        field(&field(&captured, "response"), "body_without_secret_fields"),
        Value::string(r#"{"public":"captured"}"#)
    );
    assert!(matches!(field(&captured, "code_handle"), Value::Int(_)));
    assert!(matches!(field(&captured, "verifier_handle"), Value::Int(_)));
    assert_eq!(vm.host_context().resource_count(), roots + 2);
    native_count(auth, 1);
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let wire: serde_json::Value = serde_json::from_str(&sent[0].body).expect("native capture JSON");
    assert_eq!(wire["device_id"], DEVICE);
    assert_eq!(wire["grant_type"], "device_code");
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );

    let refresh_json = if refresh {
        format!(r#", "refresh_token":"{REFRESH}""#)
    } else {
        String::new()
    };
    transport.push_raw(200, &format!(r#"{{"access_token":"{access}"{refresh_json},"token_type":"Bearer","expires_in":3600,"public":"exchanged"}}"#));
    let exchanged = call(
        vm,
        "exchange_selected",
        &[
            request(policy, TARGET, r#"{"grant_type":"authorization_code"}"#),
            record(vec![
                ("kind", Value::string("code_verifier")),
                ("code_handle", field(&captured, "code_handle")),
                ("verifier_handle", field(&captured, "verifier_handle")),
            ]),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("authorization_code")),
                ("code_field", Value::string("authorization_code")),
            ]),
        ],
    );
    assert_public(&exchanged);
    assert!(!format!("{exchanged:?}").contains(access));
    assert_eq!(field(&exchanged, "status"), Value::Int(200));
    assert_eq!(
        field(&exchanged, "body_without_secret_fields"),
        Value::string(r#"{"expires_in":3600,"public":"exchanged","token_type":"Bearer"}"#)
    );
    assert!(matches!(field(&exchanged, "access_slot"), Value::Int(_)));
    assert_eq!(
        matches!(field(&exchanged, "refresh_slot"), Value::Int(_)),
        refresh
    );
    assert_eq!(
        vm.host_context().resource_count(),
        roots + 1 + usize::from(refresh)
    );
    native_count(auth, 0);
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let wire: serde_json::Value =
        serde_json::from_str(&sent[0].body).expect("native exchange JSON");
    assert_eq!(wire["authorization_code"], CODE);
    assert_eq!(wire["code_verifier"], VERIFIER);
    assert_eq!(wire["redirect_uri"], "https://auth.example.test/callback");
    assert_eq!(wire["grant_type"], "authorization_code");
    exchanged
}
fn save_request(policy: &Value, exchanged: &Value, expected: i64, refresh: bool) -> Value {
    record(vec![
        ("credential_id", Value::string(TARGET)),
        ("expected_generation", Value::Int(expected)),
        ("policy_handle", policy.clone()),
        (
            "metadata",
            record(vec![
                ("provider", Value::string("openai-codex")),
                ("kind", Value::string("oauth")),
                ("source", Value::string("synthetic-enrollment-test")),
                ("token_type", Value::string("Bearer")),
                ("expires_at_ms", Value::Int(1_900_000_000_000)),
                ("scopes", Value::array(vec![])),
                ("account_id", Value::string("synthetic-enrollment-account")),
                ("generation", Value::Int(expected)),
                ("status", Value::string("active")),
                ("last_refresh_at_ms", Value::Null),
                ("has_refresh_token", Value::Bool(refresh)),
            ]),
        ),
        ("access_slot", field(exchanged, "access_slot")),
        (
            "refresh_action",
            Value::string(if refresh { "replace" } else { "clear" }),
        ),
        ("refresh_slot", field(exchanged, "refresh_slot")),
    ])
}

fn first_enrollment(refresh: bool, empty_auth: bool) {
    let home = FixtureHome::new(empty_auth);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = enrollment_host(&home, &transport);
    let (mut vm, policy, snapshot) = bind(&auth);
    assert_eq!(
        field(&snapshot, "credential_refs"),
        Value::array(vec![Value::string(TARGET)])
    );
    let exchanged = exchange(&mut vm, &policy, &auth, &transport, refresh, ACCESS);
    let saved = call(
        &mut vm,
        "save",
        &[save_request(&policy, &exchanged, 0, refresh)],
    );
    assert_public(&saved);
    assert_eq!(field(&saved, "outcome"), Value::string("committed"));
    assert_eq!(
        field(&field(&saved, "metadata"), "generation"),
        Value::Int(1)
    );
    assert_eq!(
        field(&field(&saved, "metadata"), "has_refresh_token"),
        Value::Bool(refresh)
    );
    let metadata = AuthStore::from_home(&home.0)
        .expect("store")
        .load_metadata(TARGET)
        .expect("persisted metadata");
    assert_eq!(metadata.generation, 1);
    assert_eq!(metadata.has_refresh_token, refresh);
    assert_eq!(vm.host_context().resource_count(), 2);
    native_count(&auth, 0);
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    AuthHost::new(home.0.clone(), cancellation()).expect("ordinary admission after enrollment");
}

#[test]
fn actual_rss_first_enrollment_with_refresh_commits_generation_zero_to_one() {
    first_enrollment(true, false);
}

#[test]
fn actual_rss_first_enrollment_without_refresh_clears_new_entry() {
    first_enrollment(false, true);
}

const OTHER: &str = "other-credential";

impl FixtureHome {
    fn add_reference(&self, provider_name: &str, credential_id: &str) {
        let path = self.0.join("config.yaml");
        let mut config: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(&path).expect("config"))
                .expect("fixture YAML");
        let mut provider = config["providers"]["openai-codex"].clone();
        provider["auth"] = serde_yaml::Value::String(credential_id.to_owned());
        config["providers"][provider_name] = provider;
        fs::write(path, serde_yaml::to_string(&config).expect("config YAML"))
            .expect("add explicit reference");
    }
    fn existing_credentials(&self, ids: &[&str]) {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config_auth_rss/auth.yaml");
        let source = fs::read_to_string(fixture)
            .expect("synthetic credential fixture")
            .replace("1788440000000", "1900000000000");
        let mut auth: serde_yaml::Value = serde_yaml::from_str(&source).expect("auth YAML");
        let template = auth["credentials"]["fixture-codex"].clone();
        let mut credentials = serde_yaml::Mapping::new();
        for id in ids {
            credentials.insert(
                serde_yaml::Value::String((*id).to_owned()),
                template.clone(),
            );
        }
        auth["credentials"] = serde_yaml::Value::Mapping(credentials);
        self.write_auth(&serde_yaml::to_string(&auth).expect("auth fixture YAML"));
    }
}

#[test]
fn enrollment_rejects_invalid_and_unreferenced_literal_targets() {
    for (id, expected) in [
        ("", "invalid_credential_id"),
        (" enrollment-target", "invalid_credential_id"),
        ("enrollment-target/child", "invalid_credential_id"),
        ("ENROLLMENT-TARGET", "credential_not_admitted"),
        ("unreferenced", "credential_not_admitted"),
        ("openai-codex", "credential_not_admitted"),
    ] {
        let home = FixtureHome::new(false);
        let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
        let failure = AuthHost::new_for_enrollment(home.0.clone(), cancellation(), id)
            .err()
            .expect("unadmitted ID");
        assert_eq!(failure, expected);
        assert_no_secrets(&failure);
        assert_eq!(
            fs::read(home.0.join("config.yaml")).expect("config bytes"),
            config_before
        );
        assert!(!home.0.join("auth.yaml").exists());
    }
}

#[test]
fn enrollment_exemption_rejects_unrelated_missing_reference_for_absent_and_existing_target() {
    for target_exists in [false, true] {
        let home = FixtureHome::new(false);
        home.add_reference("another-provider", OTHER);
        if target_exists {
            home.existing_credentials(&[TARGET]);
        }
        let auth_before = fs::read(home.0.join("auth.yaml")).ok();
        let failure = AuthHost::new_for_enrollment(home.0.clone(), cancellation(), TARGET)
            .err()
            .expect("other missing reference");
        assert_eq!(failure, "credential_reference_invalid");
        assert_eq!(
            AuthHost::new(home.0.clone(), cancellation())
                .err()
                .expect("strict validation"),
            "credential_reference_invalid"
        );
        assert_eq!(fs::read(home.0.join("auth.yaml")).ok(), auth_before);
    }
}

#[test]
fn enrollment_exempts_all_and_only_exact_selected_references_without_rewriting_config() {
    let home = FixtureHome::new(false);
    home.add_reference("same-target-provider", TARGET);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let host = AuthHost::new_for_enrollment(home.0.clone(), cancellation(), TARGET)
        .expect("same explicit target");
    let (_vm, _policy, snapshot) = bind(&host);
    assert_eq!(
        field(&snapshot, "credential_refs"),
        Value::array(vec![Value::string(TARGET)])
    );
    let Value::Array(providers) = field(&field(&snapshot, "public_config"), "providers") else {
        panic!("public providers");
    };
    assert_eq!(providers.len(), 2);
    for provider in providers.iter() {
        assert_eq!(field(provider, "auth"), Value::string(TARGET));
    }
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config bytes"),
        config_before
    );
    assert!(!home.0.join("auth.yaml").exists());
}

#[test]
fn enrollment_denies_other_valid_credential_without_damaging_target_slots_or_store() {
    let home = FixtureHome::new(false);
    home.add_reference("other-provider", OTHER);
    home.existing_credentials(&[OTHER]);
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let store = AuthStore::from_home(&home.0).expect("store");
    let other_before = store.load_metadata(OTHER).expect("other metadata");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = enrollment_host(&home, &transport);
    let (mut vm, policy, snapshot) = bind(&auth);
    assert_eq!(
        field(&snapshot, "credential_refs"),
        Value::array(vec![Value::string(TARGET)])
    );
    let exchanged = exchange(&mut vm, &policy, &auth, &transport, true, ACCESS);
    let resources = vm.host_context().resource_count();
    for (export, args) in [
        ("metadata", vec![Value::string(OTHER), policy.clone()]),
        (
            "access_handle",
            vec![Value::string(OTHER), Value::Int(4), policy.clone()],
        ),
        (
            "transport",
            vec![
                request(&policy, OTHER, "{}"),
                record(vec![("kind", Value::string("none"))]),
            ],
        ),
    ] {
        let failure = call_result(&mut vm, export, &args).expect_err("single credential policy");
        assert!(failure.to_string().ends_with("credential_not_admitted"));
        assert_no_secrets(&format!("{failure:?}\n{failure}"));
        assert!(transport.take_sent().is_empty());
        assert_eq!(vm.host_context().resource_count(), resources);
        native_count(&auth, 0);
        assert!(fs::read(home.0.join("auth.yaml")).expect("auth bytes") == auth_before);
    }
    let saved = call(
        &mut vm,
        "save",
        &[save_request(&policy, &exchanged, 0, true)],
    );
    assert_eq!(field(&saved, "outcome"), Value::string("committed"));
    assert_public(&saved);
    assert_eq!(
        store
            .load_metadata(OTHER)
            .expect("unchanged other metadata"),
        other_before
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    native_count(&auth, 0);
}

#[test]
fn actual_rss_reenrollment_preserves_generation_four_and_other_credential() {
    let home = FixtureHome::new(false);
    home.add_reference("other-provider", OTHER);
    home.existing_credentials(&[TARGET, OTHER]);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let auth_before = fs::read(home.0.join("auth.yaml")).expect("auth bytes");
    let original: serde_yaml::Value =
        serde_yaml::from_slice(&auth_before).expect("private auth fixture");
    let store = AuthStore::from_home(&home.0).expect("store");
    let other_before = store.load_metadata(OTHER).expect("other metadata");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = enrollment_host(&home, &transport);
    let (mut vm, policy, _snapshot) = bind(&auth);
    let exchanged = exchange(&mut vm, &policy, &auth, &transport, true, ACCESS);
    let failure = call_result(
        &mut vm,
        "save",
        &[save_request(&policy, &exchanged, 0, true)],
    )
    .expect_err("real generation four slots cannot save as generation zero");
    assert!(failure.to_string().ends_with("save_rejected"));
    assert_no_secrets(&format!("{failure:?}\n{failure}"));
    assert!(fs::read(home.0.join("auth.yaml")).expect("auth bytes") == auth_before);
    assert_eq!(vm.host_context().resource_count(), 4);
    let saved = call(
        &mut vm,
        "save",
        &[save_request(&policy, &exchanged, 4, true)],
    );
    assert_public(&saved);
    assert_eq!(field(&saved, "outcome"), Value::string("committed"));
    assert_eq!(
        field(&field(&saved, "metadata"), "generation"),
        Value::Int(5)
    );
    assert_eq!(
        store
            .load_metadata(TARGET)
            .expect("target metadata")
            .generation,
        5
    );
    assert_eq!(
        store.load_metadata(OTHER).expect("other metadata"),
        other_before
    );
    let updated: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(home.0.join("auth.yaml")).expect("private persisted bytes"),
    )
    .expect("private persisted YAML");
    assert!(
        original["credentials"][OTHER] == updated["credentials"][OTHER],
        "unselected private credential changed"
    );
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config bytes"),
        config_before
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    native_count(&auth, 0);
}

#[test]
fn independent_enrollment_owners_frozen_at_zero_adopt_winner_without_overwrite() {
    let home = FixtureHome::new(false);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let first_transport = Arc::new(ScriptedHttpsTransport::new());
    let second_transport = Arc::new(ScriptedHttpsTransport::new());
    let first = enrollment_host(&home, &first_transport);
    let second = enrollment_host(&home, &second_transport);
    let (mut first_vm, first_policy, _) = bind(&first);
    let (mut second_vm, second_policy, _) = bind(&second);
    let winner = exchange(
        &mut first_vm,
        &first_policy,
        &first,
        &first_transport,
        true,
        ACCESS,
    );
    let loser = exchange(
        &mut second_vm,
        &second_policy,
        &second,
        &second_transport,
        true,
        LOSER_ACCESS,
    );
    let committed = call(
        &mut first_vm,
        "save",
        &[save_request(&first_policy, &winner, 0, true)],
    );
    assert_public(&committed);
    assert_eq!(field(&committed, "outcome"), Value::string("committed"));
    assert_eq!(
        field(&field(&committed, "metadata"), "generation"),
        Value::Int(1)
    );
    let winner_bytes = fs::read(home.0.join("auth.yaml")).expect("persisted winner");
    let adopted = call(
        &mut second_vm,
        "save",
        &[save_request(&second_policy, &loser, 0, true)],
    );
    assert_public(&adopted);
    assert_eq!(field(&adopted, "outcome"), Value::string("adopted"));
    assert_eq!(field(&adopted, "metadata"), field(&committed, "metadata"));
    assert!(fs::read(home.0.join("auth.yaml")).expect("persisted winner remains") == winner_bytes);
    assert_eq!(
        AuthStore::from_home(&home.0)
            .expect("store")
            .load_metadata(TARGET)
            .expect("winner metadata")
            .generation,
        1
    );
    for (vm, auth, slots) in [
        (&mut first_vm, &first, &winner),
        (&mut second_vm, &second, &loser),
    ] {
        assert_eq!(
            vm.host_context().resource_count(),
            2,
            "terminal candidates leave Core without resetting roots"
        );
        native_count(auth, 0);
        for name in ["access_slot", "refresh_slot"] {
            let failure = call_result(vm, "close_slot", &[field(slots, name)])
                .expect_err("terminal slot Core entry already closed");
            assert_no_secrets(&format!("{failure:?}\n{failure}"));
            assert_eq!(vm.host_context().resource_count(), 2);
        }
    }
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config bytes"),
        config_before
    );
}

#[test]
fn reload_uses_generation_one_for_future_binds_and_keeps_old_owner_frozen_at_zero() {
    let home = FixtureHome::new(false);
    home.add_reference("other-provider", OTHER);
    home.existing_credentials(&[OTHER]);
    let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = enrollment_host(&home, &transport);
    let (mut old_vm, old_policy, old_snapshot) = bind(&auth);
    let initial = exchange(&mut old_vm, &old_policy, &auth, &transport, true, ACCESS);
    let committed = call(
        &mut old_vm,
        "save",
        &[save_request(&old_policy, &initial, 0, true)],
    );
    assert_eq!(field(&committed, "outcome"), Value::string("committed"));
    assert_public(&committed);
    let generation_one_bytes = fs::read(home.0.join("auth.yaml")).expect("generation one bytes");
    assert_eq!(auth.reload().expect("reload trusted selection"), 2);
    let (mut new_vm, new_policy, new_snapshot) = bind(&auth);
    assert_eq!(field(&old_snapshot, "policy_generation"), Value::Int(1));
    assert_eq!(field(&new_snapshot, "policy_generation"), Value::Int(2));
    assert_eq!(
        field(&new_snapshot, "credential_refs"),
        Value::array(vec![Value::string(TARGET)])
    );
    let denied = call_result(
        &mut new_vm,
        "metadata",
        &[Value::string(OTHER), new_policy.clone()],
    )
    .expect_err("reload preserves single credential selection");
    assert!(denied.to_string().ends_with("credential_not_admitted"));
    assert_no_secrets(&format!("{denied:?}\n{denied}"));
    assert!(transport.take_sent().is_empty());

    // The real device/capture path derives slots from the old owner's frozen0.
    let old_slots = exchange(&mut old_vm, &old_policy, &auth, &transport, true, ACCESS);
    let failure = call_result(
        &mut old_vm,
        "save",
        &[save_request(&old_policy, &old_slots, 1, true)],
    )
    .expect_err("old slots remain generation zero");
    assert!(failure.to_string().ends_with("save_rejected"));
    assert_no_secrets(&format!("{failure:?}\n{failure}"));
    assert_eq!(old_vm.host_context().resource_count(), 4);
    assert!(
        fs::read(home.0.join("auth.yaml")).expect("generation one bytes") == generation_one_bytes
    );
    let adopted = call(
        &mut old_vm,
        "save",
        &[save_request(&old_policy, &old_slots, 0, true)],
    );
    assert_public(&adopted);
    assert_eq!(field(&adopted, "outcome"), Value::string("adopted"));
    assert_eq!(
        field(&field(&adopted, "metadata"), "generation"),
        Value::Int(1)
    );
    assert!(fs::read(home.0.join("auth.yaml")).expect("winner unchanged") == generation_one_bytes);
    assert_eq!(old_vm.host_context().resource_count(), 2);

    // Future binding derives slots from the actual stored generation1.
    let new_slots = exchange(&mut new_vm, &new_policy, &auth, &transport, false, ACCESS);
    let failure = call_result(
        &mut new_vm,
        "save",
        &[save_request(&new_policy, &new_slots, 0, false)],
    )
    .expect_err("future slots are no longer generation zero");
    assert!(failure.to_string().ends_with("save_rejected"));
    assert_no_secrets(&format!("{failure:?}\n{failure}"));
    assert_eq!(new_vm.host_context().resource_count(), 3);
    assert!(
        fs::read(home.0.join("auth.yaml")).expect("generation one bytes") == generation_one_bytes
    );
    let next = call(
        &mut new_vm,
        "save",
        &[save_request(&new_policy, &new_slots, 1, false)],
    );
    assert_public(&next);
    assert_eq!(field(&next, "outcome"), Value::string("committed"));
    assert_eq!(
        field(&field(&next, "metadata"), "generation"),
        Value::Int(2)
    );
    assert_eq!(new_vm.host_context().resource_count(), 2);
    native_count(&auth, 0);
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config bytes"),
        config_before
    );
}
