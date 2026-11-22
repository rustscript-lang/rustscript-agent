//! Real RSS opaque refresh transaction: expired metadata -> fallible issuance ->
//! one trusted POST -> RSS lifetime decision -> token_save CAS -> persisted readback.

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

const CREDENTIAL_ID: &str = "fixture-codex";
const STORED_ACCESS: &str = "SYNTHETIC_ACCESS_TOKEN";
const STORED_REFRESH: &str = "SYNTHETIC_REFRESH_TOKEN";
const NEW_ACCESS: &str = "PRT_RESPONSE_ACCESS_PRIVATE_a1f";
const NEW_REFRESH: &str = "PRT_RESPONSE_REFRESH_PRIVATE_b2c";
const NOW_MS: i64 = 1_900_000_000_000;

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test TEMP"));
        let home = root.join(format!(
            "provider-refresh-txn-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&home).expect("create private fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("read synthetic config fixture")
            .replace("auth.openai.com", "auth.example.test");
        fs::write(home.join("config.yaml"), config).expect("write synthetic config");
        // Readable but expired stored OAuth credential at generation 4.
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1700000000000")
            .replace("1788436400000", "1699996400000");
        fs::write(home.join("auth.yaml"), auth).expect("write synthetic auth state");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
                .expect("private home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("private fixture file mode");
            }
        }
        Self(home)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected named RSS value, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RSS field {name} in {value:?}"))
}

fn optional_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        panic!("expected named RSS value, got {value:?}");
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn is_null_or_absent(value: &Value, name: &str) -> bool {
    matches!(optional_field(value, name), None | Some(Value::Null))
}

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(name, value)| (Value::string(name), value))
            .collect(),
    )
}

fn compile_vm(auth: &AuthHost) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/provider_refresh_transaction/main.rss");
    let source = fs::read_to_string(&path).expect("real refresh transaction RSS fixture");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile against the pinned restricted auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register the native auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind the restricted native registry");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
        .unwrap_or_else(|failure| panic!("invoke {name}: {failure:?}"))
}

fn native_host(home: &TempHome, transport: Arc<ScriptedHttpsTransport>) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(NOW_MS as u64)),
        Arc::new(ScriptedCancel::new()),
    ));
    AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("native auth host")
    .with_oauth_host(oauth)
}

fn bind_and_snapshot(auth: &AuthHost) -> (Vm, Value, Value) {
    let mut vm = compile_vm(auth);
    let bound = auth.bind_vm(&mut vm).expect("bind native owner");
    let home = field(&bound, "host_home").clone();
    let snapshot = invoke(&mut vm, "snapshot", std::slice::from_ref(&home));
    assert_eq!(field(&snapshot, "ok"), &Value::Bool(true));
    (vm, home, field(&snapshot, "policy_handle").clone())
}

fn intent(credential_id: &str) -> Value {
    record(vec![
        ("credential_id", Value::string(credential_id)),
        ("path", Value::string("/oauth/token")),
        ("public_body", Value::string("grant_type=refresh_token")),
    ])
}

fn binding(home: &Value) -> Value {
    record(vec![("home", home.clone())])
}

fn run_refresh(vm: &mut Vm, home: &Value, credential_id: &str) -> Value {
    invoke(vm, "run_refresh", &[binding(home), intent(credential_id)])
}

fn stored_yaml(home: &TempHome) -> String {
    fs::read_to_string(home.0.join("auth.yaml")).expect("persisted auth file")
}

fn metadata_of(result: &Value) -> &Value {
    field(result, "metadata")
}

fn assert_no_secrets(rendered: &str) {
    for secret in [STORED_ACCESS, STORED_REFRESH, NEW_ACCESS, NEW_REFRESH] {
        assert!(
            !rendered.contains(secret),
            "RSS output leaked a secret value"
        );
    }
}

#[test]
fn expired_credential_refresh_replaces_rotated_tokens_and_persists_generation_five() {
    let home = TempHome::new("rotated");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{NEW_ACCESS}","refresh_token":"{NEW_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth);
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "home and policy bound"
    );

    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(field(&result, "code"), &Value::string("ok"));
    assert_eq!(field(&result, "outcome"), &Value::string("committed"));
    let metadata = metadata_of(&result);
    assert_eq!(field(metadata, "generation"), &Value::Int(5));
    assert_eq!(field(metadata, "has_refresh_token"), &Value::Bool(true));
    assert_eq!(
        field(metadata, "expires_at_ms"),
        &Value::Int(NOW_MS + 3_600_000)
    );
    assert_eq!(field(metadata, "last_refresh_at_ms"), &Value::Int(NOW_MS));

    // Exactly one trusted native POST carrying the host-injected stored secret.
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "single opaque refresh attempt");
    assert_eq!(sent[0].url, "https://auth.example.test/oauth/token");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/x-www-form-urlencoded")
    );
    assert!(sent[0].body.contains("grant_type=refresh_token"));
    assert!(
        sent[0].body.contains(STORED_REFRESH),
        "host injected the stored refresh secret"
    );
    assert!(
        !sent[0].body.contains(NEW_REFRESH),
        "RSS never writes a response secret"
    );

    // Persisted readback and confined stored file prove replace persistence.
    let persisted = AuthStore::from_home(&home.0)
        .expect("open persisted store")
        .load_metadata(CREDENTIAL_ID)
        .expect("read persisted metadata");
    assert_eq!(persisted.generation, 5);
    assert!(persisted.has_refresh_token);
    assert_eq!(persisted.expires_at_ms, (NOW_MS + 3_600_000) as u64);
    let yaml = stored_yaml(&home);
    assert!(yaml.contains(NEW_ACCESS));
    assert!(yaml.contains(NEW_REFRESH));
    assert!(!yaml.contains(STORED_ACCESS));
    assert!(!yaml.contains(STORED_REFRESH));

    // Usable freshly stored access: real issuance plus authenticated transport.
    transport.push_raw(200, r#"{"ok":true}"#);
    let probed = invoke(
        &mut vm,
        "probe_access",
        &[Value::string(CREDENTIAL_ID), Value::Int(5), policy.clone()],
    );
    assert_eq!(field(&probed, "ok"), &Value::Bool(true), "{probed:?}");
    let probed_sent = transport.take_sent();
    assert_eq!(probed_sent.len(), 1, "one authenticated access send");
    assert_eq!(
        probed_sent[0].url,
        "https://chatgpt.com/backend-api/codex/responses"
    );
    assert_eq!(probed_sent[0].method, "POST");
    assert!(
        probed_sent[0].headers.get("authorization") == Some(&format!("Bearer {NEW_ACCESS}")),
        "native transport must inject the newly persisted credential"
    );

    assert_no_secrets(&format!("{result:?}{probed:?}"));
    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn nonrotating_success_keeps_the_stored_refresh_slot() {
    let home = TempHome::new("nonrotating");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{NEW_ACCESS}","token_type":"Bearer","expires_in":1800}}"#),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth);

    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(field(&result, "outcome"), &Value::string("committed"));
    let metadata = metadata_of(&result);
    assert_eq!(field(metadata, "generation"), &Value::Int(5));
    assert_eq!(field(metadata, "has_refresh_token"), &Value::Bool(true));
    assert_eq!(
        field(metadata, "expires_at_ms"),
        &Value::Int(NOW_MS + 1_800_000)
    );
    assert_eq!(transport.take_sent().len(), 1);

    let yaml = stored_yaml(&home);
    assert!(yaml.contains(NEW_ACCESS));
    assert!(
        yaml.contains(STORED_REFRESH),
        "stored refresh retained on keep"
    );
    assert!(!yaml.contains(NEW_REFRESH));
    assert_no_secrets(&format!("{result:?}"));
    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn invalid_grant_maps_reauth_required_without_save_or_second_request() {
    let home = TempHome::new("invalid-grant");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        400,
        r#"{"error":"invalid_grant","error_description":"private server description"}"#,
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth);
    let before = stored_yaml(&home);

    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(field(&result, "code"), &Value::string("reauth_required"));
    assert_eq!(field(&result, "outcome"), &Value::string(""));
    assert!(is_null_or_absent(&result, "metadata"));
    assert_eq!(stored_yaml(&home), before, "no save on reauth_required");
    assert_eq!(transport.take_sent().len(), 1, "single attempt, no retry");
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("private server description"));
    assert_no_secrets(&rendered);
    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn non_grant_client_error_is_refresh_failed_without_save() {
    let home = TempHome::new("server-error");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(500, r#"{"error":"temporarily_unavailable"}"#);
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth);
    let before = stored_yaml(&home);

    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(field(&result, "code"), &Value::string("refresh_failed"));
    assert!(is_null_or_absent(&result, "metadata"));
    assert_eq!(stored_yaml(&home), before);
    assert_eq!(transport.take_sent().len(), 1);
    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn malformed_success_lifetime_is_response_invalid_without_leak() {
    let home = TempHome::new("malformed");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{NEW_ACCESS}","token_type":"Bearer"}}"#),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, _policy) = bind_and_snapshot(&auth);
    let before = stored_yaml(&home);

    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(
        field(&result, "code"),
        &Value::string("refresh_response_invalid")
    );
    assert_eq!(field(&result, "outcome"), &Value::string(""));
    assert!(is_null_or_absent(&result, "metadata"));
    assert_eq!(
        stored_yaml(&home),
        before,
        "generation unchanged on malformed lifetime"
    );
    assert_eq!(transport.take_sent().len(), 1);
    assert_no_secrets(&format!("{result:?}"));
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "transaction-closed returned slots leave no leak"
    );
}

#[test]
fn missing_access_token_is_response_invalid_without_save() {
    let home = TempHome::new("missing-access-token");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"token_type":"Bearer","expires_in":900}"#);
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, _policy) = bind_and_snapshot(&auth);
    let before = stored_yaml(&home);
    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(
        field(&result, "code"),
        &Value::string("refresh_response_invalid")
    );
    assert_eq!(field(&result, "outcome"), &Value::string(""));
    assert!(is_null_or_absent(&result, "metadata"));
    assert_eq!(stored_yaml(&home), before);
    assert_eq!(transport.take_sent().len(), 1);
    assert_no_secrets(&format!("{result:?}"));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn explicit_null_token_type_is_response_invalid_without_save() {
    let home = TempHome::new("null-token-type");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{NEW_ACCESS}","token_type":null,"expires_in":900}}"#),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, _policy) = bind_and_snapshot(&auth);
    let before = stored_yaml(&home);
    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(
        field(&result, "code"),
        &Value::string("refresh_response_invalid")
    );
    assert_eq!(field(&result, "outcome"), &Value::string(""));
    assert!(is_null_or_absent(&result, "metadata"));
    assert_eq!(stored_yaml(&home), before);
    assert_eq!(transport.take_sent().len(), 1);
    assert_no_secrets(&format!("{result:?}"));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn nonbearer_success_is_response_invalid_without_leak() {
    let home = TempHome::new("nonbearer-success");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{NEW_ACCESS}","token_type":"MAC","expires_in":900}}"#),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, _policy) = bind_and_snapshot(&auth);
    let before = stored_yaml(&home);
    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(
        field(&result, "code"),
        &Value::string("refresh_response_invalid")
    );
    assert_eq!(field(&result, "outcome"), &Value::string(""));
    assert!(is_null_or_absent(&result, "metadata"));
    assert_eq!(stored_yaml(&home), before);
    assert_eq!(transport.take_sent().len(), 1);
    assert_no_secrets(&format!("{result:?}"));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn oversized_lifetime_is_response_invalid() {
    let home = TempHome::new("oversized");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{NEW_ACCESS}","refresh_token":"{NEW_REFRESH}","token_type":"Bearer","expires_in":86401}}"#
        ),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth);

    let result = run_refresh(&mut vm, &home_handle, CREDENTIAL_ID);
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(
        field(&result, "code"),
        &Value::string("refresh_response_invalid")
    );
    assert_eq!(transport.take_sent().len(), 1);
    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn unknown_credential_yields_typed_admission_failure_and_zero_send() {
    let home = TempHome::new("unknown");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth);
    let before = stored_yaml(&home);

    let result = run_refresh(&mut vm, &home_handle, "unknown-credential");
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(
        field(&result, "code"),
        &Value::string("credential_not_admitted")
    );
    assert!(is_null_or_absent(&result, "metadata"));
    assert_eq!(stored_yaml(&home), before);
    assert!(
        transport.take_sent().is_empty(),
        "admission failure sends nothing"
    );
    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(vm.host_context().resource_count(), 2);
}
