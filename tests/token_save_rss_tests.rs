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

const STALE_ACCESS: &str = "KK_SAVE_STALE_ACCESS_SYNTHETIC";
const STALE_REFRESH: &str = "KK_SAVE_STALE_REFRESH_SYNTHETIC";
const WRITER_ACCESS: &str = "KK_SAVE_NEWER_ACCESS_SYNTHETIC";
const WRITER_REFRESH: &str = "KK_SAVE_NEWER_REFRESH_SYNTHETIC";
const ENROLLMENT_ACCESS: &str = "KK_SAVE_INITIAL_ACCESS_SYNTHETIC";
const AUTHORIZED_PROVIDER: &str = "openai-codex";
const CREDENTIAL_ID: &str = "fixture-codex";
const EXPECTED_GENERATION: i64 = 4;

const TEST_PROBES: &str = r#"
use auth;
use config;
use oauth;

pub fn snapshot(home: resource<auth.host_home>) -> ConfigSnapshotEnvelope {
    config::load_snapshot(&home)
}

pub fn capture_tokens(policy: resource<auth.policy>, expected_generation: int) -> TransportResultEnvelope {
    let refresh = auth::refresh_handle("fixture-codex", expected_generation, &policy).handle;
    let request = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/oauth/token",
        public_headers: [{name: "content-type", value: "application/x-www-form-urlencoded"}],
        public_body: "grant_type=refresh_token"
    };
    let usage = {kind: "refresh", refresh_handle: refresh};
    oauth::transport_result(&request, &usage)
}

pub fn capture_enrollment(policy: resource<auth.policy>) -> TransportResultEnvelope {
    let request = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/oauth/token",
        public_headers: [{name: "content-type", value: "application/x-www-form-urlencoded"}],
        public_body: "grant_type=authorization_code&client_id=public-client-id"
    };
    let usage = {
        kind: "none",
        access_handle: null,
        refresh_handle: null,
        code_handle: null,
        verifier_handle: null,
        device_handle: null
    };
    oauth::transport_result(&request, &usage)
}

pub fn raw_save(request: SaveCredentialRequest) -> AuthSaveResultEnvelope {
    auth::save_if_generation_result(&request)
}

pub fn close_slot(slot: resource<auth.secret_slot>) -> null {
    auth::close_slot(slot)
}

pub fn cleanup(policy: resource<auth.policy>) -> null {
    auth::cleanup_transients(&policy)
}
"#;

fn production_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/token_save.rss");
    let mut source = fs::read_to_string(path).expect("production token-save RSS entry");
    source.push_str(TEST_PROBES);
    source
}

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test TEMP"));
        let home = root.join(format!(
            "token-save-{label}-{}-{}",
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
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "2000000000000")
            .replace("1788436400000", "1999996400000");
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

    fn new_enrollment(label: &str) -> Self {
        let home = Self::new(label);
        fs::remove_file(home.0.join("auth.yaml")).expect("remove existing credential fixture");
        home
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

fn compile_vm(auth: &AuthHost, source: &str) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        source,
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

fn native_host_with_cancellation(
    home: &TempHome,
    transport: Arc<ScriptedHttpsTransport>,
    cancellation: RunCancellation,
) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    AuthHost::new(home.0.clone(), cancellation)
        .expect("native auth host")
        .with_oauth_host(oauth)
}

fn native_host(home: &TempHome, transport: Arc<ScriptedHttpsTransport>) -> AuthHost {
    native_host_with_cancellation(
        home,
        transport,
        RunCancellation::with_timeout(Duration::from_secs(10)),
    )
}

fn native_enrollment_host(
    home: &TempHome,
    transport: Arc<ScriptedHttpsTransport>,
    cancellation: RunCancellation,
) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    AuthHost::new_for_enrollment(home.0.clone(), cancellation, CREDENTIAL_ID)
        .expect("native enrollment auth host")
        .with_oauth_host(oauth)
}

fn bind_and_snapshot(auth: &AuthHost, source: &str) -> (Vm, Value, Value) {
    let mut vm = compile_vm(auth, source);
    let bound = auth.bind_vm(&mut vm).expect("bind native owner");
    let home = field(&bound, "host_home").clone();
    let snapshot = invoke(&mut vm, "snapshot", std::slice::from_ref(&home));
    assert_eq!(field(&snapshot, "ok"), &Value::Bool(true));
    (vm, home, field(&snapshot, "policy_handle").clone())
}

fn capture_slots(vm: &mut Vm, policy: &Value) -> (Value, Value) {
    let captured = invoke(
        vm,
        "capture_tokens",
        &[policy.clone(), Value::Int(EXPECTED_GENERATION)],
    );
    assert_eq!(field(&captured, "ok"), &Value::Bool(true), "{captured:?}");
    let response = field(&captured, "value");
    let access = field(response, "access_slot").clone();
    let refresh = field(response, "refresh_slot").clone();
    assert!(!matches!(access, Value::Null));
    assert!(!matches!(refresh, Value::Null));
    for secret in [STALE_ACCESS, STALE_REFRESH, WRITER_ACCESS, WRITER_REFRESH] {
        assert!(!format!("{captured:?}").contains(secret));
    }
    (access, refresh)
}

fn save_request(
    policy: &Value,
    access: Value,
    refresh: Value,
    provider: &str,
    source: &str,
    status: &str,
    expires_at_ms: i64,
) -> Value {
    record(vec![
        ("credential_id", Value::string(CREDENTIAL_ID)),
        ("expected_generation", Value::Int(EXPECTED_GENERATION)),
        ("policy_handle", policy.clone()),
        (
            "metadata",
            record(vec![
                ("provider", Value::string(provider)),
                ("kind", Value::string("oauth")),
                ("source", Value::string(source)),
                ("token_type", Value::string("Bearer")),
                ("expires_at_ms", Value::Int(expires_at_ms)),
                ("scopes", Value::array(vec![])),
                ("account_id", Value::string("synthetic-token-save-account")),
                ("generation", Value::Int(EXPECTED_GENERATION)),
                ("status", Value::string(status)),
                ("last_refresh_at_ms", Value::Null),
                ("has_refresh_token", Value::Bool(true)),
            ]),
        ),
        ("access_slot", access),
        ("refresh_action", Value::string("replace")),
        ("refresh_slot", refresh),
    ])
}

struct SaveInputSpec<'a> {
    credential_id: &'a str,
    expected_generation: i64,
    provider: &'a str,
    source: &'a str,
    status: &'a str,
    expires_at_ms: i64,
    has_refresh_token: bool,
    refresh_action: &'a str,
}

fn save_input_for(spec: SaveInputSpec<'_>) -> Value {
    record(vec![
        ("credential_id", Value::string(spec.credential_id)),
        ("expected_generation", Value::Int(spec.expected_generation)),
        (
            "metadata",
            record(vec![
                ("provider", Value::string(spec.provider)),
                ("kind", Value::string("oauth")),
                ("source", Value::string(spec.source)),
                ("token_type", Value::string("Bearer")),
                ("expires_at_ms", Value::Int(spec.expires_at_ms)),
                ("scopes", Value::array(vec![])),
                ("account_id", Value::string("synthetic-token-save-account")),
                ("generation", Value::Int(spec.expected_generation)),
                ("status", Value::string(spec.status)),
                ("last_refresh_at_ms", Value::Null),
                ("has_refresh_token", Value::Bool(spec.has_refresh_token)),
            ]),
        ),
        ("refresh_action", Value::string(spec.refresh_action)),
    ])
}

fn save_input(provider: &str, source: &str, status: &str, expires_at_ms: i64) -> Value {
    save_input_for(SaveInputSpec {
        credential_id: CREDENTIAL_ID,
        expected_generation: EXPECTED_GENERATION,
        provider,
        source,
        status,
        expires_at_ms,
        has_refresh_token: true,
        refresh_action: "replace",
    })
}

fn saved_metadata(result: &Value) -> &Value {
    field(field(result, "value"), "metadata")
}

fn token_result_metadata(result: &Value) -> &Value {
    field(result, "value")
}

#[test]
fn native_none_credential_enrollment_saves_generation_one_without_refresh() {
    let home = TempHome::new_enrollment("enrollment");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{ENROLLMENT_ACCESS}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let auth = native_enrollment_host(&home, transport.clone(), cancellation);
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth, &production_source());

    let captured = invoke(&mut vm, "capture_enrollment", std::slice::from_ref(&policy));
    assert_eq!(field(&captured, "ok"), &Value::Bool(true), "{captured:?}");
    let response = field(&captured, "value");
    let access = field(response, "access_slot").clone();
    let refresh = field(response, "refresh_slot").clone();
    assert!(!matches!(access, Value::Null));
    assert_eq!(refresh, Value::Null);
    assert!(!format!("{captured:?}").contains(ENROLLMENT_ACCESS));
    assert_eq!(
        transport.take_sent().len(),
        1,
        "native none-credential send"
    );

    let input = save_input_for(SaveInputSpec {
        credential_id: CREDENTIAL_ID,
        expected_generation: 0,
        provider: AUTHORIZED_PROVIDER,
        source: "initial-enrollment-source",
        status: "active",
        expires_at_ms: 2_100_000_000_000,
        has_refresh_token: false,
        refresh_action: "clear",
    });
    let saved = invoke(
        &mut vm,
        "save",
        &[home_handle, policy, input, access, refresh],
    );
    assert_eq!(field(&saved, "ok"), &Value::Bool(true), "{saved:?}");
    assert_eq!(field(&saved, "code"), &Value::string("ok"));
    assert_eq!(field(&saved, "outcome"), &Value::string("committed"));
    assert_eq!(
        field(token_result_metadata(&saved), "generation"),
        &Value::Int(1)
    );
    assert_eq!(
        field(token_result_metadata(&saved), "has_refresh_token"),
        &Value::Bool(false)
    );
    assert!(!format!("{saved:?}").contains(ENROLLMENT_ACCESS));
    let persisted = AuthStore::from_home(&home.0)
        .expect("open persisted enrollment store")
        .load_metadata(CREDENTIAL_ID)
        .expect("read real enrollment metadata");
    assert_eq!(persisted.generation, 1);
    assert_eq!(persisted.status, "active");
    assert!(!persisted.has_refresh_token);
    let auth_yaml = fs::read_to_string(home.0.join("auth.yaml")).expect("persisted auth file");
    assert!(auth_yaml.contains(ENROLLMENT_ACCESS));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn native_refresh_commit_replaces_tokens_and_returns_persisted_metadata() {
    let home = TempHome::new("refresh-replacement");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{STALE_ACCESS}","refresh_token":"{STALE_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth, &production_source());
    let (access, refresh) = capture_slots(&mut vm, &policy);
    assert_eq!(transport.take_sent().len(), 1, "native refresh transport");
    let input = save_input(
        AUTHORIZED_PROVIDER,
        "committed-refresh-source",
        "active",
        2_100_000_000_000,
    );

    let result = invoke(
        &mut vm,
        "save",
        &[home_handle, policy, input, access, refresh],
    );
    assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
    assert_eq!(field(&result, "code"), &Value::string("ok"));
    assert_eq!(field(&result, "outcome"), &Value::string("committed"));
    let metadata = token_result_metadata(&result);
    assert_eq!(field(metadata, "generation"), &Value::Int(5));
    assert_eq!(
        field(metadata, "source"),
        &Value::string("committed-refresh-source")
    );
    assert_eq!(field(metadata, "has_refresh_token"), &Value::Bool(true));
    for secret in [STALE_ACCESS, STALE_REFRESH] {
        assert!(!format!("{result:?}").contains(secret));
    }
    let persisted = AuthStore::from_home(&home.0)
        .expect("open persisted refresh store")
        .load_metadata(CREDENTIAL_ID)
        .expect("read persisted refresh metadata");
    assert_eq!(persisted.generation, 5);
    assert_eq!(persisted.source, "committed-refresh-source");
    assert!(persisted.has_refresh_token);
    let auth_yaml = fs::read_to_string(home.0.join("auth.yaml")).expect("persisted auth file");
    assert!(auth_yaml.contains(STALE_ACCESS));
    assert!(auth_yaml.contains(STALE_REFRESH));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn invalid_metadata_guard_preserves_native_store_and_enclosing_cleanup_retires_slots() {
    let home = TempHome::new("invalid-metadata");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{STALE_ACCESS}","refresh_token":"{STALE_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth, &production_source());
    let (access, refresh) = capture_slots(&mut vm, &policy);
    let before = fs::read(home.0.join("auth.yaml")).expect("snapshot actual auth store");
    let input = save_input(
        AUTHORIZED_PROVIDER,
        "invalid-source",
        "disabled",
        2_100_000_000_000,
    );

    let result = invoke(
        &mut vm,
        "save",
        &[home_handle, policy.clone(), input, access, refresh],
    );
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_eq!(
        field(&result, "code"),
        &Value::string("invalid_save_metadata")
    );
    assert!(is_null_or_absent(&result, "outcome"));
    assert!(is_null_or_absent(&result, "value"));
    assert_eq!(fs::read(home.0.join("auth.yaml")).unwrap(), before);
    assert_eq!(
        vm.host_context().resource_count(),
        4,
        "both pre-save candidates remain live"
    );

    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "home and policy remain bound"
    );
    assert!(!format!("{result:?}").contains(STALE_ACCESS));
    assert!(!format!("{result:?}").contains(STALE_REFRESH));
}

#[test]
fn native_save_rejection_is_redacted_and_does_not_change_store() {
    let home = TempHome::new("native-rejection");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{STALE_ACCESS}","refresh_token":"{STALE_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth, &production_source());
    let (access, refresh) = capture_slots(&mut vm, &policy);
    let before = fs::read(home.0.join("auth.yaml")).expect("snapshot actual auth store");
    let input = save_input_for(SaveInputSpec {
        credential_id: CREDENTIAL_ID,
        expected_generation: EXPECTED_GENERATION,
        provider: AUTHORIZED_PROVIDER,
        source: "native-rejection-source",
        status: "active",
        expires_at_ms: 2_100_000_000_000,
        has_refresh_token: true,
        refresh_action: "unsupported-action",
    });

    let result = invoke(
        &mut vm,
        "save",
        &[home_handle, policy.clone(), input, access, refresh],
    );
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_ne!(field(&result, "code"), &Value::string("ok"));
    assert!(is_null_or_absent(&result, "outcome"));
    assert!(is_null_or_absent(&result, "value"));
    assert_eq!(fs::read(home.0.join("auth.yaml")).unwrap(), before);
    assert_eq!(
        vm.host_context().resource_count(),
        4,
        "native pre-write rejection leaves candidates for cleanup"
    );

    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "home and policy remain bound"
    );
    for secret in [STALE_ACCESS, STALE_REFRESH] {
        assert!(!format!("{result:?}").contains(secret));
    }
}

#[test]
fn cancelled_native_cas_fails_closed_without_persisted_mutation() {
    let home = TempHome::new("cancelled");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{STALE_ACCESS}","refresh_token":"{STALE_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let auth = native_host_with_cancellation(&home, transport.clone(), cancellation.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth, &production_source());
    let (access, refresh) = capture_slots(&mut vm, &policy);
    let before = fs::read(home.0.join("auth.yaml")).expect("snapshot actual auth store");
    cancellation.request(rustscript_agent::CancellationReason::Requested);
    let input = save_input(
        AUTHORIZED_PROVIDER,
        "cancelled-source",
        "active",
        2_100_000_000_000,
    );

    let result = invoke(
        &mut vm,
        "save",
        &[home_handle, policy.clone(), input, access, refresh],
    );
    assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
    assert_ne!(field(&result, "code"), &Value::string("ok"));
    assert!(is_null_or_absent(&result, "outcome"));
    assert!(is_null_or_absent(&result, "value"));
    assert_eq!(fs::read(home.0.join("auth.yaml")).unwrap(), before);

    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "cleanup leaves home and policy"
    );
    for secret in [STALE_ACCESS, STALE_REFRESH] {
        assert!(!format!("{result:?}").contains(secret));
    }
}

#[test]
fn closed_native_candidate_cannot_be_reported_as_success() {
    let home = TempHome::new("closed-slot");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{STALE_ACCESS}","refresh_token":"{STALE_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth, &production_source());
    let (access, refresh) = capture_slots(&mut vm, &policy);
    let before = fs::read(home.0.join("auth.yaml")).expect("snapshot actual auth store");
    let _ = invoke(&mut vm, "close_slot", std::slice::from_ref(&access));
    let input = save_input(
        AUTHORIZED_PROVIDER,
        "closed-candidate-source",
        "active",
        2_100_000_000_000,
    );

    let callable = vm
        .resolve_exported_callable("save")
        .expect("RSS save export");
    let invocation = vm.invoke_callable(
        callable,
        &[home_handle, policy.clone(), input, access, refresh],
    );
    assert!(
        invocation.is_err(),
        "closed native slot must fail closed, got {invocation:?}"
    );
    assert_eq!(fs::read(home.0.join("auth.yaml")).unwrap(), before);

    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "closed access and remaining transient are retired"
    );
}

#[test]
fn foreign_owner_home_and_policy_cannot_report_save_success() {
    let home = TempHome::new("foreign-owner-save-home");
    let foreign_home = TempHome::new("foreign-owner-save-policy");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{STALE_ACCESS}","refresh_token":"{STALE_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let foreign_transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = native_host(&home, transport.clone());
    let (mut vm, home_handle, policy) = bind_and_snapshot(&auth, &production_source());
    let foreign_auth = native_host(&foreign_home, foreign_transport);
    let (mut foreign_vm, foreign_home_handle, foreign_policy) =
        bind_and_snapshot(&foreign_auth, &production_source());
    let (access, refresh) = capture_slots(&mut vm, &policy);
    let before = fs::read(home.0.join("auth.yaml")).expect("snapshot actual auth store");
    let input = save_input(
        AUTHORIZED_PROVIDER,
        "foreign-owner-candidate-source",
        "active",
        2_100_000_000_000,
    );
    let callable = vm
        .resolve_exported_callable("save")
        .expect("RSS save export");

    let wrong_home = vm.invoke_callable(
        callable.clone(),
        &[
            foreign_home_handle,
            policy.clone(),
            input.clone(),
            access.clone(),
            refresh.clone(),
        ],
    );
    assert!(
        wrong_home.is_err(),
        "foreign home resource must be rejected before a success result"
    );
    let wrong_policy = vm.invoke_callable(
        callable,
        &[home_handle, foreign_policy, input, access, refresh],
    );
    assert!(
        wrong_policy.is_err(),
        "foreign policy resource must be rejected before a success result"
    );
    assert_eq!(fs::read(home.0.join("auth.yaml")).unwrap(), before);
    assert_eq!(
        transport.take_sent().len(),
        1,
        "only native slot capture ran"
    );
    assert_eq!(foreign_vm.host_context().resource_count(), 2);
    let _ = invoke(&mut vm, "cleanup", &[policy]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

fn prepare_two_generations(
    label: &str,
    writer_provider: &str,
    writer_status: &str,
    writer_expiry: i64,
    expect_success: bool,
) {
    let home = TempHome::new(label);
    let source = production_source();

    let stale_transport = Arc::new(ScriptedHttpsTransport::new());
    stale_transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{STALE_ACCESS}","refresh_token":"{STALE_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let stale_auth = native_host(&home, stale_transport.clone());
    let (mut stale_vm, stale_home, stale_policy) = bind_and_snapshot(&stale_auth, &source);
    let (stale_access, stale_refresh) = capture_slots(&mut stale_vm, &stale_policy);
    assert_eq!(
        stale_transport.take_sent().len(),
        1,
        "native token capture send"
    );

    let writer_transport = Arc::new(ScriptedHttpsTransport::new());
    writer_transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{WRITER_ACCESS}","refresh_token":"{WRITER_REFRESH}","token_type":"Bearer","expires_in":3600}}"#
        ),
    );
    let writer_auth = native_host(&home, writer_transport.clone());
    let (mut writer_vm, _writer_home, writer_policy) = bind_and_snapshot(&writer_auth, &source);
    let (writer_access, writer_refresh) = capture_slots(&mut writer_vm, &writer_policy);
    assert_eq!(
        writer_transport.take_sent().len(),
        1,
        "independent writer send"
    );

    let writer_request = save_request(
        &writer_policy,
        writer_access,
        writer_refresh,
        writer_provider,
        "writer-newer-source",
        writer_status,
        writer_expiry,
    );
    let writer_result = invoke(&mut writer_vm, "raw_save", &[writer_request]);
    assert_eq!(
        field(&writer_result, "ok"),
        &Value::Bool(true),
        "{writer_result:?}"
    );
    assert_eq!(
        field(field(&writer_result, "value"), "outcome"),
        &Value::string("committed")
    );
    assert_eq!(
        field(saved_metadata(&writer_result), "generation"),
        &Value::Int(5)
    );
    assert_eq!(
        field(saved_metadata(&writer_result), "status"),
        &Value::string(writer_status)
    );
    assert_eq!(writer_vm.host_context().resource_count(), 2);

    let stale_input = save_input(
        AUTHORIZED_PROVIDER,
        "stale-candidate-source",
        "active",
        2_100_000_000_000,
    );
    let result = invoke(
        &mut stale_vm,
        "save",
        &[
            stale_home,
            stale_policy,
            stale_input,
            stale_access,
            stale_refresh,
        ],
    );
    if expect_success {
        assert_eq!(field(&result, "ok"), &Value::Bool(true), "{result:?}");
        assert_eq!(field(&result, "code"), &Value::string("ok"));
        assert_eq!(field(&result, "outcome"), &Value::string("adopted"));
        assert_eq!(field(field(&result, "value"), "generation"), &Value::Int(5));
        assert_eq!(
            field(field(&result, "value"), "source"),
            &Value::string("writer-newer-source")
        );
        assert_eq!(
            field(field(&result, "value"), "status"),
            &Value::string("active")
        );
    } else {
        assert_eq!(field(&result, "ok"), &Value::Bool(false), "{result:?}");
        assert_eq!(
            field(&result, "code"),
            &Value::string("invalid_saved_metadata")
        );
        assert!(is_null_or_absent(&result, "outcome"));
        assert!(is_null_or_absent(&result, "value"));
    }
    assert_eq!(stale_vm.host_context().resource_count(), 2);

    let persisted = AuthStore::from_home(&home.0)
        .expect("open actual persisted auth store")
        .load_metadata(CREDENTIAL_ID)
        .expect("read actual adopted metadata");
    assert_eq!(persisted.generation, 5);
    assert_eq!(persisted.status, writer_status);
    let auth_yaml = fs::read_to_string(home.0.join("auth.yaml")).expect("persisted auth file");
    assert!(auth_yaml.contains(WRITER_ACCESS));
    assert!(auth_yaml.contains(WRITER_REFRESH));
    assert!(!auth_yaml.contains(STALE_ACCESS));
    assert!(!auth_yaml.contains(STALE_REFRESH));
    for secret in [STALE_ACCESS, STALE_REFRESH, WRITER_ACCESS, WRITER_REFRESH] {
        assert!(!format!("{result:?}").contains(secret));
        assert!(!format!("{writer_result:?}").contains(secret));
    }
}

#[test]
fn native_adoption_of_active_newer_state_is_read_back_without_overwrite() {
    prepare_two_generations(
        "active",
        AUTHORIZED_PROVIDER,
        "active",
        2_100_000_000_000,
        true,
    );
}

#[test]
fn native_adoption_of_inactive_state_is_rejected_by_rss() {
    prepare_two_generations(
        "inactive",
        AUTHORIZED_PROVIDER,
        "disabled",
        2_100_000_000_000,
        false,
    );
}

#[test]
fn native_adoption_of_expired_state_is_rejected_by_rss() {
    prepare_two_generations(
        "expired",
        AUTHORIZED_PROVIDER,
        "active",
        1_899_999_999_999,
        false,
    );
}

#[test]
fn native_adoption_of_wrong_provider_state_is_rejected_by_rss() {
    prepare_two_generations(
        "wrong-provider",
        "different-provider-synthetic",
        "active",
        2_100_000_000_000,
        false,
    );
}
