use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustscript_agent::{
    RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::{
            OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
            ScriptedHttpsTransport,
        },
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};

const ACCESS_SECRET: &str = "SYNTHETIC_TOKEN_METADATA_ACCESS_DO_NOT_OUTPUT";
const REFRESH_SECRET: &str = "SYNTHETIC_TOKEN_METADATA_REFRESH_DO_NOT_OUTPUT";
const TEST_ADAPTER: &str = r#"
use config;
use auth;
use oauth;

pub fn test_prepare(home: resource<auth.host_home>) -> bool {
    config::load_snapshot(&home).ok
}

pub fn test_cleanup(home: resource<auth.host_home>) -> bool {
    let snapshot = config::load_snapshot(&home);
    auth::cleanup_transients(&snapshot.policy_handle);
    true
}

pub fn test_pipeline(
    home: resource<auth.host_home>,
    intent: TokenMetadataIntent
) -> map {
    let snapshot = config::load_snapshot(&home);
    let request: TransportPublicRequest = {
        policy_handle: snapshot.policy_handle,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/oauth/token",
        public_headers: [{name: "content-type", value: "application/json"}],
        public_body: "{\"grant_type\":\"authorization_code\"}"
    };
    let usage: TransportCredentialUse = {
        kind: "none",
        access_handle: null,
        refresh_handle: null,
        code_handle: null,
        verifier_handle: null,
        device_handle: null
    };
    let response: TransportResultEnvelope = oauth::transport_result(&request, &usage);
    let parsed_policy: resource<auth.policy> = request.policy_handle;
    let parsed: TokenMetadataResult = parse_transport_result(parsed_policy, response, intent);
    {metadata_result: parsed}
}
"#;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
        let path = root.join(format!(
            "token-metadata-rss-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create isolated home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("write synthetic auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture mode");
            }
        }
        Self(path)
    }

    fn auth_path(&self) -> PathBuf {
        self.0.join("auth.yaml")
    }
}

impl AsRef<Path> for FixtureHome {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(name, value)| (Value::string(name), value))
            .collect(),
    )
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected RSS record, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RSS field {name}"))
}

fn optional_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        panic!("expected RSS record, got {value:?}");
    };
    entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name => Some(value),
        _ => None,
    })
}

fn assert_failure(output: &Value, expected_code: &str) {
    let result = field(output, "metadata_result");
    assert_eq!(field(result, "ok"), &Value::Bool(false));
    assert_eq!(field(result, "code"), &Value::string(expected_code));
    assert!(matches!(
        optional_field(result, "value"),
        None | Some(Value::Null)
    ));
    let rendered = format!("{output:?}");
    assert!(!rendered.contains(ACCESS_SECRET));
    assert!(!rendered.contains(REFRESH_SECRET));
}

fn selected_intent() -> Value {
    selected_intent_with(Value::string("/account/id"))
}

fn selected_intent_with(account_pointer: Value) -> Value {
    record(vec![
        ("provider", Value::string("selected-provider")),
        ("source", Value::string("selected-source")),
        ("expected_generation", Value::Int(37)),
        (
            "scopes",
            Value::array(vec![
                Value::string("scope.alpha"),
                Value::string("scope.beta"),
            ]),
        ),
        ("expiry_pointer", Value::string("/expires_in")),
        ("token_type_pointer", Value::string("/token_type")),
        ("account_pointer", account_pointer),
    ])
}

fn token_response_body(
    access: bool,
    refresh: bool,
    expires_json: &str,
    token_type_json: &str,
    account_json: Option<&str>,
) -> String {
    let mut fields = Vec::new();
    if access {
        fields.push(format!("\"access_token\":\"{ACCESS_SECRET}\""));
    }
    if refresh {
        fields.push(format!("\"refresh_token\":\"{REFRESH_SECRET}\""));
    }
    if !expires_json.is_empty() {
        fields.push(format!("\"expires_in\":{expires_json}"));
    }
    if !token_type_json.is_empty() {
        fields.push(format!("\"token_type\":{token_type_json}"));
    }
    if let Some(account) = account_json {
        fields.push(format!("\"account\":{account}"));
    }
    format!("{{{}}}", fields.join(","))
}

fn compile_vm(
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
    clock_ms: u64,
) -> (Vm, AuthHost, Value) {
    let module_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/token_metadata.rss");
    let mut source = fs::read_to_string(&module_path).expect("RSS token metadata source");
    source.push_str(TEST_ADAPTER);
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &module_path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .unwrap_or_else(|error| panic!("compile real token metadata RSS: {error}"));
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(clock_ms)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("native AuthHost")
    .with_oauth_host(oauth);
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register actual auth host catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted production registry");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    let bound = auth.bind_vm(&mut vm).expect("bind native host home");
    let host_home = field(&bound, "host_home").clone();
    (vm, auth, host_home)
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let callable = vm.resolve_exported_callable(name).expect("RSS test entry");
    vm.invoke_callable(callable, args).expect("RSS call")
}

fn run_fixture(
    status: u16,
    body: &str,
    clock_ms: u64,
    intent: Value,
    expected_new_slots: usize,
) -> Value {
    let home = FixtureHome::new();
    let store_before = fs::read(home.auth_path()).expect("read original auth state");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(status, body);
    let (mut vm, _auth, host_home) = compile_vm(&home, transport, clock_ms);
    assert_eq!(
        invoke(&mut vm, "test_prepare", std::slice::from_ref(&host_home)),
        Value::Bool(true)
    );
    let resources_before_transport: usize = vm.host_context().resource_count();
    let output = invoke(&mut vm, "test_pipeline", &[host_home.clone(), intent]);
    let resources_after_parse: usize = vm.host_context().resource_count();
    assert_eq!(
        resources_after_parse,
        resources_before_transport + expected_new_slots,
        "parser preserves native response slots until caller cleanup"
    );
    assert_eq!(
        invoke(&mut vm, "test_cleanup", &[host_home]),
        Value::Bool(true)
    );
    assert_eq!(
        vm.host_context().resource_count(),
        resources_before_transport,
        "caller cleanup closes transient slots"
    );
    let store_after = fs::read(home.auth_path()).expect("read auth state after parser");
    assert_eq!(
        store_after, store_before,
        "metadata parsing must not save tokens"
    );
    output
}

#[test]
fn non_200_response_is_rejected_even_when_native_transport_mints_slots() {
    let body = token_response_body(
        true,
        true,
        "60",
        "\"Bearer\"",
        Some(r#"{"id":"acct_synthetic_metadata"}"#),
    );
    let output = run_fixture(400, &body, 1_900_000_000_123, selected_intent(), 2);
    assert_failure(&output, "token_http_rejected");
}

#[test]
fn absent_native_access_slot_is_rejected() {
    let body = token_response_body(
        false,
        true,
        "60",
        "\"Bearer\"",
        Some(r#"{"id":"acct_synthetic_metadata"}"#),
    );
    let output = run_fixture(200, &body, 1_900_000_000_123, selected_intent(), 1);
    assert_failure(&output, "invalid_token_metadata");
}

#[test]
fn invalid_selected_expiry_and_token_type_fields_fail_closed() {
    let cases = [
        ("", "\"Bearer\""),
        ("0", "\"Bearer\""),
        ("-1", "\"Bearer\""),
        ("\"60\"", "\"Bearer\""),
        ("1.25", "\"Bearer\""),
        ("9223372036854776", "\"Bearer\""),
        ("60", ""),
        ("60", "null"),
        ("60", "7"),
        ("60", "\"\""),
        ("60", "\"Basic\""),
    ];
    for (expires_json, token_type_json) in cases {
        let body = token_response_body(
            true,
            true,
            expires_json,
            token_type_json,
            Some(r#"{"id":"acct_synthetic_metadata"}"#),
        );
        let output = run_fixture(200, &body, 1_900_000_000_123, selected_intent(), 2);
        assert_failure(&output, "invalid_token_metadata");
    }
}

#[test]
fn non_string_or_empty_account_values_fail_closed() {
    for account_json in [Some(r#"{"id":7}"#), Some(r#"{"id":""}"#)] {
        let body = token_response_body(true, true, "60", "\"Bearer\"", account_json);
        let output = run_fixture(200, &body, 1_900_000_000_123, selected_intent(), 2);
        assert_failure(&output, "invalid_token_metadata");
    }
}

#[test]
fn null_account_pointer_and_absent_refresh_slot_are_preserved() {
    let body = token_response_body(
        true,
        false,
        "60",
        "\"Bearer\"",
        Some(r#"{"id":"acct_synthetic_metadata"}"#),
    );
    let output = run_fixture(
        200,
        &body,
        1_900_000_000_123,
        selected_intent_with(Value::Null),
        1,
    );
    let result = field(&output, "metadata_result");
    assert_eq!(field(result, "ok"), &Value::Bool(true));
    let metadata = field(result, "value");
    assert!(matches!(
        optional_field(metadata, "account_id"),
        None | Some(Value::Null)
    ));
    assert_eq!(field(metadata, "has_refresh_token"), &Value::Bool(false));
    let rendered = format!("{output:?}");
    assert!(!rendered.contains(ACCESS_SECRET));
    assert!(!rendered.contains(REFRESH_SECRET));
}

#[test]
fn missing_or_null_account_pointer_values_return_null_account_metadata() {
    for account_json in [None, Some("null")] {
        let body = token_response_body(true, true, "60", "\"Bearer\"", account_json);
        let output = run_fixture(200, &body, 1_900_000_000_123, selected_intent(), 2);
        let result = field(&output, "metadata_result");
        assert_eq!(field(result, "ok"), &Value::Bool(true));
        let metadata = field(result, "value");
        assert!(matches!(
            optional_field(metadata, "account_id"),
            None | Some(Value::Null)
        ));
        assert_eq!(field(metadata, "has_refresh_token"), &Value::Bool(true));
        let rendered = format!("{output:?}");
        assert!(!rendered.contains(ACCESS_SECRET));
        assert!(!rendered.contains(REFRESH_SECRET));
    }
}

#[test]
fn expiry_guards_accept_exact_maximum_and_reject_overflow() {
    let body = token_response_body(
        true,
        true,
        "9223372036854775",
        "\"Bearer\"",
        Some(r#"{"id":"acct_synthetic_metadata"}"#),
    );
    let output = run_fixture(200, &body, 0, selected_intent(), 2);
    let metadata = field(field(&output, "metadata_result"), "value");
    assert_eq!(
        field(metadata, "expires_at_ms"),
        &Value::Int(9_223_372_036_854_775_000)
    );

    let body = token_response_body(
        true,
        true,
        "1",
        "\"Bearer\"",
        Some(r#"{"id":"acct_synthetic_metadata"}"#),
    );
    let at_boundary = run_fixture(200, &body, 9_223_372_036_854_774_807, selected_intent(), 2);
    let metadata = field(field(&at_boundary, "metadata_result"), "value");
    assert_eq!(field(metadata, "expires_at_ms"), &Value::Int(i64::MAX));

    let one_millisecond_past =
        run_fixture(200, &body, 9_223_372_036_854_774_808, selected_intent(), 2);
    assert_failure(&one_millisecond_past, "invalid_token_metadata");
}

#[test]
fn malformed_or_duplicate_response_json_fails_closed_without_minting_slots() {
    let duplicate = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","expires_in":60,"expires_in":30,"token_type":"Bearer","account":{{"id":"acct_synthetic_metadata"}}}}"#
    );
    let malformed = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","expires_in":}}"#
    );
    for body in [duplicate, malformed] {
        let output = run_fixture(200, &body, 1_900_000_000_123, selected_intent(), 0);
        let result = field(&output, "metadata_result");
        assert_eq!(field(result, "ok"), &Value::Bool(false));
        assert_eq!(
            field(result, "code"),
            &Value::string("token_transport_failed")
        );
        assert!(matches!(
            optional_field(result, "value"),
            None | Some(Value::Null)
        ));
        let rendered = format!("{output:?}");
        assert!(!rendered.contains(ACCESS_SECRET));
        assert!(!rendered.contains(REFRESH_SECRET));
    }
}

#[test]
fn actual_sanitized_oauth_response_uses_native_clock_and_preserves_caller_slots() {
    let body = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","expires_in":60,"token_type":"Bearer","account":{{"id":"acct_synthetic_metadata"}}}}"#
    );
    let output = run_fixture(200, &body, 1_900_000_000_123, selected_intent(), 2);
    let result = field(&output, "metadata_result");
    assert_eq!(field(result, "ok"), &Value::Bool(true));
    assert_eq!(field(result, "code"), &Value::string("ok"));
    let metadata = field(result, "value");
    assert_eq!(
        field(metadata, "provider"),
        &Value::string("selected-provider")
    );
    assert_eq!(field(metadata, "kind"), &Value::string("oauth"));
    assert_eq!(field(metadata, "source"), &Value::string("selected-source"));
    assert_eq!(field(metadata, "token_type"), &Value::string("Bearer"));
    assert_eq!(
        field(metadata, "expires_at_ms"),
        &Value::Int(1_900_000_060_123)
    );
    assert_eq!(
        field(metadata, "scopes"),
        &Value::array(vec![
            Value::string("scope.alpha"),
            Value::string("scope.beta")
        ])
    );
    assert_eq!(
        field(metadata, "account_id"),
        &Value::string("acct_synthetic_metadata")
    );
    assert_eq!(field(metadata, "generation"), &Value::Int(37));
    assert_eq!(field(metadata, "status"), &Value::string("active"));
    assert!(matches!(
        optional_field(metadata, "last_refresh_at_ms"),
        None | Some(Value::Null)
    ));
    assert_eq!(field(metadata, "has_refresh_token"), &Value::Bool(true));
    let rendered = format!("{output:?}");
    assert!(!rendered.contains(ACCESS_SECRET));
    assert!(!rendered.contains(REFRESH_SECRET));
}
