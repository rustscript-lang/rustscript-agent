use std::{fs, path::PathBuf, sync::Arc, time::Duration};

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

const ACCESS_SECRET: &str = "SYNTHETIC_OAUTH_RESPONSE_ACCESS_NEVER_EMIT";
const REFRESH_SECRET: &str = "SYNTHETIC_OAUTH_RESPONSE_REFRESH_NEVER_EMIT";
struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned task lease temp"),
        );
        let path = root.join(format!(
            "oauth-response-sanitizer-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create isolated auth home");
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixtures.join("config.yaml"), path.join("config.yaml"))
            .expect("copy current config fixture");
        let auth = fs::read_to_string(fixtures.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1900000000000");
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

    fn auth_path(&self) -> PathBuf {
        self.0.join("auth.yaml")
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

fn compile_vm(home: &FixtureHome, transport: Arc<ScriptedHttpsTransport>) -> (Vm, AuthHost, Value) {
    let module_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/fallible_contract.rss");
    let source = fs::read_to_string(&module_path).expect("read production fallible RSS");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &module_path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .unwrap_or_else(|error| panic!("compile actual fallible RSS transport driver: {error}"));
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
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
        .expect("register real auth host catalog");
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
    vm.invoke_callable(callable, args).expect("native RSS call")
}

fn transport_request(policy: &Value) -> Value {
    record(vec![
        ("policy_handle", policy.clone()),
        ("credential_id", Value::string("fixture-codex")),
        ("method", Value::string("POST")),
        ("path", Value::string("/oauth/token")),
        (
            "public_headers",
            Value::array(vec![record(vec![
                ("name", Value::string("content-type")),
                ("value", Value::string("application/json")),
            ])]),
        ),
        (
            "public_body",
            Value::string(r#"{"grant_type":"authorization_code"}"#),
        ),
    ])
}

fn credential_use() -> Value {
    record(vec![
        ("kind", Value::string("none")),
        ("access_handle", Value::Null),
        ("refresh_handle", Value::Null),
        ("code_handle", Value::Null),
        ("verifier_handle", Value::Null),
        ("device_handle", Value::Null),
    ])
}

fn send_response(vm: &mut Vm, policy: &Value) -> Value {
    invoke(
        vm,
        "transport_result",
        &[transport_request(policy), credential_use()],
    )
}

fn cleanup(vm: &mut Vm, policy: &Value) {
    assert_eq!(
        invoke(vm, "cleanup", std::slice::from_ref(policy)),
        Value::Null
    );
}

fn unique_body() -> String {
    format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","expires_in":60,"token_type":"Bearer","account":{{"id":"acct_native_sanitizer"}},"public":"normal-response"}}"#
    )
}

fn rejection_cases() -> Vec<(String, String, String)> {
    let duplicate_expiry = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","expires_in":60,"expires_in":30,"token_type":"Bearer"}}"#
    );
    let nested_duplicate = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","account":{{"id":"first","id":"second"}}}}"#
    );
    let escaped_duplicate = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","\u0065xpires_in":60,"expires_in":30}}"#
    );
    let duplicate_access = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}"}}"#
    );
    let duplicate_refresh = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","refresh_token":"{REFRESH_SECRET}"}}"#
    );
    let malformed = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","expires_in":}}"#
    );
    let trailing =
        format!(r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}"}} {{}}"#);
    let too_deep = format!("{}0{}", "[".repeat(10), "]".repeat(10));
    let too_large = format!(
        r#"{{"access_token":"{ACCESS_SECRET}","refresh_token":"{REFRESH_SECRET}","padding":"{}"}}"#,
        "x".repeat(70 * 1024)
    );
    vec![
        (
            "duplicate_expires_in".into(),
            duplicate_expiry,
            "malformed_response".into(),
        ),
        (
            "nested_duplicate_account_id".into(),
            nested_duplicate,
            "malformed_response".into(),
        ),
        (
            "escaped_duplicate_expires_in".into(),
            escaped_duplicate,
            "malformed_response".into(),
        ),
        (
            "duplicate_access_token".into(),
            duplicate_access,
            "malformed_response".into(),
        ),
        (
            "duplicate_refresh_token".into(),
            duplicate_refresh,
            "malformed_response".into(),
        ),
        (
            "malformed_json".into(),
            malformed,
            "malformed_response".into(),
        ),
        (
            "trailing_json".into(),
            trailing,
            "malformed_response".into(),
        ),
        (
            "over_depth_json".into(),
            too_deep,
            "malformed_response".into(),
        ),
        (
            "over_size_native_response".into(),
            too_large,
            "response_too_large".into(),
        ),
    ]
}

#[test]
fn native_response_rejects_duplicate_json_before_secret_slots_are_published() {
    let home = FixtureHome::new();
    let auth_before = fs::read(home.auth_path()).expect("read original synthetic auth state");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let (mut vm, _auth, host_home) = compile_vm(&home, transport.clone());
    let policy = invoke(&mut vm, "snapshot", std::slice::from_ref(&host_home));
    let baseline_resources = vm.host_context().resource_count();

    transport.push_raw(200, &unique_body());
    let unique = send_response(&mut vm, &policy);
    assert_eq!(field(&unique, "ok"), &Value::Bool(true));
    assert_eq!(field(&unique, "error"), &Value::Null);
    let sanitized = field(field(&unique, "value"), "body_without_secret_fields");
    let Value::String(sanitized_text) = sanitized else {
        panic!("native transport returned sanitized JSON text");
    };
    assert!(!sanitized_text.contains(ACCESS_SECRET));
    assert!(!sanitized_text.contains(REFRESH_SECRET));
    assert_eq!(vm.host_context().resource_count(), baseline_resources + 2);

    let ttl = invoke(
        &mut vm,
        "public_json_field_result",
        &[
            policy.clone(),
            Value::string(sanitized_text.to_string()),
            Value::string("/expires_in"),
        ],
    );
    assert_eq!(field(&ttl, "ok"), &Value::Bool(true));
    assert_eq!(field(field(&ttl, "value"), "kind"), &Value::string("int"));
    assert_eq!(field(field(&ttl, "value"), "int_value"), &Value::Int(60));
    let account = invoke(
        &mut vm,
        "public_json_field_result",
        &[
            policy.clone(),
            Value::string(sanitized_text.to_string()),
            Value::string("/account/id"),
        ],
    );
    assert_eq!(field(&account, "ok"), &Value::Bool(true));
    assert_eq!(
        field(field(&account, "value"), "kind"),
        &Value::string("string")
    );
    assert_eq!(
        field(field(&account, "value"), "string_value"),
        &Value::string("acct_native_sanitizer")
    );
    let unique_debug = format!("{unique:?}");
    assert!(!unique_debug.contains(ACCESS_SECRET));
    assert!(!unique_debug.contains(REFRESH_SECRET));
    cleanup(&mut vm, &policy);
    assert_eq!(vm.host_context().resource_count(), baseline_resources);
    assert_eq!(
        fs::read(home.auth_path()).expect("read auth after valid response"),
        auth_before
    );

    let mut observations = Vec::new();
    for (label, body, expected_code) in rejection_cases() {
        transport.push_raw(200, &body);
        let count_before = vm.host_context().resource_count();
        let output = send_response(&mut vm, &policy);
        let count_after = vm.host_context().resource_count();
        let ok = field(&output, "ok") == &Value::Bool(true);
        let code = if ok {
            "ok".to_owned()
        } else {
            match field(field(&output, "error"), "code") {
                Value::String(code) => code.to_string(),
                _ => "invalid-native-error".to_owned(),
            }
        };
        let value_is_null = matches!(field(&output, "value"), Value::Null);
        let rendered = format!("{output:?}");
        let secrets_redacted =
            !rendered.contains(ACCESS_SECRET) && !rendered.contains(REFRESH_SECRET);
        let slots_published = count_after.saturating_sub(count_before);
        let auth_unchanged =
            fs::read(home.auth_path()).expect("read auth after native response") == auth_before;
        println!("native_case={label} ok={ok} code={code} slots_published={slots_published}");
        observations.push((
            label,
            expected_code,
            ok,
            code,
            value_is_null,
            slots_published,
            secrets_redacted,
            auth_unchanged,
        ));
        cleanup(&mut vm, &policy);
        assert_eq!(vm.host_context().resource_count(), baseline_resources);
    }

    assert_eq!(transport.take_sent().len(), 1 + observations.len());
    for (
        label,
        expected_code,
        ok,
        code,
        value_is_null,
        slots_published,
        secrets_redacted,
        auth_unchanged,
    ) in observations
    {
        assert!(
            !ok,
            "{label}: ambiguous or malformed JSON was accepted by native transport"
        );
        assert_eq!(
            code, expected_code,
            "{label}: wrong sanitized native failure code"
        );
        assert!(
            value_is_null,
            "{label}: failed native result carried a response value"
        );
        assert_eq!(
            slots_published, 0,
            "{label}: native transport published a secret slot"
        );
        assert!(
            secrets_redacted,
            "{label}: native result exposed a synthetic secret"
        );
        assert!(
            auth_unchanged,
            "{label}: native response changed persisted auth state"
        );
    }
}
